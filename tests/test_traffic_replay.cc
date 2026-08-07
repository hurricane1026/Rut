// Tests for traffic replay: ReplayReader, replay_one, replay_file.
#include "fault_injection.h"
#include "rut/harness/replay_driver.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/traffic_replay.h"
#include "test.h"
#include "test_helpers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

using namespace rut;
using rut::test_fault::IoFaultConfig;
using rut::test_fault::kMatchAllIoFds;
using rut::test_fault::ScopedFakeSocket;
using rut::test_fault::ScopedIoFault;
using rut::test_fault::ScopedSyscallFault;
using rut::test_fault::SyscallFaultConfig;

// --- Helper: create a capture file with N entries ---

struct TempCapture {
    char path[64];
    i32 fd = -1;

    ~TempCapture() { cleanup(); }

    bool create(const CaptureEntry* entries, u32 count) {
        __builtin_memcpy(path, "/tmp/rut_replay_XXXXXX", 23);
        fd = mkstemp(path);
        if (fd < 0) return false;

        CaptureFileHeader hdr;
        capture_file_header_init(&hdr);
        hdr.entry_count = count;
        if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
            close(fd);
            fd = -1;
            unlink(path);
            return false;
        }

        for (u32 i = 0; i < count; i++) {
            if (capture_write_entry(fd, entries[i]) != 0) {
                close(fd);
                fd = -1;
                unlink(path);
                return false;
            }
        }

        close(fd);
        fd = -1;
        return true;
    }

    void cleanup() {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        unlink(path);
    }
};

static CaptureEntry make_captured_request(const char* req, u16 status) {
    CaptureEntry entry{};
    u32 len = 0;
    while (req[len]) len++;
    if (len > CaptureEntry::kMaxHeaderLen) len = CaptureEntry::kMaxHeaderLen;
    __builtin_memcpy(entry.raw_headers, req, len);
    entry.raw_header_len = static_cast<u16>(len);
    entry.resp_status = status;
    entry.method = static_cast<u8>(LogHttpMethod::Get);
    entry.timestamp_us = realtime_us();
    return entry;
}

static u64 replay_matrix_status_207_handler(void* /*conn*/,
                                            rut::jit::HandlerCtx* /*ctx*/,
                                            const u8* /*req*/,
                                            u32 /*len*/,
                                            void* /*arena*/) {
    return rut::jit::HandlerResult::make_status(207).pack();
}

static u64 replay_matrix_forward_0_handler(void* /*conn*/,
                                           rut::jit::HandlerCtx* /*ctx*/,
                                           const u8* /*req*/,
                                           u32 /*len*/,
                                           void* /*arena*/) {
    return rut::jit::HandlerResult::make_forward(0).pack();
}

static u64 replay_dynamic_json_handler(
    void* /*conn*/, rut::jit::HandlerCtx* ctx, const u8* /*req*/, u32 /*len*/, void* /*arena*/) {
    static constexpr char kBody[] = R"({"path":"/dynamic","code":42})";
    ctx->response_body_data = kBody;
    ctx->response_body_len = sizeof(kBody) - 1;
    ctx->response_body_valid = 1;
    auto result = rut::jit::HandlerResult::make_status(200);
    result.upstream_id = rut::jit::HandlerResult::kDynamicResponseBody;
    return result.pack();
}

// === ReplayReader ===

TEST(replay_reader, open_valid_file) {
    CaptureEntry entries[2];
    entries[0] = make_captured_request("GET / HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /b HTTP/1.1\r\nHost: x\r\n\r\n", 200);

    TempCapture tmp;
    REQUIRE(tmp.create(entries, 2));

    ReplayReader reader;
    CHECK_EQ(reader.open(tmp.path), 0);
    CHECK_EQ(reader.entry_count(), 2u);

    CaptureEntry out{};
    CHECK_EQ(reader.next(out), 0);
    CHECK_EQ(out.raw_header_len, entries[0].raw_header_len);
    CHECK_EQ(reader.next(out), 0);
    CHECK_EQ(out.raw_header_len, entries[1].raw_header_len);
    CHECK_EQ(reader.next(out), -1);  // EOF

    reader.close();
    tmp.cleanup();
}

TEST(replay_reader, open_nonexistent_fails) {
    ReplayReader reader;
    CHECK_EQ(reader.open("/tmp/rut_does_not_exist_12345"), -1);
}

TEST(replay_reader, open_injected_failure) {
    CaptureEntry entry = make_captured_request("GET /open HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(&entry, 1));

    SyscallFaultConfig fault_config;
    fault_config.open_errno = EACCES;
    fault_config.open_failures = 1;
    ScopedSyscallFault fault(fault_config);

    ReplayReader reader;
    CHECK_EQ(reader.open(tmp.path), -1);
    CHECK_EQ(errno, EACCES);
    tmp.cleanup();
}

TEST(replay_reader, open_handles_short_header_read) {
    CaptureEntry entry = make_captured_request("GET /short HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(&entry, 1));

    IoFaultConfig fault_config;
    fault_config.fd = kMatchAllIoFds;
    fault_config.read_short_len = 7;
    fault_config.read_shorts = 1;
    ScopedIoFault fault(fault_config);

    ReplayReader reader;
    CHECK_EQ(reader.open(tmp.path), 0);
    CHECK_EQ(reader.entry_count(), 1u);
    reader.close();
    tmp.cleanup();
}

TEST(replay_reader, open_invalid_magic_fails) {
    char path[] = "/tmp/rut_badmagic_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.magic[0] = 'X';  // corrupt
    write(fd, &hdr, sizeof(hdr));
    close(fd);

    ReplayReader reader;
    CHECK_EQ(reader.open(path), -1);

    unlink(path);
}

TEST(replay_reader, empty_file) {
    TempCapture tmp;
    REQUIRE(tmp.create(nullptr, 0));

    ReplayReader reader;
    CHECK_EQ(reader.open(tmp.path), 0);
    CHECK_EQ(reader.entry_count(), 0u);

    CaptureEntry out{};
    CHECK_EQ(reader.next(out), -1);

    reader.close();
    tmp.cleanup();
}

// === replay_one ===

TEST(replay_one, basic_200) {
    SmallLoop loop;
    loop.setup();

    CaptureEntry entry =
        make_captured_request("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n", 200);

    ReplayResult result = replay_one(loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.expected_status, 200);
    CHECK_EQ(result.actual_status, 200);
    CHECK(result.status_match);
}

TEST(replay_one, status_mismatch) {
    SmallLoop loop;
    loop.setup();

    // Captured entry says 404, but current config returns 200
    CaptureEntry entry = make_captured_request("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 404);

    ReplayResult result = replay_one(loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.expected_status, 404);
    CHECK_EQ(result.actual_status, 200);  // current config always returns 200
    CHECK(!result.status_match);
}

TEST(replay_one, multiple_sequential) {
    SmallLoop loop;
    loop.setup();

    const char* reqs[] = {
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        "DELETE /c HTTP/1.1\r\nHost: x\r\n\r\n",
    };

    for (i32 i = 0; i < 3; i++) {
        CaptureEntry entry = make_captured_request(reqs[i], 200);
        ReplayResult result = replay_one(loop, entry, 100 + i);
        CHECK(result.replayed);
        CHECK(result.status_match);
    }
}

TEST(replay_one, response_body_observation_is_bounded_and_reports_full_length) {
    constexpr u32 kBodyLen = ReplayResult::kMaxObservedBodyLen + 17;
    u8 response[4 + kBodyLen]{};
    response[0] = '\r';
    response[1] = '\n';
    response[2] = '\r';
    response[3] = '\n';
    for (u32 i = 0; i < kBodyLen; i++) response[4 + i] = static_cast<u8>(i & 0xffu);

    ReplayResult result{};
    observe_replay_response_body(response, sizeof(response), &result);

    REQUIRE(result.response_body_observed);
    CHECK(result.response_body_truncated);
    CHECK_EQ(result.response_body_len, kBodyLen);
    CHECK_EQ(result.observed_body_len, ReplayResult::kMaxObservedBodyLen);
    CHECK(__builtin_memcmp(result.observed_body, response + 4, ReplayResult::kMaxObservedBodyLen) ==
          0);
}

static bool reject_replay_observation(void*, const harness::Observation&) {
    return false;
}

static bool reject_replay_body_observation(void*, const harness::Observation& event) {
    return event.kind != harness::ObservationKind::ResponseBodyProduced;
}

TEST(harness_replay, maps_match_mismatch_and_failure_to_common_outcomes) {
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;

    SmallLoop matched_loop;
    matched_loop.setup();
    const CaptureEntry matched_entry =
        make_captured_request("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    const auto matched = harness::drive_replay_one(matched_loop, matched_entry, 42, spec);
    CHECK_EQ(matched.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(matched.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK_EQ(matched.harness.semantic_events, 2u);
    CHECK_EQ(matched.harness.input_bytes, matched_entry.raw_header_len);
    CHECK(matched.harness.output_bytes > 0);
    CHECK_EQ(matched.harness.output_bytes, matched.replay.output_bytes);
    CHECK_EQ(matched.harness.backend_completions, 4u);

    SmallLoop mismatched_loop;
    mismatched_loop.setup();
    const auto mismatched = harness::drive_replay_one(
        mismatched_loop,
        make_captured_request("GET /miss HTTP/1.1\r\nHost: x\r\n\r\n", 404),
        43,
        spec);
    CHECK_EQ(mismatched.harness.outcome, harness::Outcome::Mismatched);
    CHECK(mismatched.replay.replayed);

    SmallLoop exhausted_loop;
    exhausted_loop.setup();
    exhausted_loop.free_top = 0;
    const auto failed = harness::drive_replay_one(
        exhausted_loop,
        make_captured_request("GET /fail HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        44,
        spec);
    CHECK_EQ(failed.harness.outcome, harness::Outcome::Failed);
    CHECK(!failed.replay.replayed);
    CHECK(!failed.replay.skipped);

    exhausted_loop.setup();
    exhausted_loop.free_top = 0;
    harness::HarnessSpec rejecting_spec = spec;
    rejecting_spec.observations.observe = &reject_replay_observation;
    const auto rejected_failure = harness::drive_replay_one(
        exhausted_loop,
        make_captured_request("GET /fail-observed HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        45,
        rejecting_spec);
    CHECK_EQ(rejected_failure.harness.outcome, harness::Outcome::Failed);
}

TEST(harness_replay, mismatch_takes_precedence_over_unsupported) {
    harness::Outcome aggregate = harness::Outcome::Passed;
    harness::detail::merge_outcome(harness::Outcome::Mismatched, aggregate);
    harness::detail::merge_outcome(harness::Outcome::Unsupported, aggregate);
    CHECK_EQ(aggregate, harness::Outcome::Mismatched);

    aggregate = harness::Outcome::Passed;
    harness::detail::merge_outcome(harness::Outcome::Unsupported, aggregate);
    harness::detail::merge_outcome(harness::Outcome::Mismatched, aggregate);
    CHECK_EQ(aggregate, harness::Outcome::Mismatched);
}

TEST(harness_replay, enforces_input_limit_and_oracle) {
    SmallLoop loop;
    loop.setup();
    const CaptureEntry entry = make_captured_request("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200);

    harness::HarnessSpec limited_spec{};
    limited_spec.layer = harness::ExecutionLayer::Connection;
    limited_spec.required_capabilities =
        harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    limited_spec.environment_capabilities = limited_spec.required_capabilities;
    limited_spec.limits.max_input_bytes = 1;
    const auto limited = harness::drive_replay_one(loop, entry, 42, limited_spec);
    CHECK_EQ(limited.harness.outcome, harness::Outcome::Failed);
    CHECK(limited.harness.has_reached_limit);
    CHECK_EQ(limited.harness.reached_limit, harness::LimitKind::InputBytes);

    harness::HarnessSpec oracle_spec{};
    oracle_spec.layer = harness::ExecutionLayer::Connection;
    oracle_spec.required_capabilities =
        harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    oracle_spec.environment_capabilities = oracle_spec.required_capabilities;
    oracle_spec.observations.observe = &reject_replay_observation;
    const auto rejected = harness::drive_replay_one(loop, entry, 43, oracle_spec);
    CHECK_EQ(rejected.harness.outcome, harness::Outcome::Mismatched);
    CHECK_EQ(rejected.harness.cleanup, harness::CleanupOutcome::Clean);

    SmallLoop output_limited_loop;
    output_limited_loop.setup();
    harness::HarnessSpec output_limited_spec = oracle_spec;
    output_limited_spec.observations.observe = nullptr;
    output_limited_spec.limits.max_output_bytes = 1;
    const auto output_limited =
        harness::drive_replay_one(output_limited_loop, entry, 44, output_limited_spec);
    CHECK_EQ(output_limited.harness.outcome, harness::Outcome::Failed);
    CHECK_EQ(output_limited.harness.reached_limit, harness::LimitKind::OutputBytes);
    CHECK(output_limited.harness.output_bytes > 1);

    SmallLoop completion_limited_loop;
    completion_limited_loop.setup();
    harness::HarnessSpec completion_limited_spec = oracle_spec;
    completion_limited_spec.observations.observe = nullptr;
    completion_limited_spec.limits.max_backend_completions = 1;
    const auto completion_limited =
        harness::drive_replay_one(completion_limited_loop, entry, 45, completion_limited_spec);
    CHECK_EQ(completion_limited.harness.outcome, harness::Outcome::Failed);
    CHECK_EQ(completion_limited.harness.reached_limit, harness::LimitKind::BackendCompletions);
    CHECK_EQ(completion_limited.harness.backend_completions, 4u);
}

TEST(harness_replay, rejects_missing_synthetic_io_capability) {
    SmallLoop loop;
    loop.setup();
    const CaptureEntry entry = make_captured_request("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;

    const auto result = harness::drive_replay_one(loop, entry, 42, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!result.replay.replayed);
}

// === replay_file ===

TEST(replay_file, full_roundtrip) {
    // Create capture file with 5 entries (all expect 200)
    CaptureEntry entries[5];
    const char* reqs[] = {
        "GET /1 HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /2 HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /3 HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /4 HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /5 HTTP/1.1\r\nHost: x\r\n\r\n",
    };
    for (u32 i = 0; i < 5; i++) entries[i] = make_captured_request(reqs[i], 200);

    TempCapture tmp;
    REQUIRE(tmp.create(entries, 5));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    SmallLoop loop;
    loop.setup();

    ReplaySummary summary = replay_file(loop, reader);
    CHECK_EQ(summary.total, 5u);
    CHECK_EQ(summary.replayed, 5u);
    CHECK_EQ(summary.matched, 5u);
    CHECK_EQ(summary.mismatched, 0u);
    CHECK_EQ(summary.failed, 0u);

    reader.close();
    tmp.cleanup();
}

TEST(replay_file, with_mismatches) {
    // 3 entries: 2 expect 200 (match), 1 expects 404 (mismatch)
    CaptureEntry entries[3];
    entries[0] = make_captured_request("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /miss HTTP/1.1\r\nHost: x\r\n\r\n", 404);
    entries[2] = make_captured_request("GET /ok2 HTTP/1.1\r\nHost: x\r\n\r\n", 200);

    TempCapture tmp;
    REQUIRE(tmp.create(entries, 3));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    SmallLoop loop;
    loop.setup();

    ReplaySummary summary = replay_file(loop, reader);
    CHECK_EQ(summary.total, 3u);
    CHECK_EQ(summary.replayed, 3u);
    CHECK_EQ(summary.matched, 2u);
    CHECK_EQ(summary.mismatched, 1u);

    reader.close();
    tmp.cleanup();
}

TEST(harness_replay, file_adapter_preserves_summary_and_common_outcome) {
    CaptureEntry entries[3];
    entries[0] = make_captured_request("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /miss HTTP/1.1\r\nHost: x\r\n\r\n", 404);
    entries[2] = make_captured_request("GET /ok2 HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 3));
    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);
    SmallLoop loop;
    loop.setup();
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;

    const auto result = harness::drive_replay_file(loop, reader, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Mismatched);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK_EQ(result.harness.semantic_events, 6u);
    CHECK_EQ(result.harness.input_bytes,
             static_cast<u64>(entries[0].raw_header_len) + entries[1].raw_header_len +
                 entries[2].raw_header_len);
    CHECK(result.harness.output_bytes > 0);
    CHECK_EQ(result.harness.backend_completions, 12u);
    CHECK_EQ(result.replay.total, 3u);
    CHECK_EQ(result.replay.matched, 2u);
    CHECK_EQ(result.replay.mismatched, 1u);
    reader.close();
}

TEST(harness_replay, file_adapter_rejects_unopened_reader) {
    ReplayReader reader;
    SmallLoop loop;
    loop.setup();
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;

    const auto result = harness::drive_replay_file(loop, reader, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK_EQ(result.replay.total, 0u);
}

TEST(harness_replay, file_adapter_enforces_output_and_completion_limits) {
    const CaptureEntry entry =
        make_captured_request("GET /limited HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(&entry, 1));
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;

    ReplayReader output_reader;
    REQUIRE(output_reader.open(tmp.path) == 0);
    SmallLoop output_loop;
    output_loop.setup();
    spec.limits.max_output_bytes = 1;
    const auto output_limited = harness::drive_replay_file(output_loop, output_reader, spec);
    CHECK_EQ(output_limited.harness.outcome, harness::Outcome::Failed);
    CHECK_EQ(output_limited.harness.reached_limit, harness::LimitKind::OutputBytes);
    CHECK_EQ(output_limited.replay.total, 1u);
    CHECK_EQ(output_limited.replay.replayed, 1u);
    output_reader.close();

    ReplayReader completion_reader;
    REQUIRE(completion_reader.open(tmp.path) == 0);
    SmallLoop completion_loop;
    completion_loop.setup();
    spec.limits.max_output_bytes = harness::RunLimits{}.max_output_bytes;
    spec.limits.max_backend_completions = 1;
    const auto completion_limited =
        harness::drive_replay_file(completion_loop, completion_reader, spec);
    CHECK_EQ(completion_limited.harness.outcome, harness::Outcome::Failed);
    CHECK_EQ(completion_limited.harness.reached_limit, harness::LimitKind::BackendCompletions);
    CHECK_EQ(completion_limited.harness.backend_completions, 4u);
    CHECK_EQ(completion_limited.replay.total, 1u);
    CHECK_EQ(completion_limited.replay.replayed, 1u);
    completion_reader.close();
}

TEST(harness_replay, input_limit_keeps_file_summary_consistent) {
    CaptureEntry entries[2];
    entries[0] = make_captured_request("GET /one HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /two HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 2));
    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);
    SmallLoop loop;
    loop.setup();
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;
    spec.limits.max_input_bytes = entries[0].raw_header_len;

    const auto result = harness::drive_replay_file(loop, reader, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK(result.harness.has_reached_limit);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::InputBytes);
    CHECK_EQ(result.harness.input_bytes, entries[0].raw_header_len);
    CHECK_EQ(result.replay.total, 1u);
    CHECK_EQ(result.replay.replayed, 1u);
    CHECK_EQ(result.replay.matched, 1u);
    CHECK_EQ(result.replay.failed, 0u);
    CHECK_EQ(result.replay.replayed + result.replay.skipped + result.replay.failed,
             result.replay.total);
    reader.close();
}

TEST(replay_file, empty_capture) {
    TempCapture tmp;
    REQUIRE(tmp.create(nullptr, 0));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    SmallLoop loop;
    loop.setup();

    ReplaySummary summary = replay_file(loop, reader);
    CHECK_EQ(summary.total, 0u);
    CHECK_EQ(summary.replayed, 0u);

    reader.close();
    tmp.cleanup();
}

// === End-to-end: capture → file → replay → verify ===

TEST(replay_e2e, capture_then_replay) {
    // Step 1: Capture traffic from a live loop
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop capture_loop;
    capture_loop.setup();
    capture_loop.set_capture(ring);

    // Send 3 requests through the capture loop
    capture_loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = capture_loop.find_fd(42);
    REQUIRE(conn != nullptr);

    const char* reqs[] = {
        "GET /users HTTP/1.1\r\nHost: api.test\r\n\r\n",
        "POST /login HTTP/1.1\r\nHost: api.test\r\nContent-Length: 0\r\n\r\n",
        "GET /health HTTP/1.1\r\nHost: api.test\r\n\r\n",
    };
    for (int i = 0; i < 3; i++) {
        conn->recv_buf.reset();
        u32 len = 0;
        while (reqs[i][len]) len++;
        conn->recv_buf.write(reinterpret_cast<const u8*>(reqs[i]), len);
        IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(len));
        capture_loop.backend.inject(recv_ev);
        IoEvent events[8];
        u32 n = capture_loop.backend.wait(events, 8);
        for (u32 j = 0; j < n; j++) capture_loop.dispatch(events[j]);
        capture_loop.inject_and_dispatch(
            make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));
    }
    CHECK_EQ(ring->available(), 3u);

    // Step 2: Write captured entries to file
    char path[] = "/tmp/rut_e2e_replay_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = 3;
    write(fd, &hdr, sizeof(hdr));

    CaptureEntry cap{};
    for (u32 i = 0; i < 3; i++) {
        ring->pop(cap);
        capture_write_entry(fd, cap);
    }
    close(fd);

    // Step 3: Replay against a fresh loop (simulating "new config")
    ReplayReader reader;
    REQUIRE(reader.open(path) == 0);

    SmallLoop replay_loop;
    replay_loop.setup();

    ReplaySummary summary = replay_file(replay_loop, reader);
    CHECK_EQ(summary.total, 3u);
    CHECK_EQ(summary.replayed, 3u);
    CHECK_EQ(summary.matched, 3u);  // same config → same results
    CHECK_EQ(summary.mismatched, 0u);

    reader.close();
    unlink(path);
    munmap(ring, sizeof(CaptureRing));
}

// === Route matching tests (static routes) ===

// Helper: set up SmallLoop with a RouteConfig wired into config_ptr.
struct RoutedLoop {
    SmallLoop loop;
    const RouteConfig* active_config;

    void setup(RouteConfig* cfg) {
        loop.setup();
        active_config = cfg;
        loop.config_ptr = &active_config;
    }
};

struct ReplayBodyObservation {
    bool seen = false;
    bool truncated = false;
    u32 sequence = 0;
    u32 full_len = 0;
    u32 copied_len = 0;
    u8 bytes[ReplayResult::kMaxObservedBodyLen]{};
};

static bool capture_replay_body(void* context, const harness::Observation& event) {
    if (event.kind != harness::ObservationKind::ResponseBodyProduced) return true;
    auto* captured = static_cast<ReplayBodyObservation*>(context);
    captured->seen = true;
    captured->truncated = event.value1 != 0;
    captured->sequence = event.sequence;
    captured->full_len = static_cast<u32>(event.value0);
    captured->copied_len = event.label.len;
    if (event.label.len != 0) __builtin_memcpy(captured->bytes, event.label.ptr, event.label.len);
    return true;
}

struct ReplaySequenceObservation {
    u32 count = 0;
    u32 sequences[4]{};
    harness::ObservationKind kinds[4]{};
};

static bool capture_replay_sequence(void* context, const harness::Observation& event) {
    auto* captured = static_cast<ReplaySequenceObservation*>(context);
    if (captured->count >= 4) return false;
    captured->sequences[captured->count] = event.sequence;
    captured->kinds[captured->count] = event.kind;
    captured->count++;
    return true;
}

TEST(harness_replay, publishes_dynamic_json_response_body_bytes) {
    RouteConfig cfg;
    REQUIRE(cfg.add_jit_handler("/dynamic", 'G', &replay_dynamic_json_handler));
    RoutedLoop rl;
    rl.setup(&cfg);

    ReplayBodyObservation observed{};
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations = {&observed, &capture_replay_body};
    const CaptureEntry entry =
        make_captured_request("GET /dynamic HTTP/1.1\r\nHost: x\r\n\r\n", 200);

    const auto result = harness::drive_replay_one(rl.loop, entry, 42, spec);
    static constexpr char kExpected[] = R"({"path":"/dynamic","code":42})";
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(observed.seen);
    CHECK(!observed.truncated);
    CHECK_EQ(observed.sequence, 1u);
    CHECK_EQ(observed.full_len, sizeof(kExpected) - 1);
    CHECK_EQ(observed.copied_len, sizeof(kExpected) - 1);
    CHECK(__builtin_memcmp(observed.bytes, kExpected, sizeof(kExpected) - 1) == 0);
    CHECK_EQ(result.replay.response_body_len, sizeof(kExpected) - 1);
    CHECK_EQ(result.harness.semantic_events, 2u);
}

TEST(harness_replay, file_observation_sequences_are_globally_contiguous) {
    RouteConfig cfg;
    REQUIRE(cfg.add_jit_handler("/dynamic", 'G', &replay_dynamic_json_handler));
    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entries[2];
    entries[0] = make_captured_request("GET /dynamic HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /dynamic HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 2));
    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    ReplaySequenceObservation observed{};
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations = {&observed, &capture_replay_sequence};

    const auto result = harness::drive_replay_file(rl.loop, reader, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(observed.count, 4u);
    for (u32 i = 0; i < observed.count; i++) CHECK_EQ(observed.sequences[i], i);
    CHECK_EQ(observed.kinds[0], harness::ObservationKind::ResponseProduced);
    CHECK_EQ(observed.kinds[1], harness::ObservationKind::ResponseBodyProduced);
    CHECK_EQ(observed.kinds[2], harness::ObservationKind::ResponseProduced);
    CHECK_EQ(observed.kinds[3], harness::ObservationKind::ResponseBodyProduced);
    CHECK_EQ(result.harness.semantic_events, 4u);
    reader.close();
}

TEST(harness_replay, body_oracle_mismatch_takes_precedence_over_unsupported_file_entry) {
    RouteConfig cfg;
    auto upstream = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(upstream.has_value());
    REQUIRE(cfg.add_proxy("/api", 0, static_cast<u16>(upstream.value())));
    REQUIRE(cfg.add_jit_handler("/dynamic", 'G', &replay_dynamic_json_handler));
    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entries[2];
    entries[0] = make_captured_request("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /dynamic HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 2));
    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations.observe = &reject_replay_body_observation;

    const auto result = harness::drive_replay_file(rl.loop, reader, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Mismatched);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK_EQ(result.replay.total, 2u);
    CHECK_EQ(result.replay.skipped, 1u);
    CHECK_EQ(result.replay.replayed, 1u);
    CHECK_EQ(result.replay.matched, 1u);
    reader.close();
}

TEST(route, static_200) {
    RouteConfig cfg;
    cfg.add_static("/health", 'G', 200);

    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entry = make_captured_request("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.actual_status, 200);
    CHECK(result.status_match);
}

TEST(route, static_404) {
    RouteConfig cfg;
    cfg.add_static("/", 0, 404);  // catch-all 404

    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entry = make_captured_request("GET /anything HTTP/1.1\r\nHost: x\r\n\r\n", 404);
    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.actual_status, 404);
    CHECK(result.status_match);
}

TEST(route, no_match_returns_404) {
    RouteConfig cfg;
    cfg.add_static("/api", 'G', 200);
    // /other doesn't match /api

    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entry = make_captured_request("GET /other HTTP/1.1\r\nHost: x\r\n\r\n", 404);
    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.actual_status, 404);
}

TEST(route, method_filtering) {
    RouteConfig cfg;
    cfg.add_static("/admin", 'P', 403);  // POST /admin → 403
    cfg.add_static("/admin", 'G', 200);  // GET /admin → 200

    RoutedLoop rl;
    rl.setup(&cfg);

    // GET /admin → matches second rule → 200
    CaptureEntry get_entry = make_captured_request("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    ReplayResult get_result = replay_one(rl.loop, get_entry, 42);
    CHECK(get_result.replayed);
    CHECK_EQ(get_result.actual_status, 200);

    // POST /admin → matches first rule → 403
    CaptureEntry post_entry =
        make_captured_request("POST /admin HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", 403);
    post_entry.method = static_cast<u8>(LogHttpMethod::Post);
    ReplayResult post_result = replay_one(rl.loop, post_entry, 43);
    CHECK(post_result.replayed);
    CHECK_EQ(post_result.actual_status, 403);
}

TEST(route, multiple_routes_first_match_wins) {
    RouteConfig cfg;
    cfg.add_static("/api/v1", 0, 200);  // specific prefix
    cfg.add_static("/api", 0, 301);     // broader prefix
    cfg.add_static("/", 0, 404);        // catch-all

    RoutedLoop rl;
    rl.setup(&cfg);

    // /api/v1/users → matches first rule
    CaptureEntry e1 = make_captured_request("GET /api/v1/users HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    CHECK_EQ(replay_one(rl.loop, e1, 42).actual_status, 200);

    // /api/v2 → matches second rule (prefix /api)
    CaptureEntry e2 = make_captured_request("GET /api/v2 HTTP/1.1\r\nHost: x\r\n\r\n", 301);
    CHECK_EQ(replay_one(rl.loop, e2, 43).actual_status, 301);

    // /other → matches third rule (prefix /)
    CaptureEntry e3 = make_captured_request("GET /other HTTP/1.1\r\nHost: x\r\n\r\n", 404);
    CHECK_EQ(replay_one(rl.loop, e3, 44).actual_status, 404);
}

TEST(route, firewall_port_from_capture_replay_is_applied) {
    RouteConfig cfg;
    cfg.add_static("/", 0, 200);
    cfg.set_firewall_default_deny();
    cfg.add_firewall_allow_port(30000);

    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry allowed = make_captured_request("GET /any HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    allowed.peer_port = 30000;
    ReplayResult allowed_result = replay_one(rl.loop, allowed, 42);
    CHECK(allowed_result.replayed);
    CHECK_EQ(allowed_result.actual_status, 200);
    CHECK(allowed_result.status_match);

    CaptureEntry denied = make_captured_request("GET /any HTTP/1.1\r\nHost: x\r\n\r\n", 403);
    denied.peer_port = 30001;
    ReplayResult denied_result = replay_one(rl.loop, denied, 43);
    CHECK(denied_result.replayed);
    CHECK_EQ(denied_result.actual_status, 403);
    CHECK(denied_result.status_match);
}

TEST(route, replay_file_with_routing) {
    RouteConfig cfg;
    cfg.add_static("/health", 0, 200);
    cfg.add_static("/api", 0, 200);
    cfg.add_static("/", 0, 404);

    // Capture entries with expected statuses
    CaptureEntry entries[4];
    entries[0] = make_captured_request("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /api/data HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[2] = make_captured_request("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 404);
    entries[3] = make_captured_request("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 200);

    TempCapture tmp;
    REQUIRE(tmp.create(entries, 4));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    RoutedLoop rl;
    rl.setup(&cfg);

    ReplaySummary summary = replay_file(rl.loop, reader);
    CHECK_EQ(summary.total, 4u);
    CHECK_EQ(summary.replayed, 4u);
    CHECK_EQ(summary.matched, 4u);
    CHECK_EQ(summary.mismatched, 0u);

    reader.close();
    tmp.cleanup();
}

TEST(route, replay_one_route_action_matrix) {
    RouteConfig cfg;
    auto up_result = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(up_result.has_value());
    REQUIRE(cfg.add_static("/static", 'G', 204));
    REQUIRE(cfg.add_static("/post-only", 'P', 202));
    REQUIRE(cfg.add_proxy("/proxy", 'G', static_cast<u16>(up_result.value())));
    REQUIRE(cfg.add_jit_handler("/jit-status", 'G', &replay_matrix_status_207_handler));
    REQUIRE(cfg.add_jit_handler("/jit-forward", 'G', &replay_matrix_forward_0_handler));

    RoutedLoop rl;
    rl.setup(&cfg);

    struct MatrixCase {
        const char* name;
        const char* request;
        u16 expected_status;
        bool replayed;
        bool skipped;
        bool status_match;
        u16 actual_status;
    };

    const MatrixCase cases[] = {
        {"static status", "GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 204, true, false, true, 204},
        {"not found", "GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 404, true, false, true, 404},
        {"method default",
         "GET /post-only HTTP/1.1\r\nHost: x\r\n\r\n",
         404,
         true,
         false,
         true,
         404},
        {"method match",
         "POST /post-only HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
         202,
         true,
         false,
         true,
         202},
        {"static mismatch",
         "GET /static HTTP/1.1\r\nHost: x\r\n\r\n",
         201,
         true,
         false,
         false,
         204},
        {"proxy skipped", "GET /proxy/x HTTP/1.1\r\nHost: x\r\n\r\n", 502, false, true, false, 0},
        {"jit status", "GET /jit-status HTTP/1.1\r\nHost: x\r\n\r\n", 207, true, false, true, 207},
        {"jit forward skipped",
         "GET /jit-forward HTTP/1.1\r\nHost: x\r\n\r\n",
         502,
         false,
         true,
         false,
         0},
    };

    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const auto& tc = cases[i];
        CaptureEntry entry = make_captured_request(tc.request, tc.expected_status);
        ReplayResult result = replay_one(rl.loop, entry, static_cast<i32>(4200 + i));
        CHECK_MSG(result.replayed == tc.replayed, tc.name);
        CHECK_MSG(result.skipped == tc.skipped, tc.name);
        CHECK_MSG(result.status_match == tc.status_match, tc.name);
        CHECK_MSG(result.actual_status == tc.actual_status, tc.name);
    }
}

TEST(route, replay_file_route_action_matrix_summary) {
    RouteConfig cfg;
    auto up_result = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(up_result.has_value());
    REQUIRE(cfg.add_static("/static", 'G', 204));
    REQUIRE(cfg.add_static("/post-only", 'P', 202));
    REQUIRE(cfg.add_proxy("/proxy", 'G', static_cast<u16>(up_result.value())));
    REQUIRE(cfg.add_jit_handler("/jit-status", 'G', &replay_matrix_status_207_handler));
    REQUIRE(cfg.add_jit_handler("/jit-forward", 'G', &replay_matrix_forward_0_handler));

    CaptureEntry entries[] = {
        make_captured_request("GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 204),
        make_captured_request("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 404),
        make_captured_request("GET /post-only HTTP/1.1\r\nHost: x\r\n\r\n", 404),
        make_captured_request("POST /post-only HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
                              202),
        make_captured_request("GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 201),
        make_captured_request("GET /proxy/x HTTP/1.1\r\nHost: x\r\n\r\n", 502),
        make_captured_request("GET /jit-status HTTP/1.1\r\nHost: x\r\n\r\n", 207),
        make_captured_request("GET /jit-forward HTTP/1.1\r\nHost: x\r\n\r\n", 502),
    };

    TempCapture tmp;
    REQUIRE(tmp.create(entries, sizeof(entries) / sizeof(entries[0])));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    RoutedLoop rl;
    rl.setup(&cfg);

    ReplaySummary summary = replay_file(rl.loop, reader);
    CHECK_EQ(summary.total, 8u);
    CHECK_EQ(summary.replayed, 6u);
    CHECK_EQ(summary.matched, 5u);
    CHECK_EQ(summary.mismatched, 1u);
    CHECK_EQ(summary.skipped, 2u);
    CHECK_EQ(summary.failed, 0u);

    reader.close();
    tmp.cleanup();
}

// Detect config change: replay captured traffic against a DIFFERENT config
TEST(route, detect_config_regression) {
    // Old config: /api → 200, /admin → 403, / → 404
    // Captured traffic expects these statuses.
    CaptureEntry entries[3];
    entries[0] = make_captured_request("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", 403);
    entries[2] = make_captured_request("GET /other HTTP/1.1\r\nHost: x\r\n\r\n", 404);

    TempCapture tmp;
    REQUIRE(tmp.create(entries, 3));

    // New config: /admin is now 200 (permission change), /api removed
    RouteConfig new_cfg;
    new_cfg.add_static("/admin", 0, 200);  // changed from 403 to 200
    new_cfg.add_static("/", 0, 404);       // catch-all

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);

    RoutedLoop rl;
    rl.setup(&new_cfg);

    ReplaySummary summary = replay_file(rl.loop, reader);
    CHECK_EQ(summary.total, 3u);
    CHECK_EQ(summary.replayed, 3u);

    // /api/users: was 200, new config / → 404 → mismatch
    // /admin: was 403, now 200 → mismatch
    // /other: was 404, / → 404 → match
    CHECK_EQ(summary.matched, 1u);     // /other (404 → 404)
    CHECK_EQ(summary.mismatched, 2u);  // /api/users + /admin changed

    reader.close();
    tmp.cleanup();
}

// ============================================================
// Coverage gap tests
// ============================================================

// G1. Connection slot exhaustion → replay_one returns replayed=false
TEST(replay_gap, conn_slot_exhaustion) {
    SmallLoop loop;
    loop.setup();

    // Fill all 64 connection slots
    for (u32 i = 0; i < SmallLoop::kMaxConns; i++) {
        loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, static_cast<i32>(100 + i)));
    }
    CHECK_EQ(loop.free_top, 0u);

    // replay_one should fail gracefully
    CaptureEntry entry = make_captured_request("GET / HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    ReplayResult result = replay_one(loop, entry, 999);
    CHECK(!result.replayed);

    // replay_file should count it as failed
    CaptureEntry entries[2];
    entries[0] = make_captured_request("GET /a HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /b HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 2));
    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);
    ReplaySummary summary = replay_file(loop, reader);
    CHECK_EQ(summary.failed, 2u);
    reader.close();
    tmp.cleanup();
}

// G2. recv_buf 4KB truncation: entry with headers > SmallLoop::kBufSize
TEST(replay_gap, large_header_truncated_by_smallloop) {
    SmallLoop loop;
    loop.setup();

    // Create an entry with ~5KB headers (exceeds SmallLoop's 4096 buf)
    CaptureEntry entry{};
    entry.resp_status = 200;
    entry.method = static_cast<u8>(LogHttpMethod::Get);
    // Build a valid-ish request with lots of padding headers
    const char prefix[] = "GET / HTTP/1.1\r\nHost: x\r\n";
    u32 pos = 0;
    for (u32 i = 0; i < sizeof(prefix) - 1; i++)
        entry.raw_headers[pos++] = static_cast<u8>(prefix[i]);
    // Pad with headers until ~5000 bytes
    while (pos < 5000) {
        const char hdr[] = "X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
        for (u32 i = 0; i < sizeof(hdr) - 1 && pos < 5000; i++)
            entry.raw_headers[pos++] = static_cast<u8>(hdr[i]);
    }
    entry.raw_headers[pos++] = '\r';
    entry.raw_headers[pos++] = '\n';
    entry.raw_header_len = static_cast<u16>(pos);

    // replay_one should not crash — headers get truncated to 4KB
    ReplayResult result = replay_one(loop, entry, 42);
    CHECK(result.replayed);
    // Status might not match exactly due to truncation, but no crash
    CHECK_EQ(result.actual_status, 200);
}

// G3. format_static_response wire format: verify Content-Length matches body
TEST(replay_gap, format_static_response_wire_format) {
    // Test various status codes and verify the response is well-formed
    struct TestCase {
        u16 code;
        const char* reason;
        u32 reason_len;
        u32 body_len;  // 0 for no-body status codes (204, 304)
    };
    TestCase cases[] = {
        {200, "OK", 2, 2},
        {404, "Not Found", 9, 9},
        {500, "Internal Server Error", 21, 21},
        {204, "No Content", 10, 0},  // no body per HTTP spec
        {301, "Moved Permanently", 17, 17},
    };

    for (auto& tc : cases) {
        Connection conn;
        conn.reset();
        u8 send_storage[4096];
        conn.send_buf.bind(send_storage, 4096);
        format_static_response(conn, tc.code, true);

        // Parse the response to find Content-Length
        const u8* data = conn.send_buf.data();
        u32 len = conn.send_buf.len();

        // Find "Content-Length: " and parse the number
        u32 cl_val = 0;
        bool found_cl = false;
        for (u32 i = 0; i + 16 < len; i++) {
            if (data[i] == 'C' && data[i + 1] == 'o' && data[i + 8] == 'L') {
                // "Content-Length: "
                u32 j = i + 16;
                while (j < len && data[j] >= '0' && data[j] <= '9') {
                    cl_val = cl_val * 10 + (data[j] - '0');
                    j++;
                }
                found_cl = true;
                break;
            }
        }
        CHECK(found_cl);
        CHECK_EQ(cl_val, tc.body_len);

        // Find body after \r\n\r\n
        u32 body_start = 0;
        for (u32 i = 0; i + 3 < len; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' &&
                data[i + 3] == '\n') {
                body_start = i + 4;
                break;
            }
        }
        CHECK_GT(body_start, 0u);
        u32 body_len = len - body_start;
        CHECK_EQ(body_len, tc.body_len);

        // Verify status line contains the code
        CHECK_EQ(data[9], static_cast<u8>('0' + (tc.code / 100) % 10));
        CHECK_EQ(data[10], static_cast<u8>('0' + (tc.code / 10) % 10));
        CHECK_EQ(data[11], static_cast<u8>('0' + tc.code % 10));

        // Unbind to prevent Buffer destructor trap
        conn.send_buf.bind(nullptr, 0);
    }
}

// G4. Proxy route path is selected (manual setup).
TEST(replay_gap, proxy_route_enters_proxy_path) {
    RouteConfig cfg;
    auto up_result = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(up_result.has_value());
    REQUIRE(cfg.add_proxy("/api", 0, static_cast<u16>(up_result.value())));

    RoutedLoop rl;
    rl.setup(&cfg);

    // Accept and inject request manually (don't use replay_one — need
    // to check intermediate state before proxy completes)
    rl.loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = rl.loop.find_fd(42);
    REQUIRE(conn != nullptr);

    i32 fds[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    ScopedFakeSocket fake_socket(fds[0]);

    conn->recv_buf.reset();
    const char req[] = "GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    rl.loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = rl.loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) rl.loop.dispatch(events[i]);

    CHECK_EQ(conn->upstream_name[0], 'b');  // "backend"
    CHECK_EQ(conn->state, ConnState::Proxying);
    auto* connect_op = rl.loop.backend.last_op(MockOp::Connect);
    REQUIRE(connect_op != nullptr);
    CHECK_EQ(connect_op->conn_id, conn->id);

    if (conn->upstream_fd >= 0) {
        close(conn->upstream_fd);
        conn->upstream_fd = -1;
    }
    close(fds[1]);
    rl.loop.close_conn(*conn);
}

TEST(replay_gap, replay_one_proxy_route_not_replayed) {
    RouteConfig cfg;
    auto up_result = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(up_result.has_value());
    REQUIRE(cfg.add_proxy("/api", 0, static_cast<u16>(up_result.value())));

    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entry = make_captured_request("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(!result.replayed);
    CHECK(result.skipped);
    CHECK_EQ(result.expected_status, 200);
    CHECK_EQ(result.actual_status, 0);
    CHECK(!result.status_match);

    RoutedLoop harness_loop;
    harness_loop.setup(&cfg);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);
    spec.environment_capabilities = spec.required_capabilities;
    const auto adapted = harness::drive_replay_one(harness_loop.loop, entry, 43, spec);
    CHECK_EQ(adapted.harness.outcome, harness::Outcome::Unsupported);
    CHECK_EQ(adapted.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK(adapted.replay.skipped);
}

TEST(replay_gap, replay_file_proxy_route_counted_as_skipped) {
    RouteConfig cfg;
    auto up_result = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(up_result.has_value());
    REQUIRE(cfg.add_proxy("/api", 0, static_cast<u16>(up_result.value())));
    REQUIRE(cfg.add_static("/health", 0, 200));

    RoutedLoop rl;
    rl.setup(&cfg);

    CaptureEntry entries[2];
    entries[0] = make_captured_request("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entries[1] = make_captured_request("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 2));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);
    ReplaySummary summary = replay_file(rl.loop, reader);
    CHECK_EQ(summary.total, 2u);
    CHECK_EQ(summary.replayed, 1u);
    CHECK_EQ(summary.matched, 1u);
    CHECK_EQ(summary.skipped, 1u);
    CHECK_EQ(summary.failed, 0u);
    reader.close();
    tmp.cleanup();
}

// G5. Query string in path: /health?foo=bar should match /health prefix
TEST(replay_gap, query_string_in_path) {
    RouteConfig cfg;
    cfg.add_static("/health", 0, 200);
    cfg.add_static("/", 0, 404);

    RoutedLoop rl;
    rl.setup(&cfg);

    // Path with query string — depends on what HTTP parser puts in req_path
    // The parser stores the full path including query string in req.path
    CaptureEntry entry =
        make_captured_request("GET /health?check=1 HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(result.replayed);
    // /health?check=1 should prefix-match /health
    CHECK_EQ(result.actual_status, 200);
}

// G6. ReplayReader: next after close, double close
TEST(replay_gap, reader_next_after_close) {
    CaptureEntry entries[1];
    entries[0] = make_captured_request("GET / HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    TempCapture tmp;
    REQUIRE(tmp.create(entries, 1));

    ReplayReader reader;
    REQUIRE(reader.open(tmp.path) == 0);
    reader.close();

    // next after close should return -1
    CaptureEntry out{};
    CHECK_EQ(reader.next(out), -1);

    // double close should not crash
    reader.close();

    tmp.cleanup();
}

// G7. CaptureEntry::method enum vs raw bytes: raw headers win for routing
TEST(replay_gap, method_enum_vs_raw_bytes) {
    RouteConfig cfg;
    cfg.add_static("/test", 'G', 200);  // GET only
    cfg.add_static("/test", 'P', 403);  // POST → 403

    RoutedLoop rl;
    rl.setup(&cfg);

    // Entry says method=Post (enum), but raw_headers say "GET ..."
    // Route matcher should use raw bytes, not enum
    CaptureEntry entry = make_captured_request("GET /test HTTP/1.1\r\nHost: x\r\n\r\n", 200);
    entry.method = static_cast<u8>(LogHttpMethod::Post);  // lie

    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.actual_status, 200);  // matched on raw 'G', not enum Post
}

// G8. Malformed request → req_path defaults to "/" → hits catch-all
TEST(replay_gap, malformed_request_hits_catchall) {
    RouteConfig cfg;
    cfg.add_static("/", 0, 404);

    RoutedLoop rl;
    rl.setup(&cfg);

    // Completely garbage headers — parser will fail, req_path stays "/"
    CaptureEntry entry = make_captured_request("GARBAGE\r\n\r\n", 404);
    ReplayResult result = replay_one(rl.loop, entry, 42);
    CHECK(result.replayed);
    CHECK_EQ(result.actual_status, 404);  // "/" catch-all
}

// G9. Upstream name truncation at Connection::kMaxUpstreamNameLen boundary
TEST(replay_gap, upstream_name_truncation_boundary) {
    // Create upstream with name exactly 23 chars (fills 24-byte field with null)
    RouteConfig cfg;
    char long_name[32];
    for (u32 i = 0; i < 23; i++) long_name[i] = static_cast<char>('a' + i % 26);
    long_name[23] = '\0';

    auto up = cfg.add_upstream(long_name, 0x7F000001, 9999);
    REQUIRE(up.has_value());
    cfg.add_proxy("/up", 0, static_cast<u16>(up.value()));

    RoutedLoop rl;
    rl.setup(&cfg);

    rl.loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = rl.loop.find_fd(42);
    REQUIRE(conn != nullptr);

    conn->recv_buf.reset();
    const char req[] = "GET /up/test HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    rl.loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = rl.loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) rl.loop.dispatch(events[i]);

    // Name should be truncated to kMaxUpstreamNameLen-1 = 23 chars + null
    CHECK_EQ(conn->upstream_name[0], 'a');
    CHECK_EQ(conn->upstream_name[22], static_cast<char>('a' + 22 % 26));
    CHECK_EQ(conn->upstream_name[23], '\0');

    // Clean up real socket
    if (conn->upstream_fd >= 0) {
        close(conn->upstream_fd);
        conn->upstream_fd = -1;
    }
    rl.loop.inject_and_dispatch(make_ev(conn->id, IoEventType::Recv, 0));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
