#include "fault_injection.h"
#include "rut/runtime/access_log_live_producer.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/shard.h"
#include "test.h"
#include <atomic>
#include <string>
#include <thread>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

using namespace rut;
using rut::test_fault::IoFaultConfig;
using rut::test_fault::kMatchAllIoFds;
using rut::test_fault::ScopedHeldPositiveWrite;
using rut::test_fault::ScopedIoFault;

namespace {

struct Pipe {
    i32 read_fd = -1;
    i32 write_fd = -1;

    ~Pipe() {
        if (read_fd >= 0) close(read_fd);
        if (write_fd >= 0) close(write_fd);
    }

    bool open_nonblocking() {
        i32 fds[2];
        if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return false;
        read_fd = fds[0];
        write_fd = fds[1];
        return true;
    }

    SourceAccessLogFd take_writer() {
        const i32 fd = write_fd;
        write_fd = -1;
        return SourceAccessLogFd(fd);
    }
};

AccessLogEntry entry_with_size(u32 size) {
    AccessLogEntry entry{};
    entry.req_size = size;
    entry.resp_size = size + 1000u;
    return entry;
}

std::string read_available(i32 fd) {
    std::string result;
    char bytes[128];
    for (;;) {
        const ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count > 0) {
            result.append(bytes, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    return result;
}

}  // namespace

TEST(access_log_live_producer, successful_publish_notifies_and_writer_drains_exact_line) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    SourceLiveAccessLogProducer producer;
    REQUIRE(producer.init(&ring, &session, 0u));

    const auto result = producer.publish(entry_with_size(102u));
    REQUIRE(result.status == SourceLiveAccessLogPublishStatus::Published);
    REQUIRE(result.ticket.valid);
    CHECK_EQ(result.ticket.end_position, 1u);

    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(ring.acknowledged(result.ticket));
    CHECK_EQ(read_available(output.read_fd), "102\n");
}

TEST(access_log_live_producer, preexisting_first_fatal_prevents_enqueue) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    SourceLiveAccessLogProducer producer;
    REQUIRE(producer.init(&ring, &session, 0u));
    session.report_producer_fatal(SourceLiveAccessLogFatalKind::Protocol, 0u, EPROTO);

    const auto result = producer.publish(entry_with_size(102u));
    CHECK(result.status == SourceLiveAccessLogPublishStatus::Fatal);
    CHECK_FALSE(result.ticket.valid);
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 0u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    const auto fatal = session.fatal();
    CHECK(fatal.kind == SourceLiveAccessLogFatalKind::Protocol);
    CHECK_EQ(fatal.ring_index, 0u);
    CHECK_EQ(fatal.system_error, EPROTO);

    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(read_available(output.read_fd).empty());
}

TEST(access_log_live_producer, invalid_binding_reports_protocol_without_enqueue) {
    LiveAccessLogRing owned;
    LiveAccessLogRing foreign;
    owned.init();
    foreign.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&owned};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    SourceLiveAccessLogProducer producer;

    CHECK_FALSE(producer.init(&foreign, &session, 0u));
    CHECK_FALSE(producer.initialized());
    CHECK_EQ(owned.published_pos.load(std::memory_order_relaxed), 0u);
    CHECK_EQ(foreign.published_pos.load(std::memory_order_relaxed), 0u);
    const auto fatal = session.fatal();
    CHECK(fatal.kind == SourceLiveAccessLogFatalKind::Protocol);
    CHECK_EQ(fatal.ring_index, 0u);
    CHECK_EQ(fatal.system_error, EINVAL);

    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(read_available(output.read_fd).empty());
}

TEST(access_log_live_producer, notify_fatal_keeps_enqueued_record_for_finish_drain) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    SourceLiveAccessLogProducer producer;
    REQUIRE(producer.init(&ring, &session, 0u));

    SourceLiveAccessLogPublishResult result;
    {
        IoFaultConfig config;
        config.fd = kMatchAllIoFds;
        config.write_fatals = 1;
        ScopedIoFault fault(config);
        result = producer.publish(entry_with_size(102u));
    }
    REQUIRE(result.status == SourceLiveAccessLogPublishStatus::Fatal);
    REQUIRE(result.ticket.valid);
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 1u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    const auto fatal = session.fatal();
    CHECK(fatal.kind == SourceLiveAccessLogFatalKind::Notify);
    CHECK_EQ(fatal.ring_index, 0u);
    CHECK_EQ(fatal.system_error, EPIPE);

    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(ring.acknowledged(result.ticket));
    CHECK_EQ(read_available(output.read_fd), "102\n");
}

TEST(access_log_live_lease, shard_retains_pre_attach_borrow_through_shutdown_until_finish) {
    Shard<EpollEventLoop> shard;
    REQUIRE(shard.init(0u, -1).has_value());
    auto allocated = shard.init_live_access_log_ring();
    REQUIRE(allocated.has_value());
    LiveAccessLogRing* ring = allocated.value();
    const SourceLiveAccessLogRingBinding binding = shard.live_access_log_binding();
    REQUIRE_EQ(binding.ring, ring);
    REQUIRE_EQ(binding.lease, &shard.live_log_lease);

    Pipe output;
    REQUIRE(output.open_nonblocking());
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), &binding, 1u));
    REQUIRE_EQ(shard.live_log_lease.load(std::memory_order_acquire), &session);
    CHECK(shard.loop->live_access_log == nullptr);
    auto held_release = shard.release_live_access_log();
    REQUIRE_FALSE(held_release.has_value());
    CHECK(held_release.error() == ShardLiveAccessLogError::LeaseHeld);

    shard.shutdown();
    CHECK(shard.loop == nullptr);
    CHECK_EQ(shard.live_log_ring, ring);
    CHECK_EQ(shard.live_log_lease.load(std::memory_order_acquire), &session);

    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(shard.live_log_lease.load(std::memory_order_acquire) == nullptr);
    REQUIRE(shard.release_live_access_log().has_value());
    CHECK(shard.live_log_ring == nullptr);
    CHECK(read_available(output.read_fd).empty());
}

TEST(access_log_live_lease, finishing_writer_holds_lease_until_blocked_write_and_join_complete) {
    Shard<EpollEventLoop> shard;
    REQUIRE(shard.init(0u, -1).has_value());
    auto allocated = shard.init_live_access_log_ring();
    REQUIRE(allocated.has_value());
    LiveAccessLogRing* ring = allocated.value();
    const SourceLiveAccessLogRingBinding binding = shard.live_access_log_binding();

    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 output_fd = output.write_fd;
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), &binding, 1u));
    REQUIRE(shard.attach_live_access_log(&session, 0u).has_value());
    REQUIRE_EQ(shard.live_log_producer.lease(), &shard.live_log_lease);
    ScopedHeldPositiveWrite held(output_fd, 1u);
    REQUIRE(held.owns_state());

    const auto published = shard.live_log_producer.publish(entry_with_size(102u));
    REQUIRE(published.status == SourceLiveAccessLogPublishStatus::Published);
    REQUIRE(published.ticket.valid);
    REQUIRE(held.wait_until_held());
    CHECK_EQ(read_available(output.read_fd), "1");
    CHECK_FALSE(ring->acknowledged(published.ticket));

    std::atomic<bool> finish_returned{false};
    SourceLiveAccessLogFinishResult finish_result{};
    std::thread finisher([&] {
        finish_result = session.finish();
        finish_returned.store(true, std::memory_order_release);
    });
    for (u32 attempt = 0u; attempt < 100000u && session.running(); attempt++) sched_yield();
    REQUIRE_FALSE(session.running());
    CHECK_FALSE(finish_returned.load(std::memory_order_acquire));
    REQUIRE_EQ(shard.live_log_lease.load(std::memory_order_acquire), &session);
    auto finishing_release = shard.release_live_access_log();
    REQUIRE_FALSE(finishing_release.has_value());
    CHECK(finishing_release.error() == ShardLiveAccessLogError::LeaseHeld);

    shard.shutdown();
    CHECK(shard.loop == nullptr);
    CHECK_EQ(shard.live_log_ring, ring);
    CHECK_EQ(shard.live_log_lease.load(std::memory_order_acquire), &session);
    auto post_shutdown_release = shard.release_live_access_log();
    REQUIRE_FALSE(post_shutdown_release.has_value());
    CHECK(post_shutdown_release.error() == ShardLiveAccessLogError::LeaseHeld);

    REQUIRE(held.release());
    REQUIRE(held.wait_until_consumed());
    finisher.join();
    REQUIRE(finish_returned.load(std::memory_order_acquire));
    REQUIRE(finish_result.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(shard.live_log_lease.load(std::memory_order_acquire) == nullptr);
    CHECK(ring->acknowledged(published.ticket));
    CHECK_EQ(read_available(output.read_fd), "02\n");
    REQUIRE(shard.release_live_access_log().has_value());
    CHECK(shard.live_log_ring == nullptr);
}

TEST(access_log_live_lease, raw_attach_rejects_and_conflicting_start_unwinds_exact_owner) {
    {
        Shard<EpollEventLoop> shard;
        REQUIRE(shard.init(0u, -1).has_value());
        auto allocated = shard.init_live_access_log_ring();
        REQUIRE(allocated.has_value());
        LiveAccessLogRing* raw_rings[] = {allocated.value()};
        Pipe output;
        REQUIRE(output.open_nonblocking());
        SourceLiveAccessLogSession raw_session;
        REQUIRE(raw_session.start(output.take_writer(), raw_rings, 1u));
        CHECK(shard.live_log_lease.load(std::memory_order_acquire) == nullptr);
        auto attach = shard.attach_live_access_log(&raw_session, 0u);
        REQUIRE_FALSE(attach.has_value());
        CHECK(attach.error() == ShardLiveAccessLogError::SessionBinding);
        CHECK(shard.loop->live_access_log == nullptr);
        CHECK_FALSE(shard.live_log_producer.initialized());
        CHECK(shard.live_log_lease.load(std::memory_order_acquire) == nullptr);
        const auto finished = raw_session.finish();
        REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
        CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::Protocol);
        REQUIRE(shard.release_live_access_log().has_value());
        shard.shutdown();
    }

    LiveAccessLogRing free_ring;
    LiveAccessLogRing occupied_ring;
    free_ring.init();
    occupied_ring.init();
    SourceLiveAccessLogLeaseSlot free_lease{nullptr};
    SourceLiveAccessLogLeaseSlot occupied_lease{nullptr};
    const SourceLiveAccessLogRingBinding occupied_binding{&occupied_ring, &occupied_lease};
    const SourceLiveAccessLogRingBinding candidate_bindings[] = {
        {&free_ring, &free_lease},
        {&occupied_ring, &occupied_lease},
    };
    Pipe owner_output;
    Pipe candidate_output;
    REQUIRE(owner_output.open_nonblocking());
    REQUIRE(candidate_output.open_nonblocking());
    SourceLiveAccessLogSession owner;
    SourceLiveAccessLogSession candidate;
    REQUIRE(owner.start(owner_output.take_writer(), &occupied_binding, 1u));
    CHECK_EQ(occupied_lease.load(std::memory_order_acquire), &owner);
    CHECK(free_lease.load(std::memory_order_acquire) == nullptr);

    SourceAccessLogFd retained_output = candidate_output.take_writer();
    const i32 retained_fd = retained_output.get();
    auto conflict =
        candidate.start(static_cast<SourceAccessLogFd&&>(retained_output), candidate_bindings, 2u);
    REQUIRE_FALSE(conflict.has_value());
    CHECK(conflict.error().kind == SourceLiveAccessLogStartErrorKind::LeaseConflict);
    CHECK_EQ(conflict.error().ring_index, 1u);
    CHECK_EQ(retained_output.get(), retained_fd);
    CHECK(free_lease.load(std::memory_order_acquire) == nullptr);
    CHECK_EQ(occupied_lease.load(std::memory_order_acquire), &owner);

    REQUIRE(owner.finish().status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(occupied_lease.load(std::memory_order_acquire) == nullptr);
    REQUIRE(
        candidate.start(static_cast<SourceAccessLogFd&&>(retained_output), candidate_bindings, 2u));
    CHECK_EQ(free_lease.load(std::memory_order_acquire), &candidate);
    CHECK_EQ(occupied_lease.load(std::memory_order_acquire), &candidate);
    REQUIRE(candidate.finish().status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(free_lease.load(std::memory_order_acquire) == nullptr);
    CHECK(occupied_lease.load(std::memory_order_acquire) == nullptr);
}

int main() {
    return test::run_all();
}
