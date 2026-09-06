#include "fault_injection.h"
#include "rut/runtime/access_log_live_writer.h"
#include "test.h"
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

using namespace rut;
using rut::test_fault::HeldPositiveWriteError;
using rut::test_fault::IoFaultConfig;
using rut::test_fault::kMatchAllIoFds;
using rut::test_fault::ScopedHeldPositiveWrite;
using rut::test_fault::ScopedIoFault;

namespace {

AccessLogEntry request_size_entry(u32 request_size) {
    AccessLogEntry entry{};
    entry.req_size = request_size;
    return entry;
}

struct Pipe {
    i32 read_fd = -1;
    i32 write_fd = -1;

    Pipe() = default;
    Pipe(const Pipe&) = delete;
    Pipe& operator=(const Pipe&) = delete;
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

    void close_reader() {
        if (read_fd < 0) return;
        const i32 fd = read_fd;
        read_fd = -1;
        close(fd);
    }
};

std::string read_to_eagain_or_eof(i32 fd) {
    std::string result;
    char bytes[4096];
    for (;;) {
        const ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count > 0) {
            result.append(bytes, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        break;
    }
    return result;
}

bool read_exact(i32 fd, u64 length) {
    char bytes[4096];
    u64 read_count = 0u;
    while (read_count < length) {
        const u64 remaining = length - read_count;
        const size_t wanted =
            remaining < sizeof(bytes) ? static_cast<size_t>(remaining) : sizeof(bytes);
        const ssize_t result = read(fd, bytes, wanted);
        if (result > 0) {
            for (ssize_t i = 0; i < result; i++) {
                if (bytes[i] != 'x') return false;
            }
            read_count += static_cast<u64>(result);
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            sched_yield();
            continue;
        }
        return false;
    }
    return true;
}

u64 fill_pipe(i32 fd) {
    char bytes[4096];
    for (char& byte : bytes) byte = 'x';
    u64 total = 0u;
    for (;;) {
        const ssize_t result = write(fd, bytes, sizeof(bytes));
        if (result > 0) {
            total += static_cast<u64>(result);
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return total;
        return 0u;
    }
}

i32 open_fd_count() {
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr) return -1;
    i32 count = 0;
    while (dirent* entry = readdir(dir)) {
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
            continue;
        count++;
    }
    closedir(dir);
    return count;
}

std::vector<u32> parse_lines(const std::string& bytes) {
    std::vector<u32> values;
    u32 value = 0u;
    bool have_digit = false;
    for (char byte : bytes) {
        if (byte >= '0' && byte <= '9') {
            have_digit = true;
            value = value * 10u + static_cast<u32>(byte - '0');
            continue;
        }
        if (byte != '\n' || !have_digit) return {};
        values.push_back(value);
        value = 0u;
        have_digit = false;
    }
    if (have_digit) return {};
    return values;
}

u32 index_of(const std::vector<u32>& values, u32 needle) {
    for (u32 i = 0; i < values.size(); i++) {
        if (values[i] == needle) return i;
    }
    return static_cast<u32>(values.size());
}

u32 count_of(const std::vector<u32>& values, u32 needle) {
    u32 count = 0u;
    for (u32 value : values) {
        if (value == needle) count++;
    }
    return count;
}

bool wait_for_committed(const LiveAccessLogRing& ring, u64 position) {
    for (u32 attempt = 0u; attempt < 1'000'000u; attempt++) {
        if (ring.committed_pos.load(std::memory_order_acquire) == position) return true;
        sched_yield();
    }
    return false;
}

}  // namespace

TEST(access_log_live_writer, held_positive_write_seam_is_fd_specific_owned_and_consumed) {
    Pipe target;
    Pipe other;
    REQUIRE(target.open_nonblocking());
    REQUIRE(other.open_nonblocking());
    ScopedHeldPositiveWrite held(target.write_fd, 1u);
    REQUIRE(held.owns_state());
    CHECK_FALSE(held.failed_closed());
    CHECK(held.error() == HeldPositiveWriteError::None);
    ScopedHeldPositiveWrite duplicate(target.write_fd, 1u);
    CHECK_FALSE(duplicate.owns_state());
    CHECK(duplicate.failed_closed());
    CHECK(duplicate.error() == HeldPositiveWriteError::AlreadyOwned);

    REQUIRE_EQ(write(other.write_fd, "zz", 2u), 2);
    CHECK_EQ(read_to_eagain_or_eof(other.read_fd), "zz");
    CHECK_FALSE(held.prefix_consumed());
    CHECK_FALSE(held.held());

    REQUIRE_EQ(write(target.write_fd, "abcd", 4u), 1);
    CHECK(held.prefix_consumed());
    CHECK_EQ(read_to_eagain_or_eof(target.read_fd), "a");
    std::atomic<ssize_t> suffix_result{-2};
    std::thread suffix(
        [&] { suffix_result.store(write(target.write_fd, "bcd", 3u), std::memory_order_release); });
    const bool observed_hold = held.wait_until_held();
    CHECK(observed_hold);
    if (!observed_hold) {
        suffix.join();
        return;
    }
    CHECK(held.held());
    CHECK_FALSE(held.released());
    CHECK_FALSE(held.consumed());
    CHECK_EQ(read_to_eagain_or_eof(target.read_fd), "");
    const bool released = held.release();
    CHECK(released);
    CHECK(held.released());
    const bool consumed = held.wait_until_consumed();
    CHECK(consumed);
    suffix.join();
    if (!released || !consumed) return;
    CHECK_EQ(suffix_result.load(std::memory_order_acquire), 3);
    CHECK(held.consumed());
    CHECK_FALSE(held.held());
    CHECK_EQ(read_to_eagain_or_eof(target.read_fd), "bcd");
    CHECK_FALSE(held.failed_closed());
}

TEST(access_log_live_writer, notified_records_are_exact_and_acknowledged_only_by_finish) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));

    const u32 sizes[] = {0u, 102u, 4294967295u};
    LiveAccessLogTicket tickets[3];
    for (u32 i = 0; i < 3u; i++) {
        const auto published = ring.try_publish(request_size_entry(sizes[i]));
        REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
        tickets[i] = published.ticket;
        const auto notified = session.notify(0u);
        CHECK(notified == SourceLiveAccessLogNotifyStatus::Notified ||
              notified == SourceLiveAccessLogNotifyStatus::Coalesced);
    }

    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::None);
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "0\n102\n4294967295\n");
    for (const LiveAccessLogTicket ticket : tickets) CHECK(ring.acknowledged(ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 3u);
}

TEST(access_log_live_writer, short_eintr_and_eagain_retry_one_record_exactly) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));

    IoFaultConfig config;
    config.fd = output_fd;
    config.write_eagains = 1;
    config.write_eintrs = 1;
    config.write_short_len = 1u;
    config.write_shorts = 1;
    ScopedIoFault fault(config);
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(ring.acknowledged(published.ticket));
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "102\n");
}

TEST(access_log_live_writer, positive_short_prefix_is_visible_and_unacked_while_suffix_is_held) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    ScopedHeldPositiveWrite held(output_fd, 1u);
    REQUIRE(held.owns_state());

    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    REQUIRE(held.wait_until_held());
    CHECK(held.prefix_consumed());
    CHECK(held.held());
    CHECK_FALSE(held.consumed());
    CHECK_FALSE(held.failed_closed());
    const std::string prefix = read_to_eagain_or_eof(output.read_fd);
    CHECK_EQ(prefix, "1");
    CHECK_FALSE(ring.acknowledged(published.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);

    REQUIRE(held.release());
    REQUIRE(held.wait_until_consumed());
    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(held.consumed());
    CHECK_FALSE(held.failed_closed());
    CHECK_EQ(prefix + read_to_eagain_or_eof(output.read_fd), "102\n");
    CHECK(ring.acknowledged(published.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 1u);
}

TEST(access_log_live_writer, actually_full_pipe_holds_ack_until_output_is_released) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const u64 filler_length = fill_pipe(output.write_fd);
    REQUIRE_GT(filler_length, 0u);
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));

    IoFaultConfig config;
    config.fd = output_fd;
    config.write_eintrs = 1;
    ScopedIoFault fault(config);
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    while (fault.remaining_write_eintrs() != 0) sched_yield();
    CHECK_FALSE(ring.acknowledged(published.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);

    REQUIRE(read_exact(output.read_fd, filler_length));
    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(ring.acknowledged(published.ticket));
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "102\n");
}

TEST(access_log_live_writer, write_fatal_keeps_failed_and_later_records_uncommitted) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    const auto first = ring.try_publish(request_size_entry(102u));
    const auto second = ring.try_publish(request_size_entry(777u));
    REQUIRE(first.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(second.status == LiveAccessLogPublishStatus::Published);

    IoFaultConfig config;
    config.fd = output_fd;
    config.write_fatals = 1;
    ScopedIoFault fault(config);
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::Write);
    CHECK_EQ(finished.fatal.ring_index, 0u);
    CHECK_EQ(finished.fatal.system_error, EPIPE);
    CHECK_EQ(session.fatal().system_error, EPIPE);
    CHECK_FALSE(ring.acknowledged(first.ticket));
    CHECK_FALSE(ring.acknowledged(second.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK(read_to_eagain_or_eof(output.read_fd).empty());
}

TEST(access_log_live_writer, poll_fatal_after_kernel_write_eagain_is_exact) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const u64 filler_length = fill_pipe(output.write_fd);
    REQUIRE_GT(filler_length, 0u);
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);

    IoFaultConfig config;
    config.fd = output_fd;
    config.poll_fatals = 1;
    ScopedIoFault fault(config);
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::Poll);
    CHECK_EQ(finished.fatal.ring_index, 0u);
    CHECK_EQ(finished.fatal.system_error, EINVAL);
    CHECK_FALSE(ring.acknowledged(published.ticket));
    REQUIRE(read_exact(output.read_fd, filler_length));
    CHECK(read_to_eagain_or_eof(output.read_fd).empty());
}

TEST(access_log_live_writer, active_wake_drains_later_record_after_notify_eagain) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    ScopedHeldPositiveWrite held(output_fd, 1u);
    REQUIRE(held.owns_state());

    const auto first = ring.try_publish(request_size_entry(1u));
    REQUIRE(first.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    REQUIRE(held.wait_until_held());
    CHECK(held.prefix_consumed());
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "1");
    CHECK_FALSE(ring.acknowledged(first.ticket));

    const auto second = ring.try_publish(request_size_entry(102u));
    REQUIRE(second.status == LiveAccessLogPublishStatus::Published);
    {
        IoFaultConfig config;
        config.fd = kMatchAllIoFds;
        config.write_eagains = 1;
        ScopedIoFault fault(config);
        CHECK(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Coalesced);
        CHECK_EQ(fault.remaining_write_eagains(), 0);
    }
    CHECK(session.fatal().kind == SourceLiveAccessLogFatalKind::None);
    CHECK_FALSE(ring.acknowledged(second.ticket));
    REQUIRE(held.release());
    REQUIRE(held.wait_until_consumed());
    REQUIRE(wait_for_committed(ring, 2u));
    CHECK(ring.acknowledged(first.ticket));
    CHECK(ring.acknowledged(second.ticket));
    CHECK(session.fatal().kind == SourceLiveAccessLogFatalKind::None);
    CHECK_EQ(std::string("1") + read_to_eagain_or_eof(output.read_fd), "1\n102\n");

    const auto finished = session.finish();
    CHECK(finished.status == SourceLiveAccessLogFinishStatus::Success);
}

TEST(access_log_live_writer, notify_eintr_retries_and_live_writes_before_finish) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    {
        IoFaultConfig config;
        config.fd = kMatchAllIoFds;
        config.write_eintrs = 1;
        ScopedIoFault fault(config);
        CHECK(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
        CHECK_EQ(fault.remaining_write_eintrs(), 0);
    }
    REQUIRE(wait_for_committed(ring, 1u));
    CHECK(ring.acknowledged(published.ticket));
    CHECK(session.fatal().kind == SourceLiveAccessLogFatalKind::None);
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "102\n");
    CHECK(session.finish().status == SourceLiveAccessLogFinishStatus::Success);
}

TEST(access_log_live_writer, notify_fatal_is_preserved_but_finish_still_drains) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    {
        IoFaultConfig config;
        config.fd = kMatchAllIoFds;
        config.write_fatals = 1;
        ScopedIoFault fault(config);
        CHECK(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Fatal);
        CHECK_EQ(fault.remaining_write_fatals(), 0);
    }
    const SourceLiveAccessLogFatal first = session.fatal();
    CHECK(first.kind == SourceLiveAccessLogFatalKind::Notify);
    CHECK_EQ(first.ring_index, 0u);
    CHECK_EQ(first.system_error, EPIPE);
    CHECK(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Fatal);
    const auto finished = session.finish();
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::Notify);
    CHECK_EQ(finished.fatal.ring_index, 0u);
    CHECK_EQ(finished.fatal.system_error, EPIPE);
    CHECK(ring.acknowledged(published.ticket));
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "102\n");
}

TEST(access_log_live_writer, notify_first_fatal_survives_later_terminal_write_failure) {
    LiveAccessLogRing ring;
    ring.init();
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 output_fd = output.write_fd;
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    {
        IoFaultConfig notify_config;
        notify_config.fd = kMatchAllIoFds;
        notify_config.write_fatals = 1;
        ScopedIoFault notify_fault(notify_config);
        REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Fatal);
    }
    {
        IoFaultConfig output_config;
        output_config.fd = output_fd;
        output_config.write_fatals = 1;
        ScopedIoFault output_fault(output_config);
        const auto finished = session.finish();
        REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
        CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::Notify);
        CHECK_EQ(finished.fatal.ring_index, 0u);
        CHECK_EQ(finished.fatal.system_error, EPIPE);
    }
    CHECK_FALSE(ring.acknowledged(published.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK(read_to_eagain_or_eof(output.read_fd).empty());
}

TEST(access_log_live_writer, two_rings_keep_fifo_and_round_robin_fairness) {
    LiveAccessLogRing ring0;
    LiveAccessLogRing ring1;
    ring0.init();
    ring1.init();
    const u32 ring0_values[] = {10u, 11u, 12u};
    const u32 ring1_values[] = {20u, 21u};
    for (u32 value : ring0_values)
        REQUIRE(ring0.try_publish(request_size_entry(value)).status ==
                LiveAccessLogPublishStatus::Published);
    for (u32 value : ring1_values)
        REQUIRE(ring1.try_publish(request_size_entry(value)).status ==
                LiveAccessLogPublishStatus::Published);

    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring0, &ring1};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 2u));
    REQUIRE(session.notify(0u) == SourceLiveAccessLogNotifyStatus::Notified);
    REQUIRE(session.notify(1u) == SourceLiveAccessLogNotifyStatus::Notified);
    REQUIRE(session.finish().status == SourceLiveAccessLogFinishStatus::Success);

    const std::vector<u32> values = parse_lines(read_to_eagain_or_eof(output.read_fd));
    REQUIRE_EQ(values.size(), 5u);
    for (u32 value : ring0_values) CHECK_EQ(count_of(values, value), 1u);
    for (u32 value : ring1_values) CHECK_EQ(count_of(values, value), 1u);
    CHECK_LT(index_of(values, 10u), index_of(values, 11u));
    CHECK_LT(index_of(values, 11u), index_of(values, 12u));
    CHECK_LT(index_of(values, 20u), index_of(values, 21u));
    CHECK_LT(index_of(values, 20u), index_of(values, 12u));
    CHECK_EQ(ring0.committed_pos.load(std::memory_order_relaxed), 3u);
    CHECK_EQ(ring1.committed_pos.load(std::memory_order_relaxed), 2u);
}

TEST(access_log_live_writer, immediate_finish_drains_prepublished_records_without_notify) {
    LiveAccessLogRing ring;
    ring.init();
    const auto first = ring.try_publish(request_size_entry(1u));
    const auto second = ring.try_publish(request_size_entry(2u));
    REQUIRE(first.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(second.status == LiveAccessLogPublishStatus::Published);
    Pipe output;
    REQUIRE(output.open_nonblocking());
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));
    REQUIRE(session.finish().status == SourceLiveAccessLogFinishStatus::Success);
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "1\n2\n");
    CHECK(ring.acknowledged(first.ticket));
    CHECK(ring.acknowledged(second.ticket));
}

TEST(access_log_live_writer, stop_notify_failure_uses_data_fallback_and_preserves_fatal) {
    LiveAccessLogRing ring;
    ring.init();
    const auto published = ring.try_publish(request_size_entry(102u));
    REQUIRE(published.status == LiveAccessLogPublishStatus::Published);
    Pipe output;
    REQUIRE(output.open_nonblocking());
    const i32 descriptors_before_start = open_fd_count();
    REQUIRE_GE(descriptors_before_start, 0);
    LiveAccessLogRing* rings[] = {&ring};
    SourceLiveAccessLogSession session;
    REQUIRE(session.start(output.take_writer(), rings, 1u));

    SourceLiveAccessLogFinishResult finished{};
    {
        IoFaultConfig config;
        config.fd = kMatchAllIoFds;
        config.write_fatals = 1;
        ScopedIoFault fault(config);
        finished = session.finish();
        CHECK_EQ(fault.remaining_write_fatals(), 0);
    }
    REQUIRE(finished.status == SourceLiveAccessLogFinishStatus::Fatal);
    CHECK(finished.fatal.kind == SourceLiveAccessLogFatalKind::Notify);
    CHECK_EQ(finished.fatal.ring_index, kSourceLiveAccessLogNoRing);
    CHECK_EQ(finished.fatal.system_error, EPIPE);
    CHECK(ring.acknowledged(published.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 1u);
    CHECK_EQ(read_to_eagain_or_eof(output.read_fd), "102\n");
    char after_eof = '\0';
    CHECK_EQ(read(output.read_fd, &after_eof, 1u), 0);
    CHECK_EQ(open_fd_count(), descriptors_before_start - 1);
    CHECK(session.finish().status == SourceLiveAccessLogFinishStatus::InvalidLifecycle);
}

TEST(access_log_live_writer, invalid_and_double_lifecycle_fail_without_fd_leaks) {
    const i32 baseline = open_fd_count();
    REQUIRE_GE(baseline, 0);
    LiveAccessLogRing ring;
    ring.init();
    LiveAccessLogRing* valid[] = {&ring};
    SourceLiveAccessLogSession session;
    CHECK(session.finish().status == SourceLiveAccessLogFinishStatus::InvalidLifecycle);

    Pipe invalid_output;
    REQUIRE(invalid_output.open_nonblocking());
    SourceAccessLogFd invalid_fd = invalid_output.take_writer();
    auto zero = session.start(static_cast<SourceAccessLogFd&&>(invalid_fd), valid, 0u);
    REQUIRE_FALSE(zero);
    CHECK(zero.error().kind == SourceLiveAccessLogStartErrorKind::InvalidRingCount);
    CHECK(invalid_fd);
    invalid_fd.reset();

    Pipe too_many_output;
    REQUIRE(too_many_output.open_nonblocking());
    SourceAccessLogFd too_many_fd = too_many_output.take_writer();
    auto too_many = session.start(static_cast<SourceAccessLogFd&&>(too_many_fd),
                                  valid,
                                  SourceLiveAccessLogSession::kMaxRings + 1u);
    REQUIRE_FALSE(too_many);
    CHECK(too_many.error().kind == SourceLiveAccessLogStartErrorKind::InvalidRingCount);
    CHECK(too_many_fd);
    too_many_fd.reset();

    SourceAccessLogFd missing_output;
    auto missing = session.start(static_cast<SourceAccessLogFd&&>(missing_output), valid, 1u);
    REQUIRE_FALSE(missing);
    CHECK(missing.error().kind == SourceLiveAccessLogStartErrorKind::InvalidOutput);

    LiveAccessLogRing* null_ring[] = {nullptr};
    Pipe null_output;
    REQUIRE(null_output.open_nonblocking());
    SourceAccessLogFd null_fd = null_output.take_writer();
    auto null_result = session.start(static_cast<SourceAccessLogFd&&>(null_fd), null_ring, 1u);
    REQUIRE_FALSE(null_result);
    CHECK(null_result.error().kind == SourceLiveAccessLogStartErrorKind::NullRing);
    CHECK_EQ(null_result.error().ring_index, 0u);
    CHECK(null_fd);
    null_fd.reset();

    LiveAccessLogRing* duplicate[] = {&ring, &ring};
    Pipe duplicate_output;
    REQUIRE(duplicate_output.open_nonblocking());
    SourceAccessLogFd duplicate_fd = duplicate_output.take_writer();
    auto duplicate_result =
        session.start(static_cast<SourceAccessLogFd&&>(duplicate_fd), duplicate, 2u);
    REQUIRE_FALSE(duplicate_result);
    CHECK(duplicate_result.error().kind == SourceLiveAccessLogStartErrorKind::DuplicateRing);
    CHECK_EQ(duplicate_result.error().ring_index, 1u);
    CHECK(duplicate_fd);
    duplicate_fd.reset();

    ring.published_pos.store(513u, std::memory_order_relaxed);
    Pipe state_output;
    REQUIRE(state_output.open_nonblocking());
    SourceAccessLogFd state_fd = state_output.take_writer();
    auto state_result = session.start(static_cast<SourceAccessLogFd&&>(state_fd), valid, 1u);
    REQUIRE_FALSE(state_result);
    CHECK(state_result.error().kind == SourceLiveAccessLogStartErrorKind::InvalidRingState);
    CHECK(state_fd);
    state_fd.reset();
    ring.init();

    Pipe output;
    REQUIRE(output.open_nonblocking());
    REQUIRE(session.start(output.take_writer(), valid, 1u));
    Pipe second_output;
    REQUIRE(second_output.open_nonblocking());
    SourceAccessLogFd second_fd = second_output.take_writer();
    auto second_start = session.start(static_cast<SourceAccessLogFd&&>(second_fd), valid, 1u);
    REQUIRE_FALSE(second_start);
    CHECK(second_start.error().kind == SourceLiveAccessLogStartErrorKind::InvalidLifecycle);
    CHECK(second_fd);
    second_fd.reset();
    CHECK(session.notify(1u) == SourceLiveAccessLogNotifyStatus::InvalidRingIndex);
    REQUIRE(session.finish().status == SourceLiveAccessLogFinishStatus::Success);
    CHECK(session.notify(0u) == SourceLiveAccessLogNotifyStatus::InvalidLifecycle);
    CHECK(session.finish().status == SourceLiveAccessLogFinishStatus::InvalidLifecycle);

    invalid_output.close_reader();
    too_many_output.close_reader();
    null_output.close_reader();
    duplicate_output.close_reader();
    state_output.close_reader();
    second_output.close_reader();
    output.close_reader();
    CHECK_EQ(open_fd_count(), baseline);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
