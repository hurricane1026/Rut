#include "rut/runtime/access_log_live_writer.h"

#include <errno.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace rut {
namespace {

constexpr u64 encode_fatal(SourceLiveAccessLogFatalKind kind, u8 ring_index, i32 system_error) {
    return static_cast<u64>(kind) | (static_cast<u64>(ring_index) << 8u) |
           (static_cast<u64>(static_cast<u32>(system_error)) << 16u);
}

SourceLiveAccessLogFatal decode_fatal(u64 encoded) {
    if (encoded == 0u) return {};
    SourceLiveAccessLogFatal fatal{};
    fatal.kind = static_cast<SourceLiveAccessLogFatalKind>(encoded & 0xffu);
    fatal.ring_index = static_cast<u8>((encoded >> 8u) & 0xffu);
    fatal.system_error = static_cast<i32>(static_cast<u32>(encoded >> 16u));
    return fatal;
}

}  // namespace

SourceLiveAccessLogSession::~SourceLiveAccessLogSession() {
    if (state_.load(std::memory_order_acquire) == State::Running) (void)finish();
    close_owned();
}

core::Expected<void, SourceLiveAccessLogStartError> SourceLiveAccessLogSession::start(
    SourceAccessLogFd&& output, LiveAccessLogRing* const* rings, u32 ring_count) {
    SourceLiveAccessLogRingBinding bindings[kMaxRings]{};
    if (rings != nullptr && ring_count <= kMaxRings)
        for (u32 i = 0; i < ring_count; i++) bindings[i].ring = rings[i];
    return start_impl(static_cast<SourceAccessLogFd&&>(output),
                      rings != nullptr ? bindings : nullptr,
                      ring_count,
                      true);
}

core::Expected<void, SourceLiveAccessLogStartError> SourceLiveAccessLogSession::start(
    SourceAccessLogFd&& output, const SourceLiveAccessLogRingBinding* bindings, u32 ring_count) {
    return start_impl(static_cast<SourceAccessLogFd&&>(output), bindings, ring_count, false);
}

core::Expected<void, SourceLiveAccessLogStartError> SourceLiveAccessLogSession::start_impl(
    SourceAccessLogFd&& output,
    const SourceLiveAccessLogRingBinding* bindings,
    u32 ring_count,
    bool allow_unleased) {
    if (state_.load(std::memory_order_acquire) != State::New)
        return core::make_unexpected(SourceLiveAccessLogStartError{
            SourceLiveAccessLogStartErrorKind::InvalidLifecycle, kSourceLiveAccessLogNoRing, 0});
    if (!output)
        return core::make_unexpected(SourceLiveAccessLogStartError{
            SourceLiveAccessLogStartErrorKind::InvalidOutput, kSourceLiveAccessLogNoRing, 0});
    if (bindings == nullptr || ring_count == 0u || ring_count > kMaxRings)
        return core::make_unexpected(SourceLiveAccessLogStartError{
            SourceLiveAccessLogStartErrorKind::InvalidRingCount, kSourceLiveAccessLogNoRing, 0});

    for (u32 i = 0; i < ring_count; i++) {
        if (bindings[i].ring == nullptr)
            return core::make_unexpected(SourceLiveAccessLogStartError{
                SourceLiveAccessLogStartErrorKind::NullRing, static_cast<u8>(i), 0});
        for (u32 j = 0; j < i; j++) {
            if (bindings[i].ring == bindings[j].ring)
                return core::make_unexpected(SourceLiveAccessLogStartError{
                    SourceLiveAccessLogStartErrorKind::DuplicateRing, static_cast<u8>(i), 0});
        }
        if (!allow_unleased && bindings[i].lease == nullptr)
            return core::make_unexpected(SourceLiveAccessLogStartError{
                SourceLiveAccessLogStartErrorKind::NullLease, static_cast<u8>(i), 0});
        if (bindings[i].lease != nullptr) {
            for (u32 j = 0; j < i; j++) {
                if (bindings[i].lease == bindings[j].lease)
                    return core::make_unexpected(SourceLiveAccessLogStartError{
                        SourceLiveAccessLogStartErrorKind::DuplicateLease, static_cast<u8>(i), 0});
            }
        }
        const u64 published = bindings[i].ring->published_pos.load(std::memory_order_acquire);
        const u64 committed = bindings[i].ring->committed_pos.load(std::memory_order_acquire);
        if (published - committed > LiveAccessLogRing::kCapacity)
            return core::make_unexpected(SourceLiveAccessLogStartError{
                SourceLiveAccessLogStartErrorKind::InvalidRingState, static_cast<u8>(i), 0});
    }

    ring_count_ = ring_count;
    for (u32 i = 0; i < ring_count_; i++) {
        rings_[i] = bindings[i].ring;
        if (bindings[i].lease == nullptr) continue;
        SourceLiveAccessLogSession* expected = nullptr;
        if (!bindings[i].lease->compare_exchange_strong(
                expected, this, std::memory_order_acq_rel, std::memory_order_acquire)) {
            const SourceLiveAccessLogStartError error{
                SourceLiveAccessLogStartErrorKind::LeaseConflict, static_cast<u8>(i), 0};
            release_ring_borrows();
            return core::make_unexpected(error);
        }
        leases_[i] = bindings[i].lease;
    }

    const i32 data_fd = ::eventfd(0u, EFD_NONBLOCK | EFD_CLOEXEC);
    if (data_fd < 0) {
        release_ring_borrows();
        return core::make_unexpected(SourceLiveAccessLogStartError{
            SourceLiveAccessLogStartErrorKind::DataEventCreate, kSourceLiveAccessLogNoRing, errno});
    }
    const i32 stop_fd = ::eventfd(0u, EFD_NONBLOCK | EFD_CLOEXEC);
    if (stop_fd < 0) {
        const i32 saved_errno = errno;
        (void)::close(data_fd);
        release_ring_borrows();
        return core::make_unexpected(
            SourceLiveAccessLogStartError{SourceLiveAccessLogStartErrorKind::StopEventCreate,
                                          kSourceLiveAccessLogNoRing,
                                          saved_errno});
    }

    next_ring_ = 0u;
    data_event_fd_ = data_fd;
    stop_event_fd_ = stop_fd;
    output_ = static_cast<SourceAccessLogFd&&>(output);
    fatal_state_.store(0u, std::memory_order_relaxed);
    writer_terminal_.store(false, std::memory_order_relaxed);
    stop_requested_.store(false, std::memory_order_relaxed);

    const i32 create_result = ::pthread_create(&writer_, nullptr, writer_entry, this);
    if (create_result != 0) {
        close_owned();
        return core::make_unexpected(
            SourceLiveAccessLogStartError{SourceLiveAccessLogStartErrorKind::ThreadCreate,
                                          kSourceLiveAccessLogNoRing,
                                          create_result});
    }
    writer_started_ = true;
    state_.store(State::Running, std::memory_order_release);
    return {};
}

SourceLiveAccessLogNotifyStatus SourceLiveAccessLogSession::notify(u32 ring_index) {
    if (state_.load(std::memory_order_acquire) != State::Running)
        return SourceLiveAccessLogNotifyStatus::InvalidLifecycle;
    if (ring_index >= ring_count_) return SourceLiveAccessLogNotifyStatus::InvalidRingIndex;
    if (fatal().kind != SourceLiveAccessLogFatalKind::None)
        return SourceLiveAccessLogNotifyStatus::Fatal;

    const u64 one = 1u;
    for (;;) {
        const ssize_t written = ::write(data_event_fd_, &one, sizeof(one));
        if (written == static_cast<ssize_t>(sizeof(one)))
            return SourceLiveAccessLogNotifyStatus::Notified;
        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return SourceLiveAccessLogNotifyStatus::Coalesced;
        const i32 system_error = written < 0 ? errno : 0;
        publish_fatal(
            SourceLiveAccessLogFatalKind::Notify, static_cast<u8>(ring_index), system_error);
        return SourceLiveAccessLogNotifyStatus::Fatal;
    }
}

SourceLiveAccessLogFinishResult SourceLiveAccessLogSession::finish() {
    State expected = State::Running;
    if (!state_.compare_exchange_strong(
            expected, State::Finishing, std::memory_order_acq_rel, std::memory_order_acquire))
        return {};

    stop_requested_.store(true, std::memory_order_release);
    if (!signal_event(stop_event_fd_, kSourceLiveAccessLogNoRing, false)) {
        // A recorded stop-notification failure still needs a bounded cleanup
        // wake. The data event is independent and the fatal remains visible.
        (void)signal_event(data_event_fd_, kSourceLiveAccessLogNoRing, false);
    }

    if (writer_started_) {
        const i32 join_result = ::pthread_join(writer_, nullptr);
        writer_started_ = false;
        if (join_result != 0)
            publish_fatal(
                SourceLiveAccessLogFatalKind::Protocol, kSourceLiveAccessLogNoRing, join_result);
    }
    close_owned();
    state_.store(State::Finished, std::memory_order_release);
    const SourceLiveAccessLogFatal observed = fatal();
    if (observed.kind != SourceLiveAccessLogFatalKind::None)
        return {SourceLiveAccessLogFinishStatus::Fatal, observed};
    return {SourceLiveAccessLogFinishStatus::Success, {}};
}

SourceLiveAccessLogFatal SourceLiveAccessLogSession::fatal() const {
    return decode_fatal(fatal_state_.load(std::memory_order_acquire));
}

bool SourceLiveAccessLogSession::producer_binding_valid(
    const LiveAccessLogRing* ring,
    u32 ring_index,
    const SourceLiveAccessLogLeaseSlot* lease) const {
    return state_.load(std::memory_order_acquire) == State::Running && ring != nullptr &&
           ring_index < ring_count_ && rings_[ring_index] == ring && leases_[ring_index] == lease &&
           (lease == nullptr || lease->load(std::memory_order_acquire) == this);
}

bool SourceLiveAccessLogSession::running() const {
    return state_.load(std::memory_order_acquire) == State::Running;
}

void SourceLiveAccessLogSession::report_producer_fatal(SourceLiveAccessLogFatalKind kind,
                                                       u32 ring_index,
                                                       i32 system_error) {
    if (kind != SourceLiveAccessLogFatalKind::RingFull &&
        kind != SourceLiveAccessLogFatalKind::Protocol)
        kind = SourceLiveAccessLogFatalKind::Protocol;
    const u8 bounded_index = ring_index < kSourceLiveAccessLogNoRing ? static_cast<u8>(ring_index)
                                                                     : kSourceLiveAccessLogNoRing;
    publish_fatal(kind, bounded_index, system_error);
}

void* SourceLiveAccessLogSession::writer_entry(void* opaque) {
    static_cast<SourceLiveAccessLogSession*>(opaque)->writer_run();
    return nullptr;
}

void SourceLiveAccessLogSession::writer_run() {
    for (;;) {
        if (writer_terminal_.load(std::memory_order_acquire)) return;

        struct pollfd events[2] = {
            {data_event_fd_, POLLIN, 0},
            {stop_event_fd_, POLLIN, 0},
        };
        i32 poll_result;
        do {
            poll_result = ::poll(events, 2u, -1);
        } while (poll_result < 0 && errno == EINTR);
        if (poll_result < 0) {
            publish_writer_fatal(
                SourceLiveAccessLogFatalKind::Poll, kSourceLiveAccessLogNoRing, errno);
            return;
        }
        if (poll_result == 0) continue;
        for (const struct pollfd& event : events) {
            if ((event.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                publish_writer_fatal(
                    SourceLiveAccessLogFatalKind::Poll, kSourceLiveAccessLogNoRing, 0);
                return;
            }
        }
        if ((events[0].revents & POLLIN) != 0 && !drain_event_counter(data_event_fd_)) return;
        if ((events[1].revents & POLLIN) != 0 && !drain_event_counter(stop_event_fd_)) return;
        if (writer_terminal_.load(std::memory_order_acquire)) return;

        for (;;) {
            const bool progressed = service_round();
            if (writer_terminal_.load(std::memory_order_acquire)) return;
            if (!progressed) break;
        }
        if (stop_requested_.load(std::memory_order_acquire)) return;
    }
}

bool SourceLiveAccessLogSession::service_round() {
    bool progressed = false;
    const u32 start = next_ring_;
    for (u32 offset = 0; offset < ring_count_; offset++) {
        const u32 ring_index = (start + offset) % ring_count_;
        LiveAccessLogPeek peek = rings_[ring_index]->peek();
        if (!peek.valid) continue;
        if (peek.entry == nullptr) {
            publish_writer_fatal(
                SourceLiveAccessLogFatalKind::Protocol, static_cast<u8>(ring_index), 0);
            return progressed;
        }
        char line[kAccessLogDownstreamRequestBytesLineCapacity];
        const u32 line_length =
            format_access_log_downstream_request_bytes_line(*peek.entry, line, sizeof(line));
        const u64 position = peek.position;
        // Drop the only borrowed slot pointer before any commit can make the
        // slot reusable by its producer.
        peek = {};
        if (line_length == 0u) {
            publish_writer_fatal(
                SourceLiveAccessLogFatalKind::Protocol, static_cast<u8>(ring_index), 0);
            return progressed;
        }
        if (!write_record(ring_index, position, line, line_length)) return progressed;
        progressed = true;
    }
    next_ring_ = (start + 1u) % ring_count_;
    return progressed;
}

bool SourceLiveAccessLogSession::write_record(u32 ring_index,
                                              u64 position,
                                              const char* line,
                                              u32 line_length) {
    if (line == nullptr || line_length == 0u ||
        line_length > kAccessLogDownstreamRequestBytesLineCapacity) {
        publish_writer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, static_cast<u8>(ring_index), 0);
        return false;
    }

    u32 written = 0u;
    while (written < line_length) {
        const ssize_t result = ::write(output_.get(), line + written, line_length - written);
        if (result > 0) {
            written += static_cast<u32>(result);
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!wait_output_writable(ring_index)) return false;
            continue;
        }
        publish_writer_fatal(SourceLiveAccessLogFatalKind::Write,
                             static_cast<u8>(ring_index),
                             result < 0 ? errno : 0);
        return false;
    }

    if (!rings_[ring_index]->commit(position)) {
        publish_writer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, static_cast<u8>(ring_index), 0);
        return false;
    }
    return true;
}

bool SourceLiveAccessLogSession::wait_output_writable(u32 ring_index) {
    struct pollfd output_event{output_.get(), POLLOUT, 0};
    for (;;) {
        const i32 result = ::poll(&output_event, 1u, -1);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) {
            publish_writer_fatal(
                SourceLiveAccessLogFatalKind::Poll, static_cast<u8>(ring_index), errno);
            return false;
        }
        if (result == 0) continue;
        if ((output_event.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            publish_writer_fatal(
                SourceLiveAccessLogFatalKind::Poll, static_cast<u8>(ring_index), 0);
            return false;
        }
        if ((output_event.revents & POLLOUT) != 0) return true;
    }
}

bool SourceLiveAccessLogSession::drain_event_counter(i32 fd) {
    u64 counter = 0u;
    for (;;) {
        const ssize_t result = ::read(fd, &counter, sizeof(counter));
        if (result == static_cast<ssize_t>(sizeof(counter))) continue;
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        publish_writer_fatal(
            SourceLiveAccessLogFatalKind::Poll, kSourceLiveAccessLogNoRing, result < 0 ? errno : 0);
        return false;
    }
}

void SourceLiveAccessLogSession::publish_fatal(SourceLiveAccessLogFatalKind kind,
                                               u8 ring_index,
                                               i32 system_error) {
    const u64 encoded = encode_fatal(kind, ring_index, system_error);
    u64 expected = 0u;
    (void)fatal_state_.compare_exchange_strong(
        expected, encoded, std::memory_order_release, std::memory_order_relaxed);
}

void SourceLiveAccessLogSession::publish_writer_fatal(SourceLiveAccessLogFatalKind kind,
                                                      u8 ring_index,
                                                      i32 system_error) {
    writer_terminal_.store(true, std::memory_order_release);
    publish_fatal(kind, ring_index, system_error);
}

bool SourceLiveAccessLogSession::signal_event(i32 fd, u8 ring_index, bool producer_notification) {
    const u64 one = 1u;
    for (;;) {
        const ssize_t result = ::write(fd, &one, sizeof(one));
        if (result == static_cast<ssize_t>(sizeof(one))) return true;
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        publish_fatal(SourceLiveAccessLogFatalKind::Notify,
                      producer_notification ? ring_index : kSourceLiveAccessLogNoRing,
                      result < 0 ? errno : 0);
        return false;
    }
}

void SourceLiveAccessLogSession::close_owned() {
    if (data_event_fd_ >= 0) {
        const i32 fd = data_event_fd_;
        data_event_fd_ = -1;
        (void)::close(fd);
    }
    if (stop_event_fd_ >= 0) {
        const i32 fd = stop_event_fd_;
        stop_event_fd_ = -1;
        (void)::close(fd);
    }
    output_.reset();
    release_ring_borrows();
    next_ring_ = 0u;
}

void SourceLiveAccessLogSession::release_ring_borrows() {
    for (u32 i = 0; i < ring_count_; i++) {
        if (leases_[i] != nullptr) {
            SourceLiveAccessLogSession* expected = this;
            if (!leases_[i]->compare_exchange_strong(
                    expected, nullptr, std::memory_order_release, std::memory_order_relaxed))
                publish_fatal(SourceLiveAccessLogFatalKind::Protocol, static_cast<u8>(i), EPROTO);
        }
        leases_[i] = nullptr;
        rings_[i] = nullptr;
    }
    ring_count_ = 0u;
}

}  // namespace rut
