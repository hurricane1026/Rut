#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log_live.h"
#include "rut/runtime/access_log_startup.h"
#include <atomic>

#include <pthread.h>

namespace rut {

class SourceLiveAccessLogSession;
using SourceLiveAccessLogLeaseSlot = std::atomic<SourceLiveAccessLogSession*>;

struct SourceLiveAccessLogRingBinding {
    LiveAccessLogRing* ring = nullptr;
    SourceLiveAccessLogLeaseSlot* lease = nullptr;
};

enum class SourceLiveAccessLogFatalKind : u8 {
    None = 0,
    Notify = 1,
    Poll = 2,
    Write = 3,
    Protocol = 4,
    RingFull = 5,
};

inline constexpr u8 kSourceLiveAccessLogNoRing = 0xffu;

struct SourceLiveAccessLogFatal {
    SourceLiveAccessLogFatalKind kind = SourceLiveAccessLogFatalKind::None;
    u8 ring_index = kSourceLiveAccessLogNoRing;
    i32 system_error = 0;
};

enum class SourceLiveAccessLogStartErrorKind : u8 {
    InvalidLifecycle,
    InvalidOutput,
    InvalidRingCount,
    NullRing,
    DuplicateRing,
    InvalidRingState,
    NullLease,
    DuplicateLease,
    LeaseConflict,
    DataEventCreate,
    StopEventCreate,
    ThreadCreate,
};

struct SourceLiveAccessLogStartError {
    SourceLiveAccessLogStartErrorKind kind = SourceLiveAccessLogStartErrorKind::InvalidLifecycle;
    u8 ring_index = kSourceLiveAccessLogNoRing;
    i32 system_error = 0;
};

enum class SourceLiveAccessLogNotifyStatus : u8 {
    Notified,
    Coalesced,
    Fatal,
    InvalidLifecycle,
    InvalidRingIndex,
};

enum class SourceLiveAccessLogFinishStatus : u8 {
    Success,
    Fatal,
    InvalidLifecycle,
};

struct SourceLiveAccessLogFinishResult {
    SourceLiveAccessLogFinishStatus status = SourceLiveAccessLogFinishStatus::InvalidLifecycle;
    SourceLiveAccessLogFatal fatal{};
};

// One generic reliable live access-log session. On successful start(), the
// session solely owns the moved output descriptor, its two eventfds, and its
// writer thread. Rings remain caller-owned and must stay alive until finish()
// returns; they must be quiescent during start validation. A leased binding
// additionally CAS-claims its caller-owned lease slot until the writer has
// joined and can no longer access that ring. Both the ring and lease slot must
// therefore outlive finish(). Producers may
// publish and notify only while the session is running, and must be quiescent
// before finish(). The writer never retains a peeked entry pointer after
// committing its position. Each ring remains FIFO; ordering between rings is
// deliberately unspecified.
//
// The type is intentionally noncopyable and nonmovable. Its destructor finishes
// a running session and closes every owned descriptor. A failed start before
// ownership transfer leaves the caller's output descriptor intact.
class SourceLiveAccessLogSession {
public:
    static constexpr u32 kMaxRings = 64u;

    SourceLiveAccessLogSession() = default;
    SourceLiveAccessLogSession(const SourceLiveAccessLogSession&) = delete;
    SourceLiveAccessLogSession& operator=(const SourceLiveAccessLogSession&) = delete;
    SourceLiveAccessLogSession(SourceLiveAccessLogSession&&) = delete;
    SourceLiveAccessLogSession& operator=(SourceLiveAccessLogSession&&) = delete;
    ~SourceLiveAccessLogSession();

    core::Expected<void, SourceLiveAccessLogStartError> start(SourceAccessLogFd&& output,
                                                              LiveAccessLogRing* const* rings,
                                                              u32 ring_count);
    // Leased form used when ring lifetime is independently managed (for
    // example by Shard). The raw overload above is retained for standalone
    // caller-owned sessions and cannot be attached to a leased Shard ring.
    core::Expected<void, SourceLiveAccessLogStartError> start(
        SourceAccessLogFd&& output, const SourceLiveAccessLogRingBinding* bindings, u32 ring_count);

    // Called only after a successful try_publish() on ring_index. EINTR is
    // retried; eventfd saturation is a coalesced success. Other errors publish
    // the process-visible first fatal state. This operation never waits and
    // never writes the output descriptor.
    SourceLiveAccessLogNotifyStatus notify(u32 ring_index);

    // Independently wakes the writer through the stop eventfd, drains every
    // record published before producers became quiescent unless a terminal
    // Poll/Write/Protocol writer failure prevents it, joins, and closes all
    // owned descriptors. Notify fatal is reported but does not suppress this
    // final drain. A terminal writer failure leaves its current record
    // uncommitted. Repeated or premature finish fails closed.
    SourceLiveAccessLogFinishResult finish();

    SourceLiveAccessLogFatal fatal() const;

    // Producer-side validation/reporting boundary. These calls do not own or
    // publish records. The binding check is valid only while producers are
    // permitted to run; report_producer_fatal preserves the session-wide
    // first-fatal value.
    bool producer_binding_valid(const LiveAccessLogRing* ring,
                                u32 ring_index,
                                const SourceLiveAccessLogLeaseSlot* lease) const;
    bool running() const;
    void report_producer_fatal(SourceLiveAccessLogFatalKind kind, u32 ring_index, i32 system_error);

private:
    enum class State : u8 {
        New,
        Running,
        Finishing,
        Finished,
    };

    static void* writer_entry(void* opaque);
    void writer_run();
    bool service_round();
    bool write_record(u32 ring_index, u64 position, const char* line, u32 line_length);
    bool wait_output_writable(u32 ring_index);
    bool drain_event_counter(i32 fd);
    void publish_fatal(SourceLiveAccessLogFatalKind kind, u8 ring_index, i32 system_error);
    void publish_writer_fatal(SourceLiveAccessLogFatalKind kind, u8 ring_index, i32 system_error);
    bool signal_event(i32 fd, u8 ring_index, bool producer_notification);
    core::Expected<void, SourceLiveAccessLogStartError> start_impl(
        SourceAccessLogFd&& output,
        const SourceLiveAccessLogRingBinding* bindings,
        u32 ring_count,
        bool allow_unleased);
    void release_ring_borrows();
    void close_owned();

    std::atomic<State> state_{State::New};
    std::atomic<u64> fatal_state_{0u};
    std::atomic<bool> writer_terminal_{false};
    std::atomic<bool> stop_requested_{false};
    SourceAccessLogFd output_{};
    i32 data_event_fd_ = -1;
    i32 stop_event_fd_ = -1;
    pthread_t writer_{};
    bool writer_started_ = false;
    LiveAccessLogRing* rings_[kMaxRings]{};
    SourceLiveAccessLogLeaseSlot* leases_[kMaxRings]{};
    u32 ring_count_ = 0u;
    u32 next_ring_ = 0u;
};

static_assert(std::atomic<u64>::is_always_lock_free);
static_assert(SourceLiveAccessLogLeaseSlot::is_always_lock_free);

}  // namespace rut
