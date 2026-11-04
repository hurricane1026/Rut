#pragma once

#include "rut/common/types.h"
#include "rut/runtime/password_worker.h"

namespace rut {
enum class PasswordRequestStatus : u8 {
    Idle,
    Pending,
    Matched,
    Rejected,
    Unavailable,
    TimedOut,
    Cancelled
};

// Native request adapter owned exclusively by one shard. No worker callback
// touches this object. The worker must outlive all attached adapters, including
// completed/unconsumed requests; detach them before worker stop or destruction.
// Caller supplies CLOCK_MONOTONIC milliseconds, registers worker.completion_fd()
// and arms a deadline timer. Drain worker notifications BEFORE polling requests.
// This is not a Rut/JIT/native-program helper or a connection close hook.
class PasswordRequest {
public:
    static constexpr u32 kMaxTimeoutMs = 60000;
    PasswordRequest() = default;
    ~PasswordRequest() { cancel(); }
    PasswordRequest(const PasswordRequest&) = delete;
    PasswordRequest& operator=(const PasswordRequest&) = delete;

    // One request at a time. Rejects another begin until take/reset detaches the
    // prior request, even if terminal. False means no new request was started.
    // A valid begin may record Unavailable when queue/input validation fails.
    bool begin(PasswordWorker& worker, Str password, Str record, u64 now_ms, u32 timeout_ms) {
        if (status != PasswordRequestStatus::Idle || timeout_ms == 0 ||
            timeout_ms > kMaxTimeoutMs || now_ms > ~u64{0} - timeout_ms)
            return false;
        owner = &worker;
        deadline = now_ms + timeout_ms;
        task = worker.submit(password, record);
        status = task.owner ? PasswordRequestStatus::Pending : PasswordRequestStatus::Unavailable;
        return true;
    }

    PasswordRequestStatus poll(u64 now_ms) {
        if (status != PasswordRequestStatus::Pending) return status;
        // Deadline wins at equality, even if completion is already queued. A
        // late result must never authenticate a request whose budget expired.
        if (now_ms >= deadline) {
            owner->cancel(task);
            status = PasswordRequestStatus::TimedOut;
            return status;
        }
        switch (owner->poll(task)) {
            case PasswordTaskStatus::Queued:
            case PasswordTaskStatus::Running:
                break;
            case PasswordTaskStatus::Matched:
                status = PasswordRequestStatus::Matched;
                break;
            case PasswordTaskStatus::Rejected:
                status = PasswordRequestStatus::Rejected;
                break;
            case PasswordTaskStatus::Invalid:
                status = PasswordRequestStatus::Unavailable;
                break;
        }
        return status;
    }

    void cancel() {
        if (status == PasswordRequestStatus::Pending) {
            owner->cancel(task);
            status = PasswordRequestStatus::Cancelled;
        }
    }

    // Terminal results are delivered once; after take(), the object can be
    // reused. Pending/Idle take returns Idle and does not consume pending work.
    PasswordRequestStatus take() {
        if (status == PasswordRequestStatus::Idle || status == PasswordRequestStatus::Pending)
            return PasswordRequestStatus::Idle;
        const auto kResult = status;
        reset();
        return kResult;
    }

    // Explicit close/reload detach: cancel first, then forget every reference.
    // Must precede worker stop/replacement. Never resume a closed request.
    void reset() {
        cancel();
        owner = nullptr;
        task = {};
        status = PasswordRequestStatus::Idle;
        deadline = 0;
    }
    u64 deadline_ms() const { return status == PasswordRequestStatus::Pending ? deadline : 0; }

private:
    PasswordWorker* owner = nullptr;
    PasswordTask task{};
    PasswordRequestStatus status = PasswordRequestStatus::Idle;
    u64 deadline = 0;
};
}  // namespace rut
