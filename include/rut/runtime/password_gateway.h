#pragma once

#include "rut/common/types.h"
#include "rut/runtime/password_request.h"

namespace rut {
class PasswordGateway;
constexpr u64 password_h2_generation(u32 stream_id) {
    return (u64{1} << 32) | stream_id;
}

struct PasswordGatewayReply {
    PasswordRequestStatus status = PasswordRequestStatus::Unavailable;
    // Pending native handlers yield this many milliseconds using existing Timer
    // semantics, then call verify_password_for_request again on resume.
    u32 retry_ms = 0;
};

// Optional, per-loop, native HTTP password service. Lifecycle owner starts it
// before transferring it to the shard and stops it only after loop termination.
// Bind before run, or publish a newly started service through ShardControlBlock
// before adopting its requiring config. Do not replace an active service.
// verify/cancel/active_requests run exclusively on the owner shard (or after
// reclaiming it at shutdown). No configuration or connection pointer is retained
// by the worker/service.
class PasswordGateway {
public:
    PasswordGateway() = default;
    ~PasswordGateway() { stop(); }
    PasswordGateway(const PasswordGateway&) = delete;
    PasswordGateway& operator=(const PasswordGateway&) = delete;
    core::Expected<void, Error> start() { return worker.start(); }
    void stop();
    PasswordGatewayReply verify(
        u32 connection, u64 generation, Str password, Str record, u64 now_ms, u32 timeout_ms);
    void cancel(u32 connection);
    void cancel_request(u32 connection, u64 generation);
    u32 active_requests() const;

private:
    struct Entry {
        PasswordRequest request;
        u32 connection = 0;
        u64 generation = 0;
        bool active = false;
    };
    // Member order ensures request adapters are destroyed before the worker.
    PasswordWorker worker;
    Entry entries[PasswordWorker::kCapacity]{};
};

template <typename Loop>
PasswordGateway* request_password_gateway(Loop* loop) {
    if constexpr (requires { loop->password_gateway; }) return loop->password_gateway;
    return nullptr;
}

// Invocation-local binding, restored on every exit (including nested calls).
// This binds an existing native HandlerFn without extending its ABI or storing
// request context in shared global state. POD TLS pointers have no heap/dtor.
class PasswordHandlerScope {
public:
    PasswordHandlerScope(PasswordGateway* gateway, void* connection, u32 stream_id = 0);
    ~PasswordHandlerScope();
    PasswordHandlerScope(const PasswordHandlerScope&) = delete;
    PasswordHandlerScope& operator=(const PasswordHandlerScope&) = delete;

private:
    PasswordGateway* previous_gateway;
    void* previous_connection;
    u32 previous_stream = 0;
    bool engaged = false;
};

// Native HandlerFn API, also used by the bounded Rut/JIT header helper.
// First call copies credentials; subsequent calls for this request only poll the
// existing task (credential/timeout arguments cannot replace/extend it).
// Pending handlers MUST return TimerYield(retry_ms); never busy-loop or forward
// while waiting. Terminal statuses are explicit; only Matched authenticates.
// Wrong invocation, missing service and invalid request/stream identity fail closed.
PasswordGatewayReply verify_password_for_request(void* connection,
                                                 Str password,
                                                 Str record,
                                                 u32 timeout_ms);
}  // namespace rut
