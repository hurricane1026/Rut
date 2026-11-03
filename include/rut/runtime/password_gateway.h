#pragma once

#include "rut/common/types.h"
#include "rut/runtime/password_request.h"

namespace rut {
struct PasswordGatewayReply {
    PasswordRequestStatus status = PasswordRequestStatus::Unavailable;
    // Pending native handlers yield this many milliseconds using existing Timer
    // semantics, then call verify_password_for_request again on resume.
    u32 retry_ms = 0;
};

// Optional, per-loop, native HTTP/1 password service. Lifecycle owner starts it
// before transferring it to the shard and stops it only after loop termination.
// Bind loop.password_gateway once before run; do not replace while running.
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
        u32 connection, u32 generation, Str password, Str record, u64 now_ms, u32 timeout_ms);
    void cancel(u32 connection);
    u32 active_requests() const;

private:
    struct Entry {
        PasswordRequest request;
        u32 connection = 0;
        u32 generation = 0;
        bool active = false;
    };
    // Member order ensures request adapters are destroyed before the worker.
    PasswordWorker worker;
    Entry entries[PasswordWorker::kCapacity]{};
};

// Invocation-local binding, restored on every exit (including nested calls).
// This binds an existing native HandlerFn without extending its ABI or storing
// request context in shared global state. POD TLS pointers have no heap/dtor.
class PasswordHandlerScope {
public:
    PasswordHandlerScope(PasswordGateway* gateway, void* connection);
    ~PasswordHandlerScope();
    PasswordHandlerScope(const PasswordHandlerScope&) = delete;
    PasswordHandlerScope& operator=(const PasswordHandlerScope&) = delete;

private:
    PasswordGateway* previous_gateway;
    void* previous_connection;
    bool engaged = false;
};

// Trusted native HTTP/1 HandlerFn API; not yet a Rut/JIT/native-artifact helper.
// First call copies credentials; subsequent calls for this request only poll the
// existing task (credential/timeout arguments cannot replace/extend it).
// Pending handlers MUST return TimerYield(retry_ms); never busy-loop or forward
// while waiting. Terminal statuses are explicit; only Matched authenticates.
// Wrong invocation, HTTP/2, missing service and generation zero fail closed.
PasswordGatewayReply verify_password_for_request(void* connection,
                                                 Str password,
                                                 Str record,
                                                 u32 timeout_ms);
}  // namespace rut
