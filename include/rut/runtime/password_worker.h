#pragma once

#include "core/expected.h"
#include "rut/runtime/error.h"
#include "rut/runtime/password.h"

#include <pthread.h>

namespace rut {
static_assert(__atomic_always_lock_free(sizeof(u32), nullptr));
class PasswordWorker;

struct PasswordTask {
    const PasswordWorker* owner = nullptr;
    u64 generation = 0;
    u32 slot = 0;
};

enum class PasswordTaskStatus : u8 { Invalid, Queued, Running, Matched, Rejected };

// Caller-owned, one producer/consumer shard and one private background thread.
// start/stop belong to a quiescent lifecycle owner, never the request hot path;
// start before handing the object to a shard, stop only after reclaiming it.
// submit/poll/cancel belong exclusively to that shard. No concurrent API callers.
// No request views, connection pointers, callbacks or allocator state cross threads.
// Storage must remain alive and unmoved through stop. Tokens expire on destruction.
// Polling does not wake an event loop: integration must schedule its own wakeups.

class PasswordWorker {
public:
    static constexpr u32 kCapacity = 8;
    PasswordWorker() = default;
    ~PasswordWorker();
    PasswordWorker(const PasswordWorker&) = delete;
    PasswordWorker& operator=(const PasswordWorker&) = delete;

    core::Expected<void, Error> start();
    // Discards all queued/results, waits for at most the current fixed-cost KDF,
    // joins the worker and wipes storage. Idempotent. Never call on a busy shard.
    void stop();

    // Copies bounded inputs; returns an invalid token when stopped/full/invalid.
    // Completed, unpolled results still occupy capacity. No heap or mutex waits.
    PasswordTask submit(Str password, Str record);
    // Matched/Rejected consume the result; subsequent use of the token is Invalid.
    PasswordTaskStatus poll(PasswordTask task);
    // Invalidates the token immediately. Queued work is skipped when possible;
    // running KDFs finish off-shard and discard their result. Capacity is freed
    // only after the worker has wiped the cancelled task's owned inputs.
    bool cancel(PasswordTask task);

private:
    enum State : u8 { Empty, Queued, Running, Done, CancelQueued, CancelRunning };
    struct Slot {
        u32 state = Empty;   // acquire/release via compiler atomic builtins
        u64 generation = 0;  // producer-only; never accessed by worker
        char password[kPasswordMaxBytes]{};
        char record[kPasswordRecordBytes]{};
        u32 password_len = 0;
        bool matched = false;
    };
    Slot slots[kCapacity]{};
    pthread_t worker_thread{};
    u32 stopping = 0;
    bool started = false;     // lifecycle owner / producer only
    u64 next_generation = 1;  // never reset across stop/start; fail on exhaustion

    static void* entry(void* self);
    void run();
    static void wipe(Slot& slot);
    Slot* lookup(PasswordTask task);
};
}  // namespace rut
