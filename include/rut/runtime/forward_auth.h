#pragma once

#include "core/expected.h"
#include "rut/runtime/error.h"
#include "rut/runtime/https_fetch.h"

#include <pthread.h>

namespace rut {
// Fixed configuration only. Exactly one identity response field is allowlisted.
struct ForwardAuthPolicy {
    HttpsEndpoint endpoint{};
    char identity_header[129]{};
    bool load(Str configuration);
    bool valid() const;
};
bool forward_auth_policy_valid(Str header, Str configuration, u32 timeout_ms);

struct ForwardAuthReply {
    i32 status = -1;  // 1 allow, 0 unauthenticated, -3 forbidden, -1 unavailable, -2 timeout
    u32 retry_ms = 0;
    char identity[1024]{};
    u32 identity_length = 0;
};

// Single shard producer, private worker consumer. All TLS allocation, filesystem
// and socket work runs off-shard. Inputs/results are copied; no request views or
// configuration pointers cross threads. stop joins before releasing storage.
class ForwardAuthWorker {
public:
    static constexpr u32 kCapacity = 8;
    ForwardAuthWorker() = default;
    ForwardAuthWorker(const ForwardAuthWorker&) = delete;
    ForwardAuthWorker& operator=(const ForwardAuthWorker&) = delete;
    ~ForwardAuthWorker() { stop(); }
    core::Expected<void, Error> start();
    void stop();
    ForwardAuthReply authorize(u32 connection,
                               u64 generation,
                               Str credential_header,
                               const ForwardAuthPolicy& policy,
                               Str credential,
                               Str method,
                               Str target,
                               u64 now_ms,
                               u32 timeout_ms);
    void cancel(u32 connection, u64 generation = 0);

private:
    enum State : u8 { Empty, Queued, Running, Done, Cancelled };
    struct Slot {
        u32 state = Empty;
        u32 connection = 0;
        u64 generation = 0;
        u64 started_ms = 0;
        u32 timeout_ms = 0;
        ForwardAuthPolicy policy{};
        char request[6144]{};
        u32 request_length = 0;
        ForwardAuthReply reply{};
    };
    Slot slots[kCapacity]{};
    pthread_t thread{};
    u32 stopping = 0;
    bool started = false;
    static void* entry(void* self);
    void run();
};
}  // namespace rut
