#pragma once

#include "core/expected.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/error.h"
#include "rut/runtime/https_fetch.h"

#include <pthread.h>

namespace rut {
// Destination is configuration-owned; request data cannot select an address,
// trust store, TLS identity or redirect. Ordinary Rut code builds the message.
bool http_call_policy(Str configuration, HttpsEndpoint& endpoint);
bool http_call_request(
    const HttpsEndpoint& endpoint, Str document, char* out, u32 cap, u32& length);
struct HttpCallReply {
    i32 status = -1;  // 0 complete, -1 transport, -2 timeout, -3 capacity, -4 invalid request
    u32 retry_ms = 0;
    char document[8192]{};
    u32 length = 0;
};
class HttpCallWorker {
public:
    static constexpr u32 kCapacity = 8;
    HttpCallWorker() = default;
    HttpCallWorker(const HttpCallWorker&) = delete;
    HttpCallWorker& operator=(const HttpCallWorker&) = delete;
    ~HttpCallWorker() { stop(); }
    core::Expected<void, Error> start();
    void stop();
    HttpCallReply call(u32 connection,
                       u64 generation,
                       const HttpsEndpoint& endpoint,
                       Str request,
                       u64 now_ms,
                       u32 timeout_ms);
    void cancel(u32 connection, u64 generation = 0);

private:
    enum State : u8 { Empty, Queued, Running, Done, Cancelled };
    struct Slot {
        u32 state = Empty;
        u32 connection = 0;
        u64 generation = 0;
        u64 started = 0;
        u32 timeout = 0;
        HttpsEndpoint endpoint{};
        char request[6144]{};
        u32 length = 0;
        HttpCallReply reply{};
    };
    // Cold, fixed-capacity storage: do not inflate every Shard's inline size.
    MmapArena storage;
    Slot* slots = nullptr;
    pthread_t thread{};
    u32 stopping = 0;
    bool started = false;
    static void* entry(void* self);
    void run();
};
// Header shared with generated LLVM frame: immutable request snapshot follows
// the frame in the request arena. Slot zero of HandlerCtx owns the frame pointer.
struct HttpCallFrameHeader {
    u32 state;
    const u8* request;
    u32 length;
};
}  // namespace rut
