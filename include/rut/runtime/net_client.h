#pragma once
#include "core/expected.h"
#include "rut/common/upstream_tls.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/error.h"
#include "rut/runtime/tls.h"

#include <pthread.h>

namespace rut {
struct NetEndpoint {
    char address[16]{};
    u16 port = 0;
    UpstreamTlsSpec tls{};
};
bool net_endpoint(Str configuration, bool datagram, NetEndpoint& endpoint);
enum class NetOp : u8 { Tcp, Udp, Send, Receive, ReadExactly, ReadLine, Close };
struct NetReply {
    static constexpr i32 kPending = static_cast<i32>(0x80000000u);
    i32 status = -1;  // 0 complete; -1 transport, -2 timeout, -3 capacity, -4 invalid
    u32 retry_ms = 0;
    u32 scalar = 0;
    u32 length = 0;
    char bytes[8192]{};
};
// One producer shard, one bounded nonblocking I/O worker. Handles and sockets
// belong to an HTTP request/stream generation, never to a source/JIT pointer.
class NetClientWorker {
public:
    static constexpr u32 kCapacity = 16;
    static constexpr u32 kMaxBytes = 8192;
    NetClientWorker() = default;
    NetClientWorker(const NetClientWorker&) = delete;
    NetClientWorker& operator=(const NetClientWorker&) = delete;
    ~NetClientWorker() { stop(); }
    core::Expected<void, Error> start();
    void stop();
    void cancel(u32 owner, u64 generation = 0);
    NetReply call(u32 owner,
                  u64 generation,
                  NetOp operation,
                  u32 handle,
                  const NetEndpoint* endpoint,
                  Str bytes,
                  i32 amount,
                  u64 now_ms,
                  u32 timeout_ms);

private:
    enum Phase : u8 { Empty, Queued, Running, Done, Idle, Cancelled };
    struct Slot {
        u32 phase = Empty;
        u32 owner = 0, token = 0;
        u64 generation = 0, started = 0;
        u32 timeout = 0, amount = 0, offset = 0, buffered = 0;
        NetOp operation = NetOp::Tcp;
        bool datagram = false, eof = false;
        NetEndpoint endpoint{};
        NetReply reply{};
        char pending[kMaxBytes]{};
        u32 pending_length = 0;
        char buffer[kMaxBytes]{};
        bool (*step)(Slot&) = nullptr;
        int fd = -1;
        TlsClientContext tls{};
        SSL* ssl = nullptr;
    };
    MmapArena storage;
    Slot* slots = nullptr;
    pthread_t thread{};
    u32 stopping = 0, next_token = 0;
    bool started = false;
    static void* entry(void*);
    void run();
    static void close(Slot&);
    static bool success(Slot&, u32 scalar);
    static bool failed(Slot&);
    static bool begin_connect(Slot&);
    static bool connected(Slot&);
    static bool handshake(Slot&);
    static bool write(Slot&);
    static bool read(Slot&);
};
}  // namespace rut
