#include "rut/runtime/net_client.h"

#include "rut/platform/socket.h"
#include "rut/runtime/https_fetch.h"
#include "rut/runtime/json.h"
#include <new>

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

namespace rut {
bool net_endpoint(Str configuration, bool datagram, NetEndpoint& endpoint) {
    endpoint = {};
    if (!configuration.ptr || !configuration.len || configuration.len > 2048) return false;
    thread_local json::Document doc;
    if (!doc.parse(configuration) || doc.nodes[0].kind != json::Kind::Object) return false;
    u32 seen = 0;
    for (u32 n = doc.nodes[0].child; n != json::kNone; n = doc.nodes[n].next) {
        json::Writer key{doc.scratch};
        if (!doc.string(doc.nodes[n].key, key)) return false;
        const Str name{doc.scratch, key.len};
        u32 bit = 0, cap = 0;
        char* value = nullptr;
        if (name.eq(lit_str("address"))) {
            bit = 1;
            value = endpoint.address;
            cap = sizeof(endpoint.address);
        } else if (name.eq(lit_str("port"))) {
            bit = 2;
            i64 number = 0;
            if (doc.nodes[n].kind != json::Kind::Number || !json::integer(doc.raw(n), number) ||
                number < 1 || number > 65535)
                return false;
            endpoint.port = static_cast<u16>(number);
        } else if (name.eq(lit_str("tls"))) {
            bit = 4;
            const Str raw = doc.raw(n);
            if (raw.eq(lit_str("true")))
                endpoint.tls.enabled = true;
            else if (!raw.eq(lit_str("false")))
                return false;
        } else if (name.eq(lit_str("caFile"))) {
            bit = 8;
            value = endpoint.tls.ca;
            cap = sizeof(endpoint.tls.ca);
        } else if (name.eq(lit_str("serverName"))) {
            bit = 16;
            value = endpoint.tls.server_name;
            cap = sizeof(endpoint.tls.server_name);
        } else
            return false;
        if (seen & bit) return false;
        seen |= bit;
        if (value) {
            json::Writer out{value, cap - 1};
            if (!doc.string(n, out) || !out.ok || !out.len) return false;
            for (u32 i = 0; i < out.len; ++i)
                if (static_cast<u8>(value[i]) < 32 || static_cast<u8>(value[i]) == 127)
                    return false;
            value[out.len] = 0;
        }
    }
    in_addr address{};
    if ((seen & 3) != 3 || inet_pton(AF_INET, endpoint.address, &address) != 1) return false;
    if (datagram && (seen & 28)) return false;
    if (endpoint.tls.enabled) return (seen & 24) == 24 && valid_upstream_tls(endpoint.tls);
    return !(seen & 24);
}
core::Expected<void, Error> NetClientWorker::start() {
    if (started) return core::make_unexpected(Error::make(EALREADY, Error::Source::Thread));
    auto allocated = storage.init(sizeof(Slot) * kCapacity + 64);
    if (!allocated) return allocated;
    slots = storage.alloc_array<Slot>(kCapacity);
    if (!slots) {
        storage.destroy();
        return core::make_unexpected(Error::make(ENOMEM, Error::Source::Mmap));
    }
    for (u32 i = 0; i < kCapacity; ++i) ::new (&slots[i]) Slot();
    __atomic_store_n(&stopping, 0u, __ATOMIC_RELEASE);
    const int code = pthread_create(&thread, nullptr, entry, this);
    if (code) {
        storage.destroy();
        slots = nullptr;
        return core::make_unexpected(Error::make(code, Error::Source::Thread));
    }
    started = true;
    return {};
}
void NetClientWorker::stop() {
    if (!started) return;
    __atomic_store_n(&stopping, 1u, __ATOMIC_RELEASE);
    if (pthread_join(thread, nullptr) != 0) __builtin_trap();
    OPENSSL_cleanse(slots, sizeof(Slot) * kCapacity);
    storage.destroy();
    slots = nullptr;
    started = false;
}
void NetClientWorker::cancel(u32 owner, u64 generation) {
    if (!started) return;
    for (u32 i = 0; i < kCapacity; ++i) {
        auto& s = slots[i];
        const auto state = __atomic_load_n(&s.phase, __ATOMIC_ACQUIRE);
        if (state != Empty && s.owner == owner && (!generation || s.generation == generation))
            __atomic_store_n(&s.phase, static_cast<u32>(Cancelled), __ATOMIC_RELEASE);
    }
}
NetReply NetClientWorker::call(u32 owner,
                               u64 generation,
                               NetOp operation,
                               u32 handle,
                               const NetEndpoint* endpoint,
                               Str bytes,
                               i32 amount,
                               u64 now,
                               u32 timeout) {
    NetReply reply;
    if (!started || !generation || !now || !timeout || timeout > 60000) return reply;
    const bool opening = operation == NetOp::Tcp || operation == NetOp::Udp;
    Slot* found = nullptr;
    for (u32 i = 0; i < kCapacity; ++i) {
        auto& s = slots[i];
        const auto state = __atomic_load_n(&s.phase, __ATOMIC_ACQUIRE);
        if (state == Empty || state == Cancelled || s.owner != owner || s.generation != generation)
            continue;
        if ((!opening && s.token == handle) ||
            (opening && state != Idle &&
             (s.operation == NetOp::Tcp || s.operation == NetOp::Udp))) {
            found = &s;
            break;
        }
    }
    if (found) {
        auto& s = *found;
        const auto state = __atomic_load_n(&s.phase, __ATOMIC_ACQUIRE);
        if (operation == NetOp::Close) {
            __atomic_store_n(&s.phase, static_cast<u32>(Cancelled), __ATOMIC_RELEASE);
            reply.status = 0;
            reply.scalar = 1;
            return reply;
        }
        if (state != Idle) {
            if (operation != s.operation) {
                reply.status = -4;
                return reply;
            }
            if (now < s.started || now - s.started >= s.timeout) {
                __atomic_store_n(&s.phase, static_cast<u32>(Cancelled), __ATOMIC_RELEASE);
                reply.status = -2;
                return reply;
            }
            if (state == Done) {
                reply = s.reply;
                OPENSSL_cleanse(&s.reply, sizeof(s.reply));
                __atomic_store_n(
                    &s.phase, static_cast<u32>(reply.status ? Cancelled : Idle), __ATOMIC_RELEASE);
                return reply;
            }
            reply.status = NetReply::kPending;
            const auto remaining = s.timeout - (now - s.started);
            reply.retry_ms = static_cast<u32>(remaining < 10 ? remaining : 10);
            return reply;
        }
    } else {
        if (!opening || !endpoint || next_token == 0xffffffffu) {
            reply.status = -4;
            return reply;
        }
        for (u32 i = 0; i < kCapacity; ++i)
            if (__atomic_load_n(&slots[i].phase, __ATOMIC_ACQUIRE) == Empty) {
                found = &slots[i];
                break;
            }
        if (!found) {
            reply.status = -3;
            return reply;
        }
        found->endpoint = *endpoint;
        found->owner = owner;
        found->generation = generation;
        found->token = ++next_token;
        found->datagram = operation == NetOp::Udp;
    }
    auto& s = *found;
    if (amount < 0 || amount > static_cast<i32>(kMaxBytes) || bytes.len > kMaxBytes ||
        (bytes.len && !bytes.ptr) ||
        ((operation == NetOp::Receive || operation == NetOp::ReadLine) && !amount) ||
        (s.datagram && (operation == NetOp::ReadLine || operation == NetOp::ReadExactly))) {
        reply.status = -4;
        // Invalid framing operations poison the session rather than leave an
        // ambiguous read cursor available to a later operation.
        __atomic_store_n(&s.phase, static_cast<u32>(Cancelled), __ATOMIC_RELEASE);
        return reply;
    }
    s.operation = operation;
    s.started = now;
    s.timeout = timeout;
    s.amount = static_cast<u32>(amount);
    s.pending_length = bytes.len;
    if (bytes.len) __builtin_memcpy(s.pending, bytes.ptr, bytes.len);
    s.reply = {};
    __atomic_store_n(&s.phase, static_cast<u32>(Queued), __ATOMIC_RELEASE);
    reply.status = NetReply::kPending;
    reply.retry_ms = timeout < 10 ? timeout : 10;
    return reply;
}
void NetClientWorker::close(Slot& s) {
    if (s.ssl) SSL_free(s.ssl);
    s.ssl = nullptr;
    destroy_tls_client_context(s.tls);
    if (s.fd >= 0) ::close(s.fd);
    s.fd = -1;
    s.step = nullptr;
    s.buffered = 0;
    s.eof = false;
    OPENSSL_cleanse(s.pending, sizeof(s.pending));
    OPENSSL_cleanse(s.buffer, sizeof(s.buffer));
    OPENSSL_cleanse(&s.reply, sizeof(s.reply));
}
void* NetClientWorker::entry(void* pointer) {
    static_cast<NetClientWorker*>(pointer)->run();
    return nullptr;
}
void NetClientWorker::run() {
    const timespec idle{0, 1000000};
    while (!__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        for (u32 i = 0; i < kCapacity; ++i) {
            auto& s = slots[i];
            const auto phase = __atomic_load_n(&s.phase, __ATOMIC_ACQUIRE);
            if (phase == Empty || phase == Idle || phase == Done) continue;
            if (phase == Cancelled) {
                close(s);
                __atomic_store_n(&s.phase, static_cast<u32>(Empty), __ATOMIC_RELEASE);
                continue;
            }
            if (phase == Queued) {
                u32 expected = Queued;
                if (!__atomic_compare_exchange_n(&s.phase,
                                                 &expected,
                                                 static_cast<u32>(Running),
                                                 false,
                                                 __ATOMIC_ACQ_REL,
                                                 __ATOMIC_ACQUIRE))
                    continue;
                s.offset = 0;
                s.step = s.operation == NetOp::Tcp || s.operation == NetOp::Udp ? begin_connect
                         : s.operation == NetOp::Send                           ? write
                                                                                : read;
            }
            const u64 now = jwt_monotonic_ms();
            bool complete = false;
            if (!now || now < s.started || now - s.started >= s.timeout) {
                s.reply.status = -2;
                complete = true;
            } else {
                // One bounded nonblocking step per worker turn.
                complete = s.step(s);
            }
            if (!complete) continue;
            OPENSSL_cleanse(s.pending, sizeof(s.pending));
            u32 expected = Running;
            __atomic_compare_exchange_n(&s.phase,
                                        &expected,
                                        static_cast<u32>(Done),
                                        false,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED);
        }
        nanosleep(&idle, nullptr);
    }
    for (u32 i = 0; i < kCapacity; ++i) close(slots[i]);
}
bool NetClientWorker::success(Slot& s, u32 scalar) {
    s.reply.status = 0;
    s.reply.scalar = scalar;
    return true;
}
bool NetClientWorker::failed(Slot& s) {
    s.reply.status = -1;
    return true;
}
bool NetClientWorker::begin_connect(Slot& s) {
    s.fd = s.datagram ? platform::datagram_socket() : platform::stream_socket();
    if (s.fd < 0) return failed(s);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(s.endpoint.port);
    if (inet_pton(AF_INET, s.endpoint.address, &address.sin_addr) != 1) return failed(s);
    if (connect(s.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 &&
        errno != EINPROGRESS)
        return failed(s);
    s.step = connected;
    return false;
}
bool NetClientWorker::connected(Slot& s) {
    pollfd ready{s.fd, POLLOUT, 0};
    const int count = poll(&ready, 1, 0);
    if (count < 0) return errno == EINTR ? false : failed(s);
    if (!count) return false;
    int error = 0;
    socklen_t length = sizeof(error);
    if (getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error) return failed(s);
    if (!s.endpoint.tls.enabled) return success(s, s.token);
    if (!init_tls_client_context(s.tls, s.endpoint.tls, false)) return failed(s);
    auto ssl = create_tls_client_ssl(s.tls, s.fd, s.endpoint.tls.server_name);
    if (!ssl) return failed(s);
    s.ssl = ssl.value();
    s.step = handshake;
    return false;
}
bool NetClientWorker::handshake(Slot& s) {
    ERR_clear_error();
    const int result = SSL_connect(s.ssl);
    if (result == 1)
        return SSL_get_verify_result(s.ssl) == X509_V_OK ? success(s, s.token) : failed(s);
    const int error = SSL_get_error(s.ssl, result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? false : failed(s);
}
bool NetClientWorker::write(Slot& s) {
    if (s.fd < 0) return failed(s);
    if (!s.datagram && s.offset == s.pending_length) return success(s, s.pending_length);
    ERR_clear_error();
    const int n =
        s.ssl
            ? SSL_write(s.ssl, s.pending + s.offset, static_cast<int>(s.pending_length - s.offset))
            : static_cast<int>(send(
                  s.fd, s.pending + s.offset, s.pending_length - s.offset, platform::kSendFlags));
    if (n < 0 || (s.ssl && n == 0)) {
        if (s.ssl) {
            const int error = SSL_get_error(s.ssl, n);
            return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? false
                                                                                 : failed(s);
        }
        return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? false : failed(s);
    }
    if (s.datagram && static_cast<u32>(n) != s.pending_length) return failed(s);
    s.offset += static_cast<u32>(n);
    return s.offset == s.pending_length ? success(s, s.pending_length) : false;
}
bool NetClientWorker::read(Slot& s) {
    if (s.fd < 0) return failed(s);
    if (s.datagram) {
        iovec vector{s.reply.bytes, s.amount};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        const auto n = recvmsg(s.fd, &message, 0);
        if (n < 0)
            return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? false : failed(s);
        if (static_cast<u64>(n) > s.amount || (message.msg_flags & MSG_TRUNC)) return failed(s);
        s.reply.length = static_cast<u32>(n);
        return success(s, 0);
    }
    u32 wanted = s.amount;
    if (s.operation == NetOp::ReadLine) {
        wanted = 0;
        for (u32 i = 0; i < s.buffered && i < s.amount; ++i)
            if (s.buffer[i] == '\n') {
                wanted = i + 1;
                break;
            }
        if (!wanted && s.buffered >= s.amount) return failed(s);
    }
    const bool ready = s.operation == NetOp::Receive    ? s.buffered != 0 || s.eof
                       : s.operation == NetOp::ReadLine ? wanted != 0
                                                        : s.buffered >= wanted;
    if (ready) {
        if (s.operation == NetOp::Receive && wanted > s.buffered) wanted = s.buffered;
        if (wanted) __builtin_memcpy(s.reply.bytes, s.buffer, wanted);
        s.reply.length = wanted;
        s.buffered -= wanted;
        if (s.buffered) __builtin_memmove(s.buffer, s.buffer + wanted, s.buffered);
        return success(s, 0);
    }
    if (s.eof || s.buffered == kMaxBytes) return failed(s);
    ERR_clear_error();
    const int n =
        s.ssl ? SSL_read(s.ssl, s.buffer + s.buffered, static_cast<int>(kMaxBytes - s.buffered))
              : static_cast<int>(recv(s.fd, s.buffer + s.buffered, kMaxBytes - s.buffered, 0));
    if (n > 0) {
        s.buffered += static_cast<u32>(n);
        return false;
    }
    if (s.ssl) {
        const int error = SSL_get_error(s.ssl, n);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return false;
        if (error != SSL_ERROR_ZERO_RETURN) return failed(s);
    } else if (n < 0)
        return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? false : failed(s);
    s.eof = true;
    return false;
}
}  // namespace rut
