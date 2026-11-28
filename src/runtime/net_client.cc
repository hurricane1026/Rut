#include "rut/runtime/net_client.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/trap.h"
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
namespace {
using Port = range_int<1, UINT16_MAX + 1>;
}  // namespace

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
        } else if (name.eq(lit_str("dnsServer"))) {
            bit = 64;
            value = endpoint.dns_server;
            cap = sizeof(endpoint.dns_server);
        } else if (name.eq(lit_str("dnsPort"))) {
            bit = 128;
            i64 number = 0;
            Port port;
            if (doc.nodes[n].kind != json::Kind::Number || !json::integer(doc.raw(n), number) ||
                !Port::try_from_i64(number, &port))
                return false;
            endpoint.dns_port = port.to<u16>();
        } else if (name.eq(lit_str("port"))) {
            bit = 2;
            i64 number = 0;
            Port port;
            if (doc.nodes[n].kind != json::Kind::Number || !json::integer(doc.raw(n), number) ||
                !Port::try_from_i64(number, &port))
                return false;
            endpoint.port = port.to<u16>();
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
        } else if (name.eq(lit_str("poolIdleMs"))) {
            bit = 32;
            i64 number = 0;
            using IdleMillis = range_int<1, 60001>;
            IdleMillis millis;
            if (datagram || doc.nodes[n].kind != json::Kind::Number ||
                !json::integer(doc.raw(n), number) || !IdleMillis::try_from_i64(number, &millis))
                return false;
            endpoint.pool_idle_ms = millis.to<u32>();
        } else
            return false;
        if (seen & bit) return false;
        seen |= bit;
        if (value) {
            u32 text_capacity;
            if (!(range_int{cap} - range_int<1, 2>{}).to(&text_capacity)) return false;
            json::Writer out{value, text_capacity};
            if (!doc.string(n, out) || !out.ok || !out.len) return false;
            for (u32 i = 0; i < out.len; ++i)
                if (const u8 byte = byte_value(value[i]); byte < 32 || byte == 127) return false;
            value[out.len] = 0;
        }
    }
    in_addr address{};
    if ((seen & 3) != 3) return false;
    const bool literal = inet_pton(AF_INET, endpoint.address, &address) == 1;
    if (!literal && !dns_hostname(endpoint.address)) return false;
    if ((seen & 128) && !(seen & 64)) return false;
    if ((seen & 64) &&
        (literal || inet_pton(AF_INET, endpoint.dns_server, &address) != 1 || !address.s_addr))
        return false;
    if (datagram && (seen & 28)) return false;
    if (endpoint.tls.enabled) return (seen & 24) == 24 && valid_upstream_tls(endpoint.tls);
    return !(seen & 24);
}
core::Expected<void, Error> NetClientWorker::start() {
    if (started) return core::make_unexpected(Error::make(EALREADY, Error::Source::Thread));
    constexpr auto kStorageSize =
        range_int<sizeof(Slot), sizeof(Slot) + 1>{}.scaled_by<kCapacity>() + range_int<64, 65>{};
    auto allocated = storage.init(kStorageSize.to_u64());
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
    if (const int error = pthread_join(thread, nullptr); error != 0)
        RUT_TRAP("NetClientWorker::stop: pthread_join failed (error=%d)", error);
    constexpr auto kSlotBytes = range_int<sizeof(Slot), sizeof(Slot) + 1>{}.scaled_by<kCapacity>();
    OPENSSL_cleanse(slots, kSlotBytes.to_u64());
    storage.destroy();
    slots = nullptr;
    started = false;
}
void NetClientWorker::adopt_config(const void* config) {
    if (pool_config == config) return;
    pool_config = config;
    // Epoch zero disables reuse. Never wrap into an old pool generation.
    const u64 epoch = __atomic_load_n(&pool_epoch, __ATOMIC_RELAXED);
    const u64 next = epoch ? wrapping_add(epoch, u64{1}) : 0;
    __atomic_store_n(&pool_epoch, next, __ATOMIC_RELEASE);
}
void NetClientWorker::cancel(u32 owner, u64 generation) {
    if (!started) return;
    for (u32 i = 0; i < kCapacity; ++i) {
        auto& s = slots[i];
        const auto state = __atomic_load_n(&s.phase, __ATOMIC_ACQUIRE);
        if (state != Empty && s.owner == owner && (!generation || s.generation == generation))
            __atomic_store_n(&s.phase, u32{Cancelled}, __ATOMIC_RELEASE);
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
                               u32 timeout,
                               const void* config) {
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
            __atomic_store_n(&s.phase, u32{Cancelled}, __ATOMIC_RELEASE);
            reply.status = 0;
            reply.scalar = 1;
            return reply;
        }
        if (state != Idle) {
            if (operation != s.operation) {
                reply.status = -4;
                return reply;
            }
            u64 elapsed = 0;
            u32 remaining;
            if (sub_overflow(now, s.started, &elapsed) ||
                sub_overflow(s.timeout, elapsed, &remaining) || remaining == 0) {
                __atomic_store_n(&s.phase, u32{Cancelled}, __ATOMIC_RELEASE);
                reply.status = -2;
                return reply;
            }
            if (state == Done) {
                reply = s.reply;
                OPENSSL_cleanse(&s.reply, sizeof(s.reply));
                __atomic_store_n(
                    &s.phase,
                    u32{reply.status || operation == NetOp::Release ? Cancelled : Idle},
                    __ATOMIC_RELEASE);
                return reply;
            }
            reply.status = NetReply::kPending;
            reply.retry_ms = range_int{remaining}.min(range_int<10, 11>{}).to<u32>();
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
        found->pool_epoch =
            config == pool_config ? __atomic_load_n(&pool_epoch, __ATOMIC_ACQUIRE) : 0;
    }
    auto& s = *found;
    IoCount requested;
    IoCount pending_length;
    if (!IoCount::try_from_i64(amount, &requested) ||
        !IoCount::try_from_u64(bytes.len, &pending_length) || (bytes.len && !bytes.ptr) ||
        ((operation == NetOp::Receive || operation == NetOp::ReadLine) && !amount) ||
        (s.datagram && (operation == NetOp::ReadLine || operation == NetOp::ReadExactly))) {
        reply.status = -4;
        // Invalid framing operations poison the session rather than leave an
        // ambiguous read cursor available to a later operation.
        __atomic_store_n(&s.phase, u32{Cancelled}, __ATOMIC_RELEASE);
        return reply;
    }
    s.operation = operation;
    s.started = now;
    s.timeout = timeout;
    s.amount = requested;
    s.pending_length = pending_length;
    if (bytes.len) __builtin_memcpy(s.pending, bytes.ptr, bytes.len);
    s.reply = {};
    __atomic_store_n(&s.phase, u32{Queued}, __ATOMIC_RELEASE);
    reply.status = NetReply::kPending;
    reply.retry_ms = timeout < 10 ? timeout : 10;
    return reply;
}
void NetClientWorker::close(Slot& s) {
    s.dns.close();
    s.dns = {};
    s.resolved = s.address_index = 0;
    s.dns_expires = 0;
    s.dns_ready = false;
    if (s.ssl) SSL_free(s.ssl);
    s.ssl = nullptr;
    destroy_tls_client_context(s.tls);
    if (s.fd >= 0) ::close(s.fd);
    s.fd = -1;
    s.step = nullptr;
    s.buffered = {};
    s.eof = false;
    OPENSSL_cleanse(s.pending, sizeof(s.pending));
    OPENSSL_cleanse(s.buffer, sizeof(s.buffer));
    OPENSSL_cleanse(&s.reply, sizeof(s.reply));
}
void NetClientWorker::close(Parked& p) {
    if (p.ssl) SSL_free(p.ssl);
    destroy_tls_client_context(p.tls);
    if (p.fd >= 0) ::close(p.fd);
    p = {};
}
bool NetClientWorker::clean(int fd, SSL* ssl) {
    if (fd < 0 || (ssl && (SSL_pending(ssl) || SSL_has_pending(ssl)))) return false;
    pollfd probe{fd, POLLIN, 0};
    if (poll(&probe, 1, 0) != 0) return false;
    char byte;
    const auto result = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}
void NetClientWorker::sweep(u64 now) {
    const u64 epoch = __atomic_load_n(&pool_epoch, __ATOMIC_ACQUIRE);
    for (auto& p : parked) {
        u64 idle = 0;
        if (p.fd >= 0 && (!now || !epoch || p.epoch != epoch || now < p.since ||
                          (sub_overflow(now, p.since, &idle) || idle >= p.endpoint.pool_idle_ms) ||
                          (p.dns_expires && now >= p.dns_expires)))
            close(p);
    }
}
bool NetClientWorker::borrow(Slot& s) {
    if (!s.endpoint.pool_idle_ms || !s.pool_epoch ||
        s.pool_epoch != __atomic_load_n(&pool_epoch, __ATOMIC_ACQUIRE))
        return false;
    for (auto& p : parked) {
        if (p.fd < 0 || p.epoch != s.pool_epoch || p.resolved != s.resolved ||
            (p.dns_expires && jwt_monotonic_ms() >= p.dns_expires) ||
            (p.endpoint.port != s.endpoint.port ||
             p.endpoint.pool_idle_ms != s.endpoint.pool_idle_ms ||
             p.endpoint.tls.enabled != s.endpoint.tls.enabled ||
             __builtin_strcmp(p.endpoint.address, s.endpoint.address) != 0 ||
             __builtin_strcmp(p.endpoint.dns_server, s.endpoint.dns_server) != 0 ||
             p.endpoint.dns_port != s.endpoint.dns_port ||
             __builtin_strcmp(p.endpoint.tls.ca, s.endpoint.tls.ca) != 0 ||
             __builtin_strcmp(p.endpoint.tls.server_name, s.endpoint.tls.server_name) != 0 ||
             __builtin_strcmp(p.endpoint.tls.cert, s.endpoint.tls.cert) != 0 ||
             __builtin_strcmp(p.endpoint.tls.key, s.endpoint.tls.key) != 0))
            continue;
        const u64 now = jwt_monotonic_ms();
        u64 idle = 0;
        if (!now || now < p.since || sub_overflow(now, p.since, &idle) ||
            idle >= p.endpoint.pool_idle_ms || !clean(p.fd, p.ssl)) {
            close(p);
            continue;
        }
        s.fd = p.fd;
        s.tls = p.tls;
        s.ssl = p.ssl;
        p = {};
        return true;
    }
    return false;
}
bool NetClientWorker::release(Slot& s) {
    // This check cannot establish application framing. The explicit caller must
    // have consumed exactly one complete reply and restored its protocol state.
    if (!s.datagram && s.endpoint.pool_idle_ms && s.pool_epoch &&
        s.pool_epoch == __atomic_load_n(&pool_epoch, __ATOMIC_ACQUIRE) && s.buffered.value() == 0 &&
        !s.eof && (!s.dns_expires || jwt_monotonic_ms() < s.dns_expires) && clean(s.fd, s.ssl)) {
        for (auto& p : parked) {
            if (p.fd >= 0) continue;
            p.endpoint = s.endpoint;
            p.resolved = s.resolved;
            p.dns_expires = s.dns_expires;
            p.epoch = s.pool_epoch;
            p.since = jwt_monotonic_ms();
            p.fd = s.fd;
            p.tls = s.tls;
            p.ssl = s.ssl;
            s.fd = -1;
            s.tls = {};
            s.ssl = nullptr;
            return success(s, 1);
        }
    }
    close(s);
    return success(s, 0);
}
void* NetClientWorker::entry(void* pointer) {
    static_cast<NetClientWorker*>(pointer)->run();
    return nullptr;
}
void NetClientWorker::run() {
    resolver.init();
    const timespec idle{0, 1000000};
    while (!__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        sweep(jwt_monotonic_ms());
        for (u32 i = 0; i < kCapacity; ++i) {
            auto& s = slots[i];
            const auto phase = __atomic_load_n(&s.phase, __ATOMIC_ACQUIRE);
            if (phase == Empty || phase == Idle || phase == Done) continue;
            if (phase == Cancelled) {
                close(s);
                __atomic_store_n(&s.phase, u32{Empty}, __ATOMIC_RELEASE);
                continue;
            }
            if (phase == Queued) {
                u32 expected = Queued;
                if (!__atomic_compare_exchange_n(&s.phase,
                                                 &expected,
                                                 u32{Running},
                                                 false,
                                                 __ATOMIC_ACQ_REL,
                                                 __ATOMIC_ACQUIRE))
                    continue;
                s.offset = {};
                s.step = s.operation == NetOp::Tcp || s.operation == NetOp::Udp ? begin_connect
                         : s.operation == NetOp::Send                           ? write
                                                                                : read;
            }
            const u64 now = jwt_monotonic_ms();
            bool complete = false;
            u64 elapsed = 0;
            if (!now || now < s.started || sub_overflow(now, s.started, &elapsed) ||
                elapsed >= s.timeout) {
                s.reply.status = -2;
                complete = true;
            } else {
                // One bounded nonblocking step per worker turn.
                complete = s.operation == NetOp::Release             ? release(s)
                           : s.step == begin_connect && !s.dns_ready ? resolve(s)
                                                                     : s.step(s);
            }
            if (!complete) continue;
            OPENSSL_cleanse(s.pending, sizeof(s.pending));
            u32 expected = Running;
            __atomic_compare_exchange_n(
                &s.phase, &expected, u32{Done}, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        }
        nanosleep(&idle, nullptr);
    }
    for (u32 i = 0; i < kCapacity; ++i) close(slots[i]);
    for (auto& p : parked) close(p);
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
bool NetClientWorker::resolve(Slot& s) {
    in_addr literal{};
    if (inet_pton(AF_INET, s.endpoint.address, &literal) == 1) {
        s.resolved = literal.s_addr;
        // Zero is a valid literal; it must not re-enter resolution.
        s.step = connected;
    } else {
        in_addr server{};
        if (s.endpoint.dns_server[0]) inet_pton(AF_INET, s.endpoint.dns_server, &server);
        const int result = resolver.resolve(s.dns,
                                            s.endpoint.address,
                                            server.s_addr,
                                            s.endpoint.dns_port,
                                            s.pool_epoch,
                                            jwt_monotonic_ms(),
                                            s.dns_expires);
        if (result < 0) return failed(s);
        if (!result) return false;
        s.resolved = s.dns.result.addresses[0];
    }
    s.dns_ready = true;
    if (s.operation == NetOp::Tcp && borrow(s)) return success(s, s.token);
    return begin_connect(s);
}
bool NetClientWorker::retry_connect(Slot& s) {
    if (s.fd >= 0) ::close(s.fd);
    s.fd = -1;
    if (++s.address_index >= s.dns.result.count) return failed(s);
    s.resolved = s.dns.result.addresses[s.address_index];
    s.step = begin_connect;
    return false;
}
bool NetClientWorker::begin_connect(Slot& s) {
    s.fd = s.datagram ? platform::datagram_socket() : platform::stream_socket();
    if (s.fd < 0) return failed(s);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(s.endpoint.port);
    address.sin_addr.s_addr = s.resolved;
    if (connect(s.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 &&
        errno != EINPROGRESS)
        return retry_connect(s);
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
    if (getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error)
        return retry_connect(s);
    if (!s.endpoint.tls.enabled) return success(s, s.token);
    if (!init_tls_client_context(s.tls, s.endpoint.tls, false)) return failed(s);
    auto ssl = create_tls_client_ssl(s.tls, s.fd, s.endpoint.tls.server_name);
    if (!ssl) return failed(s);
    // This is a protocol-neutral TCP transport. HTTP clients configure their
    // own ALPN offer, but arbitrary TCP peers must not see an HTTP protocol.
    if (SSL_set_alpn_protos(ssl.value(), nullptr, 0) != 0) {
        SSL_free(ssl.value());
        return failed(s);
    }
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
    const auto length = s.pending_length;
    const auto cursor = s.offset;
    if (!s.datagram && cursor.value() == length.value()) return success(s, length.to<u32>());
    IoCount remaining;
    if (!length.try_count((length - cursor).value(), &remaining)) return failed(s);
    const char* const pending = s.pending + cursor.index();
    i32 written;
    if (s.ssl) {
        ERR_clear_error();
        written = SSL_write(s.ssl, pending, remaining.to<i32>());
        if (written <= 0) {
            const int error = SSL_get_error(s.ssl, written);
            return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? false
                                                                                 : failed(s);
        }
    } else {
        const auto n = send(s.fd, pending, remaining.to_u64(), platform::kSendFlags);
        if (n < 0)
            return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? false : failed(s);
        if (!range_int{n}.to(&written)) return failed(s);
    }
    if (s.datagram && written != length.to<i32>()) return failed(s);
    if (!length.try_count((cursor + range_int{written}).value(), &s.offset)) return failed(s);
    return s.offset.value() == length.value() ? success(s, length.to<u32>()) : false;
}
bool NetClientWorker::read(Slot& s) {
    if (s.fd < 0) return failed(s);
    const auto requested = s.amount;
    if (s.datagram) {
        iovec vector{s.reply.bytes, requested.to_u64()};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        const auto n = recvmsg(s.fd, &message, 0);
        if (n < 0)
            return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? false : failed(s);
        IoCount length;
        if ((message.msg_flags & MSG_TRUNC) || !requested.try_count(n, &length)) return failed(s);
        s.reply.length = length.to<u32>();
        return success(s, 0);
    }
    const auto buffered = s.buffered;
    const u32 count = buffered.to<u32>();
    u32 wanted = requested.to<u32>();
    if (s.operation == NetOp::ReadLine) {
        wanted = 0;
        for (u32 i = 0; i < count && i < requested.to<u32>(); ++i)
            if (s.buffer[i] == '\n') {
                if (!(range_int{i} + range_int<1, 2>{}).to(&wanted)) return failed(s);
                break;
            }
        if (!wanted && count >= requested.to<u32>()) return failed(s);
    }
    const bool ready = s.operation == NetOp::Receive    ? count != 0 || s.eof
                       : s.operation == NetOp::ReadLine ? wanted != 0
                                                        : count >= wanted;
    if (ready) {
        if (s.operation == NetOp::Receive && wanted > count) wanted = count;
        const auto delivered = range_int{wanted};
        IoCount remaining;
        if (!buffered.try_count((buffered - delivered).value(), &remaining)) return failed(s);
        if (wanted) __builtin_memcpy(s.reply.bytes, s.buffer, wanted);
        s.reply.length = wanted;
        s.buffered = remaining;
        if (remaining.value() != 0)
            __builtin_memmove(s.buffer, s.buffer + delivered.index(), remaining.to_u64());
        return success(s, 0);
    }
    if (s.eof || count == kMaxBytes) return failed(s);
    constexpr auto kCapacity = range_int<kMaxBytes, i64{kMaxBytes} + 1>{};
    const auto available = kCapacity - buffered;
    char* const tail = s.buffer + buffered.index();
    i32 received;
    if (s.ssl) {
        ERR_clear_error();
        received = SSL_read(s.ssl, tail, available.to<i32>());
    } else {
        const auto n = recv(s.fd, tail, available.to_u64(), 0);
        if (!range_int{n}.to(&received)) return failed(s);
    }
    if (received > 0) {
        if (!IoCount::try_from_i64((buffered + range_int{received}).value(), &s.buffered))
            return failed(s);
        return false;
    }
    if (s.ssl) {
        const int error = SSL_get_error(s.ssl, received);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return false;
        if (error != SSL_ERROR_ZERO_RETURN) return failed(s);
    } else if (received < 0) {
        return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? false : failed(s);
    }
    s.eof = true;
    return false;
}
}  // namespace rut
