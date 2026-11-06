#include "rut/runtime/forward_auth.h"

#include "core/expected.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include "rut/runtime/https_fetch.h"
#include "rut/runtime/json.h"
#include <new>

#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

namespace rut {
namespace {
bool safe_field(Str name) {
    if (!name.ptr || !name.len || name.len > 128 ||
        validate_response_header(name.ptr, name.len, "", 0) != HttpHeaderValidation::Ok)
        return false;
    // Neither credentials nor identities may control transport/routing or the
    // trusted context emitted by this callout. Identity fields must be X-*.
    constexpr Str kForbidden[] = {lit_str("Host"),
                                  lit_str("TE"),
                                  lit_str("Trailer"),
                                  lit_str("Upgrade"),
                                  lit_str("Keep-Alive"),
                                  lit_str("Accept-Encoding"),
                                  lit_str("Proxy-Authorization"),
                                  lit_str("Proxy-Authenticate"),
                                  lit_str("X-Original-Method"),
                                  lit_str("X-Original-URI")};
    for (auto value : kForbidden)
        if (http_header_name_eq_ci(name.ptr, name.len, value.ptr, value.len)) return false;
    return true;
}
bool wire_value(Str value, u32 max) {
    if (!value.ptr || !value.len || value.len > max) return false;
    for (u32 i = 0; i < value.len; ++i)
        if (static_cast<u8>(value.ptr[i]) < 0x21 || static_cast<u8>(value.ptr[i]) > 0x7e)
            return false;
    return true;
}
}  // namespace
bool ForwardAuthPolicy::load(Str configuration) {
    *this = {};
    if (!configuration.ptr || !configuration.len || configuration.len > 2048) return false;
    json::Document document;
    if (!document.parse(configuration) || document.nodes[0].kind != json::Kind::Object)
        return false;
    u32 seen = 0;
    endpoint.tls.enabled = true;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[n].key, key)) return false;
        const Str kName{document.scratch, key.len};
        char* out = nullptr;
        u32 cap = 0, bit = 0;
        if (kName.eq(lit_str("address"))) {
            out = endpoint.address;
            cap = sizeof(endpoint.address);
            bit = 1;
        } else if (kName.eq(lit_str("serverName"))) {
            out = endpoint.tls.server_name;
            cap = sizeof(endpoint.tls.server_name);
            bit = 2;
        } else if (kName.eq(lit_str("caFile"))) {
            out = endpoint.tls.ca;
            cap = sizeof(endpoint.tls.ca);
            bit = 4;
        } else if (kName.eq(lit_str("path"))) {
            out = endpoint.path;
            cap = sizeof(endpoint.path);
            bit = 8;
        } else if (kName.eq(lit_str("identityHeader"))) {
            out = identity_header;
            cap = sizeof(identity_header);
            bit = 16;
        } else if (kName.eq(lit_str("port"))) {
            i64 port = 0;
            if ((seen & 32) || document.nodes[n].kind != json::Kind::Number ||
                !json::integer(document.raw(n), port) || port < 1 || port > 65535)
                return false;
            endpoint.port = static_cast<u16>(port);
            seen |= 32;
            continue;
        } else
            return false;
        if (seen & bit) return false;
        json::Writer value{out, cap - 1};
        if (!document.string(n, value) || !value.ok || !value.len) return false;
        for (u32 i = 0; i < value.len; ++i)
            if (out[i] == 0) return false;
        out[value.len] = 0;
        seen |= bit;
    }
    return (seen & 31) == 31 && valid();
}
bool ForwardAuthPolicy::valid() const {
    u32 length = 0;
    while (length < sizeof(identity_header) && identity_header[length]) ++length;
    if (length == sizeof(identity_header)) return false;
    const Str kIdentity{identity_header, length};
    return endpoint.valid() && safe_field(kIdentity) && kIdentity.len > 2 &&
           (kIdentity.ptr[0] == 'X' || kIdentity.ptr[0] == 'x') && kIdentity.ptr[1] == '-';
}

bool forward_auth_policy_valid(Str header, Str configuration, u32 timeout_ms) {
    ForwardAuthPolicy policy;
    return safe_field(header) && timeout_ms >= 1 && timeout_ms <= 60000 &&
           policy.load(configuration) &&
           !http_header_name_eq_ci(header.ptr,
                                   header.len,
                                   policy.identity_header,
                                   static_cast<u32>(__builtin_strlen(policy.identity_header)));
}
core::Expected<void, Error> ForwardAuthWorker::start() {
    if (started) return core::make_unexpected(Error::make(EALREADY, Error::Source::Thread));
    __atomic_store_n(&stopping, 0u, __ATOMIC_RELEASE);
    const auto kResult = pthread_create(&thread, nullptr, entry, this);
    if (kResult) return core::make_unexpected(Error::make(kResult, Error::Source::Thread));
    started = true;
    return {};
}
void ForwardAuthWorker::stop() {
    if (!started) return;
    __atomic_store_n(&stopping, 1u, __ATOMIC_RELEASE);
    if (pthread_join(thread, nullptr) != 0) __builtin_trap();
    started = false;
    for (auto& slot : slots) {
        OPENSSL_cleanse(slot.request, sizeof(slot.request));
        OPENSSL_cleanse(&slot.reply, sizeof(slot.reply));
        slot.state = Empty;
    }
}
void ForwardAuthWorker::cancel(u32 connection, u64 generation) {
    for (auto& slot : slots) {
        u32 state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
        if (state == Empty || slot.connection != connection ||
            (generation && slot.generation != generation))
            continue;
        while (state != Empty && state != Cancelled &&
               !__atomic_compare_exchange_n(&slot.state,
                                            &state,
                                            static_cast<u32>(Cancelled),
                                            false,
                                            __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
        }
    }
}
ForwardAuthReply ForwardAuthWorker::authorize(u32 connection,
                                              u64 generation,
                                              Str header,
                                              const ForwardAuthPolicy& policy,
                                              Str credential,
                                              Str method,
                                              Str target,
                                              u64 now,
                                              u32 timeout) {
    if (!started || !generation || !now || !timeout || timeout > 60000) return {};
    Slot* found = nullptr;
    for (auto& slot : slots) {
        const u32 kState = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
        if (kState == Empty || kState == Cancelled || slot.connection != connection) continue;
        if (slot.generation == generation)
            found = &slot;
        else
            cancel(connection, slot.generation);
    }
    if (found) {
        if (now < found->started_ms || now - found->started_ms >= found->timeout_ms) {
            cancel(connection, generation);
            ForwardAuthReply reply;
            reply.status = -2;
            return reply;
        }
        if (__atomic_load_n(&found->state, __ATOMIC_ACQUIRE) == Done) {
            const auto kReply = found->reply;
            OPENSSL_cleanse(&found->reply, sizeof(found->reply));
            __atomic_store_n(&found->state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
            return kReply;
        }
    } else {
        if (!policy.valid() || !safe_field(header) ||
            http_header_name_eq_ci(header.ptr,
                                   header.len,
                                   policy.identity_header,
                                   static_cast<u32>(__builtin_strlen(policy.identity_header))) ||
            !wire_value(method, 16) || !wire_value(target, 2048) || target.ptr[0] != '/' ||
            !credential.ptr || !credential.len || credential.len > 2048 ||
            validate_response_header(header.ptr, header.len, credential.ptr, credential.len) !=
                HttpHeaderValidation::Ok)
            return {};
        for (auto& slot : slots) {
            if (__atomic_load_n(&slot.state, __ATOMIC_ACQUIRE) != Empty) continue;
            const int kLength =
                snprintf(slot.request,
                         sizeof(slot.request),
                         "GET %s HTTP/1.1\r\nHost: %s:%u\r\n%.*s: %.*s\r\nX-Original-Method: "
                         "%.*s\r\nX-Original-URI: %.*s\r\nAccept-Encoding: identity\r\nConnection: "
                         "close\r\n\r\n",
                         policy.endpoint.path,
                         policy.endpoint.tls.server_name,
                         policy.endpoint.port,
                         static_cast<int>(header.len),
                         header.ptr,
                         static_cast<int>(credential.len),
                         credential.ptr,
                         static_cast<int>(method.len),
                         method.ptr,
                         static_cast<int>(target.len),
                         target.ptr);
            if (kLength <= 0 || static_cast<u32>(kLength) >= sizeof(slot.request)) {
                OPENSSL_cleanse(slot.request, sizeof(slot.request));
                return {};
            }
            slot.request_length = static_cast<u32>(kLength);
            slot.policy = policy;
            slot.connection = connection;
            slot.generation = generation;
            slot.started_ms = now;
            slot.timeout_ms = timeout;
            slot.reply = {};
            __atomic_store_n(&slot.state, static_cast<u32>(Queued), __ATOMIC_RELEASE);
            found = &slot;
            break;
        }
    }
    if (!found) return {};
    ForwardAuthReply reply;
    reply.status = static_cast<i32>(0x80000000u);
    const auto kRemaining = found->timeout_ms - (now - found->started_ms);
    reply.retry_ms = static_cast<u32>(kRemaining < 10 ? kRemaining : 10);
    return reply;
}
void* ForwardAuthWorker::entry(void* self) {
    static_cast<ForwardAuthWorker*>(self)->run();
    return nullptr;
}
void ForwardAuthWorker::run() {
    HttpsFetch fetches[kCapacity];
    const timespec kIdle{0, 1000000};
    while (!__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        for (u32 i = 0; i < kCapacity; ++i) {
            auto& slot = slots[i];
            auto& fetch = fetches[i];
            auto state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
            if (state == Empty || state == Done) continue;
            if (state == Cancelled) {
                fetch.~HttpsFetch();
                ::new (&fetch) HttpsFetch();
                OPENSSL_cleanse(slot.request, sizeof(slot.request));
                OPENSSL_cleanse(&slot.reply, sizeof(slot.reply));
                __atomic_store_n(&slot.state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
                continue;
            }
            if (state == Queued) {
                u32 expected = Queued;
                if (!__atomic_compare_exchange_n(&slot.state,
                                                 &expected,
                                                 static_cast<u32>(Running),
                                                 false,
                                                 __ATOMIC_ACQ_REL,
                                                 __ATOMIC_ACQUIRE))
                    continue;
                fetch.~HttpsFetch();
                ::new (&fetch) HttpsFetch();
                if (!fetch.init_authorization(slot.policy.endpoint,
                                              {slot.request, slot.request_length}) ||
                    !fetch.start(slot.started_ms, slot.timeout_ms)) {
                    slot.reply = {};
                    OPENSSL_cleanse(slot.request, sizeof(slot.request));
                    fetch.~HttpsFetch();
                    ::new (&fetch) HttpsFetch();
                    expected = Running;
                    __atomic_compare_exchange_n(&slot.state,
                                                &expected,
                                                static_cast<u32>(Done),
                                                false,
                                                __ATOMIC_RELEASE,
                                                __ATOMIC_RELAXED);
                    continue;
                }
            }
            fetch.advance(jwt_monotonic_ms());
            if (fetch.state() == HttpsFetch::State::Busy) continue;
            slot.reply = {};
            if (fetch.state() == HttpsFetch::State::Done) {
                if (fetch.status() == 401)
                    slot.reply.status = 0;
                else if (fetch.status() == 403)
                    slot.reply.status = -3;
                else if (fetch.status() == 200) {
                    const Str kName{
                        slot.policy.identity_header,
                        static_cast<u32>(__builtin_strlen(slot.policy.identity_header))};
                    const auto kIdentity = fetch.unique_header(kName);
                    if (kIdentity.ptr && kIdentity.len &&
                        kIdentity.len <= sizeof(slot.reply.identity) &&
                        validate_response_header(
                            kName.ptr, kName.len, kIdentity.ptr, kIdentity.len) ==
                            HttpHeaderValidation::Ok) {
                        slot.reply.status = 1;
                        __builtin_memcpy(slot.reply.identity, kIdentity.ptr, kIdentity.len);
                        slot.reply.identity_length = kIdentity.len;
                    }
                }
            }
            OPENSSL_cleanse(slot.request, sizeof(slot.request));
            fetch.~HttpsFetch();
            ::new (&fetch) HttpsFetch();
            u32 expected = Running;
            __atomic_compare_exchange_n(&slot.state,
                                        &expected,
                                        static_cast<u32>(Done),
                                        false,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED);
        }
        nanosleep(&kIdle, nullptr);
    }
}
}  // namespace rut
