#include "rut/runtime/http_call.h"

#include "rut/common/http_header_validation.h"
#include "rut/runtime/json.h"
#include <new>

#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <time.h>

namespace rut {
namespace {
bool same(Str a, Str b) {
    return http_header_name_eq_ci(a.ptr, a.len, b.ptr, b.len);
}
bool decoded(json::Document& doc, u32 node, char* out, u32 cap, u32& length) {
    json::Writer writer{out, cap};
    if (!doc.string(node, writer) || !writer.ok) return false;
    length = writer.len;
    return true;
}
bool header_allowed(Str name) {
    if (!name.len || name.len > 128 ||
        validate_response_header(name.ptr, name.len, "", 0) != HttpHeaderValidation::Ok)
        return false;
    constexpr Str forbidden[] = {lit_str("Host"),
                                 lit_str("Content-Length"),
                                 lit_str("Transfer-Encoding"),
                                 lit_str("Connection"),
                                 lit_str("Keep-Alive"),
                                 lit_str("Upgrade"),
                                 lit_str("TE"),
                                 lit_str("Trailer"),
                                 lit_str("Proxy-Connection"),
                                 lit_str("Accept-Encoding")};
    for (auto field : forbidden)
        if (same(name, field)) return false;
    return true;
}
bool response_document(HttpsFetch& fetch, HttpCallReply& reply) {
    ParsedResponse response{};
    if (!fetch.headers(response)) return false;
    json::Writer out{reply.document, sizeof(reply.document)};
    char status[4];
    const int size = snprintf(status, sizeof(status), "%u", fetch.status());
    if (size != 3) return false;
    out.text(lit_str("{\"ok\":true,\"status\":"));
    out.text({status, 3});
    out.text(lit_str(",\"headers\":{"));
    bool first = true;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto name = response.headers[i].name;
        bool seen = false;
        for (u32 j = 0; j < i; ++j)
            if (same(name, response.headers[j].name)) seen = true;
        if (seen) continue;
        if (!first) out.put(',');
        first = false;
        char lower[128];
        if (name.len > sizeof(lower)) return false;
        for (u32 j = 0; j < name.len; ++j)
            lower[j] = name.ptr[j] >= 'A' && name.ptr[j] <= 'Z'
                           ? static_cast<char>(name.ptr[j] + ('a' - 'A'))
                           : name.ptr[j];
        if (!json::quote({lower, name.len}, out)) return false;
        out.text(lit_str(":["));
        bool value_first = true;
        for (u32 j = i; j < response.header_count; ++j) {
            if (!same(name, response.headers[j].name)) continue;
            if (!value_first) out.put(',');
            value_first = false;
            if (!json::quote(response.headers[j].value, out)) return false;
        }
        out.put(']');
    }
    out.text(lit_str("},\"body\":"));
    if (!json::quote(fetch.body(), out)) return false;
    out.put('}');
    if (!out.ok) return false;
    reply.length = out.len;
    reply.status = 0;
    return true;
}
}  // namespace

bool http_call_policy(Str configuration, HttpsEndpoint& endpoint) {
    endpoint = {};
    endpoint.tls.enabled = true;
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
        } else if (name.eq(lit_str("serverName"))) {
            bit = 2;
            value = endpoint.tls.server_name;
            cap = sizeof(endpoint.tls.server_name);
        } else if (name.eq(lit_str("caFile"))) {
            bit = 4;
            value = endpoint.tls.ca;
            cap = sizeof(endpoint.tls.ca);
        } else if (name.eq(lit_str("path"))) {
            bit = 8;
            value = endpoint.path;
            cap = sizeof(endpoint.path);
        } else if (name.eq(lit_str("port"))) {
            i64 port = 0;
            if ((seen & 16) || doc.nodes[n].kind != json::Kind::Number ||
                !json::integer(doc.raw(n), port) || port < 1 || port > 65535)
                return false;
            endpoint.port = static_cast<u16>(port);
            seen |= 16;
            continue;
        } else
            return false;
        u32 length = 0;
        if ((seen & bit) || !decoded(doc, n, value, cap - 1, length) || !length) return false;
        for (u32 i = 0; i < length; ++i)
            if (!value[i]) return false;
        value[length] = 0;
        seen |= bit;
    }
    return (seen & 15) == 15 && endpoint.valid();
}

bool http_call_request(const HttpsEndpoint& endpoint, Str input, char* out, u32 cap, u32& length) {
    length = 0;
    if (!endpoint.valid() || !input.ptr || !out || !cap || input.len > json::kMaxBytes)
        return false;
    thread_local json::Document doc;
    if (!doc.parse(input) || doc.nodes[0].kind != json::Kind::Object) return false;
    char method[8]{}, body[4096];
    u32 method_len = 0, body_len = 0, headers = json::kNone, seen = 0;
    for (u32 n = doc.nodes[0].child; n != json::kNone; n = doc.nodes[n].next) {
        json::Writer key{doc.scratch};
        if (!doc.string(doc.nodes[n].key, key)) return false;
        const Str name{doc.scratch, key.len};
        u32 bit = 0;
        if (name.eq(lit_str("method"))) {
            bit = 1;
            if (!decoded(doc, n, method, sizeof(method), method_len)) return false;
        } else if (name.eq(lit_str("headers"))) {
            bit = 2;
            headers = n;
            if (doc.nodes[n].kind != json::Kind::Object) return false;
        } else if (name.eq(lit_str("body"))) {
            bit = 4;
            if (!decoded(doc, n, body, sizeof(body), body_len)) return false;
        } else
            return false;
        if (seen & bit) return false;
        seen |= bit;
    }
    const Str verb{method, method_len};
    constexpr Str methods[] = {lit_str("GET"),
                               lit_str("POST"),
                               lit_str("PUT"),
                               lit_str("PATCH"),
                               lit_str("DELETE"),
                               lit_str("OPTIONS")};
    bool valid = false;
    for (auto allowed : methods)
        if (allowed.eq(verb)) valid = true;
    if (!valid || !(seen & 1)) return false;
    const int prefix = snprintf(out,
                                cap,
                                "%.*s %s HTTP/1.1\r\nHost: %s:%u\r\nAccept-Encoding: "
                                "identity\r\nConnection: close\r\nContent-Length: %u\r\n",
                                static_cast<int>(method_len),
                                method,
                                endpoint.path,
                                endpoint.tls.server_name,
                                endpoint.port,
                                body_len);
    if (prefix <= 0 || static_cast<u32>(prefix) >= cap) return false;
    json::Writer wire{out, cap, static_cast<u32>(prefix)};
    if (headers != json::kNone) {
        char names[16][128]{};
        u32 sizes[16]{}, count = 0;
        for (u32 n = doc.nodes[headers].child; n != json::kNone; n = doc.nodes[n].next) {
            if (count == 16) return false;
            json::Writer key{names[count], 128};
            if (!doc.string(doc.nodes[n].key, key)) return false;
            sizes[count] = key.len;
            const Str name{names[count], sizes[count]};
            if (!header_allowed(name)) return false;
            for (u32 i = 0; i < count; ++i)
                if (same(name, {names[i], sizes[i]})) return false;
            char value[2048];
            u32 size = 0;
            if (!decoded(doc, n, value, sizeof(value), size) ||
                validate_response_header(name.ptr, name.len, value, size) !=
                    HttpHeaderValidation::Ok)
                return false;
            wire.text(name);
            wire.text(lit_str(": "));
            wire.text({value, size});
            wire.text(lit_str("\r\n"));
            ++count;
        }
    }
    wire.text(lit_str("\r\n"));
    wire.text({body, body_len});
    if (!wire.ok) return false;
    length = wire.len;
    return true;
}

core::Expected<void, Error> HttpCallWorker::start() {
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
void HttpCallWorker::stop() {
    if (!started) return;
    __atomic_store_n(&stopping, 1u, __ATOMIC_RELEASE);
    if (pthread_join(thread, nullptr) != 0) __builtin_trap();
    started = false;
    OPENSSL_cleanse(slots, sizeof(Slot) * kCapacity);
    storage.destroy();
    slots = nullptr;
}
void HttpCallWorker::cancel(u32 connection, u64 generation) {
    if (!started) return;
    for (u32 i = 0; i < kCapacity; ++i) {
        auto& slot = slots[i];
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
HttpCallReply HttpCallWorker::call(u32 connection,
                                   u64 generation,
                                   const HttpsEndpoint& endpoint,
                                   Str request,
                                   u64 now,
                                   u32 timeout) {
    HttpCallReply reply;
    if (!started || !generation || !now || !timeout || timeout > 60000) return reply;
    Slot* found = nullptr;
    for (u32 i = 0; i < kCapacity; ++i) {
        auto& slot = slots[i];
        const auto state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
        if (state == Empty || state == Cancelled || slot.connection != connection) continue;
        if (slot.generation == generation)
            found = &slot;
        else
            cancel(connection, slot.generation);
    }
    if (found) {
        if (now < found->started || now - found->started >= found->timeout) {
            cancel(connection, generation);
            reply.status = -2;
            return reply;
        }
        if (__atomic_load_n(&found->state, __ATOMIC_ACQUIRE) == Done) {
            reply = found->reply;
            OPENSSL_cleanse(&found->reply, sizeof(found->reply));
            __atomic_store_n(&found->state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
            return reply;
        }
    } else {
        for (u32 i = 0; i < kCapacity; ++i) {
            auto& slot = slots[i];
            if (__atomic_load_n(&slot.state, __ATOMIC_ACQUIRE) != Empty) continue;
            if (!http_call_request(
                    endpoint, request, slot.request, sizeof(slot.request), slot.length)) {
                OPENSSL_cleanse(slot.request, sizeof(slot.request));
                reply.status = -4;
                return reply;
            }
            slot.endpoint = endpoint;
            slot.connection = connection;
            slot.generation = generation;
            slot.started = now;
            slot.timeout = timeout;
            slot.reply = {};
            found = &slot;
            __atomic_store_n(&slot.state, static_cast<u32>(Queued), __ATOMIC_RELEASE);
            break;
        }
    }
    if (!found) {
        reply.status = -3;
        return reply;
    }
    reply.status = static_cast<i32>(0x80000000u);
    const auto remaining = found->timeout - (now - found->started);
    reply.retry_ms = static_cast<u32>(remaining < 10 ? remaining : 10);
    return reply;
}
void* HttpCallWorker::entry(void* self) {
    static_cast<HttpCallWorker*>(self)->run();
    return nullptr;
}
void HttpCallWorker::run() {
    HttpsFetch fetches[kCapacity];
    const timespec idle{0, 1000000};
    while (!__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        for (u32 i = 0; i < kCapacity; ++i) {
            auto& slot = slots[i];
            auto& fetch = fetches[i];
            const auto state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
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
                if (!fetch.init_callout(slot.endpoint, {slot.request, slot.length}) ||
                    !fetch.start(slot.started, slot.timeout))
                    fetch.cancel();
            }
            fetch.advance(jwt_monotonic_ms());
            if (fetch.state() == HttpsFetch::State::Busy) continue;
            slot.reply = {};
            if (fetch.state() == HttpsFetch::State::Done && !response_document(fetch, slot.reply))
                slot.reply = {};
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
        nanosleep(&idle, nullptr);
    }
}
}  // namespace rut
