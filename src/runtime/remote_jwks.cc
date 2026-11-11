#include "rut/runtime/remote_jwks.h"

#include "rut/platform/socket.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

namespace rut {
namespace {
bool discovery_issuer_valid(const char* value) {
    const u32 length = static_cast<u32>(strlen(value));
    if (length <= 8 || memcmp(value, "https://", 8) != 0) return false;
    u32 authority_end = 8;
    while (authority_end < length && value[authority_end] != '/') ++authority_end;
    u32 host_end = 8;
    while (host_end < authority_end && value[host_end] != ':') ++host_end;
    if (host_end == 8 || host_end - 8 > 253) return false;
    u32 label = 0;
    for (u32 i = 8; i < host_end; ++i) {
        const char byte = value[i];
        if (byte == '.') {
            if (!label || value[i - 1] == '-') return false;
            label = 0;
        } else {
            if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                  (byte >= '0' && byte <= '9') || byte == '-') ||
                (!label && byte == '-'))
                return false;
            if (++label > 63) return false;
        }
    }
    if (!label || value[host_end - 1] == '-') return false;
    if (host_end < authority_end) {
        u32 port = 0;
        if (host_end + 1 == authority_end) return false;
        for (u32 i = host_end + 1; i < authority_end; ++i) {
            if (value[i] < '0' || value[i] > '9' || port > 6553) return false;
            port = port * 10 + static_cast<u32>(value[i] - '0');
        }
        if (!port || port > 65535) return false;
    }
    const auto hex = [](char byte) {
        return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') ||
               (byte >= 'A' && byte <= 'F');
    };
    for (u32 i = authority_end; i < length; ++i) {
        const char byte = value[i];
        if (byte == '%') {
            if (length - i < 3 || !hex(value[i + 1]) || !hex(value[i + 2])) return false;
            i += 2;
        } else if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                     (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
                     byte == '~' || byte == '!' || byte == '$' || byte == '&' || byte == '\'' ||
                     byte == '(' || byte == ')' || byte == '*' || byte == '+' || byte == ',' ||
                     byte == ';' || byte == '=' || byte == ':' || byte == '@' || byte == '/'))
            return false;
    }
    return true;
}
}  // namespace

bool RemoteJwks::load(json::Document& document, u32 node) {
    *this = {};
    if (!document.valid || node >= document.count) return false;
    RemoteJwks next;
    if (document.nodes[node].kind != json::Kind::Object) return false;
    u32 fields = 0;
    for (u32 entry = document.nodes[node].child; entry != json::kNone;
         entry = document.nodes[entry].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[entry].key, name)) return false;
        const Str kKey{document.scratch, name.len};
        if (kKey.eq(lit_str("allowedAddresses"))) {
            if (document.nodes[entry].kind != json::Kind::Array) return false;
            for (u32 n = document.nodes[entry].child; n != json::kNone;
                 n = document.nodes[n].next) {
                if (next.allowed_count == 8) return false;
                auto& address = next.allowed_addresses[next.allowed_count++];
                json::Writer value{address, sizeof(address) - 1};
                in_addr parsed{};
                if (!document.string(n, value) || !value.ok || !value.len) return false;
                address[value.len] = 0;
                if (strlen(address) != value.len || inet_pton(AF_INET, address, &parsed) != 1)
                    return false;
            }
            fields |= 256;
            continue;
        }
        char* target = nullptr;
        u32 capacity = 0;
        if (kKey.eq(lit_str("address"))) {
            target = next.endpoint.address;
            capacity = sizeof(next.endpoint.address);
            fields |= 1;
        } else if (kKey.eq(lit_str("serverName"))) {
            target = next.endpoint.tls.server_name;
            capacity = sizeof(next.endpoint.tls.server_name);
            fields |= 2;
        } else if (kKey.eq(lit_str("ca"))) {
            target = next.endpoint.tls.ca;
            capacity = sizeof(next.endpoint.tls.ca);
            fields |= 4;
        } else if (kKey.eq(lit_str("path"))) {
            target = next.endpoint.path;
            capacity = sizeof(next.endpoint.path);
            fields |= 8;
        } else if (kKey.eq(lit_str("dnsAddress"))) {
            target = next.dns_address;
            capacity = sizeof(next.dns_address);
            fields |= 512;
        } else if (kKey.eq(lit_str("discoveryPath"))) {
            target = next.discovery_path;
            capacity = sizeof(next.discovery_path);
            fields |= 1024;
        } else if (kKey.eq(lit_str("discoveryIssuer"))) {
            target = next.discovery_issuer;
            capacity = sizeof(next.discovery_issuer);
            fields |= 2048;
        }
        if (target) {
            json::Writer value{target, capacity - 1};
            if (!document.string(entry, value) || !value.ok || !value.len) return false;
            for (u32 i = 0; i < value.len; ++i)
                if (!target[i]) return false;
            target[value.len] = 0;
            continue;
        }
        i64 value = 0;
        if (document.nodes[entry].kind != json::Kind::Number ||
            !json::integer(document.raw(entry), value) || value <= 0)
            return false;
        if (kKey.eq(lit_str("port"))) {
            if (value > 65535) return false;
            next.endpoint.port = static_cast<u16>(value);
            fields |= 16;
        } else if (kKey.eq(lit_str("dnsPort"))) {
            if (value > 65535) return false;
            next.dns_port = static_cast<u16>(value);
            fields |= 4096;
        } else if (kKey.eq(lit_str("refreshSeconds"))) {
            if (value > 3600) return false;
            next.refresh_seconds = static_cast<u32>(value);
            fields |= 32;
        } else if (kKey.eq(lit_str("maxAgeSeconds"))) {
            if (value > 86400) return false;
            next.max_age_seconds = static_cast<u32>(value);
            fields |= 64;
        } else if (kKey.eq(lit_str("timeoutSeconds"))) {
            if (value > 60) return false;
            next.timeout_seconds = static_cast<u32>(value);
            fields |= 128;
        } else
            return false;
    }
    next.endpoint.tls.enabled = true;
    if ((fields & 255) != 255 || !next.endpoint.valid() ||
        next.max_age_seconds <= next.refresh_seconds)
        return false;
    if (fields & (256 | 512 | 4096)) {
        in_addr resolver{};
        if (!(fields & 256) || !(fields & 512) || !next.allowed_count ||
            inet_pton(AF_INET, next.dns_address, &resolver) != 1)
            return false;
    }
    if (fields & (1024 | 2048)) {
        if (!(fields & 1024) || !(fields & 2048) || !discovery_issuer_valid(next.discovery_issuer))
            return false;
        HttpsEndpoint discovery = next.endpoint;
        __builtin_memcpy(discovery.path, next.discovery_path, sizeof(discovery.path));
        if (!discovery.valid()) return false;
    }
    *this = next;
    return true;
}

namespace {
u16 read16(const u8* data) {
    return static_cast<u16>((data[0] << 8) | data[1]);
}
Str ctext(const char* text) {
    return {text, static_cast<u32>(strlen(text))};
}
}  // namespace

bool jwks_discovery_valid(json::Document& document, Str body, const RemoteJwks& configuration) {
    if (!document.parse(body) || document.nodes[0].kind != json::Kind::Object) return false;
    bool issuer = false, uri = false;
    char expected[1400]{};
    const int size = snprintf(expected,
                              sizeof(expected),
                              "https://%s:%u%s",
                              configuration.endpoint.tls.server_name,
                              configuration.endpoint.port,
                              configuration.endpoint.path);
    if (size <= 0 || static_cast<u32>(size) >= sizeof(expected)) return false;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[n].key, key)) return false;
        const Str name{document.scratch, key.len};
        const bool is_issuer = name.eq(lit_str("issuer"));
        const bool is_uri = name.eq(lit_str("jwks_uri"));
        if (!is_issuer && !is_uri) continue;
        json::Writer value{document.other};
        if (!document.string(n, value)) return false;
        const Str text{document.other, value.len};
        if (is_issuer)
            issuer = text.eq(ctext(configuration.discovery_issuer));
        else {
            uri = text.eq({expected, static_cast<u32>(size)});
            if (!uri && configuration.endpoint.port == 443) {
                const int canonical = snprintf(expected,
                                               sizeof(expected),
                                               "https://%s%s",
                                               configuration.endpoint.tls.server_name,
                                               configuration.endpoint.path);
                uri = canonical > 0 && static_cast<u32>(canonical) < sizeof(expected) &&
                      text.eq({expected, static_cast<u32>(canonical)});
            }
        }
    }
    return issuer && uri;
}

bool jwks_dns_answer(Str packet, Str query, const RemoteJwks& configuration, char (&address)[16]) {
    if (!packet.ptr || !query.ptr || query.len < 17 || query.len > 272 || packet.len > 512 ||
        packet.len < query.len)
        return false;
    const auto* bytes = reinterpret_cast<const u8*>(packet.ptr);
    if (memcmp(packet.ptr, query.ptr, 2) != 0 || (read16(bytes + 2) & 0xfa0f) != 0x8000 ||
        read16(bytes + 4) != 1 || read16(bytes + 8) || read16(bytes + 10) ||
        memcmp(packet.ptr + 12, query.ptr + 12, query.len - 12) != 0)
        return false;
    const u32 answers = read16(bytes + 6);
    if (!answers || answers > 8) return false;
    u32 offset = query.len;
    for (u32 i = 0; i < answers; ++i) {
        // This A-only profile permits the echoed owner or compression to that
        // exact question. It never follows CNAME, arbitrary pointers or glue.
        if (packet.len - offset >= 2 && bytes[offset] == 0xc0 && bytes[offset + 1] == 12)
            offset += 2;
        else {
            const u32 name_length = query.len - 16;
            if (packet.len - offset < name_length ||
                memcmp(packet.ptr + offset, query.ptr + 12, name_length) != 0)
                return false;
            offset += name_length;
        }
        if (packet.len - offset < 14 || read16(bytes + offset) != 1 ||
            read16(bytes + offset + 2) != 1 || read16(bytes + offset + 8) != 4 ||
            !(bytes[offset + 4] || bytes[offset + 5] || bytes[offset + 6] || bytes[offset + 7]))
            return false;
        char candidate[16]{};
        if (!inet_ntop(AF_INET, bytes + offset + 10, candidate, sizeof(candidate))) return false;
        bool allowed = false;
        for (u32 n = 0; n < configuration.allowed_count; ++n)
            if (ctext(candidate).eq(ctext(configuration.allowed_addresses[n]))) allowed = true;
        if (!allowed) return false;
        if (!i) __builtin_memcpy(address, candidate, sizeof(candidate));
        offset += 14;
    }
    return offset == packet.len;
}

JwksFetch::~JwksFetch() {
    cancel();
}
bool JwksFetch::init(const RemoteJwks& configuration) {
    configuration_ = configuration;
    if (!keys_.init(configuration.endpoint)) return false;
    if (!configuration.discovery_path[0]) return true;
    HttpsEndpoint endpoint = configuration.endpoint;
    __builtin_memcpy(endpoint.path, configuration.discovery_path, sizeof(endpoint.path));
    return discovery_.init(endpoint);
}
void JwksFetch::cancel() {
    if (dns_fd_ >= 0) ::close(dns_fd_);
    dns_fd_ = -1;
    keys_.cancel();
    discovery_.cancel();
    state_ = State::Cancelled;
}
bool JwksFetch::fail() {
    cancel();
    state_ = State::Failed;
    return false;
}
bool JwksFetch::begin_http(u64 now) {
    discovering_ = configuration_.discovery_path[0] != 0;
    auto& fetch = discovering_ ? discovery_ : keys_;
    return fetch.start(now, timeout_ - static_cast<u32>(now - started_)) || fail();
}
bool JwksFetch::start(u64 now, u32 timeout_ms) {
    if (state_ == State::Busy || !now || !timeout_ms) return false;
    cancel();
    started_ = now;
    timeout_ = timeout_ms;
    state_ = State::Busy;
    if (!configuration_.dns_address[0]) return begin_http(now);
    __builtin_memset(query_, 0, sizeof(query_));
    if (RAND_bytes(query_, 2) != 1) return fail();
    query_[2] = 1;
    query_[5] = 1;
    query_length_ = 12;
    const char* host = configuration_.endpoint.tls.server_name;
    u32 begin = 0;
    for (u32 end = 0;; ++end) {
        if (host[end] && host[end] != '.') continue;
        const u32 length = end - begin;
        if (!length || length > 63 || query_length_ + length + 6 > sizeof(query_)) return fail();
        query_[query_length_++] = static_cast<u8>(length);
        __builtin_memcpy(query_ + query_length_, host + begin, length);
        query_length_ += length;
        if (!host[end]) break;
        begin = end + 1;
    }
    query_[query_length_++] = 0;
    query_[query_length_++] = 0;
    query_[query_length_++] = 1;
    query_[query_length_++] = 0;
    query_[query_length_++] = 1;
    dns_fd_ = platform::prepare_or_close(::socket(AF_INET, SOCK_DGRAM, 0));
    sockaddr_in resolver{};
    resolver.sin_family = AF_INET;
    resolver.sin_port = htons(configuration_.dns_port);
    if (dns_fd_ < 0 || inet_pton(AF_INET, configuration_.dns_address, &resolver.sin_addr) != 1 ||
        ::connect(dns_fd_, reinterpret_cast<const sockaddr*>(&resolver), sizeof(resolver)) != 0 ||
        ::send(dns_fd_, query_, query_length_, platform::kSendFlags) != query_length_)
        return fail();
    return true;
}
void JwksFetch::advance(u64 now) {
    if (state_ != State::Busy) return;
    if (!now || now < started_ || now - started_ >= timeout_) {
        (void)fail();
        return;
    }
    if (dns_fd_ >= 0) {
        char packet[513];
        const auto count = ::recv(dns_fd_, packet, sizeof(packet), 0);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
        char address[16]{};
        if (count <= 0 || !jwks_dns_answer({packet, static_cast<u32>(count)},
                                           {reinterpret_cast<const char*>(query_), query_length_},
                                           configuration_,
                                           address)) {
            (void)fail();
            return;
        }
        ::close(dns_fd_);
        dns_fd_ = -1;
        if (!keys_.set_address(ctext(address)) ||
            (configuration_.discovery_path[0] && !discovery_.set_address(ctext(address))) ||
            !begin_http(now)) {
            (void)fail();
            return;
        }
    }
    auto& fetch = discovering_ ? discovery_ : keys_;
    fetch.advance(now);
    if (fetch.state() == State::Busy) return;
    if (fetch.state() != State::Done) {
        (void)fail();
        return;
    }
    if (discovering_) {
        json::Document document;
        if (!jwks_discovery_valid(document, discovery_.body(), configuration_)) {
            (void)fail();
            return;
        }
        discovery_.cancel();
        discovering_ = false;
        if (!keys_.start(now, timeout_ - static_cast<u32>(now - started_))) (void)fail();
    } else
        state_ = State::Done;
}
}  // namespace rut
