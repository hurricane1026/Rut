#include "rut/runtime/remote_jwks.h"

#include "rut/common/http_header_validation.h"
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
                if (!document.string(n, value) || !value.ok || !value.len) return false;
                address[value.len] = 0;
                if (strlen(address) != value.len) return false;
            }
            fields |= 256;
            continue;
        }
        if (kKey.eq(lit_str("dnsRecordType"))) {
            json::Writer value{document.other};
            if (!document.string(entry, value)) return false;
            const Str type{document.other, value.len};
            next.dns_aaaa = type.eq(lit_str("AAAA"));
            next.dns_dual_stack = type.eq(lit_str("A+AAAA"));
            if (!next.dns_aaaa && !next.dns_dual_stack && !type.eq(lit_str("A"))) return false;
            fields |= 8192;
            continue;
        }
        if (kKey.eq(lit_str("requireNonEmptyKeys"))) {
            if (document.nodes[entry].kind != json::Kind::Boolean) return false;
            next.require_non_empty_keys = document.raw(entry).eq(lit_str("true"));
            continue;
        }
        if (kKey.eq(lit_str("conditionalRequests"))) {
            if (document.nodes[entry].kind != json::Kind::Boolean) return false;
            next.conditional_requests = document.raw(entry).eq(lit_str("true"));
            continue;
        }
        if (kKey.eq(lit_str("conditionalDiscovery"))) {
            if (document.nodes[entry].kind != json::Kind::Boolean) return false;
            next.conditional_discovery = document.raw(entry).eq(lit_str("true"));
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
        } else if (kKey.eq(lit_str("dnsTimeoutSeconds"))) {
            if (value > 60) return false;
            next.dns_timeout_seconds = static_cast<u32>(value);
        } else if (kKey.eq(lit_str("discoveryTimeoutSeconds"))) {
            if (value > 60) return false;
            next.discovery_timeout_seconds = static_cast<u32>(value);
        } else if (kKey.eq(lit_str("discoveryCacheSeconds"))) {
            if (value > 3600) return false;
            next.discovery_cache_seconds = static_cast<u32>(value);
        } else if (kKey.eq(lit_str("dnsCacheSeconds"))) {
            if (value > 3600) return false;
            next.dns_cache_seconds = static_cast<u32>(value);
        } else if (kKey.eq(lit_str("refreshSeconds"))) {
            if (value > 3600) return false;
            next.refresh_seconds = static_cast<u32>(value);
            fields |= 32;
        } else if (kKey.eq(lit_str("retrySeconds"))) {
            if (value > 3600) return false;
            next.retry_seconds = static_cast<u32>(value);
        } else if (kKey.eq(lit_str("maxRetrySeconds"))) {
            if (value > 3600) return false;
            next.max_retry_seconds = static_cast<u32>(value);
        } else if (kKey.eq(lit_str("maxRetryAfterSeconds"))) {
            if (value > 3600) return false;
            next.max_retry_after_seconds = static_cast<u32>(value);
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
    if (!next.retry_seconds) next.retry_seconds = next.refresh_seconds;
    if (next.max_retry_seconds && next.max_retry_seconds < next.retry_seconds) return false;
    if (next.dns_timeout_seconds > next.timeout_seconds ||
        next.discovery_timeout_seconds > next.timeout_seconds)
        return false;
    next.endpoint.tls.enabled = true;
    next.endpoint.allow_ipv6 = true;
    if ((fields & 255) != 255 || !next.endpoint.valid() ||
        next.max_age_seconds <= next.refresh_seconds)
        return false;
    if ((fields & (256 | 512 | 4096 | 8192)) || next.dns_cache_seconds ||
        next.dns_timeout_seconds) {
        sockaddr_storage resolver{};
        if (!(fields & 256) || !(fields & 512) || !next.allowed_count ||
            !platform::ip_socket_address(next.dns_address, next.dns_port, resolver))
            return false;
        bool has_ipv4 = false;
        bool has_ipv6 = false;
        for (u32 i = 0; i < next.allowed_count; ++i) {
            auto& address = next.allowed_addresses[i];
            if (next.dns_aaaa || (next.dns_dual_stack && strchr(address, ':'))) {
                in6_addr ipv6{};
                if (inet_pton(AF_INET6, address, &ipv6) != 1 || IN6_IS_ADDR_V4MAPPED(&ipv6) ||
                    !inet_ntop(AF_INET6, &ipv6, address, sizeof(address)))
                    return false;
                has_ipv6 = true;
            } else {
                in_addr ipv4{};
                if (inet_pton(AF_INET, address, &ipv4) != 1) return false;
                has_ipv4 = true;
            }
            for (u32 j = 0; j < i; ++j)
                if (strcmp(address, next.allowed_addresses[j]) == 0) return false;
        }
        if (next.dns_dual_stack && !(has_ipv4 && has_ipv6)) return false;
    }
    if (next.discovery_cache_seconds > next.max_age_seconds) return false;
    if ((fields & (1024 | 2048)) || next.discovery_timeout_seconds || next.conditional_discovery ||
        next.discovery_cache_seconds) {
        if (!(fields & 1024) || !(fields & 2048) || !discovery_issuer_valid(next.discovery_issuer))
            return false;
        HttpsEndpoint discovery = next.endpoint;
        __builtin_memcpy(discovery.path, next.discovery_path, sizeof(discovery.path));
        if (!discovery.valid()) return false;
    }
    *this = next;
    return true;
}

bool jwks_observe_time(u64& previous_ms, u64 now_ms) {
    const bool kValid = now_ms && now_ms >= previous_ms;
    previous_ms = now_ms;
    return kValid;
}

u64 jwks_refresh_deadline(u64 completed_ms, u32 interval_seconds) {
    const u64 interval_ms = static_cast<u64>(interval_seconds) * 1000;
    return interval_ms > ~u64{0} - completed_ms ? ~u64{0} : completed_ms + interval_ms;
}

u32 JwksRetry::failure(const RemoteJwks& policy, u32 server_hint) {
    const u32 kCap = policy.max_retry_seconds;
    if (!kCap || !local_seconds_) {
        local_seconds_ = policy.retry_seconds;
    } else {
        local_seconds_ = local_seconds_ > kCap / 2 ? kCap : local_seconds_ * 2;
    }
    return server_hint > local_seconds_ ? server_hint : local_seconds_;
}

void JwksValidator::clear() {
    *this = {};
}
bool JwksValidator::bind(Str entity_tag, Str selected_address) {
    clear();
    if (!strong_etag_valid(entity_tag) || !selected_address.ptr || !selected_address.len ||
        selected_address.len >= sizeof(address))
        return false;
    __builtin_memcpy(address, selected_address.ptr, selected_address.len);
    sockaddr_storage parsed{};
    if (strlen(address) != selected_address.len ||
        !platform::ip_socket_address(address, 0, parsed)) {
        clear();
        return false;
    }
    __builtin_memcpy(tag, entity_tag.ptr, entity_tag.len);
    return true;
}
Str JwksValidator::matching(Str selected_address) const {
    if (!tag[0] || !Str{address, static_cast<u32>(strlen(address))}.eq(selected_address)) return {};
    return {tag, static_cast<u32>(strlen(tag))};
}
bool jwks_response_etag(const ParsedResponse& response, Str& entity_tag) {
    entity_tag = {};
    u32 count = 0;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& kHeader = response.headers[i];
        if (!http_header_name_eq_ci(kHeader.name.ptr, kHeader.name.len, "ETag", 4)) continue;
        if (++count > 1 || !strong_etag_valid(kHeader.value)) return false;
        entity_tag = kHeader.value;
    }
    return true;
}
u32 jwks_response_retry_after(const ParsedResponse& response, u32 cap_seconds) {
    if (!cap_seconds || (response.status_code != 429 && response.status_code != 503)) return 0;
    bool seen = false;
    u32 delay = 0;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& kHeader = response.headers[i];
        if (!http_header_name_eq_ci(kHeader.name.ptr, kHeader.name.len, "Retry-After", 11))
            continue;
        const Str kValue = kHeader.value;
        if (seen || !kValue.ptr || !kValue.len || kValue.len > 10 ||
            (kValue.len > 1 && kValue.ptr[0] == '0'))
            return 0;
        seen = true;
        for (u32 j = 0; j < kValue.len; ++j) {
            const char kDigit = kValue.ptr[j];
            if (kDigit < '0' || kDigit > '9') return 0;
            const u32 kNumber = static_cast<u32>(kDigit - '0');
            if (delay > (~u32{0} - kNumber) / 10) return 0;
            delay = delay * 10 + kNumber;
        }
    }
    return delay < cap_seconds ? delay : cap_seconds;
}
bool jwks_cache_fresh(u64 now, u64 last_success, u32 max_age_seconds) {
    return now && last_success && now >= last_success &&
           now - last_success < static_cast<u64>(max_age_seconds) * 1000;
}

namespace {
u16 read16(const u8* data) {
    return static_cast<u16>((data[0] << 8) | data[1]);
}
Str ctext(const char* text) {
    return {text, static_cast<u32>(strlen(text))};
}
// Only previously decoded label boundaries are legal compression targets. This
// cold JWKS profile intentionally rejects arbitrary DNS packet offsets.
bool jwks_dns_name(
    const u8* packet, u32 length, u32& offset, bool (&known)[512], char (&out)[254]) {
    u32 at = offset, used = 0, jumps = 0;
    bool jumped = false;
    for (u32 labels = 0; labels < 128; ++labels) {
        if (at >= length) return false;
        const u32 start = at;
        const u8 count = packet[at++];
        if ((count & 0xc0) == 0xc0) {
            if (at >= length || ++jumps > 16) return false;
            const u32 target = ((count & 63u) << 8) | packet[at++];
            if (target < 12 || target >= start || !known[target]) return false;
            known[start] = true;
            if (!jumped) offset = at;
            jumped = true;
            at = target;
            continue;
        }
        if (count & 0xc0) return false;
        if (!count) {
            if (!used) return false;
            known[start] = true;
            if (!jumped) offset = at;
            out[used] = 0;
            return true;
        }
        if (static_cast<u64>(at) + count > length || used + count + (used ? 1u : 0u) > 253 ||
            packet[at] == '-' || packet[at + count - 1] == '-')
            return false;
        if (used) out[used++] = '.';
        for (u32 i = 0; i < count; ++i) {
            const u8 byte = packet[at++];
            const char value = static_cast<char>(byte >= 'A' && byte <= 'Z' ? byte + 32 : byte);
            if ((value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-')
                return false;
            out[used++] = value;
        }
        known[start] = true;
    }
    return false;
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

bool jwks_dns_answer(Str packet,
                     Str query,
                     const RemoteJwks& configuration,
                     JwksDnsAddresses& addresses) {
    if (!packet.ptr || !query.ptr || query.len < 17 || query.len > 272 || packet.len > 512 ||
        packet.len < query.len)
        return false;
    const auto* bytes = reinterpret_cast<const u8*>(packet.ptr);
    if (memcmp(packet.ptr, query.ptr, 2) != 0 || (read16(bytes + 2) & 0xfa4f) != 0x8000 ||
        read16(bytes + 4) != 1 || read16(bytes + 8) || read16(bytes + 10) ||
        memcmp(packet.ptr + 12, query.ptr + 12, query.len - 12) != 0)
        return false;
    const u32 answers = read16(bytes + 6);
    constexpr u32 kMaxAnswers = 8;
    if (!answers || answers > kMaxAnswers ||
        configuration.allowed_count > RemoteJwks::kMaxDnsAddresses)
        return false;
    const u16 kRecordType = read16(bytes + query.len - 4);
    if (kRecordType != 1 && kRecordType != 28) return false;
    const bool kAaaa = kRecordType == 28;
    if (!configuration.dns_dual_stack && kAaaa != configuration.dns_aaaa) return false;
    bool boundaries[512]{};
    char current[254]{};
    u32 question_end = 12;
    if (!jwks_dns_name(bytes, packet.len, question_end, boundaries, current) ||
        question_end + 4 != query.len || read16(bytes + question_end) != kRecordType ||
        read16(bytes + question_end + 2) != 1)
        return false;
    struct Record {
        char owner[254]{};
        char target[254]{};
        char address[HttpsEndpoint::kAddressCapacity]{};
        u16 type = 0;
        bool used = false;
    };
    Record records[kMaxAnswers]{};
    u32 offset = query.len;
    u32 min_ttl = ~u32{0};
    for (u32 i = 0; i < answers; ++i) {
        auto& record = records[i];
        if (!jwks_dns_name(bytes, packet.len, offset, boundaries, record.owner) ||
            packet.len - offset < 10)
            return false;
        record.type = read16(bytes + offset);
        const u32 ttl =
            (static_cast<u32>(read16(bytes + offset + 4)) << 16) | read16(bytes + offset + 6);
        const u32 size = read16(bytes + offset + 8);
        if (read16(bytes + offset + 2) != 1 || !ttl || (ttl & 0x80000000u)) return false;
        if (ttl < min_ttl) min_ttl = ttl;
        offset += 10;
        if (size > packet.len - offset) return false;
        const u32 end = offset + size;
        if (record.type == 5) {
            if (!jwks_dns_name(bytes, packet.len, offset, boundaries, record.target) ||
                offset != end)
                return false;
        } else if (record.type == kRecordType) {
            const u32 expected_size = kAaaa ? 16 : 4;
            const int family = kAaaa ? AF_INET6 : AF_INET;
            if (size != expected_size ||
                !inet_ntop(family, bytes + offset, record.address, sizeof(record.address)))
                return false;
            bool allowed = false;
            for (u32 n = 0; n < configuration.allowed_count; ++n)
                allowed |= ctext(record.address).eq(ctext(configuration.allowed_addresses[n]));
            if (!allowed) return false;
            offset = end;
        } else {
            return false;
        }
    }
    if (offset != packet.len) return false;
    for (u32 depth = 0; depth <= 4; ++depth) {
        u32 alias = answers;
        JwksDnsAddresses selected;
        for (u32 i = 0; i < answers; ++i) {
            auto& record = records[i];
            if (strcmp(record.owner, current) != 0) continue;
            if (record.used) return false;
            record.used = true;
            if (record.type == 5) {
                if (alias != answers) return false;
                alias = i;
            } else {
                bool duplicate = false;
                for (u32 n = 0; n < selected.count; ++n)
                    duplicate |= strcmp(selected.values[n], record.address) == 0;
                if (!duplicate)
                    __builtin_memcpy(
                        selected.values[selected.count++], record.address, sizeof(record.address));
            }
        }
        if (selected.count) {
            if (alias != answers) return false;
            for (u32 i = 0; i < answers; ++i)
                if (!records[i].used) return false;
            selected.ttl_seconds = min_ttl;
            addresses = selected;
            return true;
        }
        if (alias == answers || depth == 4) return false;
        __builtin_memcpy(current, records[alias].target, sizeof(current));
    }
    return false;
}

JwksFetch::~JwksFetch() {
    cancel();
}
bool JwksFetch::init(const RemoteJwks& configuration) {
    if (initialized_ || state_ == State::Busy ||
        !keys_.init(configuration.endpoint, configuration.max_retry_after_seconds != 0))
        return false;
    if (configuration.discovery_path[0]) {
        HttpsEndpoint endpoint = configuration.endpoint;
        __builtin_memcpy(endpoint.path, configuration.discovery_path, sizeof(endpoint.path));
        if (!discovery_.init(endpoint)) return false;
    }
    configuration_ = configuration;
    initialized_ = true;
    return true;
}
void JwksFetch::finish_attempt() {
    if (dns_fd_ >= 0) ::close(dns_fd_);
    dns_fd_ = -1;
    keys_.cancel();
    discovery_.cancel();
    addresses_ = {};
    address_index_ = 0;
    request_validator_.clear();
    response_validator_.clear();
    sent_validator_ = false;
    sent_discovery_validator_ = false;
    validator_deadline_ = 0;
    retry_after_seconds_ = 0;
    state_ = State::Cancelled;
}
void JwksFetch::clear_dns_cache() {
    cached_addresses_ = {};
    dns_cached_at_ = 0;
    dns_cache_deadline_ = 0;
}
void JwksFetch::cancel() {
    finish_attempt();
    clear_dns_cache();
    discovery_validator_.clear();
    discovery_address_[0] = 0;
    discovery_accepted_at_ = 0;
}
bool JwksFetch::fail() {
    finish_attempt();
    state_ = State::Failed;
    return false;
}
bool JwksFetch::begin_http(u64 now) {
    discovering_ = configuration_.discovery_path[0] != 0;
    if (addresses_.count) {
        const Str kAddress = ctext(addresses_.values[address_index_]);
        if (!keys_.set_address(kAddress) || (discovering_ && !discovery_.set_address(kAddress)))
            return fail();
    }
    if (discovering_ && address_index_ == 0 &&
        jwks_cache_fresh(now, discovery_accepted_at_, configuration_.discovery_cache_seconds) &&
        ctext(discovery_address_).eq(selected_address()))
        discovering_ = false;
    auto& fetch = discovering_ ? discovery_ : keys_;
    return start_http(fetch, now);
}
bool JwksFetch::can_try_next_address(const HttpsFetch& fetch) const {
    return fetch.connect_failed() && address_index_ + 1 < addresses_.count;
}
Str JwksFetch::selected_address() const {
    return addresses_.count ? ctext(addresses_.values[address_index_])
                            : ctext(configuration_.endpoint.address);
}
bool JwksFetch::start_http(HttpsFetch& fetch, u64 now) {
    if (&fetch == &keys_ && configuration_.conditional_requests) {
        const Str kTag = address_index_ == 0 && now < validator_deadline_
                             ? request_validator_.matching(selected_address())
                             : Str{};
        if (!keys_.set_jwks_condition(kTag)) return fail();
        sent_validator_ = kTag.len != 0;
    } else if (&fetch == &discovery_ && configuration_.conditional_discovery) {
        const Str kTag =
            address_index_ == 0 &&
                    jwks_cache_fresh(now, discovery_accepted_at_, configuration_.max_age_seconds)
                ? discovery_validator_.matching(selected_address())
                : Str{};
        if (!discovery_.set_jwks_condition(kTag)) return fail();
        sent_discovery_validator_ = kTag.len != 0;
    }
    u32 stage_timeout = timeout_ - static_cast<u32>(now - started_);
    const u32 kDiscoveryTimeout = configuration_.discovery_timeout_seconds * 1000;
    if (&fetch == &discovery_ && kDiscoveryTimeout && kDiscoveryTimeout < stage_timeout)
        stage_timeout = kDiscoveryTimeout;
    // A synchronous connect error uses the same next-address path as SO_ERROR.
    if (fetch.start(now, stage_timeout) || can_try_next_address(fetch)) return true;
    if (fetch.connect_failed()) clear_dns_cache();
    return fail();
}
bool JwksFetch::start(u64 now,
                      u32 timeout_ms,
                      const JwksValidator* validator,
                      u64 validator_deadline) {
    if (!initialized_ || state_ == State::Busy || !now || !timeout_ms) return false;
    const JwksValidator kSaved = validator ? *validator : JwksValidator{};
    finish_attempt();
    if (configuration_.conditional_requests && validator) {
        request_validator_ = kSaved;
        validator_deadline_ = validator_deadline;
    }
    started_ = now;
    timeout_ = timeout_ms;
    state_ = State::Busy;
    if (!configuration_.dns_address[0]) return begin_http(now);
    if (cached_addresses_.count && now >= dns_cached_at_ && now < dns_cache_deadline_) {
        addresses_ = cached_addresses_;
        return begin_http(now);
    }
    clear_dns_cache();
    __builtin_memset(query_, 0, sizeof(query_));
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
    query_[query_length_++] = 0;
    query_[query_length_++] = 0;
    query_[query_length_++] = 1;
    sockaddr_storage resolver{};
    const socklen_t length =
        platform::ip_socket_address(configuration_.dns_address, configuration_.dns_port, resolver);
    if (!length) return fail();
    dns_fd_ = platform::datagram_socket(resolver.ss_family);
    if (dns_fd_ < 0 ||
        ::connect(dns_fd_, reinterpret_cast<const sockaddr*>(&resolver), length) != 0)
        return fail();
    return send_dns_query(configuration_.dns_aaaa || configuration_.dns_dual_stack);
}
bool JwksFetch::send_dns_query(bool aaaa) {
    if (RAND_bytes(query_, 2) != 1) return fail();
    query_[query_length_ - 3] = aaaa ? 28 : 1;
    if (::send(dns_fd_, query_, query_length_, platform::kSendFlags) != query_length_)
        return fail();
    return true;
}
bool JwksFetch::accept_discovery(u64 now) {
    if (discovery_.status() == 304) {
        ParsedResponse response{};
        Str tag{};
        if (!sent_discovery_validator_ ||
            !jwks_cache_fresh(now, discovery_accepted_at_, configuration_.max_age_seconds) ||
            !discovery_.headers(response) || !jwks_response_etag(response, tag) ||
            !tag.eq(discovery_validator_.matching(selected_address())))
            return false;
        discovery_accepted_at_ = now;
        return true;
    }
    json::Document document;
    if (!jwks_discovery_valid(document, discovery_.body(), configuration_)) return false;
    if (configuration_.conditional_discovery) {
        ParsedResponse response{};
        Str tag{};
        JwksValidator next{};
        if (!discovery_.headers(response) || !jwks_response_etag(response, tag) ||
            (tag.len && !next.bind(tag, selected_address())))
            return false;
        discovery_validator_ = next;
    }
    if (configuration_.discovery_cache_seconds) {
        const Str kAddress = selected_address();
        __builtin_memcpy(discovery_address_, kAddress.ptr, kAddress.len);
        discovery_address_[kAddress.len] = 0;
    }
    if (configuration_.conditional_discovery || configuration_.discovery_cache_seconds)
        discovery_accepted_at_ = now;
    return true;
}
void JwksFetch::advance(u64 now) {
    if (state_ != State::Busy) return;
    if (!now || now < started_ || now < dns_cached_at_ || now < discovery_accepted_at_) {
        cancel();
        state_ = State::Failed;
        return;
    }
    if (now - started_ >= timeout_) {
        (void)fail();
        return;
    }
    if (dns_fd_ >= 0) {
        const u32 kDnsTimeout = configuration_.dns_timeout_seconds * 1000;
        if (kDnsTimeout && now - started_ >= kDnsTimeout) {
            (void)fail();
            return;
        }
        char packet[513];
        const auto count = ::recv(dns_fd_, packet, sizeof(packet), 0);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
        JwksDnsAddresses result;
        if (count <= 0 || !jwks_dns_answer({packet, static_cast<u32>(count)},
                                           {reinterpret_cast<const char*>(query_), query_length_},
                                           configuration_,
                                           result)) {
            (void)fail();
            return;
        }
        if (configuration_.dns_dual_stack && query_[query_length_ - 3] == 28) {
            addresses_ = result;
            (void)send_dns_query(false);
            return;
        }
        if (result.count > RemoteJwks::kMaxDnsAddresses - addresses_.count) {
            (void)fail();
            return;
        }
        for (u32 i = 0; i < result.count; ++i)
            __builtin_memcpy(
                addresses_.values[addresses_.count++], result.values[i], sizeof(result.values[i]));
        if (!addresses_.ttl_seconds || result.ttl_seconds < addresses_.ttl_seconds)
            addresses_.ttl_seconds = result.ttl_seconds;
        ::close(dns_fd_);
        dns_fd_ = -1;
        if (configuration_.dns_cache_seconds) {
            const u32 kTtl = addresses_.ttl_seconds < configuration_.dns_cache_seconds
                                 ? addresses_.ttl_seconds
                                 : configuration_.dns_cache_seconds;
            cached_addresses_ = addresses_;
            dns_cached_at_ = now;
            dns_cache_deadline_ =
                jwks_refresh_deadline(configuration_.dns_dual_stack ? started_ : now, kTtl);
        }
        (void)begin_http(now);
        return;
    }
    auto& fetch = discovering_ ? discovery_ : keys_;
    fetch.advance(now);
    if (fetch.state() == State::Busy) return;
    if (fetch.state() != State::Done) {
        if (can_try_next_address(fetch)) {
            ++address_index_;
            (void)begin_http(now);
        } else {
            if (fetch.connect_failed()) clear_dns_cache();
            (void)fail();
        }
        return;
    }
    if (discovering_) {
        if (!accept_discovery(now)) {
            (void)fail();
            return;
        }
        discovery_.cancel();
        discovering_ = false;
        (void)start_http(keys_, now);
    } else {
        if (keys_.status() == 429 || keys_.status() == 503) {
            ParsedResponse response{};
            const u32 kDelay =
                keys_.headers(response)
                    ? jwks_response_retry_after(response, configuration_.max_retry_after_seconds)
                    : 0;
            (void)fail();
            retry_after_seconds_ = kDelay;
            return;
        }
        if (configuration_.conditional_requests) {
            ParsedResponse response{};
            Str tag{};
            if (!keys_.headers(response) || !jwks_response_etag(response, tag)) {
                (void)fail();
                return;
            }
            if (keys_.status() == 304) {
                if (!sent_validator_ || !tag.eq(ctext(request_validator_.tag))) {
                    (void)fail();
                    return;
                }
            } else if (tag.len) {
                if (!response_validator_.bind(tag, selected_address())) {
                    (void)fail();
                    return;
                }
            }
        }
        state_ = State::Done;
    }
}
}  // namespace rut
