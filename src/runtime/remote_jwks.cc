#include "rut/runtime/remote_jwks.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/range_int.h"
#include "rut/platform/socket.h"
#include <new>

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

namespace rut {
namespace {
HttpsEndpoint dns_https_endpoint(const RemoteJwks& policy) {
    HttpsEndpoint endpoint;
    __builtin_memcpy(endpoint.address, policy.dns_address, sizeof(endpoint.address));
    __builtin_memcpy(endpoint.path, policy.dns_https_path, sizeof(endpoint.path));
    endpoint.port = policy.dns_https_port;
    endpoint.tls = policy.dns_tls;
    endpoint.allow_ipv6 = true;
    return endpoint;
}

bool discovery_issuer_valid(const char* value) {
    const u32 length = static_cast<u32>(strlen(value));
    if (length <= 8 || memcmp(value, "https://", 8) != 0) return false;
    u32 authority_end = 8;
    while (authority_end < length && value[authority_end] != '/') ++authority_end;
    u32 host_end = 8;
    while (host_end < authority_end && value[host_end] != ':') ++host_end;
    if (host_end == 8 || i64{host_end} - 8 > 253) return false;
    u32 label = 0;
    for (u32 i = 8; i < host_end; ++i) {
        const char byte = value[i];
        if (byte == '.') {
            if (!label || value[i64{i} - 1] == '-') return false;
            label = 0;
        } else {
            if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                  (byte >= '0' && byte <= '9') || byte == '-') ||
                (!label && byte == '-'))
                return false;
            if (++label > 63) return false;
        }
    }
    if (!label || value[i64{host_end} - 1] == '-') return false;
    if (host_end < authority_end) {
        u32 port = 0;
        if (i64{host_end} + 1 == i64{authority_end}) return false;
        for (u32 i = static_cast<u32>(static_cast<i64>(host_end) + 1); i < authority_end; ++i) {
            if (value[i] < '0' || value[i] > '9' || port > 6553) return false;
            port = static_cast<u32>(static_cast<i64>(port) * 10 + static_cast<i64>(value[i] - '0'));
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
            if (i64{length} - i64{i} < 3 || !hex(value[i64{i} + 1]) || !hex(value[i64{i} + 2]))
                return false;
            i = static_cast<u32>(static_cast<i64>(i) + 2);
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
        if (kKey.eq(lit_str("dnsTransport"))) {
            json::Writer value{document.other};
            if (!document.string(entry, value)) return false;
            const Str transport{document.other, value.len};
            if (transport.eq(lit_str("udp")))
                next.dns_transport = DnsTransport::Udp;
            else if (transport.eq(lit_str("tcp")))
                next.dns_transport = DnsTransport::Tcp;
            else if (transport.eq(lit_str("tls")))
                next.dns_transport = DnsTransport::Tls;
            else if (transport.eq(lit_str("https")))
                next.dns_transport = DnsTransport::Https;
            else
                return false;
            fields |= 262144;
            continue;
        }
        if (kKey.eq(lit_str("requireNonEmptyKeys"))) {
            if (document.nodes[entry].kind != json::Kind::Boolean) return false;
            next.require_non_empty_keys = document.raw(entry).eq(lit_str("true"));
            continue;
        }
        if (kKey.eq(lit_str("admitNewKids"))) {
            if (document.nodes[entry].kind != json::Kind::Boolean) return false;
            next.admit_new_kids = document.raw(entry).eq(lit_str("true"));
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
        } else if (kKey.eq(lit_str("dnsTlsServerName"))) {
            target = next.dns_tls.server_name;
            capacity = sizeof(next.dns_tls.server_name);
            fields |= 524288;
        } else if (kKey.eq(lit_str("dnsTlsCa"))) {
            target = next.dns_tls.ca;
            capacity = sizeof(next.dns_tls.ca);
            fields |= 1048576;
        } else if (kKey.eq(lit_str("dnsHttpsPath"))) {
            target = next.dns_https_path;
            capacity = sizeof(next.dns_https_path);
            fields |= 4194304;
        } else if (kKey.eq(lit_str("discoveryPath"))) {
            target = next.discovery_path;
            capacity = sizeof(next.discovery_path);
            fields |= 1024;
        } else if (kKey.eq(lit_str("discoveryIssuer"))) {
            target = next.discovery_issuer;
            capacity = sizeof(next.discovery_issuer);
            fields |= 2048;
        } else if (kKey.eq(lit_str("discoveryAddress"))) {
            target = next.discovery_endpoint.address;
            capacity = sizeof(next.discovery_endpoint.address);
            fields |= 16384;
        } else if (kKey.eq(lit_str("discoveryServerName"))) {
            target = next.discovery_endpoint.tls.server_name;
            capacity = sizeof(next.discovery_endpoint.tls.server_name);
            fields |= 65536;
        } else if (kKey.eq(lit_str("discoveryCa"))) {
            target = next.discovery_endpoint.tls.ca;
            capacity = sizeof(next.discovery_endpoint.tls.ca);
            fields |= 131072;
        }
        if (target) {
            json::Writer value{target, static_cast<u32>(static_cast<i64>(capacity) - 1)};
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
        } else if (kKey.eq(lit_str("dnsTlsPort"))) {
            if (value > 65535) return false;
            next.dns_tls_port = static_cast<u16>(value);
            fields |= 2097152;
        } else if (kKey.eq(lit_str("dnsHttpsPort"))) {
            if (value > 65535) return false;
            next.dns_https_port = static_cast<u16>(value);
            fields |= 8388608;
        } else if (kKey.eq(lit_str("discoveryPort"))) {
            if (value > 65535) return false;
            next.discovery_endpoint.port = static_cast<u16>(value);
            fields |= 32768;
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
    constexpr u32 kDiscoveryOriginMask = 16384 | 32768 | 65536 | 131072;
    if (fields & kDiscoveryOriginMask) {
        if ((fields & (16384 | 65536 | 131072)) != (16384 | 65536 | 131072)) return false;
        next.discovery_separate = true;
        next.discovery_endpoint.tls.enabled = true;
        next.discovery_endpoint.allow_ipv6 = true;
    } else {
        next.discovery_endpoint = next.endpoint;
    }
    constexpr u32 kDnsTrustMask = 524288 | 1048576;
    constexpr u32 kDnsHttpsMask = 4194304 | 8388608;
    if ((fields & (256 | 512 | 4096 | 8192 | 262144 | kDnsTrustMask | 2097152 | kDnsHttpsMask)) ||
        next.dns_cache_seconds || next.dns_timeout_seconds) {
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
    const bool kDnsHttps = next.dns_transport == DnsTransport::Https;
    const bool kDnsTls = next.dns_transport == DnsTransport::Tls;
    if (kDnsTls || kDnsHttps) {
        if ((fields & kDnsTrustMask) != kDnsTrustMask || (fields & 4096)) return false;
        next.dns_tls.enabled = true;
        if (!valid_upstream_tls(next.dns_tls)) return false;
    } else if (fields & kDnsTrustMask) {
        return false;
    }
    if ((!kDnsTls && (fields & 2097152)) || (!kDnsHttps && (fields & kDnsHttpsMask))) return false;
    if (kDnsHttps && !dns_https_endpoint(next).valid()) return false;
    if (next.discovery_cache_seconds > next.max_age_seconds) return false;
    if ((fields & (1024 | 2048 | kDiscoveryOriginMask)) || next.discovery_timeout_seconds ||
        next.conditional_discovery || next.discovery_cache_seconds) {
        if (!(fields & 1024) || !(fields & 2048) || !discovery_issuer_valid(next.discovery_issuer))
            return false;
        if (next.discovery_separate) {
            __builtin_memcpy(next.discovery_endpoint.path,
                             next.discovery_path,
                             sizeof(next.discovery_endpoint.path));
            if (!next.discovery_endpoint.valid()) return false;
        } else {
            HttpsEndpoint discovery = next.endpoint;
            __builtin_memcpy(discovery.path, next.discovery_path, sizeof(discovery.path));
            if (!discovery.valid()) return false;
            next.discovery_endpoint = discovery;
        }
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
    const u64 interval_ms = range_int(interval_seconds).scaled_by<1000>().to_u64();
    u64 deadline = 0;
    return add_overflow(completed_ms, interval_ms, &deadline) ? ~u64{0} : deadline;
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
            if (static_cast<i64>(delay) >
                (static_cast<i64>(UINT32_MAX) - static_cast<i64>(kNumber)) / 10)
                return 0;
            delay = static_cast<u32>(static_cast<i64>(delay) * 10 + static_cast<i64>(kNumber));
        }
    }
    return delay < cap_seconds ? delay : cap_seconds;
}
[[nodiscard]] bool jwks_cache_fresh(u64 now, u64 last_success, u32 max_age_seconds) {
    if (!now || !last_success || now < last_success) return false;
    const u64 max_age_ms = range_int(max_age_seconds).scaled_by<1000>().to_u64();
    u64 age = 0;
    return !sub_overflow(now, last_success, &age) && age < max_age_ms;
}

namespace {
u16 read16(const u8* data) {
    return (range_int{data[0]}.scaled_by<256>() + range_int{data[1]}).to<u16>();
}
Str ctext(const char* text) {
    return {text, static_cast<u32>(strlen(text))};
}
// Only previously decoded label boundaries are legal compression targets. This
// cold JWKS profile intentionally rejects arbitrary DNS packet offsets.
[[nodiscard]] bool jwks_dns_name(
    const u8* packet, u32 length, u32* offset, bool (&known)[512], char (&out)[254]) {
    const auto wire_size = range_int{length};
    u32 at = *offset, used = 0, jumps = 0, compressed_end = 0;
    auto* output = reinterpret_cast<u8*>(out);
    for (u32 labels = 0; labels < 128; ++labels) {
        if (at >= length) return false;
        const u32 start = at;
        const u32 count = range_int{packet[at++]}.to<u32>();
        if ((count & 0xc0) == 0xc0) {
            if (at >= length || ++jumps > 16) return false;
            const auto high = bounded_remainder<64>(count).scaled_by<256>();
            const u32 target = (high + range_int{packet[at++]}).to<u32>();
            if (target < 12 || target >= start || !known[target]) return false;
            known[start] = true;
            if (compressed_end == 0) compressed_end = at;
            at = target;
            continue;
        }
        if (count & 0xc0) return false;
        if (!count) {
            if (!used) return false;
            known[start] = true;
            *offset = compressed_end == 0 ? at : compressed_end;
            output[used] = 0;
            return true;
        }
        const auto label_size = range_int{count};
        const auto last = range_int{at} + range_int{count - 1};
        const auto expanded_size = range_int{used} + label_size + range_int{u8{used != 0}};
        if (last.value() >= wire_size.value() || expanded_size.value() >= sizeof(out) ||
            packet[at] == '-' || packet[last.index()] == '-')
            return false;
        if (used) output[used++] = '.';
        for (u32 i = 0; i < count; ++i) {
            const u8 byte = packet[at++];
            using Uppercase = range_int<'A', 'Z' + 1>;
            Uppercase upper;
            const u8 value = Uppercase::try_from_u64(byte, &upper)
                                 ? (upper + range_int<'a' - 'A', 'a' - 'A' + 1>{}).to<u8>()
                                 : byte;
            if ((value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-')
                return false;
            output[used++] = value;
        }
        known[start] = true;
    }
    return false;
}
enum class DnsTransfer { Blocked, Partial, Complete, Error };

template <bool Write, typename Byte, size_t Capacity>
[[nodiscard]] DnsTransfer dns_transfer(
    int fd, SSL* ssl, Byte (&buffer)[Capacity], u32 target, u32* offset) {
    using Count = range_int<0, Capacity + 1>;
    Count limit, remaining;
    const auto cursor = range_int{*offset};
    if (!Count::try_from_u64(target, &limit) ||
        !limit.try_count((limit - cursor).value(), &remaining) || remaining.value() == 0)
        return DnsTransfer::Error;
    Byte* const data = buffer + cursor.index();
    i64 transferred;
    if (ssl) {
        ERR_clear_error();
        const int n = Write ? SSL_write(ssl, data, remaining.template to<i32>())
                            : SSL_read(ssl, data, remaining.template to<i32>());
        if (n <= 0) {
            const int error = SSL_get_error(ssl, n);
            return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE
                       ? DnsTransfer::Blocked
                       : DnsTransfer::Error;
        }
        transferred = range_int{n}.to<i64>();
    } else {
        transferred = Write ? ::send(fd, data, remaining.to_u64(), platform::kSendFlags)
                            : ::recv(fd, data, remaining.to_u64(), 0);
        if (transferred < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return DnsTransfer::Blocked;
    }
    Count bytes, end;
    if (transferred <= 0 || !remaining.try_count(transferred, &bytes) ||
        !limit.try_count((cursor + bytes).value(), &end))
        return DnsTransfer::Error;
    *offset = end.template to<u32>();
    return end.value() == limit.value() ? DnsTransfer::Complete : DnsTransfer::Partial;
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
    if (!packet.ptr || !query.ptr || query.len < 17 || query.len > 272 ||
        packet.len > kJwksDnsMessageLimit || packet.len < query.len)
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
    const u16 kRecordType = read16(bytes + range_int{query.len - 4}.index());
    if (kRecordType != 1 && kRecordType != 28) return false;
    const bool kAaaa = kRecordType == 28;
    if (!configuration.dns_dual_stack && kAaaa != configuration.dns_aaaa) return false;
    bool boundaries[512]{};
    char current[254]{};
    u32 question_end = 12;
    if (!jwks_dns_name(bytes, packet.len, &question_end, boundaries, current) ||
        question_end != query.len - 4)
        return false;
    const u8* question_tail = bytes + range_int{question_end}.index();
    if (read16(question_tail) != kRecordType || read16(question_tail + 2) != 1) return false;
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
    const auto wire_size = range_int{packet.len};
    for (u32 i = 0; i < answers; ++i) {
        auto& record = records[i];
        if (!jwks_dns_name(bytes, packet.len, &offset, boundaries, record.owner)) return false;
        const auto cursor = range_int{offset};
        auto record_data = cursor;
        if (!wire_size.try_count((cursor + range_int<10, 11>{}).value(), &record_data))
            return false;
        const u8* fields = bytes + cursor.index();
        record.type = read16(fields);
        const u32 ttl =
            (range_int{read16(fields + 4)}.scaled_by<65536>() + range_int{read16(fields + 6)})
                .to<u32>();
        const u32 size = read16(fields + 8);
        if (read16(fields + 2) != 1 || !ttl || (ttl & 0x80000000u)) return false;
        if (ttl < min_ttl) min_ttl = ttl;
        offset = record_data.to<u32>();
        auto end = record_data;
        if (!wire_size.try_count((record_data + range_int{size}).value(), &end)) return false;
        if (record.type == 5) {
            if (!jwks_dns_name(bytes, packet.len, &offset, boundaries, record.target) ||
                offset != end.value())
                return false;
        } else if (record.type == kRecordType) {
            const u32 expected_size = kAaaa ? 16 : 4;
            const int family = kAaaa ? AF_INET6 : AF_INET;
            if (size != expected_size ||
                !inet_ntop(
                    family, bytes + record_data.index(), record.address, sizeof(record.address)))
                return false;
            bool allowed = false;
            for (u32 n = 0; n < configuration.allowed_count; ++n)
                allowed |= ctext(record.address).eq(ctext(configuration.allowed_addresses[n]));
            if (!allowed) return false;
            offset = end.to<u32>();
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
    if (dns_https_) dns_https_->~HttpsFetch();
    dns_https_arena_.destroy();
    destroy_tls_client_context(dns_tls_context_);
}
bool JwksFetch::init(const RemoteJwks& configuration) {
    if (initialized_ || state_ == State::Busy ||
        !keys_.init(configuration.endpoint, configuration.max_retry_after_seconds != 0))
        return false;
    if (configuration.dns_transport == RemoteJwks::DnsTransport::Tls &&
        !init_tls_client_context(dns_tls_context_, configuration.dns_tls, false, false))
        return false;
    if (configuration.discovery_path[0]) {
        HttpsEndpoint endpoint = configuration.discovery_endpoint;
        if (!configuration.discovery_separate) {
            endpoint = configuration.endpoint;
            __builtin_memcpy(endpoint.path, configuration.discovery_path, sizeof(endpoint.path));
        }
        if (!discovery_.init(endpoint)) return false;
    }
    if (configuration.dns_transport == RemoteJwks::DnsTransport::Https) {
        // Allocate the extra HTTP buffers only for activated DoH policies.
        constexpr i64 kArenaSize = i64{sizeof(HttpsFetch)} + i64{MmapArena::Block::kHeaderSize};
        if (!dns_https_arena_.init(u64{kArenaSize})) return false;
        dns_https_ = dns_https_arena_.alloc_t<HttpsFetch>();
        if (!dns_https_ || !dns_https_->init_dns(dns_https_endpoint(configuration))) {
            if (dns_https_) dns_https_->~HttpsFetch();
            dns_https_ = nullptr;
            dns_https_arena_.destroy();
            return false;
        }
    }
    configuration_ = configuration;
    initialized_ = true;
    return true;
}
void JwksFetch::close_dns() {
    if (dns_https_) dns_https_->cancel();
    if (dns_ssl_) SSL_free(dns_ssl_);
    dns_ssl_ = nullptr;
    if (dns_fd_ >= 0) ::close(dns_fd_);
    dns_fd_ = -1;
    dns_step_ = DnsStep::None;
    dns_out_len_ = 0;
    dns_out_sent_ = 0;
    dns_length_have_ = 0;
    dns_in_len_ = 0;
    dns_in_expected_ = 0;
}
void JwksFetch::finish_attempt() {
    close_dns();
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
void JwksFetch::mark_failed() {
    finish_attempt();
    state_ = State::Failed;
}
bool JwksFetch::fail() {
    mark_failed();
    return false;
}
bool JwksFetch::begin_http(u64 now) {
    discovering_ = configuration_.discovery_path[0] != 0;
    if (addresses_.count) {
        const Str kAddress = ctext(addresses_.values[address_index_]);
        if (!keys_.set_address(kAddress) || (discovering_ && !configuration_.discovery_separate &&
                                             !discovery_.set_address(kAddress)))
            return fail();
    }
    if (discovering_ && address_index_ == 0 &&
        jwks_cache_fresh(now, discovery_accepted_at_, configuration_.discovery_cache_seconds) &&
        ctext(discovery_address_).eq(discovery_selected_address()))
        discovering_ = false;
    auto& fetch = discovering_ ? discovery_ : keys_;
    return start_http(fetch, now);
}
bool JwksFetch::can_try_next_address(const HttpsFetch& fetch) const {
    if (&fetch == &discovery_ && configuration_.discovery_separate) return false;
    return fetch.connect_failed() && i64{address_index_} + 1 < i64{addresses_.count};
}
Str JwksFetch::selected_address() const {
    return addresses_.count ? ctext(addresses_.values[address_index_])
                            : ctext(configuration_.endpoint.address);
}
Str JwksFetch::discovery_selected_address() const {
    return configuration_.discovery_separate ? ctext(configuration_.discovery_endpoint.address)
                                             : selected_address();
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
                ? discovery_validator_.matching(discovery_selected_address())
                : Str{};
        if (!discovery_.set_jwks_condition(kTag)) return fail();
        sent_discovery_validator_ = kTag.len != 0;
    }
    u64 elapsed = 0;
    u32 stage_timeout;
    if (sub_overflow(now, started_, &elapsed) || sub_overflow(timeout_, elapsed, &stage_timeout) ||
        stage_timeout == 0)
        return fail();
    constexpr auto kMaxTimeout = range_int<UINT32_MAX, i64{UINT32_MAX} + 1>{};
    const u32 kDiscoveryTimeout = range_int(configuration_.discovery_timeout_seconds)
                                      .scaled_by<1000>()
                                      .min(kMaxTimeout)
                                      .to<u32>();
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
    using QueryLength = range_int<0, sizeof(query_) + 1>;
    u32 begin = 0;
    for (u32 end = 0;; ++end) {
        if (host[end] && host[end] != '.') continue;
        using LabelLength = range_int<1, 64>;
        LabelLength label;
        QueryLength next;
        const auto cursor = range_int{query_length_};
        const auto label_start = cursor + range_int<1, 2>{};
        if (!LabelLength::try_from_i64((range_int{end} - range_int{begin}).value(), &label) ||
            !QueryLength::try_from_i64((label_start + label).value(), &next) ||
            (next + range_int<5, 6>{}).value() > sizeof(query_))
            return fail();
        query_[cursor.index()] = label.to<u8>();
        __builtin_memcpy(
            query_ + label_start.index(), host + range_int{begin}.index(), label.to_u64());
        query_length_ = next.to<u32>();
        if (!host[end]) break;
        begin = end + 1;
    }
    query_[query_length_++] = 0;
    query_[query_length_++] = 0;
    query_[query_length_++] = 0;
    query_[query_length_++] = 0;
    query_[query_length_++] = 1;
    if (configuration_.dns_transport == RemoteJwks::DnsTransport::Udp) {
        sockaddr_storage resolver{};
        const socklen_t length = platform::ip_socket_address(
            configuration_.dns_address, configuration_.dns_port, resolver);
        if (!length) return fail();
        dns_fd_ = platform::datagram_socket(resolver.ss_family);
        if (dns_fd_ < 0 ||
            ::connect(dns_fd_, reinterpret_cast<const sockaddr*>(&resolver), length) != 0)
            return fail();
    }
    return send_dns_query(configuration_.dns_aaaa || configuration_.dns_dual_stack, now);
}
bool JwksFetch::begin_dns_tls() {
    auto ssl = create_tls_client_ssl(dns_tls_context_, dns_fd_, configuration_.dns_tls.server_name);
    if (!ssl) return false;
    dns_ssl_ = ssl.value();
    dns_step_ = DnsStep::TlsHandshake;
    return true;
}
bool JwksFetch::send_dns_query(bool aaaa, u64 now) {
    using QueryLength = range_int<17, sizeof(query_) + 1>;
    QueryLength query_size;
    if (!QueryLength::try_from_u64(query_length_, &query_size)) return fail();
    query_[(query_size - range_int<3, 4>{}).index()] = aaaa ? 28 : 1;
    if (dns_https_) {
        const Str kQuery{reinterpret_cast<const char*>(query_), query_length_};
        if (!dns_https_->set_dns_query(kQuery) || !dns_https_->start(now, timeout_)) return fail();
        return true;
    }
    if (RAND_bytes(query_, 2) != 1) return fail();
    if (configuration_.dns_transport == RemoteJwks::DnsTransport::Udp) {
        if (::send(dns_fd_, query_, query_length_, platform::kSendFlags) != query_length_)
            return fail();
        return true;
    }
    close_dns();
    sockaddr_storage resolver{};
    const u16 kDnsPort = configuration_.dns_transport == RemoteJwks::DnsTransport::Tls
                             ? configuration_.dns_tls_port
                             : configuration_.dns_port;
    const socklen_t length =
        platform::ip_socket_address(configuration_.dns_address, kDnsPort, resolver);
    if (!length) return fail();
    dns_fd_ = platform::stream_socket(resolver.ss_family);
    if (dns_fd_ < 0) return fail();
    const int kConnected = ::connect(dns_fd_, reinterpret_cast<const sockaddr*>(&resolver), length);
    if (kConnected != 0 && errno != EINPROGRESS) return fail();
    const auto out_length = query_size + range_int<2, 3>{};
    static_assert(sizeof(query_) + 2 == sizeof(dns_out_));
    dns_out_len_ = out_length.to<u32>();
    auto* frame = reinterpret_cast<u8*>(dns_out_);
    frame[0] = query_size.divided_by<256>().to<u8>();
    frame[1] = bounded_remainder<256>(query_size.to_u64()).to<u8>();
    __builtin_memcpy(frame + 2, query_, query_size.to_u64());
    dns_out_sent_ = 0;
    if (kConnected != 0) {
        dns_step_ = DnsStep::Connect;
        return true;
    }
    if (configuration_.dns_transport == RemoteJwks::DnsTransport::Tls) return begin_dns_tls();
    dns_step_ = DnsStep::Write;
    return true;
}
bool JwksFetch::advance_dns_datagram(u64 now) {
    char packet[513];
    const auto count = ::recv(dns_fd_, packet, sizeof(packet), 0);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return true;
    JwksDnsAddresses result;
    using PacketLength = range_int<1, sizeof(packet) + 1>;
    PacketLength packet_length;
    if (!PacketLength::try_from_i64(count, &packet_length) ||
        !jwks_dns_answer({packet, packet_length.to<u32>()},
                         {reinterpret_cast<const char*>(query_), query_length_},
                         configuration_,
                         result))
        return false;
    return accept_dns_result(result, now);
}
bool JwksFetch::advance_dns_stream(u64 now) {
    for (u32 i = 0; i < 16 && dns_step_ != DnsStep::None; ++i) {
        if (dns_step_ == DnsStep::Connect) {
            pollfd ready{dns_fd_, POLLOUT, 0};
            const int kReady = poll(&ready, 1, 0);
            if (kReady < 0) {
                if (errno == EINTR) return true;
                return false;
            }
            if (!kReady) return true;
            int error = 0;
            socklen_t length = sizeof(error);
            if (getsockopt(dns_fd_, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error)
                return false;
            if (configuration_.dns_transport == RemoteJwks::DnsTransport::Tls) {
                if (!begin_dns_tls()) return false;
            } else {
                dns_step_ = DnsStep::Write;
            }
            continue;
        }
        if (dns_step_ == DnsStep::TlsHandshake) {
            ERR_clear_error();
            const int kResult = SSL_connect(dns_ssl_);
            if (kResult != 1) {
                const int kError = SSL_get_error(dns_ssl_, kResult);
                if (kError == SSL_ERROR_WANT_READ || kError == SSL_ERROR_WANT_WRITE) return true;
                return false;
            }
            if (SSL_get_verify_result(dns_ssl_) != X509_V_OK) return false;
            dns_step_ = DnsStep::Write;
            continue;
        }
        if (dns_step_ == DnsStep::Write) {
            const auto status =
                dns_transfer<true>(dns_fd_, dns_ssl_, dns_out_, dns_out_len_, &dns_out_sent_);
            if (status == DnsTransfer::Error) return false;
            if (status == DnsTransfer::Blocked) return true;
            if (status == DnsTransfer::Complete) dns_step_ = DnsStep::ReadLength;
            continue;
        }
        if (dns_step_ == DnsStep::ReadLength) {
            const auto status = dns_transfer<false>(
                dns_fd_, dns_ssl_, dns_length_, sizeof(dns_length_), &dns_length_have_);
            if (status == DnsTransfer::Error) return false;
            if (status == DnsTransfer::Blocked) return true;
            if (status == DnsTransfer::Partial) continue;
            const u32 expected = range_int{read16(dns_length_)}.to<u32>();
            if (expected < 12 || expected > sizeof(dns_in_)) return false;
            dns_in_expected_ = expected;
            dns_in_len_ = 0;
            dns_step_ = DnsStep::ReadBody;
            continue;
        }
        const auto status =
            dns_transfer<false>(dns_fd_, dns_ssl_, dns_in_, dns_in_expected_, &dns_in_len_);
        if (status == DnsTransfer::Error) return false;
        if (status == DnsTransfer::Blocked) return true;
        if (status == DnsTransfer::Partial) continue;
        JwksDnsAddresses result;
        if (!jwks_dns_answer({dns_in_, dns_in_len_},
                             {reinterpret_cast<const char*>(query_), query_length_},
                             configuration_,
                             result))
            return false;
        return accept_dns_result(result, now);
    }
    return true;
}
bool JwksFetch::advance_dns_https(u64 now) {
    dns_https_->advance(now);
    if (dns_https_->state() == State::Busy) return true;
    JwksDnsAddresses result;
    const Str kQuery{reinterpret_cast<const char*>(query_), query_length_};
    ParsedResponse response{};
    if (dns_https_->state() != State::Done || !dns_https_->headers(response) ||
        !jwks_dns_answer(dns_https_->body(), kQuery, configuration_, result))
        return false;

    // RFC 8484: an HTTP cache's age consumes the DNS record lifetime.
    bool seen_age = false;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& header = response.headers[i];
        if (!http_header_name_eq_ci(header.name.ptr, header.name.len, "Age", 3)) continue;
        if (seen_age || !header.value.len || header.value.len > 10) return false;
        u32 age = 0;
        for (u32 j = 0; j < header.value.len; ++j) {
            using Digit = range_int<0, 10>;
            Digit digit;
            const auto byte = range_int{byte_value(header.value.ptr[j])};
            if (!Digit::try_from_i64((byte - range_int<'0', '0' + 1>{}).value(), &digit) ||
                !(range_int{age}.scaled_by<10>() + digit).to(&age))
                return false;
        }
        if (age && age >= result.ttl_seconds) return false;
        if (!(range_int{result.ttl_seconds} - range_int{age}).to(&result.ttl_seconds)) return false;
        seen_age = true;
    }
    return accept_dns_result(result, now);
}
bool JwksFetch::accept_dns_result(const JwksDnsAddresses& result, u64 now) {
    if (configuration_.dns_dual_stack) {
        using QueryLength = range_int<17, sizeof(query_) + 1>;
        QueryLength query_size;
        if (!QueryLength::try_from_u64(query_length_, &query_size)) return false;
        if (query_[(query_size - range_int<3, 4>{}).index()] == 28) {
            addresses_ = result;
            return send_dns_query(false, now);
        }
    }
    if ((range_int{addresses_.count} + range_int{result.count}).value() >
        RemoteJwks::kMaxDnsAddresses)
        return false;
    if (!addresses_.count || result.ttl_seconds < addresses_.ttl_seconds)
        addresses_.ttl_seconds = result.ttl_seconds;
    for (u32 i = 0; i < result.count; ++i)
        __builtin_memcpy(
            addresses_.values[addresses_.count++], result.values[i], sizeof(result.values[i]));
    close_dns();
    if (configuration_.dns_cache_seconds) {
        const u32 kTtl = addresses_.ttl_seconds < configuration_.dns_cache_seconds
                             ? addresses_.ttl_seconds
                             : configuration_.dns_cache_seconds;
        cached_addresses_ = addresses_;
        dns_cached_at_ = now;
        dns_cache_deadline_ =
            jwks_refresh_deadline(configuration_.dns_dual_stack ? started_ : now, kTtl);
    }
    return begin_http(now);
}
bool JwksFetch::accept_discovery(u64 now) {
    if (discovery_.status() == 304) {
        ParsedResponse response{};
        Str tag{};
        if (!sent_discovery_validator_ ||
            !jwks_cache_fresh(now, discovery_accepted_at_, configuration_.max_age_seconds) ||
            !discovery_.headers(response) || !jwks_response_etag(response, tag) ||
            !tag.eq(discovery_validator_.matching(discovery_selected_address())))
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
            (tag.len && !next.bind(tag, discovery_selected_address())))
            return false;
        discovery_validator_ = next;
    }
    if (configuration_.discovery_cache_seconds) {
        const Str kAddress = discovery_selected_address();
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
    u64 elapsed = 0;
    if (sub_overflow(now, started_, &elapsed) || elapsed >= timeout_) {
        mark_failed();
        return;
    }
    const bool kDnsHttpsActive = dns_https_ && dns_https_->state() == State::Busy;
    const bool kDnsActive = kDnsHttpsActive || dns_step_ != DnsStep::None || dns_fd_ >= 0;
    if (kDnsActive) {
        constexpr auto kMaxTimeout = range_int<UINT32_MAX, i64{UINT32_MAX} + 1>{};
        const u32 kDnsTimeout = range_int(configuration_.dns_timeout_seconds)
                                    .scaled_by<1000>()
                                    .min(kMaxTimeout)
                                    .to<u32>();
        if (kDnsTimeout && elapsed >= kDnsTimeout) {
            mark_failed();
            return;
        }
        bool dns_ok;
        if (kDnsHttpsActive)
            dns_ok = advance_dns_https(now);
        else if (dns_step_ != DnsStep::None)
            dns_ok = advance_dns_stream(now);
        else
            dns_ok = advance_dns_datagram(now);
        if (!dns_ok && state_ == State::Busy) mark_failed();
        return;
    }
    auto& fetch = discovering_ ? discovery_ : keys_;
    fetch.advance(now);
    if (fetch.state() == State::Busy) return;
    if (fetch.state() != State::Done) {
        if (can_try_next_address(fetch)) {
            ++address_index_;
            if (!begin_http(now)) return;
        } else {
            if (fetch.connect_failed()) clear_dns_cache();
            mark_failed();
        }
        return;
    }
    if (discovering_) {
        if (!accept_discovery(now)) {
            mark_failed();
            return;
        }
        discovery_.cancel();
        discovering_ = false;
        if (!start_http(keys_, now)) return;
    } else {
        if (keys_.status() == 429 || keys_.status() == 503) {
            ParsedResponse response{};
            const u32 kDelay =
                keys_.headers(response)
                    ? jwks_response_retry_after(response, configuration_.max_retry_after_seconds)
                    : 0;
            mark_failed();
            retry_after_seconds_ = kDelay;
            return;
        }
        if (configuration_.conditional_requests) {
            ParsedResponse response{};
            Str tag{};
            if (!keys_.headers(response) || !jwks_response_etag(response, tag)) {
                mark_failed();
                return;
            }
            if (keys_.status() == 304) {
                if (!sent_validator_ || !tag.eq(ctext(request_validator_.tag))) {
                    mark_failed();
                    return;
                }
            } else if (tag.len) {
                if (!response_validator_.bind(tag, selected_address())) {
                    mark_failed();
                    return;
                }
            }
        }
        state_ = State::Done;
    }
}
}  // namespace rut
