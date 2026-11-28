#include "rut/runtime/ws_handshake.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_extensions.h"

#include <openssl/rand.h>

namespace rut {
namespace {

constexpr auto kAcceptLength =
    range_int<kWsHandshakeAcceptLength, i64{kWsHandshakeAcceptLength} + 1>{};
constexpr auto kAcceptCapacity = kAcceptLength + range_int<1, 2>{};

bool name_is(Str name, const char* value, u32 length) {
    return name.len == length && http_header_name_eq_ci(name.ptr, name.len, value, length);
}

Str trim_ows(Str value) {
    if (value.ptr == nullptr) return value;
    u32 start = 0;
    u32 end = value.len;
    while (start < end && (value.ptr[start] == ' ' || value.ptr[start] == '\t')) ++start;
    while (end > start && (value.ptr[end - 1] == ' ' || value.ptr[end - 1] == '\t')) --end;
    return value.slice(start, end);
}

int base64_value(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

bool key_is_canonical(Str key) {
    if (key.ptr == nullptr || key.len != 24 || key.ptr[22] != '=' || key.ptr[23] != '=')
        return false;
    for (i32 i = 0; i < 22; i++)
        if (base64_value(key.ptr[i]) < 0) return false;
    return (base64_value(key.ptr[21]) & 0x0f) == 0;
}

bool tchar(u8 c) {
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return true;
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

bool protocol_token_valid(Str token) {
    if (token.ptr == nullptr || token.len == 0) return false;
    for (i64 i = 0; i < token.len; i++)
        if (!tchar(byte_value(token.ptr[i]))) return false;
    return true;
}

[[nodiscard]] bool token_was_offered_before(const ParsedRequest& request,
                                            i64 current_header,
                                            u32 current_start,
                                            Str candidate) {
    for (i64 i = 0; i <= current_header; i++) {
        const Header& header = request.headers[i];
        if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
        u32 start = 0;
        for (;;) {
            u32 end = start;
            while (end < header.value.len && header.value.ptr[end] != ',') end++;
            if (i == current_header && start >= current_start) return false;
            const Str kPrevious = trim_ows(header.value.slice(start, end));
            if (kPrevious.len == candidate.len &&
                __builtin_memcmp(kPrevious.ptr, candidate.ptr, candidate.len) == 0)
                return true;
            if (end == header.value.len) break;
            start = end + 1;
        }
    }
    return false;
}

bool request_protocols_valid(const ParsedRequest& request, u32* out_canonical_len) {
    u32 canonical_len = 0;
    for (i64 i = 0; i < request.header_count; i++) {
        const Header& header = request.headers[i];
        if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
        u32 start = 0;
        for (;;) {
            u32 end = start;
            while (end < header.value.len && header.value.ptr[end] != ',') end++;
            const Str kToken = trim_ows(header.value.slice(start, end));
            if (!protocol_token_valid(kToken) ||
                token_was_offered_before(request, i, start, kToken))
                return false;
            const auto separator = canonical_len == 0 ? range_int<0, 2>::constant<0>()
                                                      : range_int<0, 2>::constant<1>();
            if (!(range_int{canonical_len} + separator + range_int{kToken.len}).to(&canonical_len))
                return false;
            if (end == header.value.len) break;
            start = end + 1;
        }
    }
    if (out_canonical_len != nullptr) *out_canonical_len = canonical_len;
    return true;
}

bool offered_protocol_exists(const u8* storage, u32 offers_len, Str candidate) {
    if (offers_len == 0) return false;
    const u8* offers = storage + kAcceptLength.index();
    i64 start = 0;
    while (start < offers_len) {
        i64 end = start;
        while (end < offers_len && offers[end] != ',') ++end;
        if (end - start == range_int{candidate.len}.to<i64>() &&
            __builtin_memcmp(offers + start, candidate.ptr, candidate.len) == 0)
            return true;
        start = end + 1;
    }
    return false;
}

bool append_request_protocols(const ParsedRequest& request,
                              u8* storage,
                              u32 storage_capacity,
                              u32* out_offers_len) {
    u32 offers_capacity;
    if (!(range_int{storage_capacity} - kAcceptLength).to(&offers_capacity)) return false;
    const auto capacity = range_int{offers_capacity};
    u8* const offers = storage + kAcceptLength.index();
    auto cursor = range_int{u32{0}};
    for (i64 i = 0; i < request.header_count; i++) {
        const Header& header = request.headers[i];
        if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
        const Str kValue = header.value;
        u32 start = 0;
        for (;;) {
            u32 end = start;
            while (end < kValue.len && kValue.ptr[end] != ',') end++;
            const Str kToken = trim_ows(kValue.slice(start, end));
            if (!protocol_token_valid(kToken)) return false;
            const bool needs_separator = cursor.value() != 0;
            const auto separator =
                needs_separator ? range_int<0, 2>::constant<1>() : range_int<0, 2>::constant<0>();
            const auto token_start = cursor + separator;
            const auto next = token_start + range_int{kToken.len};
            decltype(cursor) end_of_token;
            if (!capacity.try_count(next.value(), &end_of_token)) return false;
            if (needs_separator) offers[cursor.index()] = ',';
            __builtin_memcpy(offers + token_start.index(), kToken.ptr, kToken.len);
            cursor = end_of_token;
            if (end == kValue.len) break;
            start = end + 1;
        }
    }
    *out_offers_len = cursor.to<u32>();
    return true;
}

bool encode_accept(Str key, u8* out, u32 out_capacity) {
    static constexpr char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const rut_crypto_span_v1 kParts[] = {{reinterpret_cast<const u8*>(key.ptr), key.len},
                                         {reinterpret_cast<const u8*>(kGuid), sizeof(kGuid) - 1}};
    u8 digest[20];
    u32 digest_len = 0;
    u32 encoded_len = 0;
    return rut_crypto_digest_parts_v1(
               RUT_CRYPTO_SHA1_V1, kParts, 2, nullptr, 0, 0, digest, sizeof(digest), &digest_len) &&
           digest_len == sizeof(digest) && out_capacity >= kAcceptCapacity.to<u32>() &&
           rut_crypto_base64_encode_v1(digest, sizeof(digest), out, out_capacity, &encoded_len) &&
           encoded_len == kWsHandshakeAcceptLength;
}

bool connection_value_is_valid(Str value, bool* has_upgrade) {
    u32 start = 0;
    for (;;) {
        u32 end = start;
        while (end < value.len && value.ptr[end] != ',') end++;
        const Str kItem = trim_ows(value.slice(start, end));
        if (!protocol_token_valid(kItem)) return false;
        if (kItem.len == 7 && http_header_name_eq_ci(kItem.ptr, kItem.len, "upgrade", 7))
            *has_upgrade = true;
        if (end == value.len) return true;
        start = end + 1;
    }
}

bool upgrade_protocol_valid(Str protocol, bool* is_websocket) {
    u32 slash = protocol.len;
    for (u32 i = 0; i < protocol.len; i++) {
        if (protocol.ptr[i] != '/') continue;
        if (slash != protocol.len) return false;
        slash = i;
    }
    const Str kName = protocol.slice(0, slash);
    if (!protocol_token_valid(kName)) return false;
    if (slash != protocol.len) {
        const Str kVersion = protocol.slice(slash + 1, protocol.len);
        if (!protocol_token_valid(kVersion)) return false;
    } else if (kName.len == 9 && http_header_name_eq_ci(kName.ptr, kName.len, "websocket", 9)) {
        *is_websocket = true;
    }
    return true;
}

bool request_upgrade_value_is_valid(Str value, bool* offers_websocket) {
    u32 start = 0;
    for (;;) {
        u32 end = start;
        while (end < value.len && value.ptr[end] != ',') end++;
        const Str kItem = trim_ows(value.slice(start, end));
        if (!upgrade_protocol_valid(kItem, offers_websocket)) return false;
        if (end == value.len) return true;
        start = end + 1;
    }
}

}  // namespace

WsHandshakeRequestResult ws_prepare_h2_handshake(const ParsedRequest& request,
                                                 u8* storage,
                                                 u32 capacity,
                                                 u32* offers_len) {
    if (!offers_len || (storage && capacity < kAcceptCapacity.to<u32>()))
        return WsHandshakeRequestResult::BadRequest;
    *offers_len = 0;
    i32 versions = 0;
    i32 hosts = 0;
    Str version{};
    for (i64 i = 0; i < request.header_count; ++i) {
        const auto& h = request.headers[i];
        if (name_is(h.name, "sec-websocket-version", 21)) {
            versions++;
            version = trim_ows(h.value);
        }
        if (name_is(h.name, "host", 4)) {
            hosts++;
            if (!trim_ows(h.value).len) return WsHandshakeRequestResult::BadRequest;
        }
    }
    if (hosts != 1 || versions != 1 || !request_protocols_valid(request, offers_len) ||
        version.len == 0 || version.len > 3 || (version.len > 1 && version.ptr[0] == '0'))
        return WsHandshakeRequestResult::BadRequest;
    i32 number = 0;
    for (i64 i = 0; i < version.len; ++i) {
        if (version.ptr[i] < '0' || version.ptr[i] > '9')
            return WsHandshakeRequestResult::BadRequest;
        number = number * 10 + (version.ptr[i] - '0');
    }
    if (number > 255) return WsHandshakeRequestResult::BadRequest;
    if (number != 13) return WsHandshakeRequestResult::VersionRequired;
    if (storage && !append_request_protocols(request, storage, capacity, offers_len))
        return WsHandshakeRequestResult::InternalError;
    return WsHandshakeRequestResult::Ready;
}

bool ws_h2_response_matches(const Header* headers, u32 count, const u8* storage, u32 offers_len) {
    if (!storage) return false;
    bool selected = false;
    for (i64 i = 0; i < count; ++i) {
        const auto& h = headers[i];
        if (name_is(h.name, "sec-websocket-accept", 20) ||
            name_is(h.name, "sec-websocket-key", 17) || name_is(h.name, "content-length", 14))
            return false;
        if (!name_is(h.name, "sec-websocket-protocol", 22)) continue;
        const Str kToken = trim_ows(h.value);
        if (selected || !ws_valid_subprotocol(kToken) ||
            !offered_protocol_exists(storage, offers_len, kToken))
            return false;
        selected = true;
    }
    return true;
}

WsHandshakeRequestResult ws_prepare_handshake(const u8* request,
                                              u32 header_len,
                                              u8* storage,
                                              u32 storage_capacity,
                                              u32* out_offers_len,
                                              Str required_subprotocol,
                                              WsDeflateAgreement* downstream_deflate) {
    if (downstream_deflate) *downstream_deflate = {};
    if (request == nullptr || header_len == 0 || header_len > SlicePool::kSliceSize ||
        out_offers_len == nullptr ||
        (storage != nullptr && storage_capacity < kAcceptCapacity.to<u32>()))
        return WsHandshakeRequestResult::BadRequest;
    *out_offers_len = 0;
    HttpParser parser{};
    ParsedRequest parsed{};
    parser.reset();
    if (parser.parse(request, header_len, &parsed) != ParseStatus::Complete ||
        parser.header_end != header_len || parsed.method != HttpMethod::GET ||
        parsed.version != HttpVersion::Http11 || parsed.path.ptr == nullptr ||
        parsed.path.len == 0 || parsed.path.ptr[0] != '/' || !parsed.upgrade ||
        !parsed.has_upgrade_header || !parsed.upgrade_is_websocket || parsed.chunked ||
        parsed.transfer_encoding != RequestTransferEncoding::None ||
        parsed.content_length_count > 1 ||
        (parsed.has_content_length && parsed.content_length != 0))
        return WsHandshakeRequestResult::BadRequest;

    i32 host_count = 0;
    bool connection_upgrade = false;
    bool upgrade_websocket = false;
    i32 key_count = 0;
    i32 version_count = 0;
    Str key{};
    Str version{};
    for (i64 i = 0; i < parsed.header_count; i++) {
        const Header& header = parsed.headers[i];
        if (name_is(header.name, "host", 4)) {
            if (++host_count != 1 || trim_ows(header.value).len == 0)
                return WsHandshakeRequestResult::BadRequest;
        } else if (name_is(header.name, "upgrade", 7)) {
            if (!request_upgrade_value_is_valid(header.value, &upgrade_websocket))
                return WsHandshakeRequestResult::BadRequest;
        } else if (name_is(header.name, "sec-websocket-key", 17)) {
            if (++key_count != 1) return WsHandshakeRequestResult::BadRequest;
            key = trim_ows(header.value);
        } else if (name_is(header.name, "sec-websocket-version", 21)) {
            if (++version_count != 1) return WsHandshakeRequestResult::BadRequest;
            version = trim_ows(header.value);
        } else if (name_is(header.name, "connection", 10)) {
            if (!connection_value_is_valid(header.value, &connection_upgrade))
                return WsHandshakeRequestResult::BadRequest;
        } else if (name_is(header.name, "expect", 6) || name_is(header.name, "te", 2) ||
                   name_is(header.name, "transfer-encoding", 17)) {
            return WsHandshakeRequestResult::BadRequest;
        }
    }
    if (host_count != 1 || !upgrade_websocket || !connection_upgrade || key_count != 1 ||
        version_count != 1 || !key_is_canonical(key) ||
        !request_protocols_valid(parsed, out_offers_len))
        return WsHandshakeRequestResult::BadRequest;
    if (version.len == 0 || version.len > 3 || (version.len > 1 && version.ptr[0] == '0'))
        return WsHandshakeRequestResult::BadRequest;
    i32 version_number = 0;
    for (i64 i = 0; i < version.len; i++)
        if (version.ptr[i] < '0' || version.ptr[i] > '9')
            return WsHandshakeRequestResult::BadRequest;
        else
            version_number = version_number * 10 + (version.ptr[i] - '0');
    if (version_number > 255) return WsHandshakeRequestResult::BadRequest;
    if (version_number != 13) return WsHandshakeRequestResult::VersionRequired;
    if (required_subprotocol.len != 0) {
        if (!ws_valid_subprotocol(required_subprotocol))
            return WsHandshakeRequestResult::BadRequest;
        bool offered = false;
        for (i64 i = 0; i < parsed.header_count; i++) {
            const Header& header = parsed.headers[i];
            if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
            u32 start = 0;
            for (;;) {
                u32 end = start;
                while (end < header.value.len && header.value.ptr[end] != ',') end++;
                offered |= trim_ows(header.value.slice(start, end)).eq(required_subprotocol);
                if (end == header.value.len) break;
                start = end + 1;
            }
        }
        if (!offered) return WsHandshakeRequestResult::BadRequest;
    }
    WsDeflateAgreement selected{};
    if (!ws_select_deflate_offer(parsed.headers, parsed.header_count, &selected))
        return WsHandshakeRequestResult::BadRequest;
    if (downstream_deflate) *downstream_deflate = selected;
    if (storage == nullptr) return WsHandshakeRequestResult::Ready;
    if (!encode_accept(key, storage, storage_capacity))
        return WsHandshakeRequestResult::InternalError;
    if (!append_request_protocols(parsed, storage, storage_capacity, out_offers_len))
        return WsHandshakeRequestResult::BadRequest;
    return WsHandshakeRequestResult::Ready;
}

bool ws_handshake_response_matches(const ParsedResponse& response,
                                   const u8* storage,
                                   u32 offers_len,
                                   Str required_subprotocol,
                                   WsDeflateAgreement* upstream_deflate,
                                   bool opaque_extensions) {
    if (upstream_deflate) *upstream_deflate = {};
    if (storage == nullptr ||
        offers_len >
            (range_int<SlicePool::kSliceSize, i64{SlicePool::kSliceSize} + 1>{} - kAcceptLength)
                .to<u32>() ||
        (required_subprotocol.len != 0 && !ws_valid_subprotocol(required_subprotocol)) ||
        response.header_count > kMaxHeaders || response.version != HttpVersion::Http11 ||
        response.status_code != 101 || response.headers_truncated)
        return false;
    WsDeflateAgreement selected{};
    if (upstream_deflate &&
        !ws_accept_deflate_response(response.headers, response.header_count, &selected))
        return false;
    i32 upgrade_count = 0;
    u32 accept_count = 0;
    u32 protocol_count = 0;
    bool upgrade_ok = false;
    bool connection_upgrade = false;
    bool protocol_ok = required_subprotocol.len == 0;
    for (i64 i = 0; i < response.header_count; i++) {
        const Header& header = response.headers[i];
        if (name_is(header.name, "upgrade", 7)) {
            if (++upgrade_count != 1) return false;
            const Str kValue = trim_ows(header.value);
            upgrade_ok = kValue.len == 9 && http_header_name_eq_ci(kValue.ptr, 9, "websocket", 9);
        } else if (name_is(header.name, "connection", 10)) {
            if (!connection_value_is_valid(header.value, &connection_upgrade)) return false;
        } else if (name_is(header.name, "sec-websocket-extensions", 24)) {
            const Str kValue = trim_ows(header.value);
            if (kValue.len != 0 && !upstream_deflate && !opaque_extensions) return false;
        } else if (name_is(header.name, "sec-websocket-accept", 20)) {
            if (++accept_count != 1) return false;
            const Str kValue = trim_ows(header.value);
            if (kValue.len != kWsHandshakeAcceptLength ||
                !rut_crypto_equal_v1(
                    reinterpret_cast<const u8*>(kValue.ptr), storage, kWsHandshakeAcceptLength))
                return false;
        } else if (name_is(header.name, "sec-websocket-protocol", 22)) {
            if (++protocol_count != 1) return false;
            const Str kValue = trim_ows(header.value);
            protocol_ok = protocol_token_valid(kValue) &&
                          offered_protocol_exists(storage, offers_len, kValue) &&
                          (required_subprotocol.len == 0 || kValue.eq(required_subprotocol));
        }
    }
    const bool kValid =
        upgrade_count == 1 && upgrade_ok && connection_upgrade && accept_count == 1 && protocol_ok;
    if (kValid && upstream_deflate) *upstream_deflate = selected;
    return kValid;
}

u32 ws_build_h1_handshake(const ParsedRequest& request,
                          u8* output,
                          u32 capacity,
                          u8* storage,
                          u32 storage_capacity,
                          u32* offers_len) {
    if (!output || !storage || !offers_len || request.method != HttpMethod::CONNECT ||
        !request.path.len || request.path.ptr[0] != '/')
        return 0;
    u8 nonce[16];
    u8 key[32];
    u32 key_len = 0;
    if (RAND_bytes(nonce, sizeof(nonce)) != 1 ||
        !rut_crypto_base64_encode_v1(nonce, sizeof(nonce), key, sizeof(key), &key_len) ||
        key_len != 24)
        return 0;
    auto used = range_int{u32{0}};
    const auto limit = range_int{capacity};
    auto put = [&](Str text) {
        const auto end = used + range_int{text.len};
        decltype(used) next;
        if (!limit.try_count(end.value(), &next)) return false;
        __builtin_memcpy(output + used.index(), text.ptr, text.len);
        used = next;
        return true;
    };
    if (!put(lit_str("GET ")) || !put(request.path) ||
        !put(lit_str(
            " HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ")) ||
        !put({reinterpret_cast<const char*>(key), key_len}) || !put(lit_str("\r\n")))
        return 0;
    for (i64 i = 0; i < request.header_count; ++i) {
        const auto& h = request.headers[i];
        if (name_is(h.name, "connection", 10) || name_is(h.name, "upgrade", 7) ||
            name_is(h.name, "sec-websocket-key", 17) || name_is(h.name, "sec-websocket-accept", 20))
            continue;
        if (!put(h.name) || !put(lit_str(": ")) || !put(h.value) || !put(lit_str("\r\n"))) return 0;
    }
    if (!put(lit_str("\r\n")) ||
        ws_prepare_handshake(output, used.to<u32>(), storage, storage_capacity, offers_len) !=
            WsHandshakeRequestResult::Ready)
        return 0;
    return used.to<u32>();
}

u32 ws_restrict_subprotocol(u8* request, u32 header_len, u32 total_len, Str required_subprotocol) {
    if (request == nullptr || header_len > total_len || header_len < 4 ||
        total_len > SlicePool::kSliceSize || !ws_valid_subprotocol(required_subprotocol))
        return 0;
    const Str headers{reinterpret_cast<const char*>(request), header_len};
    const auto header_size = range_int{header_len};
    const auto last = (range_int{header_len} - range_int<1, 2>{}).value();
    u32 read = 0;
    i64 write = 0;
    bool selected = false;
    while (read < header_len) {
        u32 end = read;
        while (end < last && (request[end] != '\r' || request[end + 1] != '\n')) ++end;
        if (end >= last) return 0;
        auto next = range_int{end};
        if (!header_size.try_count((next + range_int<2, 3>{}).value(), &next)) return 0;
        u32 colon = read;
        while (colon < end && request[colon] != ':') colon++;
        const bool kIsProtocol =
            colon < end && name_is(headers.slice(read, colon), "sec-websocket-protocol", 22);
        if (kIsProtocol) {
            bool contains = false;
            u32 start = colon + 1;
            while (start < end) {
                u32 stop = start;
                while (stop < end && request[stop] != ',') stop++;
                contains |= trim_ows(headers.slice(start, stop)).eq(required_subprotocol);
                if (stop == end) break;
                start = stop + 1;
            }
            if (!selected && contains) {
                static constexpr char kHeader[] = "Sec-WebSocket-Protocol:";
                constexpr i64 kHeaderBytes = sizeof(kHeader) - 1;
                const auto length = range_int<kHeaderBytes + 2, kHeaderBytes + 3>{} +
                                    range_int{required_subprotocol.len};
                if (length.value() > (next - range_int{read}).value()) return 0;
                __builtin_memcpy(request + write, kHeader, sizeof(kHeader) - 1);
                write += kHeaderBytes;
                __builtin_memcpy(
                    request + write, required_subprotocol.ptr, required_subprotocol.len);
                write += range_int{required_subprotocol.len}.to<i64>();
                request[write] = '\r';
                ++write;
                request[write] = '\n';
                ++write;
                selected = true;
            }
        } else {
            const auto line = headers.slice(read, next.to<u32>());
            __builtin_memmove(request + write, line.ptr, line.len);
            write += range_int{line.len}.to<i64>();
        }
        read = next.to<u32>();
    }
    if (!selected) return 0;
    u32 result;
    u32 trailing;
    if (!range_int{write}.to(&result) ||
        !(range_int{total_len} - range_int{header_len}).to(&trailing))
        return 0;
    __builtin_memmove(request + write, request + range_int{header_len}.index(), trailing);
    return result;
}

}  // namespace rut
