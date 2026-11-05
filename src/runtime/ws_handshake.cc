#include "rut/runtime/ws_handshake.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_extensions.h"

namespace rut {
namespace {

bool name_is(Str name, const char* value, u32 length) {
    return name.len == length && http_header_name_eq_ci(name.ptr, name.len, value, length);
}

Str trim_ows(Str value) {
    if (value.ptr == nullptr) return value;
    u32 start = 0;
    u32 end = value.len;
    while (start < end && (value.ptr[start] == ' ' || value.ptr[start] == '\t')) start++;
    while (end > start && (value.ptr[end - 1] == ' ' || value.ptr[end - 1] == '\t')) end--;
    return {value.ptr + start, end - start};
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
    for (u32 i = 0; i < 22; i++)
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
    for (u32 i = 0; i < token.len; i++)
        if (!tchar(static_cast<u8>(token.ptr[i]))) return false;
    return true;
}

bool token_was_offered_before(const ParsedRequest& request,
                              u32 current_header,
                              u32 current_start,
                              Str candidate) {
    for (u32 i = 0; i <= current_header; i++) {
        const Header& header = request.headers[i];
        if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
        u32 start = 0;
        for (;;) {
            u32 end = start;
            while (end < header.value.len && header.value.ptr[end] != ',') end++;
            if (i == current_header && start >= current_start) return false;
            const Str kPrevious = trim_ows({header.value.ptr + start, end - start});
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
    for (u32 i = 0; i < request.header_count; i++) {
        const Header& header = request.headers[i];
        if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
        u32 start = 0;
        for (;;) {
            u32 end = start;
            while (end < header.value.len && header.value.ptr[end] != ',') end++;
            const Str kToken = trim_ows({header.value.ptr + start, end - start});
            if (!protocol_token_valid(kToken) ||
                token_was_offered_before(request, i, start, kToken))
                return false;
            const u32 kSeparator = canonical_len == 0 ? 0u : 1u;
            if (kToken.len > 0xffffffffu - canonical_len - kSeparator) return false;
            canonical_len += kSeparator + kToken.len;
            if (end == header.value.len) break;
            start = end + 1;
        }
    }
    if (out_canonical_len != nullptr) *out_canonical_len = canonical_len;
    return true;
}

bool offered_protocol_exists(const u8* storage, u32 offers_len, Str candidate) {
    u32 start = 0;
    while (start < offers_len) {
        u32 end = start;
        while (end < offers_len && storage[kWsHandshakeAcceptLength + end] != ',') end++;
        if (end - start == candidate.len &&
            __builtin_memcmp(
                storage + kWsHandshakeAcceptLength + start, candidate.ptr, candidate.len) == 0)
            return true;
        start = end + 1;
    }
    return false;
}

bool append_request_protocols(const ParsedRequest& request,
                              u8* storage,
                              u32 storage_capacity,
                              u32* out_offers_len) {
    u32 out = 0;
    for (u32 i = 0; i < request.header_count; i++) {
        const Header& header = request.headers[i];
        if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
        const Str kValue = header.value;
        u32 start = 0;
        for (;;) {
            u32 end = start;
            while (end < kValue.len && kValue.ptr[end] != ',') end++;
            const Str kToken = trim_ows({kValue.ptr + start, end - start});
            if (!protocol_token_valid(kToken)) return false;
            const u32 kSeparator = out == 0 ? 0u : 1u;
            if (out > storage_capacity - kWsHandshakeAcceptLength ||
                kSeparator + kToken.len > storage_capacity - kWsHandshakeAcceptLength - out)
                return false;
            if (kSeparator) storage[kWsHandshakeAcceptLength + out++] = ',';
            __builtin_memcpy(storage + kWsHandshakeAcceptLength + out, kToken.ptr, kToken.len);
            out += kToken.len;
            if (end == kValue.len) break;
            start = end + 1;
        }
    }
    *out_offers_len = out;
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
           digest_len == sizeof(digest) && out_capacity >= kWsHandshakeAcceptLength + 1 &&
           rut_crypto_base64_encode_v1(digest, sizeof(digest), out, out_capacity, &encoded_len) &&
           encoded_len == kWsHandshakeAcceptLength;
}

bool connection_value_is_valid(Str value, bool* has_upgrade) {
    u32 start = 0;
    for (;;) {
        u32 end = start;
        while (end < value.len && value.ptr[end] != ',') end++;
        const Str kItem = trim_ows({value.ptr + start, end - start});
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
    const Str kName = {protocol.ptr, slash};
    if (!protocol_token_valid(kName)) return false;
    if (slash != protocol.len) {
        const Str kVersion = {protocol.ptr + slash + 1, protocol.len - slash - 1};
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
        const Str kItem = trim_ows({value.ptr + start, end - start});
        if (!upgrade_protocol_valid(kItem, offers_websocket)) return false;
        if (end == value.len) return true;
        start = end + 1;
    }
}

}  // namespace

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
        (storage != nullptr && storage_capacity < kWsHandshakeAcceptLength + 1))
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

    u32 host_count = 0;
    bool connection_upgrade = false;
    bool upgrade_websocket = false;
    u32 key_count = 0;
    u32 version_count = 0;
    Str key{};
    Str version{};
    for (u32 i = 0; i < parsed.header_count; i++) {
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
    u32 version_number = 0;
    for (u32 i = 0; i < version.len; i++)
        if (version.ptr[i] < '0' || version.ptr[i] > '9')
            return WsHandshakeRequestResult::BadRequest;
        else
            version_number = version_number * 10 + static_cast<u32>(version.ptr[i] - '0');
    if (version_number > 255) return WsHandshakeRequestResult::BadRequest;
    if (version_number != 13) return WsHandshakeRequestResult::VersionRequired;
    if (required_subprotocol.len != 0) {
        if (!ws_valid_subprotocol(required_subprotocol))
            return WsHandshakeRequestResult::BadRequest;
        bool offered = false;
        for (u32 i = 0; i < parsed.header_count; i++) {
            const Header& header = parsed.headers[i];
            if (!name_is(header.name, "sec-websocket-protocol", 22)) continue;
            u32 start = 0;
            for (;;) {
                u32 end = start;
                while (end < header.value.len && header.value.ptr[end] != ',') end++;
                offered |=
                    trim_ows({header.value.ptr + start, end - start}).eq(required_subprotocol);
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
                                   WsDeflateAgreement* upstream_deflate) {
    if (upstream_deflate) *upstream_deflate = {};
    if (storage == nullptr || offers_len > SlicePool::kSliceSize - kWsHandshakeAcceptLength ||
        (required_subprotocol.len != 0 && !ws_valid_subprotocol(required_subprotocol)) ||
        response.header_count > kMaxHeaders || response.version != HttpVersion::Http11 ||
        response.status_code != 101 || response.headers_truncated)
        return false;
    WsDeflateAgreement selected{};
    if (upstream_deflate &&
        !ws_accept_deflate_response(response.headers, response.header_count, &selected))
        return false;
    u32 upgrade_count = 0;
    u32 accept_count = 0;
    u32 protocol_count = 0;
    bool upgrade_ok = false;
    bool connection_upgrade = false;
    bool protocol_ok = required_subprotocol.len == 0;
    for (u32 i = 0; i < response.header_count; i++) {
        const Header& header = response.headers[i];
        if (name_is(header.name, "upgrade", 7)) {
            if (++upgrade_count != 1) return false;
            const Str kValue = trim_ows(header.value);
            upgrade_ok = kValue.len == 9 && http_header_name_eq_ci(kValue.ptr, 9, "websocket", 9);
        } else if (name_is(header.name, "connection", 10)) {
            if (!connection_value_is_valid(header.value, &connection_upgrade)) return false;
        } else if (name_is(header.name, "sec-websocket-extensions", 24)) {
            const Str kValue = trim_ows(header.value);
            if (kValue.len != 0 && !upstream_deflate) return false;
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

u32 ws_restrict_subprotocol(u8* request, u32 header_len, u32 total_len, Str required_subprotocol) {
    if (request == nullptr || header_len > total_len || header_len < 4 ||
        total_len > SlicePool::kSliceSize || !ws_valid_subprotocol(required_subprotocol))
        return 0;
    u32 read = 0;
    u32 write = 0;
    bool selected = false;
    while (read < header_len) {
        u32 end = read;
        while (end + 1 < header_len && (request[end] != '\r' || request[end + 1] != '\n')) end++;
        if (end + 1 >= header_len) return 0;
        const u32 kNext = end + 2;
        u32 colon = read;
        while (colon < end && request[colon] != ':') colon++;
        const bool kIsProtocol =
            colon < end && http_header_name_eq_ci(reinterpret_cast<const char*>(request + read),
                                                  colon - read,
                                                  "sec-websocket-protocol",
                                                  22);
        if (kIsProtocol) {
            bool contains = false;
            u32 start = colon + 1;
            while (start < end) {
                u32 stop = start;
                while (stop < end && request[stop] != ',') stop++;
                contains |= trim_ows({reinterpret_cast<const char*>(request + start), stop - start})
                                .eq(required_subprotocol);
                start = stop + 1;
            }
            if (!selected && contains) {
                static constexpr char kHeader[] = "Sec-WebSocket-Protocol:";
                const u32 kLength = sizeof(kHeader) - 1 + required_subprotocol.len + 2;
                if (kLength > kNext - read) return 0;
                __builtin_memcpy(request + write, kHeader, sizeof(kHeader) - 1);
                write += sizeof(kHeader) - 1;
                __builtin_memcpy(
                    request + write, required_subprotocol.ptr, required_subprotocol.len);
                write += required_subprotocol.len;
                request[write++] = '\r';
                request[write++] = '\n';
                selected = true;
            }
        } else {
            __builtin_memmove(request + write, request + read, kNext - read);
            write += kNext - read;
        }
        read = kNext;
    }
    if (!selected) return 0;
    __builtin_memmove(request + write, request + header_len, total_len - header_len);
    return write;
}

}  // namespace rut
