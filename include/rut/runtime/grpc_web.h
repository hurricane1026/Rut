#pragma once

#include "rut/common/types.h"

namespace rut {

enum class GrpcWebContentType : u8 { Other, Native, Binary, Text };
constexpr u32 kGrpcWebLocalBodyCap = 16352;  // 16 KiB SliceArena slice minus its header.

inline bool grpc_web_token_equal(Str value, Str token) {
    if (value.len != token.len) return false;
    for (u32 i = 0; i < value.len; i++) {
        char c = value.ptr[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != token.ptr[i]) return false;
    }
    return true;
}

// The Web bridge advertises protobuf representations only. Native forwarding
// keeps its broader subtype compatibility separately.
inline bool grpc_web_native_proto_content_type(Str value) {
    u32 end = 0;
    while (end < value.len && value.ptr[end] != ';') end++;
    while (end && (value.ptr[end - 1] == ' ' || value.ptr[end - 1] == '\t')) end--;
    const Str media{value.ptr, end};
    return grpc_web_token_equal(media, {"application/grpc", 16}) ||
           grpc_web_token_equal(media, {"application/grpc+proto", 22});
}

inline GrpcWebContentType grpc_web_content_type(Str value) {
    u32 end = 0;
    while (end < value.len && value.ptr[end] != ';') end++;
    while (end && (value.ptr[end - 1] == ' ' || value.ptr[end - 1] == '\t')) end--;
    Str media{value.ptr, end};
    if (grpc_web_token_equal(media, {"application/grpc", 16}) ||
        (media.len > 16 && grpc_web_token_equal(media.slice(0, 16), {"application/grpc", 16}) &&
         media.ptr[16] == '+'))
        return GrpcWebContentType::Native;
    constexpr Str binary{"application/grpc-web", 20};
    constexpr Str text{"application/grpc-web-text", 25};
    auto matches_web = [media](Str base) {
        if (media.len < base.len) return false;
        for (u32 i = 0; i < base.len; i++) {
            char c = media.ptr[i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != base.ptr[i]) return false;
        }
        return media.len == base.len || media.ptr[base.len] == '+';
    };
    if (matches_web(text)) {
        const u32 suffix = text.len;
        return media.len == suffix ||
                       (media.len == suffix + 6 &&
                        grpc_web_token_equal(media.slice(suffix, media.len), {"+proto", 6}))
                   ? GrpcWebContentType::Text
                   : GrpcWebContentType::Other;
    }
    if (matches_web(binary)) {
        const u32 suffix = binary.len;
        return media.len == suffix ||
                       (media.len == suffix + 6 &&
                        grpc_web_token_equal(media.slice(suffix, media.len), {"+proto", 6}))
                   ? GrpcWebContentType::Binary
                   : GrpcWebContentType::Other;
    }
    return GrpcWebContentType::Other;
}

// A Web-family token remains a bridge candidate even when its suffix is not
// supported (for example, application/grpc-web+json). This lets request
// admission reject ambiguity instead of letting an earlier native value hide
// a later Web value.
inline bool grpc_web_content_type_candidate(Str value) {
    u32 end = 0;
    while (end < value.len && value.ptr[end] != ';') end++;
    while (end && (value.ptr[end - 1] == ' ' || value.ptr[end - 1] == '\t')) end--;
    const Str media{value.ptr, end};
    auto family = [media](Str base) {
        if (media.len < base.len) return false;
        for (u32 i = 0; i < base.len; i++) {
            char c = media.ptr[i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != base.ptr[i]) return false;
        }
        return media.len == base.len || media.ptr[base.len] == '+';
    };
    return family({"application/grpc-web", 20}) || family({"application/grpc-web-text", 25});
}

enum class GrpcWebCodecStatus : u8 { Ok, NeedOutput, Invalid, Incomplete };

inline i16 grpc_web_base64_value(u8 c) {
    if (c >= 'A' && c <= 'Z') return static_cast<i16>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<i16>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<i16>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

struct GrpcWebBase64Decoder {
    u8 quartet[4];
    u8 quartet_len;
    bool invalid;

    void init() {
        quartet_len = 0;
        invalid = false;
    }

private:
    GrpcWebCodecStatus reject() {
        invalid = true;
        return GrpcWebCodecStatus::Invalid;
    }

    GrpcWebCodecStatus emit(u8* output, u32 capacity, u32& written) {
        const i16 a = grpc_web_base64_value(quartet[0]);
        const i16 b = grpc_web_base64_value(quartet[1]);
        if (a < 0 || b < 0) return reject();
        u32 size = 3;
        i16 c = -1;
        i16 d = -1;
        if (quartet[2] == '=') {
            if (quartet[3] != '=' || (b & 15)) return reject();
            size = 1;
        } else {
            c = grpc_web_base64_value(quartet[2]);
            if (c < 0) return reject();
            if (quartet[3] == '=') {
                if (c & 3) return reject();
                size = 2;
            } else {
                d = grpc_web_base64_value(quartet[3]);
                if (d < 0) return reject();
            }
        }
        if (capacity - written < size) return GrpcWebCodecStatus::NeedOutput;
        output[written++] = static_cast<u8>((a << 2) | (b >> 4));
        if (size > 1) output[written++] = static_cast<u8>((b << 4) | (c >> 2));
        if (size > 2) output[written++] = static_cast<u8>((c << 6) | d);
        quartet_len = 0;
        return GrpcWebCodecStatus::Ok;
    }

public:
    GrpcWebCodecStatus feed(
        const u8* input, u32 length, u32& consumed, u8* output, u32 capacity, u32& written) {
        consumed = written = 0;
        if (invalid) return GrpcWebCodecStatus::Invalid;
        if ((length && !input) || (capacity && !output)) return reject();
        while (consumed < length || quartet_len == 4) {
            if (quartet_len == 4) {
                const auto status = emit(output, capacity, written);
                if (status == GrpcWebCodecStatus::Invalid) invalid = true;
                if (status != GrpcWebCodecStatus::Ok) return status;
                continue;
            }
            const u8 c = input[consumed++];
            if (c == '=') {
                if (quartet_len < 2) return reject();
            } else if (grpc_web_base64_value(c) < 0 || (quartet_len == 3 && quartet[2] == '=')) {
                return reject();
            }
            quartet[quartet_len++] = c;
        }
        return GrpcWebCodecStatus::Ok;
    }

    GrpcWebCodecStatus finish() const {
        if (invalid) return GrpcWebCodecStatus::Invalid;
        return quartet_len ? GrpcWebCodecStatus::Incomplete : GrpcWebCodecStatus::Ok;
    }
};

struct GrpcWebBase64Encoder {
    u8 pending[3];
    u8 pending_len;
    bool invalid;

    void init() {
        pending_len = 0;
        invalid = false;
    }

    static void encode_triplet(const u8* input, u8* output) {
        constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        output[0] = static_cast<u8>(alphabet[input[0] >> 2]);
        output[1] = static_cast<u8>(alphabet[((input[0] & 3) << 4) | (input[1] >> 4)]);
        output[2] = static_cast<u8>(alphabet[((input[1] & 15) << 2) | (input[2] >> 6)]);
        output[3] = static_cast<u8>(alphabet[input[2] & 63]);
    }

    GrpcWebCodecStatus feed(
        const u8* input, u32 length, u32& consumed, u8* output, u32 capacity, u32& written) {
        consumed = written = 0;
        if (invalid) return GrpcWebCodecStatus::Invalid;
        if ((length && !input) || (capacity && !output)) {
            invalid = true;
            return GrpcWebCodecStatus::Invalid;
        }
        while (consumed < length || pending_len == 3) {
            if (pending_len == 3) {
                if (capacity - written < 4) return GrpcWebCodecStatus::NeedOutput;
                encode_triplet(pending, output + written);
                written += 4;
                pending_len = 0;
                continue;
            }
            pending[pending_len++] = input[consumed++];
        }
        return GrpcWebCodecStatus::Ok;
    }

    GrpcWebCodecStatus flush(u8* output, u32 capacity, u32& written) {
        written = 0;
        if (invalid) return GrpcWebCodecStatus::Invalid;
        if (capacity && !output) {
            invalid = true;
            return GrpcWebCodecStatus::Invalid;
        }
        if (!pending_len) return GrpcWebCodecStatus::Ok;
        if (capacity < 4) return GrpcWebCodecStatus::NeedOutput;
        if (pending_len == 3) {
            encode_triplet(pending, output);
            written = 4;
            pending_len = 0;
            return GrpcWebCodecStatus::Ok;
        }
        constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        output[0] = static_cast<u8>(alphabet[pending[0] >> 2]);
        output[1] = static_cast<u8>(
            alphabet[((pending[0] & 3) << 4) | (pending_len > 1 ? pending[1] >> 4 : 0)]);
        output[2] = pending_len > 1 ? static_cast<u8>(alphabet[(pending[1] & 15) << 2]) : '=';
        output[3] = '=';
        written = 4;
        pending_len = 0;
        return GrpcWebCodecStatus::Ok;
    }
};

struct GrpcWebTrailer {
    Str name;
    Str value;
};

inline bool grpc_web_encode_trailer_envelope(
    const GrpcWebTrailer* trailers, u32 count, u8* output, u32 capacity, u32& written);

// Encode the complete body for a local unary response. The input message is
// already one native, uncompressed gRPC frame (or empty); the output owns both
// that frame and the terminal 0x80 trailer frame. Text mode feeds both frames
// through one encoder so padding is emitted only once at the end.
inline bool grpc_web_encode_local_response(GrpcWebContentType mode,
                                           const u8* message,
                                           u32 message_len,
                                           u8 status,
                                           Str grpc_message,
                                           Str grpc_details,
                                           u8* output,
                                           u32 capacity,
                                           u32& written) {
    written = 0;
    if ((message_len && !message) || !output || status > 16) return false;
    if (message_len) {
        if (message_len < 5 || message[0] != 0) return false;
        u32 payload = 0;
        for (u32 i = 1; i < 5; i++) payload = (payload << 8) | message[i];
        if (payload != message_len - 5 || payload > 8192) return false;
    }
    char status_digits[2] = {static_cast<char>('0' + status / 10),
                             static_cast<char>('0' + status % 10)};
    const Str status_value = status >= 10 ? Str{status_digits, 2} : Str{status_digits + 1, 1};
    GrpcWebTrailer trailers[3] = {{{"grpc-status", 11}, status_value},
                                  {{"grpc-message", 12}, grpc_message},
                                  {{"grpc-status-details-bin", 23}, grpc_details}};
    u32 trailer_count = 1;
    if (grpc_message.ptr != nullptr) trailers[trailer_count++] = trailers[1];
    if (grpc_details.ptr != nullptr) trailers[trailer_count++] = trailers[2];

    if (mode == GrpcWebContentType::Binary) {
        if (message_len > capacity) return false;
        if (message_len) __builtin_memcpy(output, message, message_len);
        u32 trailer_len = 0;
        if (!grpc_web_encode_trailer_envelope(
                trailers, trailer_count, output + message_len, capacity - message_len, trailer_len))
            return false;
        written = message_len + trailer_len;
        return true;
    }
    if (mode != GrpcWebContentType::Text) return false;
    GrpcWebBase64Encoder encoder;
    encoder.init();
    u32 consumed = 0;
    u32 n = 0;
    auto feed = [&](const u8* bytes, u32 len) {
        while (consumed < len) {
            u32 used = 0;
            u32 produced = 0;
            const auto st = encoder.feed(bytes + consumed,
                                         len - consumed,
                                         used,
                                         output + written,
                                         capacity - written,
                                         produced);
            consumed += used;
            written += produced;
            if (st != GrpcWebCodecStatus::Ok) return false;
        }
        return true;
    };
    if (!feed(message, message_len)) return false;
    u8 trailer[4096];
    if (!grpc_web_encode_trailer_envelope(trailers, trailer_count, trailer, sizeof(trailer), n))
        return false;
    consumed = 0;
    if (!feed(trailer, n)) return false;
    u32 flushed = 0;
    if (encoder.flush(output + written, capacity - written, flushed) != GrpcWebCodecStatus::Ok)
        return false;
    written += flushed;
    return true;
}

inline bool grpc_web_metadata_name_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '!' ||
           c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
           c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

inline bool grpc_web_encode_trailer_envelope(
    const GrpcWebTrailer* trailers, u32 count, u8* output, u32 capacity, u32& written) {
    written = 0;
    u32 payload = 0;
    if ((!trailers && count) || !output) return false;
    for (u32 i = 0; i < count; i++) {
        if (!trailers[i].name.len || !trailers[i].name.ptr ||
            (!trailers[i].value.ptr && trailers[i].value.len))
            return false;
        for (u32 j = 0; j < trailers[i].name.len; j++)
            if (!grpc_web_metadata_name_char(trailers[i].name.ptr[j])) return false;
        for (u32 j = 0; j < trailers[i].value.len; j++) {
            const u8 c = static_cast<u8>(trailers[i].value.ptr[j]);
            if ((c < 0x20 && c != '\t') || c == 0x7f || c > 0x7e) return false;
        }
        if (trailers[i].name.len > UINT32_MAX - 4 ||
            trailers[i].value.len > UINT32_MAX - 4 - trailers[i].name.len)
            return false;
        const u32 line = trailers[i].name.len + 4 + trailers[i].value.len;
        if (line > UINT32_MAX - payload) return false;
        payload += line;
    }
    if (capacity < 5 || capacity - 5 < payload) return false;
    output[0] = 0x80;
    output[1] = static_cast<u8>(payload >> 24);
    output[2] = static_cast<u8>(payload >> 16);
    output[3] = static_cast<u8>(payload >> 8);
    output[4] = static_cast<u8>(payload);
    u32 offset = 5;
    for (u32 i = 0; i < count; i++) {
        for (u32 j = 0; j < trailers[i].name.len; j++) {
            char c = trailers[i].name.ptr[j];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            output[offset++] = static_cast<u8>(c);
        }
        output[offset++] = ':';
        output[offset++] = ' ';
        for (u32 j = 0; j < trailers[i].value.len; j++)
            output[offset++] = static_cast<u8>(trailers[i].value.ptr[j]);
        output[offset++] = '\r';
        output[offset++] = '\n';
    }
    written = offset;
    return true;
}

}  // namespace rut
