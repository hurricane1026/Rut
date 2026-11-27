#include "rut/runtime/ws_terminate.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/common/utf8.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/json.h"
#include "rut/runtime/ws_deflate.h"
#include "rut/runtime/ws_frame.h"

#include <openssl/rand.h>
#include <string.h>

namespace rut {

namespace {
json::Document& ws_json_document() {
    thread_local json::Document document;
    return document;
}

bool ws_json_stringify_to_workspace(
    json::Document& document, const u8* payload, u64 len, Str path, u32& output_len) {
    output_len = 0;
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len)) {
        document.source = {};
        return false;
    }
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    json::Writer encoded{document.other};
    const bool kSerialized = kId != json::kNone && document.write(kId, encoded) && encoded.ok;
    if (kSerialized) output_len = encoded.len;
    // The source and output workspace are thread-local scratch, never callback-owned views.
    document.source = {};
    return kSerialized;
}
}  // namespace

bool ws_json_has_path(const u8* payload, u64 len, Str path) {
    // One bounded workspace per worker thread. Never narrow an unchecked message length.
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kValid =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const bool kPresent = kValid && document.pointer(path) != json::kNone;
    document.source = {};  // do not retain a borrowed message view between callbacks
    return kPresent;
}

bool ws_json_string_at_path(const u8* payload, u64 len, Str path) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    const bool kIsString = kId != json::kNone && document.nodes[kId].kind == json::Kind::String;
    document.source = {};
    return kIsString;
}

WsJsonStringScanResult ws_json_scan_string_at_path(
    const u8* payload, u64 len, Str path, WsJsonStringScanner scanner, void* context) {
    json::Document& document = ws_json_document();
    if (!scanner || !payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len)) {
        document.source = {};
        return WsJsonStringScanResult::Error;
    }
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    json::Writer decoded{document.scratch};
    const bool kDecoded = kId != json::kNone && document.nodes[kId].kind == json::Kind::String &&
                          document.string(kId, decoded) && decoded.ok;
    document.source = {};
    if (!kDecoded) return WsJsonStringScanResult::Error;
    return scanner(context, {document.scratch, decoded.len});
}

bool ws_json_number_text_at_path(const u8* payload, u64 len, Str path) {
    json::Document& document = ws_json_document();
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len)) {
        document.source = {};
        return false;
    }
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    const bool kIsNumber = kId != json::kNone && document.nodes[kId].kind == json::Kind::Number;
    document.source = {};
    return kIsNumber;
}

bool ws_json_number_text_matches_at_path(
    const u8* payload, u64 len, Str path, Str expected, WsJsonStringMatch operation) {
    json::Document& document = ws_json_document();
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len) || (!expected.ptr && expected.len)) {
        document.source = {};
        return false;
    }
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    bool matches = false;
    if (kId != json::kNone && document.nodes[kId].kind == json::Kind::Number) {
        const Str kActual = document.raw(kId);
        switch (operation) {
            case WsJsonStringMatch::Equal:
                matches =
                    kActual.len == expected.len &&
                    (expected.len == 0 || memcmp(kActual.ptr, expected.ptr, expected.len) == 0);
                break;
            case WsJsonStringMatch::Prefix:
                matches =
                    expected.len <= kActual.len &&
                    (expected.len == 0 || memcmp(kActual.ptr, expected.ptr, expected.len) == 0);
                break;
            case WsJsonStringMatch::Suffix:
                matches = expected.len <= kActual.len &&
                          (expected.len == 0 || memcmp(kActual.ptr + static_cast<i64>(kActual.len) -
                                                           static_cast<i64>(expected.len),
                                                       expected.ptr,
                                                       expected.len) == 0);
                break;
            case WsJsonStringMatch::Contains:
                matches = expected.len == 0 ||
                          (expected.len <= kActual.len &&
                           memmem(kActual.ptr, kActual.len, expected.ptr, expected.len) != nullptr);
                break;
            default:
                matches = false;
                break;
        }
    }
    document.source = {};
    return matches;
}

bool ws_json_stringify_at_path(const u8* payload, u64 len, Str path) {
    json::Document& document = ws_json_document();
    u32 output_len = 0;
    return ws_json_stringify_to_workspace(document, payload, len, path, output_len);
}

bool ws_json_stringify_matches_at_path(
    const u8* payload, u64 len, Str path, Str expected, WsJsonStringMatch operation) {
    json::Document& document = ws_json_document();
    if (!expected.ptr && expected.len) {
        document.source = {};
        return false;
    }
    u32 output_len = 0;
    if (!ws_json_stringify_to_workspace(document, payload, len, path, output_len)) return false;
    const Str kActual{document.other, output_len};
    bool matches = false;
    switch (operation) {
        case WsJsonStringMatch::Equal:
            matches = kActual.len == expected.len &&
                      (expected.len == 0 || memcmp(kActual.ptr, expected.ptr, expected.len) == 0);
            break;
        case WsJsonStringMatch::Prefix:
            matches = expected.len <= kActual.len &&
                      (expected.len == 0 || memcmp(kActual.ptr, expected.ptr, expected.len) == 0);
            break;
        case WsJsonStringMatch::Suffix:
            matches = expected.len <= kActual.len &&
                      (expected.len == 0 || memcmp(kActual.ptr + static_cast<i64>(kActual.len) -
                                                       static_cast<i64>(expected.len),
                                                   expected.ptr,
                                                   expected.len) == 0);
            break;
        case WsJsonStringMatch::Contains:
            matches = expected.len == 0 ||
                      (expected.len <= kActual.len &&
                       memmem(kActual.ptr, kActual.len, expected.ptr, expected.len) != nullptr);
            break;
        default:
            matches = false;
            break;
    }
    return matches;
}

bool ws_json_string_equals_at_path(const u8* payload, u64 len, Str path, Str expected) {
    return ws_json_string_matches_at_path(payload, len, path, expected, WsJsonStringMatch::Equal);
}

bool ws_json_string_matches_at_path(
    const u8* payload, u64 len, Str path, Str expected, WsJsonStringMatch operation) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len) || (!expected.ptr && expected.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    bool matches = false;
    if (kId != json::kNone && document.nodes[kId].kind == json::Kind::String) {
        json::Writer decoded{document.scratch};
        if (document.string(kId, decoded)) {
            switch (operation) {
                case WsJsonStringMatch::Equal:
                    matches = decoded.len == expected.len &&
                              (expected.len == 0 ||
                               memcmp(document.scratch, expected.ptr, expected.len) == 0);
                    break;
                case WsJsonStringMatch::Prefix:
                    matches = expected.len <= decoded.len &&
                              (expected.len == 0 ||
                               memcmp(document.scratch, expected.ptr, expected.len) == 0);
                    break;
                case WsJsonStringMatch::Suffix:
                    matches = expected.len <= decoded.len &&
                              (expected.len == 0 ||
                               memcmp(document.scratch + static_cast<i64>(decoded.len) -
                                          static_cast<i64>(expected.len),
                                      expected.ptr,
                                      expected.len) == 0);
                    break;
                case WsJsonStringMatch::Contains:
                    matches = expected.len == 0 ||
                              (expected.len <= decoded.len &&
                               memmem(document.scratch, decoded.len, expected.ptr, expected.len) !=
                                   nullptr);
                    break;
            }
        }
    }
    document.source = {};
    return matches;
}

bool ws_json_bool_at_path(const u8* payload, u64 len, Str path) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    const bool kIsBool = kId != json::kNone && document.nodes[kId].kind == json::Kind::Boolean;
    document.source = {};
    return kIsBool;
}

bool ws_json_bool_equals_at_path(const u8* payload, u64 len, Str path, bool expected) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    const bool kEqual = kId != json::kNone && document.nodes[kId].kind == json::Kind::Boolean &&
                        document.raw(kId).eq(expected ? lit_str("true") : lit_str("false"));
    document.source = {};
    return kEqual;
}

bool ws_json_int_at_path(const u8* payload, u64 len, Str path) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    i64 value = 0;
    const bool kIsInt = kId != json::kNone && document.nodes[kId].kind == json::Kind::Number &&
                        json::integer(document.raw(kId), value);
    document.source = {};
    return kIsInt;
}

bool ws_json_int_compare_at_path(
    const u8* payload, u64 len, Str path, i64 expected, WsJsonIntComparison comparison) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    i64 value = 0;
    bool matches = false;
    if (kId != json::kNone && document.nodes[kId].kind == json::Kind::Number &&
        json::integer(document.raw(kId), value)) {
        switch (comparison) {
            case WsJsonIntComparison::Lt:
                matches = value < expected;
                break;
            case WsJsonIntComparison::Gt:
                matches = value > expected;
                break;
            case WsJsonIntComparison::Eq:
                matches = value == expected;
                break;
        }
    }
    document.source = {};
    return matches;
}

bool ws_json_kind_equals_at_path(const u8* payload, u64 len, Str path, Str expected) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len) || (!expected.ptr && expected.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    Str kind{};
    if (kId != json::kNone) {
        switch (document.nodes[kId].kind) {
            case json::Kind::Null:
                kind = lit_str("null");
                break;
            case json::Kind::Boolean:
                kind = lit_str("boolean");
                break;
            case json::Kind::Number:
                kind = lit_str("number");
                break;
            case json::Kind::String:
                kind = lit_str("string");
                break;
            case json::Kind::Array:
                kind = lit_str("array");
                break;
            case json::Kind::Object:
                kind = lit_str("object");
                break;
        }
    }
    const bool kMatches = kId != json::kNone && kind.eq(expected);
    document.source = {};
    return kMatches;
}

bool ws_json_count_at_path(const u8* payload, u64 len, Str path) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    const bool kIsContainer =
        kId != json::kNone && (document.nodes[kId].kind == json::Kind::Array ||
                               document.nodes[kId].kind == json::Kind::Object);
    document.source = {};
    return kIsContainer;
}

bool ws_json_count_compare_at_path(
    const u8* payload, u64 len, Str path, i32 expected, WsJsonIntComparison comparison) {
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes || (!path.ptr && path.len))
        return false;
    json::Document& document = ws_json_document();
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    bool matches = false;
    if (kId != json::kNone && (document.nodes[kId].kind == json::Kind::Array ||
                               document.nodes[kId].kind == json::Kind::Object)) {
        const i32 kCount = static_cast<i32>(document.size(kId));
        switch (comparison) {
            case WsJsonIntComparison::Lt:
                matches = kCount < expected;
                break;
            case WsJsonIntComparison::Gt:
                matches = kCount > expected;
                break;
            case WsJsonIntComparison::Eq:
                matches = kCount == expected;
                break;
            default:
                matches = false;
                break;
        }
    }
    document.source = {};
    return matches;
}

bool ws_valid_json_payload(const u8* payload, u64 len) {
    return ws_json_has_path(payload, len, {});  // the empty pointer selects any valid JSON root
}

namespace {
// Re-serialize one frame (header + `len`-byte cleartext payload) into out[*produced..],
// masking the payload with a fresh key when `masked`. Returns false if it won't fit or the
// header is refused.
[[nodiscard]] bool emit_frame(u8* out,
                              u32 out_cap,
                              u32* produced,
                              WsOpcode op,
                              const u8* payload,
                              u64 len,
                              bool masked,
                              u64& mask_rng,
                              Str prefix = {},
                              Str suffix = {},
                              bool compressed = false) {
    u8 key[4] = {0, 0, 0, 0};
    (void)mask_rng;  // Retained for compatibility with the existing inspector API.
    if (masked && RAND_bytes(key, sizeof(key)) != 1) return false;
    u8 hdr[kWsMaxHeaderSize];
    u32 output_len;
    const auto decoration_len = range_int(prefix.len) + range_int(suffix.len);
    if (add_overflow(len, decoration_len.value(), &output_len)) return false;
    const u32 payload_len = static_cast<u32>(len);
    const u32 kHeaderLength =
        ws_write_header(hdr, op, /*fin=*/true, masked, key, output_len, compressed);
    if (kHeaderLength == 0) return false;
    if (static_cast<i64>(*produced) + static_cast<i64>(kHeaderLength) +
            static_cast<i64>(output_len) >
        static_cast<i64>(out_cap))
        return false;
    for (u32 i = 0; i < kHeaderLength; i++)
        out[static_cast<i64>(*produced) + static_cast<i64>(i)] = hdr[i];
    u8* dst = out + static_cast<i64>(*produced) + static_cast<i64>(kHeaderLength);
    for (u32 i = 0; i < prefix.len; i++) dst[i] = static_cast<u8>(prefix.ptr[i]);
    for (u32 i = 0; i < payload_len; i++)
        dst[static_cast<i64>(prefix.len) + static_cast<i64>(i)] = payload[i];
    const auto suffix_offset = range_int(prefix.len) + range_int(payload_len);
    for (u32 i = 0; i < suffix.len; i++)
        dst[(suffix_offset + range_int(i)).index()] = static_cast<u8>(suffix.ptr[i]);
    if (masked) ws_unmask(dst, output_len, key);
    *produced = static_cast<u32>(static_cast<i64>(*produced) + static_cast<i64>(kHeaderLength) +
                                 static_cast<i64>(output_len));
    return true;
}

#if RUT_ENABLE_WEBSOCKET
// Reuse the completed message buffer only after the result has been copied to
// owned output. It is then safe compression scratch even for dynamic or JSON
// replacements. Failed size attempts retain the original uncompressed frame.
[[nodiscard]] bool compress_emitted_message(WsInspector& st,
                                            u8* out,
                                            u32 out_cap,
                                            u32 begin,
                                            u32* produced,
                                            u8* scratch,
                                            u32 scratch_capacity) {
    if (!st.encoder || *produced == begin) return true;
    u32 frame_len;
    if (sub_overflow(*produced, begin, &frame_len)) return false;
    WsFrameHeader header{};
    if (ws_parse_header(out + range_int(begin).value(), frame_len, st.masked, &header) !=
            ParseStatus::Complete ||
        (header.opcode != WsOpcode::Text && header.opcode != WsOpcode::Binary) ||
        header.header_len > frame_len ||
        header.payload_len != (range_int(frame_len) - range_int(header.header_len)).value())
        return false;
    u8* const kPayload = out + static_cast<i64>(begin) + static_cast<i64>(header.header_len);
    if (st.masked) ws_unmask(kPayload, static_cast<u64>(header.payload_len), header.mask_key);
    u32 length = 0;
    const auto kStatus = ws_deflate_payload(*st.encoder,
                                            kPayload,
                                            static_cast<u32>(header.payload_len),
                                            scratch,
                                            scratch_capacity,
                                            &length);
    if (kStatus == WsDeflateStatus::Error) return false;
    if (kStatus == WsDeflateStatus::Ok && length < header.payload_len) {
        *produced = begin;
        return emit_frame(out,
                          out_cap,
                          produced,
                          header.opcode,
                          scratch,
                          length,
                          st.masked,
                          st.mask_rng,
                          {},
                          {},
                          true);
    }
    if (st.masked) ws_unmask(kPayload, static_cast<u64>(header.payload_len), header.mask_key);
    return true;
}
#endif

bool decode_close_payload(const u8* payload, u32 len, u16& code, Str& reason) {
    if (len > kWsMaxControlPayload || len == 1 || (!payload && len)) return false;
    code = 1005;
    reason = {};
    if (len == 0) return true;
    code = static_cast<u16>((static_cast<u16>(payload[0]) << 8) | payload[1]);
    reason = {reinterpret_cast<const char*>(payload + 2),
              static_cast<u32>(static_cast<i64>(len) - 2)};
    return ws_valid_close_code(code) && ws_valid_close_reason(reason);
}

bool emit_json_string_frame(u8* out,
                            u32 out_cap,
                            u32* produced,
                            const u8* payload,
                            u64 len,
                            Str path,
                            Str prefix,
                            Str suffix,
                            u64 max_size,
                            bool masked,
                            u64& mask_rng) {
    json::Document& document = ws_json_document();
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len)) {
        document.source = {};
        return false;
    }
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    bool emitted = false;
    if (kId != json::kNone && document.nodes[kId].kind == json::Kind::String) {
        json::Writer decoded{document.scratch};
        if (document.string(kId, decoded) && decoded.ok &&
            ws_valid_text_payload({document.scratch, decoded.len})) {
            const u64 kOutputSize =
                static_cast<u64>(static_cast<i64>(prefix.len) + static_cast<i64>(decoded.len) +
                                 static_cast<i64>(suffix.len));
            if (kOutputSize <= kWsMaxMessageCapacity &&
                (max_size == 0 || kOutputSize <= max_size)) {
                emitted = emit_frame(out,
                                     out_cap,
                                     produced,
                                     WsOpcode::Text,
                                     reinterpret_cast<const u8*>(document.scratch),
                                     decoded.len,
                                     masked,
                                     mask_rng,
                                     prefix,
                                     suffix);
            }
        }
    }
    // `document.source` and `scratch` are borrowed workspace, never route/connection state.
    document.source = {};
    return emitted;
}

bool emit_json_number_text_frame(u8* out,
                                 u32 out_cap,
                                 u32* produced,
                                 const u8* payload,
                                 u64 len,
                                 Str path,
                                 Str prefix,
                                 Str suffix,
                                 u64 max_size,
                                 bool masked,
                                 u64& mask_rng) {
    json::Document& document = ws_json_document();
    if (!payload || len > json::kMaxBytes || path.len > json::kMaxBytes ||
        (!path.ptr && path.len)) {
        document.source = {};
        return false;
    }
    const bool kParsed =
        document.parse({reinterpret_cast<const char*>(payload), static_cast<u32>(len)});
    const u32 kId = kParsed ? document.pointer(path) : json::kNone;
    bool emitted = false;
    if (kId != json::kNone && document.nodes[kId].kind == json::Kind::Number) {
        const Str kLexeme = document.raw(kId);
        const u64 kOutputSize =
            static_cast<u64>(static_cast<i64>(prefix.len) + static_cast<i64>(kLexeme.len) +
                             static_cast<i64>(suffix.len));
        if (kOutputSize <= kWsMaxMessageCapacity && (max_size == 0 || kOutputSize <= max_size)) {
            emitted = emit_frame(out,
                                 out_cap,
                                 produced,
                                 WsOpcode::Text,
                                 reinterpret_cast<const u8*>(kLexeme.ptr),
                                 kLexeme.len,
                                 masked,
                                 mask_rng,
                                 prefix,
                                 suffix);
        }
    }
    // The raw lexeme borrows the input message; its bytes have been copied into out.
    document.source = {};
    return emitted;
}

bool emit_json_stringify_frame(u8* out,
                               u32 out_cap,
                               u32* produced,
                               const u8* payload,
                               u64 len,
                               Str path,
                               Str prefix,
                               Str suffix,
                               u64 max_size,
                               bool masked,
                               u64& mask_rng) {
    json::Document& document = ws_json_document();
    u32 serialized_len = 0;
    if (!ws_json_stringify_to_workspace(document, payload, len, path, serialized_len)) return false;
    const u64 kOutputSize =
        static_cast<u64>(static_cast<i64>(prefix.len) + static_cast<i64>(serialized_len) +
                         static_cast<i64>(suffix.len));
    if (kOutputSize > kWsMaxMessageCapacity || (max_size != 0 && kOutputSize > max_size))
        return false;
    return emit_frame(out,
                      out_cap,
                      produced,
                      WsOpcode::Text,
                      reinterpret_cast<const u8*>(document.other),
                      serialized_len,
                      masked,
                      mask_rng,
                      prefix,
                      suffix);
}
}  // namespace

bool ws_valid_text_payload(Str text) {
    return (text.ptr || text.len == 0) &&
           utf8_valid(reinterpret_cast<const u8*>(text.ptr), text.len);
}

bool ws_valid_text_rewrite(const WsTextRewrite& rewrite, u64 max_size) {
    if (rewrite.source == WsTextSource::Dynamic)
        return !rewrite.prefix.ptr && !rewrite.prefix.len && !rewrite.suffix.ptr &&
               !rewrite.suffix.len && !rewrite.source_path.ptr && !rewrite.source_path.len;
    const i64 literal_size = i64{rewrite.prefix.len} + i64{rewrite.suffix.len};
    const bool kSourceValid =
        rewrite.source <= WsTextSource::MessageBytes &&
        (rewrite.source != WsTextSource::MessageBytes ||
         (rewrite.prefix.len == 0 && rewrite.suffix.len == 0)) &&
        ((rewrite.source == WsTextSource::JsonString ||
          rewrite.source == WsTextSource::JsonNumberText ||
          rewrite.source == WsTextSource::JsonStringify)
             ? rewrite.source_path.len <= json::kMaxBytes &&
                   (rewrite.source_path.ptr || rewrite.source_path.len == 0)
             : rewrite.source_path.len == 0 && rewrite.source_path.ptr == nullptr);
    const bool kPayloadValid =
        rewrite.source == WsTextSource::LiteralBinary
            ? (rewrite.prefix.ptr || rewrite.prefix.len == 0) &&
                  (rewrite.suffix.ptr || rewrite.suffix.len == 0)
            : ws_valid_text_payload(rewrite.prefix) && ws_valid_text_payload(rewrite.suffix);
    return kSourceValid && literal_size <= kWsMaxMessageCapacity &&
           (max_size == 0 || static_cast<u64>(literal_size) <= max_size) && kPayloadValid;
}

bool ws_valid_close_reason(Str reason) {
    return reason.len <= kWsMaxCloseReasonBytes && ws_valid_text_payload(reason);
}

bool WsClosePayload::assign(u16 status, Str text) {
    if ((!ws_valid_close_code(status) && status != 1005) || (status == 1005 && !text.empty()) ||
        !ws_valid_close_reason(text))
        return false;
    for (u32 i = 0; i < text.len; ++i) reason_storage[i] = text.ptr[i];
    reason_len = static_cast<u8>(text.len);
    code = status;
    return true;
}

WsInspectStatus ws_inspect(WsInspector& st,
                           const u8* in,
                           u32 in_len,
                           u8* out,
                           u32 out_cap,
                           u8* msg_buf,
                           u32 msg_cap,
                           WsMessageHandlerFn handler,
                           void* ctx,
                           u32* consumed,
                           u32* produced) {
    *consumed = 0;
    *produced = 0;
#if !RUT_ENABLE_WEBSOCKET
    if (st.decoder || st.encoder) return WsInspectStatus::Error;
#endif
    if (st.close_policy_count > kWsMaxClosePolicies ||
        (st.close_policy_count != 0 && !st.close_policies))
        return WsInspectStatus::Error;

    if (st.forward_text_count > kWsMaxForwardTexts ||
        (st.forward_text_count != 0 && !st.forward_texts))
        return WsInspectStatus::Error;

    for (;;) {
        const u32 avail = static_cast<u32>(static_cast<i64>(in_len) - static_cast<i64>(*consumed));
        const u8* p = in + static_cast<i64>(*consumed);

        WsFrameHeader h;
        if (st.partial_data_frame) {
            h = st.partial_header;
        } else {
            const ParseStatus kParseStatus =
                ws_parse_header(p, avail, st.masked, &h, st.decoder != nullptr);
            if (kParseStatus == ParseStatus::Incomplete)
                break;  // partial header — wait for more bytes
            if (kParseStatus == ParseStatus::Error) return WsInspectStatus::Error;
        }

        // Reject fragmentation the instant the header proves it — before waiting for (or
        // buffering) the payload. The in-place re-frame can't size a message spanning reads,
        // and deferring the check past the whole-frame wait below lets a peer wedge the
        // tunnel by sending only a fragmented frame's header (FIN=0) and then stalling.
        if (st.reject_fragmented && !ws_opcode_is_control(h.opcode) &&
            (h.opcode == WsOpcode::Continuation || !h.fin)) {
            return WsInspectStatus::Error;
        }

        // Fail closed on an oversized data frame as soon as its header is known — before
        // waiting for (and buffering) a payload we'd reject once complete. message_len is
        // the bytes already accumulated for an in-progress fragmented message (0 for a
        // fresh one); the sum is also the exact msg_buf write bound below.
        const bool kCompressed =
            !ws_opcode_is_control(h.opcode) &&
            (st.partial_data_frame || h.opcode == WsOpcode::Continuation ? st.compressed_message
                                                                         : h.compressed);
        const u32 kDecodedLimit = st.max_message_size && st.max_message_size < msg_cap
                                      ? static_cast<u32>(st.max_message_size)
                                      : msg_cap;
        i64 message_total = 0;
        if (!ws_opcode_is_control(h.opcode)) {
            // The header alone proves an invalid fragment sequence. Reject it
            // before waiting for the advertised payload.
            if ((h.opcode == WsOpcode::Continuation) != st.assembler.in_fragmented)
                return WsInspectStatus::Error;
            if (kCompressed) {
                u32 remaining_wire;
                if (!st.decoder ||
                    sub_overflow(
                        ws_deflate_wire_limit(kDecodedLimit), h.payload_len, &remaining_wire) ||
                    st.assembler.accumulated_len > remaining_wire)
                    return WsInspectStatus::Error;
            } else {
                if (st.message_len > kDecodedLimit) return WsInspectStatus::Error;
                const auto accumulated = range_int(static_cast<u32>(st.message_len));
                const auto available = range_int(kDecodedLimit) - accumulated;
                if (h.payload_len > available.value()) return WsInspectStatus::Error;
                message_total = (accumulated + range_int(static_cast<u32>(h.payload_len))).value();
            }
        }

        // Control payloads are small and processed whole; data payloads can span reads.
        const u32 header_len = st.partial_data_frame ? 0 : h.header_len;
        u32 remain;
        if (sub_overflow(h.payload_len, st.partial_payload_len, &remain))
            return WsInspectStatus::Error;
        const auto frame_size = range_int(header_len) + range_int(remain);
        const i64 frame_total = frame_size.value();
        if (ws_opcode_is_control(h.opcode) && avail < frame_total) break;
        if (!ws_opcode_is_control(h.opcode) && avail < frame_total && *produced != 0) break;
        // A completed fragmented message can be larger than this input chunk. Flush
        // already-produced frames first when the next output might not fit; leave this
        // frame and the assembler state untouched for the next call.
        if (*produced != 0) {
            u32 available_output;
            if (sub_overflow(out_cap, *produced, &available_output)) return WsInspectStatus::Error;
            if (ws_opcode_is_control(h.opcode)) {
                if (frame_total > available_output) break;
            } else if (h.fin) {
                const u32 kOriginalSize =
                    kCompressed ? kDecodedLimit : static_cast<u32>(message_total);
                auto rewritten_size = [kOriginalSize, &st](const WsTextRewrite& rewrite) -> u64 {
                    if (rewrite.source == WsTextSource::Dynamic) {
                        const u64 kCap =
                            st.max_message_size ? st.max_message_size : kWsMaxMessageCapacity;
                        return kCap > kWsMaxControlPayload ? kCap : kWsMaxControlPayload;
                    }
                    const u32 kSourceSize = rewrite.source == WsTextSource::JsonStringify
                                                ? json::kMaxBytes
                                            : rewrite.source != WsTextSource::Literal &&
                                                    rewrite.source != WsTextSource::LiteralBinary
                                                ? kOriginalSize
                                                : 0;
                    return (range_int(rewrite.prefix.len) + range_int(rewrite.suffix.len) +
                            range_int(kSourceSize))
                        .to_u64();
                };
                u64 data_size = rewritten_size(st.forward_text);
                if (kOriginalSize > data_size) data_size = kOriginalSize;
                for (u32 i = 0; i < st.forward_text_count; i++) {
                    const u64 size = rewritten_size(st.forward_texts[i]);
                    if (size > data_size) data_size = size;
                }
                u32 reason_size = st.close_reason.len;
                for (u32 i = 0; i < st.close_policy_count; i++)
                    if (st.close_policies[i].reason.len > reason_size)
                        reason_size = st.close_policies[i].reason.len;
                const u64 close_size =
                    (range_int<2, 3>::constant<2>() + range_int(reason_size)).to_u64();
                if (reason_size != 0 && close_size > data_size) data_size = close_size;
                u64 needed;
                if (add_overflow(data_size, kWsMaxHeaderSize, &needed))
                    return WsInspectStatus::Error;
                if (needed > available_output) break;
            }
        }
        const u8* payload = p + static_cast<i64>(header_len);

        if (ws_opcode_is_control(h.opcode)) {
            // Copy + unmask the control payload (<=125 bytes) so we can validate it and
            // re-serialize it with our own framing — terminate mode owns the outbound
            // side, so it must not leak the client's mask key or relay a malformed body.
            u8 cbuf[kWsMaxControlPayload];
            for (i64 i = 0; i < h.payload_len; i++) cbuf[i] = payload[i];
            if (st.masked) ws_unmask(cbuf, static_cast<u64>(h.payload_len), h.mask_key);

            // §7.4/§5.5.1: a Close body, if present, is a 2-byte status code (which must be
            // a valid wire code) followed by a UTF-8 reason. Fail the tunnel otherwise.
            u16 received_code = 1005;
            Str received_reason{};
            if (h.opcode == WsOpcode::Close &&
                !decode_close_payload(
                    cbuf, static_cast<u32>(h.payload_len), received_code, received_reason))
                return WsInspectStatus::Error;

            if (h.opcode == WsOpcode::Close) {
                // Receipt is independent of whether the reply can be emitted.
                // Teardown must still report the validated peer status on an
                // output-capacity or masking failure.
                st.echo_close_code = received_code;
                if (!st.set_echo_close_reason(received_reason)) return WsInspectStatus::Error;
                st.received_close = true;
            }

            if (!emit_frame(out,
                            out_cap,
                            produced,
                            h.opcode,
                            cbuf,
                            static_cast<u64>(h.payload_len),
                            st.masked,
                            st.mask_rng)) {
                return WsInspectStatus::Error;
            }
            if (!(range_int(*consumed) + frame_size).to(consumed)) return WsInspectStatus::Error;
            if (h.opcode == WsOpcode::Close) return WsInspectStatus::Close;
            continue;
        }

        // Data frame (Text/Binary or continuation).
        // Accumulate the (unmasked) payload into the reassembly buffer (bound already
        // checked above), then ask the reassembler whether the message is complete.
        const u32 available_payload =
            static_cast<u32>(static_cast<i64>(avail) - static_cast<i64>(header_len));
        const u32 chunk = remain < available_payload ? remain : available_payload;
        if (!st.partial_data_frame && h.opcode != WsOpcode::Continuation) {
            st.compressed_message = kCompressed;
#if RUT_ENABLE_WEBSOCKET
            if (kCompressed && !ws_inflate_begin(*st.decoder, kDecodedLimit))
                return WsInspectStatus::Error;
#endif
        }
        if (kCompressed) {
#if RUT_ENABLE_WEBSOCKET
            u32 decoded = 0;
            if (ws_inflate_chunk(*st.decoder,
                                 payload,
                                 chunk,
                                 h.fin && chunk == remain,
                                 msg_buf,
                                 msg_cap,
                                 &decoded,
                                 st.masked ? h.mask_key : nullptr,
                                 static_cast<u64>(st.partial_payload_len)) != WsDeflateStatus::Ok)
                return WsInspectStatus::Error;
            st.message_len = decoded;
#endif
        } else {
            // message_total includes this entire frame, so it is at least remain.
            u8* dst = msg_buf + (message_total - static_cast<i64>(remain));
            for (u32 i = 0; i < chunk; i++) dst[i] = payload[i];
            if (st.masked)
                ws_unmask_chunk(dst, chunk, h.mask_key, static_cast<u64>(st.partial_payload_len));
        }
        // The wire bound above caps this frame, and chunk is at most the remainder.
        const u32 received = static_cast<u32>(st.partial_payload_len);
        st.partial_payload_len = (range_int(received) + range_int(chunk)).value();
        if (!(range_int(*consumed) + range_int(header_len) + range_int(chunk)).to(consumed))
            return WsInspectStatus::Error;
        if (st.partial_payload_len < h.payload_len) {
            st.partial_data_frame = true;
            st.partial_header = h;
            break;
        }
        st.partial_data_frame = false;
        st.partial_payload_len = 0;

        WsOpcode msg_op;
        u64 total;
        const WsMessageStatus kMessageStatus = ws_message_feed(
            st.assembler,
            h,
            kCompressed ? ws_deflate_wire_limit(kDecodedLimit) : st.max_message_size,
            &msg_op,
            &total);
        if (kMessageStatus == WsMessageStatus::Error) return WsInspectStatus::Error;
        if (!kCompressed) st.message_len = message_total;

        if (kMessageStatus == WsMessageStatus::NeedMore) continue;  // awaiting more fragments
        if (kCompressed) total = static_cast<u64>(st.message_len);

        // §8.1: a complete Text message must be valid UTF-8, or the connection fails.
        if (msg_op == WsOpcode::Text && !utf8_valid(msg_buf, total)) {
            return WsInspectStatus::Error;
        }

        // Message complete — invoke the handler and act on its verdict.
        if (st.dynamic_output) *st.dynamic_output = {};
        const WsFrameAction action = handler(ctx, msg_op, msg_buf, total, st.from_client);
        WsHandlerOutput published{};
        if (action == WsFrameAction::ForwardDynamic || action == WsFrameAction::CloseDynamic) {
            if (st.forward_text.source != WsTextSource::Dynamic || !st.dynamic_output ||
                !st.dynamic_output->ready)
                return WsInspectStatus::Error;
            published = *st.dynamic_output;
        }
        if (st.dynamic_output) *st.dynamic_output = {};
        const u8 action_value = static_cast<u8>(action);
        const u8 first_policy = static_cast<u8>(WsFrameAction::ClosePolicy0);
        const bool policy_close =
            action_value >= first_policy &&
            static_cast<i64>(action_value) <
                static_cast<i64>(first_policy) + static_cast<i64>(kWsMaxClosePolicies);
        if (policy_close && static_cast<i64>(action_value) - static_cast<i64>(first_policy) >=
                                static_cast<i64>(st.close_policy_count))
            return WsInspectStatus::Error;
        const u8 first_text_policy = static_cast<u8>(WsFrameAction::ForwardTextPolicy0);
        const bool policy_forward =
            action_value >= first_text_policy &&
            static_cast<i64>(action_value) <
                static_cast<i64>(first_text_policy) + static_cast<i64>(kWsMaxForwardTexts);
        if (policy_forward &&
            static_cast<i64>(action_value) - static_cast<i64>(first_text_policy) >=
                static_cast<i64>(st.forward_text_count))
            return WsInspectStatus::Error;
        const u32 kOutputBegin = *produced;
        if (action == WsFrameAction::Forward) {
            // Re-serialize the whole message as a single (unfragmented) frame.
            if (!emit_frame(
                    out, out_cap, produced, msg_op, msg_buf, total, st.masked, st.mask_rng)) {
                return WsInspectStatus::Error;
            }
        } else if (action == WsFrameAction::ForwardDynamic) {
            if ((published.opcode != WsOpcode::Text && published.opcode != WsOpcode::Binary) ||
                (!published.payload.ptr && published.payload.len) ||
                published.payload.len > kWsMaxMessageCapacity ||
                (st.max_message_size && published.payload.len > st.max_message_size) ||
                (published.opcode == WsOpcode::Text && !ws_valid_text_payload(published.payload)))
                return WsInspectStatus::Error;
            if (!emit_frame(out,
                            out_cap,
                            produced,
                            published.opcode,
                            reinterpret_cast<const u8*>(published.payload.ptr),
                            published.payload.len,
                            st.masked,
                            st.mask_rng))
                return WsInspectStatus::Error;
        } else if (action == WsFrameAction::ForwardText || policy_forward) {
            // Input has already been reassembled and validated. Output owns a
            // separate slice, so replacement may grow without overwriting input.
            const WsTextRewrite& rewrite =
                policy_forward
                    ? st.forward_texts[static_cast<u8>(static_cast<i64>(action_value) -
                                                       static_cast<i64>(first_text_policy))]
                    : st.forward_text;
            const u64 kPayloadSize = rewrite.source == WsTextSource::MessageText ||
                                             rewrite.source == WsTextSource::MessageBytes
                                         ? total
                                         : 0;
            u32 output_size;
            const auto decoration_len =
                range_int(rewrite.prefix.len) + range_int(rewrite.suffix.len);
            if (add_overflow(kPayloadSize, decoration_len.value(), &output_size) ||
                rewrite.source == WsTextSource::Dynamic ||
                !ws_valid_text_rewrite(rewrite, st.max_message_size) ||
                (rewrite.source == WsTextSource::MessageText && !utf8_valid(msg_buf, total)) ||
                output_size > kWsMaxMessageCapacity ||
                (st.max_message_size != 0 && output_size > st.max_message_size))
                return WsInspectStatus::Error;
            bool emitted = false;
            switch (rewrite.source) {
                case WsTextSource::Dynamic:
                    return WsInspectStatus::Error;
                case WsTextSource::JsonNumberText:
                    emitted = emit_json_number_text_frame(out,
                                                          out_cap,
                                                          produced,
                                                          msg_buf,
                                                          total,
                                                          rewrite.source_path,
                                                          rewrite.prefix,
                                                          rewrite.suffix,
                                                          st.max_message_size,
                                                          st.masked,
                                                          st.mask_rng);
                    break;
                case WsTextSource::JsonString:
                    emitted = emit_json_string_frame(out,
                                                     out_cap,
                                                     produced,
                                                     msg_buf,
                                                     total,
                                                     rewrite.source_path,
                                                     rewrite.prefix,
                                                     rewrite.suffix,
                                                     st.max_message_size,
                                                     st.masked,
                                                     st.mask_rng);
                    break;
                case WsTextSource::JsonStringify:
                    emitted = emit_json_stringify_frame(out,
                                                        out_cap,
                                                        produced,
                                                        msg_buf,
                                                        total,
                                                        rewrite.source_path,
                                                        rewrite.prefix,
                                                        rewrite.suffix,
                                                        st.max_message_size,
                                                        st.masked,
                                                        st.mask_rng);
                    break;
                case WsTextSource::Literal:
                case WsTextSource::MessageText:
                case WsTextSource::LiteralBinary:
                case WsTextSource::MessageBytes:
                    emitted = emit_frame(out,
                                         out_cap,
                                         produced,
                                         rewrite.source == WsTextSource::LiteralBinary ||
                                                 rewrite.source == WsTextSource::MessageBytes
                                             ? WsOpcode::Binary
                                             : WsOpcode::Text,
                                         msg_buf,
                                         kPayloadSize,
                                         st.masked,
                                         st.mask_rng,
                                         rewrite.prefix,
                                         rewrite.suffix);
                    break;
            }
            if (!emitted) return WsInspectStatus::Error;
        } else if (action == WsFrameAction::Close || policy_close ||
                   action == WsFrameAction::CloseDynamic) {
            const WsClosePolicy kSelected =
                action == WsFrameAction::CloseDynamic
                    ? WsClosePolicy{published.close_code, published.payload}
                : policy_close ? st.close_policies[static_cast<u8>(static_cast<i64>(action_value) -
                                                                   static_cast<i64>(first_policy))]
                               : WsClosePolicy{st.close_code, st.close_reason};
            if (!ws_valid_close_code(kSelected.code) || !ws_valid_close_reason(kSelected.reason))
                return WsInspectStatus::Error;
            u8 cc[kWsMaxControlPayload];
            cc[0] = static_cast<u8>(kSelected.code >> 8);
            cc[1] = static_cast<u8>(kSelected.code);
            for (u32 i = 0; i < kSelected.reason.len; i++)
                cc[static_cast<i64>(i) + 2] = static_cast<u8>(kSelected.reason.ptr[i]);
            const u32 hdr = static_cast<u32>(static_cast<i64>(2) + (st.masked ? 4 : 0));
            u32 body =
                static_cast<u32>(static_cast<i64>(2) + static_cast<i64>(kSelected.reason.len));
            // Preserve the legacy empty-status fallback only for code-only closes.
            // A configured reason must fit whole; never truncate UTF-8 or silently discard it.
            if (static_cast<i64>(*produced) + static_cast<i64>(hdr) + static_cast<i64>(body) >
                static_cast<i64>(out_cap)) {
                if (kSelected.reason.len != 0) return WsInspectStatus::Error;
                body = 0;
            }
            if (!emit_frame(
                    out, out_cap, produced, WsOpcode::Close, cc, body, st.masked, st.mask_rng))
                return WsInspectStatus::Error;
            if (!st.set_echo_close_reason(kSelected.reason)) return WsInspectStatus::Error;
            st.echo_close_code = kSelected.code;
            st.received_close = false;
            st.message_len = 0;
            return WsInspectStatus::Close;
        } else if (action != WsFrameAction::Drop) {
            return WsInspectStatus::Error;
        }
#if RUT_ENABLE_WEBSOCKET
        if (!compress_emitted_message(st, out, out_cap, kOutputBegin, produced, msg_buf, msg_cap))
            return WsInspectStatus::Error;
#else
        (void)kOutputBegin;
#endif
        // Drop: emit nothing. All continuing verdicts reset for the next message.
        st.message_len = 0;
        st.compressed_message = false;
    }

    return WsInspectStatus::Ok;
}

u32 ws_emit_close_frame(u8* out, u32 out_cap, bool masked, u64& mask_rng, u16 code, Str reason) {
    if (!ws_valid_close_code(code) || !ws_valid_close_reason(reason)) return 0;
    u8 body[kWsMaxControlPayload];
    body[0] = static_cast<u8>(code >> 8);
    body[1] = static_cast<u8>(code);
    for (u32 i = 0; i < reason.len; i++)
        body[static_cast<i64>(i) + 2] = static_cast<u8>(reason.ptr[i]);
    u32 produced = 0;
    if (!emit_frame(out,
                    out_cap,
                    &produced,
                    WsOpcode::Close,
                    body,
                    static_cast<u32>(static_cast<i64>(2) + static_cast<i64>(reason.len)),
                    masked,
                    mask_rng))
        return 0;
    return produced;
}

WsClosingRead ws_read_closing(
    WsInspector& st, const u8* in, u32 in_len, u8* ping_payload, u32* ping_len, u32* consumed) {
    *consumed = 0;
    *ping_len = 0;
#if !RUT_ENABLE_WEBSOCKET
    if (st.decoder || st.encoder) return WsClosingRead::Error;
#endif
    if (st.received_close) return WsClosingRead::Close;
    while (*consumed < in_len) {
        const u8* p = in + static_cast<i64>(*consumed);
        const u32 kAvailable =
            static_cast<u32>(static_cast<i64>(in_len) - static_cast<i64>(*consumed));
        WsFrameHeader header;
        if (st.partial_data_frame) {
            header = st.partial_header;
        } else {
            const ParseStatus kStatus =
                ws_parse_header(p, kAvailable, st.masked, &header, st.decoder != nullptr);
            if (kStatus == ParseStatus::Incomplete) return WsClosingRead::NeedMore;
            if (kStatus == ParseStatus::Error) return WsClosingRead::Error;
        }
        if (ws_opcode_is_control(header.opcode)) {
            if (st.partial_data_frame ||
                header.payload_len > static_cast<i64>(kWsMaxControlPayload))
                return WsClosingRead::Error;
            const u32 kPayloadLen = static_cast<u32>(header.payload_len);
            const u32 kTotal = static_cast<u32>(static_cast<i64>(header.header_len) +
                                                static_cast<i64>(kPayloadLen));
            if (kAvailable < kTotal) return WsClosingRead::NeedMore;
            u8 body[kWsMaxControlPayload];
            memcpy(body, p + static_cast<i64>(header.header_len), kPayloadLen);
            if (header.masked) ws_unmask(body, kPayloadLen, header.mask_key);
            if (header.opcode == WsOpcode::Close) {
                u16 code = 1005;
                Str reason{};
                if (!decode_close_payload(
                        body, static_cast<u32>(header.payload_len), code, reason) ||
                    !st.set_echo_close_reason(reason))
                    return WsClosingRead::Error;
                st.echo_close_code = code;
                st.received_close = true;
                *consumed =
                    static_cast<u32>(static_cast<i64>(*consumed) + static_cast<i64>(kTotal));
                return WsClosingRead::Close;
            }
            *consumed = static_cast<u32>(static_cast<i64>(*consumed) + static_cast<i64>(kTotal));
            if (header.opcode == WsOpcode::Ping) {
                memcpy(ping_payload, body, kPayloadLen);
                *ping_len = static_cast<u32>(header.payload_len);
                return WsClosingRead::Ping;
            }
            continue;  // unsolicited Pong has no reply
        }
        const bool kCompressed = st.partial_data_frame || header.opcode == WsOpcode::Continuation
                                     ? st.compressed_message
                                     : header.compressed;
        const u32 kDecodedLimit = st.max_message_size && st.max_message_size < kWsMaxMessageCapacity
                                      ? static_cast<u32>(st.max_message_size)
                                      : kWsMaxMessageCapacity;
        const u32 kLimit = kCompressed ? ws_deflate_wire_limit(kDecodedLimit) : kDecodedLimit;
        u32 remaining_wire;
        if ((header.opcode == WsOpcode::Continuation) != st.assembler.in_fragmented ||
            sub_overflow(kLimit, header.payload_len, &remaining_wire) ||
            st.assembler.accumulated_len > remaining_wire)
            return WsClosingRead::Error;
        st.compressed_message = kCompressed;
        const u32 kHeaderLen = st.partial_data_frame ? 0 : header.header_len;
        u32 remaining;
        if (sub_overflow(header.payload_len, st.partial_payload_len, &remaining))
            return WsClosingRead::Error;
        const u32 kAvailablePayload =
            static_cast<u32>(static_cast<i64>(kAvailable) - static_cast<i64>(kHeaderLen));
        const u32 kTake = remaining < kAvailablePayload ? remaining : kAvailablePayload;
        const u32 received = static_cast<u32>(st.partial_payload_len);
        st.partial_payload_len = (range_int(received) + range_int(kTake)).value();
        if (!(range_int(*consumed) + range_int(kHeaderLen) + range_int(kTake)).to(consumed))
            return WsClosingRead::Error;
        if (st.partial_payload_len != header.payload_len) {
            st.partial_header = header;
            st.partial_data_frame = true;
            return WsClosingRead::NeedMore;
        }
        st.partial_data_frame = false;
        st.partial_payload_len = 0;
        WsOpcode opcode;
        u64 total = 0;
        if (ws_message_feed(st.assembler, header, kLimit, &opcode, &total) ==
            WsMessageStatus::Error)
            return WsClosingRead::Error;
        st.message_len = 0;  // ignored application bytes never enter reassembly storage
        if (header.fin) st.compressed_message = false;
    }
    return WsClosingRead::NeedMore;
}

u32 ws_emit_pong_frame(
    u8* out, u32 out_cap, bool masked, u64& mask_rng, const u8* payload, u32 len) {
    if (len > kWsMaxControlPayload || (!payload && len)) return 0;
    u32 produced = 0;
    if (!emit_frame(out, out_cap, &produced, WsOpcode::Pong, payload, len, masked, mask_rng))
        return 0;
    return produced;
}

u32 ws_emit_close_payload(
    u8* out, u32 out_cap, bool masked, u64& mask_rng, const WsClosePayload& payload) {
    if (payload.code != 1005)
        return ws_emit_close_frame(out, out_cap, masked, mask_rng, payload.code, payload.reason());
    if (payload.reason_len != 0) return 0;
    u32 produced = 0;
    if (!emit_frame(out, out_cap, &produced, WsOpcode::Close, nullptr, 0, masked, mask_rng))
        return 0;
    return produced;
}

}  // namespace rut
