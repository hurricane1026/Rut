#include "rut/runtime/ws_terminate.h"

#include "rut/common/types.h"
#include "rut/common/utf8.h"
#include "rut/runtime/json.h"
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
                          (expected.len == 0 || memcmp(kActual.ptr + kActual.len - expected.len,
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
            matches =
                expected.len <= kActual.len &&
                (expected.len == 0 ||
                 memcmp(kActual.ptr + kActual.len - expected.len, expected.ptr, expected.len) == 0);
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
                    matches =
                        expected.len <= decoded.len &&
                        (expected.len == 0 || memcmp(document.scratch + decoded.len - expected.len,
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
bool emit_frame(u8* out,
                u32 out_cap,
                u32* produced,
                WsOpcode op,
                const u8* payload,
                u64 len,
                bool masked,
                u64& mask_rng,
                Str prefix = {},
                Str suffix = {}) {
    u8 key[4] = {0, 0, 0, 0};
    (void)mask_rng;  // Retained for compatibility with the existing inspector API.
    if (masked && RAND_bytes(key, sizeof(key)) != 1) return false;
    u8 hdr[kWsMaxHeaderSize];
    const u64 output_len = len + prefix.len + suffix.len;
    const u32 hdr_len = ws_write_header(hdr, op, /*fin=*/true, masked, key, output_len);
    if (hdr_len == 0) return false;
    if (*produced + hdr_len + output_len > out_cap) return false;
    for (u32 i = 0; i < hdr_len; i++) out[*produced + i] = hdr[i];
    u8* dst = out + *produced + hdr_len;
    for (u32 i = 0; i < prefix.len; i++) dst[i] = static_cast<u8>(prefix.ptr[i]);
    for (u64 i = 0; i < len; i++) dst[prefix.len + i] = payload[i];
    for (u32 i = 0; i < suffix.len; i++) dst[prefix.len + len + i] = static_cast<u8>(suffix.ptr[i]);
    if (masked) ws_unmask(dst, output_len, key);
    *produced += hdr_len + static_cast<u32>(output_len);
    return true;
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
            const u64 kOutputSize = static_cast<u64>(prefix.len) + decoded.len + suffix.len;
            if (kOutputSize <= kWsTerminateMessageCapacity &&
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
        const u64 kOutputSize = static_cast<u64>(prefix.len) + kLexeme.len + suffix.len;
        if (kOutputSize <= kWsTerminateMessageCapacity &&
            (max_size == 0 || kOutputSize <= max_size)) {
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
    const u64 kOutputSize = static_cast<u64>(prefix.len) + serialized_len + suffix.len;
    if (kOutputSize > kWsTerminateMessageCapacity || (max_size != 0 && kOutputSize > max_size))
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
    const u64 literal_size = static_cast<u64>(rewrite.prefix.len) + rewrite.suffix.len;
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
    return kSourceValid && literal_size <= kWsTerminateMessageCapacity &&
           (max_size == 0 || literal_size <= max_size) && kPayloadValid;
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
    if (st.close_policy_count > kWsMaxClosePolicies ||
        (st.close_policy_count != 0 && !st.close_policies))
        return WsInspectStatus::Error;

    if (st.forward_text_count > kWsMaxForwardTexts ||
        (st.forward_text_count != 0 && !st.forward_texts))
        return WsInspectStatus::Error;

    for (;;) {
        const u32 avail = in_len - *consumed;
        const u8* p = in + *consumed;

        WsFrameHeader h;
        if (st.partial_data_frame) {
            h = st.partial_header;
        } else {
            const ParseStatus ps = ws_parse_header(p, avail, st.masked, &h);
            if (ps == ParseStatus::Incomplete) break;  // partial header — wait for more bytes
            if (ps == ParseStatus::Error) return WsInspectStatus::Error;
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
        if (!ws_opcode_is_control(h.opcode)) {
            // The header alone proves an invalid fragment sequence. Reject it
            // before waiting for the advertised payload.
            if ((h.opcode == WsOpcode::Continuation) != st.assembler.in_fragmented)
                return WsInspectStatus::Error;
            if (st.message_len + h.payload_len > msg_cap) return WsInspectStatus::Error;
            if (st.max_message_size != 0 && st.message_len + h.payload_len > st.max_message_size) {
                return WsInspectStatus::Error;
            }
        }

        // Control payloads are small and processed whole; data payloads can span reads.
        const u32 header_len = st.partial_data_frame ? 0 : h.header_len;
        const u64 frame_total =
            static_cast<u64>(header_len) + h.payload_len - st.partial_payload_len;
        if (ws_opcode_is_control(h.opcode) && avail < frame_total) break;
        if (!ws_opcode_is_control(h.opcode) && avail < frame_total && *produced != 0) break;
        // A completed fragmented message can be larger than this input chunk. Flush
        // already-produced frames first when the next output might not fit; leave this
        // frame and the assembler state untouched for the next call.
        if (*produced != 0) {
            const u64 original_size = st.message_len + h.payload_len;
            auto rewritten_size = [original_size, &st](const WsTextRewrite& rewrite) -> u64 {
                if (rewrite.source == WsTextSource::Dynamic) {
                    const u64 kCap =
                        st.max_message_size ? st.max_message_size : kWsTerminateMessageCapacity;
                    return kCap > kWsMaxControlPayload ? kCap : kWsMaxControlPayload;
                }
                const u64 kSourceSize = rewrite.source == WsTextSource::JsonStringify
                                            ? json::kMaxBytes
                                        : rewrite.source != WsTextSource::Literal &&
                                                rewrite.source != WsTextSource::LiteralBinary
                                            ? original_size
                                            : 0;
                return static_cast<u64>(rewrite.prefix.len) + rewrite.suffix.len + kSourceSize;
            };
            u64 data_size = rewritten_size(st.forward_text);
            if (original_size > data_size) data_size = original_size;
            for (u32 i = 0; i < st.forward_text_count; i++) {
                const u64 size = rewritten_size(st.forward_texts[i]);
                if (size > data_size) data_size = size;
            }
            u32 reason_size = st.close_reason.len;
            for (u32 i = 0; i < st.close_policy_count; i++)
                if (st.close_policies[i].reason.len > reason_size)
                    reason_size = st.close_policies[i].reason.len;
            const u64 close_size = 2u + static_cast<u64>(reason_size);
            if (reason_size != 0 && close_size > data_size) data_size = close_size;
            const u64 needed = ws_opcode_is_control(h.opcode)
                                   ? frame_total
                                   : (h.fin ? data_size + kWsMaxHeaderSize : 0);
            if (needed > out_cap - *produced) break;
        }
        const u8* payload = p + header_len;

        if (ws_opcode_is_control(h.opcode)) {
            // Copy + unmask the control payload (<=125 bytes) so we can validate it and
            // re-serialize it with our own framing — terminate mode owns the outbound
            // side, so it must not leak the client's mask key or relay a malformed body.
            u8 cbuf[kWsMaxControlPayload];
            for (u64 i = 0; i < h.payload_len; i++) cbuf[i] = payload[i];
            if (st.masked) ws_unmask(cbuf, h.payload_len, h.mask_key);

            // §7.4/§5.5.1: a Close body, if present, is a 2-byte status code (which must be
            // a valid wire code) followed by a UTF-8 reason. Fail the tunnel otherwise.
            u16 received_code = 1005;
            if (h.opcode == WsOpcode::Close) {
                if (h.payload_len == 1) return WsInspectStatus::Error;
                if (h.payload_len >= 2) {
                    received_code = static_cast<u16>((static_cast<u16>(cbuf[0]) << 8) | cbuf[1]);
                    if (!ws_valid_close_code(received_code)) return WsInspectStatus::Error;
                    if (!utf8_valid(cbuf + 2, h.payload_len - 2)) return WsInspectStatus::Error;
                }
            }

            if (!emit_frame(out,
                            out_cap,
                            produced,
                            h.opcode,
                            cbuf,
                            h.payload_len,
                            st.masked,
                            st.mask_rng)) {
                return WsInspectStatus::Error;
            }
            *consumed += static_cast<u32>(frame_total);
            if (h.opcode == WsOpcode::Close) {
                // Reply to the sender with the same status/reason, including an
                // empty body. Retain owned bytes before receive storage is recycled.
                st.echo_close_code = received_code;
                const Str kReason{reinterpret_cast<const char*>(cbuf + 2),
                                  h.payload_len == 0 ? 0 : static_cast<u32>(h.payload_len - 2)};
                if (!st.set_echo_close_reason(kReason)) return WsInspectStatus::Error;
                st.received_close = true;
                return WsInspectStatus::Close;
            }
            continue;
        }

        // Data frame (Text/Binary or continuation).
        // Accumulate the (unmasked) payload into the reassembly buffer (bound already
        // checked above), then ask the reassembler whether the message is complete.
        const u64 remain = h.payload_len - st.partial_payload_len;
        const u32 available_payload = avail - header_len;
        const u32 chunk = remain < available_payload ? static_cast<u32>(remain) : available_payload;
        u8* dst = msg_buf + st.message_len + st.partial_payload_len;
        for (u32 i = 0; i < chunk; i++) dst[i] = payload[i];
        if (st.masked) ws_unmask_chunk(dst, chunk, h.mask_key, st.partial_payload_len);
        st.partial_payload_len += chunk;
        *consumed += header_len + chunk;
        if (st.partial_payload_len < h.payload_len) {
            st.partial_data_frame = true;
            st.partial_header = h;
            break;
        }
        st.partial_data_frame = false;
        st.partial_payload_len = 0;

        WsOpcode msg_op;
        u64 total;
        const WsMessageStatus ms =
            ws_message_feed(st.assembler, h, st.max_message_size, &msg_op, &total);
        if (ms == WsMessageStatus::Error) return WsInspectStatus::Error;
        st.message_len += h.payload_len;

        if (ms == WsMessageStatus::NeedMore) continue;  // awaiting more fragments

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
            action_value >= first_policy && action_value < first_policy + kWsMaxClosePolicies;
        if (policy_close && action_value - first_policy >= st.close_policy_count)
            return WsInspectStatus::Error;
        const u8 first_text_policy = static_cast<u8>(WsFrameAction::ForwardTextPolicy0);
        const bool policy_forward = action_value >= first_text_policy &&
                                    action_value < first_text_policy + kWsMaxForwardTexts;
        if (policy_forward && action_value - first_text_policy >= st.forward_text_count)
            return WsInspectStatus::Error;
        if (action == WsFrameAction::Forward) {
            // Re-serialize the whole message as a single (unfragmented) frame.
            if (!emit_frame(
                    out, out_cap, produced, msg_op, msg_buf, total, st.masked, st.mask_rng)) {
                return WsInspectStatus::Error;
            }
        } else if (action == WsFrameAction::ForwardDynamic) {
            if ((published.opcode != WsOpcode::Text && published.opcode != WsOpcode::Binary) ||
                (!published.payload.ptr && published.payload.len) ||
                published.payload.len > kWsTerminateMessageCapacity ||
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
            const WsTextRewrite& rewrite = policy_forward
                                               ? st.forward_texts[action_value - first_text_policy]
                                               : st.forward_text;
            const u64 kPayloadSize = rewrite.source == WsTextSource::MessageText ||
                                             rewrite.source == WsTextSource::MessageBytes
                                         ? total
                                         : 0;
            const u64 kOutputSize = kPayloadSize + rewrite.prefix.len + rewrite.suffix.len;
            if (rewrite.source == WsTextSource::Dynamic ||
                !ws_valid_text_rewrite(rewrite, st.max_message_size) ||
                (rewrite.source == WsTextSource::MessageText && !utf8_valid(msg_buf, total)) ||
                kOutputSize > kWsTerminateMessageCapacity ||
                (st.max_message_size != 0 && kOutputSize > st.max_message_size))
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
                : policy_close ? st.close_policies[action_value - first_policy]
                               : WsClosePolicy{st.close_code, st.close_reason};
            if (!ws_valid_close_code(kSelected.code) || !ws_valid_close_reason(kSelected.reason))
                return WsInspectStatus::Error;
            u8 cc[kWsMaxControlPayload];
            cc[0] = static_cast<u8>(kSelected.code >> 8);
            cc[1] = static_cast<u8>(kSelected.code);
            for (u32 i = 0; i < kSelected.reason.len; i++)
                cc[i + 2] = static_cast<u8>(kSelected.reason.ptr[i]);
            const u32 hdr = 2u + (st.masked ? 4u : 0u);
            u32 body = 2u + kSelected.reason.len;
            // Preserve the legacy empty-status fallback only for code-only closes.
            // A configured reason must fit whole; never truncate UTF-8 or silently discard it.
            if (static_cast<u64>(*produced) + hdr + body > out_cap) {
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
        // Drop: emit nothing. All continuing verdicts reset for the next message.
        st.message_len = 0;
    }

    return WsInspectStatus::Ok;
}

u32 ws_emit_close_frame(u8* out, u32 out_cap, bool masked, u64& mask_rng, u16 code, Str reason) {
    if (!ws_valid_close_code(code) || !ws_valid_close_reason(reason)) return 0;
    u8 body[kWsMaxControlPayload];
    body[0] = static_cast<u8>(code >> 8);
    body[1] = static_cast<u8>(code);
    for (u32 i = 0; i < reason.len; i++) body[i + 2] = static_cast<u8>(reason.ptr[i]);
    u32 produced = 0;
    if (!emit_frame(
            out, out_cap, &produced, WsOpcode::Close, body, 2u + reason.len, masked, mask_rng))
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
