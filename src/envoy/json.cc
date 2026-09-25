#include "rut/envoy/json.h"

namespace rut::envoy {
namespace {

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}
bool is_digit(char c) {
    return c >= '0' && c <= '9';
}
bool is_hex(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
u32 hex_value(char c) {
    if (c <= '9') return static_cast<u32>(c - '0');
    if (c <= 'F') return static_cast<u32>(c - 'A') + 10u;
    return static_cast<u32>(c - 'a') + 10u;
}

class Parser {
public:
    Parser(Str source, JsonDocument& doc) : source_(source), doc_(doc) {}

    FrontendResult<u32> run() {
        doc_.nodes.len = 0;
        doc_.root = kJsonNoNode;
        skip_space();
        if (pos_ >= source_.len)
            return frontend_error(FrontendError::UnexpectedEof, here(), lit_str("empty JSON text"));
        auto root = parse_value(0);
        if (!root) return root;
        skip_space();
        if (pos_ < source_.len)
            return frontend_error(FrontendError::UnexpectedChar,
                                  here(),
                                  lit_str("trailing bytes after the JSON value"));
        doc_.root = root.value();
        return root.value();
    }

private:
    [[nodiscard]] Span here() const { return Span{pos_, pos_, line_, col_}; }

    void advance() {
        if (source_.ptr[pos_] == '\n') {
            line_++;
            col_ = 1;
        } else {
            col_++;
        }
        pos_++;
    }

    void skip_space() {
        while (pos_ < source_.len && is_space(source_.ptr[pos_])) advance();
    }

    [[nodiscard]] bool at_end() const { return pos_ >= source_.len; }
    [[nodiscard]] char peek() const { return source_.ptr[pos_]; }

    FrontendResult<u32> alloc(JsonKind kind, Span span) {
        if (doc_.nodes.full())
            return frontend_error(FrontendError::TooManyItems,
                                  span,
                                  lit_str("JSON document exceeds the bounded node capacity"));
        JsonNode node{};
        node.kind = kind;
        node.span = span;
        (void)doc_.nodes.push(node);
        return doc_.nodes.len - 1u;
    }

    void finish_span(u32 index, u32 start, u32 line, u32 col) {
        doc_.nodes[index].span = Span{start, pos_, line, col};
    }

    // Validate and consume one multi-byte UTF-8 sequence whose lead byte
    // (>= 0x80) is at the current position (RFC 3629). Rejects overlong
    // encodings, encoded surrogate code points (U+D800-U+DFFF), code points
    // beyond U+10FFFF, invalid lead/continuation bytes and truncated
    // sequences.
    FrontendResult<bool> scan_utf8_sequence() {
        const u8 lead = static_cast<u8>(peek());
        u32 length = 0;
        u8 lo = 0x80u;
        u8 hi = 0xBFu;
        if (lead >= 0xC2u && lead <= 0xDFu) {
            length = 1;
        } else if (lead == 0xE0u) {
            length = 2;
            lo = 0xA0u;
        } else if (lead == 0xEDu) {
            length = 2;
            hi = 0x9Fu;
        } else if ((lead >= 0xE1u && lead <= 0xECu) || lead == 0xEEu || lead == 0xEFu) {
            length = 2;
        } else if (lead == 0xF0u) {
            length = 3;
            lo = 0x90u;
        } else if (lead >= 0xF1u && lead <= 0xF3u) {
            length = 3;
        } else if (lead == 0xF4u) {
            length = 3;
            hi = 0x8Fu;
        } else {
            return frontend_error(FrontendError::UnexpectedChar,
                                  here(),
                                  lit_str("invalid UTF-8 byte in JSON string"));
        }
        advance();
        for (u32 i = 0; i < length; i++) {
            if (at_end() || static_cast<u8>(peek()) < lo || static_cast<u8>(peek()) > hi)
                return frontend_error(FrontendError::UnexpectedChar,
                                      here(),
                                      lit_str("invalid UTF-8 byte in JSON string"));
            advance();
            lo = 0x80u;
            hi = 0xBFu;
        }
        return true;
    }

    // Scan a quoted string starting at the opening quote. Returns the raw
    // slice between the quotes and whether it contains any escape.
    //
    // Raw bytes are validated as well-formed UTF-8 (RFC 3629). `\uXXXX`
    // escapes are additionally checked for lone UTF-16 surrogate halves: a
    // high surrogate (D800-DBFF) must be immediately followed by a low
    // surrogate (DC00-DFFF) escape, and a low surrogate must not appear
    // without a preceding high surrogate. This mirrors the check a
    // protobuf JSON parser performs when decoding into a UTF-8 string.
    FrontendResult<Str> scan_string(bool* has_escape) {
        const u32 open = pos_;
        const u32 line = line_;
        const u32 col = col_;
        advance();
        *has_escape = false;
        const u32 start = pos_;
        bool pending_high_surrogate = false;
        Span pending_high_span{};
        while (!at_end()) {
            const char c = peek();
            if (pending_high_surrogate &&
                !(c == '\\' && pos_ + 1u < source_.len && source_.ptr[pos_ + 1u] == 'u')) {
                return frontend_error(FrontendError::UnexpectedChar,
                                      pending_high_span,
                                      lit_str("unpaired UTF-16 surrogate in \\u escape"));
            }
            if (c == '"') {
                const Str raw = source_.slice(start, pos_);
                advance();
                return raw;
            }
            if (static_cast<u8>(c) < 0x20u)
                return frontend_error(FrontendError::UnexpectedChar,
                                      here(),
                                      lit_str("control byte inside a JSON string"));
            if (c == '\\') {
                *has_escape = true;
                const u32 esc_start = pos_;
                const u32 esc_line = line_;
                const u32 esc_col = col_;
                advance();
                if (at_end()) break;
                const char e = peek();
                if (e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' || e == 'n' ||
                    e == 'r' || e == 't') {
                    advance();
                    continue;
                }
                if (e == 'u') {
                    advance();
                    u32 value = 0;
                    for (u32 i = 0; i < 4u; i++) {
                        if (at_end() || !is_hex(peek()))
                            return frontend_error(FrontendError::UnexpectedChar,
                                                  here(),
                                                  lit_str("invalid \\u escape in JSON string"));
                        value = value * 16u + hex_value(peek());
                        advance();
                    }
                    const Span escape_span{esc_start, pos_, esc_line, esc_col};
                    if (value >= 0xD800u && value <= 0xDBFFu) {
                        if (pending_high_surrogate)
                            return frontend_error(
                                FrontendError::UnexpectedChar,
                                pending_high_span,
                                lit_str("unpaired UTF-16 surrogate in \\u escape"));
                        pending_high_surrogate = true;
                        pending_high_span = escape_span;
                    } else if (value >= 0xDC00u && value <= 0xDFFFu) {
                        if (!pending_high_surrogate)
                            return frontend_error(
                                FrontendError::UnexpectedChar,
                                escape_span,
                                lit_str("unpaired UTF-16 surrogate in \\u escape"));
                        pending_high_surrogate = false;
                    } else if (pending_high_surrogate) {
                        return frontend_error(FrontendError::UnexpectedChar,
                                              pending_high_span,
                                              lit_str("unpaired UTF-16 surrogate in \\u escape"));
                    }
                    continue;
                }
                return frontend_error(FrontendError::UnexpectedChar,
                                      here(),
                                      lit_str("invalid escape in JSON string"));
            }
            if (static_cast<u8>(c) >= 0x80u) {
                if (auto r = scan_utf8_sequence(); !r) return core::make_unexpected(r.error());
                continue;
            }
            advance();
        }
        if (pending_high_surrogate)
            return frontend_error(FrontendError::UnexpectedChar,
                                  pending_high_span,
                                  lit_str("unpaired UTF-16 surrogate in \\u escape"));
        return frontend_error(FrontendError::UnterminatedString,
                              Span{open, pos_, line, col},
                              lit_str("unterminated JSON string"));
    }

    FrontendResult<u32> parse_number() {
        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        if (peek() == '-') advance();
        if (at_end() || !is_digit(peek()))
            return frontend_error(
                FrontendError::InvalidInteger, here(), lit_str("expected digit in JSON number"));
        if (peek() == '0') {
            advance();
            if (!at_end() && is_digit(peek()))
                return frontend_error(
                    FrontendError::InvalidInteger, here(), lit_str("leading zero in JSON number"));
        } else {
            while (!at_end() && is_digit(peek())) advance();
        }
        if (!at_end() && peek() == '.') {
            advance();
            if (at_end() || !is_digit(peek()))
                return frontend_error(FrontendError::InvalidInteger,
                                      here(),
                                      lit_str("expected digit after decimal point"));
            while (!at_end() && is_digit(peek())) advance();
        }
        if (!at_end() && (peek() == 'e' || peek() == 'E')) {
            advance();
            if (!at_end() && (peek() == '+' || peek() == '-')) advance();
            if (at_end() || !is_digit(peek()))
                return frontend_error(FrontendError::InvalidInteger,
                                      here(),
                                      lit_str("expected digit in JSON exponent"));
            while (!at_end() && is_digit(peek())) advance();
        }
        auto node = alloc(JsonKind::Number, Span{start, pos_, line, col});
        if (!node) return node;
        doc_.nodes[node.value()].raw = source_.slice(start, pos_);
        return node;
    }

    bool match_word(const char* word, u32 n) {
        if (pos_ + n > source_.len) return false;
        for (u32 i = 0; i < n; i++) {
            if (source_.ptr[pos_ + i] != word[i]) return false;
        }
        for (u32 i = 0; i < n; i++) advance();
        return true;
    }

    FrontendResult<u32> parse_value(u32 depth) {
        if (at_end())
            return frontend_error(
                FrontendError::UnexpectedEof, here(), lit_str("unexpected end of JSON text"));
        if (depth > kMaxJsonDepth)
            return frontend_error(FrontendError::TooManyItems,
                                  here(),
                                  lit_str("JSON nesting exceeds the bounded depth"));
        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        const char c = peek();
        if (c == '{') return parse_object(depth);
        if (c == '[') return parse_array(depth);
        if (c == '"') {
            bool has_escape = false;
            auto raw = scan_string(&has_escape);
            if (!raw) return core::make_unexpected(raw.error());
            auto node = alloc(JsonKind::String, Span{start, pos_, line, col});
            if (!node) return node;
            doc_.nodes[node.value()].raw = raw.value();
            doc_.nodes[node.value()].has_escape = has_escape;
            return node;
        }
        if (c == '-' || is_digit(c)) return parse_number();
        if (match_word("true", 4)) {
            auto node = alloc(JsonKind::Bool, Span{start, pos_, line, col});
            if (node) doc_.nodes[node.value()].bool_value = true;
            return node;
        }
        if (match_word("false", 5)) return alloc(JsonKind::Bool, Span{start, pos_, line, col});
        if (match_word("null", 4)) return alloc(JsonKind::Null, Span{start, pos_, line, col});
        return frontend_error(
            FrontendError::UnexpectedChar, here(), lit_str("unexpected byte in JSON value"));
    }

    FrontendResult<u32> parse_array(u32 depth) {
        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        auto array = alloc(JsonKind::Array, Span{start, pos_, line, col});
        if (!array) return array;
        advance();
        skip_space();
        if (!at_end() && peek() == ']') {
            advance();
            finish_span(array.value(), start, line, col);
            return array;
        }
        u32 last = kJsonNoNode;
        for (;;) {
            skip_space();
            auto element = parse_value(depth + 1u);
            if (!element) return element;
            link_child(array.value(), &last, element.value());
            skip_space();
            if (at_end())
                return frontend_error(
                    FrontendError::UnexpectedEof, here(), lit_str("unterminated JSON array"));
            if (peek() == ',') {
                advance();
                continue;
            }
            if (peek() == ']') {
                advance();
                finish_span(array.value(), start, line, col);
                return array;
            }
            return frontend_error(FrontendError::UnexpectedChar,
                                  here(),
                                  lit_str("expected ',' or ']' in JSON array"));
        }
    }

    FrontendResult<u32> parse_object(u32 depth) {
        const u32 start = pos_;
        const u32 line = line_;
        const u32 col = col_;
        auto object = alloc(JsonKind::Object, Span{start, pos_, line, col});
        if (!object) return object;
        advance();
        skip_space();
        if (!at_end() && peek() == '}') {
            advance();
            finish_span(object.value(), start, line, col);
            return object;
        }
        u32 last = kJsonNoNode;
        for (;;) {
            skip_space();
            if (at_end())
                return frontend_error(
                    FrontendError::UnexpectedEof, here(), lit_str("unterminated JSON object"));
            if (peek() != '"')
                return frontend_error(FrontendError::UnexpectedChar,
                                      here(),
                                      lit_str("expected quoted key in JSON object"));
            const u32 key_start = pos_;
            const u32 key_line = line_;
            const u32 key_col = col_;
            bool key_has_escape = false;
            auto key = scan_string(&key_has_escape);
            if (!key) return core::make_unexpected(key.error());
            const Span key_span{key_start, pos_, key_line, key_col};
            if (!key_has_escape && doc_.member(object.value(), key.value()) != kJsonNoNode)
                return frontend_error(FrontendError::UnexpectedToken,
                                      key_span,
                                      lit_str("duplicate key in JSON object"));
            skip_space();
            if (at_end() || peek() != ':')
                return frontend_error(FrontendError::UnexpectedChar,
                                      here(),
                                      lit_str("expected ':' after JSON object key"));
            advance();
            skip_space();
            auto value = parse_value(depth + 1u);
            if (!value) return value;
            JsonNode& member = doc_.nodes[value.value()];
            member.has_key = true;
            member.key = key.value();
            member.key_has_escape = key_has_escape;
            member.key_span = key_span;
            link_child(object.value(), &last, value.value());
            skip_space();
            if (at_end())
                return frontend_error(
                    FrontendError::UnexpectedEof, here(), lit_str("unterminated JSON object"));
            if (peek() == ',') {
                advance();
                continue;
            }
            if (peek() == '}') {
                advance();
                finish_span(object.value(), start, line, col);
                return object;
            }
            return frontend_error(FrontendError::UnexpectedChar,
                                  here(),
                                  lit_str("expected ',' or '}' in JSON object"));
        }
    }

    void link_child(u32 parent, u32* last, u32 child) {
        JsonNode& p = doc_.nodes[parent];
        if (*last == kJsonNoNode) {
            p.first_child = child;
        } else {
            doc_.nodes[*last].next_sibling = child;
        }
        *last = child;
        p.child_count++;
    }

    Str source_{};
    JsonDocument& doc_;
    u32 pos_ = 0;
    u32 line_ = 1;
    u32 col_ = 1;
};

}  // namespace

u32 JsonDocument::member(u32 object, Str key) const {
    if (object == kJsonNoNode || object >= nodes.len) return kJsonNoNode;
    const JsonNode& parent = nodes[object];
    if (parent.kind != JsonKind::Object) return kJsonNoNode;
    for (u32 child = parent.first_child; child != kJsonNoNode; child = nodes[child].next_sibling) {
        const JsonNode& node = nodes[child];
        if (!node.key_has_escape && node.key.eq(key)) return child;
    }
    return kJsonNoNode;
}

FrontendResult<u32> parse_json(Str source, JsonDocument& doc) {
    return Parser(source, doc).run();
}

bool json_u32(const JsonNode& node, u32* out) {
    if (node.kind != JsonKind::Number || out == nullptr || node.raw.len == 0u) return false;
    if (node.raw.len > 1u && node.raw.ptr[0] == '0') return false;
    u64 value = 0;
    for (u32 i = 0; i < node.raw.len; i++) {
        const char c = node.raw.ptr[i];
        if (!is_digit(c)) return false;
        value = value * 10u + static_cast<u64>(c - '0');
        if (value > 0xffffffffu) return false;
    }
    *out = static_cast<u32>(value);
    return true;
}

}  // namespace rut::envoy
