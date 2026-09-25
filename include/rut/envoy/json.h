#pragma once

#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"

namespace rut::envoy {

// Bounded JSON document tree for the Envoy bootstrap frontend.
//
// The parser accepts strict RFC 8259 text only: no comments, no trailing
// commas, no unquoted keys, no NaN/Infinity, no leading zeros. Every value
// keeps its source span so a later semantic diagnostic can point at the exact
// field. String values are retained as raw source slices between the quotes;
// escape sequences are validated syntactically but never decoded. Consumers
// that need a string's contents call `is_plain()` and reject escaped strings
// as unsupported, so no decoded copy is ever needed.
//
// Object keys containing an escape sequence are rejected outright
// (UnsupportedSyntax, anchored at the key span) instead of being admitted
// into the tree. This keeps `key` always the literal source bytes, so member
// lookup and duplicate-key detection can use exact byte comparison without
// decoding; the semantic layer already treated every escaped key as
// unsupported, so nothing legitimate is lost.
//
// Nodes live in one fixed arena. Object members and array elements are linked
// through `first_child` / `next_sibling` in source order. An object member is
// the value node itself carrying its `key`; keys are not separate nodes.

enum class JsonKind : u8 {
    Null,
    Bool,
    Number,
    String,
    Object,
    Array,
};

static constexpr u32 kJsonNoNode = 0xffffffffu;

struct JsonNode {
    JsonKind kind = JsonKind::Null;
    bool bool_value = false;
    // String: raw bytes between the quotes. Number: the raw numeric token.
    Str raw{};
    bool has_escape = false;
    // Set only for object members. `key` is always the literal source bytes:
    // an escaped key is a parse error, never admitted into the tree.
    bool has_key = false;
    Str key{};
    Span key_span{};
    // Span of the whole value, including quotes/brackets.
    Span span{};
    u32 first_child = kJsonNoNode;
    u32 next_sibling = kJsonNoNode;
    u32 child_count = 0;

    [[nodiscard]] bool is_plain() const { return kind == JsonKind::String && !has_escape; }
};

// A 1 MiB input could hold far more values than this, but the bootstrap
// shapes this frontend admits are small. Overflow is a diagnostic, not a
// truncated tree.
static constexpr u32 kMaxJsonNodes = 4096;
static constexpr u32 kMaxJsonDepth = 32;

struct JsonDocument {
    FixedVec<JsonNode, kMaxJsonNodes> nodes{};
    u32 root = kJsonNoNode;

    [[nodiscard]] const JsonNode& at(u32 index) const { return nodes[index]; }

    // Look up an object member by exact key bytes. Returns kJsonNoNode when
    // `object` is not an object or the key is absent. Duplicate keys are
    // rejected by the parser, so the first match is the only match.
    [[nodiscard]] u32 member(u32 object, Str key) const;
};

// Parse one complete JSON text. Trailing whitespace is allowed; any other
// trailing byte is a diagnostic. The document borrows `source`, which must
// stay readable for as long as the document is used.
FrontendResult<u32> parse_json(Str source, JsonDocument& doc);

// Parse a raw (unescaped) JSON number token as a non-negative integer that
// fits in u32. Fractions, exponents, signs and leading zeros are rejected.
bool json_u32(const JsonNode& node, u32* out);

}  // namespace rut::envoy
