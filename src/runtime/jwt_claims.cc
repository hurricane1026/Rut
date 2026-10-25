#include "rut/runtime/jwt_claims.h"

#include "rut/common/types.h"
#include "rut/runtime/json.h"

namespace rut {
namespace {

u32 member(json::Document& document, Str name) {
    for (u32 node = document.nodes[0].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[node].key, key)) return json::kNone;
        if (Str{document.scratch, key.len}.eq(name)) return node;
    }
    return json::kNone;
}

bool string_matches(json::Document& document, u32 node, Str expected) {
    if (node == json::kNone) return false;
    json::Writer value{document.scratch};
    return document.string(node, value) && Str{document.scratch, value.len}.eq(expected);
}

bool date(json::Document& document, u32 node, i64& value) {
    return node != json::kNone && document.nodes[node].kind == json::Kind::Number &&
           json::integer(document.raw(node), value);
}

}  // namespace

bool jwt_claims_valid(
    json::Document& document, Str claims, Str issuer, Str audience, i64 unix_seconds) {
    if (claims.ptr == nullptr || issuer.ptr == nullptr || audience.ptr == nullptr ||
        issuer.len == 0 || audience.len == 0 || unix_seconds <= 0 || !document.parse(claims) ||
        document.nodes[0].kind != json::Kind::Object)
        return false;
    // The shared parser rejects all duplicate decoded object keys, including
    // escaped aliases, and enforces byte/node/depth and UTF-8 bounds.
    const u32 kSubject = member(document, lit_str("sub"));
    if (kSubject == json::kNone) return false;
    json::Writer subject{document.scratch};
    if (!document.string(kSubject, subject) || subject.len == 0) return false;
    if (!string_matches(document, member(document, lit_str("iss")), issuer)) return false;

    const u32 kAudience = member(document, lit_str("aud"));
    if (kAudience == json::kNone) return false;
    bool matches = false;
    if (document.nodes[kAudience].kind == json::Kind::String) {
        matches = string_matches(document, kAudience, audience);
    } else if (document.nodes[kAudience].kind == json::Kind::Array) {
        for (u32 node = document.nodes[kAudience].child; node != json::kNone;
             node = document.nodes[node].next) {
            json::Writer value{document.scratch};
            if (!document.string(node, value) || value.len == 0) return false;
            matches |= Str{document.scratch, value.len}.eq(audience);
        }
    } else {
        return false;
    }
    if (!matches) return false;

    i64 expires = 0;
    if (!date(document, member(document, lit_str("exp")), expires) || expires <= unix_seconds)
        return false;
    const u32 kNotBefore = member(document, lit_str("nbf"));
    i64 not_before = 0;
    if (kNotBefore != json::kNone &&
        (!date(document, kNotBefore, not_before) || not_before > unix_seconds))
        return false;
    const u32 kIssuedAt = member(document, lit_str("iat"));
    i64 issued_at = 0;
    return kIssuedAt == json::kNone ||
           (date(document, kIssuedAt, issued_at) && issued_at <= unix_seconds);
}

bool jwt_has_scope(json::Document& document, Str claims, Str required) {
    const auto kTokenByte = [](unsigned char c) {
        return c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e);
    };
    if (required.ptr == nullptr || required.len == 0 || required.len > json::kMaxBytes)
        return false;
    for (u32 i = 0; i < required.len; ++i)
        if (!kTokenByte(static_cast<unsigned char>(required.ptr[i]))) return false;
    if (claims.ptr == nullptr || !document.parse(claims) ||
        document.nodes[0].kind != json::Kind::Object)
        return false;
    const u32 kScope = member(document, lit_str("scope"));
    if (kScope == json::kNone) return false;
    json::Writer decoded{document.scratch};
    if (!document.string(kScope, decoded) || decoded.len == 0) return false;
    // Validate the whole list even after a match: a malformed suffix cannot
    // turn a malformed permission document into an authorization success.
    bool found = false;
    u32 start = 0;
    for (u32 i = 0; i <= decoded.len; ++i) {
        if (i == decoded.len || document.scratch[i] == ' ') {
            if (i == start) return false;
            found |= Str{document.scratch + start, i - start}.eq(required);
            start = i + 1;
        } else if (!kTokenByte(static_cast<unsigned char>(document.scratch[i]))) {
            return false;
        }
    }
    return found;
}

}  // namespace rut
