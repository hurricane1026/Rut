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

bool scope_token_byte(unsigned char c) {
    return c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e);
}

// Validate the entire list even after a match, so a malformed suffix cannot
// authorize a permission or be emitted by the issuer. Views are never retained.
bool scope_list_matches(Str scopes, Str required, bool& found) {
    found = false;
    if (scopes.ptr == nullptr || scopes.len == 0 || scopes.len > json::kMaxBytes) return false;
    u32 start = 0;
    for (u32 i = 0; i <= scopes.len; ++i) {
        if (i == scopes.len || scopes.ptr[i] == ' ') {
            if (i == start) return false;
            found |= Str{scopes.ptr + start, i - start}.eq(required);
            start = i + 1;
        } else if (!scope_token_byte(static_cast<unsigned char>(scopes.ptr[i]))) {
            return false;
        }
    }
    return true;
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

bool jwt_claims_valid_with_lifetime(json::Document& document,
                                    Str claims,
                                    Str issuer,
                                    Str audience,
                                    i64 unix_seconds,
                                    i64 max_age_seconds,
                                    i64 max_lifetime_seconds) {
    if (max_age_seconds <= 0 || max_lifetime_seconds <= 0 ||
        !jwt_claims_valid(document, claims, issuer, audience, unix_seconds))
        return false;

    i64 issued_at = 0;
    i64 expires = 0;
    if (!date(document, member(document, lit_str("iat")), issued_at) || issued_at <= 0 ||
        !date(document, member(document, lit_str("exp")), expires) || expires <= 0 ||
        issued_at > unix_seconds || unix_seconds >= expires || expires <= issued_at)
        return false;

    // Positivity and ordering above make both subtractions representable.
    return unix_seconds - issued_at <= max_age_seconds &&
           expires - issued_at <= max_lifetime_seconds;
}

bool jwt_scope_token_valid(Str token) {
    if (token.ptr == nullptr || token.len == 0 || token.len > json::kMaxBytes) return false;
    for (u32 i = 0; i < token.len; ++i) {
        const auto kByte = static_cast<unsigned char>(token.ptr[i]);
        if (!scope_token_byte(kByte)) return false;
    }
    return true;
}

bool jwt_scope_list_valid(Str scopes) {
    bool ignored = false;
    return scope_list_matches(scopes, {}, ignored);
}

bool jwt_has_scope(json::Document& document, Str claims, Str required) {
    if (required.ptr == nullptr || required.len == 0 || required.len > json::kMaxBytes)
        return false;
    if (!jwt_scope_token_valid(required)) return false;
    if (claims.ptr == nullptr || !document.parse(claims) ||
        document.nodes[0].kind != json::Kind::Object)
        return false;
    const u32 kScope = member(document, lit_str("scope"));
    if (kScope == json::kNone) return false;
    json::Writer decoded{document.scratch};
    if (!document.string(kScope, decoded) || decoded.len == 0) return false;
    bool found = false;
    return scope_list_matches({document.scratch, decoded.len}, required, found) && found;
}

bool jwt_has_group(json::Document& document, Str claims, Str required) {
    if (required.ptr == nullptr || required.len == 0 || required.len > json::kMaxBytes ||
        claims.ptr == nullptr || !document.parse(claims) ||
        document.nodes[0].kind != json::Kind::Object)
        return false;
    const u32 kGroups = member(document, lit_str("groups"));
    if (kGroups == json::kNone || document.nodes[kGroups].kind != json::Kind::Array ||
        document.nodes[kGroups].child == json::kNone)
        return false;

    // Membership is exact, but validate every entry even after a match so a
    // malformed suffix cannot turn an invalid policy document into success.
    bool found = false;
    for (u32 node = document.nodes[kGroups].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer value{document.scratch};
        if (!document.string(node, value) || value.len == 0) return false;
        found |= Str{document.scratch, value.len}.eq(required);
    }
    return found;
}

}  // namespace rut
