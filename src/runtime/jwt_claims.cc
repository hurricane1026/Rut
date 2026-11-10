#include "rut/runtime/jwt_claims.h"

#include "rut/common/types.h"
#include "rut/runtime/auth.h"
#include "rut/runtime/crypto_c.h"
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

namespace {

bool scope_set_matches(json::Document& document,
                       Str claims,
                       Str required_scopes,
                       bool require_all) {
    constexpr u32 kMaxRequiredBytes = 1024;
    if (required_scopes.len > kMaxRequiredBytes || !jwt_scope_list_valid(required_scopes))
        return false;
    // Preserve required bytes even when the caller borrowed document scratch.
    char required[kMaxRequiredBytes];
    for (u32 i = 0; i < required_scopes.len; ++i) required[i] = required_scopes.ptr[i];
    if (claims.ptr == nullptr || !document.parse(claims) ||
        document.nodes[0].kind != json::Kind::Object)
        return false;
    const u32 kScope = member(document, lit_str("scope"));
    if (kScope == json::kNone) return false;
    json::Writer decoded{document.scratch};
    if (!document.string(kScope, decoded)) return false;
    const Str kGranted{document.scratch, decoded.len};
    if (!jwt_scope_list_valid(kGranted)) return false;
    bool any = false;
    u32 start = 0;
    for (u32 i = 0; i <= required_scopes.len; ++i) {
        if (i != required_scopes.len && required[i] != ' ') continue;
        bool found = false;
        if (!scope_list_matches(kGranted, {required + start, i - start}, found) ||
            (require_all && !found))
            return false;
        any |= found;
        start = i + 1;
    }
    return require_all || any;
}

}  // namespace

bool jwt_has_all_scopes(json::Document& document, Str claims, Str required_scopes) {
    return scope_set_matches(document, claims, required_scopes, true);
}

bool jwt_has_any_scope(json::Document& document, Str claims, Str required_scopes) {
    return scope_set_matches(document, claims, required_scopes, false);
}

bool jwt_certificate_bound(json::Document& document, Str claims, Str certificate_sha256) {
    if (!sha256_hex_format_valid(certificate_sha256) || claims.ptr == nullptr ||
        !document.parse(claims) || document.nodes[0].kind != json::Kind::Object)
        return false;
    const u32 kConfirmation = member(document, lit_str("cnf"));
    if (kConfirmation == json::kNone || document.nodes[kConfirmation].kind != json::Kind::Object)
        return false;
    const u32 kThumbprint = document.nodes[kConfirmation].child;
    // This profile admits one confirmation method and never falls back to
    // another key/certificate claim when the certificate binding is missing.
    if (kThumbprint == json::kNone || document.nodes[kThumbprint].next != json::kNone) return false;
    json::Writer key{document.scratch};
    if (!document.string(document.nodes[kThumbprint].key, key) ||
        !Str{document.scratch, key.len}.eq(lit_str("x5t#S256")))
        return false;
    json::Writer thumbprint{document.scratch};
    if (!document.string(kThumbprint, thumbprint) || thumbprint.len != 43) return false;

    u8 digest[32]{};
    const auto kNibble = [](char value) -> u8 {
        return static_cast<u8>(value <= '9' ? value - '0' : value - 'a' + 10);
    };
    const char* hex = certificate_sha256.ptr;
    for (u32 i = 0; i < 32; ++i) {
        const u8 kHigh = kNibble(*hex++);
        const u8 kLow = kNibble(*hex++);
        digest[i] = static_cast<u8>((kHigh << 4) | kLow);
    }
    u8 encoded[45]{};
    u32 length = 0;
    if (!rut_crypto_base64_encode_v1(digest, sizeof(digest), encoded, sizeof(encoded), &length) ||
        length != 44 || encoded[43] != '=')
        return false;
    for (u32 i = 0; i < 43; ++i) {
        if (encoded[i] == '+') encoded[i] = '-';
        if (encoded[i] == '/') encoded[i] = '_';
    }
    // Comparing the canonical encoding also rejects nonzero unused padding
    // bits, standard Base64 alphabet, padding, whitespace and truncation.
    return rut_crypto_equal_v1(encoded, reinterpret_cast<const u8*>(document.scratch), 43) != 0;
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
