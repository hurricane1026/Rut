#include "rut/runtime/oauth_introspection.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/auth.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"

namespace rut {
namespace {
bool string_value(json::Document& doc, u32 node, json::Writer& output) {
    return node != json::kNone && doc.string(node, output);
}

bool date_value(json::Document& doc, u32 node, i64& value) {
    return node != json::kNone && doc.nodes[node].kind == json::Kind::Number &&
           json::integer(doc.raw(node), value) && value >= 0;
}
bool service_authorization_valid(Str authorization, bool allow_bearer) {
    if (!authorization.ptr || authorization.len > 2048) return false;
    const bool kBasic =
        authorization.len > 6 && http_header_name_eq_ci(authorization.ptr, 6, "Basic ", 6);
    const bool kBearer = allow_bearer && authorization.len > 7 &&
                         http_header_name_eq_ci(authorization.ptr, 7, "Bearer ", 7);
    if (!kBasic && !kBearer) return false;
    for (u32 i = 0; i < authorization.len; ++i) {
        const auto kByte = static_cast<u8>(authorization.ptr[i]);
        if (kByte < 0x20 || kByte > 0x7e) return false;
    }
    return true;
}

void form_value(Str value, json::Writer& form) {
    constexpr char kHex[] = "0123456789ABCDEF";
    for (u32 i = 0; i < value.len; ++i) {
        const auto kByte = static_cast<u8>(value.ptr[i]);
        if ((kByte >= 'a' && kByte <= 'z') || (kByte >= 'A' && kByte <= 'Z') ||
            (kByte >= '0' && kByte <= '9') || kByte == '-' || kByte == '.' || kByte == '_' ||
            kByte == '~') {
            form.put(static_cast<char>(kByte));
        } else {
            form.put('%');
            form.put(kHex[kByte >> 4]);
            form.put(kHex[kByte & 15]);
        }
    }
}

bool form_request(Str body, Str authorization, json::Writer& output) {
    output.text(
        lit_str("{\"method\":\"POST\",\"headers\":{\"Content-Type\":"
                "\"application/x-www-form-urlencoded\",\"Accept\":\"application/json\","
                "\"Authorization\":"));
    if (!json::quote(authorization, output)) return false;
    output.text(lit_str("},\"body\":"));
    if (!json::quote(body, output)) return false;
    output.put('}');
    return output.ok;
}
}  // namespace

bool oauth_introspection_request(Str token, Str service_authorization, json::Writer& output) {
    if (token.len > 1024 || !bearer_key_valid(token) ||
        !service_authorization_valid(service_authorization, true))
        return false;
    char body[4096];
    json::Writer form{body, sizeof(body)};
    form.text(lit_str("token="));
    form_value(token, form);
    form.text(lit_str("&token_type_hint=access_token"));
    return form.ok && form_request({body, form.len}, service_authorization, output);
}

bool oauth_client_credentials_request(Str scopes, Str service_authorization, json::Writer& output) {
    if (scopes.len > 1024 || !jwt_scope_list_valid(scopes) ||
        !service_authorization_valid(service_authorization, false))
        return false;
    char body[4096];
    json::Writer form{body, sizeof(body)};
    form.text(lit_str("grant_type=client_credentials&scope="));
    form_value(scopes, form);
    return form.ok && form_request({body, form.len}, service_authorization, output);
}

bool oauth_introspection_valid(json::Document& doc, Str claims, Str audience, i64 unix_seconds) {
    if (!audience.ptr || !audience.len || audience.len > 1024 || unix_seconds <= 0 ||
        !doc.parse(claims) || doc.nodes[0].kind != json::Kind::Object)
        return false;
    const auto kActive = doc.pointer(lit_str("/active"));
    if (kActive == json::kNone || doc.nodes[kActive].kind != json::Kind::Boolean ||
        !doc.raw(kActive).eq(lit_str("true")))
        return false;
    i64 expires = 0;
    if (!date_value(doc, doc.pointer(lit_str("/exp")), expires) || expires <= unix_seconds)
        return false;
    constexpr Str kDates[] = {lit_str("/nbf"), lit_str("/iat")};
    for (const Str kName : kDates) {
        const auto kDate = doc.pointer(kName);
        i64 value = 0;
        if (kDate != json::kNone && (!date_value(doc, kDate, value) || value > unix_seconds))
            return false;
    }
    const auto kAudience = doc.pointer(lit_str("/aud"));
    if (kAudience == json::kNone) return false;
    bool matches = false;
    if (doc.nodes[kAudience].kind == json::Kind::String) {
        json::Writer value{doc.scratch};
        matches = string_value(doc, kAudience, value) && Str{doc.scratch, value.len}.eq(audience);
    } else if (doc.nodes[kAudience].kind == json::Kind::Array) {
        for (u32 node = doc.nodes[kAudience].child; node != json::kNone;
             node = doc.nodes[node].next) {
            json::Writer value{doc.scratch};
            if (!string_value(doc, node, value) || !value.len) return false;
            matches |= Str{doc.scratch, value.len}.eq(audience);
        }
    }
    if (!matches) return false;
    const auto kSubject = doc.pointer(lit_str("/sub"));
    if (kSubject != json::kNone) {
        json::Writer value{doc.scratch};
        if (!string_value(doc, kSubject, value) || !value.len) return false;
        for (u32 i = 0; i < value.len; ++i) {
            const auto kByte = static_cast<u8>(doc.scratch[i]);
            if (kByte < 0x20 || kByte == 0x7f) return false;
        }
    }
    const auto kScope = doc.pointer(lit_str("/scope"));
    if (kScope != json::kNone) {
        json::Writer value{doc.scratch};
        if (!string_value(doc, kScope, value) || !jwt_scope_list_valid({doc.scratch, value.len}))
            return false;
    }
    const auto kType = doc.pointer(lit_str("/token_type"));
    if (kType != json::kNone) {
        json::Writer value{doc.scratch};
        if (!string_value(doc, kType, value) ||
            !http_header_name_eq_ci(doc.scratch, value.len, "Bearer", 6))
            return false;
    }
    return true;
}
}  // namespace rut
