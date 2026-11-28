#include "rut/runtime/oauth_introspection.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/auth.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

bool hex_byte(char byte) {
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') ||
           (byte >= 'A' && byte <= 'F');
}

bool resource_identifier_valid(Str resource) {
    if (!resource.ptr || resource.len > 1024 || resource.len <= 8 ||
        !http_header_name_eq_ci(resource.ptr, 8, "https://", 8))
        return false;
    u32 end = 8;
    while (end < resource.len && resource.ptr[end] != '/' && resource.ptr[end] != '?') ++end;
    if (end == 8) return false;
    u32 port;
    if (resource.ptr[8] == '[') {
        u32 close = 9;
        while (close < end && resource.ptr[close] != ']') ++close;
        char address[INET6_ADDRSTRLEN];
        const i64 address_len = i64{close} - 9;
        if (close == end || close == 9 || address_len >= i64{sizeof(address)}) return false;
        for (u32 i = 9; i < close; ++i) {
            const char kByte = resource.ptr[i];
            if (!hex_byte(kByte) && kByte != ':' && kByte != '.') return false;
            address[i64{i} - 9] = kByte;
        }
        address[address_len] = 0;
        struct in6_addr parsed{};
        if (inet_pton(AF_INET6, address, &parsed) != 1) return false;
        port = static_cast<u32>(static_cast<i64>(close) + 1);
        if (port != end && resource.ptr[port] != ':') return false;
    } else {
        u32 host_end = 8;
        while (host_end < end && resource.ptr[host_end] != ':') ++host_end;
        if (host_end == 8 || i64{host_end} - 8 > 253) return false;
        u32 label = 0;
        for (u32 i = 8; i < host_end; ++i) {
            const char kByte = resource.ptr[i];
            if (kByte == '.') {
                if (!label || resource.ptr[i64{i} - 1] == '-') return false;
                label = 0;
            } else {
                const bool kLetter =
                    (kByte >= 'a' && kByte <= 'z') || (kByte >= 'A' && kByte <= 'Z');
                const bool kDigit = kByte >= '0' && kByte <= '9';
                if (!kLetter && !kDigit && kByte != '-') return false;
                if (!label && kByte == '-') return false;
                ++label;
                if (label > 63) return false;
            }
        }
        if (!label || resource.ptr[i64{host_end} - 1] == '-') return false;
        port = host_end;
    }
    if (port < end) {
        if (++port == end) return false;
        u32 number = 0;
        for (; port < end; ++port) {
            const char kByte = resource.ptr[port];
            if (kByte < '0' || kByte > '9') return false;
            const i64 next_number = i64{number} * 10 + i64{kByte - '0'};
            if (next_number > 65535) return false;
            number = static_cast<u32>(next_number);
        }
        if (!number) return false;
    }
    // RFC 3986 pchar plus path/query separators; percent escapes are preserved,
    // not decoded. No userinfo, fragment, raw control, Unicode or backslash.
    for (u32 i = end; i < resource.len; ++i) {
        const char kByte = resource.ptr[i];
        if (kByte == '%') {
            if (i64{resource.len} - i64{i} < 3 || !hex_byte(resource.ptr[i64{i} + 1]) ||
                !hex_byte(resource.ptr[i64{i} + 2]))
                return false;
            i = static_cast<u32>(static_cast<i64>(i) + 2);
        } else {
            const bool kAllowed =
                (kByte >= 'a' && kByte <= 'z') || (kByte >= 'A' && kByte <= 'Z') ||
                (kByte >= '0' && kByte <= '9') || kByte == '-' || kByte == '.' || kByte == '_' ||
                kByte == '~' || kByte == '!' || kByte == '$' || kByte == '&' || kByte == '\'' ||
                kByte == '(' || kByte == ')' || kByte == '*' || kByte == '+' || kByte == ',' ||
                kByte == ';' || kByte == '=' || kByte == ':' || kByte == '@' || kByte == '/' ||
                kByte == '?';
            if (!kAllowed) return false;
        }
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

bool oauth_client_basic_authorization(Str client_id, Str client_secret, json::Writer& output) {
    const auto kValid = [](Str value) {
        if (!value.ptr || !value.len || value.len > 256) return false;
        for (u32 i = 0; i < value.len; ++i) {
            const auto kByte = static_cast<u8>(value.ptr[i]);
            if (kByte < 0x20 || kByte > 0x7e) return false;
        }
        return true;
    };
    if (!kValid(client_id) || !kValid(client_secret)) return false;
    struct Sensitive {
        char userinfo[1530];
        u8 encoded[2041];
        ~Sensitive() { rut_crypto_clear_v1(this, sizeof(*this)); }
    } scratch;
    json::Writer form{scratch.userinfo, sizeof(scratch.userinfo)};
    const auto kComponent = [&](Str value) {
        constexpr char kHex[] = "0123456789ABCDEF";
        for (u32 i = 0; i < value.len; ++i) {
            const auto kByte = static_cast<u8>(value.ptr[i]);
            if ((kByte >= 'a' && kByte <= 'z') || (kByte >= 'A' && kByte <= 'Z') ||
                (kByte >= '0' && kByte <= '9') || kByte == '*' || kByte == '-' || kByte == '.' ||
                kByte == '_') {
                form.put(static_cast<char>(kByte));
            } else if (kByte == ' ') {
                form.put('+');
            } else {
                form.put('%');
                form.put(kHex[kByte >> 4]);
                form.put(kHex[kByte & 15]);
            }
        }
    };
    kComponent(client_id);
    form.put(':');
    kComponent(client_secret);
    if (!form.ok) return false;
    u32 encoded_length = 0;
    if (!rut_crypto_base64_encode_v1(reinterpret_cast<const u8*>(form.data),
                                     form.len,
                                     scratch.encoded,
                                     sizeof(scratch.encoded),
                                     &encoded_length) ||
        !output.ok || output.len > output.cap ||
        i64{encoded_length} + 6 > i64{output.cap} - i64{output.len})
        return false;
    output.text(lit_str("Basic "));
    output.text({reinterpret_cast<const char*>(scratch.encoded), encoded_length});
    return output.ok;
}

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

bool oauth_client_credentials_request(Str scopes,
                                      Str service_authorization,
                                      Str resource,
                                      json::Writer& output) {
    if (scopes.len > 1024 || !jwt_scope_list_valid(scopes) ||
        !service_authorization_valid(service_authorization, false) ||
        !resource_identifier_valid(resource))
        return false;
    char body[4096];
    json::Writer form{body, sizeof(body)};
    form.text(lit_str("grant_type=client_credentials&scope="));
    form_value(scopes, form);
    form.text(lit_str("&resource="));
    form_value(resource, form);
    return form.ok && form_request({body, form.len}, service_authorization, output);
}

bool oauth_token_exchange_request(json::Document& scratch,
                                  Str subject_token,
                                  Str service_authorization,
                                  Str policy_json,
                                  json::Writer& output) {
    if (subject_token.len > 1024 || !bearer_key_valid(subject_token) ||
        !service_authorization_valid(service_authorization, false) || !scratch.parse(policy_json) ||
        scratch.nodes[0].kind != json::Kind::Object)
        return false;
    char scopes[1024], resource[1024];
    json::Writer scope_value{scopes, sizeof(scopes)}, resource_value{resource, sizeof(resource)};
    u32 seen = 0;
    for (u32 node = scratch.nodes[0].child; node != json::kNone; node = scratch.nodes[node].next) {
        json::Writer key{scratch.scratch};
        if (!scratch.string(scratch.nodes[node].key, key)) return false;
        const Str kName{scratch.scratch, key.len};
        const u32 kBit = kName.eq(lit_str("scope")) ? 1u : kName.eq(lit_str("resource")) ? 2u : 0u;
        if (!kBit || (seen & kBit)) return false;
        seen |= kBit;
        if (!scratch.string(node, kBit == 1 ? scope_value : resource_value)) return false;
    }
    if (seen != 3 || !jwt_scope_list_valid({scopes, scope_value.len}) ||
        !resource_identifier_valid({resource, resource_value.len}))
        return false;
    char body[4096];
    json::Writer form{body, sizeof(body)};
    form.text(lit_str("grant_type="));
    form_value(lit_str("urn:ietf:params:oauth:grant-type:token-exchange"), form);
    form.text(lit_str("&subject_token_type="));
    form_value(lit_str("urn:ietf:params:oauth:token-type:access_token"), form);
    form.text(lit_str("&requested_token_type="));
    form_value(lit_str("urn:ietf:params:oauth:token-type:access_token"), form);
    form.text(lit_str("&subject_token="));
    form_value(subject_token, form);
    form.text(lit_str("&scope="));
    form_value({scopes, scope_value.len}, form);
    form.text(lit_str("&resource="));
    form_value({resource, resource_value.len}, form);
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
