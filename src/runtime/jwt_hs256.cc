#include "rut/runtime/jwt_hs256.h"

#include "rut/common/types.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"

#include <stdint.h>

namespace rut {
namespace {

bool ranges_overlap(const void* left, u32 left_length, const void* right, u32 right_length) {
    if (!left || !right || left_length == 0 || right_length == 0) return false;
    const auto kLeftStart = reinterpret_cast<uintptr_t>(left);
    const auto kRightStart = reinterpret_cast<uintptr_t>(right);
    constexpr auto kMax = static_cast<uintptr_t>(-1);
    if (kLeftStart > kMax - left_length || kRightStart > kMax - right_length) return true;
    return kLeftStart < kRightStart + right_length && kRightStart < kLeftStart + left_length;
}

bool valid_claim_string(Str value) {
    if (!value.ptr || value.len == 0 || value.len > json::kMaxBytes) return false;
    u32 position = 0;
    while (position < value.len) {
        u32 codepoint = 0;
        if (!json::scalar(value, position, codepoint) || codepoint <= 0x1f || codepoint == 0x7f)
            return false;
    }
    return true;
}

bool append_positive_integer(json::Writer& output, i64 value) {
    if (value <= 0) return false;
    char reversed[20];
    u32 length = 0;
    while (value > 0) {
        reversed[length++] = static_cast<char>('0' + value % 10);
        value /= 10;
    }
    while (length > 0) output.put(reversed[--length]);
    return output.ok;
}

bool base64url_encode(const u8* input, u32 input_length, char* output, u32 capacity, u32& length) {
    length = 0;
    u32 encoded_length = 0;
    if (!rut_crypto_base64_encode_v1(
            input, input_length, reinterpret_cast<u8*>(output), capacity, &encoded_length))
        return false;
    for (u32 i = 0; i < encoded_length; ++i) {
        if (output[i] == '+')
            output[i] = '-';
        else if (output[i] == '/')
            output[i] = '_';
    }
    while (encoded_length > 0 && output[encoded_length - 1] == '=') --encoded_length;
    length = encoded_length;
    return true;
}

}  // namespace

namespace {
bool issue(Str key,
           Str subject,
           Str issuer,
           Str audience,
           Str token_id,
           bool include_id,
           Str scope,
           bool include_scope,
           i64 unix_seconds,
           i64 ttl_seconds,
           char* output,
           u32 capacity,
           u32& output_len) {
    output_len = 0;
    if (ranges_overlap(output, capacity, key.ptr, key.len) ||
        ranges_overlap(output, capacity, subject.ptr, subject.len) ||
        ranges_overlap(output, capacity, issuer.ptr, issuer.len) ||
        ranges_overlap(output, capacity, audience.ptr, audience.len) ||
        (include_id && ranges_overlap(output, capacity, token_id.ptr, token_id.len)) ||
        (include_scope && ranges_overlap(output, capacity, scope.ptr, scope.len)) ||
        ranges_overlap(&output_len, sizeof(output_len), output, capacity) ||
        ranges_overlap(&output_len, sizeof(output_len), key.ptr, key.len) ||
        ranges_overlap(&output_len, sizeof(output_len), subject.ptr, subject.len) ||
        ranges_overlap(&output_len, sizeof(output_len), issuer.ptr, issuer.len) ||
        ranges_overlap(&output_len, sizeof(output_len), audience.ptr, audience.len) ||
        (include_id &&
         ranges_overlap(&output_len, sizeof(output_len), token_id.ptr, token_id.len)) ||
        (include_scope && ranges_overlap(&output_len, sizeof(output_len), scope.ptr, scope.len)))
        return false;
    if (!key.ptr || key.len < 32 || key.len > kMaxJwtHs256KeyBytes ||
        !valid_claim_string(subject) || !valid_claim_string(issuer) ||
        !valid_claim_string(audience) || (include_id && !valid_claim_string(token_id)) ||
        (include_scope && !jwt_scope_token_valid(scope)) || unix_seconds <= 0 || ttl_seconds <= 0 ||
        ttl_seconds > 86400 || unix_seconds > 0x7fffffffffffffffLL - ttl_seconds || !output)
        return false;

    char payload[kMaxJwtHs256PayloadBytes];
    json::Writer claims{payload, sizeof(payload)};
    claims.text(lit_str("{\"sub\":"));
    if (!json::quote(subject, claims)) return false;
    claims.text(lit_str(",\"iss\":"));
    if (!json::quote(issuer, claims)) return false;
    claims.text(lit_str(",\"aud\":"));
    if (!json::quote(audience, claims)) return false;
    if (include_id) {
        claims.text(lit_str(",\"jti\":"));
        if (!json::quote(token_id, claims)) return false;
    }
    if (include_scope) {
        claims.text(lit_str(",\"scope\":"));
        if (!json::quote(scope, claims)) return false;
    }
    claims.text(lit_str(",\"iat\":"));
    if (!append_positive_integer(claims, unix_seconds)) return false;
    claims.text(lit_str(",\"exp\":"));
    if (!append_positive_integer(claims, unix_seconds + ttl_seconds)) return false;
    claims.put('}');
    if (!claims.ok || claims.len == 0) return false;

    static constexpr char kHeader[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    constexpr u32 kMaxEncodedPayloadBytes = ((kMaxJwtHs256PayloadBytes + 2) / 3) * 4 + 1;
    char encoded_payload[kMaxEncodedPayloadBytes];
    u32 encoded_payload_length = 0;
    if (!base64url_encode(reinterpret_cast<const u8*>(payload),
                          claims.len,
                          encoded_payload,
                          sizeof(encoded_payload),
                          encoded_payload_length))
        return false;

    if (capacity == 0) return false;
    const u32 kTokenCapacity =
        capacity < kMaxJwtHs256TokenBytes ? capacity : kMaxJwtHs256TokenBytes;
    constexpr u32 kHeaderB64Length = sizeof(kHeader) - 1;
    constexpr u32 kEncodedMacLength = 43;
    const u32 kSigningInputLength = kHeaderB64Length + 1 + encoded_payload_length;
    const u32 kFinalTokenLength = kSigningInputLength + 1 + kEncodedMacLength;
    if (kFinalTokenLength > kTokenCapacity) return false;

    static constexpr char kSeparator[] = ".";
    const rut_crypto_span_v1 kSigningInput[] = {
        {reinterpret_cast<const u8*>(kHeader), kHeaderB64Length},
        {reinterpret_cast<const u8*>(kSeparator), 1},
        {reinterpret_cast<const u8*>(encoded_payload), encoded_payload_length},
    };

    u8 mac[32];
    u32 mac_length = 0;
    if (!rut_crypto_digest_parts_v1(RUT_CRYPTO_SHA256_V1,
                                    kSigningInput,
                                    sizeof(kSigningInput) / sizeof(kSigningInput[0]),
                                    reinterpret_cast<const u8*>(key.ptr),
                                    key.len,
                                    1,
                                    mac,
                                    sizeof(mac),
                                    &mac_length) ||
        mac_length != sizeof(mac))
        return false;

    char encoded_mac[45];
    u32 encoded_mac_length = 0;
    if (!base64url_encode(mac, mac_length, encoded_mac, sizeof(encoded_mac), encoded_mac_length) ||
        encoded_mac_length != kEncodedMacLength)
        return false;

    u32 token_length = 0;
    for (u32 i = 0; i < kHeaderB64Length; ++i) output[token_length++] = kHeader[i];
    output[token_length++] = '.';
    for (u32 i = 0; i < encoded_payload_length; ++i) output[token_length++] = encoded_payload[i];
    output[token_length++] = '.';
    for (u32 i = 0; i < encoded_mac_length; ++i) output[token_length++] = encoded_mac[i];
    output_len = token_length;
    return true;
}
}  // namespace

bool jwt_hs256_issue(Str key,
                     Str subject,
                     Str issuer,
                     Str audience,
                     i64 unix_seconds,
                     i64 ttl_seconds,
                     char* output,
                     u32 capacity,
                     u32& output_len) {
    return issue(key,
                 subject,
                 issuer,
                 audience,
                 {},
                 false,
                 {},
                 false,
                 unix_seconds,
                 ttl_seconds,
                 output,
                 capacity,
                 output_len);
}

bool jwt_hs256_issue_with_id(Str key,
                             Str subject,
                             Str issuer,
                             Str audience,
                             Str token_id,
                             i64 unix_seconds,
                             i64 ttl_seconds,
                             char* output,
                             u32 capacity,
                             u32& output_len) {
    return issue(key,
                 subject,
                 issuer,
                 audience,
                 token_id,
                 true,
                 {},
                 false,
                 unix_seconds,
                 ttl_seconds,
                 output,
                 capacity,
                 output_len);
}

bool jwt_hs256_issue_with_id_and_scope(Str key,
                                       Str subject,
                                       Str issuer,
                                       Str audience,
                                       Str token_id,
                                       Str scope,
                                       i64 unix_seconds,
                                       i64 ttl_seconds,
                                       char* output,
                                       u32 capacity,
                                       u32& output_len) {
    return issue(key,
                 subject,
                 issuer,
                 audience,
                 token_id,
                 true,
                 scope,
                 true,
                 unix_seconds,
                 ttl_seconds,
                 output,
                 capacity,
                 output_len);
}

}  // namespace rut
