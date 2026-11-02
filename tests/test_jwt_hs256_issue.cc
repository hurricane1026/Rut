#include "rut/runtime/crypto_c.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"
#include "rut/runtime/jwt_hs256.h"
#include "test.h"

#include <openssl/crypto.h>
#include <stdlib.h>

using namespace rut;

namespace {
bool tracking = false;
u32 allocations = 0;

void* counted_malloc(size_t size, const char*, int) {
    if (tracking) ++allocations;
    return malloc(size);
}
void* counted_realloc(void* pointer, size_t size, const char*, int) {
    if (tracking) ++allocations;
    return realloc(pointer, size);
}
void counted_free(void* pointer, const char*, int) {
    free(pointer);
}

bool decode_base64url(Str input, char* output, u32 capacity, u32& length) {
    length = 0;
    if (!input.ptr || input.len % 4 == 1) return false;
    u32 accumulator = 0;
    u32 bits = 0;
    for (u32 i = 0; i < input.len; ++i) {
        const char c = input.ptr[i];
        u32 value;
        if (c >= 'A' && c <= 'Z')
            value = static_cast<u32>(c - 'A');
        else if (c >= 'a' && c <= 'z')
            value = static_cast<u32>(c - 'a' + 26);
        else if (c >= '0' && c <= '9')
            value = static_cast<u32>(c - '0' + 52);
        else if (c == '-')
            value = 62;
        else if (c == '_')
            value = 63;
        else
            return false;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (length == capacity) return false;
            output[length++] = static_cast<char>((accumulator >> bits) & 255);
        }
    }
    return bits == 0 || (accumulator & ((1u << bits) - 1)) == 0;
}

bool authenticate(Str token, Str key, char* payload, u32 capacity, u32& payload_len) {
    u32 first = token.len;
    u32 second = token.len;
    for (u32 i = 0; i < token.len; ++i) {
        if (token.ptr[i] != '.') continue;
        if (first == token.len)
            first = i;
        else if (second == token.len)
            second = i;
        else
            return false;
    }
    if (first == token.len || second == token.len || first == 0 || second <= first + 1)
        return false;
    char header[128];
    u32 header_len = 0;
    if (!decode_base64url({token.ptr, first}, header, sizeof(header), header_len) ||
        !Str{header, header_len}.eq(lit_str("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")))
        return false;
    char signature[32];
    u32 signature_len = 0;
    if (!decode_base64url({token.ptr + second + 1, token.len - second - 1},
                          signature,
                          sizeof(signature),
                          signature_len) ||
        signature_len != sizeof(signature))
        return false;
    u8 expected[32];
    u32 expected_len = 0;
    if (!rut_crypto_digest_v1(RUT_CRYPTO_SHA256_V1,
                              reinterpret_cast<const u8*>(token.ptr),
                              second,
                              reinterpret_cast<const u8*>(key.ptr),
                              key.len,
                              1,
                              expected,
                              sizeof(expected),
                              &expected_len) ||
        expected_len != sizeof(expected) ||
        !rut_crypto_equal_v1(reinterpret_cast<const u8*>(signature), expected, sizeof(expected)))
        return false;
    return decode_base64url(
        {token.ptr + first + 1, second - first - 1}, payload, capacity, payload_len);
}
}  // namespace

TEST(jwt_hs256_issue, fixed_profile_round_trips_signature_and_lifetime_claims) {
    REQUIRE(CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free));
    char key[32];
    for (char& byte : key) byte = 'k';
    const Str subject = lit_str("alice \"ops\" \\ 雪");
    const Str issuer = lit_str("issuer.example");
    const Str audience = lit_str("orders");
    char token[kMaxJwtHs256TokenBytes];
    u32 token_len = 99;
    allocations = 0;
    tracking = true;
    const bool issued = jwt_hs256_issue({key, sizeof(key)},
                                        subject,
                                        issuer,
                                        audience,
                                        1700000000,
                                        3600,
                                        token,
                                        sizeof(token),
                                        token_len);
    tracking = false;
    REQUIRE(issued);
    CHECK_EQ(allocations, 0u);
    CHECK_GT(token_len, 0u);
    CHECK((Str{token, token_len}.eq(
        lit_str("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSBcIm9wc1wiIFxcIOmbqiIsImlz"
                "cyI6Imlzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3"
                "MDAwMDM2MDB9._FET2abGSjCFAgD66bMo1mxVYCnV0Wil3HeFpMeE_V0"))));

    char payload[json::kMaxBytes];
    u32 payload_len = 0;
    CHECK(authenticate(
        {token, token_len}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
    json::Document claims;
    CHECK(jwt_claims_valid_with_lifetime(
        claims, {payload, payload_len}, issuer, audience, 1700000000, 3600, 3600));
    const Str decoded_payload{payload, payload_len};
    CHECK(
        decoded_payload.eq(lit_str("{\"sub\":\"alice \\\"ops\\\" \\\\ "
                                   "雪\",\"iss\":\"issuer.example\",\"aud\":\"orders\","
                                   "\"iat\":1700000000,\"exp\":1700003600}")));

    char changed[kMaxJwtHs256TokenBytes];
    for (u32 i = 0; i < token_len; ++i) changed[i] = token[i];
    changed[token_len - 1] = changed[token_len - 1] == 'A' ? 'B' : 'A';
    CHECK(!authenticate(
        {changed, token_len}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
    key[0] = 'x';
    CHECK(!authenticate(
        {token, token_len}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
}

TEST(jwt_hs256_issue, rejects_weak_keys_bad_text_bad_time_and_small_output) {
    char key[4097];
    for (char& byte : key) byte = 's';
    const Str valid = lit_str("valid");
    char token[kMaxJwtHs256TokenBytes];
    u32 length = 99;
    CHECK(!jwt_hs256_issue({key, 31}, valid, valid, valid, 1000, 1, token, sizeof(token), length));
    CHECK_EQ(length, 0u);
    CHECK(jwt_hs256_issue({key, 32}, valid, valid, valid, 1000, 1, token, sizeof(token), length));
    CHECK_GT(length, 0u);
    CHECK(
        !jwt_hs256_issue({key, 4097}, valid, valid, valid, 1000, 1, token, sizeof(token), length));
    CHECK_EQ(length, 0u);

    const char with_nul[] = {'a', '\0', 'b'};
    const char control[] = {'a', '\x1f', 'b'};
    const char del[] = {'a', '\x7f', 'b'};
    const char invalid_utf8[] = {static_cast<char>(0xc0), static_cast<char>(0xaf)};
    const Str invalid[] = {{with_nul, sizeof(with_nul)},
                           {control, sizeof(control)},
                           {del, sizeof(del)},
                           {invalid_utf8, sizeof(invalid_utf8)},
                           {nullptr, 1},
                           {"", 0}};
    for (Str value : invalid) {
        length = 17;
        CHECK(!jwt_hs256_issue(
            {key, 32}, value, valid, valid, 1000, 1, token, sizeof(token), length));
        CHECK_EQ(length, 0u);
        CHECK(!jwt_hs256_issue(
            {key, 32}, valid, value, valid, 1000, 1, token, sizeof(token), length));
        CHECK_EQ(length, 0u);
        CHECK(!jwt_hs256_issue(
            {key, 32}, valid, valid, value, 1000, 1, token, sizeof(token), length));
        CHECK_EQ(length, 0u);
    }

    CHECK(!jwt_hs256_issue({key, 32}, valid, valid, valid, 0, 1, token, sizeof(token), length));
    CHECK(!jwt_hs256_issue({key, 32}, valid, valid, valid, 1000, 0, token, sizeof(token), length));
    CHECK(!jwt_hs256_issue(
        {key, 32}, valid, valid, valid, 1000, 86401, token, sizeof(token), length));
    CHECK(!jwt_hs256_issue(
        {key, 32}, valid, valid, valid, 0x7fffffffffffffffLL, 1, token, sizeof(token), length));
    CHECK(jwt_hs256_issue(
        {key, 32}, valid, valid, valid, 0x7ffffffffffffffeLL, 1, token, sizeof(token), length));
    CHECK(jwt_hs256_issue({key, 32}, valid, valid, valid, 1000, 1, token, sizeof(token), length));
    const u32 exact_length = length;
    for (u32 i = 0; i < exact_length; ++i) token[i] = 'z';
    CHECK(
        !jwt_hs256_issue({key, 32}, valid, valid, valid, 1000, 1, token, exact_length - 1, length));
    CHECK_EQ(length, 0u);
    for (u32 i = 0; i < exact_length; ++i) CHECK_EQ(token[i], 'z');
    CHECK(jwt_hs256_issue({key, 32}, valid, valid, valid, 1000, 1, token, exact_length, length));
    CHECK_EQ(length, exact_length);
    CHECK(
        jwt_hs256_issue({key, 32}, valid, valid, valid, 1000, 86400, token, sizeof(token), length));
    CHECK(jwt_hs256_issue({key, 4096}, valid, valid, valid, 1000, 1, token, sizeof(token), length));

    char larger_output[kMaxJwtHs256TokenBytes + 1];
    CHECK(jwt_hs256_issue(
        {key, 32}, valid, valid, valid, 1000, 1, larger_output, sizeof(larger_output), length));
    char aliased[64] = "input";
    CHECK(!jwt_hs256_issue({key, 32}, {aliased, 5}, valid, valid, 1000, 1, aliased, 64, length));
    CHECK_EQ(length, 0u);
    u32 overlapping_storage[4] = {};
    CHECK(!jwt_hs256_issue({key, 32},
                           valid,
                           valid,
                           valid,
                           1000,
                           1,
                           reinterpret_cast<char*>(overlapping_storage),
                           sizeof(overlapping_storage),
                           overlapping_storage[0]));
}

TEST(jwt_hs256_issue, enforces_escaped_payload_limit) {
    char key[32];
    for (char& byte : key) byte = 'b';
    char quoted[1400];
    for (char& byte : quoted) byte = '"';
    const Str oversized{quoted, sizeof(quoted)};
    char token[kMaxJwtHs256TokenBytes];
    u32 length = 99;
    CHECK(!jwt_hs256_issue({key, sizeof(key)},
                           oversized,
                           oversized,
                           oversized,
                           1000,
                           1,
                           token,
                           sizeof(token),
                           length));
    CHECK_EQ(length, 0u);

    char plain[2700];
    for (char& byte : plain) byte = 'x';
    const Str large_valid{plain, sizeof(plain)};
    CHECK(jwt_hs256_issue({key, sizeof(key)},
                          large_valid,
                          large_valid,
                          large_valid,
                          1000,
                          1,
                          token,
                          sizeof(token),
                          length));
    CHECK_LE(length, kMaxJwtHs256TokenBytes);
    char payload[kMaxJwtHs256PayloadBytes];
    u32 payload_length = 0;
    CHECK(authenticate(
        {token, length}, {key, sizeof(key)}, payload, sizeof(payload), payload_length));
    json::Document claims;
    CHECK(jwt_claims_valid_with_lifetime(
        claims, {payload, payload_length}, large_valid, large_valid, 1000, 1, 1));
}

TEST(jwt_hs256_issue, issues_jti_with_bounded_validation_and_verified_signature) {
    char key[32];
    for (char& byte : key) byte = 'i';
    char token[kMaxJwtHs256TokenBytes];
    u32 length = 0;
    const Str id = lit_str("request \"42\" \\\\ 雪");
    allocations = 0;
    tracking = true;
    const bool issued = jwt_hs256_issue_with_id({key, sizeof(key)},
                                                lit_str("alice"),
                                                lit_str("issuer"),
                                                lit_str("orders"),
                                                id,
                                                1700000000,
                                                60,
                                                token,
                                                sizeof(token),
                                                length);
    tracking = false;
    CHECK(issued);
    CHECK_EQ(allocations, 0u);
    char payload[kMaxJwtHs256PayloadBytes];
    u32 payload_len = 0;
    CHECK(authenticate({token, length}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
    CHECK((Str{payload, payload_len}.eq(
        lit_str("{\"sub\":\"alice\",\"iss\":\"issuer\",\"aud\":\"orders\",\"jti\":\"request "
                "\\\"42\\\" \\\\\\\\ 雪\",\"iat\":1700000000,\"exp\":1700000060}"))));
    json::Document claims;
    CHECK(jwt_claims_valid_with_lifetime(
        claims, {payload, payload_len}, lit_str("issuer"), lit_str("orders"), 1700000000, 60, 60));
    char tampered[kMaxJwtHs256TokenBytes];
    for (u32 i = 0; i < length; ++i) tampered[i] = token[i];
    tampered[length - 1] = tampered[length - 1] == 'A' ? 'B' : 'A';
    CHECK(!authenticate(
        {tampered, length}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));

    const char bad_utf8[] = {static_cast<char>(0xc0), static_cast<char>(0xaf)};
    const char control[] = {'x', '\n'};
    const char nul[] = {'x', '\0'};
    const Str invalid[] = {{nullptr, 1},
                           {"", 0},
                           {bad_utf8, sizeof(bad_utf8)},
                           {control, sizeof(control)},
                           {nul, sizeof(nul)}};
    for (Str bad : invalid) {
        length = 99;
        CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                       lit_str("s"),
                                       lit_str("i"),
                                       lit_str("a"),
                                       bad,
                                       1000,
                                       1,
                                       token,
                                       sizeof(token),
                                       length));
        CHECK_EQ(length, 0u);
    }
    char oversized[json::kMaxBytes + 1];
    for (char& byte : oversized) byte = 'x';
    CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                   lit_str("s"),
                                   lit_str("i"),
                                   lit_str("a"),
                                   {oversized, sizeof(oversized)},
                                   1000,
                                   1,
                                   token,
                                   sizeof(token),
                                   length));
    const u32 fixed_payload = static_cast<u32>(
        lit_str(
            "{\"sub\":\"s\",\"iss\":\"i\",\"aud\":\"a\",\"jti\":\"\",\"iat\":1000,\"exp\":1001}")
            .len);
    char boundary[kMaxJwtHs256PayloadBytes];
    for (char& byte : boundary) byte = 'x';
    const u32 exact_id_length = kMaxJwtHs256PayloadBytes - fixed_payload;
    CHECK(jwt_hs256_issue_with_id({key, sizeof(key)},
                                  lit_str("s"),
                                  lit_str("i"),
                                  lit_str("a"),
                                  {boundary, exact_id_length},
                                  1000,
                                  1,
                                  token,
                                  sizeof(token),
                                  length));
    const u32 exact_capacity = length;
    CHECK(jwt_hs256_issue_with_id({key, sizeof(key)},
                                  lit_str("s"),
                                  lit_str("i"),
                                  lit_str("a"),
                                  {boundary, exact_id_length},
                                  1000,
                                  1,
                                  token,
                                  exact_capacity,
                                  length));
    CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                   lit_str("s"),
                                   lit_str("i"),
                                   lit_str("a"),
                                   {boundary, exact_id_length + 1},
                                   1000,
                                   1,
                                   token,
                                   sizeof(token),
                                   length));
    CHECK_EQ(length, 0u);
    CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                   lit_str("s"),
                                   lit_str("i"),
                                   lit_str("a"),
                                   id,
                                   0x7fffffffffffffffLL,
                                   1,
                                   token,
                                   sizeof(token),
                                   length));
    CHECK_EQ(length, 0u);
    CHECK(jwt_hs256_issue_with_id({key, sizeof(key)},
                                  lit_str("s"),
                                  lit_str("i"),
                                  lit_str("a"),
                                  id,
                                  1000,
                                  1,
                                  token,
                                  sizeof(token),
                                  length));
    const u32 exact = length;
    CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                   lit_str("s"),
                                   lit_str("i"),
                                   lit_str("a"),
                                   id,
                                   1000,
                                   1,
                                   token,
                                   exact - 1,
                                   length));
    CHECK_EQ(length, 0u);
    char aliased[32] = "identifier";
    CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                   lit_str("s"),
                                   lit_str("i"),
                                   lit_str("a"),
                                   {aliased, 10},
                                   1000,
                                   1,
                                   aliased,
                                   sizeof(aliased),
                                   length));
    CHECK_EQ(length, 0u);
    u32 overlap[4] = {};
    CHECK(!jwt_hs256_issue_with_id({key, sizeof(key)},
                                   lit_str("s"),
                                   lit_str("i"),
                                   lit_str("a"),
                                   {reinterpret_cast<char*>(&overlap[0]), 4},
                                   1000,
                                   1,
                                   token,
                                   sizeof(token),
                                   overlap[0]));
}

TEST(jwt_hs256_issue, issues_jti_and_one_scope_with_verified_signature_without_allocations) {
    char key[32];
    for (char& byte : key) byte = 's';
    const Str id = lit_str("request-17");
    const Str scope = lit_str("orders:read");
    char token[kMaxJwtHs256TokenBytes];
    u32 length = 0;
    allocations = 0;
    tracking = true;
    const bool issued = jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                                          lit_str("alice"),
                                                          lit_str("issuer"),
                                                          lit_str("orders"),
                                                          id,
                                                          scope,
                                                          1700000000,
                                                          900,
                                                          token,
                                                          sizeof(token),
                                                          length);
    tracking = false;
    REQUIRE(issued);
    CHECK_EQ(allocations, 0u);
    char payload[kMaxJwtHs256PayloadBytes];
    u32 payload_len = 0;
    REQUIRE(
        authenticate({token, length}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
    CHECK((Str{payload, payload_len}.eq(
        lit_str("{\"sub\":\"alice\",\"iss\":\"issuer\",\"aud\":\"orders\","
                "\"jti\":\"request-17\",\"scope\":\"orders:read\","
                "\"iat\":1700000000,\"exp\":1700000900}"))));
    char tampered[kMaxJwtHs256TokenBytes];
    __builtin_memcpy(tampered, token, length);
    tampered[length - 1] = tampered[length - 1] == 'A' ? 'B' : 'A';
    CHECK(!authenticate(
        {tampered, length}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
    json::Document claims;
    REQUIRE(jwt_claims_valid_with_lifetime(claims,
                                           {payload, payload_len},
                                           lit_str("issuer"),
                                           lit_str("orders"),
                                           1700000000,
                                           900,
                                           900));
    CHECK(jwt_has_scope(claims, {payload, payload_len}, scope));
    CHECK(!jwt_has_scope(claims, {payload, payload_len}, lit_str("orders:write")));

    char large_subject[json::kMaxBytes];
    for (char& byte : large_subject) byte = 'x';
    u32 low = 1;
    u32 high = sizeof(large_subject);
    u32 largest_valid = 0;
    while (low <= high) {
        const u32 mid = low + (high - low) / 2;
        u32 trial_len = 0;
        if (jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                              {large_subject, mid},
                                              lit_str("issuer"),
                                              lit_str("orders"),
                                              id,
                                              scope,
                                              1700000000,
                                              900,
                                              token,
                                              sizeof(token),
                                              trial_len)) {
            largest_valid = mid;
            low = mid + 1;
        } else {
            if (mid == 0) break;
            high = mid - 1;
        }
    }
    CHECK_GT(largest_valid, 0u);
    REQUIRE(jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                              {large_subject, largest_valid},
                                              lit_str("issuer"),
                                              lit_str("orders"),
                                              id,
                                              scope,
                                              1700000000,
                                              900,
                                              token,
                                              sizeof(token),
                                              length));
    CHECK_EQ(length, kMaxJwtHs256TokenBytes);
    REQUIRE(
        authenticate({token, length}, {key, sizeof(key)}, payload, sizeof(payload), payload_len));
    CHECK_EQ(payload_len, kMaxJwtHs256PayloadBytes);
    CHECK(!jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                             {large_subject, largest_valid},
                                             lit_str("issuer"),
                                             lit_str("orders"),
                                             id,
                                             scope,
                                             1700000000,
                                             900,
                                             token,
                                             kMaxJwtHs256TokenBytes - 1,
                                             length));
    CHECK_EQ(length, 0u);

    const char invalid_non_ascii[] = {'r', static_cast<char>(0xc3), static_cast<char>(0xa9)};
    const char control[] = {'r', '\n'};
    const Str invalid_scopes[] = {lit_str(""),
                                  lit_str("two words"),
                                  lit_str("quote\""),
                                  lit_str("slash\\"),
                                  {control, sizeof(control)},
                                  {invalid_non_ascii, sizeof(invalid_non_ascii)}};
    for (Str bad : invalid_scopes) {
        length = 99;
        CHECK(!jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                                 lit_str("alice"),
                                                 lit_str("issuer"),
                                                 lit_str("orders"),
                                                 id,
                                                 bad,
                                                 1700000000,
                                                 900,
                                                 token,
                                                 sizeof(token),
                                                 length));
        CHECK_EQ(length, 0u);
    }

    length = 0;
    CHECK(jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                            lit_str("alice"),
                                            lit_str("issuer"),
                                            lit_str("orders"),
                                            id,
                                            scope,
                                            1700000000,
                                            900,
                                            token,
                                            sizeof(token),
                                            length));
    const u32 token_size = length;
    CHECK_GT(token_size, 0u);
    CHECK(!jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                             lit_str("alice"),
                                             lit_str("issuer"),
                                             lit_str("orders"),
                                             id,
                                             scope,
                                             1700000000,
                                             900,
                                             token,
                                             token_size - 1,
                                             length));
    CHECK_EQ(length, 0u);
    u32 scope_overlap[4] = {};
    __builtin_memcpy(scope_overlap, "orders:read", 11);
    CHECK(!jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                             lit_str("alice"),
                                             lit_str("issuer"),
                                             lit_str("orders"),
                                             id,
                                             {reinterpret_cast<char*>(scope_overlap), 11},
                                             1700000000,
                                             900,
                                             token,
                                             sizeof(token),
                                             scope_overlap[0]));
    CHECK_EQ(scope_overlap[0], 0u);
    char overlap[32] = "orders:read";
    CHECK(!jwt_hs256_issue_with_id_and_scope({key, sizeof(key)},
                                             lit_str("alice"),
                                             lit_str("issuer"),
                                             lit_str("orders"),
                                             id,
                                             {overlap, 11},
                                             1700000000,
                                             900,
                                             overlap,
                                             sizeof(overlap),
                                             length));
    CHECK_EQ(length, 0u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
