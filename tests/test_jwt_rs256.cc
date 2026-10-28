#include "public_key_fixtures.h"
#include "rsa_verify_fixtures.h"
#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"
#include "rut/runtime/jwt_rs256.h"
#include "rut/runtime/public_key.h"
#include "rut/runtime/rs256_policy.h"
#include "test.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
using namespace rut;
static bool tracking = false;
static u32 allocations = 0;
static i64 allocation_budget = -1;
static void* counted_malloc(size_t n, const char*, int) {
    if (tracking) ++allocations;
    if (allocation_budget == 0) return nullptr;
    if (allocation_budget > 0) --allocation_budget;
    return malloc(n);
}
static void* counted_realloc(void* p, size_t n, const char*, int) {
    if (tracking) ++allocations;
    if (allocation_budget == 0) return nullptr;
    if (allocation_budget > 0) --allocation_budget;
    return realloc(p, n);
}
static void counted_free(void* p, const char*, int) {
    free(p);
}

static u32 encode(Str input, char* out) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    u32 accumulator = 0, bits = 0, length = 0;
    for (u32 i = 0; i < input.len; ++i) {
        accumulator = (accumulator << 8) | static_cast<u8>(input.ptr[i]);
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out[length++] = alphabet[(accumulator >> bits) & 63];
        }
    }
    if (bits) out[length++] = alphabet[(accumulator << (6 - bits)) & 63];
    return length;
}
static Str token_for(RSA* rsa, Str header, Str claims, char* output) {
    u32 length = encode(header, output);
    output[length++] = '.';
    length += encode(claims, output + length);
    u8 digest[32];
    u32 digest_length = 0;
    if (!hash_digest(HashAlgorithm::Sha256, {output, length}, {}, false, digest, 32, digest_length))
        return {};
    unsigned char signature[512];
    unsigned int signature_length = 0;
    if (!RSA_sign(NID_sha256, digest, 32, signature, &signature_length, rsa)) return {};
    output[length++] = '.';
    length += encode({reinterpret_cast<const char*>(signature), signature_length}, output + length);
    return {output, length};
}
TEST(jwt_rs256, rfc_vector_and_failure_publication) {
    RsaPublicKey key;
    RsaSha256Verifier verifier;
    json::Document doc;
    REQUIRE(key.load({reinterpret_cast<const char*>(kRfcRsaSpki), sizeof(kRfcRsaSpki)}));
    REQUIRE(verifier.init(key));
    key.reset();
    char token[1024];
    u32 length = sizeof(kMessage) - 1;
    for (u32 i = 0; i < length; ++i) token[i] = kMessage[i];
    token[length++] = '.';
    length +=
        encode({reinterpret_cast<const char*>(kSignature), sizeof(kSignature)}, token + length);
    char output[8192];
    u32 out_length = 42;
    allocations = 0;
    tracking = true;
    bool accepted =
        jwt_rs256_decode(verifier, doc, {token, length}, output, sizeof(output), out_length);
    tracking = false;
    REQUIRE(accepted);
    CHECK_EQ(allocations, 0u);
    CHECK(out_length > 0);
    CHECK(doc.source.ptr == output);
    CHECK(doc.nodes[0].kind == json::Kind::Object);
    tracking = true;
    for (u32 i = 0; i < length; ++i) {
        char old = token[i];
        token[i] = old == 'A' ? 'B' : 'A';
        CHECK(
            !jwt_rs256_decode(verifier, doc, {token, length}, output, sizeof(output), out_length));
        CHECK_EQ(out_length, 0u);
        CHECK(!doc.valid);
        CHECK_EQ(doc.count, 0u);
        CHECK(doc.source.ptr == nullptr);
        token[i] = old;
    }
    tracking = false;
    CHECK_EQ(allocations, 0u);
    CHECK(!jwt_rs256_decode(verifier, doc, {nullptr, 1}, output, sizeof(output), out_length));
    CHECK(!jwt_rs256_decode(verifier, doc, {token, 24577}, output, sizeof(output), out_length));
    CHECK(!jwt_rs256_decode(verifier, doc, {token, length}, nullptr, 8192, out_length));
    CHECK(!jwt_rs256_decode(verifier, doc, {token, length}, output, 1, out_length));
    verifier.reset();
    CHECK(!jwt_rs256_decode(verifier, doc, {token, length}, output, sizeof(output), out_length));
}
TEST(jwt_rs256, authenticated_profile_rejections_and_bounds) {
    BIGNUM* e = BN_new();
    RSA* rsa = RSA_new();
    REQUIRE(e && rsa);
    REQUIRE(BN_set_word(e, 65537));
    REQUIRE(RSA_generate_key_ex(rsa, 2048, e, nullptr));
    BN_free(e);
    EVP_PKEY* owner = EVP_PKEY_new();
    REQUIRE(owner);
    REQUIRE(EVP_PKEY_set1_RSA(owner, rsa));
    unsigned char der[8192];
    auto* cursor = der;
    int der_length = i2d_PUBKEY(owner, &cursor);
    REQUIRE(der_length > 0);
    RsaPublicKey key;
    REQUIRE(key.load({reinterpret_cast<const char*>(der), static_cast<u32>(der_length)}));
    EVP_PKEY_free(owner);
    RsaSha256Verifier verifier;
    REQUIRE(verifier.init(key));
    json::Document doc;
    char output[8192];
    u32 length = 0;
    static char token[24576];
    const Str bad_headers[] = {lit_str("{}"),
                               lit_str("[]"),
                               lit_str("{\"alg\":\"none\"}"),
                               lit_str("{\"alg\":\"HS256\"}"),
                               lit_str("{\"alg\":\"RS384\"}"),
                               lit_str("{\"alg\":42}"),
                               lit_str("{\"alg\":\"RS256\",\"alg\":\"RS256\"}"),
                               lit_str("{\"alg\":\"RS256\",\"a\\u006cg\":\"RS256\"}"),
                               lit_str("{\"alg\":\"RS256\",\"crit\":[]}"),
                               lit_str("{\"alg\":\"RS256\",\"b64\":true}"),
                               lit_str("{\"alg\":\"RS256\",\"b64\":false}")};
    for (Str header : bad_headers) {
        Str signed_token = token_for(rsa, header, lit_str("{}"), token);
        REQUIRE(signed_token.len > 0);
        CHECK(!jwt_rs256_decode(verifier, doc, signed_token, output, sizeof(output), length));
        CHECK_EQ(length, 0u);
    }
    const Str bad_claims[] = {lit_str("null"),
                              lit_str("[]"),
                              lit_str("\"string\""),
                              lit_str("{\"x\":1,\"x\":2}"),
                              lit_str("{")};
    for (Str claims : bad_claims) {
        Str signed_token = token_for(rsa, lit_str("{\"alg\":\"RS256\"}"), claims, token);
        REQUIRE(signed_token.len > 0);
        CHECK(!jwt_rs256_decode(verifier, doc, signed_token, output, sizeof(output), length));
        CHECK(!doc.valid);
        CHECK_EQ(length, 0u);
    }
    // Escaped alg is interpreted as JSON, while key hints cannot override the trusted key.
    Str valid =
        token_for(rsa,
                  lit_str("{\"a\\u006cg\":\"RS256\",\"kid\":\"ignored\",\"jku\":\"ignored\"}"),
                  lit_str("{}"),
                  token);
    REQUIRE(jwt_rs256_decode(verifier, doc, valid, output, 2, length));
    CHECK_EQ(length, 2u);
    token[valid.len++] = '=';
    CHECK(!jwt_rs256_decode(verifier, doc, valid, output, sizeof(output), length));
    token[valid.len - 1] = '.';
    CHECK(!jwt_rs256_decode(verifier, doc, valid, output, sizeof(output), length));
    static char claims[8193];
    claims[0] = '{';
    claims[1] = '}';
    for (u32 i = 2; i < sizeof(claims); ++i) claims[i] = ' ';
    Str boundary = token_for(rsa, lit_str("{\"alg\":\"RS256\"}"), {claims, 8192}, token);
    CHECK(jwt_rs256_decode(verifier, doc, boundary, output, sizeof(output), length));
    CHECK_EQ(length, 8192u);
    Str oversized = token_for(rsa, lit_str("{\"alg\":\"RS256\"}"), {claims, 8193}, token);
    CHECK(!jwt_rs256_decode(verifier, doc, oversized, output, sizeof(output), length));
    CHECK_EQ(length, 0u);
    char header[1025];
    const Str base_header = lit_str("{\"alg\":\"RS256\"}");
    for (u32 j = 0; j < sizeof(header); ++j)
        header[j] = j < base_header.len ? base_header.ptr[j] : ' ';
    Str header_boundary = token_for(rsa, {header, 1024}, lit_str("{}"), token);
    CHECK(jwt_rs256_decode(verifier, doc, header_boundary, output, sizeof(output), length));
    Str header_oversize = token_for(rsa, {header, 1025}, lit_str("{}"), token);
    CHECK(!jwt_rs256_decode(verifier, doc, header_oversize, output, sizeof(output), length));
    CHECK_EQ(length, 0u);
    RSA_free(rsa);
}
TEST(jwt_rs256, configured_jwks_to_verified_claims_policy) {
    BIGNUM* exponent = BN_new();
    RSA* rsa = RSA_new();
    REQUIRE(exponent && rsa);
    REQUIRE(BN_set_word(exponent, 65537));
    REQUIRE(RSA_generate_key_ex(rsa, 2048, exponent, nullptr));
    BN_free(exponent);
    const BIGNUM* modulus = nullptr;
    RSA_get0_key(rsa, &modulus, nullptr, nullptr);
    unsigned char binary[256];
    REQUIRE(BN_bn2bin(modulus, binary) == sizeof(binary));
    char encoded[342];
    const u32 encoded_length =
        encode({reinterpret_cast<const char*>(binary), sizeof(binary)}, encoded);
    char configuration[1024];
    json::Writer set{configuration};
    set.text(lit_str(
        R"({"keys":[{"kid":"unused","kty":"EC"},{"kid":"configured","kty":"RSA","alg":"RS256","n":")"));
    set.text({encoded, encoded_length});
    set.text(lit_str(R"(","e":"AQAB"}]})"));
    RsaPublicKey key;
    CHECK(!key.load_rs256_jwks({configuration, set.len}, lit_str("unknown")));
    REQUIRE(key.load_rs256_jwks({configuration, set.len}, lit_str("configured")));
    RsaSha256Verifier verifier;
    REQUIRE(verifier.init(key));
    key.reset();
    for (char& byte : configuration) byte = 0;
    char token[2048];
    // A signed token's kid is a hint, never authority to change configured keys.
    const Str signed_token = token_for(
        rsa,
        lit_str(R"({"alg":"RS256","kid":"untrusted","jku":"https://invalid/keys"})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"scope":"read write"})"),
        token);
    REQUIRE(signed_token.len > 0);
    RSA_free(rsa);
    json::Document document;
    char payload[8192];
    u32 length = 0;
    allocations = 0;
    tracking = true;
    const bool verified =
        jwt_rs256_decode(verifier, document, signed_token, payload, sizeof(payload), length);
    tracking = false;
    REQUIRE(verified);
    tracking = true;
    CHECK(
        jwt_claims_valid(document, {payload, length}, lit_str("issuer"), lit_str("gateway"), 100));
    CHECK(jwt_has_scope(document, {payload, length}, lit_str("read")));
    CHECK(!jwt_has_scope(document, {payload, length}, lit_str("admin")));
    CHECK(
        !jwt_claims_valid(document, {payload, length}, lit_str("other"), lit_str("gateway"), 100));
    CHECK(!jwt_claims_valid(document, {payload, length}, lit_str("issuer"), lit_str("other"), 100));
    CHECK(
        !jwt_claims_valid(document, {payload, length}, lit_str("issuer"), lit_str("gateway"), 200));
    tracking = false;
    CHECK_EQ(allocations, 0u);
}
TEST(jwt_rs256, validates_signed_claims_before_publication) {
    BIGNUM* exponent = BN_new();
    RSA* rsa = RSA_new();
    REQUIRE(exponent && rsa);
    REQUIRE(BN_set_word(exponent, 65537));
    REQUIRE(RSA_generate_key_ex(rsa, 2048, exponent, nullptr));
    BN_free(exponent);
    EVP_PKEY* owner = EVP_PKEY_new();
    REQUIRE(owner);
    REQUIRE(EVP_PKEY_set1_RSA(owner, rsa));
    unsigned char der[8192];
    auto* cursor = der;
    const int der_length = i2d_PUBKEY(owner, &cursor);
    REQUIRE(der_length > 0);
    RsaPublicKey key;
    REQUIRE(key.load({reinterpret_cast<const char*>(der), static_cast<u32>(der_length)}));
    EVP_PKEY_free(owner);
    RsaSha256Verifier verifier;
    REQUIRE(verifier.init(key));
    key.reset();
    json::Document document;
    char output[8192];
    char token[2048];
    const Str issuer = lit_str("issuer");
    const Str audience = lit_str("gateway");
    const Str valid_claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":["other","gateway"],"exp":101,"nbf":100,"iat":100})");
    const auto validate =
        [&](Str signed_token, Str expected_issuer, Str expected_audience, i64 now, u32& length) {
            return jwt_rs256_validate(verifier,
                                      document,
                                      signed_token,
                                      expected_issuer,
                                      expected_audience,
                                      now,
                                      output,
                                      sizeof(output),
                                      length);
        };
    const Str signed_token = token_for(rsa, lit_str(R"({"alg":"RS256"})"), valid_claims, token);
    REQUIRE(signed_token.len > 0);
    u32 length = 99;
    allocations = 0;
    tracking = true;
    const bool accepted = validate(signed_token, issuer, audience, 100, length);
    tracking = false;
    REQUIRE(accepted);
    CHECK_EQ(length, valid_claims.len);
    CHECK(document.valid);
    CHECK(document.source.ptr == output);
    CHECK((Str{output, length}.eq(valid_claims)));
    const auto rejected =
        [&](Str signed_value, Str expected_issuer, Str expected_audience, i64 now) {
            // Start from a published success every time, so failure cannot retain it.
            u32 published = 0;
            REQUIRE(validate(signed_token, issuer, audience, 100, published));
            published = 99;
            tracking = true;
            const bool result =
                validate(signed_value, expected_issuer, expected_audience, now, published);
            tracking = false;
            CHECK(!result);
            CHECK_EQ(published, 0u);
            CHECK(!document.valid);
            CHECK_EQ(document.count, 0u);
            CHECK(document.source.ptr == nullptr);
        };
    rejected(signed_token, lit_str("wrong"), audience, 100);
    rejected(signed_token, issuer, lit_str("wrong"), 100);
    rejected(signed_token, issuer, audience, 101);
    rejected(signed_token, issuer, audience, 99);
    rejected(signed_token, issuer, audience, 0);
    rejected(signed_token, issuer, audience, -1);
    rejected(signed_token, {}, audience, 100);
    rejected(signed_token, issuer, {}, 100);
    rejected(signed_token, {nullptr, 1}, audience, 100);
    rejected(signed_token, issuer, {nullptr, 1}, 100);
    rejected(lit_str("malformed"), issuer, audience, 100);
    char invalid_token[2048];
    const Str invalid_claims[] = {
        lit_str(R"({"iss":"issuer","aud":"gateway","exp":101})"),
        lit_str(R"({"sub":"","iss":"issuer","aud":"gateway","exp":101})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway"})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":"101"})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":101,"iat":101})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":101,"nbf":101})"),
        lit_str(R"({"sub":"alice","iss":"issuer","aud":["gateway",42],"exp":101})"),
    };
    for (Str claims : invalid_claims) {
        const Str invalid = token_for(rsa, lit_str(R"({"alg":"RS256"})"), claims, invalid_token);
        REQUIRE(invalid.len > 0);
        rejected(invalid, issuer, audience, 100);
    }
    for (u32 index = 0; index < signed_token.len; ++index) invalid_token[index] = token[index];
    invalid_token[signed_token.len - 1] = token[signed_token.len - 1] == 'A' ? 'B' : 'A';
    rejected({invalid_token, signed_token.len}, issuer, audience, 100);
    length = 99;
    CHECK(!jwt_rs256_validate(
        verifier, document, signed_token, issuer, audience, 100, output, 1, length));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
    length = 99;
    CHECK(!jwt_rs256_validate(
        verifier, document, signed_token, issuer, audience, 100, nullptr, sizeof(output), length));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
    verifier.reset();
    length = 99;
    CHECK(!validate(signed_token, issuer, audience, 100, length));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
    CHECK_EQ(allocations, 0u);
    RSA_free(rsa);
}
int main(int argc, char** argv) {
    if (!CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free)) return 2;
    return rut::test::run_all(argc, argv);
}

struct SelectedSigningKey {
    RSA* rsa = nullptr;
    ~SelectedSigningKey() { RSA_free(rsa); }
    bool init(int bits) {
        BIGNUM* exponent = BN_new();
        rsa = RSA_new();
        const bool ok = exponent && rsa && BN_set_word(exponent, 65537) &&
                        RSA_generate_key_ex(rsa, bits, exponent, nullptr);
        BN_free(exponent);
        return ok;
    }
    bool append_jwk(json::Writer& out, Str kid) const {
        const BIGNUM* modulus = nullptr;
        RSA_get0_key(rsa, &modulus, nullptr, nullptr);
        const int size = BN_num_bytes(modulus);
        if (size <= 0 || size > 512) return false;
        unsigned char bytes[512];
        if (BN_bn2bin(modulus, bytes) != size) return false;
        char encoded[684];
        const u32 length =
            encode({reinterpret_cast<const char*>(bytes), static_cast<u32>(size)}, encoded);
        out.text(lit_str("{\"kid\":"));
        if (!json::quote(kid, out)) return false;
        out.text(lit_str(R"(,"kty":"RSA","alg":"RS256","e":"AQAB","n":")"));
        out.text({encoded, length});
        out.text(lit_str("\"}"));
        return out.ok;
    }
};
static constexpr Str kSelectedClaims =
    lit_str(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"scope":"read write"})");
struct SelectedKeyFixture {
    SelectedSigningKey current;
    SelectedSigningKey previous;
    Rs256KeySet owners;
    Rs256VerifierSet verifiers;
    char configuration[4096];
    Str configuration_view{};
    char first_token[2048];
    char second_token[2048];
    Str first{};
    Str second{};
    bool init() {
        if (!current.init(2048) || !previous.init(3072)) return false;
        json::Writer out{configuration, sizeof(configuration)};
        out.text(lit_str("{\"keys\":["));
        if (!current.append_jwk(out, lit_str("current"))) return false;
        out.put(',');
        if (!previous.append_jwk(out, lit_str("previous"))) return false;
        out.put(',');
        if (!current.append_jwk(out, lit_str("not-approved"))) return false;
        out.text(lit_str(",{\"kid\":\"ignored\",\"kty\":\"EC\"}]}"));
        if (!out.ok) return false;
        configuration_view = {configuration, out.len};
        const Str approved[] = {lit_str("current"), lit_str("previous")};
        if (!owners.load(configuration_view, approved, 2) || !verifiers.init(owners)) return false;
        owners.reset();
        first = token_for(current.rsa,
                          lit_str(R"({"alg":"RS256","kid":"current"})"),
                          kSelectedClaims,
                          first_token);
        second = token_for(previous.rsa,
                           lit_str(R"({"kid":"previous","alg":"RS256"})"),
                           kSelectedClaims,
                           second_token);
        return first.len != 0 && second.len != 0;
    }
};

TEST(jwt_rs256, approved_kid_selection_verifies_both_keys_without_request_allocations) {
    SelectedKeyFixture fixture;
    REQUIRE(fixture.init());
    json::Document document;
    char payload[8192];
    u32 length = 0;
    Str verified_kid;
    allocations = 0;
    tracking = true;
    bool first = jwt_rs256_validate_set(fixture.verifiers,
                                        document,
                                        fixture.first,
                                        lit_str("issuer"),
                                        lit_str("gateway"),
                                        100,
                                        payload,
                                        sizeof(payload),
                                        length,
                                        verified_kid);
    tracking = false;
    REQUIRE(first);
    CHECK(verified_kid.eq(lit_str("current")));
    CHECK(verified_kid.ptr == fixture.verifiers.select(lit_str("current")).kid.ptr);
    CHECK(document.valid);
    CHECK(document.source.ptr == payload);
    CHECK(jwt_has_scope(document, {payload, length}, lit_str("read")));
    tracking = true;
    bool second = jwt_rs256_validate_set(fixture.verifiers,
                                         document,
                                         fixture.second,
                                         lit_str("issuer"),
                                         lit_str("gateway"),
                                         100,
                                         payload,
                                         sizeof(payload),
                                         length,
                                         verified_kid);
    tracking = false;
    REQUIRE(second);
    CHECK(verified_kid.eq(lit_str("previous")));
    CHECK_EQ(allocations, 0u);
    // Policy-bearing output must not borrow token/header storage.
    for (char& byte : fixture.second_token) byte = 0;
    CHECK(verified_kid.eq(lit_str("previous")));
    CHECK(document.valid);
}

TEST(jwt_rs256, kid_profiles_never_fallback_or_publish_unverified_identity) {
    SelectedKeyFixture fixture;
    REQUIRE(fixture.init());
    json::Document document;
    char payload[8192];
    char token[4096];
    u32 length = 0;
    Str verified_kid;
    const char* rejected[] = {
        R"({"alg":"RS256"})",
        R"({"alg":"RS256","kid":""})",
        R"({"alg":"RS256","kid":"unknown"})",
        R"({"alg":"RS256","kid":"not-approved"})",
        R"({"alg":"RS256","kid":"Current"})",
        R"({"alg":"RS256","kid":"cur"})",
        R"({"alg":"RS256","kid":"previous"})",  // signed with current, never try other keys
        R"({"alg":"RS256","kid":"current\u0000tail"})",
        R"({"alg":"RS256","kid":null})",
        R"({"alg":"RS256","kid":123})",
        R"({"alg":"RS256","kid":[]})",
        R"({"alg":"RS256","Kid":"current"})",
        R"({"alg":"RS256","kid":"current","k\u0069d":"previous"})",
        R"({"alg":"RS256","kid":"current","crit":[]})",
        R"({"alg":"RS256","kid":"current","b64":true})",
        R"({"alg":"HS256","kid":"current"})",
        R"({"alg":"none","kid":"current"})",
        R"({"alg":"PS256","kid":"current"})",
        R"({"kid":"current"})",
        R"([])",
    };
    allocations = 0;
    for (const char* header : rejected) {
        const Str signed_token = token_for(fixture.current.rsa,
                                           {header, static_cast<u32>(__builtin_strlen(header))},
                                           kSelectedClaims,
                                           token);
        REQUIRE(signed_token.len > 0);
        REQUIRE(jwt_rs256_validate_set(fixture.verifiers,
                                       document,
                                       fixture.first,
                                       lit_str("issuer"),
                                       lit_str("gateway"),
                                       100,
                                       payload,
                                       sizeof(payload),
                                       length,
                                       verified_kid));
        tracking = true;
        const bool accepted = jwt_rs256_validate_set(fixture.verifiers,
                                                     document,
                                                     signed_token,
                                                     lit_str("issuer"),
                                                     lit_str("gateway"),
                                                     100,
                                                     payload,
                                                     sizeof(payload),
                                                     length,
                                                     verified_kid);
        tracking = false;
        CHECK(!accepted);
        CHECK_EQ(length, 0u);
        CHECK(!document.valid);
        CHECK_EQ(document.count, 0u);
        CHECK(document.source.ptr == nullptr);
        CHECK(verified_kid.ptr == nullptr);
        CHECK_EQ(verified_kid.len, 0u);
    }
    CHECK_EQ(allocations, 0u);
    const Str escaped = token_for(
        fixture.current.rsa,
        lit_str(
            R"({"alg":"RS256","kid":"cu\u0072rent","jku":"https://attacker.invalid/keys","jwk":{"kty":"RSA","n":"bogus"}})"),
        kSelectedClaims,
        token);
    REQUIRE(jwt_rs256_validate_set(fixture.verifiers,
                                   document,
                                   escaped,
                                   lit_str("issuer"),
                                   lit_str("gateway"),
                                   100,
                                   payload,
                                   sizeof(payload),
                                   length,
                                   verified_kid));
    CHECK(verified_kid.eq(lit_str("current")));
}

TEST(jwt_rs256, selected_key_claim_failures_invalidate_all_publication_and_revocation_is_explicit) {
    SelectedKeyFixture fixture;
    REQUIRE(fixture.init());
    json::Document document;
    char payload[8192];
    char token[4096];
    u32 length = 0;
    Str verified_kid;
    const char* rejected_claims[] = {
        R"({"sub":"alice","iss":"other","aud":"gateway","exp":200})",
        R"({"sub":"alice","iss":"issuer","aud":"other","exp":200})",
        R"({"sub":"","iss":"issuer","aud":"gateway","exp":200})",
        R"({"iss":"issuer","aud":"gateway","exp":200})",
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":100})",
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"nbf":101})",
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"iat":101})",
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200.0})",
        R"({"sub":"alice","iss":"issuer","aud":"gateway"})",
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"exp":300})",
    };
    for (const char* claims : rejected_claims) {
        const Str signed_token = token_for(fixture.current.rsa,
                                           lit_str(R"({"alg":"RS256","kid":"current"})"),
                                           {claims, static_cast<u32>(__builtin_strlen(claims))},
                                           token);
        REQUIRE(jwt_rs256_validate_set(fixture.verifiers,
                                       document,
                                       fixture.first,
                                       lit_str("issuer"),
                                       lit_str("gateway"),
                                       100,
                                       payload,
                                       sizeof(payload),
                                       length,
                                       verified_kid));
        tracking = true;
        const bool accepted = jwt_rs256_validate_set(fixture.verifiers,
                                                     document,
                                                     signed_token,
                                                     lit_str("issuer"),
                                                     lit_str("gateway"),
                                                     100,
                                                     payload,
                                                     sizeof(payload),
                                                     length,
                                                     verified_kid);
        tracking = false;
        CHECK(!accepted);
        CHECK_EQ(length, 0u);
        CHECK(!document.valid);
        CHECK(verified_kid.ptr == nullptr);
    }
    // Retiring a key in a new generation does not silently mutate in-flight readers.
    Rs256KeySet replacement;
    const Str approved[] = {lit_str("previous")};
    REQUIRE(replacement.load(fixture.configuration_view, approved, 1));
    Rs256VerifierSet active;
    REQUIRE(active.init(replacement));
    replacement.reset();
    REQUIRE(jwt_rs256_validate_set(active,
                                   document,
                                   fixture.second,
                                   lit_str("issuer"),
                                   lit_str("gateway"),
                                   100,
                                   payload,
                                   sizeof(payload),
                                   length,
                                   verified_kid));
    const Str missing_id =
        token_for(fixture.previous.rsa, lit_str(R"({"alg":"RS256"})"), kSelectedClaims, token);
    CHECK(!jwt_rs256_validate_set(active,
                                  document,
                                  missing_id,
                                  lit_str("issuer"),
                                  lit_str("gateway"),
                                  100,
                                  payload,
                                  sizeof(payload),
                                  length,
                                  verified_kid));
    CHECK(verified_kid.ptr == nullptr);
    CHECK(!jwt_rs256_validate_set(active,
                                  document,
                                  fixture.first,
                                  lit_str("issuer"),
                                  lit_str("gateway"),
                                  100,
                                  payload,
                                  sizeof(payload),
                                  length,
                                  verified_kid));
    CHECK(!document.valid);
    CHECK_EQ(length, 0u);
    CHECK(verified_kid.ptr == nullptr);
    CHECK(jwt_rs256_validate_set(fixture.verifiers,
                                 document,
                                 fixture.first,
                                 lit_str("issuer"),
                                 lit_str("gateway"),
                                 100,
                                 payload,
                                 sizeof(payload),
                                 length,
                                 verified_kid));
    fixture.verifiers.reset();
    CHECK(!jwt_rs256_validate_set(fixture.verifiers,
                                  document,
                                  fixture.first,
                                  lit_str("issuer"),
                                  lit_str("gateway"),
                                  100,
                                  payload,
                                  sizeof(payload),
                                  length,
                                  verified_kid));
    CHECK(!document.valid);
    CHECK_EQ(length, 0u);
    CHECK(verified_kid.ptr == nullptr);
}

TEST(jwt_rs256, selected_key_id_bounds_decoding_and_output_arguments) {
    SelectedSigningKey signing;
    REQUIRE(signing.init(2048));
    const char embedded[] = "id\0tail";
    char long_id[129];
    for (char& byte : long_id) byte = 'a';
    const Str ids[] = {{long_id, 128}, {embedded, sizeof(embedded) - 1}};
    for (Str kid : ids) {
        char configuration[2048];
        json::Writer out{configuration, sizeof(configuration)};
        out.text(lit_str("{\"keys\":["));
        REQUIRE(signing.append_jwk(out, kid));
        out.text(lit_str("]}"));
        Rs256KeySet owners;
        REQUIRE(owners.load({configuration, out.len}, &kid, 1));
        Rs256VerifierSet verifiers;
        REQUIRE(verifiers.init(owners));
        owners.reset();
        char header[1024];
        json::Writer encoded{header, sizeof(header)};
        encoded.text(lit_str("{\"alg\":\"RS256\",\"kid\":"));
        REQUIRE(json::quote(kid, encoded));
        encoded.put('}');
        char token[2048];
        const Str signed_token =
            token_for(signing.rsa, {header, encoded.len}, kSelectedClaims, token);
        json::Document document;
        char payload[8192];
        u32 length = 0;
        Str verified_kid;
        REQUIRE(jwt_rs256_validate_set(verifiers,
                                       document,
                                       signed_token,
                                       lit_str("issuer"),
                                       lit_str("gateway"),
                                       100,
                                       payload,
                                       sizeof(payload),
                                       length,
                                       verified_kid));
        CHECK(verified_kid.eq(kid));
        CHECK(verified_kid.ptr == verifiers.select(kid).kid.ptr);
        struct InvalidArgs {
            Str issuer;
            Str audience;
            i64 time;
            char* output;
            u32 capacity;
        };
        const InvalidArgs invalid[] = {
            {lit_str(""), lit_str("gateway"), 100, payload, sizeof(payload)},
            {lit_str("issuer"), lit_str(""), 100, payload, sizeof(payload)},
            {lit_str("issuer"), lit_str("gateway"), 0, payload, sizeof(payload)},
            {lit_str("issuer"), lit_str("gateway"), 100, nullptr, sizeof(payload)},
            {lit_str("issuer"), lit_str("gateway"), 100, payload, 1},
        };
        for (const auto& arg : invalid) {
            REQUIRE(document.parse(lit_str("{}")));
            verified_kid = kid;
            length = 999;
            CHECK(!jwt_rs256_validate_set(verifiers,
                                          document,
                                          signed_token,
                                          arg.issuer,
                                          arg.audience,
                                          arg.time,
                                          arg.output,
                                          arg.capacity,
                                          length,
                                          verified_kid));
            CHECK(!document.valid);
            CHECK_EQ(length, 0u);
            CHECK(verified_kid.ptr == nullptr);
        }
        if (kid.len == 128) {
            json::Writer too_long{header, sizeof(header)};
            too_long.text(lit_str("{\"alg\":\"RS256\",\"kid\":"));
            REQUIRE(json::quote({long_id, 129}, too_long));
            too_long.put('}');
            const Str rejected =
                token_for(signing.rsa, {header, too_long.len}, kSelectedClaims, token);
            CHECK(!jwt_rs256_validate_set(verifiers,
                                          document,
                                          rejected,
                                          lit_str("issuer"),
                                          lit_str("gateway"),
                                          100,
                                          payload,
                                          sizeof(payload),
                                          length,
                                          verified_kid));
            CHECK(!document.valid);
            CHECK_EQ(length, 0u);
            CHECK(verified_kid.ptr == nullptr);
        }
    }
}

TEST(jwt_rs256, shard_set_activation_crypto_allocation_failures_rollback_and_retry) {
    SelectedKeyFixture fixture;
    REQUIRE(fixture.init());
    const Str approved[] = {lit_str("current"), lit_str("previous")};
    Rs256KeySet owners;
    REQUIRE(owners.load(fixture.configuration_view, approved, 2));
    bool failed = false;
    bool succeeded = false;
    for (i64 budget = 0; budget < 256; ++budget) {
        Rs256VerifierSet probe;
        allocation_budget = budget;
        const bool initialized = probe.init(owners);
        allocation_budget = -1;
        if (initialized) {
            CHECK(probe.valid());
            CHECK_EQ(probe.size(), 2u);
            succeeded = true;
            break;
        }
        failed = true;
        CHECK(!probe.valid());
        CHECK_EQ(probe.size(), 0u);
        CHECK(!probe.select(approved[0]).verifier);
        CHECK(!probe.select(approved[1]).verifier);
        REQUIRE(probe.init(owners));
        CHECK(probe.select(approved[0]).verifier != nullptr);
        CHECK(probe.select(approved[1]).verifier != nullptr);
    }
    CHECK(failed);
    CHECK(succeeded);
}

TEST(jwt_rs256, configured_policies_activate_each_shard_and_keep_generations_independent) {
    SelectedKeyFixture fixture;
    REQUIRE(fixture.init());
    char bytes[8192];
    json::Writer configuration{bytes};
    configuration.text(lit_str(
        R"({"issuer":"issuer","audience":"gateway","kids":["current","previous"],"jwks":)"));
    configuration.text(fixture.configuration_view);
    configuration.put('}');
    REQUIRE(configuration.ok);
    const Str text{bytes, configuration.len};
    Rs256Policies policies;
    REQUIRE(policies.load(&text, 1));
    json::Document document;
    char payload[8192];
    u32 length = 17;
    CHECK(
        !policies.verify(0, text, document, fixture.first, 100, payload, sizeof(payload), length));
    CHECK_EQ(length, 0u);
    REQUIRE(policies.activate(0));
    CHECK(
        !policies.verify(1, text, document, fixture.first, 100, payload, sizeof(payload), length));
    REQUIRE(policies.activate(1));
    allocations = 0;
    tracking = true;
    const bool first =
        policies.verify(0, text, document, fixture.first, 100, payload, sizeof(payload), length);
    const bool second =
        policies.verify(1, text, document, fixture.second, 100, payload, sizeof(payload), length);
    tracking = false;
    CHECK(first);
    CHECK(second);
    CHECK_EQ(allocations, 0u);
    CHECK(!policies.activate(kMaxShards));
    CHECK(!policies.verify(
        kMaxShards, text, document, fixture.first, 100, payload, sizeof(payload), length));
    CHECK(!document.valid);
    CHECK_EQ(length, 0u);
    // Drop the old key from a replacement policy, leaving in-flight old readers intact.
    char replacement[8192];
    json::Writer updated{replacement};
    updated.text(lit_str(R"({"issuer":"issuer","audience":"gateway","kids":["current"],"jwks":)"));
    updated.text(fixture.configuration_view);
    updated.put('}');
    const Str next{replacement, updated.len};
    Rs256Policies newer;
    REQUIRE(newer.load(&next, 1));
    REQUIRE(newer.activate(0));
    CHECK(!newer.verify(0, next, document, fixture.second, 100, payload, sizeof(payload), length));
    CHECK(
        policies.verify(0, text, document, fixture.second, 100, payload, sizeof(payload), length));
    CHECK(newer.verify(0, next, document, fixture.first, 100, payload, sizeof(payload), length));
    // The owner copies its configuration bytes; compiler buffers can be released.
    replacement[0] = '!';
    char lookup[8192];
    __builtin_memcpy(lookup, replacement, updated.len);
    lookup[0] = '{';
    CHECK(newer.verify(
        0, {lookup, updated.len}, document, fixture.first, 100, payload, sizeof(payload), length));
}

TEST(jwt_rs256, policy_rejects_missing_ambiguous_or_unapproved_trust_configuration) {
    const Str bad[] = {
        lit_str("{}"),
        lit_str("[]"),
        lit_str(R"({"issuer":"i","audience":"a","kids":[],"jwks":{"keys":[]}})"),
        lit_str(R"({"issuer":"i","issuer":"i","audience":"a","kids":["x"],"jwks":{"keys":[]}})"),
        lit_str(R"({"issuer":"","audience":"a","kids":["x"],"jwks":{"keys":[]}})"),
        lit_str(R"({"issuer":"i","audience":"a","kids":["x","x"],"jwks":{"keys":[]}})"),
        lit_str(
            R"({"issuer":"i","audience":"a","kids":["x"],"jwks":{"keys":[]},"jku":"https://evil"})"),
    };
    for (const auto value : bad) {
        Rs256Policy policy;
        CHECK(!policy.load(value));
        CHECK(!policy.keys().valid());
    }
    Rs256Policies policies;
    CHECK(!policies.load(nullptr, 1));
    CHECK(!policies.load(bad, Rs256Policies::kMaxPolicies + 1));
}

TEST(jwt_rs256,
     failed_policy_activation_never_initializes_on_request_or_contaminates_another_shard) {
    SelectedKeyFixture fixture;
    REQUIRE(fixture.init());
    char bytes[8192];
    json::Writer configuration{bytes};
    configuration.text(
        lit_str(R"({"issuer":"issuer","audience":"gateway","kids":["current"],"jwks":)"));
    configuration.text(fixture.configuration_view);
    configuration.put('}');
    REQUIRE(configuration.ok);
    const Str text{bytes, configuration.len};
    Rs256Policies policies;
    REQUIRE(policies.load(&text, 1));
    allocation_budget = 0;
    const bool activated = policies.activate(0);
    allocation_budget = -1;
    CHECK(!activated);
    CHECK(!policies.activate(0));
    json::Document document;
    char payload[8192];
    u32 length = 1;
    CHECK(
        !policies.verify(0, text, document, fixture.first, 100, payload, sizeof(payload), length));
    CHECK_EQ(length, 0u);
    CHECK(!document.valid);
    REQUIRE(policies.activate(1));
    CHECK(policies.verify(1, text, document, fixture.first, 100, payload, sizeof(payload), length));
    CHECK(
        !policies.verify(0, text, document, fixture.first, 100, payload, sizeof(payload), length));
}
