#include "public_key_fixtures.h"
#include "rsa_verify_fixtures.h"
#include "rut/runtime/public_key.h"
#include "test.h"

#include <openssl/err.h>

using namespace rut;

template <size_t N>
static Str der(const unsigned char (&bytes)[N]) {
    return {reinterpret_cast<const char*>(bytes), static_cast<u32>(N)};
}

TEST(public_key, owner_retains_parsed_key_not_the_configuration_view) {
    RsaPublicKey key;
    CHECK(!key.valid());
    CHECK_EQ(key.bits(), 0u);
    char source[sizeof(kRfcRsaSpki)];
    for (u32 i = 0; i < sizeof(source); ++i) source[i] = kRfcRsaSpki[i];
    REQUIRE(key.load({source, sizeof(source)}));
    for (char& byte : source) byte = 0;
    CHECK(key.valid());
    CHECK_EQ(key.bits(), 2048u);
    CHECK(!key.load(der(kRfcRsaSpki)));
    CHECK_EQ(key.bits(), 2048u);
    key.reset();
    key.reset();
    CHECK(!key.valid());
    CHECK_EQ(key.bits(), 0u);
    REQUIRE(key.load(der(kRfcRsaSpki)));
}

TEST(public_key, invalid_input_does_not_publish_a_partial_key) {
    RsaPublicKey key;
    CHECK(!key.load({nullptr, 0}));
    CHECK(!key.load({nullptr, 10}));
    CHECK(!key.load({"", 0}));
    char too_big[RsaPublicKey::kMaxDerBytes + 1]{};
    CHECK(!key.load({too_big, sizeof(too_big)}));
    const Str full = der(kRfcRsaSpki);
    for (u32 len = 1; len < full.len; ++len) {
        CHECK(!key.load({full.ptr, len}));
        CHECK(!key.valid());
    }
    char trailing[sizeof(kRfcRsaSpki) + 1];
    for (u32 i = 0; i < sizeof(kRfcRsaSpki); ++i) trailing[i] = kRfcRsaSpki[i];
    trailing[sizeof(kRfcRsaSpki)] = 0;
    CHECK(!key.load({trailing, sizeof(trailing)}));
    CHECK(!key.load(lit_str("-----BEGIN PUBLIC KEY-----")));
    CHECK(!key.valid());
    REQUIRE(key.load(full));
}

TEST(public_key, rsa_profile_rejects_key_type_size_and_exponent_confusion) {
    const Str invalid[] = {
        der(kExponentThreeSpki), der(kWeakRsaSpki), der(kOversizeRsaSpki), der(kEd25519Spki)};
    for (u32 repeat = 0; repeat < 32; ++repeat) {
        RsaPublicKey key;
        for (Str input : invalid) {
            CHECK(!key.load(input));
            CHECK(!key.valid());
        }
        REQUIRE(key.load(der(kRfcRsaSpki)));
        CHECK_EQ(key.bits(), 2048u);
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(public_key, noncanonical_ber_is_not_an_alternate_key_configuration) {
    RsaPublicKey key;
    unsigned char ber[sizeof(kRfcRsaSpki) + 1];
    REQUIRE_EQ(kRfcRsaSpki[1], 0x82u);
    ber[0] = kRfcRsaSpki[0];
    ber[1] = 0x83;
    ber[2] = 0;
    for (u32 i = 2; i < sizeof(kRfcRsaSpki); ++i) ber[i + 1] = kRfcRsaSpki[i];
    CHECK(!key.load(der(ber)));
    CHECK(!key.valid());
    REQUIRE(key.load(der(kRfcRsaSpki)));
}

TEST(public_key, parse_failures_do_not_pollute_the_callers_crypto_errors) {
    ERR_clear_error();
    RsaPublicKey key;
    CHECK(!key.load(lit_str("malformed")));
    CHECK_EQ(ERR_peek_error(), 0ul);
    ERR_put_error(ERR_LIB_USER, 0, 42, __FILE__, __LINE__);
    const unsigned long previous = ERR_peek_last_error();
    REQUIRE(previous != 0);
    CHECK(!key.load(lit_str("malformed")));
    CHECK_EQ(ERR_peek_last_error(), previous);
    ERR_clear_error();
}

static constexpr char kJwkModulus[] =
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-"
    "4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_"
    "7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-"
    "UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_"
    "h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";

// Compose different profiles around the independent RFC 7515 Appendix A.2 modulus.
static Str jwk(char (&buffer)[2048],
               Str prefix,
               Str suffix,
               Str modulus = {kJwkModulus, sizeof(kJwkModulus) - 1}) {
    u32 length = 0;
    const Str parts[] = {prefix, modulus, suffix};
    for (Str part : parts) {
        for (u32 i = 0; i < part.len; ++i) buffer[length++] = part.ptr[i];
    }
    return {buffer, length};
}

TEST(public_key, public_jwk_owns_key_and_verifies_published_signature) {
    char buffer[2048];
    RsaPublicKey key;
    const Str input = jwk(
        buffer,
        lit_str(R"({"kty":"RSA","alg":"RS256","n":")"),
        lit_str(
            R"(","e":"AQAB","use":"sig","key_ops":["verify"],"jku":"https://invalid.example/ignored"})"));
    REQUIRE(key.load_rs256_jwk(input));
    CHECK_EQ(key.bits(), 2048u);
    CHECK(!key.load_rs256_jwk(input));
    for (char& c : buffer) c = 0;
    RsaSha256Verifier verifier;
    REQUIRE(verifier.init(key));
    key.reset();
    CHECK(verifier.verify({kMessage, sizeof(kMessage) - 1}, der(kSignature)));
}

TEST(public_key, jwk_rejects_confused_profiles_and_private_material) {
    const Str prefixes[] = {
        lit_str(R"({"kty":"EC","alg":"RS256","n":")"),
        lit_str(R"({"kty":"RSA","alg":"PS256","n":")"),
        lit_str(R"({"kty":"RSA","n":")"),
        lit_str(R"({"alg":"RS256","n":")"),
        lit_str(R"({"kty":"RSA","alg":null,"n":")"),
        lit_str(R"({"kty":"RSA","alg":"RS256","k\u0074y":"RSA","n":")"),
    };
    char buffer[2048];
    RsaPublicKey key;
    for (Str prefix : prefixes) {
        CHECK(!key.load_rs256_jwk(jwk(buffer, prefix, lit_str(R"(","e":"AQAB"})"))));
        CHECK(!key.valid());
    }
    const Str suffixes[] = {
        lit_str(R"("})"),
        lit_str(R"(","e":"Aw"})"),
        lit_str(R"(","e":"AAEAAQ"})"),
        lit_str(R"(","e":65537})"),
        lit_str(R"(","e":"AQAB","use":"enc"})"),
        lit_str(R"(","e":"AQAB","key_ops":[]})"),
        lit_str(R"(","e":"AQAB","key_ops":["sign"]})"),
        lit_str(R"(","e":"AQAB","key_ops":["verify","sign"]})"),
        lit_str(R"(","e":"AQAB","key_ops":"verify"})"),
        lit_str(R"(","e":"AQAB","d":null})"),
        lit_str(R"(","e":"AQAB","p":null})"),
        lit_str(R"(","e":"AQAB","q":null})"),
        lit_str(R"(","e":"AQAB","dp":null})"),
        lit_str(R"(","e":"AQAB","dq":null})"),
        lit_str(R"(","e":"AQAB","qi":null})"),
        lit_str(R"(","e":"AQAB","oth":[]})"),
        lit_str(R"(","e":"AQAB","\u0064":null})"),
    };
    for (Str suffix : suffixes) {
        CHECK(!key.load_rs256_jwk(
            jwk(buffer, lit_str(R"({"kty":"RSA","alg":"RS256","n":")"), suffix)));
        CHECK(!key.valid());
    }
}

TEST(public_key, jwk_bounds_canonical_integer_and_crypto_error_preservation) {
    char buffer[2048];
    const Str prefix = lit_str(R"({"kty":"RSA","alg":"RS256","n":")");
    const Str suffix = lit_str(R"(","e":"AQAB"})");
    RsaPublicKey key;
    CHECK(!key.load_rs256_jwk({nullptr, 1}));
    CHECK(!key.load_rs256_jwk(lit_str("[]")));
    char oversized[RsaPublicKey::kMaxDerBytes + 1]{};
    CHECK(!key.load_rs256_jwk({oversized, sizeof(oversized)}));
    for (u32 length = 0; length < sizeof(kJwkModulus) - 1; ++length) {
        CHECK(!key.load_rs256_jwk(jwk(buffer, prefix, suffix, {kJwkModulus, length})));
        CHECK(!key.valid());
    }
    char invalid[sizeof(kJwkModulus)];
    for (u32 i = 0; i < sizeof(invalid); ++i) invalid[i] = kJwkModulus[i];
    // Last canonical symbol Q has four unused zero bits; R is noncanonical.
    invalid[sizeof(invalid) - 2] = 'R';
    CHECK(!key.load_rs256_jwk(jwk(buffer, prefix, suffix, {invalid, sizeof(invalid) - 1})));
    invalid[sizeof(invalid) - 2] = kJwkModulus[sizeof(invalid) - 2];
    invalid[0] = '=';
    CHECK(!key.load_rs256_jwk(jwk(buffer, prefix, suffix, {invalid, sizeof(invalid) - 1})));
    // Canonical tail but an even modulus, then a below-profile bit length.
    invalid[0] = kJwkModulus[0];
    invalid[sizeof(invalid) - 2] = 'A';
    CHECK(!key.load_rs256_jwk(jwk(buffer, prefix, suffix, {invalid, sizeof(invalid) - 1})));
    invalid[0] = 'A';
    invalid[sizeof(invalid) - 2] = kJwkModulus[sizeof(invalid) - 2];
    CHECK(!key.load_rs256_jwk(jwk(buffer, prefix, suffix, {invalid, sizeof(invalid) - 1})));
    char oversized_modulus[684];
    for (char& c : oversized_modulus) c = 'A';
    CHECK(!key.load_rs256_jwk(
        jwk(buffer, prefix, suffix, {oversized_modulus, sizeof(oversized_modulus)})));
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, 42, __FILE__, __LINE__);
    const unsigned long previous = ERR_peek_last_error();
    REQUIRE(key.load_rs256_jwk(jwk(buffer, prefix, suffix)));
    CHECK_EQ(ERR_peek_last_error(), previous);
    ERR_clear_error();
}
