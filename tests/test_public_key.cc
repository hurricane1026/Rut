#include "public_key_fixtures.h"
#include "rsa_verify_fixtures.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/json.h"
#include "rut/runtime/public_key.h"
#include "test.h"

#include <openssl/err.h>
#include <pthread.h>

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

TEST(public_key, c_abi_imports_trusted_jwk_and_jwks) {
    alignas(64) unsigned char storage[256];
    REQUIRE(rut_crypto_rsa_key_size_v1() <= sizeof(storage));
    REQUIRE(rut_crypto_rsa_key_align_v1() <= 64);
    char buffer[2048];
    auto* key = rut_crypto_rsa_key_init_v1(storage, sizeof(storage));
    REQUIRE(key);
    auto input =
        jwk(buffer, lit_str(R"({"kty":"RSA","alg":"RS256","n":")"), lit_str(R"(","e":"AQAB"})"));
    CHECK(!rut_crypto_rsa_key_load_jwk_v1(key, nullptr, 1));
    REQUIRE(rut_crypto_rsa_key_load_jwk_v1(
        key, reinterpret_cast<const uint8_t*>(input.ptr), input.len));
    rut_crypto_rsa_key_destroy_v1(key);
    key = rut_crypto_rsa_key_init_v1(storage, sizeof(storage));
    REQUIRE(key);
    input = jwk(buffer,
                lit_str(R"({"keys":[{"kid":"fixed","kty":"RSA","alg":"RS256","n":")"),
                lit_str(R"(","e":"AQAB"}]})"));
    auto* bytes = reinterpret_cast<const uint8_t*>(input.ptr);
    CHECK(!rut_crypto_rsa_key_load_jwks_v1(
        key, bytes, input.len, reinterpret_cast<const uint8_t*>("other"), 5));
    CHECK(!rut_crypto_rsa_key_load_jwks_v1(key, bytes, input.len, nullptr, 1));
    REQUIRE(rut_crypto_rsa_key_load_jwks_v1(
        key, bytes, input.len, reinterpret_cast<const uint8_t*>("fixed"), 5));
    rut_crypto_rsa_key_destroy_v1(key);
}

TEST(public_key, c_abi_key_set_keeps_shard_verifier_alive) {
    alignas(64) unsigned char key_storage[8192];
    alignas(64) unsigned char verifier_storage[8192];
    REQUIRE(rut_crypto_rsa_key_set_size_v1() <= sizeof(key_storage));
    REQUIRE(rut_crypto_rsa_key_set_align_v1() <= 64);
    REQUIRE(rut_crypto_rsa_verifier_set_size_v1() <= sizeof(verifier_storage));
    REQUIRE(rut_crypto_rsa_verifier_set_align_v1() <= 64);
    auto* keys = rut_crypto_rsa_key_set_init_v1(key_storage, sizeof(key_storage));
    REQUIRE(keys);
    char buffer[2048];
    Str input = jwk(buffer,
                    lit_str(R"({"keys":[{"kid":"fixed","kty":"RSA","alg":"RS256","n":")"),
                    lit_str(R"(","e":"AQAB"}]})"));
    const rut_crypto_span_v1 ids[] = {{reinterpret_cast<const uint8_t*>("fixed"), 5}};
    CHECK(!rut_crypto_rsa_key_set_load_v1(
        keys, reinterpret_cast<const uint8_t*>(input.ptr), input.len, ids, 17));
    REQUIRE(rut_crypto_rsa_key_set_load_v1(
        keys, reinterpret_cast<const uint8_t*>(input.ptr), input.len, ids, 1));
    auto* set =
        rut_crypto_rsa_verifier_set_init_v1(verifier_storage, sizeof(verifier_storage), keys);
    REQUIRE(set);
    rut_crypto_rsa_key_set_destroy_v1(keys);
    for (char& c : buffer) c = 0;
    CHECK(
        !rut_crypto_rsa_verifier_set_select_v1(set, reinterpret_cast<const uint8_t*>("other"), 5));
    auto* verifier =
        rut_crypto_rsa_verifier_set_select_v1(set, reinterpret_cast<const uint8_t*>("fixed"), 5);
    REQUIRE(verifier);
    CHECK(rut_crypto_rsa_verify_sha256_v1(verifier,
                                          reinterpret_cast<const uint8_t*>(kMessage),
                                          sizeof(kMessage) - 1,
                                          kSignature,
                                          sizeof(kSignature)));
    rut_crypto_rsa_verifier_set_destroy_v1(set);
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

TEST(public_key, jwks_selects_only_trusted_exact_id_and_owns_selected_key) {
    char buffer[2048];
    const Str set = jwk(
        buffer,
        lit_str(
            R"({"keys":[{"kid":"other","kty":"EC"},{"kid":"fixed","kty":"RSA","alg":"RS256","n":")"),
        lit_str(R"(","e":"AQAB"}]})"));
    RsaPublicKey key;
    CHECK(!key.load_rs256_jwks(set, lit_str("unknown")));
    CHECK(!key.valid());
    CHECK(!key.load_rs256_jwks(set, lit_str("Fixed")));
    REQUIRE(key.load_rs256_jwks(set, lit_str("fixed")));
    CHECK(!key.load_rs256_jwks(set, lit_str("fixed")));
    for (char& c : buffer) c = 0;
    RsaSha256Verifier verifier;
    REQUIRE(verifier.init(key));
    key.reset();
    CHECK(verifier.verify({kMessage, sizeof(kMessage) - 1}, der(kSignature)));
}

TEST(public_key, jwks_rejects_ambiguous_ids_and_invalid_set_shapes) {
    RsaPublicKey key;
    const Str bad[] = {
        lit_str("null"),
        lit_str("[]"),
        lit_str("{}"),
        lit_str(R"({"keys":{}})"),
        lit_str(R"({"keys":[]})"),
        lit_str(R"({"keys":[null]})"),
        lit_str(R"({"keys":[{}]})"),
        lit_str(R"({"keys":[{"kid":null}]})"),
        lit_str(R"({"keys":[{"kid":""}]})"),
        lit_str(R"({"keys":[{"kid":"fixed","kid":"fixed"}]})"),
        lit_str(R"({"keys":[{"kid":"other"},{"kid":"oth\u0065r"}]})"),
        lit_str(R"({"keys":[],"k\u0065ys":[]})"),
    };
    for (Str set : bad) {
        CHECK(!key.load_rs256_jwks(set, lit_str("fixed")));
        CHECK(!key.valid());
    }
    char buffer[2048];
    const Str prefix = lit_str(R"({"keys":[{"kid":"fixed","kty":"RSA","alg":"RS256","n":")");
    const Str suffixes[] = {
        lit_str(R"(","e":"AQAB"},{"kid":"fixed"}]})"),
        lit_str(R"(","e":"AQAB"},{"kid":"other"},{"kid":"oth\u0065r"}]})"),
        lit_str(R"(","e":"AQAB"},{}]})"),
        lit_str(R"(","e":"AQAB","d":null}]})"),
        lit_str(R"(","e":"Aw"}]})"),
    };
    for (Str suffix : suffixes) {
        CHECK(!key.load_rs256_jwks(jwk(buffer, prefix, suffix), lit_str("fixed")));
        CHECK(!key.valid());
    }
    const Str valid = jwk(buffer, prefix, lit_str(R"(","e":"AQAB"}]})"));
    CHECK(!key.load_rs256_jwks(valid, {nullptr, 1}));
    CHECK(!key.load_rs256_jwks(valid, lit_str("")));
    char oversized_id[129]{};
    CHECK(!key.load_rs256_jwks(valid, {oversized_id, sizeof(oversized_id)}));
    for (u32 length = 0; length < valid.len; ++length) {
        CHECK(!key.load_rs256_jwks({valid.ptr, length}, lit_str("fixed")));
        CHECK(!key.valid());
    }
    REQUIRE(key.load_rs256_jwks(valid, lit_str("fixed")));
}

TEST(public_key, jwks_enforces_set_count_and_decoded_id_bounds) {
    char selected[2048];
    const Str first = jwk(selected,
                          lit_str(R"({"kid":"fixed","kty":"RSA","alg":"RS256","n":")"),
                          lit_str(R"(","e":"AQAB"})"));
    char buffer[8192];
    const u32 counts[] = {16u, 17u};
    for (u32 count : counts) {
        json::Writer output{buffer};
        output.text(lit_str(R"({"keys":[)"));
        output.text(first);
        for (u32 i = 1; i < count; ++i) {
            output.text(lit_str(R"(,{"kid":")"));
            output.put(static_cast<char>('A' + i));
            output.text(lit_str(R"("})"));
        }
        output.text(lit_str("]}"));
        RsaPublicKey key;
        CHECK_EQ(key.load_rs256_jwks({buffer, output.len}, lit_str("fixed")), count == 16);
    }
    const u32 lengths[] = {128u, 129u};
    for (u32 length : lengths) {
        json::Writer output{buffer};
        output.text(lit_str(R"({"keys":[)"));
        output.text(first);
        output.text(lit_str(R"(,{"kid":")"));
        for (u32 i = 0; i < length; ++i) output.put('a');
        output.text(lit_str(R"("}]})"));
        RsaPublicKey key;
        CHECK_EQ(key.load_rs256_jwks({buffer, output.len}, lit_str("fixed")), length == 128);
    }
    RsaPublicKey key;
    CHECK(!key.load_rs256_jwks({nullptr, 1}, lit_str("fixed")));
    CHECK(!key.load_rs256_jwks({buffer, sizeof(buffer) + 1}, lit_str("fixed")));
}

static Str rfc_jwk_set(char* buffer, u32 capacity, const Str* ids, u32 count) {
    json::Writer out{buffer, capacity};
    out.text(lit_str("{\"keys\":["));
    for (u32 i = 0; i < count; ++i) {
        if (i) out.put(',');
        out.text(lit_str("{\"kid\":"));
        if (!json::quote(ids[i], out)) return {};
        out.text(lit_str(R"(,"kty":"RSA","alg":"RS256","e":"AQAB","n":")"));
        out.text({kJwkModulus, sizeof(kJwkModulus) - 1});
        out.text(lit_str("\"}"));
    }
    out.text(lit_str("]}"));
    return out.ok ? Str{buffer, out.len} : Str{};
}

TEST(public_key, trusted_key_subset_and_shard_verifiers_own_independent_lifetimes) {
    char configuration[8192];
    char current_id[] = "current";
    char previous_id[] = "previous";
    const Str available[] = {{current_id, sizeof(current_id) - 1},
                             {previous_id, sizeof(previous_id) - 1},
                             lit_str("not-approved")};
    const Str approved[] = {available[1], available[0]};
    auto input = rfc_jwk_set(configuration, sizeof(configuration), available, 3);
    REQUIRE(input.len > 0);
    Rs256KeySet keys;
    REQUIRE(keys.load(input, approved, 2));
    CHECK_EQ(keys.size(), 2u);
    CHECK(!keys.load(input, available, 3));
    CHECK_EQ(keys.size(), 2u);
    for (char& byte : current_id) byte = 0;
    for (char& byte : previous_id) byte = 0;
    Rs256VerifierSet first;
    Rs256VerifierSet second;
    REQUIRE(first.init(keys));
    REQUIRE(second.init(keys));
    CHECK(!first.init(keys));
    keys.reset();
    for (char& byte : configuration) byte = 0;
    const auto current = first.select(lit_str("current"));
    REQUIRE(current.verifier);
    CHECK(current.kid.eq(lit_str("current")));
    CHECK(current.verifier->verify({kMessage, sizeof(kMessage) - 1}, der(kSignature)));
    const auto previous = first.select(lit_str("previous"));
    REQUIRE(previous.verifier);
    CHECK(previous.verifier != current.verifier);
    CHECK(previous.verifier->verify({kMessage, sizeof(kMessage) - 1}, der(kSignature)));
    CHECK(!first.select(lit_str("not-approved")).verifier);
    CHECK(!first.select(lit_str("Current")).verifier);
    CHECK(!first.select(lit_str("curr")).verifier);
    CHECK(!first.select({nullptr, 1}).verifier);
    CHECK(!first.select(lit_str("")).verifier);
    first.reset();
    first.reset();
    CHECK(!first.valid());
    CHECK(!first.select(lit_str("current")).verifier);
    auto retained = second.select(lit_str("current"));
    REQUIRE(retained.verifier);
    CHECK(retained.verifier->verify({kMessage, sizeof(kMessage) - 1}, der(kSignature)));
}

TEST(public_key, trusted_key_set_rejects_ambiguous_or_partial_preparation) {
    char configuration[8192];
    const Str ids[] = {lit_str("current"), lit_str("previous")};
    auto input = rfc_jwk_set(configuration, sizeof(configuration), ids, 2);
    Rs256KeySet keys;
    Rs256VerifierSet verifiers;
    CHECK(!verifiers.init(keys));
    CHECK(!keys.load(input, nullptr, 1));
    CHECK(!keys.load(input, ids, 0));
    CHECK(!keys.load(input, ids, 17));
    const Str duplicate[] = {ids[0], ids[0]};
    CHECK(!keys.load(input, duplicate, 2));
    const Str missing[] = {ids[0], lit_str("unknown")};
    CHECK(!keys.load(input, missing, 2));
    CHECK(!keys.valid());
    CHECK_EQ(keys.size(), 0u);
    // Failure after the first key load must permit clean preparation afterward.
    REQUIRE(keys.load(input, ids, 2));
    REQUIRE(verifiers.init(keys));
    Rs256KeySet empty;
    CHECK(!verifiers.init(empty));
    CHECK(verifiers.select(ids[0]).verifier != nullptr);
    keys.reset();
    const Str ambiguous[] = {ids[0], ids[1], ids[1]};
    input = rfc_jwk_set(configuration, sizeof(configuration), ambiguous, 3);
    CHECK(!keys.load(input, ids, 1));
    CHECK(!keys.valid());
    CHECK(!keys.load(lit_str("{\"keys\":[{\"kid\":\"current\",\"kty\":\"EC\"}]}"), ids, 1));
    CHECK(!keys.load({nullptr, 1}, ids, 1));
    CHECK(!keys.load({configuration, sizeof(configuration) + 1}, ids, 1));
    const Str invalid_ids[] = {{nullptr, 1}, lit_str("")};
    for (Str id : invalid_ids) CHECK(!keys.load(input, &id, 1));
}

TEST(public_key, trusted_key_set_bounds_ids_and_preserves_decoded_bytes) {
    char configuration[8192];
    char id_bytes[17];
    Str ids[17];
    for (u32 i = 0; i < 17; ++i) {
        id_bytes[i] = static_cast<char>('A' + i);
        ids[i] = {id_bytes + i, 1};
    }
    Rs256KeySet keys;
    auto input = rfc_jwk_set(configuration, sizeof(configuration), ids, 16);
    REQUIRE(input.len > 0);
    REQUIRE(keys.load(input, ids, 16));
    CHECK_EQ(keys.size(), 16u);
    Rs256VerifierSet verifiers;
    REQUIRE(verifiers.init(keys));
    for (u32 i = 0; i < 16; ++i) CHECK(verifiers.select(ids[i]).verifier != nullptr);
    CHECK(!verifiers.select(ids[16]).verifier);
    keys.reset();
    input = rfc_jwk_set(configuration, sizeof(configuration), ids, 17);
    REQUIRE(input.len > 0);
    CHECK(!keys.load(input, ids, 1));
    char long_id[129];
    for (char& byte : long_id) byte = 'a';
    const u32 lengths[] = {128u, 129u};
    for (u32 length : lengths) {
        Str id{long_id, length};
        input = rfc_jwk_set(configuration, sizeof(configuration), &id, 1);
        CHECK_EQ(keys.load(input, &id, 1), length == 128);
        keys.reset();
    }
    const char nul_id[] = "id\0tail";
    const Str id{nul_id, sizeof(nul_id) - 1};
    input = rfc_jwk_set(configuration, sizeof(configuration), &id, 1);
    REQUIRE(keys.load(input, &id, 1));
    verifiers.reset();
    REQUIRE(verifiers.init(keys));
    CHECK(verifiers.select(id).verifier != nullptr);
    CHECK(!verifiers.select(lit_str("id")).verifier);
}

struct KeySetThreadInput {
    const Rs256KeySet* keys;
    bool ok = false;
};
static void* exercise_key_set_on_shard(void* value) {
    auto* input = static_cast<KeySetThreadInput*>(value);
    Rs256VerifierSet verifiers;
    if (!verifiers.init(*input->keys)) return nullptr;
    const Str ids[] = {lit_str("current"), lit_str("previous")};
    for (u32 i = 0; i < 32; ++i) {
        for (Str kid : ids) {
            auto selected = verifiers.select(kid);
            if (!selected.verifier ||
                !selected.verifier->verify({kMessage, sizeof(kMessage) - 1}, der(kSignature)))
                return nullptr;
        }
    }
    input->ok = true;
    return nullptr;
}
TEST(public_key, each_execution_thread_activates_its_own_verifier_set) {
    char configuration[8192];
    const Str ids[] = {lit_str("current"), lit_str("previous")};
    auto input = rfc_jwk_set(configuration, sizeof(configuration), ids, 2);
    Rs256KeySet keys;
    REQUIRE(keys.load(input, ids, 2));
    struct Threads {
        pthread_t threads[2]{};
        u32 count = 0;
        ~Threads() {
            for (u32 i = 0; i < count; ++i) pthread_join(threads[i], nullptr);
        }
    };
    KeySetThreadInput cases[] = {{&keys}, {&keys}};
    Threads threads;
    for (u32 i = 0; i < 2; ++i) {
        REQUIRE(pthread_create(
                    &threads.threads[i], nullptr, exercise_key_set_on_shard, &cases[i]) == 0);
        ++threads.count;
    }
    while (threads.count != 0) {
        REQUIRE(pthread_join(threads.threads[threads.count - 1], nullptr) == 0);
        --threads.count;
    }
    CHECK(cases[0].ok);
    CHECK(cases[1].ok);
}
