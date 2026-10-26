#include "public_key_fixtures.h"
#include "rsa_verify_fixtures.h"
#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"
#include "rut/runtime/jwt_rs256.h"
#include "rut/runtime/public_key.h"
#include "test.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
using namespace rut;
static bool tracking = false;
static u32 allocations = 0;
static void* counted_malloc(size_t n, const char*, int) {
    if (tracking) ++allocations;
    return malloc(n);
}
static void* counted_realloc(void* p, size_t n, const char*, int) {
    if (tracking) ++allocations;
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
int main(int argc, char** argv) {
    if (!CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free)) return 2;
    return rut::test::run_all(argc, argv);
}
