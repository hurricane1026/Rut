#include "public_key_fixtures.h"
#include "rsa_verify_fixtures.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/hash.h"
#include "rut/runtime/public_key.h"
#include "test.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
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
template <size_t N>
static Str span(const unsigned char (&b)[N]) {
    return {reinterpret_cast<const char*>(b), static_cast<u32>(N)};
}
TEST(rsa_verify, c_abi_borrows_caller_storage_and_keeps_key_reference) {
    alignas(64) unsigned char key_storage[256]{};
    alignas(64) unsigned char verifier_storage[1024]{};
    REQUIRE(rut_crypto_rsa_key_size_v1() <= sizeof(key_storage));
    REQUIRE(rut_crypto_rsa_key_align_v1() <= 64);
    REQUIRE(rut_crypto_rsa_verifier_size_v1() <= sizeof(verifier_storage));
    REQUIRE(rut_crypto_rsa_verifier_align_v1() <= 64);
    CHECK(rut_crypto_rsa_key_init_v1(key_storage, 0) == nullptr);
    CHECK(rut_crypto_rsa_key_init_v1(key_storage + 1, sizeof(key_storage) - 1) == nullptr);
    auto* key = rut_crypto_rsa_key_init_v1(key_storage, sizeof(key_storage));
    REQUIRE(key);
    CHECK(!rut_crypto_rsa_key_load_der_v1(key, nullptr, 1));
    REQUIRE(rut_crypto_rsa_key_load_der_v1(key, kRfcRsaSpki, sizeof(kRfcRsaSpki)));
    auto* verifier =
        rut_crypto_rsa_verifier_init_v1(verifier_storage, sizeof(verifier_storage), key);
    REQUIRE(verifier);
    rut_crypto_rsa_key_destroy_v1(key);
    allocations = 0;
    tracking = true;
    bool ok = rut_crypto_rsa_verify_sha256_v1(verifier,
                                              reinterpret_cast<const u8*>(kMessage),
                                              sizeof(kMessage) - 1,
                                              kSignature,
                                              sizeof(kSignature));
    bool bad = rut_crypto_rsa_verify_sha256_v1(
        verifier, reinterpret_cast<const u8*>("wrong"), 5, kSignature, sizeof(kSignature));
    tracking = false;
    CHECK(ok);
    CHECK(!bad);
    CHECK_EQ(allocations, 0u);
    CHECK(!rut_crypto_rsa_verify_sha256_v1(verifier, nullptr, 1, kSignature, sizeof(kSignature)));
    rut_crypto_rsa_verifier_destroy_v1(verifier);
}
TEST(rsa_verify, published_vector_lifetime_and_request_allocations) {
    RsaPublicKey key;
    RsaSha256Verifier verifier;
    CHECK(!verifier.init(key));
    tracking = true;
    bool loaded = key.load(span(kRfcRsaSpki));
    bool initialized = loaded && verifier.init(key);
    tracking = false;
    REQUIRE(initialized);
    CHECK(allocations > 0);
    CHECK(!verifier.init(key));
    key.reset();
    allocations = 0;
    tracking = true;
    bool valid = verifier.verify({kMessage, sizeof(kMessage) - 1}, span(kSignature));
    bool wrong_message = verifier.verify(lit_str("changed"), span(kSignature));
    unsigned char modified[sizeof(kSignature)];
    bool rejected = true;
    for (u32 i = 0; i < sizeof(kSignature); ++i) {
        for (u32 j = 0; j < sizeof(kSignature); ++j) modified[j] = kSignature[j];
        modified[i] ^= 1;
        if (verifier.verify({kMessage, sizeof(kMessage) - 1}, span(modified))) rejected = false;
    }
    const u32 fills[] = {0u, 1u, 255u};
    for (u32 byte : fills) {
        for (auto& x : modified) x = static_cast<unsigned char>(byte);
        if (verifier.verify({nullptr, 0}, span(modified))) rejected = false;
    }
    tracking = false;
    CHECK(valid);
    CHECK(!wrong_message);
    CHECK(rejected);
    CHECK_EQ(allocations, 0u);
    CHECK(!verifier.verify({nullptr, 1}, span(kSignature)));
    CHECK(!verifier.verify({kMessage, 1024 * 1024 + 1}, span(kSignature)));
    CHECK(!verifier.verify(lit_str(""), {nullptr, 256}));
    CHECK(!verifier.verify(lit_str(""), {reinterpret_cast<const char*>(kSignature), 255}));
    verifier.reset();
    verifier.reset();
    CHECK(!verifier.valid());
    CHECK(!verifier.verify({kMessage, sizeof(kMessage) - 1}, span(kSignature)));
}
TEST(rsa_verify, key_widths_binary_empty_limits_and_strict_encoding) {
    const int widths[] = {2048, 2049, 3072, 4096};
    static char message[1024 * 1024];
    message[0] = 'a';
    message[2] = 'b';
    for (int width : widths) {
        BIGNUM* exponent = BN_new();
        RSA* rsa = RSA_new();
        REQUIRE(exponent && rsa);
        REQUIRE(BN_set_word(exponent, 65537));
        REQUIRE(RSA_generate_key_ex(rsa, width, exponent, nullptr));
        BN_free(exponent);
        EVP_PKEY* owner = EVP_PKEY_new();
        REQUIRE(owner);
        REQUIRE(EVP_PKEY_set1_RSA(owner, rsa));
        unsigned char encoded[8192];
        unsigned char* cursor = encoded;
        int length = i2d_PUBKEY(owner, &cursor);
        REQUIRE(length > 0);
        RsaPublicKey key;
        REQUIRE(key.load({reinterpret_cast<const char*>(encoded), static_cast<u32>(length)}));
        EVP_PKEY_free(owner);
        RsaSha256Verifier verifier;
        REQUIRE(verifier.init(key));
        key.reset();
        const u32 lengths[] = {0, 3, sizeof(message)};
        for (u32 len : lengths) {
            u8 digest[32];
            u32 digest_len = 0;
            REQUIRE(hash_digest(HashAlgorithm::Sha256,
                                {message, len},
                                {},
                                false,
                                digest,
                                sizeof(digest),
                                digest_len));
            unsigned char signature[512];
            unsigned int signature_len = 0;
            REQUIRE(RSA_sign(NID_sha256, digest, 32, signature, &signature_len, rsa));
            allocations = 0;
            tracking = true;
            bool accepted = verifier.verify(
                {message, len}, {reinterpret_cast<const char*>(signature), signature_len});
            tracking = false;
            CHECK(accepted);
            CHECK_EQ(allocations, 0u);
            // Recover the independently encoded EM, then sign deliberately
            // malformed padding and DigestInfo with this disposable test key.
            unsigned char em[512];
            REQUIRE(RSA_public_decrypt(signature_len, signature, em, rsa, RSA_NO_PADDING) ==
                    static_cast<int>(signature_len));
            const u32 positions[] = {
                0, 1, 2, signature_len - 52, signature_len - 33, signature_len - 1};
            for (u32 index : positions) {
                // A leading 1 can exceed a non-byte-aligned modulus; that
                // representative is already covered by the explicit s == n test.
                if (index == 0 && width % 8 != 0) continue;
                em[index] ^= 1;
                REQUIRE(RSA_private_encrypt(signature_len, em, signature, rsa, RSA_NO_PADDING) ==
                        static_cast<int>(signature_len));
                em[index] ^= 1;
                allocations = 0;
                tracking = true;
                bool bad = verifier.verify(
                    {message, len}, {reinterpret_cast<const char*>(signature), signature_len});
                tracking = false;
                CHECK(!bad);
                CHECK_EQ(allocations, 0u);
            }
        }
        verifier.reset();
        REQUIRE(key.load(span(kRfcRsaSpki)));
        REQUIRE(verifier.init(key));
        CHECK(verifier.verify({kMessage, sizeof(kMessage) - 1}, span(kSignature)));
        RSA_free(rsa);
    }
}

TEST(rsa_verify, preserves_caller_errors_and_rejects_representative_at_modulus) {
    RsaPublicKey key;
    REQUIRE(key.load(span(kRfcRsaSpki)));
    RsaSha256Verifier verifier;
    REQUIRE(verifier.init(key));
    const unsigned char* cursor = kRfcRsaSpki;
    EVP_PKEY* parsed = d2i_PUBKEY(nullptr, &cursor, sizeof(kRfcRsaSpki));
    REQUIRE(parsed);
    const BIGNUM* modulus = nullptr;
    RSA_get0_key(EVP_PKEY_get0_RSA(parsed), &modulus, nullptr, nullptr);
    unsigned char signature[256];
    REQUIRE(BN_bn2binpad(modulus, signature, sizeof(signature)) == sizeof(signature));
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, 42, __FILE__, __LINE__);
    unsigned long previous = ERR_peek_last_error();
    CHECK(!verifier.verify({kMessage, sizeof(kMessage) - 1}, span(signature)));
    CHECK(verifier.verify({kMessage, sizeof(kMessage) - 1}, span(kSignature)));
    CHECK_EQ(ERR_peek_last_error(), previous);
    ERR_clear_error();
    EVP_PKEY_free(parsed);
}

int main(int argc, char** argv) {
    if (!CRYPTO_set_mem_functions(counted_malloc, counted_realloc, counted_free)) return 2;
    return rut::test::run_all(argc, argv);
}
