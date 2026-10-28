#pragma once

#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace rut::test {
// Generated test-only signing material, never installed in runtime configuration.
struct Rs256Fixture {
    RSA* key = nullptr;
    char policy_bytes[4096]{};
    Str policy{};
    ~Rs256Fixture() { RSA_free(key); }
    static u32 encode(Str input, char* output) {
        constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        u32 accumulator = 0, bits = 0, length = 0;
        for (u32 i = 0; i < input.len; ++i) {
            accumulator = (accumulator << 8) | static_cast<u8>(input.ptr[i]);
            bits += 8;
            while (bits >= 6) {
                bits -= 6;
                output[length++] = alphabet[(accumulator >> bits) & 63];
            }
        }
        if (bits) output[length++] = alphabet[(accumulator << (6 - bits)) & 63];
        return length;
    }
    bool init() {
        BIGNUM* exponent = BN_new();
        key = RSA_new();
        const bool generated = exponent && key && BN_set_word(exponent, 65537) &&
                               RSA_generate_key_ex(key, 2048, exponent, nullptr);
        BN_free(exponent);
        if (!generated) return false;
        const BIGNUM* modulus = nullptr;
        RSA_get0_key(key, &modulus, nullptr, nullptr);
        unsigned char bytes[512];
        const int size = BN_bn2bin(modulus, bytes);
        char encoded[684];
        const u32 length =
            encode({reinterpret_cast<const char*>(bytes), static_cast<u32>(size)}, encoded);
        json::Writer out{policy_bytes, sizeof(policy_bytes)};
        out.text(lit_str(
            R"({"issuer":"issuer","audience":"gateway","kids":["current"],"jwks":{"keys":[{"kid":"current","kty":"RSA","alg":"RS256","e":"AQAB","n":")"));
        out.text({encoded, length});
        out.text(lit_str(R"("}]}})"));
        policy = {policy_bytes, out.len};
        return out.ok;
    }
    Str sign(Str header, Str claims, char* output) const {
        u32 length = encode(header, output);
        output[length++] = '.';
        length += encode(claims, output + length);
        u8 digest[32];
        u32 digest_length = 0;
        if (!hash_digest(
                HashAlgorithm::Sha256, {output, length}, {}, false, digest, 32, digest_length))
            return {};
        unsigned char signature[512];
        unsigned int signature_length = 0;
        if (!RSA_sign(NID_sha256, digest, 32, signature, &signature_length, key)) return {};
        output[length++] = '.';
        length +=
            encode({reinterpret_cast<const char*>(signature), signature_length}, output + length);
        return {output, length};
    }
    static constexpr Str header = lit_str(R"({"alg":"RS256","kid":"current"})");
    static constexpr Str claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read write"})");
};
}  // namespace rut::test
