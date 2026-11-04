#pragma once

#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

namespace rut::test {
// Test-only signing material; never installed in runtime configuration. Sign
// with the library's independent ECDSA implementation, not the runtime verifier.
struct Es256Fixture {
    EC_KEY* key = nullptr;
    char policy_bytes[2048]{};
    Str policy{};
    ~Es256Fixture() { EC_KEY_free(key); }
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
        key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!key || EC_KEY_generate_key(key) != 1) return false;
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        unsigned char coordinates[64];
        const bool valid =
            x && y &&
            EC_POINT_get_affine_coordinates(
                EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, nullptr) == 1 &&
            BN_bn2binpad(x, coordinates, 32) == 32 && BN_bn2binpad(y, coordinates + 32, 32) == 32;
        BN_free(x);
        BN_free(y);
        if (!valid) return false;
        char encoded[43];
        json::Writer out{policy_bytes, sizeof(policy_bytes)};
        out.text(lit_str(
            R"({"issuer":"issuer","audience":"gateway","kids":["current"],"jwks":{"keys":[{"kid":"current","kty":"EC","alg":"ES256","crv":"P-256","x":")"));
        out.text({encoded, encode({reinterpret_cast<const char*>(coordinates), 32}, encoded)});
        out.text(lit_str(R"(","y":")"));
        out.text({encoded, encode({reinterpret_cast<const char*>(coordinates + 32), 32}, encoded)});
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
        if (!hash_digest(HashAlgorithm::Sha256,
                         {output, length},
                         {},
                         false,
                         digest,
                         sizeof(digest),
                         digest_length))
            return {};
        ECDSA_SIG* signed_value = ECDSA_do_sign(digest, sizeof(digest), key);
        if (!signed_value) return {};
        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(signed_value, &r, &s);
        u8 signature[64];
        const bool valid =
            BN_bn2binpad(r, signature, 32) == 32 && BN_bn2binpad(s, signature + 32, 32) == 32;
        ECDSA_SIG_free(signed_value);
        if (!valid) return {};
        output[length++] = '.';
        length +=
            encode({reinterpret_cast<const char*>(signature), sizeof(signature)}, output + length);
        return {output, length};
    }
    static constexpr Str header = lit_str(R"({"alg":"ES256","kid":"current"})");
    static constexpr Str claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read write"})");
};
}  // namespace rut::test
