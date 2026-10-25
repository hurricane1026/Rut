#include "rut/runtime/auth.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>

namespace rut {
namespace {

// HTTP authentication schemes are case-insensitive and use 1*SP before data.
// Field-level OWS is handled by the HTTP parser, not by this credential parser.
Str auth_payload(Str authorization, Str scheme) {
    if (authorization.ptr == nullptr || authorization.len <= scheme.len ||
        !http_header_name_eq_ci(authorization.ptr, scheme.len, scheme.ptr, scheme.len) ||
        authorization.ptr[scheme.len] != ' ')
        return {nullptr, 0};
    u32 begin = scheme.len + 1;
    while (begin < authorization.len && authorization.ptr[begin] == ' ') ++begin;
    return {authorization.ptr + begin, authorization.len - begin};
}

}  // namespace

static bool bearer_bytes_valid(Str key, u32 maximum) {
    if (key.ptr == nullptr || key.len == 0 || key.len > maximum) return false;
    bool padding = false;
    u32 data_len = 0;
    for (u32 i = 0; i < key.len; ++i) {
        const auto kByte = static_cast<u8>(key.ptr[i]);
        if (kByte == '=') {
            padding = true;
            continue;
        }
        const bool kDataByte = (kByte >= 'A' && kByte <= 'Z') || (kByte >= 'a' && kByte <= 'z') ||
                               (kByte >= '0' && kByte <= '9') || kByte == '-' || kByte == '.' ||
                               kByte == '_' || kByte == '~' || kByte == '+' || kByte == '/';
        if (padding || !kDataByte) return false;
        ++data_len;
    }
    return data_len != 0;
}

bool bearer_key_valid(Str key) {
    return bearer_bytes_valid(key, kMaxBearerKeyBytes);
}

Str bearer_token(Str authorization) {
    const Str kToken = auth_payload(authorization, lit_str("Bearer"));
    return bearer_bytes_valid(kToken, kMaxBearerTokenBytes) ? kToken : Str{nullptr, 0};
}

bool bearer_matches(Str authorization, Str key) {
    if (!bearer_key_valid(key)) return false;
    const Str kToken = auth_payload(authorization, lit_str("Bearer"));
    return kToken.len == key.len && kToken.ptr != nullptr &&
           CRYPTO_memcmp(kToken.ptr, key.ptr, key.len) == 0;
}

bool basic_credentials_valid(Str credentials) {
    if (credentials.ptr == nullptr || credentials.len == 0 ||
        credentials.len > kMaxBasicCredentialBytes)
        return false;
    u32 separator = credentials.len;
    for (u32 i = 0; i < credentials.len; ++i) {
        const auto kByte = static_cast<u8>(credentials.ptr[i]);
        if (kByte < 0x20 || kByte == 0x7f) return false;
        if (kByte == ':' && separator == credentials.len) separator = i;
    }
    return separator != 0 && separator != credentials.len;
}

bool basic_matches(Str authorization, Str credentials) {
    if (!basic_credentials_valid(credentials)) return false;
    const Str kToken = auth_payload(authorization, lit_str("Basic"));
    const u32 kExpectedLen = ((credentials.len + 2) / 3) * 4;
    if (kToken.ptr == nullptr || kToken.len != kExpectedLen) return false;
    // Encode the trusted credential instead of decoding attacker-controlled data.
    // Exact comparison also rejects malformed/noncanonical padding and pad bits.
    u8 encoded[((kMaxBasicCredentialBytes + 2) / 3) * 4 + 1];
    const size_t kWritten = EVP_EncodeBlock(
        encoded, reinterpret_cast<const u8*>(credentials.ptr), static_cast<int>(credentials.len));
    const bool kMatches =
        kWritten == kExpectedLen && CRYPTO_memcmp(kToken.ptr, encoded, kExpectedLen) == 0;
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return kMatches;
}

bool hmac_sha256_matches(Str message, Str key, Str signature, Str prefix) {
    if ((message.ptr == nullptr && message.len != 0) || message.len > kMaxHmacMessageBytes ||
        key.ptr == nullptr || key.len == 0 || key.len > kMaxHmacKeyBytes ||
        signature.ptr == nullptr || prefix.len > 64 || (prefix.ptr == nullptr && prefix.len != 0) ||
        signature.len != prefix.len + 64)
        return false;
    // Prefix is a public wire-format marker chosen by trusted policy.
    for (u32 i = 0; i < prefix.len; ++i)
        if (signature.ptr[i] != prefix.ptr[i]) return false;
    // Same stack-based RFC 2104 construction used by the JWT verifier. Avoid
    // EVP/HMAC context allocation on the request path.
    u8 block[64]{};
    u8 inner[32]{};
    u8 expected[32]{};
    SHA256_CTX ctx;
    if (key.len > sizeof(block)) {
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, key.ptr, key.len);
        SHA256_Final(block, &ctx);
    } else {
        for (u32 i = 0; i < key.len; ++i) block[i] = static_cast<u8>(key.ptr[i]);
    }
    for (u8& byte : block) byte ^= 0x36;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, block, sizeof(block));
    if (message.len != 0) SHA256_Update(&ctx, message.ptr, message.len);
    SHA256_Final(inner, &ctx);
    for (u8& byte : block) byte ^= 0x36 ^ 0x5c;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, block, sizeof(block));
    SHA256_Update(&ctx, inner, sizeof(inner));
    SHA256_Final(expected, &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_cleanse(inner, sizeof(inner));
    char encoded[64]{};
    constexpr char kHex[] = "0123456789abcdef";
    for (u32 i = 0; i < 32; ++i) {
        encoded[static_cast<size_t>(i) * 2] = kHex[expected[i] >> 4];
        encoded[static_cast<size_t>(i) * 2 + 1] = kHex[expected[i] & 15];
    }
    const bool kMatches = CRYPTO_memcmp(encoded, signature.ptr + prefix.len, sizeof(encoded)) == 0;
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return kMatches;
}

}  // namespace rut
