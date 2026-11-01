#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace rut::test::jwt_lifetime {

inline constexpr char kSecret[] = "jwt-lifetime-test-secret-abcdefghijklmnopqrstuvwxyz";

inline std::string base64url(const unsigned char* bytes, std::size_t length) {
    std::string result(4 * ((length + 2) / 3), '\0');
    const int encoded = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(result.data()), bytes, static_cast<int>(length));
    if (encoded <= 0) return {};
    result.resize(static_cast<std::size_t>(encoded));
    for (char& c : result) {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    while (!result.empty() && result.back() == '=') result.pop_back();
    return result;
}

inline std::string base64url(const std::string& value) {
    return base64url(reinterpret_cast<const unsigned char*>(value.data()), value.size());
}

inline std::string make_token(const std::string& claims) {
    const std::string header = base64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    const std::string payload = base64url(claims);
    const std::string signing_input = header + "." + payload;
    unsigned char signature[EVP_MAX_MD_SIZE]{};
    unsigned int signature_len = 0;
    if (HMAC(EVP_sha256(),
             kSecret,
             static_cast<int>(sizeof(kSecret) - 1),
             reinterpret_cast<const unsigned char*>(signing_input.data()),
             signing_input.size(),
             signature,
             &signature_len) == nullptr)
        return {};
    return signing_input + "." + base64url(signature, signature_len);
}

inline std::string claims(std::int64_t issued_at,
                          std::int64_t expires,
                          const char* issuer = "issuer",
                          bool include_issued_at = true) {
    std::string value = "{\"sub\":\"alice\",\"iss\":\"";
    value += issuer;
    value += "\",\"aud\":\"gateway\",\"exp\":" + std::to_string(expires);
    if (include_issued_at) value += ",\"iat\":" + std::to_string(issued_at);
    value += "}";
    return value;
}

}  // namespace rut::test::jwt_lifetime
