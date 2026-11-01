#pragma once

#include <string>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>

namespace rut::test::signed_request {

inline constexpr char kKeyId[] = "rut-test-key";
inline constexpr char kSecret[] = "signed-request-test-secret-32bytes";

struct Headers {
    std::string date;
    std::string digest;
    std::string authorization;
};

inline std::string base64(const unsigned char* bytes, unsigned int length) {
    std::string result(4 * ((length + 2) / 3), '\0');
    const int encoded = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(result.data()), bytes, static_cast<int>(length));
    result.resize(encoded > 0 ? static_cast<size_t>(encoded) : 0);
    return result;
}

inline std::string format_date(long long unix_seconds) {
    const time_t seconds = static_cast<time_t>(unix_seconds);
    struct tm utc{};
    if (gmtime_r(&seconds, &utc) == nullptr) return {};
    static constexpr const char* kWeekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static constexpr const char* kMonths[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (utc.tm_wday < 0 || utc.tm_wday >= 7 || utc.tm_mon < 0 || utc.tm_mon >= 12) return {};
    char value[30]{};
    const int length = __builtin_snprintf(value,
                                          sizeof(value),
                                          "%s, %02d %s %04d %02d:%02d:%02d GMT",
                                          kWeekdays[utc.tm_wday],
                                          utc.tm_mday,
                                          kMonths[utc.tm_mon],
                                          utc.tm_year + 1900,
                                          utc.tm_hour,
                                          utc.tm_min,
                                          utc.tm_sec);
    return length == 29 ? std::string(value, 29) : std::string{};
}

inline Headers make_headers(const char* method,
                            const std::string& target,
                            const std::string& body,
                            long long unix_seconds) {
    Headers result;
    result.date = format_date(unix_seconds);
    unsigned char body_hash[EVP_MAX_MD_SIZE]{};
    unsigned int body_hash_len = 0;
    if (EVP_Digest(body.data(), body.size(), body_hash, &body_hash_len, EVP_sha256(), nullptr) != 1)
        return {};
    result.digest = "SHA-256=" + base64(body_hash, body_hash_len);

    const std::string canonical = std::string(kKeyId) + "\n" + method + " " + target + "\n" +
                                  "date: " + result.date + "\n" + "digest: " + result.digest + "\n";
    unsigned char signature[EVP_MAX_MD_SIZE]{};
    unsigned int signature_len = 0;
    if (HMAC(EVP_sha256(),
             kSecret,
             sizeof(kSecret) - 1,
             reinterpret_cast<const unsigned char*>(canonical.data()),
             canonical.size(),
             signature,
             &signature_len) == nullptr)
        return {};
    result.authorization = "Signature keyId=\"";
    result.authorization += kKeyId;
    result.authorization +=
        "\",algorithm=\"hmac-sha256\",headers=\"@request-target date digest\",signature=\"";
    result.authorization += base64(signature, signature_len);
    result.authorization += '"';
    return result;
}

}  // namespace rut::test::signed_request
