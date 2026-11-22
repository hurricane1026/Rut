#include "rut/runtime/signed_request.h"

#include "rut/common/types.h"
#include "rut/runtime/crypto_c.h"

namespace rut {
namespace {

constexpr u32 kMaxAuth = 4096;
constexpr u32 kMaxTarget = 8192;
constexpr u32 kMaxBody = 1024 * 1024;
constexpr u32 kDigestSize = 32;
constexpr u32 kBase64Size = 44;

bool equal(Str a, const char* b, u32 length) {
    return a.ptr && a.len == length && __builtin_memcmp(a.ptr, b, length) == 0;
}

bool valid_key_id(Str id) {
    if (!id.ptr || id.len == 0 || id.len > 128) return false;
    for (u32 i = 0; i < id.len; ++i) {
        const u8 kC = static_cast<u8>(id.ptr[i]);
        if (kC < 0x21 || kC > 0x7e || kC == '"' || kC == '\\' || kC == ',') return false;
    }
    return true;
}

bool supported_method(Str method) {
    return equal(method, "GET", 3) || equal(method, "POST", 4) || equal(method, "PUT", 3) ||
           equal(method, "DELETE", 6) || equal(method, "PATCH", 5) || equal(method, "HEAD", 4) ||
           equal(method, "OPTIONS", 7) || equal(method, "TRACE", 5);
}

bool valid_target(Str target) {
    if (!target.ptr || target.len == 0 || target.len > kMaxTarget || target.ptr[0] != '/')
        return false;
    for (u32 i = 0; i < target.len; ++i) {
        const u8 kC = static_cast<u8>(target.ptr[i]);
        if (kC <= 0x20 || kC == 0x7f || kC == '#') return false;
    }
    return true;
}

struct AuthFields {
    Str key_id{};
    Str algorithm{};
    Str headers{};
    Str signature{};
    u8 seen = 0;
};

bool parse_authorization(Str auth, AuthFields& out) {
    if (!auth.ptr || auth.len == 0 || auth.len > kMaxAuth || auth.len < 10 ||
        !equal({auth.ptr, 10}, "Signature ", 10))
        return false;
    for (u32 i = 0; i < auth.len; ++i) {
        const u8 kC = static_cast<u8>(auth.ptr[i]);
        if (kC == '\r' || kC == '\n' || kC == 0) return false;
    }

    u32 pos = 10;
    u32 count = 0;
    while (pos < auth.len) {
        if (count != 0) {
            while (pos < auth.len && (auth.ptr[pos] == ' ' || auth.ptr[pos] == '\t')) ++pos;
        }
        const u32 kNameBegin = pos;
        while (pos < auth.len && ((auth.ptr[pos] >= 'a' && auth.ptr[pos] <= 'z') ||
                                  (auth.ptr[pos] >= 'A' && auth.ptr[pos] <= 'Z')))
            ++pos;
        if (kNameBegin == pos || pos >= auth.len || auth.ptr[pos] != '=') return false;
        ++pos;
        if (pos >= auth.len || auth.ptr[pos] != '"') return false;
        ++pos;
        const Str kName{auth.ptr + static_cast<i64>(kNameBegin),
                        static_cast<u32>(static_cast<i64>(pos) - static_cast<i64>(kNameBegin) - 2)};
        const u32 kValueBegin = pos;
        while (pos < auth.len && auth.ptr[pos] != '"') {
            const u8 kC = static_cast<u8>(auth.ptr[pos]);
            if (kC < 0x20 || kC > 0x7e || kC == '\\' || kC == ',') return false;
            ++pos;
        }
        if (pos >= auth.len) return false;
        const Str kValue{auth.ptr + static_cast<i64>(kValueBegin),
                         static_cast<u32>(static_cast<i64>(pos) - static_cast<i64>(kValueBegin))};
        ++pos;

        u8 bit = 0;
        Str* target = nullptr;
        if (equal(kName, "keyId", 5)) {
            bit = 1;
            target = &out.key_id;
        } else if (equal(kName, "algorithm", 9)) {
            bit = 2;
            target = &out.algorithm;
        } else if (equal(kName, "headers", 7)) {
            bit = 4;
            target = &out.headers;
        } else if (equal(kName, "signature", 9)) {
            bit = 8;
            target = &out.signature;
        } else {
            return false;
        }
        if ((out.seen & bit) != 0) return false;
        out.seen |= bit;
        *target = kValue;
        ++count;

        if (pos == auth.len) break;
        if (auth.ptr[pos] != ',') return false;
        ++pos;
        if (pos == auth.len) return false;
    }
    return count == 4 && out.seen == 15;
}

bool parse_http_date(Str value, u64& seconds) {
    if (!value.ptr || value.len != 29 || value.ptr[3] != ',' || value.ptr[4] != ' ' ||
        value.ptr[7] != ' ' || value.ptr[11] != ' ' || value.ptr[16] != ' ' ||
        value.ptr[19] != ':' || value.ptr[22] != ':' || value.ptr[25] != ' ' ||
        !equal({value.ptr + 26, 3}, "GMT", 3))
        return false;
    const char* p = value.ptr;
    auto number = [&](u32 start, u32 count, u32& result) {
        result = 0;
        for (u32 i = 0; i < count; ++i) {
            const char kC = p[static_cast<i64>(start) + static_cast<i64>(i)];
            if (kC < '0' || kC > '9') return false;
            result = static_cast<u32>(static_cast<i64>(result) * 10 + static_cast<i64>(kC - '0'));
        }
        return true;
    };
    u32 day, year, hour, minute, second;
    if (!number(5, 2, day) || !number(12, 4, year) || !number(17, 2, hour) ||
        !number(20, 2, minute) || !number(23, 2, second) || year < 1970 || hour > 23 ||
        minute > 59 || second > 59)
        return false;
    constexpr char kMonths[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    constexpr u32 kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    u32 month = 0;
    while (month < 12 && !equal({p + 8, 3}, kMonths + static_cast<i64>(month) * 3, 3)) ++month;
    if (month == 12) return false;
    const bool kLeap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (day == 0 ||
        static_cast<i64>(day) > static_cast<i64>(kDays[month]) + (month == 1 && kLeap ? 1 : 0))
        return false;
    auto leap_years = [](u32 y) -> i64 {
        return static_cast<i64>(y / 4) - static_cast<i64>(y / 100) + static_cast<i64>(y / 400);
    };
    i64 days = (static_cast<i64>(year) - 1970) * 365 +
               leap_years(static_cast<u32>(static_cast<i64>(year) - 1)) - leap_years(1969);
    for (u32 i = 0; i < month; ++i) days += static_cast<i64>(kDays[i]) + (i == 1 && kLeap ? 1 : 0);
    days += static_cast<i64>(day) - 1;
    constexpr char kWeekdays[] = "SunMonTueWedThuFriSat";
    if (!equal({p, 3}, kWeekdays + static_cast<i64>((days + 4) % 7) * 3, 3)) return false;
    const i64 seconds_wide = days * 86400 + static_cast<i64>(hour) * 3600 +
                             static_cast<i64>(minute) * 60 + static_cast<i64>(second);
    seconds = static_cast<u64>(seconds_wide);
    return true;
}

bool fresh_enough(u64 timestamp, i64 now) {
    if (now <= 0) return false;
    const u64 kCurrent = static_cast<u64>(now);
    u64 delta = 0;
    if (timestamp > kCurrent) {
        (void)__builtin_sub_overflow(timestamp, kCurrent, &delta);
    } else {
        (void)__builtin_sub_overflow(kCurrent, timestamp, &delta);
    }
    return delta <= 300;
}

bool matches_canonical_base64(Str value, const u8* bytes, u32 length) {
    u8 expected[static_cast<size_t>(static_cast<i64>(kBase64Size) + 1)]{};
    u32 expected_len = 0;
    const bool kEncoded =
        rut_crypto_base64_encode_v1(bytes, length, expected, sizeof(expected), &expected_len) != 0;
    const bool kMatches =
        kEncoded && expected_len == value.len &&
        rut_crypto_equal_v1(reinterpret_cast<const u8*>(value.ptr), expected, expected_len) != 0;
    rut_crypto_clear_v1(expected, sizeof(expected));
    return kMatches;
}

}  // namespace

bool signed_request_hmac_sha256_valid(Str method,
                                      Str request_target,
                                      Str authorization,
                                      Str date,
                                      Str digest,
                                      Str raw_body,
                                      Str trusted_key_id,
                                      Str trusted_secret,
                                      i64 unix_seconds) {
    if (!supported_method(method) || !valid_target(request_target) || !trusted_key_id.ptr ||
        !valid_key_id(trusted_key_id) || !trusted_secret.ptr || trusted_secret.len == 0 ||
        trusted_secret.len > 4096 || (!raw_body.ptr && raw_body.len) || raw_body.len > kMaxBody)
        return false;

    AuthFields fields{};
    if (!parse_authorization(authorization, fields) || !valid_key_id(fields.key_id) ||
        !fields.key_id.eq(trusted_key_id) || !equal(fields.algorithm, "hmac-sha256", 11) ||
        !equal(fields.headers, "@request-target date digest", 27))
        return false;
    if (!fields.signature.ptr || fields.signature.len != kBase64Size) return false;

    u64 date_seconds = 0;
    if (!parse_http_date(date, date_seconds) || !fresh_enough(date_seconds, unix_seconds))
        return false;

    u8 body_hash[kDigestSize]{};
    u32 body_hash_len = 0;
    if (!rut_crypto_digest_v1(RUT_CRYPTO_SHA256_V1,
                              reinterpret_cast<const u8*>(raw_body.ptr),
                              raw_body.len,
                              nullptr,
                              0,
                              0,
                              body_hash,
                              sizeof(body_hash),
                              &body_hash_len) ||
        body_hash_len != sizeof(body_hash))
        return false;
    u8 expected_digest[static_cast<size_t>(static_cast<i64>(kBase64Size) + 1)]{};
    u32 expected_digest_len = 0;
    const bool kDigestEncoded = rut_crypto_base64_encode_v1(body_hash,
                                                            sizeof(body_hash),
                                                            expected_digest,
                                                            sizeof(expected_digest),
                                                            &expected_digest_len) != 0;
    static constexpr char kDigestPrefix[] = "SHA-256=";
    const bool kDigestMatches =
        digest.ptr && kDigestEncoded && expected_digest_len == kBase64Size &&
        digest.len == static_cast<u32>(static_cast<i64>(sizeof(kDigestPrefix) - 1) +
                                       static_cast<i64>(kBase64Size)) &&
        __builtin_memcmp(digest.ptr, kDigestPrefix, sizeof(kDigestPrefix) - 1) == 0 &&
        rut_crypto_equal_v1(
            reinterpret_cast<const u8*>(digest.ptr + static_cast<i64>(sizeof(kDigestPrefix) - 1)),
            expected_digest,
            kBase64Size);
    rut_crypto_clear_v1(body_hash, sizeof(body_hash));
    rut_crypto_clear_v1(expected_digest, sizeof(expected_digest));
    if (!kDigestMatches) return false;

    static constexpr u8 kLf[] = {'\n'};
    static constexpr u8 kSpace[] = {' '};
    static constexpr u8 kDatePrefix[] = {'d', 'a', 't', 'e', ':', ' '};
    static constexpr u8 kDigestLinePrefix[] = {'d', 'i', 'g', 'e', 's', 't', ':', ' '};
    static constexpr u8 kDigestPrefixBytes[] = "SHA-256=";
    const rut_crypto_span_v1 kParts[] = {
        {reinterpret_cast<const u8*>(trusted_key_id.ptr), trusted_key_id.len},
        {kLf, sizeof(kLf)},
        {reinterpret_cast<const u8*>(method.ptr), method.len},
        {kSpace, sizeof(kSpace)},
        {reinterpret_cast<const u8*>(request_target.ptr), request_target.len},
        {kLf, sizeof(kLf)},
        {kDatePrefix, sizeof(kDatePrefix)},
        {reinterpret_cast<const u8*>(date.ptr), date.len},
        {kLf, sizeof(kLf)},
        {kDigestLinePrefix, sizeof(kDigestLinePrefix)},
        {kDigestPrefixBytes, sizeof(kDigestPrefixBytes) - 1},
        {reinterpret_cast<const u8*>(digest.ptr + sizeof(kDigestPrefix) - 1), kBase64Size},
        {kLf, sizeof(kLf)},
    };
    u8 mac[kDigestSize]{};
    u32 mac_len = 0;
    const bool kComputed =
        rut_crypto_digest_parts_v1(RUT_CRYPTO_SHA256_V1,
                                   kParts,
                                   sizeof(kParts) / sizeof(kParts[0]),
                                   reinterpret_cast<const u8*>(trusted_secret.ptr),
                                   trusted_secret.len,
                                   1,
                                   mac,
                                   sizeof(mac),
                                   &mac_len) != 0 &&
        mac_len == sizeof(mac);
    const bool kValid = kComputed && matches_canonical_base64(fields.signature, mac, mac_len);
    rut_crypto_clear_v1(mac, sizeof(mac));
    return kValid;
}

}  // namespace rut
