#include "rut/runtime/webhook.h"

#include "rut/runtime/crypto_c.h"
#include "rut/runtime/hash.h"

#include <time.h>

namespace rut {
namespace {
int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
}  // namespace

bool standard_webhook_valid(Str id,
                            Str timestamp,
                            Str signature,
                            Str body,
                            Str raw_key,
                            i64 unix_seconds,
                            u32 tolerance_seconds) {
    if (!id.ptr || id.len == 0 || id.len > 256 || !timestamp.ptr || timestamp.len == 0 ||
        timestamp.len > 19 || !signature.ptr || signature.len == 0 || signature.len > 4096 ||
        (!body.ptr && body.len != 0) || body.len > kMaxHashInputBytes || !raw_key.ptr ||
        raw_key.len == 0 || raw_key.len > kMaxHashKeyBytes || unix_seconds <= 0 ||
        tolerance_seconds > 300)
        return false;
    for (u32 i = 0; i < id.len; ++i)
        if (id.ptr[i] < 0x21 || id.ptr[i] > 0x7e || id.ptr[i] == '.') return false;
    if (timestamp.ptr[0] < '1' || timestamp.ptr[0] > '9') return false;
    u64 seconds = 0;
    constexpr u64 kMaxTime = 9223372036854775807ULL;
    for (u32 i = 0; i < timestamp.len; ++i) {
        const char c = timestamp.ptr[i];
        if (c < '0' || c > '9') return false;
        const u64 digit = static_cast<u64>(c - '0');
        if (seconds > (kMaxTime - digit) / 10) return false;
        seconds = seconds * 10 + digit;
    }
    const u64 now = static_cast<u64>(unix_seconds);
    if ((seconds > now ? seconds - now : now - seconds) > tolerance_seconds) return false;

    static constexpr u8 kDot[] = {'.'};
    const rut_crypto_span_v1 parts[] = {
        {reinterpret_cast<const u8*>(id.ptr), id.len},
        {kDot, sizeof(kDot)},
        {reinterpret_cast<const u8*>(timestamp.ptr), timestamp.len},
        {kDot, sizeof(kDot)},
        {reinterpret_cast<const u8*>(body.ptr), body.len},
    };
    u8 digest[32];
    u32 digest_len = 0;
    if (!rut_crypto_digest_parts_v1(RUT_CRYPTO_SHA256_V1,
                                    parts,
                                    5,
                                    reinterpret_cast<const u8*>(raw_key.ptr),
                                    raw_key.len,
                                    1,
                                    digest,
                                    sizeof(digest),
                                    &digest_len))
        return false;
    u8 encoded[45];
    u32 encoded_len = 0;
    bool valid =
        digest_len == sizeof(digest) &&
        rut_crypto_base64_encode_v1(digest, digest_len, encoded, sizeof(encoded), &encoded_len) &&
        encoded_len == 44;
    rut_crypto_clear_v1(digest, sizeof(digest));
    bool matches = false;
    u32 begin = 0;
    u32 count = 0;
    while (valid && begin < signature.len) {
        if (++count > 16) {
            valid = false;
            break;
        }
        u32 end = begin;
        while (end < signature.len && signature.ptr[end] != ' ') ++end;
        u32 comma = begin;
        while (comma < end && signature.ptr[comma] != ',') {
            const char c = signature.ptr[comma];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
                valid = false;
            ++comma;
        }
        if (comma == begin || comma == end || comma + 1 == end) {
            valid = false;
            break;
        }
        for (u32 i = comma + 1; i < end; ++i)
            if (signature.ptr[i] < 0x21 || signature.ptr[i] > 0x7e || signature.ptr[i] == ',')
                valid = false;
        if (Str{signature.ptr + begin, comma - begin}.eq(lit_str("v1"))) {
            const Str value{signature.ptr + comma + 1, end - comma - 1};
            if (value.len != 44 || value.ptr[43] != '=') {
                valid = false;
                break;
            }
            for (u32 i = 0; i < 43; ++i)
                if (base64_value(value.ptr[i]) < 0) valid = false;
            if ((base64_value(value.ptr[42]) & 3) != 0) valid = false;
            matches |=
                rut_crypto_equal_v1(reinterpret_cast<const u8*>(value.ptr), encoded, 44) != 0;
        }
        if (end == signature.len) break;
        begin = end + 1;
        if (begin == signature.len) valid = false;
    }
    rut_crypto_clear_v1(encoded, sizeof(encoded));
    return valid && matches;
}

bool standard_webhook_valid_now(Str id, Str timestamp, Str signature, Str body, Str raw_key) {
    timespec now{};
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000)
        return false;
    return standard_webhook_valid(
        id, timestamp, signature, body, raw_key, static_cast<i64>(now.tv_sec), 300);
}
}  // namespace rut
