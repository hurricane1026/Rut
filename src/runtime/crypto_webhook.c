#include "rut/runtime/crypto_c.h"

static int base64_value(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

uint32_t rut_crypto_standard_webhook_valid_v1(const rut_crypto_span_v1* id,
                                              const rut_crypto_span_v1* timestamp,
                                              const rut_crypto_span_v1* signature,
                                              const rut_crypto_span_v1* body,
                                              const rut_crypto_span_v1* raw_key,
                                              int64_t unix_seconds,
                                              uint32_t tolerance_seconds) {
    if (!id || !timestamp || !signature || !body || !raw_key || !id->data || !id->len ||
        id->len > 256 || !timestamp->data || !timestamp->len || timestamp->len > 19 ||
        !signature->data || !signature->len || signature->len > 4096 ||
        (!body->data && body->len) || body->len > 1024u * 1024u || !raw_key->data ||
        !raw_key->len || raw_key->len > 4096 || unix_seconds <= 0 || tolerance_seconds > 300)
        return 0;
    for (uint32_t i = 0; i < id->len; ++i)
        if (id->data[i] < 0x21 || id->data[i] > 0x7e || id->data[i] == '.') return 0;
    if (timestamp->data[0] < '1' || timestamp->data[0] > '9') return 0;
    uint64_t seconds = 0;
    const uint64_t max_time = 9223372036854775807ULL;
    for (uint32_t i = 0; i < timestamp->len; ++i) {
        uint8_t c = timestamp->data[i];
        if (c < '0' || c > '9') return 0;
        uint64_t digit = (uint64_t)(c - '0');
        if (seconds > (max_time - digit) / 10) return 0;
        seconds = seconds * 10 + digit;
    }
    const uint64_t now = (uint64_t)unix_seconds;
    if ((seconds > now ? seconds - now : now - seconds) > tolerance_seconds) return 0;
    static const uint8_t dot[] = {'.'};
    const rut_crypto_span_v1 parts[] = {*id, {dot, 1}, *timestamp, {dot, 1}, *body};
    uint8_t digest[32];
    uint32_t length = 0;
    if (!rut_crypto_digest_parts_v1(RUT_CRYPTO_SHA256_V1,
                                    parts,
                                    5,
                                    raw_key->data,
                                    raw_key->len,
                                    1,
                                    digest,
                                    sizeof(digest),
                                    &length))
        return 0;
    uint8_t encoded[45];
    uint32_t written = 0;
    uint32_t valid =
        rut_crypto_base64_encode_v1(digest, sizeof(digest), encoded, sizeof(encoded), &written) &&
        written == 44;
    rut_crypto_clear_v1(digest, sizeof(digest));
    uint32_t matches = 0, begin = 0, count = 0;
    while (valid && begin < signature->len) {
        if (++count > 16) {
            valid = 0;
            break;
        }
        uint32_t end = begin;
        while (end < signature->len && signature->data[end] != ' ') ++end;
        uint32_t comma = begin;
        while (comma < end && signature->data[comma] != ',') {
            uint8_t c = signature->data[comma];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
                valid = 0;
            ++comma;
        }
        if (comma == begin || comma == end || comma + 1 == end) {
            valid = 0;
            break;
        }
        for (uint32_t i = comma + 1; i < end; ++i)
            if (signature->data[i] < 0x21 || signature->data[i] > 0x7e || signature->data[i] == ',')
                valid = 0;
        if (comma - begin == 2 && signature->data[begin] == 'v' &&
            signature->data[begin + 1] == '1') {
            const uint8_t* value = signature->data + comma + 1;
            if (end - comma - 1 != 44 || value[43] != '=') {
                valid = 0;
                break;
            }
            for (uint32_t i = 0; i < 43; ++i)
                if (base64_value(value[i]) < 0) valid = 0;
            if ((base64_value(value[42]) & 3) != 0) valid = 0;
            matches |= rut_crypto_equal_v1(value, encoded, 44);
        }
        if (end == signature->len) break;
        begin = end + 1;
        if (begin == signature->len) valid = 0;
    }
    rut_crypto_clear_v1(encoded, sizeof(encoded));
    return valid && matches;
}
