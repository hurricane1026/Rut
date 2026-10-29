#include "rut/runtime/crypto_c.h"

#include <stddef.h>

int main(void) {
    static const uint8_t expected[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                       0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                       0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                       0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    static const uint8_t input[] = {'a', 'b', 'c'};
    uint8_t out[64] = {0};
    uint32_t len = 999;
    if (!rut_crypto_digest_v1(
            RUT_CRYPTO_SHA256_V1, input, sizeof(input), NULL, 0, 0, out, sizeof(out), &len) ||
        len != sizeof(expected))
        return 1;
    for (uint32_t i = 0; i < sizeof(expected); ++i)
        if (out[i] != expected[i]) return 2;
    out[0] = 0xa5;
    len = 999;
    if (rut_crypto_digest_v1(
            RUT_CRYPTO_SHA256_V1, input, sizeof(input), NULL, 0, 0, out, 31, &len) ||
        len != 0 || out[0] != 0xa5)
        return 3;
    len = 999;
    if (rut_crypto_digest_v1(999, input, sizeof(input), NULL, 0, 0, out, sizeof(out), &len) ||
        len != 0 || out[0] != 0xa5)
        return 4;
    if (rut_crypto_digest_v1(RUT_CRYPTO_SHA256_V1, NULL, 1, NULL, 0, 0, out, sizeof(out), &len) ||
        len != 0 || out[0] != 0xa5)
        return 5;
    if (rut_crypto_digest_v1(
            RUT_CRYPTO_SHA256_V1, input, sizeof(input), NULL, 0, 2, out, sizeof(out), &len) ||
        len != 0 || out[0] != 0xa5)
        return 6;
    if (rut_crypto_digest_v1(
            RUT_CRYPTO_SHA256_V1, input, 1024u * 1024u + 1, NULL, 0, 0, out, sizeof(out), &len) ||
        len != 0 || out[0] != 0xa5)
        return 7;
    if (rut_crypto_digest_v1(
            RUT_CRYPTO_SHA256_V1, input, sizeof(input), NULL, 0, 0, out, sizeof(out), NULL) ||
        out[0] != 0xa5)
        return 8;
    static const uint8_t hmac_key[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    static const uint8_t message[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
    static const uint8_t hmac_expected[32] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
                                              0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                                              0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                                              0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    if (!rut_crypto_digest_v1(RUT_CRYPTO_SHA256_V1,
                              message,
                              sizeof(message),
                              hmac_key,
                              sizeof(hmac_key),
                              1,
                              out,
                              sizeof(out),
                              &len) ||
        len != sizeof(hmac_expected))
        return 9;
    for (uint32_t i = 0; i < sizeof(hmac_expected); ++i)
        if (out[i] != hmac_expected[i]) return 10;
    const rut_crypto_span_v1 parts[] = {{message, 3}, {message + 3, sizeof(message) - 3}};
    if (!rut_crypto_digest_parts_v1(RUT_CRYPTO_SHA256_V1,
                                    parts,
                                    2,
                                    hmac_key,
                                    sizeof(hmac_key),
                                    1,
                                    out,
                                    sizeof(out),
                                    &len) ||
        len != sizeof(hmac_expected))
        return 11;
    for (uint32_t i = 0; i < sizeof(hmac_expected); ++i)
        if (out[i] != hmac_expected[i]) return 12;
    out[0] = 0xa5;
    if (rut_crypto_digest_parts_v1(
            RUT_CRYPTO_SHA256_V1, NULL, 1, hmac_key, sizeof(hmac_key), 1, out, sizeof(out), &len) ||
        len != 0 || out[0] != 0xa5)
        return 13;
    const rut_crypto_span_v1 invalid[] = {{NULL, 1}};
    if (rut_crypto_digest_parts_v1(RUT_CRYPTO_SHA256_V1,
                                   invalid,
                                   1,
                                   hmac_key,
                                   sizeof(hmac_key),
                                   1,
                                   out,
                                   sizeof(out),
                                   &len) ||
        len != 0 || out[0] != 0xa5)
        return 14;
    uint8_t long_key[4097];
    for (uint32_t i = 0; i < sizeof(long_key); ++i) long_key[i] = 'k';
    static const uint8_t jwt[] = {'j', 'w', 't'};
    static const uint8_t long_expected[32] = {0xce, 0xae, 0x45, 0xc6, 0xee, 0xa0, 0x33, 0x30,
                                              0x44, 0xd2, 0xfd, 0x01, 0x48, 0x68, 0xf8, 0x18,
                                              0x7b, 0x44, 0x69, 0x1f, 0x97, 0x3c, 0xbb, 0xaa,
                                              0x07, 0x07, 0x4e, 0x55, 0x25, 0x2f, 0x7b, 0xaf};
    if (!rut_crypto_hmac_long_key_v1(RUT_CRYPTO_SHA256_V1,
                                     jwt,
                                     sizeof(jwt),
                                     long_key,
                                     sizeof(long_key),
                                     out,
                                     sizeof(out),
                                     &len) ||
        len != 32)
        return 15;
    for (uint32_t i = 0; i < sizeof(long_expected); ++i)
        if (out[i] != long_expected[i]) return 16;
    out[0] = 0xa5;
    if (rut_crypto_hmac_long_key_v1(RUT_CRYPTO_SHA256_V1,
                                    jwt,
                                    sizeof(jwt),
                                    long_key,
                                    0x80000000u,
                                    out,
                                    sizeof(out),
                                    &len) ||
        len != 0 || out[0] != 0xa5)
        return 17;
    return 0;
}
