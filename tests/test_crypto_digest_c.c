#include "rut/runtime/crypto_c.h"

#include <stdint.h>

int main(void) {
    static const uint8_t input[] = {'a', 'b', 'c'};
    static const uint8_t expected[] =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    uint8_t output[64];
    uint32_t length = 0;
    if (!rut_crypto_digest_hex_v1(
            RUT_CRYPTO_SHA256_V1, input, sizeof(input), 0, 0, 0, output, sizeof(output), &length) ||
        length != sizeof(output))
        return 1;
    if (!rut_crypto_equal_v1(output, expected, sizeof(output))) return 2;
    if (!rut_crypto_equal_bounded_v1(0, 0, 0, 0) ||
        rut_crypto_equal_bounded_v1(input, sizeof(input), output, 0) ||
        rut_crypto_equal_bounded_v1(input, 16385, input, 16385))
        return 6;
    rut_crypto_clear_v1(output, sizeof(output));
    for (uint32_t i = 0; i < sizeof(output); ++i)
        if (output[i]) return 3;
    static const uint8_t key[] = {'k', 'e', 'y'};
    static const uint8_t signature[] =
        "sha256=9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab";
    static const uint8_t prefix[] = "sha256=";
    if (!rut_crypto_hmac_sha256_matches_v1(input,
                                           sizeof(input),
                                           key,
                                           sizeof(key),
                                           signature,
                                           sizeof(signature) - 1,
                                           prefix,
                                           sizeof(prefix) - 1))
        return 4;
    if (rut_crypto_hmac_sha256_matches_v1(input,
                                          sizeof(input) - 1,
                                          key,
                                          sizeof(key),
                                          signature,
                                          sizeof(signature) - 1,
                                          prefix,
                                          sizeof(prefix) - 1) ||
        rut_crypto_hmac_sha256_matches_v1(input,
                                          sizeof(input),
                                          0,
                                          0,
                                          signature,
                                          sizeof(signature) - 1,
                                          prefix,
                                          sizeof(prefix) - 1))
        return 5;
    static const uint8_t id[] = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    static const uint8_t timestamp[] = "1700000000";
    static const uint8_t body[] = "{\"test\": 2432232314}";
    static const uint8_t webhook_signature[] = "v1,hw6D+jquXiPwVQiZTwb2ek9FSrOofldv7tv4JVMsFUY=";
    static const uint8_t webhook_key[] = {0x31, 0xf2, 0x90, 0xf6, 0xbf, 0x06, 0x29, 0x8a,
                                          0xab, 0x4f, 0x08, 0xd4, 0x3c, 0x3f, 0x08, 0x2c,
                                          0xf6, 0x48, 0xa3, 0x62, 0xda, 0x2d, 0xa4, 0xb0};
    const rut_crypto_span_v1 id_span = {id, sizeof(id) - 1};
    const rut_crypto_span_v1 time_span = {timestamp, sizeof(timestamp) - 1};
    const rut_crypto_span_v1 body_span = {body, sizeof(body) - 1};
    const rut_crypto_span_v1 signature_span = {webhook_signature, sizeof(webhook_signature) - 1};
    const rut_crypto_span_v1 key_span = {webhook_key, sizeof(webhook_key)};
    if (!rut_crypto_standard_webhook_valid_v1(
            &id_span, &time_span, &signature_span, &body_span, &key_span, 1700000000, 300) ||
        rut_crypto_standard_webhook_valid_v1(
            &id_span, &time_span, &signature_span, &body_span, &key_span, 1700000301, 300) ||
        rut_crypto_standard_webhook_valid_v1(
            0, &time_span, &signature_span, &body_span, &key_span, 1700000000, 300))
        return 7;
    return 0;
}
