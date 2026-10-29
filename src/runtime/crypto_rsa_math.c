#include "crypto_rsa_math_internal.h"
#include "rut/runtime/crypto_c.h"

#include <openssl/bn.h>

uint32_t rut_crypto_rsa_verify_internal(const BIGNUM* modulus,
                                        const BIGNUM* exponent,
                                        BIGNUM* input,
                                        BIGNUM* output,
                                        BN_CTX* scratch,
                                        BN_MONT_CTX* mont,
                                        uint32_t bytes,
                                        const uint8_t* message,
                                        uint32_t message_len,
                                        const uint8_t* signature,
                                        uint32_t signature_len) {
    if (!modulus || !exponent || !input || !output || !scratch || !mont || bytes < 256 ||
        bytes > 512 || !signature || signature_len != bytes || (!message && message_len) ||
        message_len > 1024u * 1024u)
        return 0;
    if (!BN_bin2bn(signature, (int)bytes, input) || BN_cmp(input, modulus) >= 0 ||
        !BN_mod_exp_mont(output, input, exponent, modulus, scratch, mont))
        return 0;
    uint8_t actual[512];
    if (BN_bn2binpad(output, actual, (int)bytes) != (int)bytes) return 0;
    /* RFC 8017 9.2: compare the complete fixed SHA-256 encoded message. */
    static const uint8_t digest_info[] = {0x30,
                                          0x31,
                                          0x30,
                                          0x0d,
                                          0x06,
                                          0x09,
                                          0x60,
                                          0x86,
                                          0x48,
                                          0x01,
                                          0x65,
                                          0x03,
                                          0x04,
                                          0x02,
                                          0x01,
                                          0x05,
                                          0x00,
                                          0x04,
                                          0x20};
    uint8_t expected[512];
    const uint32_t padding_end = bytes - sizeof(digest_info) - 32 - 1;
    expected[0] = 0;
    expected[1] = 1;
    for (uint32_t i = 2; i < padding_end; ++i) expected[i] = 0xff;
    expected[padding_end] = 0;
    for (uint32_t i = 0; i < sizeof(digest_info); ++i)
        expected[padding_end + 1 + i] = digest_info[i];
    uint32_t digest_len = 0;
    if (!rut_crypto_digest_v1(RUT_CRYPTO_SHA256_V1,
                              message,
                              message_len,
                              0,
                              0,
                              0,
                              expected + bytes - 32,
                              32,
                              &digest_len) ||
        digest_len != 32)
        return 0;
    return rut_crypto_equal_v1(actual, expected, bytes);
}
