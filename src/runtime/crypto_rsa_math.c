#include "crypto_rsa_math_internal.h"
#include "rut/runtime/crypto_c.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

void rut_crypto_rsa_key_free_internal(EVP_PKEY* key) {
    EVP_PKEY_free(key);
}
uint32_t rut_crypto_rsa_key_bits_internal(const EVP_PKEY* key) {
    return key ? (uint32_t)EVP_PKEY_bits(key) : 0;
}

EVP_PKEY* rut_crypto_rsa_load_der_internal(const uint8_t* der, uint32_t length) {
    if (!der || !length || length > 8192) return 0;
    const uint8_t* cursor = der;
    EVP_PKEY* candidate = d2i_PUBKEY(0, &cursor, length);
    if (!candidate) return 0;
    if (cursor != der + length || EVP_PKEY_id(candidate) != EVP_PKEY_RSA) goto fail;
    const int bits = EVP_PKEY_bits(candidate);
    if (bits < 2048 || bits > 4096) goto fail;
    const RSA* rsa = EVP_PKEY_get0_RSA(candidate);
    if (!rsa) goto fail;
    const BIGNUM* modulus = 0;
    const BIGNUM* exponent = 0;
    RSA_get0_key(rsa, &modulus, &exponent, 0);
    if (!modulus || !exponent || !BN_is_odd(modulus) || !BN_is_word(exponent, 65537)) goto fail;
    const int canonical_size = i2d_PUBKEY(candidate, 0);
    if (canonical_size <= 0 || (uint32_t)canonical_size != length) goto fail;
    uint8_t canonical[8192];
    uint8_t* output = canonical;
    if (i2d_PUBKEY(candidate, &output) != canonical_size) goto fail;
    uint32_t identical = 1;
    for (uint32_t i = 0; i < length; ++i)
        if (canonical[i] != der[i]) identical = 0;
    if (!identical) goto fail;
    return candidate;
fail:
    EVP_PKEY_free(candidate);
    return 0;
}

EVP_PKEY* rut_crypto_rsa_from_modulus_internal(const uint8_t* modulus, uint32_t length) {
    if (!modulus || length < 256 || length > 512) return 0;
    RSA* rsa = RSA_new();
    BIGNUM* n = BN_bin2bn(modulus, (int)length, 0);
    BIGNUM* e = BN_new();
    EVP_PKEY* owner = EVP_PKEY_new();
    EVP_PKEY* accepted = 0;
    if (rsa && n && e && owner && BN_set_word(e, 65537) && RSA_set0_key(rsa, n, e, 0)) {
        n = 0;
        e = 0;
        if (EVP_PKEY_set1_RSA(owner, rsa)) {
            uint8_t der[8192];
            const int size = i2d_PUBKEY(owner, 0);
            if (size > 0 && (uint32_t)size <= sizeof(der)) {
                uint8_t* cursor = der;
                if (i2d_PUBKEY(owner, &cursor) == size)
                    accepted = rut_crypto_rsa_load_der_internal(der, (uint32_t)size);
            }
        }
    }
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
    EVP_PKEY_free(owner);
    return accepted;
}

void rut_crypto_rsa_workspace_reset_internal(EVP_PKEY** key,
                                             const BIGNUM** modulus,
                                             const BIGNUM** exponent,
                                             BIGNUM** input,
                                             BIGNUM** output,
                                             BN_CTX** scratch,
                                             BN_MONT_CTX** mont,
                                             uint32_t* bytes) {
    BN_free(*input);
    BN_free(*output);
    BN_CTX_free(*scratch);
    BN_MONT_CTX_free(*mont);
    EVP_PKEY_free(*key);
    *key = 0;
    *modulus = 0;
    *exponent = 0;
    *input = 0;
    *output = 0;
    *scratch = 0;
    *mont = 0;
    *bytes = 0;
}

uint32_t rut_crypto_rsa_workspace_init_internal(EVP_PKEY* source,
                                                EVP_PKEY** key,
                                                const BIGNUM** modulus,
                                                const BIGNUM** exponent,
                                                BIGNUM** input,
                                                BIGNUM** output,
                                                BN_CTX** scratch,
                                                BN_MONT_CTX** mont,
                                                uint32_t* bytes) {
    if (!source || *key || !EVP_PKEY_up_ref(source)) return 0;
    *key = source;
    const RSA* rsa = EVP_PKEY_get0_RSA(source);
    RSA_get0_key(rsa, modulus, exponent, 0);
    *input = BN_new();
    *output = BN_new();
    *scratch = BN_CTX_new();
    *mont = BN_MONT_CTX_new();
    if (!*input || !*output || !*scratch || !*mont || !BN_MONT_CTX_set(*mont, *modulus, *scratch))
        goto fail;
    const int bits = BN_num_bits(*modulus);
    if (!BN_set_bit(*input, bits + 64) || !BN_set_bit(*output, bits + 64) ||
        !BN_copy(*input, *modulus) || !BN_sub_word(*input, 1) ||
        !BN_mod_exp_mont(*output, *input, *exponent, *modulus, *scratch, *mont))
        goto fail;
    BN_zero(*input);
    BN_zero(*output);
    *bytes = (uint32_t)((bits + 7) / 8);
    return 1;
fail:
    rut_crypto_rsa_workspace_reset_internal(
        key, modulus, exponent, input, output, scratch, mont, bytes);
    return 0;
}

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
