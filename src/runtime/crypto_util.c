#include "rut/runtime/crypto_c.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

uint32_t rut_crypto_digest_hex_v1(uint32_t algorithm,
                                  const uint8_t* data,
                                  uint32_t data_len,
                                  const uint8_t* key,
                                  uint32_t key_len,
                                  uint32_t keyed,
                                  uint8_t* output,
                                  uint32_t capacity,
                                  uint32_t* output_len) {
    if (!output_len) return 0;
    *output_len = 0;
    uint8_t digest[64];
    uint32_t length = 0;
    if (!rut_crypto_digest_v1(
            algorithm, data, data_len, key, key_len, keyed, digest, sizeof(digest), &length))
        return 0;
    if (!output || capacity < length * 2) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return 0;
    }
    static const char hex[] = "0123456789abcdef";
    for (uint32_t i = 0; i < length; ++i) {
        *output++ = hex[digest[i] >> 4];
        *output++ = hex[digest[i] & 15];
    }
    OPENSSL_cleanse(digest, sizeof(digest));
    *output_len = length * 2;
    return 1;
}

uint32_t rut_crypto_equal_v1(const uint8_t* a, const uint8_t* b, uint32_t length) {
    if (length == 0) return 1;
    if (!a || !b) return 0;
    return CRYPTO_memcmp(a, b, length) == 0;
}

void rut_crypto_clear_v1(void* data, uint32_t length) {
    if (data && length) OPENSSL_cleanse(data, length);
}

uint32_t rut_crypto_base64_encode_v1(const uint8_t* input,
                                     uint32_t length,
                                     uint8_t* output,
                                     uint32_t capacity,
                                     uint32_t* output_len) {
    if (!output_len) return 0;
    *output_len = 0;
    if ((!input && length) || !output || length > 1024u * 1024u) return 0;
    uint32_t needed = ((length + 2) / 3) * 4;
    if (capacity <= needed) return 0;
    static const uint8_t empty = 0;
    int written = EVP_EncodeBlock(output, input ? input : &empty, (int)length);
    if (written < 0 || (uint32_t)written != needed) return 0;
    *output_len = needed;
    return 1;
}
