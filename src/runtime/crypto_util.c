#include "rut/runtime/crypto_c.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

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
