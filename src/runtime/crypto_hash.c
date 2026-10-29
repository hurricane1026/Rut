#include "crypto_hash_internal.h"

#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

typedef union {
    MD5_CTX md5;
    SHA_CTX sha1;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
} HashContext;

static uint32_t digest_size(uint32_t algorithm) {
    static const uint8_t sizes[] = {16, 20, 28, 32, 48, 64};
    return algorithm <= RUT_CRYPTO_SHA512_V1 ? sizes[algorithm] : 0;
}
static void hash_init(HashContext* ctx, uint32_t algorithm) {
    switch (algorithm) {
        case RUT_CRYPTO_MD5_V1:
            MD5_Init(&ctx->md5);
            break;
        case RUT_CRYPTO_SHA1_V1:
            SHA1_Init(&ctx->sha1);
            break;
        case RUT_CRYPTO_SHA224_V1:
            SHA224_Init(&ctx->sha256);
            break;
        case RUT_CRYPTO_SHA256_V1:
            SHA256_Init(&ctx->sha256);
            break;
        case RUT_CRYPTO_SHA384_V1:
            SHA384_Init(&ctx->sha512);
            break;
        case RUT_CRYPTO_SHA512_V1:
            SHA512_Init(&ctx->sha512);
            break;
        default:
            break;
    }
}
static void hash_update(HashContext* ctx, uint32_t algorithm, const void* data, uint32_t length) {
    if (!length) return;
    switch (algorithm) {
        case RUT_CRYPTO_MD5_V1:
            MD5_Update(&ctx->md5, data, length);
            break;
        case RUT_CRYPTO_SHA1_V1:
            SHA1_Update(&ctx->sha1, data, length);
            break;
        case RUT_CRYPTO_SHA224_V1:
        case RUT_CRYPTO_SHA256_V1:
            SHA256_Update(&ctx->sha256, data, length);
            break;
        case RUT_CRYPTO_SHA384_V1:
        case RUT_CRYPTO_SHA512_V1:
            SHA512_Update(&ctx->sha512, data, length);
            break;
        default:
            break;
    }
}
static void hash_finish(HashContext* ctx, uint32_t algorithm, uint8_t* output) {
    switch (algorithm) {
        case RUT_CRYPTO_MD5_V1:
            MD5_Final(output, &ctx->md5);
            break;
        case RUT_CRYPTO_SHA1_V1:
            SHA1_Final(output, &ctx->sha1);
            break;
        case RUT_CRYPTO_SHA224_V1:
            SHA224_Final(output, &ctx->sha256);
            break;
        case RUT_CRYPTO_SHA256_V1:
            SHA256_Final(output, &ctx->sha256);
            break;
        case RUT_CRYPTO_SHA384_V1:
            SHA384_Final(output, &ctx->sha512);
            break;
        case RUT_CRYPTO_SHA512_V1:
            SHA512_Final(output, &ctx->sha512);
            break;
        default:
            break;
    }
}

/* Internal core: legacy callers enforce their own input and key size limits. */
uint32_t rut_crypto_digest_unbounded_internal(uint32_t algorithm,
                                              const rut_crypto_span_v1* parts,
                                              uint32_t count,
                                              const uint8_t* key,
                                              uint32_t key_len,
                                              uint32_t keyed,
                                              uint8_t* output,
                                              uint32_t capacity,
                                              uint32_t* output_len) {
    if (!output_len) return 0;
    *output_len = 0;
    const uint32_t size = digest_size(algorithm);
    if (!size || !output || capacity < size || (!parts && count) || count > 16 ||
        (keyed && !key && key_len))
        return 0;
    for (uint32_t i = 0; i < count; ++i)
        if (!parts[i].data && parts[i].len) return 0;
    HashContext ctx = {0};
    uint8_t result[64] = {0};
    if (!keyed) {
        hash_init(&ctx, algorithm);
        for (uint32_t i = 0; i < count; ++i)
            hash_update(&ctx, algorithm, parts[i].data, parts[i].len);
        hash_finish(&ctx, algorithm, result);
    } else {
        const uint32_t block_size = algorithm >= RUT_CRYPTO_SHA384_V1 ? 128 : 64;
        uint8_t block[128] = {0};
        uint8_t inner[64] = {0};
        if (key_len > block_size) {
            hash_init(&ctx, algorithm);
            hash_update(&ctx, algorithm, key, key_len);
            hash_finish(&ctx, algorithm, block);
        } else {
            for (uint32_t i = 0; i < key_len; ++i) block[i] = key[i];
        }
        for (uint32_t i = 0; i < block_size; ++i) block[i] ^= 0x36;
        hash_init(&ctx, algorithm);
        hash_update(&ctx, algorithm, block, block_size);
        for (uint32_t i = 0; i < count; ++i)
            hash_update(&ctx, algorithm, parts[i].data, parts[i].len);
        hash_finish(&ctx, algorithm, inner);
        for (uint32_t i = 0; i < block_size; ++i) block[i] ^= 0x36 ^ 0x5c;
        hash_init(&ctx, algorithm);
        hash_update(&ctx, algorithm, block, block_size);
        hash_update(&ctx, algorithm, inner, size);
        hash_finish(&ctx, algorithm, result);
        OPENSSL_cleanse(block, sizeof(block));
        OPENSSL_cleanse(inner, sizeof(inner));
    }
    for (uint32_t i = 0; i < size; ++i) output[i] = result[i];
    *output_len = size;
    OPENSSL_cleanse(result, sizeof(result));
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    return 1;
}

uint32_t rut_crypto_digest_v1(uint32_t algorithm,
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
    if (algorithm > RUT_CRYPTO_SHA512_V1 || keyed > 1 || data_len > 1024u * 1024u ||
        key_len > 4096 || (!data && data_len) || (!key && key_len))
        return 0;
    const rut_crypto_span_v1 part = {data, data_len};
    return rut_crypto_digest_unbounded_internal(
        algorithm, &part, 1, key, key_len, keyed, output, capacity, output_len);
}

uint32_t rut_crypto_digest_parts_v1(uint32_t algorithm,
                                    const rut_crypto_span_v1* parts,
                                    uint32_t count,
                                    const uint8_t* key,
                                    uint32_t key_len,
                                    uint32_t keyed,
                                    uint8_t* output,
                                    uint32_t capacity,
                                    uint32_t* output_len) {
    if (!output_len) return 0;
    *output_len = 0;
    if (algorithm > RUT_CRYPTO_SHA512_V1 || keyed > 1 || count > 16 || (!parts && count) ||
        key_len > 4096 || (!key && key_len))
        return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if ((!parts[i].data && parts[i].len) || parts[i].len > (1024u * 1024u + 4096u) - total)
            return 0;
        total += parts[i].len;
    }
    return rut_crypto_digest_unbounded_internal(
        algorithm, parts, count, key, key_len, keyed, output, capacity, output_len);
}

uint32_t rut_crypto_hmac_long_key_v1(uint32_t algorithm,
                                     const uint8_t* data,
                                     uint32_t data_len,
                                     const uint8_t* key,
                                     uint32_t key_len,
                                     uint8_t* output,
                                     uint32_t capacity,
                                     uint32_t* output_len) {
    if (!output_len) return 0;
    *output_len = 0;
    if (algorithm > RUT_CRYPTO_SHA512_V1 || data_len > 1024u * 1024u || key_len > 0x7fffffffu ||
        (!data && data_len) || (!key && key_len))
        return 0;
    const rut_crypto_span_v1 part = {data, data_len};
    return rut_crypto_digest_unbounded_internal(
        algorithm, &part, 1, key, key_len, 1, output, capacity, output_len);
}
