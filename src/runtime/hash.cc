#include "rut/runtime/hash.h"

#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace rut {
namespace {

union HashContext {
    MD5_CTX md5;
    SHA_CTX sha1;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
};

u32 digest_size(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::Md5:
            return 16;
        case HashAlgorithm::Sha1:
            return 20;
        case HashAlgorithm::Sha224:
            return 28;
        case HashAlgorithm::Sha256:
            return 32;
        case HashAlgorithm::Sha384:
            return 48;
        case HashAlgorithm::Sha512:
            return 64;
    }
    return 0;
}

void init(HashContext& ctx, HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::Md5:
            MD5_Init(&ctx.md5);
            break;
        case HashAlgorithm::Sha1:
            SHA1_Init(&ctx.sha1);
            break;
        case HashAlgorithm::Sha224:
            SHA224_Init(&ctx.sha256);
            break;
        case HashAlgorithm::Sha256:
            SHA256_Init(&ctx.sha256);
            break;
        case HashAlgorithm::Sha384:
            SHA384_Init(&ctx.sha512);
            break;
        case HashAlgorithm::Sha512:
            SHA512_Init(&ctx.sha512);
            break;
    }
}

void update(HashContext& ctx, HashAlgorithm algorithm, const void* data, u32 length) {
    if (length == 0) return;
    switch (algorithm) {
        case HashAlgorithm::Md5:
            MD5_Update(&ctx.md5, data, length);
            break;
        case HashAlgorithm::Sha1:
            SHA1_Update(&ctx.sha1, data, length);
            break;
        case HashAlgorithm::Sha224:
        case HashAlgorithm::Sha256:
            SHA256_Update(&ctx.sha256, data, length);
            break;
        case HashAlgorithm::Sha384:
        case HashAlgorithm::Sha512:
            SHA512_Update(&ctx.sha512, data, length);
            break;
    }
}

void finish(HashContext& ctx, HashAlgorithm algorithm, u8* output) {
    switch (algorithm) {
        case HashAlgorithm::Md5:
            MD5_Final(output, &ctx.md5);
            break;
        case HashAlgorithm::Sha1:
            SHA1_Final(output, &ctx.sha1);
            break;
        case HashAlgorithm::Sha224:
            SHA224_Final(output, &ctx.sha256);
            break;
        case HashAlgorithm::Sha256:
            SHA256_Final(output, &ctx.sha256);
            break;
        case HashAlgorithm::Sha384:
            SHA384_Final(output, &ctx.sha512);
            break;
        case HashAlgorithm::Sha512:
            SHA512_Final(output, &ctx.sha512);
            break;
    }
}

}  // namespace

bool hash_digest(HashAlgorithm algorithm,
                 Str data,
                 Str key,
                 bool keyed,
                 u8* output,
                 u32 capacity,
                 u32& output_len) {
    output_len = 0;
    const u32 kSize = digest_size(algorithm);
    if (kSize == 0 || output == nullptr || capacity < kSize ||
        (data.ptr == nullptr && data.len != 0) || (keyed && key.ptr == nullptr && key.len != 0))
        return false;
    HashContext ctx{};
    u8 result[kMaxHashDigestBytes]{};
    if (!keyed) {
        init(ctx, algorithm);
        update(ctx, algorithm, data.ptr, data.len);
        finish(ctx, algorithm, result);
    } else {
        // RFC 2104 over OpenSSL's allocation-free streaming digest primitives.
        const u32 kBlockSize =
            algorithm == HashAlgorithm::Sha384 || algorithm == HashAlgorithm::Sha512 ? 128u : 64u;
        u8 block[128]{};
        u8 inner[kMaxHashDigestBytes]{};
        if (key.len > kBlockSize) {
            init(ctx, algorithm);
            update(ctx, algorithm, key.ptr, key.len);
            finish(ctx, algorithm, block);
        } else {
            for (u32 i = 0; i < key.len; ++i) block[i] = static_cast<u8>(key.ptr[i]);
        }
        for (u32 i = 0; i < kBlockSize; ++i) block[i] ^= 0x36;
        init(ctx, algorithm);
        update(ctx, algorithm, block, kBlockSize);
        update(ctx, algorithm, data.ptr, data.len);
        finish(ctx, algorithm, inner);
        for (u32 i = 0; i < kBlockSize; ++i) block[i] ^= 0x36 ^ 0x5c;
        init(ctx, algorithm);
        update(ctx, algorithm, block, kBlockSize);
        update(ctx, algorithm, inner, kSize);
        finish(ctx, algorithm, result);
        OPENSSL_cleanse(block, sizeof(block));
        OPENSSL_cleanse(inner, sizeof(inner));
    }
    for (u32 i = 0; i < kSize; ++i) output[i] = result[i];
    output_len = kSize;
    OPENSSL_cleanse(result, sizeof(result));
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    return true;
}

bool hash_hex(HashAlgorithm algorithm,
              Str data,
              Str key,
              bool keyed,
              char (&output)[kMaxHashHexBytes],
              u32& output_len) {
    output_len = 0;
    if (data.len > kMaxHashInputBytes || (keyed && key.len > kMaxHashKeyBytes)) return false;
    u8 bytes[kMaxHashDigestBytes]{};
    u32 length = 0;
    if (!hash_digest(algorithm, data, key, keyed, bytes, sizeof(bytes), length)) return false;
    constexpr char kHex[] = "0123456789abcdef";
    for (u32 i = 0; i < length; ++i) {
        const u32 kOffset = 2 * i;
        output[kOffset] = kHex[bytes[i] >> 4];
        output[kOffset + 1] = kHex[bytes[i] & 15];
    }
    output_len = length * 2;
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return true;
}

}  // namespace rut
