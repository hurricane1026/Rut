#include "crypto_ec_math_internal.h"
#include "rut/runtime/crypto_c.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <stdint.h>

EVP_PKEY* rut_crypto_ec_load_der_internal(const uint8_t* der, uint32_t length) {
    if (!der || !length || length > 8192) return 0;
    const uint8_t* cursor = der;
    EVP_PKEY* candidate = d2i_PUBKEY(0, &cursor, length);
    if (!candidate) return 0;
    if (cursor != der + length || EVP_PKEY_id(candidate) != EVP_PKEY_EC) goto fail;
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(candidate);
    const EC_GROUP* group = ec ? EC_KEY_get0_group(ec) : 0;
    const EC_POINT* point = ec ? EC_KEY_get0_public_key(ec) : 0;
    if (!group || !point || EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1 ||
        EC_GROUP_get_asn1_flag(group) != OPENSSL_EC_NAMED_CURVE ||
        EC_POINT_is_at_infinity(group, point) != 0 || EC_KEY_check_key(ec) != 1)
        goto fail;
    const int kSize = i2d_PUBKEY(candidate, 0);
    if (kSize <= 0 || (uint32_t)kSize != length) goto fail;
    uint8_t canonical[8192];
    uint8_t* output = canonical;
    if (i2d_PUBKEY(candidate, &output) != kSize) goto fail;
    for (uint32_t i = 0; i < length; ++i)
        if (canonical[i] != der[i]) goto fail;
    return candidate;
fail:
    EVP_PKEY_free(candidate);
    return 0;
}

EVP_PKEY* rut_crypto_ec_from_coordinates_internal(const uint8_t x[32], const uint8_t y[32]) {
    if (!x || !y) return 0;
    /* Canonical named-curve, uncompressed SubjectPublicKeyInfo. d2i_PUBKEY plus
       EC_KEY_check_key validates coordinates, curve membership and infinity. */
    static const uint8_t kPrefix[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                      0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                      0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};
    uint8_t der[91];
    for (uint32_t i = 0; i < sizeof(kPrefix); ++i) der[i] = kPrefix[i];
    for (uint32_t i = 0; i < 32; ++i) {
        der[sizeof(kPrefix) + i] = x[i];
        der[sizeof(kPrefix) + 32 + i] = y[i];
    }
    return rut_crypto_ec_load_der_internal(der, sizeof(der));
}

void rut_crypto_ec_workspace_reset_internal(EVP_PKEY** key,
                                            EC_POINT** points,
                                            BIGNUM** values,
                                            BN_CTX** scratch) {
    for (uint32_t i = 0; i < 4; ++i) {
        EC_POINT_free(points[i]);
        points[i] = 0;
    }
    for (uint32_t i = 0; i < 7; ++i) {
        BN_free(values[i]);
        values[i] = 0;
    }
    BN_CTX_free(*scratch);
    EVP_PKEY_free(*key);
    *scratch = 0;
    *key = 0;
}

/* -1 means a math failure, 0 a rejected signature, 1 a verified signature.
   This deliberately avoids EC_POINT_mul/EVP verification's per-call scratch
   allocation. Shamir's two-scalar multiplication uses preallocated points and
   the pinned library's field operations. Every scalar/branch is public data. */
static int verify_digest(EVP_PKEY* key,
                         EC_POINT* const* points,
                         BIGNUM* const* values,
                         BN_CTX* scratch,
                         const uint8_t digest[32],
                         const uint8_t signature[64]) {
    const EC_GROUP* group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key));
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BIGNUM *r = values[0], *s = values[1], *w = values[2], *u = values[3], *v = values[4],
           *e = values[5], *x = values[6];
    if (!BN_bin2bn(signature, 32, r) || !BN_bin2bn(signature + 32, 32, s)) return -1;
    if (BN_is_zero(r) || BN_is_zero(s) || BN_cmp(r, order) >= 0 || BN_cmp(s, order) >= 0) return 0;
    if (!BN_bin2bn(digest, 32, e) || !BN_mod_inverse(w, s, order, scratch) ||
        !BN_mod_mul(u, e, w, order, scratch) || !BN_mod_mul(v, r, w, order, scratch) ||
        !EC_POINT_set_to_infinity(group, points[3]))
        return -1;
    for (int bit = 255; bit >= 0; --bit) {
        const int kIndex = BN_is_bit_set(u, bit) | (BN_is_bit_set(v, bit) << 1);
        if (!EC_POINT_dbl(group, points[3], points[3], scratch) ||
            (kIndex && !EC_POINT_add(group, points[3], points[3], points[kIndex - 1], scratch)))
            return -1;
    }
    if (EC_POINT_is_at_infinity(group, points[3])) return 0;
    if (!EC_POINT_get_affine_coordinates(group, points[3], x, 0, scratch) ||
        !BN_nnmod(x, x, order, scratch))
        return -1;
    return BN_cmp(x, r) == 0;
}

uint32_t rut_crypto_ec_workspace_init_internal(
    EVP_PKEY* source, EVP_PKEY** key, EC_POINT** points, BIGNUM** values, BN_CTX** scratch) {
    if (!source || *key || EVP_PKEY_id(source) != EVP_PKEY_EC || !EVP_PKEY_up_ref(source)) return 0;
    *key = source;
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(source);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    if (!group || EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1) goto fail;
    *scratch = BN_CTX_new();
    if (!*scratch) goto fail;
    /* Reserve bounded scratch before serving, including exceptional point and
       inversion paths. No request-dependent lazy initialization is permitted. */
    BN_CTX_start(*scratch);
    for (uint32_t i = 0; i < 64; ++i) {
        BIGNUM* value = BN_CTX_get(*scratch);
        if (!value || !BN_set_bit(value, 1024)) {
            BN_CTX_end(*scratch);
            goto fail;
        }
    }
    BN_CTX_end(*scratch);
    for (uint32_t i = 0; i < 7; ++i) {
        values[i] = BN_new();
        if (!values[i] || !BN_set_bit(values[i], 1024)) goto fail;
    }
    for (uint32_t i = 0; i < 4; ++i) {
        points[i] = EC_POINT_new(group);
        if (!points[i]) goto fail;
    }
    if (!EC_POINT_copy(points[0], EC_GROUP_get0_generator(group)) ||
        !EC_POINT_copy(points[1], EC_KEY_get0_public_key(ec)) ||
        !EC_POINT_add(group, points[2], points[0], points[1], *scratch))
        goto fail;
    /* The generic field implementation may reserve an extra carry limb when
       halving an odd sum for Y. Warm result storage with a fixed generator
       sequence, independently of Q (including Q=-G, where G+Q is infinity).
       Subsequent copies/doublings retain this point's allocated capacity. */
    if (!EC_POINT_copy(points[3], points[0])) goto fail;
    for (uint32_t i = 0; i < 16; ++i)
        if (!EC_POINT_dbl(group, points[3], points[3], *scratch) ||
            !EC_POINT_add(group, points[3], points[3], points[0], *scratch))
            goto fail;
    const uint8_t kDigest[32] = {1};
    uint8_t signature[64] = {0};
    signature[31] = 1;
    signature[63] = 1;
    if (verify_digest(*key, points, values, *scratch, kDigest, signature) < 0) goto fail;
    return 1;
fail:
    rut_crypto_ec_workspace_reset_internal(key, points, values, scratch);
    return 0;
}

uint32_t rut_crypto_ec_verify_internal(EVP_PKEY* key,
                                       EC_POINT* const* points,
                                       BIGNUM* const* values,
                                       BN_CTX* scratch,
                                       const uint8_t* message,
                                       uint32_t message_len,
                                       const uint8_t* signature,
                                       uint32_t signature_len) {
    if (!key || !scratch || !signature || signature_len != 64 || (!message && message_len) ||
        message_len > 1024u * 1024u)
        return 0;
    uint8_t digest[32];
    uint32_t length = 0;
    if (!rut_crypto_digest_v1(
            RUT_CRYPTO_SHA256_V1, message, message_len, 0, 0, 0, digest, sizeof(digest), &length) ||
        length != sizeof(digest))
        return 0;
    return verify_digest(key, points, values, scratch, digest, signature) == 1;
}
