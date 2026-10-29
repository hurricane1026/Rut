#ifndef RUT_RUNTIME_CRYPTO_C_H
#define RUT_RUNTIME_CRYPTO_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version 1 algorithm identifiers; numeric values are part of the C ABI. */
enum rut_crypto_digest_algorithm_v1 {
    RUT_CRYPTO_MD5_V1 = 0,
    RUT_CRYPTO_SHA1_V1 = 1,
    RUT_CRYPTO_SHA224_V1 = 2,
    RUT_CRYPTO_SHA256_V1 = 3,
    RUT_CRYPTO_SHA384_V1 = 4,
    RUT_CRYPTO_SHA512_V1 = 5
};

/* Borrow input bytes for this synchronous call and write the raw digest to
 * caller-owned output. No pointer is retained. A null input is allowed only
 * for zero length. keyed must be 0 or 1; empty HMAC keys are valid here and
 * credential policy must reject them separately. Inputs are bounded to 1 MiB,
 * keys to 4096 bytes. output_len is required and is set to zero on failure.
 * Output and output_len must not overlap inputs or each other. Returns 1 on
 * success and 0 on failure; failed calls do not write output bytes. */
uint32_t rut_crypto_digest_v1(uint32_t algorithm,
                              const uint8_t* data,
                              uint32_t data_len,
                              const uint8_t* key,
                              uint32_t key_len,
                              uint32_t keyed,
                              uint8_t* output,
                              uint32_t capacity,
                              uint32_t* output_len);

#ifdef __cplusplus
}
#endif
#endif
