#pragma once

#include <openssl/ec.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
EVP_PKEY* rut_crypto_ec_load_der_internal(const uint8_t* der, uint32_t length);
EVP_PKEY* rut_crypto_ec_from_coordinates_internal(const uint8_t x[32], const uint8_t y[32]);
uint32_t rut_crypto_ec_workspace_init_internal(
    EVP_PKEY* source, EVP_PKEY** key, EC_POINT** points, BIGNUM** values, BN_CTX** scratch);
void rut_crypto_ec_workspace_reset_internal(EVP_PKEY** key,
                                            EC_POINT** points,
                                            BIGNUM** values,
                                            BN_CTX** scratch);
uint32_t rut_crypto_ec_verify_internal(EVP_PKEY* key,
                                       EC_POINT* const* points,
                                       BIGNUM* const* values,
                                       BN_CTX* scratch,
                                       const uint8_t* message,
                                       uint32_t message_len,
                                       const uint8_t* signature,
                                       uint32_t signature_len);
#ifdef __cplusplus
}
#endif
