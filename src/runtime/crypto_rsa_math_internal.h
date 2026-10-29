#pragma once

#include <openssl/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Internal shard-owned workspace; no pointers are retained by this call. */
uint32_t rut_crypto_rsa_workspace_init_internal(EVP_PKEY* source,
                                                EVP_PKEY** key,
                                                const BIGNUM** modulus,
                                                const BIGNUM** exponent,
                                                BIGNUM** input,
                                                BIGNUM** output,
                                                BN_CTX** scratch,
                                                BN_MONT_CTX** mont,
                                                uint32_t* bytes);
void rut_crypto_rsa_workspace_reset_internal(EVP_PKEY** key,
                                             const BIGNUM** modulus,
                                             const BIGNUM** exponent,
                                             BIGNUM** input,
                                             BIGNUM** output,
                                             BN_CTX** scratch,
                                             BN_MONT_CTX** mont,
                                             uint32_t* bytes);
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
                                        uint32_t signature_len);
#ifdef __cplusplus
}
#endif
