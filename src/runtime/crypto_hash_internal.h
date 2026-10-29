#pragma once

#include "rut/runtime/crypto_c.h"

#ifdef __cplusplus
extern "C" {
#endif
/* This core is private; public entry points enforce their documented bounds. */
uint32_t rut_crypto_digest_unbounded_internal(uint32_t algorithm,
                                              const rut_crypto_span_v1* parts,
                                              uint32_t count,
                                              const uint8_t* key,
                                              uint32_t key_len,
                                              uint32_t keyed,
                                              uint8_t* output,
                                              uint32_t capacity,
                                              uint32_t* output_len);
#ifdef __cplusplus
}
#endif
