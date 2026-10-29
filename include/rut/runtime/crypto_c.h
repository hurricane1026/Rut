#ifndef RUT_RUNTIME_CRYPTO_C_H
#define RUT_RUNTIME_CRYPTO_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version 1 algorithm identifiers; numeric values are part of the C ABI. */
/* NOLINTNEXTLINE(performance-enum-size): C-compatible ABI. */
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

/* Lowercase hexadecimal digest, with no terminating NUL. Input, key, failure
 * and aliasing rules match rut_crypto_digest_v1. */
uint32_t rut_crypto_digest_hex_v1(uint32_t algorithm,
                                  const uint8_t* data,
                                  uint32_t data_len,
                                  const uint8_t* key,
                                  uint32_t key_len,
                                  uint32_t keyed,
                                  uint8_t* output,
                                  uint32_t capacity,
                                  uint32_t* output_len);

typedef struct rut_crypto_span_v1 {
    const uint8_t* data;
    uint32_t len;
} rut_crypto_span_v1;

/* Hash up to 16 borrowed spans as one byte sequence without concatenation.
 * The aggregate input is bounded to 1 MiB + 4096 bytes; key and output rules
 * are identical to rut_crypto_digest_v1. No pointer is retained. */
uint32_t rut_crypto_digest_parts_v1(uint32_t algorithm,
                                    const rut_crypto_span_v1* parts,
                                    uint32_t count,
                                    const uint8_t* key,
                                    uint32_t key_len,
                                    uint32_t keyed,
                                    uint8_t* output,
                                    uint32_t capacity,
                                    uint32_t* output_len);

/* HMAC with a legacy-compatible key length up to INT32_MAX bytes. Input data
 * remains limited to 1 MiB. The caller owns and must bound the key storage;
 * processing time grows with key length. Buffer and failure rules match
 * rut_crypto_digest_v1. */
uint32_t rut_crypto_hmac_long_key_v1(uint32_t algorithm,
                                     const uint8_t* data,
                                     uint32_t data_len,
                                     const uint8_t* key,
                                     uint32_t key_len,
                                     uint8_t* output,
                                     uint32_t capacity,
                                     uint32_t* output_len);

/* Compare equally sized byte strings without content-dependent timing. A null
 * pointer is valid only for zero length. Length itself is public. */
uint32_t rut_crypto_equal_v1(const uint8_t* a, const uint8_t* b, uint32_t length);
/* Compare public lengths and at most 16 KiB of secret content. Empty inputs
 * compare equal, including null/zero spans; other null pointers fail closed. */
uint32_t rut_crypto_equal_bounded_v1(const uint8_t* a,
                                     uint32_t a_len,
                                     const uint8_t* b,
                                     uint32_t b_len);
/* Verify a canonical lowercase hexadecimal HMAC-SHA256 signature with an
 * optional exact public prefix (at most 64 bytes). The message is bounded to
 * 1 MiB and the nonempty key to 4096 bytes. Inputs are borrowed synchronously;
 * null is allowed only for a zero-length message or prefix. Returns 0 for an
 * invalid input or mismatch and retains no pointers. */
uint32_t rut_crypto_hmac_sha256_matches_v1(const uint8_t* message,
                                           uint32_t message_len,
                                           const uint8_t* key,
                                           uint32_t key_len,
                                           const uint8_t* signature,
                                           uint32_t signature_len,
                                           const uint8_t* prefix,
                                           uint32_t prefix_len);
/* Wipe caller-owned bytes; null is valid only for zero length. */
void rut_crypto_clear_v1(void* data, uint32_t length);
/* Padded Base64. Output includes a trailing NUL, excluded from output_len.
 * Input is limited to 1 MiB; buffers and output_len must not overlap.
 * On failure output_len is zero and output bytes are unchanged. */
uint32_t rut_crypto_base64_encode_v1(const uint8_t* input,
                                     uint32_t length,
                                     uint8_t* output,
                                     uint32_t capacity,
                                     uint32_t* output_len);

/* RSA objects are constructed in caller-owned, correctly aligned storage.
 * Query size and alignment before reserving storage. Each successful init must
 * be paired with destroy before reusing storage. Do not copy initialized
 * objects; do not call init twice on live storage. A verifier is shard-owned,
 * retains a key reference and may outlive its key owner; it must not be used
 * concurrently. Key and verifier storage must not overlap. OpenSSL may allocate while
 * loading/initializing, never rely on these calls being allocation-free. Verify borrows inputs
 * synchronously. */
typedef struct rut_crypto_rsa_key_v1 rut_crypto_rsa_key_v1;
typedef struct rut_crypto_rsa_verifier_v1 rut_crypto_rsa_verifier_v1;
uint32_t rut_crypto_rsa_key_size_v1(void);
uint32_t rut_crypto_rsa_key_align_v1(void);
rut_crypto_rsa_key_v1* rut_crypto_rsa_key_init_v1(void* storage, uint32_t capacity);
void rut_crypto_rsa_key_destroy_v1(rut_crypto_rsa_key_v1* key);
uint32_t rut_crypto_rsa_key_load_der_v1(rut_crypto_rsa_key_v1* key,
                                        const uint8_t* der,
                                        uint32_t der_len);
uint32_t rut_crypto_rsa_key_load_jwk_v1(rut_crypto_rsa_key_v1* key,
                                        const uint8_t* jwk,
                                        uint32_t jwk_len);
uint32_t rut_crypto_rsa_key_load_jwks_v1(rut_crypto_rsa_key_v1* key,
                                         const uint8_t* jwks,
                                         uint32_t jwks_len,
                                         const uint8_t* kid,
                                         uint32_t kid_len);
uint32_t rut_crypto_rsa_verifier_size_v1(void);
uint32_t rut_crypto_rsa_verifier_align_v1(void);
rut_crypto_rsa_verifier_v1* rut_crypto_rsa_verifier_init_v1(void* storage,
                                                            uint32_t capacity,
                                                            const rut_crypto_rsa_key_v1* key);
void rut_crypto_rsa_verifier_destroy_v1(rut_crypto_rsa_verifier_v1* verifier);
uint32_t rut_crypto_rsa_verify_sha256_v1(rut_crypto_rsa_verifier_v1* verifier,
                                         const uint8_t* message,
                                         uint32_t message_len,
                                         const uint8_t* signature,
                                         uint32_t signature_len);

/* Configuration key sets own copied IDs and keys. Verifier sets retain their
 * own key references and copied IDs and are shard-local. Their caller-owned
 * storage follows the same size, alignment and lifetime rules as RSA objects
 * above; no initialized storage may overlap any other live object. A selected
 * verifier is borrowed, must not be destroyed directly and expires when its
 * verifier set is destroyed. Input spans are borrowed only during each call. */
typedef struct rut_crypto_rsa_key_set_v1 rut_crypto_rsa_key_set_v1;
typedef struct rut_crypto_rsa_verifier_set_v1 rut_crypto_rsa_verifier_set_v1;
uint32_t rut_crypto_rsa_key_set_size_v1(void);
uint32_t rut_crypto_rsa_key_set_align_v1(void);
rut_crypto_rsa_key_set_v1* rut_crypto_rsa_key_set_init_v1(void* storage, uint32_t capacity);
void rut_crypto_rsa_key_set_destroy_v1(rut_crypto_rsa_key_set_v1* keys);
uint32_t rut_crypto_rsa_key_set_load_v1(rut_crypto_rsa_key_set_v1* keys,
                                        const uint8_t* jwks,
                                        uint32_t jwks_len,
                                        const rut_crypto_span_v1* approved_ids,
                                        uint32_t count);
uint32_t rut_crypto_rsa_verifier_set_size_v1(void);
uint32_t rut_crypto_rsa_verifier_set_align_v1(void);
rut_crypto_rsa_verifier_set_v1* rut_crypto_rsa_verifier_set_init_v1(
    void* storage, uint32_t capacity, const rut_crypto_rsa_key_set_v1* keys);
void rut_crypto_rsa_verifier_set_destroy_v1(rut_crypto_rsa_verifier_set_v1* verifiers);
rut_crypto_rsa_verifier_v1* rut_crypto_rsa_verifier_set_select_v1(
    rut_crypto_rsa_verifier_set_v1* verifiers, const uint8_t* kid, uint32_t kid_len);
/* On success, canonical_id borrows the stored trusted ID until set destruction.
 * Both output parameters are required and must not alias inputs or each other.
 * On failure they are set to null and zero. This selection is not proof that
 * a signature is valid. */
rut_crypto_rsa_verifier_v1* rut_crypto_rsa_verifier_set_select_id_v1(
    rut_crypto_rsa_verifier_set_v1* verifiers,
    const uint8_t* kid,
    uint32_t kid_len,
    const uint8_t** canonical_id,
    uint32_t* canonical_id_len);

#ifdef __cplusplus
}
#endif
#endif
