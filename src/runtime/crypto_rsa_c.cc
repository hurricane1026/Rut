#include "core/placement_new.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/public_key.h"

namespace {
bool suitable(void* storage, uint32_t capacity, uint32_t size, uint32_t alignment) {
    return storage && capacity >= size && reinterpret_cast<uintptr_t>(storage) % alignment == 0;
}
}  // namespace

extern "C" uint32_t rut_crypto_rsa_key_size_v1(void) {
    return sizeof(rut::RsaPublicKey);
}
extern "C" uint32_t rut_crypto_rsa_key_align_v1(void) {
    return alignof(rut::RsaPublicKey);
}

extern "C" rut_crypto_rsa_key_v1* rut_crypto_rsa_key_init_v1(void* storage, uint32_t capacity) {
    if (!suitable(storage, capacity, sizeof(rut::RsaPublicKey), alignof(rut::RsaPublicKey)))
        return nullptr;
    return reinterpret_cast<rut_crypto_rsa_key_v1*>(new (storage) rut::RsaPublicKey());
}

extern "C" void rut_crypto_rsa_key_destroy_v1(rut_crypto_rsa_key_v1* key) {
    if (key) reinterpret_cast<rut::RsaPublicKey*>(key)->~RsaPublicKey();
}

extern "C" uint32_t rut_crypto_rsa_key_load_der_v1(rut_crypto_rsa_key_v1* key,
                                                   const uint8_t* der,
                                                   uint32_t der_len) {
    if (!key || (!der && der_len)) return 0;
    return reinterpret_cast<rut::RsaPublicKey*>(key)->load(
               {reinterpret_cast<const char*>(der), der_len})
               ? 1u
               : 0u;
}

extern "C" uint32_t rut_crypto_rsa_key_load_jwk_v1(rut_crypto_rsa_key_v1* key,
                                                   const uint8_t* jwk,
                                                   uint32_t len) {
    if (!key || (!jwk && len)) return 0;
    return reinterpret_cast<rut::RsaPublicKey*>(key)->load_rs256_jwk(
               {reinterpret_cast<const char*>(jwk), len})
               ? 1u
               : 0u;
}

extern "C" uint32_t rut_crypto_rsa_key_load_jwks_v1(rut_crypto_rsa_key_v1* key,
                                                    const uint8_t* jwks,
                                                    uint32_t len,
                                                    const uint8_t* kid,
                                                    uint32_t kid_len) {
    if (!key || (!jwks && len) || (!kid && kid_len)) return 0;
    return reinterpret_cast<rut::RsaPublicKey*>(key)->load_rs256_jwks(
               {reinterpret_cast<const char*>(jwks), len},
               {reinterpret_cast<const char*>(kid), kid_len})
               ? 1u
               : 0u;
}

extern "C" uint32_t rut_crypto_rsa_verifier_size_v1(void) {
    return sizeof(rut::RsaSha256Verifier);
}
extern "C" uint32_t rut_crypto_rsa_verifier_align_v1(void) {
    return alignof(rut::RsaSha256Verifier);
}

extern "C" rut_crypto_rsa_verifier_v1* rut_crypto_rsa_verifier_init_v1(
    void* storage, uint32_t capacity, const rut_crypto_rsa_key_v1* key) {
    if (!key ||
        !suitable(
            storage, capacity, sizeof(rut::RsaSha256Verifier), alignof(rut::RsaSha256Verifier)))
        return nullptr;
    auto* verifier = new (storage) rut::RsaSha256Verifier();
    if (!verifier->init(*reinterpret_cast<const rut::RsaPublicKey*>(key))) {
        verifier->~RsaSha256Verifier();
        return nullptr;
    }
    return reinterpret_cast<rut_crypto_rsa_verifier_v1*>(verifier);
}

extern "C" void rut_crypto_rsa_verifier_destroy_v1(rut_crypto_rsa_verifier_v1* verifier) {
    if (verifier) reinterpret_cast<rut::RsaSha256Verifier*>(verifier)->~RsaSha256Verifier();
}

extern "C" uint32_t rut_crypto_rsa_verify_sha256_v1(rut_crypto_rsa_verifier_v1* verifier,
                                                    const uint8_t* message,
                                                    uint32_t message_len,
                                                    const uint8_t* signature,
                                                    uint32_t signature_len) {
    if (!verifier || (!message && message_len) || (!signature && signature_len)) return 0;
    return reinterpret_cast<rut::RsaSha256Verifier*>(verifier)->verify(
               {reinterpret_cast<const char*>(message), message_len},
               {reinterpret_cast<const char*>(signature), signature_len})
               ? 1u
               : 0u;
}
