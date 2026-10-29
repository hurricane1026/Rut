#include "crypto_rsa_math_internal.h"

#define constexpr const
#include "public_key_fixtures.h"
#include "rsa_verify_fixtures.h"
#undef constexpr

int main(void) {
    if (rut_crypto_rsa_load_der_internal(kRfcRsaSpki, sizeof(kRfcRsaSpki) - 1)) return 1;
    EVP_PKEY* source = rut_crypto_rsa_load_der_internal(kRfcRsaSpki, sizeof(kRfcRsaSpki));
    if (!source || rut_crypto_rsa_key_bits_internal(source) != 2048) return 2;
    EVP_PKEY* owner = 0;
    const BIGNUM* modulus = 0;
    const BIGNUM* exponent = 0;
    BIGNUM* input = 0;
    BIGNUM* output = 0;
    BN_CTX* scratch = 0;
    BN_MONT_CTX* mont = 0;
    uint32_t bytes = 0;
    if (!rut_crypto_rsa_workspace_init_internal(
            source, &owner, &modulus, &exponent, &input, &output, &scratch, &mont, &bytes))
        return 3;
    rut_crypto_rsa_key_free_internal(source);
    const uint8_t* message = (const uint8_t*)kMessage;
    if (!rut_crypto_rsa_verify_internal(modulus,
                                        exponent,
                                        input,
                                        output,
                                        scratch,
                                        mont,
                                        bytes,
                                        message,
                                        sizeof(kMessage) - 1,
                                        kSignature,
                                        sizeof(kSignature)))
        return 4;
    if (rut_crypto_rsa_verify_internal(modulus,
                                       exponent,
                                       input,
                                       output,
                                       scratch,
                                       mont,
                                       bytes,
                                       message,
                                       sizeof(kMessage) - 2,
                                       kSignature,
                                       sizeof(kSignature)))
        return 5;
    rut_crypto_rsa_workspace_reset_internal(
        &owner, &modulus, &exponent, &input, &output, &scratch, &mont, &bytes);
    if (owner || modulus || exponent || input || output || scratch || mont || bytes) return 6;
    return 0;
}
