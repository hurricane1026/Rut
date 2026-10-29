#include "rut/runtime/crypto_c.h"

#include <stdint.h>

int main(void) {
    static const uint8_t input[] = {'a', 'b', 'c'};
    static const uint8_t expected[] =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    uint8_t output[64];
    uint32_t length = 0;
    if (!rut_crypto_digest_hex_v1(
            RUT_CRYPTO_SHA256_V1, input, sizeof(input), 0, 0, 0, output, sizeof(output), &length) ||
        length != sizeof(output))
        return 1;
    if (!rut_crypto_equal_v1(output, expected, sizeof(output))) return 2;
    rut_crypto_clear_v1(output, sizeof(output));
    for (uint32_t i = 0; i < sizeof(output); ++i)
        if (output[i]) return 3;
    return 0;
}
