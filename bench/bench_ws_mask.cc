// Benchmark-only payload preparation. No runtime dependency or allocation.
// Copy and XOR in one contiguous pass; preserve the exact RFC6455 mask bytes.
extern "C" void rut_bench_ws_mask(unsigned char* output,
                                  const unsigned char* input,
                                  unsigned long length,
                                  const unsigned char* key) {
    unsigned int word_key;
    __builtin_memcpy(&word_key, key, 4);
    const unsigned long long kMask = static_cast<unsigned long long>(word_key) |
                                     (static_cast<unsigned long long>(word_key) << 32);
    unsigned long offset = 0;
    for (; offset + 8 <= length; offset += 8) {
        unsigned long long word;
        __builtin_memcpy(&word, input + offset, 8);
        word ^= kMask;
        __builtin_memcpy(output + offset, &word, 8);
    }
    for (; offset < length; ++offset) output[offset] = input[offset] ^ key[offset & 3];
}
