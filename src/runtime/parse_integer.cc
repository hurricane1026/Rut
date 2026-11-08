#include "rut/runtime/parse_integer_simd.h"

namespace rut {

bool parse_integer32(Str text, i64& output) {
    return parse_integer<false, integer_detail::SelectedDigits>(text, output);
}
bool parse_integer64(Str text, i64& output) {
    return parse_integer<true, integer_detail::SelectedDigits>(text, output);
}
const char* parse_integer_arch() {
#if defined(RUT_INTEGER_ARCH_SSE2)
    return "sse2";
#elif defined(RUT_INTEGER_ARCH_AVX2)
    return "avx2";
#elif defined(RUT_INTEGER_ARCH_AVX512)
    return "avx512bw";
#elif defined(RUT_INTEGER_ARCH_NEON)
    return "neon";
#else
    return "portable";
#endif
}

}  // namespace rut
