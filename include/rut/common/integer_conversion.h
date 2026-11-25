#pragma once

#include "rut/common/types.h"

namespace rut {

// The checked arithmetic builtin tests representability in the output type.
// Publish the converted value only if the entire input fits in i64.
[[nodiscard]] constexpr bool try_u64_to_i64(u64 value, i64& out) {
    i64 converted;
    if (__builtin_add_overflow(value, u64{0}, &converted)) return false;
    out = converted;
    return true;
}

}  // namespace rut
