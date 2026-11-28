// Exercised with Clang -verify by the integer safety audit.
#include "rut/common/byte_span.h"

using namespace rut;

bool checked_absolute(const void* buffer, u32 len, uintptr_t* end) {
    const auto address = reinterpret_cast<uintptr_t>(buffer);
    const auto alias = address;
    // expected-warning@+1 {{use bounded offsets for address arithmetic}}
    return !add_overflow(alias, len, end);
}

bool unchecked_absolute(const void* buffer, u32 len, uintptr_t* end) {
    // expected-warning@+1 {{use bounded offsets for address arithmetic}}
    return !__builtin_add_overflow(len, reinterpret_cast<uintptr_t>(buffer), end);
}

uintptr_t wrapped_absolute(const void* buffer, uintptr_t len) {
    // expected-warning@+1 {{use bounded offsets for address arithmetic}}
    return wrapping_add((uintptr_t)buffer, len);
}

bool checked_offset(const void* buffer, const void* data, u32 len, uintptr_t* end) {
    const auto begin = reinterpret_cast<uintptr_t>(buffer);
    const auto address = reinterpret_cast<uintptr_t>(data);
    return !add_overflow(address - begin, len, end);
}

bool bounded_span(const void* buffer, u32 used, const void* data, u32 len) {
    u32 offset;
    return byte_span_offset_within(buffer, used, data, len, &offset);
}

bool raw_span(const void* data, u32 len, uintptr_t* end) {
    return raw_byte_span_address_end(data, len, end);
}
