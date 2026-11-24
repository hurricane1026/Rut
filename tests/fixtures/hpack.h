#pragma once

#include "rut/runtime/hpack.h"

namespace rut::test::hpack_fixture {

template <size_t Capacity, typename Encode>
bool append_field(u8 (&block)[Capacity], u32& offset, Str name, Str value, Encode encode) {
    // Literal fields can use at most three six-byte HPACK integer prefixes.
    // Huffman encoding is selected only when it reduces the string size.
    const u64 bound = static_cast<u64>(name.len) + value.len + 18u;
    if (offset > Capacity || bound > Capacity - offset) return false;
    const i64 size = encode(block + offset, name, value);
    u32 next;
    if (size < 0 || __builtin_add_overflow(offset, size, &next) || next > Capacity) return false;
    offset = next;
    return true;
}

}  // namespace rut::test::hpack_fixture
