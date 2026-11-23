#pragma once
#include "rut/common/types.h"

namespace rut::test::integer_literals {
inline constexpr char kSource[] = R"rut(
func classify(_ value: i32) -> i32 {
  match value {
    0b1010 => 0o310
    -0x1 => 0x190
    _ => 4_22_
  }
}
route GET "/" {
    guard let value = parseInt(req.header("X-Value").or("")) else { return 0x190 }
    let packed = bitwise.or(bitwise.shiftLeft(i64(value), 0x20), 0xffff_ffff)
    guard bitwise.shiftRight(packed, 0o40) == i64(value) else { return 500 }
    let wrapped = 0x7fff_ffff_ffff_ffff + i64(value)
    guard wrapped == -0x8000_0000_0000_0000 + i64(value) - 1 else { return 500 }
    match classify(value) {
        0o310 => return 0xC8
        0x190 => return 0b110010000
        _ => return 4_22_
    }
}
)rut";
struct Case {
    const char* value;
    u32 status;
};
inline constexpr Case kCases[] = {{"10", 200},
                                  {"9", 422},
                                  {"-1", 400},
                                  {"2147483647", 422},
                                  {"-2147483648", 422},
                                  {"0xA", 400},
                                  {"1_0", 400}};
}  // namespace rut::test::integer_literals
