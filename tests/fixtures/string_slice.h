#pragma once
#include "rut/common/types.h"

namespace rut::test::string_slice {
inline constexpr char kSource[] = R"rut(
func field(_ text: str, _ start: i32, _ end: i32) -> str => text.slice(start, end)
route POST "/" {
    guard let start = parseInt(req.header("X-Start").or("")) else { return 400 }
    guard let end = parseInt(req.header("X-End").or("")) else { return 400 }
    guard let value = field(req.body, start, end) else { return 416 }
    return response(200, body: value)
}
)rut";
struct Case {
    Str input;
    i32 start;
    i32 end;
    Str expected;
    u32 status = 200;
};
inline constexpr Case kCases[] = {
    {lit_str(""), 0, 0, lit_str("")},
    {lit_str("abc"), 0, 0, lit_str("")},
    {lit_str("abc"), 3, 3, lit_str("")},
    {lit_str("abc"), 0, 3, lit_str("abc")},
    {lit_str("abc"), 1, 2, lit_str("b")},
    {lit_str("a\0\xffz"), 1, 3, lit_str("\0\xff")},
    {lit_str("\xc3\xa9x"), 1, 2, lit_str("\xa9")},
    {lit_str("a%2Cb+c"), 1, 7, lit_str("%2Cb+c")},
    {lit_str("abc"), -1, 1, {}, 416},
    {lit_str("abc"), 2, 1, {}, 416},
    {lit_str("abc"), 0, 4, {}, 416},
    {lit_str("abc"), 4, 4, {}, 416},
    {lit_str("abc"), 0, 2147483647, {}, 416},
    {lit_str("abc"), -2147483647 - 1, 1, {}, 416},
};
}  // namespace rut::test::string_slice
