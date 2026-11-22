#pragma once
#include "rut/common/types.h"

namespace rut::test::string_find {
inline constexpr char kSource[] = R"rut(
func locate(_ text: str, _ delimiter: str, _ start: i32) -> i32 => text.find(delimiter, start)
route POST "/" {
    guard let width = parseInt(req.header("X-Width").or("")) else { return 400 }
    guard let start = parseInt(req.header("X-Start").or("")) else { return 400 }
    guard let expected = parseInt(req.header("X-Expected").or("")) else { return 400 }
    let body = req.body
    guard let delimiter = body.slice(0, width) else { return 400 }
    guard let text = body.slice(width, body.len) else { return 400 }
    let position = locate(text, delimiter, start)
    guard position.or(-1) == expected else { return 422 }
    guard let index = position else { return 404 }
    guard let tail = text.slice(index, text.len) else { return 500 }
    return response(200, body: tail)
}
)rut";
struct Case {
    Str input;
    Str delimiter;
    i32 start;
    i32 expected;
};
inline constexpr Case kCases[] = {
    {lit_str(""), lit_str(""), 0, 0},
    {lit_str(""), lit_str("x"), 0, -1},
    {lit_str("abc"), lit_str(""), 0, 0},
    {lit_str("abc"), lit_str(""), 3, 3},
    {lit_str("abc"), lit_str("c"), 3, -1},
    {lit_str("abc"), lit_str("abc"), 0, 0},
    {lit_str("abc"), lit_str("b"), 0, 1},
    {lit_str("abc"), lit_str("bc"), 2, -1},
    {lit_str("abc"), lit_str("B"), 0, -1},
    {lit_str("abc"), lit_str("abcd"), 0, -1},
    {lit_str("aaaaa"), lit_str("aaa"), 1, 1},
    {lit_str("ab:ab:"), lit_str(":"), 3, 5},
    {lit_str("a\0\xffz"), lit_str("\0\xff"), 0, 1},
    {lit_str("\xc3\xa9x"), lit_str("\xa9"), 0, 1},
    {lit_str("a%2Cb+c"), lit_str(","), 0, -1},
    {lit_str("a%2Cb+c"), lit_str("+"), 0, 5},
    {lit_str("abc"), lit_str(""), -1, -1},
    {lit_str("abc"), lit_str(""), 4, -1},
    {lit_str("abc"), lit_str(""), -2147483647 - 1, -1},
    {lit_str("abc"), lit_str(""), 2147483647, -1},
};
}  // namespace rut::test::string_find
