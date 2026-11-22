#pragma once
#include "rut/common/types.h"

namespace rut::test::string_split {
inline constexpr char kSource[] = R"rut(
func fields(_ text: str, _ separator: str) -> Collected<str> { text.split(separator) }
route POST "/" {
    let pending = fields(req.body, req.header("X-Separator").or(","))
    guard let parts = pending else { return 503 }
    guard parts.count == parseInt(req.header("X-Count").or("-1")).or(-1) else { return 409 }
    guard parts.get(0).or("<absent>") == req.header("X-First").or("<absent>") &&
          parts.get(parts.count - 1).or("<absent>") == req.header("X-Last").or("<absent>") &&
          parts.get(-1) == nil && parts.get(parts.count) == nil else { return 422 }
    return 204
}
)rut";
struct Case {
    Str input;
    Str separator;
    u32 count;
    Str first;
    Str last;
    u32 status = 204;
};
inline constexpr Case kCases[] = {
    {lit_str(""), lit_str(","), 1, lit_str(""), lit_str("")},
    {lit_str("one"), lit_str(","), 1, lit_str("one"), lit_str("one")},
    {lit_str(","), lit_str(","), 2, lit_str(""), lit_str("")},
    {lit_str(",a,,b,"), lit_str(","), 5, lit_str(""), lit_str("")},
    {lit_str("a::b::c"), lit_str("::"), 3, lit_str("a"), lit_str("c")},
    {lit_str("aaaaa"), lit_str("aa"), 3, lit_str(""), lit_str("a")},
    {lit_str("abababa"), lit_str("aba"), 3, lit_str(""), lit_str("")},
    {lit_str("a,b\0z,c"), lit_str(","), 3, lit_str("a"), lit_str("c")},
    {lit_str("a%2Cb+c"), lit_str(","), 1, lit_str("a%2Cb+c"), lit_str("a%2Cb+c")},
    {lit_str("a"), lit_str("long delimiter"), 1, lit_str("a"), lit_str("a")},
    {lit_str("a"), lit_str(""), 0, lit_str(""), lit_str(""), 503},
};
}  // namespace rut::test::string_split
