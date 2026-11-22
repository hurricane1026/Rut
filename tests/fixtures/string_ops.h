#pragma once
#include "rut/common/types.h"
namespace rut::test::string_ops {
inline constexpr char kSource[] = R"rut(
func clean(_ s: str) -> str { s.trim() }
func shout(_ s: str) -> str { s | upper(_) }
route POST "/upper" {
    let pending = shout(req.body)
    guard let value = pending else { return 503 }
    return response(200, body: value)
}
route POST "/lower" {
    let pending = lower(req.body)
    guard let value = pending else { return 503 }
    return response(200, body: value)
}
route POST "/replace" {
    let pending = replace(req.body, req.header("X-Old").or("aa"), req.header("X-New").or("X"))
    guard let value = pending else { return 503 }
    return response(200, body: value)
}
route POST "/regex" {
    let pending = req.body.replace(re"/+", req.header("X-New").or("X"))
    guard let value = pending else { return 503 }
    return response(200, body: value)
}
route POST "/trim" {
    let value = clean(req.body)
    return response(200, body: value)
}
)rut";
struct Case {
    u32 route;
    Str input;
    Str output;
};
inline constexpr Case kCases[] = {
    {0, lit_str("aBz\0\xff"), lit_str("ABZ\0\xff")},
    {1, lit_str("AbZ\0\xff"), lit_str("abz\0\xff")},
    {2, lit_str("aaaaa"), lit_str("XXa")},
    {2, lit_str("b\0z"), lit_str("b\0z")},
    {3, lit_str("//a///b/"), lit_str("XaXbX")},
    {4, lit_str(" \t\r\n a\0\xff \v\f"), lit_str("a\0\xff")},
    {0, lit_str(""), lit_str("")},
    {1, lit_str(""), lit_str("")},
    {2, lit_str(""), lit_str("")},
    {3, lit_str(""), lit_str("")},
    {4, lit_str(" \r\n\t\v\f"), lit_str("")},
};
}  // namespace rut::test::string_ops
