#pragma once

namespace rut::test::query_all {
inline constexpr char kSource[] = R"rut(
func tags() -> Collected<str> { req.queryAll("ta\u{67}") }
route GET "/" {
    let pending = tags()
    guard let values = pending else { return 503 }
    guard values.count == parseInt(req.header("X-Count").or("-1")).or(-1) else { return 409 }
    guard values.get(0).or("<absent>") == req.header("X-First").or("<absent>") &&
          values.get(values.count - 1).or("<absent>") == req.header("X-Last").or("<absent>") &&
          values.get(-1) == nil && values.get(values.count) == nil else { return 422 }
    return 204
}
)rut";
struct Case {
    const char* target;
    unsigned count;
    const char* first;
    const char* last;
};
inline constexpr Case kCases[] = {
    {"/", 0, "<absent>", "<absent>"},
    {"/?", 0, "<absent>", "<absent>"},
    {"/?other=x", 0, "<absent>", "<absent>"},
    {"/?tag", 1, "", ""},
    {"/?tag=", 1, "", ""},
    {"/?tag=a&other=x&tag=b", 2, "a", "b"},
    {"/?tag=one&TAG=wrong&tag=two", 2, "one", "two"},
    {"/?t%61g=wrong&tag=a%26b+c", 1, "a%26b+c", "a%26b+c"},
    {"/?tagged=wrong&tag=right&x=tag=wrong", 1, "right", "right"},
    {"/?&&tag=&&tag=b&&", 2, "", "b"},
    {"/?tag=a=b&tag==", 2, "a=b", "="},
    {"/?tag=one#fragment&tag=wrong", 1, "one", "one"},
    {"/#fragment?tag=wrong", 0, "<absent>", "<absent>"},
    {"/?tag=a;tag=b", 1, "a;tag=b", "a;tag=b"},
    {"/?tag=repeat&tag=repeat", 2, "repeat", "repeat"},
};
}  // namespace rut::test::query_all
