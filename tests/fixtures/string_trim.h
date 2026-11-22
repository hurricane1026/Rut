#pragma once

namespace rut::test::string_trim {
inline constexpr char kSource[] = R"rut(
func strip(_ text: str, _ prefix: str, _ suffix: str) -> str {
    text.trimPrefix(prefix).trimSuffix(suffix)
}
route GET "/" {
    let text = req.header("X-Text").or("")
    let prefix = req.header("X-Prefix").or("")
    let suffix = req.header("X-Suffix").or("")
    let actual = strip(text, prefix, suffix)
    guard actual == req.header("X-Expected").or("") else { return 400 }
    return 204
}
)rut";
struct Case {
    const char* text;
    const char* prefix;
    const char* suffix;
    const char* expected;
    unsigned status = 204;
};
inline constexpr Case kCases[] = {
    {"Bearer:token.end", "Bearer:", ".end", "token"},
    {"prepretoken.end.end", "pre", ".end", "pretoken.end"},
    {"token", "longer", "longer", "token"},
    {"token", "TOKEN", "TOKEN", "token"},
    {"token", "", "", "token"},
    {"token", "token", "", ""},
    {"token", "", "token", ""},
    {"token", "token", "token", ""},
    {"", "", "", ""},
    {"", "prefix", "suffix", ""},
    {"évalue界", "é", "界", "value"},
    {"a.b", "a.", ".b", "b"},
    {"token", "t", "n", "token", 400},
};
}  // namespace rut::test::string_trim
