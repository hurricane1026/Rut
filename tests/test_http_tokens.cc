#include "rut/runtime/http_tokens.h"
#include "test.h"

using namespace rut;

TEST(http_tokens, whole_tokens_case_and_ows) {
    CHECK(http_token_list_allows(lit_str("GET, POST"), lit_str("POST"), true));
    CHECK(!http_token_list_allows(lit_str("GET, POST"), lit_str("post"), true));
    CHECK(http_token_list_allows(
        lit_str("Authorization, X-Trace"), lit_str("x-trace, authorization"), false));
    CHECK(http_token_list_allows(
        lit_str("\tX-Trace \t, Authorization\t"), lit_str(" x-trace\t"), false));
    CHECK(!http_token_list_allows(lit_str("X-Trace-Extra"), lit_str("X-Trace"), false));
    CHECK(!http_token_list_allows(lit_str("*"), lit_str("Authorization"), false));
    CHECK(http_token_list_allows(lit_str("*"), lit_str("*"), false));
    CHECK(http_token_list_allows(lit_str("GET"), lit_str("GET, GET"), true));
    CHECK(http_token_list_allows(lit_str("GET, GET"), lit_str("GET"), true));
    CHECK(http_token_list_allows(
        lit_str("!#$%&'*+-.^_`|~012AZaz"), lit_str("!#$%&'*+-.^_`|~012AZaz"), true));
}
TEST(http_tokens, both_complete_lists_must_be_valid) {
    const char* invalid[] = {",GET",
                             "GET,",
                             "GET,,POST",
                             "GET, ,POST",
                             "G ET",
                             "GET POST",
                             "GET;POST",
                             "\"GET\"",
                             "GET\r\n",
                             "GET,\nPOST",
                             "GET,\vPOST",
                             "GET,\x7f",
                             "GET,\xc3\xa9"};
    for (auto text : invalid) {
        const Str value{text, static_cast<u32>(__builtin_strlen(text))};
        CHECK(!http_token_list_allows(value, lit_str("GET"), true));
        CHECK(!http_token_list_allows(lit_str("GET"), value, true));
        CHECK(!http_token_list_allows(value, lit_str(""), false));
    }
    const char binary[] = {'G', 'E', 'T', 0, ',', 'X'};
    CHECK(!http_token_list_allows({binary, sizeof(binary)}, lit_str("GET"), true));
    CHECK(!http_token_list_allows({nullptr, 1}, {}, false));
    CHECK(!http_token_list_allows({}, {nullptr, 1}, false));
    CHECK(http_token_list_allows({}, {}, false));
    CHECK(http_token_list_allows(lit_str(" \t"), {}, false));
    CHECK(!http_token_list_allows({}, lit_str("X"), false));
}
TEST(http_tokens, bounded_bytes_and_items) {
    char list[2 * kMaxHttpTokenListItems + 2];
    u32 list_len = 0;
    for (u32 i = 0; i < kMaxHttpTokenListItems; ++i) {
        if (i) list[list_len++] = ',';
        list[list_len++] = 'x';
    }
    const Str item_limit{list, list_len};
    CHECK(http_token_list_allows(item_limit, lit_str("x"), true));
    list[list_len++] = ',';
    list[list_len++] = 'x';
    const Str item_over_limit{list, list_len};
    CHECK(!http_token_list_allows(item_over_limit, lit_str("x"), true));
    CHECK(!http_token_list_allows(lit_str("x"), item_over_limit, true));
    char bytes[kMaxHttpTokenListBytes + 1];
    for (u32 i = 0; i < kMaxHttpTokenListBytes; ++i) bytes[i] = 'x';
    const Str limit{bytes, kMaxHttpTokenListBytes};
    CHECK(http_token_list_allows(limit, limit, false));
    bytes[kMaxHttpTokenListBytes] = 'x';
    CHECK(!http_token_list_allows({bytes, kMaxHttpTokenListBytes + 1}, {}, false));
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(http_tokens, origin_lists_validate_all_entries_and_credentials) {
    const Str list = lit_str("https://app.example.com,\thttps://admin.example.com:8443 ");
    CHECK(http_origin_list_allows(list, {}, true));
    CHECK(http_origin_list_allows(list, lit_str("https://app.example.com"), true));
    CHECK(http_origin_list_allows(list, lit_str("https://admin.example.com:8443"), true));
    CHECK(!http_origin_list_allows(list, lit_str("https://app.example.com.evil"), true));
    CHECK(!http_origin_list_allows(list, lit_str("https://APP.example.com"), true));
    CHECK(http_origin_list_allows(lit_str("*"), {}, false));
    CHECK(http_origin_list_allows(lit_str("*"), lit_str("https://any.example"), false));
    CHECK(!http_origin_list_allows(lit_str("*"), {}, true));
    CHECK(!http_origin_list_allows(lit_str("*"), lit_str("https://any.example"), true));
    CHECK(!http_origin_list_allows(lit_str("*"), lit_str("*"), false));
    CHECK(!http_origin_list_allows(lit_str("*"), lit_str("garbage"), false));
    CHECK(http_origin_list_allows(lit_str("null"), lit_str("null"), true));
    CHECK(!http_origin_list_allows(list, lit_str("null"), false));
    CHECK(http_origin_list_allows(lit_str("http://[::1]:0"), lit_str("http://[::1]:0"), true));
    CHECK(http_origin_list_allows(lit_str("https://[2001:db8::1]"), {}, true));
    const char* invalid[] = {
        "",
        " ",
        ",https://app.example",
        "https://app.example,",
        "https://app.example,,null",
        "https://app.example,garbage",
        "https://app.example,*",
        " * ",
        "*,null",
        "http://",
        "https://",
        "http://user@host",
        "http://host/",
        "http://host?q=x",
        "http://host#x",
        "http://host:",
        "http://host:65536",
        "http://host:-1",
        "http://host:80x",
        "http://.host",
        "http://host.",
        "http://a..b",
        "http://-host",
        "http://host-",
        "http://[::1",
        "http://[]",
        "http://[xyz]",
        "http://[::1]x",
        "http://[::1]:",
        "http://[::1%zone]",
        "HTTP://host",
        "https://host\r\n",
        "https://host;evil",
        "file://host",
        "https://host,\t",
        "https://host\xc3\xa9",
    };
    for (const char* value : invalid) {
        const Str text{value, static_cast<u32>(__builtin_strlen(value))};
        CHECK(!http_origin_list_allows(text, {}, false));
        CHECK(!http_origin_list_allows(text, lit_str("https://app.example"), true));
        if (text.len) CHECK(!http_origin_list_allows(lit_str("*"), text, false));
    }
    CHECK(!http_origin_list_allows({nullptr, 1}, {}, false));
    CHECK(!http_origin_list_allows(lit_str("*"), {nullptr, 1}, false));
    char list32[512];
    __builtin_memcpy(list32, "https://host", 12);
    u32 list32_len = 12;
    for (u32 i = 1; i < 32; ++i) {
        __builtin_memcpy(list32 + list32_len, ",https://host", 13);
        list32_len += 13;
    }
    CHECK(http_origin_list_allows({list32, list32_len}, {}, true));
    __builtin_memcpy(list32 + list32_len, ",https://host", 13);
    list32_len += 13;
    CHECK(!http_origin_list_allows({list32, list32_len}, {}, true));
    char long_text[4097];
    for (char& value : long_text) value = 'x';
    CHECK(!http_origin_list_allows({long_text, 4097}, {}, false));
    CHECK(!http_origin_list_allows(lit_str("*"), {long_text, 2049}, false));
    char too_long_ipv6[64];
    const u32 too_long_prefix_len = 9;
    __builtin_memcpy(too_long_ipv6, "https://[", too_long_prefix_len);
    for (u32 i = 0; i < 46; ++i) too_long_ipv6[too_long_prefix_len + i] = 'a';
    too_long_ipv6[too_long_prefix_len + 46] = ']';
    CHECK(!http_origin_list_allows({too_long_ipv6, too_long_prefix_len + 47}, {}, false));
    char padded[4096];
    __builtin_memcpy(padded, "https://host", 12);
    for (u32 i = 12; i < sizeof(padded); ++i) padded[i] = ' ';
    CHECK(http_origin_list_allows({padded, sizeof(padded)}, lit_str("https://host"), true));
    CHECK(http_origin_list_allows(lit_str("http://host:65535"), {}, false));
    const char binary[] = "https://host\0,https://other";
    CHECK(!http_origin_list_allows({binary, sizeof(binary) - 1}, {}, false));
    const char invalid_ipv6_nul[] = "https://[::1\0not-an-address]";
    const Str invalid_ipv6_nul_str{invalid_ipv6_nul, sizeof(invalid_ipv6_nul) - 1};
    CHECK(!http_origin_list_allows(invalid_ipv6_nul_str, {}, false));
    const char mixed_invalid_ipv6_nul[] = "https://host,https://[::1\0not-an-address]";
    CHECK(!http_origin_list_allows(
        {mixed_invalid_ipv6_nul, sizeof(mixed_invalid_ipv6_nul) - 1}, {}, false));
    CHECK(!http_origin_list_allows(lit_str("*"), invalid_ipv6_nul_str, false));
    CHECK(http_origin_list_allows(lit_str("https://[::1]"), lit_str("https://[::1]"), true));
}
