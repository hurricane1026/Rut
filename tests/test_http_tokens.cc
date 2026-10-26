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
