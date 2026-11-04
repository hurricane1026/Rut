#include "rut/runtime/ws_extensions.h"
#include "test.h"
#include <cstring>
#include <string>

using namespace rut;

namespace {
Header extension(Str value) {
    Header result{};
    result.name = lit_str("Sec-WebSocket-Extensions");
    result.value = value;
    return result;
}
}  // namespace

TEST(ws_extensions, offer_selection_retains_scalar_facts_and_honors_window_hints) {
    Header headers[] = {extension(lit_str("x-unknown; token=ok")),
                        extension(lit_str("permessage-deflate; server_max_window_bits=8; "
                                          "client_max_window_bits=\"1\\5\""))};
    WsDeflateAgreement result{};
    REQUIRE(ws_select_deflate_offer(headers, 2, &result));
    CHECK(result.enabled);
    CHECK(result.server_no_context_takeover);
    CHECK_FALSE(result.client_no_context_takeover);
    CHECK(result.server_window_present);
    CHECK(result.client_window_present);
    CHECK_EQ(result.server_window, 8u);
    CHECK_EQ(result.client_window, 15u);
    headers[0] =
        extension(lit_str("permessage-deflate; client_no_context_takeover; "
                          "client_max_window_bits"));
    REQUIRE(ws_select_deflate_offer(headers, 2, &result));
    CHECK(result.client_no_context_takeover);
    CHECK_FALSE(result.server_window_present);
    CHECK_EQ(result.client_window, 15u);
}

TEST(ws_extensions, unsupported_offers_can_fall_back_but_broken_grammar_cannot) {
    const char* unsupported[] = {
        "permessage-deflate; unknown=1",
        "permessage-deflate; server_max_window_bits",
        "permessage-deflate; server_max_window_bits=7",
        "permessage-deflate; client_max_window_bits=08",
        "permessage-deflate; server_no_context_takeover=1",
        "permessage-deflate; client_max_window_bits=12; client_max_window_bits=12",
    };
    for (const char* text : unsupported) {
        Header header = extension({text, static_cast<u32>(strlen(text))});
        WsDeflateAgreement result{};
        REQUIRE(ws_select_deflate_offer(&header, 1, &result));
        CHECK_FALSE(result.enabled);
        const std::string fallback = std::string(text) + ", permessage-deflate";
        header.value = {fallback.data(), static_cast<u32>(fallback.size())};
        REQUIRE(ws_select_deflate_offer(&header, 1, &result));
        CHECK(result.enabled);
    }
    const char* malformed[] = {",permessage-deflate",
                               "permessage-deflate,",
                               "permessage-deflate;",
                               "permessage-deflate; x=",
                               "permessage-deflate; x=\"\"",
                               "permessage-deflate; x=\"two words\"",
                               "permessage-deflate; x=\"15",
                               "permessage-deflate garbage"};
    for (const char* text : malformed) {
        Header headers[] = {extension(lit_str("permessage-deflate")),
                            extension({text, static_cast<u32>(strlen(text))})};
        WsDeflateAgreement result{};
        CHECK_FALSE(ws_select_deflate_offer(headers, 2, &result));
        CHECK_FALSE(result.enabled);
    }
}

TEST(ws_extensions, response_validation_uses_the_actual_agreement_not_the_client_hints) {
    Header header = extension(lit_str("permessage-deflate"));
    WsDeflateAgreement result{};
    REQUIRE(ws_accept_deflate_response(&header, 1, &result));
    CHECK(result.enabled);
    CHECK_FALSE(result.server_no_context_takeover);
    CHECK_FALSE(result.client_no_context_takeover);
    CHECK_EQ(result.server_window, 15u);
    CHECK_EQ(result.client_window, 15u);
    header.value = lit_str(
        "permessage-deflate; server_max_window_bits=8; "
        "client_max_window_bits=9; server_no_context_takeover");
    REQUIRE(ws_accept_deflate_response(&header, 1, &result));
    CHECK_EQ(result.server_window, 8u);
    CHECK_EQ(result.client_window, 9u);
    CHECK(result.server_no_context_takeover);
    const char* invalid[] = {
        "unknown",
        "permessage-deflate, permessage-deflate",
        "permessage-deflate; client_max_window_bits",
        "permessage-deflate; server_max_window_bits=16",
        "permessage-deflate; client_no_context_takeover=true",
        "permessage-deflate; unknown=1",
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover"};
    for (const char* text : invalid) {
        header.value = {text, static_cast<u32>(strlen(text))};
        CHECK_FALSE(ws_accept_deflate_response(&header, 1, &result));
        CHECK_FALSE(result.enabled);
    }
    Header duplicate[] = {extension(lit_str("permessage-deflate")),
                          extension(lit_str("permessage-deflate"))};
    CHECK_FALSE(ws_accept_deflate_response(duplicate, 2, &result));
    CHECK(ws_accept_deflate_response(nullptr, 0, &result));
    CHECK_FALSE(result.enabled);
}

TEST(ws_extensions, canonical_values_round_trip_every_window_pair_without_overwriting_bounds) {
    for (u8 server = 8; server <= 15; ++server) {
        for (u8 client = 8; client <= 15; ++client) {
            WsDeflateAgreement selected{};
            selected.enabled = true;
            selected.server_no_context_takeover = true;
            selected.client_no_context_takeover = true;
            selected.server_window_present = true;
            selected.client_window_present = true;
            selected.server_window = server;
            selected.client_window = client;
            char value[192]{};
            const u32 length = ws_format_deflate_agreement(selected, value, sizeof(value));
            REQUIRE(length != 0);
            Header header = extension({value, length});
            WsDeflateAgreement parsed{};
            REQUIRE(ws_accept_deflate_response(&header, 1, &parsed));
            CHECK_EQ(parsed.server_window, server);
            CHECK_EQ(parsed.client_window, client);
            CHECK(parsed.server_no_context_takeover);
            CHECK(parsed.client_no_context_takeover);
            char short_value[192];
            memset(short_value, 0x5a, sizeof(short_value));
            CHECK_EQ(ws_format_deflate_agreement(selected, short_value, length - 1), 0u);
            CHECK_EQ(short_value[length - 1], 0x5a);
            CHECK_EQ(ws_format_deflate_agreement(selected, short_value, length), length);
            CHECK_EQ(memcmp(value, short_value, length), 0);
        }
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
