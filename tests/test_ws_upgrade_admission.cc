#include "mock_backend.h"
#include "rut/common/types.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/io_event.h"
#include "test.h"
#include "test_helpers.h"

#include <string.h>

using namespace rut;

static bool parse_response(const char* raw, ParsedResponse* response) {
    HttpResponseParser parser{};
    parser.reset();
    return parser.parse(reinterpret_cast<const u8*>(raw),
                        static_cast<u32>(strlen(raw)),
                        response) == ParseStatus::Complete;
}

TEST(websocket_upgrade_admission, response_accepts_exact_websocket_and_connection_tokens) {
    ParsedResponse response{};
    REQUIRE(
        parse_response("HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: \tWebSocket \t\r\n"
                       "Connection: keep-alive, Upgrade\r\n"
                       "Connection: x-test\r\n\r\n",
                       &response));
    CHECK(ws_terminate_response_admitted(response));
    CHECK(ws_terminate_handshake_admitted(true, true, response));
    CHECK_FALSE(ws_terminate_handshake_admitted(false, true, response));
    CHECK_FALSE(ws_terminate_handshake_admitted(true, false, response));
}

TEST(websocket_upgrade_admission, response_rejects_mismatched_or_ambiguous_headers) {
    const char* invalid[] = {
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket, h2c\r\n"
        "Connection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: keep-alive, UpgradeX\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: keep-alive Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade/1\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade /1\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
    };
    for (const char* raw : invalid) {
        ParsedResponse response{};
        REQUIRE(parse_response(raw, &response));
        CHECK_FALSE(ws_terminate_response_admitted(response));
        CHECK_FALSE(ws_terminate_handshake_admitted(true, true, response));
    }
    ParsedResponse response{};
    REQUIRE(
        parse_response("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                       "Connection: Upgrade\r\n\r\n",
                       &response));
    response.headers_truncated = true;
    CHECK_FALSE(ws_terminate_response_admitted(response));
}

TEST(websocket_upgrade_admission, parser_truncated_header_block_is_not_admitted) {
    char raw[4096] = "HTTP/1.1 101 Switching Protocols\r\n";
    u32 length = static_cast<u32>(strlen(raw));
    for (u32 i = 0; i <= kMaxHeaders; i++) {
        static constexpr char kFiller[] = "X-Filler: a\r\n";
        memcpy(raw + length, kFiller, sizeof(kFiller) - 1);
        length += sizeof(kFiller) - 1;
    }
    static constexpr char kTail[] = "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    memcpy(raw + length, kTail, sizeof(kTail) - 1);
    length += sizeof(kTail) - 1;
    HttpResponseParser parser{};
    parser.reset();
    ParsedResponse response{};
    REQUIRE(parser.parse(reinterpret_cast<const u8*>(raw), length, &response) ==
            ParseStatus::Complete);
    CHECK(response.headers_truncated);
    CHECK_FALSE(ws_terminate_response_admitted(response));
}

TEST(websocket_upgrade_admission, request_requires_exact_comma_list_token) {
    const char* request =
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c, WebSocket\r\n\r\n";
    HttpParser parser{};
    ParsedRequest parsed{};
    parser.reset();
    REQUIRE(parser.parse(reinterpret_cast<const u8*>(request),
                         static_cast<u32>(strlen(request)),
                         &parsed) == ParseStatus::Complete);
    CHECK(parsed.upgrade);
    CHECK(parsed.has_upgrade_header);
    CHECK(parsed.upgrade_is_websocket);

    const char* invalid[] = {
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket/13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c websocket\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket /13\r\n\r\n",
    };
    for (const char* invalid_request : invalid) {
        parser.reset();
        parsed.reset();
        REQUIRE(parser.parse(reinterpret_cast<const u8*>(invalid_request),
                             static_cast<u32>(strlen(invalid_request)),
                             &parsed) == ParseStatus::Complete);
        CHECK(parsed.upgrade);
        CHECK(parsed.has_upgrade_header);
        CHECK_FALSE(parsed.upgrade_is_websocket);
    }
}

TEST(websocket_upgrade_admission, sent_callback_never_falls_back_for_unqualified_terminate) {
    SmallLoop loop;
    loop.setup();
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 123;
    conn->upstream_fd = 456;
    conn->is_ws_terminate_route = true;
    conn->req_wants_upgrade = true;
    conn->req_upgrade_is_websocket = true;
    conn->resp_upgrade_is_websocket = false;
    conn->resp_status = 101;
    loop.backend.clear_ops();

    on_ws_101_sent<SmallLoop>(&loop, *conn, IoEvent{conn->id, 64, 0, 0, IoEventType::Send, 0});

    CHECK_EQ(loop.backend.count_ops(MockOp::Send), 0u);
    CHECK_EQ(loop.free_top, SmallLoop::kMaxConns);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
