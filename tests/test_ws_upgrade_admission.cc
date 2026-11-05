#include "mock_backend.h"
#include "rut/common/types.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/io_event.h"
#include "test.h"
#include "test_helpers.h"

#include <stdio.h>
#include <string.h>

using namespace rut;

static bool parse_response(const char* raw, ParsedResponse* response) {
    HttpResponseParser parser{};
    parser.reset();
    return parser.parse(reinterpret_cast<const u8*>(raw),
                        static_cast<u32>(strlen(raw)),
                        response) == ParseStatus::Complete;
}

TEST(websocket_upgrade_admission, parser_truncated_header_block_is_not_admitted) {
    char raw[4096] = "HTTP/1.1 101 Switching Protocols\r\n";
    u32 length = static_cast<u32>(strlen(raw));
    for (u32 i = 0; i <= kMaxHeaders; i++) {
        static constexpr char kFiller[] = "X-Filler: a\r\n";
        memcpy(raw + length, kFiller, sizeof(kFiller) - 1);
        length += sizeof(kFiller) - 1;
    }
    static constexpr char kTail[] =
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    memcpy(raw + length, kTail, sizeof(kTail) - 1);
    length += sizeof(kTail) - 1;
    HttpResponseParser parser{};
    parser.reset();
    ParsedResponse response{};
    REQUIRE(parser.parse(reinterpret_cast<const u8*>(raw), length, &response) ==
            ParseStatus::Complete);
    CHECK(response.headers_truncated);
    u8 storage[SlicePool::kSliceSize]{};
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    u32 offers_len = 0;
    REQUIRE(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                                 sizeof(kRequest) - 1,
                                 storage,
                                 sizeof(storage),
                                 &offers_len) == WsHandshakeRequestResult::Ready);
    CHECK_FALSE(ws_handshake_response_matches(response, storage, offers_len));
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

TEST(websocket_upgrade_admission, opening_request_uses_rfc_accept_and_canonical_offers) {
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: keep-alive, Upgrade\r\n"
        "Upgrade: h2c/1, WebSocket\r\nUpgrade: spdy/3\r\n"
        "Sec-WebSocket-Key: \tdGhlIHNhbXBsZSBub25jZQ== \t\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat, superchat\r\n\r\n";
    u8 storage[SlicePool::kSliceSize]{};
    u32 offers_len = 0;
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                               static_cast<u32>(sizeof(kRequest) - 1),
                               storage,
                               sizeof(storage),
                               &offers_len) == WsHandshakeRequestResult::Ready);
    CHECK_EQ(offers_len, 14u);
    CHECK(memcmp(storage, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", 28) == 0);
    CHECK(memcmp(storage + kWsHandshakeAcceptLength, "chat,superchat", 14) == 0);

    ParsedResponse response{};
    REQUIRE(
        parse_response("HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                       "Sec-WebSocket-Protocol: chat\r\n\r\n",
                       &response));
    CHECK(ws_handshake_response_matches(response, storage, offers_len));
    REQUIRE(
        parse_response("HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
                       "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                       &response));
    CHECK(ws_handshake_response_matches(response, storage, offers_len));
}

TEST(websocket_upgrade_admission, required_subprotocol_constrains_both_handshake_peers) {
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: old\r\nsEc-WeBsOcKeT-pRoToCoL:\tchat, other \t\r\n\r\n";
    const Str required = lit_str("chat");
    u8 storage[SlicePool::kSliceSize]{};
    u32 offers_len = 0;
    REQUIRE(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                                 sizeof(kRequest) - 1,
                                 storage,
                                 sizeof(storage),
                                 &offers_len,
                                 required) == WsHandshakeRequestResult::Ready);
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                               sizeof(kRequest) - 1,
                               nullptr,
                               0,
                               &offers_len,
                               lit_str("Chat")) == WsHandshakeRequestResult::BadRequest);
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                               sizeof(kRequest) - 1,
                               nullptr,
                               0,
                               &offers_len,
                               lit_str("missing")) == WsHandshakeRequestResult::BadRequest);
    REQUIRE(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                                 sizeof(kRequest) - 1,
                                 storage,
                                 sizeof(storage),
                                 &offers_len,
                                 required) == WsHandshakeRequestResult::Ready);
    const char* values[] = {"chat", "other", "Chat", "chat,other", ""};
    for (const char* value : values) {
        char response_bytes[512];
        snprintf(response_bytes,
                 sizeof(response_bytes),
                 "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                 "Sec-WebSocket-Protocol: %s\r\n\r\n",
                 value);
        ParsedResponse response{};
        REQUIRE(parse_response(response_bytes, &response));
        CHECK_EQ(ws_handshake_response_matches(response, storage, offers_len, required),
                 strcmp(value, "chat") == 0);
    }
    ParsedResponse omitted{};
    REQUIRE(
        parse_response("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                       &omitted));
    CHECK_FALSE(ws_handshake_response_matches(omitted, storage, offers_len, required));
    CHECK(ws_handshake_response_matches(omitted, storage, offers_len));

    // A matching token in a later physical field must survive compaction; the
    // coalesced first frame is opaque, even when its payload resembles a header.
    static constexpr char kTail[] =
        "\x81\x1a"
        "Sec-WebSocket-Protocol:other";
    u8 request[1024];
    memcpy(request, kRequest, sizeof(kRequest) - 1);
    memcpy(request + sizeof(kRequest) - 1, kTail, sizeof(kTail) - 1);
    const u32 header = ws_restrict_subprotocol(
        request, sizeof(kRequest) - 1, sizeof(kRequest) + sizeof(kTail) - 2, required);
    REQUIRE(header != 0);
    CHECK(memcmp(request + header, kTail, sizeof(kTail) - 1) == 0);
    HttpParser parser{};
    ParsedRequest parsed{};
    parser.reset();
    REQUIRE(parser.parse(request, header, &parsed) == ParseStatus::Complete);
    u32 count = 0;
    for (u32 i = 0; i < parsed.header_count; i++) {
        if (!http_header_name_eq_ci(parsed.headers[i].name.ptr,
                                    parsed.headers[i].name.len,
                                    "sec-websocket-protocol",
                                    22))
            continue;
        count++;
        CHECK(parsed.headers[i].value.eq(required));
    }
    CHECK_EQ(count, 1u);
    CHECK_EQ(ws_restrict_subprotocol(request, header, header + sizeof(kTail) - 1, required),
             header);
}

TEST(websocket_upgrade_admission, opening_request_shape_and_protocol_tokens_fail_closed) {
    const char* invalid[] = {
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade /1\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade, Upgrade /1\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket garbage\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket/13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nHost: other\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat,chat\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat,\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=!\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: thirteen\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 013\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 00013\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 256\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 999\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 1234\r\n\r\n",
        "POST /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.0\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\nContent-Length: 1\r\n\r\n",
    };
    u8 storage[SlicePool::kSliceSize]{};
    for (const char* request : invalid) {
        u32 offers_len = 0;
        CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(request),
                                   static_cast<u32>(strlen(request)),
                                   storage,
                                   sizeof(storage),
                                   &offers_len) == WsHandshakeRequestResult::BadRequest);
    }
    static constexpr char kWrongVersion[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 12\r\n\r\n";
    u32 offers_len = 0;
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(kWrongVersion),
                               sizeof(kWrongVersion) - 1,
                               nullptr,
                               0,
                               &offers_len) == WsHandshakeRequestResult::VersionRequired);
    static constexpr const char* kOtherVersions[] = {"0", "8", "255"};
    for (const char* version : kOtherVersions) {
        char request[256];
        const int length =
            snprintf(request,
                     sizeof(request),
                     "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                     "Sec-WebSocket-Version: %s\r\n\r\n",
                     version);
        REQUIRE(length > 0 && static_cast<u32>(length) < sizeof(request));
        CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(request),
                                   static_cast<u32>(length),
                                   nullptr,
                                   0,
                                   &offers_len) == WsHandshakeRequestResult::VersionRequired);
    }
}

TEST(websocket_upgrade_admission, response_requires_matching_accept_and_offered_protocol) {
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: chat\r\n\r\n";
    u8 storage[SlicePool::kSliceSize]{};
    u32 offers_len = 0;
    REQUIRE(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                                 sizeof(kRequest) - 1,
                                 storage,
                                 sizeof(storage),
                                 &offers_len) == WsHandshakeRequestResult::Ready);
    const char* invalid[] = {
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: incorrect\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade /1\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade, Upgrade /1\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Protocol: Chat\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Protocol: chat, other\r\n\r\n",
    };
    for (const char* raw : invalid) {
        ParsedResponse response{};
        REQUIRE(parse_response(raw, &response));
        CHECK_FALSE(ws_handshake_response_matches(response, storage, offers_len));
    }
}

TEST(websocket_upgrade_admission, near_slice_capacity_offer_is_stored_without_a_smaller_cap) {
    static constexpr char kPrefix[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: ";
    static constexpr char kSuffix[] = "\r\n\r\n";
    char request[SlicePool::kSliceSize];
    const u32 prefix_len = sizeof(kPrefix) - 1;
    const u32 suffix_len = sizeof(kSuffix) - 1;
    const u32 token_len = SlicePool::kSliceSize - prefix_len - suffix_len - 1;
    memcpy(request, kPrefix, prefix_len);
    memset(request + prefix_len, 'a', token_len);
    memcpy(request + prefix_len + token_len, kSuffix, suffix_len);
    const u32 header_len = prefix_len + token_len + suffix_len;
    u8 storage[SlicePool::kSliceSize]{};
    u32 offers_len = 0;
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(request),
                               header_len,
                               storage,
                               sizeof(storage),
                               &offers_len) == WsHandshakeRequestResult::Ready);
    CHECK_EQ(offers_len, token_len);
    CHECK(memcmp(storage + kWsHandshakeAcceptLength, request + prefix_len, token_len) == 0);
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

TEST(websocket_upgrade_admission, handshake_slice_is_owned_and_retired_once) {
    SmallLoop loop;
    loop.setup();
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 123;
    conn->is_ws_terminate_route = true;
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    conn->req_header_end = sizeof(kRequest) - 1;

    REQUIRE(ws_prepare_handshake_before_forward(&loop, *conn));
    CHECK(conn->ws_handshake_slice == loop.ws_handshake_storage);
    CHECK_EQ(conn->ws_handshake_phase, WsHandshakePhase::Prepared);
    CHECK_EQ(loop.ws_handshake_free_calls, 0u);
    CHECK(ws_retire_handshake_storage(&loop, *conn));
    CHECK(ws_retire_handshake_storage(&loop, *conn));
    CHECK_EQ(loop.ws_handshake_free_calls, 1u);
    CHECK_FALSE(loop.ws_handshake_in_use);
    loop.close_conn(*conn);

    conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 124;
    conn->is_ws_terminate_route = true;
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    conn->req_header_end = sizeof(kRequest) - 1;
    REQUIRE(ws_prepare_handshake_before_forward(&loop, *conn));
    loop.close_conn(*conn);
    CHECK_EQ(loop.ws_handshake_free_calls, 2u);
    CHECK_FALSE(loop.ws_handshake_in_use);
}

TEST(websocket_upgrade_admission, required_protocol_rejects_before_allocation_and_is_reset) {
    SmallLoop loop;
    loop.setup();
    loop.fail_ws_handshake_alloc = true;
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 123;
    conn->is_ws_terminate_route = true;
    conn->ws_subprotocol = lit_str("chat");
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    conn->req_header_end = sizeof(kRequest) - 1;
    CHECK_FALSE(ws_prepare_handshake_before_forward(&loop, *conn));
    CHECK_EQ(conn->resp_status, 400u);
    CHECK_EQ(conn->upstream_fd, -1);
    CHECK_FALSE(loop.ws_handshake_in_use);
    loop.close_conn(*conn);
    conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    CHECK_EQ(conn->ws_subprotocol.len, 0u);
    CHECK_EQ(conn->ws_subprotocol.ptr, nullptr);
    loop.close_conn(*conn);
}

TEST(websocket_upgrade_admission, handshake_slice_pool_exhaustion_returns_503_before_connect) {
    SmallLoop loop;
    loop.setup();
    loop.fail_ws_handshake_alloc = true;
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 123;
    conn->is_ws_terminate_route = true;
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    conn->req_header_end = sizeof(kRequest) - 1;

    CHECK_FALSE(ws_prepare_handshake_before_forward(&loop, *conn));
    CHECK_EQ(conn->resp_status, 503u);
    CHECK(conn->ws_handshake_slice == nullptr);
    CHECK_EQ(loop.backend.count_ops(MockOp::Connect), 0u);
    CHECK_EQ(loop.backend.count_ops(MockOp::Send), 1u);
    loop.close_conn(*conn);
}

TEST(websocket_upgrade_admission, rejected_handshake_reply_send_failure_closes_once) {
    static constexpr bool kCloseCases[] = {false, true};
    static constexpr bool kInvalidHeaderCases[] = {false, true};
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    for (bool invalid_header : kInvalidHeaderCases) {
        for (bool backend_closes : kCloseCases) {
            SmallLoop loop;
            loop.setup();
            loop.fail_ws_handshake_alloc = !invalid_header;
            loop.backend.fail_send = true;
            loop.close_on_failed_send = backend_closes;
            Connection* conn = loop.alloc_conn();
            REQUIRE(conn != nullptr);
            conn->fd = 123;
            conn->is_ws_terminate_route = true;
            if (!invalid_header) {
                REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(kRequest),
                                                sizeof(kRequest) - 1),
                           sizeof(kRequest) - 1);
                conn->req_header_end = sizeof(kRequest) - 1;
            }

            CHECK_FALSE(ws_prepare_handshake_before_forward(&loop, *conn));
            CHECK_EQ(loop.free_top, SmallLoop::kMaxConns);
            CHECK_EQ(loop.send_submit_attempts, 1u);
            CHECK_EQ(loop.backend.count_ops(MockOp::Connect), 0u);
            CHECK_EQ(loop.ws_handshake_free_calls, 0u);
            CHECK_EQ(conn->fd, -1);
        }
    }
}

TEST(websocket_upgrade_admission, validated_101_pending_send_close_retires_owned_slice) {
    SmallLoop loop;
    loop.setup();
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 123;
    conn->upstream_fd = 456;
    conn->state = ConnState::Proxying;
    conn->on_upstream_recv = &on_upstream_response<SmallLoop>;
    conn->is_ws_terminate_route = true;
    conn->req_wants_upgrade = true;
    conn->req_upgrade_is_websocket = true;
    conn->req_method = static_cast<u8>(LogHttpMethod::Get);
    REQUIRE(loop.alloc_upstream_buf(*conn));
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    conn->req_header_end = sizeof(kRequest) - 1;
    REQUIRE(ws_prepare_handshake_before_forward(&loop, *conn));
    static constexpr char kResponse[] =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    ParsedResponse parsed_response{};
    REQUIRE(parse_response(kResponse, &parsed_response));
    REQUIRE(ws_handshake_response_matches(
        parsed_response, conn->ws_handshake_slice, conn->ws_handshake_offers_len));
    REQUIRE_EQ(conn->upstream_recv_buf.write(reinterpret_cast<const u8*>(kResponse),
                                             sizeof(kResponse) - 1),
               sizeof(kResponse) - 1);

    on_upstream_response<SmallLoop>(
        &loop, *conn, make_ev(conn->id, IoEventType::UpstreamRecv, sizeof(kResponse) - 1));
    CHECK_EQ(conn->ws_handshake_phase, WsHandshakePhase::Validated);
    REQUIRE(conn->ws_handshake_slice != nullptr);
    CHECK(loop.ws_terminate_in_use);
    CHECK(conn->ws_c2u_msg != nullptr);
    CHECK(conn->ws_u2c_msg != nullptr);
    CHECK(conn->ws_c2u_out != nullptr);
    CHECK(conn->ws_u2c_out != nullptr);
    Connection* const unrelated = loop.alloc_conn();
    REQUIRE(unrelated != nullptr);
    loop.close_conn(*unrelated);
    CHECK(loop.ws_terminate_in_use);
    CHECK(conn->ws_c2u_msg != nullptr);
    const MockOp* handshake_send = loop.backend.last_op(MockOp::Send);
    REQUIRE(handshake_send != nullptr);
    REQUIRE(handshake_send->send_len > 1);

    loop.close_conn(*conn);
    CHECK_FALSE(loop.ws_terminate_in_use);
    CHECK(conn->ws_c2u_msg == nullptr);
    CHECK(conn->ws_u2c_msg == nullptr);
    CHECK(conn->ws_c2u_out == nullptr);
    CHECK(conn->ws_u2c_out == nullptr);
    CHECK_EQ(loop.ws_handshake_free_calls, 1u);
    CHECK_FALSE(loop.ws_handshake_in_use);
    CHECK_EQ(conn->fd, -1);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
