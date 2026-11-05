#pragma once
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_terminate.h"
#include <cstring>
#include <initializer_list>
#include <memory>
#endif

namespace rut::test::ws_dynamic_output {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func bytes(_ m: WebSocketMessage, _ client: bool) -> Bytes {
    if client { m.payload } else { b"\x00\xff" }
}
func text(_ m: WebSocketMessage, _ client: bool) -> str {
    if client { m.text } else { "reply" }
}
route GET "/bytes" { return websocket(ws) { msg in
    let value = bytes(msg, msg.fromClient)
    msg.forward(value)
} }
route GET "/text" { return websocket(ws) { msg in
    let value = text(msg, msg.fromClient)
    msg.forward(value)
} }
route GET "/uuid" { return websocket(ws) { msg in
    let token = uuid()
    guard let value = token else { msg.close() }
    msg.forward(value)
} }
route GET "/close" { return websocket(ws) { msg in
    let code = 1000 + msg.len
    let reason = msg.text
    msg.close(code, reason)
} }
route GET "/select" { return websocket(ws) { msg in
    if msg.fromClient { msg.forward(msg.text) }
    else { msg.close(1000 + msg.len, text(msg, msg.fromClient)) }
} })rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(const Config& config, TestCase* _tc) {
    REQUIRE_EQ(config.route_count, 5u);
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto conn = std::make_unique<ConnectionBase>();
    REQUIRE(conn->json_arena.init(&pool));
    const u8 input[] = {'x', 0, 'y'};
    for (u32 route = 0; route < 5; ++route) {
        const auto& entry = config.routes[route];
        REQUIRE(entry.ws_frame_handler);
        CHECK(entry.ws_forward_text.source == WsTextSource::Dynamic);
        for (bool client : {false, true}) {
            const auto action =
                entry.ws_frame_handler(conn.get(), WsOpcode::Binary, input, sizeof(input), client);
            const auto& result = conn->ws_handler_output;
            REQUIRE(result.ready);
            CHECK(action == (route == 3 || (route == 4 && !client)
                                 ? WsFrameAction::CloseDynamic
                                 : WsFrameAction::ForwardDynamic));
            if (route == 0) {
                CHECK(result.opcode == WsOpcode::Binary);
                CHECK(result.payload.eq(client ? Str{reinterpret_cast<const char*>(input), 3}
                                               : Str{"\0\xff", 2}));
            } else if (route == 1) {
                CHECK(result.opcode == WsOpcode::Text);
                CHECK(result.payload.eq(client ? Str{"x\0y", 3} : lit_str("reply")));
            } else if (route == 2) {
                CHECK_EQ(result.payload.len, 36u);
                CHECK_EQ(result.payload.ptr[8], '-');
            } else if (route == 3) {
                CHECK_EQ(result.close_code, 1003u);
                CHECK(result.payload.eq({"x\0y", 3}));
            } else {
                CHECK(result.payload.eq(client ? Str{"x\0y", 3} : lit_str("reply")));
                if (!client) CHECK_EQ(result.close_code, 1003u);
            }
            CHECK(entry.ws_frame_handler(nullptr, WsOpcode::Text, input, sizeof(input), client) ==
                  WsFrameAction::Close);
        }
    }
    // Validate before narrowing, and clear a previous publication on every callback.
    const u8 invalid[5]{};
    CHECK(config.routes[3].ws_frame_handler(conn.get(), WsOpcode::Binary, invalid, 5, true) ==
          WsFrameAction::CloseDynamic);
    CHECK_EQ(conn->ws_handler_output.close_code, 1011u);
    CHECK_EQ(conn->ws_handler_output.payload.len, 0u);
    conn->json_arena.destroy();
    u8* held[8]{};
    for (auto& slice : held) {
        slice = pool.alloc();
        REQUIRE(slice);
    }
    conn->ws_handler_output.ready = true;
    CHECK(config.routes[2].ws_frame_handler(conn.get(), WsOpcode::Text, input, 3, true) ==
          WsFrameAction::Close);
    CHECK_FALSE(conn->ws_handler_output.ready);
    CHECK_EQ(pool.in_use(), 8u);
    for (auto* slice : held) pool.free(slice);
    conn->json_arena.destroy();
    pool.destroy();
}
#endif
}  // namespace rut::test::ws_dynamic_output
