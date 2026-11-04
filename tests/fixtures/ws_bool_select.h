#pragma once

#include "rut/common/types.h"
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"
#endif
#include <initializer_list>

namespace rut::test::ws_bool_select {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func accepted(_ client: bool, _ text: bool, _ size: i32) -> bool {
    if client { text && size <= 4 } else { !text || size == 0 }
}
func nested(_ msg: WebSocketMessage) -> bool {
    if msg.fromClient {
        if msg.isText { msg.payload == b"ok" } else { msg.len == 2 }
    } else {
        if msg.isBinary { msg.len <= 3 } else { msg.text == "server" }
    }
}
func scanned(_ msg: WebSocketMessage) -> bool {
    if msg.fromClient { msg.text.matches(re"^ok$") }
    else { msg.text.matches(re"^server$") }
}
func maybeBytes(_ msg: WebSocketMessage) -> Bytes {
    guard accepted(msg.fromClient, msg.isText, msg.len) else { nil }
    msg.payload
}
route GET "/direct" { return websocket(ws) { msg in
    guard accepted(msg.fromClient, msg.isText, msg.len) else { msg.drop() }
    msg.forward()
} }
route GET "/let" { return websocket(ws) { msg in
    let allowed: bool = identity(accepted(msg.fromClient, msg.isText, msg.payload.count))
    guard !allowed == false else { msg.drop() }
    msg.forward()
} }
route GET "/nested" { return websocket(ws) { msg in
    guard nested(msg) else { msg.drop() }
    msg.forward()
} }
route GET "/scan" { return websocket(ws) { msg in
    guard scanned(msg) else { msg.drop() }
    msg.forward()
} }
route GET "/optional" { return websocket(ws) { msg in
    guard let bytes = maybeBytes(msg) else { msg.drop() }
    msg.forward(bytes)
} }
route POST "/http" {
    guard accepted(true, req.bodyBytes.isEmpty, req.bodyBytes.count) else { return 403 }
    return 200
}
)rut";

#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 6u);
    const Str payloads[] = {
        {"", 0}, {"ok", 2}, {"server", 6}, {"xxxx", 4}, {"longer", 6}, {"\0\xff", 2}};
    for (u32 i = 0; i < 5; ++i) {
        const auto handler = config.routes[i].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
                for (Str bytes : payloads) {
                    const bool text = op == WsOpcode::Text;
                    bool accepted = client ? text && bytes.len <= 4 : !text || bytes.len == 0;
                    if (i == 2)
                        accepted = client ? (text ? bytes.eq(lit_str("ok")) : bytes.len == 2)
                                          : (text ? bytes.eq(lit_str("server")) : bytes.len <= 3);
                    if (i == 3) accepted = bytes.eq(client ? lit_str("ok") : lit_str("server"));
                    const auto actual = handler(
                        nullptr, op, reinterpret_cast<const u8*>(bytes.ptr), bytes.len, client);
                    CHECK(actual == (!accepted ? WsFrameAction::Drop
                                     : i == 4  ? WsFrameAction::ForwardText
                                               : WsFrameAction::Forward));
                }
            }
        }
    }
    CHECK(config.routes[4].ws_forward_text.source == WsTextSource::MessageBytes);
}
#endif
}  // namespace rut::test::ws_bool_select
