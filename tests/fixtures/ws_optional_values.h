#pragma once

#include "rut/common/types.h"
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"
#endif
#include <cstring>
#include <initializer_list>

namespace rut::test::ws_optional_values {

inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func same<T: Eq>(_ lhs: T, _ rhs: T) -> bool => lhs == rhs
func safeName(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    json.string(root).or("fallback")
}
func maybeText(_ msg: WebSocketMessage) -> str {
    if msg.fromClient { msg.text } else { nil }
}
func lengthIfText(_ msg: WebSocketMessage) -> i32 {
    if msg.isText { msg.payload.count } else { nil }
}
func flagIfText(_ msg: WebSocketMessage) -> bool {
    if msg.isText { false } else { nil }
}
func bytesIfClient(_ msg: WebSocketMessage) -> Bytes {
    if msg.fromClient { b"\x00\xff" }
    else { if msg.isText { b"" } else { nil } }
}
func label(_ msg: WebSocketMessage) -> str {
    guard let text = maybeText(msg) else { nil }
    if text == "raw" { "literal" } else { text }
}
route GET "/fallback" { return websocket(ws) { msg in
    guard let name = safeName(msg) else { msg.drop() }
    guard !name.isEmpty else { msg.forward("empty") }
    msg.forward("[" + name + "]")
} }
route GET "/message" { return websocket(ws) { msg in
    if let text = maybeText(msg) {
        guard text.hasPrefix("ok") && text.contains("A") else { msg.drop() }
        msg.forward("<" + text + ">")
    } else { msg.forward("server") }
} }
route GET "/number" { return websocket(ws) { msg in
    if let count = lengthIfText(msg) {
        guard count == 0 else { msg.forward("nonempty") }
        msg.forward("zero")
    } else { msg.drop() }
} }
route GET "/bool" { return websocket(ws) { msg in
    if let value = flagIfText(msg) {
        guard same(value, false) else { msg.drop() }
        msg.forward("false")
    } else { msg.forward("absent") }
} }
route GET "/bytes" { return websocket(ws) { msg in
    guard let bytes = bytesIfClient(msg) else { msg.drop() }
    msg.forward(bytes)
} }
route GET "/label" { return websocket(ws) { msg in
    if let text = label(msg) { msg.forward("<" + text + ">") }
    else { msg.forward("absent") }
} }
func emptyIfClient(_ msg: WebSocketMessage) -> str {
    if msg.fromClient { "" } else { nil }
}
func maybePacket(_ msg: WebSocketMessage) -> WebSocketMessage {
    if msg.fromClient { msg } else { nil }
}
func maybeKind(_ msg: WebSocketMessage) -> WebSocketMessageKind {
    if msg.fromClient { msg.kind } else { nil }
}
func maybePayload(_ msg: WebSocketMessage) -> Bytes {
    if msg.fromClient { msg.payload } else { nil }
}
route GET "/empty" { return websocket(ws) { msg in
    if let text = emptyIfClient(msg) {
        guard text.isEmpty && text.hasSuffix("") else { msg.drop() }
        msg.forward("[" + text + "]")
    } else { msg.forward("absent") }
} }
route GET "/borrowed" { return websocket(ws) { msg in
    guard let packet = maybePacket(msg) else { msg.drop() }
    guard let kind = maybeKind(packet) else { msg.drop() }
    guard let bytes = maybePayload(packet) else { msg.drop() }
    guard kind == WebSocketMessageKind.text && bytes.isEmpty else { msg.drop() }
    packet.forward()
} }
)rut";

#if RUT_ENABLE_WEBSOCKET
// The same observable behavior must survive source loading and native serialization.
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 8u);
    for (u32 i = 0; i < config.route_count; ++i) REQUIRE(config.routes[i].ws_frame_handler);
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const auto run = [&](u32 route, const char* payload) {
                return config.routes[route].ws_frame_handler(nullptr,
                                                             op,
                                                             reinterpret_cast<const u8*>(payload),
                                                             static_cast<u32>(strlen(payload)),
                                                             client);
            };
            CHECK(run(0, "\"ok\"") == WsFrameAction::ForwardText);
            CHECK(run(0, "\"\"") == WsFrameAction::ForwardTextPolicy0);
            CHECK(run(0, "null") == WsFrameAction::ForwardTextPolicy2);
            CHECK(run(0, "false") == WsFrameAction::ForwardTextPolicy2);
            CHECK(run(0, "0") == WsFrameAction::ForwardTextPolicy2);
            CHECK(run(0, "broken") == WsFrameAction::Drop);
            CHECK(run(1, "okA") ==
                  (client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
            CHECK(run(1, "no") == (client ? WsFrameAction::Drop : WsFrameAction::ForwardText));
            CHECK(run(2, "") ==
                  (op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy1 : WsFrameAction::Drop));
            CHECK(run(2, "x") ==
                  (op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::Drop));
            CHECK(run(3, "") == (op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy0
                                                      : WsFrameAction::ForwardText));
            CHECK(run(4, "x") == (client                 ? WsFrameAction::ForwardText
                                  : op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy0
                                                         : WsFrameAction::Drop));
            CHECK(run(5, "raw") ==
                  (client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
            CHECK(run(5, "other") ==
                  (client ? WsFrameAction::ForwardTextPolicy1 : WsFrameAction::ForwardText));
            CHECK(run(6, "x") ==
                  (client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
            CHECK(run(7, "") ==
                  (client && op == WsOpcode::Text ? WsFrameAction::Forward : WsFrameAction::Drop));
            CHECK(run(7, "x") == WsFrameAction::Drop);
        }
    }
    const auto& fallback = config.routes[0];
    CHECK(fallback.ws_forward_text.source == WsTextSource::JsonString);
    CHECK(fallback.ws_forward_text.prefix.eq(lit_str("[")));
    CHECK(fallback.ws_forward_text.suffix.eq(lit_str("]")));
    REQUIRE_EQ(fallback.ws_forward_text_count, 3u);
    CHECK(fallback.ws_forward_texts[0].prefix.eq(lit_str("empty")));
    CHECK(fallback.ws_forward_texts[2].source == WsTextSource::Literal);
    CHECK(fallback.ws_forward_texts[2].prefix.eq(lit_str("[fallback]")));
    CHECK(config.routes[1].ws_forward_texts[0].source == WsTextSource::MessageText);
    CHECK(config.routes[2].ws_forward_texts[0].prefix.eq(lit_str("nonempty")));
    CHECK(config.routes[2].ws_forward_texts[1].prefix.eq(lit_str("zero")));
    CHECK(config.routes[3].ws_forward_texts[0].prefix.eq(lit_str("false")));
    const auto& binary = config.routes[4];
    CHECK(binary.ws_forward_text.source == WsTextSource::LiteralBinary);
    REQUIRE_EQ(binary.ws_forward_text.prefix.len, 2u);
    CHECK_EQ(static_cast<u8>(binary.ws_forward_text.prefix.ptr[0]), 0u);
    CHECK_EQ(static_cast<u8>(binary.ws_forward_text.prefix.ptr[1]), 255u);
    REQUIRE_EQ(binary.ws_forward_text_count, 1u);
    CHECK(binary.ws_forward_texts[0].source == WsTextSource::LiteralBinary);
    CHECK_EQ(binary.ws_forward_texts[0].prefix.len, 0u);
    CHECK(config.routes[5].ws_forward_texts[0].prefix.eq(lit_str("<literal>")));
    CHECK(config.routes[5].ws_forward_texts[1].source == WsTextSource::MessageText);
    CHECK(config.routes[6].ws_forward_texts[0].prefix.eq(lit_str("[]")));
}
#endif

}  // namespace rut::test::ws_optional_values
