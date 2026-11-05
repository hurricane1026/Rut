#pragma once

#include "rut/common/types.h"
#include "test.h"
#include "ws_callback_probe.h"
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
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const auto expect = [&](u32 route,
                                    Str input,
                                    WsFrameAction action,
                                    Str output = {},
                                    WsOpcode output_op = WsOpcode::Text) {
                probe.expect(_tc,
                             config.routes[route].ws_frame_handler,
                             op,
                             input,
                             client,
                             action,
                             output,
                             output_op);
            };
            expect(0, lit_str("\"ok\""), WsFrameAction::ForwardText, lit_str("[ok]"));
            expect(0, lit_str("\"\""), WsFrameAction::ForwardTextPolicy0, lit_str("empty"));
            for (Str input : {lit_str("null"), lit_str("false"), lit_str("0")})
                expect(0, input, WsFrameAction::ForwardTextPolicy2, lit_str("[fallback]"));
            expect(0, lit_str("broken"), WsFrameAction::Drop);
            expect(1,
                   lit_str("okA"),
                   client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText,
                   client ? lit_str("<okA>") : lit_str("server"));
            expect(1,
                   lit_str("no"),
                   client ? WsFrameAction::Drop : WsFrameAction::ForwardText,
                   lit_str("server"));
            expect(2,
                   lit_str(""),
                   op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy1 : WsFrameAction::Drop,
                   lit_str("zero"));
            expect(2,
                   lit_str("x"),
                   op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::Drop,
                   lit_str("nonempty"));
            expect(3,
                   lit_str(""),
                   op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy0
                                        : WsFrameAction::ForwardText,
                   op == WsOpcode::Text ? lit_str("false") : lit_str("absent"));
            expect(4,
                   lit_str("x"),
                   client                 ? WsFrameAction::ForwardText
                   : op == WsOpcode::Text ? WsFrameAction::ForwardTextPolicy0
                                          : WsFrameAction::Drop,
                   client ? Str{"\0\xff", 2} : lit_str(""),
                   WsOpcode::Binary);
            expect(5,
                   lit_str("raw"),
                   client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText,
                   client ? lit_str("<literal>") : lit_str("absent"));
            expect(5,
                   lit_str("other"),
                   client ? WsFrameAction::ForwardTextPolicy1 : WsFrameAction::ForwardText,
                   client ? lit_str("<other>") : lit_str("absent"));
            expect(6,
                   lit_str("x"),
                   client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText,
                   client ? lit_str("[]") : lit_str("absent"));
            expect(7,
                   lit_str(""),
                   client && op == WsOpcode::Text ? WsFrameAction::Forward : WsFrameAction::Drop);
            expect(7, lit_str("x"), WsFrameAction::Drop);
        }
    }
    // This pure Binary projection still uses route-owned exact-byte storage.
    const auto& binary = config.routes[4];
    CHECK(binary.ws_forward_text.source == WsTextSource::LiteralBinary);
    CHECK(binary.ws_forward_text.prefix.eq({"\0\xff", 2}));
    REQUIRE_EQ(binary.ws_forward_text_count, 1u);
    CHECK(binary.ws_forward_texts[0].prefix.len == 0);
}
#endif

}  // namespace rut::test::ws_optional_values
