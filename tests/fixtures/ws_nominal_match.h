#pragma once
#include "ws_callback_probe.h"

namespace rut::test::ws_nominal_match {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func kindLabel(_ kind: WebSocketMessageKind) -> str {
    match kind { .text => "T"
 .binary => "B" }
}
func directionLabel(_ direction: WebSocketDirection) -> str {
    match direction {
        WebSocketDirection.clientToUpstream => "client"
        WebSocketDirection.upstreamToClient => "server"
    }
}
func classify(_ input: str) -> WebSocketMessageKind {
    let unused = sha256(input)
    if input == "t" { WebSocketMessageKind.text } else { WebSocketMessageKind.binary }
}
route GET "/kind" { return websocket(ws) { msg in
    match msg.kind { .text => msg.forward("T")
 .binary => msg.forward("B") }
} }
route GET "/direction" { return websocket(ws) { msg in
    msg.forward(directionLabel(msg.direction) + kindLabel(msg.kind))
} }
route GET "/once" { return websocket(ws) { msg in
    match classify(msg.text) { .text => msg.forward("T")
 .binary => msg.forward("B") }
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 3u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
        for (bool client : {false, true}) {
            const Str label = op == WsOpcode::Text ? lit_str("T") : lit_str("B");
            probe.expect(_tc,
                         config.routes[0].ws_frame_handler,
                         op,
                         lit_str("x"),
                         client,
                         WsFrameAction::ForwardText,
                         label);
            const Str combined =
                client ? op == WsOpcode::Text ? lit_str("clientT") : lit_str("clientB")
                : op == WsOpcode::Text ? lit_str("serverT")
                                       : lit_str("serverB");
            probe.expect(_tc,
                         config.routes[1].ws_frame_handler,
                         op,
                         lit_str("x"),
                         client,
                         WsFrameAction::ForwardText,
                         combined);
            for (Str input : {lit_str("t"), lit_str("b")}) {
                probe.expect(_tc,
                             config.routes[2].ws_frame_handler,
                             op,
                             input,
                             client,
                             WsFrameAction::ForwardText,
                             input.eq(lit_str("t")) ? lit_str("T") : lit_str("B"));
                CHECK_EQ(probe.conn->json_arena.space_used(), 64u);
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_nominal_match
