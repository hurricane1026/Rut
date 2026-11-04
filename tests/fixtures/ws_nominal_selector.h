#pragma once
#include "ws_callback_probe.h"
namespace rut::test::ws_nominal_selector {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func classify(_ input: str) -> WebSocketMessageKind {
    let unused = sha256(input)
    if input == "t" { WebSocketMessageKind.text } else { WebSocketMessageKind.binary }
}
route GET "/ignored" { return websocket(ws) { msg in
    match classify(msg.text) { _ => msg.forward("ignored") }
} }
route GET "/guarded" { return websocket(ws) { msg in
    match classify(msg.text) {
        .text if msg.fromClient => msg.forward("first")
        .text => msg.forward("second")
        _ => msg.forward("other")
    }
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 2u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (bool client : {false, true}) {
        for (Str input : {lit_str("t"), lit_str("b")}) {
            for (u32 route : {0u, 1u}) {
                const Str expected = route == 0                ? lit_str("ignored")
                                     : !input.eq(lit_str("t")) ? lit_str("other")
                                     : client                  ? lit_str("first")
                                                               : lit_str("second");
                probe.expect(_tc,
                             config.routes[route].ws_frame_handler,
                             WsOpcode::Binary,
                             input,
                             client,
                             WsFrameAction::ForwardText,
                             expected);
                CHECK_EQ(probe.conn->json_arena.space_used(), 64u);
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_nominal_selector
