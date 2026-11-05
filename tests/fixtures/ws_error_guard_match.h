#pragma once
#include "ws_callback_probe.h"
namespace rut::test::ws_error_guard_match {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
variant MessageError { bad, empty }
func inspect(_ input: str) -> str {
    let unused = sha256(input)
    if input == "bad" { error(MessageError.bad) }
    else { if input == "" { error(MessageError.empty) } else { input } }
}
route GET "/ws" { return websocket(ws) { msg in
    let result = inspect(msg.text)
    guard match result else {
        .bad => msg.forward("bad input")
        .empty => msg.close(1008, "empty")
        _ => msg.close(1011)
    }
    guard let plain = result else { msg.close(1011) }
    msg.forward(plain)
} }
route GET "/direct" { return websocket(ws) { msg in
    guard match inspect(msg.text) else {
        .bad => msg.forward("bad input")
        .empty => msg.close(1008, "empty")
        _ => msg.close(1011)
    }
    msg.forward(msg.text)
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 2u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (u32 route : {0u, 1u}) {
        for (bool client : {false, true}) {
            for (Str input : {lit_str("ok"), lit_str("bad"), lit_str("")}) {
                probe.expect(_tc,
                             config.routes[route].ws_frame_handler,
                             WsOpcode::Binary,
                             input,
                             client,
                             input.len == 0 ? WsFrameAction::Close : WsFrameAction::ForwardText,
                             input.eq(lit_str("bad")) ? lit_str("bad input") : input,
                             WsOpcode::Text,
                             1008,
                             lit_str("empty"));
                CHECK_EQ(probe.conn->json_arena.space_used(), 64u);
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_error_guard_match
