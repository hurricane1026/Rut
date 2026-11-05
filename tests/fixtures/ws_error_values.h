#pragma once
#include "ws_callback_probe.h"
namespace rut::test::ws_error_values {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func pick(_ input: str) -> str {
    let unused = sha256(input)
    if input == "fail" { error(7) } else { if input == "nil" { nil } else { input } }
}
func again(_ input: str) -> str {
    let result = pick(input)
    result
}
func recover(_ input: str) -> str {
    let result = pick(input)
    result.or("fallback")
}
route GET "/guard" { return websocket(ws) { msg in
    let result = again(msg.text)
    guard let plain = result else { msg.forward("failed") }
    msg.forward(plain)
} }
route GET "/if" { return websocket(ws) { msg in
    let result = pick(msg.text)
    if let plain = result { msg.forward(plain) } else { msg.forward("failed") }
} }
route GET "/or" { return websocket(ws) { msg in
    let result = pick(msg.text)
    msg.forward(result.or("fallback"))
} }
route GET "/presence" { return websocket(ws) { msg in
    let result = pick(msg.text)
    if result == nil { msg.forward("absent") }
    else {
        guard let plain = result else { msg.close(1011) }
        msg.forward(plain)
    }
} }
route GET "/unused" { return websocket(ws) { msg in
    let result = pick(msg.text)
    msg.forward("unused")
} }
route GET "/helper" { return websocket(ws) { msg in
    msg.forward(recover(msg.text))
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 6u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (bool client : {false, true}) {
        for (u32 route = 0; route < config.route_count; ++route) {
            for (Str input : {lit_str("ok"), lit_str("fail"), lit_str("nil"), lit_str("")}) {
                const bool failed = input.eq(lit_str("fail")) || input.eq(lit_str("nil"));
                const Str expected = route == 4                 ? lit_str("unused")
                                     : !failed                  ? input
                                     : route == 2 || route == 5 ? lit_str("fallback")
                                     : route == 3               ? lit_str("absent")
                                                                : lit_str("failed");
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
}  // namespace rut::test::ws_error_values
