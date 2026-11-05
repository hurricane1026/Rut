#pragma once
#include "ws_callback_probe.h"
namespace rut::test::ws_error_scalars {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func flag(_ input: str) -> bool {
    let unused = sha256(input)
    if input == "fail" { error(7) } else { if input == "nil" { nil } else { false } }
}
func number(_ input: str) -> i32 {
    let unused = sha256(input)
    if input == "fail" { error(7) } else { if input == "nil" { nil } else { 0 } }
}
route GET "/bool" { return websocket(ws) { msg in
    let result = flag(msg.text)
    if let plain = result {
        if plain { msg.forward("true") } else { msg.forward("false") }
    } else { msg.forward("absent") }
} }
route GET "/number" { return websocket(ws) { msg in
    let result = number(msg.text)
    guard let plain = result else { msg.forward("absent") }
    guard plain == 0 else { msg.close(1011) }
    msg.forward("zero")
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 2u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (bool client : {false, true}) {
        for (u32 route : {0u, 1u}) {
            for (Str input : {lit_str("ok"), lit_str("fail"), lit_str("nil"), lit_str("")}) {
                const bool absent = input.eq(lit_str("fail")) || input.eq(lit_str("nil"));
                probe.expect(_tc,
                             config.routes[route].ws_frame_handler,
                             WsOpcode::Binary,
                             input,
                             client,
                             WsFrameAction::ForwardText,
                             absent       ? lit_str("absent")
                             : route == 0 ? lit_str("false")
                                          : lit_str("zero"));
                CHECK_EQ(probe.conn->json_arena.space_used(), 64u);
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_error_scalars
