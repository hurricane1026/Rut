#pragma once
#include "rut/common/types.h"
#include "ws_callback_probe.h"

namespace rut::test::ip_parse {
inline constexpr char kSource[] = R"rut(
let seenAddresses = Cache<IP, i64>(capacity: 64)
func readAddress(_ text: str) -> IP { IP.parse(text) }
func sameAddress(_ left: IP, _ right: IP) -> bool { left == right }
route POST "/" {
    let pending = readAddress(req.body)
    guard let address = pending else { return 400 }
    guard let expected = IP.parse(req.header("X-Expected").or("")) else { return 422 }
    guard sameAddress(address, expected) else { return 409 }
    let fallback = IP.parse("invalid").or(address)
    guard fallback == address else { return 500 }
    if let repeated = IP.parse(req.body) {
        guard repeated == address else { return 500 }
        return 204
    } else { return 500 }
}
route POST "/peer" {
    guard let address = IP.parse(req.body) else { return 400 }
    guard address == req.remoteAddr else { return 403 }
    return 204
}
route POST "/cache" {
    let address = IP.parse(req.body).or(req.remoteAddr)
    let prior = seenAddresses.get(address).or(0)
    seenAddresses.set(address, prior + 1)
    if prior == 0 { return 201 } else { return 202 }
}
)rut";
#if RUT_ENABLE_WEBSOCKET
inline constexpr char kWsSource[] = R"rut(upstream ws at "127.0.0.1:9999"
route GET "/ws" { return websocket(ws) { message in
    guard let address = IP.parse(message.text) else { message.drop() }
    guard address == message.connection.remoteAddr else { message.drop() }
    message.forward()
} }
)rut";
template <typename Config>
void check_ws(TestCase* _tc, const Config& config) {
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    const u8 peer[] = {127, 0, 0, 1};
    __builtin_memcpy(&probe.conn->peer_addr, peer, sizeof(peer));
    const Str inputs[] = {
        lit_str("127.0.0.1"), lit_str("1.2.3.4"), lit_str("0127.0.0.1"), lit_str("::1")};
    for (const auto text : inputs)
        probe.expect(_tc,
                     config.routes[0].ws_frame_handler,
                     WsOpcode::Text,
                     text,
                     true,
                     text.eq(inputs[0]) ? WsFrameAction::Forward : WsFrameAction::Drop);
    CHECK_EQ(probe.conn->json_arena.space_used(), 0u);
}
#endif
struct Case {
    const char* input;
    const char* expected;
    unsigned status;
};
inline constexpr Case kCases[] = {
    {"0.0.0.0", "0.0.0.0", 204},
    {"255.255.255.255", "255.255.255.255", 204},
    {"127.0.0.1", "127.0.0.1", 204},
    {"192.168.10.42", "192.168.10.42", 204},
    {"1.2.3.4", "4.3.2.1", 409},
    {"1.2.3.4", "invalid", 422},
    {"01.2.3.4", "1.2.3.4", 400},
    {"256.2.3.4", "1.2.3.4", 400},
    {"1.2.3.4:80", "1.2.3.4", 400},
    {"1.2.3.4/24", "1.2.3.4", 400},
    {"1.2.3.4 ", "1.2.3.4", 400},
    {" 1.2.3.4", "1.2.3.4", 400},
    {"127.1", "127.0.0.1", 400},
    {"::ffff:127.0.0.1", "127.0.0.1", 400},
    {"", "0.0.0.0", 400},
};
}  // namespace rut::test::ip_parse
