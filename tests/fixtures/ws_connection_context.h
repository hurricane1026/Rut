#pragma once
#include "ws_callback_probe.h"
namespace rut::test::ws_connection_context {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func identity(_ connection: WebSocketConnection) -> WebSocketConnection => connection
func peer(_ connection: WebSocketConnection) -> IP => connection.remoteAddr
func port(_ connection: WebSocketConnection) -> i32 => connection.remotePort
func selected(_ connection: WebSocketConnection) -> str {
    let unused = sha256(connection.subprotocol)
    connection.subprotocol
}
route GET "/ws" { return websocket(ws, subprotocol: "chat") { msg in
    let connection = identity(msg.connection)
    guard peer(connection) == peer(msg.connection) else { msg.close(1011) }
    guard port(connection) == 43210 else { msg.close(1011) }
    let chosen = selected(connection)
    if connection.isTls { msg.forward(chosen) }
    else { msg.forward("plain:" + chosen) }
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 1u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    probe.conn->peer_addr = 0x0100007fu;
    probe.conn->peer_port = 43210;
    for (bool tls : {false, true}) {
        probe.conn->tls_active = tls;
        for (Str protocol : {lit_str("chat"), lit_str("other"), lit_str("")}) {
            probe.conn->ws_subprotocol = protocol;
            for (bool client : {false, true}) {
                char expected[32]{};
                const Str prefix = tls ? lit_str("") : lit_str("plain:");
                __builtin_memcpy(expected, prefix.ptr, prefix.len);
                __builtin_memcpy(expected + prefix.len, protocol.ptr, protocol.len);
                probe.expect(_tc,
                             config.routes[0].ws_frame_handler,
                             WsOpcode::Binary,
                             lit_str("payload"),
                             client,
                             WsFrameAction::ForwardText,
                             {expected, prefix.len + protocol.len});
                CHECK(probe.conn->json_arena.space_used() >= 64u);
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_connection_context
