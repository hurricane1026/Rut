#pragma once

namespace rut::test::ws_general_expressions {
inline constexpr const char* kSource = R"rut(upstream backend at "127.0.0.1:9999"
func allowed(_ size: i32, _ client: bool) -> bool =>
    !client || bitwise.and(size, 3) == 2
route POST "/http" {
    let size = req.bodyBytes.count + 1
    guard allowed(size, true) else { return 403 }
    return 200
}
route GET "/ws" { return websocket(backend) { msg in
    let size = msg.payload.count + 1
    guard size >= 1 else { msg.close() }
    guard size <= 12 else { msg.close() }
    guard allowed(size, msg.fromClient) else { msg.drop() }
    if msg.isText && msg.len == 5 { msg.drop() } else { msg.forward() }
} }
route GET "/guards" { return websocket(backend) { msg in
    guard msg.len != 0 else { msg.drop() }
    guard msg.len != 1 else { msg.drop() }
    guard msg.len != 2 else { msg.drop() }
    guard msg.len != 3 else { msg.drop() }
    guard msg.len != 4 else { msg.drop() }
    msg.forward()
} })rut";
}  // namespace rut::test::ws_general_expressions
