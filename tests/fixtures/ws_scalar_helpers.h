#pragma once

#include "rut/common/types.h"
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"
#endif
#include <cstring>
#include <initializer_list>

namespace rut::test::ws_scalar_helpers {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func same<T: Eq>(_ lhs: T, _ rhs: T) -> bool => lhs == rhs
func within<T: Ord>(_ ceiling: T, _ amount: T) -> bool => ceiling >= amount
func limit() -> i32 => 2
func largeBound() => 9223372036854775807
func largeFloor() => -2147483649
func expectedNumber() -> str => "1.2300e+9"
func boolPolicy(_ flag: bool, _ client: bool) -> bool => same(flag, !client)
func textPolicy(_ text: str, _ client: bool) -> bool {
    if client { text.matches(re"^allow[0-9]+$") } else { text.matches(re"^server$") }
}
route GET "/flag" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let flag = json.bool(root) else { msg.drop() }
    guard boolPolicy(flag, msg.fromClient) else { msg.drop() }
    msg.forward()
} }
route GET "/text" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let name = json.string(root) else { msg.drop() }
    guard same(name, identity("ok")) || same("", name) else { msg.drop() }
    msg.forward()
} }
route GET "/scan" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let name = json.string(root) else { msg.drop() }
    guard textPolicy(name, msg.fromClient) else { msg.drop() }
    msg.forward()
} }
route GET "/count" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let amount = json.count(root) else { msg.drop() }
    guard within(limit(), amount) else { msg.drop() }
    msg.forward()
} }
route GET "/number" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let text = json.numberText(root) else { msg.drop() }
    guard same(text, expectedNumber()) else { msg.drop() }
    msg.forward()
} }
route GET "/render" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let text = json.stringify(root) else { msg.drop() }
    guard same(text, "{\"x\":1}") else { msg.drop() }
    msg.forward()
} }
route GET "/kind" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let tag = json.kind(root) else { msg.drop() }
    guard same(tag, "null") || same("array", tag) else { msg.drop() }
    msg.forward()
} }
route GET "/wide" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let number = json.int(root) else { msg.drop() }
    guard number <= largeBound() && largeFloor() <= number else { msg.drop() }
    msg.forward()
} }
route GET "/branch" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    if let text = json.string(root) {
        guard same(text, "ok") else { msg.drop() }
        msg.forward(text)
    } else { msg.drop() }
} }
route GET "/nested" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let field = json.get(root, "/a~1b/~0") else { msg.drop() }
    guard let text = json.string(field) else { msg.drop() }
    guard same(identity(text), "ok") else { msg.drop() }
    msg.forward()
} }
)rut";

#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 10u);
    struct Case {
        u32 route;
        const char* text;
        bool client;
        bool server;
    };
    const Case cases[] = {{0, "false", true, false},
                          {0, "true", false, true},
                          {0, "null", false, false},
                          {0, "0", false, false},
                          {0, "broken", false, false},
                          {1, "\"ok\"", true, true},
                          {1, "\"\"", true, true},
                          {1, "\"no\"", false, false},
                          {1, "null", false, false},
                          {1, "false", false, false},
                          {2, "\"allow\\u0037\"", true, false},
                          {2, "\"server\"", false, true},
                          {2, "\"allow\\u00007\"", false, false},
                          {2, "\"\"", false, false},
                          {2, "null", false, false},
                          {2, "broken", false, false},
                          {3, "[]", true, true},
                          {3, "[0,1]", true, true},
                          {3, "[0,1,2]", false, false},
                          {3, "{}", true, true},
                          {3, "null", false, false},
                          {4, "1.2300e+9", true, true},
                          {4, "1.23e9", false, false},
                          {4, "\"1.2300e+9\"", false, false},
                          {5, "{ \"x\" : 1 }", true, true},
                          {5, "{\"x\":2}", false, false},
                          {5, "null", false, false},
                          {6, "null", true, true},
                          {6, "[]", true, true},
                          {6, "false", false, false},
                          {6, "{}", false, false},
                          {7, "9223372036854775807", true, true},
                          {7, "-2147483649", true, true},
                          {7, "-2147483650", false, false},
                          {7, "-9223372036854775808", false, false},
                          {7, "2147483648", true, true},
                          {7, "0", true, true},
                          {7, "1.0", false, false},
                          {8, "\"ok\"", true, true},
                          {8, "\"no\"", false, false},
                          {8, "null", false, false},
                          {9, "{\"a/b\":{\"~\":\"ok\"}}", true, true},
                          {9, "{\"a/b\":{\"~\":\"no\"}}", false, false},
                          {9, "{\"a/b\":{\"~\":false}}", false, false},
                          {9, "{}", false, false}};
    for (const auto& test : cases) {
        const auto handler = config.routes[test.route].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
                const bool accepted = client ? test.client : test.server;
                CHECK(handler(nullptr,
                              op,
                              reinterpret_cast<const u8*>(test.text),
                              static_cast<u32>(strlen(test.text)),
                              client) == (!accepted         ? WsFrameAction::Drop
                                          : test.route == 8 ? WsFrameAction::ForwardTextPolicy0
                                                            : WsFrameAction::Forward));
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_scalar_helpers
