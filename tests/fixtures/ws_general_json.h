#pragma once
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include <initializer_list>
#include <memory>
#endif

namespace rut::test::ws_general_json {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func pointer(_ client: bool) -> str { if client { "/name" } else { "/reply" } }
struct Payload { label: str count: i32 }
route GET "/path" { return websocket(ws) { msg in
    let path = pointer(msg.fromClient)
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let selected = json.get(root, path) else { msg.close(1008) }
    guard let value = json.string(selected) else { msg.close(1003) }
    let expected = value
    guard value == expected else { msg.drop() }
    msg.forward(value)
} }
route GET "/edit" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let replacement = json.value({ length: msg.len }) else { msg.close(1011) }
    guard let added = json.member(root, "stamp", replacement) else { msg.close(1008) }
    guard let edited = json.set(added, "/stamp", replacement) else { msg.close(1008) }
    guard let output = json.stringify(edited) else { msg.close(1011) }
    msg.forward(output)
} }
route GET "/decode" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let value = json.decode(Payload, root) else { msg.close(1003) }
    guard value.count >= 0 else { msg.close(1008) }
    msg.forward(value.label)
} }
route GET "/lifetime" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let first = json.string(root) else { msg.close(1003) }
    guard let other = json.parse("\"other\"") else { msg.close(1011) }
    guard let second = json.string(other) else { msg.close(1011) }
    guard first != second else { msg.drop() }
    msg.forward(first)
} }
route GET "/unused" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    let unused = json.string(root)
    msg.forward()
} })rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(const Config& config, TestCase* _tc) {
    REQUIRE_EQ(config.route_count, 5u);
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto conn = std::make_unique<ConnectionBase>();
    REQUIRE(conn->json_arena.init(&pool));
    const Str path_input = lit_str(R"({"name":"a\u0000b","reply":"back"})");
    const Str payload_input = lit_str(R"({"label":"a\u0000b","count":3})");
    const Str lifetime_input = lit_str(R"("a\u0000b")");
    const Str inputs[] = {path_input, lit_str("{}"), payload_input, lifetime_input, lifetime_input};
    const Str outputs[] = {
        {"a\0b", 3}, lit_str(R"({"stamp":{"length":2}})"), {"a\0b", 3}, {"a\0b", 3}};
    for (u32 route = 0; route < 5; ++route) {
        const auto handler = config.routes[route].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            const auto input = inputs[route];
            const auto result = handler(conn.get(),
                                        WsOpcode::Binary,
                                        reinterpret_cast<const u8*>(input.ptr),
                                        input.len,
                                        client);
            CHECK(result == (route == 4 ? WsFrameAction::Forward : WsFrameAction::ForwardDynamic));
            if (route != 4) {
                REQUIRE(conn->ws_handler_output.ready);
                CHECK(conn->ws_handler_output.opcode == WsOpcode::Text);
                CHECK(conn->ws_handler_output.payload.eq(route == 0 && !client ? lit_str("back")
                                                                               : outputs[route]));
            }
            CHECK_EQ(pool.in_use(), 1u);
            if (route == 3) CHECK_EQ(conn->json_arena.space_used(), 16u);
            if (route == 4) CHECK_EQ(conn->json_arena.space_used(), 8u);
        }
    }
    const Str invalid[] = {lit_str("{"), lit_str(R"({"x":1,"x":2})")};
    for (const auto input : invalid) {
        CHECK(config.routes[0].ws_frame_handler(conn.get(),
                                                WsOpcode::Text,
                                                reinterpret_cast<const u8*>(input.ptr),
                                                input.len,
                                                true) == WsFrameAction::CloseDynamic);
        CHECK_EQ(conn->ws_handler_output.close_code, 1007u);
    }
    conn->json_arena.destroy();
    u8* held[8]{};
    for (auto& slice : held) {
        slice = pool.alloc();
        REQUIRE(slice);
    }
    for (u32 route = 0; route < 5; ++route) {
        const auto input = inputs[route];
        const auto result = config.routes[route].ws_frame_handler(
            conn.get(), WsOpcode::Binary, reinterpret_cast<const u8*>(input.ptr), input.len, true);
        CHECK(result == (route == 4 ? WsFrameAction::Forward : WsFrameAction::CloseDynamic));
        CHECK_EQ(pool.in_use(), 8u);
    }
    for (auto* slice : held) pool.free(slice);
    conn->json_arena.destroy();
    pool.destroy();
}
#endif
}  // namespace rut::test::ws_general_json
