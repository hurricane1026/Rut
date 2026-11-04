#pragma once
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include <memory>
#endif

namespace rut::test::ws_helper_lexical {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func hashed(_ input: str) -> str {
    guard let hash = sha256(input) else { nil }
    let alias = hash
    if alias == hash { hash } else { nil }
}
func nested(_ input: str) -> str {
    guard let result = hashed(input) else { nil }
    result
}
func decoded(_ input: str) -> str {
    guard let root = json.parse(input) else { nil }
    guard let text = json.string(root) else { nil }
    let alias = text
    if alias == text { text } else { nil }
}
func ignored(_ input: str) -> str {
    let unused = sha256(input)
    "ok"
}
func selected(_ client: bool, _ input: str) -> str {
    if client { hashed(input) } else { "skip" }
}
func absent(_ input: str) -> str {
    let unused = sha256(input)
    nil
}
func same(_ value: str) -> bool => value == value
func choose(_ first: str, _ second: str) -> str => second
route GET "/hash" { return websocket(ws) { msg in
    guard let value = nested(msg.text) else { msg.close(1011) }
    msg.forward(value)
} }
route GET "/decoded" { return websocket(ws) { msg in
    guard let value = decoded(msg.text) else { msg.close(1007) }
    msg.forward(value)
} }
route GET "/unused" { return websocket(ws) { msg in msg.forward(ignored(msg.text)) } }
route GET "/selected" { return websocket(ws) { msg in
    guard let value = selected(msg.fromClient, msg.text) else { msg.close(1011) }
    msg.forward(value)
} }
route GET "/absent" { return websocket(ws) { msg in
    guard let value = absent(msg.text) else { msg.forward("absent") }
    msg.forward(value)
} }
route GET "/argument" { return websocket(ws) { msg in
    guard same(sha256(msg.text).or("missing")) else { msg.drop() }
    msg.forward()
} }
route GET "/arguments" { return websocket(ws) { msg in
    msg.forward(choose(sha256(msg.text).or("first"), sha256(msg.text).or("second")))
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(const Config& config, TestCase* _tc) {
    REQUIRE_EQ(config.route_count, 7u);
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto conn = std::make_unique<ConnectionBase>();
    REQUIRE(conn->json_arena.init(&pool));
    const Str hash = lit_str("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    for (u32 route = 0; route < 7; ++route) {
        const Str input = route == 1 ? lit_str(R"("a\u0000b")") : lit_str("abc");
        const auto handler = config.routes[route].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            auto result = handler(conn.get(),
                                  WsOpcode::Binary,
                                  reinterpret_cast<const u8*>(input.ptr),
                                  input.len,
                                  client);
            CHECK(result == (route == 5 ? WsFrameAction::Forward : WsFrameAction::ForwardDynamic));
            const u32 bytes = route == 1 ? 8 : route == 3 && !client ? 0 : route == 6 ? 128 : 64;
            CHECK_EQ(conn->json_arena.space_used(), bytes);
            if (route == 5) continue;
            REQUIRE(conn->ws_handler_output.ready);
            CHECK(conn->ws_handler_output.opcode == WsOpcode::Text);
            const Str expected = route == 1              ? Str{"a\0b", 3}
                                 : route == 2            ? lit_str("ok")
                                 : route == 3 && !client ? lit_str("skip")
                                 : route == 4            ? lit_str("absent")
                                                         : hash;
            CHECK(conn->ws_handler_output.payload.eq(expected));
        }
    }
    conn->json_arena.destroy();
    u8* held[8]{};
    for (auto& slice : held) {
        slice = pool.alloc();
        REQUIRE(slice);
    }
    for (u32 route : {0u, 2u, 3u, 4u, 5u, 6u}) {
        const auto result = config.routes[route].ws_frame_handler(
            conn.get(), WsOpcode::Binary, reinterpret_cast<const u8*>("abc"), 3, true);
        CHECK(result == (route == 0 || route == 3 ? WsFrameAction::CloseDynamic
                         : route == 5             ? WsFrameAction::Forward
                                                  : WsFrameAction::ForwardDynamic));
        CHECK_EQ(pool.in_use(), 8u);
    }
    for (auto* slice : held) pool.free(slice);
    conn->json_arena.destroy();
    pool.destroy();
}
#endif
}  // namespace rut::test::ws_helper_lexical
