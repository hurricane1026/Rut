#pragma once
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include <initializer_list>
#include <memory>
#endif

namespace rut::test::ws_hash_output {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
route GET "/guard" { return websocket(ws) { msg in
    guard let digest = sha256(msg.text) else { msg.close() }
    msg.forward(digest)
} }
route GET "/if" { return websocket(ws) { msg in
    if let digest = sha256(msg.text) { msg.forward(digest) }
    else { msg.close() }
} }
route GET "/let" { return websocket(ws) { msg in
    let pending = sha256(msg.text)
    guard let first = pending else { msg.close() }
    guard let second = pending else { msg.close() }
    guard first == second else { msg.drop() }
    msg.forward(first)
} }
route GET "/hmac" { return websocket(ws) { msg in
    guard let digest = hmacSha256("key", msg.text) else { msg.close() }
    msg.forward(digest)
} }
route GET "/skip" { return websocket(ws) { msg in
    if msg.fromClient { msg.forward() }
    else {
        guard let digest = sha256(msg.text) else { msg.close() }
        msg.forward(digest)
    }
} })rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(const Config& config, TestCase* _tc) {
    REQUIRE_EQ(config.route_count, 5u);
    SlicePool pool;
    REQUIRE(pool.init(4));
    auto conn = std::make_unique<ConnectionBase>();
    REQUIRE(conn->json_arena.init(&pool));
    const u8 input[] = {'a', 0, 'b'};
    const Str hash = lit_str("59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138");
    const Str hmac = lit_str("29c5f0eea2d0a51b661193b3a56191192b2861f543ea0499a7f9725f7e7062fc");
    for (u32 route = 0; route < 5; ++route) {
        const auto handler = config.routes[route].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            const bool kSkipped = route == 4 && client;
            CHECK(handler(conn.get(), WsOpcode::Binary, input, 3, client) ==
                  (kSkipped ? WsFrameAction::Forward : WsFrameAction::ForwardDynamic));
            CHECK_EQ(conn->json_arena.space_used(), kSkipped ? 0u : 64u);
            CHECK_EQ(pool.in_use(), kSkipped ? 0u : 1u);
            if (!kSkipped) {
                REQUIRE(conn->ws_handler_output.ready);
                CHECK(conn->ws_handler_output.payload.eq(route == 3 ? hmac : hash));
            }
            CHECK(handler(nullptr, WsOpcode::Text, input, 3, client) ==
                  (kSkipped ? WsFrameAction::Forward : WsFrameAction::Close));
        }
    }
    conn->json_arena.destroy();
    u8* held[4]{};
    for (auto& slice : held) {
        slice = pool.alloc();
        REQUIRE(slice);
    }
    for (u32 route = 0; route < 5; ++route) {
        CHECK(config.routes[route].ws_frame_handler(
                  conn.get(), WsOpcode::Binary, input, 3, false) == WsFrameAction::Close);
        CHECK_FALSE(conn->ws_handler_output.ready);
        CHECK_EQ(pool.in_use(), 4u);
    }
    for (auto* slice : held) pool.free(slice);
    conn->json_arena.destroy();
    pool.destroy();
}
#endif
}  // namespace rut::test::ws_hash_output
