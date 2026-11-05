#pragma once

#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_terminate.h"
#include <initializer_list>
#include <memory>
#endif

namespace rut::test::ws_eager_bindings {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
route GET "/once" { return websocket(ws) { msg in
    let token = uuid()
    guard let first = token else { msg.close() }
    guard let second = token else { msg.close() }
    guard same(first, second) else { msg.drop() }
    msg.forward()
} }
route GET "/unused" { return websocket(ws) { msg in
    let unused = uuid()
    msg.forward()
} }
route GET "/conditional" { return websocket(ws) { msg in
    if msg.fromClient { let unused = uuid() msg.forward() }
    else { msg.forward() }
} }
route GET "/distinct" { return websocket(ws) { msg in
    let first = uuid()
    let second = uuid()
    guard let a = first else { msg.close() }
    guard let b = second else { msg.close() }
    guard same(a, b) else { msg.drop() }
    msg.forward()
} })rut";

#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(const Config& config, TestCase* _tc) {
    REQUIRE_EQ(config.route_count, 4u);
    const auto once = config.routes[0].ws_frame_handler;
    const auto unused = config.routes[1].ws_frame_handler;
    const auto conditional = config.routes[2].ws_frame_handler;
    const auto distinct = config.routes[3].ws_frame_handler;
    REQUIRE(once && unused && conditional && distinct);
    CHECK(once(nullptr, WsOpcode::Text, nullptr, 0, true) == WsFrameAction::Close);
    CHECK(unused(nullptr, WsOpcode::Text, nullptr, 0, true) == WsFrameAction::Forward);
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto connection = std::make_unique<ConnectionBase>();
    REQUIRE(connection->json_arena.init(&pool));
    for (bool client : {false, true}) {
        CHECK(distinct(connection.get(), WsOpcode::Text, nullptr, 0, client) ==
              WsFrameAction::Drop);
        CHECK(once(connection.get(), WsOpcode::Text, nullptr, 0, client) == WsFrameAction::Forward);
        CHECK_EQ(pool.in_use(), 1u);
        CHECK(unused(connection.get(), WsOpcode::Text, nullptr, 0, client) ==
              WsFrameAction::Forward);
        CHECK_EQ(pool.in_use(), 1u);
        CHECK(conditional(connection.get(), WsOpcode::Binary, nullptr, 0, client) ==
              WsFrameAction::Forward);
        CHECK_EQ(pool.in_use(), client ? 1u : 0u);
    }
    connection->json_arena.destroy();
    // Failure consumes no extra slice and cannot release unrelated send storage.
    u8* held[8]{};
    for (u32 i = 0; i < 8; ++i) {
        held[i] = pool.alloc();
        REQUIRE(held[i]);
        held[i][0] = static_cast<u8>(i + 1);
    }
    CHECK(once(connection.get(), WsOpcode::Text, nullptr, 0, true) == WsFrameAction::Close);
    CHECK(unused(connection.get(), WsOpcode::Text, nullptr, 0, true) == WsFrameAction::Forward);
    CHECK_EQ(pool.in_use(), 8u);
    for (u32 i = 0; i < 8; ++i) {
        CHECK_EQ(held[i][0], i + 1);
        pool.free(held[i]);
    }
    connection->json_arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}
#endif
}  // namespace rut::test::ws_eager_bindings
