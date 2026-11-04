#pragma once
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include <memory>
#endif

namespace rut::test::ws_general_regex {
inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func accepted(_ value: str) -> bool => value.matches(re"a.*")
func path(_ client: bool) -> str { if client { "/name" } else { "/reply" } }
route GET "/local" {
    guard req.path.matches(re"/.*") else { return 403 }
    return websocket(ws) { msg in
    let allowed = accepted(msg.text)
    guard allowed else { msg.drop() }
    msg.forward(msg.payload)
} }
route GET "/json" { return websocket(ws) { msg in
    let pointer = path(msg.fromClient)
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let selected = json.get(root, pointer) else { msg.drop() }
    guard let text = json.string(selected) else { msg.drop() }
    let allowed = accepted(text)
    guard allowed else { msg.drop() }
    msg.forward(text)
} }
route GET "/number" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let number = json.numberText(root) else { msg.drop() }
    let allowed = number.matches(re"[0-9]+")
    guard allowed else { msg.drop() }
    msg.forward(number)
} }
route GET "/stringify" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let text = json.stringify(root) else { msg.drop() }
    let allowed = text.matches(re".*id.*")
    guard !allowed else { msg.drop() }
    msg.forward(text)
} }
route GET "/many" { return websocket(ws) { msg in
    guard msg.len >= 0 else { msg.drop() }
    guard msg.len < 999 else { msg.drop() }
    guard msg.isText || msg.isBinary else { msg.drop() }
    guard msg.payload.count == msg.len else { msg.drop() }
    guard !msg.fromClient || accepted(msg.text) else { msg.drop() }
    msg.forward()
} }
route GET "/unused" { return websocket(ws) { msg in
    let unused = accepted(msg.text)
    msg.forward()
} })rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(const Config& config, TestCase* _tc) {
    REQUIRE_EQ(config.route_count, 6u);
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto conn = std::make_unique<ConnectionBase>();
    REQUIRE(conn->json_arena.init(&pool));
    struct Case {
        u32 route;
        Str input;
        bool client;
        WsFrameAction action;
        Str output;
        WsOpcode opcode = WsOpcode::Text;
    };
    const Case cases[] = {
        {0, {"a\0\xff", 3}, true, WsFrameAction::ForwardDynamic, {"a\0\xff", 3}, WsOpcode::Binary},
        {0, lit_str("bad"), false, WsFrameAction::Drop, {}},
        {1,
         lit_str(R"({"name":"a\u0000b","reply":"answer"})"),
         true,
         WsFrameAction::ForwardDynamic,
         {"a\0b", 3}},
        {1,
         lit_str(R"({"name":"bad","reply":"answer"})"),
         false,
         WsFrameAction::ForwardDynamic,
         lit_str("answer")},
        {1, lit_str(R"({"name":"bad"})"), true, WsFrameAction::Drop, {}},
        {2, lit_str("1234"), true, WsFrameAction::ForwardDynamic, lit_str("1234")},
        {2, lit_str("-1"), false, WsFrameAction::Drop, {}},
        {3,
         lit_str(R"({"name":1})"),
         true,
         WsFrameAction::ForwardDynamic,
         lit_str(R"({"name":1})")},
        {3, lit_str(R"({"id":1})"), false, WsFrameAction::Drop, {}},
        {4, lit_str("allow"), true, WsFrameAction::Forward, {}},
        {4, lit_str("bad"), true, WsFrameAction::Drop, {}},
        {4, lit_str("bad"), false, WsFrameAction::Forward, {}},
        {5, lit_str("bad"), true, WsFrameAction::Forward, {}},
    };
    for (const auto& item : cases) {
        const auto handler = config.routes[item.route].ws_frame_handler;
        REQUIRE(handler);
        auto result = handler(conn.get(),
                              WsOpcode::Binary,
                              reinterpret_cast<const u8*>(item.input.ptr),
                              item.input.len,
                              item.client);
        CHECK(result == item.action);
        if (item.action == WsFrameAction::ForwardDynamic) {
            REQUIRE(conn->ws_handler_output.ready);
            CHECK(conn->ws_handler_output.payload.eq(item.output));
            CHECK(conn->ws_handler_output.opcode == item.opcode);
        }
    }
    conn->json_arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}
#endif
}  // namespace rut::test::ws_general_regex
