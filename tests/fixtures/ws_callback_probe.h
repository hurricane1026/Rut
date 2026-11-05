#pragma once
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/connection_base.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_terminate.h"
#include <memory>

namespace rut::test {
// General callbacks need their real arena/publication context. Check observable
// bytes instead of requiring a particular specialized policy-table layout.
struct WsCallbackProbe {
    SlicePool pool;
    std::unique_ptr<ConnectionBase> conn = std::make_unique<ConnectionBase>();
    bool init() { return pool.init(8) && conn->json_arena.init(&pool); }
    ~WsCallbackProbe() {
        conn->json_arena.destroy();
        pool.destroy();
    }

    void expect(TestCase* _tc,
                WsMessageHandlerFn handler,
                WsOpcode op,
                Str input,
                bool client,
                WsFrameAction expected,
                Str payload = {},
                WsOpcode output_opcode = WsOpcode::Text,
                u16 code = 1000,
                Str reason = {}) {
        REQUIRE(handler);
        const auto action =
            handler(conn.get(), op, reinterpret_cast<const u8*>(input.ptr), input.len, client);
        const auto& output = conn->ws_handler_output;
        if (action == WsFrameAction::ForwardDynamic) {
            CHECK(expected == WsFrameAction::ForwardText ||
                  (expected >= WsFrameAction::ForwardTextPolicy0 &&
                   expected <= WsFrameAction::ForwardTextPolicy3));
            REQUIRE(output.ready);
            CHECK(output.opcode == output_opcode);
            CHECK(output.payload.eq(payload));
        } else if (action == WsFrameAction::CloseDynamic) {
            CHECK(expected == WsFrameAction::Close || (expected >= WsFrameAction::ClosePolicy0 &&
                                                       expected <= WsFrameAction::ClosePolicy3));
            REQUIRE(output.ready);
            CHECK_EQ(output.close_code, code);
            CHECK(output.payload.eq(reason));
        } else {
            CHECK(action == expected);
        }
    }
};
}  // namespace rut::test
#endif
