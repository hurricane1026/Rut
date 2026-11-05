#pragma once

#include "rut/common/types.h"
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"
#endif
#include <cstring>
#include <initializer_list>

namespace rut::test::ws_borrowed_binary {

inline constexpr char kSource[] = R"rut(upstream ws at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func payload(_ msg: WebSocketMessage) -> Bytes => msg.payload
func maybePayload(_ msg: WebSocketMessage) -> Bytes {
    if msg.fromClient { payload(msg) } else { nil }
}
func selected(_ msg: WebSocketMessage) -> Bytes {
    if msg.fromClient { msg.payload }
    else { if msg.isText { b"\x00\xff" } else { nil } }
}
route GET "/direct" { return websocket(ws) { msg in msg.forward(msg.payload) } }
route GET "/helper" { return websocket(ws) { msg in
    let packet = identity(msg)
    let bytes: Bytes = identity(payload(packet))
    packet.forward(bytes)
} }
route GET "/optional" { return websocket(ws) { msg in
    guard let bytes = maybePayload(msg) else { msg.drop() }
    msg.forward(bytes)
} }
route GET "/choice" { return websocket(ws) { msg in
    guard let bytes = selected(msg) else { msg.drop() }
    msg.forward(bytes)
} }
route GET "/guard" { return websocket(ws) { msg in
    guard !msg.fromClient else { msg.forward(payload(msg)) }
    msg.forward("server")
} }
)rut";

#if RUT_ENABLE_WEBSOCKET
template <typename Config>
void check(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 5u);
    for (u32 i = 0; i < 4; ++i)
        CHECK(config.routes[i].ws_forward_text.source == WsTextSource::MessageBytes);
    REQUIRE_EQ(config.routes[3].ws_forward_text_count, 1u);
    CHECK(config.routes[3].ws_forward_texts[0].source == WsTextSource::LiteralBinary);
    REQUIRE_EQ(config.routes[4].ws_forward_text_count, 1u);
    CHECK(config.routes[4].ws_forward_texts[0].source == WsTextSource::MessageBytes);
    const Str payloads[] = {{}, {"A\0B", 3}, {"\xc3\xa9", 2}, {"\0\xff", 2}};
    for (u32 i = 0; i < config.route_count; ++i) {
        const auto& route = config.routes[i];
        REQUIRE(route.ws_frame_handler);
        for (bool client : {false, true}) {
            for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
                for (Str bytes : payloads) {
                    if (op == WsOpcode::Text && !ws_valid_text_payload(bytes)) continue;
                    WsInspector st;
                    st.from_client = client;
                    st.max_message_size = route.ws_max_message_size;
                    st.forward_text = route.ws_forward_text;
                    st.forward_texts = route.ws_forward_texts;
                    st.forward_text_count = route.ws_forward_text_count;
                    u8 in[16] = {static_cast<u8>(0x80u | static_cast<u8>(op)),
                                 static_cast<u8>(bytes.len)};
                    if (bytes.len) memcpy(in + 2, bytes.ptr, bytes.len);
                    u8 out[32], msg[16];
                    u32 used = 0, produced = 0;
                    REQUIRE(ws_inspect(st,
                                       in,
                                       2 + bytes.len,
                                       out,
                                       sizeof(out),
                                       msg,
                                       sizeof(msg),
                                       route.ws_frame_handler,
                                       nullptr,
                                       &used,
                                       &produced) == WsInspectStatus::Ok);
                    CHECK_EQ(used, 2u + bytes.len);
                    if (!client && (i == 2 || (i == 3 && op == WsOpcode::Binary))) {
                        CHECK_EQ(produced, 0u);
                        continue;
                    }
                    const Str expected = !client && i == 3   ? Str{"\0\xff", 2}
                                         : !client && i == 4 ? lit_str("server")
                                                             : bytes;
                    REQUIRE_EQ(produced, 2u + expected.len);
                    CHECK_EQ(out[0], !client && i == 4 ? 0x81u : 0x82u);
                    CHECK_EQ(out[1], expected.len);
                    // The output must remain valid after the borrowed input is overwritten.
                    memset(in, 0xee, sizeof(in));
                    memset(msg, 0xee, sizeof(msg));
                    if (expected.len) CHECK(memcmp(out + 2, expected.ptr, expected.len) == 0);
                }
            }
        }
    }
}
#endif
}  // namespace rut::test::ws_borrowed_binary
