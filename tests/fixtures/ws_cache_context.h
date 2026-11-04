#pragma once
#include "ws_callback_probe.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/cache_table.h"
#endif
namespace rut::test::ws_cache_context {
inline constexpr char kSource[] = R"rut(let counts = Cache<IP, i64>(capacity: 64)
upstream ws at "127.0.0.1:9999"
func counterExists(_ key: IP) -> bool => counts.get(key) != nil
route GET "/ws" { return websocket(ws) { msg in
    guard msg.text != "skip" else { msg.drop() }
    let key = msg.connection.remoteAddr
    let before = counts.get(key).or(0)
    counts.set(key, before + 1)
    if before < 2 { msg.forward() } else { msg.drop() }
} }
route GET "/selected" { return websocket(ws) { msg in
    let key = msg.connection.remoteAddr
    if msg.fromClient {
        guard msg.text != "skip" else { msg.drop() }
        counts.set(key, 77)
        msg.forward()
    } else { msg.forward() }
} }
route GET "/clock" { return websocket(ws) { msg in
    let first = time.nowMicros()
    let unused = sha256(msg.text)
    guard first == time.nowMicros() else { msg.close(1011) }
    if first < 1000 { msg.forward("early") } else { msg.forward("late") }
} }
route GET "/optional" { return websocket(ws) { msg in
    let key = msg.connection.remoteAddr
    guard counterExists(key) else { msg.forward("missing") }
    guard let value = counts.get(key) else { msg.forward("missing") }
    if value == 0 { msg.forward("zero") } else { msg.forward("present") }
} }
)rut";
inline constexpr char kReorderedSource[] = R"rut(let other = Cache<IP, i64>(capacity: 64)
let counts = Cache<IP, i64>(capacity: 64)
upstream ws at "127.0.0.1:9999"
route GET "/seed" { return websocket(ws) { msg in
    other.set(msg.connection.remoteAddr, 500)
    counts.set(msg.connection.remoteAddr, 0)
    msg.forward()
} }
)rut";
#if RUT_ENABLE_WEBSOCKET
template <typename Config, typename Activate>
void check(TestCase* _tc, const Config& config, const Config& reordered, Activate activate) {
    REQUIRE_EQ(config.route_count, 4u);
    rut_helper_cache_reset_local_state();
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    constexpr u32 kKey = 0x01020304u;
    probe.conn->peer_addr = kKey;
    const auto call =
        [&](u32 route, bool client, Str text, WsFrameAction expected, Str output = {}) {
            probe.expect(_tc,
                         config.routes[route].ws_frame_handler,
                         WsOpcode::Text,
                         text,
                         client,
                         expected,
                         output);
        };
    const auto value_at = [&](u32 slot, bool present, i64 expected) {
        u8 has = 0;
        i64 value = 0;
        rut_helper_cache_get(slot, kKey, &has, &value);
        CHECK_EQ(has, present ? 1 : 0);
        if (present) CHECK_EQ(value, expected);
    };
    call(0, true, lit_str("skip"), WsFrameAction::Drop);
    value_at(0, false, 0);
    call(3, true, lit_str("read"), WsFrameAction::ForwardText, lit_str("missing"));
    for (u32 attempt = 0; attempt < 4; ++attempt)
        call(0,
             attempt % 2 == 0,
             lit_str("count"),
             attempt < 2 ? WsFrameAction::Forward : WsFrameAction::Drop);
    value_at(0, true, 4);
    call(1, false, lit_str("set"), WsFrameAction::Forward);
    value_at(0, true, 4);
    call(1, true, lit_str("skip"), WsFrameAction::Drop);
    value_at(0, true, 4);
    call(1, true, lit_str("set"), WsFrameAction::Forward);
    value_at(0, true, 77);

    const u32 caps[] = {64, 64};
    const u64 names[] = {cache_instance_identity("other", 5), cache_instance_identity("counts", 6)};
    // Activate a genuinely recompiled configuration while the old callbacks
    // remain alive. Its handler seeds both declarations through compiled writes.
    activate();
    REQUIRE_EQ(reordered.route_count, 1u);
    probe.expect(_tc,
                 reordered.routes[0].ws_frame_handler,
                 WsOpcode::Text,
                 lit_str("seed"),
                 true,
                 WsFrameAction::Forward);
    call(3, true, lit_str("read"), WsFrameAction::ForwardText, lit_str("zero"));
    call(0, true, lit_str("count"), WsFrameAction::Forward);
    value_at(0, true, 500);
    value_at(1, true, 1);
    call(3, false, lit_str("read"), WsFrameAction::ForwardText, lit_str("present"));
    call(0, false, lit_str("count"), WsFrameAction::Forward);
    call(0, true, lit_str("count"), WsFrameAction::Drop);
    value_at(0, true, 500);
    value_at(1, true, 3);
    cache_registry_publish(caps, names, 1);  // old handler's counts declaration removed
    call(3, true, lit_str("read"), WsFrameAction::ForwardText, lit_str("missing"));
    call(0, true, lit_str("count"), WsFrameAction::Forward);
    value_at(0, true, 500);
    cache_registry_publish(caps, names, 2);
    value_at(1, false, 0);
    call(0, true, lit_str("count"), WsFrameAction::Forward);
    value_at(1, true, 1);

    u64 clock = 500;
    struct RestoreClock {
        const u64* previous;
        ~RestoreClock() { rut_helper_time_set_virtual_clock(previous); }
    } restore{rut_helper_time_set_virtual_clock(&clock)};
    call(2, true, lit_str("time"), WsFrameAction::ForwardText, lit_str("early"));
    clock = 1500;  // change the provider, without explicitly unlatching its cached value
    call(2, false, lit_str("time"), WsFrameAction::ForwardText, lit_str("late"));
    clock = 500;
    call(2, true, lit_str("time"), WsFrameAction::ForwardText, lit_str("early"));
    rut_helper_cache_reset_local_state();
}
#endif
}  // namespace rut::test::ws_cache_context
