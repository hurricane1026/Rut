#pragma once
#include "ws_callback_probe.h"
#if RUT_ENABLE_WEBSOCKET
namespace rut::test::ws_helper_observables {
template <typename Config>
void choices(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 6u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const auto expect = [&](u32 route,
                                    Str input,
                                    WsFrameAction action,
                                    Str output = {},
                                    WsOpcode output_op = WsOpcode::Text,
                                    u16 code = 1000,
                                    Str reason = {}) {
                probe.expect(_tc,
                             config.routes[route].ws_frame_handler,
                             op,
                             input,
                             client,
                             action,
                             output,
                             output_op,
                             code,
                             reason);
            };
            expect(0,
                   lit_str(R"({"a":"okA","b":"okB"})"),
                   client ? WsFrameAction::ForwardText : WsFrameAction::ForwardTextPolicy0,
                   client ? lit_str("<okA>") : lit_str("<okB>"));
            expect(0,
                   lit_str(R"({"a":"","b":"noB"})"),
                   client ? WsFrameAction::ClosePolicy0 : WsFrameAction::ClosePolicy1,
                   {},
                   WsOpcode::Text,
                   1008);
            for (Str input : {lit_str(R"({"b":"okB"})"), lit_str(R"({"a":null,"b":"okB"})")})
                expect(0,
                       input,
                       client ? WsFrameAction::Drop : WsFrameAction::ForwardTextPolicy0,
                       lit_str("<okB>"));
            expect(0, lit_str("broken"), WsFrameAction::Drop);
            expect(0,
                   lit_str(R"({"a":"okA","b":false})"),
                   client ? WsFrameAction::ForwardText : WsFrameAction::Drop,
                   lit_str("<okA>"));
            const Str branches[] = {lit_str(R"({"a":"A","b":"B"})"),
                                    lit_str(R"({"a":"","b":""})"),
                                    lit_str(R"({"b":"B"})"),
                                    lit_str("broken")};
            for (u32 i = 0; i < 4; ++i) {
                const bool present = i < 2 || (i == 2 && !client);
                const Str output = !present ? lit_str("absent")
                                   : i == 1 ? lit_str("")
                                   : client ? lit_str("A")
                                            : lit_str("B");
                expect(1,
                       branches[i],
                       present ? client ? WsFrameAction::ForwardTextPolicy0
                                        : WsFrameAction::ForwardTextPolicy1
                               : WsFrameAction::ForwardText,
                       output);
            }
            const Str alternatives[] = {lit_str(R"({"a":"A","b":"B"})"),
                                        lit_str(R"({"b":"B"})"),
                                        lit_str(R"({"a":null,"b":"B"})"),
                                        lit_str(R"({"a":false,"b":"B"})"),
                                        lit_str(R"({"a":"","b":"B"})")};
            for (u32 i = 0; i < 5; ++i) {
                const bool present = i == 0 || i == 1 || i == 4;
                const Str value = i == 0 ? lit_str("A") : i == 1 ? lit_str("B") : lit_str("");
                expect(3,
                       alternatives[i],
                       i == 1    ? WsFrameAction::ForwardTextPolicy0
                       : present ? WsFrameAction::ForwardText
                                 : WsFrameAction::Drop,
                       value);
                const auto action = !client                  ? WsFrameAction::ForwardText
                                    : i == 1                 ? WsFrameAction::ForwardTextPolicy1
                                    : present                ? WsFrameAction::ForwardTextPolicy0
                                    : op == WsOpcode::Binary ? WsFrameAction::ForwardTextPolicy2
                                                             : WsFrameAction::Drop;
                expect(2,
                       alternatives[i],
                       action,
                       !client   ? lit_str("server")
                       : present ? value
                                 : Str{"\xff", 1},
                       client && !present ? WsOpcode::Binary : WsOpcode::Text);
            }
            const Str scalars[] = {lit_str("\"\""),
                                   lit_str("\"ok\""),
                                   lit_str("0"),
                                   lit_str("1.2300e+999"),
                                   lit_str("null")};
            for (u32 i = 0; i < 5; ++i)
                expect(5,
                       scalars[i],
                       i < 2   ? WsFrameAction::ForwardText
                       : i < 4 ? WsFrameAction::ForwardTextPolicy0
                               : WsFrameAction::Drop,
                       i == 0   ? lit_str("")
                       : i == 1 ? lit_str("ok")
                                : scalars[i]);
            expect(4,
                   lit_str(R"({"a":"okA","b":"okB"})"),
                   client ? WsFrameAction::Close : WsFrameAction::ClosePolicy0,
                   {},
                   WsOpcode::Text,
                   1008,
                   lit_str("policy"));
            expect(4, lit_str("broken"), WsFrameAction::Close);
        }
    }
}

template <typename Config>
void bindings(TestCase* _tc, const Config& config) {
    REQUIRE_EQ(config.route_count, 5u);
    WsCallbackProbe probe;
    REQUIRE(probe.init());
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const auto expect =
                [&](u32 route, Str input, WsFrameAction action, Str output = {}, u16 code = 1000) {
                    probe.expect(_tc,
                                 config.routes[route].ws_frame_handler,
                                 op,
                                 input,
                                 client,
                                 action,
                                 output,
                                 WsOpcode::Text,
                                 code);
                };
            const Str names[] = {lit_str(R"({"name":"a\u0000b"})"),
                                 lit_str(R"({"name":""})"),
                                 lit_str("{}"),
                                 lit_str(R"({"name":false})"),
                                 lit_str("broken")};
            for (u32 i = 0; i < 5; ++i)
                expect(0,
                       names[i],
                       i < 2 ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText,
                       i == 0   ? Str{"<a\0b>", 5}
                       : i == 1 ? lit_str("<>")
                                : lit_str("absent"));
            const Str flags[] = {lit_str(R"({"flag":false})"),
                                 lit_str(R"({"flag":true})"),
                                 lit_str(R"({"flag":null})"),
                                 lit_str("{}"),
                                 lit_str("broken")};
            for (u32 i = 0; i < 5; ++i)
                expect(1,
                       flags[i],
                       i == 0   ? WsFrameAction::ForwardTextPolicy0
                       : i == 1 ? WsFrameAction::ForwardTextPolicy1
                                : WsFrameAction::ForwardText,
                       i == 0   ? lit_str("false")
                       : i == 1 ? lit_str("true")
                                : lit_str("absent"));
            const Str roots[] = {lit_str("\"\""),
                                 lit_str("\"ok\""),
                                 lit_str("null"),
                                 lit_str("false"),
                                 lit_str("broken")};
            for (u32 i = 0; i < 5; ++i)
                expect(2,
                       roots[i],
                       i < 2    ? WsFrameAction::ForwardText
                       : i == 4 ? WsFrameAction::ClosePolicy0
                                : WsFrameAction::Drop,
                       i == 0 ? lit_str("") : lit_str("ok"),
                       1007);
            const Str paths[] = {lit_str(R"({"a/b":{"~":"ok"}})"),
                                 lit_str(R"({"a/b":{"~":""}})"),
                                 lit_str("{}"),
                                 lit_str(R"({"a/b":{"~":false}})")};
            for (u32 i = 0; i < 4; ++i)
                expect(3,
                       paths[i],
                       i < 2 ? WsFrameAction::ForwardText : WsFrameAction::Drop,
                       i == 0 ? lit_str("ok") : lit_str(""));
            const Str seconds[] = {lit_str(R"({"a":null,"b":"second"})"),
                                   lit_str(R"({"a":"first","b":""})"),
                                   lit_str(R"({"b":"second"})"),
                                   lit_str(R"({"a":null,"b":false})")};
            for (u32 i = 0; i < 4; ++i)
                expect(4,
                       seconds[i],
                       i < 2 ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText,
                       i == 0   ? lit_str("second")
                       : i == 1 ? lit_str("")
                                : lit_str("absent"));
        }
    }
}
}  // namespace rut::test::ws_helper_observables
#endif
