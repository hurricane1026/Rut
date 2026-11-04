#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/verifier.h"
#include "test.h"
#include <memory>
#include <string>
#include <utility>

#if RUT_ENABLE_JIT
#include "fixtures/ws_callback_probe.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/serve_loader.h"
#include <cstdlib>

#include <fcntl.h>
#include <unistd.h>
#endif

using namespace rut;

#if RUT_ENABLE_WEBSOCKET
namespace {
constexpr char kSource[] = R"rut(
let counts = Cache<IP, i64>(capacity: 64)
upstream ws at "127.0.0.1:9999"
func peer(_ c: WebSocketConnection) -> IP => c.remoteAddr
func status(_ closed: WebSocketClose) -> i32 => closed.code
route GET "/ws" {
 return websocket(ws) { msg in
  if counts.get(msg.connection.remoteAddr).or(0) == 11 { msg.forward() }
  else { msg.drop() }
 }
 onOpen: { connection in
  guard connection.remotePort > 0 else { connection.close(1008, "port") }
  let key = peer(connection)
  if connection.isTls { counts.set(key, 10) }
  match connection.isTls {
   true => counts.set(key, 10)
   false => counts.set(key, 0)
  }
  counts.set(key, counts.get(key).or(0) + 1)
 }
 onClose: { closed in
  let key = peer(closed.connection)
  if closed.wasClean && status(closed) == 3001 && closed.upstreamCode == 3002 {
   guard closed.reason == "ack" && closed.upstreamReason == "ack" else { return }
   counts.set(key, counts.get(key).or(0) + 100)
  }
 }
}
route GET "/read" { return websocket(ws) { msg in
 if counts.get(msg.connection.remoteAddr).or(0) == 111 { msg.forward() } else { msg.drop() }
} }
)rut";

void check_hooks(test::TestCase* _tc, const HirModule& module, u32 route_count = 2) {
    REQUIRE_EQ(module.routes.len, route_count);
    const auto& route = module.routes[0];
    const u32 roots[] = {route.ws_handler.open_body_expr, route.ws_handler.close_body_expr};
    const WsCallbackPhase phases[] = {WsCallbackPhase::Open, WsCallbackPhase::Close};
    for (u32 i = 0; i < 2; ++i) {
        REQUIRE(roots[i] < route.exprs.len);
        auto callback = std::make_unique<HirRoute>();
        callback->is_ws_callback = true;
        callback->ws_callback_phase = phases[i];
        HirLocal result{};
        result.type = HirTypeKind::I32;
        result.ref_index = 0;
        result.is_runtime_synthetic = true;
        result.init = route.exprs[roots[i]];
        REQUIRE(callback->locals.push(result));
        callback->control.kind = HirControlKind::Direct;
        callback->control.direct_term.kind = HirTerminatorKind::ReturnStatus;
        callback->control.direct_term.source_kind = HirTerminatorSourceKind::LocalRef;
        callback->control.direct_term.local_ref_index = 0;
        auto copy = std::make_unique<HirRoute>(*callback);
        callback.reset();
        auto assigned = std::make_unique<HirRoute>();
        *assigned = *copy;
        copy.reset();
        auto moved = std::make_unique<HirRoute>(std::move(*assigned));
        assigned.reset();
        copy = std::make_unique<HirRoute>();
        *copy = std::move(*moved);
        moved.reset();
        REQUIRE(copy->ws_callback_phase == phases[i]);
        auto built = build_mir_route(module, *copy);
        REQUIRE(built);
        std::unique_ptr<MirModule> mir(built.value());
        FrontendRirModule rir{};
        REQUIRE(lower_to_rir(*mir, rir));
        CHECK(rir::verify_module(rir.module).ok);
        rir.destroy();
        copy->ws_callback_phase = WsCallbackPhase::Message;
        auto forged = build_mir_route(module, *copy);
        if (forged) delete forged.value();
        CHECK_FALSE(forged);
    }
}
}  // namespace

TEST(ws_lifecycle, callback_roots_survive_all_ast_ownership_transfers) {
    auto tokens = lex(lit_str(kSource));
    REQUIRE(tokens);
    auto parsed = parse_file(tokens.value());
    REQUIRE(parsed);
    auto source = std::unique_ptr<AstFile>(parsed.value());
    auto copied = std::make_unique<AstFile>(*source);
    source.reset();
    auto assigned = std::make_unique<AstFile>();
    *assigned = *copied;
    copied.reset();
    auto moved = std::make_unique<AstFile>(std::move(*assigned));
    assigned.reset();
    auto final = std::make_unique<AstFile>();
    *final = std::move(*moved);
    moved.reset();
    auto analyzed = analyze_file(*final);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    final.reset();
    auto owned_hir = std::make_unique<HirModule>(*hir);
    hir.reset();
    check_hooks(_tc, *owned_hir);
}

TEST(ws_lifecycle, sequential_conditions_keep_bounded_shared_control_flow) {
    std::string source =
        "let counts = Cache<IP, i64>(capacity: 64)\nupstream ws\nroute GET \"/\" { return "
        "websocket(ws) { msg in msg.forward() } onOpen: { c in let key = c.remoteAddr\n";
    for (u32 i = 0; i < 7; ++i)
        source += "if c.remotePort > 0 { counts.set(key, counts.get(key).or(0) + 1) }\n";
    source += "} onClose: { c in guard c.wasClean else { return } } }";
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto parsed = parse_file(tokens.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    auto result = analyze_file(*ast);
    REQUIRE(result);
    std::unique_ptr<HirModule> module(result.value());
    CHECK(module->routes[0].exprs.len < 4096u);
    CHECK(module->routes[0].ws_handler.open_body_expr < module->routes[0].exprs.len);
    check_hooks(_tc, *module, 1);
}

TEST(ws_lifecycle, phase_and_lifetime_errors_are_rejected) {
    const char* invalid[] = {
        "{ msg in msg.forward() } onOpen: { c in c.forward() }",
        "{ msg in msg.forward() } onOpen: { c in let value = c.text }",
        "{ msg in msg.forward() } onOpen: { c in let value = req.remoteAddr }",
        "{ msg in msg.forward() } onClose: { c in c.close() }",
        "{ msg in msg.forward() } onClose: { c in let value = c.payload }",
        "{ msg in msg.forward() } onClose: { c in let value = c.connection.kind }",
        "{ msg in msg.forward() } onOpen: { c in guard c.isTls else { } }",
        "{ msg in msg.forward() } onOpen: { c in } onOpen: { c in }",
        "{ msg in msg.forward() } onFinish: { c in }",
        "{ msg in return }",
        "{ msg in msg.forward() } onClose: { c in return 200 }",
        "{ msg in msg.forward() } onOpen: { c in c.close(1006) }",
    };
    for (const char* body : invalid) {
        const std::string source =
            std::string("upstream ws\nroute GET \"/\" { return websocket(ws) ") + body + " }";
        auto tokens = lex({source.data(), static_cast<u32>(source.size())});
        REQUIRE(tokens);
        auto parsed = parse_file(tokens.value());
        if (!parsed) continue;
        std::unique_ptr<AstFile> ast(parsed.value());
        auto result = analyze_file(*ast);
        if (result) delete result.value();
        CHECK_FALSE(result);
    }
}

#if RUT_ENABLE_JIT
TEST(ws_lifecycle, compiled_callbacks_share_ordinary_concepts_and_preserve_close_facts) {
    const char* temp = getenv("TMPDIR");
    std::string path = std::string(temp ? temp : "/tmp") + "/rut-ws-lifecycle-XXXXXX";
    const int kFd = mkstemp(path.data());
    REQUIRE(kFd >= 0);
    REQUIRE_EQ(write(kFd, kSource, sizeof(kSource) - 1), static_cast<ssize_t>(sizeof(kSource) - 1));
    close(kFd);
    struct ProgramOwner {
        LoadedProgram program;
        ~ProgramOwner() { program.destroy(); }
    } owner;
    LoadError error;
    const bool kLoaded = load_rut_program(path.c_str(), owner.program, error);
    unlink(path.c_str());
    if (!kLoaded) {
        char diagnostic[1024];
        format_load_error(error, diagnostic, sizeof(diagnostic));
        fprintf(stderr, "%s\n", diagnostic);
    }
    REQUIRE(kLoaded);
    activate_rut_program(owner.program);
    struct ResetCache {
        ~ResetCache() { rut_helper_cache_reset_local_state(); }
    } reset;
    test::WsCallbackProbe probe;
    REQUIRE(probe.init());
    auto& route = owner.program.config.routes[0];
    REQUIRE(route.ws_open_handler);
    REQUIRE(route.ws_close_handler);
    probe.conn->peer_addr = 0x0100007fu;
    probe.conn->peer_port = 43210;
    probe.conn->tls_active = true;
    CHECK(route.ws_open_handler(probe.conn.get(), WsOpcode::Text, nullptr, 0, true) ==
          WsFrameAction::Drop);
    probe.expect(_tc,
                 route.ws_frame_handler,
                 WsOpcode::Text,
                 lit_str("after open"),
                 true,
                 WsFrameAction::Forward);
    probe.conn->peer_addr = 0x0200007fu;
    probe.conn->tls_active = false;
    CHECK(route.ws_open_handler(probe.conn.get(), WsOpcode::Text, nullptr, 0, true) ==
          WsFrameAction::Drop);
    u8 present = 0;
    i64 value = 0;
    rut_helper_cache_get(0, probe.conn->peer_addr, &present, &value);
    CHECK_EQ(present, 1u);
    CHECK_EQ(value, 1);
    probe.conn->peer_addr = 0x0100007fu;
    probe.conn->tls_active = true;
    probe.conn->ws_c2u.received_close = true;
    probe.conn->ws_c2u.echo_close_code = 3001;
    REQUIRE(probe.conn->ws_c2u.set_echo_close_reason(lit_str("ack")));
    REQUIRE(probe.conn->ws_record_peer_close(true, probe.conn->ws_c2u));
    probe.conn->ws_u2c.received_close = true;
    probe.conn->ws_u2c.echo_close_code = 3002;
    REQUIRE(probe.conn->ws_u2c.set_echo_close_reason(lit_str("ack")));
    REQUIRE(probe.conn->ws_record_peer_close(false, probe.conn->ws_u2c));
    probe.conn->ws_c2u.reset();
    probe.conn->ws_u2c.reset();
    probe.conn->ws_close_handshake_complete = true;
    CHECK(route.ws_close_handler(probe.conn.get(), WsOpcode::Text, nullptr, 0, true) ==
          WsFrameAction::Drop);
    probe.expect(_tc,
                 owner.program.config.routes[1].ws_frame_handler,
                 WsOpcode::Text,
                 lit_str("after close"),
                 true,
                 WsFrameAction::Forward);
    probe.conn->peer_port = 0;
    probe.expect(_tc,
                 route.ws_open_handler,
                 WsOpcode::Text,
                 {},
                 true,
                 WsFrameAction::Close,
                 {},
                 WsOpcode::Text,
                 1008,
                 lit_str("port"));
}
#endif
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
