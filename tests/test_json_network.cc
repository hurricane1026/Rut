#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/jit/codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/compile_to_config.h"
#include "test.h"
#include "test_helpers.h"
#include <memory>
#include <string>

using namespace rut;

struct JsonProgram {
    std::unique_ptr<AstFile> ast;
    std::unique_ptr<HirModule> hir;
    std::unique_ptr<MirModule> mir;
    FrontendRirModule rir{};
    jit::JitEngine engine;
    std::unique_ptr<RouteConfig> config = std::make_unique<RouteConfig>();
    bool init() {
        const Str source = lit_str(R"rut(
route POST "/json" {
    guard let doc = req.bodyJson() else { return 400 }
    return response(200, body: doc)
}
)rut");
        auto tokens = lex(source);
        if (!tokens) return false;
        auto a = parse_file(tokens.value());
        if (!a) return false;
        ast.reset(a.value());
        auto h = analyze_file(*ast);
        if (!h) return false;
        hir.reset(h.value());
        auto m = build_mir(*hir);
        if (!m) return false;
        mir.reset(m.value());
        if (!lower_to_rir(*mir, rir)) return false;
        auto cg = jit::codegen(rir.module);
        if (!cg.ok || !engine.init() || !engine.compile(cg.mod, cg.ctx)) return false;
        return populate_route_config(*config, rir.module) &&
               register_jit_routes(*config, rir.module, engine);
    }
    jit::HandlerFn handler() {
        return reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    }
    ~JsonProgram() {
        engine.shutdown();
        rir.destroy();
    }
};

TEST(json_network, http1_json_body_head_and_keepalive) {
    JsonProgram program;
    REQUIRE(program.init());
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(32));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->json_arena.backend.pool = &pool;
    const char* methods[] = {"POST", "HEAD", "POST"};
    const char* versions[] = {"HTTP/1.1", "HTTP/1.1", "HTTP/1.0"};
    const std::string body = "{\"ok\":true,\"message\":\"Rut\"}";
    for (u32 i = 0; i < 3; ++i) {
        const std::string request =
            std::string(methods[i]) + " /json " + versions[i] +
            "\r\nHost: test\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        auto outcome = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, 200u);
        handle_jit_outcome(loop.get(), *conn, outcome, program.handler(), i < 2);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        CHECK(response.find(std::string(versions[i]) + " 200") == 0);
        CHECK(response.find("Content-Type: application/json") != std::string::npos);
        CHECK(response.find("Content-Length: " + std::to_string(body.size())) != std::string::npos);
        if (i == 1)
            CHECK(response.find(body) == std::string::npos);
        else
            CHECK(response.ends_with(body));
    }
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, http2_response_owns_body_before_next_handler) {
    JsonProgram program;
    REQUIRE(program.init());
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(32));
    conn->json_arena.backend.pool = &pool;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    conn->epoch_held = true;
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    RouteEntry route{};
    route.fn = program.handler();
    char request[] = "POST /json HTTP/1.1\r\nHost: test\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
    u8 bytes[4096]{};
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, bytes, sizeof(bytes), 0, false};
    h2_invoke_emit(dispatch,
                   1,
                   &route,
                   nullptr,
                   0,
                   program.config.get(),
                   reinterpret_cast<const u8*>(request),
                   sizeof(request) - 1,
                   false,
                   true);
    CHECK(!dispatch.overflow);
    REQUIRE_EQ(h2->outbound_stream, 1u);
    CHECK(h2->outbound_source == H2OutboundBodySource::Json);
    CHECK((Str{reinterpret_cast<const char*>(h2->outbound_body), h2->outbound_body_len}.eq(
        lit_str("{\"ok\":true}"))));
    conn->json_arena.destroy();
    __builtin_memset(request, 'x', sizeof(request) - 1);
    CHECK((Str{reinterpret_cast<const char*>(h2->outbound_body), h2->outbound_body_len}.eq(
        lit_str("{\"ok\":true}"))));
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    h2->streams[0].send_window = 0;
    H2PumpStatus status{};
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 0u);
    CHECK(status == H2PumpStatus::Blocked);
    // A small stream window must preserve the owned body across multiple DATA frames.
    h2->streams[0].send_window = 4;
    const u32 first = h2_pump_outbound(*h2, bytes, sizeof(bytes), status);
    CHECK_EQ(first, kFrameHeaderSize + 4u);
    CHECK(status == H2PumpStatus::Produced);
    CHECK_EQ(bytes[3], 0u);       // DATA
    CHECK_EQ(bytes[4] & 1u, 0u);  // No END_STREAM before the final byte.
    CHECK((Str{reinterpret_cast<const char*>(bytes + kFrameHeaderSize), 4}.eq(lit_str("{\"ok"))));
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 0u);
    CHECK(status == H2PumpStatus::Blocked);
    h2->streams[0].send_window = 7;
    const u32 sent = h2_pump_outbound(*h2, bytes, sizeof(bytes), status);
    CHECK_EQ(sent, kFrameHeaderSize + 7u);
    CHECK(status == H2PumpStatus::Produced);
    CHECK_EQ(bytes[3], 0u);
    CHECK_EQ(bytes[4] & 1u, 1u);  // END_STREAM exactly once, on the last fragment.
    CHECK(
        (Str{reinterpret_cast<const char*>(bytes + kFrameHeaderSize), 7}.eq(lit_str("\":true}"))));
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 0u);
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
