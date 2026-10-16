#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/jit/codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/hpack.h"
#include "rut/runtime/http2_frame.h"
#include "test.h"
#include "test_helpers.h"
#include <memory>
#include <string>

using namespace rut;

static Str cstr(const char* value) {
    u32 len = 0;
    while (value[len] != '\0') ++len;
    return {value, len};
}

struct JsonProgram {
    std::unique_ptr<AstFile> ast;
    std::unique_ptr<HirModule> hir;
    std::unique_ptr<MirModule> mir;
    FrontendRirModule rir{};
    jit::JitEngine engine;
    std::unique_ptr<RouteConfig> config = std::make_unique<RouteConfig>();
    bool init(const char* custom_source = nullptr) {
        const Str source = custom_source != nullptr ? cstr(custom_source) : lit_str(R"rut(
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
    jit::HandlerFn handler(u32 route_index = 0) {
        char name[] = "handler_route_0";
        name[14] = static_cast<char>('0' + route_index);
        return reinterpret_cast<jit::HandlerFn>(engine.lookup(name));
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

TEST(json_network, aliased_json_response_content_type_is_serialized_on_h1_and_h2) {
    const char* source = R"rut(
route GET "/implicit" {
    guard let payload = json({ name: "Ada" }) else { return 500 }
    let alias = payload
    return response(200, body: alias)
}
route GET "/custom" {
    guard let payload = json({ name: "Ada" }) else { return 500 }
    let alias = payload
    return response(200, body: alias, headers: { "Content-Type": "text/custom" })
}
)rut";
    JsonProgram program;
    REQUIRE(program.init(source));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(32));
    const char* paths[] = {"/implicit", "/custom"};
    const char* expected_types[] = {"application/json", "text/custom"};
    const std::string expected_body = "{\"name\":\"Ada\"}";

    for (u32 i = 0; i < 2; ++i) {
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->json_arena.backend.pool = &pool;
        const std::string request =
            std::string("GET ") + paths[i] + " HTTP/1.1\r\nHost: test\r\n\r\n";
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        auto handler = program.handler(i);
        auto outcome = invoke_jit_handler(
            handler, conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, 200u);
        handle_jit_outcome(loop.get(), *conn, outcome, handler, false);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        const std::string content_type = std::string("Content-Type: ") + expected_types[i] + "\r\n";
        CHECK(response.find(content_type) != std::string::npos);
        CHECK_EQ(response.find(content_type), response.find("Content-Type:"));
        CHECK_EQ(response.find("Content-Type:", response.find("Content-Type:") + 1),
                 std::string::npos);
        CHECK(response.ends_with(expected_body));
        loop->free_conn(*conn);
    }

    for (u32 i = 0; i < 2; ++i) {
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->json_arena.backend.pool = &pool;
        auto h2 = std::make_unique<Http2Conn>();
        h2->init();
        conn->h2 = h2.get();
        conn->epoch_held = true;
        h2->nstreams = 1;
        h2->streams[0].id = 1;
        h2->streams[0].state = Http2StreamState::HalfClosedRemote;
        RouteEntry route{};
        route.fn = program.handler(i);
        const std::string request =
            std::string("GET ") + paths[i] + " HTTP/1.1\r\nHost: test\r\n\r\n";
        u8 wire[4096]{};
        H2Dispatch<SmallLoop> dispatch{loop.get(), conn, wire, sizeof(wire), 0, false};
        h2_invoke_emit(dispatch,
                       1,
                       &route,
                       nullptr,
                       0,
                       program.config.get(),
                       reinterpret_cast<const u8*>(request.data()),
                       request.size(),
                       false,
                       true);
        CHECK_FALSE(dispatch.overflow);
        CHECK(dispatch.resp_len > kFrameHeaderSize);
        Http2FrameHeader frame{};
        REQUIRE_EQ(parse_frame_header(wire, dispatch.resp_len, &frame), ParseStatus::Complete);
        REQUIRE_EQ(frame.type, static_cast<u8>(Http2FrameType::Headers));
        REQUIRE((frame.flags & http2_flag::kEndHeaders) != 0);
        REQUIRE_EQ(kFrameHeaderSize + frame.length, dispatch.resp_len);
        hpack::DynamicTable decoder{};
        decoder.init(kDefaultHeaderTableSize);
        hpack::Header headers[16]{};
        u8 header_storage[1024]{};
        u32 header_count = 0;
        REQUIRE(hpack::decode_header_block(decoder,
                                           wire + kFrameHeaderSize,
                                           frame.length,
                                           header_storage,
                                           sizeof(header_storage),
                                           headers,
                                           16,
                                           &header_count));
        u32 content_type_count = 0;
        bool saw_status = false;
        bool saw_expected_type = false;
        for (u32 j = 0; j < header_count; ++j) {
            saw_status |=
                headers[j].name.eq(lit_str(":status")) && headers[j].value.eq(lit_str("200"));
            if (headers[j].name.eq(lit_str("content-type"))) {
                ++content_type_count;
                saw_expected_type = headers[j].value.eq(cstr(expected_types[i]));
            }
        }
        CHECK(saw_status);
        CHECK_EQ(content_type_count, 1u);
        CHECK(saw_expected_type);
        CHECK_EQ(h2->outbound_source, H2OutboundBodySource::Json);
        CHECK((Str{reinterpret_cast<const char*>(h2->outbound_body), h2->outbound_body_len}.eq(
            lit_str("{\"name\":\"Ada\"}"))));
        conn->h2 = nullptr;
        loop->free_conn(*conn);
    }
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
