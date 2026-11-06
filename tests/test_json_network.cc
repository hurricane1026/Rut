#include "es256_fixture.h"
#include "fault_injection.h"
#include "fixtures/jwt_lifetime.h"
#include "fixtures/signed_request.h"
#include "rs256_fixture.h"
#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/jit/codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/hpack.h"
#include "rut/runtime/http2_frame.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"
#include "rut/runtime/jwt_hs256.h"
#include "test.h"
#include "test_helpers.h"
#include <memory>
#include <string>
#include <utility>

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>

using namespace rut;

static bool slice_is_in_use(const SlicePool& pool, const u8* ptr) {
    if (!ptr || !pool.base || !pool.in_use_map || pool.count == 0) return false;
    const u64 base = reinterpret_cast<u64>(pool.base);
    const u64 address = reinterpret_cast<u64>(ptr);
    const u64 bytes = static_cast<u64>(pool.count) * SlicePool::kSliceSize;
    if (address < base || address - base >= bytes) return false;
    const u64 offset = address - base;
    if (offset % SlicePool::kSliceSize != 0) return false;
    return pool.in_use_map[offset / SlicePool::kSliceSize] != 0;
}

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
    Rs256Policies rs256;
    Es256Policies es256;
    std::unique_ptr<RouteConfig> config = std::make_unique<RouteConfig>();
    bool init(const char* custom_source = nullptr, const char* source_path = nullptr) {
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
        auto h =
            source_path != nullptr ? analyze_file(*ast, cstr(source_path)) : analyze_file(*ast);
        if (!h) return false;
        hir.reset(h.value());
        auto m = build_mir(*hir);
        if (!m) return false;
        mir.reset(m.value());
        if (!lower_to_rir(*mir, rir)) return false;
        auto cg = jit::codegen(rir.module);
        if (!cg.ok || !engine.init() || !engine.compile(cg.mod, cg.ctx)) return false;
        if (!populate_route_config(*config, rir.module) ||
            !rs256.load(config->rs256_configurations, config->rs256_configuration_count))
            return false;
        config->rs256 = &rs256;
        if (!es256.load(config->es256_configurations, config->es256_configuration_count))
            return false;
        config->es256 = &es256;
        return register_jit_routes(*config, rir.module, engine);
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
    CHECK(h2->outbound_source == H2OutboundBodySource::JitDynamic);
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

TEST(json_network, large_http2_dynamic_body_survives_flow_control) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(4));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;
    conn->epoch_held = true;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    h2->nstreams = 1;
    h2->streams[0] = {1, Http2StreamState::Open, 0, 0, true};

    constexpr u32 kBodySize = 9 * 1024;
    u8 source[kBodySize];
    for (u32 i = 0; i < kBodySize; ++i) source[i] = static_cast<u8>(i % 251);
    u8 response[4096]{};
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
    REQUIRE(h2_stage_owned_response(dispatch,
                                    1,
                                    200,
                                    nullptr,
                                    0,
                                    source,
                                    kBodySize,
                                    H2OutboundBodySource::JitDynamic,
                                    nullptr));
    REQUIRE(h2->jit_outbound_slice != nullptr);
    u8* owned_slice = h2->jit_outbound_slice;
    CHECK_EQ(h2->outbound_body, h2->jit_outbound_slice);
    CHECK(slice_is_in_use(pool, owned_slice));
    __builtin_memset(source, 0, sizeof(source));

    std::unique_ptr<u8[]> received = std::make_unique<u8[]>(kBodySize);
    u32 received_len = 0;
    H2PumpStatus status{};
    CHECK_EQ(h2_pump_outbound(*h2, response, sizeof(response), status), 0u);
    CHECK(status == H2PumpStatus::Blocked);
    while (h2->outbound_stream != 0) {
        h2->conn_send_window = static_cast<i32>(kBodySize);
        h2->streams[0].send_window = static_cast<i32>(kBodySize);
        const u32 written = h2_pump_outbound(*h2, response, sizeof(response), status);
        REQUIRE(written >= kFrameHeaderSize);
        REQUIRE_EQ(response[3], static_cast<u8>(Http2FrameType::Data));
        const u32 frame_len = (static_cast<u32>(response[0]) << 16) |
                              (static_cast<u32>(response[1]) << 8) | response[2];
        REQUIRE_EQ(written, kFrameHeaderSize + frame_len);
        REQUIRE(received_len + frame_len <= kBodySize);
        __builtin_memcpy(received.get() + received_len, response + kFrameHeaderSize, frame_len);
        received_len += frame_len;
        if (h2->outbound_final_staged) {
            CHECK(status == H2PumpStatus::Produced);
            h2_clear_primary_outbound(*h2);
        }
    }
    REQUIRE_EQ(received_len, kBodySize);
    bool body_matches = true;
    for (u32 i = 0; i < kBodySize; ++i) body_matches &= received[i] == static_cast<u8>(i % 251);
    CHECK(body_matches);
    CHECK(h2->jit_outbound_slice == nullptr);
    CHECK_FALSE(slice_is_in_use(pool, owned_slice));
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, large_req_body_response_is_supported_on_h1_and_h2) {
    const char* source = R"rut(
route POST "/echo" {
    let body = req.body
    return response(200, body: body)
}
)rut";
    JsonProgram program;
    REQUIRE(program.init(source));
    constexpr u32 kBodySize = 9 * 1024;
    std::string body(kBodySize, '\0');
    for (u32 i = 0; i < kBodySize; ++i) body[i] = static_cast<char>('a' + (i % 23));
    std::string request =
        "POST /echo HTTP/1.1\r\nHost: test\r\nContent-Length: " + std::to_string(kBodySize) +
        "\r\n\r\n" + body;

    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;
    u8* original_recv_slice = conn->recv_slice;
    const u32 original_recv_capacity = conn->recv_slice_capacity;
    u8* original_send_slice = conn->send_slice;
    const u32 original_send_capacity = SmallLoop::kBufSize;
    u8 request_buffer[SlicePool::kSliceSize];
    conn->bind_request_receive_buffer(request_buffer, sizeof(request_buffer));
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
               request.size());
    u8 send_buffer[SlicePool::kSliceSize];
    conn->send_buf.bind(send_buffer, sizeof(send_buffer));
    capture_request_metadata(*conn);
    conn->request_config = program.config.get();
    auto* ctx = conn->reset_jit_ctx();
    auto outcome = invoke_jit_handler(
        program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
    CHECK_EQ(outcome.status_code, 200u);
    handle_jit_outcome(loop.get(), *conn, outcome, program.handler(), false);
    const std::string h1(reinterpret_cast<const char*>(conn->send_buf.data()),
                         conn->send_buf.len());
    CHECK(h1.find("HTTP/1.1 200") == 0);
    CHECK(h1.ends_with(body));
    conn->bind_request_receive_buffer(original_recv_slice, original_recv_capacity);
    conn->send_buf.bind(original_send_slice, original_send_capacity);

    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    conn->epoch_held = true;
    h2->nstreams = 1;
    h2->streams[0] = {1, Http2StreamState::HalfClosedRemote, 0, 0, true};
    RouteEntry route{};
    route.fn = program.handler();
    u8 wire[2048]{};
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
    CHECK(!dispatch.overflow);
    REQUIRE_EQ(h2->outbound_stream, 1u);
    REQUIRE_EQ(h2->outbound_body_len, kBodySize);
    CHECK_EQ(memcmp(h2->outbound_body, body.data(), kBodySize), 0);
    CHECK(h2->jit_outbound_slice != nullptr);
    __builtin_memset(request.data() + request.size() - kBodySize, 'x', kBodySize);
    CHECK_EQ(memcmp(h2->outbound_body, body.data(), kBodySize), 0);
    h2_clear_outbound(*h2);
    CHECK(h2->jit_outbound_slice == nullptr);
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, large_dynamic_body_allocation_failure_is_transactional) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(1));
    u8* occupied = pool.alloc();
    REQUIRE(occupied != nullptr);
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;
    conn->epoch_held = true;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    h2->nstreams = 1;
    h2->streams[0] = {1, Http2StreamState::Open, 0, 0, true};
    u8 body[9 * 1024];
    __builtin_memset(body, 'z', sizeof(body));
    conn->jit_response_body = {reinterpret_cast<const char*>(body), sizeof(body)};
    conn->jit_response_body_valid = true;
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 200;
    outcome.response_body_idx = 0xffffu;
    u8 response[2048]{};
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
    h2_emit_outcome(dispatch, 1, outcome, nullptr, false);
    CHECK_EQ(h2->outbound_stream, 0u);
    CHECK_EQ(h2->queued_stream, 0u);
    REQUIRE_GT(dispatch.resp_len, 0u);
    Http2FrameHeader frame{};
    REQUIRE_EQ(parse_frame_header(response, dispatch.resp_len, &frame), ParseStatus::Complete);
    REQUIRE_EQ(frame.type, static_cast<u8>(Http2FrameType::Headers));
    hpack::DynamicTable decoded;
    decoded.init(kDefaultHeaderTableSize);
    hpack::Header headers[8];
    u8 scratch[256]{};
    u32 decoded_count = 0;
    REQUIRE(hpack::decode_header_block(decoded,
                                       response + kFrameHeaderSize,
                                       frame.length,
                                       scratch,
                                       sizeof(scratch),
                                       headers,
                                       8,
                                       &decoded_count));
    bool saw_500 = false;
    for (u32 i = 0; i < decoded_count; ++i)
        saw_500 |= headers[i].name.eq(lit_str(":status")) && headers[i].value.eq(lit_str("500"));
    CHECK(saw_500);
    CHECK(slice_is_in_use(pool, occupied));
    pool.free(occupied);
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, dynamic_response_helper_rejects_body_over_one_slice) {
    SmallLoop loop;
    loop.setup();
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    u8 oversized[SlicePool::kSliceSize + 1];
    __builtin_memset(oversized, 'x', sizeof(oversized));
    const u8 request[] = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    rut_helper_resp_body(conn,
                         reinterpret_cast<const char*>(oversized),
                         sizeof(oversized),
                         request,
                         sizeof(request) - 1);
    CHECK_FALSE(conn->jit_response_body_valid);
    CHECK_EQ(conn->jit_response_body.len, sizeof(oversized));
    loop.free_conn(*conn);
}

TEST(json_network, queued_large_dynamic_body_transfers_slice_ownership) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(4));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;
    conn->epoch_held = true;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    h2->nstreams = 2;
    h2->streams[0] = {1, Http2StreamState::Open, 0, 0, true};
    h2->streams[1] = {3, Http2StreamState::Open, 0, 0, true};
    u8 body[9 * 1024];
    __builtin_memset(body, 'q', sizeof(body));
    u8 response[2048]{};
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
    REQUIRE(h2_stage_owned_response(dispatch,
                                    1,
                                    200,
                                    nullptr,
                                    0,
                                    body,
                                    sizeof(body),
                                    H2OutboundBodySource::JitDynamic,
                                    nullptr));
    u8* first_slice = h2->jit_outbound_slice;
    REQUIRE(first_slice != nullptr);
    H2Dispatch<SmallLoop> queued{
        loop.get(), conn, response, sizeof(response), dispatch.resp_len, false};
    REQUIRE(h2_stage_owned_response(
        queued, 3, 200, nullptr, 0, body, sizeof(body), H2OutboundBodySource::JitDynamic, nullptr));
    u8* queued_slice = h2->jit_queued_slice;
    REQUIRE(queued_slice != nullptr);
    CHECK(first_slice != queued_slice);
    h2_promote_queued(*h2);
    CHECK_FALSE(slice_is_in_use(pool, first_slice));
    CHECK_EQ(h2->outbound_stream, 3u);
    CHECK_EQ(h2->outbound_body, queued_slice);
    CHECK(slice_is_in_use(pool, queued_slice));
    CHECK_EQ(memcmp(h2->outbound_body, body, sizeof(body)), 0);
    CHECK(h2->jit_queued_slice == nullptr);
    h2_clear_outbound(*h2);
    CHECK_FALSE(slice_is_in_use(pool, queued_slice));
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
        CHECK_EQ(h2->outbound_source, H2OutboundBodySource::JitDynamic);
        CHECK((Str{reinterpret_cast<const char*>(h2->outbound_body), h2->outbound_body_len}.eq(
            lit_str("{\"name\":\"Ada\"}"))));
        conn->h2 = nullptr;
        loop->free_conn(*conn);
    }
    pool.destroy();
}

TEST(json_network, uuid_response_serialization_and_h2_request_arena_retirement) {
    JsonProgram program;
    REQUIRE(program.init(
        "route GET \"/id\" { let pending = uuid() guard let id = pending else { return 503 } "
        "return response(200, body: id) }"));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->json_arena.backend.pool = &pool;
    const char request[] = "GET /id HTTP/1.1\r\nHost: test\r\n\r\n";
    for (u32 i = 0; i < 2; ++i) {
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request), sizeof(request) - 1),
                   sizeof(request) - 1);
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        auto outcome = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        REQUIRE_EQ(outcome.status_code, 200u);
        REQUIRE_EQ(conn->jit_response_body.len, 36u);
        const std::string body(conn->jit_response_body.ptr, conn->jit_response_body.len);
        handle_jit_outcome(loop.get(), *conn, outcome, program.handler(), true);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        CHECK(wire.find("HTTP/1.1 200") == 0);
        CHECK(wire.find("Content-Length: 36") != std::string::npos);
        CHECK(wire.ends_with(body));
        conn->json_arena.destroy();
    }
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    conn->epoch_held = true;
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    RouteEntry route{};
    route.fn = program.handler();
    u8 wire[4096]{};
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, wire, sizeof(wire), 0, false};
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
    CHECK_FALSE(dispatch.overflow);
    REQUIRE_EQ(h2->outbound_body_len, 36u);
    REQUIRE(h2->outbound_body != nullptr);
    char saved[36];
    __builtin_memcpy(saved, h2->outbound_body, sizeof(saved));
    conn->json_arena.destroy();
    auto* recycled = pool.alloc();
    REQUIRE(recycled);
    __builtin_memset(recycled, 'x', SlicePool::kSliceSize);
    CHECK_EQ(memcmp(h2->outbound_body, saved, sizeof(saved)), 0);
    pool.free(recycled);
    h2_clear_outbound(*h2);
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(json_network, jwt_decode_verifies_hs256_and_returns_claims) {
    const char* token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "AL_nmexgcwawKDK5uJ0RtfAxT1GguksdPuaahEACpHc";
    const char* payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));

    auto decode =
        [&](const char* secret, const char* jwt = nullptr, const char* algorithm = nullptr) {
            if (jwt == nullptr) jwt = token;
            u8 has = 0;
            const char* out = nullptr;
            u32 len = 0;
            i64 number = 0;
            rut_helper_json(
                nullptr,
                &arena,
                static_cast<u32>(algorithm ? json::Op::JwtDecodePinned : json::Op::JwtDecode),
                jwt,
                static_cast<u32>(__builtin_strlen(jwt)),
                secret,
                static_cast<u32>(__builtin_strlen(secret)),
                algorithm,
                algorithm ? static_cast<u32>(__builtin_strlen(algorithm)) : 0,
                0,
                &has,
                &out,
                &len,
                &number);
            return std::pair<bool, Str>{has != 0, Str{out, len}};
        };

    const auto ok = decode("01234567890123456789012345678901");
    CHECK(ok.first);
    CHECK(ok.second.eq({payload, static_cast<u32>(__builtin_strlen(payload))}));
    CHECK_FALSE(decode("wrong-secret").first);
    CHECK_FALSE(decode(std::string(32, 'y').c_str()).first);
    CHECK_FALSE(decode("").first);

    const char* hs384 =
        "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJvayJ9."
        "cZs_Wk2VoNrX8sTen4A9Yq6gOB4YtDtIxbe_uxxEgP6uvDdDJNJ1kNRtlF7Lbq0C";
    const char* hs512 =
        "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJvayJ9."
        "p_rhc57EpVQ9_ZGxlTT895mw-_gpUswNyGkwXVkzD4zD0TctOZPa3wahaqakkp3-rteIrBsD3UiLrk36-2J8GA";
    const std::string hs256_key(32, 'x');
    const std::string hs384_key(48, 'x');
    const std::string hs512_key(64, 'x');
    CHECK(
        decode(hs256_key.c_str(),
               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvayJ9.IfR5W5USO_w4xSkuH-3bkLY-rSj9vIYL4V9jUdcNv4U")
            .first);
    CHECK(decode(hs384_key.c_str(), hs384).first);
    CHECK(decode(hs512_key.c_str(), hs512).first);
    CHECK(decode(hs384_key.c_str(), hs384, "HS384").first);
    CHECK(decode(hs512_key.c_str(), hs512, "HS512").first);
    // Both tokens are correctly signed with the SAME 64-byte key. Policy must
    // reject a different supported algorithm, independently of key length.
    const char* hs256_same_key =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvayJ9.acrJbLo2WVaennGuy-GBFdjrMmJWT5kD5M7o4-j7sW8";
    CHECK(decode(hs512_key.c_str(), hs256_same_key).first);
    CHECK(decode(hs512_key.c_str(), hs256_same_key, "HS256").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs256_same_key, "HS512").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs512, "HS256").first);

    CHECK_FALSE(decode(hs384_key.c_str(), hs384, "HS256").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs512, "HS384").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs512, "").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs512, "hs512").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs512, "none").first);
    CHECK_FALSE(decode(hs512_key.c_str(), hs512, "RS256").first);
    CHECK(decode("01234567890123456789012345678901", token, "HS256").first);
    CHECK_FALSE(decode("01234567890123456789012345678901", token, "HS512").first);

    CHECK(
        decode(std::string(65, 'x').c_str(),
               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvayJ9.mtYtHuqIBzRucu6RKwhPy5qdCUlENvY0xsz9zqTioKg")
            .first);
    CHECK(decode(std::string(129, 'x').c_str(),
                 "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJvayJ9.JRV-"
                 "gATamPa5fRjGEIMaLLqBGezuBB5nCsxYJFM1SiEpDUb17YaAUCajN55mCnSA")
              .first);
    CHECK(decode(std::string(129, 'x').c_str(),
                 "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJvayJ9.akk8BrpagvgRV-0SJjwW2ASRv-"
                 "ZvqJe9wRRTW3cbMjxKsQxDwIxj_UlSjGwoyJmqHyE9UxSq-50dIEKM8loUAA")
              .first);
    CHECK_FALSE(decode(std::string(31, 'x').c_str()).first);
    CHECK_FALSE(decode(std::string(47, 'x').c_str(), hs384).first);
    CHECK_FALSE(decode(std::string(63, 'x').c_str(), hs512).first);
    CHECK_FALSE(
        decode(hs256_key.c_str(), "eyJhbGciOiJIUzI1NiIsInh4eHh4eHh4eHh4eHh4eHh4IjoxfQ.e30.AA")
            .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(), "eyJhbGciOiJYWFhYWFhYWFhYWFhYWFhYWCJ9.eyJzdWIiOiJvayJ9.AA")
            .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(), "eyJhbGciOiJIUzI1NiIsImFsZyI6IkhTMjU2In0.eyJzdWIiOiJvayJ9.AA")
            .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(), "eyJhbGciOiJIUzI1NiIsImFsZyI6IkhTNTEyIn0.eyJzdWIiOiJvayJ9.AA")
            .first);
    CHECK_FALSE(decode(hs256_key.c_str(), "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl19.e30.AA").first);
    CHECK_FALSE(decode(hs256_key.c_str(), "eyJjcml0IjpbImV4cCJdLCJhbGciOiJIUzI1NiJ9.e30.AA").first);
    CHECK(decode(std::string(32, 'x').c_str(),
                 "eyJodHRwczovL2V4YW1wbGUuY29tL3ZlcnktbG9uZy1wdWJsaWMtbmFtZSI6IngiLCJhbGciOiJIUzI1N"
                 "iJ9.eyJzdWIiOiJvayJ9.GFhV-6WnIYxQ9t8-jqQFJ_9okmYFm8xj2_1F18Nchtk")
              .first);
    CHECK(decode(std::string(32, 'x').c_str(),
                 "eyJhbGciOiJIUzI1NiIsImh0dHBzOi8vZXhhbXBsZS5jb20vdmVyeS1sb25nLXB1YmxpYy1uYW1lIjoie"
                 "CJ9.eyJzdWIiOiJvayJ9.wDDSJKjj8zlcKW0-S4XMpfl10_xTTxWVWtCfZRaaO_I")
              .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(),
               "eyJhbGciOiJIUzI1NiJ9=.eyJzdWIiOiJvayJ9.GFhV-6WnIYxQ9t8-jqQFJ_9okmYFm8xj2_1F18Nchtk")
            .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(),
               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvayJ9=.IfR5W5USO_w4xSkuH-3bkLY-rSj9vIYL4V9jUdcNv4U")
            .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(),
               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvayJ9.IfR5W5USO_w4xSkuH-3bkLY-rSj9vIYL4V9jUdcNv4U=")
            .first);
    CHECK_FALSE(
        decode(hs256_key.c_str(),
               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvayJ9.IfR5W5USO_w4xSkuH-3bkLY-rSj9vIYL4V9jUdcNv4U!")
            .first);
    auto b64url = [](const std::string& input) {
        static constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        for (size_t i = 0; i < input.size(); i += 3) {
            const u32 left = static_cast<unsigned char>(input[i]);
            const u32 middle = i + 1 < input.size() ? static_cast<unsigned char>(input[i + 1]) : 0;
            const u32 right = i + 2 < input.size() ? static_cast<unsigned char>(input[i + 2]) : 0;
            out += alphabet[left >> 2];
            out += alphabet[((left & 3) << 4) | (middle >> 4)];
            if (i + 1 < input.size()) out += alphabet[((middle & 15) << 2) | (right >> 6)];
            if (i + 2 < input.size()) out += alphabet[right & 63];
        }
        return out;
    };
    auto sign_header = [&](const std::string& header) {
        const std::string encoded_header = b64url(header);
        const std::string signing_input = encoded_header + ".e30";
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        HMAC(EVP_sha256(),
             hs256_key.data(),
             static_cast<int>(hs256_key.size()),
             reinterpret_cast<const unsigned char*>(signing_input.data()),
             signing_input.size(),
             digest,
             &digest_len);
        return signing_input + "." +
               b64url(std::string(reinterpret_cast<const char*>(digest), digest_len));
    };
    const char* lifetime_token =
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJhbGljZSIsImlzcyI6Imlzc3VlciIsImF1ZCI6ImdhdGV3YXkiLCJpYXQiOjkwMCwiZXhwIjoxMTAwfQ"
        "."
        "ioTapzc9b_9jxlQrsgD3HbDtf4GtxUTzewPKeKDH6ZM";
    const auto authenticated = decode(hs256_key.c_str(), lifetime_token);
    REQUIRE(authenticated.first);
    json::Document authenticated_claims;
    REQUIRE(authenticated_claims.parse(authenticated.second));
    CHECK(jwt_claims_valid_with_lifetime(authenticated_claims,
                                         authenticated.second,
                                         lit_str("issuer"),
                                         lit_str("gateway"),
                                         1000,
                                         100,
                                         200));
    CHECK(!jwt_claims_valid_with_lifetime(authenticated_claims,
                                          authenticated.second,
                                          lit_str("issuer"),
                                          lit_str("gateway"),
                                          1000,
                                          99,
                                          200));
    auto signed_header = [&](size_t target_size) {
        std::string header = R"({"alg":"HS256","x":""})";
        header.insert(header.size() - 2, target_size - header.size(), 'x');
        return sign_header(header);
    };
    CHECK(decode(hs256_key.c_str(), signed_header(1024).c_str()).first);
    CHECK_FALSE(decode(hs256_key.c_str(), signed_header(1025).c_str()).first);
    CHECK(decode(hs256_key.c_str(), sign_header(R"({"alg":"HS256","b64":true})").c_str()).first);
    CHECK_FALSE(
        decode(hs256_key.c_str(), sign_header(R"({"alg":"HS256","b64":false})").c_str()).first);
    CHECK_FALSE(decode(hs256_key.c_str(),
                       sign_header(R"({"alg":"HS256","b64":false,"crit":["b64"]})").c_str())
                    .first);
    std::string flood = R"({"alg":"HS256")";
    for (u32 i = 0; i < 700; ++i) flood += ",\"x" + std::to_string(i) + "\":0";
    flood += '}';
    CHECK(flood.size() > 5000);
    const std::string flood_token = sign_header(flood);
    CHECK_FALSE(decode(hs256_key.c_str(), flood_token.c_str()).first);
    std::string oversized = R"({"alg":"HS256","x":")" + std::string(1010, 'x') + "\"}";
    CHECK(oversized.size() > 1024);
    const std::string oversized_token = b64url(oversized) + ".e30.AA";
    CHECK_FALSE(decode(hs256_key.c_str(), oversized_token.c_str()).first);

    arena.destroy();
    pool.destroy();
}

TEST(json_network, hs256_issue_helper_uses_request_arena_and_fails_closed_on_budget) {
    SlicePool pool;
    REQUIRE(pool.init(24));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char key[32];
    for (char& byte : key) byte = 'k';
    u8 has_value = 9;
    const char* output = reinterpret_cast<const char*>(1);
    u32 output_len = 99;
    rut_helper_jwt_issue_hs256(nullptr,
                               &arena,
                               "alice",
                               5,
                               "issuer",
                               6,
                               "orders",
                               6,
                               key,
                               sizeof(key),
                               60,
                               &has_value,
                               &output,
                               &output_len);
    REQUIRE(has_value);
    REQUIRE(output != nullptr);
    CHECK_GT(output_len, 100u);
    CHECK_LE(arena.space_allocated(), SlicePool::kSliceSize);
    CHECK(reinterpret_cast<uintptr_t>(output) >= reinterpret_cast<uintptr_t>(pool.base));
    CHECK(reinterpret_cast<uintptr_t>(output) <
          reinterpret_cast<uintptr_t>(pool.base) +
              static_cast<u64>(pool.count) * SlicePool::kSliceSize);

    arena.reset();
    has_value = 9;
    output = reinterpret_cast<const char*>(1);
    output_len = 99;
    rut_helper_jwt_issue_hs256(nullptr,
                               &arena,
                               "alice",
                               5,
                               "issuer",
                               6,
                               "orders",
                               6,
                               key,
                               sizeof(key) - 1,
                               60,
                               &has_value,
                               &output,
                               &output_len);
    CHECK_EQ(has_value, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);

    has_value = 9;
    output = reinterpret_cast<const char*>(1);
    output_len = 99;
    rut_helper_jwt_issue_hs256(nullptr,
                               &arena,
                               "alice",
                               5,
                               "issuer",
                               6,
                               "orders",
                               6,
                               key,
                               sizeof(key),
                               0,
                               &has_value,
                               &output,
                               &output_len);
    CHECK_EQ(has_value, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);

    test_fault::SyscallFaultConfig clock_failure{};
    clock_failure.clock_gettime_errno = EIO;
    clock_failure.clock_gettime_failures = 1;
    {
        test_fault::ScopedSyscallFault fault(clock_failure);
        has_value = 9;
        output = reinterpret_cast<const char*>(1);
        output_len = 99;
        rut_helper_jwt_issue_hs256(nullptr,
                                   &arena,
                                   "alice",
                                   5,
                                   "issuer",
                                   6,
                                   "orders",
                                   6,
                                   key,
                                   sizeof(key),
                                   60,
                                   &has_value,
                                   &output,
                                   &output_len);
    }
    CHECK_EQ(has_value, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);

    arena.reset();
    while (arena.space_used() <= kHashRequestBudget) {
        REQUIRE(arena.alloc(15 * 1024) != nullptr);
    }
    has_value = 9;
    output = reinterpret_cast<const char*>(1);
    output_len = 99;
    rut_helper_jwt_issue_hs256(nullptr,
                               &arena,
                               "alice",
                               5,
                               "issuer",
                               6,
                               "orders",
                               6,
                               key,
                               sizeof(key),
                               60,
                               &has_value,
                               &output,
                               &output_len);
    CHECK_EQ(has_value, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);
    arena.destroy();
    pool.destroy();
}

TEST(json_network, issued_jwt_body_survives_http1_and_http2_send_paths) {
    constexpr char kIssueSource[] = R"rut(
import "middleware/auth.rut"
route GET "/issue" {
    let identity = auth.apiKey(req.authorization.or(""), "issue-secret", "alice", "api-key")
    let requestId = uuid()
    guard let tokenId = requestId else { return response(503) }
    guard let token = auth.jwtForIdentityHs256WithIdAndScope(
        identity, "issuer", "orders", tokenId, "orders:read",
        "01234567890123456789012345678901", 900) else {
        return response(503)
    }
    return response(200, body: token)
}
)rut";
    constexpr char kValidateSource[] = R"rut(
import "middleware/auth.rut"
route POST "/validate" {
    let claims = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    guard jwtClaimsValidWithLifetime(claims, "issuer", "orders", i64(900), i64(900)) else { return 401 }
    let checked = auth.requireUnrevokedJwt(claims, "revoked-token-1", "revoked-token-2")
    guard jwtHasScope(checked, "orders:read") else { return 403 }
    return 204
}
)rut";
    JsonProgram program;
    JsonProgram validation_program;
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-issue-auth.rut";
    REQUIRE(program.init(kIssueSource, source_path.c_str()));
    REQUIRE(validation_program.init(kValidateSource, source_path.c_str()));
    const auto verify_token = [&](Str token, SliceArena& arena, u16 expected_status) {
        arena.reset();
        const std::string request = std::string("POST /validate HTTP/1.1\r\nHost: test\r\n") +
                                    "Authorization: Bearer " + std::string(token.ptr, token.len) +
                                    "\r\n\r\n";
        const auto result = jit::HandlerResult::unpack(
            validation_program.handler()(nullptr,
                                         nullptr,
                                         reinterpret_cast<const u8*>(request.data()),
                                         static_cast<u32>(request.size()),
                                         &arena));
        CHECK_EQ(result.status_code, expected_status);
    };

    SmallLoop loop;
    loop.setup();
    SlicePool pool;
    REQUIRE(pool.init(48));
    auto* conn = loop.alloc_conn();
    REQUIRE(conn);
    conn->json_arena.backend.pool = &pool;
    const char request[] =
        "GET /issue HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer issue-secret\r\n\r\n";
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request), sizeof(request) - 1),
               sizeof(request) - 1);
    capture_request_metadata(*conn);
    conn->request_config = program.config.get();
    auto* ctx = conn->reset_jit_ctx();
    auto outcome = invoke_jit_handler(
        program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
    CHECK_EQ(outcome.status_code, 200u);
    handle_jit_outcome(&loop, *conn, outcome, program.handler(), false);
    conn->json_arena.destroy();
    Str h1_wire{reinterpret_cast<const char*>(conn->send_buf.data()), conn->send_buf.len()};
    const char* h1_body_start = nullptr;
    for (u32 i = 3; i < h1_wire.len; ++i) {
        if (__builtin_memcmp(h1_wire.ptr + i - 3, "\r\n\r\n", 4) == 0) {
            h1_body_start = h1_wire.ptr + i + 1;
            break;
        }
    }
    REQUIRE(h1_body_start != nullptr);
    const Str h1_token{h1_body_start, static_cast<u32>(h1_wire.ptr + h1_wire.len - h1_body_start)};
    CHECK_EQ(h1_token.ptr[0], 'e');
    CHECK(h1_token.len > 100u);
    SliceArena verify_arena;
    REQUIRE(verify_arena.init(&pool));
    verify_token(h1_token, verify_arena, 204);

    char tampered[kMaxJwtHs256TokenBytes];
    __builtin_memcpy(tampered, h1_token.ptr, h1_token.len);
    tampered[h1_token.len - 1] = tampered[h1_token.len - 1] == 'A' ? 'B' : 'A';
    verify_token({tampered, h1_token.len}, verify_arena, 401);

    char signing_key[32];
    const char kSigningKey[] = "01234567890123456789012345678901";
    for (u32 i = 0; i < sizeof(signing_key); ++i) signing_key[i] = kSigningKey[i];
    struct timespec now{};
    REQUIRE_EQ(clock_gettime(CLOCK_REALTIME, &now), 0);
    char legacy_token[kMaxJwtHs256TokenBytes];
    u32 legacy_token_len = 0;
    REQUIRE(jwt_hs256_issue({signing_key, sizeof(signing_key)},
                            lit_str("alice"),
                            lit_str("issuer"),
                            lit_str("orders"),
                            static_cast<i64>(now.tv_sec),
                            60,
                            legacy_token,
                            sizeof(legacy_token),
                            legacy_token_len));
    verify_token({legacy_token, legacy_token_len}, verify_arena, 401);
    char no_scope_token[kMaxJwtHs256TokenBytes];
    u32 no_scope_token_len = 0;
    REQUIRE(jwt_hs256_issue_with_id({signing_key, sizeof(signing_key)},
                                    lit_str("alice"),
                                    lit_str("issuer"),
                                    lit_str("orders"),
                                    lit_str("request-no-scope"),
                                    static_cast<i64>(now.tv_sec),
                                    60,
                                    no_scope_token,
                                    sizeof(no_scope_token),
                                    no_scope_token_len));
    verify_token({no_scope_token, no_scope_token_len}, verify_arena, 403);
    char wrong_scope_token[kMaxJwtHs256TokenBytes];
    u32 wrong_scope_token_len = 0;
    REQUIRE(jwt_hs256_issue_with_id_and_scope({signing_key, sizeof(signing_key)},
                                              lit_str("alice"),
                                              lit_str("issuer"),
                                              lit_str("orders"),
                                              lit_str("request-wrong-scope"),
                                              lit_str("orders:write"),
                                              static_cast<i64>(now.tv_sec),
                                              60,
                                              wrong_scope_token,
                                              sizeof(wrong_scope_token),
                                              wrong_scope_token_len));
    verify_token({wrong_scope_token, wrong_scope_token_len}, verify_arena, 403);
    for (Str revoked_id : {lit_str("revoked-token-1"), lit_str("revoked-token-2")}) {
        char revoked_token[kMaxJwtHs256TokenBytes];
        u32 revoked_token_len = 0;
        REQUIRE(jwt_hs256_issue_with_id_and_scope({signing_key, sizeof(signing_key)},
                                                  lit_str("alice"),
                                                  lit_str("issuer"),
                                                  lit_str("orders"),
                                                  revoked_id,
                                                  lit_str("orders:read"),
                                                  static_cast<i64>(now.tv_sec),
                                                  60,
                                                  revoked_token,
                                                  sizeof(revoked_token),
                                                  revoked_token_len));
        verify_token({revoked_token, revoked_token_len}, verify_arena, 401);
    }
    verify_arena.destroy();

    REQUIRE(conn->json_arena.init(&pool));
    conn->send_buf.reset();
    conn->recv_buf.reset();
    conn->protocol = ConnProtocol::Http2;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    conn->epoch_held = true;
    h2->nstreams = 1;
    h2->streams[0] = {1, Http2StreamState::HalfClosedRemote, 0, 0, true};
    u8 wire[4096]{};
    H2Dispatch<SmallLoop> dispatch{&loop, conn, wire, sizeof(wire), 0, false};
    h2_invoke_emit(dispatch,
                   1,
                   &program.config->routes[0],
                   nullptr,
                   0,
                   program.config.get(),
                   reinterpret_cast<const u8*>(request),
                   sizeof(request) - 1,
                   false,
                   true);
    CHECK_FALSE(dispatch.overflow);
    REQUIRE_EQ(h2->outbound_stream, 1u);
    CHECK(h2->outbound_source == H2OutboundBodySource::JitDynamic);
    CHECK(h2->outbound_body_len > 100u);
    const u32 expected_h2_token_len = h2->outbound_body_len;
    conn->json_arena.destroy();
    std::unique_ptr<char[]> h2_token = std::make_unique<char[]>(expected_h2_token_len);
    u32 h2_token_len = 0;
    H2PumpStatus status{};
    h2->conn_send_window = 65535;
    h2->streams[0].send_window = 65535;
    while (h2->outbound_stream != 0) {
        const u32 sent = h2_pump_outbound(*h2, wire, sizeof(wire), status);
        REQUIRE_GT(sent, 0u);
        if (wire[3] == static_cast<u8>(Http2FrameType::Data)) {
            const u32 frame_len =
                (static_cast<u32>(wire[0]) << 16) | (static_cast<u32>(wire[1]) << 8) | wire[2];
            REQUIRE(h2_token_len + frame_len <= expected_h2_token_len);
            __builtin_memcpy(h2_token.get() + h2_token_len, wire + kFrameHeaderSize, frame_len);
            h2_token_len += frame_len;
        }
        if (h2->outbound_final_staged) h2_clear_primary_outbound(*h2);
    }
    CHECK_EQ(h2_token_len, expected_h2_token_len);
    REQUIRE(verify_arena.init(&pool));
    verify_token({h2_token.get(), h2_token_len}, verify_arena, 204);
    verify_arena.destroy();
    conn->h2 = nullptr;
    loop.free_conn(*conn);
    pool.destroy();
}

TEST(json_network, hs256_issue_with_id_helper_uses_request_arena_and_fails_closed) {
    SlicePool pool;
    REQUIRE(pool.init(24));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char key[32];
    for (char& byte : key) byte = 'k';
    u8 has_value = 9;
    const char* output = reinterpret_cast<const char*>(1);
    u32 output_len = 99;
    rut_helper_jwt_issue_hs256_with_id(nullptr,
                                       &arena,
                                       "alice",
                                       5,
                                       "issuer",
                                       6,
                                       "orders",
                                       6,
                                       "request-42",
                                       10,
                                       key,
                                       sizeof(key),
                                       60,
                                       &has_value,
                                       &output,
                                       &output_len);
    REQUIRE(has_value);
    REQUIRE(output != nullptr);
    CHECK_GT(output_len, 100u);
    CHECK(reinterpret_cast<uintptr_t>(output) >= reinterpret_cast<uintptr_t>(pool.base));
    CHECK(reinterpret_cast<uintptr_t>(output) <
          reinterpret_cast<uintptr_t>(pool.base) +
              static_cast<u64>(pool.count) * SlicePool::kSliceSize);

    arena.reset();
    has_value = 9;
    output = reinterpret_cast<const char*>(1);
    output_len = 99;
    rut_helper_jwt_issue_hs256_with_id(nullptr,
                                       &arena,
                                       "alice",
                                       5,
                                       "issuer",
                                       6,
                                       "orders",
                                       6,
                                       "",
                                       0,
                                       key,
                                       sizeof(key),
                                       60,
                                       &has_value,
                                       &output,
                                       &output_len);
    CHECK_EQ(has_value, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);

    arena.reset();
    while (arena.space_used() <= kHashRequestBudget) REQUIRE(arena.alloc(15 * 1024) != nullptr);
    rut_helper_jwt_issue_hs256_with_id(nullptr,
                                       &arena,
                                       "alice",
                                       5,
                                       "issuer",
                                       6,
                                       "orders",
                                       6,
                                       "request-42",
                                       10,
                                       key,
                                       sizeof(key),
                                       60,
                                       &has_value,
                                       &output,
                                       &output_len);
    CHECK_EQ(has_value, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);
    arena.destroy();
    pool.destroy();
}

TEST(json_network, hs256_issue_with_id_and_scope_helper_uses_request_arena_and_fails_closed) {
    SlicePool pool;
    REQUIRE(pool.init(24));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char key[32];
    for (char& byte : key) byte = 's';
    u8 has = 0;
    const char* output = nullptr;
    u32 output_len = 0;
    rut_helper_jwt_issue_hs256_with_id_and_scope(nullptr,
                                                 &arena,
                                                 "alice",
                                                 5,
                                                 "issuer",
                                                 6,
                                                 "orders",
                                                 6,
                                                 "request-9",
                                                 9,
                                                 "orders:read",
                                                 11,
                                                 key,
                                                 sizeof(key),
                                                 60,
                                                 &has,
                                                 &output,
                                                 &output_len);
    REQUIRE_EQ(has, 1u);
    REQUIRE(output != nullptr);
    CHECK_GT(output_len, 100u);
    CHECK(reinterpret_cast<uintptr_t>(output) >= reinterpret_cast<uintptr_t>(pool.base));

    arena.reset();
    has = 1;
    output = reinterpret_cast<const char*>(1);
    output_len = 99;
    rut_helper_jwt_issue_hs256_with_id_and_scope(nullptr,
                                                 &arena,
                                                 "alice",
                                                 5,
                                                 "issuer",
                                                 6,
                                                 "orders",
                                                 6,
                                                 "request-9",
                                                 9,
                                                 "two words",
                                                 10,
                                                 key,
                                                 sizeof(key),
                                                 60,
                                                 &has,
                                                 &output,
                                                 &output_len);
    CHECK_EQ(has, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);
    arena.reset();
    while (arena.space_used() <= kHashRequestBudget) REQUIRE(arena.alloc(15 * 1024) != nullptr);
    rut_helper_jwt_issue_hs256_with_id_and_scope(nullptr,
                                                 &arena,
                                                 "alice",
                                                 5,
                                                 "issuer",
                                                 6,
                                                 "orders",
                                                 6,
                                                 "request-9",
                                                 9,
                                                 "orders:read",
                                                 11,
                                                 key,
                                                 sizeof(key),
                                                 60,
                                                 &has,
                                                 &output,
                                                 &output_len);
    CHECK_EQ(has, 0u);
    CHECK(output == nullptr);
    CHECK_EQ(output_len, 0u);
    arena.destroy();
    pool.destroy();
}

TEST(json_network, native_hs256_issue_round_trips_existing_decoder_and_claim_policy) {
    char key[32];
    for (char& byte : key) byte = 'k';
    char token[kMaxJwtHs256TokenBytes];
    u32 token_len = 0;
    const Str issuer = lit_str("issuer.example");
    const Str audience = lit_str("orders");
    REQUIRE(jwt_hs256_issue({key, sizeof(key)},
                            lit_str("alice"),
                            issuer,
                            audience,
                            1700000000,
                            3600,
                            token,
                            sizeof(token),
                            token_len));

    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 has_value = 0;
    const char* decoded = nullptr;
    u32 decoded_len = 0;
    i64 number = 0;
    rut_helper_json(nullptr,
                    &arena,
                    static_cast<u32>(json::Op::JwtDecodePinned),
                    token,
                    token_len,
                    key,
                    sizeof(key),
                    "HS256",
                    5,
                    0,
                    &has_value,
                    &decoded,
                    &decoded_len,
                    &number);
    REQUIRE(has_value);
    json::Document claims;
    CHECK(jwt_claims_valid_with_lifetime(
        claims, {decoded, decoded_len}, issuer, audience, 1700000000, 3600, 3600));
    arena.destroy();
    pool.destroy();
}

TEST(json_network, jit_jwt_decode_returns_claims_subject) {
    REQUIRE_EQ(setenv("RUT_TEST_JWT_SECRET", "01234567890123456789012345678901", 1), 0);
    JsonProgram program;
    REQUIRE(program.init(R"rut(
route POST "/jwt" {
    guard let token = req.header("Authorization") else { return 401 }
    guard let claims = jwtDecode(token, env("RUT_TEST_JWT_SECRET"), "HS256") else { return 401 }
    guard let sub_json = json.get(claims, "/sub") else { return 400 }
    guard let sub = json.string(sub_json) else { return 400 }
    return response(200, body: sub)
}
)rut"));
    unsetenv("RUT_TEST_JWT_SECRET");
    const char* token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "AL_nmexgcwawKDK5uJ0RtfAxT1GguksdPuaahEACpHc";
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(32));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->json_arena.backend.pool = &pool;

    auto run = [&](const char* auth, u32 expected_status) {
        const std::string request = std::string(
                                        "POST /jwt HTTP/1.1\r\nHost: test\r\n"
                                        "Authorization: ") +
                                    auth + "\r\nContent-Length: 0\r\n\r\n";
        conn->recv_buf.reset();
        conn->send_buf.reset();
        CHECK_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
                 request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        auto outcome = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, expected_status);
        handle_jit_outcome(loop.get(), *conn, outcome, program.handler(), true);
        return std::string(reinterpret_cast<const char*>(conn->send_buf.data()),
                           conn->send_buf.len());
    };

    const std::string good = run(token, 200);
    CHECK(good.find("HTTP/1.1 200") == 0);
    CHECK(good.ends_with("1234567890"));
    const std::string bad = run("not-a-jwt", 401);
    CHECK(bad.find("HTTP/1.1 401") == 0);

    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, jwt_claims_policy_uses_epoch_clock_and_fails_closed_without_an_arena) {
    const char* claims =
        R"({"sub":"alice","iss":"issuer","aud":["other","gateway"],"exp":1001,"nbf":1000})";
    auto check = [&](const test_fault::SyscallFaultConfig& clock, i64 expected) {
        test_fault::ScopedSyscallFault fault(clock);
        u8 has = 0;
        const char* bytes = nullptr;
        u32 length = 0;
        i64 result = 7;
        rut_helper_json(nullptr,
                        nullptr,
                        static_cast<u32>(json::Op::JwtClaimsValid),
                        claims,
                        static_cast<u32>(__builtin_strlen(claims)),
                        "issuer",
                        6,
                        "gateway",
                        7,
                        0,
                        &has,
                        &bytes,
                        &length,
                        &result);
        CHECK_EQ(result, expected);
        if (expected == 1) CHECK_EQ(has, 1u);
    };
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 0), 1);
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1001, 0), 0);
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, 999, 0), 0);
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, 0, 0), 0);
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, -1, 0), 0);
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, -1), 0);
    check(test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 1000000000), 0);
    test_fault::SyscallFaultConfig failed;
    failed.clock_gettime_errno = EIO;
    failed.clock_gettime_failures = 1;
    check(failed, 0);
}

TEST(json_network, signed_jwt_claims_gate_identity_publication) {
    JsonProgram program;
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-claims-auth.rut";
    REQUIRE(program.init(R"rut(
import "middleware/auth.rut"
route GET "/identity" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentity(document, "issuer", "gateway", "issuer-key")
    guard jwtHasScope(document, "orders:read") else { return response(403, headers: {"WWW-Authenticate": "Bearer error=\"insufficient_scope\""}) }
    guard req.path != "/all" || jwtHasScope(document, "orders:write") else { return response(403, headers: {"WWW-Authenticate": "Bearer error=\"insufficient_scope\""}) }
    let userId = identity.consumerId
    return response(200, body: userId)
}
)rut",
                         source_path.c_str()));
    const auto encode = [](const std::string& input) {
        std::string output(4 * ((input.size() + 2) / 3) + 1, '\0');
        const int count = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()),
                                          reinterpret_cast<const unsigned char*>(input.data()),
                                          static_cast<int>(input.size()));
        output.resize(count);
        for (char& c : output) {
            if (c == '+')
                c = '-';
            else if (c == '/')
                c = '_';
        }
        while (!output.empty() && output.back() == '=') output.pop_back();
        return output;
    };
    const auto sign = [&](const char* payload) {
        const std::string message = "eyJhbGciOiJIUzI1NiJ9." + encode(payload);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        HMAC(EVP_sha256(),
             "01234567890123456789012345678901",
             32,
             reinterpret_cast<const unsigned char*>(message.data()),
             message.size(),
             digest,
             &length);
        return message + "." + encode(std::string(reinterpret_cast<const char*>(digest), length));
    };
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(16));
    conn->json_arena.backend.pool = &pool;
    struct Case {
        const char* claims;
        u16 status;
        const char* path = "/identity";
    };
    const Case cases[] = {
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:read"})", 200},
        {R"({"sub":"alice","iss":"issuer","aud":["other","gateway"],"exp":1001,"nbf":1000,"scope":"profile orders:read"})",
         200},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1000})", 401},
        {R"({"sub":"alice","iss":"other","aud":"gateway","exp":1001})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"other","exp":1001})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"nbf":1001})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"iat":1001})", 401},
        {R"({"sub":"","iss":"issuer","aud":"gateway","exp":1001})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway"})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:read"})", 200},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001})", 403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:reader"})",
         403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":["orders:read"]})",
         403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:read "})",
         403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1000,"scope":"orders:read"})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:read orders:write"})",
         200,
         "/all"},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:read"})",
         403,
         "/all"},
    };
    for (const auto& tc : cases) {
        const std::string request = std::string("GET ") + tc.path +
                                    " HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer " +
                                    sign(tc.claims) + "\r\n\r\n";
        // Match the production request boundary before reusing this connection.
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 0));
        auto outcome = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, tc.status);
        if (tc.status == 200)
            CHECK(conn->jit_response_body.eq(lit_str("alice")));
        else
            CHECK(!conn->jit_response_body_valid);
        handle_jit_outcome(loop.get(), *conn, outcome, program.handler(), true);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        if (tc.status == 403)
            CHECK(wire.find("Bearer error=\"insufficient_scope\"") != std::string::npos);
    }
    JsonProgram revocation;
    REQUIRE(revocation.init(R"rut(
import "middleware/auth.rut"
route GET "/identity" {
    guard let document = jwtDecode(bearerToken(req.authorization.or("")).or(""), "01234567890123456789012345678901", "HS256") else { return 401 }
    guard jwtClaimsValid(document, "issuer", "gateway") else { return 401 }
    let checked = auth.requireUnrevokedJwt(document, "revoked-one", "revoked-two")
    guard jwtHasScope(checked, "orders:read") else { return 403 }
    return 200
}
)rut",
                            source_path.c_str()));
    const Case revocation_cases[] = {
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"allowed","scope":"orders:read"})",
         200},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"revoked-one","scope":"orders:read"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"revoked-two","scope":"orders:read"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"Revoked-one","scope":"orders:read"})",
         200},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"","scope":"orders:read"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"scope":"orders:read"})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":12,"scope":"orders:read"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"allowed","\u006ati":"revoked-one","scope":"orders:read"})",
         401},
        {R"({"sub":"alice","iss":"other","aud":"gateway","exp":1001,"jti":"allowed","scope":"orders:read"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1001,"jti":"allowed","scope":"orders:write"})",
         403},
    };
    for (const auto& tc : revocation_cases) {
        const std::string request =
            std::string("GET /identity HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer ") +
            sign(tc.claims) + "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = revocation.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 0));
        auto outcome = invoke_jit_handler(
            revocation.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, tc.status);
        CHECK(!conn->jit_response_body_valid);
        if (tc.status == 401 && __builtin_strstr(tc.claims, "\"jti\":\"revoked-one\"") != nullptr) {
            handle_jit_outcome(loop.get(), *conn, outcome, revocation.handler(), true);
            const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
            CHECK(wire.find("Bearer error=\"invalid_token\"") != std::string::npos);
        }
    }
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, hs256_jwt_lifetime_policy_gates_identity_and_clock) {
    JsonProgram program;
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-claims-auth.rut";
    REQUIRE(program.init(R"rut(
import "middleware/auth.rut"
route GET "/identity" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentityWithLifetime(document, "issuer", "gateway", "jwt-credential", 100, 200)
    guard identity.consumerId == "alice" && identity.credentialId == "jwt-credential" && identity.method == "jwt" else { return 500 }
    let userId = identity.consumerId
    return response(200, body: userId)
}
route GET "/age-limit" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentityWithLifetime(document, "issuer", "gateway", "jwt-credential", 99, 200)
    let userId = identity.consumerId
    return response(200, body: userId)
}
route GET "/lifetime-limit" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentityWithLifetime(document, "issuer", "gateway", "jwt-credential", 100, 200)
    let userId = identity.consumerId
    return response(200, body: userId)
}
route GET "/missing-iat" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentityWithLifetime(document, "issuer", "gateway", "jwt-credential", 100, 200)
    let userId = identity.consumerId
    return response(200, body: userId)
}
route GET "/wrong-issuer" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentityWithLifetime(document, "other-issuer", "gateway", "jwt-credential", 100, 200)
    let userId = identity.consumerId
    return response(200, body: userId)
}
route GET "/bad-config" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), "01234567890123456789012345678901")
    let identity = auth.jwtIdentityWithLifetime(document, "issuer", "gateway", "jwt-credential", 0, 200)
    let userId = identity.consumerId
    return response(200, body: userId)
}
)rut",
                         source_path.c_str()));
    REQUIRE_EQ(program.config->route_count, 6u);
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(32));
    conn->json_arena.backend.pool = &pool;

    const auto encode = [](const std::string& input) {
        std::string output(4 * ((input.size() + 2) / 3) + 1, '\0');
        const int count = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()),
                                          reinterpret_cast<const unsigned char*>(input.data()),
                                          static_cast<int>(input.size()));
        output.resize(count);
        for (char& c : output) {
            if (c == '+')
                c = '-';
            else if (c == '/')
                c = '_';
        }
        while (!output.empty() && output.back() == '=') output.pop_back();
        return output;
    };
    const auto sign = [&](const char* claims) {
        const std::string message = "eyJhbGciOiJIUzI1NiJ9." + encode(claims);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        HMAC(EVP_sha256(),
             "01234567890123456789012345678901",
             32,
             reinterpret_cast<const unsigned char*>(message.data()),
             message.size(),
             digest,
             &digest_len);
        return message + "." +
               encode(std::string(reinterpret_cast<const char*>(digest), digest_len));
    };
    const std::string valid =
        sign(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1100})");
    const std::string too_old =
        sign(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":899,"exp":1100})");
    const std::string too_long =
        sign(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1101})");
    const std::string no_iat = sign(R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1100})");
    std::string tampered = valid;
    tampered.back() = tampered.back() == 'A' ? 'B' : 'A';
    const char* route_paths[] = {"/identity",
                                 "/age-limit",
                                 "/lifetime-limit",
                                 "/missing-iat",
                                 "/wrong-issuer",
                                 "/bad-config"};

    auto run = [&](const char* path,
                   const std::string& token,
                   u32 status,
                   const test_fault::SyscallFaultConfig& clock,
                   bool invalid_token = false) {
        u32 route_index = program.config->route_count;
        for (u32 i = 0; i < program.config->route_count; ++i)
            if (std::string(path) == route_paths[i]) route_index = i;
        CHECK_LT(route_index, program.config->route_count);
        if (route_index >= program.config->route_count) return std::string{};
        const auto handler = program.handler(route_index);
        const std::string request = std::string("GET ") + path +
                                    " HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer " + token +
                                    "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        const u32 written =
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size());
        CHECK_EQ(written, request.size());
        if (written != request.size()) return std::string{};
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault fault(clock);
        const auto outcome = invoke_jit_handler(
            handler, conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, status);
        handle_jit_outcome(loop.get(), *conn, outcome, handler, true);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        CHECK(wire.find("HTTP/1.1 " + std::to_string(status)) == 0);
        if (status == 200)
            CHECK(wire.ends_with("alice"));
        else
            CHECK(wire.find("alice") == std::string::npos);
        if (status == 401) CHECK(wire.find("WWW-Authenticate: Bearer") != std::string::npos);
        if (invalid_token) CHECK(wire.find("Bearer error=\"invalid_token\"") != std::string::npos);
        return wire;
    };
    const auto good_clock = test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 0);
    run("/identity", valid, 200, good_clock);
    run("/age-limit", valid, 401, good_clock, true);
    run("/lifetime-limit", too_long, 401, good_clock, true);
    run("/identity", too_old, 401, good_clock, true);
    run("/missing-iat", no_iat, 401, good_clock, true);
    run("/wrong-issuer", valid, 401, good_clock, true);
    run("/bad-config", valid, 503, good_clock);
    run("/identity", tampered, 401, good_clock);
    run("/identity", valid, 401, test_fault::fixed_clock_gettime(CLOCK_REALTIME, 0, 0), true);
    run("/identity", valid, 401, test_fault::fixed_clock_gettime(CLOCK_REALTIME, -1, 0), true);
    run("/identity", valid, 401, test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, -1), true);
    run("/identity",
        valid,
        401,
        test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 1000000000),
        true);
    test_fault::SyscallFaultConfig clock_failure{};
    clock_failure.clock_gettime_errno = EIO;
    clock_failure.clock_gettime_failures = 1;
    run("/identity", valid, 401, clock_failure, true);

    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, jwt_algorithm_middleware_rejects_empty_secret) {
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-claims-auth.rut";
    for (const char* helper : {"jwtDocumentHs256", "jwtDocumentHs384", "jwtDocumentHs512"}) {
        JsonProgram program;
        const std::string source =
            "import \"middleware/auth.rut\"\nroute GET \"/\" { "
            "let doc = auth." +
            std::string(helper) + "(req.authorization.or(\"\"), \"\") return 200 }";
        REQUIRE(program.init(source.c_str(), source_path.c_str()));
        auto loop = std::make_unique<SmallLoop>();
        loop->setup();
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        const char* request = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request), __builtin_strlen(request)),
            __builtin_strlen(request));
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        auto outcome = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(outcome.status_code, 503u);
        loop->free_conn(*conn);
    }
}

TEST(json_network, rs256_http_identity_requires_static_trust_signature_claims_and_scope) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    Rs256Policy checked;
    REQUIRE(checked.load(fixture.policy));
    const std::string policy(fixture.policy.ptr, fixture.policy.len);
    REQUIRE_EQ(setenv("RUT_TEST_RS256_POLICY", policy.c_str(), 1), 0);
    struct Environment {
        ~Environment() { unsetenv("RUT_TEST_RS256_POLICY"); }
    } environment;
    JsonProgram program;
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-rs256-auth.rut";
    REQUIRE(program.init(R"rut(
import "middleware/auth.rut"
route GET "/rs256" {
    let configured = env("RUT_TEST_RS256_POLICY")
    let policy = configured
    let identity = auth.jwtIdentityRs256(req.authorization.or(""), policy, "read", "issuer-rs256")
    let userId = identity.consumerId
    return response(200, body: userId)
}
)rut",
                         source_path.c_str()));
    CHECK_EQ(program.config->rs256_configuration_count, 1u);
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(64));
    conn->json_arena.backend.pool = &pool;
    auto run = [&](Str token, u32 status, bool duplicate = false) {
        const std::string auth(token.ptr ? token.ptr : "", token.len);
        const std::string request = "GET /rs256 HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer " +
                                    auth + (duplicate ? "\r\nAuthorization: Bearer " + auth : "") +
                                    "\r\n\r\n";
        conn->recv_buf.reset();
        conn->send_buf.reset();
        conn->json_arena.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        const auto result = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(result.status_code, status);
        handle_jit_outcome(loop.get(), *conn, result, program.handler(), true);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        if (status == 200)
            CHECK(response.ends_with("alice"));
        else
            CHECK(response.find("alice") == std::string::npos);
        if (status == 401) CHECK(response.find("WWW-Authenticate: Bearer") != std::string::npos);
    };
    char token[4096];
    Str good = fixture.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, token);
    REQUIRE(good.len);
    // No lazy initialization on the first request, and each shard needs its own activation.
    run(good, 401);
    REQUIRE(program.config->activate_rs256(0));
    run(good, 200);
    run(good, 401, true);
    conn->shard_id = 1;
    run(good, 401);
    REQUIRE(program.config->activate_rs256(1));
    run(good, 200);
    struct Case {
        const char* header;
        const char* claims;
        u32 status;
    };
    const Case cases[] = {
        {R"({"alg":"RS256","kid":"unknown"})", nullptr, 401},
        {R"({"alg":"RS256"})", nullptr, 401},
        {R"({"alg":"HS256","kid":"current"})", nullptr, 401},
        {R"({"alg":"none","kid":"current"})", nullptr, 401},
        {R"({"alg":"RS256","kid":"current","crit":["x"],"x":true})", nullptr, 401},
        {nullptr,
         R"({"sub":"alice","iss":"other","aud":"gateway","exp":4102444800,"scope":"read"})",
         401},
        {nullptr,
         R"({"sub":"alice","iss":"issuer","aud":"other","exp":4102444800,"scope":"read"})",
         401},
        {nullptr, R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":1,"scope":"read"})", 401},
        {nullptr,
         R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"nbf":4102444799,"scope":"read"})",
         401},
        {nullptr,
         R"({"sub":"","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read"})",
         401},
        {nullptr,
         R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"reader"})",
         403},
        {nullptr, R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800})", 403},
    };
    for (const auto& item : cases) {
        const Str header = item.header ? cstr(item.header) : test::Rs256Fixture::header;
        const Str claims = item.claims ? cstr(item.claims) : test::Rs256Fixture::claims;
        run(fixture.sign(header, claims, token), item.status);
    }
    good = fixture.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, token);
    token[good.len - 4] = token[good.len - 4] == 'a' ? 'b' : 'a';
    run(good, 401);
    run(lit_str("not-a-jwt"), 401);
    good = fixture.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, token);
    test_fault::SyscallFaultConfig clock;
    clock.clock_gettime_errno = EIO;
    clock.clock_gettime_failures = 100;
    {
        test_fault::ScopedSyscallFault fault(clock);
        run(good, 401);
    }

    JsonProgram lifetime_program;
    REQUIRE(lifetime_program.init(R"rut(
import "middleware/auth.rut"
route GET "/rs256-lifetime" {
    let configured = env("RUT_TEST_RS256_POLICY")
    let policy = configured
    let document = auth.jwtDocumentRs256(req.authorization.or(""), policy)
    let identity = auth.jwtIdentityWithLifetime(document, "issuer", "gateway", "rsa-credential", 100, 200)
    guard identity.consumerId == "alice" && identity.credentialId == "rsa-credential" && identity.method == "jwt" else { return 500 }
    let userId = identity.consumerId
    return response(200, body: userId)
}
)rut",
                                  source_path.c_str()));
    CHECK_EQ(lifetime_program.config->rs256_configuration_count, 1u);
    conn->shard_id = 0;
    REQUIRE(lifetime_program.config->activate_rs256(0));
    const auto run_lifetime = [&](const char* claims, u32 status) {
        const Str signed_token = fixture.sign(test::Rs256Fixture::header, cstr(claims), token);
        REQUIRE(signed_token.len > 0);
        const std::string request =
            "GET /rs256-lifetime HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer " +
            std::string(signed_token.ptr, signed_token.len) + "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        conn->json_arena.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = lifetime_program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault fixed_clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 1000, 0));
        const auto outcome = invoke_jit_handler(lifetime_program.handler(),
                                                conn,
                                                *ctx,
                                                conn->recv_buf.data(),
                                                conn->recv_buf.len(),
                                                nullptr);
        CHECK_EQ(outcome.status_code, status);
        handle_jit_outcome(loop.get(), *conn, outcome, lifetime_program.handler(), true);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        CHECK(wire.find("HTTP/1.1 " + std::to_string(status)) == 0);
        if (status == 200)
            CHECK(wire.ends_with("alice"));
        else
            CHECK(wire.find("WWW-Authenticate: Bearer") != std::string::npos);
    };
    run_lifetime(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1100})", 200);
    run_lifetime(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":899,"exp":1100})", 401);
    run_lifetime(R"({"sub":"alice","iss":"issuer","aud":"gateway","iat":900,"exp":1101})", 401);
    loop->free_conn(*conn);
    pool.destroy();
}

static u16 signed_request_h2_status(const u8* data, u32 len, u32 stream_id) {
    u32 pos = 0;
    hpack::DynamicTable dyn;
    dyn.init(kDefaultHeaderTableSize);
    while (pos + kFrameHeaderSize <= len) {
        Http2FrameHeader frame{};
        if (parse_frame_header(data + pos, len - pos, &frame) != ParseStatus::Complete) return 0;
        const u32 total = kFrameHeaderSize + frame.length;
        if (total > len - pos) return 0;
        if (frame.type == static_cast<u8>(Http2FrameType::Headers) &&
            frame.stream_id == stream_id) {
            hpack::Header headers[16];
            u8 scratch[1024];
            u32 count = 0;
            if (!hpack::decode_header_block(dyn,
                                            data + pos + kFrameHeaderSize,
                                            frame.length,
                                            scratch,
                                            sizeof(scratch),
                                            headers,
                                            16,
                                            &count))
                return 0;
            for (u32 i = 0; i < count; i++) {
                if (!headers[i].name.eq(lit_str(":status")) || headers[i].value.len != 3) continue;
                return static_cast<u16>((headers[i].value.ptr[0] - '0') * 100 +
                                        (headers[i].value.ptr[1] - '0') * 10 +
                                        headers[i].value.ptr[2] - '0');
            }
            return 0;
        }
        pos += total;
    }
    return 0;
}

TEST(json_network, signed_request_auth_binds_http_method_target_headers_and_complete_body) {
    using ::rut::test::signed_request::Headers;
    constexpr i64 kNow = 1700000000;
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/multi-consumer-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(R"rut(
import "middleware/auth.rut"
route "/signed" {
    let identity = auth.signedRequest("rut-test-key", "signed-request-test-secret-32bytes", "consumer-a", "credential-a")
    let authMethod = identity.method
    return response(200, body: authMethod)
}
route "/empty-config" {
    let identity = auth.signedRequest("", "", "", "")
    let authMethod = identity.method
    return response(200, body: authMethod)
}
)rut",
                         source_path.c_str()));
    REQUIRE_EQ(program.config->route_count, 2u);
    CHECK(program.config->routes[0].needs_req_body);

    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(32));
    conn->json_arena.backend.pool = &pool;

    auto run_h1 = [&](const char* method,
                      const std::string& target,
                      const std::string& body,
                      const Headers& auth,
                      u32 expected_status,
                      const std::string& extra_headers = {},
                      bool clock_failure = false) {
        std::string request = std::string(method) + " " + target + " HTTP/1.1\r\nHost: test\r\n";
        if (!auth.authorization.empty()) request += "Authorization: " + auth.authorization + "\r\n";
        if (!auth.date.empty()) request += "Date: " + auth.date + "\r\n";
        if (!auth.digest.empty()) request += "Digest: " + auth.digest + "\r\n";
        request +=
            extra_headers + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        const u32 route_index = target == "/empty-config" ? 1u : 0u;
        const auto handler = program.handler(route_index);
        const auto outcome = [&]() {
            if (clock_failure) {
                test_fault::SyscallFaultConfig failed{};
                failed.clock_gettime_errno = EIO;
                failed.clock_gettime_failures = 100;
                test_fault::ScopedSyscallFault fault(failed);
                return invoke_jit_handler(
                    handler, conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
            }
            test_fault::ScopedSyscallFault clock(
                test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
            return invoke_jit_handler(
                handler, conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        }();
        CHECK_EQ(outcome.status_code, expected_status);
        handle_jit_outcome(loop.get(), *conn, outcome, handler, true);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        if (expected_status == 200)
            CHECK(wire.ends_with("signedRequest"));
        else
            CHECK(wire.find("signedRequest") == std::string::npos);
    };

    const std::string target = "/signed?x=%2F&x=two";
    const std::string body = "first=one&second=two";
    const Headers good = ::rut::test::signed_request::make_headers("POST", target, body, kNow);
    REQUIRE(!good.authorization.empty());
    const RouteConfig* active_config = program.config.get();
    loop->config_ptr = &active_config;
    auto run_segmented_h1 = [&](const Headers& auth, u32 expected_status) {
        auto* segmented = loop->alloc_conn();
        REQUIRE(segmented);
        segmented->json_arena.backend.pool = &pool;
        const std::string prefix = "first=one";
        const std::string head = "POST " + target +
                                 " HTTP/1.1\r\nHost: test\r\nAuthorization: " + auth.authorization +
                                 "\r\nDate: " + auth.date + "\r\nDigest: " + auth.digest +
                                 "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        REQUIRE_EQ(segmented->recv_buf.write(reinterpret_cast<const u8*>(head.data()), head.size()),
                   head.size());
        REQUIRE_EQ(
            segmented->recv_buf.write(reinterpret_cast<const u8*>(prefix.data()), prefix.size()),
            prefix.size());
        const u32 conn_id = segmented->id;
        {
            test_fault::ScopedSyscallFault clock(
                test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
            on_header_received<SmallLoop>(
                loop.get(),
                *segmented,
                make_ev(conn_id, IoEventType::Recv, head.size() + prefix.size()));
        }
        CHECK(segmented->on_recv == &on_jit_request_body_recvd<SmallLoop>);
        CHECK_EQ(segmented->req_body_remaining, body.size() - prefix.size());
        CHECK_EQ(segmented->send_buf.len(), 0u);
        const std::string suffix = body.substr(prefix.size());
        REQUIRE_EQ(
            segmented->recv_buf.write(reinterpret_cast<const u8*>(suffix.data()), suffix.size()),
            suffix.size());
        {
            test_fault::ScopedSyscallFault clock(
                test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
            segmented->on_recv(
                loop.get(), *segmented, make_ev(conn_id, IoEventType::Recv, suffix.size()));
        }
        const std::string wire(reinterpret_cast<const char*>(segmented->send_buf.data()),
                               segmented->send_buf.len());
        CHECK(wire.find(expected_status == 200 ? "HTTP/1.1 200" : "HTTP/1.1 401") == 0);
        if (expected_status == 200)
            CHECK(wire.ends_with("signedRequest"));
        else
            CHECK(wire.find("signedRequest") == std::string::npos);
        release_completed_jit_json(*segmented);
        loop->free_conn(*segmented);
    };
    run_segmented_h1(good, 200);
    const Headers signed_prefix =
        ::rut::test::signed_request::make_headers("POST", target, "first=one", kNow);
    run_segmented_h1(signed_prefix, 401);

    run_h1("POST", target, body, good, 200);
    run_h1("POST", "/signed?x=%2F&x=changed", body, good, 401);
    run_h1("GET", target, body, good, 401, "X-Method: POST\r\nX-Path: /signed\r\n");
    run_h1("POST", target, body + "!", good, 401);

    Headers bad = good;
    const size_t signature_field = bad.authorization.find("signature=\"");
    REQUIRE(signature_field != std::string::npos);
    const size_t signature_byte = signature_field + sizeof("signature=\"") - 1;
    bad.authorization[signature_byte] = bad.authorization[signature_byte] == 'A' ? 'B' : 'A';
    run_h1("POST", target, body, bad, 401);
    bad = good;
    bad.digest.back() = bad.digest.back() == 'A' ? 'B' : 'A';
    run_h1("POST", target, body, bad, 401);
    bad = good;
    const std::string key_id = "keyId=\"" + std::string(::rut::test::signed_request::kKeyId) + "\"";
    const size_t key_id_at = bad.authorization.find(key_id);
    REQUIRE(key_id_at != std::string::npos);
    bad.authorization.replace(key_id_at, key_id.size(), "keyId=\"other-key\"");
    run_h1("POST", target, body, bad, 401);
    bad = ::rut::test::signed_request::make_headers("POST", target, body, kNow - 301);
    run_h1("POST", target, body, bad, 401);
    bad = ::rut::test::signed_request::make_headers("POST", target, body, kNow + 301);
    run_h1("POST", target, body, bad, 401);
    run_h1("POST", target, body, good, 401, "authorization: duplicate\r\n");
    run_h1("POST", target, body, good, 401, "dAtE: duplicate\r\n");
    run_h1("POST", target, body, good, 401, "dIgEsT: duplicate\r\n");
    bad = good;
    bad.authorization.clear();
    run_h1("POST", target, body, bad, 401);
    bad = good;
    bad.date.clear();
    run_h1("POST", target, body, bad, 401);
    bad = good;
    bad.digest.clear();
    run_h1("POST", target, body, bad, 401);

    const size_t signature_start = good.authorization.find("signature=\"");
    REQUIRE(signature_start != std::string::npos);
    const size_t signature_value_start = signature_start + sizeof("signature=\"") - 1;
    const size_t signature_end = good.authorization.find('"', signature_value_start);
    REQUIRE(signature_end != std::string::npos);
    const std::string signature =
        good.authorization.substr(signature_value_start, signature_end - signature_value_start);
    bad = good;
    bad.authorization =
        "Signature signature=\"" + signature +
        "\",headers=\"@request-target date digest\",algorithm=\"hmac-sha256\",keyId=\"" +
        ::rut::test::signed_request::kKeyId + "\"";
    run_h1("POST", target, body, bad, 200);
    run_h1("POST", target, body, good, 401, {}, true);
    run_h1("GET", "/empty-config", body, good, 503);

    auto run_segmented_h2 = [&](const Headers& auth, u32 expected_status) {
        SmallLoop h2_loop;
        h2_loop.setup();
        h2_loop.config_ptr = &active_config;
        auto* h2_conn = h2_loop.alloc_conn();
        REQUIRE(h2_conn);
        h2_conn->json_arena.backend.pool = &pool;
        h2_conn->protocol = ConnProtocol::Http2;
        Http2Conn h2;
        h2.init();
        h2_conn->h2 = &h2;
        const u32 h2_conn_id = h2_conn->id;

        u8 initial[4096]{};
        u32 initial_len = 0;
        __builtin_memcpy(initial, kClientPreface, kClientPrefaceLen);
        initial_len += kClientPrefaceLen;
        Http2Settings settings{};
        settings.set_defaults();
        initial_len += write_settings_frame(initial + initial_len, settings);
        const std::string content_length = std::to_string(body.size());
        const hpack::Header headers[] = {
            {{":method", 7}, {"POST", 4}},
            {{":scheme", 7}, {"http", 4}},
            {{":path", 5}, {target.data(), static_cast<u32>(target.size())}},
            {{":authority", 10}, {"test", 4}},
            {{"content-length", 14},
             {content_length.data(), static_cast<u32>(content_length.size())}},
            {{"authorization", 13},
             {auth.authorization.data(), static_cast<u32>(auth.authorization.size())}},
            {{"date", 4}, {auth.date.data(), static_cast<u32>(auth.date.size())}},
            {{"digest", 6}, {auth.digest.data(), static_cast<u32>(auth.digest.size())}},
        };
        const u32 headers_len = http2_write_headers(initial + initial_len,
                                                    sizeof(initial) - initial_len,
                                                    1,
                                                    headers,
                                                    sizeof(headers) / sizeof(headers[0]),
                                                    false);
        REQUIRE_GT(headers_len, 0u);
        initial_len += headers_len;
        REQUIRE_EQ(h2_conn->recv_buf.write(initial, initial_len), initial_len);
        on_h2_data<SmallLoop>(
            &h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Recv, initial_len));
        CHECK_EQ(h2.pending_stream, 1u);
        CHECK_EQ(h2.outbound_stream, 0u);
        CHECK_EQ(signed_request_h2_status(h2_conn->send_buf.data(), h2_conn->send_buf.len(), 1),
                 0u);
        if (h2_conn->send_buf.len() != 0) {
            REQUIRE(h2_conn->on_send != nullptr);
            h2_conn->on_send(&h2_loop,
                             *h2_conn,
                             make_ev(h2_conn_id, IoEventType::Send, h2_conn->send_buf.len()));
        }
        CHECK_EQ(h2_conn->send_buf.len(), 0u);

        const std::string prefix = "first=one";
        Http2FrameHeader data_header{};
        data_header.length = prefix.size();
        data_header.type = static_cast<u8>(Http2FrameType::Data);
        data_header.stream_id = 1;
        u8 data_frame[256]{};
        write_frame_header(data_frame, data_header);
        __builtin_memcpy(data_frame + kFrameHeaderSize, prefix.data(), prefix.size());
        const u32 data_len = kFrameHeaderSize + prefix.size();
        REQUIRE_EQ(h2_conn->recv_buf.write(data_frame, data_len), data_len);
        on_h2_data<SmallLoop>(&h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Recv, data_len));
        CHECK_EQ(h2.pending_stream, 1u);
        CHECK_EQ(h2.pending_body_len, prefix.size());
        CHECK_EQ(h2.outbound_stream, 0u);
        CHECK_EQ(signed_request_h2_status(h2_conn->send_buf.data(), h2_conn->send_buf.len(), 1),
                 0u);

        const std::string suffix = body.substr(prefix.size());
        data_header.length = suffix.size();
        data_header.flags = http2_flag::kEndStream;
        write_frame_header(data_frame, data_header);
        __builtin_memcpy(data_frame + kFrameHeaderSize, suffix.data(), suffix.size());
        const u32 final_len = kFrameHeaderSize + suffix.size();
        REQUIRE_EQ(h2_conn->recv_buf.write(data_frame, final_len), final_len);
        {
            test_fault::ScopedSyscallFault clock(
                test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
            on_h2_data<SmallLoop>(
                &h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Recv, final_len));
        }
        CHECK_EQ(h2.pending_stream, 0u);
        CHECK_EQ(signed_request_h2_status(h2_conn->send_buf.data(), h2_conn->send_buf.len(), 1),
                 expected_status);
        if (expected_status == 200) {
            CHECK_EQ(h2.outbound_stream, 1u);
            CHECK((Str{reinterpret_cast<const char*>(h2.outbound_body), h2.outbound_body_len}.eq(
                lit_str("signedRequest"))));
        } else {
            CHECK_EQ(h2.outbound_stream, 0u);
        }
        h2_clear_outbound(h2);
        h2_conn->h2 = nullptr;
        release_completed_jit_json(*h2_conn);
        h2_loop.free_conn(*h2_conn);
    };
    run_segmented_h2(good, 200);
    run_segmented_h2(signed_prefix, 401);
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, rotating_signed_request_selects_and_revokes_configured_keys) {
    using ::rut::test::signed_request::Headers;
    constexpr i64 kNow = 1700000000;
    constexpr const char* kCurrentId = "current-credential";
    constexpr const char* kPreviousId = "previous-credential";
    constexpr const char* kCurrentKeyId = "rotation-current";
    constexpr const char* kPreviousKeyId = "rotation-previous";
    constexpr const char* kCurrentKey = "rotation-current-secret-32-bytes";
    constexpr const char* kPreviousKey = "rotation-previous-secret-32-bytes";
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/multi-consumer-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(R"rut(
import "middleware/auth.rut"
route "/rotate" {
    let config = auth.SignedRequestRotation(currentKeyId: "rotation-current", currentKey: "rotation-current-secret-32-bytes", previousKeyId: "rotation-previous", previousKey: "rotation-previous-secret-32-bytes", consumerId: "consumer-rotation", currentId: "current-credential", previousId: "previous-credential")
    let identity = auth.rotatingSignedRequest(config)
    let credential = identity.credentialId
    return response(200, body: credential)
}
route "/revoked" {
    let config = auth.SignedRequestRotation(currentKeyId: "rotation-current", currentKey: "rotation-current-secret-32-bytes", previousKeyId: "", previousKey: "", consumerId: "consumer-rotation", currentId: "current-credential", previousId: "previous-credential")
    let identity = auth.rotatingSignedRequest(config)
    let credential = identity.credentialId
    return response(200, body: credential)
}
route "/ambiguous" {
    let config = auth.SignedRequestRotation(currentKeyId: "rotation-current", currentKey: "rotation-current-secret-32-bytes", previousKeyId: "rotation-current", previousKey: "rotation-previous-secret-32-bytes", consumerId: "consumer-rotation", currentId: "current-credential", previousId: "previous-credential")
    let identity = auth.rotatingSignedRequest(config)
    let credential = identity.credentialId
    return response(200, body: credential)
}
route "/partial" {
    let config = auth.SignedRequestRotation(currentKeyId: "rotation-current", currentKey: "", previousKeyId: "", previousKey: "", consumerId: "consumer-rotation", currentId: "current-credential", previousId: "previous-credential")
    let identity = auth.rotatingSignedRequest(config)
    let credential = identity.credentialId
    return response(200, body: credential)
}
)rut",
                         source_path.c_str()));
    REQUIRE_EQ(program.config->route_count, 4u);
    for (u32 i = 0; i < program.config->route_count; ++i)
        CHECK(program.config->routes[i].needs_req_body);

    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(32));
    conn->json_arena.backend.pool = &pool;
    const RouteConfig* active_config = program.config.get();
    loop->config_ptr = &active_config;

    const std::string body = "first=one&second=two";
    const std::string target_query = "?x=%2F&x=two";
    auto run_h1 = [&](const char* path,
                      const Headers& auth,
                      u32 expected_status,
                      const char* expected_body = nullptr) {
        const std::string target = std::string(path) + target_query;
        const std::string head = "POST " + target +
                                 " HTTP/1.1\r\nHost: test\r\nAuthorization: " + auth.authorization +
                                 "\r\nDate: " + auth.date + "\r\nDigest: " + auth.digest +
                                 "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        const std::string prefix = "first=one";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(head.data()), head.size()),
                   head.size());
        REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(prefix.data()), prefix.size()),
                   prefix.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        const u32 conn_id = conn->id;
        {
            test_fault::ScopedSyscallFault clock(
                test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
            on_header_received<SmallLoop>(
                loop.get(),
                *conn,
                make_ev(conn_id, IoEventType::Recv, head.size() + prefix.size()));
        }
        CHECK(conn->on_recv == &on_jit_request_body_recvd<SmallLoop>);
        CHECK_EQ(conn->req_body_remaining, body.size() - prefix.size());
        CHECK_EQ(conn->send_buf.len(), 0u);
        const std::string suffix = body.substr(prefix.size());
        REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(suffix.data()), suffix.size()),
                   suffix.size());
        {
            test_fault::ScopedSyscallFault clock(
                test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
            conn->on_recv(loop.get(), *conn, make_ev(conn_id, IoEventType::Recv, suffix.size()));
        }
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        const std::string expected_status_line = "HTTP/1.1 " + std::to_string(expected_status);
        CHECK(wire.find(expected_status_line) == 0);
        if (expected_body != nullptr) CHECK(wire.ends_with(expected_body));
    };

    const std::string target = "/rotate" + target_query;
    const Headers current = ::rut::test::signed_request::make_headers(
        "POST", target, body, kNow, kCurrentKeyId, kCurrentKey);
    const Headers previous = ::rut::test::signed_request::make_headers(
        "POST", target, body, kNow, kPreviousKeyId, kPreviousKey);
    REQUIRE(!current.authorization.empty());
    REQUIRE(!previous.authorization.empty());
    run_h1("/rotate", current, 200, kCurrentId);
    run_h1("/rotate", previous, 200, kPreviousId);

    const Headers revoked = ::rut::test::signed_request::make_headers(
        "POST", "/revoked" + target_query, body, kNow, kPreviousKeyId, kPreviousKey);
    run_h1("/revoked", revoked, 401);
    const Headers unknown = ::rut::test::signed_request::make_headers(
        "POST", target, body, kNow, "unrecognized-key", kCurrentKey);
    run_h1("/rotate", unknown, 401);
    const Headers same_id_wrong_secret = ::rut::test::signed_request::make_headers(
        "POST", target, body, kNow, kCurrentKeyId, "wrong-secret-for-current-key");
    run_h1("/rotate", same_id_wrong_secret, 401);
    const Headers ambiguous = ::rut::test::signed_request::make_headers(
        "POST", "/ambiguous" + target_query, body, kNow, kCurrentKeyId, kCurrentKey);
    run_h1("/ambiguous", ambiguous, 503);
    const Headers partial = ::rut::test::signed_request::make_headers(
        "POST", "/partial" + target_query, body, kNow, kCurrentKeyId, kCurrentKey);
    run_h1("/partial", partial, 503);

    // The H2 callback path must retain the request until END_STREAM before selecting a slot.
    SmallLoop h2_loop;
    h2_loop.setup();
    h2_loop.config_ptr = &active_config;
    auto* h2_conn = h2_loop.alloc_conn();
    REQUIRE(h2_conn);
    h2_conn->json_arena.backend.pool = &pool;
    h2_conn->protocol = ConnProtocol::Http2;
    Http2Conn h2;
    h2.init();
    h2_conn->h2 = &h2;
    const u32 h2_conn_id = h2_conn->id;
    u8 initial[4096]{};
    u32 initial_len = 0;
    __builtin_memcpy(initial, kClientPreface, kClientPrefaceLen);
    initial_len += kClientPrefaceLen;
    Http2Settings settings{};
    settings.set_defaults();
    initial_len += write_settings_frame(initial + initial_len, settings);
    const std::string h2_target = "/rotate" + target_query;
    const std::string content_length = std::to_string(body.size());
    const hpack::Header headers[] = {
        {{":method", 7}, {"POST", 4}},
        {{":scheme", 7}, {"http", 4}},
        {{":path", 5}, {h2_target.data(), static_cast<u32>(h2_target.size())}},
        {{":authority", 10}, {"test", 4}},
        {{"content-length", 14}, {content_length.data(), static_cast<u32>(content_length.size())}},
        {{"authorization", 13},
         {previous.authorization.data(), static_cast<u32>(previous.authorization.size())}},
        {{"date", 4}, {previous.date.data(), static_cast<u32>(previous.date.size())}},
        {{"digest", 6}, {previous.digest.data(), static_cast<u32>(previous.digest.size())}},
    };
    const u32 headers_len = http2_write_headers(initial + initial_len,
                                                sizeof(initial) - initial_len,
                                                1,
                                                headers,
                                                sizeof(headers) / sizeof(headers[0]),
                                                false);
    REQUIRE_GT(headers_len, 0u);
    initial_len += headers_len;
    REQUIRE_EQ(h2_conn->recv_buf.write(initial, initial_len), initial_len);
    on_h2_data<SmallLoop>(&h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Recv, initial_len));
    CHECK_EQ(h2.pending_stream, 1u);
    CHECK_EQ(signed_request_h2_status(h2_conn->send_buf.data(), h2_conn->send_buf.len(), 1), 0u);
    if (h2_conn->send_buf.len() != 0)
        h2_conn->on_send(
            &h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Send, h2_conn->send_buf.len()));
    const std::string prefix = "first=one";
    Http2FrameHeader data_header{};
    data_header.length = prefix.size();
    data_header.type = static_cast<u8>(Http2FrameType::Data);
    data_header.stream_id = 1;
    u8 data_frame[256]{};
    write_frame_header(data_frame, data_header);
    __builtin_memcpy(data_frame + kFrameHeaderSize, prefix.data(), prefix.size());
    const u32 prefix_len = kFrameHeaderSize + prefix.size();
    REQUIRE_EQ(h2_conn->recv_buf.write(data_frame, prefix_len), prefix_len);
    on_h2_data<SmallLoop>(&h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Recv, prefix_len));
    CHECK_EQ(h2.pending_stream, 1u);
    CHECK_EQ(signed_request_h2_status(h2_conn->send_buf.data(), h2_conn->send_buf.len(), 1), 0u);
    const std::string suffix = body.substr(prefix.size());
    data_header.length = suffix.size();
    data_header.flags = http2_flag::kEndStream;
    write_frame_header(data_frame, data_header);
    __builtin_memcpy(data_frame + kFrameHeaderSize, suffix.data(), suffix.size());
    const u32 suffix_len = kFrameHeaderSize + suffix.size();
    REQUIRE_EQ(h2_conn->recv_buf.write(data_frame, suffix_len), suffix_len);
    {
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, kNow, 0));
        on_h2_data<SmallLoop>(
            &h2_loop, *h2_conn, make_ev(h2_conn_id, IoEventType::Recv, suffix_len));
    }
    CHECK_EQ(h2.pending_stream, 0u);
    CHECK_EQ(signed_request_h2_status(h2_conn->send_buf.data(), h2_conn->send_buf.len(), 1), 200u);
    CHECK_EQ(h2.outbound_stream, 1u);
    CHECK((Str{reinterpret_cast<const char*>(h2.outbound_body), h2.outbound_body_len}.eq(
        lit_str("previous-credential"))));
    h2_clear_outbound(h2);
    h2_conn->h2 = nullptr;
    release_completed_jit_json(*h2_conn);
    h2_loop.free_conn(*h2_conn);
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, rs256_revocation_rejects_before_identity_publication) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    std::string policy(fixture.policy.ptr, fixture.policy.len - 1);
    policy += R"(,"revokedJtis":["revoked"],"issuedAfter":50})";
    char source[8192];
    json::Writer writer{source, sizeof(source) - 1};
    writer.text(lit_str(R"rut(import "middleware/auth.rut"
route GET "/" {
    let identity = auth.jwtIdentityRs256(req.authorization.or(""), )rut"));
    REQUIRE(json::quote({policy.data(), static_cast<u32>(policy.size())}, writer));
    writer.text(lit_str(R"rut(, "read", "issuer-rs256")
    let user = identity.consumerId
    return response(200, body: user)
}
)rut"));
    REQUIRE(writer.ok);
    source[writer.len] = '\0';
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-rs256-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(source, source_path.c_str()));
    REQUIRE(program.config->activate_rs256(0));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(64));
    conn->json_arena.backend.pool = &pool;
    const struct {
        const char* extra;
        u32 status;
    } cases[] = {
        {R"(,"jti":"live","iat":51)", 200},
        {R"(,"jti":"revoked","iat":51)", 401},
        {R"(,"jti":"live","iat":50)", 401},
        {R"(,"jti":"live","iat":49)", 401},
        {R"(,"jti":"live")", 401},
        {R"(,"iat":51)", 401},
        {R"(,"jti":null,"iat":51)", 401},
        {R"(,"jti":"revo\u006bed","iat":51)", 401},
        {R"(,"jti":"Revoked","iat":51)", 200},
    };
    for (const auto& item : cases) {
        std::string claims(test::Rs256Fixture::claims.ptr, test::Rs256Fixture::claims.len - 1);
        claims += item.extra;
        claims += '}';
        char token[4096];
        const Str signed_token = fixture.sign(
            test::Rs256Fixture::header, {claims.data(), static_cast<u32>(claims.size())}, token);
        REQUIRE(signed_token.len);
        const std::string request =
            "GET / HTTP/1.1\r\nHost: test\r\nX-Consumer-ID: attacker\r\n"
            "Authorization: Bearer " +
            std::string(signed_token.ptr, signed_token.len) + "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 100, 0));
        const auto result = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(result.status_code, item.status);
        handle_jit_outcome(loop.get(), *conn, result, program.handler(), true);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        if (item.status == 200) {
            CHECK(response.ends_with("alice"));
        } else {
            CHECK(response.find("alice") == std::string::npos);
            CHECK(response.find("WWW-Authenticate: Bearer") != std::string::npos);
            CHECK(!conn->jit_response_body_valid);
        }
    }
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, es256_explicit_type_rejects_cross_purpose_tokens) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    std::string policy(fixture.policy.ptr, fixture.policy.len - 1);
    policy += R"(,"requiredType":"at+jwt"})";
    char source[8192];
    json::Writer writer{source, sizeof(source) - 1};
    writer.text(lit_str(R"rut(import "middleware/auth.rut"
route GET "/" {
    let identity = auth.jwtIdentityEs256(req.authorization.or(""), )rut"));
    REQUIRE(json::quote({policy.data(), static_cast<u32>(policy.size())}, writer));
    writer.text(lit_str(R"rut(, "read", "issuer-es256")
    let user = identity.consumerId
    return response(200, body: user)
}
)rut"));
    REQUIRE(writer.ok);
    source[writer.len] = '\0';
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-es256-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(source, source_path.c_str()));
    REQUIRE(program.config->activate_es256(0));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(64));
    conn->json_arena.backend.pool = &pool;
    const struct {
        const char* header;
        u32 status;
    } cases[] = {
        {R"({"alg":"ES256","kid":"current","typ":"at+jwt"})", 200},
        {R"({"alg":"ES256","kid":"current","typ":"JWT"})", 401},
        {R"({"alg":"ES256","kid":"current"})", 401},
        {R"({"alg":"ES256","kid":"current","typ":null})", 401},
        {R"({"alg":"ES256","kid":"current","typ":"AT+JWT"})", 401},
        {R"({"alg":"ES256","kid":"current","typ":"application/at+jwt"})", 401},
        {R"({"alg":"ES256","kid":"current","cty":"at+jwt"})", 401},
        {R"({"alg":"ES256","kid":"current","typ":"at+jwt","t\u0079p":"at+jwt"})", 401},
        {R"({"alg":"ES256","kid":"current","t\u0079p":"at\u002bjwt"})", 200},
    };
    for (const auto& item : cases) {
        char token[4096];
        // A payload claim/HTTP field named typ must never satisfy the policy.
        const Str claims = lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"scope":"read","typ":"at+jwt"})");
        const Str signed_token = fixture.sign(cstr(item.header), claims, token);
        REQUIRE(signed_token.len);
        const std::string request =
            "GET / HTTP/1.1\r\nHost: test\r\nX-Consumer-ID: attacker\r\ntyp: at+jwt\r\n"
            "Authorization: Bearer " +
            std::string(signed_token.ptr, signed_token.len) + "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 100, 0));
        const auto result = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(result.status_code, item.status);
        handle_jit_outcome(loop.get(), *conn, result, program.handler(), true);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        if (item.status == 200) {
            CHECK(response.ends_with("alice"));
        } else {
            CHECK(response.find("alice") == std::string::npos);
            CHECK(response.find("WWW-Authenticate: Bearer") != std::string::npos);
            CHECK(!conn->jit_response_body_valid);
        }
    }
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, rs256_explicit_type_rejects_cross_purpose_tokens) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    std::string policy(fixture.policy.ptr, fixture.policy.len - 1);
    policy += R"(,"requiredType":"at+jwt"})";
    char source[8192];
    json::Writer writer{source, sizeof(source) - 1};
    writer.text(lit_str(R"rut(import "middleware/auth.rut"
route GET "/" {
    let identity = auth.jwtIdentityRs256(req.authorization.or(""), )rut"));
    REQUIRE(json::quote({policy.data(), static_cast<u32>(policy.size())}, writer));
    writer.text(lit_str(R"rut(, "read", "issuer-rs256")
    let user = identity.consumerId
    return response(200, body: user)
}
)rut"));
    REQUIRE(writer.ok);
    source[writer.len] = '\0';
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-rs256-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(source, source_path.c_str()));
    REQUIRE(program.config->activate_rs256(0));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(64));
    conn->json_arena.backend.pool = &pool;
    const struct {
        const char* header;
        u32 status;
    } cases[] = {
        {R"({"alg":"RS256","kid":"current","typ":"at+jwt"})", 200},
        {R"({"alg":"RS256","kid":"current","typ":"JWT"})", 401},
        {R"({"alg":"RS256","kid":"current"})", 401},
        {R"({"alg":"RS256","kid":"current","typ":null})", 401},
        {R"({"alg":"RS256","kid":"current","typ":"AT+JWT"})", 401},
        {R"({"alg":"RS256","kid":"current","typ":"application/at+jwt"})", 401},
        {R"({"alg":"RS256","kid":"current","cty":"at+jwt"})", 401},
        {R"({"alg":"RS256","kid":"current","typ":"at+jwt","t\u0079p":"at+jwt"})", 401},
        {R"({"alg":"RS256","kid":"current","t\u0079p":"at\u002bjwt"})", 200},
    };
    for (const auto& item : cases) {
        char token[4096];
        // A payload claim/HTTP field named typ must never satisfy the policy.
        const Str claims = lit_str(
            R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"scope":"read","typ":"at+jwt"})");
        const Str signed_token = fixture.sign(cstr(item.header), claims, token);
        REQUIRE(signed_token.len);
        const std::string request =
            "GET / HTTP/1.1\r\nHost: test\r\nX-Consumer-ID: attacker\r\ntyp: at+jwt\r\n"
            "Authorization: Bearer " +
            std::string(signed_token.ptr, signed_token.len) + "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 100, 0));
        const auto result = invoke_jit_handler(
            program.handler(), conn, *ctx, conn->recv_buf.data(), conn->recv_buf.len(), nullptr);
        CHECK_EQ(result.status_code, item.status);
        handle_jit_outcome(loop.get(), *conn, result, program.handler(), true);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        if (item.status == 200) {
            CHECK(response.ends_with("alice"));
        } else {
            CHECK(response.find("alice") == std::string::npos);
            CHECK(response.find("WWW-Authenticate: Bearer") != std::string::npos);
            CHECK(!conn->jit_response_body_valid);
        }
    }
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, jwt_client_binding_requires_signed_client_claim_and_preserves_subject) {
    const std::string key = test::jwt_lifetime::kSecret;
    std::string source = "import \"middleware/auth.rut\"\n";
    const char* configurations[][4] = {
        {"issuer", "gateway", "orders-web", "issuer-key"},
        {"", "gateway", "orders-web", "issuer-key"},
        {"issuer", "", "orders-web", "issuer-key"},
        {"issuer", "gateway", "", "issuer-key"},
        {"issuer", "gateway", "orders-web", ""},
    };
    for (u32 i = 0; i < 5; ++i) {
        source += "route GET \"/" + std::to_string(i) + "\" {\n";
        source += "let doc = auth.jwtDocumentHs256(req.authorization.or(\"\"), \"" + key + "\")\n";
        source += "let identity = auth.jwtClientIdentity(doc";
        for (const char* field : configurations[i]) source += std::string(", \"") + field + "\"";
        source +=
            ")\nguard identity.credentialId == \"issuer-key\" && identity.method == \"jwt\" else { "
            "return 500 }\n";
        source += "let user = identity.consumerId\nreturn response(200, body: user)\n}\n";
    }
    JsonProgram program;
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/jwt-client-auth.rut";
    REQUIRE(program.init(source.c_str(), source_path.c_str()));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(64));
    conn->json_arena.backend.pool = &pool;
    const struct {
        const char* claims;
        u32 status;
    } cases[] = {
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":"orders-web"})",
         200},
        {R"({"sub":"bob","iss":"issuer","aud":["other","gateway"],"exp":200,"client\u005fid":"orders\u002dweb"})",
         200},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":"mobile"})", 403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":"Orders-web"})",
         403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":"orders-web-extra"})",
         403},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":"orders-web\u0000"})",
         403},
        {R"({"sub":"orders-web","iss":"issuer","aud":"gateway","exp":200,"azp":"orders-web"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":""})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":null})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":42})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":["orders-web"]})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":{}})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"client_id":"orders-web","client\u005fid":"orders-web"})",
         401},
        {R"({"sub":"alice","iss":"wrong","aud":"gateway","exp":200,"client_id":"orders-web"})",
         401},
        {R"({"sub":"alice","iss":"issuer","aud":"wrong","exp":200,"client_id":"orders-web"})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":100,"client_id":"orders-web"})",
         401},
        {R"({"sub":"","iss":"issuer","aud":"gateway","exp":200,"client_id":"orders-web"})", 401},
        {R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":200,"iat":101,"client_id":"orders-web"})",
         401},
    };
    auto run = [&](u32 route, const std::string& token, u32 expected, const char* user = "alice") {
        const std::string request =
            "GET / HTTP/1.1\r\nHost: test\r\nX-Client-ID: orders-web\r\nX-Consumer-ID: attacker\r\n"
            "Authorization: Bearer " +
            token + "\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        test_fault::ScopedSyscallFault clock(
            test_fault::fixed_clock_gettime(CLOCK_REALTIME, 100, 0));
        const auto outcome = invoke_jit_handler(program.handler(route),
                                                conn,
                                                *ctx,
                                                conn->recv_buf.data(),
                                                conn->recv_buf.len(),
                                                nullptr);
        CHECK_EQ(outcome.status_code, expected);
        handle_jit_outcome(loop.get(), *conn, outcome, program.handler(route), true);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        if (expected == 200) {
            CHECK(response.ends_with(user));
        } else {
            CHECK(response.find("alice") == std::string::npos);
            CHECK(!conn->jit_response_body_valid);
        }
        if (expected == 401) CHECK(response.find("WWW-Authenticate: Bearer") != std::string::npos);
    };
    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const std::string token = test::jwt_lifetime::make_token(cases[i].claims);
        REQUIRE(!token.empty());
        run(0, token, cases[i].status, i == 1 ? "bob" : "alice");
    }
    const std::string good = test::jwt_lifetime::make_token(cases[0].claims);
    for (u32 route = 1; route < 5; ++route) run(route, good, 503);
    std::string tampered = good;
    tampered[tampered.size() - 5] = tampered[tampered.size() - 5] == 'A' ? 'B' : 'A';
    run(0, tampered, 401);
    run(0, "malformed", 401);
    run(0, good + "\r\nauthorization: Bearer " + good, 401);
    run(0, good, 200);
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, mtls_consumer_mapping_rejects_ambiguous_ownership_and_composes_authorization) {
    const std::string first(64, 'a'), second(64, 'b'), invalid(64, 'A');
    const std::string configs[][6] = {
        {first, "alice", "alice-cert", second, "bob", "bob-cert"},
        {"", "alice", "alice-cert", second, "bob", "bob-cert"},
        {first, "alice", "alice-cert", "", "bob", "bob-cert"},
        {first, "alice", "alice-cert", first, "bob", "bob-cert"},
        {first, "alice", "alice-cert", second, "alice", "bob-cert"},
        {first, "alice", "alice-cert", invalid, "bob", "bob-cert"},
        {"short", "alice", "alice-cert", second, "bob", "bob-cert"},
        {"", "alice", "alice-cert", "", "bob", "bob-cert"},
        {first, "", "alice-cert", second, "bob", "bob-cert"},
        {first, "alice", "", second, "bob", "bob-cert"},
        {first, "alice", "alice-cert", second, "", "bob-cert"},
        {first, "alice", "alice-cert", second, "bob", ""},
    };
    std::string source = "import \"middleware/mtls.rut\"\n";
    const auto mapping = [](const std::string* c) {
        return "mtls.identity(mtls.Consumer(consumerId: \"" + c[1] + "\", sha256: \"" + c[0] +
               "\", credentialId: \"" + c[2] + "\"), mtls.Consumer(consumerId: \"" + c[4] +
               "\", sha256: \"" + c[3] + "\", credentialId: \"" + c[5] + "\"))";
    };
    for (u32 i = 0; i < 12; ++i) {
        source +=
            "route GET \"/" + std::to_string(i) + "\" {\nlet identity = " + mapping(configs[i]);
        source +=
            "\nguard identity.method == \"mtls\" else { return 500 }\n"
            "guard (identity.consumerId == \"alice\" && identity.credentialId == \"alice-cert\") "
            "|| "
            "(identity.consumerId == \"bob\" && identity.credentialId == \"bob-cert\") else { "
            "return 500 }\n"
            "let credential = identity.credentialId\n"
            "return response(200, body: credential)\n}\n";
    }
    source += "route GET \"/allow\" {\nlet identity = mtls.requireConsumer(" + mapping(configs[0]) +
              ", \"alice\")\nlet consumer = identity.consumerId\nreturn response(200, body: "
              "consumer)\n}\n";
    source += "route GET \"/deny\" {\nlet identity = mtls.denyConsumer(" + mapping(configs[0]) +
              ", \"alice\")\nlet consumer = identity.consumerId\nreturn response(200, body: "
              "consumer)\n}\n";
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/mtls-consumers-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(source.c_str(), source_path.c_str()));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(32));
    conn->json_arena.backend.pool = &pool;
    const auto run = [&](u32 route,
                         char fingerprint,
                         bool tls,
                         bool handshake,
                         bool verified,
                         u32 expected,
                         const char* body = "") {
        conn->tls_active = tls;
        conn->tls_handshake_complete = handshake;
        conn->tls_client_cert_sha256_valid = verified;
        __builtin_memset(
            conn->tls_client_cert_sha256, fingerprint, sizeof(conn->tls_client_cert_sha256));
        const std::string request =
            "GET / HTTP/1.1\r\nHost: test\r\nX-Client-Cert-Sha256: " + first +
            "\r\nX-Consumer-ID: alice\r\nX-Credential-ID: alice-cert\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        const auto outcome = invoke_jit_handler(program.config->routes[route].fn,
                                                conn,
                                                *ctx,
                                                conn->recv_buf.data(),
                                                conn->recv_buf.len(),
                                                nullptr);
        CHECK_EQ(outcome.status_code, expected);
        if (expected == 200) {
            CHECK(conn->jit_response_body_valid);
            CHECK(conn->jit_response_body.eq(cstr(body)));
        } else {
            CHECK(!conn->jit_response_body_valid);
        }
    };
    run(0, 'a', true, true, true, 200, "alice-cert");
    run(0, 'b', true, true, true, 200, "bob-cert");
    run(0, 'c', true, true, true, 403);
    run(1, 'a', true, true, true, 403);
    run(1, 'b', true, true, true, 200, "bob-cert");
    run(2, 'a', true, true, true, 200, "alice-cert");
    run(2, 'b', true, true, true, 403);
    for (u32 route = 3; route < 12; ++route) {
        run(route, 'a', true, true, true, 503);
        run(route, 'b', true, true, true, 503);
        run(route, 'a', false, false, false, 503);
    }
    run(0, 'a', false, false, false, 403);
    run(0, 'a', true, false, true, 403);
    run(0, 'a', true, true, false, 403);
    run(0, 'a', false, true, true, 403);
    run(12, 'a', true, true, true, 200, "alice");
    run(12, 'b', true, true, true, 403);
    run(13, 'a', true, true, true, 403);
    run(13, 'b', true, true, true, 200, "bob");
    run(12, 'c', true, true, true, 403);
    run(0, 'a', true, true, true, 200, "alice-cert");
    conn->tls_active = false;
    conn->tls_handshake_complete = false;
    conn->tls_client_cert_sha256_valid = false;
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, rotating_mtls_pins_validate_configuration_and_map_only_verified_certificates) {
    const std::string first(64, 'a'), second(64, 'b'), invalid(64, 'A');
    const std::string configurations[][5] = {
        {first, second, "customer", "current", "previous"},
        {first, "", "customer", "current", "previous"},
        {"", second, "customer", "current", "previous"},
        {first, first, "customer", "current", "previous"},
        {"", "", "customer", "current", "previous"},
        {first, invalid, "customer", "current", "previous"},
        {"short", second, "customer", "current", "previous"},
        {first, second, "", "current", "previous"},
        {first, second, "customer", "", "previous"},
        {first, second, "customer", "current", ""},
    };
    std::string source = "import \"middleware/auth.rut\"\n";
    for (u32 i = 0; i < 10; ++i) {
        source += "route GET \"/" + std::to_string(i) + "\" {\n";
        source += "let identity = auth.rotatingPinnedMtlsIdentity(";
        for (u32 j = 0; j < 5; ++j) {
            if (j) source += ", ";
            source += "\"" + configurations[i][j] + "\"";
        }
        source +=
            ")\nguard identity.consumerId == \"customer\" && identity.method == \"mtls\" else { "
            "return 500 }\n";
        source +=
            "let credential = identity.credentialId\nreturn response(200, body: credential)\n}\n";
    }
    const std::string file = __FILE__;
    const std::string source_path =
        file.substr(0, file.rfind("/tests/")) + "/examples/mtls-rotating-auth.rut";
    JsonProgram program;
    REQUIRE(program.init(source.c_str(), source_path.c_str()));
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    SlicePool pool;
    REQUIRE(pool.init(32));
    conn->json_arena.backend.pool = &pool;
    auto run = [&](u32 route,
                   char fingerprint,
                   bool tls,
                   bool handshake,
                   bool verified,
                   u32 expected,
                   const char* credential = "") {
        conn->tls_active = tls;
        conn->tls_handshake_complete = handshake;
        conn->tls_client_cert_sha256_valid = verified;
        __builtin_memset(
            conn->tls_client_cert_sha256, fingerprint, sizeof(conn->tls_client_cert_sha256));
        const std::string request =
            "GET / HTTP/1.1\r\nHost: test\r\nX-Client-Cert-Sha256: " + first +
            "\r\nX-Consumer-ID: customer\r\nX-Credential-ID: current\r\n\r\n";
        release_completed_jit_json(*conn);
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = program.config.get();
        auto* ctx = conn->reset_jit_ctx();
        const auto outcome = invoke_jit_handler(program.handler(route),
                                                conn,
                                                *ctx,
                                                conn->recv_buf.data(),
                                                conn->recv_buf.len(),
                                                nullptr);
        CHECK_EQ(outcome.status_code, expected);
        if (expected == 200) {
            CHECK(conn->jit_response_body_valid);
            CHECK(conn->jit_response_body.eq(cstr(credential)));
        } else {
            CHECK(!conn->jit_response_body_valid);
        }
    };
    run(0, 'a', true, true, true, 200, "current");
    run(0, 'b', true, true, true, 200, "previous");
    run(0, 'c', true, true, true, 403);
    run(1, 'a', true, true, true, 200, "current");
    run(1, 'b', true, true, true, 403);
    run(2, 'a', true, true, true, 403);
    run(2, 'b', true, true, true, 200, "previous");
    run(3, 'a', true, true, true, 200, "current");
    run(3, 'b', true, true, true, 403);
    for (u32 route = 4; route < 10; ++route) {
        run(route, 'a', true, true, true, 503);
        run(route, 'b', true, true, true, 503);
        run(route, 'a', false, false, false, 503);
    }
    run(0, 'a', false, false, false, 403);
    run(0, 'a', true, false, true, 403);
    run(0, 'a', true, true, false, 403);
    run(0, 'a', false, true, true, 403);
    run(0, 'a', true, true, true, 200, "current");
    conn->tls_active = false;
    conn->tls_handshake_complete = false;
    conn->tls_client_cert_sha256_valid = false;
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, forward_auth_jit_suspends_before_effects_and_fails_closed) {
    JsonProgram program;
    REQUIRE(program.init(R"rut(route GET "/private" {
        let decision = forwardAuthHeader("Authorization", "{\"address\":\"127.0.0.1\",\"serverName\":\"localhost\",\"caFile\":\"/missing/rut-forward-auth-ca.pem\",\"path\":\"/authorize\",\"identityHeader\":\"X-Consumer-ID\"}", 1000)
        match decision {
            1 => {
                req.set("X-Should-Not-Run", "yes")
                return 200
            }
            _ => return 503
        }
    })rut"));
    REQUIRE(program.config->requires_password_gateway());
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    ConnectionBase conn{};
    conn.reset();
    conn.fd = 42;
    conn.id = 1;
    conn.handler_gen = 1;
    conn.transition_to_exec_handler_wait();
    jit::HandlerCtx ctx{};
    const char request[] =
        "GET /private HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer secret\r\n\r\n";
    const auto handler = program.handler();
    REQUIRE(handler != nullptr);
    const auto deadline = monotonic_us() + 2000000;
    u32 yields = 0;
    for (;;) {
        PasswordHandlerScope scope(&gateway, &conn);
        const auto reply = jit::HandlerResult::unpack(handler(
            &conn, &ctx, reinterpret_cast<const u8*>(request), sizeof(request) - 1, nullptr));
        CHECK_EQ(conn.req_header_override_count, 0u);
        if (reply.action != jit::HandlerAction::Yield) {
            CHECK_EQ(reply.status_code, 503u);
            break;
        }
        ++yields;
        CHECK(reply.yield_kind == jit::YieldKind::Timer);
        CHECK_EQ(reply.next_state, 0u);
        REQUIRE(monotonic_us() < deadline);
        usleep(1000);
    }
    CHECK(yields > 0);
}
