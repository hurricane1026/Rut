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
#include "test.h"
#include "test_helpers.h"
#include <memory>
#include <string>
#include <utility>

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

    auto decode = [&](const char* secret, const char* jwt = nullptr) {
        if (jwt == nullptr) jwt = token;
        u8 has = 0;
        const char* out = nullptr;
        u32 len = 0;
        i64 number = 0;
        rut_helper_json(nullptr,
                        &arena,
                        static_cast<u32>(json::Op::JwtDecode),
                        jwt,
                        static_cast<u32>(__builtin_strlen(jwt)),
                        secret,
                        static_cast<u32>(__builtin_strlen(secret)),
                        nullptr,
                        0,
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

TEST(json_network, jit_jwt_decode_returns_claims_subject) {
    REQUIRE_EQ(setenv("RUT_TEST_JWT_SECRET", "01234567890123456789012345678901", 1), 0);
    JsonProgram program;
    REQUIRE(program.init(R"rut(
route POST "/jwt" {
    guard let token = req.header("Authorization") else { return 401 }
    guard let claims = jwtDecode(token, env("RUT_TEST_JWT_SECRET")) else { return 401 }
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

TEST(json_network, grpc_local_trailers_follow_data_without_flow_control_credit) {
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    auto* stream = &h2->streams[0];
    stream->state = Http2StreamState::HalfClosedRemote;
    const u8 body[] = {0, 0, 0, 0, 0};
    h2->outbound_stream = 1;
    h2->outbound_body = body;
    h2->outbound_body_len = sizeof(body);
    h2->outbound_grpc_status = 16;
    stream->send_window = 2;
    h2->conn_send_window = 5;
    u8 bytes[128];
    H2PumpStatus status{};
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 11u);
    CHECK_EQ(bytes[3], 0u);
    CHECK_EQ(bytes[4] & 1u, 0u);
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 0u);
    stream->send_window = 3;
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 12u);
    CHECK_EQ(bytes[4] & 1u, 0u);
    CHECK(!h2->outbound_final_staged);
    CHECK_EQ(h2->conn_send_window, 0);
    CHECK_EQ(stream->send_window, 0);
    // Too-small output cannot retire the stream or lose the pending status.
    CHECK_EQ(h2_pump_outbound(*h2, bytes, 9, status), 0u);
    CHECK(!h2->outbound_final_staged);
    CHECK(h2_pump_outbound(*h2, bytes, sizeof(bytes), status) > 9u);
    CHECK_EQ(bytes[3], 1u);  // HEADERS
    CHECK_EQ(bytes[4] & 1u, 1u);
    CHECK(h2->outbound_final_staged);
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 0u);
    h2_clear_outbound(*h2);
    CHECK_EQ(h2->outbound_grpc_status, 255u);
    CHECK_EQ(h2->queued_grpc_status, 255u);
    h2->queued_stream = 3;
    h2->queued_body = body;
    h2->queued_body_len = sizeof(body);
    h2->queued_source = H2OutboundBodySource::RouteConfig;
    h2->queued_grpc_status = 7;
    h2_promote_queued(*h2);
    CHECK_EQ(h2->outbound_stream, 3u);
    CHECK_EQ(h2->outbound_grpc_status, 7u);
    CHECK_EQ(h2->queued_grpc_status, 255u);
    h2_clear_outbound(*h2);
    h2->outbound_stream = 1;
    h2->outbound_body = body;
    h2->outbound_body_len = sizeof(body);
    h2->conn_send_window = 5;
    stream->send_window = 5;
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 14u);
    CHECK_EQ(bytes[4] & 1u, 1u);  // Ordinary HTTP still ends on its final DATA.
}

TEST(json_network, grpc_local_response_rejects_invalid_status_or_frame_before_staging) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    auto h2 = std::make_unique<Http2Conn>();
    conn->h2 = h2.get();
    const char good[] = {0, 0, 0, 0, 0};
    const char compressed[] = {1, 0, 0, 0, 0};
    const char truncated[] = {0, 0, 0, 0, 1};
    const Str bodies[] = {{good, 5},
                          {good, 5},
                          {good, 5},
                          {good, 5},
                          {"bad", 3},
                          {compressed, 5},
                          {truncated, 5},
                          {good, 5},
                          {good, 5},
                          {good, 5},
                          {good, 5}};
    const Str statuses[] = {{"17", 2},
                            {"00", 2},
                            {"-1", 2},
                            {"", 0},
                            {"0", 1},
                            {"0", 1},
                            {"0", 1},
                            {"0", 1},
                            {"0", 1},
                            {"0", 1},
                            {"0", 1}};
    for (u32 i = 0; i < 11; ++i) {
        h2->init();
        h2->nstreams = 1;
        h2->streams[0].id = 1;
        h2->streams[0].state = Http2StreamState::HalfClosedRemote;
        conn->epoch_held = true;
        conn->jit_response_body_valid = true;
        conn->jit_response_body = bodies[i];
        conn->resp_header_mutation_count = 2;
        conn->resp_header_mutations[0] = {{"content-type", 12},
                                          {"application/grpc", 16},
                                          Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[1] = {
            {"grpc-status", 11}, statuses[i], Connection::RespHeaderMutationMode::Set};
        if (i == 9 || i == 10) {
            conn->resp_header_mutation_count = 3;
            conn->resp_header_mutations[2] =
                i == 9 ? conn->resp_header_mutations[1] : conn->resp_header_mutations[0];
            conn->resp_header_mutations[2].mode = Connection::RespHeaderMutationMode::Add;
        }
        JitDispatchOutcome outcome{};
        outcome.status_code = i == 7 ? 201 : 200;
        outcome.response_body_idx = 0xffffu;
        u8 response[1024];
        H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
        h2_emit_outcome(dispatch, 1, outcome, nullptr, i == 8);
        CHECK_EQ(h2->outbound_stream, 0u);
        CHECK_EQ(h2->queued_stream, 0u);
        Http2FrameHeader frame{};
        REQUIRE_EQ(parse_frame_header(response, dispatch.resp_len, &frame), ParseStatus::Complete);
        CHECK_EQ(frame.flags & http2_flag::kEndStream, http2_flag::kEndStream);
        hpack::DynamicTable decoder;
        decoder.init(kDefaultHeaderTableSize);
        hpack::Header headers[8];
        u8 scratch[256];
        u32 count = 0;
        REQUIRE(hpack::decode_header_block(decoder,
                                           response + kFrameHeaderSize,
                                           frame.length,
                                           scratch,
                                           sizeof(scratch),
                                           headers,
                                           8,
                                           &count));
        bool failed_closed = false;
        for (u32 j = 0; j < count; ++j)
            failed_closed |=
                headers[j].name.eq(lit_str(":status")) && headers[j].value.eq(lit_str("500"));
        CHECK(failed_closed);
    }
    conn->h2 = nullptr;
    loop->free_conn(*conn);
}
