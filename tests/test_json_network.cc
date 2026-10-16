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
#include "test.h"
#include "test_helpers.h"
#include <memory>
#include <string>

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
