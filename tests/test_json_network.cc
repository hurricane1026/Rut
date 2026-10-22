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

static u32 web_admission_calls;
static u32 web_admission_body_len;
static u8 web_admission_flag;
static u64 web_admission_handler(void*, jit::HandlerCtx* ctx, const u8* raw, u32 len, void*) {
    ++web_admission_calls;
    const char* body = nullptr;
    rut_helper_req_body_ctx(raw, len, ctx, &body, &web_admission_body_len);
    web_admission_flag = web_admission_body_len ? static_cast<u8>(body[0]) : 255;
    return jit::HandlerResult::make_status(422).pack();
}

struct H1DeadlineLoop : SmallLoop {
    bool active_deadline_at_send = false;
    bool submit_send(Connection& conn, const u8* bytes, u32 len) {
        active_deadline_at_send |=
            conn.on_local_grpc_deadline != nullptr || conn.local_grpc_deadline.present;
        return SmallLoop::submit_send(conn, bytes, len);
    }
    bool arm_local_grpc_deadline(Connection& conn, u64 absolute_us) {
        return conn.local_grpc_deadline_timer.arm(absolute_us);
    }
    void disarm_local_grpc_deadline(Connection& conn) {
        if (conn.local_grpc_deadline_timer.target_owned)
            conn.local_grpc_deadline_timer.reclaim_target(
                conn.local_grpc_deadline_timer.owner_generation);
        conn.on_local_grpc_deadline = nullptr;
        conn.local_grpc_deadline.reset();
    }
    void disarm_yield_timer(Connection& conn) { conn.yield_armed = false; }
};

static u32 h1_deadline_handler_calls;
static u64 h1_deadline_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    ++h1_deadline_handler_calls;
    return jit::HandlerResult::make_status(204).pack();
}

TEST(json_network, h1_grpc_web_zero_timeout_expires_before_handler_binary_and_text) {
    const std::string binary_body("\0\0\0\0\1x", 6);
    for (const char* content_type : {"application/grpc-web", "application/grpc-web-text"}) {
        const std::string body = content_type[20] == '-' ? "AAAAAAF4" : binary_body;
        const std::string request =
            std::string("POST /body HTTP/1.1\r\nHost: test\r\n") + "Content-Type: " + content_type +
            "\r\ngrpc-timeout: 0n\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" +
            body;
        auto loop = std::make_unique<H1DeadlineLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
        const RouteConfig* config_ptr = config.get();
        loop->config_ptr = &config_ptr;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        u8 input[1024];
        conn->recv_buf.bind(input, sizeof(input));
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        h1_deadline_handler_calls = 0;
        on_header_received<H1DeadlineLoop>(
            loop.get(),
            *conn,
            {conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(h1_deadline_handler_calls, 0u);
        CHECK_EQ(conn->resp_status, 200u);
        CHECK(conn->send_buf.len() > 0);
        CHECK(conn->on_local_grpc_deadline == nullptr);
        loop->free_conn(*conn);
        pool.destroy();
    }
}

static u64 h1_deadline_yield_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    ++h1_deadline_handler_calls;
    if (ctx->state == 0) return jit::HandlerResult::make_yield(1, jit::YieldKind::Timer).pack();
    return jit::HandlerResult::make_status(204).pack();
}

TEST(json_network, h1_grpc_web_deadline_rejects_invalid_duplicate_and_expires_partial_bodies) {
    const std::string body("\0\0\0\0\1x", 6);
    const char* bad_headers[] = {"grpc-timeout: 1S\r\ngrpc-timeout: 2S\r\n",
                                 "grpc-timeout: bad\r\n"};
    for (const char* extra : bad_headers) {
        const std::string request = std::string("POST /body HTTP/1.1\r\nHost: test\r\n") +
                                    "Content-Type: application/grpc-web\r\n" + extra +
                                    "Content-Length: 6\r\n\r\n" + body;
        auto loop = std::make_unique<H1DeadlineLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
        const RouteConfig* config_ptr = config.get();
        loop->config_ptr = &config_ptr;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        u8 input[1024];
        conn->recv_buf.bind(input, sizeof(input));
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        h1_deadline_handler_calls = 0;
        on_header_received<H1DeadlineLoop>(
            loop.get(),
            *conn,
            {conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(conn->resp_status, 400u);
        CHECK_EQ(h1_deadline_handler_calls, 0u);
        CHECK_FALSE(conn->local_grpc_deadline_timer.target_owned);
        loop->free_conn(*conn);
        pool.destroy();
    }

    const std::string partial_header =
        "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web\r\n"
        "grpc-timeout: 1S\r\nContent-Length: 6\r\n\r\n";
    auto loop = std::make_unique<H1DeadlineLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto config = std::make_unique<RouteConfig>();
    REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
    const RouteConfig* config_ptr = config.get();
    loop->config_ptr = &config_ptr;
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->fd = 41;
    conn->json_arena.backend.pool = &pool;
    u8 input[1024];
    conn->recv_buf.bind(input, sizeof(input));
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(partial_header.data()),
                                    partial_header.size()),
               partial_header.size());
    on_header_received<H1DeadlineLoop>(
        loop.get(),
        *conn,
        {conn->id, static_cast<i32>(partial_header.size()), 0, 0, IoEventType::Recv, 0});
    REQUIRE(conn->on_local_grpc_deadline != nullptr);
    auto timeout = conn->on_local_grpc_deadline;
    timeout(loop.get(), *conn, {conn->id, -ETIME, 0, 0, IoEventType::LocalGrpcDeadlineTimer, 0});
    CHECK_EQ(conn->resp_status, 200u);
    CHECK_FALSE(conn->keep_alive);
    const std::string binary_wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                                  conn->send_buf.len());
    CHECK(binary_wire.find("grpc-status: 4\r\n") != std::string::npos);
    CHECK(conn->local_grpc_deadline_timer.reusable());
    loop->free_conn(*conn);
    pool.destroy();

    const std::string chunked_header =
        "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web-text\r\n"
        "grpc-timeout: 1S\r\nTransfer-Encoding: chunked\r\n\r\n";
    auto text_loop = std::make_unique<H1DeadlineLoop>();
    text_loop->setup();
    SlicePool text_pool;
    REQUIRE(text_pool.init(16));
    auto text_config = std::make_unique<RouteConfig>();
    REQUIRE(text_config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
    const RouteConfig* text_config_ptr = text_config.get();
    text_loop->config_ptr = &text_config_ptr;
    auto* text_conn = text_loop->alloc_conn();
    REQUIRE(text_conn);
    text_conn->fd = 41;
    text_conn->json_arena.backend.pool = &text_pool;
    u8 text_input[1024];
    text_conn->recv_buf.bind(text_input, sizeof(text_input));
    REQUIRE_EQ(text_conn->recv_buf.write(reinterpret_cast<const u8*>(chunked_header.data()),
                                         chunked_header.size()),
               chunked_header.size());
    on_header_received<H1DeadlineLoop>(
        text_loop.get(),
        *text_conn,
        {text_conn->id, static_cast<i32>(chunked_header.size()), 0, 0, IoEventType::Recv, 0});
    REQUIRE(text_conn->on_local_grpc_deadline != nullptr);
    auto text_timeout = text_conn->on_local_grpc_deadline;
    text_timeout(text_loop.get(),
                 *text_conn,
                 {text_conn->id, -ETIME, 0, 0, IoEventType::LocalGrpcDeadlineTimer, 0});
    CHECK_EQ(text_conn->resp_status, 200u);
    const std::string text_wire(reinterpret_cast<const char*>(text_conn->send_buf.data()),
                                text_conn->send_buf.len());
    CHECK(text_wire.find("gAAAABBncnBjLXN0YXR1czogNA0K") != std::string::npos);
    CHECK(text_conn->local_grpc_deadline_timer.reusable());
    text_loop->free_conn(*text_conn);
    text_pool.destroy();
}

TEST(json_network, h1_grpc_web_unsupported_timer_backend_preserves_legacy_requests) {
    for (const char* timeout : {"1S", "bad"}) {
        auto loop = std::make_unique<SmallLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
        const RouteConfig* active = config.get();
        loop->config_ptr = &active;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        const std::string request =
            std::string(
                "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web\r\n") +
            "grpc-timeout: " + timeout + "\r\nContent-Length: 6\r\n\r\n" +
            std::string("\0\0\0\0\1x", 6);
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        h1_deadline_handler_calls = 0;
        on_header_received<SmallLoop>(
            loop.get(),
            *conn,
            {conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(h1_deadline_handler_calls, 1u);
        CHECK_EQ(conn->resp_status, 204u);
        CHECK_FALSE(conn->local_grpc_deadline.present);
        CHECK(conn->local_grpc_deadline_timer.reusable());
        loop->free_conn(*conn);
        pool.destroy();
    }
}

TEST(json_network, h1_grpc_web_expiry_wins_over_malformed_envelopes) {
    for (bool fragmented : {false, true}) {
        auto loop = std::make_unique<H1DeadlineLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
        const RouteConfig* active = config.get();
        loop->config_ptr = &active;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        const std::string header =
            std::string(
                "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web\r\n") +
            (fragmented ? "grpc-timeout: 1S\r\n" : "grpc-timeout: 0n\r\n") +
            "Content-Length: 6\r\n\r\n";
        const std::string malformed("\1\0\0\0\1x", 6);
        const std::string request = header + (fragmented ? std::string() : malformed);
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        h1_deadline_handler_calls = 0;
        on_header_received<H1DeadlineLoop>(
            loop.get(),
            *conn,
            {conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        if (fragmented) {
            REQUIRE(conn->on_local_grpc_deadline != nullptr);
            conn->local_grpc_deadline.deadline_us = monotonic_us() - 1;
            REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(malformed.data()),
                                            malformed.size()),
                       malformed.size());
            on_jit_request_body_recvd<H1DeadlineLoop>(
                loop.get(),
                *conn,
                {conn->id, static_cast<i32>(malformed.size()), 0, 0, IoEventType::Recv, 0});
        }
        CHECK_EQ(h1_deadline_handler_calls, 0u);
        CHECK_EQ(conn->resp_status, 200u);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        CHECK(wire.find("grpc-status: 4") != std::string::npos);
        CHECK(conn->local_grpc_deadline_timer.reusable());
        loop->free_conn(*conn);
        pool.destroy();
    }
}

TEST(json_network, h1_grpc_web_expiry_replaces_formatted_unsent_segmented_response) {
    auto loop = std::make_unique<H1DeadlineLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->fd = 41;
    conn->json_arena.backend.pool = &pool;
    conn->local_grpc_deadline.present = true;
    conn->local_grpc_deadline.deadline_us = monotonic_us() - 1;
    conn->local_grpc_deadline_mode = static_cast<u8>(GrpcWebContentType::Binary);
    conn->on_local_grpc_deadline = &on_local_grpc_deadline_expired<H1DeadlineLoop>;
    REQUIRE(loop->arm_local_grpc_deadline(*conn, conn->local_grpc_deadline.deadline_us));
    format_static_response(*conn, 200, true);
    const u8 staged[] = "unsent normal response";
    conn->local_body_cursor = staged;
    conn->local_body_base = staged;
    conn->local_body_remaining = sizeof(staged);
    conn->local_body_send_len = sizeof(staged);
    conn->local_body_file_fd = 123;
    conn->local_response_size = 100000;
    CHECK_FALSE(prepare_local_grpc_deadline_publication(loop.get(), *conn));
    CHECK_FALSE(loop->active_deadline_at_send);
    CHECK(conn->local_grpc_deadline_timer.reusable());
    CHECK_EQ(conn->local_body_remaining, 0u);
    CHECK_EQ(conn->local_body_send_len, 0u);
    CHECK_EQ(conn->local_body_file_fd, -1);
    CHECK(conn->local_body_base == nullptr);
    const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                           conn->send_buf.len());
    CHECK(wire.find("grpc-status: 4") != std::string::npos);
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, h1_grpc_web_malformed_chunk_settles_before_response_publication) {
    auto loop = std::make_unique<H1DeadlineLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto config = std::make_unique<RouteConfig>();
    REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
    const RouteConfig* active = config.get();
    loop->config_ptr = &active;
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->fd = 41;
    conn->json_arena.backend.pool = &pool;
    const char request[] =
        "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web\r\n"
        "grpc-timeout: 1S\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n";
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request), sizeof(request) - 1),
               sizeof(request) - 1);
    h1_deadline_handler_calls = 0;
    on_header_received<H1DeadlineLoop>(
        loop.get(), *conn, {conn->id, sizeof(request) - 1, 0, 0, IoEventType::Recv, 0});
    CHECK_EQ(h1_deadline_handler_calls, 0u);
    CHECK_EQ(conn->resp_status, 400u);
    CHECK_FALSE(loop->active_deadline_at_send);
    CHECK(conn->local_grpc_deadline_timer.reusable());
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, h1_grpc_web_timer_yield_expiry_does_not_resume) {
    const std::string body("\0\0\0\0\1x", 6);
    const std::string request =
        "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web\r\n"
        "grpc-timeout: 1S\r\nContent-Length: 6\r\n\r\n" +
        body;
    auto loop = std::make_unique<H1DeadlineLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto config = std::make_unique<RouteConfig>();
    REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_yield_handler, true));
    const RouteConfig* config_ptr = config.get();
    loop->config_ptr = &config_ptr;
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->fd = 41;
    conn->json_arena.backend.pool = &pool;
    u8 input[1024];
    conn->recv_buf.bind(input, sizeof(input));
    REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
               request.size());
    h1_deadline_handler_calls = 0;
    on_header_received<H1DeadlineLoop>(
        loop.get(),
        *conn,
        {conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
    CHECK_EQ(h1_deadline_handler_calls, 1u);
    REQUIRE(conn->on_local_grpc_deadline != nullptr);
    auto timeout = conn->on_local_grpc_deadline;
    timeout(loop.get(), *conn, {conn->id, -ETIME, 0, 0, IoEventType::LocalGrpcDeadlineTimer, 0});
    CHECK_EQ(h1_deadline_handler_calls, 1u);
    CHECK_EQ(conn->resp_status, 200u);
    CHECK(conn->on_local_grpc_deadline == nullptr);
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, h1_grpc_web_deadline_rejects_forward_and_event_yields_before_io) {
    for (auto kind : {JitDispatchOutcome::Kind::Forward, JitDispatchOutcome::Kind::EventYield}) {
        for (auto yield : {jit::YieldKind::Send, jit::YieldKind::Recv, jit::YieldKind::HttpGet}) {
            auto loop = std::make_unique<H1DeadlineLoop>();
            loop->setup();
            auto* conn = loop->alloc_conn();
            REQUIRE(conn);
            conn->fd = 41;
            conn->local_grpc_deadline.present = true;
            conn->local_grpc_deadline.deadline_us = monotonic_us() + 1000000;
            conn->local_grpc_deadline_mode = static_cast<u8>(GrpcWebContentType::Binary);
            conn->on_local_grpc_deadline = &on_local_grpc_deadline_expired<H1DeadlineLoop>;
            REQUIRE(loop->arm_local_grpc_deadline(*conn, conn->local_grpc_deadline.deadline_us));
            JitDispatchOutcome outcome{};
            outcome.kind = kind;
            outcome.yield_kind = yield;
            handle_jit_outcome(loop.get(), *conn, outcome, &h1_deadline_handler, true, nullptr);
            CHECK_EQ(conn->resp_status, 400u);
            CHECK_FALSE(loop->active_deadline_at_send);
            CHECK(conn->local_grpc_deadline_timer.reusable());
            CHECK(conn->pending_handler_fn == nullptr);
            for (u32 i = 0; i < loop->backend.op_count; ++i) {
                const auto& op = loop->backend.ops[i];
                CHECK(op.type != MockOp::Connect);
                CHECK(op.type != MockOp::Recv);
                if (op.type == MockOp::Send) CHECK_EQ(op.fd, conn->fd);
            }
            loop->free_conn(*conn);
        }
    }
}

static u64 h1_deadline_overrun_handler(void* opaque, jit::HandlerCtx*, const u8*, u32, void*) {
    auto& conn = *static_cast<Connection*>(opaque);
    ++h1_deadline_handler_calls;
    // Model a synchronous handler that crosses the request's absolute boundary.
    conn.local_grpc_deadline.deadline_us = monotonic_us() - 1;
    return jit::HandlerResult::make_status(204).pack();
}

TEST(json_network, h1_grpc_web_sync_outcome_deadline_arbitration) {
    for (bool overrun : {false, true}) {
        auto loop = std::make_unique<H1DeadlineLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler(
            "/body", 0, overrun ? &h1_deadline_overrun_handler : &h1_deadline_handler, true));
        const RouteConfig* active = config.get();
        loop->config_ptr = &active;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        const std::string request =
            std::string(
                "POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: application/grpc-web\r\n") +
            "grpc-timeout: 1S\r\nContent-Length: 6\r\n\r\n" + std::string("\0\0\0\0\1x", 6);
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        h1_deadline_handler_calls = 0;
        on_header_received<H1DeadlineLoop>(
            loop.get(),
            *conn,
            {conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(h1_deadline_handler_calls, 1u);
        CHECK_EQ(conn->resp_status, overrun ? 200u : 204u);
        CHECK(conn->on_local_grpc_deadline == nullptr);
        CHECK_FALSE(conn->local_grpc_deadline.present);
        CHECK(conn->local_grpc_deadline_timer.reusable());
        CHECK_FALSE(loop->active_deadline_at_send);
        const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
        CHECK_EQ(wire.find("grpc-status: 4") != std::string::npos, overrun);
        loop->free_conn(*conn);
        pool.destroy();
    }
}

TEST(json_network, h1_grpc_web_slow_body_real_sync_backend_socket) {
    // Use the production timer heap, send backend and real socket ownership.
    // The request stops in the middle of either transport framing shape.
    for (bool chunked : {false, true}) {
        struct Cleanup {
            RealLoop* loop = nullptr;
            Connection* conn = nullptr;
            i32 peer = -1;
            bool initialized = false;
            ~Cleanup() {
                if (initialized) {
                    if (conn && conn->fd >= 0) loop->close_conn(*conn);
                    loop->shutdown();
                }
                if (peer >= 0) close(peer);
                destroy_real_loop(loop);
            }
        } guard;
        guard.loop = create_real_loop();
        REQUIRE(guard.loop);
        REQUIRE(guard.loop->init(0, -1, 0).has_value());
        guard.initialized = true;
        i32 sockets[2];
        REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
        guard.peer = sockets[1];
        REQUIRE_EQ(fcntl(sockets[0], F_SETFL, O_NONBLOCK), 0);
        REQUIRE_EQ(fcntl(sockets[1], F_SETFL, O_NONBLOCK), 0);
        guard.conn = guard.loop->alloc_conn();
        REQUIRE(guard.conn);
        auto& conn = *guard.conn;
        conn.fd = sockets[0];
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &h1_deadline_handler, true));
        const RouteConfig* config_ptr = config.get();
        guard.loop->config_ptr = &config_ptr;
        const std::string request =
            std::string("POST /body HTTP/1.1\r\nHost: test\r\nContent-Type: ") +
            (chunked ? "application/grpc-web-text\r\n" : "application/grpc-web\r\n") +
            "grpc-timeout: 100m\r\n" +
            (chunked ? "Transfer-Encoding: chunked\r\n\r\n8\r\nAA" : "Content-Length: 6\r\n\r\nx");
        REQUIRE_EQ(conn.recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
                   request.size());
        h1_deadline_handler_calls = 0;
        on_header_received<RealLoop>(
            guard.loop,
            conn,
            {conn.id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        REQUIRE(conn.local_grpc_deadline.present);
        const u64 deadline = conn.local_grpc_deadline.deadline_us;
        while (monotonic_us() < deadline) usleep(100);
        guard.loop->drain_yield_heap();
        CHECK_EQ(h1_deadline_handler_calls, 0u);
        CHECK(conn.req_body_abandoned);
        CHECK_FALSE(conn.keep_alive);
        CHECK(conn.local_grpc_deadline_timer.reusable());
        char wire[1024]{};
        const i32 received = recv_timeout(guard.peer, wire, sizeof(wire) - 1, 1000);
        REQUIRE_GT(received, 0);
        const std::string response(wire, received);
        CHECK(response.find("HTTP/1.1 200") == 0);
        CHECK(response.find("Connection: close") != std::string::npos);
        CHECK(response.find(chunked ? "gAAAABBncnBjLXN0YXR1czogNA0K" : "grpc-status: 4") !=
              std::string::npos);
        // A late receive is discarded through the abandoned-upload path.
        const u32 response_len = conn.send_buf.len();
        guard.loop->handle_unhandled_recv(conn, {conn.id, -ENOBUFS, 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(conn.resp_status, 200u);
        CHECK_EQ(conn.send_buf.len(), response_len);
        CHECK_GE(conn.fd, 0);
    }
}

TEST(json_network, grpc_web_runtime_admission_precedes_handler) {
    const std::string valid("\0\0\0\0\1x", 6);
    struct Case {
        const char* method;
        const char* headers;
        std::string body;
        bool accepted;
        bool fail_arena = false;
    };
    const Case cases[] = {
        {"POST", "Content-Type: application/grpc-web\r\n", valid, true},
        {"POST", "Content-Type: application/grpc-web+proto\r\n", valid, true},
        {"POST", "Content-Type: application/grpc-web-text+proto\r\n", "AAAAAAF4", true},
        // Each source byte is independently padded, including the frame prefix.
        {"POST", "Content-Type: application/grpc-web-text\r\n", "AA==AA==AA==AA==AQ==eA==", true},
        {"GET", "Content-Type: application/grpc-web\r\n", valid, false},
        {"POST", "Content-Type: application/grpc-web+json\r\n", valid, false},
        {"POST",
         "Content-Type: application/grpc-web\r\nContent-Type: text/plain\r\n",
         valid,
         false},
        {"POST",
         "Content-Type: text/plain\r\nContent-Type: application/grpc-web\r\n",
         valid,
         false},
        {"POST", "Content-Type: application/grpc-web\r\n", std::string("\1\0\0\0\1x", 6), false},
        {"POST", "Content-Type: application/grpc-web\r\n", std::string("\x80\0\0\0\1x", 6), false},
        {"POST", "Content-Type: application/grpc-web\r\n", valid.substr(0, 5), false},
        {"POST", "Content-Type: application/grpc-web\r\n", valid + valid, false},
        {"POST", "Content-Type: application/grpc-web\r\n", std::string("\0\0\0\0\2x", 6), false},
        {"POST", "Content-Type: application/grpc-web-text\r\n", "AAAAAAF!", false},
        {"POST", "Content-Type: application/grpc-web-text\r\n", "A===", false},
        {"POST", "Content-Type: application/grpc-web-text\r\n", "AB==", false},
        {"POST",
         "Content-Type: application/grpc-web\r\n",
         std::string("\0\0\0\x20\0", 5) + std::string(8192, 'x'),
         true},
        {"POST",
         "Content-Type: application/grpc-web\r\n",
         std::string("\0\0\0\x20\1", 5) + std::string(8193, 'x'),
         false},
        {"POST", "Content-Type: application/grpc-web\r\n", valid, false, true},
    };
    for (const auto& item : cases) {
        const std::string request = std::string(item.method) + " /body HTTP/1.1\r\nHost: test\r\n" +
                                    item.headers +
                                    "Content-Length: " + std::to_string(item.body.size()) +
                                    "\r\nConnection: close\r\n\r\n" + item.body;
        for (bool h2_path : {false, true}) {
            auto loop = std::make_unique<SmallLoop>();
            loop->setup();
            SlicePool pool;
            REQUIRE(pool.init(16));
            auto config = std::make_unique<RouteConfig>();
            REQUIRE(config->add_jit_handler("/body", 0, &web_admission_handler, true));
            const RouteConfig* config_ptr = config.get();
            loop->config_ptr = &config_ptr;
            auto* conn = loop->alloc_conn();
            REQUIRE(conn);
            conn->fd = 41;
            conn->json_arena.backend.pool = item.fail_arena ? nullptr : &pool;
            web_admission_calls = 0;
            web_admission_body_len = 0;
            web_admission_flag = 255;
            if (!h2_path) {
                u8 input[16384];
                conn->recv_buf.bind(input, sizeof(input));
                REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()),
                                                request.size()),
                           request.size());
                on_header_received<SmallLoop>(
                    loop.get(),
                    *conn,
                    IoEvent{
                        conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
                CHECK_EQ(conn->resp_status, item.accepted ? 422u : 400u);
            } else {
                auto h2 = std::make_unique<Http2Conn>();
                h2->init();
                h2->nstreams = 1;
                h2->streams[0].id = 1;
                h2->streams[0].state = Http2StreamState::HalfClosedRemote;
                conn->h2 = h2.get();
                u8 response[1024];
                H2Dispatch<SmallLoop> dispatch{
                    loop.get(), conn, response, sizeof(response), 0, false};
                h2_invoke_emit(dispatch,
                               1,
                               &config->routes[0],
                               nullptr,
                               0,
                               config.get(),
                               reinterpret_cast<const u8*>(request.data()),
                               request.size(),
                               true,
                               true);
                Http2FrameHeader frame{};
                REQUIRE_EQ(parse_frame_header(response, dispatch.resp_len, &frame),
                           ParseStatus::Complete);
                hpack::DynamicTable decoder;
                decoder.init(kDefaultHeaderTableSize);
                hpack::Header headers[8];
                u8 scratch[512];
                u32 count = 0;
                REQUIRE(hpack::decode_header_block(decoder,
                                                   response + kFrameHeaderSize,
                                                   frame.length,
                                                   scratch,
                                                   sizeof(scratch),
                                                   headers,
                                                   8,
                                                   &count));
                bool status_matches = false;
                for (u32 i = 0; i < count; ++i)
                    if (headers[i].name.eq(lit_str(":status")))
                        status_matches =
                            headers[i].value.eq(item.accepted ? lit_str("422") : lit_str("400"));
                CHECK(status_matches);
                conn->h2 = nullptr;
            }
            CHECK_EQ(web_admission_calls, item.accepted ? 1u : 0u);
            if (item.accepted) {
                CHECK_EQ(web_admission_flag, 0u);
                CHECK_EQ(web_admission_body_len, item.body.size() >= 8197 ? 8197u : 6u);
            }
            loop->free_conn(*conn);
            pool.destroy();
        }
    }
}

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

TEST(json_network, local_grpc_web_static_frames_fit_and_keepalive_recycles) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(32));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 41;
    // Keep current null so handle_jit_outcome exercises lazy arena setup.
    conn->json_arena.backend.pool = &pool;
    u8 send_storage[SlicePool::kSliceSize];
    u8* original_send_slice = conn->send_slice;
    const u32 original_send_capacity = SmallLoop::kBufSize;
    conn->send_buf.bind(send_storage, sizeof(send_storage));

    constexpr u32 kMaxEncoded = 16384;
    u8 expected[kMaxEncoded]{};
    u8 native[8197]{};
    const GrpcWebContentType modes[] = {GrpcWebContentType::Binary, GrpcWebContentType::Text};
    const u32 frame_lengths[] = {8193, 8194, 8195, 8196, 8197};
    for (const GrpcWebContentType mode : modes) {
        for (const u32 frame_len : frame_lengths) {
            native[0] = 0;
            const u32 payload_len = frame_len - 5;
            native[1] = static_cast<u8>(payload_len >> 24);
            native[2] = static_cast<u8>(payload_len >> 16);
            native[3] = static_cast<u8>(payload_len >> 8);
            native[4] = static_cast<u8>(payload_len);
            for (u32 i = 5; i < frame_len; ++i) native[i] = static_cast<u8>('a' + (i % 23));

            RouteConfig cfg;
            const u16 body_idx =
                cfg.add_response_body_view(reinterpret_cast<const char*>(native), frame_len);
            REQUIRE(body_idx != 0);
            const char* keys[] = {"content-type", "grpc-status"};
            const u32 key_lens[] = {12, 11};
            const char* values[] = {mode == GrpcWebContentType::Text ? "application/grpc-web-text"
                                                                     : "application/grpc-web",
                                    "0"};
            const u32 value_lens[] = {mode == GrpcWebContentType::Text ? 25u : 20u, 1};
            const u16 headers_idx =
                cfg.add_response_header_set(keys, key_lens, values, value_lens, 2);
            REQUIRE(headers_idx != 0);

            JitDispatchOutcome outcome{};
            outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
            outcome.status_code = 200;
            outcome.response_body_idx = body_idx;
            outcome.response_headers_idx = headers_idx;
            const char* request =
                "POST /grpc-web HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n";
            conn->recv_buf.reset();
            conn->send_buf.reset();
            REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request),
                                            __builtin_strlen(request)),
                       __builtin_strlen(request));
            capture_request_metadata(*conn);
            conn->request_config = &cfg;
            handle_jit_outcome(loop.get(), *conn, outcome, nullptr, true);

            u32 expected_len = 0;
            REQUIRE(grpc_web_encode_local_response(
                mode, native, frame_len, 0, {}, {}, expected, sizeof(expected), expected_len));
            const char* wire = reinterpret_cast<const char*>(conn->send_buf.data());
            const std::string response(wire, conn->send_buf.len());
            CHECK(response.starts_with("HTTP/1.1 200 OK\r\n"));
            CHECK(response.find("Content-Length: " + std::to_string(expected_len)) !=
                  std::string::npos);
            const size_t body_start = response.find("\r\n\r\n");
            REQUIRE(body_start != std::string::npos);
            CHECK_EQ(response.size() - (body_start + 4), expected_len);
            CHECK_EQ(memcmp(response.data() + body_start + 4, expected, expected_len), 0);
            CHECK(conn->keep_alive);
            CHECK_EQ(conn->local_body_remaining, 0u);
            CHECK_EQ(conn->local_response_size, 0u);

            REQUIRE(conn->on_send != nullptr);
            const auto send_done = conn->on_send;
            send_done(
                loop.get(),
                *conn,
                {conn->id, static_cast<i32>(conn->send_buf.len()), 0, 0, IoEventType::Send, 0});
            CHECK(conn->state == ConnState::ReadingHeader || conn->state == ConnState::ReadingBody);

            const char* successor = "GET /next HTTP/1.1\r\nHost: test\r\n\r\n";
            conn->recv_buf.reset();
            conn->send_buf.reset();
            REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(successor),
                                            __builtin_strlen(successor)),
                       __builtin_strlen(successor));
            capture_request_metadata(*conn);
            conn->request_config = nullptr;
            JitDispatchOutcome next{};
            next.kind = JitDispatchOutcome::Kind::ReturnStatus;
            next.status_code = 200;
            handle_jit_outcome(loop.get(), *conn, next, nullptr, true);
            const std::string next_response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                            conn->send_buf.len());
            CHECK(next_response.starts_with("HTTP/1.1 200 OK\r\n"));
            CHECK(next_response.ends_with("OK"));
            CHECK(next_response.find("Content-Length: 2") != std::string::npos);
            CHECK(next_response.find("Connection: keep-alive") != std::string::npos);
            REQUIRE(conn->on_send != nullptr);
            const auto successor_send_done = conn->on_send;
            successor_send_done(
                loop.get(),
                *conn,
                {conn->id, static_cast<i32>(conn->send_buf.len()), 0, 0, IoEventType::Send, 0});
            CHECK(conn->state == ConnState::ReadingHeader || conn->state == ConnState::ReadingBody);
        }
    }
    conn->send_buf.bind(original_send_slice, original_send_capacity);
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, dynamic_grpc_web_head_fallback_preserves_version_and_suppresses_body) {
    SmallLoop loop;
    loop.setup();
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;

    u8 native[] = {0, 0, 0, 0, 1, 'x'};
    const char* keys[] = {"content-type", "grpc-status"};
    const u32 key_lens[] = {12, 11};
    const char* values[] = {"application/grpc-web", "0"};
    const u32 value_lens[] = {20, 1};
    RouteConfig cfg;
    const u16 headers_idx = cfg.add_response_header_set(keys, key_lens, values, value_lens, 2);
    REQUIRE(headers_idx != 0);

    const char* request = "HEAD /grpc-web HTTP/1.0\r\nHost: test\r\n\r\n";
    REQUIRE_EQ(
        conn->recv_buf.write(reinterpret_cast<const u8*>(request), __builtin_strlen(request)),
        __builtin_strlen(request));
    capture_request_metadata(*conn);
    conn->request_config = &cfg;
    conn->jit_response_body = {reinterpret_cast<const char*>(native), sizeof(native)};
    conn->jit_response_body_valid = true;
    conn->jit_response_head = true;

    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 200;
    outcome.response_body_idx = 0xffffu;
    outcome.response_headers_idx = headers_idx;
    handle_jit_outcome(&loop, *conn, outcome, nullptr, true);

    const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                               conn->send_buf.len());
    CHECK(response.starts_with("HTTP/1.0 500 Internal Server Error\r\n"));
    const size_t body_start = response.find("\r\n\r\n");
    REQUIRE(body_start != std::string::npos);
    CHECK_EQ(response.size(), body_start + 4);
    CHECK(response.find("Content-Length: 21\r\n") != std::string::npos);
    CHECK(response.find("Connection: close\r\n") != std::string::npos);
    CHECK_EQ(conn->resp_status, 500u);
    CHECK_FALSE(conn->keep_alive);
    loop.free_conn(*conn);
    pool.destroy();
}

TEST(json_network, static_grpc_web_rejection_preserves_http10_error_framing) {
    SmallLoop loop;
    loop.setup();
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;

    // The declared payload length is two bytes, but only one payload byte is
    // present. This reaches the configured static gRPC-Web conversion path and
    // must use the ordinary local 500 formatter after rejecting the frame.
    const u8 malformed[] = {0, 0, 0, 0, 2, 'x'};
    RouteConfig cfg;
    const u16 body_idx =
        cfg.add_response_body_view(reinterpret_cast<const char*>(malformed), sizeof(malformed));
    REQUIRE(body_idx != 0);
    const char* keys[] = {"content-type", "grpc-status"};
    const u32 key_lens[] = {12, 11};
    const char* values[] = {"application/grpc-web", "0"};
    const u32 value_lens[] = {20, 1};
    const u16 headers_idx = cfg.add_response_header_set(keys, key_lens, values, value_lens, 2);
    REQUIRE(headers_idx != 0);

    const char* methods[] = {"GET", "HEAD"};
    for (const char* method : methods) {
        const std::string request =
            std::string(method) + " /grpc-web HTTP/1.0\r\nHost: test\r\n\r\n";
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        capture_request_metadata(*conn);
        conn->request_config = &cfg;
        JitDispatchOutcome outcome{};
        outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
        outcome.status_code = 200;
        outcome.response_body_idx = body_idx;
        outcome.response_headers_idx = headers_idx;
        handle_jit_outcome(&loop, *conn, outcome, nullptr, true);

        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        CHECK(response.starts_with("HTTP/1.0 500 Internal Server Error\r\n"));
        const size_t body_start = response.find("\r\n\r\n");
        REQUIRE(body_start != std::string::npos);
        CHECK(response.find("Content-Length: 21\r\n") != std::string::npos);
        CHECK(response.find("Connection: close\r\n") != std::string::npos);
        if (method[0] == 'H') {
            CHECK_EQ(response.size(), body_start + 4);
        } else {
            CHECK(response.ends_with("Internal Server Error"));
        }
        CHECK_EQ(conn->resp_status, 500u);
        CHECK_FALSE(conn->keep_alive);
    }
    loop.free_conn(*conn);
    pool.destroy();
}

TEST(json_network, unsupported_grpc_web_suffix_fails_closed_on_h1_and_h2) {
    SmallLoop loop;
    loop.setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto* conn = loop.alloc_conn();
    REQUIRE(conn);
    conn->json_arena.backend.pool = &pool;
    const u8 native[] = {0, 0, 0, 0, 1, 'x'};
    const char* keys[] = {"content-type", "grpc-status"};
    const u32 key_lens[] = {12, 11};
    const char* values[] = {"application/grpc-web+json", "0"};
    const u32 value_lens[] = {25, 1};
    RouteConfig cfg;
    const u16 body_idx =
        cfg.add_response_body_view(reinterpret_cast<const char*>(native), sizeof(native));
    const u16 headers_idx = cfg.add_response_header_set(keys, key_lens, values, value_lens, 2);
    REQUIRE(body_idx != 0);
    REQUIRE(headers_idx != 0);

    const auto assert_h1_500 = [&](const RouteConfig& response_cfg, JitDispatchOutcome outcome) {
        const char request[] = "POST /grpc-web HTTP/1.1\r\nHost: test\r\n\r\n";
        conn->recv_buf.reset();
        conn->send_buf.reset();
        REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(request), sizeof(request) - 1),
                   sizeof(request) - 1);
        capture_request_metadata(*conn);
        conn->request_config = &response_cfg;
        handle_jit_outcome(&loop, *conn, outcome, nullptr, true);
        const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
        CHECK(response.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        CHECK(response.find("grpc-status:") == std::string::npos);
        CHECK_EQ(conn->resp_status, 500u);
    };

    JitDispatchOutcome dynamic{};
    dynamic.kind = JitDispatchOutcome::Kind::ReturnStatus;
    dynamic.status_code = 200;
    dynamic.response_body_idx = 0xffffu;
    dynamic.response_headers_idx = headers_idx;
    conn->jit_response_body = {reinterpret_cast<const char*>(native), sizeof(native)};
    conn->jit_response_body_valid = true;
    assert_h1_500(cfg, dynamic);

    const char* mixed_types[] = {"application/grpc-web+json", "text/plain"};
    const u32 mixed_type_lens[] = {25, 10};
    for (u32 order = 0; order < 2; ++order) {
        RouteConfig mixed_cfg;
        const char* mixed_keys[] = {"content-type", "grpc-status"};
        const u32 mixed_key_lens[] = {12, 11};
        const char* mixed_values[] = {mixed_types[order], "0"};
        const u32 mixed_value_lens[] = {mixed_type_lens[order], 1};
        const u16 mixed_headers_idx = mixed_cfg.add_response_header_set(
            mixed_keys, mixed_key_lens, mixed_values, mixed_value_lens, 2);
        REQUIRE(mixed_headers_idx != 0);
        conn->resp_header_mutation_count = 1;
        conn->resp_header_mutations[0] = {{"content-type", 12},
                                          {mixed_types[1 - order], mixed_type_lens[1 - order]},
                                          Connection::RespHeaderMutationMode::Add};
        JitDispatchOutcome mixed = dynamic;
        mixed.response_headers_idx = mixed_headers_idx;
        assert_h1_500(mixed_cfg, mixed);
    }
    conn->resp_header_mutation_count = 0;

    JitDispatchOutcome statik{};
    statik.kind = JitDispatchOutcome::Kind::ReturnStatus;
    statik.status_code = 200;
    statik.response_body_idx = body_idx;
    statik.response_headers_idx = headers_idx;
    assert_h1_500(cfg, statik);

    auto h2 = std::make_unique<Http2Conn>();
    conn->h2 = h2.get();
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    conn->epoch_held = true;
    conn->resp_header_mutation_count = 2;
    conn->resp_header_mutations[0] = {{"content-type", 12},
                                      {"application/grpc-web+json", 25},
                                      Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[1] = {
        {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
    conn->jit_response_body_valid = true;
    conn->jit_response_body = {reinterpret_cast<const char*>(native), sizeof(native)};
    JitDispatchOutcome h2_outcome{};
    h2_outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    h2_outcome.status_code = 200;
    h2_outcome.response_body_idx = 0xffffu;
    u8 response[1024];
    H2Dispatch<SmallLoop> dispatch{&loop, conn, response, sizeof(response), 0, false};
    h2_emit_outcome(dispatch, 1, h2_outcome, nullptr, false);
    CHECK_EQ(h2->outbound_stream, 0u);
    Http2FrameHeader frame{};
    REQUIRE_EQ(parse_frame_header(response, dispatch.resp_len, &frame), ParseStatus::Complete);
    hpack::DynamicTable decoder;
    decoder.init(kDefaultHeaderTableSize);
    hpack::Header decoded[4];
    u8 scratch[128];
    u32 count = 0;
    REQUIRE(hpack::decode_header_block(decoder,
                                       response + kFrameHeaderSize,
                                       frame.length,
                                       scratch,
                                       sizeof(scratch),
                                       decoded,
                                       4,
                                       &count));
    REQUIRE_EQ(count, 1u);
    CHECK(decoded[0].name.eq(lit_str(":status")));
    CHECK(decoded[0].value.eq(lit_str("500")));
    conn->epoch_held = false;
    conn->h2 = nullptr;
    loop.free_conn(*conn);
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

TEST(json_network, queued_static_grpc_web_response_uses_owned_transformed_body) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    REQUIRE(conn->json_arena.init(&pool));
    conn->epoch_held = true;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    h2->nstreams = 2;
    h2->streams[0] = {1, Http2StreamState::Open, 0, 0, true};
    h2->streams[1] = {3, Http2StreamState::Open, 0, 0, true};

    u8 native[8197]{};
    native[3] = 0x20;
    for (u32 i = 5; i < sizeof(native); i++) native[i] = 'q';
    RouteConfig cfg;
    const u16 body_idx =
        cfg.add_response_body_view(reinterpret_cast<const char*>(native), sizeof(native));
    REQUIRE(body_idx != 0);
    const char* keys[] = {"content-type", "grpc-status"};
    const u32 key_lens[] = {12, 11};
    const char* values[] = {"application/grpc-web", "0"};
    const u32 value_lens[] = {20, 1};
    const u16 headers_idx = cfg.add_response_header_set(keys, key_lens, values, value_lens, 2);
    REQUIRE(headers_idx != 0);
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 200;
    outcome.response_body_idx = body_idx;
    outcome.response_headers_idx = headers_idx;
    u8 response[4096]{};
    H2Dispatch<SmallLoop> first{loop.get(), conn, response, sizeof(response), 0, false};
    h2_emit_outcome(first, 1, outcome, &cfg, false);
    REQUIRE_EQ(h2->outbound_stream, 1u);
    CHECK_EQ(h2->outbound_source, H2OutboundBodySource::JitDynamic);
    REQUIRE(h2->jit_outbound_slice != nullptr);
    const u8* first_slice = h2->jit_outbound_slice;
    CHECK_EQ(h2->outbound_body[0], 0u);
    CHECK_EQ(h2->outbound_body[8197], 0x80u);
    u8 expected_body[16384]{};
    const u32 expected_body_len = h2->outbound_body_len;
    REQUIRE(expected_body_len <= sizeof(expected_body));
    __builtin_memcpy(expected_body, h2->outbound_body, expected_body_len);

    h2_emit_outcome(first, 3, outcome, &cfg, false);
    REQUIRE_EQ(h2->queued_stream, 3u);
    CHECK_EQ(h2->queued_source, H2OutboundBodySource::JitDynamic);
    REQUIRE(h2->jit_queued_slice != nullptr);
    const u8* queued_slice = h2->jit_queued_slice;
    CHECK(queued_slice != first_slice);
    h2->conn_send_window = 5;
    h2->streams[0].send_window = 5;
    H2PumpStatus status{};
    CHECK_EQ(h2_pump_outbound(*h2, response, sizeof(response), status), kFrameHeaderSize + 5u);
    CHECK(status == H2PumpStatus::Produced);
    h2->conn_send_window = 65535;
    h2->streams[0].send_window = 65535;
    h2_clear_primary_outbound(*h2);
    h2_promote_queued(*h2);
    CHECK_FALSE(slice_is_in_use(pool, first_slice));
    REQUIRE_EQ(h2->outbound_stream, 3u);
    CHECK_EQ(h2->outbound_source, H2OutboundBodySource::JitDynamic);
    CHECK_EQ(h2->outbound_body[8197], 0x80u);
    CHECK_EQ(h2->outbound_body, queued_slice);
    h2->conn_send_window = 0;
    h2->streams[1].send_window = 0;
    CHECK_EQ(h2_pump_outbound(*h2, response, sizeof(response), status), 0u);
    CHECK(status == H2PumpStatus::Blocked);
    CHECK_EQ(h2->outbound_body_offset, 0u);
    __builtin_memset(cfg.body_pool, 'z', cfg.body_pool_used);
    __builtin_memset(cfg.header_bytes_pool, 'z', cfg.header_bytes_pool_used);
    __builtin_memset(native, 'z', sizeof(native));
    conn->json_arena.destroy();
    CHECK_EQ(memcmp(h2->outbound_body, expected_body, expected_body_len), 0);
    h2->nstreams = 3;
    h2->streams[2] = {5, Http2StreamState::Open, 0, 0, true};
    h2->conn_send_window = 65535;
    h2->streams[1].send_window = 65535;
    H2Dispatch<SmallLoop> third{loop.get(), conn, response, sizeof(response), 0, false};
    REQUIRE(h2_stage_owned_response(third,
                                    5,
                                    200,
                                    nullptr,
                                    0,
                                    h2->outbound_body,
                                    h2->outbound_body_len,
                                    H2OutboundBodySource::JitDynamic,
                                    nullptr));
    REQUIRE(h2->jit_queued_slice != nullptr);
    const u8* reset_slice = h2->jit_queued_slice;
    H2Dispatch<SmallLoop> reset_dispatch{loop.get(), conn, response, sizeof(response), 0, false};
    h2_on_reset_dispatch_cb<SmallLoop>(&reset_dispatch, *h2, 5, Http2Error::Cancel);
    CHECK_EQ(h2->queued_stream, 0u);
    CHECK_EQ(h2->jit_queued_slice, nullptr);
    CHECK_FALSE(slice_is_in_use(pool, reset_slice));
    CHECK(slice_is_in_use(pool, queued_slice));
    h2_clear_outbound(*h2);
    conn->h2 = nullptr;
    conn->json_arena.destroy();
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

TEST(json_network, chunked_grpc_web_event_yield_is_rejected_before_upstream_io) {
    SmallLoop loop;
    loop.setup();
    auto* conn = loop.alloc_conn();
    REQUIRE(conn);
    conn->grpc_web_local_chunk_done = true;
    conn->upstream_fd = -1;
    conn->req_method = static_cast<u8>(LogHttpMethod::Post);
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::EventYield;
    outcome.yield_kind = jit::YieldKind::UpstreamConnect;
    handle_jit_outcome(&loop, *conn, outcome, nullptr, false, nullptr);
    CHECK_EQ(conn->resp_status, 400u);
    CHECK_EQ(conn->upstream_fd, -1);
    CHECK(conn->send_buf.len() != 0);
    loop.free_conn(*conn);
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
    const char first_message[] = "first%20message";
    __builtin_memcpy(h2->outbound_grpc_message, first_message, sizeof(first_message) - 1);
    h2->outbound_grpc_message_len = sizeof(first_message) - 1;
    h2->outbound_grpc_message_present = true;
    const char first_details[] = "opaque-details";
    __builtin_memcpy(h2->outbound_grpc_status_details, first_details, sizeof(first_details) - 1);
    h2->outbound_grpc_status_details_len = sizeof(first_details) - 1;
    h2->outbound_grpc_status_details_present = true;
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
    Http2FrameHeader trailer_frame{};
    REQUIRE_EQ(parse_frame_header(bytes, 128, &trailer_frame), ParseStatus::Complete);
    hpack::DynamicTable trailer_decoder;
    trailer_decoder.init(kDefaultHeaderTableSize);
    hpack::Header trailer_headers[4];
    u8 trailer_scratch[256];
    u32 trailer_count = 0;
    REQUIRE(hpack::decode_header_block(trailer_decoder,
                                       bytes + kFrameHeaderSize,
                                       trailer_frame.length,
                                       trailer_scratch,
                                       sizeof(trailer_scratch),
                                       trailer_headers,
                                       4,
                                       &trailer_count));
    bool saw_message = false;
    bool saw_details = false;
    for (u32 i = 0; i < trailer_count; ++i)
        if (trailer_headers[i].name.eq(lit_str("grpc-message"))) {
            saw_message = trailer_headers[i].value.eq(lit_str("first%20message"));
        } else if (trailer_headers[i].name.eq(lit_str("grpc-status-details-bin")))
            saw_details =
                trailer_headers[i].value.eq(Str{first_details, sizeof(first_details) - 1});
    CHECK(saw_message);
    CHECK(saw_details);
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 0u);
    h2_clear_outbound(*h2);
    CHECK_EQ(h2->outbound_grpc_status, 255u);
    CHECK_EQ(h2->queued_grpc_status, 255u);
    h2->queued_stream = 3;
    h2->queued_body = body;
    h2->queued_body_len = sizeof(body);
    h2->queued_source = H2OutboundBodySource::RouteConfig;
    h2->queued_grpc_status = 7;
    const char second_message[] = "second%2Fmessage";
    __builtin_memcpy(h2->queued_grpc_message, second_message, sizeof(second_message) - 1);
    h2->queued_grpc_message_len = sizeof(second_message) - 1;
    h2->queued_grpc_message_present = true;
    const char second_details[] = "queued-details";
    __builtin_memcpy(h2->queued_grpc_status_details, second_details, sizeof(second_details) - 1);
    h2->queued_grpc_status_details_len = sizeof(second_details) - 1;
    h2->queued_grpc_status_details_present = true;
    h2_promote_queued(*h2);
    CHECK_EQ(h2->outbound_stream, 3u);
    CHECK_EQ(h2->outbound_grpc_status, 7u);
    CHECK(h2->outbound_grpc_message_present);
    CHECK_EQ(h2->outbound_grpc_message_len, sizeof(second_message) - 1);
    CHECK(__builtin_memcmp(h2->outbound_grpc_message, second_message, sizeof(second_message) - 1) ==
          0);
    CHECK(h2->outbound_grpc_status_details_present);
    CHECK_EQ(h2->outbound_grpc_status_details_len, sizeof(second_details) - 1);
    CHECK(__builtin_memcmp(
              h2->outbound_grpc_status_details, second_details, sizeof(second_details) - 1) == 0);
    CHECK_EQ(h2->queued_grpc_status, 255u);
    CHECK(!h2->queued_grpc_message_present);
    CHECK_EQ(h2->queued_grpc_message_len, 0u);
    CHECK(!h2->queued_grpc_status_details_present);
    CHECK_EQ(h2->queued_grpc_status_details_len, 0u);
    h2_clear_outbound(*h2);
    CHECK(!h2->outbound_grpc_message_present);
    CHECK_EQ(h2->outbound_grpc_message_len, 0u);
    CHECK(!h2->outbound_grpc_status_details_present);
    CHECK_EQ(h2->outbound_grpc_status_details_len, 0u);
    h2->outbound_stream = 1;
    h2->outbound_body = body;
    h2->outbound_body_len = sizeof(body);
    h2->conn_send_window = 5;
    stream->send_window = 5;
    CHECK_EQ(h2_pump_outbound(*h2, bytes, sizeof(bytes), status), 14u);
    CHECK_EQ(bytes[4] & 1u, 1u);  // Ordinary HTTP still ends on its final DATA.
    auto check_message_header = [&](bool expected, Str value) {
        Http2FrameHeader frame{};
        REQUIRE_EQ(parse_frame_header(bytes, 128, &frame), ParseStatus::Complete);
        hpack::DynamicTable decoder;
        decoder.init(kDefaultHeaderTableSize);
        hpack::Header headers[4];
        u8 scratch[256];
        u32 count = 0;
        REQUIRE(hpack::decode_header_block(decoder,
                                           bytes + kFrameHeaderSize,
                                           frame.length,
                                           scratch,
                                           sizeof(scratch),
                                           headers,
                                           4,
                                           &count));
        bool found = false;
        for (u32 i = 0; i < count; ++i)
            if (headers[i].name.eq(lit_str("grpc-message"))) {
                found = true;
                CHECK(headers[i].value.eq(value));
            }
        CHECK_EQ(found, expected);
    };
    h2_clear_outbound(*h2);
    h2->hpack_enc.init(kDefaultHeaderTableSize);
    h2->outbound_stream = 1;
    h2->outbound_body = body;
    h2->outbound_body_len = sizeof(body);
    h2->outbound_grpc_status = 0;
    h2->outbound_grpc_message_present = true;
    h2->conn_send_window = 5;
    stream->send_window = 5;
    CHECK(h2_pump_outbound(*h2, bytes, sizeof(bytes), status) != 0);
    CHECK(h2_pump_outbound(*h2, bytes, sizeof(bytes), status) != 0);
    check_message_header(true, Str{"", 0});
    h2_clear_outbound(*h2);
    h2->hpack_enc.init(kDefaultHeaderTableSize);
    h2->outbound_stream = 1;
    h2->outbound_body = body;
    h2->outbound_body_len = sizeof(body);
    h2->outbound_grpc_status = 0;
    h2->conn_send_window = 5;
    stream->send_window = 5;
    CHECK(h2_pump_outbound(*h2, bytes, sizeof(bytes), status) != 0);
    CHECK(h2_pump_outbound(*h2, bytes, sizeof(bytes), status) != 0);
    check_message_header(false, Str{"", 0});
}

TEST(json_network, grpc_web_local_outcome_stages_owned_binary_and_text_body) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(32));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    REQUIRE(conn->json_arena.init(&pool));
    auto h2 = std::make_unique<Http2Conn>();
    conn->h2 = h2.get();
    const u8 native[] = {0, 0, 0, 0, 1, 'x'};
    const char* types[] = {"application/grpc-web", "application/grpc-web-text"};
    for (u32 mode = 0; mode < 2; mode++) {
        h2->init();
        h2->nstreams = 1;
        h2->streams[0].id = 1;
        h2->streams[0].state = Http2StreamState::HalfClosedRemote;
        conn->epoch_held = true;
        conn->jit_response_body_valid = true;
        conn->jit_response_body = {reinterpret_cast<const char*>(native), sizeof(native)};
        conn->resp_header_mutation_count = 4;
        conn->resp_header_mutations[0] = {{"content-type", 12},
                                          {types[mode], mode ? 25u : 20u},
                                          Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[1] = {
            {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[2] = {
            {"grpc-message", 12}, {"ok", 2}, Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[3] = {{"grpc-status-details-bin", 23},
                                          {"opaque", 6},
                                          Connection::RespHeaderMutationMode::Set};
        JitDispatchOutcome outcome{};
        outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
        outcome.status_code = 200;
        outcome.response_body_idx = 0xffffu;
        u8 response[2048];
        H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
        h2_emit_outcome(dispatch, 1, outcome, nullptr, false);
        REQUIRE_EQ(h2->outbound_stream, 1u);
        CHECK_EQ(h2->outbound_grpc_status, 255u);
        CHECK_EQ(h2->outbound_body[0], mode == 0 ? 0 : static_cast<u8>('A'));
        // The staged body is owned independently of both the JIT input and arena.
        conn->jit_response_body.ptr = nullptr;
        conn->json_arena.destroy();
        CHECK(h2->outbound_body_len > sizeof(native));
        if (mode == 0) {
            CHECK_EQ(h2->outbound_body[0], 0u);
            CHECK_EQ(h2->outbound_body[5], 'x');
            CHECK_EQ(h2->outbound_body[6], 0x80u);
        } else {
            GrpcWebBase64Decoder decoder{};
            decoder.init();
            u8 decoded[256]{};
            u32 consumed = 0, written = 0;
            REQUIRE(decoder.feed(h2->outbound_body,
                                 h2->outbound_body_len,
                                 consumed,
                                 decoded,
                                 sizeof(decoded),
                                 written) == GrpcWebCodecStatus::Ok);
            REQUIRE(decoder.finish() == GrpcWebCodecStatus::Ok);
            CHECK_EQ(decoded[0], 0u);
            CHECK_EQ(decoded[5], 'x');
            CHECK_EQ(decoded[6], 0x80u);
        }
        u8 wire[2048];
        H2PumpStatus pump_status{};
        h2->conn_send_window = 65535;
        h2->streams[0].send_window = 65535;
        const u32 wire_len = h2_pump_outbound(*h2, wire, sizeof(wire), pump_status);
        REQUIRE(wire_len > kFrameHeaderSize);
        Http2FrameHeader data_frame{};
        REQUIRE_EQ(parse_frame_header(wire, wire_len, &data_frame), ParseStatus::Complete);
        CHECK_EQ(data_frame.type, static_cast<u8>(Http2FrameType::Data));
        CHECK_EQ(data_frame.flags & http2_flag::kEndStream, http2_flag::kEndStream);
        CHECK_EQ(h2_pump_outbound(*h2, wire, sizeof(wire), pump_status), 0u);
        h2_clear_outbound(*h2);
        conn->epoch_held = false;
        REQUIRE(conn->json_arena.init(&pool));
    }
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    conn->epoch_held = true;
    conn->jit_response_body_valid = true;
    conn->jit_response_body = {nullptr, 0};
    conn->resp_header_mutation_count = 2;
    conn->resp_header_mutations[0] = {{"content-type", 12},
                                      {"application/grpc-web", 20},
                                      Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[1] = {
        {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
    JitDispatchOutcome trailers_only{};
    trailers_only.kind = JitDispatchOutcome::Kind::ReturnStatus;
    trailers_only.status_code = 200;
    trailers_only.response_body_idx = 0xffffu;
    u8 trailers_response[1024];
    H2Dispatch<SmallLoop> trailers_dispatch{
        loop.get(), conn, trailers_response, sizeof(trailers_response), 0, false};
    h2_emit_outcome(trailers_dispatch, 1, trailers_only, nullptr, false);
    REQUIRE_EQ(h2->outbound_stream, 1u);
    CHECK_EQ(h2->outbound_body[0], 0x80u);
    CHECK_EQ(h2->outbound_grpc_status, 255u);
    conn->json_arena.destroy();
    h2_clear_outbound(*h2);
    conn->epoch_held = false;
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}

TEST(json_network, grpc_web_local_http1_outcome_writes_body_and_trailers_only) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    const u8 message[] = {0, 0, 0, 0, 1, 'x'};
    const char* types[] = {"application/grpc-web", "application/grpc-web-text"};
    for (u32 mode = 0; mode < 2; mode++) {
        for (u32 empty = 0; empty < 2; empty++) {
            REQUIRE(conn->json_arena.init(&pool));
            conn->req_method = static_cast<u8>(LogHttpMethod::Post);
            conn->req_http_version = static_cast<u8>(HttpVersion::Http11);
            conn->jit_response_body_valid = true;
            conn->jit_response_body = {reinterpret_cast<const char*>(empty ? nullptr : message),
                                       empty ? 0u : static_cast<u32>(sizeof(message))};
            conn->resp_header_mutation_count = 2;
            conn->resp_header_mutations[0] = {{"content-type", 12},
                                              {types[mode], mode ? 25u : 20u},
                                              Connection::RespHeaderMutationMode::Set};
            conn->resp_header_mutations[1] = {
                {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
            JitDispatchOutcome outcome{};
            outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
            outcome.status_code = 200;
            outcome.response_body_idx = 0xffffu;
            conn->send_buf.reset();
            handle_jit_outcome(loop.get(), *conn, outcome, nullptr, true);
            const std::string wire(reinterpret_cast<const char*>(conn->send_buf.data()),
                                   conn->send_buf.len());
            CHECK(wire.find("HTTP/1.1 200") == 0);
            CHECK(wire.find("content-type: ") != std::string::npos ||
                  wire.find("Content-Type: ") != std::string::npos);
            CHECK(wire.find("content-length: ") != std::string::npos ||
                  wire.find("Content-Length: ") != std::string::npos);
            const size_t header_end = wire.find("\r\n\r\n");
            REQUIRE(header_end != std::string::npos);
            CHECK(wire.find("grpc-status:", 0) == std::string::npos ||
                  wire.find("grpc-status:", 0) >= header_end + 4);
            CHECK(wire.size() > header_end + 4);
        }
    }
    loop->free_conn(*conn);
    pool.destroy();
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
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    h2->hpack_enc.init(kDefaultHeaderTableSize);
    conn->epoch_held = true;
    conn->jit_response_body_valid = true;
    conn->jit_response_body = {nullptr, 0};
    conn->resp_header_mutation_overflow = false;
    conn->resp_header_mutation_count = 2;
    conn->resp_header_mutations[0] = {
        {"content-type", 12}, {"text/plain", 10}, Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[1] = {
        {"grpc-message", 12}, {"ordinary%20value", 16}, Connection::RespHeaderMutationMode::Set};
    JitDispatchOutcome ordinary_outcome{};
    ordinary_outcome.status_code = 200;
    ordinary_outcome.response_body_idx = 0xffffu;
    u8 ordinary_response[1024];
    H2Dispatch<SmallLoop> ordinary_dispatch{
        loop.get(), conn, ordinary_response, sizeof(ordinary_response), 0, false};
    h2_emit_outcome(ordinary_dispatch, 1, ordinary_outcome, nullptr, false);
    Http2FrameHeader ordinary_frame{};
    REQUIRE_EQ(parse_frame_header(ordinary_response, ordinary_dispatch.resp_len, &ordinary_frame),
               ParseStatus::Complete);
    hpack::DynamicTable ordinary_decoder;
    ordinary_decoder.init(kDefaultHeaderTableSize);
    hpack::Header ordinary_headers[4];
    u8 ordinary_scratch[256];
    u32 ordinary_count = 0;
    REQUIRE(hpack::decode_header_block(ordinary_decoder,
                                       ordinary_response + kFrameHeaderSize,
                                       ordinary_frame.length,
                                       ordinary_scratch,
                                       sizeof(ordinary_scratch),
                                       ordinary_headers,
                                       4,
                                       &ordinary_count));
    bool ordinary_message = false;
    for (u32 i = 0; i < ordinary_count; ++i)
        if (ordinary_headers[i].name.eq(lit_str("grpc-message"))) {
            ordinary_message = true;
            CHECK(ordinary_headers[i].value.eq(lit_str("ordinary%20value")));
        }
    CHECK(ordinary_message);
    auto reject_message_headers = [&](const Str& message, bool duplicate) {
        h2->init();
        h2->nstreams = 1;
        h2->streams[0].id = 1;
        h2->streams[0].state = Http2StreamState::HalfClosedRemote;
        conn->epoch_held = true;
        conn->jit_response_body_valid = true;
        conn->jit_response_body = {good, 5};
        conn->resp_header_mutation_count = duplicate ? 4 : 3;
        conn->resp_header_mutations[0] = {{"content-type", 12},
                                          {"application/grpc", 16},
                                          Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[1] = {
            {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[2] = {
            {"grpc-message", 12}, message, Connection::RespHeaderMutationMode::Set};
        if (duplicate)
            conn->resp_header_mutations[3] = {
                {"GRPC-MESSAGE", 12}, {"duplicate", 9}, Connection::RespHeaderMutationMode::Add};
        JitDispatchOutcome outcome{};
        outcome.status_code = 200;
        outcome.response_body_idx = 0xffffu;
        u8 response[2048];
        H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
        h2_emit_outcome(dispatch, 1, outcome, nullptr, false);
        CHECK_EQ(h2->outbound_stream, 0u);
        CHECK_EQ(h2->queued_stream, 0u);
        Http2FrameHeader frame{};
        REQUIRE_EQ(parse_frame_header(response, dispatch.resp_len, &frame), ParseStatus::Complete);
        CHECK_EQ(frame.flags & http2_flag::kEndStream, http2_flag::kEndStream);
    };
    auto reject_details_headers = [&](const Str& details, bool duplicate) {
        h2->init();
        h2->nstreams = 1;
        h2->streams[0].id = 1;
        h2->streams[0].state = Http2StreamState::HalfClosedRemote;
        conn->epoch_held = true;
        conn->jit_response_body_valid = true;
        conn->jit_response_body = {good, 5};
        conn->resp_header_mutation_count = duplicate ? 4 : 3;
        conn->resp_header_mutations[0] = {{"content-type", 12},
                                          {"application/grpc", 16},
                                          Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[1] = {
            {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
        conn->resp_header_mutations[2] = {
            {"grpc-status-details-bin", 23}, details, Connection::RespHeaderMutationMode::Set};
        if (duplicate)
            conn->resp_header_mutations[3] = {{"GRPC-STATUS-DETAILS-BIN", 23},
                                              {"duplicate", 9},
                                              Connection::RespHeaderMutationMode::Add};
        JitDispatchOutcome outcome{};
        outcome.status_code = 200;
        outcome.response_body_idx = 0xffffu;
        u8 response[2048];
        H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
        h2_emit_outcome(dispatch, 1, outcome, nullptr, false);
        CHECK_EQ(h2->outbound_stream, 0u);
        CHECK_EQ(h2->queued_stream, 0u);
        CHECK(!h2->outbound_grpc_status_details_present);
        CHECK_EQ(h2->outbound_grpc_status_details_len, 0u);
        CHECK(!h2->queued_grpc_status_details_present);
        CHECK_EQ(h2->queued_grpc_status_details_len, 0u);
        Http2FrameHeader frame{};
        REQUIRE_EQ(parse_frame_header(response, dispatch.resp_len, &frame), ParseStatus::Complete);
        hpack::DynamicTable decoder;
        decoder.init(kDefaultHeaderTableSize);
        hpack::Header headers[4];
        u8 scratch[256];
        u32 count = 0;
        REQUIRE(hpack::decode_header_block(decoder,
                                           response + kFrameHeaderSize,
                                           frame.length,
                                           scratch,
                                           sizeof(scratch),
                                           headers,
                                           4,
                                           &count));
        bool failed_closed = false;
        for (u32 i = 0; i < count; ++i)
            failed_closed |=
                headers[i].name.eq(lit_str(":status")) && headers[i].value.eq(lit_str("500"));
        CHECK(failed_closed);
    };
    char oversized_message[1025];
    __builtin_memset(oversized_message, 'a', sizeof(oversized_message));
    reject_message_headers({"denied", 6}, true);
    reject_message_headers({oversized_message, sizeof(oversized_message)}, false);
    reject_details_headers({"opaque-details", 14}, true);
    reject_details_headers({oversized_message, sizeof(oversized_message)}, false);
    char boundary_message[1024];
    __builtin_memset(boundary_message, 'b', sizeof(boundary_message));
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    conn->epoch_held = true;
    conn->jit_response_body_valid = true;
    conn->jit_response_body = {good, 5};
    conn->resp_header_mutation_count = 3;
    conn->resp_header_mutations[0] = {
        {"content-type", 12}, {"application/grpc", 16}, Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[1] = {
        {"grpc-status", 11}, {"0", 1}, Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[2] = {{"grpc-message", 12},
                                      {boundary_message, sizeof(boundary_message)},
                                      Connection::RespHeaderMutationMode::Set};
    JitDispatchOutcome boundary_outcome{};
    boundary_outcome.status_code = 200;
    boundary_outcome.response_body_idx = 0xffffu;
    u8 boundary_response[4096];
    H2Dispatch<SmallLoop> boundary_dispatch{
        loop.get(), conn, boundary_response, sizeof(boundary_response), 0, false};
    h2_emit_outcome(boundary_dispatch, 1, boundary_outcome, nullptr, false);
    CHECK_EQ(h2->outbound_stream, 1u);
    CHECK(h2->outbound_grpc_message_present);
    CHECK_EQ(h2->outbound_grpc_message_len, 1024u);
    conn->resp_header_mutation_count = 3;
    char accepted_details[] = "boundary-details";
    const char expected_details_storage[] = "boundary-details";
    const Str expected_details{expected_details_storage, sizeof(expected_details_storage) - 1};
    conn->resp_header_mutations[2] = {{"grpc-status-details-bin", 23},
                                      {accepted_details, sizeof(accepted_details) - 1},
                                      Connection::RespHeaderMutationMode::Set};
    u8 details_boundary_response[4096];
    H2Dispatch<SmallLoop> details_boundary_dispatch{
        loop.get(), conn, details_boundary_response, sizeof(details_boundary_response), 0, false};
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    conn->epoch_held = true;
    conn->jit_response_body_valid = true;
    conn->jit_response_body = {good, 5};
    conn->resp_header_mutation_overflow = false;
    h2_emit_outcome(details_boundary_dispatch, 1, boundary_outcome, nullptr, false);
    CHECK_EQ(h2->outbound_stream, 1u);
    CHECK(h2->outbound_grpc_status_details_present);
    CHECK_EQ(h2->outbound_grpc_status_details_len, sizeof(accepted_details) - 1);
    Http2FrameHeader initial_frame{};
    REQUIRE_EQ(parse_frame_header(
                   details_boundary_response, details_boundary_dispatch.resp_len, &initial_frame),
               ParseStatus::Complete);
    hpack::DynamicTable wire_decoder;
    wire_decoder.init(kDefaultHeaderTableSize);
    hpack::Header initial_headers[8];
    u8 initial_scratch[2048];
    u32 initial_count = 0;
    REQUIRE(hpack::decode_header_block(wire_decoder,
                                       details_boundary_response + kFrameHeaderSize,
                                       initial_frame.length,
                                       initial_scratch,
                                       sizeof(initial_scratch),
                                       initial_headers,
                                       8,
                                       &initial_count));
    for (u32 i = 0; i < initial_count; ++i)
        CHECK(!initial_headers[i].name.eq(lit_str("grpc-status-details-bin")));
    h2_commit_owned_hpack(details_boundary_dispatch);
    __builtin_memset(accepted_details, 'z', sizeof(accepted_details) - 1);
    h2->conn_send_window = 5;
    h2->streams[0].send_window = 5;
    u8 wire[2048];
    H2PumpStatus wire_status{};
    CHECK(h2_pump_outbound(*h2, wire, sizeof(wire), wire_status) != 0);
    CHECK_EQ(wire[4] & 1u, 0u);
    h2->conn_send_window = 5;
    h2->streams[0].send_window = 5;
    u32 wire_len = h2_pump_outbound(*h2, wire, sizeof(wire), wire_status);
    if (wire_len != 0 && wire[3] != 1) {
        h2->conn_send_window = 5;
        h2->streams[0].send_window = 5;
        wire_len = h2_pump_outbound(*h2, wire, sizeof(wire), wire_status);
    }
    CHECK(wire_len > 9u);
    CHECK_EQ(wire[3], 1u);
    Http2FrameHeader final_frame{};
    REQUIRE_EQ(parse_frame_header(wire, wire_len, &final_frame), ParseStatus::Complete);
    h2_clear_outbound(*h2);
    CHECK_EQ(final_frame.flags & http2_flag::kEndStream, http2_flag::kEndStream);
    hpack::Header final_headers[8];
    u8 final_scratch[2048];
    u32 final_count = 0;
    REQUIRE(hpack::decode_header_block(wire_decoder,
                                       wire + kFrameHeaderSize,
                                       final_frame.length,
                                       final_scratch,
                                       sizeof(final_scratch),
                                       final_headers,
                                       8,
                                       &final_count));
    bool preserved_details = false;
    for (u32 i = 0; i < final_count; ++i)
        if (final_headers[i].name.eq(lit_str("grpc-status-details-bin"))) {
            preserved_details = final_headers[i].value.eq(expected_details);
        }
    CHECK(preserved_details);
    h2->init();
    h2->nstreams = 1;
    h2->streams[0].id = 1;
    h2->streams[0].state = Http2StreamState::HalfClosedRemote;
    conn->epoch_held = true;
    conn->jit_response_body_valid = true;
    conn->jit_response_body = {nullptr, 0};
    conn->resp_header_mutation_count = 3;
    conn->resp_header_mutations[0] = {
        {"content-type", 12}, {"application/grpc", 16}, Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[1] = {
        {"grpc-status", 11}, {"7", 1}, Connection::RespHeaderMutationMode::Set};
    conn->resp_header_mutations[2] = {{"grpc-status-details-bin", 23},
                                      {accepted_details, sizeof(accepted_details) - 1},
                                      Connection::RespHeaderMutationMode::Set};
    u8 bodyless_response[2048];
    H2Dispatch<SmallLoop> bodyless_dispatch{
        loop.get(), conn, bodyless_response, sizeof(bodyless_response), 0, false};
    JitDispatchOutcome bodyless_outcome{};
    bodyless_outcome.status_code = 200;
    bodyless_outcome.response_body_idx = 0xffffu;
    h2_emit_outcome(bodyless_dispatch, 1, bodyless_outcome, nullptr, false);
    Http2FrameHeader bodyless_frame{};
    REQUIRE_EQ(parse_frame_header(bodyless_response, bodyless_dispatch.resp_len, &bodyless_frame),
               ParseStatus::Complete);
    CHECK_EQ(bodyless_frame.flags & http2_flag::kEndStream, http2_flag::kEndStream);
    hpack::DynamicTable bodyless_decoder;
    bodyless_decoder.init(kDefaultHeaderTableSize);
    hpack::Header bodyless_headers[8];
    u8 bodyless_scratch[2048];
    u32 bodyless_count = 0;
    REQUIRE(hpack::decode_header_block(bodyless_decoder,
                                       bodyless_response + kFrameHeaderSize,
                                       bodyless_frame.length,
                                       bodyless_scratch,
                                       sizeof(bodyless_scratch),
                                       bodyless_headers,
                                       8,
                                       &bodyless_count));
    bool bodyless_details = false;
    bool bodyless_status = false;
    u32 bodyless_details_count = 0;
    for (u32 i = 0; i < bodyless_count; ++i)
        if (bodyless_headers[i].name.eq(lit_str("grpc-status-details-bin"))) {
            ++bodyless_details_count;
            bodyless_details =
                bodyless_headers[i].value.eq(Str{accepted_details, sizeof(accepted_details) - 1});
        } else if (bodyless_headers[i].name.eq(lit_str("grpc-status")))
            bodyless_status = bodyless_headers[i].value.eq(lit_str("7"));
    CHECK(bodyless_details);
    CHECK_EQ(bodyless_details_count, 1u);
    CHECK(bodyless_status);
    CHECK_EQ(h2->outbound_stream, 0u);
    CHECK_EQ(h2->queued_stream, 0u);
    conn->h2 = nullptr;
    loop->free_conn(*conn);
}

TEST(json_network, h2_grpc_web_reset_releases_parked_normalization_arena) {
    SmallLoop loop;
    loop.setup();
    SlicePool pool;
    REQUIRE(pool.init(4));
    auto* conn = loop.alloc_conn();
    REQUIRE(conn);
    conn->json_arena.backend.pool = &pool;
    REQUIRE(conn->json_arena.init(&pool));
    REQUIRE(conn->json_arena.alloc(8197) != nullptr);
    Http2Conn h2;
    h2.init();
    h2.async_stream = 1;
    conn->h2 = &h2;
    auto* ctx = conn->reset_jit_ctx();
    ctx->req_body_override_ptr = reinterpret_cast<const u8*>(1);
    ctx->req_body_override_len = 6;
    ctx->req_body_override_valid = 1;
    u8 response[1]{};
    H2Dispatch<SmallLoop> dispatch{&loop, conn, response, sizeof(response), 0, false};
    h2_on_reset_dispatch_cb<SmallLoop>(&dispatch, h2, 1, Http2Error::Cancel);
    CHECK_EQ(h2.async_stream, 0u);
    CHECK(conn->json_arena.current == nullptr);
    CHECK_FALSE(conn->jit_ctx()->req_body_override_valid);
    conn->h2 = nullptr;
    loop.free_conn(*conn);
    pool.destroy();
}

TEST(json_network, chunked_grpc_web_wire_accounting_is_fragmentation_independent) {
    const std::string headers =
        "POST /body HTTP/1.1\r\nHost: test\r\n"
        "Content-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n";
    const std::string chunks =
        std::string("6\r\n") + std::string("\0\0\0\0\1x", 6) + "\r\n0\r\n\r\n";
    for (u32 initial : {0u, 4u, static_cast<u32>(chunks.size())}) {
        auto loop = std::make_unique<SmallLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &web_admission_handler, true));
        const RouteConfig* config_ptr = config.get();
        loop->config_ptr = &config_ptr;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        u8 input[4096];
        conn->recv_buf.bind(input, sizeof(input));
        const std::string first = headers + chunks.substr(0, initial);
        REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(first.data()), first.size()),
                   first.size());
        web_admission_calls = 0;
        on_header_received<SmallLoop>(
            loop.get(),
            *conn,
            IoEvent{conn->id, static_cast<i32>(first.size()), 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(conn->req_size, first.size());
        CHECK_EQ(conn->downstream_req_size, first.size());
        for (u32 pos = initial; pos < chunks.size(); ++pos) {
            REQUIRE_EQ(conn->recv_buf.write(reinterpret_cast<const u8*>(chunks.data() + pos), 1),
                       1u);
            on_jit_request_body_recvd<SmallLoop>(
                loop.get(), *conn, IoEvent{conn->id, 1, 0, 0, IoEventType::Recv, 0});
            CHECK_EQ(conn->req_size, headers.size() + pos + 1);
            CHECK_EQ(conn->downstream_req_size, headers.size() + pos + 1);
        }
        CHECK_EQ(web_admission_calls, 1u);
        CHECK_EQ(conn->resp_status, 422u);
        loop->free_conn(*conn);
        pool.destroy();
    }
}

static u32 web_wait_calls;
static const u8* web_wait_slice;
static SlicePool* web_wait_pool;
static u32 web_wait_owned_slices;
static u64 web_wait_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    ++web_wait_calls;
    web_wait_slice = ctx->req_body_override_ptr;
    web_wait_owned_slices = 0;
    for (u32 i = 0; i < web_wait_pool->count; ++i)
        web_wait_owned_slices += web_wait_pool->in_use_map[i] != 0;
    return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 10).pack();
}

TEST(json_network, h2_web_data_wait_and_reset_in_one_process_reclaims_body) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto config = std::make_unique<RouteConfig>();
    REQUIRE(config->add_jit_handler("/body", 0, &web_wait_handler, true));
    auto* conn = loop->alloc_conn();
    REQUIRE(conn);
    conn->request_config = config.get();
    conn->json_arena.backend.pool = &pool;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    conn->h2 = h2.get();
    u8 response[4096];
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
    h2->cb_ctx = &dispatch;
    h2->on_headers = &h2_on_headers_cb<SmallLoop>;
    h2->on_data = &h2_on_data_cb<SmallLoop>;
    h2->on_reset = &h2_on_reset_dispatch_cb<SmallLoop>;
    u8 wire[2048];
    u32 n = kClientPrefaceLen;
    __builtin_memcpy(wire, kClientPreface, n);
    write_frame_header(wire + n,
                       Http2FrameHeader{0, 0, static_cast<u8>(Http2FrameType::Settings), 0});
    n += kFrameHeaderSize;
    u8 block[512];
    u32 b = 0;
    b += hpack::encode_header(block + b, lit_str(":method"), lit_str("POST"));
    b += hpack::encode_header(block + b, lit_str(":scheme"), lit_str("http"));
    b += hpack::encode_header(block + b, lit_str(":path"), lit_str("/body"));
    b += hpack::encode_header(block + b, lit_str(":authority"), lit_str("test"));
    b += hpack::encode_header(block + b, lit_str("content-type"), lit_str("application/grpc-web"));
    write_frame_header(
        wire + n,
        Http2FrameHeader{b, 1, static_cast<u8>(Http2FrameType::Headers), http2_flag::kEndHeaders});
    n += kFrameHeaderSize;
    __builtin_memcpy(wire + n, block, b);
    n += b;
    write_frame_header(
        wire + n,
        Http2FrameHeader{6, 1, static_cast<u8>(Http2FrameType::Data), http2_flag::kEndStream});
    n += kFrameHeaderSize;
    const u8 body[] = {0, 0, 0, 0, 1, 'x'};
    __builtin_memcpy(wire + n, body, sizeof(body));
    n += sizeof(body);
    n += write_rst_stream(wire + n, 1, Http2Error::Cancel);
    web_wait_calls = 0;
    web_wait_slice = nullptr;
    web_wait_pool = &pool;
    u8 control[4096];
    u32 written = 0;
    const auto result = h2->process(wire, n, control, sizeof(control), &written);
    CHECK_EQ(result.consumed, n);
    CHECK_EQ(web_wait_calls, 1u);
    REQUIRE(web_wait_slice != nullptr);
    CHECK_EQ(h2->async_stream, 0u);
    CHECK(conn->json_arena.current == nullptr);
    CHECK_FALSE(conn->jit_ctx()->req_body_override_valid);
    CHECK(web_wait_owned_slices > 0);
    u32 remaining_slices = 0;
    for (u32 i = 0; i < pool.count; ++i) remaining_slices += pool.in_use_map[i] != 0;
    CHECK_EQ(remaining_slices, 0u);
    CHECK_EQ(dispatch.resp_len, 0u);
    conn->h2 = nullptr;
    loop->free_conn(*conn);
    pool.destroy();
}

static jit::YieldKind web_event_kind;
static bool web_event_timer_first;
static u32 web_event_calls;
static bool web_event_normalized;
static u64 web_event_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    ++web_event_calls;
    web_event_normalized = ctx->req_body_override_valid && ctx->req_body_override_len == 6;
    if (web_event_timer_first && ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 1).pack();
    return jit::HandlerResult::make_yield_payload(2, web_event_kind, 1).pack();
}

TEST(json_network, chunked_web_handler_event_wait_never_submits_upstream_io) {
    const std::string request =
        std::string(
            "POST /body HTTP/1.1\r\nHost: test\r\n"
            "Content-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n") +
        std::string("\0\0\0\0\1x", 6) + "\r\n0\r\n\r\n";
    for (auto kind : {jit::YieldKind::UpstreamConnect, jit::YieldKind::UpstreamSend}) {
        for (bool timer_first : {false, true}) {
            auto loop = std::make_unique<SmallLoop>();
            loop->setup();
            SlicePool pool;
            REQUIRE(pool.init(16));
            auto config = std::make_unique<RouteConfig>();
            REQUIRE(config->add_jit_handler("/body", 0, &web_event_handler, true));
            REQUIRE(config->add_upstream("api", 0x0100007fu, 8080));
            const RouteConfig* config_ptr = config.get();
            loop->config_ptr = &config_ptr;
            auto* conn = loop->alloc_conn();
            REQUIRE(conn);
            conn->fd = 41;
            conn->json_arena.backend.pool = &pool;
            const i32 upstream_fd =
                kind == jit::YieldKind::UpstreamSend ? socket(AF_INET, SOCK_STREAM, 0) : -1;
            if (kind == jit::YieldKind::UpstreamSend) REQUIRE(upstream_fd >= 0);
            conn->upstream_fd = upstream_fd;
            conn->upstream_idx = 0;
            u8 input[4096];
            conn->recv_buf.bind(input, sizeof(input));
            REQUIRE_EQ(
                conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
                request.size());
            web_event_kind = kind;
            web_event_timer_first = timer_first;
            web_event_calls = 0;
            web_event_normalized = false;
            on_header_received<SmallLoop>(
                loop.get(),
                *conn,
                IoEvent{conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
            REQUIRE(web_event_normalized);
            if (timer_first) {
                REQUIRE(conn->pending_handler_fn != nullptr);
                resume_jit_handler(loop.get(), *conn);
            }
            CHECK_EQ(web_event_calls, timer_first ? 2u : 1u);
            CHECK_EQ(conn->resp_status, 400u);
            CHECK_EQ(conn->upstream_fd, upstream_fd);
            CHECK_FALSE(conn->keep_alive);
            for (u32 i = 0; i < loop->backend.op_count; ++i) {
                const auto& op = loop->backend.ops[i];
                CHECK(op.type != MockOp::Connect);
                if (op.type == MockOp::Send || op.type == MockOp::Recv) CHECK_EQ(op.fd, conn->fd);
            }
            loop->free_conn(*conn);
            pool.destroy();
        }
    }
}

TEST(json_network, web_admission_errors_preserve_head_and_malformed_header_rules) {
    struct Case {
        const char* method;
        const char* headers;
        bool chunked;
        bool accepted;
    };
    const Case cases[] = {
        {"HEAD", "Content-Type: application/grpc-web\r\n", false, false},
        {"HEAD", "Content-Type: application/grpc-web\r\n", true, false},
        {"HEAD", "Content-Type: application/grpc-web\r\nBroken\r\n", false, false},
        {"POST", "Content-Type: application/grpc-web\r\nBroken\r\n", false, false},
        {"POST", "Broken\r\nContent-Type: application/grpc-web\r\n", false, false},
        {"POST", "Broken\r\ncOnTeNt-TyPe:\tapplication/grpc-web-text+proto; x=y\r\n", false, false},
        {"POST", "Content-Type: text/plain\r\nBroken\r\n", false, true},
    };
    for (const auto& item : cases) {
        auto loop = std::make_unique<SmallLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &web_admission_handler, true));
        const RouteConfig* config_ptr = config.get();
        loop->config_ptr = &config_ptr;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        const std::string body("\0\0\0\0\1x", 6);
        const std::string request =
            std::string(item.method) + " /body HTTP/1.1\r\nHost: test\r\n" +
            (item.chunked ? "Transfer-Encoding: chunked\r\n" : "Content-Length: 6\r\n") +
            item.headers + "\r\n" + (item.chunked ? "6\r\n" + body + "\r\n0\r\n\r\n" : body);
        u8 input[4096];
        conn->recv_buf.bind(input, sizeof(input));
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        web_admission_calls = 0;
        on_header_received<SmallLoop>(
            loop.get(),
            *conn,
            IoEvent{conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        CHECK_EQ(web_admission_calls, item.accepted ? 1u : 0u);
        CHECK_EQ(conn->resp_status, item.accepted ? 422u : 400u);
        if (item.method[0] == 'H') {
            const std::string response(reinterpret_cast<const char*>(conn->send_buf.data()),
                                       conn->send_buf.len());
            const auto end = response.find("\r\n\r\n");
            REQUIRE(end != std::string::npos);
            CHECK_EQ(response.size(), end + 4);
        }
        loop->free_conn(*conn);
        pool.destroy();
    }
}

static u32 web_downstream_calls;
static bool web_downstream_normalized;
static u64 web_downstream_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    ++web_downstream_calls;
    web_downstream_normalized = ctx->req_body_override_valid && ctx->req_body_override_len == 6 &&
                                ctx->req_body_override_ptr[5] == 'x';
    if (ctx->state == 0) return jit::HandlerResult::make_yield(1, web_event_kind).pack();
    return jit::HandlerResult::make_status(422).pack();
}

TEST(json_network, chunked_web_downstream_waits_preserve_normalized_body) {
    const std::string request =
        std::string(
            "POST /body HTTP/1.1\r\nHost: test\r\n"
            "Content-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n") +
        std::string("\0\0\0\0\1x", 6) + "\r\n0\r\n\r\n";
    for (auto kind : {jit::YieldKind::Send, jit::YieldKind::Recv, jit::YieldKind::Any}) {
        auto loop = std::make_unique<SmallLoop>();
        loop->setup();
        SlicePool pool;
        REQUIRE(pool.init(16));
        auto config = std::make_unique<RouteConfig>();
        REQUIRE(config->add_jit_handler("/body", 0, &web_downstream_handler, true));
        const RouteConfig* config_ptr = config.get();
        loop->config_ptr = &config_ptr;
        auto* conn = loop->alloc_conn();
        REQUIRE(conn);
        conn->fd = 41;
        conn->json_arena.backend.pool = &pool;
        u8 input[4096];
        conn->recv_buf.bind(input, sizeof(input));
        REQUIRE_EQ(
            conn->recv_buf.write(reinterpret_cast<const u8*>(request.data()), request.size()),
            request.size());
        web_event_kind = kind;
        web_downstream_calls = 0;
        web_downstream_normalized = false;
        on_header_received<SmallLoop>(
            loop.get(),
            *conn,
            IoEvent{conn->id, static_cast<i32>(request.size()), 0, 0, IoEventType::Recv, 0});
        if (kind != jit::YieldKind::Send) {
            REQUIRE(conn->pending_handler_fn != nullptr);
            CHECK_EQ(web_downstream_calls, 1u);
            bool recv_submitted = false;
            for (u32 i = 0; i < loop->backend.op_count; ++i)
                recv_submitted |= loop->backend.ops[i].type == MockOp::Recv &&
                                  loop->backend.ops[i].fd == conn->fd;
            CHECK(recv_submitted);
            conn->resume_event_kind = jit::YieldKind::Recv;
            conn->resume_event_result = 1;
            resume_jit_handler(loop.get(), *conn);
        }
        CHECK_EQ(web_downstream_calls, 2u);
        CHECK(web_downstream_normalized);
        CHECK_EQ(conn->resp_status, 422u);
        CHECK_EQ(conn->upstream_fd, -1);
        loop->free_conn(*conn);
        pool.destroy();
    }
}
