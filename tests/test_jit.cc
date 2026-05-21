#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_builder.h"
#include "rut/jit/codegen.h"
#include "rut/jit/handler_abi.h"
#include "rut/jit/jit_engine.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/jit_dispatch.h"
#include "test.h"
#include <filesystem>
#include <fstream>

#include <pthread.h>
#include <stdio.h>

using namespace rut;
using namespace rut::rir;
using namespace rut::jit;

extern "C" u32 rut_helper_regex_scratch_cache_entry_count_for_test();

// ── Helpers ────────────────────────────────────────────────────────

static Str lit(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return {s, n};
}

struct TestHandlerCtxFrame {
    HandlerCtx ctx{};
    u64 slots[ConnectionBase::kMaxJitHandlerSlots]{};

    TestHandlerCtxFrame() { ctx.slot_count = ConnectionBase::kMaxJitHandlerSlots; }
};

// RAII wrapper — frontend APIs (parse_file/analyze_file/build_mir) all
// .release() a unique_ptr. Without ownership the raw pointer leaks; the
// test suite was leaking ~75 MB per test case before this guard landed.
template <typename T>
struct HeapFrontendResult {
    FrontendResult<T*> inner;

    HeapFrontendResult() = default;
    HeapFrontendResult(FrontendResult<T*> v) : inner(std::move(v)) {}
    HeapFrontendResult(const HeapFrontendResult&) = delete;
    HeapFrontendResult& operator=(const HeapFrontendResult&) = delete;
    HeapFrontendResult(HeapFrontendResult&& other) noexcept : inner(std::move(other.inner)) {
        other.inner = core::make_unexpected(Diagnostic{});
    }
    HeapFrontendResult& operator=(HeapFrontendResult&& other) noexcept {
        if (this != &other) {
            reset();
            inner = std::move(other.inner);
            other.inner = core::make_unexpected(Diagnostic{});
        }
        return *this;
    }
    ~HeapFrontendResult() { reset(); }

    void reset() {
        if (inner.has_value()) {
            delete inner.value();
            inner = core::make_unexpected(Diagnostic{});
        }
    }

    bool has_value() const { return inner.has_value(); }
    explicit operator bool() const { return static_cast<bool>(inner); }
    T* operator->() { return inner.value(); }
    const T* operator->() const { return inner.value(); }
    T& value() { return *inner.value(); }
    const T& value() const { return *inner.value(); }
    Diagnostic& error() { return inner.error(); }
    const Diagnostic& error() const { return inner.error(); }
};

static HeapFrontendResult<AstFile> parse_file_heap(const LexedTokens& tokens) {
    auto ast = parse_file(tokens);
    if (!ast) return {core::make_unexpected(ast.error())};
    return {ast.value()};
}

static HeapFrontendResult<HirModule> analyze_file_heap(const AstFile& file) {
    auto hir = analyze_file(file);
    if (!hir) return {core::make_unexpected(hir.error())};
    return {hir.value()};
}

static HeapFrontendResult<HirModule> analyze_file_heap_with_path(const AstFile& file,
                                                                 const std::string& source_path) {
    Str path{source_path.c_str(), static_cast<u32>(source_path.size())};
    auto hir = analyze_file(file, path);
    if (!hir) return {core::make_unexpected(hir.error())};
    return {hir.value()};
}

static HeapFrontendResult<MirModule> build_mir_heap(const HirModule& module) {
    auto mir = build_mir(module);
    if (!mir) return {core::make_unexpected(mir.error())};
    return {mir.value()};
}

// Unwrap Expected.
#define V(expr)                                                \
    __extension__({                                            \
        auto&& _v_result = (expr);                             \
        REQUIRE(static_cast<bool>(_v_result));                 \
        static_cast<decltype(_v_result)&&>(_v_result).value(); \
    })

#define VOK(expr) REQUIRE(static_cast<bool>(expr))

// MmapArena-backed module initialization (same pattern as test_rir.cc).
struct TestContext {
    MmapArena arena;
    Module mod;

    bool init() {
        if (!arena.init(4096)) return false;
        mod.name = lit("test_jit.rut");
        mod.arena = &arena;

        static constexpr u32 kMaxFuncs = 8;
        mod.functions = arena.alloc_array<Function>(kMaxFuncs);
        if (!mod.functions) {
            arena.destroy();
            return false;
        }
        mod.func_count = 0;
        mod.func_cap = kMaxFuncs;
        static constexpr u32 kMaxStructs = 8;
        mod.struct_defs = arena.alloc_array<StructDef*>(kMaxStructs);
        if (!mod.struct_defs) {
            arena.destroy();
            return false;
        }
        mod.struct_count = 0;
        mod.struct_cap = kMaxStructs;
        return true;
    }

    void destroy() { arena.destroy(); }
};

// A minimal HTTP GET request for testing.
static const char kGetApiRequest[] =
    "GET /api/users HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "\r\n";

static const char kGetApiQueryRequest[] =
    "GET /api/users?x=1 HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "\r\n";

static const char kGetRootRequest[] =
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "\r\n";

// ── Tests ──────────────────────────────────────────────────────────

// Test: runtime helpers work from C++ (sanity check)
TEST(jit, helpers_sanity) {
    const char* out_ptr = nullptr;
    u32 out_len = 0;
    rut_helper_req_path(reinterpret_cast<const u8*>(kGetApiRequest),
                        sizeof(kGetApiRequest) - 1,
                        &out_ptr,
                        &out_len);
    rut::test::out("  path: ");
    if (out_ptr) {
        for (u32 i = 0; i < out_len; i++) {
            char ch = out_ptr[i];
            (void)::write(1, &ch, 1);
        }
    }
    rut::test::out(" len=");
    rut::test::out_int(static_cast<int>(out_len));
    rut::test::out("\n");
    CHECK(out_ptr != nullptr);
    CHECK(out_len > 0);
    CHECK(out_len == 10);
    CHECK(__builtin_memcmp(out_ptr, "/api/users", 10) == 0);

    rut_helper_req_path(reinterpret_cast<const u8*>(kGetApiQueryRequest),
                        sizeof(kGetApiQueryRequest) - 1,
                        &out_ptr,
                        &out_len);
    CHECK(out_ptr != nullptr);
    CHECK(out_len == 14);
    CHECK(__builtin_memcmp(out_ptr, "/api/users?x=1", 14) == 0);

    static const char fragment_req[] =
        "GET /api/users?x=1#section HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    rut_helper_req_path_only(
        reinterpret_cast<const u8*>(fragment_req), sizeof(fragment_req) - 1, &out_ptr, &out_len);
    CHECK(out_ptr != nullptr);
    CHECK(out_len == 10);
    CHECK(__builtin_memcmp(out_ptr, "/api/users", 10) == 0);

    static const char body_req[] =
        "POST /api/users HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "payload";
    rut_helper_req_body(
        reinterpret_cast<const u8*>(body_req), sizeof(body_req) - 1, &out_ptr, &out_len);
    CHECK(out_ptr != nullptr);
    CHECK(out_len == 7);
    CHECK(__builtin_memcmp(out_ptr, "payload", 7) == 0);
}

// Test: Simple handler that always returns 200.
// RIR equivalent: return 200
TEST(jit, return_200) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("always_200"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);
    VOK(b.emit_ret_status(200));

    // Codegen
    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    // JIT compile
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    // Lookup
    void* addr = engine.lookup("handler_always_200");
    REQUIRE(addr != nullptr);

    auto handler = reinterpret_cast<HandlerFn>(addr);
    auto result = HandlerResult::unpack(handler(nullptr,
                                                nullptr,
                                                reinterpret_cast<const u8*>(kGetApiRequest),
                                                sizeof(kGetApiRequest) - 1,
                                                nullptr));

    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK(result.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

TEST(jit, frontend_req_header_or_fallback) {
    const char* src =
        "route GET \"/users\" { let host = req.header(\"Host\") let value = or(host, \"fallback\") "
        "return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_standard_header_alias_or_fallback) {
    const char* src =
        "route GET \"/users\" { let auth = or(req.authorization, \"\") let request = "
        "or(req.xRequestId, \"\") if auth == \"Bearer root\" { if request == \"req-1\" { "
        "return 204 } else { return 401 } } else { return 401 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char hit[] =
        "GET /users HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer root\r\n"
        "X-Request-ID: req-1\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    auto miss = HandlerResult::unpack(handler(nullptr,
                                              nullptr,
                                              reinterpret_cast<const u8*>(kGetApiRequest),
                                              sizeof(kGetApiRequest) - 1,
                                              nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK(miss.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_remote_addr_read) {
    const char* src = "route GET \"/addr\" { let addr = req.remoteAddr return 204 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    Connection conn;
    conn.reset();
    conn.peer_addr = 0x0100007F;
    auto r = HandlerResult::unpack(handler(&conn,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_route_param_field_guard) {
    const char* src =
        "route GET \"/users/:id\" { if req.id == \"42\" { return 204 } else { return 401 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    static const char id_name[] = "id";
    static const char id_hit[] = "42";
    frame.ctx.route_param_count = 1;
    frame.ctx.route_params[0] = {id_name, 2, id_hit, 2};

    auto hit = HandlerResult::unpack(handler(nullptr,
                                             &frame.ctx,
                                             reinterpret_cast<const u8*>(kGetApiRequest),
                                             sizeof(kGetApiRequest) - 1,
                                             nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 204u);

    frame.ctx.route_params[0].value = "41";
    auto miss = HandlerResult::unpack(handler(nullptr,
                                              &frame.ctx,
                                              reinterpret_cast<const u8*>(kGetApiRequest),
                                              sizeof(kGetApiRequest) - 1,
                                              nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_string_or_fallback) {
    const char* src =
        "route GET \"/search\" { let raw = or(req.queryString, \"\") if raw == "
        "\"q=rut&empty=\" { return 204 } else { return 401 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char hit[] = "GET /search?q=rut&empty=#frag HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char miss[] = "GET /search HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_path_only_ignores_query_and_fragment) {
    const char* src =
        "route GET \"/search\" { let path = req.pathOnly if path == \"/search\" { return 204 } "
        "else { return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char hit[] = "GET /search?q=rut#frag HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char miss[] = "GET /other?q=rut#frag HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss_r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(miss_r.action == HandlerAction::ReturnStatus);
    CHECK(miss_r.status_code == 404);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_body_matches_content_length_bounded_bytes) {
    const char* src =
        "route POST \"/upload\" { let body = req.body if body == \"payload\" { return 204 } "
        "else { return 400 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char hit[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\r\npayloadextra";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char miss[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\npayload";
    auto miss_r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(miss_r.action == HandlerAction::ReturnStatus);
    CHECK(miss_r.status_code == 400);

    static const char partial[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\npayload";
    auto partial_r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(partial), sizeof(partial) - 1, nullptr));
    CHECK(partial_r.action == HandlerAction::ReturnStatus);
    CHECK(partial_r.status_code == 400);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_request_flags_reflect_parsed_headers) {
    const char* src =
        "route POST \"/upload\" { if req.keepAlive { if req.chunked { return 204 } else { "
        "return 400 } } else { return 408 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char hit[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char not_chunked[] = "POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto not_chunked_r = HandlerResult::unpack(handler(nullptr,
                                                       nullptr,
                                                       reinterpret_cast<const u8*>(not_chunked),
                                                       sizeof(not_chunked) - 1,
                                                       nullptr));
    CHECK(not_chunked_r.action == HandlerAction::ReturnStatus);
    CHECK(not_chunked_r.status_code == 400);

    static const char close_req[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        "Transfer-Encoding: chunked\r\n\r\n";
    auto close_r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(close_req), sizeof(close_req) - 1, nullptr));
    CHECK(close_r.action == HandlerAction::ReturnStatus);
    CHECK(close_r.status_code == 408);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_has_content_length_distinguishes_zero_from_absent) {
    const char* src =
        "route POST \"/upload\" { if req.hasContentLength { return 204 } else { return 411 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char zero_len[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(zero_len), sizeof(zero_len) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char absent[] = "POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(absent), sizeof(absent) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 411);

    static const char nonzero[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(nonzero), sizeof(nonzero) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_http_version_flags_reflect_request_line) {
    const char* src =
        "route GET \"/version\" { if req.http10 { return 210 } else { if req.http11 { return 211 "
        "} else { return 400 } } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char http10[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http10), sizeof(http10) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 210);

    static const char http11[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http11), sizeof(http11) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 211);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_http_version_string_reflects_request_line) {
    const char* src =
        "route GET \"/version\" { let version = req.httpVersion if version == \"HTTP/1.0\" { "
        "return 210 } else { if version == \"HTTP/1.1\" { return 211 } else { return 400 } } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char http10[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http10), sizeof(http10) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 210);

    static const char http11[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http11), sizeof(http11) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 211);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_cookie_or_fallback) {
    const char* src =
        "route GET \"/session\" { let sid = or(req.cookie(\"sid\"), \"\") if sid == \"ok\" { "
        "return 204 } else { return 401 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char hit[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=ok; lang=en\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char miss[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=nope\r\n\r\n";
    r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    r = HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(kGetApiRequest),
                                      sizeof(kGetApiRequest) - 1,
                                      nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_merges_imported_function_symbols) {
    const std::string dir = "/tmp/rut_import_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/auth.rut", std::ios::binary);
        out << "func jwtAuth() -> i32 => 200\n";
    }
    const auto src = R"rut(
import "auth.rut"
route GET "/users" { if jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_with_package_decl_merges_imported_function_symbols) {
    const std::string dir = "/tmp/rut_import_packaged_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/auth.rut", std::ios::binary);
        out << "package auth\n";
        out << "func jwtAuth() -> i32 => 200\n";
    }
    const auto src = R"rut(
import "auth.rut"
route GET "/users" { if jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    if (!hir) {
        std::fprintf(stderr,
                     "hir error code=%d detail=%.*s span=(%u,%u)\n",
                     static_cast<int>(hir.error().code),
                     static_cast<int>(hir.error().detail.len),
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    }
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_merges_imported_variant_symbol) {
    const std::string dir = "/tmp/rut_import_variant_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/types.rut", std::ios::binary);
        out << "variant AuthState { ok, err }\n";
    }
    const auto src = R"rut(
import "types.rut"
route GET "/users" { let state = AuthState.ok match state { case .ok: return 200 case _: return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    if (!lowered) {
        std::fprintf(stderr,
                     "lower err code=%d line=%u col=%u\n",
                     static_cast<int>(lowered.error().code),
                     lowered.error().span.line,
                     lowered.error().span.col);
    }
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_merges_imported_impl_symbol) {
    const std::string dir = "/tmp/rut_import_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" { if run(Box(value: 1)) == 1 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_merges_imported_generic_impl_symbol) {
    const std::string dir = "/tmp/rut_import_generic_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable {\n";
        out << "    func hash(self: Box<T>) -> i32 => 200\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" { if run(Box(value: 123)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_merges_imported_concrete_generic_impl_symbol) {
    const std::string dir = "/tmp/rut_import_concrete_generic_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<i32> impl Hashable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 7)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_allows_distinct_local_concrete_generic_impl) {
    const std::string dir = "/tmp/rut_import_concrete_generic_impl_distinct_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<i32> impl Hashable {\n";
        out << "    func hash(self: Box<i32>) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
Box<str> impl Hashable {
    func hash(self: Box<str>) -> i32 => 200
}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: "ok")) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_dispatches_distinct_concrete_generic_impls) {
    const std::string dir = "/tmp/rut_import_concrete_generic_impl_dual_dispatch_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<i32> impl Hashable {\n";
        out << "    func hash(self: Box<i32>) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
Box<str> impl Hashable {
    func hash(self: Box<str>) -> i32 => 200
}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 7)) == 7 {
        if run(Box(value: "ok")) == 200 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_relative_file_merges_imported_empty_impl_for_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_default_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit,
     frontend_import_relative_file_merges_imported_generic_empty_impl_for_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_default_method_dispatch_with_parameter) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_param_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder { func add(x: i32) -> i32 => x }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" { if run(Box(value: 1)) == 201 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_optional_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_optional_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code() -> i32 => nil }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => or(x.code(), 200)
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_error_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_error_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code() -> i32 => error(.timeout) }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => or(x.code(), 200)
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_tuple_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_tuple_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func second(a: i32, b: i32) -> i32 => b
func run<T: Pairable>(x: T) -> i32 => x.pair() | second(_2, _1)
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_tuple_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_tuple_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func second(a: i32, b: i32) -> i32 => b
func run<T: Pairable>(x: T) -> i32 => x.pair() | second(_2, _1)
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_tuple_default_method_equality) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_tuple_eq_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Pairable>(x: T) -> (i32, i32) => x.pair()
route GET "/users" { if run(Box(value: 1)) == (200, 500) { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_tuple_default_method_ordering) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_tuple_ord_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Pairable>(x: T) -> (i32, i32) => x.pair()
route GET "/users" { if run(Box(value: 1)) < (200, 600) { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_block_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode {\n";
        out << "    func code() -> i32 {\n";
        out << "        let x = 200\n";
        out << "        x\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => x.code()
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_block_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode {\n";
        out << "    func code() -> i32 {\n";
        out << "        let x = 200\n";
        out << "        x\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => x.code()
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_block_body_default_method_dispatch_with_parameter) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_block_param_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" { if run(Box(value: 1)) == 201 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_block_body_default_method_dispatch_with_parameter) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_block_param_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" { if run(Box(value: 1)) == 201 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_if_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_if_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code(ok: bool) -> i32 { if ok { 200 } else { 500 } } }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => x.code(true)
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_if_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_if_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code(ok: bool) -> i32 { if ok { 200 } else { 500 } } }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => x.code(true)
route GET "/users" { if run(Box(value: 1)) == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_error_default_method_guard_match) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_error_guard_match_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code(ok: bool) -> i32 { if ok { 200 } else { "
               "error(.timeout) } } }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 {
    let failed = x.code(false)
    guard match failed else { case .timeout => 401 case _ => 500 }
    200
}
route GET "/users" { if run(Box(value: 1)) == 401 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_selective_import_relative_file_merges_selected_function_symbol) {
    const std::string dir = "/tmp/rut_selective_import_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/auth.rut", std::ios::binary);
        out << "func jwtAuth() -> i32 => 200\n";
        out << "func basicAuth() -> i32 => 500\n";
    }
    const auto src = R"rut(
import { jwtAuth } from "auth.rut"
route GET "/users" { if jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_function_call) {
    const std::string dir = "/tmp/rut_import_namespace_function_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/auth.rut", std::ios::binary);
        out << "func jwtAuth() -> i32 => 200\n";
    }
    const auto src = R"rut(
import "auth.rut"
route GET "/users" { if auth.jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_function_call_for_file_with_package_decl) {
    const std::string dir = "/tmp/rut_import_namespace_packaged_function_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/auth.rut", std::ios::binary);
        out << "package auth\n";
        out << "func jwtAuth() -> i32 => 200\n";
    }
    const auto src = R"rut(
import "auth.rut"
route GET "/users" { if auth.jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_same_package_multiple_files_still_use_file_namespaces) {
    const std::string dir = "/tmp/rut_import_same_package_file_namespaces_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/jwt.rut", std::ios::binary);
        out << "package auth\n";
        out << "func jwtAuth() -> i32 => 200\n";
    }
    {
        std::ofstream out(dir + "/basic.rut", std::ios::binary);
        out << "package auth\n";
        out << "func basicAuth() -> i32 => 200\n";
    }
    const auto src = R"rut(
import "jwt.rut"
import "basic.rut"
route GET "/users" { if jwt.jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_namespace_type_ref_and_protocol_constraint) {
    const std::string dir = "/tmp/rut_import_namespace_type_ref_constraint_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box { value: i32 }\n";
    }
    const auto src = R"rut(
import * as proto from "proto.rut"
proto.Box impl proto.Hashable { func hash(self: proto.Box) -> i32 => self.value }
func run<T: proto.Hashable>(x: T) -> i32 => x.hash()
func read(x: proto.Box) -> i32 => x.value
route GET "/users" { if run(proto.Box(value: 1)) == read(proto.Box(value: 1)) { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_generic_type_ref) {
    const std::string dir = "/tmp/rut_import_namespace_generic_type_ref_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Result<T> { ok(T), err }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func wrap(x: proto.Result<i32>) -> proto.Result<i32> => x
route GET "/users" { let state = wrap(proto.Result<i32>.ok(1)) match state { case .ok(v): return 200 case .err: return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_nested_generic_payload_lowering_path) {
    const std::string dir = "/tmp/rut_import_namespace_nested_generic_type_arg_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "struct Box<T> { value: T }\n";
        out << "variant Result<T> { ok(T), err }\n";
    }
    const auto src = R"rut(
import * as proto from "proto.rut"
func wrap(x: proto.Result<proto.Box<proto.Result<i32>>>) -> proto.Result<proto.Box<proto.Result<i32>>> => x
route GET "/users" { let state = wrap(proto.Result<proto.Box<proto.Result<i32>>>.ok(proto.Box<proto.Result<i32>>(value: proto.Result<i32>.ok(1)))) match state { case .ok(v): return 200 case .err: return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_struct_init) {
    const std::string dir = "/tmp/rut_import_namespace_struct_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "struct Box { value: i32 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" { if proto.Box(value: 1).value == 1 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_namespace_variant_constructor) {
    const std::string dir = "/tmp/rut_import_namespace_variant_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Result { ok(i32), err }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    match proto.Result.ok(200) {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_namespace_payloadless_variant_case) {
    const std::string dir = "/tmp/rut_import_namespace_payloadless_variant_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Token { ready, pending }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    match proto.Token.ready {
    case .ready: return 200
    case .pending: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_alias_resolves_same_stem_conflict) {
    const std::string dir = "/tmp/rut_import_namespace_alias_conflict_jit";
    std::filesystem::create_directories(dir + "/a");
    std::filesystem::create_directories(dir + "/b");
    {
        std::ofstream out(dir + "/a/auth.rut", std::ios::binary);
        out << "func jwtAuth() -> i32 => 200\n";
    }
    {
        std::ofstream out(dir + "/b/auth.rut", std::ios::binary);
        out << "func jwtAuth() -> i32 => 500\n";
    }
    const auto src = R"rut(
import * as authA from "a/auth.rut"
import * as authB from "b/auth.rut"
route GET "/users" { if authA.jwtAuth() == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_selective_import_relative_file_aliases_selected_function_symbol) {
    const std::string dir = "/tmp/rut_selective_import_alias_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/auth.rut", std::ios::binary);
        out << "func jwtAuth() -> i32 => 200\n";
        out << "func basicAuth() -> i32 => 500\n";
    }
    const auto src = R"rut(
import { jwtAuth as authV1 } from "auth.rut"
route GET "/users" { if authV1() == 200 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_selective_import_relative_file_aliases_selected_protocol_and_struct_with_impl) {
    const std::string dir = "/tmp/rut_selective_import_alias_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import { Hashable as Digestible, Box as AuthBox } from "proto.rut"
func run<T: Digestible>(x: T) -> i32 => x.hash()
route GET "/users" { if run(AuthBox(value: 1)) == 1 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_selective_import_relative_file_merges_selected_protocol_and_struct_with_impl) {
    const std::string dir = "/tmp/rut_selective_import_impl_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import { Hashable, Box } from "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" { if run(Box(value: 1)) == 1 { return 200 } else { return 500 } }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_using_alias_function_call) {
    const auto src = R"rut(
using authV1 = v1.jwtAuth
func jwtAuth() -> i32 => 200
route GET "/users" { if authV1() == 200 { return 200 } else { return 500 } }
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_header_alias_or_fallback) {
    const char* src =
        "route GET \"/users\" { let host = req.header(\"Host\") let alias = host let value = "
        "or(alias, \"fallback\") return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_match) {
    const char* src =
        "variant AuthState { timeout, forbidden }\n"
        "route GET \"/users\" { let state = AuthState.timeout match state { case .timeout: return "
        "200 case _: return 403 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_string_match_returns_matching_status_and_fallback) {
    const char* src =
        "route GET \"/users\" { let path = req.path match path { case \"/api/users\": return 200 "
        "case _: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto matched = HandlerResult::unpack(handler(nullptr,
                                                 nullptr,
                                                 reinterpret_cast<const u8*>(kGetApiRequest),
                                                 sizeof(kGetApiRequest) - 1,
                                                 nullptr));
    CHECK(matched.action == HandlerAction::ReturnStatus);
    CHECK(matched.status_code == 200);

    auto fallback = HandlerResult::unpack(handler(nullptr,
                                                  nullptr,
                                                  reinterpret_cast<const u8*>(kGetRootRequest),
                                                  sizeof(kGetRootRequest) - 1,
                                                  nullptr));
    CHECK(fallback.action == HandlerAction::ReturnStatus);
    CHECK(fallback.status_code == 404);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_match_arm_guard_false_falls_through) {
    const char* src =
        "route GET \"/users\" { let code = 200 match code { case 200 if req.method == POST: "
        "return 500 case _: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 404);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_source_function_match_arm_guard_false_executes_fallback) {
    const auto src = R"(
func pick(x: i32) -> i32 {
    match x {
        case 200 if false => 201
        case _ => 404
    }
}
route GET "/users" {
    let code = pick(200)
    if code == 404 { return 200 } else { return 500 }
}
)";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_source_function_match_arm_guard_payload_binding_executes_match) {
    const auto src = R"(
variant Result { ok(i32), err }
func pick(result: Result) -> i32 {
    match result {
        case .ok(code) if code == 200 => code
        case _ => 404
    }
}
route GET "/users" {
    let code = pick(Result.ok(200))
    if code == 200 { return 200 } else { return 500 }
}
)";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_source_function_match_arm_guard_seeds_named_error_case) {
    const auto src = R"(
func pick(x: i32) -> i32 {
    match x {
        case 200 if error(.timeout, "timed out").code == 0 => 200
        case _ => 500
    }
}
route GET "/users" {
    let code = pick(200)
    if code == 200 { return 200 } else { return 500 }
}
)";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_nested_match_payload_variant_case_compares_tag) {
    const auto src = R"(
variant Auth { ok, denied }
variant Result { ok(i32), err }
route GET "/users" {
    let auth = Auth.ok
    let result = Result.ok(200)
    match auth {
    case .ok:
        match result {
        case .ok: return 200
        case _: return 404
        }
    case .denied:
        return 403
    }
}
)";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_single_payload_match) {
    const char* src =
        "variant Result { ok(i32), err }\n"
        "route GET \"/users\" { let state = Result.ok(200) match state { case .ok(x): return 200 "
        "case .err: return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_payload_binding_match_if) {
    const char* src =
        "variant Result { ok(i32), err }\n"
        "route GET \"/users\" { let state = Result.ok(200) match state { case .ok(x): if x == 200 "
        "{ return 200 } else { return 500 } case .err: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_payload_binding_match_block) {
    const char* src =
        "variant Result { ok(i32), err }\n"
        "route GET \"/users\" { let state = Result.ok(200) match state { case .ok(x): { let y = x "
        "if y == 200 { return 200 } else { return 500 } } case .err: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_payload_binding_match_block_with_guard) {
    const char* src =
        "variant Result { ok(i32), err }\n"
        "route GET \"/users\" { let state = Result.ok(200) match state { case .ok(x): { let failed "
        "= error(7) guard failed else { return 401 } if x == 200 { return 200 } else { return 500 "
        "} } case .err: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_payload_binding_match_block_with_guard_match) {
    const char* src =
        "variant Result { ok(i32), err }\n"
        "route GET \"/users\" { let state = Result.ok(200) match state { case .ok(x): { let failed "
        "= error(.timeout) guard match failed else { case .timeout: return 401 case _: return 402 "
        "} if x == 200 { return 200 } else { return 500 } } case .err: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_if_const) {
    const char* src = "route GET \"/users\" { if const true { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_match_const_variant) {
    const char* src =
        "variant Result { ok(i32), err }\n"
        "route GET \"/users\" { let state = Result.ok(200) match const state { case .ok(x): if x "
        "== 200 { return 200 } else { return 500 } case .err: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_mixed_payload_match) {
    const char* src =
        "variant Mixed { count(i32), ready(bool), label(str), none }\n"
        "route GET \"/users\" { let state = Mixed.ready(true) match state { case .count(x): return "
        "200 case .ready(flag): if flag == true { return 201 } else { return 202 } case "
        ".label(name): return 203 case .none: return 204 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 201);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_tuple_payload_match_pipe_multi_slot) {
    const char* src =
        "variant Result { ok((i32, i32)), err }\n"
        "func second(a: i32, b: i32) -> i32 => b\n"
        "route GET \"/users\" { let state = Result.ok((200, 500)) match state { case .ok(pair): { "
        "let code = pair | second(_2, _1) if code == 200 { return 200 } else { return 500 } } case "
        ".err: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_variant_constructor_and_match) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
route GET "/users" {
    let state = Result<i32>.ok(200)
    match state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_explicit_generic_variant_constructor_nested_type_arg) {
    const auto src = R"rut(
struct Box<T> { value: T }
variant Wrap<T> { some(T), none }
route GET "/users" {
    match Wrap<Box<i32>>.some(Box<i32>(value: 200)) {
    case .some(v): {
        if v.value == 200 { return 200 } else { return 500 }
    }
    case .none: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_tuple_of_struct_payload_binding) {
    const auto src = R"rut(
struct Box { value: i32 }
variant Result { ok((Box, i32)), err }
func boxCode(x: Box) -> i32 => x.value
route GET "/users" {
    match Result.ok((Box(value: 200), 7)) {
    case .ok(v): {
        let code = v | boxCode(_1)
        if code == 200 { return 200 } else { return 500 }
    }
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_match_nested_struct_payload_projection) {
    const auto src = R"rut(
struct Box { value: i32 }
struct Outer { inner: Box }
variant Result { ok(Outer), err }
route GET "/users" {
    let state = Result.ok(Outer(inner: Box(value: 200)))
    match state {
    case .ok(v): {
        let code = v.inner.value
        if code == 200 { return 200 } else { return 500 }
    }
    case .err: return 404
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_variant_tuple_of_struct_payload_binding) {
    const auto src = R"rut(
struct Item { value: i32 }
variant Result<T> { ok(T), err }
func itemCode(x: Item) -> i32 => x.value
route GET "/users" {
    match Result.ok((Item(value: 200), 7)) {
    case .ok(v): {
        let code = v | itemCode(_1)
        if code == 200 { return 200 } else { return 500 }
    }
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_variant_constructor_infers_type_argument_from_single_payload_case) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
route GET "/users" {
    let state = Result.ok(200)
    match state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_known_named_error_match) {
    const char* src =
        "route GET \"/users\" { let failed = error(.timeout) match failed { case .timeout: return "
        "503 case _: return 200 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 503);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_known_named_error_runtime_guard_true_matches_case) {
    const auto src = R"(
route GET "/users" {
    let failed = error(.timeout)
    let allow = req.path == "/api/users"
    match failed {
    case .timeout if allow: return 503
    case _: return 200
    }
}
)";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    CHECK_EQ(static_cast<u8>(hir->routes[0].control.kind), static_cast<u8>(HirControlKind::Match));
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 503);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_known_named_error_runtime_guard_false_falls_through) {
    const auto src = R"(
route GET "/users" {
    let failed = error(.timeout)
    let allow = req.path == "/missing"
    match failed {
    case .timeout if allow: return 503
    case _: return 200
    }
}
)";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    CHECK_EQ(static_cast<u8>(hir->routes[0].control.kind), static_cast<u8>(HirControlKind::Match));
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_explicit_error_variant_match) {
    const char* src =
        "variant AuthError { timeout, forbidden }\n"
        "route GET \"/users\" { let failed = error(AuthError.forbidden) match failed { case "
        ".forbidden: return 403 case _: return 200 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 403);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_error_struct_guard_match) {
    const char* src =
        "struct AuthError { err: Error }\n"
        "route GET \"/users\" { let failed = error(AuthError, .timeout, \"timed out\") guard match "
        "failed else { case .timeout: return 503 case _: return 500 } return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 503);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_error_struct_with_extra_fields_guard_match) {
    const char* src =
        "struct AuthError { err: Error, token: str, retry: i32 }\n"
        "route GET \"/users\" { let failed = error(AuthError, .timeout, \"timed out\", token: "
        "\"abc\", retry: 3) guard match failed else { case .timeout: return 503 case _: return 500 "
        "} return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 503);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_error_struct_with_tuple_field_guard_match) {
    const char* src =
        "struct AuthError { err: Error, pair: (i32, i32) }\n"
        "route GET \"/users\" { let failed = error(AuthError, .timeout, \"timed out\", pair: (200, "
        "500)) guard match failed else { case .timeout: return 503 case _: return 500 } return 200 "
        "}\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 503);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_multiple_top_level_guards) {
    const char* src =
        "route GET \"/users\" { let ok = 200 guard ok else { return 401 } let failed = error(7) "
        "guard failed else { return 402 } return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 402);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_struct_constructor_and_field_projection) {
    const char* src =
        "struct Box<T> { value: T }\n"
        "route GET \"/users\" { let box = Box<i32>(value: 200) if box.value == 200 { return 200 } "
        "else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_struct_constructor_infers_type_argument_from_field_shape) {
    const char* src =
        "struct Box<T> { value: T }\n"
        "route GET \"/users\" { let box = Box(value: 200) if box.value == 200 { return 200 } else "
        "{ return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_type_refs_are_supported_in_let_types) {
    const char* src =
        "variant Result<T> { ok(T), err }\n"
        "route GET \"/users\" { let state: Result<i32> = Result.ok(200) match state { case .ok(v): "
        "return 200 case .err: return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_type_refs_are_supported_in_function_signatures) {
    const char* src =
        "variant Result<T> { ok(T), err }\n"
        "func wrap(x: Result<i32>) -> Result<i32> => x\n"
        "route GET \"/users\" { let state = wrap(Result.ok(200)) match state { case .ok(v): return "
        "200 case .err: return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    if (r.status_code != 200) {
        rut::test::out("    status=");
        rut::test::out_int(r.status_code);
        rut::test::out("\n");
    }
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(r.status_code, 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_struct_type_refs_are_supported_in_function_signatures) {
    const char* src =
        "struct Box<T> { value: T }\n"
        "func wrap(x: Box<i32>) -> Box<i32> => x\n"
        "route GET \"/users\" { let box = wrap(Box(value: 200)) if box.value == 200 { return 200 } "
        "else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_type_refs_are_supported_in_struct_fields) {
    const char* src =
        "variant Result<T> { ok(T), err }\n"
        "struct Holder { state: Result<i32> }\n"
        "route GET \"/users\" { let holder = Holder(state: Result.ok(200)) match holder.state { "
        "case .ok(v): return 200 case .err: return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_struct_field_projection_equality) {
    const char* src =
        "variant Result<T> { ok(T), err }\n"
        "struct Holder { state: Result<i32> }\n"
        "route GET \"/users\" { let holder = Holder(state: Result.ok(200)) if holder.state == "
        "Result.ok(200) { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_variant_struct_field_projection_ordering) {
    const char* src =
        "variant Result<T> { ok(T), err }\n"
        "struct Holder { state: Result<i32> }\n"
        "route GET \"/users\" { let holder = Holder(state: Result.ok(200)) if holder.state < "
        "Result.ok(500) { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_variant_struct_field_projection_equality) {
    const std::string dir = "/tmp/rut_import_namespace_variant_field_eq_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Result { ok(i32), err }\n";
        out << "struct Holder { state: Result }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let holder = proto.Holder(state: proto.Result.ok(200))
    if holder.state == proto.Result.ok(200) { return 200 } else { return 500 }
}
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_variant_struct_field_projection_ordering) {
    const std::string dir = "/tmp/rut_import_namespace_variant_field_ord_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Result { ok(i32), err }\n";
        out << "struct Holder { state: Result }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let holder = proto.Holder(state: proto.Result.ok(200))
    if holder.state < proto.Result.ok(500) { return 200 } else { return 500 }
}
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_tuple_of_struct_field_projection_ordering) {
    const char* src =
        "struct Item { value: i32 }\n"
        "struct Holder { pair: (Item, i32) }\n"
        "route GET \"/users\" { let holder = Holder(pair: (Item(value: 200), 500)) if holder.pair "
        "< (Item(value: 200), 600) { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_import_namespace_tuple_of_struct_field_projection_ordering) {
    const std::string dir = "/tmp/rut_import_namespace_tuple_struct_field_ord_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "struct Item { value: i32 }\n";
        out << "struct Holder { pair: (Item, i32) }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let holder = proto.Holder(pair: (proto.Item(value: 200), 500))
    if holder.pair < (proto.Item(value: 200), 600) { return 200 } else { return 500 }
}
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_type_refs_are_supported_in_variant_payloads) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
variant Outer { wrap(Result<i32>), bad }
route GET "/users" {
    let state = Outer.wrap(Result.ok(200))
    match state {
    case .wrap(inner): {
        let copied = inner
        return 200
    }
    case .bad:
        return 404
    }
}
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(r.status_code, 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_struct_type_refs_are_supported_in_variant_payloads) {
    const char* src =
        "struct Box<T> { value: T }\n"
        "variant Outer { wrap(Box<i32>), bad }\n"
        "func is200(x: Box<i32>) -> bool => x.value == 200\n"
        "route GET \"/users\" { let state = Outer.wrap(Box(value: 200)) match state { case "
        ".wrap(inner): { let ok = is200(inner) if ok { return 200 } else { return 500 } } case "
        ".bad: return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_if_branch_block_with_let) {
    const char* src =
        "route GET \"/users\" { let ok = true if ok { let code = 200 if code == 200 { return 200 } "
        "else { return 500 } } else { return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_if_branch_block_with_guard) {
    const char* src =
        "route GET \"/users\" { let ok = true if ok { let failed = error(7) guard failed else { "
        "return 401 } return 200 } else { return 404 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_guard_else_block_with_let) {
    const char* src =
        "route GET \"/users\" { let failed = error(7) guard failed else { let code = 401 if code "
        "== 401 { return 401 } else { return 500 } } return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_guard_match_routes_fail_and_success_paths) {
    {
        const char* src =
            "route GET \"/users\" { let failed = error(.timeout) guard match failed else { case "
            ".timeout: return 503 case _: return 500 } return 200 }\n";

        auto lexed = lex(lit(src));
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap(ast.value());
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);

        FrontendRirModule rir{};
        auto lowered = lower_to_rir(mir.value(), rir);
        REQUIRE(lowered);

        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);

        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));

        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);

        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 503);

        engine.shutdown();
        rir.destroy();
    }

    {
        const char* src =
            "func maybefail(ok: bool) -> i32 { if ok { 200 } else { error(.timeout) } }\n"
            "route GET \"/users\" { let ok = maybefail(true) guard match ok else { case .timeout: "
            "return 503 case _: return 500 } return 200 }\n";

        auto lexed = lex(lit(src));
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap(ast.value());
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);

        FrontendRirModule rir{};
        auto lowered = lower_to_rir(mir.value(), rir);
        REQUIRE(lowered);

        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);

        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));

        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);

        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 200);

        engine.shutdown();
        rir.destroy();
    }
}

TEST(jit, runtime_error_kind_match_from_mir) {
    auto* mir = new MirModule{};
    MirVariant err_variant{};
    err_variant.span = {1, 1, 1, 1};
    err_variant.name = lit("AuthError");
    MirVariant::CaseDecl timeout{};
    timeout.name = lit("timeout");
    MirVariant::CaseDecl forbidden{};
    forbidden.name = lit("forbidden");
    REQUIRE(err_variant.cases.push(timeout));
    REQUIRE(err_variant.cases.push(forbidden));
    REQUIRE(mir->variants.push(err_variant));

    MirFunction fn{};
    fn.span = {1, 1, 1, 1};
    fn.method = 'G';
    fn.path = lit("/users");
    fn.name = lit("route");

    MirLocal failed{};
    failed.span = fn.span;
    failed.name = lit("failed");
    failed.type = MirTypeKind::I32;
    failed.may_error = true;
    failed.error_variant_index = 0;
    failed.init.kind = MirValueKind::Error;
    failed.init.type = MirTypeKind::Unknown;
    failed.init.may_error = true;
    failed.init.error_variant_index = 0;
    failed.init.error_case_index = 1;
    REQUIRE(fn.locals.push(failed));

    MirValue subject{};
    subject.kind = MirValueKind::LocalRef;
    subject.type = MirTypeKind::I32;
    subject.may_error = true;
    subject.local_index = 0;
    subject.error_variant_index = 0;
    REQUIRE(fn.values.push(subject));

    MirValue timeout_pat{};
    timeout_pat.kind = MirValueKind::VariantCase;
    timeout_pat.type = MirTypeKind::Variant;
    timeout_pat.variant_index = 0;
    timeout_pat.case_index = 0;
    timeout_pat.int_value = 0;
    REQUIRE(fn.values.push(timeout_pat));

    MirBlock test{};
    test.label = lit("entry");
    test.term.kind = MirTerminatorKind::Branch;
    test.term.use_cmp = true;
    test.term.span = fn.span;
    test.term.lhs = fn.values[0];
    test.term.rhs = fn.values[1];
    test.term.then_block = 1;
    test.term.else_block = 2;
    REQUIRE(fn.blocks.push(test));

    MirBlock then_block{};
    then_block.label = lit("then");
    then_block.term.kind = MirTerminatorKind::ReturnStatus;
    then_block.term.span = fn.span;
    then_block.term.status_code = 503;
    REQUIRE(fn.blocks.push(then_block));

    MirBlock else_block{};
    else_block.label = lit("else");
    else_block.term.kind = MirTerminatorKind::ReturnStatus;
    else_block.term.span = fn.span;
    else_block.term.status_code = 403;
    REQUIRE(fn.blocks.push(else_block));
    REQUIRE(mir->functions.push(fn));

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir, rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 403);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, runtime_error_code_field_from_mir) {
    auto* hir = new HirModule{};
    HirRoute route{};
    route.span = {1, 1, 1, 1};
    route.method = 'G';
    route.path = lit("/users");

    HirLocal failed{};
    failed.span = route.span;
    failed.name = lit("failed");
    failed.type = HirTypeKind::I32;
    failed.may_error = true;
    failed.init.kind = HirExprKind::Error;
    failed.init.type = HirTypeKind::Unknown;
    failed.init.may_error = true;
    failed.init.int_value = 503;
    failed.init.msg = lit("boom");
    REQUIRE(route.locals.push(failed));

    HirExpr failed_ref{};
    failed_ref.kind = HirExprKind::LocalRef;
    failed_ref.type = HirTypeKind::I32;
    failed_ref.may_error = true;
    failed_ref.local_index = 0;
    REQUIRE(route.exprs.push(failed_ref));

    HirLocal code{};
    code.span = route.span;
    code.name = lit("code");
    code.type = HirTypeKind::I32;
    code.init.kind = HirExprKind::Field;
    code.init.type = HirTypeKind::I32;
    code.init.lhs = &route.exprs[0];
    code.init.str_value = lit("code");
    REQUIRE(route.locals.push(code));

    route.control.kind = HirControlKind::If;
    route.control.cond.kind = HirExprKind::Eq;
    route.control.cond.type = HirTypeKind::Bool;

    HirExpr code_ref{};
    code_ref.kind = HirExprKind::LocalRef;
    code_ref.type = HirTypeKind::I32;
    code_ref.local_index = 1;
    REQUIRE(route.exprs.push(code_ref));

    HirExpr expected{};
    expected.kind = HirExprKind::IntLit;
    expected.type = HirTypeKind::I32;
    expected.int_value = 503;
    REQUIRE(route.exprs.push(expected));

    route.control.cond.lhs = &route.exprs[1];
    route.control.cond.rhs = &route.exprs[2];
    route.control.then_term.kind = HirTerminatorKind::ReturnStatus;
    route.control.then_term.status_code = 200;
    route.control.else_term.kind = HirTerminatorKind::ReturnStatus;
    route.control.else_term.status_code = 500;
    REQUIRE(hir->routes.push(route));

    auto mir = build_mir(*hir);
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

// Test: Handler with path prefix guard.
// RIR equivalent:
//   %path = req.path
//   %prefix = const.str "/api"
//   %has = str.has_prefix %path, %prefix
//   br %has, ok_block, reject_block
//   reject_block: ret.status 404
//   ok_block: ret.status 200
TEST(jit, guard_path_prefix) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("path_guard"), lit("/api"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok_blk = V(b.create_block(fn, lit("ok")));
    auto reject_blk = V(b.create_block(fn, lit("reject")));

    // Entry block: check path prefix
    b.set_insert_point(fn, entry);
    auto path = V(b.emit_req_path());
    auto prefix = V(b.emit_const_str(lit("/api")));
    auto has = V(b.emit_str_has_prefix(path, prefix));
    VOK(b.emit_br(has, ok_blk, reject_blk));

    // Reject block: 404
    b.set_insert_point(fn, reject_blk);
    VOK(b.emit_ret_status(404));

    // OK block: 200
    b.set_insert_point(fn, ok_blk);
    VOK(b.emit_ret_status(200));

    // Codegen + JIT
    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto* addr = engine.lookup("handler_path_guard");
    REQUIRE(addr != nullptr);
    auto handler = reinterpret_cast<HandlerFn>(addr);

    // Test with /api path — should return 200
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 200);
    }

    // Test with / path — should return 404
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 404);
    }

    engine.shutdown();
    tc.destroy();
}

TEST(jit, guard_path_regex_match) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("path_regex_guard"), lit("/api"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok_blk = V(b.create_block(fn, lit("ok")));
    auto reject_blk = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto path = V(b.emit_req_path());
    auto matched = V(b.emit_str_regex_match(path, lit("^/api/[a-z]+$")));
    VOK(b.emit_br(matched, ok_blk, reject_blk));

    b.set_insert_point(fn, reject_blk);
    VOK(b.emit_ret_status(404));

    b.set_insert_point(fn, ok_blk);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto* addr = engine.lookup("handler_path_regex_guard");
    REQUIRE(addr != nullptr);
    auto handler = reinterpret_cast<HandlerFn>(addr);

    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 200);
    }

    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiQueryRequest),
                                               sizeof(kGetApiQueryRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 404);
    }

    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 404);
    }

    engine.shutdown();
    tc.destroy();
}

TEST(jit, duplicate_regex_literals_share_one_db_symbol) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("duplicate_regex_guard"), lit("/api"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok_blk = V(b.create_block(fn, lit("ok")));
    auto reject_blk = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto path = V(b.emit_req_path());
    (void)V(b.emit_str_regex_match(path, lit("^/api/[a-z]+$")));
    auto matched = V(b.emit_str_regex_match(path, lit("^/api/[a-z]+$")));
    VOK(b.emit_br(matched, ok_blk, reject_blk));

    b.set_insert_point(fn, reject_blk);
    VOK(b.emit_ret_status(404));

    b.set_insert_point(fn, ok_blk);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    CHECK(engine.regex_slot_count == 1);

    engine.shutdown();
    tc.destroy();
}

TEST(jit, regex_registration_rolls_back_on_failed_compile) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("invalid_regex_guard"), lit("/api"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok_blk = V(b.create_block(fn, lit("ok")));
    auto reject_blk = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto path = V(b.emit_req_path());
    (void)V(b.emit_str_regex_match(path, lit("^/api/[a-z]+$")));
    auto invalid = V(b.emit_str_regex_match(path, lit("[")));
    VOK(b.emit_br(invalid, ok_blk, reject_blk));

    b.set_insert_point(fn, reject_blk);
    VOK(b.emit_ret_status(404));

    b.set_insert_point(fn, ok_blk);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    CHECK(!engine.compile(cg.mod, cg.ctx));
    CHECK(engine.regex_slot_count == 0);

    TestContext tc_valid;
    REQUIRE(tc_valid.init());
    Builder b_valid;
    b_valid.init(&tc_valid.mod);
    auto* fn_valid = V(b_valid.create_function(lit("valid_after_regex_fail"), lit("/api"), 'G'));
    auto entry_valid = V(b_valid.create_block(fn_valid, lit("entry")));
    auto ok_valid = V(b_valid.create_block(fn_valid, lit("ok")));
    auto reject_valid = V(b_valid.create_block(fn_valid, lit("reject")));
    b_valid.set_insert_point(fn_valid, entry_valid);
    auto path_valid = V(b_valid.emit_req_path());
    auto matched_valid = V(b_valid.emit_str_regex_match(path_valid, lit("^/api/[a-z]+$")));
    VOK(b_valid.emit_br(matched_valid, ok_valid, reject_valid));
    b_valid.set_insert_point(fn_valid, reject_valid);
    VOK(b_valid.emit_ret_status(404));
    b_valid.set_insert_point(fn_valid, ok_valid);
    VOK(b_valid.emit_ret_status(200));

    auto cg_valid = codegen(tc_valid.mod);
    REQUIRE(cg_valid.ok);
    REQUIRE(engine.compile(cg_valid.mod, cg_valid.ctx));
    CHECK(engine.regex_slot_count == 1);

    engine.shutdown();
    tc_valid.destroy();
    tc.destroy();
}

// Test: Handler that reads a header.
// RIR equivalent:
//   %auth = req.header "Authorization"
//   %is_nil = opt.is_nil %auth
//   br %is_nil, no_auth, has_auth
//   no_auth: ret.status 401
//   has_auth: ret.status 200
TEST(jit, header_check) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("auth_check"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto no_auth = V(b.create_block(fn, lit("no_auth")));
    auto has_auth = V(b.create_block(fn, lit("has_auth")));

    b.set_insert_point(fn, entry);
    auto auth = V(b.emit_req_header(lit("Authorization")));
    auto is_nil = V(b.emit_opt_is_nil(auth));
    VOK(b.emit_br(is_nil, no_auth, has_auth));

    b.set_insert_point(fn, no_auth);
    VOK(b.emit_ret_status(401));

    b.set_insert_point(fn, has_auth);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto* addr = engine.lookup("handler_auth_check");
    REQUIRE(addr != nullptr);
    auto handler = reinterpret_cast<HandlerFn>(addr);

    // Request without Authorization → 401
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 401);
    }

    // Request with Authorization → 200
    {
        static const char req[] =
            "GET /api HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Authorization: Bearer token123\r\n"
            "\r\n";
        auto r = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(req), sizeof(req) - 1, nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 200);
    }

    engine.shutdown();
    tc.destroy();
}

// Test: Handler with comparison.
// RIR equivalent:
//   %method = req.method
//   %get = const.method 'G'
//   %is_get = cmp.eq %method, %get
//   br %is_get, ok, reject
//   reject: ret.status 405
//   ok: ret.status 200
TEST(jit, method_check) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("method_check"), lit("/"), 0));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto method = V(b.emit_req_method());
    auto get_const = V(b.emit_const_method(static_cast<u8>(0)));  // GET = 0 in HttpMethod enum
    auto is_get = V(b.emit_cmp(Opcode::CmpEq, method, get_const));
    VOK(b.emit_br(is_get, ok, reject));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(405));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto* addr = engine.lookup("handler_method_check");
    REQUIRE(addr != nullptr);
    auto handler = reinterpret_cast<HandlerFn>(addr);

    // GET request → 200
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        // Method enum value: GET=0 matches const_method(0)
        CHECK(r.status_code == 200);
    }

    // POST request → 405
    {
        static const char post_req[] =
            "POST /api HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(post_req),
                                               sizeof(post_req) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 405);
    }

    engine.shutdown();
    tc.destroy();
}

// ── Runtime Helper Tests ───────────────────────────────────────────

TEST(helpers, req_method) {
    // GET
    u8 m = rut_helper_req_method(reinterpret_cast<const u8*>(kGetApiRequest),
                                 sizeof(kGetApiRequest) - 1);
    CHECK(m == 0);  // HttpMethod::GET = 0

    // POST
    static const char post[] = "POST / HTTP/1.1\r\nHost: h\r\n\r\n";
    m = rut_helper_req_method(reinterpret_cast<const u8*>(post), sizeof(post) - 1);
    CHECK(m == 1);  // HttpMethod::POST = 1
}

TEST(helpers, req_flags_keep_alive_and_chunked) {
    static const char chunked[] =
        "POST / HTTP/1.1\r\n"
        "Host: h\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n";
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(chunked), sizeof(chunked) - 1, 0) == 1);
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(chunked), sizeof(chunked) - 1, 1) == 1);
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(chunked), sizeof(chunked) - 1, 2) == 0);
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(chunked), sizeof(chunked) - 1, 3) == 0);
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(chunked), sizeof(chunked) - 1, 4) == 1);

    static const char close_req[] =
        "POST / HTTP/1.1\r\n"
        "Host: h\r\n"
        "Connection: close\r\n"
        "\r\n";
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(close_req), sizeof(close_req) - 1, 0) ==
          0);
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(close_req), sizeof(close_req) - 1, 1) ==
          0);

    static const char zero_len_req[] =
        "POST / HTTP/1.1\r\n"
        "Host: h\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    CHECK(rut_helper_req_flag(
              reinterpret_cast<const u8*>(zero_len_req), sizeof(zero_len_req) - 1, 2) == 1);

    static const char http10_req[] =
        "POST / HTTP/1.0\r\n"
        "Host: h\r\n"
        "\r\n";
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(http10_req), sizeof(http10_req) - 1, 3) ==
          1);
    CHECK(rut_helper_req_flag(reinterpret_cast<const u8*>(http10_req), sizeof(http10_req) - 1, 4) ==
          0);
}

TEST(helpers, req_header_case_insensitive) {
    static const char req[] =
        "GET / HTTP/1.1\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;

    // Exact case
    rut_helper_req_header(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "Content-Type", 12, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 9);  // "text/html"

    // Lowercase lookup
    has = 0;
    ptr = nullptr;
    len = 0;
    rut_helper_req_header(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "content-type", 12, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 9);

    // Missing header
    has = 1;
    rut_helper_req_header(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "X-Missing", 9, &has, &ptr, &len);
    CHECK(has == 0);
}

TEST(helpers, req_param_from_handler_ctx) {
    TestHandlerCtxFrame frame{};
    static const char id_name[] = "id";
    static const char id_value[] = "42";
    static const char book_name[] = "book";
    static const char book_value[] = "rut";
    frame.ctx.route_param_count = 2;
    frame.ctx.route_params[0] = {id_name, 2, id_value, 2};
    frame.ctx.route_params[1] = {book_name, 4, book_value, 3};

    const char* ptr = nullptr;
    u32 len = 0;
    rut_helper_req_param(&frame.ctx, "book", 4, &ptr, &len);
    REQUIRE(ptr != nullptr);
    CHECK_EQ(len, 3u);
    CHECK((Str{ptr, len}.eq(Str{"rut", 3})));

    ptr = reinterpret_cast<const char*>(0x1);
    len = 99;
    rut_helper_req_param(&frame.ctx, "missing", 7, &ptr, &len);
    CHECK(ptr != nullptr);
    CHECK_EQ(len, 0u);
}

TEST(helpers, req_cookie_from_request_bytes) {
    static const char req[] =
        "GET / HTTP/1.1\r\n"
        "Host: h\r\n"
        "Cookie: theme=dark; sid=ok; empty=; spaced=value \t; malformed; lang=en\r\n"
        "Cookie: other=second\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;

    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "sid", 3, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK_EQ(len, 2u);
    CHECK((Str{ptr, len}.eq(Str{"ok", 2})));

    has = 0;
    ptr = nullptr;
    len = 0;
    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "empty", 5, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK_EQ(len, 0u);
    CHECK(ptr != nullptr);

    has = 0;
    ptr = nullptr;
    len = 0;
    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "spaced", 6, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK_EQ(len, 5u);
    CHECK((Str{ptr, len}.eq(Str{"value", 5})));

    has = 0;
    ptr = nullptr;
    len = 0;
    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "other", 5, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK_EQ(len, 6u);
    CHECK((Str{ptr, len}.eq(Str{"second", 6})));

    has = 1;
    ptr = reinterpret_cast<const char*>(0x1);
    len = 99;
    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "missing", 7, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
}

TEST(helpers, req_query_from_request_bytes) {
    static const char req[] =
        "GET /search?q=rut&book=cpp&empty= HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;

    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "q", 1, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 3);
    CHECK((Str{ptr, len}.eq(Str{"rut", 3})));

    has = 0;
    ptr = nullptr;
    len = 0;
    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "empty", 5, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 0u);
    CHECK(ptr != nullptr);

    has = 1;
    ptr = reinterpret_cast<const char*>(0x1);
    len = 99;
    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "missing", 7, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(len == 0u);
}

TEST(helpers, req_query_ignores_fragment_suffix) {
    static const char req[] =
        "GET /search?q=rut&empty=#section HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;

    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "q", 1, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 3u);
    CHECK((Str{ptr, len}.eq(Str{"rut", 3})));

    has = 0;
    ptr = nullptr;
    len = 99;
    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "empty", 5, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 0u);
}

TEST(helpers, req_query_ignores_question_mark_inside_fragment) {
    static const char req[] =
        "GET /search#frag?q=rut HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    u8 has = 1;
    const char* ptr = reinterpret_cast<const char*>(0x1);
    u32 len = 99;

    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "q", 1, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
}

TEST(helpers, req_query_string_from_request_bytes) {
    static const char req[] =
        "GET /search?q=rut&empty=#section HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;

    rut_helper_req_query_string(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, &has, &ptr, &len);
    CHECK(has == 1);
    CHECK(len == 12u);
    CHECK((Str{ptr, len}.eq(Str{"q=rut&empty=", 12})));

    static const char no_query[] = "GET /search#section HTTP/1.1\r\nHost: localhost\r\n\r\n";
    has = 1;
    ptr = reinterpret_cast<const char*>(0x1);
    len = 99;
    rut_helper_req_query_string(
        reinterpret_cast<const u8*>(no_query), sizeof(no_query) - 1, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK(len == 0u);
}

TEST(helpers, req_content_length_from_request_bytes) {
    static const char req[] =
        "POST /upload HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 123\r\n"
        "\r\n";
    CHECK_EQ(rut_helper_req_content_length(reinterpret_cast<const u8*>(req), sizeof(req) - 1),
             123u);

    static const char no_len[] = "POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\n";
    CHECK_EQ(rut_helper_req_content_length(reinterpret_cast<const u8*>(no_len), sizeof(no_len) - 1),
             0u);
}

TEST(jit, req_param_guard) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("param_guard"), lit("/users/:id"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto id = V(b.emit_req_param(lit("id")));
    auto want = V(b.emit_const_str(lit("42")));
    auto matches = V(b.emit_cmp(Opcode::CmpEq, id, want));
    VOK(b.emit_br(matches, ok, reject));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(404));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_param_guard"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    static const char id_name[] = "id";
    static const char id_value[] = "42";
    frame.ctx.route_param_count = 1;
    frame.ctx.route_params[0] = {id_name, 2, id_value, 2};

    auto hit = HandlerResult::unpack(handler(nullptr,
                                             &frame.ctx,
                                             reinterpret_cast<const u8*>(kGetApiRequest),
                                             sizeof(kGetApiRequest) - 1,
                                             nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 200u);

    frame.ctx.route_params[0].value = "41";
    auto miss = HandlerResult::unpack(handler(nullptr,
                                              &frame.ctx,
                                              reinterpret_cast<const u8*>(kGetApiRequest),
                                              sizeof(kGetApiRequest) - 1,
                                              nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 404u);

    engine.shutdown();
    tc.destroy();
}

TEST(jit, req_content_length_guard) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("content_length_guard"), lit("/upload"), 'P'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto len = V(b.emit_req_content_length());
    auto want = V(b.emit_const_bytesize(123));
    auto matches = V(b.emit_cmp(Opcode::CmpEq, len, want));
    VOK(b.emit_br(matches, ok, reject));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(413));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_content_length_guard"));
    REQUIRE(handler != nullptr);

    static const char hit_req[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 123\r\n\r\n";
    auto hit = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(hit_req), sizeof(hit_req) - 1, nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 200u);

    static const char miss_req[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 124\r\n\r\n";
    auto miss = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(miss_req), sizeof(miss_req) - 1, nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 413u);

    engine.shutdown();
    tc.destroy();
}

TEST(jit, req_query_guard) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("query_guard"), lit("/search"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));
    auto missing = V(b.create_block(fn, lit("missing")));
    auto found = V(b.create_block(fn, lit("found")));

    b.set_insert_point(fn, entry);
    auto q = V(b.emit_req_query(lit("q")));
    auto is_nil = V(b.emit_opt_is_nil(q));
    VOK(b.emit_br(is_nil, missing, found));

    b.set_insert_point(fn, missing);
    VOK(b.emit_ret_status(404));

    // Get the inner Str type for unwrap
    auto str_ty = V(b.make_type(TypeKind::Str));

    b.set_insert_point(fn, found);
    auto val = V(b.emit_opt_unwrap(q, str_ty));
    auto want = V(b.emit_const_str(lit("rut")));
    auto matches = V(b.emit_cmp(Opcode::CmpEq, val, want));
    VOK(b.emit_br(matches, ok, reject));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(404));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_query_guard"));
    REQUIRE(handler != nullptr);

    static const char hit_req[] =
        "GET /search?q=rut HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    auto hit = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(hit_req), sizeof(hit_req) - 1, nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 200u);

    static const char miss_req[] =
        "GET /search?q=cpp HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    auto miss = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(miss_req), sizeof(miss_req) - 1, nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 404u);

    engine.shutdown();
    tc.destroy();
}

TEST(helpers, req_remote_addr) {
    Connection conn;
    conn.reset();
    conn.peer_addr = 0x0A000001;  // 10.0.0.1 in network order
    u32 addr = rut_helper_req_remote_addr(&conn);
    CHECK(addr == 0x0A000001);
}

TEST(helpers, str_has_prefix_edge_cases) {
    // Empty prefix matches everything
    CHECK(rut_helper_str_has_prefix("hello", 5, "", 0) == 1);

    // Equal strings
    CHECK(rut_helper_str_has_prefix("/api", 4, "/api", 4) == 1);

    // Prefix longer than string
    CHECK(rut_helper_str_has_prefix("/a", 2, "/api", 4) == 0);

    // Empty string with non-empty prefix
    CHECK(rut_helper_str_has_prefix("", 0, "/", 1) == 0);

    // Both empty
    CHECK(rut_helper_str_has_prefix("", 0, "", 0) == 1);
}

TEST(helpers, str_regex_match) {
    if (!rut_helper_regex_backend_available()) SKIP("vectorscan backend not available");
    void* db = rut_helper_regex_compile("^/v[0-9]+/users$", 16);
    REQUIRE(db != nullptr);
    CHECK(rut_helper_str_regex_match("/v12/users", 10, db) == 1);
    CHECK(rut_helper_str_regex_match("/v12/users/extra", 16, db) == 0);
    rut_helper_regex_free(db);

    db = rut_helper_regex_compile("users", 5);
    REQUIRE(db != nullptr);
    CHECK(rut_helper_str_regex_match("users", 5, db) == 1);
    CHECK(rut_helper_str_regex_match("/api/users", 10, db) == 0);
    rut_helper_regex_free(db);

    db = rut_helper_regex_compile("a.{0,10}z", 9);
    REQUIRE(db != nullptr);
    CHECK(rut_helper_str_regex_match("abcdez", 6, db) == 1);
    rut_helper_regex_free(db);

    db = rut_helper_regex_compile("^/api/users$", 12);
    REQUIRE(db != nullptr);
    CHECK(rut_helper_str_regex_match("/api/users", 10, db) == 1);
    CHECK(rut_helper_str_regex_match("/api/users?x=1", 14, db) == 0);
    rut_helper_regex_free(db);

    CHECK(rut_helper_regex_compile("[", 1) == nullptr);
}

TEST(helpers, str_regex_scratch_cache_grows_and_reuses_entries) {
    if (!rut_helper_regex_backend_available()) SKIP("vectorscan backend not available");

    static constexpr u32 kRegexCount = 40;
    char patterns[kRegexCount][16]{};
    u32 lens[kRegexCount]{};
    void* dbs[kRegexCount]{};

    for (u32 i = 0; i < kRegexCount; i++) {
        int n = snprintf(patterns[i], sizeof(patterns[i]), "^/r%u$", i);
        REQUIRE(n > 0);
        lens[i] = static_cast<u32>(n);
        dbs[i] = rut_helper_regex_compile(patterns[i], lens[i]);
        REQUIRE(dbs[i] != nullptr);
    }

    u32 before_count = rut_helper_regex_scratch_cache_entry_count_for_test();
    for (u32 i = 0; i < kRegexCount; i++) {
        char value[16]{};
        int n = snprintf(value, sizeof(value), "/r%u", i);
        REQUIRE(n > 0);
        CHECK(rut_helper_str_regex_match(value, static_cast<u32>(n), dbs[i]) == 1);
    }
    u32 warmed_count = rut_helper_regex_scratch_cache_entry_count_for_test();
    CHECK(warmed_count == before_count + kRegexCount);

    for (u32 i = 0; i < kRegexCount; i++) {
        char value[16]{};
        int n = snprintf(value, sizeof(value), "/r%u", i);
        REQUIRE(n > 0);
        CHECK(rut_helper_str_regex_match(value, static_cast<u32>(n), dbs[i]) == 1);
    }
    CHECK(rut_helper_regex_scratch_cache_entry_count_for_test() == warmed_count);

    for (u32 i = 0; i < kRegexCount; i++) {
        rut_helper_regex_free(dbs[i]);
    }
    CHECK(rut_helper_regex_scratch_cache_entry_count_for_test() == before_count);
}

struct RegexScratchPruneThreadState {
    void* db = nullptr;
    pthread_barrier_t* warmed = nullptr;
    pthread_barrier_t* pruned = nullptr;
    u32 warm_count = 0;
    u32 final_count = 0;
    u8 matched = 0;
};

static void* regex_scratch_prune_thread(void* arg) {
    auto* state = static_cast<RegexScratchPruneThreadState*>(arg);
    state->matched = rut_helper_str_regex_match("/worker", 7, state->db);
    state->warm_count = rut_helper_regex_scratch_cache_entry_count_for_test();
    pthread_barrier_wait(state->warmed);
    pthread_barrier_wait(state->pruned);
    state->final_count = rut_helper_regex_scratch_cache_entry_count_for_test();
    return nullptr;
}

TEST(helpers, str_regex_free_prunes_other_thread_scratch_cache) {
    if (!rut_helper_regex_backend_available()) SKIP("vectorscan backend not available");

    void* db = rut_helper_regex_compile("^/worker$", 9);
    REQUIRE(db != nullptr);

    pthread_barrier_t warmed;
    pthread_barrier_t pruned;
    REQUIRE(pthread_barrier_init(&warmed, nullptr, 2) == 0);
    REQUIRE(pthread_barrier_init(&pruned, nullptr, 2) == 0);

    RegexScratchPruneThreadState state{};
    state.db = db;
    state.warmed = &warmed;
    state.pruned = &pruned;

    pthread_t thread{};
    REQUIRE(pthread_create(&thread, nullptr, regex_scratch_prune_thread, &state) == 0);
    pthread_barrier_wait(&warmed);

    CHECK(state.matched == 1);
    CHECK(state.warm_count == 1);
    rut_helper_regex_free(db);
    pthread_barrier_wait(&pruned);

    REQUIRE(pthread_join(thread, nullptr) == 0);
    CHECK(state.final_count == 0);

    pthread_barrier_destroy(&pruned);
    pthread_barrier_destroy(&warmed);
}

TEST(helpers, str_trim_prefix) {
    const char* out = nullptr;
    u32 len = 0;

    // Prefix present
    rut_helper_str_trim_prefix("/api/users", 10, "/api", 4, &out, &len);
    CHECK(len == 6);  // "/users"
    CHECK(out[0] == '/');
    CHECK(out[1] == 'u');

    // Prefix not present
    rut_helper_str_trim_prefix("/other", 6, "/api", 4, &out, &len);
    CHECK(len == 6);  // unchanged
    CHECK(out[0] == '/');
    CHECK(out[1] == 'o');

    // Trim entire string
    rut_helper_str_trim_prefix("/api", 4, "/api", 4, &out, &len);
    CHECK(len == 0);
}

// ── HandlerResult pack/unpack Tests ───────────────────────────────

TEST(result, pack_unpack_status) {
    auto r = HandlerResult::make_status(404);
    u64 packed = r.pack();
    auto r2 = HandlerResult::unpack(packed);
    CHECK(r2.action == HandlerAction::ReturnStatus);
    CHECK(r2.status_code == 404);
    CHECK(r2.upstream_id == 0);
    CHECK(r2.next_state == 0);
}

TEST(result, pack_unpack_forward) {
    auto r = HandlerResult::make_forward(7);
    u64 packed = r.pack();
    auto r2 = HandlerResult::unpack(packed);
    CHECK(r2.action == HandlerAction::Forward);
    CHECK(r2.upstream_id == 7);
    CHECK(r2.status_code == 0);
}

TEST(result, pack_unpack_yield) {
    auto r = HandlerResult::make_yield(3, YieldKind::Forward);
    u64 packed = r.pack();
    auto r2 = HandlerResult::unpack(packed);
    CHECK(r2.action == HandlerAction::Yield);
    CHECK(r2.next_state == 3);
    CHECK(r2.yield_kind == YieldKind::Forward);
}

TEST(result, pack_matches_codegen_layout) {
    // Verify pack() produces the same bit layout as the codegen's i64.
    // Codegen for RetStatus(200): action(0) | (200 << 8)
    u64 codegen_200 = 0 | (static_cast<u64>(200) << 8);
    auto r = HandlerResult::unpack(codegen_200);
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // And the other direction
    auto r2 = HandlerResult::make_status(200);
    CHECK(r2.pack() == codegen_200);
}

// ── Codegen: Unconditional Jump ───────────────────────────────────

// handler:
//   entry: jmp ok
//   ok: ret.status 200
TEST(jit, unconditional_jmp) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("jmp_test"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));

    b.set_insert_point(fn, entry);
    VOK(b.emit_jmp(ok));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_jmp_test"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: ConstBool + comparison operators ─────────────────────

// handler:
//   %t = const.bool true
//   %f = const.bool false
//   %eq = cmp.eq %t, %f  → false
//   br %eq, bad, good
//   bad: ret.status 500
//   good: ret.status 200
TEST(jit, const_bool_and_cmp_ne) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("bool_test"), lit("/"), 0));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto good = V(b.create_block(fn, lit("good")));
    auto bad = V(b.create_block(fn, lit("bad")));

    b.set_insert_point(fn, entry);
    auto t = V(b.emit_const_bool(true));
    auto f = V(b.emit_const_bool(false));
    auto eq = V(b.emit_cmp(Opcode::CmpEq, t, f));
    VOK(b.emit_br(eq, bad, good));

    b.set_insert_point(fn, bad);
    VOK(b.emit_ret_status(500));

    b.set_insert_point(fn, good);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_bool_test"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);  // true != false → good path

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: ConstI32 + CmpLt ─────────────────────────────────────

// Simulates: if (42 < 100) return 200 else return 500
TEST(jit, const_i32_cmp_lt) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("i32_lt"), lit("/"), 0));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto yes = V(b.create_block(fn, lit("yes")));
    auto no = V(b.create_block(fn, lit("no")));

    b.set_insert_point(fn, entry);
    auto a = V(b.emit_const_i32(42));
    auto bb_val = V(b.emit_const_i32(100));
    auto lt = V(b.emit_cmp(Opcode::CmpLt, a, bb_val));
    VOK(b.emit_br(lt, yes, no));

    b.set_insert_point(fn, yes);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, no);
    VOK(b.emit_ret_status(500));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_i32_lt"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);  // 42 < 100 → yes

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: Unsigned comparison (ByteSize) ───────────────────────

// Verifies that CmpLt on unsigned types uses unsigned predicates.
// ByteSize is i64 with unsigned semantics. A large ByteSize value
// has the high bit set; signed comparison would treat it as negative.
//
//   %a = const.bytesize 0x8000000000000000  (2^63, large positive unsigned)
//   %b = const.bytesize 1
//   %lt = cmp.lt %a, %b   → unsigned: false (2^63 > 1)
//                          → WRONG if signed: true (-2^63 < 1)
//   br %lt, wrong, correct
//   wrong: ret.status 500
//   correct: ret.status 200
TEST(jit, unsigned_cmp_lt) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("ucmp_lt"), lit("/"), 0));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto wrong = V(b.create_block(fn, lit("wrong")));
    auto correct = V(b.create_block(fn, lit("correct")));

    b.set_insert_point(fn, entry);
    // 0x8000000000000000 = 2^63 — high bit set, positive as unsigned
    auto a = V(b.emit_const_bytesize(static_cast<i64>(0x8000000000000000ULL)));
    auto bb_val = V(b.emit_const_bytesize(1));
    auto lt = V(b.emit_cmp(Opcode::CmpLt, a, bb_val));
    VOK(b.emit_br(lt, wrong, correct));

    b.set_insert_point(fn, wrong);
    VOK(b.emit_ret_status(500));

    b.set_insert_point(fn, correct);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_ucmp_lt"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);  // 2^63 is NOT < 1 (unsigned)

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: OptUnwrap ────────────────────────────────────────────

// handler:
//   %hdr = req.header "Host"
//   %nil = opt.is_nil %hdr
//   br %nil, missing, found
//   missing: ret.status 400
//   found:
//     %val = opt.unwrap %hdr
//     %prefix = const.str "localhost"
//     %match = str.has_prefix %val, %prefix
//     br %match, ok, mismatch
//   ok: ret.status 200
//   mismatch: ret.status 421
TEST(jit, opt_unwrap_and_use) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("unwrap_test"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto missing = V(b.create_block(fn, lit("missing")));
    auto found = V(b.create_block(fn, lit("found")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto mismatch = V(b.create_block(fn, lit("mismatch")));

    b.set_insert_point(fn, entry);
    auto hdr = V(b.emit_req_header(lit("Host")));
    auto nil = V(b.emit_opt_is_nil(hdr));
    VOK(b.emit_br(nil, missing, found));

    b.set_insert_point(fn, missing);
    VOK(b.emit_ret_status(400));

    // Get the inner Str type for unwrap
    auto str_ty = V(b.make_type(TypeKind::Str));

    b.set_insert_point(fn, found);
    auto val = V(b.emit_opt_unwrap(hdr, str_ty));
    auto prefix = V(b.emit_const_str(lit("localhost")));
    auto match = V(b.emit_str_has_prefix(val, prefix));
    VOK(b.emit_br(match, ok, mismatch));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, mismatch);
    VOK(b.emit_ret_status(421));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_unwrap_test"));
    REQUIRE(handler != nullptr);

    // Request with Host: localhost → 200
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 200);
    }

    // Request with Host: example.com → 421
    {
        static const char req[] =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";
        auto r = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(req), sizeof(req) - 1, nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 421);
    }

    engine.shutdown();
    tc.destroy();
}

// handler:
//   %some = opt.wrap 7
//   %nil = opt.is_nil %some
//   %val = opt.unwrap %some
//   %fb = const.i32 200
//   %sel = select %nil, %fb, %val
//   %want = const.i32 7
//   %ok = cmp.eq %sel, %want
//   br %ok, ok, bad
//   ok: ret.status 207
//   bad: ret.status 500
TEST(jit, optional_i32_select_value_flow) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("opt_i32_select"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto bad = V(b.create_block(fn, lit("bad")));

    auto i32_ty = V(b.make_type(TypeKind::I32));

    b.set_insert_point(fn, entry);
    auto seven = V(b.emit_const_i32(7));
    auto some = V(b.emit_opt_wrap(seven));
    auto is_nil = V(b.emit_opt_is_nil(some));
    auto unwrapped = V(b.emit_opt_unwrap(some, i32_ty));
    auto fallback = V(b.emit_const_i32(200));
    auto selected = V(b.emit_select(is_nil, fallback, unwrapped));
    auto want = V(b.emit_const_i32(7));
    auto eq = V(b.emit_cmp(Opcode::CmpEq, selected, want));
    VOK(b.emit_br(eq, ok, bad));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(207));

    b.set_insert_point(fn, bad);
    VOK(b.emit_ret_status(500));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_opt_i32_select"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 207);

    engine.shutdown();
    tc.destroy();
}

// handler:
//   %none = opt.nil(i32)
//   %nil = opt.is_nil %none
//   %val = opt.unwrap %none
//   %fb = const.i32 200
//   %sel = select %nil, %fb, %val
//   %want = const.i32 200
//   %ok = cmp.eq %sel, %want
//   br %ok, ok, bad
//   ok: ret.status 200
//   bad: ret.status 500
TEST(jit, optional_i32_select_fallback_from_nil) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("opt_i32_nil_select"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto bad = V(b.create_block(fn, lit("bad")));

    auto i32_ty = V(b.make_type(TypeKind::I32));

    b.set_insert_point(fn, entry);
    auto none = V(b.emit_opt_nil(i32_ty));
    auto is_nil = V(b.emit_opt_is_nil(none));
    auto unwrapped = V(b.emit_opt_unwrap(none, i32_ty));
    auto fallback = V(b.emit_const_i32(200));
    auto selected = V(b.emit_select(is_nil, fallback, unwrapped));
    auto want = V(b.emit_const_i32(200));
    auto eq = V(b.emit_cmp(Opcode::CmpEq, selected, want));
    VOK(b.emit_br(eq, ok, bad));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, bad);
    VOK(b.emit_ret_status(500));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_opt_i32_nil_select"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// handler:
//   %v = opt.wrap 7
//   %nil = opt.is_nil %v
//   %false = const.bool false
//   %ok = cmp.eq %nil, %false
//   br %ok, pass, fail
//   pass: ret.status 200
//   fail: ret.status 401
TEST(jit, optional_i32_no_error_guard_shape) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("opt_i32_guard"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto pass = V(b.create_block(fn, lit("pass")));
    auto fail = V(b.create_block(fn, lit("fail")));

    b.set_insert_point(fn, entry);
    auto seven = V(b.emit_const_i32(7));
    auto wrapped = V(b.emit_opt_wrap(seven));
    auto is_nil = V(b.emit_opt_is_nil(wrapped));
    auto false_v = V(b.emit_const_bool(false));
    auto no_error = V(b.emit_cmp(Opcode::CmpEq, is_nil, false_v));
    VOK(b.emit_br(no_error, pass, fail));

    b.set_insert_point(fn, pass);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, fail);
    VOK(b.emit_ret_status(401));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_opt_i32_guard"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// handler:
//   %prefix = const.str "api"
//   %some = opt.wrap %prefix
//   %nil = opt.is_nil %some
//   %fb = const.str "fallback"
//   %val = opt.unwrap %some
//   %sel = select %nil, %fb, %val
//   %want = const.str "api"
//   %ok = str.has_prefix %sel, %want
//   br %ok, ok, bad
//   ok: ret.status 200
//   bad: ret.status 500
TEST(jit, optional_str_select_value_flow) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("opt_str_select"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto bad = V(b.create_block(fn, lit("bad")));

    auto str_ty = V(b.make_type(TypeKind::Str));

    b.set_insert_point(fn, entry);
    auto prefix = V(b.emit_const_str(lit("api")));
    auto some = V(b.emit_opt_wrap(prefix));
    auto is_nil = V(b.emit_opt_is_nil(some));
    auto fallback = V(b.emit_const_str(lit("fallback")));
    auto unwrapped = V(b.emit_opt_unwrap(some, str_ty));
    auto selected = V(b.emit_select(is_nil, fallback, unwrapped));
    auto want = V(b.emit_const_str(lit("api")));
    auto has_prefix = V(b.emit_str_has_prefix(selected, want));
    VOK(b.emit_br(has_prefix, ok, bad));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, bad);
    VOK(b.emit_ret_status(500));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_opt_str_select"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// handler:
//   %inner_none = opt.nil(i32)
//   %outer_some = opt.wrap %inner_none
//   %is_error = opt.is_nil %outer_some
//   %inner = opt.unwrap %outer_some
//   %is_nil = opt.is_nil %inner
//   %t = const.bool true
//   %missing = select %is_error, %t, %is_nil
//   %val = opt.unwrap %inner
//   %fb = const.i32 200
//   %sel = select %missing, %fb, %val
//   ...
TEST(jit, optional_optional_i32_select_value_flow) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("opt_opt_i32_select"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto bad = V(b.create_block(fn, lit("bad")));

    auto i32_ty = V(b.make_type(TypeKind::I32));
    auto opt_i32_ty = V(b.make_type(TypeKind::Optional, i32_ty));
    b.set_insert_point(fn, entry);
    auto inner_none = V(b.emit_opt_nil(i32_ty));
    auto outer_some = V(b.emit_opt_wrap(inner_none));
    auto is_error = V(b.emit_opt_is_nil(outer_some));
    auto inner = V(b.emit_opt_unwrap(outer_some, opt_i32_ty));
    auto is_nil = V(b.emit_opt_is_nil(inner));
    auto t = V(b.emit_const_bool(true));
    auto missing = V(b.emit_select(is_error, t, is_nil));
    auto val = V(b.emit_opt_unwrap(inner, i32_ty));
    auto fallback = V(b.emit_const_i32(200));
    auto selected = V(b.emit_select(missing, fallback, val));
    auto want = V(b.emit_const_i32(200));
    auto eq = V(b.emit_cmp(Opcode::CmpEq, selected, want));
    VOK(b.emit_br(eq, ok, bad));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, bad);
    VOK(b.emit_ret_status(500));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_opt_opt_i32_select"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// handler:
//   %inner_none = opt.nil(i32)
//   %outer_some = opt.wrap %inner_none
//   %is_error = opt.is_nil %outer_some
//   %false = const.bool false
//   %ok = cmp.eq %is_error, %false
//   br %ok, pass, fail
TEST(jit, optional_optional_i32_no_error_guard_shape) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("opt_opt_i32_guard"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto pass = V(b.create_block(fn, lit("pass")));
    auto fail = V(b.create_block(fn, lit("fail")));

    auto i32_ty = V(b.make_type(TypeKind::I32));

    b.set_insert_point(fn, entry);
    auto inner_none = V(b.emit_opt_nil(i32_ty));
    auto outer_some = V(b.emit_opt_wrap(inner_none));
    auto is_error = V(b.emit_opt_is_nil(outer_some));
    auto false_v = V(b.emit_const_bool(false));
    auto no_error = V(b.emit_cmp(Opcode::CmpEq, is_error, false_v));
    VOK(b.emit_br(no_error, pass, fail));

    b.set_insert_point(fn, pass);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, fail);
    VOK(b.emit_ret_status(401));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_opt_opt_i32_guard"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: StrTrimPrefix ────────────────────────────────────────

// handler:
//   %path = req.path
//   %prefix = const.str "/api"
//   %trimmed = str.trim_prefix %path, %prefix
//   %slash = const.str "/users"
//   %match = str.has_prefix %trimmed, %slash
//   br %match, ok, reject
//   ok: ret.status 200
//   reject: ret.status 404
TEST(jit, str_trim_prefix) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("trim_test"), lit("/api"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto path = V(b.emit_req_path());
    auto prefix = V(b.emit_const_str(lit("/api")));
    auto trimmed = V(b.emit_str_trim_prefix(path, prefix));
    auto suffix = V(b.emit_const_str(lit("/users")));
    auto match = V(b.emit_str_has_prefix(trimmed, suffix));
    VOK(b.emit_br(match, ok, reject));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(404));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_trim_test"));
    REQUIRE(handler != nullptr);

    // /api/users → trim "/api" → "/users" → has_prefix "/users" → 200
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 200);
    }

    // / → trim "/api" fails → "/" → has_prefix "/users" → 404
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
        CHECK(r.action == HandlerAction::ReturnStatus);
        CHECK(r.status_code == 404);
    }

    engine.shutdown();
    tc.destroy();
}

// ── Runtime helper: req_remote_addr via Connection ────────────────
// ReqRemoteAddr returns TypeKind::IP which can't be compared with
// ConstI32 (TypeKind::I32) at the RIR level — IP comparisons use
// IpInCidr (Phase 2). Here we test the helper directly from C++
// and verify the codegen emits a valid call.

TEST(jit, req_remote_addr) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    // Minimal handler that calls req.remote_addr then returns 200.
    // This verifies the codegen emits the helper call correctly;
    // we check the addr value via the C++ helper test above.
    auto* fn = V(b.create_function(lit("addr_test"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));

    b.set_insert_point(fn, entry);
    V(b.emit_req_remote_addr());  // exercise codegen, discard result
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_addr_test"));
    REQUIRE(handler != nullptr);

    Connection conn;
    conn.reset();
    conn.peer_addr = 0x0100007F;
    auto r = HandlerResult::unpack(handler(&conn,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: Multiple functions in one module ─────────────────────

TEST(jit, multiple_functions) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    // Function 1: always 200
    {
        auto* fn = V(b.create_function(lit("fn_a"), lit("/a"), 'G'));
        auto entry = V(b.create_block(fn, lit("entry")));
        b.set_insert_point(fn, entry);
        VOK(b.emit_ret_status(200));
    }

    // Function 2: always 404
    {
        auto* fn = V(b.create_function(lit("fn_b"), lit("/b"), 'G'));
        auto entry = V(b.create_block(fn, lit("entry")));
        b.set_insert_point(fn, entry);
        VOK(b.emit_ret_status(404));
    }

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto fn_a = reinterpret_cast<HandlerFn>(engine.lookup("handler_fn_a"));
    auto fn_b = reinterpret_cast<HandlerFn>(engine.lookup("handler_fn_b"));
    REQUIRE(fn_a != nullptr);
    REQUIRE(fn_b != nullptr);

    auto ra = HandlerResult::unpack(fn_a(nullptr,
                                         nullptr,
                                         reinterpret_cast<const u8*>(kGetApiRequest),
                                         sizeof(kGetApiRequest) - 1,
                                         nullptr));
    CHECK(ra.status_code == 200);

    auto rb = HandlerResult::unpack(fn_b(nullptr,
                                         nullptr,
                                         reinterpret_cast<const u8*>(kGetApiRequest),
                                         sizeof(kGetApiRequest) - 1,
                                         nullptr));
    CHECK(rb.status_code == 404);

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: Diamond CFG (if/else join) ───────────────────────────

// handler:
//   entry:
//     %path = req.path
//     %prefix = const.str "/admin"
//     %is_admin = str.has_prefix %path, %prefix
//     br %is_admin, admin, user
//   admin:
//     jmp merge
//   user:
//     jmp merge
//   merge:
//     ret.status 200
//
// Tests: forward Jmp + multiple predecessors on merge block
TEST(jit, diamond_cfg) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("diamond"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto admin = V(b.create_block(fn, lit("admin")));
    auto user = V(b.create_block(fn, lit("user")));
    auto merge = V(b.create_block(fn, lit("merge")));

    b.set_insert_point(fn, entry);
    auto path = V(b.emit_req_path());
    auto prefix = V(b.emit_const_str(lit("/admin")));
    auto is_admin = V(b.emit_str_has_prefix(path, prefix));
    VOK(b.emit_br(is_admin, admin, user));

    b.set_insert_point(fn, admin);
    VOK(b.emit_jmp(merge));

    b.set_insert_point(fn, user);
    VOK(b.emit_jmp(merge));

    b.set_insert_point(fn, merge);
    VOK(b.emit_ret_status(200));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_diamond"));
    REQUIRE(handler != nullptr);

    // Both paths merge to 200
    auto r1 = HandlerResult::unpack(handler(nullptr,
                                            nullptr,
                                            reinterpret_cast<const u8*>(kGetApiRequest),
                                            sizeof(kGetApiRequest) - 1,
                                            nullptr));
    CHECK(r1.status_code == 200);

    static const char admin_req[] = "GET /admin/dashboard HTTP/1.1\r\nHost: h\r\n\r\n";
    auto r2 = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(admin_req), sizeof(admin_req) - 1, nullptr));
    CHECK(r2.status_code == 200);

    engine.shutdown();
    tc.destroy();
}

// ── Codegen: Deep chain (entry → b1 → b2 → b3 → ret) ────────────

TEST(jit, chained_blocks) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("chain"), lit("/"), 0));
    auto b0 = V(b.create_block(fn, lit("b0")));
    auto b1 = V(b.create_block(fn, lit("b1")));
    auto b2 = V(b.create_block(fn, lit("b2")));
    auto b3 = V(b.create_block(fn, lit("b3")));

    b.set_insert_point(fn, b0);
    VOK(b.emit_jmp(b1));

    b.set_insert_point(fn, b1);
    VOK(b.emit_jmp(b2));

    b.set_insert_point(fn, b2);
    VOK(b.emit_jmp(b3));

    b.set_insert_point(fn, b3);
    VOK(b.emit_ret_status(201));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_chain"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 201);

    engine.shutdown();
    tc.destroy();
}

// ── JIT Engine: lookup failure ────────────────────────────────────

TEST(jit, lookup_nonexistent) {
    JitEngine engine;
    REQUIRE(engine.init());

    // No modules compiled — any lookup should return nullptr
    void* addr = engine.lookup("nonexistent_function");
    CHECK(addr == nullptr);

    engine.shutdown();
}

TEST(jit, frontend_custom_error_struct_field_projection) {
    const char* src =
        "struct AuthError { err: Error, token: str, retry: i32 }\n"
        "route GET \"/users\" { let failed = error(AuthError, .timeout, \"timed out\", token: "
        "\"abc\", retry: 3) let retry = failed.retry if retry == 3 { return 200 } else { return "
        "500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_error_struct_tuple_field_projection_pipe) {
    const char* src =
        "struct AuthError { err: Error, pair: (i32, i32) }\n"
        "func second(a: i32, b: i32) -> i32 => b\n"
        "route GET \"/users\" { let failed = error(AuthError, .timeout, \"timed out\", pair: (200, "
        "500)) let code = failed.pair | second(_2, _1) if code == 200 { return 200 } else { return "
        "500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_error_nested_struct_field_projection) {
    const char* src =
        "struct Box { value: i32 }\n"
        "struct AuthError { err: Error, inner: Box }\n"
        "route GET \"/users\" { let failed = error(AuthError, .timeout, \"timed out\", inner: "
        "Box(value: 200)) let code = failed.inner.value if code == 200 { return 200 } else { "
        "return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_plain_struct_constructor_and_field_projection) {
    constexpr auto src =
        "struct Foo { code: i32, msg: str }\n"
        "route GET \"/users\" { let foo = Foo(code: 200, msg: \"ok\") let code = foo.code let msg "
        "= foo.msg if code == 200 { return 200 } else { return 500 } }\n";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_plain_struct_tuple_field_projection_pipe) {
    const char* src =
        "struct Foo { pair: (i32, i32) }\n"
        "func second(a: i32, b: i32) -> i32 => b\n"
        "route GET \"/users\" { let foo = Foo(pair: (200, 500)) let code = foo.pair | second(_2, "
        "_1) if code == 200 { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_nested_struct_field_projection) {
    const char* src =
        "struct Box { value: i32 }\n"
        "struct Outer { inner: Box }\n"
        "route GET \"/users\" { let outer = Outer(inner: Box(value: 200)) let code = "
        "outer.inner.value if code == 200 { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_plain_struct_variant_field_projection_match) {
    const char* src =
        "variant AuthState { timeout, forbidden }\n"
        "struct Foo { state: AuthState }\n"
        "route GET \"/users\" { let foo = Foo(state: AuthState.timeout) match foo.state { case "
        ".timeout: return 200 case _: return 403 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_error_standard_field_projection) {
    const char* src =
        "route GET \"/users\" { let failed = error(.timeout, \"timed out\") let code = failed.code "
        "if code == 0 { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_error_line_field_projection) {
    const char* src =
        "route GET \"/users\" { let failed = error(.timeout, \"timed out\") let line = failed.line "
        "if line == 1 { return 200 } else { return 500 } }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_error_file_and_func_field_projection) {
    const char* src =
        "route GET \"/users\" { let failed = error(.timeout, \"timed out\") let file_name = "
        "failed.file let fn_name = failed.func return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

// ── Codegen: RetForward ─────────────────────────────────────────────

// handler:
//   %upstream = const.i32 3
//   ret.forward %upstream
TEST(jit, ret_forward) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("proxy_test"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));

    b.set_insert_point(fn, entry);
    auto upstream = V(b.emit_const_i32(3));
    VOK(b.emit_ret_forward(upstream));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_proxy_test"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::Forward);
    CHECK(r.upstream_id == 3);

    engine.shutdown();
    tc.destroy();
}

// ── Complex: multi-guard handler ──────────────────────────────────

// Simulates a realistic middleware chain:
//   guard req.method == GET else { return 405 }
//   guard req.path.has_prefix("/api") else { return 404 }
//   guard req.header("Authorization") != nil else { return 401 }
//   return 200
TEST(jit, multi_guard) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);

    auto* fn = V(b.create_function(lit("multi_guard"), lit("/api"), 'G'));
    auto check_method = V(b.create_block(fn, lit("check_method")));
    auto check_path = V(b.create_block(fn, lit("check_path")));
    auto check_auth = V(b.create_block(fn, lit("check_auth")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto err_405 = V(b.create_block(fn, lit("err_405")));
    auto err_404 = V(b.create_block(fn, lit("err_404")));
    auto err_401 = V(b.create_block(fn, lit("err_401")));

    // Guard 1: method == GET
    b.set_insert_point(fn, check_method);
    auto method = V(b.emit_req_method());
    auto get = V(b.emit_const_method(0));
    auto is_get = V(b.emit_cmp(Opcode::CmpEq, method, get));
    VOK(b.emit_br(is_get, check_path, err_405));

    // Guard 2: path.has_prefix("/api")
    b.set_insert_point(fn, check_path);
    auto path = V(b.emit_req_path());
    auto prefix = V(b.emit_const_str(lit("/api")));
    auto has_prefix = V(b.emit_str_has_prefix(path, prefix));
    VOK(b.emit_br(has_prefix, check_auth, err_404));

    // Guard 3: header("Authorization") != nil
    b.set_insert_point(fn, check_auth);
    auto auth = V(b.emit_req_header(lit("Authorization")));
    auto no_auth = V(b.emit_opt_is_nil(auth));
    VOK(b.emit_br(no_auth, err_401, ok));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, err_405);
    VOK(b.emit_ret_status(405));

    b.set_insert_point(fn, err_404);
    VOK(b.emit_ret_status(404));

    b.set_insert_point(fn, err_401);
    VOK(b.emit_ret_status(401));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_multi_guard"));
    REQUIRE(handler != nullptr);

    // All guards pass: GET /api with Authorization → 200
    {
        static const char req[] =
            "GET /api/v1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Authorization: Bearer tok\r\n"
            "\r\n";
        auto r = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(req), sizeof(req) - 1, nullptr));
        CHECK(r.status_code == 200);
    }

    // Wrong method: POST → 405
    {
        static const char req[] =
            "POST /api/v1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Authorization: Bearer tok\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        auto r = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(req), sizeof(req) - 1, nullptr));
        CHECK(r.status_code == 405);
    }

    // Wrong path: GET / → 404
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
        CHECK(r.status_code == 404);
    }

    // Missing auth: GET /api without Authorization → 401
    {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK(r.status_code == 401);
    }

    engine.shutdown();
    tc.destroy();
}

TEST(jit, frontend_function_call_inlines_i32_expression_body) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = id(200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    if (r.status_code != 200) {
        rut::test::out("    status=");
        rut::test::out_int(r.status_code);
        rut::test::out("\n");
    }
    CHECK_EQ(r.status_code, 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_struct_can_reference_generic_variant_with_same_type_arg) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
struct Holder<T> { state: Result<T> }
route GET "/users" {
    let holder = Holder<i32>(state: Result.ok(200))
    match holder.state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_variant_can_reference_generic_struct_with_same_type_arg) {
    const auto src = R"rut(
struct Box<T> { value: T }
variant Wrap<T> { some(Box<T>), none }
route GET "/users" {
    let state = Wrap<i32>.some(Box(value: 200))
    match state {
    case .some(box): {
        if box.value == 200 { return 200 } else { return 500 }
    }
    case .none:
        return 404
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_match_payload_binding_preserves_protocol_constraint) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
i32 impl Hashable { func hash(self: i32) -> i32 => self }
variant Wrap<T> { some(T) }
func run<T: Hashable>(state: Wrap<T>) -> i32 {
    match state {
    case .some(v) => v.hash()
    }
}
route GET "/users" {
    let code = run(Wrap<i32>.some(200))
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_struct_field_projection_preserves_protocol_constraint) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
i32 impl Hashable { func hash(self: i32) -> i32 => self }
struct Holder<T> { state: T }
func run<T: Hashable>(x: Holder<T>) -> i32 => x.state.hash()
route GET "/users" {
    let code = run(Holder<i32>(state: 200))
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_nested_generic_struct_type_refs_are_supported_in_function_signatures) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
struct Holder<T> { state: Result<T> }
func unwrap(x: Holder<i32>) -> Result<i32> => x.state
route GET "/users" {
    let state = unwrap(Holder<i32>(state: Result.ok(200)))
    match state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_imported_function_body_struct_init_projection) {
    const std::string dir = "/tmp/rut_import_function_body_struct_init_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "struct Box { value: i32 }\n";
        out << "func make() -> Box => Box(value: 200)\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let box = make()
    if box.value == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_imported_function_body_variant_case_projection) {
    const std::string dir = "/tmp/rut_import_function_body_variant_case_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Result { ok(i32), err }\n";
        out << "struct Holder { state: Result }\n";
        out << "func make() -> Result => Result.ok(200)\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let holder = proto.Holder(state: make())
    if holder.state == proto.Result.ok(200) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_imported_function_body_ifelse_struct_projection) {
    const std::string dir = "/tmp/rut_import_function_body_ifelse_struct_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "struct Box { value: i32 }\n";
        out << "func make(ok: bool) -> Box {\n";
        out << "    if ok { Box(value: 200) } else { Box(value: 500) }\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let box = make(true)
    if box.value == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_imported_function_body_or) {
    const std::string dir = "/tmp/rut_import_function_body_or_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "func maybe(ok: bool) { if ok { 200 } else { nil } }\n";
        out << "func pick(ok: bool) -> i32 => or(maybe(ok), 500)\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let code = pick(true)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_imported_function_body_match) {
    const std::string dir = "/tmp/rut_import_function_body_match_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "variant Result { ok, err }\n";
        out << "func pick(x: Result) -> i32 {\n";
        out << "    match x {\n";
        out << "        case .ok => 200\n";
        out << "        case .err => 500\n";
        out << "    }\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let code = pick(proto.Result.ok)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_nested_generic_struct_type_ref_preserves_instance_shape_index) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
struct Holder<T> { state: T }
func unwrap(x: Holder<Result<i32>>) -> Result<i32> => x.state
route GET "/users" {
    let state = unwrap(Holder<Result<i32>>(state: Result.ok(200)))
    match state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_explicit_generic_struct_init_nested_type_arg) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
struct Holder<T> { state: T }
route GET "/users" {
    let holder = Holder<Result<i32>>(state: Result<i32>.ok(200))
    match holder.state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_nested_generic_variant_type_refs_are_supported_in_function_signatures) {
    const auto src = R"rut(
struct Box<T> { value: T }
variant Wrap<T> { some(Box<T>), none }
func make() -> Wrap<i32> => Wrap<i32>.some(Box(value: 200))
route GET "/users" {
    let x = make()
    match x {
    case .some(box): {
        if box.value == 200 { return 200 } else { return 500 }
    }
    case .none:
        return 404
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK_EQ(r.status_code, 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_call_inlines_i32_expression_body_without_return_annotation) {
    const auto src = R"(
func id(x: i32) => x
route GET "/users" {
    let code = id(200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_call_inlines_i32_expression_body) {
    const auto src = R"rut(
func id<T>(x: T) -> T => x
route GET "/users" {
    let code = id(200)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_reuses_same_type_parameter_shape) {
    const auto src = R"rut(
func first<T>(x: T, y: T) -> T => x
route GET "/users" {
    let code = first(200, 500)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_explicit_type_arguments) {
    const auto src = R"rut(
func id<T>(x: T) -> T => x
route GET "/users" {
    let code = id<i32>(200)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_supports_nested_generic_param_and_return_shapes) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
struct Holder<T> { state: Result<T> }
func unwrap<T>(x: Holder<T>) -> Result<T> => x.state
route GET "/users" {
    let state = unwrap(Holder(state: Result.ok(200)))
    match state {
    case .ok(v): return 200
    case .err: return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_custom_protocol_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box { value: i32 }
Box impl Hashable {
    func hash(self: Box) -> i32 => self.value
}
route GET "/users" {
    if Box(value: 200).hash() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_receiver_custom_protocol_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box { value: i32 }
Box impl Hashable {
    func hash(self: Box) -> i32 => self.value
}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 200)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_custom_protocol_method_dispatch_with_parameter) {
    const auto src = R"rut(
protocol Hashable { func hash(x: i32) -> i32 }
struct Box { value: i32 }
Box impl Hashable {
    func hash(self: Box, x: i32) -> i32 => x
}
route GET "/users" {
    if Box(value: 200).hash(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_multi_protocol_impl_block) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
protocol Adder { func add(x: i32) -> i32 }
struct Box { value: i32 }
Box impl Hashable, Adder {
    func hash(self: Box) -> i32 => self.value
    func add(self: Box, x: i32) -> i32 => x
}
route GET "/users" {
    if Box(value: 7).hash() == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_struct_field_projection_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box { value: i32 }
Box impl Hashable { func hash(self: Box) -> i32 => self.value }
struct Holder { state: Box }
route GET "/users" {
    let holder = Holder(state: Box(value: 200))
    let code = holder.state.hash()
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_custom_protocol_default_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
struct Box { value: i32 }
Box impl Hashable {}
route GET "/users" {
    if Box(value: 7).hash() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_receiver_custom_protocol_default_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
struct Box { value: i32 }
Box impl Hashable {}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 7)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_custom_protocol_default_method_dispatch_with_parameter) {
    const auto src = R"rut(
protocol Adder { func add(x: i32) -> i32 => x }
struct Box { value: i32 }
Box impl Adder {}
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_receiver_custom_protocol_default_method_dispatch_with_parameter) {
    const auto src = R"rut(
protocol Adder { func add(x: i32) -> i32 => x }
struct Box { value: i32 }
Box impl Adder {}
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" {
    if run(Box(value: 7)) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_receiver_custom_protocol_default_method_supports_tuple_return) {
    const auto src = R"rut(
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Pairable {}
func second(a: i32, b: i32) -> i32 => b
func run<T: Pairable>(x: T) -> i32 => x.pair() | second(_2, _1)
route GET "/users" {
    if run(Box(value: 7)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_receiver_custom_protocol_default_method_tuple_return_supports_ordering) {
    const auto src = R"rut(
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Pairable {}
func run<T: Pairable>(x: T) -> (i32, i32) => x.pair()
route GET "/users" {
    if run(Box(value: 7)) < (200, 600) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_receiver_custom_protocol_default_method_tuple_return_supports_equality) {
    const auto src = R"rut(
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Pairable {}
func run<T: Pairable>(x: T) -> (i32, i32) => x.pair()
route GET "/users" {
    if run(Box(value: 7)) == (200, 500) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_multi_protocol_impl_may_omit_methods_with_default_bodies) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
}
protocol Adder {
    func add(x: i32) -> i32 => x
}
struct Box<T> { value: T }
Box<T> impl Hashable, Adder {
    func hash(self: Box<T>) -> i32 => 7
}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 7 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 11)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_multi_protocol_impl_may_omit_methods_with_block_body_default) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
}
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box<T> { value: T }
Box<T> impl Hashable, Adder {
    func hash(self: Box<T>) -> i32 => 7
}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 7 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 11)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_multi_protocol_impl_may_omit_methods_with_if_body_default) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
}
protocol Adder {
    func add(ok: bool) -> i32 {
        if ok { 3 } else { 0 }
    }
}
struct Box<T> { value: T }
Box<T> impl Hashable, Adder {
    func hash(self: Box<T>) -> i32 => 7
}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 7 { x.add(true) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 11)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_multi_protocol_impl_with_default_bodies) {
    const std::string dir = "/tmp/rut_import_generic_multi_protocol_impl_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 => x\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable, Adder {\n";
        out << "    func hash(self: Box<T>) -> i32 => 7\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 7 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 11)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_multi_protocol_impl_with_block_body_default) {
    const std::string dir = "/tmp/rut_import_generic_multi_protocol_impl_block_body_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable, Adder {\n";
        out << "    func hash(self: Box<T>) -> i32 => 7\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 7 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 11)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_multi_protocol_impl_with_if_body_default) {
    const std::string dir = "/tmp/rut_import_generic_multi_protocol_impl_if_body_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(ok: bool) -> i32 {\n";
        out << "        if ok { 3 } else { 0 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable, Adder {\n";
        out << "    func hash(self: Box<T>) -> i32 => 7\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 7 { x.add(true) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 11)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_impl_may_omit_methods_with_block_body_default) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
}
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box { value: i32 }
Box impl Hashable, Adder {
    func hash(self: Box) -> i32 => self.value
}
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_impl_may_omit_methods_with_if_body_default) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
}
protocol Adder {
    func add(ok: bool) -> i32 {
        if ok { 3 } else { 0 }
    }
}
struct Box { value: i32 }
Box impl Hashable, Adder {
    func hash(self: Box) -> i32 => self.value
}
route GET "/users" {
    if Box(value: 7).add(true) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit,
     frontend_import_relative_file_merges_imported_multi_protocol_impl_with_block_body_default) {
    const std::string dir = "/tmp/rut_import_multi_protocol_impl_block_body_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_merges_imported_multi_protocol_impl_with_if_body_default) {
    const std::string dir = "/tmp/rut_import_multi_protocol_impl_if_body_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(ok: bool) -> i32 {\n";
        out << "        if ok { 3 } else { 0 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).add(true) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_multi_protocol_impl_may_omit_methods_with_default_bodies) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
    func add(x: i32) -> i32 => x
}
protocol Adder {
    func mul(x: i32) -> i32 => x
}
struct Box { value: i32 }
Box impl Hashable, Adder {
    func hash(self: Box) -> i32 => self.value
}
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_merges_imported_multi_protocol_impl_with_default_bodies) {
    const std::string dir = "/tmp/rut_import_multi_protocol_impl_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "    func add(x: i32) -> i32 => x\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func mul(x: i32) -> i32 => x\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_supports_tuple_return) {
    const auto src = R"rut(
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Pairable {}
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = Box(value: 7).pair() | second(_2, _1)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_tuple_return_supports_ordering) {
    const auto src = R"rut(
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Pairable {}
route GET "/users" {
    if Box(value: 7).pair() < (200, 600) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_tuple_return_supports_equality) {
    const auto src = R"rut(
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Pairable {}
route GET "/users" {
    if Box(value: 7).pair() == (200, 500) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_supports_optional_return) {
    const auto src = R"rut(
protocol MaybeCode { func code() -> i32 => nil }
struct Box { value: i32 }
Box impl MaybeCode {}
route GET "/users" {
    let code = or(Box(value: 7).code(), 200)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_custom_protocol_default_method_supports_error_return) {
    const auto src = R"rut(
protocol MaybeCode { func code() -> i32 => error(.timeout) }
struct Box { value: i32 }
Box impl MaybeCode {}
route GET "/users" {
    let code = or(Box(value: 7).code(), 200)
    if code == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_custom_protocol_default_method_supports_block_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code() -> i32 {
        let x = 200
        x
    }
}
struct Box { value: i32 }
Box impl MaybeCode {}
route GET "/users" {
    if Box(value: 7).code() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_receiver_custom_protocol_default_method_supports_block_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code() -> i32 {
        let x = 200
        x
    }
}
struct Box { value: i32 }
Box impl MaybeCode {}
func run<T: MaybeCode>(x: T) -> i32 => x.code()
route GET "/users" {
    if run(Box(value: 7)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_supports_block_body_with_parameter) {
    const auto src = R"rut(
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box { value: i32 }
Box impl Adder {}
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit,
     frontend_generic_receiver_custom_protocol_default_method_supports_block_body_with_parameter) {
    const auto src = R"rut(
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box { value: i32 }
Box impl Adder {}
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" {
    if run(Box(value: 7)) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_supports_if_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code(ok: bool) -> i32 {
        if ok { 200 } else { 500 }
    }
}
struct Box { value: i32 }
Box impl MaybeCode {}
route GET "/users" {
    if Box(value: 7).code(true) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_receiver_custom_protocol_default_method_supports_if_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code(ok: bool) -> i32 {
        if ok { 200 } else { 500 }
    }
}
struct Box { value: i32 }
Box impl MaybeCode {}
func run<T: MaybeCode>(x: T) -> i32 => x.code(true)
route GET "/users" {
    if run(Box(value: 7)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_supports_guard_prefix) {
    const auto src = R"rut(
protocol MaybeCode {
    func code(ok: bool) -> i32 {
        let y = maybefail(ok)
        guard y else { 401 }
        200
    }
}
struct Box { value: i32 }
Box impl MaybeCode {}
func maybefail(ok: bool) -> i32 { if ok { 200 } else { error(.timeout) } }
route GET "/users" {
    if Box(value: 7).code(true) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_custom_protocol_default_method_supports_guard_match_prefix) {
    const auto src = R"rut(
protocol MaybeCode {
    func code(ok: bool) -> i32 {
        let y = maybefail(ok)
        guard match y else { case .timeout => 401 case _ => 500 }
        200
    }
}
struct Box { value: i32 }
Box impl MaybeCode {}
func maybefail(ok: bool) -> i32 { if ok { 200 } else { error(.timeout) } }
route GET "/users" {
    if Box(value: 7).code(false) == 401 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_impl_overrides_protocol_default_method_with_optional_return) {
    const auto src = R"rut(
protocol MaybeCode { func code() -> i32 => nil }
struct Box { value: i32 }
Box impl MaybeCode { func code(self: Box) -> i32 => self.value }
route GET "/users" {
    let code = or(Box(value: 7).code(), 200)
    if code == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit,
     frontend_import_relative_file_impl_overrides_protocol_default_method_with_optional_return) {
    const std::string dir = "/tmp/rut_import_impl_overrides_optional_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code() -> i32 => nil }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl MaybeCode { func code(self: Box) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let code = or(Box(value: 7).code(), 200)
    if code == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_impl_overrides_protocol_default_method_with_error_return) {
    const auto src = R"rut(
protocol MaybeCode { func code() -> i32 => error(.timeout) }
struct Box { value: i32 }
Box impl MaybeCode { func code(self: Box) -> i32 => self.value }
route GET "/users" {
    let code = or(Box(value: 7).code(), 200)
    if code == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_impl_overrides_protocol_default_method_with_block_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code() -> i32 {
        let x = 200
        x
    }
}
struct Box { value: i32 }
Box impl MaybeCode { func code(self: Box) -> i32 => self.value }
route GET "/users" {
    if Box(value: 7).code() == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_impl_overrides_protocol_default_method_with_if_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code(ok: bool) -> i32 {
        if ok { 200 } else { 500 }
    }
}
struct Box { value: i32 }
Box impl MaybeCode { func code(self: Box, ok: bool) -> i32 => self.value }
route GET "/users" {
    if Box(value: 7).code(true) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_impl_overrides_protocol_default_method_with_block_body_and_parameter) {
    const auto src = R"rut(
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box { value: i32 }
Box impl Adder { func add(self: Box, x: i32) -> i32 => self.value }
route GET "/users" {
    if Box(value: 7).add(201) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_impl_overrides_protocol_default_method_with_if_body_and_parameter) {
    const auto src = R"rut(
protocol Adder {
    func add(ok: bool) -> i32 {
        if ok { 3 } else { 0 }
    }
}
struct Box { value: i32 }
Box impl Adder { func add(self: Box, ok: bool) -> i32 => self.value }
route GET "/users" {
    if Box(value: 7).add(true) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_impl_overrides_protocol_default_method_with_error_return) {
    const std::string dir = "/tmp/rut_import_impl_overrides_error_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code() -> i32 => error(.timeout) }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl MaybeCode { func code(self: Box) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let code = or(Box(value: 7).code(), 200)
    if code == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_impl_overrides_protocol_default_method_with_block_body) {
    const std::string dir = "/tmp/rut_import_impl_overrides_block_body_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode {\n";
        out << "    func code() -> i32 {\n";
        out << "        let x = 200\n";
        out << "        x\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl MaybeCode { func code(self: Box) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).code() == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_impl_overrides_protocol_default_method_with_if_body) {
    const std::string dir = "/tmp/rut_import_impl_overrides_if_body_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode {\n";
        out << "    func code(ok: bool) -> i32 {\n";
        out << "        if ok { 200 } else { 500 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl MaybeCode { func code(self: Box, ok: bool) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).code(true) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_impl_overrides_protocol_default_method_with_block_body_and_parameter) {
    const std::string dir =
        "/tmp/rut_import_impl_overrides_block_body_parameter_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Adder { func add(self: Box, x: i32) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).add(201) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_impl_overrides_protocol_default_method_with_if_body_and_parameter) {
    const std::string dir = "/tmp/rut_import_impl_overrides_if_body_parameter_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder {\n";
        out << "    func add(ok: bool) -> i32 {\n";
        out << "        if ok { 3 } else { 0 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Adder { func add(self: Box, ok: bool) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).add(true) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_impl_takes_precedence_over_protocol_default_method) {
    const std::string dir = "/tmp/rut_import_impl_precedence_over_default_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable { func hash(self: Box) -> i32 => self.value }\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).hash() == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_impl_may_omit_protocol_method_with_default_body) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32
    func add(x: i32) -> i32 => x
}
struct Box { value: i32 }
Box impl Hashable {
    func hash(self: Box) -> i32 => self.value
}
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_import_relative_file_impl_may_omit_protocol_method_with_default_body) {
    const std::string dir = "/tmp/rut_import_impl_omit_default_body_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32\n";
        out << "    func add(x: i32) -> i32 => x\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable {\n";
        out << "    func hash(self: Box) -> i32 => self.value\n";
        out << "}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    if Box(value: 7).add(201) == 201 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_impl_overrides_generic_receiver_protocol_default_method) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
struct Box<T> { value: T }
Box<T> impl Hashable { func hash(self: Box<T>) -> i32 => 7 }
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_generic_impl_overrides_generic_receiver_protocol_default_method_with_optional_return) {
    const auto src = R"rut(
protocol MaybeCode { func code() -> i32 => nil }
struct Box<T> { value: T }
Box<T> impl MaybeCode { func code(self: Box<T>) -> i32 => 7 }
func run<T: MaybeCode>(x: T) -> i32 => or(x.code(), 200)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit,
     frontend_generic_impl_overrides_generic_receiver_protocol_default_method_with_error_return) {
    const auto src = R"rut(
protocol MaybeCode { func code() -> i32 => error(.timeout) }
struct Box<T> { value: T }
Box<T> impl MaybeCode { func code(self: Box<T>) -> i32 => 7 }
func run<T: MaybeCode>(x: T) -> i32 => or(x.code(), 200)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit,
     frontend_generic_impl_overrides_generic_receiver_protocol_default_method_with_block_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code() -> i32 {
        let x = 200
        x
    }
}
struct Box<T> { value: T }
Box<T> impl MaybeCode { func code(self: Box<T>) -> i32 => 7 }
func run<T: MaybeCode>(x: T) -> i32 => x.code()
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_generic_impl_overrides_generic_receiver_protocol_default_method_with_if_body) {
    const auto src = R"rut(
protocol MaybeCode {
    func code(ok: bool) -> i32 {
        if ok { 200 } else { 500 }
    }
}
struct Box<T> { value: T }
Box<T> impl MaybeCode { func code(self: Box<T>, ok: bool) -> i32 => 7 }
func run<T: MaybeCode>(x: T) -> i32 => x.code(true)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_generic_impl_overrides_generic_receiver_protocol_default_method_with_block_body_and_parameter) {
    const auto src = R"rut(
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box<T> { value: T }
Box<T> impl Adder { func add(self: Box<T>, x: i32) -> i32 => 7 }
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_generic_impl_overrides_generic_receiver_protocol_default_method_with_if_body_and_parameter) {
    const auto src = R"rut(
protocol Adder {
    func add(ok: bool) -> i32 {
        if ok { 3 } else { 0 }
    }
}
struct Box<T> { value: T }
Box<T> impl Adder { func add(self: Box<T>, ok: bool) -> i32 => 7 }
func run<T: Adder>(x: T) -> i32 => x.add(true)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method_with_optional_return) {
    const std::string dir =
        "/tmp/rut_import_generic_impl_overrides_generic_receiver_optional_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code() -> i32 => nil }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode { func code(self: Box<T>) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => or(x.code(), 200)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method_with_error_return) {
    const std::string dir =
        "/tmp/rut_import_generic_impl_overrides_generic_receiver_error_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode { func code() -> i32 => error(.timeout) }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode { func code(self: Box<T>) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => or(x.code(), 200)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method_with_block_body) {
    const std::string dir =
        "/tmp/rut_import_generic_impl_overrides_generic_receiver_block_body_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode {\n";
        out << "    func code() -> i32 {\n";
        out << "        let x = 200\n";
        out << "        x\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode { func code(self: Box<T>) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => x.code()
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method_with_if_body) {
    const std::string dir =
        "/tmp/rut_import_generic_impl_overrides_generic_receiver_if_body_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol MaybeCode {\n";
        out << "    func code(ok: bool) -> i32 {\n";
        out << "        if ok { 200 } else { 500 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl MaybeCode { func code(self: Box<T>, ok: bool) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: MaybeCode>(x: T) -> i32 => x.code(true)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method_with_block_body_and_parameter) {
    const std::string dir =
        "/tmp/"
        "rut_import_generic_impl_overrides_generic_receiver_block_body_parameter_default_method_"
        "jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Adder { func add(self: Box<T>, x: i32) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Adder>(x: T) -> i32 => x.add(201)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method_with_if_body_and_parameter) {
    const std::string dir =
        "/tmp/"
        "rut_import_generic_impl_overrides_generic_receiver_if_body_parameter_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Adder {\n";
        out << "    func add(ok: bool) -> i32 {\n";
        out << "        if ok { 3 } else { 0 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Adder { func add(self: Box<T>, ok: bool) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Adder>(x: T) -> i32 => x.add(true)
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_generic_impl_overrides_generic_receiver_protocol_default_method) {
    const std::string dir =
        "/tmp/rut_import_generic_impl_overrides_generic_receiver_default_method_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable { func hash(self: Box<T>) -> i32 => 7 }\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 123)) == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_receiver_multi_protocol_default_method_dispatch_is_supported) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Adder { func add(x: i32) -> i32 => x }
struct Box { value: i32 }
Box impl Hashable {}
Box impl Adder {}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 200 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_generic_receiver_multi_protocol_empty_impl_block_default_method_dispatch_is_supported) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Adder { func add(x: i32) -> i32 => x }
struct Box { value: i32 }
Box impl Hashable, Adder {}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 200 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_empty_impl_block_default_method_dispatch_is_supported) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Adder { func add(x: i32) -> i32 => x }
struct Box { value: i32 }
Box impl Hashable, Adder {}
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).add(3) == 3 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_empty_impl_block_default_method_supports_block_body) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32 {
        let x = 200
        x
    }
}
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box { value: i32 }
Box impl Hashable, Adder {}
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).add(3) == 3 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit,
     frontend_generic_receiver_multi_protocol_empty_impl_block_default_method_supports_block_body) {
    const auto src = R"rut(
protocol Hashable {
    func hash() -> i32 {
        let x = 200
        x
    }
}
protocol Adder {
    func add(x: i32) -> i32 {
        let y = x
        y
    }
}
struct Box { value: i32 }
Box impl Hashable, Adder {}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 200 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_empty_impl_block_default_method_supports_if_body) {
    const auto src = R"rut(
protocol Hashable {
    func hash(ok: bool) -> i32 {
        if ok { 200 } else { 500 }
    }
}
protocol Adder {
    func add(ok: bool) -> i32 {
        if ok { 3 } else { 0 }
    }
}
struct Box { value: i32 }
Box impl Hashable, Adder {}
route GET "/users" {
    let h = Box(value: 7).hash(true)
    if h == 200 {
        if Box(value: 7).add(true) == 3 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_empty_impl_block_default_method_supports_tuple_return) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Hashable, Pairable {}
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).pair() == (200, 500) { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit, frontend_multi_protocol_empty_impl_block_default_method_tuple_return_supports_ordering) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Hashable, Pairable {}
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).pair() < (200, 600) { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(jit,
     frontend_generic_receiver_multi_protocol_empty_impl_block_default_method_supports_if_body) {
    const auto src = R"rut(
protocol Hashable {
    func hash(ok: bool) -> i32 {
        if ok { 200 } else { 500 }
    }
}
protocol Adder {
    func add(ok: bool) -> i32 {
        if ok { 3 } else { 0 }
    }
}
struct Box { value: i32 }
Box impl Hashable, Adder {}
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash(true)
    if h == 200 { x.add(true) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_generic_receiver_multi_protocol_empty_impl_block_default_method_supports_tuple_return) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Hashable, Pairable {}
func run<T: Hashable, Pairable>(x: T) -> (i32, i32) {
    let h = x.hash()
    if h == 200 { x.pair() } else { (0, 0) }
}
route GET "/users" {
    if run(Box(value: 7)) == (200, 500) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_generic_receiver_multi_protocol_empty_impl_block_default_method_tuple_return_supports_ordering) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
protocol Pairable { func pair() -> (i32, i32) => (200, 500) }
struct Box { value: i32 }
Box impl Hashable, Pairable {}
func run<T: Hashable, Pairable>(x: T) -> (i32, i32) {
    let h = x.hash()
    if h == 200 { x.pair() } else { (0, 0) }
}
route GET "/users" {
    if run(Box(value: 7)) < (200, 600) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_empty_impl_for_generic_receiver_multi_protocol_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_generic_multi_protocol_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Adder { func add(x: i32) -> i32 => x }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable {}\n";
        out << "Box<T> impl Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 200 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_receiver_multi_protocol_empty_impl_block_for_tuple_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_tuple_default_impl_generic_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Pairable>(x: T) -> (i32, i32) {
    let h = x.hash()
    if h == 200 { x.pair() } else { (0, 0) }
}
route GET "/users" {
    if run(Box(value: 7)) == (200, 500) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_receiver_multi_protocol_empty_impl_block_for_tuple_default_method_ordering) {
    const std::string dir =
        "/tmp/rut_import_tuple_ordering_default_impl_generic_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Pairable>(x: T) -> (i32, i32) {
    let h = x.hash()
    if h == 200 { x.pair() } else { (0, 0) }
}
route GET "/users" {
    if run(Box(value: 7)) < (200, 600) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_receiver_multi_protocol_empty_impl_block_for_if_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_if_body_default_impl_generic_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash(ok: bool) -> i32 {\n";
        out << "        if ok { 200 } else { 500 }\n";
        out << "    }\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(ok: bool) -> i32 {\n";
        out << "        if ok { 3 } else { 0 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash(true)
    if h == 200 { x.add(true) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_multi_protocol_empty_impl_block_for_tuple_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_tuple_default_impl_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).pair() == (200, 500) { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_multi_protocol_empty_impl_block_for_tuple_default_method_ordering) {
    const std::string dir = "/tmp/rut_import_tuple_ordering_default_impl_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Pairable { func pair() -> (i32, i32) => (200, 500) }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Pairable {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).pair() < (200, 600) { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_multi_protocol_empty_impl_block_for_if_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_if_body_default_impl_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash(ok: bool) -> i32 {\n";
        out << "        if ok { 200 } else { 500 }\n";
        out << "    }\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(ok: bool) -> i32 {\n";
        out << "        if ok { 3 } else { 0 }\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let h = Box(value: 7).hash(true)
    if h == 200 {
        if Box(value: 7).add(true) == 3 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_multi_protocol_empty_impl_block_for_block_body_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_block_body_default_impl_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32 {\n";
        out << "        let x = 200\n";
        out << "        x\n";
        out << "    }\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).add(3) == 3 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_receiver_multi_protocol_empty_impl_block_for_block_body_default_method_dispatch) {
    const std::string dir =
        "/tmp/rut_import_block_body_default_impl_generic_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable {\n";
        out << "    func hash() -> i32 {\n";
        out << "        let x = 200\n";
        out << "        x\n";
        out << "    }\n";
        out << "}\n";
        out << "protocol Adder {\n";
        out << "    func add(x: i32) -> i32 {\n";
        out << "        let y = x\n";
        out << "        y\n";
        out << "    }\n";
        out << "}\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 200 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_multi_protocol_empty_impl_block_for_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_default_impl_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Adder { func add(x: i32) -> i32 => x }\n";
        out << "struct Box { value: i32 }\n";
        out << "Box impl Hashable, Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
route GET "/users" {
    let h = Box(value: 7).hash()
    if h == 200 {
        if Box(value: 7).add(3) == 3 { return 200 } else { return 500 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}
TEST(
    jit,
    frontend_import_relative_file_merges_imported_generic_multi_protocol_empty_impl_block_for_default_method_dispatch) {
    const std::string dir = "/tmp/rut_import_generic_default_impl_multi_protocol_block_jit";
    std::filesystem::create_directories(dir);
    {
        std::ofstream out(dir + "/proto.rut", std::ios::binary);
        out << "protocol Hashable { func hash() -> i32 => 200 }\n";
        out << "protocol Adder { func add(x: i32) -> i32 => x }\n";
        out << "struct Box<T> { value: T }\n";
        out << "Box<T> impl Hashable, Adder {}\n";
    }
    const auto src = R"rut(
import "proto.rut"
func run<T: Hashable, Adder>(x: T) -> i32 {
    let h = x.hash()
    if h == 200 { x.add(3) } else { 0 }
}
route GET "/users" {
    if run(Box(value: 7)) == 3 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_impl_takes_precedence_over_protocol_default_method) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
struct Box { value: i32 }
Box impl Hashable { func hash(self: Box) -> i32 => self.value }
route GET "/users" {
    if Box(value: 7).hash() == 7 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_concrete_generic_struct_impl_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box<T> { value: T }
Box<i32> impl Hashable {
    func hash(self: Box<i32>) -> i32 => self.value
}
route GET "/users" {
    if Box(value: 200).hash() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_struct_impl_method_dispatch) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box<T> { value: T }
Box<T> impl Hashable {
    func hash(self: Box<T>) -> i32 => 200
}
route GET "/users" {
    if Box(value: 123).hash() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_receiver_custom_protocol_method_dispatch_with_generic_impl_target) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box<T> { value: T }
Box<T> impl Hashable {
    func hash(self: Box<T>) -> i32 => 200
}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 123)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(
    jit,
    frontend_generic_receiver_custom_protocol_method_dispatch_with_generic_impl_target_tuple_of_struct_arg) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Item { value: i32 }
struct Box<T> { value: T }
Box<T> impl Hashable {
    func hash(self: Box<T>) -> i32 => 200
}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: (Item(value: 7), 9))) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_impl_target_accepts_renamed_placeholder) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Box<T> { value: T }
Box<U> impl Hashable {
    func hash(self: Box<U>) -> i32 => 200
}
route GET "/users" {
    if Box(value: 7).hash() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_impl_target_accepts_multiple_type_params) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 }
struct Pair<T, U> { left: T, right: U }
Pair<A, B> impl Hashable {
    func hash(self: Pair<A, B>) -> i32 => 200
}
route GET "/users" {
    if Pair(left: 7, right: "x").hash() == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_struct_instance_custom_protocol_conformance_is_supported) {
    const auto src = R"rut(
protocol Hashable { func hash() -> i32 => 200 }
struct Box<T> { value: T }
Box<i32> impl Hashable {}
func run<T: Hashable>(x: T) -> i32 => x.hash()
route GET "/users" {
    if run(Box(value: 7)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_custom_protocol_constraint_for_builtin_conformance) {
    const auto src = R"rut(
protocol Hashable {}
i32 impl Hashable {}
func hash<T: Hashable>(x: T) -> i32 => 200
route GET "/users" {
    if hash(200) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_custom_protocol_constraint_for_struct_conformance) {
    const auto src = R"rut(
protocol Hashable {}
struct Box { value: i32 }
Box impl Hashable {}
func hash<T: Hashable>(x: T) -> i32 => 200
route GET "/users" {
    if hash(Box(value: 200)) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_error_constraint_and_standard_field_access) {
    const auto src = R"rut(
struct AuthError { err: Error, retry: i32 }
func codeOf<E: Error>(x: E) -> i32 => x.code
route GET "/users" {
    return 200
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_and_ne_method) {
    const auto src = R"rut(
func diff<T: Eq>(x: T, y: T) -> bool => x.ne(y)
route GET "/users" {
    if diff(200, 300) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_and_le_ge_methods) {
    const auto src = R"rut(
func clampOk<T: Ord>(x: T, lo: T, hi: T) -> bool => x.ge(lo).eq(x.le(hi))
route GET "/users" {
    if clampOk(5, 1, 9) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_error_standard_fields_are_accessible_via_methods) {
    const auto src = R"rut(
route GET "/users" {
    let failed = error(.timeout, "timed out")
    let code = failed.code()
    let line = failed.line()
    if code == line { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_and_eq_method) {
    const auto src = R"rut(
func same<T: Eq>(x: T, y: T) -> bool => x.eq(y)
route GET "/users" {
    if same(200, 200) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_and_lt_method) {
    const auto src = R"rut(
func min<T: Ord>(x: T, y: T) -> T {
    if x.lt(y) { x } else { y }
}
route GET "/users" {
    if min(200, 300) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_and_equality) {
    const auto src = R"rut(
func same<T: Eq>(x: T, y: T) -> bool => x == y
route GET "/users" {
    if same("a", "a") { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_for_tuple) {
    const auto src = R"rut(
func same<T: Eq>(x: T, y: T) -> bool => x == y
route GET "/users" {
    if same((200, 500), (200, 500)) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_for_tuple_of_struct) {
    const auto src = R"rut(
struct Box { value: i32 }
func same<T: Eq>(x: T, y: T) -> bool => x == y
route GET "/users" {
    if same((Box(value: 200), 500), (Box(value: 200), 500)) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_and_lt_for_str) {
    const auto src = R"rut(
func min<T: Ord>(x: T, y: T) -> T {
    if x < y { x } else { y }
}
route GET "/users" {
    if min("alpha", "beta") == "alpha" { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           static_cast<u32>(sizeof(kGetApiRequest) - 1),
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_for_tuple) {
    const auto src = R"rut(
func min<T: Ord>(x: T, y: T) -> T {
    if x < y { x } else { y }
}
route GET "/users" {
    if min((200, 500), (200, 600)) == (200, 500) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           static_cast<u32>(sizeof(kGetApiRequest) - 1),
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_for_tuple_of_struct) {
    const auto src = R"rut(
struct Box { value: i32 }
func min<T: Ord>(x: T, y: T) -> T {
    if x < y { x } else { y }
}
route GET "/users" {
    if min((Box(value: 200), 500), (Box(value: 200), 600)) == (Box(value: 200), 500) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           static_cast<u32>(sizeof(kGetApiRequest) - 1),
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_for_struct) {
    const auto src = R"rut(
struct Box<T> { value: T }
func min<T: Ord>(x: T, y: T) -> T {
    if x < y { x } else { y }
}
route GET "/users" {
    if min(Box(value: 200), Box(value: 500)) == Box(value: 200) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           static_cast<u32>(sizeof(kGetApiRequest) - 1),
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_for_variant) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
func min<T: Ord>(x: T, y: T) -> T {
    if x < y { x } else { y }
}
route GET "/users" {
    if min(Result<i32>.ok(200), Result<i32>.ok(500)) == Result<i32>.ok(200) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           static_cast<u32>(sizeof(kGetApiRequest) - 1),
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_for_struct) {
    const auto src = R"rut(
struct Box<T> { value: T }
func same<T: Eq>(x: T, y: T) -> bool => x == y
route GET "/users" {
    if same(Box(value: 200), Box(value: 200)) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_ord_constraint_and_lt) {
    const auto src = R"rut(
func min<T: Ord>(x: T, y: T) -> T {
    if x < y { x } else { y }
}
route GET "/users" {
    if min(200, 500) == 200 { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_accepts_eq_constraint_for_variant_payload) {
    const auto src = R"rut(
variant Result<T> { ok(T), err }
func same<T: Eq>(x: T, y: T) -> bool => x == y
route GET "/users" {
    if same(Result.ok(200), Result.ok(500)) { return 200 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);

    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);

    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_call_inlines_variant_expression_body) {
    const auto src = R"(
variant AuthState { ok, err }
func success() -> AuthState => AuthState.ok
route GET "/users" {
    match success() {
    case .ok: return 200
    case _: return 500
    }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_call_inlines_variant_expression_body_without_return_annotation) {
    const auto src = R"(
variant AuthState { ok, err }
func success() => AuthState.ok
route GET "/users" {
    match success() {
    case .ok: return 200
    case _: return 500
    }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_supports_explicit_tuple_return_type) {
    const auto src = R"(
func pair() -> (i32, i32) { (200, 500) }
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = pair() | second(_2, _1)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_supports_explicit_tuple_param_type) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
func pick(pair: (i32, i32)) -> i32 => pair | second(_2, _1)
route GET "/users" {
    let code = pick((200, 500))
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_let_supports_explicit_tuple_type) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let pair: (i32, i32) = (200, 500)
    let code = pair | second(_2, _1)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_let_supports_explicit_tuple_type) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
func pick() -> i32 {
    let pair: (i32, i32) = (200, 500)
    pair | second(_2, _1)
}
route GET "/users" {
    let code = pick()
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_call_propagates_optional_value_flow) {
    const auto src = R"(
func maybe() -> i32 => nil
route GET "/users" {
    let code = or(maybe(), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_allows_pure_nil_with_explicit_return_type) {
    const auto src = R"(
func maybe() -> i32 {
    nil
}
route GET "/users" {
    let code = or(maybe(), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_infers_optional_return_from_if_without_annotation) {
    const auto src = R"(
func maybe(ok: bool) {
    if ok { 200 } else { nil }
}
route GET "/users" {
    let code = or(maybe(true), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_call_propagates_error_value_flow) {
    const auto src = R"(
func fail() -> i32 => error(.timeout)
route GET "/users" {
    let code = or(fail(), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_allows_pure_error_with_explicit_return_type) {
    const auto src = R"(
func fail() -> i32 {
    error(.timeout)
}
route GET "/users" {
    let code = or(fail(), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_infers_error_return_from_if_without_annotation) {
    const auto src = R"(
func maybefail(ok: bool) {
    if ok { 200 } else { error(.timeout) }
}
route GET "/users" {
    let code = or(maybefail(true), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_allows_pure_nil_if_with_explicit_return_type) {
    const auto src = R"(
func maybe(ok: bool) -> i32 {
    if ok { nil } else { nil }
}
route GET "/users" {
    let code = or(maybe(true), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_with_let_prefix_inlines) {
    const auto src = R"(
func wrap(x: i32) -> i32 {
    let y = x
    y
}
route GET "/users" {
    let code = wrap(200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_with_guard_prefix_inlines) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { 200 } else { error(.timeout) }
}
func wrap(ok: bool) -> i32 {
    let y = maybefail(ok)
    guard y else { 401 }
    200
}
route GET "/users" {
    let code = wrap(false)
    if code == 401 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_with_guard_let_prefix_binds_value) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { 200 } else { error(.timeout) }
}
func wrap(ok: bool) -> i32 {
    guard let y = maybefail(ok) else { 401 }
    y
}
route GET "/users" {
    let code = wrap(true)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_with_guard_match_prefix_inlines) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { 200 } else { error(.timeout) }
}
func wrap(ok: bool) -> i32 {
    let y = maybefail(ok)
    guard match y else { case .timeout => 401 case _ => 500 }
    200
}
route GET "/users" {
    let code = wrap(false)
    if code == 401 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_with_final_if_inlines) {
    const auto src = R"(
func wrap(x: i32) -> i32 {
    let y = x
    if y == 200 { 200 } else { 500 }
}
route GET "/users" {
    let code = wrap(200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_block_body_with_final_match_inlines) {
    const auto src = R"(
variant Result { ok, err }
func pick(x: Result) -> i32 {
    let y = x
    match y {
        case .ok => 200
        case .err => 500
    }
}
route GET "/users" {
    let code = pick(Result.ok)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_match_arm_block_with_let_inlines) {
    const auto src = R"(
variant Result { ok, err }
func pick(x: Result) -> i32 {
    match x {
        case .ok => { let y = 200 y }
        case .err => { let z = 500 z }
    }
}
route GET "/users" {
    let code = pick(Result.ok)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_infers_optional_return_from_match_without_annotation) {
    const auto src = R"(
variant Result { ok, err }
func pick(x: Result) {
    match x {
        case .ok => 200
        case .err => nil
    }
}
route GET "/users" {
    let code = or(pick(Result.ok), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_infers_error_return_from_match_without_annotation) {
    const auto src = R"(
variant Result { ok, err }
func pick(x: Result) {
    match x {
        case .ok => 200
        case .err => error(.timeout)
    }
}
route GET "/users" {
    let code = or(pick(Result.ok), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_function_allows_pure_error_match_with_explicit_return_type) {
    const auto src = R"(
variant Result { ok, err }
func pick(x: Result) -> i32 {
    match x {
        case .ok => error(.timeout)
        case .err => error(.timeout)
    }
}
route GET "/users" {
    let code = or(pick(Result.ok), 200)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_single_stage) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = 200 | id(_)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_chained_stages) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = 200 | id(_) | id(_)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_placeholder_position) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = 200 | second(500, _)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_placeholder_slot_one_alias) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = 200 | second(500, _1)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_method_stage_receiver_placeholder) {
    const auto src = R"(
route GET "/users" {
    let ok = 200 | _.eq(200)
    if ok { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_method_stage_runtime_optional_lhs_flows_via_or) {
    const auto src = R"(
route GET "/users" {
    let ok = req.header("X-Missing") | _.eq("example.com")
    let safe = or(ok, true)
    if safe { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_method_stage_runtime_optional_lhs_dispatches_protocol_method) {
    const auto src = R"(
protocol MaybeCode { func code() -> i32 }
struct Box { value: i32 }
Box impl MaybeCode {
    func code(self: Box) -> i32 => self.value
}
func maybeBox(ok: bool) -> Box {
    if ok { Box(value: 200) } else { nil }
}
route GET "/users" {
    let code = maybeBox(req.http11) | _.code()
    let safe = or(code, 500)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_tuple_literal_multi_slot_placeholders) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = (200, 500) | second(_2, _1)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_tuple_returning_function_multi_slot_placeholders) {
    const auto src = R"(
func pair() { (200, 500) }
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = pair() | second(_2, _1)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_tuple_of_struct_binding_preserves_struct_slots) {
    const auto src = R"rut(
struct Box { value: i32 }
func id<T>(x: T) -> T => x
func boxCode(b: Box) -> i32 => b.value
route GET "/users" {
    let pair = id((Box(value: 200), 1))
    let code = pair | boxCode(_1)
    if code == 200 { return 200 } else { return 500 }
}
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_generic_function_explicit_tuple_of_struct_type_arg_preserves_struct_slots) {
    const auto src = R"rut(
struct Box { value: i32 }
func id<T>(x: T) -> T => x
func boxCode(b: Box) -> i32 => b.value
route GET "/users" {
    let pair = id<(Box, i32)>((Box(value: 200), 1))
    let code = pair | boxCode(_1)
    if code == 200 { return 200 } else { return 500 }
}
)rut";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetApiRequest),
                                           sizeof(kGetApiRequest) - 1,
                                           nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_tuple_local_alias_multi_slot_placeholders) {
    const auto src = R"(
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let pair = (200, 500)
    let code = pair | second(_2, _1)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_chains_tuple_returning_stage_multi_slot_placeholders) {
    const auto src = R"(
func swap(a: i32, b: i32) { (b, a) }
func second(a: i32, b: i32) -> i32 => b
route GET "/users" {
    let code = (200, 500) | swap(_1, _2) | second(_1, _2)
    if code == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_placeholder_slot_eleven_is_rejected_at_parse) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = 200 | id(_11)
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE_FALSE(ast.has_value());
    CHECK_EQ(static_cast<u8>(ast.error().code), static_cast<u8>(FrontendError::UnsupportedSyntax));
}

TEST(jit, frontend_pipe_runtime_fallible_lhs_slot_two_is_rejected) {
    const auto src = R"(
func id(x: str) -> str => x
route GET "/users" {
    let code = req.header("Host") | id(_2)
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE_FALSE(hir.has_value());
    CHECK_EQ(static_cast<u8>(hir.error().code), static_cast<u8>(FrontendError::UnsupportedSyntax));
}

TEST(jit, frontend_pipe_known_nil_falls_back_via_or) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = nil | id(_)
    let safe = or(code, 200)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_known_error_falls_back_via_or) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let failed = error(.timeout)
    let code = failed | id(_)
    let safe = or(code, 200)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_via_or) {
    const auto src = R"(
func id(x: str) -> str => x
route GET "/users" {
    let host = req.header("Host") | id(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_error_lhs_flows_via_or) {
    const auto src = R"(
func fail() -> i32 => error(.timeout)
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = fail() | id(_)
    let safe = or(code, 200)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_error_lhs_flows_via_or_nil_branch) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { nil } else { error(.timeout) }
}
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = maybefail(true) | id(_)
    let safe = or(code, 200)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_error_lhs_flows_via_or_error_branch) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { nil } else { error(.timeout) }
}
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = maybefail(false) | id(_)
    let safe = or(code, 200)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_into_optional_stage_via_or) {
    const auto src = R"(
func drop(x: str) -> str { nil }
route GET "/users" {
    let host = req.header("Host") | drop(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_into_error_stage_via_or) {
    const auto src = R"(
func failstage(x: str) -> str => error(.timeout)
route GET "/users" {
    let host = req.header("Host") | failstage(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_error_lhs_flows_into_optional_stage_via_or) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func drop(x: str) -> str { nil }
route GET "/users" {
    let host = fail() | drop(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_error_lhs_flows_into_error_stage_via_or) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func failstage(x: str) -> str => error(.timeout)
route GET "/users" {
    let host = fail() | failstage(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_into_optional_error_stage_via_or) {
    const auto src = R"(
func tri(x: str) -> str {
    if x == "host" { nil } else { error(.timeout) }
}
route GET "/users" {
    let host = req.header("Host") | tri(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_runtime_optional_error_stage_direct_via_or) {
    const auto src = R"(
func tri(x: str) -> str {
    if x == "host" { nil } else { error(.timeout) }
}
route GET "/users" {
    let raw = req.header("Host")
    let input = or(raw, "fallback")
    let host = tri(input)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_error_lhs_flows_into_optional_error_stage_via_or) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func tri(x: str) -> str {
    if x == "host" { nil } else { error(.timeout) }
}
route GET "/users" {
    let host = fail() | tri(_)
    let safe = or(host, "missing")
    return 200
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK(r.status_code == 200);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_decorator_pass_runs_handler) {
    const auto src = R"rut(
func passing(_ req: i32) -> i32 => 0
route {
    @passing "*"
    GET "/users" { return 200 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK_EQ(r.status_code, 200);  // handler ran
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_decorator_reject_short_circuits_handler) {
    const auto src = R"rut(
func rejecting(_ req: i32) -> i32 => 401
route {
    @rejecting "*"
    GET "/users" { return 200 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK_EQ(r.status_code, 401);  // decorator's return short-circuited the handler
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_decorator_chain_second_rejects) {
    const auto src = R"rut(
func passing(_ req: i32) -> i32 => 0
func rejecting(_ req: i32) -> i32 => 403
route {
    @passing "*"
    @rejecting "*"
    GET "/users" { return 200 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    auto r = HandlerResult::unpack(handler(nullptr,
                                           nullptr,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK_EQ(r.status_code, 403);  // first decorator passed, second rejected
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_decorator_rejects_before_wait_yield) {
    const auto src = R"rut(
func rejecting(_ req: i32) -> i32 => 401
route {
    @rejecting "*"
    GET "/sleep" { wait(1000) return 200 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto r = HandlerResult::unpack(handler(nullptr,
                                           &ctx,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK_EQ(static_cast<u8>(r.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r.status_code, 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_decorator_passes_then_waits) {
    const auto src = R"rut(
func passing(_ req: i32) -> i32 => 0
route {
    @passing "*"
    GET "/sleep" { wait(1000) return 200 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto r0 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r0.next_state, 1);
    CHECK_EQ(static_cast<u8>(r0.yield_kind), static_cast<u8>(YieldKind::Timer));
    CHECK_EQ(r0.yield_payload_u32(), 1000u);

    ctx.state = r0.next_state;
    auto r1 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r1.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r1.status_code, 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_decorator_passes_then_multiple_waits) {
    const auto src = R"rut(
func passing(_ req: i32) -> i32 => 0
route {
    @passing "*"
    GET "/sleep" { wait(100) wait(200) return 202 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    const u32 expected_ms[] = {100u, 200u};
    for (u16 state = 0; state < 2; state++) {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
        CHECK_EQ(static_cast<u8>(r.action), static_cast<u8>(HandlerAction::Yield));
        CHECK_EQ(r.next_state, static_cast<u16>(state + 1));
        CHECK_EQ(static_cast<u8>(r.yield_kind), static_cast<u8>(YieldKind::Timer));
        CHECK_EQ(r.yield_payload_u32(), expected_ms[state]);
        ctx.state = r.next_state;
    }

    auto done = HandlerResult::unpack(handler(nullptr,
                                              &ctx,
                                              reinterpret_cast<const u8*>(kGetRootRequest),
                                              sizeof(kGetRootRequest) - 1,
                                              nullptr));
    CHECK_EQ(static_cast<u8>(done.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(done.status_code, 202);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_wait_emits_yield_then_terminal_status) {
    // Source: one wait(1000) followed by return 200.
    // Expected: first handler call returns Yield(next_state=1, kind=Timer, payload=1000);
    //           second call with ctx.state = 1 returns ReturnStatus 200.
    const auto src = R"rut(
route GET "/sleep" { wait(1000) return 200 }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    ctx.handler_idx = 0;

    // First call: state=0 → yield
    auto r0 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r0.next_state, 1);
    CHECK_EQ(static_cast<u8>(r0.yield_kind), static_cast<u8>(YieldKind::Timer));
    CHECK_EQ(r0.status_code, 1000);  // payload slot carries ms

    // Second call: state=1 → terminal return 200
    ctx.state = 1;
    auto r1 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r1.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r1.status_code, 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_event_waits_emit_event_yield_kinds) {
    struct Case {
        const char* wait_src;
        YieldKind kind;
        u32 payload;
    };
    const Case cases[] = {
        {"wait()", YieldKind::Any, 0},
        {"wait(any(downstream.recv(), timer(250)))", YieldKind::Any, 250},
        {"wait(downstream.recv())", YieldKind::Recv, 0},
        {"wait(upstream(api).connect())", YieldKind::UpstreamConnect, 1},
        {"wait(upstream(api).recv())", YieldKind::UpstreamRecv, 1},
        {"wait(upstream(api).send(req.body))", YieldKind::UpstreamSend, 1},
    };

    for (const auto& c : cases) {
        char src[240];
        int n = snprintf(src,
                         sizeof(src),
                         "upstream api at \"127.0.0.1:9000\"\nroute GET \"/x\" { %s return 204 }\n",
                         c.wait_src);
        REQUIRE(n > 0);
        REQUIRE(static_cast<size_t>(n) < sizeof(src));

        auto lexed = lex(lit(src));
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap(ast.value());
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);
        FrontendRirModule rir{};
        auto lowered = lower_to_rir(mir.value(), rir);
        REQUIRE(lowered);
        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);
        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);

        TestHandlerCtxFrame frame{};
        HandlerCtx& ctx = frame.ctx;
        ctx.state = 0;
        auto r0 = HandlerResult::unpack(handler(nullptr,
                                                &ctx,
                                                reinterpret_cast<const u8*>(kGetRootRequest),
                                                sizeof(kGetRootRequest) - 1,
                                                nullptr));
        CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
        CHECK_EQ(r0.next_state, 1);
        CHECK_EQ(static_cast<u8>(r0.yield_kind), static_cast<u8>(c.kind));
        CHECK_EQ(r0.yield_payload_u32(), c.payload);

        ctx.state = r0.next_state;
        auto r1 = HandlerResult::unpack(handler(nullptr,
                                                &ctx,
                                                reinterpret_cast<const u8*>(kGetRootRequest),
                                                sizeof(kGetRootRequest) - 1,
                                                nullptr));
        CHECK_EQ(static_cast<u8>(r1.action), static_cast<u8>(HandlerAction::ReturnStatus));
        CHECK_EQ(r1.status_code, 204);

        engine.shutdown();
        rir.destroy();
    }
}

TEST(jit, frontend_route_wait_any_statement_branches_on_winning_event) {
    const auto src = R"rut(
route GET "/x" {
    wait any {
        downstream.recv() => { return 204 }
        timer(250) => { return 408 }
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame recv_frame{};
    HandlerCtx& recv_ctx = recv_frame.ctx;
    auto first = HandlerResult::unpack(handler(nullptr,
                                               &recv_ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
    REQUIRE_EQ(static_cast<u8>(first.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(first.next_state, 1);
    CHECK_EQ(static_cast<u8>(first.yield_kind), static_cast<u8>(YieldKind::Any));
    CHECK_EQ(first.yield_payload_u32(), 250u);

    recv_ctx.state = first.next_state;
    recv_ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
    recv_ctx.resume_event_result = 8;
    auto recv_done = HandlerResult::unpack(handler(nullptr,
                                                   &recv_ctx,
                                                   reinterpret_cast<const u8*>(kGetRootRequest),
                                                   sizeof(kGetRootRequest) - 1,
                                                   nullptr));
    CHECK_EQ(static_cast<u8>(recv_done.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(recv_done.status_code, 204);

    TestHandlerCtxFrame timer_frame{};
    HandlerCtx& timer_ctx = timer_frame.ctx;
    auto timer_first = HandlerResult::unpack(handler(nullptr,
                                                     &timer_ctx,
                                                     reinterpret_cast<const u8*>(kGetRootRequest),
                                                     sizeof(kGetRootRequest) - 1,
                                                     nullptr));
    REQUIRE_EQ(static_cast<u8>(timer_first.action), static_cast<u8>(HandlerAction::Yield));
    timer_ctx.state = timer_first.next_state;
    timer_ctx.resume_event_kind = static_cast<u32>(YieldKind::Timer);
    timer_ctx.resume_event_result = 0;
    auto timer_done = HandlerResult::unpack(handler(nullptr,
                                                    &timer_ctx,
                                                    reinterpret_cast<const u8*>(kGetRootRequest),
                                                    sizeof(kGetRootRequest) - 1,
                                                    nullptr));
    CHECK_EQ(static_cast<u8>(timer_done.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(timer_done.status_code, 408);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, decorated_route_prologue_yields_preserve_event_kind) {
    const auto src = R"rut(
func auth(_ req: i32) -> i32 => 0
route {
    @auth "*"
    GET "/x" { wait(5) wait(downstream.recv()) return 204 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    auto first = HandlerResult::unpack(handler(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
    CHECK_EQ(static_cast<u8>(first.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(first.next_state, 1);
    CHECK_EQ(static_cast<u8>(first.yield_kind), static_cast<u8>(YieldKind::Timer));
    CHECK_EQ(first.yield_payload_u32(), 5u);

    ctx.state = first.next_state;
    auto second = HandlerResult::unpack(handler(nullptr,
                                                &ctx,
                                                reinterpret_cast<const u8*>(kGetRootRequest),
                                                sizeof(kGetRootRequest) - 1,
                                                nullptr));
    CHECK_EQ(static_cast<u8>(second.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(second.next_state, 2);
    CHECK_EQ(static_cast<u8>(second.yield_kind), static_cast<u8>(YieldKind::Recv));
    CHECK_EQ(second.yield_payload_u32(), 0u);

    ctx.state = second.next_state;
    auto done = HandlerResult::unpack(handler(nullptr,
                                              &ctx,
                                              reinterpret_cast<const u8*>(kGetRootRequest),
                                              sizeof(kGetRootRequest) - 1,
                                              nullptr));
    CHECK_EQ(static_cast<u8>(done.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(done.status_code, 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_wait_result_fields_drive_control_flow) {
    const auto src = R"rut(
route GET "/x" {
    let ev = wait(downstream.recv())
    guard ev.ok else { return 500 }
    if ev.eof { return 499 } else { return 204 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto r0 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r0.next_state, 1);
    CHECK_EQ(static_cast<u8>(r0.yield_kind), static_cast<u8>(YieldKind::Recv));

    ctx.state = r0.next_state;
    ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
    ctx.resume_event_result = 12;
    auto r_data = HandlerResult::unpack(handler(nullptr,
                                                &ctx,
                                                reinterpret_cast<const u8*>(kGetRootRequest),
                                                sizeof(kGetRootRequest) - 1,
                                                nullptr));
    CHECK_EQ(static_cast<u8>(r_data.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r_data.status_code, 204);

    ctx.resume_event_result = 0;
    auto r_eof = HandlerResult::unpack(handler(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
    CHECK_EQ(static_cast<u8>(r_eof.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r_eof.status_code, 499);

    ctx.resume_event_kind = static_cast<u32>(YieldKind::UpstreamConnect);
    ctx.resume_event_result = 0;
    auto r_connect_ok = HandlerResult::unpack(handler(nullptr,
                                                      &ctx,
                                                      reinterpret_cast<const u8*>(kGetRootRequest),
                                                      sizeof(kGetRootRequest) - 1,
                                                      nullptr));
    CHECK_EQ(static_cast<u8>(r_connect_ok.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r_connect_ok.status_code, 204);

    ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
    ctx.resume_event_result = -104;
    auto r_err = HandlerResult::unpack(handler(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
    CHECK_EQ(static_cast<u8>(r_err.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r_err.status_code, 500);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_wait_result_store_skips_missing_frame_slots) {
    const auto src = R"rut(
route GET "/x" {
    let ev = wait(downstream.recv())
    if ev.recv { return 204 } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    struct NoSlotCtx {
        HandlerCtx ctx{};
        u64 canary0 = 0x1122334455667788ull;
        u64 canary1 = 0x8877665544332211ull;
    } frame;

    auto first = HandlerResult::unpack(handler(nullptr,
                                               &frame.ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
    REQUIRE_EQ(static_cast<u8>(first.action), static_cast<u8>(HandlerAction::Yield));
    frame.ctx.state = first.next_state;
    frame.ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
    frame.ctx.resume_event_result = 8;
    auto done = HandlerResult::unpack(handler(nullptr,
                                              &frame.ctx,
                                              reinterpret_cast<const u8*>(kGetRootRequest),
                                              sizeof(kGetRootRequest) - 1,
                                              nullptr));
    CHECK_EQ(static_cast<u8>(done.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(done.status_code, 204);
    CHECK_EQ(frame.canary0, 0x1122334455667788ull);
    CHECK_EQ(frame.canary1, 0x8877665544332211ull);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_parameterized_event_waits_emit_payloads) {
    struct Case {
        const char* src;
        YieldKind kind;
        u32 payload;
    };
    const Case cases[] = {
        {"upstream api at \"127.0.0.1:9000\"\n"
         "route GET \"/x\" { wait(upstream(api).connect()) return 204 }\n",
         YieldKind::UpstreamConnect,
         1},
    };
    for (const auto& c : cases) {
        auto lexed = lex(lit(c.src));
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap(ast.value());
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);
        FrontendRirModule rir{};
        auto lowered = lower_to_rir(mir.value(), rir);
        REQUIRE(lowered);
        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);
        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);

        TestHandlerCtxFrame frame{};
        HandlerCtx& ctx = frame.ctx;
        ctx.state = 0;
        auto r0 = HandlerResult::unpack(handler(nullptr,
                                                &ctx,
                                                reinterpret_cast<const u8*>(kGetRootRequest),
                                                sizeof(kGetRootRequest) - 1,
                                                nullptr));
        CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
        CHECK_EQ(static_cast<u8>(r0.yield_kind), static_cast<u8>(c.kind));
        CHECK_EQ(r0.yield_payload_u32(), c.payload);

        engine.shutdown();
        rir.destroy();
    }
}

TEST(jit, frontend_route_wait_event_predicate_fields_drive_control_flow) {
    struct Case {
        const char* wait_src;
        const char* field;
        YieldKind resume_kind;
    };
    const Case cases[] = {
        {"wait(any(downstream.recv(), timer(250)))", "timer", YieldKind::Timer},
        {"wait(downstream.recv())", "recv", YieldKind::Recv},
        {"wait(downstream.recv())", "send", YieldKind::Send},
        {"wait(upstream(api).connect())", "upstream_connect", YieldKind::UpstreamConnect},
        {"wait(upstream(api).recv())", "upstream_recv", YieldKind::UpstreamRecv},
        {"wait(upstream(api).send(req.body))", "upstream_send", YieldKind::UpstreamSend},
    };
    for (const auto& c : cases) {
        char src[320];
        int n = snprintf(src,
                         sizeof(src),
                         "upstream api at \"127.0.0.1:9000\"\n"
                         "route GET \"/x\" { let ev = %s if ev.%s { return 204 } else { return "
                         "500 } }\n",
                         c.wait_src,
                         c.field);
        REQUIRE(n > 0);
        REQUIRE(static_cast<size_t>(n) < sizeof(src));
        auto lexed = lex(lit(src));
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap(ast.value());
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);
        FrontendRirModule rir{};
        auto lowered = lower_to_rir(mir.value(), rir);
        REQUIRE(lowered);
        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);
        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);

        TestHandlerCtxFrame frame{};
        HandlerCtx& ctx = frame.ctx;
        ctx.state = 0;
        auto yielded = HandlerResult::unpack(handler(nullptr,
                                                     &ctx,
                                                     reinterpret_cast<const u8*>(kGetRootRequest),
                                                     sizeof(kGetRootRequest) - 1,
                                                     nullptr));
        REQUIRE_EQ(static_cast<u8>(yielded.action), static_cast<u8>(HandlerAction::Yield));
        ctx.state = yielded.next_state;
        ctx.resume_event_kind = static_cast<u32>(c.resume_kind);
        ctx.resume_event_result = 1;
        auto matched = HandlerResult::unpack(handler(nullptr,
                                                     &ctx,
                                                     reinterpret_cast<const u8*>(kGetRootRequest),
                                                     sizeof(kGetRootRequest) - 1,
                                                     nullptr));
        CHECK_EQ(static_cast<u8>(matched.action), static_cast<u8>(HandlerAction::ReturnStatus));
        CHECK_EQ(matched.status_code, 204);

        ctx.resume_event_kind = static_cast<u32>(YieldKind::Timer);
        if (c.resume_kind == YieldKind::Timer)
            ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
        auto missed = HandlerResult::unpack(handler(nullptr,
                                                    &ctx,
                                                    reinterpret_cast<const u8*>(kGetRootRequest),
                                                    sizeof(kGetRootRequest) - 1,
                                                    nullptr));
        CHECK_EQ(static_cast<u8>(missed.action), static_cast<u8>(HandlerAction::ReturnStatus));
        CHECK_EQ(missed.status_code, 500);

        engine.shutdown();
        rir.destroy();
    }
}

TEST(jit, frontend_route_wait_result_fields_survive_later_waits) {
    const auto src = R"rut(
route GET "/x" {
    let first = wait(any(downstream.recv(), timer(250)))
    let second = wait(downstream.recv())
    if first.timer {
        if second.recv { return 204 } else { return 501 }
    } else {
        return 500
    }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto first_yield = HandlerResult::unpack(handler(nullptr,
                                                     &ctx,
                                                     reinterpret_cast<const u8*>(kGetRootRequest),
                                                     sizeof(kGetRootRequest) - 1,
                                                     nullptr));
    REQUIRE_EQ(static_cast<u8>(first_yield.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(static_cast<u8>(first_yield.yield_kind), static_cast<u8>(YieldKind::Any));

    ctx.state = first_yield.next_state;
    ctx.resume_event_kind = static_cast<u32>(YieldKind::Timer);
    ctx.resume_event_result = 0;
    auto second_yield = HandlerResult::unpack(handler(nullptr,
                                                      &ctx,
                                                      reinterpret_cast<const u8*>(kGetRootRequest),
                                                      sizeof(kGetRootRequest) - 1,
                                                      nullptr));
    REQUIRE_EQ(static_cast<u8>(second_yield.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(static_cast<u8>(second_yield.yield_kind), static_cast<u8>(YieldKind::Recv));

    ctx.state = second_yield.next_state;
    ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
    ctx.resume_event_result = 8;
    auto done = HandlerResult::unpack(handler(nullptr,
                                              &ctx,
                                              reinterpret_cast<const u8*>(kGetRootRequest),
                                              sizeof(kGetRootRequest) - 1,
                                              nullptr));
    CHECK_EQ(static_cast<u8>(done.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(done.status_code, 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_multiple_waits_chain_through_states) {
    // Two waits: state 0 yields 500ms, state 1 yields 1000ms, state 2 returns 201.
    const auto src = R"rut(
route GET "/sleep" { wait(500) wait(1000) return 201 }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    ctx.handler_idx = 0;

    // Drive the state machine: expect yield(500) → yield(1000) → status(201).
    const u16 kExpectedMs[] = {500, 1000};
    for (u16 s = 0; s < 2; s++) {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(kGetRootRequest),
                                               sizeof(kGetRootRequest) - 1,
                                               nullptr));
        CHECK_EQ(static_cast<u8>(r.action), static_cast<u8>(HandlerAction::Yield));
        CHECK_EQ(r.next_state, static_cast<u16>(s + 1));
        CHECK_EQ(r.status_code, kExpectedMs[s]);
        ctx.state = r.next_state;
    }
    auto rf = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(rf.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(rf.status_code, 201);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_route_source_ordered_guard_waits) {
    const auto src = R"rut(
route GET "/" {
    guard req.path == "/" else { return 404 }
    wait(50)
    guard req.method == GET else { return 405 }
    wait(downstream.recv())
    return 204
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto r0 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r0.next_state, 1);
    CHECK_EQ(static_cast<u8>(r0.yield_kind), static_cast<u8>(YieldKind::Timer));
    CHECK_EQ(r0.yield_payload_u32(), 50u);

    ctx.state = r0.next_state;
    auto r1 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r1.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r1.next_state, 2);
    CHECK_EQ(static_cast<u8>(r1.yield_kind), static_cast<u8>(YieldKind::Recv));

    ctx.state = r1.next_state;
    ctx.resume_event_kind = static_cast<u32>(YieldKind::Recv);
    ctx.resume_event_result = 3;
    auto r2 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r2.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r2.status_code, 204);

    ctx.state = 0;
    auto r_fail = HandlerResult::unpack(handler(
        nullptr, &ctx, reinterpret_cast<const u8*>("GET /bad HTTP/1.1\r\n\r\n"), 21, nullptr));
    CHECK_EQ(static_cast<u8>(r_fail.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r_fail.status_code, 404);

    engine.shutdown();
    rir.destroy();
}

TEST(jit_dispatch, timer_seconds_rounds_up_from_ms) {
    CHECK_EQ(timer_seconds_from_ms(0), 0);
    CHECK_EQ(timer_seconds_from_ms(1), 1);     // 1ms → 1s
    CHECK_EQ(timer_seconds_from_ms(999), 1);   // 999ms → 1s
    CHECK_EQ(timer_seconds_from_ms(1000), 1);  // 1000ms → 1s (exact)
    CHECK_EQ(timer_seconds_from_ms(1001), 2);  // 1001ms → 2s
    CHECK_EQ(timer_seconds_from_ms(2500), 3);  // 2500ms → 3s
}

TEST(jit_dispatch, wait_handler_yields_then_resumes_to_status) {
    const auto src = R"rut(
route GET "/sleep" { wait(1500) return 200 }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;

    // First call: TimerYield carrying raw 1500 ms payload.
    auto o0 = invoke_jit_handler(handler,
                                 nullptr,
                                 ctx,
                                 reinterpret_cast<const u8*>(kGetRootRequest),
                                 sizeof(kGetRootRequest) - 1,
                                 nullptr);
    CHECK_EQ(static_cast<u8>(o0.kind), static_cast<u8>(JitDispatchOutcome::Kind::TimerYield));
    CHECK_EQ(o0.next_state, 1u);
    CHECK_EQ(o0.timer_ms, 1500u);
    CHECK_EQ(timer_seconds_from_ms(o0.timer_ms), 2u);  // legacy wheel path rounds up

    // Resume: caller sets ctx.state to next_state, invoke again → ReturnStatus.
    ctx.state = o0.next_state;
    auto o1 = invoke_jit_handler(handler,
                                 nullptr,
                                 ctx,
                                 reinterpret_cast<const u8*>(kGetRootRequest),
                                 sizeof(kGetRootRequest) - 1,
                                 nullptr);
    CHECK_EQ(static_cast<u8>(o1.kind), static_cast<u8>(JitDispatchOutcome::Kind::ReturnStatus));
    CHECK_EQ(o1.status_code, 200u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit_dispatch, timer_payload_round_trips_through_u32_packing) {
    // Payload >65535 must survive: status_code + upstream_id slots combine
    // into the 32-bit ms payload. Handler-side: codegen packs; runtime-side:
    // invoke_jit_handler decodes via yield_payload_u32.
    const auto src = R"rut(
route GET "/long" { wait(100000) return 200 }
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto outcome = invoke_jit_handler(handler,
                                      nullptr,
                                      ctx,
                                      reinterpret_cast<const u8*>(kGetRootRequest),
                                      sizeof(kGetRootRequest) - 1,
                                      nullptr);
    CHECK_EQ(static_cast<u8>(outcome.kind), static_cast<u8>(JitDispatchOutcome::Kind::TimerYield));
    CHECK_EQ(outcome.timer_ms, 100000u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit_dispatch, null_handler_returns_error_outcome) {
    HandlerCtx ctx{};
    auto o = invoke_jit_handler(nullptr, nullptr, ctx, nullptr, 0, nullptr);
    CHECK_EQ(static_cast<u8>(o.kind), static_cast<u8>(JitDispatchOutcome::Kind::Error));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
