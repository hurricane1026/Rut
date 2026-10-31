#include "deferred_preflight_fixture.h"
#include "framing_selection_preflight_fixture.h"
#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_builder.h"
#include "rut/jit/art_jit_codegen.h"
#include "rut/jit/codegen.h"
#include "rut/jit/handler_abi.h"
#include "rut/jit/jit_engine.h"
#include "rut/jit/native_helper_symbols.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/json.h"
#include "rut/runtime/rate_limit_key.h"
#include "rut/runtime/uuid.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"
#endif
#include "test.h"
#include <filesystem>
#include <fstream>
#include <memory>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

using namespace rut;
using namespace rut::rir;

TEST(jit, crypto_c_abi_symbol_resolves_in_jit) {
    jit::JitEngine engine;
    REQUIRE(engine.init());
    auto* symbol = engine.lookup("rut_crypto_digest_v1");
    REQUIRE(symbol != nullptr);
    using DigestFn = decltype(&rut_crypto_digest_v1);
    auto digest = reinterpret_cast<DigestFn>(symbol);
    const u8 input[] = {'a', 'b', 'c'};
    u8 output[32]{};
    u32 length = 0;
    CHECK_EQ(digest(RUT_CRYPTO_SHA256_V1,
                    input,
                    sizeof(input),
                    nullptr,
                    0,
                    0,
                    output,
                    sizeof(output),
                    &length),
             1u);
    CHECK_EQ(length, 32u);
    CHECK_EQ(output[0], 0xbau);
    CHECK_EQ(output[31], 0xadu);
    engine.shutdown();
}
using namespace rut::jit;

TEST(jit, native_helper_allowlist_matches_orc_symbol_bindings) {
    JitEngine engine;
    REQUIRE(engine.init());
    u32 count = 0;
    const NativeHelperSymbol* symbols = native_helper_symbols(count);
    REQUIRE(symbols != nullptr);
    REQUIRE(count > 0);
    for (u32 i = 0; i < count; ++i) {
        const Str name{symbols[i].name, static_cast<u32>(__builtin_strlen(symbols[i].name))};
        REQUIRE(symbols[i].address != nullptr);
        CHECK(find_native_helper(name) == symbols[i].address);
        CHECK(engine.lookup(symbols[i].name) == symbols[i].address);
        for (u32 j = 0; j < i; ++j)
            CHECK(!name.eq({symbols[j].name, static_cast<u32>(__builtin_strlen(symbols[j].name))}));
    }
    CHECK(find_native_helper(lit_str("malloc")) == nullptr);
    CHECK(find_native_helper(lit_str("rut_helper_hash_suffix")) == nullptr);
    CHECK(find_native_helper({nullptr, 1}) == nullptr);
    CHECK(find_native_helper({"", 0}) == nullptr);
    engine.shutdown();
}

extern "C" u32 rut_helper_regex_scratch_cache_entry_count_for_test();
extern "C" u32 rut_helper_regex_scratch_cache_count_for_test();

// ── Helpers ────────────────────────────────────────────────────────

static Str lit(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return {s, n};
}

static u64 invalid_redirect_handler(void*, HandlerCtx*, const u8*, u32, void*) {
    auto result = HandlerResult::make_redirect(1);
    result.status_code = 1;
    return result.pack();
}

static u64 invalid_action_handler(void*, HandlerCtx*, const u8*, u32, void*) {
    return 0xffu;
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

TEST(jit, redirect_abi_and_compiled_action_are_fail_closed) {
    for (u16 id : {static_cast<u16>(1), static_cast<u16>(65535)}) {
        const auto packed = HandlerResult::make_redirect(id).pack();
        const auto decoded = HandlerResult::unpack(packed);
        CHECK(HandlerResult::redirect_fields_valid(decoded));
        CHECK_EQ(decoded.upstream_id, id);
        CHECK_EQ(decoded.status_code, 0u);
        CHECK_EQ(decoded.next_state, 0u);
        CHECK_EQ(decoded.yield_kind, YieldKind::HttpGet);
    }
    auto zero = HandlerResult::make_redirect(0);
    CHECK_FALSE(HandlerResult::redirect_fields_valid(zero));
    auto bad_status = HandlerResult::make_redirect(1);
    bad_status.status_code = 1;
    CHECK_FALSE(HandlerResult::redirect_fields_valid(bad_status));
    auto bad_next = HandlerResult::make_redirect(1);
    bad_next.next_state = 1;
    CHECK_FALSE(HandlerResult::redirect_fields_valid(bad_next));
    auto bad_kind = HandlerResult::make_redirect(1);
    bad_kind.yield_kind = YieldKind::Timer;
    CHECK_FALSE(HandlerResult::redirect_fields_valid(bad_kind));
    HandlerCtx invalid_ctx{};
    const u8 request[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    auto invalid_outcome = invoke_jit_handler(
        &invalid_redirect_handler, nullptr, invalid_ctx, request, sizeof(request) - 1, nullptr);
    CHECK_EQ(invalid_outcome.kind, JitDispatchOutcome::Kind::Error);
    invalid_outcome = invoke_jit_handler(
        &invalid_action_handler, nullptr, invalid_ctx, request, sizeof(request) - 1, nullptr);
    CHECK_EQ(invalid_outcome.kind, JitDispatchOutcome::Kind::Error);

    TestContext tc;
    REQUIRE(tc.init());
    Builder b;
    b.init(&tc.mod);
    auto* fn = V(b.create_function(lit("redirect"), lit("/api"), 0));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);
    VOK(b.emit_ret_redirect(65535));
    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_redirect"));
    REQUIRE(handler != nullptr);
    HandlerCtx ctx{};
    const u8 redirect_request[] = "GET /api HTTP/1.1\r\nHost: x\r\n\r\n";
    const auto outcome = invoke_jit_handler(
        handler, nullptr, ctx, redirect_request, sizeof(redirect_request) - 1, nullptr);
    CHECK_EQ(outcome.kind, JitDispatchOutcome::Kind::Redirect);
    CHECK_EQ(outcome.redirect_policy_id, 65535u);
    engine.shutdown();
    tc.destroy();
}

TEST(jit, frontend_nil_presence_test_executes_both_ways) {
    const char* src =
        "route GET \"/users\" { let h = req.header(\"Host\") let m = req.header(\"X-Missing\") "
        "guard h != nil else { return 401 } if m == nil { return 200 } else { return 500 } }\n";

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

    // With X-Missing present, `m == nil` is false -> the else branch, 500.
    static const char with_header[] =
        "GET /api/users HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-Missing: here\r\n"
        "\r\n";
    r = HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(with_header),
                                      sizeof(with_header) - 1,
                                      nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 500);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, static_multi_consumer_authentication_maps_credentials_and_rejects_ambiguity) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    const auto config = [](const char* consumer,
                           const char* key,
                           const char* password,
                           const char* key_id,
                           const char* password_id) {
        return std::string("auth.ConsumerCredentials(consumerId: \"") + consumer + "\", key: \"" +
               key + "\", credentials: \"" + password + "\", keyId: \"" + key_id +
               "\", passwordId: \"" + password_id + "\")";
    };
    const std::string alice =
        config("alice", "alice-key", "alice:pass", "alice-key-id", "alice-password-id");
    const std::string bob = config("bob", "bob-key", "bob:pass", "bob-key-id", "bob-password-id");
    const std::string configurations[][2] = {
        {alice, bob},
        {config("alice", "", "", "alice-key-id", "alice-password-id"), bob},
        {config("alice", "", "", "a", "b"), config("bob", "", "", "c", "d")},
        {alice, config("bob", "alice-key", "bob:pass", "c", "d")},
        {alice, config("bob", "bob-key", "alice:pass", "c", "d")},
        {alice, config("alice", "bob-key", "bob:pass", "c", "d")},
        {alice, config("bob", "bob-key", "bob:pass", "", "d")},
    };
    std::string source = "import \"middleware/auth.rut\"\n";
    for (u32 i = 0; i < sizeof(configurations) / sizeof(configurations[0]); ++i) {
        source += "route GET \"/" + std::to_string(i) +
                  "\" { let identity = auth.multiAuth(req.authorization.or(\"\"), " +
                  configurations[i][0] + ", " + configurations[i][1] + ")\n";
        if (i == 0) {
            source += R"rut(
    guard (identity.consumerId == "alice" &&
        ((identity.method == "apiKey" && identity.credentialId == "alice-key-id") ||
         (identity.method == "basic" && identity.credentialId == "alice-password-id"))) ||
        (identity.consumerId == "bob" &&
        ((identity.method == "apiKey" && identity.credentialId == "bob-key-id") ||
         (identity.method == "basic" && identity.credentialId == "bob-password-id"))) else { return 500 }
    match identity.credentialId {
        "alice-key-id" => return 201
        "alice-password-id" => return 202
        "bob-key-id" => return 203
        "bob-password-id" => return 204
        _ => return 500
    }
)rut";
        } else
            source += "return 200\n";
        source += "}\n";
    }
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "multi-consumer: %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        u16 status;
    };
    const Case cases[] = {
        {0, "Authorization: Bearer alice-key\r\n", 201},
        {0, "Authorization: Basic YWxpY2U6cGFzcw==\r\n", 202},
        {0, "Authorization: Bearer bob-key\r\n", 203},
        {0, "Authorization: bAsIc   Ym9iOnBhc3M=\r\n", 204},
        {0, "Authorization: Bearer bob-key\r\nX-Consumer-ID: alice\r\n", 203},
        {0, "", 401},
        {0, "Authorization: Bearer unknown\r\n", 401},
        {0, "Authorization: Basic Ym9iOndyb25n\r\n", 401},
        {0, "Authorization: Basic bob-key\r\n", 401},
        {0, "Authorization: Bearer Ym9iOnBhc3M=\r\n", 401},
        {0, "Authorization: Bearer alice-key\r\nauthorization: Bearer bob-key\r\n", 401},
        {0, "Authorization: Bearer bob-key\r\nAuthorization: Bearer bob-key\r\n", 401},
        {1, "Authorization: Bearer alice-key\r\n", 401},
        {1, "Authorization: Basic YWxpY2U6cGFzcw==\r\n", 401},
        {1, "Authorization: Bearer bob-key\r\n", 200},
        {1, "Authorization: Basic Ym9iOnBhc3M=\r\n", 200},
        {2, "", 503},
        {3, "Authorization: Bearer alice-key\r\n", 503},
        {4, "Authorization: Basic YWxpY2U6cGFzcw==\r\n", 503},
        {5, "Authorization: Bearer bob-key\r\n", 503},
        {6, "Authorization: Bearer bob-key\r\n", 503},
    };
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + tc.headers + "\r\n";
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != tc.status)
            std::fprintf(
                stderr, "route %u got %u expected %u\n", tc.route, result.status_code, tc.status);
        CHECK_EQ(result.status_code, tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_header_any_fallback) {
    const char* src =
        "route GET \"/users\" { let host = req.header(\"Host\") let value = any(host, "
        "\"fallback\") "
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

TEST(jit, frontend_bitwise_ops_execute) {
    const char* src =
        "route GET \"/users\" { let a = 6 let b = 3 if bitwise.and(a, b) == 2 && "
        "bitwise.or(a, b) == 7 && bitwise.xor(a, b) == 5 { return 200 } else { return 500 } "
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
    CHECK(r.status_code == 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_bitwise_pipe_stage_executes) {
    const char* src =
        "route GET \"/users\" { let m = 6 let v = m | bitwise.and(_, 3) let pair = (6, 3) "
        "let w = pair | bitwise.xor(_1, _2) if v == 2 && w == 5 { return 200 } else { "
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

TEST(jit, frontend_bitwise_shift_saturation_executes) {
    const char* src =
        "route GET \"/users\" { let one = 1 let big = 40 let neg = bitwise.flip(7) "
        "if bitwise.shiftLeft(one, big) == 0 && bitwise.shiftRight(neg, big) == "
        "bitwise.flip(0) && bitwise.shiftLeft(one, 4) == 16 { return 200 } else { return "
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

TEST(jit, frontend_arith_ops_execute) {
    const char* src =
        "route GET \"/users\" { let a = 7 let b = 3 if a + b == 10 && a - b == 4 && "
        "a * b == 21 && a / b == 2 && a % b == 1 { return 200 } else { return 500 } }\n";

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

TEST(jit, frontend_arith_div_mod_guards_execute) {
    // Runtime operands (locals don't fold at use sites), so the codegen
    // select guards — not the analyze fold — produce these results.
    const char* src =
        "route GET \"/users\" { let z = 0 let a = 7 let m = -2147483648 let n = -1 "
        "if a / z == 0 && a % z == 0 && m / n == -2147483648 && m % n == 0 { return 200 } "
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

TEST(jit, frontend_match_negative_pattern_executes) {
    const char* src =
        "route GET \"/users\" { let a = 0 - 1 match a { -1 => return 204 _ => return 500 } "
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
    CHECK(r.status_code == 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_i64_arith_and_compares_execute) {
    // Runtime i64 values crossing the i32 boundary: widen, arithmetic, and
    // ordered compares all at 64-bit width.
    const char* src =
        "route GET \"/users\" { let a = 2147483647 let w = i64(a) let big = w + 1 "
        "if big == 2147483648 && big > w && w < big && big * 2 == 4294967296 "
        "{ return 200 } else { return 500 } }\n";

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

TEST(jit, frontend_i64_div_mod_guards_and_wrap_execute) {
    // Runtime operands (locals don't fold at use sites): the width-aware
    // codegen guards must produce the defined results at INT64 boundaries,
    // and overflow must wrap at 64 bits.
    const char* src =
        "route GET \"/users\" { let z = i64(0) let a = i64(7) "
        "let max = 9223372036854775807 let one = i64(1) let m = max + one let n = i64(0) - one "
        "if a / z == z && a % z == z && m / n == m && m % n == z && max + one == m "
        "{ return 200 } else { return 500 } }\n";

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

TEST(jit, frontend_i64_runtime_widen_across_wait_executes) {
    // A RUNTIME-widened i64 (WidenI64/sext, not a folded literal) used
    // after a wait. MIR substitutes LocalRefs with the local's init tree at
    // each use site and lowering re-materializes that tree inside the block
    // that uses it, so the resume block re-executes the sext locally —
    // there is no cross-block SSA reference back into the entry block.
    const auto src = R"rut(
route GET "/sleep" { let a = 5 let w = i64(a) wait(1000) if w == i64(5) { return 200 } else { return 500 } }
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

    auto r0 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r0.next_state, 1);

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

TEST(jit, frontend_bitwise_i64_pack_unpack_executes) {
    // The packed fixed-window shape end-to-end at runtime: pack a window
    // index and a count into one i64, unpack both, and check 64-bit shift
    // saturation with a runtime amount.
    const char* src =
        "route GET \"/users\" { let a = 7 let win = i64(a) let cnt = i64(9) "
        "let packed = bitwise.or(bitwise.shiftLeft(win, 32), cnt) "
        "let win2 = bitwise.shiftRight(packed, 32) "
        "let cnt2 = bitwise.and(packed, 4294967295) "
        "let big = i64(70) "
        "if win2 == win && cnt2 == cnt && bitwise.shiftLeft(win, big) == i64(0) "
        "{ return 200 } else { return 500 } }\n";

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

TEST(jit, math_library_import_executes_with_runtime_bounds_and_ordered_types) {
    const auto source = R"rut(
import * as math from "../lib/math.rut"
route GET "/math" {
    let count = req.headerCount("X-Tag")
    let signed = count - 4
    let now = time.nowMicros()
    if max(now, 0) >= now && min(now, 0) == 0 &&
       math.min(count, 4) == min(count, 4) &&
       math.max(count, 4) == max(count, 4) &&
       math.clamp(count, 2, 6) == req.headerCount("X-Expected") &&
       math.clamp(4, count, count + 2) == max(count, min(4, count + 2)) &&
       math.clamp(4, count + 2, count) == count + 2 &&
       math.clamp(signed, -2, 2) == req.headerCount("X-Expected") - 4 &&
       math.clamp(count, 4, 4) == 4 &&
       math.clamp(count, 6, 2) == 6 &&
       math.min(-2147483648, 2147483647) == -2147483648 &&
       math.max(-2147483648, 2147483647) == 2147483647 &&
       math.clamp(-2147483648, -2147483648, 2147483647) == -2147483648 &&
       math.min("alpha", "beta") == "alpha" &&
       math.max("alpha", "beta") == "beta" &&
       math.clamp("gamma", "alpha", "beta") == "beta" {
        return 200
    } else { return 500 }
}
)rut";
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/math.rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        fprintf(stderr,
                "math analysis failed at %u:%u: %.*s\n",
                hir.error().span.line,
                hir.error().span.col,
                hir.error().detail.len,
                hir.error().detail.ptr);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    struct Case {
        u32 count;
        u32 expected;
    };
    const Case cases[] = {{0, 2}, {1, 2}, {2, 2}, {3, 3}, {6, 6}, {7, 6}, {10, 6}};
    for (const auto& test : cases) {
        std::string request = "GET /math HTTP/1.1\r\nHost: localhost\r\n";
        for (u32 i = 0; i < test.count; ++i) request += "X-Tag: tag\r\n";
        for (u32 i = 0; i < test.expected; ++i) request += "X-Expected: tag\r\n";
        request += "\r\n";
        auto result = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    request.size(),
                                                    nullptr));
        CHECK_EQ(result.action, HandlerAction::ReturnStatus);
        CHECK_EQ(result.status_code, 200);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_time_minmax_gcra_shape_executes) {
    // The full GCRA expression shape at runtime: latched now, i64
    // arithmetic, max() over (stored tat, now). Pins the per-invocation
    // time latch: every use of a now-bound local sees the SAME value
    // (without the latch, init-tree re-materialization would re-read the
    // clock per use).
    const char* src =
        "route GET \"/a\" { let t1 = time.nowMicros() let t2 = time.nowMicros() "
        "if t2 == t1 { return 200 } else { return 500 } }\n"
        "route GET \"/b\" { let t1 = time.nowMicros() "
        "if t1 > 0 { return 200 } else { return 500 } }\n"
        "route GET \"/c\" { let t1 = time.nowMicros() let tat = max(t1 + 5, t1) "
        "if tat - t1 == 5 { return 200 } else { return 500 } }\n";

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

    auto call_route = [&](const char* sym) {
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(sym));
        if (handler == nullptr) return 0u;
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        return static_cast<u32>(r.status_code);
    };
    CHECK_EQ(call_route("handler_route_0"), 200u);  // t2 == t1 (latched now)
    CHECK_EQ(call_route("handler_route_1"), 200u);  // t1 > 0
    CHECK_EQ(call_route("handler_route_2"), 200u);  // max/sub shape

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_time_latch_resets_per_invocation_without_parse) {
    // A handler that samples time.nowMicros() but never reads the request
    // gets no parse_prime (the usual latch reset), so it needs the dedicated
    // prologue unlatch — without it the thread's clock freezes at the first
    // sampled value and GCRA-style buckets never observe elapsed time.
    // Observed via the helper: after each invocation the latch still holds
    // that invocation's value, so two spaced invocations must differ.
    const char* src =
        "route GET \"/t\" { let t1 = time.nowMicros() "
        "if t1 > 0 { return 200 } else { return 500 } }\n";

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
    auto invoke = [&] {
        auto r = HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(kGetApiRequest),
                                               sizeof(kGetApiRequest) - 1,
                                               nullptr));
        CHECK_EQ(r.status_code, 200);
        return rut_helper_time_now_micros();  // latch still holds this invocation's value
    };
    const i64 first = invoke();
    usleep(2000);
    const i64 second = invoke();
    CHECK_GT(second, first);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_rut_gcra_token_bucket_executes) {
    // THE capstone: the complete GCRA token bucket from
    // examples/ratelimit.rut, written entirely in Rut, executing under the
    // JIT. emit == tau → two conforming requests, third rejected; another
    // IP has independent state. The successor is committed only in the
    // conforming branch, matching the built-in limiter on rejection.
    const auto src = R"rut(
let buckets = Cache<IP, i64>(capacity: 4096)

route GET "/users" {
    let now = time.nowMicros()
    let tat = max(buckets.get(req.remoteAddr).or(0), now)
    if tat - now <= 600000000 {
        buckets.set(req.remoteAddr, tat + 600000000)
        return 200
    } else {
        return 429
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

    cache_registry_set_seed(0x6CFAu);
    const u32 caps[1] = {4096};
    const u64 idents[1] = {cache_instance_identity("buckets", 7)};
    cache_registry_publish(caps, idents, 1);

    Connection conn;
    conn.reset();
    conn.peer_addr = 0x0A0000FE;

    auto call = [&]() {
        return static_cast<u32>(
            HandlerResult::unpack(handler(&conn,
                                          nullptr,
                                          reinterpret_cast<const u8*>(kGetApiRequest),
                                          sizeof(kGetApiRequest) - 1,
                                          nullptr))
                .status_code);
    };
    CHECK_EQ(call(), 200u);
    CHECK_EQ(call(), 200u);
    CHECK_EQ(call(), 429u);

    conn.peer_addr = 0x0A0000FF;  // fresh IP → fresh bucket
    CHECK_EQ(call(), 200u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_i64_local_across_wait_executes) {
    // Locals re-materialize fresh in resume states (no ctx slots involved),
    // so an i64 local crosses a wait exactly like an i32 — this pins the
    // deferred CtxLoad/StoreSlotI64 decision.
    const auto src = R"rut(
route GET "/sleep" { let big = 2147483648 wait(1000) if big == 2147483648 { return 200 } else { return 500 } }
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

    auto r0 = HandlerResult::unpack(handler(nullptr,
                                            &ctx,
                                            reinterpret_cast<const u8*>(kGetRootRequest),
                                            sizeof(kGetRootRequest) - 1,
                                            nullptr));
    CHECK_EQ(static_cast<u8>(r0.action), static_cast<u8>(HandlerAction::Yield));
    CHECK_EQ(r0.next_state, 1);

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

TEST(jit, frontend_arith_overflow_wraps_executes) {
    const char* src =
        "route GET \"/users\" { let big = 2147483647 let one = 1 "
        "if big + one == -2147483648 && (0 - big) - 2 == 2147483647 { return 200 } else { "
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

TEST(jit, frontend_req_header_all_requires_present_value_present_or_missing) {
    const char* src =
        "route GET \"/users\" { let host = all(req.header(\"Host\"), \"fallback\") if host == "
        "\"fallback\" { return 204 } else { return 401 } }\n";

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

    auto hit = HandlerResult::unpack(handler(nullptr,
                                             nullptr,
                                             reinterpret_cast<const u8*>(kGetApiRequest),
                                             sizeof(kGetApiRequest) - 1,
                                             nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 204u);

    static const char missing_host_request[] =
        "GET /api/users HTTP/1.1\r\nUser-Agent: curl\r\n\r\n";
    auto miss = HandlerResult::unpack(handler(nullptr,
                                              nullptr,
                                              reinterpret_cast<const u8*>(missing_host_request),
                                              sizeof(missing_host_request) - 1,
                                              nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_standard_header_alias_any_fallback) {
    const char* src =
        "route GET \"/users\" { let auth = any(req.authorization, \"\") let request = "
        "any(req.xRequestId, \"\") if auth == \"Bearer root\" { if request == \"req-1\" { "
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

TEST(jit, frontend_cache_counter_pattern_executes) {
    // The first real algorithm-in-Rut: a per-IP request counter. Three
    // invocations of the same handler → 200, 200, 429; a different IP
    // starts its own count. Exercises CacheGet miss → .or(0), literal
    // adoption in prev + 1, the bare CacheSet statement, and the
    // thread_local table publish/rebuild path.
    const auto src = R"rut(
let buckets = Cache<IP, i64>(capacity: 1024)

route GET "/users" {
    let prev = buckets.get(req.remoteAddr).or(0)
    buckets.set(req.remoteAddr, prev + 1)
    if prev + 1 > 2 { return 429 } else { return 200 }
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

    // Publish the instance descriptors (the loader's job in production) with
    // a deterministic seed and a distinct capacity so this test's tables
    // rebuild fresh even if another test touched the registry.
    cache_registry_set_seed(0x5EEDu);
    const u32 caps[1] = {1024};
    const u64 idents[1] = {cache_instance_identity("buckets", 7)};
    cache_registry_publish(caps, idents, 1);

    Connection conn;
    conn.reset();
    conn.peer_addr = 0x0A00002A;  // 10.0.0.42

    auto call = [&]() {
        return HandlerResult::unpack(handler(&conn,
                                             nullptr,
                                             reinterpret_cast<const u8*>(kGetApiRequest),
                                             sizeof(kGetApiRequest) - 1,
                                             nullptr));
    };
    auto r1 = call();
    CHECK(r1.action == HandlerAction::ReturnStatus);
    CHECK_EQ(r1.status_code, 200);
    // Probe the table directly: call 1 must have stored count 1.
    u8 probe_has = 0;
    i64 probe_val = 0;
    rut_helper_cache_get(0, 0x0A00002A, &probe_has, &probe_val);
    CHECK_EQ(probe_has, 1);
    CHECK_EQ(probe_val, 1);
    auto r2 = call();
    CHECK_EQ(r2.status_code, 200);
    auto r3 = call();
    CHECK_EQ(r3.status_code, 429);

    // A different IP has independent state.
    conn.peer_addr = 0x0A000001;
    auto other = call();
    CHECK_EQ(other.status_code, 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_cache_branch_write_only_meters_accepted_requests) {
    const auto src = R"rut(
let buckets = Cache<IP, i64>(capacity: 1024)

route GET "/users" {
    guard req.http11 else { return 505 }
    let prev = buckets.get(req.remoteAddr).or(0)
    if prev < 2 {
        guard req.http11 else { return 505 }
        buckets.set(req.remoteAddr, prev + 1)
        return 200
    } else {
        return 429
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

    cache_registry_set_seed(0xB4A4C4u);
    const u32 caps[1] = {1024};
    const u64 idents[1] = {cache_instance_identity("branch-buckets", 14)};
    cache_registry_publish(caps, idents, 1);

    Connection conn;
    conn.reset();
    conn.peer_addr = 0x0A00002Bu;
    auto call = [&]() {
        return HandlerResult::unpack(handler(&conn,
                                             nullptr,
                                             reinterpret_cast<const u8*>(kGetApiRequest),
                                             sizeof(kGetApiRequest) - 1,
                                             nullptr));
    };
    CHECK_EQ(call().status_code, 200);
    CHECK_EQ(call().status_code, 200);
    CHECK_EQ(call().status_code, 429);
    CHECK_EQ(call().status_code, 429);

    // Rejected calls do not execute the accepted branch's CacheSet.
    u8 probe_has = 0;
    i64 probe_val = 0;
    rut_helper_cache_get(0, conn.peer_addr, &probe_has, &probe_val);
    CHECK_EQ(probe_has, 1);
    CHECK_EQ(probe_val, 2);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_set_and_add_record_request_header_modes) {
    const auto src = R"rut(
route GET "/users" {
    req.set("X-Mode", "replace")
    req.add("X-Tag", "tail")
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

    Connection conn;
    conn.reset();
    const auto result = HandlerResult::unpack(handler(&conn,
                                                      nullptr,
                                                      reinterpret_cast<const u8*>(kGetApiRequest),
                                                      sizeof(kGetApiRequest) - 1,
                                                      nullptr));
    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK_EQ(result.status_code, 200);
    REQUIRE_EQ(conn.req_header_override_count, 2u);
    CHECK(conn.req_header_overrides[0].name.eq(lit("X-Mode")));
    CHECK(conn.req_header_overrides[0].value.eq(lit("replace")));
    CHECK(conn.req_header_overrides[1].name.eq(lit("X-Tag")));
    CHECK(conn.req_header_overrides[1].value.eq(lit("tail")));
    CHECK_EQ(conn.req_header_append_mask, 2u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_response_dynamic_headers_record_ordered_mutations) {
    const auto src = R"rut(
route GET "/api/users" {
    let resp = response(200)
    resp.add("X-Base", "static")
    resp.set("X-Path", req.path)
    resp.add("X-Path", "tail")
    let observed = resp.header("X-Path").or("missing")
    resp.set("X-Observed", observed)
    resp.remove("X-Base")
    return resp
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

    Connection conn;
    conn.reset();
    const auto result = HandlerResult::unpack(handler(&conn,
                                                      nullptr,
                                                      reinterpret_cast<const u8*>(kGetApiRequest),
                                                      sizeof(kGetApiRequest) - 1,
                                                      nullptr));
    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK_EQ(result.status_code, 200);
    REQUIRE_EQ(conn.resp_header_mutation_count, 4u);
    CHECK(conn.resp_header_mutations[0].mode == ConnectionBase::RespHeaderMutationMode::Set);
    CHECK(conn.resp_header_mutations[0].name.eq(lit("X-Path")));
    CHECK(conn.resp_header_mutations[0].value.eq(lit("/api/users")));
    CHECK(conn.resp_header_mutations[1].mode == ConnectionBase::RespHeaderMutationMode::Add);
    CHECK(conn.resp_header_mutations[1].name.eq(lit("X-Path")));
    CHECK(conn.resp_header_mutations[1].value.eq(lit("tail")));
    CHECK(conn.resp_header_mutations[2].mode == ConnectionBase::RespHeaderMutationMode::Set);
    CHECK(conn.resp_header_mutations[2].name.eq(lit("X-Observed")));
    CHECK(conn.resp_header_mutations[2].value.eq(lit("/api/users")));
    CHECK(conn.resp_header_mutations[3].mode == ConnectionBase::RespHeaderMutationMode::Remove);
    CHECK(conn.resp_header_mutations[3].name.eq(lit("X-Base")));
    CHECK_FALSE(conn.resp_header_mutation_overflow);

    conn.reset();
    CHECK_EQ(conn.resp_header_mutation_count, 0u);
    CHECK_FALSE(conn.resp_header_mutation_overflow);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, chain_after_response_headers_commit_on_guard_rejection) {
    const auto src = R"rut(
func response_headers(_ req: i32, _ resp: Response) -> i32 {
    resp.set("X-Path", req.path)
    resp.add("X-Stage", "after")
    resp.remove("Server")
    0
}
func require_http11(_ req: i32) -> i32 {
    guard req.http11 else { respond 505 }
    0
}
chain access { before require_http11(req) after response_headers(req, resp) }
route GET "/api/users" use chain access { return 200 }
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

    Connection conn;
    conn.reset();
    static const char kHttp10Request[] = "GET /api/users HTTP/1.0\r\nHost: localhost\r\n\r\n";
    const auto rejected = HandlerResult::unpack(handler(&conn,
                                                        nullptr,
                                                        reinterpret_cast<const u8*>(kHttp10Request),
                                                        sizeof(kHttp10Request) - 1,
                                                        nullptr));
    CHECK(rejected.action == HandlerAction::ReturnStatus);
    CHECK_EQ(rejected.status_code, 505);
    REQUIRE_EQ(conn.resp_header_mutation_count, 3u);
    CHECK(conn.resp_header_mutations[0].name.eq(lit("X-Path")));
    CHECK(conn.resp_header_mutations[0].value.eq(lit("/api/users")));
    CHECK(conn.resp_header_mutations[1].value.eq(lit("after")));
    CHECK(conn.resp_header_mutations[2].mode == ConnectionBase::RespHeaderMutationMode::Remove);
    CHECK_FALSE(conn.resp_header_mutation_overflow);

    conn.reset();
    const auto result = HandlerResult::unpack(handler(&conn,
                                                      nullptr,
                                                      reinterpret_cast<const u8*>(kGetApiRequest),
                                                      sizeof(kGetApiRequest) - 1,
                                                      nullptr));
    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK_EQ(result.status_code, 200);
    REQUIRE_EQ(conn.resp_header_mutation_count, 3u);
    CHECK(conn.resp_header_mutations[0].mode == ConnectionBase::RespHeaderMutationMode::Set);
    CHECK(conn.resp_header_mutations[0].name.eq(lit("X-Path")));
    CHECK(conn.resp_header_mutations[0].value.eq(lit("/api/users")));
    CHECK(conn.resp_header_mutations[1].mode == ConnectionBase::RespHeaderMutationMode::Add);
    CHECK(conn.resp_header_mutations[1].name.eq(lit("X-Stage")));
    CHECK(conn.resp_header_mutations[1].value.eq(lit("after")));
    CHECK(conn.resp_header_mutations[2].mode == ConnectionBase::RespHeaderMutationMode::Remove);
    CHECK(conn.resp_header_mutations[2].name.eq(lit("Server")));
    CHECK_FALSE(conn.resp_header_mutation_overflow);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, cache_helpers_miss_and_out_of_range) {
    cache_registry_set_seed(0x5EEDu);
    const u32 caps[1] = {64};
    const u64 idents[1] = {cache_instance_identity("buckets", 7)};
    cache_registry_publish(caps, idents, 1);

    u8 has = 0xff;
    i64 val = -1;
    rut_helper_cache_get(0, 0x7F000001u, &has, &val);
    CHECK_EQ(has, 0);
    CHECK_EQ(val, 0);

    rut_helper_cache_set(0, 0x7F000001u, 77);
    rut_helper_cache_get(0, 0x7F000001u, &has, &val);
    CHECK_EQ(has, 1);
    CHECK_EQ(val, 77);

    // Out-of-range instance: get misses, set is a no-op.
    rut_helper_cache_get(7, 0x7F000001u, &has, &val);
    CHECK_EQ(has, 0);
    rut_helper_cache_set(7, 0x7F000001u, 1);
}

TEST(jit, cache_get_optionals_from_two_instances_merge_and_verify) {
    // Two cache instances' Optional<I64> results flowing through nested .or
    // fallbacks must produce ONE LLVM carrier type — pins the canonical
    // Optional<I64> in emit_cache_get (and that LLVM literal-struct
    // uniquing keeps the select well-typed under JIT verification).
    const char* src =
        "let a = Cache<IP, i64>(capacity: 64)\n"
        "let b = Cache<IP, i64>(capacity: 64)\n"
        "route GET \"/x\" { "
        "let n = a.get(req.remoteAddr).or(b.get(req.remoteAddr).or(0)) "
        "if n > 0 { return 200 } else { return 204 } }\n";
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
    REQUIRE(engine.compile(cg.mod, cg.ctx));  // JIT verification passes
    engine.shutdown();
    rir.destroy();
}

TEST(jit, cache_registry_identity_governs_persistence_across_publish) {
    cache_registry_set_seed(0x5EEDu);
    const u32 caps[1] = {64};
    const u64 ident_a[1] = {cache_instance_identity("alpha", 5)};
    const u64 ident_b[1] = {cache_instance_identity("beta", 4)};
    cache_registry_publish(caps, ident_a, 1);
    rut_helper_cache_set(0, 0x01020304u, 42);
    u8 has = 0;
    i64 val = 0;
    rut_helper_cache_get(0, 0x01020304u, &has, &val);
    CHECK_EQ(has, 1);
    CHECK_EQ(val, 42);

    // Identical re-publish (same name, same capacity) → state persists
    // across the config swap (documented).
    cache_registry_publish(caps, ident_a, 1);
    rut_helper_cache_get(0, 0x01020304u, &has, &val);
    CHECK_EQ(has, 1);
    CHECK_EQ(val, 42);

    // Same capacity but a different declaration at this index (rename /
    // reorder) → different logical cache: the old entries must NOT bleed
    // through; the shard drops and rebuilds the table.
    cache_registry_publish(caps, ident_b, 1);
    rut_helper_cache_get(0, 0x01020304u, &has, &val);
    CHECK_EQ(has, 0);
}

TEST(jit, frontend_req_route_param_field_guard) {
    const char* src =
        "route GET \"/users/:id\" { if req.params.id == \"42\" { return 204 } else { return 401 } "
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

TEST(jit, frontend_req_query_string_any_fallback) {
    const char* src =
        "route GET \"/search\" { let raw = any(req.queryString, \"\") if raw == "
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

TEST(jit, frontend_req_query_all_requires_present_value) {
    const char* src =
        "route GET \"/search\" { let query = all(req.query(\"x\"), \"\") if query == \"\" { "
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

    auto hit = HandlerResult::unpack(handler(nullptr,
                                             nullptr,
                                             reinterpret_cast<const u8*>(kGetApiQueryRequest),
                                             sizeof(kGetApiQueryRequest) - 1,
                                             nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 204u);

    static const char missing_query_request[] = "GET /search HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss = HandlerResult::unpack(handler(nullptr,
                                              nullptr,
                                              reinterpret_cast<const u8*>(missing_query_request),
                                              sizeof(missing_query_request) - 1,
                                              nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_header_all_requires_present_value_request_matrix) {
    const char* src =
        "route GET \"/users\" { let host = all(req.header(\"Host\"), \"fallback\") if host == "
        "\"fallback\" { return 204 } else { return 401 } }\n";

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

    static const char present_request[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto present = HandlerResult::unpack(handler(nullptr,
                                                 nullptr,
                                                 reinterpret_cast<const u8*>(present_request),
                                                 sizeof(present_request) - 1,
                                                 nullptr));
    CHECK(present.action == HandlerAction::ReturnStatus);
    CHECK_EQ(present.status_code, 204u);

    static const char mismatch_request[] = "GET /users HTTP/1.1\r\nHost: api.local\r\n\r\n";
    auto mismatch = HandlerResult::unpack(handler(nullptr,
                                                  nullptr,
                                                  reinterpret_cast<const u8*>(mismatch_request),
                                                  sizeof(mismatch_request) - 1,
                                                  nullptr));
    CHECK(mismatch.action == HandlerAction::ReturnStatus);
    CHECK_EQ(mismatch.status_code, 204u);

    static const char missing_request[] = "GET /users HTTP/1.1\r\nUser-Agent: curl\r\n\r\n";
    auto missing = HandlerResult::unpack(handler(nullptr,
                                                 nullptr,
                                                 reinterpret_cast<const u8*>(missing_request),
                                                 sizeof(missing_request) - 1,
                                                 nullptr));
    CHECK(missing.action == HandlerAction::ReturnStatus);
    CHECK_EQ(missing.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_all_non_short_circuit_evaluates_rhs_when_missing_query) {
    const char* src =
        "route GET \"/users\" { let value = all(req.query(\"x\"), \"fallback\") if value == "
        "\"fallback\" { return 204 } else { return 401 } }\n";

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

    static const char missing_query_request[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto no_query =
        HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(missing_query_request),
                                      sizeof(missing_query_request) - 1,
                                      nullptr));
    CHECK(no_query.action == HandlerAction::ReturnStatus);
    CHECK_EQ(no_query.status_code, 401u);

    static const char query_request[] = "GET /users?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto with_query = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(query_request),
                                                    sizeof(query_request) - 1,
                                                    nullptr));
    CHECK(with_query.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_query.status_code, 204u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_cookie_all_requires_present_value_present_or_missing) {
    const char* src =
        "route GET \"/session\" { let sid = all(req.cookie(\"sid\"), \"ok\") if sid == \"ok\" "
        "{ return 204 } else { return 401 } }\n";

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

    static const char present_request[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=ok; lang=en\r\n\r\n";
    auto hit = HandlerResult::unpack(handler(nullptr,
                                             nullptr,
                                             reinterpret_cast<const u8*>(present_request),
                                             sizeof(present_request) - 1,
                                             nullptr));
    CHECK(hit.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit.status_code, 204u);

    static const char mismatch_request[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=nope; lang=en\r\n\r\n";
    auto miss = HandlerResult::unpack(handler(nullptr,
                                              nullptr,
                                              reinterpret_cast<const u8*>(mismatch_request),
                                              sizeof(mismatch_request) - 1,
                                              nullptr));
    CHECK(miss.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss.status_code, 204u);

    static const char missing_request[] = "GET /session HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto no_cookie = HandlerResult::unpack(handler(nullptr,
                                                   nullptr,
                                                   reinterpret_cast<const u8*>(missing_request),
                                                   sizeof(missing_request) - 1,
                                                   nullptr));
    CHECK(no_cookie.action == HandlerAction::ReturnStatus);
    CHECK_EQ(no_cookie.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_all_non_short_circuit_eager_rhs_is_observed_with_present_query) {
    const char* src =
        "func fallback() -> str => error(.timeout)\n"
        "route GET \"/users\" { let value = all(req.query(\"x\"), fallback()) if value == "
        "\"x\" { return 204 } else { return 401 } }\n";

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

    static const char missing_query_request[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto no_query =
        HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(missing_query_request),
                                      sizeof(missing_query_request) - 1,
                                      nullptr));
    CHECK(no_query.action == HandlerAction::ReturnStatus);
    CHECK_EQ(no_query.status_code, 500u);

    static const char query_request[] = "GET /users?x=x HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto with_query = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(query_request),
                                                    sizeof(query_request) - 1,
                                                    nullptr));
    CHECK(with_query.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_query.status_code, 500u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_any_non_short_circuit_eager_rhs_is_observed_with_present_query) {
    const char* src =
        "func fallback() -> str => error(.timeout)\n"
        "route GET \"/users\" { let value = any(req.query(\"x\"), fallback()) if value == "
        "\"x\" { return 204 } else { return 401 } }\n";

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

    static const char missing_query_request[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto no_query =
        HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(missing_query_request),
                                      sizeof(missing_query_request) - 1,
                                      nullptr));
    CHECK(no_query.action == HandlerAction::ReturnStatus);
    CHECK_EQ(no_query.status_code, 500u);

    static const char query_request[] = "GET /users?x=x HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto with_query = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(query_request),
                                                    sizeof(query_request) - 1,
                                                    nullptr));
    CHECK(with_query.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_query.status_code, 500u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_if_let_function_body_eager_arm_jit_valid_and_recovers) {
    // Round-2 finding 4: a value-position function-body `if let x = v { x } else
    // { 0 }` lowers to an IfElse MirValue whose arms are materialized eagerly
    // before a select — the then arm's `ValueOf(v)` unwrap runs even on v's error
    // path. This asserts the eager lowering produces a JIT-VALID module (a real
    // domination bug would fail engine.compile, as the post-wait finding-1 shape
    // did) and RUNS correctly on the ERROR path: `any(literal, fallback())`
    // eagerly evaluates fallback(), whose error propagates, so v is an error at
    // runtime. The eager `ValueOf(v)` unwrap therefore executes over an errored
    // carrier (a pure, total LLVMBuildExtractValue yielding a discarded garbage
    // payload — no fault, no deref, no error-channel write), the select (cond =
    // HasValue(v) = false) picks the else, and the if-let recovers x = 0. f
    // returns 0, so the route observes 0 != 200 and returns 401. That the result
    // is a clean 401 (not a leaked-error prelude 500, nor a crash) is the direct
    // runtime proof the eager arm is benign.
    const char* src =
        "func fallback() -> i32 => error(.timeout)\n"
        "func f() -> i32 { let v = any(200, fallback()) if let x = v { x } else { 0 } }\n"
        "route GET \"/api/users\" { if f() == 200 { return 204 } else { return 401 } }\n";
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
    CHECK_EQ(r.status_code, 401u);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_guard_let_function_body_parity_jit_valid_and_recovers) {
    // Finding 4 guard-let parity: the guard-let form of the same recovery
    // (`guard let x = v else { 0 } x`) is JIT-valid and, on the identical error
    // path (v is an eager-error at runtime), takes its else and recovers to 0, so
    // the route observes 0 != 200 and returns 401 — identical to the if-let form
    // above. Same recovery, same observable result: parity holds.
    const char* src =
        "func fallback() -> i32 => error(.timeout)\n"
        "func g() -> i32 { let v = any(200, fallback()) guard let x = v else { 0 } x }\n"
        "route GET \"/api/users\" { if g() == 200 { return 204 } else { return 401 } }\n";
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
    CHECK_EQ(r.status_code, 401u);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_header_all_non_short_circuit_eager_rhs_is_observed_with_present_header) {
    const char* src =
        "func fallback() -> str => error(.timeout)\n"
        "route GET \"/users\" { let value = all(req.header(\"X-Foo\"), fallback()) if value == "
        "\"x\" "
        "{ return 204 } else { return 401 } }\n";

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

    static const char missing_header_request[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto no_header =
        HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(missing_header_request),
                                      sizeof(missing_header_request) - 1,
                                      nullptr));
    CHECK(no_header.action == HandlerAction::ReturnStatus);
    CHECK_EQ(no_header.status_code, 500u);

    static const char header_request[] =
        "GET /users HTTP/1.1\r\nHost: localhost\r\nX-Foo: x\r\n\r\n";
    auto with_header = HandlerResult::unpack(handler(nullptr,
                                                     nullptr,
                                                     reinterpret_cast<const u8*>(header_request),
                                                     sizeof(header_request) - 1,
                                                     nullptr));
    CHECK(with_header.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_header.status_code, 500u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_header_any_non_short_circuit_eager_rhs_is_observed_with_present_header) {
    const char* src =
        "func fallback() -> str => error(.timeout)\n"
        "route GET \"/users\" { let value = any(req.header(\"X-Foo\"), fallback()) if value == "
        "\"x\" "
        "{ return 204 } else { return 401 } }\n";

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

    static const char missing_header_request[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto no_header =
        HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(missing_header_request),
                                      sizeof(missing_header_request) - 1,
                                      nullptr));
    CHECK(no_header.action == HandlerAction::ReturnStatus);
    CHECK_EQ(no_header.status_code, 500u);

    static const char header_request[] =
        "GET /users HTTP/1.1\r\nHost: localhost\r\nX-Foo: x\r\n\r\n";
    auto with_header = HandlerResult::unpack(handler(nullptr,
                                                     nullptr,
                                                     reinterpret_cast<const u8*>(header_request),
                                                     sizeof(header_request) - 1,
                                                     nullptr));
    CHECK(with_header.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_header.status_code, 500u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_cookie_all_non_short_circuit_eager_rhs_is_observed_with_present_cookie) {
    const char* src =
        "func fallback() -> str => error(.timeout)\n"
        "route GET \"/session\" { let sid = all(req.cookie(\"sid\"), fallback()) if sid == \"ok\" "
        "{ return 204 } else { return 401 } }\n";

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

    static const char missing_cookie[] = "GET /session HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss_cookie = HandlerResult::unpack(handler(nullptr,
                                                     nullptr,
                                                     reinterpret_cast<const u8*>(missing_cookie),
                                                     sizeof(missing_cookie) - 1,
                                                     nullptr));
    CHECK(miss_cookie.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss_cookie.status_code, 500u);

    static const char hit_cookie[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=ok; lang=en\r\n\r\n";
    auto with_cookie = HandlerResult::unpack(handler(nullptr,
                                                     nullptr,
                                                     reinterpret_cast<const u8*>(hit_cookie),
                                                     sizeof(hit_cookie) - 1,
                                                     nullptr));
    CHECK(with_cookie.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_cookie.status_code, 500u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_cookie_any_non_short_circuit_eager_rhs_is_observed_with_present_cookie) {
    const char* src =
        "func fallback() -> str => error(.timeout)\n"
        "route GET \"/session\" { let sid = any(req.cookie(\"sid\"), fallback()) if sid == \"ok\" "
        "{ return 204 } else { return 401 } }\n";

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

    static const char missing_cookie[] = "GET /session HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss_cookie = HandlerResult::unpack(handler(nullptr,
                                                     nullptr,
                                                     reinterpret_cast<const u8*>(missing_cookie),
                                                     sizeof(missing_cookie) - 1,
                                                     nullptr));
    CHECK(miss_cookie.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss_cookie.status_code, 500u);

    static const char hit_cookie[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=ok; lang=en\r\n\r\n";
    auto with_cookie = HandlerResult::unpack(handler(nullptr,
                                                     nullptr,
                                                     reinterpret_cast<const u8*>(hit_cookie),
                                                     sizeof(hit_cookie) - 1,
                                                     nullptr));
    CHECK(with_cookie.action == HandlerAction::ReturnStatus);
    CHECK_EQ(with_cookie.status_code, 500u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_and_requires_both_operands) {
    const char* src =
        "route GET \"/users\" { if req.pathOnly == \"/users\" && any(req.queryString, \"\") == "
        "\"\" { return "
        "204 } else { return 401 } }\n";

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

    static const char hit[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(r.status_code, 204u);

    static const char miss[] = "GET /users?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss_r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(miss_r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss_r.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_or_requires_either_operand) {
    const char* src =
        "route GET \"/users\" { if req.pathOnly == \"/admin\" || req.queryString == \"q=1\" { "
        "return "
        "204 } else { return 401 } }\n";

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

    static const char hit[] = "GET /users?q=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(r.status_code, 204u);

    static const char miss[] = "GET /users HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss_r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(miss_r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss_r.status_code, 401u);

    static const char miss2[] = "GET /users?q=2 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss2_r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss2), sizeof(miss2) - 1, nullptr));
    CHECK(miss2_r.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss2_r.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_req_query_all_requires_expected_alternative) {
    const char* src =
        "route GET \"/search\" { let q = req.query(\"q\") let value = all(q, \"rut\") if value == "
        "\"rut\" || req.queryString == \"q=admin\" { return 204 } else { return 401 } }\n";

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

    static const char hit_by_value[] = "GET /search?q=rut HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto hit_by_value_res = HandlerResult::unpack(handler(nullptr,
                                                          nullptr,
                                                          reinterpret_cast<const u8*>(hit_by_value),
                                                          sizeof(hit_by_value) - 1,
                                                          nullptr));
    CHECK(hit_by_value_res.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit_by_value_res.status_code, 204u);

    static const char hit_by_query_string[] =
        "GET /search?q=admin HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto hit_by_query_string_res =
        HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(hit_by_query_string),
                                      sizeof(hit_by_query_string) - 1,
                                      nullptr));
    CHECK(hit_by_query_string_res.action == HandlerAction::ReturnStatus);
    CHECK_EQ(hit_by_query_string_res.status_code, 204u);

    static const char miss[] = "GET /search HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto miss_res = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
    CHECK(miss_res.action == HandlerAction::ReturnStatus);
    CHECK_EQ(miss_res.status_code, 401u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_rejects_or_function_call_form) {
    const char* src =
        "route GET \"/users\" { let token = req.header(\"Authorization\") let x = or(token, \"\") "
        "return 200 }\n";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE_FALSE(ast);
    CHECK_EQ(static_cast<u8>(ast.error().code), static_cast<u8>(FrontendError::UnsupportedSyntax));
    CHECK(ast.error().detail.eq(lit("`or` is not Rut syntax; use `||`")));
}

TEST(jit, frontend_rejects_and_function_call_form) {
    const char* src =
        "route GET \"/users\" { let query = req.query(\"x\") let x = and(query, \"\") return 200 "
        "}\n";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE_FALSE(ast);
    CHECK_EQ(static_cast<u8>(ast.error().code), static_cast<u8>(FrontendError::UnsupportedSyntax));
    CHECK(ast.error().detail.eq(lit("`and` is not Rut syntax; use `&&`")));
}

TEST(jit, frontend_accepts_double_ampersand_operator) {
    const char* src = "route GET \"/users\" { let value = true && false return 200 }\n";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
}

TEST(jit, frontend_accepts_double_pipe_operator) {
    const char* src = "route GET \"/users\" { let value = true || false return 200 }\n";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
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

TEST(jit, frontend_req_body_without_content_length_does_not_expose_trailing_data) {
    const char* src =
        "route POST \"/upload\" { let b = req.body if b == \"ping\" { return 204 } else { return "
        "400 } }\n";

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

    // Without a Content-Length the trailing octets are the next pipelined
    // keep-alive request, not this request's body. They must not surface as
    // req.body, so "ping" is invisible and the handler falls through to 400.
    static const char trailing[] = "POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\nping";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(trailing), sizeof(trailing) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 400);

    static const char missing[] = "POST /upload HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(missing), sizeof(missing) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 400);

    // With an explicit Content-Length the same octets are framed as the body
    // and become visible, confirming the gate above is the content-length,
    // not the absence of trailing bytes.
    static const char framed[] =
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nping";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(framed), sizeof(framed) - 1, nullptr));
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

TEST(jit, frontend_req_cookie_any_fallback) {
    const char* src =
        "route GET \"/session\" { let sid = any(req.cookie(\"sid\"), \"\") if sid == \"ok\" { "
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

TEST(jit, frontend_req_cookie_all_requires_present_value_request_matrix) {
    const char* src =
        "route GET \"/session\" { let sid = all(req.cookie(\"sid\"), \"ok\") if sid == \"ok\" { "
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
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; sid=42; lang=en\r\n\r\n";
    auto r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(hit), sizeof(hit) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char miss[] =
        "GET /session HTTP/1.1\r\nHost: localhost\r\nCookie: theme=dark; lang=en\r\n\r\n";
    r = HandlerResult::unpack(
        handler(nullptr, nullptr, reinterpret_cast<const u8*>(miss), sizeof(miss) - 1, nullptr));
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
route GET "/users" { let state = AuthState.ok match state { .ok => return 200 _ => return 500 } }
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
func run<T: MaybeCode>(x: T) -> i32 => any(x.code(), 200)
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
func run<T: MaybeCode>(x: T) -> i32 => any(x.code(), 200)
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
    guard match failed else { .timeout => 401 _ => 500 }
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
route GET "/users" { let state = wrap(proto.Result<i32>.ok(1)) match state { .ok(v) => return 200 .err => return 500 } }
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
route GET "/users" { let state = wrap(proto.Result<proto.Box<proto.Result<i32>>>.ok(proto.Box<proto.Result<i32>>(value: proto.Result<i32>.ok(1)))) match state { .ok(v) => return 200 .err => return 500 } }
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
    .ok(v) => return 200
    .err => return 500
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
    .ready => return 200
    .pending => return 500
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

TEST(jit, frontend_req_header_alias_any_fallback) {
    const char* src =
        "route GET \"/users\" { let host = req.header(\"Host\") let alias = host let value = "
        "any(alias, \"fallback\") return 200 }\n";

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
        "route GET \"/users\" { let state = AuthState.timeout match state { .timeout => return "
        "200 _ => return 403 } }\n";

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
        "route GET \"/users\" { let path = req.path match path { \"/api/users\" => return 200 "
        "_ => return 404 } }\n";

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
        "route GET \"/users\" { let code = 200 match code { 200 if req.method == POST => "
        "return 500 _ => return 404 } }\n";

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
        200 if false => 201
        _ => 404
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
        .ok(code) if code == 200 => code
        _ => 404
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
        200 if error(.timeout, "timed out").code == 0 => 200
        _ => 500
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
    .ok =>
        match result {
        .ok => return 200
        _ => return 404
        }
    .denied =>
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
        "route GET \"/users\" { let state = Result.ok(200) match state { .ok(x) => return 200 "
        ".err => return 500 } }\n";

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
        "route GET \"/users\" { let state = Result.ok(200) match state { .ok(x) => if x == 200 "
        "{ return 200 } else { return 500 } .err => return 404 } }\n";

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
        "route GET \"/users\" { let state = Result.ok(200) match state { .ok(x) => { let y = x "
        "if y == 200 { return 200 } else { return 500 } } .err => return 404 } }\n";

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
        "route GET \"/users\" { let state = Result.ok(200) match state { .ok(x) => { let failed "
        "= error(7) guard let failed else { return 401 } if x == 200 { return 200 } else { return "
        "500 "
        "} } .err => return 404 } }\n";

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
        "route GET \"/users\" { let state = Result.ok(200) match state { .ok(x) => { let failed "
        "= error(.timeout) guard match failed else { .timeout => return 401 _ => return 402 "
        "} if x == 200 { return 200 } else { return 500 } } .err => return 404 } }\n";

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
        "route GET \"/users\" { let state = Result.ok(200) match const state { .ok(x) => if x "
        "== 200 { return 200 } else { return 500 } .err => return 404 } }\n";

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
        "route GET \"/users\" { let state = Mixed.ready(true) match state { .count(x) => return "
        "200 .ready(flag) => if flag == true { return 201 } else { return 202 } "
        ".label(name) => return 203 .none => return 204 } }\n";

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
        "route GET \"/users\" { let state = Result.ok((200, 500)) match state { .ok(pair) => { "
        "let code = pair | second(_2, _1) if code == 200 { return 200 } else { return 500 } } "
        ".err => return 404 } }\n";

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
    .ok(v) => return 200
    .err => return 500
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
    .some(v) => {
        if v.value == 200 { return 200 } else { return 500 }
    }
    .none => return 500
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
    .ok(v) => {
        let code = v | boxCode(_1)
        if code == 200 { return 200 } else { return 500 }
    }
    .err => return 500
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
    .ok(v) => {
        let code = v.inner.value
        if code == 200 { return 200 } else { return 500 }
    }
    .err => return 404
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
    .ok(v) => {
        let code = v | itemCode(_1)
        if code == 200 { return 200 } else { return 500 }
    }
    .err => return 500
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
    .ok(v) => return 200
    .err => return 500
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
        "route GET \"/users\" { let failed = error(.timeout) match failed { .timeout => return "
        "503 _ => return 200 } }\n";

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
    .timeout if allow => return 503
    _ => return 200
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
    .timeout if allow => return 503
    _ => return 200
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
        "route GET \"/users\" { let failed = error(AuthError.forbidden) match failed { "
        ".forbidden => return 403 _ => return 200 } }\n";

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
        "failed else { .timeout => return 503 _ => return 500 } return 200 }\n";

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
        "\"abc\", retry: 3) guard match failed else { .timeout => return 503 _ => return 500 "
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
        "500)) guard match failed else { .timeout => return 503 _ => return 500 } return 200 "
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
        "route GET \"/users\" { let ok = 200 guard let ok else { return 401 } let failed = "
        "error(7) "
        "guard let failed else { return 402 } return 200 }\n";

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
        "route GET \"/users\" { let state: Result<i32> = Result.ok(200) match state { .ok(v) => "
        "return 200 .err => return 500 } }\n";

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
        "route GET \"/users\" { let state = wrap(Result.ok(200)) match state { .ok(v) => return "
        "200 .err => return 500 } }\n";

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
        ".ok(v) => return 200 .err => return 500 } }\n";

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
    .wrap(inner) => {
        let copied = inner
        return 200
    }
    .bad =>
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
        "route GET \"/users\" { let state = Outer.wrap(Box(value: 200)) match state { "
        ".wrap(inner) => { let ok = is200(inner) if ok { return 200 } else { return 500 } } "
        ".bad => return 404 } }\n";

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
        "route GET \"/users\" { let ok = true if ok { let failed = error(7) guard let failed else "
        "{ "
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
        "route GET \"/users\" { let failed = error(7) guard let failed else { let code = 401 if "
        "code "
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
            "route GET \"/users\" { let failed = error(.timeout) guard match failed else { "
            ".timeout => return 503 _ => return 500 } return 200 }\n";

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
            "route GET \"/users\" { let ok = maybefail(true) guard match ok else { .timeout => "
            "return 503 _ => return 500 } return 200 }\n";

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

TEST(helpers, req_authorization_duplicate_is_ambiguous) {
    static const char req[] =
        "GET / HTTP/1.1\r\n"
        "Authorization: first\r\n"
        "authorization: second\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;
    rut_helper_req_header(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "Authorization", 13, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK(len == 0);
}

// Regression: a JIT handler primes the per-thread parse cache for its
// request buffer. After it returns, a direct rut_helper_req_* call that
// reuses the same buffer address+length with different bytes must reparse
// rather than return the handler's stale parse (the prime is cleared at
// handler exit).
TEST(helpers, parse_cache_not_stale_after_handler) {
    const char* src =
        "route GET \"/\" { let t = all(req.header(\"X-Tag\"), \"none\") if t == \"zzz\" { return "
        "201 } else { return 200 } }\n";
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

    // Two requests of identical length, differing only in the X-Tag value.
    char buf[] = "GET / HTTP/1.1\r\nX-Tag: aaa\r\n\r\n";
    static const char req2[] = "GET / HTTP/1.1\r\nX-Tag: bbb\r\n\r\n";
    REQUIRE(sizeof(buf) == sizeof(req2));
    const u32 buf_len = sizeof(buf) - 1;

    TestHandlerCtxFrame frame{};
    // Run the handler: it primes the parse cache for `buf`.
    handler(nullptr, &frame.ctx, reinterpret_cast<const u8*>(buf), buf_len, nullptr);

    // Reuse the same address+length with different content, then read a
    // header directly. Must observe the new value, not the primed parse.
    for (u32 i = 0; i < buf_len; i++) buf[i] = req2[i];
    u8 has = 0;
    const char* ptr = nullptr;
    u32 vlen = 0;
    rut_helper_req_header(reinterpret_cast<const u8*>(buf), buf_len, "X-Tag", 5, &has, &ptr, &vlen);
    CHECK(has == 1);
    REQUIRE(vlen == 3);
    REQUIRE(ptr != nullptr);
    CHECK(ptr[0] == 'b');
    CHECK(ptr[1] == 'b');
    CHECK(ptr[2] == 'b');

    engine.shutdown();
    rir.destroy();
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

TEST(helpers, rate_limit_key_matches_request_extractor_identity) {
    static const char req[] =
        "GET /search?=rotating&UID=rotating&uid=fixed HTTP/1.1\r\n"
        "X-Key: fixed \t\r\n"
        "Cookie: =rotating\r\n"
        "Cookie: SID=rotating\r\n"
        "Cookie: sid=fixed \t\r\n"
        "\r\n";
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;

    rut_helper_req_header(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "X-Key", 5, &has, &ptr, &len);
    REQUIRE(has == 1);
    REQUIRE_EQ(len, 5u);
    CHECK((Str{ptr, len}.eq(Str{"fixed", 5})));
    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "uid", 3, &has, &ptr, &len);
    REQUIRE(has == 1);
    REQUIRE_EQ(len, 5u);
    CHECK((Str{ptr, len}.eq(Str{"fixed", 5})));
    has = 1;
    rut_helper_req_query(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "", 0, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "sid", 3, &has, &ptr, &len);
    REQUIRE(has == 1);
    REQUIRE_EQ(len, 5u);
    CHECK((Str{ptr, len}.eq(Str{"fixed", 5})));
    has = 1;
    rut_helper_req_cookie(
        reinterpret_cast<const u8*>(req), sizeof(req) - 1, "", 0, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);

    static const char malformed[] =
        "GET /search?uid=rotating HTTP/1.1\r\n"
        "Bad Header\r\n"
        "\r\n";
    has = 1;
    ptr = reinterpret_cast<const char*>(0x1);
    len = 99;
    rut_helper_req_query(
        reinterpret_cast<const u8*>(malformed), sizeof(malformed) - 1, "uid", 3, &has, &ptr, &len);
    CHECK(has == 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);

    TestHandlerCtxFrame frame{};
    static const char upper_name[] = "ID";
    static const char lower_name[] = "id";
    static const char rotating[] = "rotating";
    static const char fixed[] = "fixed";
    frame.ctx.route_param_count = 2;
    frame.ctx.route_params[0] = {upper_name, 2, rotating, 8};
    frame.ctx.route_params[1] = {lower_name, 2, fixed, 5};
    rut_helper_req_param(&frame.ctx, "id", 2, &ptr, &len);
    REQUIRE_EQ(len, 5u);
    CHECK((Str{ptr, len}.eq(Str{"fixed", 5})));

    RateLimitKeyInput input{};
    input.req_buf = reinterpret_cast<const u8*>(req);
    input.req_header_end = sizeof(req) - 1;
    input.params = frame.ctx.route_params;
    input.param_count = frame.ctx.route_param_count;
    RateLimitKeyComponent components[4]{};
    components[0].kind = RateLimitKeyKind::Header;
    components[0].set_name("X-Key", 5);
    components[1].kind = RateLimitKeyKind::Query;
    components[1].set_name("uid", 3);
    components[2].kind = RateLimitKeyKind::Cookie;
    components[2].set_name("sid", 3);
    components[3].kind = RateLimitKeyKind::Param;
    components[3].set_name("id", 2);
    const u64 key = rate_limit_key(0, components, 4, input);

    static const char canonical[] =
        "GET /search?uid=fixed HTTP/1.1\r\n"
        "X-Key: fixed\r\n"
        "Cookie: sid=fixed\r\n"
        "\r\n";
    RateLimitKeyInput canonical_input = input;
    canonical_input.req_buf = reinterpret_cast<const u8*>(canonical);
    canonical_input.req_header_end = sizeof(canonical) - 1;
    CHECK_EQ(key, rate_limit_key(0, components, 4, canonical_input));
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

struct RegexScratchExitThreadState {
    void* db = nullptr;
    u8 matched = 0;
};

static void* regex_scratch_exit_thread(void* arg) {
    auto* state = static_cast<RegexScratchExitThreadState*>(arg);
    state->matched = rut_helper_str_regex_match("/worker", 7, state->db);
    return nullptr;
}

TEST(helpers, str_regex_scratch_cache_is_reclaimed_on_thread_exit) {
    if (!rut_helper_regex_backend_available()) SKIP("vectorscan backend not available");

    void* db = rut_helper_regex_compile("^/worker$", 9);
    REQUIRE(db != nullptr);
    const u32 cache_count_before = rut_helper_regex_scratch_cache_count_for_test();
    RegexScratchExitThreadState state{db};
    pthread_t thread{};
    REQUIRE(pthread_create(&thread, nullptr, regex_scratch_exit_thread, &state) == 0);
    REQUIRE(pthread_join(thread, nullptr) == 0);
    CHECK(state.matched == 1);
    CHECK(rut_helper_regex_scratch_cache_count_for_test() == cache_count_before);
    rut_helper_regex_free(db);
}

struct RegexScratchPruneThreadState {
    void* db = nullptr;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    bool warmed = false;
    bool pruned = false;
    u32 warm_count = 0;
    u32 final_count = 0;
    u8 matched = 0;

    ~RegexScratchPruneThreadState() {
        pthread_cond_destroy(&condition);
        pthread_mutex_destroy(&mutex);
    }
};

static void* regex_scratch_prune_thread(void* arg) {
    auto* state = static_cast<RegexScratchPruneThreadState*>(arg);
    state->matched = rut_helper_str_regex_match("/worker", 7, state->db);
    state->warm_count = rut_helper_regex_scratch_cache_entry_count_for_test();
    pthread_mutex_lock(&state->mutex);
    state->warmed = true;
    pthread_cond_signal(&state->condition);
    while (!state->pruned) pthread_cond_wait(&state->condition, &state->mutex);
    pthread_mutex_unlock(&state->mutex);
    state->final_count = rut_helper_regex_scratch_cache_entry_count_for_test();
    return nullptr;
}

TEST(helpers, str_regex_free_prunes_other_thread_scratch_cache) {
    if (!rut_helper_regex_backend_available()) SKIP("vectorscan backend not available");

    void* db = rut_helper_regex_compile("^/worker$", 9);
    REQUIRE(db != nullptr);

    RegexScratchPruneThreadState state{};
    state.db = db;

    pthread_t thread{};
    REQUIRE(pthread_create(&thread, nullptr, regex_scratch_prune_thread, &state) == 0);
    pthread_mutex_lock(&state.mutex);
    while (!state.warmed) pthread_cond_wait(&state.condition, &state.mutex);

    CHECK(state.matched == 1);
    CHECK(state.warm_count == 1);
    rut_helper_regex_free(db);
    state.pruned = true;
    pthread_cond_signal(&state.condition);
    pthread_mutex_unlock(&state.mutex);

    REQUIRE(pthread_join(thread, nullptr) == 0);
    CHECK(state.final_count == 0);
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

TEST(result, pack_unpack_forward_bundle_preserves_16bit_ids) {
    auto r = HandlerResult::make_forward_with_bundle(0xFFFFu, 0xFFFFu, 0xFFFFu);
    auto r2 = HandlerResult::unpack(r.pack());
    CHECK(r2.action == HandlerAction::ForwardBundle);
    CHECK(r2.upstream_id == 0xFFFFu);
    CHECK(r2.status_code == 0xFFFFu);
    CHECK(r2.next_state == 0xFFFFu);
    auto legacy = HandlerResult::make_forward_with_policies(0xFFFFu, 0xFFFFu, 0xFFFFu);
    auto legacy2 = HandlerResult::unpack(legacy.pack());
    CHECK(legacy2.action == HandlerAction::Forward);
    CHECK(legacy2.upstream_id == 0xFFFFu);
    CHECK(legacy2.status_code == 0xFFFFu);
    CHECK(legacy2.next_state == 0xFFFFu);
}

static u64 test_forward_bundle_handler(void*, HandlerCtx*, const u8*, u32, void*) {
    return HandlerResult::make_forward_with_bundle(7, 9, 11).pack();
}

TEST(jit_dispatch, forward_bundle_keeps_request_and_bundle_ids_independent) {
    HandlerCtx ctx{};
    auto out = invoke_jit_handler(&test_forward_bundle_handler, nullptr, ctx, nullptr, 0, nullptr);
    CHECK(out.kind == JitDispatchOutcome::Kind::Forward);
    CHECK(out.upstream_id == 7);
    CHECK(out.request_policy_id == 9);
    CHECK(out.policy_bundle_id == 11);
    CHECK(out.response_policy_id == 0);
}

TEST(jit, compiled_failure_only_forward_bundle_preserves_zero_response_id) {
    const char* src =
        "upstream b\nroute GET \"/\" { return forward(b, load_balance: .roundRobin, "
        "failure_policy: { version: .http11, "
        "status: 502, reason: \"Bad Gateway\", content_type: \"text/plain\", server: \"nginx\", "
        "date: .current, connection: .request, body: b\"x\" }) }\n";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    const auto raw = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
    CHECK(raw.action == HandlerAction::ForwardBundle);
    CHECK(raw.status_code == 0);
    CHECK(raw.next_state == 1);
    HandlerCtx ctx{};
    auto out = invoke_jit_handler(handler, nullptr, ctx, nullptr, 0, nullptr);
    CHECK(out.kind == JitDispatchOutcome::Kind::Forward);
    CHECK(out.request_policy_id == 0);
    CHECK(out.policy_bundle_id == 1);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, compiled_timeout_failure_policy_preserves_single_packed_bundle_id) {
    const char* src = R"rut(
upstream b
route GET "/" {
    return forward(b, load_balance: .roundRobin, response_policy: {
        version: .http11, framing: .contentLength, connection: .request,
        server: "s", date: .current, hide_headers: []
    }, failure_policy: {
        version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "s", date: .current,
        connection: .request, body: b"bad"
    }, timeout_failure_policy: {
        version: .http11, status: 504, reason: "Gateway Time-out",
        content_type: "text/plain", server: "s", date: .current,
        connection: .request, body: b"slow"
    })
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
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].timeout_failure_policy_id, 2u);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    const auto raw = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
    CHECK(raw.action == HandlerAction::ForwardBundle);
    CHECK_EQ(raw.next_state, 1u);
    HandlerCtx ctx{};
    const auto out = invoke_jit_handler(handler, nullptr, ctx, nullptr, 0, nullptr);
    CHECK(out.kind == JitDispatchOutcome::Kind::Forward);
    CHECK_EQ(out.policy_bundle_id, 1u);
    CHECK_EQ(out.timeout_failure_policy_id, 0u);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, compiled_response_read_timeout_preserves_single_bundle_and_request_policy_abi) {
    const char source[] = R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" {
    return forward(b, load_balance: .roundRobin, request_policy: {
        version: .http11, host: .upstream, connection: .omit,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
    }, response_policy: {
        version: .http11, framing: .contentLength, connection: .request,
        server: "rut", date: .current, hide_headers: []
    }, response_read_timeout: 7s)
}
route GET "/later" { return 204 }
)rut";
    auto lexed = lex(lit(source));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
    REQUIRE_EQ(rir.module.func_count, 2u);
    CHECK_EQ(rir.module.functions[0].preflight_forward_policy_bundle_id, 1u);
    CHECK_EQ(rir.module.functions[1].preflight_forward_policy_bundle_id, 0u);
    CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 0u);
    CHECK_EQ(rir.module.policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(rir.module.policy_bundles[0].response_read_timeout_seconds, 7u);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    const auto raw = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
    CHECK(raw.action == HandlerAction::ForwardBundle);
    CHECK_EQ(raw.status_code, 1u);
    CHECK_EQ(raw.next_state, 1u);
    HandlerCtx ctx{};
    const auto out = invoke_jit_handler(handler, nullptr, ctx, nullptr, 0, nullptr);
    CHECK(out.kind == JitDispatchOutcome::Kind::Forward);
    CHECK_EQ(out.request_policy_id, 1u);
    CHECK_EQ(out.policy_bundle_id, 1u);
    CHECK_EQ(out.response_read_timeout_seconds, 0u);

    auto config = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*config, rir.module));
    REQUIRE_EQ(config->response_policy_count, 1u);
    config->response_policy_count = 0;
    REQUIRE(config->use_segment_trie());
    CHECK_FALSE(register_jit_routes(*config, rir.module, engine));
    CHECK_EQ(config->route_count, 0u);
    CHECK_EQ(config->timer_count, 0u);
    CHECK(config->dispatch_kind() == RouteConfig::DispatchKind::SegmentTrie);
    config->response_policy_count = 1;
    REQUIRE(config->use_art());

    config->policy_bundles[0].response_read_timeout_seconds = 6;
    CHECK_FALSE(register_jit_routes(*config, rir.module, engine));
    CHECK_EQ(config->route_count, 0u);
    CHECK_EQ(config->timer_count, 0u);
    config->policy_bundles[0].response_read_timeout_seconds = 7;

    const Str saved_pattern = rir.module.functions[1].route_pattern;
    rir.module.functions[1].route_pattern = {"/bad?x", 6};
    CHECK_FALSE(register_jit_routes(*config, rir.module, engine));
    CHECK_EQ(config->route_count, 0u);
    CHECK_EQ(config->timer_count, 0u);
    rir.module.functions[1].route_pattern = saved_pattern;
    REQUIRE(register_jit_routes(*config, rir.module, engine));
    REQUIRE_EQ(config->route_count, 2u);
    CHECK_EQ(config->routes[0].preflight_forward_policy_bundle_id, 1u);
    CHECK_EQ(config->routes[1].preflight_forward_policy_bundle_id, 0u);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, compiled_response_buffering_reaches_config_without_changing_handler_result_abi) {
    const char source[] = R"rut(
upstream b at "127.0.0.1:9000"
route POST "/" {
    return forward(b, load_balance: .roundRobin,
        request_policy: { version: .http11, host: .upstream, connection: .omit,
            strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade] },
        response_policy: { version: .http11, framing: .contentLength,
            connection: .request, server: "s", date: .current, hide_headers: [] },
        failure_policy: { version: .http11, status: 502, reason: "Bad Gateway",
            content_type: "text/plain", server: "s", date: .current,
            connection: .request, body: b"bad" },
        timeout_failure_policy: { version: .http11, status: 504,
            reason: "Gateway Time-out", content_type: "text/plain", server: "s",
            date: .current, connection: .request, body: b"slow" },
        response_read_timeout: 1s,
        response_buffering: .completeContentLength)
}
)rut";
    for (const bool any_route : {false, true}) {
        std::string selected(source);
        if (any_route) {
            const auto method = selected.find("route POST");
            REQUIRE_NE(method, std::string::npos);
            selected.replace(method, sizeof("route POST") - 1u, "route");
        }
        const u8 expected_method = any_route ? kRouteMethodAny : kRouteMethodPost;
        auto lexed = lex({selected.data(), static_cast<u32>(selected.size())});
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap(ast.value());
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);
        FrontendRirModule rir{};
        REQUIRE(lower_to_rir(mir.value(), rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.func_count, 1u);
        CHECK_EQ(rir.module.functions[0].http_method, expected_method);
        REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
        static_assert(sizeof(ForwardPolicyBundle) == 8);
        static_assert(sizeof(HandlerResult::make_forward_with_bundle(0, 1, 1).pack()) ==
                      sizeof(u64));
        CHECK_EQ(rir.module.policy_bundles[0].response_buffering,
                 ForwardResponseBufferingMode::CompleteContentLength);

        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);
        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);
        const auto raw = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
        CHECK_EQ(raw.action, HandlerAction::ForwardBundle);
        CHECK_EQ(raw.status_code, 1u);
        CHECK_EQ(raw.upstream_id, 0u);
        CHECK_EQ(raw.next_state, 1u);
        HandlerCtx ctx{};
        const auto outcome = invoke_jit_handler(handler, nullptr, ctx, nullptr, 0, nullptr);
        CHECK_EQ(outcome.kind, JitDispatchOutcome::Kind::Forward);
        CHECK_EQ(outcome.request_policy_id, static_cast<u16>(RequestPolicyId::Http11FixedStrip));
        CHECK_EQ(outcome.policy_bundle_id, 1u);

        auto config = std::make_unique<RouteConfig>();
        REQUIRE(populate_route_config(*config, rir.module));
        REQUIRE_EQ(config->policy_bundle_count, 1u);
        CHECK_EQ(config->policy_bundles[0].response_buffering,
                 ForwardResponseBufferingMode::CompleteContentLength);
        config->policy_bundles[0].response_buffering = ForwardResponseBufferingMode::None;
        CHECK_FALSE(register_jit_routes(*config, rir.module, engine));
        CHECK_EQ(config->route_count, 0u);
        config->policy_bundles[0].response_buffering =
            ForwardResponseBufferingMode::CompleteContentLength;
        REQUIRE(register_jit_routes(*config, rir.module, engine));
        REQUIRE_EQ(config->route_count, 1u);
        CHECK_EQ(config->routes[0].method, expected_method);
        CHECK_EQ(config->routes[0].preflight_forward_policy_bundle_id, 1u);
        engine.shutdown();
        rir.destroy();
    }
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
        "route GET \"/users\" { let foo = Foo(state: AuthState.timeout) match foo.state { "
        ".timeout => return 200 _ => return 403 } }\n";

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

TEST(jit, target_transform_effect_records_and_fails_closed) {
    TestContext tc;
    REQUIRE(tc.init());
    Builder b;
    b.init(&tc.mod);

    auto add = [&](const char* name, i32 encoded_id, bool duplicate) {
        auto* fn = V(b.create_function(lit(name), lit("/"), 'G'));
        auto entry = V(b.create_block(fn, lit("entry")));
        b.set_insert_point(fn, entry);
        VOK(b.emit_req_set_target_transform(1));
        fn->entry()->insts[0].imm.i32_val = encoded_id;
        if (duplicate) VOK(b.emit_req_set_target_transform(1));
        auto upstream = V(b.emit_const_i32(3));
        VOK(b.emit_ret_forward(upstream));
    };
    add("proxy_transform_valid", 1, false);
    add("proxy_transform_zero", 0, false);
    add("proxy_transform_wide", static_cast<i32>(kMaxForwardTargetTransforms + 1), false);
    add("proxy_transform_duplicate", 1, true);

    auto* bounds = V(b.create_function(lit("proxy_transform_bounds"), lit("/"), 'G'));
    auto bounds_entry = V(b.create_block(bounds, lit("entry")));
    b.set_insert_point(bounds, bounds_entry);
    CHECK_FALSE(b.emit_req_set_target_transform(0));
    CHECK_FALSE(b.emit_req_set_target_transform(kMaxForwardTargetTransforms + 1));
    auto upstream = V(b.emit_const_i32(3));
    VOK(b.emit_ret_forward(upstream));

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    const char* names[] = {"handler_proxy_transform_valid",
                           "handler_proxy_transform_zero",
                           "handler_proxy_transform_wide",
                           "handler_proxy_transform_duplicate"};
    const u16 ids[] = {1,
                       kInvalidForwardTargetTransformId,
                       kInvalidForwardTargetTransformId,
                       kInvalidForwardTargetTransformId};
    for (u32 i = 0; i < 4; i++) {
        Connection conn;
        conn.reset();
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(names[i]));
        REQUIRE(handler != nullptr);
        const auto result =
            HandlerResult::unpack(handler(&conn,
                                          nullptr,
                                          reinterpret_cast<const u8*>(kGetApiRequest),
                                          sizeof(kGetApiRequest) - 1,
                                          nullptr));
        CHECK(result.action == HandlerAction::Forward);
        CHECK(conn.target_transform_recorded);
        CHECK_EQ(conn.target_transform_id, ids[i]);
    }

    engine.shutdown();
    tc.destroy();
}

TEST(jit, ret_forward_request_policy_abi_fails_closed) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);
    auto add = [&](const char* name, bool wide, i64 value) {
        auto* fn = V(b.create_function(lit(name), lit("/"), 'G'));
        auto entry = V(b.create_block(fn, lit("entry")));
        b.set_insert_point(fn, entry);
        auto upstream = V(b.emit_const_i32(7));
        auto policy =
            wide ? V(b.emit_const_i64(value)) : V(b.emit_const_i32(static_cast<i32>(value)));
        VOK(b.emit_ret_forward(upstream, policy));
    };
    add("proxy_policy_valid", false, 1);
    add("proxy_policy_u16_overflow", false, 256);
    add("proxy_policy_negative", false, -1);
    add("proxy_policy_i64_overflow", true, 65536);

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    const char* names[] = {"handler_proxy_policy_valid",
                           "handler_proxy_policy_u16_overflow",
                           "handler_proxy_policy_negative",
                           "handler_proxy_policy_i64_overflow"};
    const u16 policies[] = {1, 256, 0xffffu, 0xffffu};
    for (u32 i = 0; i < 4; i++) {
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(names[i]));
        REQUIRE(handler != nullptr);
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(kGetApiRequest),
                                          sizeof(kGetApiRequest) - 1,
                                          nullptr));
        CHECK(result.action == HandlerAction::Forward);
        CHECK_EQ(result.upstream_id, 7u);
        CHECK_EQ(result.status_code, policies[i]);
    }

    engine.shutdown();
    tc.destroy();
}

TEST(jit, ret_forward_response_policy_abi_uses_next_state_and_fails_closed) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);
    auto add = [&](const char* name, i32 request_value, bool wide, i64 value) {
        auto* fn = V(b.create_function(lit(name), lit("/"), 'G'));
        auto entry = V(b.create_block(fn, lit("entry")));
        b.set_insert_point(fn, entry);
        auto upstream = V(b.emit_const_i32(7));
        auto request = V(b.emit_const_i32(request_value));
        auto response =
            wide ? V(b.emit_const_i64(value)) : V(b.emit_const_i32(static_cast<i32>(value)));
        VOK(b.emit_ret_forward(upstream, request, response));
    };
    add("proxy_response_policy_valid", 7, false, 1);
    add("proxy_response_policy_u16_boundary", 9, false, 256);
    add("proxy_response_policy_u16_overflow", 11, false, 65536);
    add("proxy_response_policy_negative", 13, false, -1);
    add("proxy_response_policy_i64_overflow", 15, true, 0x100000000LL);

    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    const char* names[] = {"handler_proxy_response_policy_valid",
                           "handler_proxy_response_policy_u16_boundary",
                           "handler_proxy_response_policy_u16_overflow",
                           "handler_proxy_response_policy_negative",
                           "handler_proxy_response_policy_i64_overflow"};
    const u16 request_policies[] = {7, 9, 11, 13, 15};
    const u16 response_policies[] = {1, 256, 0xffffu, 0xffffu, 0xffffu};
    for (u32 i = 0; i < 5; i++) {
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(names[i]));
        REQUIRE(handler != nullptr);
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(kGetApiRequest),
                                          sizeof(kGetApiRequest) - 1,
                                          nullptr));
        CHECK(result.action == HandlerAction::Forward);
        CHECK_EQ(result.upstream_id, 7u);
        CHECK_EQ(result.status_code, request_policies[i]);
        CHECK_EQ(result.next_state, response_policies[i]);
    }
    auto dispatch_handler = reinterpret_cast<HandlerFn>(engine.lookup(names[0]));
    jit::HandlerCtx dispatch_ctx{};
    auto dispatch = invoke_jit_handler(dispatch_handler,
                                       nullptr,
                                       dispatch_ctx,
                                       reinterpret_cast<const u8*>(kGetApiRequest),
                                       sizeof(kGetApiRequest) - 1,
                                       nullptr);
    CHECK(dispatch.kind == JitDispatchOutcome::Kind::Forward);
    CHECK_EQ(dispatch.request_policy_id, 7u);
    CHECK_EQ(dispatch.response_policy_id, 1u);

    engine.shutdown();
    tc.destroy();
}

TEST(jit, ret_forward_response_policy_builder_rejects_noncontiguous_and_invalid_atomically) {
    TestContext tc;
    REQUIRE(tc.init());

    Builder b;
    b.init(&tc.mod);
    auto* fn = V(b.create_function(lit("proxy_response_policy_builder"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);
    auto upstream = V(b.emit_const_i32(7));
    auto request = V(b.emit_const_i32(1));
    auto response = V(b.emit_const_i32(1));
    const u32 before = fn->blocks[entry.id].inst_count;

    auto response_only = b.emit_ret_forward(upstream, rir::kNoValue, response);
    CHECK_FALSE(response_only.has_value());
    CHECK_EQ(fn->blocks[entry.id].inst_count, before);

    const u32 before_invalid = fn->blocks[entry.id].inst_count;
    auto invalid = b.emit_ret_forward(upstream, request, ValueId{0xfffffffeu});
    CHECK_FALSE(invalid.has_value());
    CHECK_EQ(fn->blocks[entry.id].inst_count, before_invalid);

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
    .ok(v) => return 200
    .err => return 500
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
    .some(box) => {
        if box.value == 200 { return 200 } else { return 500 }
    }
    .none =>
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
    .some(v) => v.hash()
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
    .ok(v) => return 200
    .err => return 500
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
        out << "func pick(ok: bool) -> i32 => any(maybe(ok), 500)\n";
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
        out << "        .ok => 200\n";
        out << "        .err => 500\n";
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
    .ok(v) => return 200
    .err => return 500
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
    .ok(v) => return 200
    .err => return 500
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
    .some(box) => {
        if box.value == 200 { return 200 } else { return 500 }
    }
    .none =>
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
    .ok(v) => return 200
    .err => return 500
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
    let code = any(Box(value: 7).code(), 200)
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
    let code = any(Box(value: 7).code(), 200)
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
        guard let y else { 401 }
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
        guard match y else { .timeout => 401 _ => 500 }
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
    let code = any(Box(value: 7).code(), 200)
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
    let code = any(Box(value: 7).code(), 200)
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
    let code = any(Box(value: 7).code(), 200)
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
    let code = any(Box(value: 7).code(), 200)
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
func run<T: MaybeCode>(x: T) -> i32 => any(x.code(), 200)
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
func run<T: MaybeCode>(x: T) -> i32 => any(x.code(), 200)
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
func run<T: MaybeCode>(x: T) -> i32 => any(x.code(), 200)
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
func run<T: MaybeCode>(x: T) -> i32 => any(x.code(), 200)
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
    .ok => return 200
    _ => return 500
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
    .ok => return 200
    _ => return 500
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
    let code = any(maybe(), 200)
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
    let code = any(maybe(), 200)
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
    let code = any(maybe(true), 200)
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
    let code = any(fail(), 200)
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
    let code = any(fail(), 200)
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
    let code = any(maybefail(true), 200)
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
    let code = any(maybe(true), 200)
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
    guard let y else { 401 }
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
    guard match y else { .timeout => 401 _ => 500 }
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
        .ok => 200
        .err => 500
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
        .ok => { let y = 200 y }
        .err => { let z = 500 z }
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
        .ok => 200
        .err => nil
    }
}
route GET "/users" {
    let code = any(pick(Result.ok), 200)
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
        .ok => 200
        .err => error(.timeout)
    }
}
route GET "/users" {
    let code = any(pick(Result.ok), 200)
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
        .ok => error(.timeout)
        .err => error(.timeout)
    }
}
route GET "/users" {
    let code = any(pick(Result.ok), 200)
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

TEST(jit, frontend_pipe_method_stage_runtime_optional_lhs_flows_via_any) {
    const auto src = R"(
route GET "/users" {
    let ok = req.header("X-Missing") | _.eq("example.com")
    let safe = any(ok, true)
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
    let safe = any(code, 500)
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

TEST(jit, frontend_pipe_method_stage_reuses_analyzed_lhs_receiver) {
    const auto src = R"(
struct Box { value: i32 }
route GET "/users" {
    let box = Box(value: 200)
    let ok = box.value | _.eq(200)
    if ok { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    REQUIRE_EQ(hir->routes[0].locals.len, 2u);
    CHECK(hir->routes[0].locals[1].type == HirTypeKind::Bool);
    CHECK_FALSE(hir->routes[0].locals[1].may_nil);
    CHECK_FALSE(hir->routes[0].locals[1].may_error);
}

TEST(jit, frontend_pipe_method_stage_direct_dispatch_keeps_receiver_placeholder) {
    const auto src = R"(
protocol Ident { func id() -> i32 }
struct Box { value: i32 }
Box impl Ident {
    func id(self: Box) -> i32 => self.value
}
route GET "/users" {
    let box = Box(value: 200)
    let code = box | _.id()
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

TEST(jit, frontend_pipe_method_stage_known_nil_dispatches_protocol_method_shape) {
    const auto src = R"(
protocol MaybeCode { func code() -> i32 }
struct Box { value: i32 }
Box impl MaybeCode {
    func code(self: Box) -> i32 => self.value
}
route GET "/users" {
    let box: Box = nil
    let code = box | _.code()
    let safe = any(code, 500)
    if safe == 200 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    REQUIRE_EQ(hir->routes[0].locals.len, 3u);
    CHECK(hir->routes[0].locals[1].type == HirTypeKind::I32);
    CHECK(hir->routes[0].locals[1].may_nil);
    CHECK_FALSE(hir->routes[0].locals[1].may_error);
    CHECK(hir->routes[0].locals[2].type == HirTypeKind::I32);
    CHECK_FALSE(hir->routes[0].locals[2].may_nil);
    CHECK_FALSE(hir->routes[0].locals[2].may_error);
}
TEST(jit, frontend_pipe_method_stage_known_nil_falls_back_via_any) {
    const auto src = R"(
protocol MaybeCode { func code() -> i32 }
struct Box { value: i32 }
Box impl MaybeCode {
    func code(self: Box) -> i32 => self.value
}
route GET "/users" {
    let box: Box = nil
    let code = box | _.code()
    let safe = any(code, 500)
    if safe == 500 { return 200 } else { return 500 }
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
TEST(jit, frontend_pipe_tuple_stage_then_method_stage) {
    const auto src = R"(
protocol HasValue { func as_value() -> i32 }
struct Box { value: i32 }
Box impl HasValue {
    func as_value(self: Box) -> i32 => self.value
}
func build_box(a: i32, b: i32) -> Box => Box(value: b)
route GET "/users" {
    let code = (200, 500) | build_box(_1, _2) | _.as_value()
    if code == 500 { return 200 } else { return 500 }
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
TEST(jit, frontend_pipe_tuple_slot_reuse_keeps_placeholder_semantics) {
    const auto src = R"(
protocol HasValue { func as_value() -> i32 }
struct Box { value: i32 }
Box impl HasValue {
    func as_value(self: Box) -> i32 => self.value
}
func build_box(a: i32, b: i32) -> Box => Box(value: a)
route GET "/users" {
    let code = (200, 500) | build_box(_1, _1) | _.as_value()
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
    CHECK(ast.error().detail.eq(lit("placeholder index must be between _1 and _10")));
}

TEST(jit, frontend_pipe_with_non_unit_placeholder_is_rejected) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = 200 | id(_2)
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
    CHECK(hir.error().detail.eq(lit("non-tuple source with non-unit placeholder")));
}
TEST(jit, frontend_pipe_keeps_placeholder_slot_zero_identifier_scalar) {
    const auto src = R"(
func second(x: i32, y: i32) -> i32 => y
route GET "/users" {
    let _0 = 204
    let code = 200 | second(_, _0)
    if code == 204 { return 200 } else { return 500 }
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
TEST(jit, frontend_pipe_with_tuple_placeholder_slot_exceeds_tuple_arity_is_rejected) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = (200, 500) | id(_3)
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
    CHECK(hir.error().detail.eq(lit("placeholder slot exceeds tuple arity")));
}
TEST(jit, frontend_pipe_keeps_placeholder_slot_zero_identifier_tuple) {
    const auto src = R"(
func second(x: i32, y: i32) -> i32 => y
route GET "/users" {
    let _0 = 204
    let code = (200, 500) | second(_1, _0)
    if code == 204 { return 200 } else { return 500 }
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
TEST(jit, frontend_pipe_runtime_fallible_lhs_slot_two_is_rejected_with_detail) {
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
    CHECK(hir.error().detail.eq(lit("placeholder value in conditional pipe must be 1")));
}
TEST(jit, frontend_pipe_conditional_return_type_unsupported_is_rejected) {
    const auto src = R"(
func may_fail(ok: bool) -> i32 {
    if ok { 200 } else { error(.timeout) }
}
func pair(x: i32) -> (i32, i32) => (x, 500)
route GET "/users" {
    let code = may_fail(req.http11) | pair(_)
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
    CHECK(hir.error().detail.eq(lit("pipe return type unsupported")));
}
TEST(jit, frontend_pipe_conditional_error_variant_mismatch_is_rejected) {
    const auto src = R"(
func may_fail(ok: bool) -> i32 {
    if ok { 200 } else { error(.timeout) }
}
func maybe_forbidden(x: i32) -> i32 {
    if x == 200 { x } else { error(.forbidden) }
}
route GET "/users" {
    let code = may_fail(req.http11) | maybe_forbidden(_)
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
    CHECK(hir.error().detail.eq(lit("pipe error variant mismatch")));
}
TEST(jit, frontend_pipe_conditional_with_non_unit_placeholder_is_rejected) {
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
    CHECK(hir.error().detail.eq(lit("placeholder value in conditional pipe must be 1")));
}
TEST(jit, frontend_pipe_conditional_keeps_placeholder_slot_zero_identifier) {
    const auto src = R"(
func choose(x: str, y: str) -> str => y
route GET "/users" {
    let _0 = "fallback"
    let value = req.header("Host") | choose(_, _0)
    let safe = any(value, "")
    if safe == "fallback" { return 200 } else { return 500 }
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
TEST(jit, frontend_pipe_conditional_missing_later_custom_constraint_is_rejected) {
    const auto src = R"(
protocol First {}
protocol Second {}
str impl First {}
func requireBoth<T>(x: T) -> i32 where First(T), Second(T) => 200
route GET "/users" {
    let code = req.header("Host") | requireBoth(_)
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
TEST(jit, frontend_pipe_without_placeholder_is_rejected) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = 200 | id(200)
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
TEST(jit, frontend_pipe_with_non_stage_rhs_is_rejected) {
    const auto src = R"(
route GET "/users" {
    let code = 200 | 404
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
    CHECK(hir.error().detail.eq(lit("pipe rhs must be a call stage or _.method(...) stage")));
}
TEST(jit, frontend_pipe_method_stage_runtime_optional_tuple_return_is_rejected) {
    const auto src = R"(
protocol Pairable { func pair() -> (i32, i32) }
struct Box { value: i32 }
Box impl Pairable {
    func pair(self: Box) -> (i32, i32) => (self.value, 500)
}
func maybeBox(ok: bool) -> Box {
    if ok { Box(value: 200) } else { nil }
}
route GET "/users" {
    let pair = maybeBox(req.http11) | _.pair()
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
    CHECK(
        hir.error().detail.eq(lit("pipe method stage with nil/error propagation must return bool, "
                                  "i32, str, variant, or struct")));
}
TEST(jit, frontend_pipe_method_stage_slot_two_is_rejected) {
    const auto src = R"(
route GET "/users" {
    let code = 200 | _2.eq(200)
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
    CHECK(hir.error().detail.eq(lit("non-tuple source with non-unit placeholder")));
}
TEST(jit, frontend_pipe_method_stage_known_nil_typed_cmp_mismatch_is_rejected) {
    const auto src = R"(
route GET "/users" {
    let code: i32 = nil
    let ok = code | _.eq("200")
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
TEST(jit, frontend_pipe_method_stage_known_nil_typed_matches_non_string_receiver_is_rejected) {
    const auto src = R"(
route GET "/users" {
    let code: i32 = nil
    let ok = code | _.matches(re"2")
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
#if RUT_VALIDATE_REGEX_WITH_VECTORSCAN
TEST(jit, frontend_pipe_method_stage_known_nil_validates_regex) {
    const auto src = R"(
route GET "/users" {
    let ok = nil | _.matches(re"[")
    let safe = any(ok, false)
    if safe { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE_FALSE(hir.has_value());
    CHECK_EQ(hir.error().code, FrontendError::InvalidRegex);
}
#endif
#if RUT_VALIDATE_REGEX_WITH_VECTORSCAN
TEST(jit, frontend_pipe_method_stage_runtime_source_validates_regex) {
    const auto src = R"(
route GET "/users" {
    let ok = req.path | _.matches(re"[")
    let safe = any(ok, false)
    if safe { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE_FALSE(hir.has_value());
    CHECK_EQ(hir.error().code, FrontendError::InvalidRegex);
}
#endif
TEST(jit, frontend_pipe_method_stage_known_nil_tuple_return_is_rejected) {
    const auto src = R"(
protocol Pairable { func pair() -> (i32, i32) }
struct Box { value: i32 }
Box impl Pairable {
    func pair(self: Box) -> (i32, i32) => (self.value, 500)
}
func maybe_box(ok: bool) -> Box {
    if ok { Box(value: 200) } else { nil }
}
route GET "/users" {
    let box = maybe_box(req.http11) | _.pair()
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
    CHECK(
        hir.error().detail.eq(lit("pipe method stage with nil/error propagation must return bool, "
                                  "i32, str, variant, or struct")));
}
TEST(jit, frontend_pipe_method_stage_known_error_tuple_return_is_rejected) {
    const auto src = R"(
protocol Pairable { func pair() -> (i32, i32) }
struct Box { value: i32 }
Box impl Pairable {
    func pair(self: Box) -> (i32, i32) => (self.value, 500)
}
route GET "/users" {
    let box: Box = error(.timeout)
    let pair = box | _.pair()
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
    CHECK(
        hir.error().detail.eq(lit("pipe method stage with nil/error propagation must return bool, "
                                  "i32, str, variant, or struct")));
}
TEST(jit, frontend_pipe_different_error_variants_in_method_stage_is_rejected) {
    const auto src = R"(
struct Box { value: i32 }
struct AuthError { err: Error, token: str }
protocol MaybeFail { func failstage() -> Box }
Box impl MaybeFail {
    func failstage(self: Box) -> Box => error(.forbidden)
}
func maybe_box(ok: bool) -> Box {
    if ok { Box(value: 200) } else { error(AuthError, .timeout, "timed out", token: "abc") }
}
route GET "/users" {
    let box = maybe_box(req.http11) | _.failstage()
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
    CHECK(hir.error().detail.eq(
        lit("pipe method stage cannot combine different propagated error variants")));
}
TEST(jit, frontend_pipe_method_stage_known_error_accesses_standard_error_field_shape) {
    const auto src = R"(
route GET "/users" {
    let failed = error(.timeout)
    let code = failed | _.code()
    let safe = any(code, 500)
    if safe == 500 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    REQUIRE_EQ(hir->routes[0].locals.len, 3u);
    CHECK(hir->routes[0].locals[1].type == HirTypeKind::I32);
    CHECK(hir->routes[0].locals[1].may_error);
    CHECK_EQ(hir->routes[0].locals[1].error_variant_index,
             hir->routes[0].locals[0].error_variant_index);
    CHECK(hir->routes[0].locals[2].type == HirTypeKind::I32);
    CHECK_FALSE(hir->routes[0].locals[2].may_error);
}
TEST(jit, frontend_pipe_method_stage_known_error_dispatches_value_method_shape) {
    const auto src = R"(
protocol MaybeMsg { func msg() -> i32 }
struct Box { value: i32 }
Box impl MaybeMsg {
    func msg(self: Box) -> i32 => self.value
}
route GET "/users" {
    let box: Box = error(.timeout)
    let code = box | _.msg()
    let safe = any(code, 500)
    if safe == 500 { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    REQUIRE_EQ(hir->routes[0].locals.len, 3u);
    CHECK(hir->routes[0].locals[1].type == HirTypeKind::I32);
    CHECK(hir->routes[0].locals[1].may_error);
    CHECK_EQ(hir->routes[0].locals[1].error_variant_index,
             hir->routes[0].locals[0].error_variant_index);
    CHECK(hir->routes[0].locals[2].type == HirTypeKind::I32);
    CHECK_FALSE(hir->routes[0].locals[2].may_error);
}

TEST(jit, frontend_pipe_method_stage_known_error_preserves_error_variant) {
    const auto src = R"(
route GET "/users" {
    let failed = error(.timeout)
    let ok = failed | _.eq(200)
    let safe = any(ok, false)
    if safe { return 200 } else { return 500 }
}
)";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    REQUIRE_EQ(hir->routes[0].locals.len, 3u);
    CHECK(hir->routes[0].locals[1].type == HirTypeKind::Bool);
    CHECK(hir->routes[0].locals[1].may_error);
    CHECK_EQ(hir->routes[0].locals[1].error_variant_index,
             hir->routes[0].locals[0].error_variant_index);
    CHECK(hir->routes[0].locals[2].type == HirTypeKind::Bool);
    CHECK_FALSE(hir->routes[0].locals[2].may_error);
}

TEST(jit, frontend_pipe_known_nil_falls_back_via_any) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = nil | id(_)
    let safe = any(code, 200)
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

TEST(jit, frontend_pipe_known_error_falls_back_via_any) {
    const auto src = R"(
func id(x: i32) -> i32 => x
route GET "/users" {
    let failed = error(.timeout)
    let code = failed | id(_)
    let safe = any(code, 200)
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
TEST(jit, frontend_pipe_method_stage_known_error_falls_back_via_any) {
    const auto src = R"(
protocol MaybeMsg { func msg() -> i32 }
struct Box { value: i32 }
Box impl MaybeMsg {
    func msg(self: Box) -> i32 => self.value
}
route GET "/users" {
    let box: Box = error(.timeout)
    let code = box | _.msg()
    let safe = any(code, 200)
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

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_via_any) {
    const auto src = R"(
func id(x: str) -> str => x
route GET "/users" {
    let host = req.header("Host") | id(_)
    let safe = any(host, "missing")
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

TEST(jit, frontend_pipe_runtime_error_lhs_flows_via_any) {
    const auto src = R"(
func fail() -> i32 => error(.timeout)
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = fail() | id(_)
    let safe = any(code, 200)
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

TEST(jit, frontend_any_present_lhs_fallible_rhs_observes_rhs_error) {
    const auto src = R"(
func fallback() -> i32 => error(.timeout)
route GET "/users" {
    let value = any(200, fallback())
    if value == 200 { return 204 } else { return 401 }
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
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_all_present_lhs_fallible_rhs_observes_rhs_error) {
    const auto src = R"(
func fallback() -> i32 => error(.timeout)
route GET "/users" {
    let value = all(200, fallback())
    if value == 200 { return 204 } else { return 401 }
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
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_all_present_lhs_fallible_rhs_local_can_be_recovered_by_any) {
    const auto src = R"(
func fallback() -> i32 => error(.timeout)
route GET "/users" {
    let value = all(200, fallback())
    let safe = any(value, 204)
    if safe == 204 { return 204 } else { return 401 }
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
    CHECK(r.status_code == 204);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_eager_error_local_can_be_recovered_by_fallible_any) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func recover(ok: bool) -> str {
    if ok { "safe" } else { error(.timeout) }
}
route GET "/users" {
    let host = any("present", fail())
    let safe = any(host, recover(req.http11))
    if safe == "safe" { return 204 } else { return 401 }
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
    CHECK(r.status_code == 204);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_eager_error_local_can_be_recovered_in_terminator) {
    const auto src = R"(
func fail() -> i32 => error(.timeout)
route GET "/users" {
    let code = any(200, fail())
    if any(code, 204) == 204 { return 204 } else { return 401 }
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
    CHECK(r.status_code == 204);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_fallible_bool_condition_returns_error_status) {
    const auto src = R"(
func fallback() -> bool => error(.timeout)
route GET "/users" {
    if any(true, fallback()) { return 204 } else { return 401 }
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
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_fallible_equality_operand_returns_error_status) {
    const auto src = R"(
func maybe(ok: bool) -> str {
    if ok { "ok" } else { error(.timeout) }
}
route GET "/users" {
    if maybe(req.http10) == "ok" { return 204 } else { return 401 }
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
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_recovered_local_still_errors_on_unrecovered_comparison) {
    const auto src = R"(
func fail() -> str => error(.timeout)
route GET "/users" {
    let host = any(req.query("q"), fail())
    let safe = any(host, "missing")
    if host == "rut" { return 204 } else { return 401 }
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
    CHECK(r.status_code == 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_explicit_resume_state_zero_enters_error_prelude) {
    const auto src = R"(
func fail() -> str => error(.timeout)
route GET "/" {
    let value = any(req.query("q"), fail())
    guard req.path == "/" else { return 404 }
    guard let value else { return 500 }
    guard value == "rut" else { return 401 }
    wait(1000)
    return 204
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
    TestHandlerCtxFrame frame{};
    HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    auto r = HandlerResult::unpack(handler(nullptr,
                                           &ctx,
                                           reinterpret_cast<const u8*>(kGetRootRequest),
                                           sizeof(kGetRootRequest) - 1,
                                           nullptr));
    CHECK_EQ(static_cast<u8>(r.action), static_cast<u8>(HandlerAction::ReturnStatus));
    CHECK_EQ(r.status_code, 500);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, frontend_pipe_runtime_optional_error_lhs_flows_via_any_nil_branch) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { nil } else { error(.timeout) }
}
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = maybefail(true) | id(_)
    let safe = any(code, 200)
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

TEST(jit, frontend_pipe_runtime_optional_error_lhs_flows_via_any_error_branch) {
    const auto src = R"(
func maybefail(ok: bool) -> i32 {
    if ok { nil } else { error(.timeout) }
}
func id(x: i32) -> i32 => x
route GET "/users" {
    let code = maybefail(false) | id(_)
    let safe = any(code, 200)
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

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_into_optional_stage_via_any) {
    const auto src = R"(
func drop(x: str) -> str { nil }
route GET "/users" {
    let host = req.header("Host") | drop(_)
    let safe = any(host, "missing")
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

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_into_error_stage_via_any) {
    const auto src = R"(
func failstage(x: str) -> str => error(.timeout)
route GET "/users" {
    let host = req.header("Host") | failstage(_)
    let safe = any(host, "missing")
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

TEST(jit, frontend_pipe_runtime_error_lhs_flows_into_optional_stage_via_any) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func drop(x: str) -> str { nil }
route GET "/users" {
    let host = fail() | drop(_)
    let safe = any(host, "missing")
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

TEST(jit, frontend_pipe_runtime_error_lhs_flows_into_error_stage_via_any) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func failstage(x: str) -> str => error(.timeout)
route GET "/users" {
    let host = fail() | failstage(_)
    let safe = any(host, "missing")
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

TEST(jit, frontend_pipe_runtime_optional_lhs_flows_into_optional_error_stage_via_any) {
    const auto src = R"(
func tri(x: str) -> str {
    if x == "host" { nil } else { error(.timeout) }
}
route GET "/users" {
    let host = req.header("Host") | tri(_)
    let safe = any(host, "missing")
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

TEST(jit, frontend_runtime_optional_error_stage_direct_via_any) {
    const auto src = R"(
func tri(x: str) -> str {
    if x == "host" { nil } else { error(.timeout) }
}
route GET "/users" {
    let raw = req.header("Host")
    let input = any(raw, "fallback")
    let host = tri(input)
    let safe = any(host, "missing")
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

TEST(jit, frontend_pipe_runtime_error_lhs_flows_into_optional_error_stage_via_any) {
    const auto src = R"(
func fail() -> str => error(.timeout)
func tri(x: str) -> str {
    if x == "host" { nil } else { error(.timeout) }
}
route GET "/users" {
    let host = fail() | tri(_)
    let safe = any(host, "missing")
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
        {"wait(downstream.recv())", YieldKind::Recv, 0},
        {"wait(downstream.send())", YieldKind::Send, 0},
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
        {"wait(250)", "timer", YieldKind::Timer},
        {"wait(downstream.recv())", "recv", YieldKind::Recv},
        {"wait(downstream.send())", "send", YieldKind::Send},
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

TEST(jit, frontend_route_wait_any_expression_result_fields_are_rejected) {
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
    REQUIRE_FALSE(hir);
    CHECK_EQ(hir.error().code, FrontendError::UnsupportedSyntax);
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

TEST(jit, deferred_preflight_selector_returns_only_exact_redirect_or_bundle_identity) {
    auto lexed = lex(lit(kDeferredPreflightSource));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.functions[0].forward_preflight_mode,
               ForwardPreflightMode::AfterCanonicalSelection);
    REQUIRE_EQ(rir.module.functions[0].preflight_forward_policy_bundle_id, 1u);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    struct Case {
        const char* request;
        HandlerAction action;
    } cases[] = {
        {"GET /old HTTP/1.1\r\nHost: test\r\n\r\n", HandlerAction::Redirect},
        {"GET /old?x=1 HTTP/1.1\r\nHost: test\r\n\r\n", HandlerAction::Redirect},
        {"GET /old/ HTTP/1.1\r\nHost: test\r\n\r\n", HandlerAction::ForwardBundle},
        {"GET / HTTP/1.1\r\nHost: test\r\n\r\n", HandlerAction::ForwardBundle},
    };
    for (const auto& test : cases) {
        const u32 len = static_cast<u32>(__builtin_strlen(test.request));
        const auto raw = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(test.request), len, nullptr));
        CHECK_EQ(raw.action, test.action);
        if (test.action == HandlerAction::Redirect) {
            CHECK_EQ(raw.status_code, 0u);
            CHECK_EQ(raw.upstream_id, 1u);
            CHECK_EQ(raw.next_state, 0u);
        } else {
            CHECK_EQ(raw.status_code, 1u);
            CHECK_EQ(raw.upstream_id, 0u);
            CHECK_EQ(raw.next_state, 1u);
        }
    }

    engine.shutdown();
    rir.destroy();
}

TEST(jit, request_framing_preflight_selects_literal_policy_identity_by_content_length) {
    auto lexed = lex(lit(kFramingSelectionPreflightSource));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.functions[0].forward_preflight_mode,
               ForwardPreflightMode::AfterRequestFramingSelection);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    struct Case {
        const char* request;
        RequestPolicyId expected;
    } cases[] = {
        {"HEAD /one HTTP/1.1\r\nHost: test\r\nContent-Length: 12\r\n\r\nhello world!",
         RequestPolicyId::Http11FixedStripContentLengthAfterHost},
        {"HEAD /one HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n",
         RequestPolicyId::Http11FixedStripContentLengthAfterHost},
        {"HEAD /one HTTP/1.1\r\nHost: test\r\n\r\n", RequestPolicyId::Http11FixedStrip},
    };
    for (const auto& test : cases) {
        const u32 len = static_cast<u32>(__builtin_strlen(test.request));
        const auto result = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(test.request), len, nullptr));
        CHECK_EQ(result.action, HandlerAction::ForwardBundle);
        CHECK_EQ(result.status_code, static_cast<u16>(test.expected));
        CHECK_EQ(result.upstream_id, 0u);
        CHECK_EQ(result.next_state, 1u);
    }

    engine.shutdown();
    rir.destroy();
}

TEST(jit, complete_content_length_request_framing_selects_get_id1_or_id3) {
    auto lexed = lex(lit(kCompleteContentLengthFramingSelectionSource));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    struct Case {
        const char* request;
        RequestPolicyId expected;
    } cases[] = {
        {"GET /one HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\nbody",
         RequestPolicyId::Http11FixedStrip},
        {"GET /one HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n",
         RequestPolicyId::Http11FixedStrip},
        {"GET /one HTTP/1.1\r\nHost: test\r\n\r\n", RequestPolicyId::Http11FixedTrimSpPreserveHtab},
    };
    for (const auto& test : cases) {
        const u32 len = static_cast<u32>(__builtin_strlen(test.request));
        const auto result = HandlerResult::unpack(
            handler(nullptr, nullptr, reinterpret_cast<const u8*>(test.request), len, nullptr));
        CHECK_EQ(result.action, HandlerAction::ForwardBundle);
        CHECK_EQ(result.status_code, static_cast<u16>(test.expected));
        CHECK_EQ(result.upstream_id, 0u);
        CHECK_EQ(result.next_state, 1u);
    }

    engine.shutdown();
    rir.destroy();
}

TEST(jit, fixed_302_conditional_returns_redirect_identity_and_neighbor_bundle) {
    const char source[] = R"rut(
upstream backend at "127.0.0.1:9000"
route GET "/" {
  if req.pathOnly == "/old" {
    return redirect({scheme: .http, authority: .static,
      static_authority: "redirect.example", port: .omit, path: .static,
      query: .discard, date: .current, connection: .close,
      header_order: .connectionThenLocation, status: 302,
      reason: "Moved Temporarily", server: "wire-test", content_type: "text/html",
      target_path: "/new", body: b"fixed-302"})
  } else {
    return forward(backend, load_balance: .roundRobin,
      response_policy: {version: .http11, framing: .contentLength,
        connection: .request, server: "rut", date: .current, hide_headers: []},
      failure_policy: {version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/plain", server: "rut", date: .current,
        connection: .request, body: b"bad"})
  }
}
)rut";
    auto lexed = lex(lit(source));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    REQUIRE_EQ(rir.module.redirect_policies[0].status_code, 302u);
    REQUIRE_EQ(rir.module.policy_bundle_count, 1u);

    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    const auto redirect = HandlerResult::unpack(
        handler(nullptr,
                nullptr,
                reinterpret_cast<const u8*>("GET /old?x=1 HTTP/1.1\r\nHost: alternate\r\n\r\n"),
                sizeof("GET /old?x=1 HTTP/1.1\r\nHost: alternate\r\n\r\n") - 1,
                nullptr));
    CHECK_EQ(redirect.action, HandlerAction::Redirect);
    CHECK(HandlerResult::redirect_fields_valid(redirect));
    CHECK_EQ(redirect.upstream_id, 1u);
    CHECK_EQ(redirect.status_code, 0u);
    CHECK_EQ(redirect.next_state, 0u);
    CHECK_EQ(redirect.yield_kind, YieldKind::HttpGet);

    const auto forward = HandlerResult::unpack(
        handler(nullptr,
                nullptr,
                reinterpret_cast<const u8*>("GET /old/ HTTP/1.1\r\nHost: alternate\r\n\r\n"),
                sizeof("GET /old/ HTTP/1.1\r\nHost: alternate\r\n\r\n") - 1,
                nullptr));
    CHECK_EQ(forward.action, HandlerAction::ForwardBundle);
    CHECK_EQ(forward.status_code, 0u);
    CHECK_EQ(forward.upstream_id, 0u);
    CHECK_EQ(forward.next_state, 1u);
    CHECK_EQ(forward.yield_kind, YieldKind::HttpGet);

    engine.shutdown();
    rir.destroy();
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

#if RUT_ENABLE_WEBSOCKET
TEST(jit, websocket_condition_forest_rejects_invalid_graphs) {
    WsLenGuardSpec nodes[3]{};
    nodes[0].accessor = 2;
    nodes[0].is_operand = true;
    nodes[1].accessor = 1;
    nodes[1].is_operand = true;
    nodes[2].accessor = 4;
    nodes[2].lhs = 0;
    nodes[2].rhs = 1;
    auto valid = codegen_ws_handler(0, nodes, 3, 0);
    REQUIRE(valid.ok);
    dispose_module(valid.mod, valid.ctx);
    nodes[2].rhs = 2;  // self-reference
    CHECK_FALSE(codegen_ws_handler(0, nodes, 3, 0).ok);
    nodes[2].rhs = 0;  // shared child would expand code; also leaves an orphan
    CHECK_FALSE(codegen_ws_handler(0, nodes, 3, 0).ok);
    nodes[2].rhs = 1;
    nodes[1].is_operand = false;  // child is another source guard
    CHECK_FALSE(codegen_ws_handler(0, nodes, 3, 0).ok);
    CHECK_FALSE(codegen_ws_handler(0, nullptr, 1, 0).ok);
    CHECK_FALSE(codegen_ws_handler(0, nodes, WsLenGuardSpec::kMaxConditions + 1, 0).ok);
}

TEST(jit, websocket_branch_policy_verdict_validation) {
    WsLenGuardSpec node{};
    node.accessor = 0;
    node.cmp = 0;
    node.bound = 10;
    for (u8 verdict = 4; verdict <= 11; verdict++) {
        node.verdict = verdict;
        auto cg = codegen_ws_handler(0, &node, 1, 0);
        REQUIRE(cg.ok);
        dispose_module(cg.mod, cg.ctx);
    }
    node.verdict = 3;  // the default payload selector cannot select a guard payload
    CHECK_FALSE(codegen_ws_handler(0, &node, 1, 0).ok);
    node.verdict = 12;
    CHECK_FALSE(codegen_ws_handler(0, &node, 1, 0).ok);
}

TEST(jit, byte_substring_helper_boundaries) {
    const char payload[] = {'x', 'a', 0, 'b', 'y', 'a', 0, 'b'};
    const char needle[] = {'a', 0, 'b'};
    CHECK(rut_helper_str_contains(payload, sizeof(payload), needle, sizeof(needle)));
    CHECK(rut_helper_str_contains(payload, 4, needle, sizeof(needle)));
    CHECK_FALSE(rut_helper_str_contains(payload, 3, needle, sizeof(needle)));
    CHECK_FALSE(rut_helper_str_contains(payload, sizeof(payload), "aby", 3));
    CHECK(rut_helper_str_contains(nullptr, 0, nullptr, 0));
    CHECK(rut_helper_str_contains(payload, sizeof(payload), nullptr, 0));
    CHECK_FALSE(rut_helper_str_contains(nullptr, 10, needle, sizeof(needle)));
    CHECK_FALSE(rut_helper_str_contains(payload, sizeof(payload), nullptr, 1));
    // Repeated prefixes exercise the search's overlap/fallback behavior.
    char repeated[16370];
    memset(repeated, 'a', sizeof(repeated));
    repeated[sizeof(repeated) - 1] = 'b';
    CHECK(rut_helper_str_contains(repeated, sizeof(repeated), "aaaaab", 6));
    CHECK_FALSE(rut_helper_str_contains(repeated, sizeof(repeated) - 1, "aaaaab", 6));
    CHECK(rut_helper_str_contains(
        repeated, sizeof(repeated), repeated + 8000, sizeof(repeated) - 8000));
    CHECK_FALSE(rut_helper_str_contains(
        repeated, sizeof(repeated) - 1, repeated + 8000, sizeof(repeated) - 8000));
    CHECK(rut_helper_str_contains("a.b", 3, ".", 1));
    CHECK_FALSE(rut_helper_str_contains("axb", 3, ".", 1));
}

TEST(jit, websocket_text_literal_rejects_missing_storage) {
    WsLenGuardSpec node{};
    node.accessor = 6;
    node.pattern_len = 4;
    CHECK_FALSE(codegen_ws_handler(0, &node, 1, 0).ok);
    node.pattern_len = 0;
    auto empty = codegen_ws_handler(0, &node, 1, 0);
    REQUIRE(empty.ok);
    dispose_module(empty.mod, empty.ctx);
    for (u8 accessor : {7, 8, 9}) {
        node.accessor = accessor;
        node.pattern_len = 4;
        CHECK_FALSE(codegen_ws_handler(0, &node, 1, 0).ok);
        node.pattern_len = 0;
        auto affix = codegen_ws_handler(0, &node, 1, 0);
        REQUIRE(affix.ok);
        dispose_module(affix.mod, affix.ctx);
    }
    node.accessor = 10;
    CHECK_FALSE(codegen_ws_handler(0, &node, 1, 0).ok);
}

// Compile a `websocket(x){ frame in frame.<verdict>() }` program end-to-end through the
// constant-verdict frame-handler JIT path (analyze -> codegen_ws_handler -> JIT -> lookup -> CALL),
// and return the verdict the compiled function actually produces. Returns 255 on any failure.
static WsFrameAction jit_ws_verdict(const char* src) {
    constexpr auto kFail = static_cast<WsFrameAction>(255);
    auto lexed = lex(lit(src));
    if (!lexed) return kFail;
    auto ast = parse_file_heap(lexed.value());
    if (!ast) return kFail;
    auto hir = analyze_file_heap(ast.value());
    if (!hir) return kFail;
    if (hir->routes.len != 1 || !hir->routes[0].is_ws_terminate) return kFail;
    const u8 verdict = static_cast<u8>(hir->routes[0].ws_handler.default_verdict);

    auto cg = codegen_ws_handler(verdict, nullptr, 0, 0);
    if (!cg.ok) return kFail;
    JitEngine engine;
    if (!engine.init() || !engine.compile(cg.mod, cg.ctx)) return kFail;
    auto fn = reinterpret_cast<WsMessageHandlerFn>(engine.lookup("ws_handler_0"));
    const WsFrameAction r = fn ? fn(nullptr, WsOpcode::Text, nullptr, 0, false) : kFail;
    engine.shutdown();
    return r;
}

TEST(jit, ws_handler_forward_returns_forward) {
    // frame.forward() compiles to a verdict function that, when called, returns Forward.
    CHECK(jit_ws_verdict("upstream ws\nroute GET \"/ws\" { return websocket(ws) { frame in "
                         "frame.forward() } }\n") == WsFrameAction::Forward);
}

TEST(jit, ws_handler_drop_returns_drop) {
    CHECK(jit_ws_verdict("upstream ws\nroute GET \"/ws\" { return websocket(ws) { frame in "
                         "frame.drop() } }\n") == WsFrameAction::Drop);
}

TEST(jit, ws_handler_close_returns_close) {
    CHECK(jit_ws_verdict("upstream ws\nroute GET \"/ws\" { return websocket(ws) { frame in "
                         "frame.close() } }\n") == WsFrameAction::Close);
}
#endif  // RUT_ENABLE_WEBSOCKET

TEST(jit, chain_respond_capable_step_short_circuits) {
    // The unified middleware surface: a chain step whose helper responds
    // short-circuits the request at runtime with the helper's status/body;
    // a passing request falls through to the handler.
    const char* src =
        "func check(_ req: i32) -> i32 { guard req.http11 else { respond 401, \"denied\" } 7 }\n"
        "chain auth { before check(req) }\n"
        "route {\n"
        " use chain auth\n"
        " GET \"/version\" { return 200 }\n"
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

    // HTTP/1.1 -> check passes -> handler runs, 200.
    static const char http11[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http11), sizeof(http11) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> check responds -> 401 short-circuit, handler never runs.
    static const char http10[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http10), sizeof(http10) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, chain_respond_response_local_short_circuits) {
    const char* src =
        "func check(_ req: i32) -> i32 { let resp = response(401) "
        "resp.set(\"X-Reason\", \"auth\") guard req.http11 else { respond resp } 7 }\n"
        "chain auth { before check(req) }\n"
        "route { use chain auth GET \"/version\" { return 200 } }\n";

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

    static const char http11[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto result = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http11), sizeof(http11) - 1, nullptr));
    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK_EQ(result.status_code, 200);

    static const char http10[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    result = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(http10), sizeof(http10) - 1, nullptr));
    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK_EQ(result.status_code, 401);
    CHECK_NE(result.next_state, 0u);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, guard_let_takes_else_branch_on_runtime_error) {
    // Spec 3.3.7: guard let binds the usable value or takes else at RUNTIME.
    // The guard's HasValue cond consumes the error, so the state-0 error
    // prelude must not intercept with a generic 500 first (PR #162 review).
    const char* src =
        "func pick(ok: bool) -> str { if ok { \"rut\" } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = pick(req.http11) "
        "guard let value else { return 401 } "
        "if value == \"rut\" { return 200 } else { return 500 } }\n";

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

    // HTTP/1.1 -> pick(true) -> usable value bound and narrowed -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> pick(false) errors -> the guard's else, not a generic 500.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, fail_closed_pre_reject_runs_before_later_error_recovery) {
    // The carrier errors whenever X-Pick is absent. HTTP/1.0 takes a benign
    // 403 pre-reject before recovery; HTTP/1.1 continues to guard-let, which
    // turns that same error into 401. Neither path may be intercepted by the
    // automatic state-0 500 prelude.
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.header(\"X-Pick\") == \"ok\")) "
        "guard req.http11 else { return 403 } "
        "guard let value else { return 401 } return 200 }\n";

    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);

    static const char rejected[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(rejected), sizeof(rejected) - 1, nullptr));
    CHECK_EQ(r.status_code, 403);

    static const char recovered[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(recovered), sizeof(recovered) - 1, nullptr));
    CHECK_EQ(r.status_code, 401);

    static const char accepted[] = "GET /version HTTP/1.1\r\nHost: localhost\r\nX-Pick: ok\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(accepted), sizeof(accepted) - 1, nullptr));
    CHECK_EQ(r.status_code, 200);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, nil_presence_test_stored_in_local_consumes_runtime_error) {
    // Value-position presence test: `let missing = value == nil` consumes the
    // error the same way the branch-condition form does — the stored bool is
    // about presence, so a runtime error must flow into `missing == true`,
    // not be intercepted by the state-0 prelude (PR #168 review round 2).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let missing = value == nil "
        "if missing { return 401 } else { return 200 } }\n";

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

    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, nil_presence_test_consumes_runtime_error) {
    // `v == nil` on a fallible carrier consumes the error as "absent" — the
    // state-0 error prelude must not intercept with a generic 500 first,
    // exactly like the guard-let HasValue cond (PR #168 review).
    // The eager-fallback init shape is the one gated by the state-0 error
    // prelude (any() is non-short-circuit: pick()'s error propagates into
    // `value` even though 200 is always usable).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if value == nil { return 401 } else { return 200 } }\n";

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

    // HTTP/1.1 -> pick(true) -> usable value -> the else branch, 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> pick(false) errors -> `== nil` is true -> 401, not 500.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, nested_nil_presence_test_keeps_error_prelude_on_unguarded_sibling) {
    // A presence test nested under a conditional does NOT dominate: the
    // sibling arm never observes the carrier, so dropping the state-0 error
    // prelude would let pick()'s error masquerade as the sibling's 204. The
    // prelude must stay — same dominance restriction as guard-let recovery
    // (PR #168 review round 3, P1).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if req.http11 { if value == nil { return 401 } else { return 200 } } "
        "else { return 204 } }\n";

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

    // HTTP/1.1 -> usable value -> nested presence test -> else branch, 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> pick(false) errors AND the outer condition routes to the
    // sibling arm that never runs the presence test. The prelude must
    // intercept with 500 — 204 here would be an error escaping as success.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 500);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, dominating_nil_presence_test_allows_compare_in_present_arm) {
    // A TOP-LEVEL presence branch dominates every exit: on error it routes to
    // the nil arm before the present-arm compare can run, so an optional
    // compare downstream must not force the prelude back — that would turn
    // the programmed 401 into a generic 500 (PR #168 review round 3, P2).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if value == nil { return 401 } "
        "else { if value == 200 { return 200 } else { return 204 } } }\n";

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

    // HTTP/1.1 -> value usable (any()'s 200 arm) -> present arm -> the
    // optional compare hits -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> pick(false) errors -> dominating `== nil` reads true ->
    // 401, NOT a generic 500 from a prelude the present-arm compare forced.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, short_circuit_presence_test_keeps_error_prelude) {
    // `req.http11 && value == nil` only evaluates the presence test when
    // req.http11 is true — on the short-circuited path the error is never
    // consumed, so the state-0 prelude must stay: a runtime error must be
    // intercepted with 500, not fall through as the else arm's 204
    // (PR #168 review round 4, P1).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if req.http11 && value == nil { return 401 } else { return 204 } }\n";

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

    // HTTP/1.1 -> usable value -> presence test evaluates false -> 204.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    // HTTP/1.0 -> pick(false) errors AND && short-circuits past the test.
    // The prelude must intercept with 500 — 204 would be an error escaping.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 500);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, stored_presence_bool_consumed_in_non_dominated_branch) {
    // A stored presence bool branched on inside a NON-dominated block: the
    // eager `missing` init consumes the error at state 0, so the nested
    // `if missing` must route a runtime error to its 401 arm — no state-0
    // 500 — even though the branch does not dominate (PR #168 review
    // round 4, P2). The flood's no-dominance narrowing has no further
    // representable counterexample today: re-testing/comparing the carrier
    // inside a presence-narrowed arm and if/else nesting deeper than two
    // levels are both analyzer-rejected.
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let missing = value == nil "
        "if req.http11 { return 204 } "
        "else { if missing { return 401 } else { return 503 } } }\n";

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

    // HTTP/1.1 -> usable -> the http11 arm -> 204.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    // HTTP/1.0 -> error -> missing eagerly true -> the non-dominated
    // `if missing` routes to 401, with no state-0 500 in the way.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, stored_presence_bool_routes_error_flood) {
    // A presence test stored in a bool local keeps its routing power: on
    // error `missing` eagerly computes to true, so `if missing` provably
    // takes the 401 arm and the compare in the else arm can never see the
    // error — the prelude must stay suppressed (PR #168 review round 4, P2).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let missing = value == nil "
        "if missing { return 401 } "
        "else { if value == 200 { return 200 } else { return 204 } } }\n";

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

    // HTTP/1.1 -> usable (any()'s 200 arm) -> missing false -> compare -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> error -> missing true -> 401, not 500.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, alias_presence_test_consumes_runtime_error) {
    // A bare `let alias = value` copy is a rename: a presence test on the
    // alias observes the same error field, so it must recover the carrier's
    // error exactly like testing the carrier directly — 401, not a state-0
    // 500 fired before the alias test runs (PR #168 review round 4, P2).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let alias = value "
        "if alias == nil { return 401 } else { return 200 } }\n";

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

    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, presence_test_in_short_circuit_lhs_consumes_runtime_error) {
    // `value != nil && req.http11`: the presence test is the && LHS — the
    // one operand a short-circuit ALWAYS evaluates — so it consumes the
    // error and the whole condition folds false on the error path, routing
    // to the programmed else arm (401), never a state-0 500. The dual
    // shape with an optional payload compare on the RHS (codex round 5) is
    // analyzer-rejected today; the scan is hardened for it regardless
    // (PR #168 review round 5).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if value != nil && req.http11 { return 200 } else { return 401 } }\n";

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

    // HTTP/1.1 -> usable && http11 -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> error -> presence LHS false, && short-circuits -> 401.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, presence_test_split_across_short_circuit_paths_recovers) {
    // `req.http11 && value == nil || value == nil`: no single operand
    // dominates, but EVERY evaluation path of the condition runs one of
    // the presence tests — the (rec_true, rec_false) result-path analysis
    // must credit the split coverage and drop the prelude so a runtime
    // error routes to the programmed 401 (PR #168 review round 6).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if req.http11 && value == nil || value == nil { return 401 } "
        "else { return 204 } }\n";

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

    // HTTP/1.1 -> usable -> both tests read present -> 204.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    // HTTP/1.0 -> error -> whichever short-circuit path runs, a presence
    // test reads absent -> 401, not a state-0 500.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, presence_tests_in_both_arms_cover_all_paths) {
    // Recovery split across sibling arms: neither presence branch
    // dominates, but every control path from the entry evaluates one —
    // the block-level path recursion must accept this and drop the
    // prelude so each arm's programmed nil response fires
    // (PR #168 review round 6).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if req.http11 { if value == nil { return 401 } else { return 200 } } "
        "else { if value == nil { return 402 } else { return 204 } } }\n";

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

    // HTTP/1.1 -> usable -> http11 arm -> present -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> error -> the else arm's own presence test reads absent
    // -> 402, not a state-0 500.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 402);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, stored_split_presence_expression_recovers) {
    // Path-complete presence coverage stored in a bool local: the init
    // evaluates eagerly and every one of ITS evaluation paths runs a
    // presence test, so it recovers exactly like the direct branch form
    // (PR #168 review round 7).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let covered = req.http11 && value == nil || value == nil "
        "if covered { return 401 } else { return 204 } }\n";

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

    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, presence_test_in_or_fallback_arg_recovers) {
    // MirValueKind::Or is the EAGER any/.or fallback — both operands
    // materialize before the select — so a presence test in the fallback
    // argument ALWAYS runs and consumes the carrier's error; it must not
    // be gated like a short-circuit operand (PR #168 review round 7).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "func maybe(ok: bool) -> bool { if ok { true } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let handled = maybe(req.http11).or(value != nil) "
        "if handled { return 200 } else { return 204 } }\n";

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

    // HTTP/1.1 -> maybe(true) usable -> handled=true -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> maybe errors -> fallback `value != nil` reads absent ->
    // handled=false -> 204, not a state-0 500 from value's kept prelude.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, match_on_split_presence_subject_recovers) {
    // A match subject covered on every evaluation path recovers like a
    // plain branch condition — the use_cmp lowering's subject slot gets
    // the same recovers_on_all_paths treatment (PR #168 review round 7).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "match req.http11 && value == nil || value == nil "
        "{ true => return 401 _ => return 204 } }\n";

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

    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, split_presence_condition_folds_in_error_flood) {
    // The both-arms-agree fold: `req.http11 && value == nil || value ==
    // nil` reads true under the error outcome whichever way req.http11
    // went, so the flood routes the error to the then arm and the payload
    // compare in the else arm cannot force the prelude back
    // (PR #168 review round 7).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "if req.http11 && value == nil || value == nil { return 401 } "
        "else { if value == 200 { return 200 } else { return 204 } } }\n";

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

    // HTTP/1.1 -> usable -> condition false -> present-arm compare -> 200.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> error -> split condition reads true -> 401, not a 500
    // forced by the unreachable else-arm compare.
    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, presence_test_survives_never_missing_any_fold) {
    // `any(false, value == nil)`: the lhs is never missing, so the old
    // analyze fold dropped the whole fallback — including the eagerly-
    // evaluated presence test that consumes value's error. The fold is now
    // gated on the fallback containing a fallible HasValue, and the Or
    // lowering yields the never-missing lhs after materializing the
    // fallback, so a runtime error takes the programmed 204 branch instead
    // of a state-0 500 (PR #168 review round 8).
    const char* src =
        "func pick(ok: bool) -> i32 { if ok { 7 } else { error(.timeout) } }\n"
        "route GET \"/version\" { let value = any(200, pick(req.http11)) "
        "let handled = any(false, value == nil) "
        "if handled { return 401 } else { return 204 } }\n";

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

    // handled is always false (the never-missing lhs wins the select) —
    // the interesting difference is 204 vs 500 on the error path.
    static const char with_q[] = "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char without_q[] = "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, or_fallback_runtime_present_and_absent) {
    // `.or(default)` end-to-end: query present -> value; absent -> default.
    const char* src =
        "route GET \"/search\" { let q = req.query(\"q\").or(\"dflt\") "
        "if q == \"rut\" { return 200 } else { if q == \"dflt\" { return 404 } else { return "
        "500 } } }\n";

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

    static const char with_q[] = "GET /search?q=rut HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_q), sizeof(with_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    static const char without_q[] = "GET /search HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 404);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, guard_let_over_pure_optional_query_binds_and_narrows) {
    // Migration slice: pure-optional carrier binding. `guard let q =
    // req.query("q")` — present binds the narrowed str (usable in a plain
    // compare), absent takes the else. No error channel involved anywhere.
    const char* src =
        "route GET \"/search\" { guard let q = req.query(\"q\") else { return 400 } "
        "if q == \"rut\" { return 200 } else { return 204 } }\n";

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

    static const char match_q[] = "GET /search?q=rut HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(match_q), sizeof(match_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    static const char other_q[] = "GET /search?q=zig HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(other_q), sizeof(other_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char without_q[] = "GET /search HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 400);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, if_let_over_pure_optional_header_takes_both_branches) {
    // `if let` over a pure-optional header: present -> then-branch with the
    // narrowed binding usable; absent -> else-branch.
    const char* src =
        "route GET \"/tagged\" { if let tag = req.header(\"X-Tag\") "
        "{ if tag == \"edge\" { return 200 } else { return 204 } } "
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

    static const char with_tag[] = "GET /tagged HTTP/1.1\r\nHost: localhost\r\nX-Tag: edge\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(with_tag), sizeof(with_tag) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    static const char other_tag[] =
        "GET /tagged HTTP/1.1\r\nHost: localhost\r\nX-Tag: core\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(other_tag), sizeof(other_tag) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 204);

    static const char without_tag[] = "GET /tagged HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(nullptr,
                                      nullptr,
                                      reinterpret_cast<const u8*>(without_tag),
                                      sizeof(without_tag) - 1,
                                      nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 404);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, guard_let_over_optional_struct_func_result) {
    // Pure-optional STRUCT carrier: a func returning `nil` in one branch.
    // The guard binds the struct on the present path (field access on the
    // narrowed binding) and takes the else on nil.
    const char* src =
        "struct Box { value: i32 }\n"
        "func maybeBox(ok: bool) -> Box { if ok { Box(value: 201) } else { nil } }\n"
        "route GET \"/box\" { guard let picked = maybeBox(req.http11) else { return 401 } "
        "if picked.value == 201 { return 200 } else { return 500 } }\n";

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

    // HTTP/1.1 -> Box present -> narrowed field access compares -> 200.
    static const char present[] = "GET /box HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(present), sizeof(present) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    // HTTP/1.0 -> nil -> guard else -> 401.
    static const char absent[] = "GET /box HTTP/1.0\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(absent), sizeof(absent) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 401);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, guard_let_shorthand_over_pure_optional_local) {
    // Swift 5.7 shorthand over a pure-optional local: `guard let q` rebinds
    // the Optional<Str> local as a narrowed plain str.
    const char* src =
        "route GET \"/s\" { let q = req.query(\"q\") guard let q else { return 400 } "
        "if q == \"rut\" { return 200 } else { return 204 } }\n";

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

    static const char match_q[] = "GET /s?q=rut HTTP/1.1\r\nHost: localhost\r\n\r\n";
    auto r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(match_q), sizeof(match_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 200);

    static const char without_q[] = "GET /s HTTP/1.1\r\nHost: localhost\r\n\r\n";
    r = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(without_q), sizeof(without_q) - 1, nullptr));
    CHECK(r.action == HandlerAction::ReturnStatus);
    CHECK(r.status_code == 400);

    engine.shutdown();
    rir.destroy();
}

TEST(jit, uuid_storage_budget_failure_and_live_views) {
    u8 has = 1;
    const char* ptr = "stale";
    u32 len = 99;
    rut_helper_uuid(nullptr, nullptr, &has, &ptr, &len);
    CHECK_EQ(has, 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const char* first = nullptr;
    char saved[kUuidTextLength];
    u32 successes = 0;
    for (u32 i = 0; i < 7000; ++i) {
        rut_helper_uuid(nullptr, &arena, &has, &ptr, &len);
        if (!has) break;
        REQUIRE_EQ(len, kUuidTextLength);
        if (successes == 0) {
            first = ptr;
            __builtin_memcpy(saved, ptr, sizeof(saved));
        }
        ++successes;
    }
    REQUIRE(successes > 0);
    CHECK(successes <= kUuidRequestBudget / 40u);
    CHECK_EQ(has, 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    CHECK(arena.space_used() <= kUuidRequestBudget);
    CHECK((Str{first, kUuidTextLength}.eq({saved, sizeof(saved)})));
    arena.destroy();
    pool.destroy();
    // A one-slice arena cannot grow after its current slice is consumed.
    REQUIRE(pool.init(1));
    REQUIRE(arena.init(&pool));
    REQUIRE(arena.alloc(arena.current->remaining()) != nullptr);
    rut_helper_uuid(nullptr, &arena, &has, &ptr, &len);
    CHECK_EQ(has, 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    arena.destroy();
    pool.destroy();
}

TEST(jit, uuid_helper_inlining_single_evaluation_and_response_lifetime) {
    const char* source = R"rut(
func useId(_ id: str) -> str => id
route GET "/id" {
    let pending = uuid()
    guard let id = pending else { return 503 }
    let echoed = useId(id)
    guard echoed == id else { return 500 }
    return response(200, body: id)
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    u32 calls = 0;
    for (u32 fi = 0; fi < rir.module.func_count; ++fi)
        for (u32 bi = 0; bi < rir.module.functions[fi].block_count; ++bi)
            for (u32 ii = 0; ii < rir.module.functions[fi].blocks[bi].inst_count; ++ii)
                calls += rir.module.functions[fi].blocks[bi].insts[ii].op == Opcode::Uuid;
    CHECK_EQ(calls, 1u);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    engine.opt_level = OptLevel::O3;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    const char request[] = "GET /id HTTP/1.1\r\nHost: test\r\n\r\n";
    auto failed = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(request), sizeof(request) - 1, nullptr));
    CHECK_EQ(failed.status_code, 503u);
    SlicePool pool;
    REQUIRE(pool.init(8));
    auto connection = std::make_unique<Connection>();
    for (u32 i = 0; i < 3; ++i) {
        connection->reset();
        connection->json_arena.backend.pool = &pool;
        auto result = HandlerResult::unpack(handler(connection.get(),
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request),
                                                    sizeof(request) - 1,
                                                    nullptr));
        CHECK_EQ(result.status_code, 200u);
        REQUIRE(connection->jit_response_body_valid);
        auto id = connection->jit_response_body;
        REQUIRE_EQ(id.len, kUuidTextLength);
        CHECK_EQ(id.ptr[14], '4');
        CHECK(id.ptr[19] == '8' || id.ptr[19] == '9' || id.ptr[19] == 'a' || id.ptr[19] == 'b');
        for (u32 j = 0; j < id.len; ++j) {
            if (j == 8 || j == 13 || j == 18 || j == 23)
                CHECK_EQ(id.ptr[j], '-');
            else
                CHECK((id.ptr[j] >= '0' && id.ptr[j] <= '9') ||
                      (id.ptr[j] >= 'a' && id.ptr[j] <= 'f'));
        }
    }
    connection->reset();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(jit, art_segment_prefix_terminal_boundaries) {
    JitEngine engine;
    REQUIRE(engine.init());
    auto cfg = std::make_unique<RouteConfig>();
    auto& trie = cfg->art_state;
    REQUIRE(trie.insert(lit("/"), 0, 0));
    REQUIRE(trie.insert(lit("/api"), 0, 1));
    REQUIRE(trie.insert(lit("/api/v1"), 0, 2));
    REQUIRE(trie.insert(lit("/apix"), 0, 3));
    REQUIRE(trie.insert(lit("/api"), 'G', 4));
    auto fn = art_jit_specialize(engine, trie, "test_segment_boundaries");
    REQUIRE(fn != nullptr);
    struct Case {
        const char* path;
        u8 method;
        u16 expected;
    };
    const Case cases[] = {{"", 'G', 0},
                          {"api", 'G', 4},
                          {"api/child", 'G', 4},
                          {"apifoo", 'G', 0},
                          {"api/v1x", 'G', 4},
                          {"api/v1/child", 'G', 2},
                          {"apix", 'G', 3},
                          {"apixyz", 'G', 0},
                          {"api", 'P', 1}};
    for (const auto& c : cases) {
        Str path = lit(c.path);
        u8 key = static_cast<u8>(method_slot(c.method));
        CHECK_EQ(trie.match_canonical_key(path, key), c.expected);
        CHECK_EQ(fn(path.ptr, path.len, key), c.expected);
    }
    engine.shutdown();
}

TEST(jit, art_segment_boundary_at_unreadable_page) {
    const long page_size = sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    struct Mapping {
        void* ptr;
        size_t size;
        ~Mapping() {
            if (ptr != MAP_FAILED) munmap(ptr, size);
        }
    } mapping{mmap(nullptr,
                   static_cast<size_t>(page_size) * 2,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1,
                   0),
              static_cast<size_t>(page_size) * 2};
    REQUIRE(mapping.ptr != MAP_FAILED);
    char* end = static_cast<char*>(mapping.ptr) + page_size;
    REQUIRE(mprotect(end, static_cast<size_t>(page_size), PROT_NONE) == 0);
    end[-3] = 'a';
    end[-2] = 'p';
    end[-1] = 'i';
    JitEngine engine;
    REQUIRE(engine.init());
    ArtTrie trie(ArtMatchMode::SegmentPrefix);
    REQUIRE(trie.insert(lit("/api"), 0, 1));
    auto fn = art_jit_specialize(engine, trie, "test_segment_guard_page");
    REQUIRE(fn != nullptr);
    const u8 key = static_cast<u8>(method_slot('G'));
    CHECK_EQ(fn(end - 3, 3, key), 1u);
    CHECK_EQ(fn(end, 0, key), TrieNode::kInvalidRoute);
    CHECK_EQ(trie.match_canonical_key({end - 3, 3}, key), 1u);
    engine.shutdown();
}

TEST(jit, art_chunk_comparison_all_bytes_and_guard_page) {
    const long page_size = sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 128);
    void* mapping = mmap(nullptr,
                         static_cast<size_t>(page_size) * 2,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1,
                         0);
    REQUIRE(mapping != MAP_FAILED);
    struct MappingGuard {
        void* ptr;
        size_t size;
        ~MappingGuard() { munmap(ptr, size); }
    } mapping_guard{mapping, static_cast<size_t>(page_size) * 2};
    char* end = static_cast<char*>(mapping) + page_size;
    REQUIRE(mprotect(end, static_cast<size_t>(page_size), PROT_NONE) == 0);
    JitEngine engine;
    REQUIRE(engine.init());
    struct EngineGuard {
        JitEngine& engine;
        ~EngineGuard() { engine.shutdown(); }
    } engine_guard{engine};
    const u32 lengths[] = {1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65};
    for (u32 length : lengths) {
        char route[66]{};
        for (u32 i = 0; i < length; ++i) route[i] = static_cast<char>('a' + i % 26);
        ArtTrie trie(ArtMatchMode::SegmentPrefix);
        REQUIRE(trie.insert({route, length}, kRouteMethodGet, 23));
        char symbol[64];
        snprintf(symbol, sizeof(symbol), "chunk_guard_%u", length);
        auto fn = art_jit_specialize(engine, trie, symbol);
        REQUIRE(fn != nullptr);
        char* target = end - length;
        for (u32 i = 0; i < length; ++i) target[i] = route[i];
        CHECK_EQ(fn(target, length, kRouteMethodGet), 23u);
        CHECK_EQ(fn(target, length, kRouteMethodPost), TrieNode::kInvalidRoute);
        // Every truncated request ends at the guard page; no wide overread.
        for (u32 n = 0; n < length; ++n)
            CHECK_EQ(fn(end - n, n, kRouteMethodGet), TrieNode::kInvalidRoute);
        for (u32 i = 0; i < length; ++i) {
            target[i] ^= 0x40;
            CHECK_EQ(fn(target, length, kRouteMethodGet), TrieNode::kInvalidRoute);
            target[i] ^= 0x40;
        }
    }
}

TEST(jit, literal_boundary_overlap_keeps_art_dispatch) {
    const char* source =
        "route GET \"/api\" { return 201 }\n"
        "route GET \"/apix\" { return 202 }\n";
    auto lexed = lex(lit(source));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto config = std::make_unique<RouteConfig>();
    REQUIRE(configure_route_dispatch(*config, rir.module));
    CHECK(config->dispatch_kind() == RouteConfig::DispatchKind::ArtJit);
}

TEST(jit, json_nested_struct_field_access_and_decode_failures) {
    const char* src = R"rut(
struct Profile {
    name: str
    active: bool
}
struct User {
    profile: Profile
    age: i32
    id: i32
}
route POST "/decode" {
    guard let doc = req.bodyJson() else { return 400 }
    guard let user = json.decode(User, doc) else { return 422 }
    if user.profile.name == "Rut" && !user.profile.active &&
       user.age == -2147483648 && user.id == 2147483647 {
        return 200
    } else { return 409 }
}
route POST "/body" {
    guard let user = req.body(User) else { return 422 }
    if user.profile.name == "Rut" && !user.profile.active &&
       user.age == -2147483648 && user.id == 2147483647 {
        return 200
    } else { return 409 }
}
)rut";
    auto tokens = lex(lit(src));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    if (!lowered)
        fprintf(stderr,
                "JSON lowering error %u: %.*s\n",
                static_cast<u32>(lowered.error().code),
                lowered.error().detail.len,
                lowered.error().detail.ptr);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    SlicePool pool;
    REQUIRE(pool.init(64));
    SliceArena arena;
    REQUIRE(arena.init(&pool));

    struct Case {
        const char* body;
        u32 status;
    };
    const Case cases[] = {
        // Field lookup must follow names, not input order; decode escaped names and values.
        {R"({"id":2147483647,"extra":[null],"age":-2147483648,"profile":{"active":false,"na\u006de":"R\u0075t"}})",
         200},
        {R"({"profile":{"name":"Rut","active":true},"age":-2147483648,"id":2147483647})", 409},
        {R"({"profile":{"name":"Other","active":false},"age":-2147483648,"id":2147483647})", 409},
        {R"({"profile":{"name":"Rut","active":false},"age":0,"id":2147483647})", 409},
        {R"({"profile":{"name":"Rut","active":false},"age":-2147483648,"id":-2147483648})", 409},
        {R"({"profile":{"name":"Rut"},"age":0,"id":1})", 422},
        {R"({"profile":{"name":null,"active":false},"age":0,"id":1})", 422},
        {R"({"profile":{"name":"Rut","active":0},"age":0,"id":1})", 422},
        {R"({"profile":null,"age":0,"id":1})", 422},
        {R"({"profile":[],"age":0,"id":1})", 422},
        {R"({"age":0,"id":1})", 422},
        {R"({"profile":{"name":"Rut","active":false},"age":-2147483649,"id":1})", 422},
        {R"({"profile":{"name":"Rut","active":false},"age":2147483648,"id":1})", 422},
        {R"({"profile":{"name":"Rut","active":false},"age":0,"id":2147483648})", 422},
        {R"({"profile":{"name":"Rut","active":false},"age":0,"id":-2147483649})", 422},
        {R"({"profile":{"name":"Rut","active":false},"age":1.5,"id":1})", 422},
        {R"({"profile":{"name":"Rut","active":false},"age":0,"id":"1"})", 422},
        {"[]", 422},
        {"null", 422},
        {R"({"profile":{"name":"Rut","name":"Other","active":false},"age":0,"id":1})", 400},
        {"{", 400},
        // A failed decode must not poison a subsequent request using the same arena.
        {R"({"profile":{"name":"Rut","active":false},"age":-2147483648,"id":2147483647})", 200},
    };
    for (u32 route = 0; route < 2; ++route) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler);
        for (const auto& c : cases) {
            char request[512];
            const int len = snprintf(request,
                                     sizeof(request),
                                     "POST / HTTP/1.1\r\nContent-Length: %u\r\n\r\n%s",
                                     lit(c.body).len,
                                     c.body);
            REQUIRE(len > 0 && static_cast<u32>(len) < sizeof(request));
            const auto result = HandlerResult::unpack(handler(nullptr,
                                                              nullptr,
                                                              reinterpret_cast<const u8*>(request),
                                                              static_cast<u32>(len),
                                                              &arena));
            const u32 expected = route == 1 && c.status == 400 ? 422 : c.status;
            if (result.status_code != expected)
                fprintf(stderr, "JSON route %u, body: %s\n", route, c.body);
            CHECK_EQ(result.status_code, expected);
            arena.reset();
        }
    }
    arena.destroy();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jit, json_helper_owned_strings_survive_workspace_reuse) {
    SlicePool pool;
    REQUIRE(pool.init(64));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 has = 0;
    const char* ptr = nullptr;
    u32 len = 0;
    i64 number = 0;
    auto call = [&](json::Op op, Str input) {
        rut_helper_json(nullptr,
                        &arena,
                        static_cast<u32>(op),
                        input.ptr,
                        input.len,
                        nullptr,
                        0,
                        nullptr,
                        0,
                        0,
                        &has,
                        &ptr,
                        &len,
                        &number);
    };
    char input[] = "\"a\\u0000b\"";
    call(json::Op::AsString, {input, sizeof(input) - 1});
    REQUIRE(has);
    REQUIRE_EQ(len, 3u);
    const Str saved{ptr, len};
    CHECK_EQ(saved.ptr[1], '\0');
    __builtin_memset(input, 'x', sizeof(input) - 1);
    call(json::Op::Quote, lit_str("replacement"));
    REQUIRE(has);
    CHECK((Str{ptr, len}.eq(lit_str("\"replacement\""))));
    CHECK(saved.eq(lit_str("a\0b")));
    call(json::Op::AsString, lit_str("\"\""));
    REQUIRE(has);
    CHECK(ptr != nullptr);
    CHECK_EQ(len, 0u);
    call(json::Op::AsInt, lit_str("9223372036854775808"));
    CHECK_EQ(has, 0u);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    CHECK_EQ(number, 0);
    CHECK(saved.eq(lit_str("a\0b")));
    call(json::Op::AsBool, lit_str("false"));
    REQUIRE(has);
    CHECK_EQ(number, 0);
    arena.destroy();
    pool.destroy();
}

TEST(jit, json_helper_rejects_combined_depth_and_request_budget_overflow) {
    SlicePool pool;
    REQUIRE(pool.init(128));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 has = 1;
    const char* ptr = "stale";
    u32 len = 5;
    i64 number = 1;
    char nested[2 * json::kMaxDepth + 1];
    for (u32 i = 0; i < json::kMaxDepth; ++i) nested[i] = '[';
    nested[json::kMaxDepth] = '0';
    for (u32 i = 0; i < json::kMaxDepth; ++i) nested[json::kMaxDepth + 1 + i] = ']';
    // Both operands are valid alone; their combination is one level too deep.
    rut_helper_json(nullptr,
                    &arena,
                    static_cast<u32>(json::Op::Append),
                    "[]",
                    2,
                    "",
                    0,
                    nested,
                    sizeof(nested),
                    0,
                    &has,
                    &ptr,
                    &len,
                    &number);
    CHECK_EQ(has, 0u);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    CHECK_EQ(number, 0);

    char text[4096];
    __builtin_memset(text, 'x', sizeof(text));
    bool exhausted = false;
    u32 successes = 0;
    for (u32 i = 0; i < 100; ++i) {
        rut_helper_json(nullptr,
                        &arena,
                        static_cast<u32>(json::Op::Quote),
                        text,
                        sizeof(text),
                        nullptr,
                        0,
                        nullptr,
                        0,
                        0,
                        &has,
                        &ptr,
                        &len,
                        &number);
        if (!has) {
            exhausted = true;
            CHECK(ptr == nullptr);
            CHECK_EQ(len, 0u);
            break;
        }
        ++successes;
        CHECK_EQ(len, sizeof(text) + 2);
        CHECK(arena.space_used() <= 262144u);
    }
    CHECK(successes > 0);
    CHECK(exhausted);
    arena.reset();
    rut_helper_json(nullptr,
                    &arena,
                    static_cast<u32>(json::Op::Quote),
                    "ok",
                    2,
                    nullptr,
                    0,
                    nullptr,
                    0,
                    0,
                    &has,
                    &ptr,
                    &len,
                    &number);
    REQUIRE(has);
    CHECK((Str{ptr, len}.eq(lit_str("\"ok\""))));
    arena.destroy();
    pool.destroy();
}

TEST(jit, json_nested_struct_producer_evaluated_once_and_executes) {
    const char* src = R"rut(struct Inner { value: i32 }
struct Outer { inner: Inner, label: str }
func make() -> Outer { Outer(inner: Inner(value: 7), label: "x") }
route GET "/x" { guard let encoded = json(make()) else { return 500 } return response(200, body: encoded) }
)rut";
    auto tokens = lex(lit(src));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    REQUIRE_EQ(mir.value().functions.len, 1u);
    const auto& function = mir.value().functions[0];
    u32 producers = 0;
    for (u32 i = 0; i < function.locals.len; ++i) {
        const auto& local = function.locals[i];
        if (local.name.len == 0 && local.init.kind == MirValueKind::StructInit &&
            local.init.struct_index < mir.value().structs.len &&
            mir.value().structs[local.init.struct_index].name.eq(lit_str("Outer")))
            ++producers;
    }
    CHECK_EQ(producers, 1u);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    SlicePool pool;
    REQUIRE(pool.init(16));
    auto connection = std::make_unique<Connection>();
    connection->reset();
    connection->json_arena.backend.pool = &pool;
    auto result = HandlerResult::unpack(handler(connection.get(),
                                                nullptr,
                                                reinterpret_cast<const u8*>(kGetApiRequest),
                                                sizeof(kGetApiRequest) - 1,
                                                nullptr));
    CHECK_EQ(result.status_code, 200u);
    CHECK(connection->jit_response_body_valid);
    CHECK(connection->jit_response_body.eq(lit_str("{\"inner\":{\"value\":7},\"label\":\"x\"}")));
    connection->reset();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jit, json_decode_nonlocal_source_is_evaluated_once) {
    const char* src = R"rut(
struct Payload { a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32 }
route POST "/decode" {
    guard let doc = req.bodyJson() else { return 400 }
    guard let value = json.decode(Payload,
        json.remove(json.remove(json.remove(json.remove(doc, "/x1").or(doc), "/x2").or(doc), "/x3").or(doc), "/x4").or(doc)) else { return 422 }
    if value.a == 1 && value.b == 2 && value.c == 3 && value.d == 4 &&
       value.e == 5 && value.f == 6 && value.g == 7 && value.h == 8 { return 200 }
    else { return 409 }
}
)rut";
    auto tokens = lex(lit(src));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    const auto& route = hir.value().routes[0];
    u32 synthetic_sources = 0;
    for (u32 i = 0; i < route.locals.len; ++i) {
        const auto& local = route.locals[i];
        if (local.is_runtime_synthetic && local.type == HirTypeKind::Json) synthetic_sources++;
    }
    CHECK_EQ(synthetic_sources, 1u);

    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);

    char body[json::kMaxBytes];
    u32 body_len = 0;
    const char* prefix = "{\"padding\":\"";
    __builtin_memcpy(body + body_len, prefix, strlen(prefix));
    body_len += static_cast<u32>(strlen(prefix));
    __builtin_memset(body + body_len, 'x', 7000);
    body_len += 7000;
    const char* suffix =
        "\",\"x1\":1,\"x2\":2,\"x3\":3,\"x4\":4,\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5,\"f\":6,"
        "\"g\":7,\"h\":8}";
    __builtin_memcpy(body + body_len, suffix, strlen(suffix));
    body_len += static_cast<u32>(strlen(suffix));
    char request[json::kMaxBytes + 128];
    const int header_len = snprintf(
        request, sizeof(request), "POST /decode HTTP/1.1\r\nContent-Length: %u\r\n\r\n", body_len);
    REQUIRE(header_len > 0 && static_cast<u32>(header_len) + body_len < sizeof(request));
    __builtin_memcpy(request + header_len, body, body_len);

    SlicePool pool;
    REQUIRE(pool.init(64));
    auto connection = std::make_unique<Connection>();
    connection->reset();
    connection->json_arena.backend.pool = &pool;
    const auto result = HandlerResult::unpack(handler(connection.get(),
                                                      nullptr,
                                                      reinterpret_cast<const u8*>(request),
                                                      static_cast<u32>(header_len) + body_len,
                                                      nullptr));
    CHECK_EQ(result.status_code, 200u);
    CHECK(connection->json_arena.space_used() < 128 * 1024u);
    connection->reset();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jit, json_struct_producer_respects_route_local_capacity) {
    auto compile_with_preceding_locals = [](u32 local_count) {
        char source[2048]{};
        u32 length = 0;
        auto append = [&](const char* text, u32 text_length) {
            __builtin_memcpy(source + length, text, text_length);
            length += text_length;
        };
        const char* prefix =
            "struct Inner { value: i32 }\n"
            "struct Outer { inner: Inner, label: str }\n"
            "func make() -> Outer { Outer(inner: Inner(value: 7), label: \"x\") }\n"
            "route GET \"/x\" {\n";
        append(prefix,
               sizeof("struct Inner { value: i32 }\n"
                      "struct Outer { inner: Inner, label: str }\n"
                      "func make() -> Outer { Outer(inner: Inner(value: 7), label: \"x\") }\n"
                      "route GET \"/x\" {\n") -
                   1);
        for (u32 i = 0; i < local_count; ++i) {
            char declaration[] = "let v00 = 0\n";
            declaration[5] = static_cast<char>('0' + i / 10);
            declaration[6] = static_cast<char>('0' + i % 10);
            append(declaration, sizeof(declaration) - 1);
        }
        const char* suffix =
            "guard let encoded = json(make()) else { return 500 }\n"
            "return response(200, body: encoded)\n}\n";
        append(suffix,
               sizeof("guard let encoded = json(make()) else { return 500 }\n"
                      "return response(200, body: encoded)\n}\n") -
                   1);
        auto tokens = lex({source, length});
        if (!tokens) return 0x100u + static_cast<u32>(tokens.error().code);
        auto ast = parse_file_heap(tokens.value());
        if (!ast) return 0x200u + static_cast<u32>(ast.error().code);
        auto hir = analyze_file_heap(ast.value());
        if (!hir) return 0x300u + static_cast<u32>(hir.error().code);
        return hir.value().routes[0].locals.len;
    };
    // 13 user locals + Outer/Inner producer locals + the encoded guard binding
    // fill HirRoute::kMaxLocals exactly; one more user local must fail cleanly.
    CHECK_EQ(compile_with_preceding_locals(13), HirRoute::kMaxLocals);
    CHECK_EQ(compile_with_preceding_locals(14),
             0x300u + static_cast<u32>(FrontendError::TooManyItems));
}

TEST(jit, json_decode_source_respects_route_local_capacity) {
    auto compile_with_preceding_locals = [](u32 local_count) {
        char source[1024]{};
        u32 length = 0;
        auto append = [&](const char* text, u32 text_length) {
            __builtin_memcpy(source + length, text, text_length);
            length += text_length;
        };
        const char* prefix = "struct Payload { value: i32 }\nroute POST \"/\" {\n";
        append(prefix, static_cast<u32>(strlen(prefix)));
        for (u32 i = 0; i < local_count; ++i) {
            char declaration[] = "let v00 = 0\n";
            declaration[5] = static_cast<char>('0' + i / 10);
            declaration[6] = static_cast<char>('0' + i % 10);
            append(declaration, sizeof(declaration) - 1);
        }
        const char* suffix =
            "guard let doc = req.bodyJson() else { return 400 }\n"
            "guard let value = json.decode(Payload, json.remove(doc, \"/missing\").or(doc)) "
            "else { return 422 }\n"
            "return 200\n}\n";
        append(suffix, static_cast<u32>(strlen(suffix)));
        auto tokens = lex({source, length});
        if (!tokens) return 0x100u + static_cast<u32>(tokens.error().code);
        auto ast = parse_file_heap(tokens.value());
        if (!ast) return 0x200u + static_cast<u32>(ast.error().code);
        auto hir = analyze_file_heap(ast.value());
        if (!hir) return 0x300u + static_cast<u32>(hir.error().code);
        return hir.value().routes[0].locals.len;
    };
    // The non-local Json source adds one synthetic local before the decoded
    // binding, and must fail cleanly when that exceeds the route-local budget.
    CHECK_EQ(compile_with_preceding_locals(13), HirRoute::kMaxLocals);
    CHECK_EQ(compile_with_preceding_locals(14),
             0x300u + static_cast<u32>(FrontendError::TooManyItems));
}

TEST(jit, gateway_access_module_import_and_policy_order) {
    // Load the shipped example and its real import rather than duplicating helpers.
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/gateway-access.rut";
    std::ifstream input(source_path, std::ios::binary);
    REQUIRE(input.good());
    std::string source((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    for (u32 scenario = 0; scenario < 3; ++scenario) {
        const bool maintenance = scenario == 1;
        const bool empty_host_config = scenario == 2;
        auto src = source;
        if (maintenance) {
            auto pos = src.find("maintenance(false)");
            REQUIRE(pos != std::string::npos);
            src.replace(pos, sizeof("maintenance(false)") - 1, "maintenance(true)");
        }
        if (empty_host_config) {
            auto pos = src.find("api.example.com");
            REQUIRE(pos != std::string::npos);
            src.erase(pos, sizeof("api.example.com") - 1);
        }
        auto lexed = lex(lit(src.c_str()));
        REQUIRE(lexed);
        auto ast = parse_file_heap(lexed.value());
        REQUIRE(ast);
        auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
        if (!hir)
            fprintf(stderr,
                    "access analyze failed at %u:%u: %.*s\n",
                    hir.inner.error().span.line,
                    hir.inner.error().span.col,
                    hir.inner.error().detail.len,
                    hir.inner.error().detail.ptr);
        REQUIRE(hir);
        auto mir = build_mir_heap(hir.value());
        REQUIRE(mir);
        FrontendRirModule rir{};
        REQUIRE(lower_to_rir(mir.value(), rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        auto cg = codegen(rir.module);
        REQUIRE(cg.ok);
        JitEngine engine;
        REQUIRE(engine.init());
        REQUIRE(engine.compile(cg.mod, cg.ctx));
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
        REQUIRE(handler != nullptr);
        struct Case {
            const char* headers;
            u16 status;
        } cases[] = {
            {"Host: api.example.com\r\nX-Client-Version: 1\r\n", 200},
            {"hOsT: api.example.com\r\nx-client-version: 1\r\n", 200},
            {"Host: attacker.example\r\nX-Client-Version: 1\r\n", 403},
            {"Host: api.example.com.attacker.example\r\nX-Client-Version: 1\r\n", 403},
            {"Host: api.example.com:8080\r\nX-Client-Version: 1\r\n", 403},
            {"X-Client-Version: 1\r\n", 403},
            {"Host: api.example.com\r\n", 400},
            {"Host: api.example.com\r\nX-Client-Version: \r\n", 400},
            {"Host: attacker.example\r\n", 403},
        };
        for (const char* version : {"HTTP/1.1", "HTTP/1.0"}) {
            for (const auto& test : cases) {
                auto request = std::string("GET /api ") + version + "\r\n" + test.headers + "\r\n";
                auto result =
                    HandlerResult::unpack(handler(nullptr,
                                                  nullptr,
                                                  reinterpret_cast<const u8*>(request.data()),
                                                  request.size(),
                                                  nullptr));
                CHECK_EQ(result.action, HandlerAction::ReturnStatus);
                CHECK_EQ(result.status_code,
                         maintenance ? 503 : (empty_host_config ? 403 : test.status));
            }
        }
        engine.shutdown();
        rir.destroy();
    }
}

TEST(jit, constant_time_equal_helper_binary_bounds_and_invalid_spans) {
    CHECK_EQ(rut_helper_str_constant_time_equal(nullptr, 0, nullptr, 0), 1);
    CHECK_EQ(rut_helper_str_constant_time_equal(nullptr, 1, "a", 1), 0);
    CHECK_EQ(rut_helper_str_constant_time_equal("a", 1, nullptr, 1), 0);
    CHECK_EQ(rut_helper_str_constant_time_equal(nullptr, 1, nullptr, 2), 0);
    // Invalid/over-limit spans must be rejected before dereferencing their pointers.
    CHECK_EQ(rut_helper_str_constant_time_equal(
                 nullptr, kMaxConstantTimeEqualBytes + 1, nullptr, kMaxConstantTimeEqualBytes + 1),
             0);
    const char a[] = {'a', '\0', static_cast<char>(0xff), 'z'};
    char b[] = {'a', '\0', static_cast<char>(0xff), 'z'};
    CHECK_EQ(rut_helper_str_constant_time_equal(a, sizeof(a), b, sizeof(b)), 1);
    for (u32 i = 0; i < sizeof(a); ++i) {
        b[i] ^= 1;
        CHECK_EQ(rut_helper_str_constant_time_equal(a, sizeof(a), b, sizeof(b)), 0);
        b[i] ^= 1;
    }
    char left[kMaxConstantTimeEqualBytes + 1]{};
    char right[kMaxConstantTimeEqualBytes + 1]{};
    CHECK_EQ(rut_helper_str_constant_time_equal(
                 left, kMaxConstantTimeEqualBytes, right, kMaxConstantTimeEqualBytes),
             1);
    right[kMaxConstantTimeEqualBytes - 1] = 1;
    CHECK_EQ(rut_helper_str_constant_time_equal(
                 left, kMaxConstantTimeEqualBytes, right, kMaxConstantTimeEqualBytes),
             0);
    right[kMaxConstantTimeEqualBytes - 1] = 0;
    CHECK_EQ(rut_helper_str_constant_time_equal(left, sizeof(left), right, sizeof(right)), 0);
}

TEST(jit, constant_time_equal_frontend_helpers_pipe_and_runtime_values) {
    const char* source = R"rut(
func same(_ a: str, _ b: str) -> bool => constantTimeEqual(a, b)
route GET "/compare" {
let a = req.header("X-Left").or("")
let b = req.header("X-Right").or("")
guard constantTimeEqual("fixed", "fixed") else { return 403 }
guard same(a, b) else { return 401 }
guard a | constantTimeEqual(_, b) else { return 402 }
return 200
}
)rut";
    auto lexed = lex(lit(source));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    u32 secure_comparisons = 0;
    for (u32 fi = 0; fi < rir.module.func_count; ++fi)
        for (u32 bi = 0; bi < rir.module.functions[fi].block_count; ++bi)
            for (u32 ii = 0; ii < rir.module.functions[fi].blocks[bi].inst_count; ++ii)
                secure_comparisons += rir.module.functions[fi].blocks[bi].insts[ii].op ==
                                      Opcode::StrConstantTimeEqual;
    CHECK_EQ(secure_comparisons, 3u);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    engine.opt_level = OptLevel::O3;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    struct Case {
        const char* headers;
        u16 status;
    } cases[] = {
        {"X-Left: secret\r\nX-Right: secret\r\n", 200},
        {"X-Left: Secret\r\nX-Right: secret\r\n", 401},
        {"X-Left: secreT\r\nX-Right: secret\r\n", 401},
        {"X-Left: secret-extra\r\nX-Right: secret\r\n", 401},
        {"X-Left: secret\r\n", 401},
        {"", 200},
    };
    for (const auto& test : cases) {
        auto request =
            std::string("GET /compare HTTP/1.1\r\nHost: test\r\n") + test.headers + "\r\n";
        auto result = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    request.size(),
                                                    nullptr));
        CHECK_EQ(result.action, HandlerAction::ReturnStatus);
        CHECK_EQ(result.status_code, test.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, forward_load_balance_survives_timer_yield_and_distinct_routes) {
    const char* source = R"(
upstream api at "127.0.0.1:9001"
route GET "/rr" { return forward(api, load_balance: .roundRobin) }
route GET "/least" { wait(1ms) return forward(api, load_balance: .leastRequests) }
)";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule out{};
    REQUIRE(lower_to_rir(mir.value(), out));
    auto cg = codegen(out.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto rr = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    auto least = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_1"));
    REQUIRE(rr != nullptr);
    REQUIRE(least != nullptr);
    ConnectionBase conn;
    conn.reset();
    HandlerCtx ctx{};
    auto result = HandlerResult::unpack(rr(&conn, &ctx, nullptr, 0, nullptr));
    CHECK_EQ(result.action, HandlerAction::Forward);
    CHECK_EQ(conn.forward_load_balance.policy, LoadBalancePolicy::RoundRobin);
    const u16 first_site = conn.forward_load_balance.site;
    conn.forward_load_balance = {};
    result = HandlerResult::unpack(least(&conn, &ctx, nullptr, 0, nullptr));
    REQUIRE_EQ(result.action, HandlerAction::Yield);
    CHECK_EQ(conn.forward_load_balance.policy, LoadBalancePolicy::None);
    ctx.state = result.next_state;
    ctx.resume_event_kind = static_cast<u32>(YieldKind::Timer);
    result = HandlerResult::unpack(least(&conn, &ctx, nullptr, 0, nullptr));
    CHECK_EQ(result.action, HandlerAction::Forward);
    CHECK_EQ(conn.forward_load_balance.policy, LoadBalancePolicy::LeastRequests);
    CHECK(conn.forward_load_balance.site != first_site);
    engine.shutdown();
    out.destroy();
}

TEST(jit, unique_credential_headers_reject_ambiguity_without_changing_ordinary_reads) {
    const char* src = R"rut(
route GET "/custom" {
    guard let key = req.uniqueHeader("X-API-Key") else { return 401 }
    guard constantTimeEqual(key, "secret") else { return 401 }
    return 200
}
route GET "/authorization" {
    guard let key = req.authorization else { return 401 }
    if key == "Bearer secret" { return 200 } else { return 401 }
}
route GET "/ordinary" {
    guard let tag = req.header("X-Tag") else { return 401 }
    if tag == "first" { return 200 } else { return 401 }
}
)rut";
    auto tokens = lex(lit(src));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        u16 status;
    };
    const Case cases[] = {
        {0, "X-API-Key: secret\r\n", 200},
        {0, "x-api-key: secret\r\n", 200},
        {0, "", 401},
        {0, "X-API-Key: wrong\r\n", 401},
        {0, "X-API-Key: secret\r\nx-api-key: wrong\r\n", 401},
        {0, "X-API-Key: wrong\r\nx-api-key: secret\r\n", 401},
        {0, "X-API-Key: secret\r\nx-api-key: secret\r\n", 401},
        {1, "Authorization: Bearer secret\r\n", 200},
        {1, "Authorization: Bearer secret\r\nauthorization: wrong\r\n", 401},
        {1, "Authorization: Bearer secret\r\nauthorization: Bearer secret\r\n", 401},
        {2, "X-Tag: first\r\nx-tag: second\r\n", 200},
        {0, "X-API-Key: secret\r\n", 200},
        {0, "", 401},
    };
    for (const auto& tc : cases) {
        char name[] = "handler_route_0";
        name[14] = static_cast<char>('0' + tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: local\r\n") + tc.headers + "\r\n";
        auto result = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    static_cast<u32>(request.size()),
                                                    nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK_EQ(result.status_code, tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, basic_authentication_and_key_rotation_identity_matrix) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    const char* src = R"rut(
import "middleware/auth.rut"
route GET "/basic" {
    let identity = auth.basic(req.authorization.or(""), "Aladdin:open sesame", "customer-a", "password-1")
    if identity.method == "basic" && identity.consumerId == "customer-a" && identity.credentialId == "password-1" {
        return 200
    } else { return 500 }
}
route GET "/rotation" {
    let identity = auth.rotatingApiKey(req.authorization.or(""), "new-key", "old-key", "customer-a", "new", "old")
    if identity.credentialId == "new" { return 201 } else { return 202 }
}
route GET "/revoked" {
    let identity = auth.rotatingApiKey(req.authorization.or(""), "new-key", "", "customer-a", "new", "old")
    return 201
}
route GET "/disabled" {
    let identity = auth.rotatingApiKey(req.authorization.or(""), "", "", "customer-a", "new", "old")
    return 201
}
route GET "/duplicate-key" {
    let identity = auth.rotatingApiKey(req.authorization.or(""), "same-key", "same-key", "customer-a", "new", "old")
    if identity.credentialId == "new" { return 201 } else { return 500 }
}
route GET "/empty-basic" {
    let identity = auth.basic(req.authorization.or(""), "", "customer-a", "password-1")
    return 200
}
route GET "/previous-only" {
    let identity = auth.rotatingApiKey(req.authorization.or(""), "", "old-key", "customer-a", "new", "old")
    if identity.credentialId == "old" { return 202 } else { return 500 }
}
route GET "/header-key" {
    let identity = auth.headerKey(req.uniqueHeader("X-API-Key").or(""), "opaque:secret", "customer-b", "header-1")
    if identity.consumerId == "customer-b" && identity.credentialId == "header-1" && identity.method == "apiKey" {
        return 203
    } else { return 500 }
}
route GET "/empty-header-key" {
    let identity = auth.headerKey(req.uniqueHeader("X-API-Key").or(""), "", "customer-b", "header-1")
    return 203
}
route GET "/bearer-token" {
    guard let token = bearerToken(req.authorization.or("")) else { return 401 }
    if constantTimeEqual(token, "new-key") { return 200 } else { return 401 }
}
route GET "/basic-rotation" {
    let identity = auth.rotatingBasic(req.authorization.or(""), "user:new", "user:old", "customer-a", "new", "old")
    guard identity.method == "basic" && identity.consumerId == "customer-a" else { return 500 }
    if identity.credentialId == "new" { return 201 } else { return 202 }
}
route GET "/basic-revoked" {
    let identity = auth.rotatingBasic(req.authorization.or(""), "user:new", "", "customer-a", "new", "old")
    return 201
}
route GET "/basic-disabled" {
    let identity = auth.rotatingBasic(req.authorization.or(""), "", "", "customer-a", "new", "old")
    return 201
}
route GET "/basic-same" {
    let identity = auth.rotatingBasic(req.authorization.or(""), "user:new", "user:new", "customer-a", "new", "old")
    if identity.credentialId == "new" { return 201 } else { return 500 }
}
route GET "/basic-old-only" {
    let identity = auth.rotatingBasic(req.authorization.or(""), "", "user:old", "customer-a", "new", "old")
    if identity.credentialId == "old" { return 202 } else { return 500 }
}
route GET "/basic-missing-id" {
    let identity = auth.rotatingBasic(req.authorization.or(""), "user:new", "user:old", "customer-a", "", "old")
    return 201
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "auth matrix: %d %.*s at %u:%u\n",
                     static_cast<int>(hir.error().code),
                     static_cast<int>(hir.error().detail.len),
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        u16 status;
    };
    const Case cases[] = {
        {0, "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n", 200},
        {0, "Authorization: bAsIc   QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n", 200},
        {0,
         "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\nX-Consumer-ID: attacker\r\n",
         200},
        {0, "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZR==\r\n", 401},
        {0, "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ\r\n", 401},
        {0, "Authorization: Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n", 401},
        {0,
         "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\nauthorization: Basic wrong\r\n",
         401},
        {0, "X-Consumer-ID: customer-a\r\n", 401},
        {1, "Authorization: Bearer new-key\r\n", 201},
        {1, "Authorization: bearer   old-key\r\n", 202},
        {1, "Authorization: Bearer invalid\r\n", 401},
        {1, "", 401},
        {2, "Authorization: Bearer old-key\r\n", 401},
        {2, "Authorization: Bearer new-key\r\n", 201},
        {3, "Authorization: Bearer new-key\r\n", 503},
        {4, "Authorization: Bearer same-key\r\n", 201},
        {5, "", 503},
        {6, "Authorization: Bearer old-key\r\n", 202},
        {6, "Authorization: Bearer new-key\r\n", 401},
        {7, "X-API-Key: opaque:secret\r\n", 203},
        {7, "x-api-key: opaque:secret\r\nX-Consumer-ID: attacker\r\n", 203},
        {7, "", 401},
        {7, "X-API-Key: \r\n", 401},
        {7, "X-API-Key: wrong\r\n", 401},
        {7, "X-API-Key: opaque:secret\r\nx-api-key: wrong\r\n", 401},
        {7, "X-API-Key: wrong\r\nx-api-key: opaque:secret\r\n", 401},
        {7, "X-API-Key: opaque:secret\r\nx-api-key: opaque:secret\r\n", 401},
        {7, "Authorization: Bearer opaque:secret\r\n", 401},
        {7, "X-API-Key: opaque:secret\r\n", 203},
        {8, "", 503},
        {9, "Authorization: bEaReR   new-key\r\n", 200},
        {9, "Authorization: Bearer new-key,other\r\n", 401},
        {9, "Authorization: Basic new-key\r\n", 401},
        {9, "", 401},
        {10, "Authorization: Basic dXNlcjpuZXc=\r\n", 201},
        {10, "Authorization: Basic dXNlcjpvbGQ=\r\n", 202},
        {10, "Authorization: Basic dXNlcjpiYWQ=\r\n", 401},
        {10, "", 401},
        {10, "Authorization: Basic dXNlcjpuZXc=\r\nauthorization: Basic dXNlcjpvbGQ=\r\n", 401},
        {11, "Authorization: Basic dXNlcjpvbGQ=\r\n", 401},
        {11, "Authorization: Basic dXNlcjpuZXc=\r\n", 201},
        {12, "", 503},
        {13, "Authorization: Basic dXNlcjpuZXc=\r\n", 201},
        {14, "Authorization: Basic dXNlcjpvbGQ=\r\n", 202},
        {14, "Authorization: Basic dXNlcjpuZXc=\r\n", 401},
        {15, "Authorization: Basic dXNlcjpuZXc=\r\n", 503},
    };
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + tc.headers + "\r\n";
        auto result = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    static_cast<u32>(request.size()),
                                                    nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK(result.status_code == tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, multi_authentication_and_consumer_authorization) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    const char* src = R"rut(
import "middleware/auth.rut"
route GET "/both" {
    let identity = auth.apiKeyOrBasic(req.authorization.or(""), "secret", "user:pass", "customer-a", "key-1", "password-1")
    let permitted = auth.requireConsumer(identity, "customer-a")
    if permitted.consumerId == "customer-a" && permitted.method == "apiKey" && permitted.credentialId == "key-1" {
        return 201
    } else {
        if permitted.method == "basic" && permitted.credentialId == "password-1" { return 202 } else { return 500 }
    }
}
route GET "/key-only" {
    let identity = auth.apiKeyOrBasic(req.authorization.or(""), "secret", "", "customer-a", "key-1", "password-1")
    return 200
}
route GET "/basic-only" {
    let identity = auth.apiKeyOrBasic(req.authorization.or(""), "", "user:pass", "customer-a", "key-1", "password-1")
    return 200
}
route GET "/disabled" {
    let identity = auth.apiKeyOrBasic(req.authorization.or(""), "", "", "customer-a", "key-1", "password-1")
    return 200
}
route GET "/missing-id" {
    let identity = auth.apiKeyOrBasic(req.authorization.or(""), "secret", "", "customer-a", "key-1", "")
    return 200
}
route GET "/allow-mismatch" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "customer-a", "key-1")
    let permitted = auth.requireConsumer(identity, "customer")
    return 200
}
route GET "/deny-match" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "customer-a", "key-1")
    let permitted = auth.denyConsumer(identity, "customer-a")
    return 200
}
route GET "/deny-mismatch" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "customer-a", "key-1")
    let first = auth.denyConsumer(identity, "customer")
    let permitted = auth.denyConsumer(first, "Customer-a")
    if permitted.credentialId == "key-1" { return 200 } else { return 500 }
}
route GET "/empty-allow" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "customer-a", "key-1")
    let permitted = auth.requireConsumer(identity, "")
    return 200
}
route GET "/empty-deny" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "customer-a", "key-1")
    let permitted = auth.denyConsumer(identity, "")
    return 200
}
route GET "/deny-before-allow" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "customer-a", "key-1")
    let first = auth.denyConsumer(identity, "customer-a")
    let permitted = auth.requireConsumer(first, "customer-a")
    return 200
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "multi-auth: code=%d %.*s at %u:%u\n",
                     static_cast<int>(hir.error().code),
                     static_cast<int>(hir.error().detail.len),
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    if (!mir)
        std::fprintf(stderr,
                     "multi-auth MIR: code=%d %.*s at %u:%u\n",
                     static_cast<int>(mir.error().code),
                     static_cast<int>(mir.error().detail.len),
                     mir.error().detail.ptr,
                     mir.error().span.line,
                     mir.error().span.col);
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        u16 status;
    };
    const Case cases[] = {
        {0, "Authorization: Bearer secret\r\n", 201},
        {0, "Authorization: Basic dXNlcjpwYXNz\r\n", 202},
        {0, "Authorization: bAsIc   dXNlcjpwYXNz\r\n", 202},
        {0, "", 401},
        {0, "Authorization: Bearer wrong\r\n", 401},
        {0, "Authorization: Basic wrong\r\n", 401},
        {0, "Authorization: Digest secret\r\n", 401},
        {0, "Authorization: Basic secret\r\n", 401},
        {0, "Authorization: Bearer dXNlcjpwYXNz\r\n", 401},
        {0, "Authorization: Bearer secret, Basic dXNlcjpwYXNz\r\n", 401},
        {0, "Authorization: Bearer secret\r\nauthorization: Basic dXNlcjpwYXNz\r\n", 401},
        {0, "Authorization: Basic dXNlcjpwYXNz\r\nauthorization: Bearer secret\r\n", 401},
        {0, "Authorization: Bearer secret\r\nAuthorization: Bearer secret\r\n", 401},
        {0, "X-Consumer-ID: customer-a\r\nX-API-Key: secret\r\n", 401},
        {0, "Authorization: Bearer secret\r\nX-Consumer-ID: attacker\r\n", 201},
        {0, "Authorization: Basic dXNlcjpwYXNz\r\n", 202},
        {1, "Authorization: Bearer secret\r\n", 200},
        {1, "Authorization: Basic dXNlcjpwYXNz\r\n", 401},
        {2, "Authorization: Basic dXNlcjpwYXNz\r\n", 200},
        {2, "Authorization: Bearer secret\r\n", 401},
        {3, "Authorization: Bearer secret\r\n", 503},
        {4, "Authorization: Bearer secret\r\n", 503},
        {5, "Authorization: Bearer secret\r\nX-Consumer-ID: customer\r\n", 403},
        {5, "", 401},
        {6, "Authorization: Bearer secret\r\n", 403},
        {6, "", 401},
        {7, "Authorization: Bearer secret\r\n", 200},
        {8, "Authorization: Bearer secret\r\n", 503},
        {9, "Authorization: Bearer secret\r\n", 503},
        {10, "Authorization: Bearer secret\r\n", 403},
    };
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + tc.headers + "\r\n";
        auto result = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    static_cast<u32>(request.size()),
                                                    nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != tc.status)
            std::fprintf(stderr,
                         "multi-auth route %u: got %u expected %u\n",
                         tc.route,
                         result.status_code,
                         tc.status);
        CHECK(result.status_code == tc.status);
        if (tc.status == 401) {
            REQUIRE(result.next_state != 0);
            REQUIRE(result.next_state <= rir.module.header_set_count);
            const auto& headers = rir.module.header_sets[result.next_state - 1];
            CHECK(headers.count == (tc.route <= 4 ? 2 : 1));
            CHECK(rir.module.header_keys[headers.offset].eq(lit("WWW-Authenticate")));
            CHECK(rir.module.header_values[headers.offset].eq(lit("Bearer")));
            if (tc.route <= 4) {
                CHECK(rir.module.header_keys[headers.offset + 1].eq(lit("WWW-Authenticate")));
                CHECK(rir.module.header_values[headers.offset + 1].eq(lit("Basic realm=\"rut\"")));
            }
        } else {
            // Neither authorization failures nor config failures carry a challenge.
            CHECK(result.next_state == 0);
        }
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, large_inlined_auth_policy_grows_expression_pools) {
    // A balanced tree exercises thousands of nodes without making source nesting
    // depth or the number of locals/guards the limiting factor.
    auto choices = [](auto&& self, u32 begin, u32 end) -> std::string {
        if (end - begin == 1) return "value == \"consumer-" + std::to_string(begin) + "\"";
        const u32 middle = begin + (end - begin) / 2;
        return "(" + self(self, begin, middle) + " || " + self(self, middle, end) + ")";
    };
    const std::string source =
        "func allowed(_ value: str) -> bool => " + choices(choices, 0, 256) +
        "\nroute GET \"/\" { let ok = allowed(req.uniqueHeader(\"X-Consumer\").or(\"\")) "
        "if ok { return 200 } else { return 403 } }";
    auto lexed = lex(lit(source.c_str()));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    CHECK(hir->functions[0].exprs.len > 128);
    CHECK(hir->routes[0].exprs.len > 128);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    CHECK(mir->functions[0].values.len > 128);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    for (const char* value : {"consumer-0", "consumer-127", "consumer-255", "consumer-256", ""}) {
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\nX-Consumer: ") + value + "\r\n\r\n";
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK(result.status_code ==
              (value[0] != '\0' && !lit(value).eq(lit("consumer-256")) ? 200 : 403));
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, codegen_grows_block_map_beyond_stack_scratch) {
    TestContext tc;
    REQUIRE(tc.init());
    Builder b;
    b.init(&tc.mod);
    auto* fn = V(b.create_function(lit("many_blocks"), lit("/"), 'G'));
    rir::BlockId blocks[96];
    for (auto& block : blocks) block = V(b.create_block(fn, lit("step")));
    for (u32 i = 0; i < 96; ++i) {
        b.set_insert_point(fn, blocks[i]);
        if (i + 1 == 96) {
            VOK(b.emit_ret_status(204));
        } else {
            VOK(b.emit_jmp(blocks[i + 1]));
        }
    }
    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_many_blocks"));
    REQUIRE(handler != nullptr);
    const auto result = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
    CHECK(result.action == HandlerAction::ReturnStatus);
    CHECK(result.status_code == 204);
    engine.shutdown();
}

TEST(jit, crypto_system_import_checks_namespace_and_argument_types) {
    const char* valid = R"rut(
import Crypto
func equal(_ a: str, _ b: str) -> bool => false
route GET "/" {
    guard Crypto.equal("same", "same") else { return 401 }
    guard !equal("same", "same") else { return 402 }
    guard let digest = digestSha256("abc") else { return 503 }
    guard digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" else { return 500 }
    return 200
}

)rut";
    auto tokens = lex(lit(valid));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    SlicePool pool;
    REQUIRE(pool.init(4));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const auto result = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, &arena));
    CHECK_EQ(result.status_code, 200u);
    arena.destroy();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
    const char* invalid[] = {
        "route GET \"/\" { guard Crypto.equal(\"a\", \"a\") else { return 401 } return 200 }",
        "import Crypto\nroute GET \"/\" { guard Crypto.equal(\"a\", 1) else { return 401 } return "
        "200 }",
        "import Crypto\nroute GET \"/\" { guard Crypto.unknown(\"a\") else { return 401 } return "
        "200 }",
        "import Crypto\nfunc unknown(_ value: str) -> bool => true\n"
        "route GET \"/\" { guard Crypto.unknown(\"a\") else { return 401 } return 200 }",
    };
    for (const char* source : invalid) {
        auto parsed_tokens = lex(lit(source));
        REQUIRE(parsed_tokens);
        auto parsed = parse_file_heap(parsed_tokens.value());
        REQUIRE(parsed);
        CHECK(!analyze_file_heap(parsed.value()));
    }
}

TEST(jit, crypto_system_webhook_valid_routes_through_native_runtime) {
    timespec now{};
    REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
    REQUIRE(now.tv_sec > 1000);
    const std::string timestamp = std::to_string(now.tv_sec);
    const std::string message = "msg_1." + timestamp + ".hello";
    unsigned char digest[32];
    unsigned int digest_len = 0;
    REQUIRE(HMAC(EVP_sha256(),
                 "secret",
                 6,
                 reinterpret_cast<const unsigned char*>(message.data()),
                 message.size(),
                 digest,
                 &digest_len) != nullptr);
    REQUIRE(digest_len == sizeof(digest));
    unsigned char encoded[45];
    REQUIRE(EVP_EncodeBlock(encoded, digest, sizeof(digest)) == 44);
    const std::string signature = "v1," + std::string(reinterpret_cast<const char*>(encoded), 44);
    const std::string source =
        "import Crypto\n"
        "route GET \"/valid\" { guard Crypto.webhookValid(\"msg_1\", \"" +
        timestamp + "\", \"" + signature +
        "\", \"hello\", \"secret\") else { return 401 } return 204 }\n" +
        "route GET \"/invalid\" { guard Crypto.webhookValid(\"msg_1\", \"" + timestamp + "\", \"" +
        signature + "\", \"Hello\", \"secret\") else { return 401 } return 204 }\n";
    auto tokens = lex(lit(source.c_str()));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    for (u32 i = 0; i < 2; ++i) {
        const std::string name = "handler_route_" + std::to_string(i);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name.c_str()));
        REQUIRE(handler);
        const auto result = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
        CHECK_EQ(result.status_code, i == 0 ? 204u : 401u);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, crypto_system_import_works_at_file_import_depth_limit) {
    char directory[] = "/tmp/rut_crypto_module_XXXXXX";
    REQUIRE(mkdtemp(directory));
    const std::string dir = directory;
    {
        std::ofstream file(dir + "/a.rut");
        file << "import \"b.rut\"\nfunc outer() -> bool => b.inner()\n";
    }
    {
        std::ofstream file(dir + "/b.rut");
        file << "import Crypto\nfunc inner() -> bool => Crypto.equal(\"a\", \"a\")\n";
    }
    const auto source = R"rut(
import "a.rut"
route GET "/" { guard a.outer() else { return 401 } return 200 }
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), dir + "/main.rut");
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    const auto result = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
    CHECK_EQ(result.status_code, 200u);
    engine.shutdown();
    rir.destroy();
    std::filesystem::create_directories(dir + "/@rut");
    {
        std::ofstream file(dir + "/@rut/Crypto.rut");
        file << "func equal(_ a: str, _ b: str) -> bool => true\n";
    }
    const auto collision = R"rut(
import Crypto
import "@rut/Crypto.rut"
route GET "/" { return 200 }
)rut";
    auto collision_tokens = lex(lit(collision));
    REQUIRE(collision_tokens);
    auto collision_ast = parse_file_heap(collision_tokens.value());
    REQUIRE(collision_ast);
    CHECK(!analyze_file_heap_with_path(collision_ast.value(), dir + "/main.rut"));
    std::filesystem::remove_all(dir);
}

TEST(jit, crypto_system_import_coexists_with_auth_module) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    const auto source = R"rut(
import Crypto
import "middleware/auth.rut"
route GET "/" {
    guard Crypto.equal("same", "same") else { return 500 }
    let identity = auth.hmac("abc", "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab", "key", "user", "key-id")
    guard identity.consumerId == "user" else { return 500 }
    return 200
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    const auto result = HandlerResult::unpack(handler(nullptr, nullptr, nullptr, 0, nullptr));
    CHECK_EQ(result.status_code, 200u);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, hmac_webhook_authentication_and_rotation) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/webhook-auth.rut";
    const char* source = R"rut(
import "middleware/auth.rut"
route POST "/webhook" {
    let identity = auth.githubWebhook(req.body, req.uniqueHeader("X-Hub-Signature-256").or(""),
                                      "It's a Secret to Everybody", "github", "webhook-1")
    guard identity.consumerId == "github" && identity.method == "hmac" else { return 500 }
    return 204
}
route POST "/rotate" {
    let identity = auth.rotatingHmac(req.body, req.uniqueHeader("X-Signature").or(""),
                                     "new-secret", "It's a Secret to Everybody", "github", "new", "old")
    guard identity.credentialId == "old" else { return 500 }
    return 202
}
route POST "/revoked" {
    let identity = auth.rotatingHmac(req.body, req.uniqueHeader("X-Signature").or(""),
                                     "new-secret", "", "github", "new", "old")
    return 204
}
route POST "/misconfigured" {
    let identity = auth.githubWebhook(req.body, req.uniqueHeader("X-Hub-Signature-256").or(""), "", "github", "webhook-1")
    return 204
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "hmac analysis %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    // The runtime must buffer the complete framed body before verification.
    for (u32 i = 0; i < rir.module.func_count; ++i)
        CHECK(rir_function_needs_req_body(rir.module.functions[i]));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        const char* body;
        u16 status;
    };
    const Case cases[] = {
        {0,
         "X-Hub-Signature-256: "
         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, World!",
         204},
        {0,
         "x-hub-signature-256: "
         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\nX-Consumer-ID:"
         " attacker\r\n",
         "Hello, World!",
         204},
        {0,
         "X-Hub-Signature-256: "
         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, world!",
         401},
        {0,
         "X-Hub-Signature-256: "
         "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, World!",
         401},
        {0,
         "X-Hub-Signature-256: "
         "sha1=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, World!",
         401},
        {0,
         "X-Hub-Signature-256: "
         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\nx-hub-"
         "signature-256: "
         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, World!",
         401},
        {0, "", "Hello, World!", 401},
        {0, "X-Hub-Signature-256: sha256=\r\n", "Hello, World!", 401},
        {1,
         "X-Signature: 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, World!",
         202},
        {2,
         "X-Signature: 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17\r\n",
         "Hello, World!",
         401},
        {3, "", "Hello, World!", 503},
    };
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        const std::string body(tc.body);
        const std::string request =
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\n" + tc.headers + "\r\n" + body;
        auto result = HandlerResult::unpack(handler(nullptr,
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    static_cast<u32>(request.size()),
                                                    nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK(result.status_code == tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, digest_and_hmac_builtins_return_owned_hex_for_exact_body_bytes) {
    const char* source = R"rut(
func digestInHelper(_ data: str) -> str {
    guard let value = sha256(data) else { respond 503 }
    value
}
route POST "/md5" {
    guard let digest = md5(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/sha1" {
    guard let digest = sha1(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/sha224" {
    guard let digest = sha224(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/sha256" {
    guard let digest = sha256(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/sha384" {
    guard let digest = sha384(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/sha512" {
    guard let digest = sha512(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/hmacMd5" {
    guard let digest = hmacMd5("Jefe", req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/hmacSha1" {
    guard let digest = hmacSha1("Jefe", req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/hmacSha224" {
    guard let digest = hmacSha224("Jefe", req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/hmacSha256" {
    guard let digest = hmacSha256("Jefe", req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/hmacSha384" {
    guard let digest = hmacSha384("Jefe", req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/hmacSha512" {
    guard let digest = hmacSha512("Jefe", req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/lifetime" {
    guard let first = sha256(req.body) else { return 503 }
    guard let second = sha512(req.body) else { return 503 }
    guard first == req.uniqueHeader("X-Expected").or("") else { return 409 }
    return response(200, body: first)
}
route POST "/helper" {
    let digest = digestInHelper(req.body)
    return response(200, body: digest)
}
route POST "/nested" {
    guard let first = sha256(req.body) else { return 503 }
    guard let nested = sha256(first) else { return 503 }
    return response(200, body: nested)
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    if (!hir)
        std::fprintf(stderr,
                     "hash analysis %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    SlicePool pool;
    REQUIRE(pool.init(64));
    auto connection = std::make_unique<Connection>();
    struct Case {
        u32 route;
        const char* body;
        u32 length;
        const char* expected;
    };
    const Case cases[] = {
        {0, "", 0, "d41d8cd98f00b204e9800998ecf8427e"},
        {0, "\x61\x62\x63", 3, "900150983cd24fb0d6963f7d28e17f72"},
        {0, "\x61\x00\x62\xff", 4, "0dd4df5b5be53b9566c53387ec9a7bac"},
        {1, "", 0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {1, "\x61\x62\x63", 3, "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {1, "\x61\x00\x62\xff", 4, "63fcb4a9187af3e3e3319584f43e809426e0b000"},
        {2, "", 0, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        {2, "\x61\x62\x63", 3, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
        {2, "\x61\x00\x62\xff", 4, "6aa2a868a9c3ce5b5410a8873d4d7dac6d755965e4836f79dd30fe47"},
        {3, "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {3, "\x61\x62\x63", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {3,
         "\x61\x00\x62\xff",
         4,
         "a37cc3026aae4d519e0b19c298fa913b4dccfdf0658cbccbb7deaa0226d5acdb"},
        {4,
         "",
         0,
         "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14"
         "898b95b"},
        {4,
         "\x61\x62\x63",
         3,
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca13"
         "4c825a7"},
        {4,
         "\x61\x00\x62\xff",
         4,
         "47f55ceefdbee8e10c2d3621c27916990d7dc39155a09dffc95096d05b7f920f60218dc4a0e184b24a6a3a68b"
         "90f5765"},
        {5,
         "",
         0,
         "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d28"
         "77eec2f63b931bd47417a81a538327af927da3e"},
        {5,
         "\x61\x62\x63",
         3,
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a"
         "3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
        {5,
         "\x61\x00\x62\xff",
         4,
         "1e76645fa15e740d214209146606412765717327c1ec1f3f8ef0bb29af267ff80fbc4a459420a32b19508e175"
         "20e7ded1cf6a9633186d1f1381aa67dc075ef39"},
        {6, "", 0, "60b57da4237ed7c91b475eddf0e798d3"},
        {6, "\x61\x62\x63", 3, "0c23dc19a0f341f59659378f4621bb4b"},
        {6, "\x61\x00\x62\xff", 4, "2c090028602287ab3f9c34e1c3d62222"},
        {7, "", 0, "09d9e59d72239e62a8155c583d52743de9b7231a"},
        {7, "\x61\x62\x63", 3, "1f81e4c0f425d93623df95a0eb5672555612abbb"},
        {7, "\x61\x00\x62\xff", 4, "b541a7358b164af0df7bdefd9ab230ff2e9393eb"},
        {8, "", 0, "e10ba93c2f6fae317af180e83500ed3d54e812db29eadb25ccc43d30"},
        {8, "\x61\x62\x63", 3, "88496a64f06a13e26cea871fe4cfcd58ae7471d86f8d5f3374e02b9e"},
        {8, "\x61\x00\x62\xff", 4, "3be6ab496af031e07e0bb43d4cd833605c8edb27449099a72f84b26d"},
        {9, "", 0, "923598ca6d64af2a5dba79dcd021a8a0fe5c5f557519adaaf0ad532d4506dd30"},
        {9, "\x61\x62\x63", 3, "7cf4ec4f741f51cb0d887013c46251d6f4175643c4f422906a1aaec688cc13e8"},
        {9,
         "\x61\x00\x62\xff",
         4,
         "5bf498b8d33c6bf3082794b7e7d7d04a35ba35c822c5bf519dfead05b87ca434"},
        {10,
         "",
         0,
         "99e07b65e0bfdedd41f44a433e51475a027ef03fe6c9bb6ecf67a700d375dae3863d8b5c3ff63c693d942a291"
         "add2e78"},
        {10,
         "\x61\x62\x63",
         3,
         "f73621bbae8b012137a65db5ab260ac622fded492b1443aec9f0679cefb908539463ee92a7dc0944fd3cc9373"
         "8e4eaf5"},
        {10,
         "\x61\x00\x62\xff",
         4,
         "bd44d3dcc426cfda3f1475a3e5aa055a95003e33ae9340d69289c3c50d8fb7d2365f86479fdc9f8a7a0a80650"
         "35eb9a5"},
        {11,
         "",
         0,
         "b9d14c51a6d4dd41604eb06c9c240f1f64f143b5cfdea37129b28bb75d1371d326fc219216171261a84e6c057"
         "07cd3be0f61e0a973a33f706d190db9acffc68f"},
        {11,
         "\x61\x62\x63",
         3,
         "b5af0318c3b88834d89dda9fe6461f2e9fecc953e6f94a09c1786509b1819e5baa8225e9e26268763c41fec71"
         "0d4cf8cbd29f854215da3455bded16172b932bd"},
        {11,
         "\x61\x00\x62\xff",
         4,
         "9ebec6d25b8bede43592b9635373df98681f31dedd1252735063e1f86762fb97609e35d0020059a9ed6c154d6"
         "c4fa2810c7076871f4d7b8320d2d509eb0bffd5"},
        {12, "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {13, "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {14, "abc", 3, "dfe7a23fefeea519e9bbfdd1a6be94c4b2e4529dd6b7cbea83f9959c2621b13c"},
    };
    for (const auto& tc : cases) {
        char symbol[32];
        snprintf(symbol, sizeof(symbol), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(symbol));
        REQUIRE(handler);
        connection->reset();
        connection->json_arena.backend.pool = &pool;
        const std::string request =
            "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: " + std::to_string(tc.length) +
            "\r\nX-Expected: " + tc.expected + "\r\n\r\n" + std::string(tc.body, tc.length);
        auto result = HandlerResult::unpack(handler(connection.get(),
                                                    nullptr,
                                                    reinterpret_cast<const u8*>(request.data()),
                                                    static_cast<u32>(request.size()),
                                                    nullptr));
        CHECK_EQ(result.status_code, 200u);
        REQUIRE(connection->jit_response_body_valid);
        CHECK(connection->jit_response_body.eq(lit(tc.expected)));
    }
    // Missing result storage must produce nil rather than a borrowed stack view.
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    const char request[] = "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n";
    auto missing = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(request), sizeof(request) - 1, nullptr));
    CHECK_EQ(missing.status_code, 503u);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, hash_helper_enforces_storage_budget_without_overwriting_prior_results) {
    SlicePool pool;
    REQUIRE(pool.init(64));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 has = 99;
    const char* text = nullptr;
    u32 length = 99;
    rut_helper_hash(nullptr, &arena, 3, "abc", 3, nullptr, 0, &has, &text, &length);
    REQUIRE_EQ(has, 1u);
    const Str first{text, length};
    while (arena.space_used() < 256 * 1024) REQUIRE(arena.alloc(128));
    rut_helper_hash(nullptr, &arena, 5, "abc", 3, nullptr, 0, &has, &text, &length);
    CHECK_EQ(has, 0u);
    CHECK(text == nullptr);
    CHECK_EQ(length, 0u);
    CHECK(first.eq(lit("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")));
    rut_helper_hash(nullptr, &arena, 0x200, "abc", 3, nullptr, 0, &has, &text, &length);
    CHECK_EQ(has, 0u);
}

TEST(jit, credential_removal_preserves_original_authentication_reads) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    const char* source = R"rut(
import "middleware/auth.rut"
upstream backend
route GET "/bearer" {
    req.remove("Authorization")
    req.remove("X-API-Key")
    req.remove("X-Consumer-ID")
    let identity = auth.apiKey(req.authorization.or(""), "secret", "consumer", "key-1")
    if identity.consumerId == "consumer" { return forward(backend, load_balance: .roundRobin) } else { return 403 }
}
route GET "/custom" {
    req.remove("Authorization")
    req.remove("X-API-Key")
    req.remove("X-Consumer-ID")
    let identity = auth.headerKey(req.uniqueHeader("X-API-Key").or(""), "opaque:key", "consumer", "key-2")
    if identity.credentialId == "key-2" { return forward(backend, load_balance: .roundRobin) } else { return 403 }
}
route GET "/branch" {
    match req.header("X-Strip").or("") {
        "yes" => { req.remove("Authorization") return 200 }
        _ => return 200
    }
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    if (!ast)
        std::fprintf(stderr,
                     "credential removal parse: %.*s at %u:%u\n",
                     static_cast<int>(ast.error().detail.len),
                     ast.error().detail.ptr,
                     ast.error().span.line,
                     ast.error().span.col);
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "credential removal: %.*s at %u:%u\n",
                     static_cast<int>(hir.error().detail.len),
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        bool forward;
    };
    const Case cases[] = {
        {0, "Authorization: Bearer secret\r\n", true},
        {0, "Authorization: Bearer wrong\r\n", false},
        {0, "", false},
        {0, "Authorization: Bearer secret\r\nauthorization: Bearer secret\r\n", false},
        {0, "Authorization: Bearer secret\r\nX-Consumer-ID: attacker\r\n", true},
        {1, "X-API-Key: opaque:key\r\nAuthorization: garbage\r\n", true},
        {1, "X-API-Key: wrong\r\n", false},
        {1, "X-API-Key: opaque:key\r\nx-api-key: opaque:key\r\n", false},
        {1, "", false},
        {1, "x-api-key: opaque:key\r\n", true},
    };
    Connection conn;
    conn.reset();
    for (const auto& test : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", test.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        conn.reset();
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + test.headers + "\r\n";
        const auto result =
            HandlerResult::unpack(handler(&conn,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action ==
              (test.forward ? HandlerAction::Forward : HandlerAction::ReturnStatus));
        if (!test.forward) CHECK(result.status_code == 401);
        CHECK(conn.req_header_override_count == 3);
        CHECK(conn.req_header_remove_mask == 7);
        CHECK(conn.req_header_append_mask == 0);
        CHECK(conn.req_header_overrides[0].name.eq(lit("Authorization")));
        CHECK(conn.req_header_overrides[1].name.eq(lit("X-API-Key")));
        CHECK(conn.req_header_overrides[2].name.eq(lit("X-Consumer-ID")));
        if (test.forward) {
            u8 wire[512]{};
            u32 wire_len = 0;
            REQUIRE(h2_prepare_forward_request(conn,
                                               reinterpret_cast<const u8*>(request.data()),
                                               static_cast<u32>(request.size()),
                                               wire,
                                               sizeof(wire),
                                               &wire_len));
            const char expected[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
            CHECK(wire_len == sizeof(expected) - 1);
            CHECK(__builtin_memcmp(wire, expected, sizeof(expected) - 1) == 0);
        }
    }
    auto branch_handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_2"));
    REQUIRE(branch_handler != nullptr);
    for (bool strip : {true, false}) {
        conn.reset();
        const char* request = strip ? "GET / HTTP/1.1\r\nHost: localhost\r\nX-Strip: "
                                      "yes\r\nAuthorization: secret\r\n\r\n"
                                    : "GET / HTTP/1.1\r\nHost: localhost\r\nX-Strip: "
                                      "no\r\nAuthorization: secret\r\n\r\n";
        const auto result = HandlerResult::unpack(branch_handler(
            &conn, nullptr, reinterpret_cast<const u8*>(request), lit(request).len, nullptr));
        CHECK(result.status_code == 200);
        CHECK(conn.req_header_override_count == (strip ? 1 : 0));
        CHECK(conn.req_header_remove_mask == (strip ? 1 : 0));
    }
    conn.reset();
    CHECK(conn.req_header_remove_mask == 0);
    CHECK(conn.req_header_override_count == 0);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, direct_ir_credential_removal_overflow_is_explicit) {
    TestContext tc;
    REQUIRE(tc.init());
    Builder b;
    b.init(&tc.mod);
    auto* fn = V(b.create_function(lit("remove_overflow"), lit("/"), 'G'));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);
    for (u32 i = 0; i <= ConnectionBase::kMaxReqHeaderOverrides; ++i)
        VOK(b.emit_req_remove_header(lit("Authorization")));
    VOK(b.emit_ret_status(200));
    auto cg = codegen(tc.mod);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_remove_overflow"));
    REQUIRE(handler != nullptr);
    Connection conn;
    conn.reset();
    handler(&conn, nullptr, nullptr, 0, nullptr);
    CHECK(conn.req_header_override_overflow);
    CHECK(conn.req_header_override_count == ConnectionBase::kMaxReqHeaderOverrides);
    CHECK(conn.req_header_remove_mask == 0xffffu);
    CHECK(conn.req_header_append_mask == 0);
    engine.shutdown();
}

TEST(jit, optional_response_headers_set_remove_and_commit_on_guard_status) {
    const char* source = R"rut(
func conditional_headers(_ req: i32, _ resp: Response) -> i32 {
    resp.set("X-Test", req.uniqueHeader("X-Test"))
    0
}
func fail_request() -> i32 => error(.timeout)
chain headers { after conditional_headers(req, resp) }
route GET "/" use chain headers {
    guard req.http11 else { return 505 }
    return 204
}
route GET "/fault" use chain headers {
    let code = fail_request()
    if code == 200 { return 204 } else { return 204 }
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    auto fault_handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_1"));
    REQUIRE(fault_handler);
    struct Case {
        const char* request;
        bool present;
        const char* value;
        u16 status;
    };
    const Case cases[] = {
        {"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: yes\r\n\r\n", true, "yes", 204},
        {"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", false, "", 204},
        {"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test:\r\n\r\n", true, "", 204},
        {"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: a\r\nX-Test: b\r\n\r\n", false, "", 204},
        {"GET / HTTP/1.0\r\nHost: localhost\r\nX-Test: yes\r\n\r\n", true, "yes", 505},
    };
    Connection conn;
    for (const auto& item : cases) {
        conn.reset();
        const auto result = HandlerResult::unpack(handler(&conn,
                                                          nullptr,
                                                          reinterpret_cast<const u8*>(item.request),
                                                          lit(item.request).len,
                                                          nullptr));
        CHECK(result.status_code == item.status);
        CHECK(conn.resp_header_mutation_count == 1);
        const auto& mutation = conn.resp_header_mutations[0];
        CHECK(mutation.mode == (item.present ? Connection::RespHeaderMutationMode::Set
                                             : Connection::RespHeaderMutationMode::Remove));
        CHECK(mutation.name.eq(lit("X-Test")));
        if (item.present) CHECK(mutation.value.eq(lit(item.value)));
    }
    conn.reset();
    const char* fault_request = "GET /fault HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const auto fault_result =
        HandlerResult::unpack(fault_handler(&conn,
                                            nullptr,
                                            reinterpret_cast<const u8*>(fault_request),
                                            lit(fault_request).len,
                                            nullptr));
    CHECK(fault_result.status_code == 500);
    REQUIRE(conn.resp_header_mutation_pending_count == 1);
    CHECK(conn.resp_header_mutations[0].mode == Connection::RespHeaderMutationMode::Remove);
    CHECK(conn.resp_header_mutations[0].name.eq(lit("X-Test")));
    CHECK(conn.resp_header_mutations[0].value.empty());
    CHECK(conn.resp_header_mutation_count == 0);
    // Nil must not inspect an unspecified optional payload.
    conn.reset();
    rut_helper_resp_set_optional_header(
        &conn, "X-Test", 6, reinterpret_cast<const char*>(1), ~u32{0}, 0);
    REQUIRE(conn.resp_header_mutation_pending_count == 1);
    CHECK(conn.resp_header_mutations[0].mode == Connection::RespHeaderMutationMode::Remove);
    CHECK(!conn.resp_header_mutation_pending_overflow);
    rut_helper_resp_set_optional_header(&conn, "X-Test", 6, nullptr, 0, 2);
    CHECK(conn.resp_header_mutation_pending_overflow);
    conn.reset();
    CHECK(!conn.resp_header_mutation_pending_overflow);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, standard_webhook_builtin_executes_five_operands_with_freshness) {
    const char* source = R"rut(
func verify(_ id: str, _ timestamp: str, _ signature: str, _ body: str) -> bool {
    standardWebhookValid(id, timestamp, signature, body, "secret")
}
route POST "/" {
    guard verify(req.uniqueHeader("webhook-id").or(""),
                 req.uniqueHeader("webhook-timestamp").or(""),
                 req.uniqueHeader("webhook-signature").or(""), req.body) else { return 401 }
    return 204
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    CHECK(rir_function_needs_req_body(rir.module.functions[0]));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    timespec now{};
    REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
    REQUIRE(now.tv_sec > 1000);
    const std::string timestamp = std::to_string(now.tv_sec);
    auto signature_for = [&](const std::string& timestamp, std::string& result) {
        const std::string message = "msg_1." + timestamp + ".hello";
        unsigned char digest[32];
        unsigned int length = 0;
        REQUIRE(HMAC(EVP_sha256(),
                     "secret",
                     6,
                     reinterpret_cast<const unsigned char*>(message.data()),
                     message.size(),
                     digest,
                     &length) != nullptr);
        REQUIRE(length == 32);
        unsigned char encoded[45];
        REQUIRE(EVP_EncodeBlock(encoded, digest, 32) == 44);
        result = std::string("v1,") + reinterpret_cast<const char*>(encoded);
    };
    std::string signature;
    signature_for(timestamp, signature);
    REQUIRE(!signature.empty());
    const std::string stale = std::to_string(now.tv_sec - 1000);
    std::string stale_signature;
    signature_for(stale, stale_signature);
    REQUIRE(!stale_signature.empty());
    struct Case {
        const char* id;
        std::string timestamp;
        std::string signature;
        const char* body;
        u16 status;
    };
    const Case cases[] = {
        {"msg_1", timestamp, signature, "hello", 204},
        {"msg_2", timestamp, signature, "hello", 401},
        {"msg_1", timestamp, signature, "Hello", 401},
        {"msg_1", timestamp, "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "hello", 401},
        {"msg_1", stale, stale_signature, "hello", 401},
    };
    for (const auto& tc : cases) {
        const std::string body(tc.body);
        const std::string request =
            "POST / HTTP/1.1\r\nHost: localhost\r\nwebhook-id: " + std::string(tc.id) +
            "\r\nwebhook-timestamp: " + tc.timestamp + "\r\nwebhook-signature: " + tc.signature +
            "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK(result.status_code == tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, required_credentials_and_exact_consumer_union_fail_closed) {
    const auto source_path = std::filesystem::path(__FILE__).parent_path().parent_path() /
                             "examples/multi-consumer-auth.rut";
    std::string source = R"rut(
import "middleware/auth.rut"
route GET "/dual" {
    let identity = auth.headerKeyAndBasic(req.uniqueHeader("X-API-Key").or(""), req.authorization.or(""),
        "opaque:secret", "user:pass", "alice", "required-pair")
    guard identity.consumerId == "alice" && identity.credentialId == "required-pair" &&
          identity.method == "apiKeyAndBasic" else { return 500 }
    return 204
}
route GET "/empty-key" {
    let identity = auth.headerKeyAndBasic("", "", "", "user:pass", "alice", "pair")
    return 204
}
route GET "/empty-password" {
    let identity = auth.headerKeyAndBasic("", "", "key", "", "alice", "pair")
    return 204
}
route GET "/empty-consumer" {
    let identity = auth.headerKeyAndBasic("", "", "key", "user:pass", "", "pair")
    return 204
}
route GET "/empty-policy" {
    let identity = auth.headerKeyAndBasic("", "", "key", "user:pass", "alice", "")
    return 204
}
)rut";
    const char* consumers[] = {"alice", "bob", "carol", "Alice", "alice-extra", "alice", "alice"};
    for (u32 i = 0; i < 7; ++i) {
        source += "route GET \"/allow-" + std::to_string(i) + "\" {\n" +
                  "let identity = auth.apiKey(req.authorization.or(\"\"), \"secret\", \"" +
                  consumers[i] + "\", \"key\")\n" +
                  "let allowed = auth.requireAnyConsumer(identity, \"" + (i == 5 ? "" : "alice") +
                  "\", \"" + (i == 6 ? "" : "bob") + "\")\n" +
                  "guard allowed.consumerId == identity.consumerId && allowed.credentialId == "
                  "\"key\" && allowed.method == \"apiKey\" else { return 500 }\nreturn 204\n}\n";
    }
    source += R"rut(
route GET "/denied-before-allow" {
    let identity = auth.apiKey(req.authorization.or(""), "secret", "alice", "key")
    let excluded = auth.denyConsumer(identity, "alice")
    let allowed = auth.requireAnyConsumer(excluded, "alice", "bob")
    return 204
}
)rut";
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "required auth: %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        u16 status;
    };
    const Case cases[] = {
        {0, "X-API-Key: opaque:secret\r\nAuthorization: Basic dXNlcjpwYXNz\r\n", 204},
        {0,
         "x-api-key: opaque:secret\r\nAuthorization: bAsIc   dXNlcjpwYXNz\r\nX-Consumer-ID: "
         "carol\r\n",
         204},
        {0, "", 401},
        {0, "X-API-Key: opaque:secret\r\n", 401},
        {0, "Authorization: Basic dXNlcjpwYXNz\r\n", 401},
        {0, "X-API-Key: wrong\r\nAuthorization: Basic dXNlcjpwYXNz\r\n", 401},
        {0, "X-API-Key: opaque:secret\r\nAuthorization: Basic dXNlcjp3cm9uZw==\r\n", 401},
        {0, "X-API-Key: opaque:secret\r\nAuthorization: Bearer opaque:secret\r\n", 401},
        {0,
         "X-API-Key: opaque:secret\r\nx-api-key: opaque:secret\r\nAuthorization: Basic "
         "dXNlcjpwYXNz\r\n",
         401},
        {0,
         "X-API-Key: opaque:secret\r\nx-api-key: wrong\r\nAuthorization: Basic dXNlcjpwYXNz\r\n",
         401},
        {0,
         "X-API-Key: opaque:secret\r\nAuthorization: Basic dXNlcjpwYXNz\r\nauthorization: Basic "
         "dXNlcjpwYXNz\r\n",
         401},
        {0, "X-API-Key: opaque:secret\r\nAuthorization: \r\n", 401},
        {1, "", 503},
        {2, "", 503},
        {3, "", 503},
        {4, "", 503},
        {5, "Authorization: Bearer secret\r\n", 204},
        {6, "Authorization: Bearer secret\r\n", 204},
        {7, "Authorization: Bearer secret\r\n", 403},
        {8, "Authorization: Bearer secret\r\n", 403},
        {9, "Authorization: Bearer secret\r\n", 403},
        {10, "Authorization: Bearer secret\r\n", 503},
        {11, "Authorization: Bearer secret\r\n", 503},
        {5, "Authorization: Bearer wrong\r\n", 401},
        {5, "", 401},
        {5, "Authorization: Bearer secret\r\nAuthorization: Bearer secret\r\n", 401},
        {12, "Authorization: Bearer secret\r\n", 403},
    };
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + tc.headers + "\r\n";
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != tc.status)
            std::fprintf(
                stderr, "route %u got %u expected %u\n", tc.route, result.status_code, tc.status);
        CHECK_EQ(result.status_code, tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, consumer_groups_bind_verified_identity_and_default_deny) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    std::string source = "import \"middleware/auth.rut\"\n";
    const char* groups[] = {
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"\", second: \"\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"\"), "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"ops\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"reports\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"ops\", second: \"reports\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"ops\", second: \"\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"reports\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"Alice\", first: \"reports\", second: \"\"), "
        "auth.ConsumerGroups(consumerId: \"carol\", first: \"reports\", second: \"\")",
        "auth.ConsumerGroups(consumerId: \"\", first: \"reports\", second: \"\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"reports\", second: \"\")",
    };
    for (u32 i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        source += "route GET \"/" + std::to_string(i) + "\" {\n";
        source += R"rut(
    let identity = auth.multiAuth(req.authorization.or(""),
        auth.ConsumerCredentials(consumerId: "alice", key: "a", credentials: "", keyId: "ak", passwordId: "ap"),
        auth.ConsumerCredentials(consumerId: "bob", key: "b", credentials: "", keyId: "bk", passwordId: "bp"))
    let allowed = auth.requireGroup(identity, "reports",
)rut";
        source += groups[i];
        source +=
            ")\n guard (allowed.credentialId == \"ak\" || allowed.credentialId == \"bk\") && "
            "allowed.method == \"apiKey\" else { return 500 }\n return 204\n}\n";
    }
    const char* any_group_policies[] = {
        "auth.requireAnyGroup(identity, \"reports\", \"security\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"security\", \"ops\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"reports\", \"ops\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"security\", \"billing\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"\", \"ops\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"reports\", \"security\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"reports\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"reports\", \"security\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"reports\", \"reports\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"security\", \"billing\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"security\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"reports\", \"\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
        "auth.requireAnyGroup(identity, \"Reports\", \"report\", "
        "auth.ConsumerGroups(consumerId: \"alice\", first: \"reports\", second: \"ops\"), "
        "auth.ConsumerGroups(consumerId: \"bob\", first: \"ops\", second: \"\"))",
    };
    for (u32 i = 0; i < sizeof(any_group_policies) / sizeof(any_group_policies[0]); ++i) {
        source += "route GET \"/any-" + std::to_string(i) + "\" {\n";
        source += R"rut(
    let identity = auth.multiAuth(req.authorization.or(""),
        auth.ConsumerCredentials(consumerId: "alice", key: "a", credentials: "", keyId: "ak", passwordId: "ap"),
        auth.ConsumerCredentials(consumerId: "bob", key: "b", credentials: "", keyId: "bk", passwordId: "bp"))
    let allowed = )rut";
        source += any_group_policies[i];
        source +=
            "\n guard allowed.consumerId == identity.consumerId && "
            "allowed.credentialId == identity.credentialId && allowed.method == \"apiKey\" "
            "else { return 500 }\n return 204\n}\n";
    }
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "consumer-groups: %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        u16 status;
    };
    const Case cases[] = {
        {0, "Authorization: Bearer a\r\n", 204},
        {0, "Authorization: Bearer b\r\n", 403},
        {0,
         "Authorization: Bearer b\r\nX-Consumer-ID: alice\r\nX-Consumer-Groups: reports\r\n",
         403},
        {0, "Authorization: Bearer wrong\r\n", 401},
        {0, "", 401},
        {0, "Authorization: Bearer a\r\nauthorization: Bearer a\r\n", 401},
        {1, "Authorization: Bearer a\r\n", 403},
        {2, "Authorization: Bearer a\r\n", 503},
        {3, "Authorization: Bearer a\r\n", 503},
        {4, "Authorization: Bearer a\r\n", 204},
        {5, "Authorization: Bearer b\r\n", 204},
        {5, "Authorization: Bearer a\r\n", 403},
        {6, "Authorization: Bearer a\r\n", 403},
        {7, "Authorization: Bearer a\r\n", 503},
        {8, "Authorization: Bearer a\r\n", 204},
        {9, "Authorization: Bearer a\r\n", 204},
        {10, "Authorization: Bearer b\r\n", 204},
        {11, "Authorization: Bearer a\r\nX-Consumer-Groups: security,billing\r\n", 403},
        {12, "Authorization: Bearer a\r\n", 503},
        {13, "Authorization: Bearer a\r\n", 503},
        {14, "Authorization: Bearer a\r\n", 503},
        {15, "Authorization: Bearer a\r\n", 204},
        {16, "Authorization: Bearer a\r\n", 403},
        {17, "Authorization: Bearer a\r\n", 503},
        {18, "Authorization: Bearer a\r\n", 403},
        {11, "Authorization: Bearer wrong\r\n", 401},
        {11, "Authorization: Bearer a\r\nauthorization: Bearer a\r\n", 401},
    };
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + tc.headers + "\r\n";
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != tc.status)
            std::fprintf(
                stderr, "route %u got %u expected %u\n", tc.route, result.status_code, tc.status);
        CHECK_EQ(result.status_code, tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, consumer_group_denials_preserve_identity_and_take_precedence) {
    const auto source_path = std::filesystem::path(__FILE__).parent_path().parent_path() /
                             "examples/consumer-group-deny-auth.rut";
    const auto member = [](const char* id, const char* first, const char* second) {
        return std::string("auth.ConsumerGroups(consumerId: \"") + id + "\", first: \"" + first +
               "\", second: \"" + second + "\")";
    };
    const std::string alice = member("alice", "ops", "suspended");
    const std::string bob = member("bob", "ops", "");
    const std::string members = alice + ", " + bob;
    struct Policy {
        std::string expression;
        u16 alice_status;
        u16 bob_status;
    };
    const Policy policies[] = {
        {"auth.denyGroup(identity, \"suspended\", " + members + ")", 403, 204},
        {"auth.denyGroup(identity, \"ops\", " + members + ")", 403, 403},
        {"auth.denyGroup(identity, \"Suspended\", " + members + ")", 204, 204},
        {"auth.denyGroup(identity, \"suspend\", " + members + ")", 204, 204},
        {"auth.denyGroup(identity, \"\", " + members + ")", 503, 503},
        {"auth.denyAnyGroup(identity, \"quarantined\", \"suspended\", " + members + ")", 403, 204},
        {"auth.denyAnyGroup(identity, \"suspended\", \"quarantined\", " + members + ")", 403, 204},
        {"auth.denyAnyGroup(identity, \"suspended\", \"ops\", " + members + ")", 403, 403},
        {"auth.denyAnyGroup(identity, \"other\", \"other\", " + members + ")", 204, 204},
        {"auth.denyAnyGroup(identity, \"\", \"suspended\", " + members + ")", 503, 503},
        {"auth.denyAnyGroup(identity, \"suspended\", \"\", " + members + ")", 503, 503},
        {"auth.denyGroup(identity, \"other\", " + alice + ", " + alice + ")", 503, 503},
        {"auth.denyGroup(identity, \"other\", " + member("alice", "ops", "ops") + ", " + bob + ")",
         503,
         503},
        {"auth.denyAnyGroup(identity, \"other\", \"absent\", " + alice + ", " +
             member("bob", "ops", "ops") + ")",
         503,
         503},
        {"auth.denyGroup(identity, \"other\", " + member("", "ops", "") + ", " + bob + ")",
         503,
         503},
        {"auth.denyAnyGroup(identity, \"other\", \"absent\", " + alice + ", " +
             member("", "ops", "") + ")",
         503,
         503},
        {"auth.denyGroup(identity, \"other\", " + member("Alice", "ops", "") + ", " + bob + ")",
         403,
         204},
        {"auth.denyGroup(identity, \"suspended\", " + member("alice", "", "") + ", " +
             member("bob", "", "") + ")",
         204,
         204},
        {"auth.denyGroup(identity, \"suspended\", " + member("bob", "suspended", "ops") + ", " +
             member("alice", "ops", "") + ")",
         204,
         403},
        {"auth.requireAnyGroup(auth.denyGroup(identity, \"suspended\", " + members +
             "), \"ops\", \"suspended\", " + members + ")",
         403,
         204},
        {"auth.requireGroup(auth.denyAnyGroup(identity, \"quarantined\", \"ops\", " + members +
             "), \"ops\", " + members + ")",
         403,
         403},
        {"auth.denyAnyGroup(identity, \"quarantined\", \"suspended\", " +
             member("alice", "ops", "") + ", " + member("bob", "ops", "suspended") + ")",
         204,
         403},
    };
    const std::string credentials = R"rut(
        auth.ConsumerCredentials(consumerId: "alice", key: "a", credentials: "alice:pw", keyId: "ak", passwordId: "ap"),
        auth.ConsumerCredentials(consumerId: "bob", key: "b", credentials: "bob:pw", keyId: "bk", passwordId: "bp"))rut";
    std::string source = "import \"middleware/auth.rut\"\n";
    for (u32 i = 0; i < sizeof(policies) / sizeof(policies[0]); ++i) {
        source += "route GET \"/" + std::to_string(i) + "\" {\n";
        source +=
            "let identity = auth.multiAuth(req.authorization.or(\"\"), " + credentials + ")\n";
        source += "let allowed = " + policies[i].expression + "\n";
        source +=
            "guard allowed.consumerId == identity.consumerId && "
            "allowed.credentialId == identity.credentialId && allowed.method == identity.method "
            "else { return 500 }\n return 204\n}\n";
    }
    source +=
        "route GET \"/unregistered\" {\n"
        "let identity = auth.apiKey(req.authorization.or(\"\"), \"c\", \"carol\", \"ck\")\n"
        "let allowed = auth.denyAnyGroup(identity, \"suspended\", \"quarantined\", " +
        members + ")\n return 204\n}\n";
    source +=
        "route GET \"/anonymous\" {\n"
        "let identity = auth.multiAuthOrAnonymous(req.headerCount(\"Authorization\"), "
        "req.authorization.or(\"\"), " +
        credentials +
        ", \"guest\")\n"
        "let allowed = auth.denyGroup(identity, \"suspended\", " +
        members + ")\n return 204\n}\n";
    source +=
        "route GET \"/registered-guest\" {\n"
        "let identity = auth.multiAuthOrAnonymous(req.headerCount(\"Authorization\"), "
        "req.authorization.or(\"\"), " +
        credentials +
        ", \"guest\")\n"
        "let allowed = auth.denyAnyGroup(identity, \"suspended\", \"quarantined\", " +
        member("guest", "", "") + ", " + bob +
        ")\n guard allowed.consumerId == identity.consumerId && "
        "allowed.credentialId == identity.credentialId && allowed.method == identity.method "
        "else { return 500 }\n return 204\n}\n";
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr, "group deny: %.*s\n", hir.error().detail.len, hir.error().detail.ptr);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    if (!mir)
        std::fprintf(stderr,
                     "group deny MIR code %d: %.*s at %u:%u\n",
                     static_cast<int>(mir.error().code),
                     mir.error().detail.len,
                     mir.error().detail.ptr,
                     mir.error().span.line,
                     mir.error().span.col);
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    const auto check = [&](u32 route, const char* headers, u16 status) {
        const std::string name = "handler_route_" + std::to_string(route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name.c_str()));
        REQUIRE(handler != nullptr);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\n") + headers + "\r\n";
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != status)
            std::fprintf(stderr,
                         "group deny route %u got %u expected %u\n",
                         route,
                         result.status_code,
                         status);
        CHECK_EQ(result.status_code, status);
    };
    for (u32 i = 0; i < sizeof(policies) / sizeof(policies[0]); ++i) {
        check(i, "Authorization: Bearer a\r\n", policies[i].alice_status);
        check(i, "Authorization: Basic YWxpY2U6cHc=\r\n", policies[i].alice_status);
        check(i, "Authorization: Bearer b\r\n", policies[i].bob_status);
        check(i, "Authorization: Basic Ym9iOnB3\r\n", policies[i].bob_status);
        check(i,
              "Authorization: Bearer a\r\nX-Consumer-ID: bob\r\nX-Consumer-Groups: ops\r\n",
              policies[i].alice_status);
        check(i, "", 401);
        check(i, "Authorization:\r\n", 401);
        check(i, "Authorization: Bearer wrong\r\n", 401);
        check(i, "Authorization: Bearer a\r\nauthorization: Bearer b\r\n", 401);
    }
    const auto count = static_cast<u32>(sizeof(policies) / sizeof(policies[0]));
    check(count, "Authorization: Bearer c\r\nX-Consumer-ID: bob\r\n", 403);
    check(count, "Authorization: Bearer a\r\n", 401);
    check(count + 1, "", 403);
    check(count + 1, "Authorization: Bearer a\r\n", 403);
    check(count + 1, "Authorization: Bearer b\r\n", 204);
    check(count + 1, "Authorization:\r\n", 401);
    check(count + 1, "Authorization: Bearer wrong\r\n", 401);
    check(count + 1, "Authorization: Bearer b\r\nauthorization: Bearer b\r\n", 401);
    check(count + 2, "", 204);
    check(count + 2, "Authorization: Bearer a\r\n", 403);
    check(count + 2, "Authorization: Bearer b\r\n", 204);
    check(count + 2, "Authorization: Bearer wrong\r\n", 401);
    check(count + 2, "Authorization: Bearer b\r\nauthorization: Bearer b\r\n", 401);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, consumer_group_deny_example_compiles) {
    const auto source_path = std::filesystem::path(__FILE__).parent_path().parent_path() /
                             "examples/consumer-group-deny-auth.rut";
    std::ifstream input(source_path, std::ios::binary);
    REQUIRE(input.good());
    const std::string source((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    engine.shutdown();
    rir.destroy();
}

TEST(jit, standard_webhook_identity_helper_rejects_ambiguous_headers_and_bad_config) {
    const char* source = R"rut(
import "middleware/auth.rut"
route POST "/webhook" {
    let identity = auth.standardWebhook(req.uniqueHeader("webhook-id").or(""),
        req.uniqueHeader("webhook-timestamp").or(""),
        req.uniqueHeader("webhook-signature").or(""), req.body,
        "trusted-raw-key", "configured-consumer", "endpoint-v1")
    guard identity.consumerId == "configured-consumer" && identity.credentialId == "endpoint-v1" &&
          identity.method == "standardWebhook" else { return 500 }
    return 204
}
route POST "/empty-key" {
    let identity = auth.standardWebhook("", "", "", req.body, "", "configured-consumer", "endpoint-v1")
    return 204
}
route POST "/empty-consumer" {
    let identity = auth.standardWebhook("", "", "", req.body, "trusted-raw-key", "", "endpoint-v1")
    return 204
}
route POST "/empty-credential" {
    let identity = auth.standardWebhook("", "", "", req.body, "trusted-raw-key", "configured-consumer", "")
    return 204
}
route POST "/rotating" {
    let identity = auth.rotatingStandardWebhook(req.uniqueHeader("webhook-id").or(""),
        req.uniqueHeader("webhook-timestamp").or(""), req.uniqueHeader("webhook-signature").or(""),
        req.body, auth.WebhookRotation(currentKey: "trusted-raw-key", previousKey: "previous-key", consumerId: "configured-consumer", currentId: "current", previousId: "previous"))
    if identity.credentialId == "current" { return 204 } else { return 202 }
}
route POST "/revoked" {
    let identity = auth.rotatingStandardWebhook(req.uniqueHeader("webhook-id").or(""),
        req.uniqueHeader("webhook-timestamp").or(""), req.uniqueHeader("webhook-signature").or(""),
        req.body, auth.WebhookRotation(currentKey: "trusted-raw-key", previousKey: "", consumerId: "configured-consumer", currentId: "current", previousId: "previous"))
    return 204
}
route POST "/disabled" {
    let identity = auth.rotatingStandardWebhook("", "", "", req.body, auth.WebhookRotation(currentKey: "", previousKey: "", consumerId: "configured-consumer", currentId: "current", previousId: "previous"))
    return 204
}
route POST "/same" {
    let identity = auth.rotatingStandardWebhook(req.uniqueHeader("webhook-id").or(""),
        req.uniqueHeader("webhook-timestamp").or(""), req.uniqueHeader("webhook-signature").or(""),
        req.body, auth.WebhookRotation(currentKey: "trusted-raw-key", previousKey: "trusted-raw-key", consumerId: "configured-consumer", currentId: "current", previousId: "previous"))
    if identity.credentialId == "current" { return 204 } else { return 500 }
}
)rut";
    const auto source_path = std::filesystem::path(__FILE__).parent_path().parent_path() /
                             "examples/standard-webhook-auth.rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "standard webhook middleware analysis %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    const std::string id = "evt_standard_1";
    const std::string timestamp = std::to_string(static_cast<i64>(time(nullptr)));
    const auto signature_for =
        [&](const std::string& body, std::string& signature, const char* key = "trusted-raw-key") {
            const std::string message = id + "." + timestamp + "." + body;
            unsigned char digest[32];
            unsigned int digest_len = 0;
            REQUIRE(HMAC(EVP_sha256(),
                         key,
                         strlen(key),
                         reinterpret_cast<const unsigned char*>(message.data()),
                         message.size(),
                         digest,
                         &digest_len) != nullptr);
            REQUIRE_EQ(digest_len, 32u);
            unsigned char encoded[45];
            REQUIRE_EQ(EVP_EncodeBlock(encoded, digest, digest_len), 44);
            signature = std::string("v1,") + reinterpret_cast<const char*>(encoded);
        };
    const std::string body = "{\"event\":\"paid\"}";
    std::string signature;
    signature_for(body, signature);
    const std::string valid = "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
                              "\r\nwebhook-signature: " + signature + "\r\n";
    std::string bad_signature = signature;
    bad_signature[3] = bad_signature[3] == 'A' ? 'B' : 'A';
    std::string bad_timestamp = timestamp;
    bad_timestamp.back() = bad_timestamp.back() == '1' ? '2' : '1';
    const std::string binary_body("a\0b", 3);
    std::string binary_signature;
    signature_for(binary_body, binary_signature);
    std::string empty_signature;
    signature_for("", empty_signature);
    std::string previous_signature;
    signature_for(body, previous_signature, "previous-key");
    const std::string previous_headers = "webhook-id: " + id +
                                         "\r\nwebhook-timestamp: " + timestamp +
                                         "\r\nwebhook-signature: " + previous_signature + "\r\n";
    struct Case {
        u32 route;
        const char* path;
        std::string headers;
        std::string body;
        u16 status;
    };
    const Case cases[] = {
        {0, "/webhook", valid, body, 204},
        {0, "/webhook", valid + "X-Consumer-ID: attacker\r\n", body, 204},
        {0, "/webhook", valid + "Webhook-ID: " + id + "\r\n", body, 401},
        {0, "/webhook", valid + "webhook-timestamp: " + timestamp + "\r\n", body, 401},
        {0, "/webhook", valid + "webhook-signature: " + signature + "\r\n", body, 401},
        {0,
         "/webhook",
         "webhook-timestamp: " + timestamp + "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-timestamp: " + timestamp + "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-signature: " + signature + "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0, "/webhook", valid, body + "!", 401},
        {0,
         "/webhook",
         "webhook-id: evt_standard_2\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + bad_timestamp +
             "\r\nwebhook-signature: " + signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-signature: " + bad_signature + "\r\n",
         body,
         401},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-signature: " + empty_signature + "\r\n",
         "",
         204},
        {0,
         "/webhook",
         "webhook-id: " + id + "\r\nwebhook-timestamp: " + timestamp +
             "\r\nwebhook-signature: " + binary_signature + "\r\n",
         binary_body,
         204},
        {1, "/empty-key", "", "", 503},
        {2, "/empty-consumer", "", "", 503},
        {3, "/empty-credential", "", "", 503},
        {4, "/rotating", valid, body, 204},
        {4, "/rotating", previous_headers, body, 202},
        {4, "/rotating", previous_headers, body + "!", 401},
        {4, "/rotating", previous_headers + "Webhook-ID: " + id + "\r\n", body, 401},
        {5, "/revoked", previous_headers, body, 401},
        {6, "/disabled", "", "", 503},
        {7, "/same", valid, body, 204},
    };
    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char handler_name[32];
        snprintf(handler_name, sizeof(handler_name), "handler_route_%u", cases[i].route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(handler_name));
        REQUIRE(handler != nullptr);
        const std::string request = std::string("POST ") + cases[i].path +
                                    " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                                    std::to_string(cases[i].body.size()) + "\r\n" +
                                    cases[i].headers + "\r\n" + cases[i].body;
        const auto result =
            HandlerResult::unpack(handler(nullptr,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK_EQ(result.status_code, cases[i].status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, header_count_distinguishes_absent_empty_duplicate_and_invalid_requests) {
    const char* source = R"rut(
func countAuthorization() -> i32 { req.headerCount("aUtHoRiZaTiOn") }
route GET "/count" {
    match countAuthorization() {
        0 => return 204
        1 => return 201
        2 => return 202
        _ => return 400
    }
}
route GET "/unique" {
    guard req.headerCount("Authorization") == 1 && req.authorization != nil else { return 401 }
    return 204
}
route GET "/removed" {
    req.remove("Authorization")
    match req.headerCount("Authorization") {
        0 => return 204
        1 => return 201
        2 => return 202
        _ => return 400
    }
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* request;
        u16 status;
        i32 count;
    };
    const Case cases[] = {
        {0, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 204, 0},
        {0, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization:\r\n\r\n", 201, 1},
        {0, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: \t \r\n\r\n", 201, 1},
        {0, "GET / HTTP/1.1\r\nHost: localhost\r\nauthorization: Bearer key\r\n\r\n", 201, 1},
        {0,
         "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer key\r\nAUTHORIZATION: Bearer "
         "key\r\n\r\n",
         202,
         2},
        {0,
         "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: wrong\r\nauthorization: Bearer "
         "key\r\n\r\n",
         202,
         2},
        {0, "incomplete", 400, -1},
        {0, "GET / HTTP/1.1\r\nBad Name: value\r\n\r\n", 400, -1},
        {0, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: value\r\n", 400, -1},
        {1, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 401, 0},
        {1, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization:\r\n\r\n", 204, 1},
        {1,
         "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: x\r\nauthorization: x\r\n\r\n",
         401,
         2},
        {2, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 204, 0},
        {2, "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer key\r\n\r\n", 201, 1},
        {2,
         "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: x\r\nauthorization: x\r\n\r\n",
         202,
         2},
    };
    Connection conn;
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        conn.reset();
        const auto request = lit(tc.request);
        const auto result = HandlerResult::unpack(handler(
            &conn, nullptr, reinterpret_cast<const u8*>(request.ptr), request.len, nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        CHECK_EQ(result.status_code, tc.status);
        CHECK_EQ(rut_helper_req_header_count(
                     reinterpret_cast<const u8*>(request.ptr), request.len, "Authorization", 13),
                 tc.count);
    }
    // Reusing the same storage for different requests must not reuse stale counts.
    char request[] = "GET / HTTP/1.1\r\nAuthorization: x\r\n\r\n";
    CHECK_EQ(rut_helper_req_header_count(
                 reinterpret_cast<const u8*>(request), sizeof(request) - 1, "Authorization", 13),
             1);
    request[16] = 'X';
    CHECK_EQ(rut_helper_req_header_count(
                 reinterpret_cast<const u8*>(request), sizeof(request) - 1, "Authorization", 13),
             0);
    CHECK_EQ(rut_helper_req_header_count(nullptr, 0, "Authorization", 13), -1);
    CHECK_EQ(rut_helper_req_header_count(
                 reinterpret_cast<const u8*>(request), sizeof(request) - 1, "Bad Name", 8),
             -1);
    // Header overflow cannot masquerade as absence beyond the parser's retained fields.
    std::string overflow = "GET / HTTP/1.1\r\n";
    for (u32 i = 0; i < kMaxHeaders; ++i) overflow += "X-Pad: x\r\n";
    overflow += "Authorization: key\r\n\r\n";
    CHECK_EQ(rut_helper_req_header_count(reinterpret_cast<const u8*>(overflow.data()),
                                         static_cast<u32>(overflow.size()),
                                         "Authorization",
                                         13),
             -1);
    engine.shutdown();
    rir.destroy();
}

TEST(jit, anonymous_authentication_requires_proven_absence_and_distinct_identity) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/anonymous-auth.rut";
    std::string source = R"rut(
import "middleware/auth.rut"
route GET "/optional" {
    let identity = auth.apiKeyOrAnonymous(req.headerCount("Authorization"), req.authorization.or(""),
        "secret", "registered-app", "primary-key", "guest")
    guard (identity.method == "anonymous" && identity.consumerId == "guest" && identity.credentialId == "") ||
          (identity.method == "apiKey" && identity.consumerId == "registered-app" && identity.credentialId == "primary-key") else { return 500 }
    match identity.method {
        "anonymous" => return 200
        "apiKey" => return 201
        _ => return 500
    }
}
route GET "/private" {
    let identity = auth.apiKeyOrAnonymous(req.headerCount("Authorization"), req.authorization.or(""),
        "secret", "registered-app", "primary-key", "guest")
    let permitted = auth.requireConsumer(identity, "registered-app")
    guard permitted.credentialId == "primary-key" else { return 500 }
    return 204
}
route GET "/removed" {
    req.remove("Authorization")
    let identity = auth.apiKeyOrAnonymous(req.headerCount("Authorization"), req.authorization.or(""),
        "secret", "registered-app", "primary-key", "guest")
    let permitted = auth.requireConsumer(identity, "registered-app")
    return 204
}
)rut";
    const char* configurations[] = {
        "\"\", \"registered-app\", \"primary-key\", \"guest\"",
        "\"secret\", \"\", \"primary-key\", \"guest\"",
        "\"secret\", \"registered-app\", \"\", \"guest\"",
        "\"secret\", \"registered-app\", \"primary-key\", \"\"",
        "\"secret\", \"registered-app\", \"primary-key\", \"registered-app\"",
    };
    for (u32 i = 0; i < 5; ++i) {
        source += "route GET \"/bad-config-" + std::to_string(i) + "\" {\n" +
                  "let identity = auth.apiKeyOrAnonymous(req.headerCount(\"Authorization\"), "
                  "req.authorization.or(\"\"), " +
                  configurations[i] + ")\nreturn 204\n}\n";
    }
    source += R"rut(
route GET "/parse-error" {
    let identity = auth.apiKeyOrAnonymous(-1, "", "secret", "registered-app", "primary-key", "guest")
    return 204
}
route GET "/inconsistent-duplicate" {
    let identity = auth.apiKeyOrAnonymous(2, "Bearer secret", "secret", "registered-app", "primary-key", "guest")
    return 204
}
route GET "/inconsistent-absent" {
    let identity = auth.apiKeyOrAnonymous(0, "Bearer secret", "secret", "registered-app", "primary-key", "guest")
    return 204
}
)rut";
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        std::fprintf(stderr,
                     "anonymous auth: %.*s at %u:%u\n",
                     hir.error().detail.len,
                     hir.error().detail.ptr,
                     hir.error().span.line,
                     hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        const char* body;
        u16 status;
    };
    const Case cases[] = {
        {0, "", "", 200},
        {0, "X-Consumer-ID: registered-app\r\nX-Credential-ID: primary-key\r\n", "", 200},
        {0, "X-API-Key: secret\r\n", "", 200},
        {0, "", "Authorization: Bearer secret", 200},
        {0, "Authorization: Bearer secret\r\n", "", 201},
        {0, "aUtHoRiZaTiOn: bEaReR   secret\r\nX-Consumer-ID: guest\r\n", "", 201},
        {0, "Authorization:\r\n", "", 401},
        {0, "Authorization: \t \r\n", "", 401},
        {0, "Authorization: Bearer\r\n", "", 401},
        {0, "Authorization: Bearer wrong\r\nX-API-Key: secret\r\n", "", 401},
        {0, "Authorization: Basic dXNlcjpwYXNz\r\n", "", 401},
        {0, "Authorization: Bearer secret,wrong\r\n", "", 401},
        {0, "Authorization: Bearer secret\r\nauthorization: Bearer secret\r\n", "", 401},
        {0, "Authorization: wrong\r\nAuthorization: Bearer secret\r\n", "", 401},
        {0, "Authorization: Bearer secret\r\nAuthorization: wrong\r\n", "", 401},
        {0, "Authorization:\r\nauthorization:\r\n", "", 401},
        {0, "Bad Name: value\r\n", "", 401},
        {1, "", "", 403},
        {1, "Authorization: Bearer secret\r\n", "", 204},
        {1, "Authorization: Bearer wrong\r\n", "", 401},
        {2, "", "", 403},
        {2, "Authorization: Bearer secret\r\n", "", 204},
        {2, "Authorization: Bearer wrong\r\n", "", 401},
        {2, "Authorization: Bearer secret\r\nauthorization: Bearer secret\r\n", "", 401},
        {3, "", "", 503},
        {4, "", "", 503},
        {5, "", "", 503},
        {6, "", "", 503},
        {7, "", "", 503},
        {7, "Authorization: Bearer secret\r\n", "", 503},
        {8, "", "", 401},
        {9, "", "", 401},
        {10, "", "", 401},
    };
    Connection conn;
    for (const auto& tc : cases) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        conn.reset();
        const std::string body(tc.body);
        const std::string request =
            std::string("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: ") +
            std::to_string(body.size()) + "\r\n" + tc.headers + "\r\n" + body;
        const auto result =
            HandlerResult::unpack(handler(&conn,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != tc.status)
            std::fprintf(stderr,
                         "anonymous route %u got %u expected %u\n",
                         tc.route,
                         result.status_code,
                         tc.status);
        CHECK_EQ(result.status_code, tc.status);
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, optional_multi_authentication_never_downgrades_presented_credentials) {
    const auto source_path = std::filesystem::path(__FILE__).parent_path().parent_path() /
                             "examples/optional-multi-auth.rut";
    std::string source = R"rut(
import "middleware/auth.rut"
func alice() -> auth.ConsumerCredentials {
    auth.ConsumerCredentials(consumerId: "alice", key: "a", credentials: "alice:pass",
        keyId: "alice-key", passwordId: "alice-password")
}
func bob() -> auth.ConsumerCredentials {
    auth.ConsumerCredentials(consumerId: "bob", key: "b", credentials: "bob:pass",
        keyId: "bob-key", passwordId: "bob-password")
}
route GET "/optional" {
    let identity = auth.multiAuthOrAnonymous(req.headerCount("Authorization"),
        req.authorization.or(""), alice(), bob(), "guest")
    guard identity.consumerId == req.header("X-Expected-Consumer").or("") &&
          identity.credentialId == req.header("X-Expected-Credential").or("") &&
          identity.method == req.header("X-Expected-Method").or("") else { return 500 }
    return 200
}
route GET "/private" {
    let identity = auth.multiAuthOrAnonymous(req.headerCount("Authorization"),
        req.authorization.or(""), alice(), bob(), "guest")
    let permitted = auth.requireAnyConsumer(identity, "alice", "bob")
    return 204
}
route GET "/removed" {
    req.remove("Authorization")
    let identity = auth.multiAuthOrAnonymous(req.headerCount("Authorization"),
        req.authorization.or(""), alice(), bob(), "guest")
    let permitted = auth.requireAnyConsumer(identity, "alice", "bob")
    return 204
}
)rut";
    // Exercise all configuration gates before both anonymous and authenticated paths.
    const char* configurations[] = {
        "alice(), bob(), \"\"",
        "alice(), bob(), \"alice\"",
        "alice(), bob(), \"bob\"",
        "alice(), alice(), \"guest\"",
        "auth.ConsumerCredentials(consumerId: \"\", key: \"a\", credentials: \"\", keyId: \"k\", "
        "passwordId: \"p\"), bob(), \"guest\"",
        "auth.ConsumerCredentials(consumerId: \"alice\", key: \"b\", credentials: \"\", keyId: "
        "\"k\", passwordId: \"p\"), bob(), \"guest\"",
        "auth.ConsumerCredentials(consumerId: \"alice\", key: \"\", credentials: \"bob:pass\", "
        "keyId: \"k\", passwordId: \"p\"), bob(), \"guest\"",
        "auth.ConsumerCredentials(consumerId: \"alice\", key: \"\", credentials: \"\", keyId: "
        "\"\", passwordId: \"p\"), bob(), \"guest\"",
        "alice(), auth.ConsumerCredentials(consumerId: \"bob\", key: \"\", credentials: \"\", "
        "keyId: \"k\", passwordId: \"\"), \"guest\"",
        "auth.ConsumerCredentials(consumerId: \"alice\", key: \"\", credentials: \"\", keyId: "
        "\"k\", passwordId: \"p\"), auth.ConsumerCredentials(consumerId: \"bob\", key: \"\", "
        "credentials: \"\", keyId: \"k\", passwordId: \"p\"), \"guest\"",
    };
    for (u32 i = 0; i < sizeof(configurations) / sizeof(configurations[0]); ++i)
        source += "route GET \"/bad-" + std::to_string(i) +
                  "\" { let identity = "
                  "auth.multiAuthOrAnonymous(req.headerCount(\"Authorization\"), "
                  "req.authorization.or(\"\"), " +
                  configurations[i] + ") return 204 }\n";
    source += R"rut(
route GET "/parse-error" {
    let identity = auth.multiAuthOrAnonymous(-1, "", alice(), bob(), "guest")
    return 204
}
route GET "/inconsistent-absent" {
    let identity = auth.multiAuthOrAnonymous(0, "Bearer a", alice(), bob(), "guest")
    return 204
}
route GET "/inconsistent-duplicate" {
    let identity = auth.multiAuthOrAnonymous(2, "Bearer a", alice(), bob(), "guest")
    return 204
}
route GET "/disabled-alice" {
    let identity = auth.multiAuthOrAnonymous(req.headerCount("Authorization"), req.authorization.or(""),
        auth.ConsumerCredentials(consumerId: "alice", key: "", credentials: "", keyId: "alice-key", passwordId: "alice-password"), bob(), "guest")
    guard identity.consumerId != "alice" else { return 500 }
    return 200
}
)rut";
    auto tokens = lex({source.data(), static_cast<u32>(source.size())});
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    if (!hir)
        fprintf(stderr,
                "optional multi-auth: %.*s at %u:%u\n",
                hir.error().detail.len,
                hir.error().detail.ptr,
                hir.error().span.line,
                hir.error().span.col);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    struct Case {
        u32 route;
        const char* headers;
        const char* body;
        u16 status;
        const char* consumer = "guest";
        const char* credential = "";
        const char* method = "anonymous";
    };
    const Case cases[] = {
        {0, "", "", 200},
        {0, "X-Consumer-ID: alice\r\nX-Credential-ID: alice-key\r\n", "", 200},
        {0, "X-API-Key: a\r\n", "Authorization: Bearer a", 200},
        {0, "Authorization: Bearer a\r\n", "", 200, "alice", "alice-key", "apiKey"},
        {0,
         "aUtHoRiZaTiOn: bEaReR   b\r\nX-Consumer-ID: guest\r\n",
         "",
         200,
         "bob",
         "bob-key",
         "apiKey"},
        {0,
         "Authorization: Basic YWxpY2U6cGFzcw==\r\n",
         "",
         200,
         "alice",
         "alice-password",
         "basic"},
        {0,
         "Authorization: Basic Ym9iOnBhc3M=\r\nX-Consumer-ID: alice\r\n",
         "",
         200,
         "bob",
         "bob-password",
         "basic"},
        {0, "Authorization:\r\n", "", 401},
        {0, "Authorization: \t \r\n", "", 401},
        {0, "Authorization: Bearer\r\n", "", 401},
        {0, "Authorization: Bearer wrong\r\nX-API-Key: a\r\n", "", 401},
        {0, "Authorization: Basic YWxpY2U6d3Jvbmc=\r\n", "", 401},
        {0, "Authorization: Basic !!!\r\n", "", 401},
        {0, "Authorization: Digest a\r\n", "", 401},
        {0, "Authorization: Bearer a,b\r\n", "", 401},
        {0, "Authorization: Bearer a\r\nauthorization: Basic Ym9iOnBhc3M=\r\n", "", 401},
        {0, "Authorization: wrong\r\nAuthorization: Bearer a\r\n", "", 401},
        {0, "Authorization:\r\nauthorization:\r\n", "", 401},
        {0, "Bad Name: x\r\n", "", 401},
        {1, "", "", 403},
        {1, "Authorization: Bearer a\r\n", "", 204},
        {1, "Authorization: Basic Ym9iOnBhc3M=\r\n", "", 204},
        {1, "Authorization: Bearer wrong\r\n", "", 401},
        {2, "", "", 403},
        {2, "Authorization: Bearer a\r\n", "", 204},
        {2, "Authorization: Bearer wrong\r\n", "", 401},
        {2, "Authorization: Bearer a\r\nAuthorization: Bearer b\r\n", "", 401},
        {13, "", "", 401},
        {14, "", "", 401},
        {15, "", "", 401},
        {16, "", "", 200},
        {16, "Authorization: Bearer b\r\n", "", 200},
        {16, "Authorization: Bearer a\r\n", "", 401},
        {16, "Authorization: Basic YWxpY2U6cGFzcw==\r\n", "", 401},
    };
    Connection conn;
    const auto check = [&](const Case& tc, const char* version) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", tc.route);
        auto handler = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(handler != nullptr);
        conn.reset();
        const std::string body(tc.body);
        const std::string request =
            std::string("GET / ") + version +
            "\r\nHost: localhost\r\nContent-Length: " + std::to_string(body.size()) + "\r\n" +
            tc.headers + "X-Expected-Consumer: " + tc.consumer + "\r\n" +
            "X-Expected-Credential: " + tc.credential + "\r\n" + "X-Expected-Method: " + tc.method +
            "\r\n\r\n" + body;
        const auto result =
            HandlerResult::unpack(handler(&conn,
                                          nullptr,
                                          reinterpret_cast<const u8*>(request.data()),
                                          static_cast<u32>(request.size()),
                                          nullptr));
        CHECK(result.action == HandlerAction::ReturnStatus);
        if (result.status_code != tc.status)
            fprintf(stderr,
                    "optional multi-auth route %u: got %u expected %u\n",
                    tc.route,
                    result.status_code,
                    tc.status);
        CHECK_EQ(result.status_code, tc.status);
        if (tc.status == 401) {
            REQUIRE(result.next_state != 0 && result.next_state <= rir.module.header_set_count);
            const auto& headers = rir.module.header_sets[result.next_state - 1];
            REQUIRE_EQ(headers.count, 2u);
            CHECK(rir.module.header_keys[headers.offset].eq(lit("WWW-Authenticate")));
            CHECK(rir.module.header_keys[headers.offset + 1].eq(lit("WWW-Authenticate")));
            CHECK(rir.module.header_values[headers.offset].eq(lit("Bearer")));
            CHECK(rir.module.header_values[headers.offset + 1].eq(lit("Basic realm=\"rut\"")));
        } else {
            CHECK_EQ(result.next_state, 0u);
        }
    };
    for (const char* version : {"HTTP/1.0", "HTTP/1.1"}) {
        for (const auto& tc : cases) check(tc, version);
        for (u32 i = 3; i < 13; ++i) {
            check({i, "", "", 503}, version);
            check({i, "Authorization: Bearer a\r\n", "", 503}, version);
        }
    }
    engine.shutdown();
    rir.destroy();
}

TEST(jit, owned_request_headers_copy_borrowed_inputs_and_fail_closed) {
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    Connection conn;
    conn.reset();
    char name[] = "X-Consumer-ID";
    char value[] = "alice";
    rut_helper_req_set_owned_header(
        &conn, &arena, name, sizeof(name) - 1, value, sizeof(value) - 1);
    REQUIRE_EQ(conn.req_header_override_count, 1u);
    name[0] = 'z';
    value[0] = 'z';
    CHECK(conn.req_header_overrides[0].name.eq(lit("X-Consumer-ID")));
    CHECK(conn.req_header_overrides[0].value.eq(lit("alice")));
    CHECK_EQ(conn.req_header_owned_bytes, 18u);
    CHECK(!conn.req_header_override_overflow);
    CHECK_EQ(conn.req_header_append_mask, 0u);
    rut_helper_req_set_owned_header(&conn, &arena, "X-Empty", 7, nullptr, 0);
    REQUIRE_EQ(conn.req_header_override_count, 2u);
    CHECK(conn.req_header_overrides[1].value.empty());
    const char* invalid_values[] = {"a\r\nb", "a\nb", "a\x7f"};
    for (const char* invalid : invalid_values) {
        conn.reset();
        rut_helper_req_set_owned_header(&conn, &arena, "X-Test", 6, invalid, lit(invalid).len);
        CHECK(conn.req_header_override_overflow);
        CHECK_EQ(conn.req_header_override_count, 0u);
    }
    conn.reset();
    rut_helper_req_set_owned_header(&conn, &arena, "Content-Length", 14, "1", 1);
    CHECK(conn.req_header_override_overflow);
    CHECK_EQ(conn.req_header_override_count, 0u);
    conn.reset();
    char large[ConnectionBase::kMaxReqHeaderOwnedBytes];
    __builtin_memset(large, 'a', sizeof(large));
    rut_helper_req_set_owned_header(&conn, &arena, "X", 1, large, sizeof(large) - 1);
    REQUIRE_EQ(conn.req_header_owned_bytes, ConnectionBase::kMaxReqHeaderOwnedBytes);
    rut_helper_req_set_owned_header(&conn, &arena, "X", 1, "", 0);
    CHECK(conn.req_header_override_overflow);
    CHECK_EQ(conn.req_header_override_count, 1u);
    conn.reset();
    CHECK_EQ(conn.req_header_owned_bytes, 0u);
    CHECK(!conn.req_header_override_overflow);
    for (u32 i = 0; i <= ConnectionBase::kMaxReqHeaderOverrides; ++i)
        rut_helper_req_set_owned_header(&conn, &arena, "X", 1, "a", 1);
    CHECK(conn.req_header_override_overflow);
    CHECK_EQ(conn.req_header_override_count, ConnectionBase::kMaxReqHeaderOverrides);
    conn.reset();
    rut_helper_req_set_owned_header(&conn, nullptr, "X", 1, "a", 1);
    CHECK(conn.req_header_override_overflow);  // No request pool in this direct caller.
    CHECK_EQ(conn.req_header_override_count, 0u);
    arena.destroy();
    pool.destroy();
    REQUIRE(pool.init(1));
    REQUIRE(arena.init(&pool));
    REQUIRE(arena.alloc(arena.current->remaining()));
    conn.reset();
    rut_helper_req_set_owned_header(&conn, &arena, "X", 1, "a", 1);
    CHECK(conn.req_header_override_overflow);
    CHECK_EQ(conn.req_header_override_count, 0u);
    CHECK_EQ(conn.req_header_owned_bytes, 0u);
    arena.destroy();
    pool.destroy();
}

TEST(jit, verified_identity_header_is_only_recorded_on_selected_auth_path) {
    const auto source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "examples/authentication.rut";
    const char* source = R"rut(
import "middleware/auth.rut"
upstream backend
route GET "/" {
    req.remove("Authorization")
    let identity = auth.apiKey(req.authorization.or(""), "secret", "alice", "key")
    match identity.consumerId {
        "alice" => { req.set("X-Consumer-ID", identity.consumerId) return forward(backend, load_balance: .roundRobin) }
        _ => return 403
    }
}
)rut";
    auto tokens = lex(lit(source));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap_with_path(ast.value(), source_path.string());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler != nullptr);
    SlicePool pool;
    REQUIRE(pool.init(32));
    Connection conn;
    for (bool valid : {false, true}) {
        conn.reset();
        conn.json_arena.backend.pool = &pool;
        const char* request = valid ? "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "
                                      "secret\r\nX-Consumer-ID: attacker\r\n\r\n"
                                    : "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "
                                      "wrong\r\nX-Consumer-ID: attacker\r\n\r\n";
        const auto result = HandlerResult::unpack(handler(
            &conn, nullptr, reinterpret_cast<const u8*>(request), lit(request).len, nullptr));
        if (!valid) {
            CHECK_EQ(result.status_code, 401);
            CHECK_EQ(conn.req_header_override_count, 1u);
        } else {
            CHECK(result.action == HandlerAction::Forward);
            REQUIRE_EQ(conn.req_header_override_count, 2u);
            CHECK(conn.req_header_overrides[1].value.eq(lit("alice")));
            u8 wire[512]{};
            u32 wire_len = 0;
            REQUIRE(h2_prepare_forward_request(conn,
                                               reinterpret_cast<const u8*>(request),
                                               lit(request).len,
                                               wire,
                                               sizeof(wire),
                                               &wire_len));
            const char expected[] =
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Consumer-ID: alice\r\n\r\n";
            CHECK_EQ(wire_len, sizeof(expected) - 1);
            CHECK(__builtin_memcmp(wire, expected, sizeof(expected) - 1) == 0);
        }
    }
    conn.json_arena.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jit, json_type_parse_construct_edit_and_extract) {
    const char* src = R"rut(
func identity(_ value: Json) -> Json => value
route POST "/json" {
    guard let doc = json.parse(req.body) else { return 400 }
    guard let items = json.get(doc, "/items") else { return 401 }
    guard let n = json.count(items) else { return 402 }
    guard let first = json.at(items, 0) else { return 403 }
    guard let number = json.int(first) else { return 404 }
    if n == 2 && number == 9223372036854775807 { return 200 } else { return 500 }
}
route GET "/build" {
    guard let v = json.parse("{\"name\":\"rut\",\"items\":[true,null,42],\"nested\":{\"active\":false}}") else { return 405 }
    guard let replacement = json.value("gateway") else { return 406 }
    guard let edited = json.set(v, "/name", replacement) else { return 407 }
    guard let name = json.get(identity(edited), "/name") else { return 408 }
    guard let text = json.string(name) else { return 409 }
    guard let encoded = json(edited) else { return 410 }
    if text == "gateway" {
        return 200
    } else { return 500 }
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    if (!ast)
        fprintf(stderr,
                "JSON parse error %u at %u:%u: %.*s\n",
                static_cast<u32>(ast.error().code),
                ast.error().span.line,
                ast.error().span.col,
                ast.error().detail.len,
                ast.error().detail.ptr);
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    if (!hir)
        fprintf(stderr,
                "JSON analyze error %u at %u:%u: %.*s\n",
                static_cast<u32>(hir.error().code),
                hir.error().span.line,
                hir.error().span.col,
                hir.error().detail.len,
                hir.error().detail.ptr);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(mir.value(), rir);
    REQUIRE(lowered);
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    SlicePool pool;
    REQUIRE(pool.init(64));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const char request[] =
        "POST /json HTTP/1.1\r\nContent-Length: 35\r\n\r\n{\"items\":[9223372036854775807,null]}";
    // Build length from the actual body so this also exercises runtime body extraction.
    const char body[] = "{\"items\":[9223372036854775807,null]}";
    char bytes[256];
    const int len = snprintf(bytes,
                             sizeof(bytes),
                             "POST /json HTTP/1.1\r\nContent-Length: %zu\r\n\r\n%s",
                             sizeof(body) - 1,
                             body);
    (void)request;
    auto result = HandlerResult::unpack(handler(
        nullptr, nullptr, reinterpret_cast<const u8*>(bytes), static_cast<u32>(len), &arena));
    CHECK_EQ(result.status_code, 200);
    arena.reset();
    auto build = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_1"));
    REQUIRE(build);
    result = HandlerResult::unpack(
        build(nullptr, nullptr, reinterpret_cast<const u8*>(bytes), static_cast<u32>(len), &arena));
    CHECK_EQ(result.status_code, 200);
    arena.destroy();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jit, json_struct_codec_and_dynamic_response_body) {
    const char* src = R"rut(
struct User {
    name: str
    active: bool
    age: i32
}
route POST "/codec" {
    guard let doc = req.bodyJson() else { return 400 }
    guard let user = json.decode(User, doc) else { return 422 }
    guard let encoded = json.value(user) else { return 500 }
    return response(200, body: encoded)
}
)rut";
    auto lexed = lex(lit(src));
    REQUIRE(lexed);
    auto ast = parse_file_heap(lexed.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    if (!hir)
        fprintf(stderr,
                "JSON codec analyze error %u at %u:%u: %.*s\n",
                static_cast<u32>(hir.error().code),
                hir.error().span.line,
                hir.error().span.col,
                hir.error().detail.len,
                hir.error().detail.ptr);
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler = reinterpret_cast<HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler);
    SlicePool pool;
    REQUIRE(pool.init(64));
    auto conn = std::make_unique<Connection>();
    conn->reset();
    conn->json_arena.backend.pool = &pool;
    const char* cases[] = {"{\"name\":\"Rut\",\"active\":false,\"age\":42}",
                           "{\"name\":\"Rut\",\"active\":false}",
                           "{\"name\":1,\"active\":false,\"age\":42}",
                           "{\"name\":\"Rut\",\"active\":false,\"age\":2147483648}",
                           "null",
                           "not-json"};
    const u32 statuses[] = {200, 422, 422, 422, 422, 400};
    for (u32 i = 0; i < 6; ++i) {
        char request[256];
        const int len = snprintf(request,
                                 sizeof(request),
                                 "POST /codec HTTP/1.1\r\nContent-Length: %zu\r\n\r\n%s",
                                 strlen(cases[i]),
                                 cases[i]);
        conn->json_arena.destroy();
        conn->jit_response_body_valid = false;
        const auto result = HandlerResult::unpack(handler(conn.get(),
                                                          nullptr,
                                                          reinterpret_cast<const u8*>(request),
                                                          static_cast<u32>(len),
                                                          nullptr));
        CHECK_EQ(result.status_code, statuses[i]);
        if (i == 0) {
            CHECK_EQ(result.upstream_id, 0xffffu);
            CHECK(conn->jit_response_body_valid);
            CHECK(conn->jit_response_body.eq(lit(cases[i])));
        } else
            CHECK(!conn->jit_response_body_valid);
    }
    conn->reset();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jit, json_allocation_failure_is_explicit) {
    u8 has = 1;
    const char* ptr = "old";
    u32 len = 3;
    i64 number = 1;
    rut_helper_json(nullptr,
                    nullptr,
                    static_cast<u32>(json::Op::Quote),
                    "x",
                    1,
                    nullptr,
                    0,
                    nullptr,
                    0,
                    0,
                    &has,
                    &ptr,
                    &len,
                    &number);
    CHECK_EQ(has, 0);
    CHECK(ptr == nullptr);
    CHECK_EQ(len, 0u);
    CHECK_EQ(number, 0);
}

TEST(jit, json_literal_escapes_null_and_number_lexemes) {
    const char* src = R"rut(
route GET "/literal" {
    guard let doc = json.parse("{\"text\":\"\\uD83D\\uDE00\\n\",\"number\":1e999,\"nil\":null}") else { return 400 }
    guard let item = json.get(doc, "/text") else { return 401 }
    guard let text = json.string(item) else { return 402 }
    if text == "\u{1F600}\n" { return 200 } else { return 500 }
}
route GET "/number" {
    guard let doc = json.number("1.2300e+999") else { return 400 }
    guard let text = json.numberText(doc) else { return 401 }
    if text == "1.2300e+999" { return 200 } else { return 500 }
}
route GET "/null" {
    guard let doc = json.value(nil) else { return 400 }
    guard let kind = json.kind(doc) else { return 401 }
    if kind == "null" { return 200 } else { return 500 }
}
)rut";
    auto tokens = lex(lit(src));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto cg = codegen(rir.module);
    REQUIRE(cg.ok);
    JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    for (u32 i = 0; i < 3; ++i) {
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", i);
        auto fn = reinterpret_cast<HandlerFn>(engine.lookup(name));
        REQUIRE(fn);
        const auto result = HandlerResult::unpack(fn(nullptr, nullptr, nullptr, 0, &arena));
        CHECK_EQ(result.status_code, 200);
        arena.reset();
    }
    arena.destroy();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}
