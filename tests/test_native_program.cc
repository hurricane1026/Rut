#include "deferred_preflight_fixture.h"
#include "es256_fixture.h"
#include "fixtures/jwt_lifetime.h"
#include "fixtures/signed_request.h"
#include "fixtures/ws_borrowed_binary.h"
#include "fixtures/ws_optional_values.h"
#include "framing_selection_preflight_fixture.h"
#include "rs256_fixture.h"
#include "rut/jit/native_helper_symbols.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/native_program.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/ebpf_plan.h"
#include "rut/runtime/password_gateway.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"
#include <filesystem>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace rut;
TEST(native_program, helper_resolver_rejects_unlisted_symbols) {
    u32 count = 0;
    const auto* symbols = native_helper_symbols(count);
    REQUIRE(symbols);
    REQUIRE(count > 0);
    for (u32 i = 0; i < count; ++i) {
        const Str name{symbols[i].name, static_cast<u32>(strlen(symbols[i].name))};
        CHECK(find_native_helper(name) == symbols[i].address);
    }
    CHECK(find_native_helper(lit_str("malloc")) == nullptr);
    CHECK(find_native_helper(lit_str("rut_helper_hash_extra")) == nullptr);
    CHECK(find_native_helper({nullptr, 1}) == nullptr);
    CHECK(find_native_helper(lit_str("rut_helper_jwt_issue_hs256")) != nullptr);
    CHECK(find_native_helper(lit_str("rut_helper_jwt_issue_hs256_with_id")) != nullptr);
}
namespace {
struct Source {
    char path[4096] = "/tmp/rut native source-XXXXXX";
    int fd = -1;
    Source() {
        const char* directory = getenv("TMPDIR");
        if (directory && snprintf(path, sizeof(path), "%s/rut native source-XXXXXX", directory) >=
                             static_cast<int>(sizeof(path)))
            return;
        fd = mkstemp(path);
    }
    bool append(const char* bytes, u32 len) {
        while (len) {
            ssize_t n = write(fd, bytes, len);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            bytes += n;
            len -= static_cast<u32>(n);
        }
        return true;
    }
    bool append(const char* text) { return append(text, static_cast<u32>(strlen(text))); }
    ~Source() {
        if (fd >= 0) close(fd);
        unlink(path);
    }
};
struct Program {
    NativeProgram* p = nullptr;
    MmapArena arena;
    Program() {
        if (arena.init(sizeof(NativeProgram) + 4096)) p = arena.alloc_t<NativeProgram>();
    }
    ~Program() {
        if (p) p->destroy();
        arena.destroy();
    }
};
struct SigchldRestore {
    struct sigaction old{};
    bool active = sigaction(SIGCHLD, nullptr, &old) == 0;
    ~SigchldRestore() {
        if (active) sigaction(SIGCHLD, &old, nullptr);
    }
};
jit::HandlerResult invoke(const RouteEntry& route, const char* request) {
    jit::HandlerCtx ctx{};
    return jit::HandlerResult::unpack(route.fn(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(request),
                                               static_cast<u32>(strlen(request)),
                                               nullptr));
}
jit::HandlerResult invoke(const RouteEntry& route, const std::string& request) {
    jit::HandlerCtx ctx{};
    return jit::HandlerResult::unpack(route.fn(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(request.data()),
                                               static_cast<u32>(request.size()),
                                               nullptr));
}
bool load(Source& source, NativeProgram& p, u8 opt = 2) {
    char error[512];
    bool ok = load_native_program(source.path, p, error, sizeof(error), opt);
    if (!ok) fprintf(stderr, "%s\n", error);
    return ok;
}
}  // namespace

TEST(native_program, mtls_pin_and_request_property_execute_after_source_removal) {
    const char* names[] = {"MTLS_CLIENT_PIN", "MTLS_CONSUMER_ID", "MTLS_CREDENTIAL_ID"};
    const char* values[] = {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "test-client",
                            "fixture-cert-v1"};
    const bool had_values[] = {
        getenv(names[0]) != nullptr, getenv(names[1]) != nullptr, getenv(names[2]) != nullptr};
    std::string old_values[3];
    for (u32 i = 0; i < 3; ++i) {
        if (had_values[i]) old_values[i] = getenv(names[i]);
        REQUIRE_EQ(setenv(names[i], values[i], 1), 0);
    }
    struct RestoreEnv {
        const char** names;
        const bool* had_values;
        const std::string* old_values;
        ~RestoreEnv() {
            for (u32 i = 0; i < 3; ++i) {
                if (had_values[i])
                    (void)setenv(names[i], old_values[i].c_str(), 1);
                else
                    (void)unsetenv(names[i]);
            }
        }
    } restore{names, had_values, old_values};

    const auto source_path = std::filesystem::path(__FILE__).parent_path().parent_path() /
                             "examples/mtls-pinned-auth.rut";
    FILE* input = fopen(source_path.c_str(), "rb");
    REQUIRE(input != nullptr);
    char source_bytes[4096];
    const size_t source_len = fread(source_bytes, 1, sizeof(source_bytes), input);
    const bool source_ok = !ferror(input) && feof(input);
    fclose(input);
    REQUIRE(source_ok);
    REQUIRE_LT(source_len, sizeof(source_bytes));
    std::string temp_template = source_path.parent_path().string() + "/mtls-native-XXXXXX";
    const i32 source_fd = mkstemp(temp_template.data());
    REQUIRE(source_fd >= 0);
    u32 written = 0;
    while (written < source_len) {
        const ssize_t amount = write(source_fd, source_bytes + written, source_len - written);
        REQUIRE_GT(amount, 0);
        written += static_cast<u32>(amount);
    }
    static constexpr char kNegativeRoutes[] =
        "\nroute GET \"/wrong-pin\" {\n"
        "    let identity = auth.pinnedMtlsIdentity(\n"
        "        \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\n"
        "        env(\"MTLS_CONSUMER_ID\"), env(\"MTLS_CREDENTIAL_ID\"))\n"
        "    let consumerId = identity.consumerId\n"
        "    return response(200, body: consumerId)\n}\n"
        "route GET \"/bad-config\" {\n"
        "    let identity = auth.pinnedMtlsIdentity(\n"
        "        \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n\",\n"
        "        env(\"MTLS_CONSUMER_ID\"), env(\"MTLS_CREDENTIAL_ID\"))\n"
        "    let consumerId = identity.consumerId\n"
        "    return response(200, body: consumerId)\n}\n";
    const ssize_t extra_written = write(source_fd, kNegativeRoutes, sizeof(kNegativeRoutes) - 1);
    REQUIRE_EQ(extra_written, static_cast<ssize_t>(sizeof(kNegativeRoutes) - 1));
    close(source_fd);
    Program owner;
    REQUIRE(owner.p != nullptr);
    char error[512]{};
    REQUIRE_MSG(
        load_native_program(temp_template.c_str(), *owner.p, error, sizeof(error), 0, false),
        error);
    REQUIRE_EQ(unlink(temp_template.c_str()), 0);
    auto& config = owner.p->config;
    REQUIRE_EQ(config.route_count, 3u);
    ConnectionBase conn{};
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls_client_cert_sha256_valid = true;
    memset(conn.tls_client_cert_sha256, 'a', sizeof(conn.tls_client_cert_sha256));
    const char* paths[] = {"/private", "/wrong-pin", "/bad-config"};
    const u16 statuses[] = {200, 403, 503};
    for (u32 i = 0; i < 3; ++i) {
        REQUIRE(config.routes[i].fn != nullptr);
        char request[128];
        const int request_len = snprintf(
            request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", paths[i]);
        REQUIRE_GT(request_len, 0);
        jit::HandlerCtx ctx{};
        const auto result =
            jit::HandlerResult::unpack(config.routes[i].fn(&conn,
                                                           &ctx,
                                                           reinterpret_cast<const u8*>(request),
                                                           static_cast<u32>(request_len),
                                                           nullptr));
        CHECK_EQ(result.status_code, statuses[i]);
        if (i == 0) {
            CHECK(conn.jit_response_body_valid);
            CHECK(conn.jit_response_body.eq(lit_str("test-client")));
        }
    }
}

#if RUT_ENABLE_WEBSOCKET

TEST(native_program, websocket_required_subprotocol_survives_source_removal) {
    Source source;
    REQUIRE(source.fd >= 0);
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend, subprotocol: \"chat\") "
                      "{ message in message.forward() } }\n"
                      "route GET \"/other\" { return websocket(backend, subprotocol: \"other\") "
                      "{ message in message.drop() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 2u);
    const RouteEntry& route = owner.p->config.routes[0];
    CHECK(route.ws_subprotocol.eq(lit_str("chat")));
    CHECK(owner.p->config.routes[1].ws_subprotocol.eq(lit_str("other")));
    CHECK(route.ws_frame_handler(nullptr, WsOpcode::Text, nullptr, 0, true) ==
          WsFrameAction::Forward);
    static constexpr char kRequest[] =
        "GET /ws HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: chat,other\r\n\r\n";
    u8 storage[SlicePool::kSliceSize];
    u32 offers_len = 0;
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                               sizeof(kRequest) - 1,
                               storage,
                               sizeof(storage),
                               &offers_len,
                               route.ws_subprotocol) == WsHandshakeRequestResult::Ready);
    CHECK(ws_prepare_handshake(reinterpret_cast<const u8*>(kRequest),
                               sizeof(kRequest) - 1,
                               storage,
                               sizeof(storage),
                               &offers_len,
                               lit_str("missing")) == WsHandshakeRequestResult::BadRequest);
}

TEST(native_program, websocket_terminate_http_guards_and_dual_handlers_survive_source_removal) {
    Source source;
    REQUIRE(source.fd >= 0);
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { guard let origin = req.uniqueHeader(\"Origin\") "
                      "else { return 403 }\n"
                      "guard origin == \"https://allowed.example\" else { return 403 }\n"
                      "return websocket(backend) { message in message.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    char error[512]{};
    REQUIRE(load_native_program(source.path, *owner.p, error, sizeof(error), 2));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& config = owner.p->config;
    REQUIRE_EQ(config.route_count, 1u);
    const RouteEntry& route = config.routes[0];
    CHECK(route.action == RouteAction::JitHandler);
    REQUIRE(route.fn);
    CHECK(route.ws_terminate);
    REQUIRE(route.ws_frame_handler);
    CHECK_EQ(route.upstream_id, 0u);
    const auto denied = invoke(route, "GET /ws HTTP/1.1\r\nHost: test\r\n\r\n");
    CHECK(denied.action == jit::HandlerAction::ReturnStatus);
    CHECK_EQ(denied.status_code, 403u);
    const auto allowed =
        invoke(route, "GET /ws HTTP/1.1\r\nHost: test\r\nOrigin: https://allowed.example\r\n\r\n");
    CHECK(allowed.action == jit::HandlerAction::Forward);
    CHECK_EQ(allowed.upstream_id, route.upstream_id);
}

TEST(native_program, websocket_terminate_rejects_unsupported_http_prelude_before_publish) {
    Source source;
    REQUIRE(source.fd >= 0);
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "func allowed() -> bool => true\n"
                      "route GET \"/ws\" { guard allowed() else { return 403 }\n"
                      "return websocket(backend) { message in message.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    char error[512]{};
    CHECK_FALSE(load_native_program(source.path, *owner.p, error, sizeof(error), 2));
    CHECK_EQ(owner.p->config.route_count, 0u);
    CHECK_EQ(owner.p->library, nullptr);
}

TEST(native_program, websocket_dual_handlers_keep_mixed_http_timer_ordinals) {
    Source source;
    REQUIRE(source.append(
        "upstream backend at \"127.0.0.1:9999\"\n"
        "route GET \"/before\" { return 200 }\n"
        "timer tick, every: 1s { }\n"
        "route GET \"/ws-one\" { return websocket(backend) { message in message.drop() } }\n"
        "route GET \"/middle\" { return 204 }\n"
        "route GET \"/ws-two\" { return websocket(backend) { message in message.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& config = owner.p->config;
    REQUIRE_EQ(config.route_count, 4u);
    REQUIRE_EQ(config.timer_count, 1u);
    auto route_path = [&](u32 index) {
        return Str{config.routes[index].path, config.routes[index].path_len};
    };
    CHECK(route_path(0).eq(lit_str("/before")));
    CHECK_FALSE(config.routes[0].ws_terminate);
    CHECK(route_path(1).eq(lit_str("/ws-one")));
    REQUIRE(config.routes[1].fn);
    REQUIRE(config.routes[1].ws_frame_handler);
    CHECK(config.routes[1].ws_terminate);
    CHECK(route_path(2).eq(lit_str("/middle")));
    CHECK_FALSE(config.routes[2].ws_terminate);
    CHECK(route_path(3).eq(lit_str("/ws-two")));
    REQUIRE(config.routes[3].fn);
    REQUIRE(config.routes[3].ws_frame_handler);
    CHECK(config.routes[3].ws_terminate);
    CHECK(config.routes[1].ws_frame_handler(
              nullptr, WsOpcode::Text, reinterpret_cast<const u8*>("x"), 1, true) ==
          WsFrameAction::Drop);
    CHECK(config.routes[3].ws_frame_handler(
              nullptr, WsOpcode::Text, reinterpret_cast<const u8*>("x"), 1, true) ==
          WsFrameAction::Forward);
}
#endif

TEST(native_program, upstream_tls_configuration_is_owned_after_compiler_exit) {
    Source source;
    REQUIRE(source.append(
        "upstream secure { host: \"127.0.0.1\", port: 443, protocol: .http2, "
        "tls: { ca: \"ca.pem\", server_name: \"backend.example\", "
        "cert: \"client.pem\", key: \"client.key\" } }\n"
        "route POST \"/test.Echo/Call\" { return forward(secure, load_balance: .roundRobin) }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& target = owner.p->config.upstreams[0];
    CHECK(target.http2);
    CHECK(target.tls.enabled);
    CHECK_EQ(strcmp(target.tls.ca, "ca.pem"), 0);
    CHECK_EQ(strcmp(target.tls.server_name, "backend.example"), 0);
    CHECK_EQ(strcmp(target.tls.cert, "client.pem"), 0);
    CHECK_EQ(strcmp(target.tls.key, "client.key"), 0);
}

TEST(native_program, code_and_views_survive_compiler_exit_and_source_removal) {
    Source source;
    REQUIRE(source.append(
        "accessLog { path: \"/tmp/rut-native.log\", format: downstreamRequestBytes, publication: "
        "live }\n"
        "listen 127.0.0.1:0\n"
        "route GET \"/users/:id\" { guard req.params.id == \"42\" else { return 403 } "
        "return response(201, body: \"native body\", headers: {\"X-Native\": \"yes\"}) }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& c = owner.p->config;
    REQUIRE_EQ(c.route_count, 1u);
    CHECK(owner.p->has_listener);
    CHECK_EQ(owner.p->listener.port, 0u);
    CHECK(owner.p->access_log.present);
    CHECK_EQ(strcmp(owner.p->access_log.path, "/tmp/rut-native.log"), 0);
    RouteParam params[kMaxRouteParams];
    u32 count = 0;
    const auto* route =
        c.match_canonical(lit_str("users/42"), kRouteMethodGet, params, &count, kMaxRouteParams);
    REQUIRE(route);
    REQUIRE_EQ(count, 1u);
    // The request helper obtains captures from HandlerCtx rather than reparsing the route.
    jit::HandlerCtx ctx{};
    for (u32 i = 0; i < count; i++) ctx.route_params[i] = params[i];
    ctx.route_param_count = count;
    const char* req = "GET /users/42 HTTP/1.1\r\nHost: test\r\n\r\n";
    auto result = jit::HandlerResult::unpack(
        route->fn(nullptr, &ctx, reinterpret_cast<const u8*>(req), strlen(req), nullptr));
    CHECK_EQ(result.status_code, 201u);
    REQUIRE_EQ(c.response_body_count, 1u);
    CHECK((Str{c.response_bodies[0].data, c.response_bodies[0].len}.eq(lit_str("native body"))));
    REQUIRE_EQ(c.header_pool_used, 1u);
    CHECK((Str{c.header_keys[0].data, c.header_keys[0].len}.eq(lit_str("X-Native"))));
    CHECK((Str{c.header_values[0].data, c.header_values[0].len}.eq(lit_str("yes"))));
}

TEST(native_program, password_header_suspends_after_compiler_exit_and_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(route GET "/login" {
        let result = passwordVerifyHeader("X-Password", "$rut-pbkdf2-sha256$600000$000102030405060708090a0b0c0d0e0f$3bc37118e625093e9b79ed08930ea7af7389591233fdd92dddf369371e60dbc0", 5000)
        match result {
            1 => {
                req.set("X-Authenticated", "yes")
                return 200
            }
            _ => return 401
        }
    })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE(owner.p->config.requires_password_gateway());
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    ConnectionBase conn{};
    conn.reset();
    conn.fd = 42;
    conn.id = 1;
    conn.handler_gen = 1;
    conn.transition_to_exec_handler_wait();
    jit::HandlerCtx ctx{};
    const char request[] = "GET /login HTTP/1.1\r\nHost: test\r\nX-Password: password\r\n\r\n";
    const u64 deadline = monotonic_us() + 10000000;
    bool suspended = false;
    for (;;) {
        PasswordHandlerScope binding(&gateway, &conn);
        const auto result = jit::HandlerResult::unpack(owner.p->config.routes[0].fn(
            &conn, &ctx, reinterpret_cast<const u8*>(request), sizeof(request) - 1, nullptr));
        if (result.action != jit::HandlerAction::Yield) {
            CHECK_EQ(result.status_code, 200u);
            break;
        }
        suspended = true;
        CHECK_EQ(conn.req_header_override_count, 0u);
        REQUIRE(result.yield_kind == jit::YieldKind::Timer);
        CHECK_EQ(result.next_state, 0u);
        REQUIRE(result.yield_payload_u32() > 0 && result.yield_payload_u32() <= 10);
        REQUIRE(monotonic_us() < deadline);
        usleep(result.yield_payload_u32() * 1000);
    }
    CHECK(suspended);
    CHECK_EQ(conn.req_header_override_count, 1u);
    CHECK_EQ(gateway.active_requests(), 0u);
}

TEST(native_program, jwt_issue_helper_survives_native_artifact_source_removal) {
    Source source;
    const char rut_source[] =
        "route GET \"/token\" { let issued = jwtIssueHs256(\"alice\", \"issuer\", "
        "\"orders\", \"01234567890123456789012345678901\", 60) "
        "guard let token = issued else { return 503 } "
        "guard let claims = jwtDecode(token, \"01234567890123456789012345678901\", \"HS256\") "
        "else { return 501 } "
        "guard jwtClaimsValid(claims, \"issuer\", \"orders\") else { return 502 } "
        "return 204 }\n";
    REQUIRE(source.append(rut_source, sizeof(rut_source) - 1));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 1u);
    REQUIRE_EQ(unlink(source.path), 0);
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    jit::HandlerCtx ctx{};
    const char request[] = "GET /token HTTP/1.1\r\nHost: test\r\n\r\n";
    const auto result = jit::HandlerResult::unpack(owner.p->config.routes[0].fn(
        nullptr, &ctx, reinterpret_cast<const u8*>(request), sizeof(request) - 1, &arena));
    CHECK_EQ(result.status_code, 204u);
    arena.destroy();
    pool.destroy();
}

TEST(native_program, jwt_issue_with_id_helper_survives_native_artifact_source_removal) {
    Source source;
    const char rut_source[] =
        "route GET \"/token\" { let issued = jwtIssueHs256WithId(\"alice\", \"issuer\", "
        "\"orders\", \"request-42\", \"01234567890123456789012345678901\", 60) "
        "guard let token = issued else { return 503 } "
        "guard let claims = jwtDecode(token, \"01234567890123456789012345678901\", \"HS256\") "
        "else { return 501 } "
        "guard jwtClaimsValid(claims, \"issuer\", \"orders\") else { return 502 } "
        "guard let idJson = json.get(claims, \"/jti\") else { return 504 } "
        "guard let tokenId = json.string(idJson) else { return 505 } "
        "guard tokenId == \"request-42\" else { return 506 } return 204 }\n";
    REQUIRE(source.append(rut_source, sizeof(rut_source) - 1));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 1u);
    REQUIRE_EQ(unlink(source.path), 0);
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    jit::HandlerCtx ctx{};
    const char request[] = "GET /token HTTP/1.1\r\nHost: test\r\n\r\n";
    const auto result = jit::HandlerResult::unpack(owner.p->config.routes[0].fn(
        nullptr, &ctx, reinterpret_cast<const u8*>(request), sizeof(request) - 1, &arena));
    CHECK_EQ(result.status_code, 204u);
    arena.destroy();
    pool.destroy();
}

TEST(native_program, jwt_issue_with_id_and_scope_helper_survives_source_removal) {
    Source source;
    const char rut_source[] =
        "route GET \"/token\" { let issued = jwtIssueHs256WithIdAndScope(\"alice\", \"issuer\", "
        "\"orders\", \"request-88\", \"orders:read\", \"01234567890123456789012345678901\", 60) "
        "guard let token = issued else { return 503 } "
        "guard let claims = jwtDecode(token, \"01234567890123456789012345678901\", \"HS256\") "
        "else { return 501 } "
        "guard jwtClaimsValid(claims, \"issuer\", \"orders\") else { return 502 } "
        "guard jwtHasScope(claims, \"orders:read\") else { return 504 } "
        "guard !jwtHasScope(claims, \"orders:write\") else { return 505 } return 204 }\n";
    REQUIRE(source.append(rut_source, sizeof(rut_source) - 1));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 1u);
    REQUIRE_EQ(unlink(source.path), 0);
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    jit::HandlerCtx ctx{};
    const char request[] = "GET /token HTTP/1.1\r\nHost: test\r\n\r\n";
    const auto result = jit::HandlerResult::unpack(owner.p->config.routes[0].fn(
        nullptr, &ctx, reinterpret_cast<const u8*>(request), sizeof(request) - 1, &arena));
    CHECK_EQ(result.status_code, 204u);
    arena.destroy();
    pool.destroy();
}

TEST(native_program, signed_request_helper_survives_native_artifact_source_removal) {
    Source source;
    const auto auth_path = (std::filesystem::path(__FILE__).parent_path().parent_path() /
                            "examples/middleware/auth.rut")
                               .string();
    const std::string rut_source =
        "import \"" + auth_path +
        "\"\nroute POST \"/signed\" { let identity = auth.signedRequest(\"" +
        ::rut::test::signed_request::kKeyId + "\", \"" + ::rut::test::signed_request::kSecret +
        "\", \"orders\", \"key-v1\") "
        "guard identity.consumerId == \"orders\" && identity.credentialId == \"key-v1\" else { "
        "return 500 } "
        "return 204 }\n";
    REQUIRE(source.append(rut_source.data(), static_cast<u32>(rut_source.size())));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 1u);
    REQUIRE_EQ(unlink(source.path), 0);

    timespec now{};
    REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
    REQUIRE(now.tv_sec > 1000);
    const std::string target = "/signed?artifact=source-free";
    const std::string body("native\0body", 11);
    const auto headers =
        ::rut::test::signed_request::make_headers("POST", target, body, now.tv_sec);
    REQUIRE(!headers.authorization.empty());
    const std::string request =
        "POST " + target +
        " HTTP/1.1\r\nHost: localhost\r\nAuthorization: " + headers.authorization +
        "\r\nDate: " + headers.date + "\r\nDigest: " + headers.digest +
        "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    const auto result = invoke(owner.p->config.routes[0], request);
    CHECK_EQ(result.status_code, 204u);
}

TEST(native_program, rotating_signed_request_survives_native_artifact_source_removal) {
    Source source;
    const auto auth_path = (std::filesystem::path(__FILE__).parent_path().parent_path() /
                            "examples/middleware/auth.rut")
                               .string();
    const std::string rut_source =
        "import \"" + auth_path +
        "\"\nroute POST \"/signed-current\" { let config = "
        "auth.SignedRequestRotation(currentKeyId: "
        "\"current-kid\", currentKey: \"current-secret\", previousKeyId: \"previous-kid\", "
        "previousKey: \"previous-secret\", consumerId: \"orders\", currentId: \"key-current\", "
        "previousId: \"key-previous\") let identity = auth.rotatingSignedRequest(config) "
        "guard identity.consumerId == \"orders\" && identity.credentialId == \"key-current\" else "
        "{ "
        "return 500 } "
        "return 204 }\n"
        "route POST \"/signed-previous\" { let config = auth.SignedRequestRotation(currentKeyId: "
        "\"current-kid\", currentKey: \"current-secret\", previousKeyId: \"previous-kid\", "
        "previousKey: \"previous-secret\", consumerId: \"orders\", currentId: \"key-current\", "
        "previousId: \"key-previous\") let identity = auth.rotatingSignedRequest(config) "
        "guard identity.consumerId == \"orders\" && identity.credentialId == \"key-previous\" else "
        "{ "
        "return 500 } "
        "return 204 }\n"
        "route POST \"/signed-revoked\" { let config = auth.SignedRequestRotation(currentKeyId: "
        "\"current-kid\", currentKey: \"current-secret\", previousKeyId: \"\", previousKey: \"\", "
        "consumerId: \"orders\", currentId: \"key-current\", previousId: \"key-previous\") let "
        "identity = auth.rotatingSignedRequest(config) return 204 }\n";
    REQUIRE(source.append(rut_source.data(), static_cast<u32>(rut_source.size())));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 3u);
    REQUIRE_EQ(unlink(source.path), 0);

    timespec now{};
    REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
    REQUIRE(now.tv_sec > 1000);
    const std::string target = "/signed-current?artifact=source-free";
    const std::string body("native\0body", 11);
    const auto headers = ::rut::test::signed_request::make_headers(
        "POST", target, body, now.tv_sec, "current-kid", "current-secret");
    REQUIRE(!headers.authorization.empty());
    const std::string request =
        "POST " + target +
        " HTTP/1.1\r\nHost: localhost\r\nAuthorization: " + headers.authorization +
        "\r\nDate: " + headers.date + "\r\nDigest: " + headers.digest +
        "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    const auto result = invoke(owner.p->config.routes[0], request);
    CHECK_EQ(result.status_code, 204u);
    const std::string previous_target = "/signed-previous?artifact=source-free";
    const auto previous_headers = ::rut::test::signed_request::make_headers(
        "POST", previous_target, body, now.tv_sec, "previous-kid", "previous-secret");
    const std::string previous_request =
        "POST " + previous_target +
        " HTTP/1.1\r\nHost: localhost\r\nAuthorization: " + previous_headers.authorization +
        "\r\nDate: " + previous_headers.date + "\r\nDigest: " + previous_headers.digest +
        "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    CHECK_EQ(invoke(owner.p->config.routes[1], previous_request).status_code, 204u);
    const std::string revoked_target = "/signed-revoked?artifact=source-free";
    const auto revoked_headers = ::rut::test::signed_request::make_headers(
        "POST", revoked_target, body, now.tv_sec, "previous-kid", "previous-secret");
    const std::string revoked_request =
        "POST " + revoked_target +
        " HTTP/1.1\r\nHost: localhost\r\nAuthorization: " + revoked_headers.authorization +
        "\r\nDate: " + revoked_headers.date + "\r\nDigest: " + revoked_headers.digest +
        "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    CHECK_EQ(invoke(owner.p->config.routes[2], revoked_request).status_code, 401u);
}

TEST(native_program, jwt_lifetime_policy_survives_native_artifact_source_removal) {
    Source source;
    const auto auth_path = (std::filesystem::path(__FILE__).parent_path().parent_path() /
                            "examples/middleware/auth.rut")
                               .string();
    const std::string rut_source =
        "import \"" + auth_path +
        "\"\nroute GET \"/jwt\" { let verified = auth.jwtDocumentHs256(req.authorization.or(\"\"), "
        "\"" +
        ::rut::test::jwt_lifetime::kSecret +
        "\") let identity = auth.jwtIdentityWithLifetime(verified, \"issuer\", \"gateway\", "
        "\"age-policy\", 300, 7200) "
        "guard identity.consumerId == \"alice\" && identity.credentialId == \"age-policy\" && "
        "identity.method == \"jwt\" else { return 500 } return 204 }\n";
    REQUIRE(source.append(rut_source.data(), static_cast<u32>(rut_source.size())));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 1u);
    REQUIRE_EQ(unlink(source.path), 0);

    timespec now{};
    REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
    REQUIRE(now.tv_sec > 1000);
    const auto claims = ::rut::test::jwt_lifetime::claims(now.tv_sec - 30, now.tv_sec + 1800);
    const auto token = ::rut::test::jwt_lifetime::make_token(claims);
    REQUIRE(!token.empty());
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    jit::HandlerCtx ctx{};
    const auto invoke_token = [&](const std::string& compact) {
        arena.reset();
        const std::string request =
            "GET /jwt HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + compact + "\r\n\r\n";
        return jit::HandlerResult::unpack(
            owner.p->config.routes[0].fn(nullptr,
                                         &ctx,
                                         reinterpret_cast<const u8*>(request.data()),
                                         static_cast<u32>(request.size()),
                                         &arena));
    };
    CHECK_EQ(invoke_token(token).status_code, 204u);
    const auto old_claims = ::rut::test::jwt_lifetime::claims(now.tv_sec - 400, now.tv_sec + 1800);
    const auto old_token = ::rut::test::jwt_lifetime::make_token(old_claims);
    REQUIRE(!old_token.empty());
    CHECK_EQ(invoke_token(old_token).status_code, 401u);
    arena.destroy();
    pool.destroy();
}

TEST(native_program, links_with_closed_stderr) {
    Source source;
    REQUIRE(source.append("route GET \"/\" { return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    const int saved_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    REQUIRE(saved_stderr >= 0);
    REQUIRE_EQ(close(STDERR_FILENO), 0);
    char error[512]{};
    const bool loaded = load_native_program(source.path, *owner.p, error, sizeof(error));
    const bool restored = dup2(saved_stderr, STDERR_FILENO) == STDERR_FILENO;
    close(saved_stderr);
    REQUIRE(restored);
    if (!loaded) fprintf(stderr, "closed-stderr load failed: %s\n", error);
    CHECK(loaded);
}

TEST(native_program, regex_and_independent_program_lifetimes) {
    Source source;
    REQUIRE(
        source.append("route GET \"/regex\" { guard req.path.matches(re\"/regex\") else { return "
                      "403 } return 201 }\n"));
    Program first;
    Program second;
    REQUIRE(first.p && second.p);
    REQUIRE(load(source, *first.p, 0));
    REQUIRE(load(source, *second.p, 3));
    CHECK_EQ(first.p->regex_count, 1u);
    const auto* route = first.p->config.match_canonical(lit_str("regex"), kRouteMethodGet);
    REQUIRE(route);
    CHECK_EQ(invoke(*route, "GET /regex HTTP/1.1\r\n\r\n").status_code, 201u);
    CHECK_EQ(invoke(*route, "GET /other HTTP/1.1\r\n\r\n").status_code, 403u);
    first.p->destroy();
    route = second.p->config.match_canonical(lit_str("regex"), kRouteMethodGet);
    REQUIRE(route);
    CHECK_EQ(invoke(*route, "GET /regex HTTP/1.1\r\n\r\n").status_code, 201u);
}

TEST(native_program, large_body_file_is_owned_by_server) {
    Source source;
    REQUIRE(source.append("route GET \"/large\" { return response(200, body: \""));
    char chunk[4096];
    memset(chunk, 'x', sizeof(chunk));
    for (u32 i = 0; i < 256; i++) REQUIRE(source.append(chunk, sizeof(chunk)));
    REQUIRE(source.append("\") }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    unlink(source.path);
    auto& b = owner.p->config.response_bodies[0];
    CHECK_EQ(b.len, 1048576u);
    CHECK_EQ(b.data[0], 'x');
    CHECK_EQ(b.data[b.len - 1], 'x');
#ifdef __linux__
    REQUIRE(b.file_ref);
    int fd = b.file_fd();
    char value = 0;
    REQUIRE_EQ(pread(fd, &value, 1, 1048575), 1);
    CHECK_EQ(value, 'x');
    CHECK((fcntl(fd, F_GET_SEALS) & F_SEAL_WRITE) != 0);
    owner.p->destroy();
    CHECK_EQ(fcntl(fd, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
#endif
}

TEST(native_program, timer_cache_activation_and_fail_closed) {
    Source source;
    REQUIRE(
        source.append("let buckets = Cache<IP, i64>(capacity: 128)\n"
                      "timer cleanup, every: 5s, shard: 0 { }\n"
                      "route GET \"/\" { let n = buckets.get(req.remoteAddr).or(0) "
                      "buckets.set(req.remoteAddr, n + 1) return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p, 1));
    CHECK_EQ(owner.p->config.timer_count, 1u);
    CHECK_EQ(owner.p->config.timers[0].interval_ms, 5000u);
    CHECK_EQ(owner.p->config.timers[0].shard, 0);
    REQUIRE(owner.p->config.timers[0].fn);
    jit::HandlerCtx ctx{};
    owner.p->config.timers[0].fn(nullptr, &ctx, nullptr, 0, nullptr);
    activate_native_program(*owner.p);
    CHECK_EQ(cache_registry().capacities[0].load(std::memory_order_relaxed), 128u);
    owner.p->destroy();
    CHECK_EQ(cache_registry().owner.load(std::memory_order_relaxed), nullptr);
    Source bad;
    REQUIRE(bad.append("route GET \"/\" { broken\n"));
    char error[512];
    CHECK_FALSE(load_native_program(bad.path, *owner.p, error, sizeof(error)));
    CHECK(strstr(error, "rut-compile failed") != nullptr);
    CHECK_EQ(owner.p->config.route_count, 0u);
    CHECK_EQ(owner.p->library, nullptr);
}

#if RUT_ENABLE_WEBSOCKET
TEST(native_program, websocket_json_field_presence_survives_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard json.get(document, "/a~1b/~0/0") != nil && json.get(document, "/\0") != nil else {
  message.close(1008)
 }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const char* payloads[] = {"{\"a/b\":{\"~\":[null]},\"\\u0000\":1}", "{}", "{"};
    for (const char* payload : payloads) {
        const auto expected = payload[1] == '"'   ? WsFrameAction::Forward
                              : payload[1] == '}' ? WsFrameAction::ClosePolicy1
                                                  : WsFrameAction::ClosePolicy0;
        CHECK(handler(nullptr,
                      WsOpcode::Text,
                      reinterpret_cast<const u8*>(payload),
                      strlen(payload),
                      true) == expected);
    }
}

TEST(native_program, websocket_json_string_aliases_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/type") else { message.close(1008) }
 guard let kind = json.string(field) else { message.close(1003) }
 guard kind == "subscribe" else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const char* accepted[] = {R"({"type":"subscribe"})", R"({"type":"sub\u0073cribe"})"};
    for (const char* payload : accepted) {
        CHECK(handler(nullptr,
                      WsOpcode::Text,
                      reinterpret_cast<const u8*>(payload),
                      strlen(payload),
                      true) == WsFrameAction::Forward);
    }
    CHECK(handler(nullptr,
                  WsOpcode::Text,
                  reinterpret_cast<const u8*>(R"({"type":null})"),
                  strlen(R"({"type":null})"),
                  true) == WsFrameAction::ClosePolicy2);
    CHECK(handler(nullptr,
                  WsOpcode::Text,
                  reinterpret_cast<const u8*>(R"({"type":"publish"})"),
                  strlen(R"({"type":"publish"})"),
                  true) == WsFrameAction::Drop);
    REQUIRE_EQ(owner.p->config.routes[0].ws_close_policy_count, 3u);
}

TEST(native_program, websocket_json_string_rewrite_path_and_affixes_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/data/name") else { message.close(1008) }
 guard let text = json.string(field) else { message.close(1003) }
 guard text != "drop" else { message.forward("[" + text + "]") }
 message.forward("<" + text + ">")
} }
route GET "/root" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let root = json.string(document) else { message.close(1003) }
 message.forward("(" + root + ")")
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    REQUIRE_EQ(route.ws_forward_text.source, WsTextSource::JsonString);
    CHECK(route.ws_forward_text.source_path.eq(lit_str("/data/name")));
    REQUIRE_EQ(route.ws_forward_text_count, 1u);
    const WsTextRewrite& branch = route.ws_forward_texts[0];
    CHECK_EQ(branch.source, WsTextSource::JsonString);
    CHECK(branch.source_path.eq(lit_str("/data/name")));
    const char json_payload[] = R"({"data":{"name":"x\u0000\u20ac"}})";
    u8 input[64], output[64], msg[64];
    input[0] = 0x82;
    input[1] = static_cast<u8>(sizeof(json_payload) - 1);
    memcpy(input + 2, json_payload, sizeof(json_payload) - 1);
    WsInspector st;
    st.forward_text = route.ws_forward_text;
    st.forward_texts = route.ws_forward_texts;
    st.forward_text_count = route.ws_forward_text_count;
    st.max_message_size = route.ws_max_message_size;
    u32 used = 0, produced = 0;
    REQUIRE(ws_inspect(st,
                       input,
                       sizeof(json_payload) + 1,
                       output,
                       sizeof(output),
                       msg,
                       sizeof(msg),
                       route.ws_frame_handler,
                       nullptr,
                       &used,
                       &produced) == WsInspectStatus::Ok);
    const Str expected{"<x\0\xe2\x82\xac>", 7};
    REQUIRE_EQ(produced, expected.len + 2);
    CHECK_EQ(output[0], 0x81u);
    CHECK_EQ(output[1], expected.len);
    CHECK(memcmp(output + 2, expected.ptr, expected.len) == 0);
    const auto& root_route = owner.p->config.routes[1];
    REQUIRE_EQ(root_route.ws_forward_text.source, WsTextSource::JsonString);
    CHECK_EQ(root_route.ws_forward_text.source_path.len, 0u);
    CHECK(root_route.ws_forward_text.source_path.ptr != nullptr);
    const char root_json[] = R"("\uD83D\uDE00")";
    input[0] = 0x81;
    input[1] = static_cast<u8>(sizeof(root_json) - 1);
    memcpy(input + 2, root_json, sizeof(root_json) - 1);
    WsInspector root_st;
    root_st.forward_text = root_route.ws_forward_text;
    root_st.max_message_size = root_route.ws_max_message_size;
    used = 0;
    produced = 0;
    REQUIRE(ws_inspect(root_st,
                       input,
                       sizeof(root_json) + 1,
                       output,
                       sizeof(output),
                       msg,
                       sizeof(msg),
                       root_route.ws_frame_handler,
                       nullptr,
                       &used,
                       &produced) == WsInspectStatus::Ok);
    const Str root_expected{"(\xf0\x9f\x98\x80)", 6};
    REQUIRE_EQ(produced, root_expected.len + 2);
    CHECK(memcmp(output + 2, root_expected.ptr, root_expected.len) == 0);
}

TEST(native_program, websocket_json_number_text_recipe_survives_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/number" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/n") else { message.close(1008) }
 guard let number = json.numberText(field) else { message.close(1003) }
 guard number == "1.2300e+999" else { message.forward("[" + number + "]") }
 message.forward("<" + number + ">")
} }
route GET "/root-number" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let number = json.numberText(document) else { message.close(1003) }
 message.forward("(" + number + ")")
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    REQUIRE_EQ(route.ws_forward_text.source, WsTextSource::JsonNumberText);
    CHECK(route.ws_forward_text.source_path.eq(lit_str("/n")));
    REQUIRE_EQ(route.ws_forward_text_count, 1u);
    CHECK_EQ(route.ws_forward_texts[0].source, WsTextSource::JsonNumberText);
    const char payload[] = R"({"n":1.2300e+999})";
    u8 input[64]{}, output[128]{}, msg[64]{};
    input[0] = 0x82;
    input[1] = static_cast<u8>(sizeof(payload) - 1);
    memcpy(input + 2, payload, sizeof(payload) - 1);
    WsInspector st;
    st.forward_text = route.ws_forward_text;
    st.forward_texts = route.ws_forward_texts;
    st.forward_text_count = route.ws_forward_text_count;
    st.max_message_size = route.ws_max_message_size;
    u32 used = 0, produced = 0;
    REQUIRE(ws_inspect(st,
                       input,
                       sizeof(payload) + 1,
                       output,
                       sizeof(output),
                       msg,
                       sizeof(msg),
                       route.ws_frame_handler,
                       nullptr,
                       &used,
                       &produced) == WsInspectStatus::Ok);
    const char expected[] = "<1.2300e+999>";
    REQUIRE_EQ(produced, sizeof(expected) - 1 + 2);
    CHECK_EQ(output[0], 0x81u);
    CHECK_EQ(output[1], sizeof(expected) - 1);
    CHECK(memcmp(output + 2, expected, sizeof(expected) - 1) == 0);
    const char branch_payload[] = R"({"n":2})";
    input[0] = 0x82;
    input[1] = static_cast<u8>(sizeof(branch_payload) - 1);
    memcpy(input + 2, branch_payload, sizeof(branch_payload) - 1);
    used = 0;
    produced = 0;
    REQUIRE(ws_inspect(st,
                       input,
                       sizeof(branch_payload) + 1,
                       output,
                       sizeof(output),
                       msg,
                       sizeof(msg),
                       route.ws_frame_handler,
                       nullptr,
                       &used,
                       &produced) == WsInspectStatus::Ok);
    const char branch_expected[] = "[2]";
    REQUIRE_EQ(produced, sizeof(branch_expected) - 1 + 2);
    CHECK_EQ(output[0], 0x81u);
    CHECK_EQ(output[1], sizeof(branch_expected) - 1);
    CHECK(memcmp(output + 2, branch_expected, sizeof(branch_expected) - 1) == 0);
    const auto& root_route = owner.p->config.routes[1];
    REQUIRE_EQ(root_route.ws_forward_text.source, WsTextSource::JsonNumberText);
    CHECK_EQ(root_route.ws_forward_text.source_path.len, 0u);
    CHECK(root_route.ws_forward_text.source_path.ptr != nullptr);
    const char root_payload[] = "1.2300e+999";
    u8 root_input[64]{}, root_output[128]{}, root_message[64]{};
    root_input[0] = 0x82;
    root_input[1] = static_cast<u8>(sizeof(root_payload) - 1);
    memcpy(root_input + 2, root_payload, sizeof(root_payload) - 1);
    WsInspector root_inspector;
    root_inspector.forward_text = root_route.ws_forward_text;
    root_inspector.forward_texts = root_route.ws_forward_texts;
    root_inspector.forward_text_count = root_route.ws_forward_text_count;
    root_inspector.max_message_size = root_route.ws_max_message_size;
    used = 0;
    produced = 0;
    REQUIRE(ws_inspect(root_inspector,
                       root_input,
                       sizeof(root_payload) + 1,
                       root_output,
                       sizeof(root_output),
                       root_message,
                       sizeof(root_message),
                       root_route.ws_frame_handler,
                       nullptr,
                       &used,
                       &produced) == WsInspectStatus::Ok);
    const char root_expected[] = "(1.2300e+999)";
    REQUIRE_EQ(produced, sizeof(root_expected) - 1 + 2);
    CHECK_EQ(root_output[0], 0x81u);
    CHECK_EQ(root_output[1], sizeof(root_expected) - 1);
    CHECK(memcmp(root_output + 2, root_expected, sizeof(root_expected) - 1) == 0);
}

TEST(native_program, websocket_json_string_regex_survives_source_removal_and_multiple_routes) {
    Source source;
    REQUIRE(source.append(R"rut(upstream ws at "127.0.0.1:9999"
route GET "/root" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let text = json.string(document) else { message.close(1003) }
 guard text.matches(re"sub[0-9]+") && message.text.matches(re".+") else { message.drop() }
 message.forward()
} }
route GET "/selected" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/a~1b/\0") else { message.close(1008) }
 guard let text = json.string(field) else { message.close(1003) }
 guard !text.matches(re"deny[0-9]+") else { message.drop() }
 message.forward()
} }
route GET "/other" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/other") else { message.close(1008) }
 guard let text = json.string(field) else { message.close(1003) }
 guard text.matches(re"other[0-9]+") else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 3u);
    struct Case {
        u32 route;
        const char* payload;
        WsFrameAction action;
    };
    const Case cases[] = {
        {0, R"("sub12")", WsFrameAction::Forward},
        {0, R"("sub\u0031\u0032")", WsFrameAction::Forward},
        {0, R"("sub12suffix")", WsFrameAction::Drop},
        {0, R"("other7")", WsFrameAction::Drop},
        {1, R"({"a/b":{"\u0000":"deny7"}})", WsFrameAction::Drop},
        {1, R"({"a/b":{"\u0000":"xdeny7"}})", WsFrameAction::Forward},
        {1, R"({"a/b":{"\u0000":null}})", WsFrameAction::ClosePolicy2},
        {1, R"({"a/b":{}})", WsFrameAction::ClosePolicy1},
        {2, R"({"other":"other9"})", WsFrameAction::Forward},
        {2, R"({"other":"sub12"})", WsFrameAction::Drop},
    };
    for (const auto& c : cases) {
        const auto handler = owner.p->config.routes[c.route].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
                CHECK(handler(nullptr,
                              op,
                              reinterpret_cast<const u8*>(c.payload),
                              strlen(c.payload),
                              client) == c.action);
            }
        }
    }
}

TEST(native_program, websocket_direct_json_scalar_guards_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream ws at "127.0.0.1:9999"
route GET "/nested" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.drop() }
 guard let parent = json.get(document, "/payload") else { message.drop() }
 guard let field = json.get(parent, "/enabled") else { message.drop() }
 guard json.bool(field) == false else { message.drop() }
 message.forward()
} }
route GET "/string" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.drop() }
 guard json.string(document) == "x\0" else { message.drop() }
 message.forward()
} }
route GET "/int" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.drop() }
 guard json.int(document) == -9223372036854775808 else { message.drop() }
 message.forward()
} }
route GET "/nil" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.drop() }
 guard json.int(document) == nil else { message.drop() }
 message.forward()
} }
route GET "/not-false" { return websocket(ws) { message in
 guard let document = json.parse(message.text) else { message.drop() }
 guard json.bool(document) != false else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 5u);
    struct Case {
        u32 route;
        const char* payload;
        bool accepted;
    };
    const Case cases[] = {
        {0, R"({"payload":{"enabled":false}})", true},
        {0, R"({"payload":{"enabled":true}})", false},
        {0, R"({"payload":{"enabled":null}})", false},
        {0, R"({"payload":{}})", false},
        {1, R"("x\u0000")", true},
        {1, R"("x")", false},
        {1, "null", false},
        {2, "-9223372036854775808", true},
        {2, "-9223372036854775809", false},
        {2, "-9223372036854775808.0", false},
        {2, "null", false},
        {3, "null", true},
        {3, "1.0", true},
        {3, "9223372036854775808", true},
        {3, "1", false},
        {3, "{", false},
        {4, "true", true},
        {4, "false", false},
        {4, "null", true},
        {4, "0", true},
    };
    for (const auto& c : cases) {
        const auto handler = owner.p->config.routes[c.route].ws_frame_handler;
        REQUIRE(handler);
        for (bool client : {false, true}) {
            for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
                CHECK(handler(nullptr,
                              op,
                              reinterpret_cast<const u8*>(c.payload),
                              strlen(c.payload),
                              client) ==
                      (c.accepted ? WsFrameAction::Forward : WsFrameAction::Drop));
            }
        }
    }
}

TEST(native_program, websocket_json_stringify_recipe_survives_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/default" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let encoded = json.stringify(document) else { message.close(1003) }
 message.forward("<" + encoded + ">")
} }
route GET "/else" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/payload") else { message.close(1008) }
 guard let encoded = json.stringify(field) else { message.close(1003) }
 guard encoded == "never" else { message.forward("[" + encoded + "]") }
 message.forward()
} }
route GET "/root" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let encoded = json.stringify(document) else { message.close(1003) }
 message.forward("(" + encoded + ")")
} }
route GET "/second" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let parent = json.get(document, "/other") else { message.close(1008) }
 guard let field = json.get(parent, "/value") else { message.close(1008) }
 guard let encoded = json.stringify(field) else { message.close(1003) }
 message.forward(encoded)
} }
route GET "/nested-string" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let parent = json.get(document, "/a~1b") else { message.close(1008) }
 guard let field = json.get(parent, "/~0/0") else { message.close(1008) }
 guard let text = json.string(field) else { message.close(1003) }
 message.forward("<" + text + ">")
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(owner.p->config.route_count, 5u);
    REQUIRE_EQ(unlink(source.path), 0);

    CHECK_EQ(owner.p->config.routes[0].ws_forward_text.source, WsTextSource::JsonStringify);
    CHECK_EQ(owner.p->config.routes[0].ws_forward_text.source_path.len, 0u);
    CHECK(owner.p->config.routes[0].ws_forward_text.source_path.ptr != nullptr);
    CHECK_EQ(owner.p->config.routes[1].ws_forward_text_count, 1u);
    CHECK_EQ(owner.p->config.routes[1].ws_forward_texts[0].source, WsTextSource::JsonStringify);
    CHECK(owner.p->config.routes[1].ws_forward_texts[0].source_path.eq(lit_str("/payload")));
    CHECK_EQ(owner.p->config.routes[3].ws_forward_text.source, WsTextSource::JsonStringify);
    CHECK(owner.p->config.routes[3].ws_forward_text.source_path.eq(lit_str("/other/value")));
    CHECK(owner.p->config.routes[4].ws_forward_text.source_path.eq(lit_str("/a~1b/~0/0")));

    auto inspect = [&](u32 route_index, const char* payload, const char* expected) {
        const RouteEntry& route = owner.p->config.routes[route_index];
        const u32 payload_len = static_cast<u32>(strlen(payload));
        u8 input[256]{}, output[512]{}, message[256]{};
        input[0] = 0x82;
        input[1] = static_cast<u8>(payload_len);
        memcpy(input + 2, payload, payload_len);
        WsInspector inspector;
        inspector.forward_text = route.ws_forward_text;
        inspector.forward_texts = route.ws_forward_texts;
        inspector.forward_text_count = route.ws_forward_text_count;
        inspector.max_message_size = route.ws_max_message_size;
        u32 used = 0, produced = 0;
        REQUIRE(ws_inspect(inspector,
                           input,
                           payload_len + 2,
                           output,
                           sizeof(output),
                           message,
                           sizeof(message),
                           route.ws_frame_handler,
                           nullptr,
                           &used,
                           &produced) == WsInspectStatus::Ok);
        CHECK_EQ(used, payload_len + 2);
        CHECK_EQ(output[0], 0x81u);
        CHECK_EQ(output[1], strlen(expected));
        CHECK(memcmp(output + 2, expected, strlen(expected)) == 0);
    };
    inspect(0, R"({"b":2,"a":1.2300})", R"(<{"b":2,"a":1.2300}>)");
    inspect(1, R"({"payload":{"x":true,"n":-0}})", R"([{"x":true,"n":-0}])");
    inspect(2, R"(null)", "(null)");
    inspect(3, R"({"other":{"value":[1,2]}})", "[1,2]");
    inspect(4, R"({"a/b":{"~":["hello"]}})", "<hello>");
}

TEST(native_program, websocket_json_string_predicates_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/topic") else { message.close(1008) }
 guard let topic = json.string(field) else { message.close(1003) }
 guard !topic.isEmpty && topic.hasPrefix("topic.") && topic.hasSuffix(":end") &&
       topic.contains("mid\0\u{20ac}") else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const char* kAccepted[] = {R"({"topic":"topic.mid\u0000\u20ac:end"})",
                               R"({"topic":"topic.mid\u0000€:end"})"};
    for (const char* payload : kAccepted) {
        CHECK(handler(nullptr,
                      WsOpcode::Text,
                      reinterpret_cast<const u8*>(payload),
                      strlen(payload),
                      true) == WsFrameAction::Forward);
    }
    CHECK(handler(nullptr,
                  WsOpcode::Text,
                  reinterpret_cast<const u8*>(R"({"topic":"topic.mid\u0000X:end"})"),
                  strlen(R"({"topic":"topic.mid\u0000X:end"})"),
                  true) == WsFrameAction::Drop);
    CHECK(handler(nullptr,
                  WsOpcode::Text,
                  reinterpret_cast<const u8*>(R"({"topic":null})"),
                  strlen(R"({"topic":null})"),
                  true) == WsFrameAction::ClosePolicy2);
}

TEST(native_program, websocket_json_false_boolean_alias_survives_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/enabled") else { message.close(1008) }
 guard let enabled = json.bool(field) else { message.close(1003) }
 guard enabled == false else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const char* payloads[] = {
        R"({"enabled":false})", R"({"enabled":true})", R"({"enabled":null})", "{}", "{"};
    const WsFrameAction expected[] = {WsFrameAction::Forward,
                                      WsFrameAction::Drop,
                                      WsFrameAction::ClosePolicy2,
                                      WsFrameAction::ClosePolicy1,
                                      WsFrameAction::ClosePolicy0};
    for (u32 i = 0; i < sizeof(payloads) / sizeof(payloads[0]); ++i) {
        CHECK(handler(nullptr,
                      WsOpcode::Text,
                      reinterpret_cast<const u8*>(payloads[i]),
                      strlen(payloads[i]),
                      true) == expected[i]);
    }
    REQUIRE_EQ(owner.p->config.routes[0].ws_close_policy_count, 3u);
}

TEST(native_program, websocket_json_i64_bounds_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/count") else { message.close(1008) }
 guard let count = json.int(field) else { message.close(1003) }
 guard count == -9223372036854775808 || count == 9223372036854775807 else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const char* const payloads[] = {R"({"count":-9223372036854775808})",
                                    R"({"count":9223372036854775807})",
                                    R"({"count":2147483648})",
                                    R"({"count":1.0})",
                                    R"({"count":9223372036854775808})"};
    const WsFrameAction expected[] = {WsFrameAction::Forward,
                                      WsFrameAction::Forward,
                                      WsFrameAction::Drop,
                                      WsFrameAction::ClosePolicy2,
                                      WsFrameAction::ClosePolicy2};
    for (u32 i = 0; i < sizeof(payloads) / sizeof(payloads[0]); ++i) {
        CHECK(handler(nullptr,
                      WsOpcode::Text,
                      reinterpret_cast<const u8*>(payloads[i]),
                      strlen(payloads[i]),
                      i % 2 == 0) == expected[i]);
    }
    REQUIRE_EQ(owner.p->config.routes[0].ws_close_policy_count, 3u);
}

TEST(native_program, websocket_json_kind_and_count_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/kind" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/value") else { message.close(1008) }
 guard let tag = json.kind(field) else { message.close(1003) }
 guard "object" == tag else { message.drop() }
 message.forward()
} }
route GET "/count" { return websocket(backend) { message in
 guard let document = json.parse(message.text) else { message.close(1007) }
 guard let field = json.get(document, "/items") else { message.close(1008) }
 guard let amount = json.count(field) else { message.close(1003) }
 guard 1 < amount && amount <= 2 else { message.drop() }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);

    const auto kind_handler = owner.p->config.routes[0].ws_frame_handler;
    const auto count_handler = owner.p->config.routes[1].ws_frame_handler;
    REQUIRE(kind_handler);
    REQUIRE(count_handler);
    CHECK(kind_handler(nullptr,
                       WsOpcode::Text,
                       reinterpret_cast<const u8*>(R"({"value":{}})"),
                       strlen(R"({"value":{}})"),
                       true) == WsFrameAction::Forward);
    CHECK(kind_handler(nullptr,
                       WsOpcode::Text,
                       reinterpret_cast<const u8*>(R"({"value":null})"),
                       strlen(R"({"value":null})"),
                       false) == WsFrameAction::Drop);
    CHECK(count_handler(nullptr,
                        WsOpcode::Text,
                        reinterpret_cast<const u8*>(R"({"items":[1,2]})"),
                        strlen(R"({"items":[1,2]})"),
                        true) == WsFrameAction::Forward);
    CHECK(count_handler(nullptr,
                        WsOpcode::Binary,
                        reinterpret_cast<const u8*>(R"({"items":[]})"),
                        strlen(R"({"items":[]})"),
                        false) == WsFrameAction::Drop);
    CHECK(count_handler(nullptr,
                        WsOpcode::Text,
                        reinterpret_cast<const u8*>(R"({"items":null})"),
                        strlen(R"({"items":null})"),
                        true) == WsFrameAction::ClosePolicy2);
}

TEST(native_program, websocket_json_validation_survives_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
 guard !message.fromClient || !message.isText || json.parse(message.text) != nil else {
  message.close(1007, "invalid JSON")
 }
 message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    const auto handler = route.ws_frame_handler;
    REQUIRE(handler);
    const u8 valid[] = {'n', 'u', 'l', 'l'};
    const u8 invalid[] = {'{'};
    CHECK(handler(nullptr, WsOpcode::Text, valid, sizeof(valid), true) == WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Text, invalid, sizeof(invalid), true) ==
          WsFrameAction::ClosePolicy0);
    CHECK(handler(nullptr, WsOpcode::Text, nullptr, 0x100000000ULL, false) ==
          WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Binary, invalid, sizeof(invalid), true) ==
          WsFrameAction::Forward);
    REQUIRE_EQ(route.ws_close_policy_count, 1u);
    CHECK_EQ(route.ws_close_policies[0].code, 1007u);
}

TEST(native_program, websocket_rewrite_survives_compiler_exit_and_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { message in "
                      "message.forward(\"native\\0text\") } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    REQUIRE_EQ(route.ws_forward_text.prefix.len, 11u);
    CHECK(memcmp(route.ws_forward_text.prefix.ptr, "native\0text", 11) == 0);
    WsInspector st;
    st.forward_text = route.ws_forward_text;
    st.max_message_size = route.ws_max_message_size;
    const u8 input[] = {0x82, 0};
    u8 output[64], msg[64];
    u32 consumed = 0, produced = 0;
    REQUIRE(ws_inspect(st,
                       input,
                       sizeof(input),
                       output,
                       sizeof(output),
                       msg,
                       sizeof(msg),
                       route.ws_frame_handler,
                       nullptr,
                       &consumed,
                       &produced) == WsInspectStatus::Ok);
    REQUIRE_EQ(produced, 13u);
    CHECK_EQ(output[0], 0x81);
    CHECK(memcmp(output + 2, "native\0text", 11) == 0);
}

TEST(native_program, websocket_binary_replacements_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(
upstream backend at "127.0.0.1:9999"
route GET "/ws" { return websocket(backend) { message in
    guard message.text != "a" else { message.forward(b"\x00\xff") }
    guard message.text != "b" else { message.forward("text") }
    guard message.text != "c" else { message.forward() }
    guard message.text != "d" else { message.forward(b"") }
    message.forward(b"\x80\x00end")
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    REQUIRE_EQ(route.ws_forward_text_count, 3u);
    const Str expected[] = {{"\0\xff", 2}, {"text", 4}, {"c", 1}, {}, {"\x80\0end", 5}};
    for (u32 i = 0; i < 5; ++i) {
        WsInspector st;
        st.forward_text = route.ws_forward_text;
        st.forward_texts = route.ws_forward_texts;
        st.forward_text_count = route.ws_forward_text_count;
        st.max_message_size = route.ws_max_message_size;
        const u8 input[] = {0x82, 1, static_cast<u8>('a' + i)};
        u8 out[32], msg[32];
        u32 used = 0, produced = 0;
        REQUIRE(ws_inspect(st,
                           input,
                           sizeof(input),
                           out,
                           sizeof(out),
                           msg,
                           sizeof(msg),
                           route.ws_frame_handler,
                           nullptr,
                           &used,
                           &produced) == WsInspectStatus::Ok);
        CHECK_EQ(used, sizeof(input));
        REQUIRE_EQ(produced, 2u + expected[i].len);
        CHECK_EQ(out[0], i == 1 ? 0x81u : 0x82u);
        if (expected[i].len) CHECK(memcmp(out + 2, expected[i].ptr, expected[i].len) == 0);
    }
}

TEST(native_program, websocket_affix_rewrites_survive_source_removal) {
    Source source;
    REQUIRE(source.append(
        "upstream backend at \"127.0.0.1:9999\"\n"
        "route GET \"/ws\" { let prefix = \"one\\0\"\n"
        " let alias = prefix\n let suffix = \"\\u{20ac}\"\n"
        " return websocket(backend) { message in\n"
        " guard message.text != \"a\" else { message.forward(alias + message.text + "
        "suffix) }\n"
        " guard message.text != \"b\" else { message.forward(message.text + \"end\") }\n"
        " guard message.text != \"c\" else { message.forward(\"pre\" + message.text) }\n"
        " guard message.text != \"d\" else { message.forward(\"fixed\") }\n"
        " message.forward(\"[\" + message.text + \"]\") } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];

    REQUIRE_EQ(route.ws_forward_text_count, 4u);
    const Str expected[] = {
        {"one\0a\xe2\x82\xac", 8}, {"bend", 4}, {"prec", 4}, {"fixed", 5}, {"[e]", 3}};
    for (u32 i = 0; i < 5; i++) {
        WsInspector st;
        st.forward_text = route.ws_forward_text;
        st.forward_texts = route.ws_forward_texts;
        st.forward_text_count = route.ws_forward_text_count;
        st.max_message_size = route.ws_max_message_size;
        const u8 input[] = {0x81, 1, static_cast<u8>('a' + i)};
        u8 out[128], msg[32];
        u32 used = 0, produced = 0;
        REQUIRE(ws_inspect(st,
                           input,
                           sizeof(input),
                           out,
                           sizeof(out),
                           msg,
                           sizeof(msg),
                           route.ws_frame_handler,
                           nullptr,
                           &used,
                           &produced) == WsInspectStatus::Ok);
        REQUIRE_EQ(produced, 2u + expected[i].len);
        CHECK_EQ(out[0], 0x81u);
        CHECK(memcmp(out + 2, expected[i].ptr, expected[i].len) == 0);
    }
}

TEST(native_program, websocket_affixes_survive_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { message in\n"
                      "guard !message.fromClient || (message.text.hasPrefix(\"a\\0\") && "
                      "message.text.hasSuffix(\"\\u{20ac}\")) else { message.drop() }\n"
                      "message.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const u8 payload[] = {'a', 0, 'x', 0xe2, 0x82, 0xac};
    CHECK(handler(nullptr, WsOpcode::Text, payload, sizeof(payload), true) ==
          WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Binary, payload, sizeof(payload), true) ==
          WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Text, payload, sizeof(payload) - 1, true) ==
          WsFrameAction::Drop);
    CHECK(handler(nullptr, WsOpcode::Text, payload + 1, sizeof(payload) - 1, true) ==
          WsFrameAction::Drop);
    CHECK(handler(nullptr, WsOpcode::Text, nullptr, 123, false) == WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Text, nullptr, 0, true) == WsFrameAction::Drop);
}

TEST(native_program, websocket_contains_survives_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { message in\n"
                      "guard !message.fromClient || (message.text.contains(\"a\\0\") && "
                      "!message.text.contains(\"\\u{20ac}\")) else { message.drop() }\n"
                      "message.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const u8 payload[] = {'x', 'a', 0, 'x', 0xe2, 0x82, 0xac};
    CHECK(handler(nullptr, WsOpcode::Text, payload, 4, true) == WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Binary, payload, 4, true) == WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Text, payload, sizeof(payload), true) == WsFrameAction::Drop);
    CHECK(handler(nullptr, WsOpcode::Text, nullptr, 123, false) == WsFrameAction::Forward);
    CHECK(handler(nullptr, WsOpcode::Text, nullptr, 0, true) == WsFrameAction::Drop);
}

TEST(native_program, websocket_close_reason_survives_source_removal) {
    Source source;
    REQUIRE(source.append(
        "upstream backend at \"127.0.0.1:9999\"\n"
        "route GET \"/ws\" { return websocket(backend) { message in message.close(1008, "
        "\"native\\0\\u{20ac}\") } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    const char expected[] = "native\0\xe2\x82\xac";
    REQUIRE_EQ(route.ws_close_reason.len, sizeof(expected) - 1);
    CHECK(memcmp(route.ws_close_reason.ptr, expected, sizeof(expected) - 1) == 0);
    WsInspector st;
    st.close_code = route.ws_close_code;
    st.close_reason = route.ws_close_reason;
    const u8 input[] = {0x81, 0};
    u8 out[128], msg[32];
    u32 used = 0, produced = 0;
    REQUIRE(ws_inspect(st,
                       input,
                       sizeof(input),
                       out,
                       sizeof(out),
                       msg,
                       sizeof(msg),
                       route.ws_frame_handler,
                       nullptr,
                       &used,
                       &produced) == WsInspectStatus::Close);
    CHECK_EQ(produced, 4u + route.ws_close_reason.len);
    CHECK(memcmp(out + 4, expected, sizeof(expected) - 1) == 0);
}

TEST(native_program, websocket_guard_close_policies_survive_source_removal) {
    Source source;
    REQUIRE(source.append(
        "upstream backend at \"127.0.0.1:9999\"\nroute GET \"/ws\" { return "
        "websocket(backend) { message in\n"
        "guard message.text != \"a\" else { message.close(1008, \"a\\0\\u{20ac}\") }\n"
        "guard message.text != \"b\" else { message.close(1009) }\n"
        "guard message.text != \"c\" else { message.close(1011, \"third\") }\n"
        "guard message.text != \"d\" else { message.close(4001, \"fourth\") }\n"
        "message.close(1000, \"default\") } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    REQUIRE_EQ(route.ws_close_policy_count, 4u);
    const u16 codes[] = {1008, 1009, 1011, 4001, 1000};
    const Str reasons[] = {{"a\0\xe2\x82\xac", 5}, {}, {"third", 5}, {"fourth", 6}, {"default", 7}};
    for (u32 i = 0; i < 5; i++) {
        WsInspector st;
        st.close_code = route.ws_close_code;
        st.close_reason = route.ws_close_reason;
        st.close_policies = route.ws_close_policies;
        st.close_policy_count = route.ws_close_policy_count;
        const u8 input[] = {0x81, 1, static_cast<u8>('a' + i)};
        u8 out[128], msg[32];
        u32 used = 0, produced = 0;
        REQUIRE(ws_inspect(st,
                           input,
                           sizeof(input),
                           out,
                           sizeof(out),
                           msg,
                           sizeof(msg),
                           route.ws_frame_handler,
                           nullptr,
                           &used,
                           &produced) == WsInspectStatus::Close);
        CHECK_EQ(st.echo_close_code, codes[i]);
        CHECK(st.echo_close_reason.eq(reasons[i]));
        CHECK_EQ(produced, 4u + reasons[i].len);
        if (!reasons[i].empty()) CHECK(memcmp(out + 4, reasons[i].ptr, reasons[i].len) == 0);
    }
}

TEST(native_program, websocket_typed_message_helpers_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func accepted(_ text: str) -> bool => text.matches(re"o.k")
func allowed(_ msg: WebSocketMessage) -> bool =>
    !msg.fromClient || (msg.isText == true && msg.len <= 3 && accepted(msg.text))
route GET "/ws" { return websocket(backend) { message in
    guard true else { message.close() }
    guard allowed(message) else { message.drop() }
    guard message.isText != message.isBinary else { message.close() }
    message.forward()
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler);
    const Str payloads[] = {{"o\0k", 3}, {"oak", 3}, {"no", 2}, {"", 0}, {"oaks", 4}};
    const bool flags[] = {false, true};
    const WsOpcode opcodes[] = {WsOpcode::Text, WsOpcode::Binary};
    for (bool client : flags) {
        for (WsOpcode op : opcodes) {
            for (u32 i = 0; i < 5; ++i) {
                const auto payload = payloads[i];
                const bool pass = !client || (op == WsOpcode::Text && i < 2);
                CHECK(handler(nullptr,
                              op,
                              reinterpret_cast<const u8*>(payload.ptr),
                              payload.len,
                              client) == (pass ? WsFrameAction::Forward : WsFrameAction::Drop));
            }
        }
    }
}

TEST(native_program, websocket_domain_types_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
func isText(_ kind: WebSocketMessageKind) -> bool => same(kind, WebSocketMessageKind.text)
func fromClient(_ direction: WebSocketDirection) -> bool =>
    same(direction, WebSocketDirection.clientToUpstream)
func classify(_ path: str) -> WebSocketMessageKind {
    if path == "/text" { WebSocketMessageKind.text } else { WebSocketMessageKind.binary }
}
route GET "/http" {
    let kind = classify(req.path)
    guard isText(kind) else { return 403 }
    return 200
}
route GET "/ws" { return websocket(backend) { message in
    guard !fromClient(message.direction) || isText(message.kind) else { message.drop() }
    message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 2u);
    const char* requests[] = {"GET /text HTTP/1.1\r\nHost: test\r\n\r\n",
                              "GET /binary HTTP/1.1\r\nHost: test\r\n\r\n"};
    const auto http = owner.p->config.routes[0].fn;
    REQUIRE(http);
    for (u32 i = 0; i < 2; ++i) {
        const auto result =
            jit::HandlerResult::unpack(http(nullptr,
                                            nullptr,
                                            reinterpret_cast<const u8*>(requests[i]),
                                            static_cast<u32>(strlen(requests[i])),
                                            nullptr));
        CHECK_EQ(result.status_code, i == 0 ? 200u : 403u);
    }
    const auto handler = owner.p->config.routes[1].ws_frame_handler;
    REQUIRE(handler);
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            CHECK(handler(nullptr, op, nullptr, 0, client) ==
                  (!client || op == WsOpcode::Text ? WsFrameAction::Forward : WsFrameAction::Drop));
        }
    }
}

TEST(native_program, websocket_borrowed_binary_survives_source_removal) {
    Source source;
    REQUIRE(source.append(test::ws_borrowed_binary::kSource));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    test::ws_borrowed_binary::check(_tc, owner.p->config);
}

TEST(native_program, websocket_optional_values_survive_source_removal) {
    Source source;
    REQUIRE(source.append(test::ws_optional_values::kSource));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    test::ws_optional_values::check(_tc, owner.p->config);
}

TEST(native_program, websocket_value_choices_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream ws at "127.0.0.1:9999"
func pick(_ msg: WebSocketMessage, _ root: Json) -> Json {
    if msg.fromClient { json.get(root, "/a") } else { json.get(root, "/b") }
}
func readChoice(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let field = pick(msg, root) else { nil }
    json.string(field)
}
func fallback(_ root: Json) -> Json {
    if let field = json.get(root, "/a") { field } else { json.get(root, "/b") }
}
func readFallback(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let field = fallback(root) else { nil }
    json.string(field)
}
route GET "/guard" { return websocket(ws) { msg in
    guard let text = readChoice(msg) else { msg.drop() }
    guard text.hasPrefix("ok") else { msg.close(1008) }
    msg.forward("<" + text + ">")
} }
route GET "/if" { return websocket(ws) { msg in
    if let text = readChoice(msg) { msg.forward(text) }
    else { msg.forward("absent") }
} }
route GET "/early" { return websocket(ws) { msg in
    if msg.fromClient {
        if let text = readFallback(msg) { msg.forward(text) }
        guard msg.isBinary else { msg.drop() }
        msg.forward(b"\xff")
    } else { msg.forward("server") }
} }
route GET "/fallback" { return websocket(ws) { msg in
    guard let text = readFallback(msg) else { msg.drop() }
    msg.forward(text)
} }
route GET "/bare" { return websocket(ws) { msg in
    guard let text = readChoice(msg) else { msg.close() }
    msg.close(1008, "policy")
} }
func textOrNumber(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    if let text = json.string(root) { text } else { json.numberText(root) }
}
route GET "/scalar" { return websocket(ws) { msg in
    guard let text = textOrNumber(msg) else { msg.drop() }
    msg.forward(text)
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& program = *owner.p;
    REQUIRE_EQ(program.config.route_count, 6u);
    const auto guard = program.config.routes[0].ws_frame_handler;
    const auto branch = program.config.routes[1].ws_frame_handler;
    const auto early = program.config.routes[2].ws_frame_handler;
    const auto fallback = program.config.routes[3].ws_frame_handler;
    const auto bare = program.config.routes[4].ws_frame_handler;
    const auto scalar = program.config.routes[5].ws_frame_handler;
    REQUIRE(guard);
    REQUIRE(branch);
    REQUIRE(early);
    REQUIRE(fallback);
    REQUIRE(bare);
    REQUIRE(scalar);
    struct Case {
        const char* json;
        WsFrameAction client;
        WsFrameAction server;
    };
    const Case guards[] = {
        {"{\"a\":\"okA\",\"b\":\"okB\"}",
         WsFrameAction::ForwardText,
         WsFrameAction::ForwardTextPolicy0},
        {"{\"a\":\"\",\"b\":\"noB\"}", WsFrameAction::ClosePolicy0, WsFrameAction::ClosePolicy1},
        {"{\"b\":\"okB\"}", WsFrameAction::Drop, WsFrameAction::ForwardTextPolicy0},
        {"{\"a\":null,\"b\":\"okB\"}", WsFrameAction::Drop, WsFrameAction::ForwardTextPolicy0},
        {"broken", WsFrameAction::Drop, WsFrameAction::Drop},
        {"{\"a\":\"okA\",\"b\":false}", WsFrameAction::ForwardText, WsFrameAction::Drop}};
    const Case branches[] = {
        {"{\"a\":\"A\",\"b\":\"B\"}",
         WsFrameAction::ForwardTextPolicy0,
         WsFrameAction::ForwardTextPolicy1},
        {"{\"a\":\"\",\"b\":\"\"}",
         WsFrameAction::ForwardTextPolicy0,
         WsFrameAction::ForwardTextPolicy1},
        {"{\"b\":\"B\"}", WsFrameAction::ForwardText, WsFrameAction::ForwardTextPolicy1},
        {"broken", WsFrameAction::ForwardText, WsFrameAction::ForwardText}};
    const char* alternatives[] = {"{\"a\":\"A\",\"b\":\"B\"}",
                                  "{\"b\":\"B\"}",
                                  "{\"a\":null,\"b\":\"B\"}",
                                  "{\"a\":false,\"b\":\"B\"}",
                                  "{\"a\":\"\",\"b\":\"B\"}"};
    const char* scalars[] = {"\"\"", "\"ok\"", "0", "1.2300e+999", "null"};
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            for (const auto& test : guards)
                CHECK(guard(nullptr,
                            op,
                            reinterpret_cast<const u8*>(test.json),
                            static_cast<u32>(strlen(test.json)),
                            client) == (client ? test.client : test.server));
            for (const auto& test : branches)
                CHECK(branch(nullptr,
                             op,
                             reinterpret_cast<const u8*>(test.json),
                             static_cast<u32>(strlen(test.json)),
                             client) == (client ? test.client : test.server));
            for (u32 i = 0; i < 5; ++i) {
                const auto* bytes = reinterpret_cast<const u8*>(alternatives[i]);
                const u32 size = static_cast<u32>(strlen(alternatives[i]));
                const auto selected = i == 0 || i == 4 ? WsFrameAction::ForwardText
                                      : i == 1         ? WsFrameAction::ForwardTextPolicy0
                                                       : WsFrameAction::Drop;
                CHECK(fallback(nullptr, op, bytes, size, client) == selected);
                const auto resumed = !client                  ? WsFrameAction::ForwardText
                                     : i == 0 || i == 4       ? WsFrameAction::ForwardTextPolicy0
                                     : i == 1                 ? WsFrameAction::ForwardTextPolicy1
                                     : op == WsOpcode::Binary ? WsFrameAction::ForwardTextPolicy2
                                                              : WsFrameAction::Drop;
                CHECK(early(nullptr, op, bytes, size, client) == resumed);
                CHECK(scalar(nullptr,
                             op,
                             reinterpret_cast<const u8*>(scalars[i]),
                             static_cast<u32>(strlen(scalars[i])),
                             client) == (i < 2   ? WsFrameAction::ForwardText
                                         : i < 4 ? WsFrameAction::ForwardTextPolicy0
                                                 : WsFrameAction::Drop));
            }
            const char* valid = "{\"a\":\"okA\",\"b\":\"okB\"}";
            CHECK(bare(nullptr,
                       op,
                       reinterpret_cast<const u8*>(valid),
                       static_cast<u32>(strlen(valid)),
                       client) == (client ? WsFrameAction::Close : WsFrameAction::ClosePolicy0));
            CHECK(bare(nullptr, op, reinterpret_cast<const u8*>("broken"), 6, client) ==
                  WsFrameAction::Close);
        }
    }
    CHECK(program.config.routes[0].ws_forward_text.source_path.eq(lit_str("/a")));
    CHECK(program.config.routes[0].ws_forward_texts[0].source_path.eq(lit_str("/b")));
    CHECK_EQ(program.config.routes[4].ws_close_code, 1008u);
    CHECK(program.config.routes[4].ws_close_reason.eq(lit_str("policy")));
    CHECK(program.config.routes[5].ws_forward_text.source == WsTextSource::JsonString);
    CHECK(program.config.routes[5].ws_forward_texts[0].source == WsTextSource::JsonNumberText);
}

TEST(native_program, websocket_helper_bindings_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream ws at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func readName(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let field = json.get(identity(root), "/name") else { nil }
    guard let value = json.string(field) else { nil }
    value
}
func readFlag(_ msg: WebSocketMessage) -> bool {
    if let root = json.parse(msg.text) {
        if let field = json.get(root, "/flag") {
            if let value = json.bool(field) { value } else { nil }
        } else { nil }
    } else { nil }
}
func readRoot(_ msg: WebSocketMessage) -> Json {
    guard let root = json.parse(msg.text) else { nil }
    root
}
func readNested(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let child = json.get(root, "/a~1b") else { nil }
    guard let field = json.get(child, "/~0") else { nil }
    if let value = json.string(field) { value } else { nil }
}
func readSecond(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let first = json.get(root, "/a") else { nil }
    guard let second = json.get(root, "/b") else { nil }
    json.string(second)
}
route GET "/name" { return websocket(ws) { msg in
    if let text = readName(msg) { msg.forward("<" + text + ">") }
    else { msg.forward("absent") }
} }
route GET "/flag" { return websocket(ws) { msg in
    if let value = readFlag(msg) {
        if value == false { msg.forward("false") } else { msg.forward("true") }
    } else { msg.forward("absent") }
} }
route GET "/root" { return websocket(ws) { msg in
    guard let root = readRoot(msg) else { msg.close(1007) }
    guard let text = json.string(root) else { msg.drop() }
    msg.forward(text)
} }
route GET "/nested" { return websocket(ws) { msg in
    guard let text = readNested(msg) else { msg.drop() }
    msg.forward(text)
} }
route GET "/different" { return websocket(ws) { msg in
    if let text = readSecond(msg) { msg.forward(text) }
    else { msg.forward("absent") }
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& program = *owner.p;
    REQUIRE_EQ(program.config.route_count, 5u);
    const auto name = program.config.routes[0].ws_frame_handler;
    const auto flag = program.config.routes[1].ws_frame_handler;
    const auto root = program.config.routes[2].ws_frame_handler;
    const auto nested = program.config.routes[3].ws_frame_handler;
    const auto different = program.config.routes[4].ws_frame_handler;
    REQUIRE(name);
    REQUIRE(flag);
    REQUIRE(root);
    REQUIRE(nested);
    REQUIRE(different);
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const char* names[] = {
                "{\"name\":\"a\\u0000b\"}", "{\"name\":\"\"}", "{}", "{\"name\":false}", "broken"};
            for (u32 j = 0; j < 5; ++j)
                CHECK(name(nullptr,
                           op,
                           reinterpret_cast<const u8*>(names[j]),
                           static_cast<u32>(strlen(names[j])),
                           client) ==
                      (j < 2 ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
            const char* flags[] = {
                "{\"flag\":false}", "{\"flag\":true}", "{\"flag\":null}", "{}", "broken"};
            for (u32 j = 0; j < 5; ++j)
                CHECK(flag(nullptr,
                           op,
                           reinterpret_cast<const u8*>(flags[j]),
                           static_cast<u32>(strlen(flags[j])),
                           client) == (j == 0   ? WsFrameAction::ForwardTextPolicy0
                                       : j == 1 ? WsFrameAction::ForwardTextPolicy1
                                                : WsFrameAction::ForwardText));
            const char* roots[] = {"\"\"", "\"ok\"", "null", "false", "broken"};
            for (u32 j = 0; j < 5; ++j)
                CHECK(root(nullptr,
                           op,
                           reinterpret_cast<const u8*>(roots[j]),
                           static_cast<u32>(strlen(roots[j])),
                           client) == (j < 2    ? WsFrameAction::ForwardText
                                       : j == 4 ? WsFrameAction::ClosePolicy0
                                                : WsFrameAction::Drop));
            const char* paths[] = {"{\"a/b\":{\"~\":\"ok\"}}",
                                   "{\"a/b\":{\"~\":\"\"}}",
                                   "{}",
                                   "{\"a/b\":{\"~\":false}}"};
            for (u32 j = 0; j < 4; ++j)
                CHECK(nested(nullptr,
                             op,
                             reinterpret_cast<const u8*>(paths[j]),
                             static_cast<u32>(strlen(paths[j])),
                             client) == (j < 2 ? WsFrameAction::ForwardText : WsFrameAction::Drop));
            const char* different_paths[] = {"{\"a\":null,\"b\":\"second\"}",
                                             "{\"a\":\"first\",\"b\":\"\"}",
                                             "{\"b\":\"second\"}",
                                             "{\"a\":null,\"b\":false}"};
            for (u32 j = 0; j < 4; ++j)
                CHECK(different(nullptr,
                                op,
                                reinterpret_cast<const u8*>(different_paths[j]),
                                static_cast<u32>(strlen(different_paths[j])),
                                client) ==
                      (j < 2 ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
        }
    }
    CHECK(program.config.routes[0].ws_forward_texts[0].source_path.eq(lit_str("/name")));
    CHECK(program.config.routes[3].ws_forward_text.source_path.eq(lit_str("/a~1b/~0")));
    CHECK(program.config.routes[4].ws_forward_texts[0].source_path.eq(lit_str("/b")));
}

TEST(native_program, websocket_optional_conditions_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream ws at "127.0.0.1:9999"
func readClient(_ msg: WebSocketMessage) -> Json {
    guard msg.fromClient else { nil }
    if msg.isText { json.parse(msg.text) } else { nil }
}
func readServer(_ msg: WebSocketMessage) -> Json {
    if msg.fromClient { nil } else { json.parse(msg.text) }
}
func selectedString(_ msg: WebSocketMessage, _ root: Json) -> str {
    if msg.fromClient { json.string(root) } else { nil }
}
route GET "/client" { return websocket(ws) { msg in
    if let root = readClient(msg) {
        guard let field = json.get(root, "/name") else { msg.close(1008) }
        guard let text = json.string(field) else { msg.close(1003) }
        msg.forward("<" + text + ">")
    } else { msg.forward() }
} }
route GET "/server" { return websocket(ws) { msg in
    if let root = readServer(msg) { msg.forward("json") }
    else { msg.forward("absent") }
} }
route GET "/scalar" { return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    if let value = selectedString(msg, root) { msg.forward(value) }
    else { msg.forward("absent") }
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 3u);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    const auto server = owner.p->config.routes[1].ws_frame_handler;
    const auto scalar = owner.p->config.routes[2].ws_frame_handler;
    REQUIRE(handler);
    REQUIRE(server);
    REQUIRE(scalar);
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const char* values[] = {"{\"name\":\"\"}", "{\"name\":null}", "{}", "broken"};
            for (u32 j = 0; j < 4; ++j) {
                const auto* data = reinterpret_cast<const u8*>(values[j]);
                const u32 size = static_cast<u32>(strlen(values[j]));
                CHECK(handler(nullptr, op, data, size, client) ==
                      (!client || op == WsOpcode::Binary || j == 3 ? WsFrameAction::Forward
                       : j == 0 ? WsFrameAction::ForwardTextPolicy0
                       : j == 1 ? WsFrameAction::ClosePolicy1
                                : WsFrameAction::ClosePolicy0));
                CHECK(server(nullptr, op, data, size, client) ==
                      (!client && j != 3 ? WsFrameAction::ForwardTextPolicy0
                                         : WsFrameAction::ForwardText));
            }
            const char* values2[] = {"\"\"", "\"ok\"", "null", "broken"};
            for (u32 j = 0; j < 4; ++j)
                CHECK(scalar(nullptr,
                             op,
                             reinterpret_cast<const u8*>(values2[j]),
                             static_cast<u32>(strlen(values2[j])),
                             client) == (j == 3            ? WsFrameAction::ClosePolicy0
                                         : client && j < 2 ? WsFrameAction::ForwardTextPolicy0
                                                           : WsFrameAction::ForwardText));
        }
    }
}

TEST(native_program, websocket_json_helpers_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func document(_ msg: WebSocketMessage) -> Json => json.parse(msg.text)
func select(_ value: Json, _ pointer: str) -> Json => json.get(identity(value), pointer)
func stringValue(_ value: Json) -> str => json.string(value)
func flag(_ value: Json) -> bool => json.bool(value)
route GET "/name" { return websocket(backend) { msg in
    if msg.fromClient {
        guard let root = document(msg) else { msg.close(1007) }
        guard let field = select(root, "/a~1b") else { msg.drop() }
        guard let text = stringValue(field) else { msg.drop() }
        msg.forward("<" + text + ">")
    } else { msg.forward() }
} }
route GET "/flag" { return websocket(backend) { msg in
    if let root = document(identity(msg)) {
        if let field = select(root, "/flag") {
            if let value = flag(identity(field)) {
                guard value == false else { msg.forward("true") }
                msg.forward("false")
            } else { msg.forward("wrong") }
        } else { msg.forward("missing") }
    } else { msg.close(1007) }
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 2u);
    const auto names = owner.p->config.routes[0].ws_frame_handler;
    const auto flags = owner.p->config.routes[1].ws_frame_handler;
    REQUIRE(names);
    REQUIRE(flags);
    for (bool client : {false, true}) {
        for (WsOpcode op : {WsOpcode::Text, WsOpcode::Binary}) {
            const char* strings[] = {
                "{\"a/b\":\"a\\u0000b\"}", "{\"a/b\":\"\"}", "{\"a/b\":false}", "{}", "broken"};
            for (u32 j = 0; j < 5; ++j)
                CHECK(names(nullptr,
                            op,
                            reinterpret_cast<const u8*>(strings[j]),
                            static_cast<u32>(strlen(strings[j])),
                            client) == (!client ? WsFrameAction::Forward
                                        : j < 2 ? WsFrameAction::ForwardTextPolicy0
                                        : j < 4 ? WsFrameAction::Drop
                                                : WsFrameAction::ClosePolicy0));
            const char* values[] = {
                "{\"flag\":false}", "{\"flag\":true}", "{\"flag\":null}", "{}", "broken"};
            const WsFrameAction actions[] = {WsFrameAction::ForwardTextPolicy1,
                                             WsFrameAction::ForwardTextPolicy0,
                                             WsFrameAction::ForwardTextPolicy2,
                                             WsFrameAction::ForwardTextPolicy3,
                                             WsFrameAction::Close};
            for (u32 j = 0; j < 5; ++j)
                CHECK(flags(nullptr,
                            op,
                            reinterpret_cast<const u8*>(values[j]),
                            static_cast<u32>(strlen(values[j])),
                            client) == actions[j]);
        }
    }
    const auto& route = owner.p->config.routes[0];
    CHECK(route.ws_forward_texts[0].source == WsTextSource::JsonString);
}

TEST(native_program, websocket_branch_bindings_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
route GET "/guard" { return websocket(backend) { msg in
    if msg.fromClient {
        guard let document = json.parse(msg.text) else { msg.close(1007) }
        guard let field = json.get(document, "/name") else { msg.close(1008) }
        guard let name = json.string(field) else { msg.close(1003) }
        msg.forward("<" + name + ">")
    } else { msg.forward() }
} }
route GET "/iflet" { return websocket(backend) { msg in
    if let document = json.parse(msg.text) {
        if let field = json.get(document, "/flag") {
            if let value = json.bool(field) {
                guard value == false else { msg.forward("true") }
                msg.forward("false")
            } else { msg.forward("wrong") }
        } else { msg.forward("missing") }
    } else { msg.close(1007) }
} }
route GET "/continuation" { return websocket(backend) { msg in
    if msg.fromClient {
        if let document = json.parse(msg.text) { msg.forward("json") }
        guard msg.isBinary else { msg.drop() }
        msg.forward(b"\x00\xff")
    } else { msg.forward("server") }
} }
route GET "/fallthrough" { return websocket(backend) { msg in
    if msg.fromClient {
        if msg.isText { msg.drop() }
        msg.forward(b"\x00\xff")
    } else { msg.forward("server") }
} }
route GET "/root-iflet" { return websocket(backend) { msg in
    if let document = json.parse(msg.text) {
        if let text = json.string(document) { msg.forward(text) }
        else { msg.drop() }
    }
    msg.forward(b"\xff")
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& program = *owner.p;
    REQUIRE_EQ(program.config.route_count, 5u);
    const auto guarded = program.config.routes[0].ws_frame_handler;
    const auto optional = program.config.routes[1].ws_frame_handler;
    const auto continuation = program.config.routes[2].ws_frame_handler;
    const auto fallthrough = program.config.routes[3].ws_frame_handler;
    const auto root = program.config.routes[4].ws_frame_handler;
    REQUIRE(guarded);
    REQUIRE(optional);
    REQUIRE(continuation);
    REQUIRE(fallthrough);
    REQUIRE(root);
    for (bool client : {false, true}) {
        const char* documents[] = {
            "{\"name\":\"ok\"}", "{\"name\":\"\"}", "{}", "{\"name\":false}", "broken"};
        for (u32 i = 0; i < 5; ++i)
            CHECK(guarded(nullptr,
                          WsOpcode::Text,
                          reinterpret_cast<const u8*>(documents[i]),
                          static_cast<u32>(strlen(documents[i])),
                          client) == (!client  ? WsFrameAction::Forward
                                      : i < 2  ? WsFrameAction::ForwardTextPolicy0
                                      : i == 2 ? WsFrameAction::ClosePolicy1
                                      : i == 3 ? WsFrameAction::ClosePolicy2
                                               : WsFrameAction::ClosePolicy0));
        const char* flags[] = {
            "{\"flag\":false}", "{\"flag\":true}", "{\"flag\":null}", "{}", "broken"};
        for (u32 i = 0; i < 5; ++i)
            CHECK(optional(nullptr,
                           WsOpcode::Text,
                           reinterpret_cast<const u8*>(flags[i]),
                           static_cast<u32>(strlen(flags[i])),
                           client) == (i == 0   ? WsFrameAction::ForwardTextPolicy1
                                       : i == 1 ? WsFrameAction::ForwardTextPolicy0
                                       : i == 2 ? WsFrameAction::ForwardTextPolicy2
                                       : i == 3 ? WsFrameAction::ForwardTextPolicy3
                                                : WsFrameAction::Close));
        const u8 bad[] = {0xff, 0};
        const char* json = "null";
        const char* broken = "broken";
        CHECK(continuation(nullptr, WsOpcode::Binary, bad, 2, client) ==
              (client ? WsFrameAction::ForwardTextPolicy1 : WsFrameAction::ForwardText));
        CHECK(continuation(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(json), 4, client) ==
              (client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
        CHECK(
            continuation(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(broken), 6, client) ==
            (client ? WsFrameAction::Drop : WsFrameAction::ForwardText));
        CHECK(fallthrough(nullptr, WsOpcode::Binary, bad, 2, client) ==
              (client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
        CHECK(
            fallthrough(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(broken), 6, client) ==
            (client ? WsFrameAction::Drop : WsFrameAction::ForwardText));
        const char* strings[] = {"\"\"", "null", "broken"};
        for (u32 i = 0; i < 3; ++i)
            CHECK(root(nullptr,
                       WsOpcode::Text,
                       reinterpret_cast<const u8*>(strings[i]),
                       static_cast<u32>(strlen(strings[i])),
                       client) == (i == 0   ? WsFrameAction::ForwardTextPolicy0
                                   : i == 1 ? WsFrameAction::Drop
                                            : WsFrameAction::ForwardText));
    }
    REQUIRE_EQ(program.config.routes[1].ws_forward_text_count, 4u);
    CHECK_EQ(program.config.routes[1].ws_close_code, 1007u);
}

TEST(native_program, websocket_nested_if_preserves_control_targets_after_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
route GET "/nested" { return websocket(backend) { packet in
    let msg = identity(packet)
    if msg.fromClient {
        let payload: Bytes = msg.payload
        if payload.isEmpty { msg.drop() }
        else {
            if msg.kind == WebSocketMessageKind.binary { msg.forward(b"\xff\x00") }
            else { msg.forward("<" + msg.text + ">") }
        }
    } else {
        let prefix = "["
        if msg.payload.isEmpty { msg.close() }
        else { msg.forward(prefix + msg.text + "]") }
    }
} }
route GET "/early" { return websocket(backend) { msg in
    if msg.fromClient {
        if msg.isBinary { msg.forward(b"\x00\xff") }
        else { msg.drop() }
    }
    guard let document = json.parse(msg.text) else { msg.close(1007) }
    guard let name = json.string(document) else { msg.close(1003) }
    msg.forward(name)
} }
route GET "/json" { return websocket(backend) { msg in
    guard let document = json.parse(msg.text) else { msg.close(1007) }
    if msg.fromClient {
        if json.bool(document) == false { msg.forward("false") }
        else if json.bool(document) == true { msg.forward("true") }
        else { msg.drop() }
    } else { msg.close(1008, "policy") }
} }
route GET "/close" { return websocket(backend) { msg in
    if msg.fromClient {
        if msg.isBinary { msg.close() }
        else { msg.close(1003, "text") }
    } else { msg.close(1008, "policy") }
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& program = *owner.p;
    REQUIRE_EQ(program.config.route_count, 4u);
    const auto nested = program.config.routes[0].ws_frame_handler;
    const auto early = program.config.routes[1].ws_frame_handler;
    const auto json = program.config.routes[2].ws_frame_handler;
    const auto close = program.config.routes[3].ws_frame_handler;
    REQUIRE(nested);
    REQUIRE(early);
    REQUIRE(json);
    REQUIRE(close);
    const u8 bad[] = {0xff, 0};
    const char* text = "hello";
    for (bool client : {false, true}) {
        CHECK(nested(nullptr, WsOpcode::Binary, bad, 2, client) ==
              (client ? WsFrameAction::ForwardTextPolicy0 : WsFrameAction::ForwardText));
        CHECK(nested(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(text), 5, client) ==
              (client ? WsFrameAction::ForwardTextPolicy1 : WsFrameAction::ForwardText));
        CHECK(nested(nullptr, WsOpcode::Binary, nullptr, 0, client) ==
              (client ? WsFrameAction::Drop : WsFrameAction::ClosePolicy0));
        CHECK(close(nullptr, WsOpcode::Binary, nullptr, 0, client) ==
              (client ? WsFrameAction::ClosePolicy0 : WsFrameAction::Close));
        CHECK(close(nullptr, WsOpcode::Text, nullptr, 0, client) ==
              (client ? WsFrameAction::ClosePolicy1 : WsFrameAction::Close));
        const char* values[] = {"false", "true", "null", "{}", "broken"};
        for (u32 i = 0; i < 5; ++i)
            CHECK(json(nullptr,
                       WsOpcode::Text,
                       reinterpret_cast<const u8*>(values[i]),
                       static_cast<u32>(strlen(values[i])),
                       client) == (i == 4    ? WsFrameAction::ClosePolicy0
                                   : !client ? WsFrameAction::Close
                                   : i == 0  ? WsFrameAction::ForwardTextPolicy0
                                   : i == 1  ? WsFrameAction::ForwardTextPolicy1
                                             : WsFrameAction::Drop));
    }
    const char* allowed = "\"allow\"";
    const char* broken = "broken";
    CHECK(early(nullptr, WsOpcode::Binary, bad, 2, true) == WsFrameAction::ForwardTextPolicy0);
    CHECK(early(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(broken), 6, true) ==
          WsFrameAction::Drop);
    CHECK(early(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(allowed), 7, false) ==
          WsFrameAction::ForwardText);
    CHECK(early(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(broken), 6, false) ==
          WsFrameAction::ClosePolicy0);
    REQUIRE_EQ(program.config.routes[3].ws_close_policy_count, 2u);
    CHECK_EQ(program.config.routes[3].ws_close_policies[0].code, 1000u);
    CHECK_EQ(program.config.routes[3].ws_close_policies[1].code, 1003u);
    CHECK_EQ(program.config.routes[3].ws_close_code, 1008u);
}

TEST(native_program, websocket_if_branches_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func allowed(_ bytes: Bytes) -> bool => bytes.count == 2 && bytes == b"\x00\xff"
route GET "/branches" { return websocket(backend) { packet in
    let msg = identity(packet)
    if msg.fromClient && !allowed(msg.payload) { msg.drop() }
    if msg.kind == WebSocketMessageKind.text {
        let copy = msg
        let text = copy.text
        copy.forward("[" + text + "]")
    } else if msg.payload == b"\x00\xff" {
        let copy = msg
        copy.forward(b"\xff\x00")
    } else {
        let copy = msg
        copy.close(1008, "policy")
    }
} }
route GET "/json" { return websocket(backend) { msg in
    guard let document = json.parse(msg.text) else { msg.close(1007) }
    guard let field = json.get(document, "/name") else { msg.close(1008) }
    guard let name = json.string(field) else { msg.close(1003) }
    if msg.fromClient && name == "deny" { msg.drop() }
    else {
        let prefix = "<"
        msg.forward(prefix + name + ">")
    }
} }
route GET "/close" { return websocket(backend) { msg in
    if msg.fromClient { msg.close() }
    else { msg.close(1008, "policy") }
} }
route GET "/optional" { return websocket(backend) { msg in
    guard let document = json.parse(msg.text) else { msg.close(1007) }
    if json.bool(document) == false { msg.forward("false") }
    else if json.bool(document) == true { msg.forward("true") }
    else if json.bool(document) == nil { msg.forward("missing") }
    else { msg.drop() }
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& program = *owner.p;
    REQUIRE_EQ(program.config.route_count, 4u);
    const auto branches = program.config.routes[0].ws_frame_handler;
    const auto json = program.config.routes[1].ws_frame_handler;
    const auto close = program.config.routes[2].ws_frame_handler;
    const auto optional = program.config.routes[3].ws_frame_handler;
    REQUIRE(branches);
    REQUIRE(json);
    REQUIRE(close);
    REQUIRE(optional);
    REQUIRE_EQ(program.config.routes[0].ws_forward_text_count, 2u);
    const Str payloads[] = {{"\0\xff", 2}, {"\xff\0", 2}, {"", 0}, {"ok", 2}};
    for (bool client : {false, true}) {
        for (u32 i = 0; i < 4; ++i) {
            const auto action = branches(nullptr,
                                         WsOpcode::Binary,
                                         reinterpret_cast<const u8*>(payloads[i].ptr),
                                         payloads[i].len,
                                         client);
            CHECK(action == (i == 0   ? WsFrameAction::ForwardTextPolicy1
                             : client ? WsFrameAction::Drop
                                      : WsFrameAction::Close));
        }
        const char* text = "hello";
        CHECK(branches(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(text), 5, client) ==
              (client ? WsFrameAction::Drop : WsFrameAction::ForwardTextPolicy0));
        const char* documents[] = {
            "{\"name\":\"ok\"}", "{\"name\":\"deny\"}", "{}", "{\"name\":false}", "broken"};
        for (u32 i = 0; i < 5; ++i) {
            const auto action = json(nullptr,
                                     WsOpcode::Text,
                                     reinterpret_cast<const u8*>(documents[i]),
                                     static_cast<u32>(strlen(documents[i])),
                                     client);
            CHECK(action == (i == 0 || (i == 1 && !client) ? WsFrameAction::ForwardText
                             : i == 1                      ? WsFrameAction::Drop
                             : i == 2                      ? WsFrameAction::ClosePolicy1
                             : i == 3                      ? WsFrameAction::ClosePolicy2
                                                           : WsFrameAction::ClosePolicy0));
        }
        CHECK(close(nullptr, WsOpcode::Binary, nullptr, 0, client) ==
              (client ? WsFrameAction::ClosePolicy0 : WsFrameAction::Close));
        const char* values[] = {"false", "true", "null", "0", "{}", "[]"};
        for (u32 i = 0; i < 6; ++i)
            CHECK(optional(nullptr,
                           WsOpcode::Text,
                           reinterpret_cast<const u8*>(values[i]),
                           static_cast<u32>(strlen(values[i])),
                           client) == (i == 0   ? WsFrameAction::ForwardTextPolicy0
                                       : i == 1 ? WsFrameAction::ForwardTextPolicy1
                                                : WsFrameAction::ForwardTextPolicy2));
    }
    REQUIRE_EQ(program.config.routes[2].ws_close_policy_count, 1u);
    CHECK_EQ(program.config.routes[2].ws_close_policies[0].code, 1000u);
    CHECK_EQ(program.config.routes[2].ws_close_code, 1008u);
}

TEST(native_program, websocket_callback_scope_survives_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func identity<T>(_ value: T) -> T => value
func same<T: Eq>(_ left: T, _ right: T) -> bool => left == right
func payloadSize(_ bytes: Bytes) -> i32 => bytes.count
route GET "/bytes" {
    let required = 2
    return websocket(backend) { msg in
        let alias: WebSocketMessage = identity(msg)
        let bytes: Bytes = alias.payload
        let marker: Bytes = b"\x00\xff"
        let permitted: bool = payloadSize(bytes) == required && same(bytes, marker)
        let client = alias.direction == WebSocketDirection.clientToUpstream
        guard !client || permitted else { alias.drop() }
        alias.forward()
    }
}
route GET "/json" { return websocket(backend) { event in
    let copy = identity(event)
    let text: str = copy.text
    guard let document = json.parse(text) else { copy.close(1007, "invalid JSON") }
    let client = copy.fromClient
    guard let field = json.get(document, "/name") else { copy.drop() }
    guard let name = json.string(field) else { copy.drop() }
    guard !client || name == "ok" else { copy.drop() }
    copy.forward("[" + text + "]")
} }
)rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 2u);
    const auto binary = owner.p->config.routes[0].ws_frame_handler;
    const auto json = owner.p->config.routes[1].ws_frame_handler;
    REQUIRE(binary);
    REQUIRE(json);
    const Str payloads[] = {{"\0\xff", 2}, {"\xff\0", 2}, {"", 0}};
    for (bool client : {true, false}) {
        for (u32 i = 0; i < 3; ++i)
            CHECK(binary(nullptr,
                         WsOpcode::Binary,
                         reinterpret_cast<const u8*>(payloads[i].ptr),
                         payloads[i].len,
                         client) ==
                  (!client || i == 0 ? WsFrameAction::Forward : WsFrameAction::Drop));
        const char* documents[] = {"{\"name\":\"ok\"}", "{\"name\":\"no\"}", "{}", "broken"};
        for (u32 i = 0; i < 4; ++i)
            CHECK(json(nullptr,
                       WsOpcode::Text,
                       reinterpret_cast<const u8*>(documents[i]),
                       static_cast<u32>(strlen(documents[i])),
                       client) == (i == 3                            ? WsFrameAction::ClosePolicy0
                                   : (i == 0 || (i == 1 && !client)) ? WsFrameAction::ForwardText
                                                                     : WsFrameAction::Drop));
    }
}

TEST(native_program, websocket_payload_bytes_survive_source_removal) {
    Source source;
    REQUIRE(source.append(R"rut(upstream backend at "127.0.0.1:9999"
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
func allowed(_ bytes: Bytes) -> bool =>
    !bytes.isEmpty && bytes.count == 2 && same(bytes, b"\x00\xff")
func choose(_ path: str) -> Bytes {
    if path == "/yes" { b"\x00\xff" } else { b"" }
}
route GET "/http" {
    let bytes = choose(req.path)
    guard allowed(bytes) else { return 403 }
    return 200
}
route POST "/body" {
    guard allowed(req.bodyBytes) else { return 403 }
    return 200
}
route GET "/ws" { return websocket(backend) { message in
    guard allowed(message.payload) else { message.drop() }
    message.forward()
} })rut"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(owner.p->config.route_count, 3u);
    const auto http = owner.p->config.routes[0].fn;
    REQUIRE(http);
    const char* requests[] = {"GET /yes HTTP/1.1\r\nHost: test\r\n\r\n",
                              "GET /no HTTP/1.1\r\nHost: test\r\n\r\n"};
    for (u32 i = 0; i < 2; ++i) {
        const auto result =
            jit::HandlerResult::unpack(http(nullptr,
                                            nullptr,
                                            reinterpret_cast<const u8*>(requests[i]),
                                            static_cast<u32>(strlen(requests[i])),
                                            nullptr));
        CHECK_EQ(result.status_code, i == 0 ? 200u : 403u);
    }
    REQUIRE(owner.p->config.routes[1].needs_req_body);
    const auto body = owner.p->config.routes[1].fn;
    REQUIRE(body);
    const char body_request[] =
        "POST /body HTTP/1.1\r\nHost: test\r\nContent-Length: 2\r\n\r\n\0\xff";
    auto body_result = jit::HandlerResult::unpack(body(nullptr,
                                                       nullptr,
                                                       reinterpret_cast<const u8*>(body_request),
                                                       sizeof(body_request) - 1,
                                                       nullptr));
    CHECK_EQ(body_result.status_code, 200u);
    const auto handler = owner.p->config.routes[2].ws_frame_handler;
    REQUIRE(handler);
    const Str payloads[] = {{"\0\xff", 2}, {"\xff\0", 2}, {"", 0}};
    for (u32 i = 0; i < 3; ++i)
        CHECK(handler(nullptr,
                      WsOpcode::Binary,
                      reinterpret_cast<const u8*>(payloads[i].ptr),
                      payloads[i].len,
                      true) == (i == 0 ? WsFrameAction::Forward : WsFrameAction::Drop));
}

TEST(native_program, websocket_message_type_guards_survive_compiler_exit) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { message in\n"
                      "guard !message.fromClient || (message.isText && message.text == \"ok\") "
                      "else { message.drop() }\nmessage.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto handler = owner.p->config.routes[0].ws_frame_handler;
    REQUIRE(handler != nullptr);
    const bool flags[] = {false, true};
    const WsOpcode opcodes[] = {WsOpcode::Text, WsOpcode::Binary};
    for (bool client : flags) {
        for (WsOpcode op : opcodes) {
            for (bool matches : flags) {
                const auto* payload = reinterpret_cast<const u8*>(matches ? "ok" : "no");
                const bool pass = !client || (op == WsOpcode::Text && matches);
                CHECK(handler(nullptr, op, payload, 2, client) ==
                      (pass ? WsFrameAction::Forward : WsFrameAction::Drop));
            }
        }
    }
}

TEST(native_program, websocket_regex_handler_survives_compiler_exit) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { message in\n"
                      "guard !message.text.matches(re\".*badword.*\") else { message.drop() }\n"
                      "message.forward() } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    WsMessageHandlerFn handler = nullptr;
    for (u32 i = 0; i < owner.p->config.route_count; i++)
        if (owner.p->config.routes[i].ws_terminate)
            handler = owner.p->config.routes[i].ws_frame_handler;
    REQUIRE(handler);
    CHECK(handler(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>("badword"), 7, true) ==
          WsFrameAction::Drop);
    CHECK(handler(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>("good"), 4, true) ==
          WsFrameAction::Forward);
}
#endif

TEST(native_program, forward_policies_and_deferred_preflight_survive_relocation) {
    const char* fixtures[] = {kDeferredPreflightSource, kFramingSelectionPreflightSource};
    for (u32 i = 0; i < 2; i++) {
        Source source;
        REQUIRE(source.append(fixtures[i]));
        Program owner;
        REQUIRE(owner.p);
        REQUIRE(load(source, *owner.p));
        unlink(source.path);
        auto& c = owner.p->config;
        REQUIRE_EQ(c.route_count, 1u);
        CHECK(c.routes[0].forward_preflight_mode ==
              (i == 0 ? ForwardPreflightMode::AfterCanonicalSelection
                      : ForwardPreflightMode::AfterRequestFramingSelection));
        REQUIRE_EQ(c.policy_bundle_count, 1u);
        CHECK_EQ(c.policy_bundles[0].response_read_timeout_seconds, 1u);
        CHECK(c.response_policies[0].server.eq(lit_str("rut")));
        CHECK(c.failure_policies[0].body.eq(lit_str("bad")));
        CHECK(c.failure_policies[1].body.eq(lit_str("slow")));
        auto result = invoke(c.routes[0],
                             i == 0 ? "GET /old HTTP/1.1\r\n\r\n" : "HEAD /one HTTP/1.1\r\n\r\n");
        CHECK(result.action ==
              (i == 0 ? jit::HandlerAction::Redirect : jit::HandlerAction::ForwardBundle));
        if (i == 0) {
            REQUIRE_EQ(c.redirect_policy_count, 1u);
            CHECK(c.redirect_policies[0].target_path.eq(lit_str("/new")));
            CHECK(c.redirect_policies[0].body.eq(lit_str("fixed")));
        }
    }
}

TEST(native_program, exact_response_metadata_and_imported_constants_are_owned) {
    Source imported;
    REQUIRE(imported.append("func tag() -> str => \"/imported\"\n"));
    Source source;
    char text[2048];
    snprintf(
        text,
        sizeof(text),
        "import \"%s\"\n"
        "route GET \"/\" { guard req.path == tag() else { return 403 } return 202 }\n"
        "route exact GET \"/empty\" { return local_response({ version: .http11, "
        "status: 204, reason: \"No Content\", server: \"nginx/1.29.7\", date: .current, "
        "content_type: \"\", connection: .request, head_mode: .suppressBody, body: b\"\" }) }\n",
        imported.path);
    REQUIRE(source.append(text));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    unlink(source.path);
    unlink(imported.path);
    auto& c = owner.p->config;
    REQUIRE_EQ(c.route_count, 1u);
    CHECK_EQ(invoke(c.routes[0], "GET /imported HTTP/1.1\r\n\r\n").status_code, 202u);
    REQUIRE_EQ(c.strict_local_response_policy_count, 1u);
    REQUIRE_EQ(c.exact_strict_local_response_binding_count, 1u);
    CHECK(c.strict_local_response_table_is_valid());
    CHECK(c.strict_local_response_policies[0].reason.eq(lit_str("No Content")));
    CHECK(c.strict_local_response_policies[0].server.eq(lit_str("nginx/1.29.7")));
}

TEST(native_program, serving_loader_does_not_map_llvm) {
#ifdef __linux__
    FILE* maps = fopen("/proc/self/maps", "r");
    REQUIRE(maps);
    char line[8192];
    bool llvm = false;
    while (fgets(line, sizeof(line), maps)) llvm |= strstr(line, "libLLVM") != nullptr;
    fclose(maps);
    CHECK_FALSE(llvm);
#endif
}

TEST(native_program, preserves_sigchld_disposition) {
    Source source;
    REQUIRE(source.append("route GET \"/\" { return 200 }\n"));
    Source bad;
    REQUIRE(bad.append("route GET \"/\" { broken\n"));
    void (*const dispositions[])(int) = {
        SIG_IGN,
#ifdef SA_NOCLDWAIT
        SIG_DFL,
#endif
    };
    for (u32 i = 0; i < sizeof(dispositions) / sizeof(dispositions[0]); i++) {
        SigchldRestore restore;
        REQUIRE(restore.active);
        struct sigaction requested{};
        requested.sa_handler = dispositions[i];
        sigemptyset(&requested.sa_mask);
        sigaddset(&requested.sa_mask, SIGUSR1);
#ifdef SA_NOCLDWAIT
        if (i == 1) requested.sa_flags = SA_NOCLDWAIT;
#endif
        REQUIRE_EQ(sigaction(SIGCHLD, &requested, nullptr), 0);
        struct sigaction baseline{};
        REQUIRE_EQ(sigaction(SIGCHLD, nullptr, &baseline), 0);
        Program owner;
        REQUIRE(owner.p);
        char error[512];
        REQUIRE(load_native_program(source.path, *owner.p, error, sizeof(error)));
        struct sigaction observed{};
        REQUIRE_EQ(sigaction(SIGCHLD, nullptr, &observed), 0);
        CHECK_EQ(observed.sa_handler, baseline.sa_handler);
        CHECK_EQ(observed.sa_flags, baseline.sa_flags);
        CHECK_EQ(sigismember(&observed.sa_mask, SIGUSR1), sigismember(&baseline.sa_mask, SIGUSR1));
        owner.p->destroy();
        CHECK_FALSE(load_native_program(bad.path, *owner.p, error, sizeof(error)));
        REQUIRE_EQ(sigaction(SIGCHLD, nullptr, &observed), 0);
        CHECK_EQ(observed.sa_handler, baseline.sa_handler);
        CHECK_EQ(observed.sa_flags, baseline.sa_flags);
        CHECK_EQ(sigismember(&observed.sa_mask, SIGUSR1), sigismember(&baseline.sa_mask, SIGUSR1));
    }
}
#if RUT_ENABLE_EBPF
TEST(native_program, ebpf_body_plan_survives_compiler_exit_and_is_validated) {
    Source source;
    REQUIRE(source.append(
        "upstream b at \"127.0.0.1:9999\"\n"
        "route GET \"/plain\" { return forward(b, load_balance: .roundRobin) }\n"
        "route GET \"/headers\" { return forward(b, load_balance: .roundRobin, request_policy: { "
        "version: .http11, "
        "host: .upstream, connection: .omit, strip_headers: [.connection, .keepAlive, .te, "
        ".expect, .upgrade] }) }\n"
        "route GET \"/static\" { return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    char error[512];
    REQUIRE(load_native_program(source.path, *owner.p, error, sizeof(error), 2, true));
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE(owner.p->has_ebpf_plan);
    auto& plan = owner.p->ebpf_plan;
    CHECK_EQ(plan.route_count, 3u);
    CHECK_EQ(plan.candidate_count, 2u);
    CHECK_EQ(plan.routes[0].decision, ebpf::Decision::BodyCandidate);
    CHECK_EQ(plan.routes[1].request_policy_id, 1u);
    CHECK_EQ(plan.routes[2].reason, ebpf::Reason::NotForward);
    CHECK(validate_ebpf_plan(plan, owner.p->config));
    owner.p->config.upstreams[0].http2 = true;
    CHECK_FALSE(validate_ebpf_plan(plan, owner.p->config));
    owner.p->config.upstreams[0].http2 = false;
    CHECK(validate_ebpf_plan(plan, owner.p->config));
    // Relocation placeholders must remain zero until an actual kernel load.
    plan.bytecode.verdict[ebpf::kSocketMapRelocation].immediate = 99;
    CHECK_FALSE(validate_ebpf_plan(plan, owner.p->config));
    plan.bytecode.verdict[ebpf::kSocketMapRelocation].immediate = 0;
    plan.handoff.verdict[plan.handoff.verdict_ring_map].immediate = 99;
    CHECK_FALSE(validate_ebpf_plan(plan, owner.p->config));
    plan.handoff.verdict[plan.handoff.verdict_ring_map].immediate = 0;
    plan.routes[0].upstream_id = 99;
    CHECK_FALSE(validate_ebpf_plan(plan, owner.p->config));
    plan.routes[0].upstream_id = 0;
    plan.routes[0].request_policy_id = 99;
    CHECK_FALSE(validate_ebpf_plan(plan, owner.p->config));
    plan.routes[0].request_policy_id = 0;
    plan.candidate_count = 0;
    CHECK_FALSE(validate_ebpf_plan(plan, owner.p->config));
    owner.p->destroy();
    CHECK_FALSE(owner.p->has_ebpf_plan);
    CHECK_EQ(owner.p->ebpf_plan.route_count, 0u);
}
#endif

TEST(native_program, constant_time_equal_is_available_after_compiler_exit) {
    const u8 levels[] = {0, 3};
    for (u8 opt : levels) {
        Source source;
        REQUIRE(source.append(
            "route GET \"/\" { guard let value = req.header(\"X-Key\") else { return 401 } "
            "guard constantTimeEqual(value, \"native-secret\") else { return 403 } return 200 "
            "}\n"));
        Program owner;
        REQUIRE(owner.p);
        REQUIRE(load(source, *owner.p, opt));
        REQUIRE_EQ(unlink(source.path), 0);
        REQUIRE_EQ(owner.p->config.route_count, 1u);
        const auto& route = owner.p->config.routes[0];
        CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\nX-Key: native-secret\r\n\r\n").status_code, 200);
        CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\nX-Key: Native-secret\r\n\r\n").status_code, 403);
        CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\nX-Key: native-secreT\r\n\r\n").status_code, 403);
        CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\nX-Key: native-secret-long\r\n\r\n").status_code,
                 403);
        CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\n\r\n").status_code, 401);
    }
}

TEST(native_program, uuid_is_available_after_compiler_exit_with_request_arena) {
    Source source;
    REQUIRE(source.append(
        "route GET \"/\" { let pending = uuid() guard let id = pending else { return 503 } "
        "guard id == id else { return 500 } return 200 }\n"
        "route GET \"/two\" { let first = uuid() let second = uuid() guard let a = first else { "
        "return 503 } "
        "guard let b = second else { return 503 } "
        "guard a == a && b == b else { return 500 } return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p, 3));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\n\r\n").status_code, 503u);
    SlicePool pool;
    REQUIRE(pool.init(2));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    jit::HandlerCtx ctx{};
    const char req[] = "GET / HTTP/1.1\r\n\r\n";
    auto result = jit::HandlerResult::unpack(
        route.fn(nullptr, &ctx, reinterpret_cast<const u8*>(req), sizeof(req) - 1, &arena));
    CHECK_EQ(result.status_code, 200u);
    CHECK_EQ(arena.space_used(), 40u);
    REQUIRE_EQ(owner.p->config.route_count, 2u);
    result = jit::HandlerResult::unpack(owner.p->config.routes[1].fn(
        nullptr, &ctx, reinterpret_cast<const u8*>(req), sizeof(req) - 1, &arena));
    CHECK_EQ(result.status_code, 200u);
    CHECK_EQ(arena.space_used(), 120u);
    arena.destroy();
    pool.destroy();
}

TEST(native_program, hmac_uses_c_crypto_after_compiler_exit) {
    Source source;
    REQUIRE(
        source.append("import Crypto\n"
                      "route GET \"/\" { "
                      "guard Crypto.hmacSha256Valid(\"abc\", \"key\", "
                      "req.uniqueHeader(\"X-Signature\").or(\"\"), "
                      "\"sha256=\") else { return 401 } return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    CHECK_EQ(
        invoke(route,
               "GET / HTTP/1.1\r\nX-Signature: "
               "sha256=9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab\r\n\r\n")
            .status_code,
        200u);
    CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\nX-Signature: sha256=wrong\r\n\r\n").status_code,
             401u);
}

TEST(native_program, digest_uses_c_crypto_after_compiler_exit) {
    Source source;
    REQUIRE(source.append(
        "import Crypto\n"
        "route GET \"/\" { guard let digest = Crypto.digestSha256(\"abc\") else { return 503 } "
        "guard digest == \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" "
        "else { return 500 } return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p, 3));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    CHECK_EQ(invoke(route, "GET / HTTP/1.1\r\n\r\n").status_code, 503u);
    SlicePool pool;
    REQUIRE(pool.init(24));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    jit::HandlerCtx ctx{};
    const char req[] = "GET / HTTP/1.1\r\n\r\n";
    const auto result = jit::HandlerResult::unpack(
        route.fn(nullptr, &ctx, reinterpret_cast<const u8*>(req), sizeof(req) - 1, &arena));
    CHECK_EQ(result.status_code, 200u);
    CHECK(arena.space_used() >= 64u);
    arena.destroy();
    REQUIRE(arena.init(&pool));
    char* preserved = nullptr;
    for (u32 i = 0; i < 16; ++i) {
        auto* bytes = static_cast<char*>(arena.alloc(16000));
        REQUIRE(bytes);
        if (i == 0) {
            preserved = bytes;
            preserved[0] = 'x';
        }
    }
    REQUIRE(arena.alloc(6104));
    const auto exhausted = jit::HandlerResult::unpack(
        route.fn(nullptr, &ctx, reinterpret_cast<const u8*>(req), sizeof(req) - 1, &arena));
    CHECK_EQ(exhausted.status_code, 503u);
    CHECK_EQ(preserved[0], 'x');
    arena.destroy();
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(native_program, forward_load_balance_survives_relocation_without_live_gauges) {
    Source source;
    REQUIRE(source.append(
        "upstream api at \"127.0.0.1:9001\"\n"
        "route GET \"/rr\" { return forward(api, load_balance: .roundRobin) }\n"
        "route GET \"/least\" { return forward(api, load_balance: .leastRequests) }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    ConnectionBase conn;
    conn.reset();
    jit::HandlerCtx ctx{};
    auto& cfg = owner.p->config;
    REQUIRE_EQ(cfg.route_count, 2u);
    for (u32 i = 0; i < 2; ++i) {
        const auto result =
            jit::HandlerResult::unpack(cfg.routes[i].fn(&conn, &ctx, nullptr, 0, nullptr));
        CHECK_EQ(result.action, jit::HandlerAction::Forward);
        CHECK_EQ(conn.forward_load_balance.site, i + 1);
        CHECK_EQ(conn.forward_load_balance.policy,
                 i == 0 ? LoadBalancePolicy::RoundRobin : LoadBalancePolicy::LeastRequests);
        CHECK_EQ(cfg.backend_selection[0].active[0][0], 0u);
        CHECK_EQ(cfg.backend_selection[0].cursor[i], 0u);
    }
}

TEST(native_program, rs256_policy_survives_compiler_exit_source_removal_and_shard_activation) {
    test::Rs256Fixture fixture;
    REQUIRE(fixture.init());
    char source_bytes[8192];
    json::Writer source_text{source_bytes, sizeof(source_bytes) - 1};
    source_text.text(lit_str(R"rut(import Crypto
route GET "/" {
    guard let claims = Crypto.jwtRs256(bearerToken(req.authorization.or("")).or(""), )rut"));
    REQUIRE(json::quote(fixture.policy, source_text));
    source_text.text(lit_str(R"rut() else { return 401 }
    guard jwtHasScope(claims, "read") else { return 403 }
    guard jwtHasGroup(claims, "read") else { return 403 }
    return 200
}
)rut"));
    char revoked_bytes[8192];
    json::Writer revoked{revoked_bytes};
    revoked.text({fixture.policy.ptr, fixture.policy.len - 1});
    revoked.text(lit_str(R"(,"revokedJtis":["revoked"],"issuedAfter":50})"));
    REQUIRE(revoked.ok);
    source_text.text(lit_str(R"rut(route GET "/revocation" {
    guard let claims = Crypto.jwtRs256(bearerToken(req.authorization.or("")).or(""), )rut"));
    REQUIRE(json::quote({revoked_bytes, revoked.len}, source_text));
    source_text.text(lit_str(R"rut() else { return 401 }
    return 200
}
)rut"));
    char typed_bytes[8192];
    json::Writer typed{typed_bytes};
    typed.text({fixture.policy.ptr, fixture.policy.len - 1});
    typed.text(lit_str(R"(,"requiredType":"at+jwt"})"));
    REQUIRE(typed.ok);
    source_text.text(lit_str(R"rut(route GET "/typed" {
    guard let claims = Crypto.jwtRs256(bearerToken(req.authorization.or("")).or(""), )rut"));
    REQUIRE(json::quote({typed_bytes, typed.len}, source_text));
    source_text.text(lit_str(R"rut() else { return 401 }
    return 200
}
)rut"));
    REQUIRE(source_text.ok);
    source_bytes[source_text.len] = '\0';
    Source source;
    REQUIRE(source.append(source_bytes));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& config = owner.p->config;
    REQUIRE_EQ(config.rs256_configuration_count, 3u);
    REQUIRE(config.rs256);
    auto* connection = owner.arena.alloc_t<ConnectionBase>();
    REQUIRE(connection);
    connection->request_config = &config;
    connection->shard_id = 2;
    SlicePool pool;
    REQUIRE(pool.init(32));
    connection->json_arena.backend.pool = &pool;
    char token[4096];
    const auto member_claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read write","groups":["read","admin"]})");
    Str signed_token = fixture.sign(test::Rs256Fixture::header, member_claims, token);
    REQUIRE(signed_token.len);
    auto run = [&](u32 route = 0) {
        char request[8192];
        const int count =
            snprintf(request,
                     sizeof(request),
                     "GET / HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer %.*s\r\n\r\n",
                     signed_token.len,
                     signed_token.ptr);
        jit::HandlerCtx context{};
        connection->json_arena.reset();
        const auto result =
            jit::HandlerResult::unpack(config.routes[route].fn(connection,
                                                               &context,
                                                               reinterpret_cast<const u8*>(request),
                                                               static_cast<u32>(count),
                                                               nullptr));
        return result.status_code;
    };
    CHECK_EQ(run(), 401u);
    REQUIRE(config.activate_rs256(2));
    CHECK_EQ(run(), 200u);
    token[signed_token.len - 4] = token[signed_token.len - 4] == 'a' ? 'b' : 'a';
    CHECK_EQ(run(), 401u);
    signed_token = fixture.sign(test::Rs256Fixture::header, member_claims, token);
    CHECK_EQ(run(), 200u);
    const auto nonmember_claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read write","groups":["admin"]})");
    signed_token = fixture.sign(test::Rs256Fixture::header, nonmember_claims, token);
    CHECK_EQ(run(), 403u);
    const Str extras[] = {
        lit_str(R"(,"jti":"live","iat":51)"),
        lit_str(R"(,"jti":"revoked","iat":51)"),
        lit_str(R"(,"jti":"live","iat":50)"),
        lit_str(R"(,"jti":"live")"),
        lit_str(R"(,"iat":51)"),
    };
    for (u32 i = 0; i < sizeof(extras) / sizeof(extras[0]); ++i) {
        char claims_bytes[1024];
        json::Writer claims{claims_bytes, sizeof(claims_bytes)};
        claims.text({member_claims.ptr, member_claims.len - 1});
        claims.text(extras[i]);
        claims.put('}');
        REQUIRE(claims.ok);
        signed_token = fixture.sign(test::Rs256Fixture::header, {claims_bytes, claims.len}, token);
        REQUIRE(signed_token.len);
        CHECK_EQ(run(), 200u);  // The original policy has no revocation requirements.
        CHECK_EQ(run(1), i == 0 ? 200u : 401u);
    }
    const Str types[] = {
        test::Rs256Fixture::header,
        lit_str(R"({"alg":"RS256","kid":"current","typ":"JWT"})"),
        lit_str(R"({"alg":"RS256","kid":"current","typ":"at+jwt"})"),
        lit_str(R"({"alg":"RS256","kid":"current","t\u0079p":"at\u002bjwt"})"),
    };
    for (u32 i = 0; i < 4; ++i) {
        signed_token = fixture.sign(types[i], member_claims, token);
        REQUIRE(signed_token.len);
        CHECK_EQ(run(), 200u);
        CHECK_EQ(run(2), i >= 2 ? 200u : 401u);
    }
    connection->json_arena.destroy();
    pool.destroy();
}

TEST(native_program, websocket_guard_text_policies_survive_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { message in\n"
                      " guard message.text != \"a\" else { message.forward(\"one\\0\\u{20ac}\") }\n"
                      " guard message.text != \"b\" else { message.forward(\"\") }\n"
                      " guard message.text != \"c\" else { message.forward(\"third\") }\n"
                      " guard message.text != \"d\" else { message.forward(\"fourth\") }\n"
                      " message.forward(\"default\") } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];

    REQUIRE_EQ(route.ws_forward_text_count, 4u);
    const Str texts[] = {{"one\0\xe2\x82\xac", 7}, {}, {"third", 5}, {"fourth", 6}, {"default", 7}};
    for (u32 i = 0; i < 5; i++) {
        WsInspector st;
        st.forward_text = route.ws_forward_text;
        st.forward_texts = route.ws_forward_texts;
        st.forward_text_count = route.ws_forward_text_count;
        st.max_message_size = route.ws_max_message_size;
        const u8 input[] = {0x82, 1, static_cast<u8>('a' + i)};
        u8 out[128], msg[32];
        u32 used = 0, produced = 0;
        REQUIRE(ws_inspect(st,
                           input,
                           sizeof(input),
                           out,
                           sizeof(out),
                           msg,
                           sizeof(msg),
                           route.ws_frame_handler,
                           nullptr,
                           &used,
                           &produced) == WsInspectStatus::Ok);
        CHECK_EQ(used, sizeof(input));
        REQUIRE_EQ(produced, 2u + texts[i].len);
        CHECK_EQ(out[0], 0x81u);
        if (texts[i].len) CHECK(memcmp(out + 2, texts[i].ptr, texts[i].len) == 0);
    }
}

TEST(native_program, es256_policy_survives_compiler_exit_source_removal_and_shard_activation) {
    test::Es256Fixture fixture;
    REQUIRE(fixture.init());
    char source_bytes[8192];
    json::Writer source_text{source_bytes, sizeof(source_bytes) - 1};
    source_text.text(lit_str(R"rut(import Crypto
route GET "/" {
    guard let claims = Crypto.jwtEs256(bearerToken(req.authorization.or("")).or(""), )rut"));
    REQUIRE(json::quote(fixture.policy, source_text));
    source_text.text(lit_str(R"rut() else { return 401 }
    guard jwtHasScope(claims, "read") else { return 403 }
    guard jwtHasGroup(claims, "read") else { return 403 }
    return 200
}
)rut"));
    char revoked_bytes[8192];
    json::Writer revoked{revoked_bytes};
    revoked.text({fixture.policy.ptr, fixture.policy.len - 1});
    revoked.text(lit_str(R"(,"revokedJtis":["revoked"],"issuedAfter":50})"));
    REQUIRE(revoked.ok);
    source_text.text(lit_str(R"rut(route GET "/revocation" {
    guard let claims = Crypto.jwtEs256(bearerToken(req.authorization.or("")).or(""), )rut"));
    REQUIRE(json::quote({revoked_bytes, revoked.len}, source_text));
    source_text.text(lit_str(R"rut() else { return 401 }
    return 200
}
)rut"));
    REQUIRE(source_text.ok);
    source_bytes[source_text.len] = '\0';
    Source source;
    REQUIRE(source.append(source_bytes));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    auto& config = owner.p->config;
    REQUIRE_EQ(config.es256_configuration_count, 2u);
    REQUIRE(config.es256);
    auto* connection = owner.arena.alloc_t<ConnectionBase>();
    REQUIRE(connection);
    connection->request_config = &config;
    connection->shard_id = 2;
    SlicePool pool;
    REQUIRE(pool.init(32));
    connection->json_arena.backend.pool = &pool;
    char token[4096];
    const auto member_claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read write","groups":["read","admin"]})");
    Str signed_token = fixture.sign(test::Es256Fixture::header, member_claims, token);
    REQUIRE(signed_token.len);
    auto run = [&](u32 route = 0) {
        char request[8192];
        const int count =
            snprintf(request,
                     sizeof(request),
                     "GET / HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer %.*s\r\n\r\n",
                     signed_token.len,
                     signed_token.ptr);
        jit::HandlerCtx context{};
        connection->json_arena.reset();
        const auto result =
            jit::HandlerResult::unpack(config.routes[route].fn(connection,
                                                               &context,
                                                               reinterpret_cast<const u8*>(request),
                                                               static_cast<u32>(count),
                                                               nullptr));
        return result.status_code;
    };
    CHECK_EQ(run(), 401u);
    REQUIRE(config.activate_es256(2));
    CHECK_EQ(run(), 200u);
    token[signed_token.len - 4] = token[signed_token.len - 4] == 'a' ? 'b' : 'a';
    CHECK_EQ(run(), 401u);
    signed_token = fixture.sign(test::Es256Fixture::header, member_claims, token);
    CHECK_EQ(run(), 200u);
    const auto nonmember_claims = lit_str(
        R"({"sub":"alice","iss":"issuer","aud":"gateway","exp":4102444800,"scope":"read write","groups":["admin"]})");
    signed_token = fixture.sign(test::Es256Fixture::header, nonmember_claims, token);
    CHECK_EQ(run(), 403u);
    const Str extras[] = {
        lit_str(R"(,"jti":"live","iat":51)"),
        lit_str(R"(,"jti":"revoked","iat":51)"),
        lit_str(R"(,"jti":"live","iat":50)"),
        lit_str(R"(,"jti":"live")"),
        lit_str(R"(,"iat":51)"),
    };
    for (u32 i = 0; i < sizeof(extras) / sizeof(extras[0]); ++i) {
        char claims_bytes[1024];
        json::Writer claims{claims_bytes, sizeof(claims_bytes)};
        claims.text({member_claims.ptr, member_claims.len - 1});
        claims.text(extras[i]);
        claims.put('}');
        REQUIRE(claims.ok);
        signed_token = fixture.sign(test::Es256Fixture::header, {claims_bytes, claims.len}, token);
        REQUIRE(signed_token.len);
        CHECK_EQ(run(), 200u);  // The original policy has no revocation requirements.
        CHECK_EQ(run(1), i == 0 ? 200u : 401u);
    }
    connection->json_arena.destroy();
    pool.destroy();
}
