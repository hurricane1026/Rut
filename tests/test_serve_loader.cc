// Tests for the .rut program loader (src/serve_loader.cc): the bridge that
// compiles a source file end to end (lex -> parse -> analyze -> MIR -> RIR ->
// JIT) into a RouteConfig, plus its fail-closed error reporting.

#include "deferred_preflight_fixture.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/listener.h"
#include "rut/runtime/route_method.h"
#include "rut/serve_loader.h"
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"  // WsMessageHandlerFn / WsFrameAction / WsOpcode
#endif
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <sys/mman.h>

using namespace rut;

namespace {

// Write `contents` to a fresh file under a unique per-test directory and
// return its path. The directory is created if needed.
std::string write_file(const std::string& dir, const char* name, const char* contents) {
    std::filesystem::create_directories(dir);
    const std::string path = dir + "/" + name;
    std::ofstream out(path, std::ios::binary);
    out << contents;
    out.close();
    return path;
}

bool contains(const char* haystack, const char* needle) {
    return std::string(haystack).find(needle) != std::string::npos;
}

std::string make_eighty_route_source() {
    std::string source;
    source.reserve(80u * 40u);
    for (u32 i = 0; i < 80; i++) {
        source += "route ";
        source += (i % 2u == 0u) ? "GET" : "POST";
        source += " \"/capacity/";
        source += std::to_string(i);
        source += "\" { return ";
        source += (i % 2u == 0u) ? "200" : "201";
        source += " }\n";
    }
    return source;
}

std::string make_653_slot_route_source() {
    std::string source = "listen :0\n";
    source.reserve(4u * 1024u);
    for (u32 i = 0; i < 91; i++) {
        source += "route ";
        source += (i % 2u == 0u) ? "GET" : "POST";
        source += " \"/capacity/";
        source += std::to_string(i);
        source += "\" { return ";
        source += (i % 2u == 0u) ? "200" : "201";
        source += " }\n";
    }
    for (u32 i = 91; i < 93; i++) {
        source += "route \"/capacity/";
        source += std::to_string(i);
        source += "\" { return 202 }\n";
    }
    return source;
}

}  // namespace

static StrictLocalResponsePolicySpec synthetic_no_content_policy(Str content_type = {},
                                                                 Str body = {}) {
    StrictLocalResponsePolicySpec policy{};
    policy.version = StrictLocalResponseVersion::Http11;
    policy.status_code = 204;
    policy.date = StrictLocalResponseDate::Current;
    policy.connection = StrictLocalResponseConnection::Request;
    policy.head_mode = StrictLocalResponseHeadMode::SuppressBody;
    policy.reason = {"No Content", 10};
    policy.content_type = content_type;
    policy.server = {"nginx/1.29.7", 12};
    policy.body = body;
    return policy;
}

static u64 sentinel_timer_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return jit::HandlerResult::make_status(200).pack();
}

TEST(serve_loader, status_routes_load) {
    const std::string dir = "/tmp/rut_serve_loader_status";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "route GET \"/\" { return 200 }\n"
                                        "route GET \"/health\" { return 204 }\n");

    LoadedProgram program;
    program.has_listener = true;
    program.listener = {ListenerAddress::IPv4Exact, ListenerTransport::Tls, 8443u, 0x7f000001u};
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(!program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    // Both routes registered into the config the shards will serve.
    CHECK_EQ(program.config.route_count, 2u);
    program.destroy();
}

TEST(serve_loader, public_no_content_strict_source_and_default_activation_are_owned) {
    static constexpr char kSource[] = R"rut(
pre_route TRACE { return local_response({
  version: "HTTP/1.1", status: 204, reason: "No Content", server: "pre",
  date: "current", content_type: "", connection: "request",
  head_mode: "suppress_body", body: b""
}) }
route exact GET "/static" { return local_response({
  version: "HTTP/1.1", status: 204, reason: "No Content", server: "nginx/1.29.7",
  date: "current", content_type: "", connection: "request",
  head_mode: "suppress_body", body: b""
}) }
unmatched POST { return local_response({
  version: "HTTP/1.1", status: 204, reason: "No Content", server: "unmatched",
  date: "current", content_type: "", connection: "request",
  head_mode: "suppress_body", body: b""
}) }
)rut";
    const std::string path =
        write_file("/tmp/rut_serve_loader_public_no_content", "app.rut", kSource);
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE(rir::verify_module(program.rir.module).ok);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    REQUIRE_EQ(program.rir.module.strict_local_response_policy_count, 3u);
    REQUIRE_EQ(program.config.strict_local_response_policy_count, 3u);
    CHECK_EQ(program.config.pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK_EQ(program.config.unmatched_policy_ids[kRouteMethodPost], 3u);
    CHECK(program.config.has_exact_strict_local_response_inventory());
    CHECK_EQ(program.config.match_exact_strict_local_response({"/static", 7}, kRouteMethodGet), 2u);
    for (u32 i = 0; i < 3; i++) {
        const auto& loaded = program.config.strict_local_response_policies[i];
        CHECK_EQ(strict_local_response_policy_profile(loaded),
                 StrictLocalResponseProfile::NoContent204);
        CHECK(loaded.content_type.ptr != nullptr);
        CHECK(loaded.body.ptr != nullptr);
        CHECK_EQ(loaded.content_type.len, 0u);
        CHECK_EQ(loaded.body.len, 0u);
        CHECK(program.config.strict_local_response_bytes_owned(loaded.content_type));
        CHECK(program.config.strict_local_response_bytes_owned(loaded.body));
    }
    program.rir.destroy();
    REQUIRE(program.config.strict_local_response_table_is_valid());
    CHECK(program.config.strict_local_response_policies[0].server.eq({"pre", 3}));
    CHECK(program.config.strict_local_response_policies[1].server.eq({"nginx/1.29.7", 12}));
    CHECK(program.config.strict_local_response_policies[2].server.eq({"unmatched", 9}));
    for (u32 i = 0; i < 3; i++) {
        CHECK(program.config.strict_local_response_bytes_owned(
            program.config.strict_local_response_policies[i].content_type));
        CHECK(program.config.strict_local_response_bytes_owned(
            program.config.strict_local_response_policies[i].body));
    }
    program.destroy();
    std::filesystem::remove(path);

    rir::Module mod{};
    mod.strict_local_response_policies[0] = synthetic_no_content_policy();
    mod.strict_local_response_policy_count = 1;
    mod.unmatched_policy_ids[kRouteMethodAny] = 1;
    REQUIRE(rir::verify_module_for_internal_propagation(mod).ok);
    REQUIRE(rir::verify_module(mod).ok);

    auto public_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*public_cfg, mod));
    REQUIRE(public_cfg->strict_local_response_table_is_valid());
    REQUIRE_EQ(public_cfg->strict_local_response_policy_count, 1u);
    CHECK(public_cfg->strict_local_response_policies[0].content_type.ptr != nullptr);
    CHECK(public_cfg->strict_local_response_policies[0].body.ptr != nullptr);

    auto internal_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config_for_internal_propagation(*internal_cfg, mod));
    REQUIRE(internal_cfg->strict_local_response_table_is_valid());
    REQUIRE_EQ(internal_cfg->strict_local_response_policy_count, 1u);
    const auto& owned = internal_cfg->strict_local_response_policies[0];
    CHECK_EQ(strict_local_response_policy_profile(owned), StrictLocalResponseProfile::NoContent204);
    CHECK(owned.content_type.ptr != nullptr);
    CHECK(owned.body.ptr != nullptr);
    CHECK_EQ(owned.content_type.len, 0u);
    CHECK_EQ(owned.body.len, 0u);
    CHECK_EQ(internal_cfg->strict_local_response_bytes_used, 22u);

    jit::JitEngine engine;
    REQUIRE(register_jit_routes(*public_cfg, mod, engine));
    REQUIRE(register_jit_routes(*internal_cfg, mod, engine));
    REQUIRE(register_jit_routes_for_internal_propagation(*internal_cfg, mod, engine));
    CHECK_EQ(internal_cfg->route_count, 0u);
    CHECK_EQ(internal_cfg->timer_count, 0u);
    REQUIRE(internal_cfg->strict_local_response_table_is_valid());

    auto mismatched = mod;
    mismatched.strict_local_response_policies[0].server = {"rut", 3};
    REQUIRE(rir::verify_module_for_internal_propagation(mismatched).ok);
    auto mismatch_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config_for_internal_propagation(*mismatch_cfg, mod));
    std::vector<u8> mismatch_before(sizeof(RouteConfig));
    __builtin_memcpy(mismatch_before.data(), mismatch_cfg.get(), sizeof(RouteConfig));
    CHECK_FALSE(register_jit_routes_for_internal_propagation(*mismatch_cfg, mismatched, engine));
    CHECK_EQ(__builtin_memcmp(mismatch_before.data(), mismatch_cfg.get(), sizeof(RouteConfig)), 0);

    auto forged = mod;
    forged.strict_local_response_policies[0].body = {nullptr, 1};
    auto rejected = std::make_unique<RouteConfig>();
    REQUIRE(rejected->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> rejected_before(sizeof(RouteConfig));
    __builtin_memcpy(rejected_before.data(), rejected.get(), sizeof(RouteConfig));
    CHECK_FALSE(populate_route_config_for_internal_propagation(*rejected, forged));
    CHECK_EQ(__builtin_memcmp(rejected_before.data(), rejected.get(), sizeof(RouteConfig)), 0);
}

TEST(serve_loader, public_no_content_source_rejections_leave_runtime_config_unmodified) {
    const std::string base =
        "route exact GET \"/static\" { return local_response({ version: \"HTTP/1.1\", "
        "status: 204, reason: \"No Content\", server: \"nginx/1.29.7\", date: \"current\", "
        "content_type: \"\", connection: \"request\", head_mode: \"suppress_body\", "
        "body: b\"\" }) }";
    auto replace_once = [&](std::string value, const std::string& from, const std::string& to) {
        const auto pos = value.find(from);
        CHECK(pos != std::string::npos);
        if (pos == std::string::npos) return std::string{};
        value.replace(pos, from.size(), to);
        return value;
    };
    struct Rejection {
        std::string source;
        FrontendError code;
    };
    std::vector<Rejection> rejected;
    for (const char* status : {"199", "201", "205", "206", "304", "100"})
        rejected.push_back({replace_once(base, "status: 204", std::string("status: ") + status),
                            FrontendError::InvalidStatusCode});
    const std::string mutations[] = {
        replace_once(base, "reason: \"No Content\"", "reason: \"Not Content\""),
        replace_once(base, "reason: \"No Content\", ", ""),
        replace_once(base, "server: \"nginx/1.29.7\"", "server: \"\""),
        replace_once(base, "HTTP/1.1", "HTTP/1.0"),
        replace_once(base, "date: \"current\"", "date: \"static\""),
        replace_once(base, "content_type: \"\"", "content_type: \"text/plain\""),
        replace_once(base, "connection: \"request\"", "connection: \"close\""),
        replace_once(base, "head_mode: \"suppress_body\"", "head_mode: \"reject\""),
        replace_once(base, "body: b\"\"", "body: b\"x\""),
    };
    for (const auto& mutation : mutations)
        rejected.push_back({mutation, FrontendError::UnsupportedSyntax});

    const std::string dir = "/tmp/rut_serve_loader_public_no_content_rejections";
    for (const auto& test : rejected) {
        const std::string path = write_file(dir, "app.rut", test.source.c_str());
        LoadedProgram program;
        LoadError err;
        CHECK_FALSE(load_rut_program(path.c_str(), program, err));
        CHECK_EQ(err.stage, LoadStage::Parse);
        CHECK(err.has_diag);
        CHECK_EQ(err.diag.code, test.code);
        CHECK_GT(err.diag.span.end, err.diag.span.start);
        CHECK_EQ(program.config.route_count, 0u);
        CHECK_EQ(program.config.strict_local_response_policy_count, 0u);
        CHECK_FALSE(program.config.has_strict_local_response_table_inventory());
        program.destroy();
    }
    std::filesystem::remove(dir + "/app.rut");
}

TEST(serve_loader, public_and_internal_no_content_population_roll_back_late_pool_failure) {
    std::string first_body(RouteConfig::kResponseBodyPoolBytes / 2 + 1, 'a');
    std::string second_body(RouteConfig::kResponseBodyPoolBytes / 2 + 1, 'b');
    rir::Module mod{};
    mod.strict_local_response_policies[0] = synthetic_no_content_policy();
    mod.strict_local_response_policy_count = 1;
    mod.unmatched_policy_ids[kRouteMethodAny] = 1;
    mod.response_bodies[0] = {first_body.data(), static_cast<u32>(first_body.size())};
    mod.response_bodies[1] = {second_body.data(), static_cast<u32>(second_body.size())};
    mod.response_body_count = 2;
    mod.upstreams[0].name = {"sentinel", 8};
    mod.upstream_count = 1;
    REQUIRE(rir::verify_module_for_internal_propagation(mod).ok);
    REQUIRE(rir::verify_module(mod).ok);

    auto rejects_atomically = [&](bool internal_propagation) {
        auto destination = std::make_unique<RouteConfig>();
        REQUIRE(destination->add_upstream("sentinel", 0x7f000001u, 9000).has_value());
        REQUIRE(destination->add_timer("kept", 4, 1000, sentinel_timer_handler));
        destination->firewall_default_allow = false;
        destination->firewall_allow_ips[0] = 0x01020304u;
        destination->firewall_allow_count = 1;
        destination->body_pool[RouteConfig::kResponseBodyPoolBytes - 1] = 'z';
        destination->response_bodies[RouteConfig::kMaxResponseBodies - 1] = {
            destination->body_pool + RouteConfig::kResponseBodyPoolBytes - 1, 1};
        destination
            ->strict_local_response_bytes[RouteConfig::kStrictLocalResponseBytesPoolBytes - 1] =
            'q';

        std::vector<u8> before(sizeof(RouteConfig));
        __builtin_memcpy(before.data(), destination.get(), sizeof(RouteConfig));
        const bool populated =
            internal_propagation ? populate_route_config_for_internal_propagation(*destination, mod)
                                 : populate_route_config(*destination, mod);
        CHECK_FALSE(populated);
        CHECK_EQ(__builtin_memcmp(before.data(), destination.get(), sizeof(RouteConfig)), 0);
        CHECK_EQ(destination->upstream_count, 1u);
        CHECK_EQ(destination->route_count, 0u);
        CHECK_EQ(destination->timer_count, 1u);
        CHECK_EQ(destination->response_body_count, 0u);
        CHECK_EQ(destination->body_pool_used, 0u);
        CHECK_EQ(destination->response_policy_count, 0u);
        CHECK_EQ(destination->failure_policy_count, 0u);
        CHECK_EQ(destination->policy_bundle_count, 0u);
        CHECK_EQ(destination->strict_local_response_policy_count, 0u);
        CHECK_EQ(destination->strict_local_response_bytes_used, 0u);
        CHECK_EQ(destination->exact_strict_local_response_binding_count, 0u);
        CHECK_EQ(destination->firewall_allow_count, 1u);
        CHECK_FALSE(destination->firewall_default_allow);
    };
    rejects_atomically(false);
    rejects_atomically(true);
}

TEST(serve_loader, forward_preflight_mode_reaches_owned_routes_and_deferred_publication_rejects) {
    static constexpr char kSource[] = R"rut(
upstream b at "127.0.0.1:9000"
route GET "/buffered" {
    return forward(b,
        response_policy: { version: "HTTP/1.1", framing: "content_length",
            connection: "request", server: "s", date: "current", hide_headers: [] },
        failure_policy: { version: "HTTP/1.1", status: 502, reason: "Bad Gateway",
            content_type: "text/plain", server: "s", date: "current",
            connection: "request", body: b"bad" },
        timeout_failure_policy: { version: "HTTP/1.1", status: 504,
            reason: "Gateway Time-out", content_type: "text/plain", server: "s",
            date: "current", connection: "request", body: b"slow" },
        response_read_timeout: 1s,
        response_buffering: "complete_content_length")
}
route GET "/plain" { return 204 }
)rut";
    const std::string path =
        write_file("/tmp/rut_serve_loader_forward_preflight", "app.rut", kSource);

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE_EQ(program.rir.module.func_count, 2u);
    REQUIRE_EQ(program.config.route_count, 2u);
    CHECK_EQ(program.rir.module.functions[0].forward_preflight_mode,
             ForwardPreflightMode::EagerDirect);
    CHECK_EQ(program.rir.module.functions[0].preflight_forward_policy_bundle_id, 1u);
    CHECK_EQ(program.config.routes[0].forward_preflight_mode, ForwardPreflightMode::EagerDirect);
    CHECK_EQ(program.config.routes[0].preflight_forward_policy_bundle_id, 1u);
    CHECK_EQ(program.config.routes[1].forward_preflight_mode, ForwardPreflightMode::None);
    CHECK_EQ(program.config.routes[1].preflight_forward_policy_bundle_id, 0u);
    REQUIRE_EQ(program.config.policy_bundle_count, 1u);
    CHECK_EQ(program.config.policy_bundles[0].response_buffering,
             ForwardResponseBufferingMode::CompleteContentLength);

    auto unpublished = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*unpublished, program.rir.module));
    REQUIRE_EQ(unpublished->route_count, 0u);
    const u32 upstream_count = unpublished->upstream_count;
    const u32 policy_bundle_count = unpublished->policy_bundle_count;
    std::vector<u8> unpublished_before(sizeof(RouteConfig));
    __builtin_memcpy(unpublished_before.data(), unpublished.get(), sizeof(RouteConfig));
    program.rir.module.functions[0].forward_preflight_mode =
        ForwardPreflightMode::AfterCanonicalSelection;
    CHECK_FALSE(register_jit_routes(*unpublished, program.rir.module, program.engine));
    CHECK_EQ(unpublished->route_count, 0u);
    CHECK_EQ(unpublished->upstream_count, upstream_count);
    CHECK_EQ(unpublished->policy_bundle_count, policy_bundle_count);
    CHECK_EQ(__builtin_memcmp(unpublished_before.data(), unpublished.get(), sizeof(RouteConfig)),
             0);

    program.rir.module.functions[0].forward_preflight_mode = ForwardPreflightMode::EagerDirect;
    program.rir.destroy();
    CHECK_EQ(program.config.routes[0].forward_preflight_mode, ForwardPreflightMode::EagerDirect);
    CHECK_EQ(program.config.routes[0].preflight_forward_policy_bundle_id, 1u);
    CHECK_EQ(program.config.routes[1].forward_preflight_mode, ForwardPreflightMode::None);
    program.destroy();
}

TEST(serve_loader, eighty_route_source_registers_all_routes) {
    const std::string dir = "/tmp/rut_serve_loader_eighty_routes";
    const std::string source = make_eighty_route_source();
    const std::string path = write_file(dir, "app.rut", source.c_str());

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE_EQ(program.config.route_count, 80u);

    const RouteEntry& first = program.config.routes[0];
    CHECK_EQ(first.method, kRouteMethodGet);
    CHECK_EQ(first.path_len, 11u);
    CHECK(std::string(first.path, first.path_len) == "/capacity/0");

    const RouteEntry& last = program.config.routes[79];
    CHECK_EQ(last.method, kRouteMethodPost);
    CHECK_EQ(last.path_len, 12u);
    CHECK(std::string(last.path, last.path_len) == "/capacity/79");
    program.destroy();
}

TEST(serve_loader, six_hundred_fifty_three_slot_source_registers_owned_routes) {
    const std::string dir = "/tmp/rut_serve_loader_653_tokens";
    const std::string source = make_653_slot_route_source();
    const std::string path = write_file(dir, "app.rut", source.c_str());

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK_EQ(program.listener.port, 0u);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    REQUIRE_EQ(program.config.route_count, 93u);

    const RouteEntry& first = program.config.routes[0];
    CHECK_EQ(first.method, kRouteMethodGet);
    CHECK_EQ(first.path_len, 11u);
    CHECK(std::string(first.path, first.path_len) == "/capacity/0");

    const RouteEntry& last = program.config.routes[92];
    CHECK_EQ(last.method, kRouteMethodAny);
    CHECK_EQ(last.path_len, 12u);
    CHECK(std::string(last.path, last.path_len) == "/capacity/92");
    program.destroy();
}

TEST(serve_loader, source_listener_metadata_is_owned_by_loaded_program) {
    const std::string dir = "/tmp/rut_serve_loader_listener";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "listen :0\n"
                                        "route GET \"/\" { return 200 }\n");

    LoadedProgram program;
    program.has_listener = true;
    program.listener = {ListenerAddress::IPv4Exact, ListenerTransport::Tls, 8443u, 0x7f000001u};
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK_EQ(program.listener.port, 0u);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.ipv4_host, 0u);

    // destroy() must clear address metadata just as load_rut_program() does at
    // entry; a reused owner must never retain a prior exact-address value.
    program.listener = {ListenerAddress::IPv4Exact, ListenerTransport::Tls, 8443u, 0x7f000001u};
    program.destroy();
    CHECK(!program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
}

TEST(serve_loader, omitted_method_route_registers_any_key_and_preserves_specific_precedence) {
    const struct {
        const char* name;
        const char* source;
    } cases[] = {
        {"any_first",
         "route \"/\" { return 200 }\n"
         "route GET \"/\" { return 201 }\n"},
        {"get_first",
         "route GET \"/\" { return 201 }\n"
         "route \"/\" { return 200 }\n"},
    };
    for (const auto& tc : cases) {
        const std::string dir = std::string("/tmp/rut_serve_loader_any_method/") + tc.name;
        const std::string path = write_file(dir, "app.rut", tc.source);

        LoadedProgram program;
        LoadError err;
        REQUIRE(load_rut_program(path.c_str(), program, err));
        REQUIRE_EQ(program.config.route_count, 2u);

        const char root[] = "/";
        const RouteEntry* get =
            program.config.match(reinterpret_cast<const u8*>(root), 1, kRouteMethodGet);
        const RouteEntry* post =
            program.config.match(reinterpret_cast<const u8*>(root), 1, kRouteMethodPost);
        const RouteEntry* trace =
            program.config.match(reinterpret_cast<const u8*>(root), 1, kRouteMethodTrace);
        const RouteEntry* connect =
            program.config.match(reinterpret_cast<const u8*>(root), 1, kRouteMethodConnect);
        REQUIRE(get != nullptr);
        REQUIRE(post != nullptr);
        REQUIRE(trace != nullptr);
        REQUIRE(connect != nullptr);
        CHECK_EQ(get->method, kRouteMethodGet);
        CHECK_EQ(post->method, kRouteMethodAny);
        CHECK_EQ(trace->method, kRouteMethodAny);
        CHECK_EQ(connect->method, kRouteMethodAny);
        program.destroy();
    }
}

#if RUT_ENABLE_WEBSOCKET
TEST(serve_loader, websocket_terminate_route_registers_and_runs) {
    // End-to-end (Phase 4 D/E): a `websocket(x){ frame in frame.drop() }` route compiles, its
    // constant verdict is JIT'd, and it's published as a terminate route whose frame handler — when
    // called — returns the compiled verdict.
    const std::string dir = "/tmp/rut_serve_loader_ws";
    const std::string path =
        write_file(dir,
                   "app.rut",
                   "upstream backend at \"127.0.0.1:9999\"\n"
                   "route GET \"/ws\" { return websocket(backend) { frame in frame.drop() } }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    bool found = false;
    for (u32 i = 0; i < program.config.route_count; i++) {
        const auto& r = program.config.routes[i];
        if (!r.ws_terminate) continue;
        found = true;
        REQUIRE(r.ws_frame_handler != nullptr);
        CHECK(r.ws_frame_handler(nullptr, WsOpcode::Text, nullptr, 0, false) ==
              WsFrameAction::Drop);
    }
    CHECK(found);
    program.destroy();
}

TEST(serve_loader, websocket_terminate_len_guard_branches_on_length) {
    // Conditional verdict end-to-end: `guard frame.len < 4096 else { frame.drop() }` then
    // forward. The JIT'd handler must branch on the message length — drop at/over the cap,
    // forward under it. Proves parser -> analyze -> HIR guards -> branching codegen -> serve all
    // wire up and the compiled function actually computes the right verdict per length. (Rut has
    // no <= operator, so the cap is exclusive: len < 4096.)
    const std::string dir = "/tmp/rut_serve_loader_ws_guard";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend) { frame in\n"
                                        "  guard frame.len < 4096 else { frame.drop() }\n"
                                        "  frame.forward()\n"
                                        "} }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    WsMessageHandlerFn h = nullptr;
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (program.config.routes[i].ws_terminate) {
            h = program.config.routes[i].ws_frame_handler;
            break;
        }
    }
    REQUIRE(h != nullptr);
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 5000, false) == WsFrameAction::Drop);  // over cap
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 4096, false) ==
          WsFrameAction::Drop);  // at cap (excl)
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 4095, false) ==
          WsFrameAction::Forward);                                                     // just under
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 100, false) == WsFrameAction::Forward);  // under cap
    program.destroy();
}

TEST(serve_loader, websocket_terminate_opcode_guard_drops_binary) {
    // Opcode discrimination end-to-end: `guard frame.isText else { frame.drop() }` then forward
    // — a text-only handler. The JIT'd handler must branch on the opcode param: forward Text,
    // drop Binary.
    const std::string dir = "/tmp/rut_serve_loader_ws_opcode";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend) { frame in\n"
                                        "  guard frame.isText else { frame.drop() }\n"
                                        "  frame.forward()\n"
                                        "} }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    WsMessageHandlerFn h = nullptr;
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (program.config.routes[i].ws_terminate) {
            h = program.config.routes[i].ws_frame_handler;
            break;
        }
    }
    REQUIRE(h != nullptr);
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 100, false) == WsFrameAction::Forward);  // text->fwd
    CHECK(h(nullptr, WsOpcode::Binary, nullptr, 100, false) == WsFrameAction::Drop);   // bin->drop
    program.destroy();
}

TEST(serve_loader, websocket_terminate_direction_guard_polices_client_leg) {
    // Direction discrimination end-to-end: `guard frame.fromClient else { frame.forward() }`
    // then `frame.drop()`. The handler should drop only the client→upstream leg and forward the
    // upstream→client leg. Proves the from_client param threads through analyze -> HIR -> codegen
    // ABI (param 4) -> serve.
    const std::string dir = "/tmp/rut_serve_loader_ws_dir";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend) { frame in\n"
                                        "  guard frame.fromClient else { frame.forward() }\n"
                                        "  frame.drop()\n"
                                        "} }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    WsMessageHandlerFn h = nullptr;
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (program.config.routes[i].ws_terminate) {
            h = program.config.routes[i].ws_frame_handler;
            break;
        }
    }
    REQUIRE(h != nullptr);
    // from_client=true  -> guard passes -> falls through to default drop
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 100, true) == WsFrameAction::Drop);
    // from_client=false -> guard fails  -> else verdict forward
    CHECK(h(nullptr, WsOpcode::Text, nullptr, 100, false) == WsFrameAction::Forward);
    program.destroy();
}

TEST(serve_loader, websocket_terminate_close_code_reaches_route) {
    // close(code) end-to-end: `frame.close(1008)` must publish the route with ws_close_code
    // == 1008 (the runtime puts that on the wire), and the JIT'd handler still returns Close.
    // Proves close_code threads analyze -> HIR -> add_ws_terminate -> RouteEntry.
    const std::string dir = "/tmp/rut_serve_loader_ws_close_code";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend) { frame in\n"
                                        "  frame.close(1008)\n"
                                        "} }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    bool found = false;
    for (u32 i = 0; i < program.config.route_count; i++) {
        const auto& r = program.config.routes[i];
        if (!r.ws_terminate) continue;
        found = true;
        CHECK_EQ(r.ws_close_code, 1008u);
        REQUIRE(r.ws_frame_handler != nullptr);
        CHECK(r.ws_frame_handler(nullptr, WsOpcode::Text, nullptr, 0, false) ==
              WsFrameAction::Close);
    }
    CHECK(found);
    program.destroy();
}

TEST(serve_loader, websocket_terminate_default_close_code_is_1000) {
    // A bare frame.close() (or any non-close default) leaves ws_close_code at the 1000 default.
    const std::string dir = "/tmp/rut_serve_loader_ws_close_default";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend) { frame in\n"
                                        "  frame.close()\n"
                                        "} }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    bool found = false;
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (!program.config.routes[i].ws_terminate) continue;
        found = true;
        CHECK_EQ(program.config.routes[i].ws_close_code, 1000u);
    }
    CHECK(found);
    program.destroy();
}

TEST(serve_loader, websocket_terminate_max_message_size_kwarg_reaches_route) {
    // `maxMessageSize: 4kb` end-to-end: the published terminate route carries 4096 as its cap
    // (proves the kwarg threads parser → HIR → add_ws_terminate → RouteEntry). Omitting it
    // falls back to the engine default (~16 KB), checked separately.
    const std::string dir = "/tmp/rut_serve_loader_ws_maxmsg";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend, "
                                        "maxMessageSize: 4kb) { frame in\n"
                                        "  frame.forward()\n"
                                        "} }\n");
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    bool found = false;
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (!program.config.routes[i].ws_terminate) continue;
        found = true;
        CHECK_EQ(program.config.routes[i].ws_max_message_size, 4096u);
    }
    CHECK(found);
    program.destroy();
}

TEST(serve_loader, websocket_terminate_default_max_message_size) {
    // No kwarg → the route gets the engine's single-slice default cap (nonzero, ~16 KB).
    const std::string dir = "/tmp/rut_serve_loader_ws_maxmsg_default";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "upstream backend at \"127.0.0.1:9999\"\n"
                                        "route GET \"/ws\" { return websocket(backend) { frame in\n"
                                        "  frame.forward()\n"
                                        "} }\n");
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (!program.config.routes[i].ws_terminate) continue;
        CHECK(program.config.routes[i].ws_max_message_size > 4096u);  // ~16 KB slice default
    }
    program.destroy();
}

TEST(serve_loader, add_ws_terminate_rejects_invalid_close_code) {
    // Defense-in-depth on the C++ route surface: a close code the runtime would never put on
    // the wire (reserved/local-only or out of range) must be refused at registration, not
    // serialized into a Close frame later. (The .rut analyze path already rejects these; this
    // guards direct callers of add_ws_terminate.)
    RouteConfig cfg;
    auto up = cfg.add_upstream("backend", 0x7F000001u, 9999);
    REQUIRE(up.has_value());
    const u16 uid = static_cast<u16>(up.value());
    WsMessageHandlerFn h = [](void*, WsOpcode, const u8*, u64, bool) {
        return WsFrameAction::Forward;
    };
    CHECK_FALSE(cfg.add_ws_terminate("/a", 0, uid, h, 4096, 1005));  // reserved local-only
    CHECK_FALSE(cfg.add_ws_terminate("/b", 0, uid, h, 4096, 1006));  // reserved local-only
    CHECK_FALSE(cfg.add_ws_terminate("/c", 0, uid, h, 4096, 999));   // below range
    CHECK_FALSE(cfg.add_ws_terminate("/d", 0, uid, h, 4096, 5000));  // above range
    CHECK_FALSE(cfg.add_ws_terminate("/g", 0, uid, h, 4096, 2000));  // reserved 1016–2999
    // Valid application codes are accepted.
    CHECK(cfg.add_ws_terminate("/e", 0, uid, h, 4096, 1000));
    CHECK(cfg.add_ws_terminate("/f", 0, uid, h, 4096, 1008));
    CHECK(cfg.add_ws_terminate("/h", 0, uid, h, 4096, 4000));  // private-use range
}
#endif

#if RUT_ENABLE_WEBSOCKET
TEST(serve_loader, websocket_terminate_text_match_guard_filters_content) {
    // Content blocklist end-to-end: `guard !frame.text.matches(re".*badword.*") else { drop }`
    // then forward. The JIT'd handler runs the compiled regex over the payload — drop a message
    // that matches, forward one that doesn't. Proves the regex pattern/db globals emitted by
    // emit_ws_handler are compiled + back-patched by JIT finalization and called at runtime.
    // matches() is full-string (the helper wraps the pattern as ^(?:…)$), so a substring filter
    // needs the explicit `.*….*`.
    const std::string dir = "/tmp/rut_serve_loader_ws_text_match";
    const std::string path =
        write_file(dir,
                   "app.rut",
                   "upstream backend at \"127.0.0.1:9999\"\n"
                   "route GET \"/ws\" { return websocket(backend) { frame in\n"
                   "  guard !frame.text.matches(re\".*badword.*\") else { frame.drop() }\n"
                   "  frame.forward()\n"
                   "} }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    WsMessageHandlerFn h = nullptr;
    for (u32 i = 0; i < program.config.route_count; i++) {
        if (program.config.routes[i].ws_terminate) {
            h = program.config.routes[i].ws_frame_handler;
            break;
        }
    }
    REQUIRE(h != nullptr);
    const char* clean = "hello world";
    const char* dirty = "you said badword again";
    // contains badword -> matches -> `not match` false -> guard fails -> Drop
    CHECK(h(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(dirty), strlen(dirty), true) ==
          WsFrameAction::Drop);
    // no match -> `not match` true -> guard passes -> default Forward
    CHECK(h(nullptr, WsOpcode::Text, reinterpret_cast<const u8*>(clean), strlen(clean), true) ==
          WsFrameAction::Forward);
    program.destroy();
}
#endif

TEST(serve_loader, missing_file_fails_at_read) {
    LoadedProgram program;
    LoadError err;
    CHECK_FALSE(load_rut_program("/tmp/rut_serve_loader_does_not_exist.rut", program, err));
    CHECK(err.stage == LoadStage::Read);
    CHECK_FALSE(err.has_diag);
    program.destroy();
}

TEST(serve_loader, empty_program_loads_routeless) {
    // Zero-byte file: must load (no null-pointer arithmetic in lex) and
    // produce an empty route table.
    const std::string path = write_file("/tmp/rut_serve_loader_empty", "empty.rut", "");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK_EQ(program.config.route_count, 0u);
    program.destroy();
}

TEST(serve_loader, cache_registry_changes_only_at_activation) {
    cache_registry_set_seed(0x5EEDu);
    const u32 old_caps[1] = {64};
    const u64 old_ids[1] = {cache_instance_identity("old", 3)};
    cache_registry_publish(old_caps, old_ids, 1);

    const std::string path =
        write_file("/tmp/rut_serve_loader_cache_activation",
                   "app.rut",
                   "let buckets = Cache<IP, i64>(capacity: 128)\n"
                   "route GET \"/\" { let n = buckets.get(req.remoteAddr).or(0) "
                   "buckets.set(req.remoteAddr, n + 1) return 200 }\n");
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));

    auto& reg = cache_registry();
    CHECK_EQ(reg.capacities[0].load(std::memory_order_relaxed), 64u);
    CHECK_EQ(reg.identities[0].load(std::memory_order_relaxed), old_ids[0]);

    activate_rut_program(program);
    CHECK_EQ(reg.capacities[0].load(std::memory_order_relaxed), 128u);
    CHECK_EQ(reg.identities[0].load(std::memory_order_relaxed),
             cache_instance_identity("buckets", 7));
    program.destroy();
}

TEST(serve_loader, parse_error_reports_stage_and_message) {
    const std::string path =
        write_file("/tmp/rut_serve_loader_parse", "bad.rut", "route GET \"/\" { this is broken\n");

    LoadedProgram program;
    LoadError err;
    CHECK_FALSE(load_rut_program(path.c_str(), program, err));
    CHECK(err.stage == LoadStage::Parse);
    CHECK(err.has_diag);

    char msg[256];
    const u32 n = format_load_error(err, msg, sizeof(msg));
    CHECK_GT(n, 0u);
    CHECK(contains(msg, "parse"));
    CHECK(contains(msg, "failed"));
    program.destroy();
}

TEST(serve_loader, import_resolves_relative_to_program) {
    const std::string dir = "/tmp/rut_serve_loader_import";
    write_file(dir, "auth.rut", "func jwtAuth() -> i32 => 200\n");
    const std::string path = write_file(
        dir,
        "main.rut",
        "import \"auth.rut\"\n"
        "route GET \"/users\" { if jwtAuth() == 200 { return 200 } else { return 500 } }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK_EQ(program.config.route_count, 1u);
    program.destroy();
}

TEST(serve_loader, unknown_import_reports_copied_detail) {
    // The diagnostic detail (the imported name) lives in analyzer storage
    // that is freed when load_rut_program returns; format_load_error must
    // still read it (the loader copies it into LoadError).
    const std::string path = write_file("/tmp/rut_serve_loader_badimport",
                                        "main.rut",
                                        "import \"missing.rut\"\n"
                                        "route GET \"/\" { return 200 }\n");

    LoadedProgram program;
    LoadError err;
    CHECK_FALSE(load_rut_program(path.c_str(), program, err));
    CHECK(err.has_diag);

    char msg[256];
    format_load_error(err, msg, sizeof(msg));
    // Detail names the unresolved import — proves the copy survived return.
    CHECK(contains(msg, "missing.rut"));
    program.destroy();
}

TEST(serve_loader, format_read_stage_without_diag) {
    LoadError err;
    err.stage = LoadStage::Read;
    err.has_diag = false;

    char msg[128];
    const u32 n = format_load_error(err, msg, sizeof(msg));
    CHECK_GT(n, 0u);
    CHECK(contains(msg, "read source file"));
    CHECK(contains(msg, "failed"));
}

TEST(serve_loader, unmatched_source_loads_into_owned_runtime_table) {
    const std::string path = write_file(
        "/tmp/rut_serve_loader_unmatched_guard",
        "app.rut",
        "unmatched OPTIONS { return local_response({ version: \"HTTP/1.1\", status: 400, "
        "reason: \"Bad Request\", server: \"rut\", date: \"current\", content_type: "
        "\"text/plain\", connection: \"request\", head_mode: \"reject\", body: b\"x\" }) }\n"
        "route GET \"/\" { return 200 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK_EQ(program.rir.module.strict_local_response_policy_count, 1u);
    CHECK_EQ(program.rir.module.unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(program.config.route_count, 1u);
    CHECK_EQ(program.config.upstream_count, 0u);
    CHECK_EQ(program.config.strict_local_response_policy_count, 1u);
    CHECK_EQ(program.config.unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK(program.config.unmatched_policy_table_is_valid());
    CHECK(program.config.strict_local_response_policy_id_is_owned(1));
    program.destroy();
}

TEST(serve_loader, unmatched_representation200_is_deep_owned_and_copyable) {
    const std::string path =
        write_file("/tmp/rut_serve_loader_unmatched_representation200",
                   "app.rut",
                   "unmatched { return local_response({ version: \"HTTP/1.1\", status: 200, "
                   "reason: \"OK\", server: \"nginx/1.29.7\", date: \"current\", content_type: "
                   "\"text/plain\", connection: \"request\", head_mode: \"suppress_body\", "
                   "body: b\"successor-static\" }) }\n"
                   "route GET \"/\" { return 204 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE_EQ(program.rir.module.strict_local_response_policy_count, 1u);
    REQUIRE_EQ(program.config.strict_local_response_policy_count, 1u);
    CHECK_EQ(program.rir.module.unmatched_policy_ids[kRouteMethodAny], 1u);
    CHECK_EQ(program.config.unmatched_policy_ids[kRouteMethodAny], 1u);
    const auto& rir_policy = program.rir.module.strict_local_response_policies[0];
    const auto& owned = program.config.strict_local_response_policies[0];
    CHECK(strict_local_response_policy_spec_valid(rir_policy));
    CHECK(strict_local_response_policy_spec_valid(owned));
    CHECK_EQ(strict_local_response_profile(owned.status_code),
             StrictLocalResponseProfile::Representation200);
    CHECK(owned.reason.eq({"OK", 2}));
    CHECK(owned.content_type.eq({"text/plain", 10}));
    CHECK(owned.server.eq({"nginx/1.29.7", 12}));
    CHECK(owned.body.eq({"successor-static", 16}));
    CHECK(owned.reason.ptr != rir_policy.reason.ptr);
    CHECK(owned.content_type.ptr != rir_policy.content_type.ptr);
    CHECK(owned.server.ptr != rir_policy.server.ptr);
    CHECK(owned.body.ptr != rir_policy.body.ptr);
    CHECK(program.config.strict_local_response_policy_id_is_owned(1));
    CHECK(program.config.unmatched_policy_table_is_valid());

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_unmatched_policy_table_from_owned(program.config));
    REQUIRE(copied->unmatched_policy_table_is_valid());
    const auto& copied_policy = copied->strict_local_response_policies[0];
    CHECK(copied_policy.body.eq({"successor-static", 16}));
    CHECK(copied_policy.reason.ptr != owned.reason.ptr);
    CHECK(copied_policy.content_type.ptr != owned.content_type.ptr);
    CHECK(copied_policy.server.ptr != owned.server.ptr);
    CHECK(copied_policy.body.ptr != owned.body.ptr);

    copied->strict_local_response_policies[0].reason = {"Created", 7};
    CHECK_FALSE(copied->unmatched_policy_table_is_valid());
    CHECK_FALSE(copied->strict_local_response_policy_id_is_owned(1));
    program.destroy();
}

TEST(serve_loader, unmatched_population_owns_valid_table_and_rejects_forgery_before_mutation) {
    static constexpr char kReason[] = "Bad Request";
    static constexpr char kType[] = "text/plain";
    static constexpr char kServer[] = "rut";
    static constexpr char kBody[] = "x";
    rir::Module mod{};
    auto& policy = mod.strict_local_response_policies[0];
    policy.version = StrictLocalResponseVersion::Http11;
    policy.status_code = 400;
    policy.date = StrictLocalResponseDate::Current;
    policy.connection = StrictLocalResponseConnection::Request;
    policy.head_mode = StrictLocalResponseHeadMode::Reject;
    policy.reason = {kReason, sizeof(kReason) - 1};
    policy.content_type = {kType, sizeof(kType) - 1};
    policy.server = {kServer, sizeof(kServer) - 1};
    policy.body = {kBody, sizeof(kBody) - 1};
    mod.strict_local_response_policy_count = 1;
    mod.unmatched_policy_ids[kRouteMethodOptions] = 1;
    mod.upstream_count = 1;
    mod.upstreams[0].name = {"would_mutate", 12};
    mod.upstreams[0].has_address = true;
    mod.upstreams[0].ip = 0x7f000001u;
    mod.upstreams[0].port = 9000;
    REQUIRE(rir::verify_module(mod).ok);

    auto valid_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*valid_cfg, mod));
    CHECK_EQ(valid_cfg->route_count, 0u);
    CHECK_EQ(valid_cfg->upstream_count, 1u);
    CHECK_EQ(valid_cfg->response_body_count, 0u);
    CHECK(valid_cfg->unmatched_policy_table_is_valid());
    CHECK(valid_cfg->strict_local_response_policies[0].reason.ptr != kReason);
    CHECK(valid_cfg->strict_local_response_policies[0].body.ptr != kBody);
    CHECK(valid_cfg->strict_local_response_policies[0].reason.eq(policy.reason));
    CHECK(valid_cfg->strict_local_response_policies[0].body.eq(policy.body));
    const StrictLocalResponsePolicySpec valid_policy = policy;

    mod.strict_local_response_policy_count = 0;
    auto forged_cfg = std::make_unique<RouteConfig>();
    CHECK_FALSE(populate_route_config(*forged_cfg, mod));
    CHECK_EQ(forged_cfg->route_count, 0u);
    CHECK_EQ(forged_cfg->upstream_count, 0u);
    CHECK_EQ(forged_cfg->response_body_count, 0u);
    CHECK_FALSE(forged_cfg->has_unmatched_metadata());

    mod.strict_local_response_policy_count = 1;
    mod.strict_local_response_policies[0].reason = {nullptr, 1};
    auto null_pointer_cfg = std::make_unique<RouteConfig>();
    CHECK_FALSE(populate_route_config(*null_pointer_cfg, mod));
    CHECK_EQ(null_pointer_cfg->upstream_count, 0u);
    CHECK_FALSE(null_pointer_cfg->has_unmatched_metadata());
    mod.strict_local_response_policies[0].reason = valid_policy.reason;

    mod.strict_local_response_policies[0].head_mode = static_cast<StrictLocalResponseHeadMode>(255);
    auto enum_cfg = std::make_unique<RouteConfig>();
    CHECK_FALSE(populate_route_config(*enum_cfg, mod));
    CHECK_EQ(enum_cfg->upstream_count, 0u);
    CHECK_FALSE(enum_cfg->has_unmatched_metadata());
    mod.strict_local_response_policies[0].head_mode = StrictLocalResponseHeadMode::Reject;

    mod.strict_local_response_policy_count = kMaxStrictLocalResponsePolicies + 1;
    auto count_cfg = std::make_unique<RouteConfig>();
    CHECK_FALSE(populate_route_config(*count_cfg, mod));
    CHECK_EQ(count_cfg->upstream_count, 0u);
    CHECK_FALSE(count_cfg->has_unmatched_metadata());

    // Aggregate pool overflow is rejected before the declared upstream can be
    // appended to the destination.
    const std::string body1(4096, 'a');
    const std::string body2(4070, 'b');
    mod.strict_local_response_policy_count = 2;
    mod.strict_local_response_policies[0] = valid_policy;
    mod.strict_local_response_policies[0].body = {body1.data(), static_cast<u32>(body1.size())};
    auto& second = mod.strict_local_response_policies[1];
    second = valid_policy;
    second.status_code = 405;
    second.reason = {"x", 1};
    second.content_type = {"x", 1};
    second.server = {"x", 1};
    second.body = {body2.data(), static_cast<u32>(body2.size())};
    mod.unmatched_policy_ids[kRouteMethodConnect] = 2;
    auto capacity_cfg = std::make_unique<RouteConfig>();
    CHECK_FALSE(populate_route_config(*capacity_cfg, mod));
    CHECK_EQ(capacity_cfg->upstream_count, 0u);
    CHECK_FALSE(capacity_cfg->has_unmatched_metadata());

    mod.strict_local_response_policy_count = 0;
    mod.unmatched_policy_ids[kRouteMethodOptions] = 0;
    mod.unmatched_policy_ids[kRouteMethodConnect] = 0;
    mod.upstream_count = 0;
    auto omitted_cfg = std::make_unique<RouteConfig>();
    CHECK(populate_route_config(*omitted_cfg, mod));
    CHECK_EQ(omitted_cfg->route_count, 0u);
    CHECK_EQ(omitted_cfg->upstream_count, 0u);
}

TEST(serve_loader, exact_strict_local_response_metadata_installs_atomically) {
    rir::Module mod{};
    auto& policy = mod.strict_local_response_policies[0];
    policy.version = StrictLocalResponseVersion::Http11;
    policy.status_code = 400;
    policy.date = StrictLocalResponseDate::Current;
    policy.connection = StrictLocalResponseConnection::Request;
    policy.head_mode = StrictLocalResponseHeadMode::Reject;
    policy.reason = {"Bad Request", 11};
    policy.content_type = {"text/plain", 10};
    policy.server = {"rut", 3};
    policy.body = {"x", 1};
    mod.strict_local_response_policy_count = 1;
    auto& binding = mod.exact_strict_local_response_bindings[0];
    const Str path{"/static", 7};
    for (u32 i = 0; i < path.len; i++) binding.path[i] = path.ptr[i];
    binding.path_len = static_cast<u8>(path.len);
    binding.method = kRouteMethodGet;
    binding.policy_id = 1;
    mod.exact_strict_local_response_binding_count = 1;
    mod.upstream_count = 1;
    mod.upstreams[0].name = {"would_mutate", 12};
    mod.upstreams[0].has_address = true;
    mod.upstreams[0].ip = 0x7f000001u;
    mod.upstreams[0].port = 9000;
    REQUIRE(rir::verify_module(mod).ok);

    auto cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*cfg, mod));
    CHECK_EQ(cfg->upstream_count, 1u);
    CHECK_EQ(cfg->route_count, 0u);
    REQUIRE(cfg->strict_local_response_table_is_valid());
    CHECK(cfg->has_exact_strict_local_response_inventory());
    CHECK_EQ(cfg->exact_strict_local_response_binding_count, 1u);
    CHECK_EQ(cfg->match_exact_strict_local_response({"/static?x=1", 11}, kRouteMethodGet), 1u);
    CHECK_EQ(cfg->match_exact_strict_local_response({"/static/", 8}, kRouteMethodGet), 0u);

    rir::Module hidden{};
    hidden.exact_strict_local_response_bindings[7].reserved1 = 1;
    auto hidden_cfg = std::make_unique<RouteConfig>();
    CHECK_FALSE(populate_route_config(*hidden_cfg, hidden));
    CHECK_EQ(hidden_cfg->upstream_count, 0u);
    CHECK_EQ(hidden_cfg->route_count, 0u);

    rir::Module normalized = mod;
    normalized.strict_local_response_policies[1] = policy;
    normalized.strict_local_response_policy_count = 2;
    normalized.exact_strict_local_response_bindings[1] = binding;
    normalized.exact_strict_local_response_bindings[1].path_view = ExactPathView::SlashNormalized;
    normalized.exact_strict_local_response_bindings[1].policy_id = 2;
    normalized.exact_strict_local_response_binding_count = 2;
    REQUIRE(rir::verify_module(normalized).ok);
    auto normalized_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*normalized_cfg, normalized));
    REQUIRE(normalized_cfg->strict_local_response_table_is_valid());
    CHECK_EQ(normalized_cfg->upstream_count, 1u);
    CHECK_EQ(normalized_cfg->exact_strict_local_response_binding_count, 2u);
    CHECK_EQ(normalized_cfg->strict_local_response_policy_count, 1u);
    CHECK_EQ(normalized_cfg->exact_strict_local_response_bindings[0].policy_id, 1u);
    CHECK_EQ(normalized_cfg->exact_strict_local_response_bindings[1].policy_id, 1u);
    CHECK_EQ(normalized_cfg->exact_strict_local_response_bindings[1].path_view,
             ExactPathView::SlashNormalized);
}

TEST(serve_loader, slash_normalized_exact_source_loads_and_owns_runtime_inventory) {
    static constexpr char kSource[] = R"rut(
route exact slash_normalized GET "/health/check" { return local_response({
  version: "HTTP/1.1", status: 400, reason: "Bad Request", server: "rut",
  date: "current", content_type: "text/plain", connection: "request",
  head_mode: "reject", body: b"get"
}) }
route exact slash_normalized "/health/any" { return local_response({
  version: "HTTP/1.1", status: 401, reason: "Unauthorized", server: "rut",
  date: "current", content_type: "text/plain", connection: "request",
  head_mode: "suppress_body", body: b"any"
}) }
)rut";
    const std::string path =
        write_file("/tmp/rut_serve_loader_slash_normalized_stage2", "app.rut", kSource);
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE(rir::verify_module(program.rir.module).ok);
    REQUIRE_EQ(program.rir.module.exact_strict_local_response_binding_count, 2u);
    const auto& get = program.rir.module.exact_strict_local_response_bindings[0];
    const auto& any = program.rir.module.exact_strict_local_response_bindings[1];
    CHECK_EQ(get.path_view, ExactPathView::SlashNormalized);
    CHECK_EQ(get.method, kRouteMethodGet);
    CHECK((Str{get.path, get.path_len}.eq({"/health/check", 13})));
    CHECK_EQ(any.path_view, ExactPathView::SlashNormalized);
    CHECK_EQ(any.method, kRouteMethodAny);
    CHECK((Str{any.path, any.path_len}.eq({"/health/any", 11})));
    CHECK_EQ(program.config.route_count, 0u);
    CHECK_EQ(program.config.upstream_count, 0u);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    CHECK(program.config.has_strict_local_response_table_inventory());
    CHECK_EQ(program.config.exact_strict_local_response_binding_count, 2u);
    CHECK_EQ(program.config.exact_strict_local_response_bindings[0].path_view,
             ExactPathView::SlashNormalized);
    CHECK_EQ(program.config.exact_strict_local_response_bindings[1].path_view,
             ExactPathView::SlashNormalized);
    CHECK(program.config.has_slash_normalized_exact_strict_local_response_inventory());

    // Both public activation paths admit the verified owned table.
    REQUIRE_EQ(program.rir.module.func_count, 0u);
    auto direct_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*direct_cfg, program.rir.module));
    REQUIRE(register_jit_routes(*direct_cfg, program.rir.module, program.engine));
    CHECK_EQ(direct_cfg->route_count, 0u);
    CHECK_EQ(direct_cfg->timer_count, 0u);
    CHECK(direct_cfg->has_slash_normalized_exact_strict_local_response_inventory());

    // load_rut_program has already destroyed AST/HIR/MIR. End every remaining
    // compiler/source lifetime and prove the prepared RouteConfig owns both
    // normalized inline paths and the GET/ANY policies independently.
    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0;
    std::filesystem::remove(path);
    REQUIRE(direct_cfg->strict_local_response_table_is_valid());
    const auto owned_get = direct_cfg->match_exact_strict_local_response_views(
        {"/health//check", 14}, {"/health/check", 13}, kRouteMethodGet);
    CHECK_EQ(owned_get.state, ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(owned_get.policy_id, 1u);
    const auto owned_any = direct_cfg->match_exact_strict_local_response_views(
        {"/health//any", 12}, {"/health/any", 11}, kRouteMethodPost);
    CHECK_EQ(owned_any.state, ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(owned_any.policy_id, 2u);
    CHECK(direct_cfg->strict_local_response_policies[0].body.eq({"get", 3}));
    CHECK(direct_cfg->strict_local_response_policies[1].body.eq({"any", 3}));
    program.destroy();
}

TEST(serve_loader, slash_normalized_exact_and_jit_route_activate_together) {
    static constexpr char kSource[] = R"rut(
route exact slash_normalized GET "/health/check" { return local_response({
  version: "HTTP/1.1", status: 400, reason: "Bad Request", server: "rut",
  date: "current", content_type: "text/plain", connection: "request",
  head_mode: "reject", body: b"get"
}) }
route GET "/sentinel" { return 204 }
)rut";
    const std::string path =
        write_file("/tmp/rut_serve_loader_slash_normalized_direct_jit_stage2", "app.rut", kSource);
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE(rir::verify_module(program.rir.module).ok);
    REQUIRE_EQ(program.rir.module.exact_strict_local_response_binding_count, 1u);
    REQUIRE_EQ(program.rir.module.func_count, 1u);
    CHECK_EQ(program.rir.module.exact_strict_local_response_bindings[0].path_view,
             ExactPathView::SlashNormalized);
    CHECK((program.rir.module.functions[0].route_pattern.eq({"/sentinel", 9})));
    REQUIRE(program.engine.lookup("handler_route_0") != nullptr);

    // Direct registration cannot omit or substitute the module's verified
    // strict inventory. Both failures precede lookup/replay and leave every
    // destination byte unchanged.
    auto omitted_cfg = std::make_unique<RouteConfig>();
    std::vector<u8> omitted_before(sizeof(RouteConfig));
    __builtin_memcpy(omitted_before.data(), omitted_cfg.get(), sizeof(RouteConfig));
    CHECK_FALSE(register_jit_routes(*omitted_cfg, program.rir.module, program.engine));
    CHECK_EQ(__builtin_memcmp(omitted_before.data(), omitted_cfg.get(), sizeof(RouteConfig)), 0);

    auto mismatched_module = program.rir.module;
    mismatched_module.strict_local_response_policies[0].body = {"different", 9};
    REQUIRE(rir::verify_module(mismatched_module).ok);
    auto mismatched_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*mismatched_cfg, mismatched_module));
    std::vector<u8> mismatched_before(sizeof(RouteConfig));
    __builtin_memcpy(mismatched_before.data(), mismatched_cfg.get(), sizeof(RouteConfig));
    CHECK_FALSE(register_jit_routes(*mismatched_cfg, program.rir.module, program.engine));
    CHECK_EQ(__builtin_memcmp(mismatched_before.data(), mismatched_cfg.get(), sizeof(RouteConfig)),
             0);

    // A separately populated destination activates the normalized selector and
    // ordinary route in the same transactional registration step.
    auto direct_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*direct_cfg, program.rir.module));
    REQUIRE(register_jit_routes(*direct_cfg, program.rir.module, program.engine));
    CHECK_EQ(direct_cfg->route_count, 1u);
    CHECK_EQ(direct_cfg->timer_count, 0u);
    CHECK(direct_cfg->has_slash_normalized_exact_strict_local_response_inventory());
    program.destroy();
}

TEST(serve_loader, exact_strict_local_response_source_reaches_runtime_config) {
    const std::string path =
        write_file("/tmp/rut_serve_loader_exact_strict_foundation",
                   "app.rut",
                   "route exact GET \"/static\" { return local_response({ version: \"HTTP/1.1\", "
                   "status: 400, reason: \"Bad Request\", server: \"rut\", date: \"current\", "
                   "content_type: \"text/plain\", connection: \"request\", head_mode: \"reject\", "
                   "body: b\"x\" }) }\n"
                   "route GET \"/sentinel\" { return 204 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK_EQ(program.config.route_count, 1u);
    CHECK_EQ(program.config.upstream_count, 0u);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    CHECK(program.config.has_exact_strict_local_response_inventory());
    CHECK_EQ(program.config.match_exact_strict_local_response({"/static", 7}, kRouteMethodGet), 1u);

    // Raw exact metadata remains admissible through both public activation
    // steps, including a direct register_jit_routes call on an independently
    // populated destination.
    auto direct_cfg = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*direct_cfg, program.rir.module));
    REQUIRE(register_jit_routes(*direct_cfg, program.rir.module, program.engine));
    CHECK_EQ(direct_cfg->route_count, 1u);
    CHECK_EQ(direct_cfg->timer_count, 0u);
    CHECK_EQ(direct_cfg->match_exact_strict_local_response({"/static", 7}, kRouteMethodGet), 1u);
    program.destroy();
}

TEST(serve_loader, pre_route_source_installs_full_owned_deduplicated_selector_table) {
    static constexpr char kSource[] = R"rut(
upstream backend at "127.0.0.1:9000"
pre_route TRACE { return local_response({
  version: "HTTP/1.1", status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "reject", body: b"trace-rejected"
}) }
pre_route OPTIONS { return local_response({
  version: "HTTP/1.1", status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "reject", body: b"trace-rejected"
}) }
route exact "/static" { return local_response({
  version: "HTTP/1.1", status: 200, reason: "OK", server: "nginx/1.29.7",
  date: "current", content_type: "text/plain", connection: "request",
  head_mode: "suppress_body", body: b"successor-static"
}) }
route "/" { return forward(backend) }
unmatched TRACE { return local_response({
  version: "HTTP/1.1", status: 405, reason: "Not Allowed", server: "nginx/1.29.7",
  date: "current", content_type: "text/html", connection: "request",
  head_mode: "reject", body: b"trace-rejected"
}) }
)rut";
    const std::string path =
        write_file("/tmp/rut_serve_loader_pre_route_source", "app.rut", kSource);
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE_EQ(program.rir.module.strict_local_response_policy_count, 4u);
    CHECK_EQ(program.rir.module.pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(program.rir.module.pre_route_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(program.rir.module.exact_strict_local_response_bindings[0].policy_id, 3u);
    CHECK_EQ(program.rir.module.unmatched_policy_ids[kRouteMethodTrace], 4u);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    REQUIRE(program.config.has_pre_route_metadata());
    REQUIRE(program.config.has_unmatched_metadata());
    REQUIRE(program.config.has_exact_strict_local_response_inventory());
    CHECK_EQ(program.config.route_count, 1u);
    CHECK_EQ(program.config.upstream_count, 1u);
    // Stable semantic dedup collapses the three equal 405 source policies.
    REQUIRE_EQ(program.config.strict_local_response_policy_count, 2u);
    CHECK_EQ(program.config.pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(program.config.pre_route_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(program.config.unmatched_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(program.config.exact_strict_local_response_bindings[0].policy_id, 2u);
    CHECK_EQ(program.config.pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK_EQ(program.config.pre_route_policy_id(kRouteMethodOptions), 1u);
    CHECK_EQ(program.config.match_exact_strict_local_response({"/static", 7}, kRouteMethodGet), 2u);
    const auto& source_policy = program.rir.module.strict_local_response_policies[0];
    const auto& owned = program.config.strict_local_response_policies[0];
    CHECK(owned.reason.ptr != source_policy.reason.ptr);
    CHECK(owned.server.ptr != source_policy.server.ptr);
    CHECK(owned.content_type.ptr != source_policy.content_type.ptr);
    CHECK(owned.body.ptr != source_policy.body.ptr);
    CHECK(owned.reason.eq({"Not Allowed", 11}));
    CHECK(owned.server.eq({"nginx/1.29.7", 12}));
    CHECK(owned.content_type.eq({"text/html", 9}));
    CHECK(owned.body.eq({"trace-rejected", 14}));

    auto copied = std::make_unique<RouteConfig>();
    REQUIRE(copied->copy_strict_local_response_table_from_owned(program.config));
    REQUIRE(copied->strict_local_response_table_is_valid());
    CHECK(copied->strict_local_response_policies[0].body.ptr != owned.body.ptr);
    CHECK(copied->strict_local_response_policies[0].body.eq({"trace-rejected", 14}));
    CHECK((Str{copied->exact_strict_local_response_bindings[0].path,
               copied->exact_strict_local_response_bindings[0].path_len}
               .eq({"/static", 7})));

    // A forged full-table transaction is rejected before any destination byte
    // changes, even though the module also contains an upstream and route.
    auto forged = program.rir.module;
    forged.pre_route_policy_ids[kRouteMethodAny] = 1;
    auto destination = std::make_unique<RouteConfig>();
    REQUIRE(destination->add_static("/kept", kRouteMethodGet, 207));
    std::vector<u8> before(sizeof(RouteConfig));
    __builtin_memcpy(before.data(), destination.get(), sizeof(RouteConfig));
    CHECK_FALSE(populate_route_config(*destination, forged));
    CHECK_EQ(__builtin_memcmp(before.data(), destination.get(), sizeof(RouteConfig)), 0);

    // Compiler arena storage can disappear while the installed RouteConfig
    // remains valid and independently owned.
    program.rir.destroy();
    REQUIRE(program.config.strict_local_response_table_is_valid());
    CHECK_EQ(program.config.pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK(program.config.strict_local_response_policies[0].reason.eq({"Not Allowed", 11}));
    CHECK(program.config.strict_local_response_policies[0].body.eq({"trace-rejected", 14}));
    CHECK((Str{program.config.exact_strict_local_response_bindings[0].path,
               program.config.exact_strict_local_response_bindings[0].path_len}
               .eq({"/static", 7})));

    // The independently copied table likewise survives all LoadedProgram
    // compiler/config storage destruction.
    program.destroy();
    REQUIRE(copied->strict_local_response_table_is_valid());
    CHECK_EQ(copied->pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK(copied->strict_local_response_policies[0].reason.eq({"Not Allowed", 11}));
    CHECK(copied->strict_local_response_policies[0].body.eq({"trace-rejected", 14}));
    CHECK((Str{copied->exact_strict_local_response_bindings[0].path,
               copied->exact_strict_local_response_bindings[0].path_len}
               .eq({"/static", 7})));
}

TEST(serve_loader, no_pre_route_source_keeps_pre_route_table_neutral) {
    const std::string path = write_file(
        "/tmp/rut_serve_loader_pre_route_neutral",
        "app.rut",
        "unmatched OPTIONS { return local_response({ version: \"HTTP/1.1\", status: 400, "
        "reason: \"Bad Request\", server: \"rut\", date: \"current\", content_type: "
        "\"text/plain\", connection: \"request\", head_mode: \"reject\", body: b\"x\" }) }\n"
        "route exact GET \"/static\" { return local_response({ version: \"HTTP/1.1\", "
        "status: 400, reason: \"Bad Request\", server: \"rut\", date: \"current\", "
        "content_type: \"text/plain\", connection: \"request\", head_mode: \"reject\", "
        "body: b\"y\" }) }\n");
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
        CHECK_EQ(program.rir.module.pre_route_policy_ids[slot], 0u);
        CHECK_EQ(program.config.pre_route_policy_ids[slot], 0u);
    }
    CHECK_FALSE(program.config.has_pre_route_metadata());
    REQUIRE(program.config.strict_local_response_table_is_valid());
    program.destroy();
}

TEST(serve_loader, verified_deferred_preflight_route_owns_identity_after_compiler_destruction) {
    const std::string path =
        write_file("/tmp/rut_serve_loader_deferred_preflight", "app.rut", kDeferredPreflightSource);
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE_EQ(program.rir.module.func_count, 1u);
    REQUIRE_EQ(program.config.route_count, 1u);
    CHECK_EQ(program.rir.module.functions[0].forward_preflight_mode,
             ForwardPreflightMode::AfterCanonicalSelection);
    CHECK_EQ(program.rir.module.functions[0].preflight_forward_policy_bundle_id, 1u);
    const auto& route = program.config.routes[0];
    CHECK_EQ(route.forward_preflight_mode, ForwardPreflightMode::AfterCanonicalSelection);
    CHECK_EQ(route.preflight_forward_policy_bundle_id, 1u);
    CHECK_EQ(route.method, kRouteMethodGet);
    REQUIRE(route.fn != nullptr);
    REQUIRE_EQ(program.config.policy_bundle_count, 1u);
    CHECK_EQ(program.config.policy_bundles[0].response_buffering,
             ForwardResponseBufferingMode::CompleteContentLength);

    // Native/legacy APIs cannot opt into deferred execution even when handed a
    // superficially valid bundle. Only verified RIR publication can do so.
    auto native = std::make_unique<RouteConfig>();
    REQUIRE(native->add_response_policy(program.config.response_policies[0]) == 1u);
    REQUIRE(native->add_failure_policy(program.config.failure_policies[0]) == 1u);
    REQUIRE(native->add_failure_policy(program.config.failure_policies[1]) == 2u);
    REQUIRE(native->add_policy_bundle(
                1, 1, 2, 1, ForwardResponseBufferingMode::CompleteContentLength) == 1u);
    CHECK_FALSE(native->add_jit_handler(
        "/", kRouteMethodGet, route.fn, false, ForwardPreflightMode::AfterCanonicalSelection, 1));

    program.rir.destroy();
    CHECK_EQ(program.config.routes[0].forward_preflight_mode,
             ForwardPreflightMode::AfterCanonicalSelection);
    CHECK_EQ(program.config.routes[0].preflight_forward_policy_bundle_id, 1u);
    CHECK(program.config.redirect_policies[0].static_authority.eq({"redirect.example", 16}));
    CHECK(program.config.redirect_policies[0].target_path.eq({"/new", 4}));
    CHECK(program.config.redirect_policies[0].body.eq({"fixed", 5}));
    program.destroy();
}

TEST(serve_loader, fixed_302_source_deletion_preserves_owned_policy_and_jit_route) {
    const char source[] = R"rut(
route GET "/old" { return redirect({scheme: "http", authority: "static",
  static_authority: "redirect.example", port: "omit", path: "static",
  query: "discard", date: "current", connection: "close",
  header_order: "connection_then_location", status: 302,
  reason: "Moved Temporarily", server: "wire-test", content_type: "text/html",
  target_path: "/new", body: b"fixed-302"}) }
)rut";
    const std::string path = write_file("/tmp/rut_serve_loader_fixed_302", "app.rut", source);
    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    REQUIRE(std::filesystem::remove(path));
    CHECK_FALSE(std::filesystem::exists(path));
    REQUIRE_EQ(program.rir.module.redirect_policy_count, 1u);
    REQUIRE_EQ(program.config.redirect_policy_count, 1u);
    REQUIRE_EQ(program.config.route_count, 1u);
    REQUIRE(program.config.redirect_policy_id_is_valid(1));
    const auto& lowered = program.rir.module.redirect_policies[0];
    const auto& owned = program.config.redirect_policies[0];
    CHECK_EQ(owned.status_code, 302u);
    CHECK(owned.reason.eq({"Moved Temporarily", 17}));
    CHECK(owned.static_authority.eq({"redirect.example", 16}));
    CHECK(owned.body.eq({"fixed-302", 9}));
    CHECK_NE(owned.reason.ptr, lowered.reason.ptr);
    CHECK_NE(owned.static_authority.ptr, lowered.static_authority.ptr);
    CHECK_NE(owned.body.ptr, lowered.body.ptr);
    REQUIRE_EQ(program.config.routes[0].action, RouteAction::JitHandler);
    REQUIRE(program.config.routes[0].fn != nullptr);
    program.rir.destroy();
    REQUIRE(program.config.redirect_policy_id_is_valid(1));
    CHECK(program.config.redirect_policies[0].reason.eq({"Moved Temporarily", 17}));
    CHECK(program.config.redirect_policies[0].body.eq({"fixed-302", 9}));
    program.destroy();

    const char invalid_source[] = R"rut(
route GET "/old" { return redirect({scheme: "http", authority: "static",
  static_authority: "redirect.example", port: "omit", path: "static",
  query: "discard", date: "current", connection: "close",
  header_order: "connection_then_location", status: 303,
  reason: "See Other", server: "wire-test", content_type: "text/html",
  target_path: "/new", body: b"fixed-303"}) }
)rut";
    const std::string invalid_path =
        write_file("/tmp/rut_serve_loader_fixed_303", "app.rut", invalid_source);
    LoadedProgram rejected;
    LoadError rejected_error;
    CHECK_FALSE(load_rut_program(invalid_path.c_str(), rejected, rejected_error));
    CHECK_EQ(rejected.config.redirect_policy_count, 0u);
    CHECK_EQ(rejected.config.route_count, 0u);
    CHECK_FALSE(rejected.jit_inited);
    CHECK_EQ(rejected.rir.module.redirect_policy_count, 0u);
    rejected.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
