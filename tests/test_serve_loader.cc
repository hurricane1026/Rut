// Tests for the .rut program loader (src/serve_loader.cc): the bridge that
// compiles a source file end to end (lex -> parse -> analyze -> MIR -> RIR ->
// JIT) into a RouteConfig, plus its fail-closed error reporting.

#include "deferred_preflight_fixture.h"
#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/listener.h"
#include "rut/runtime/route_method.h"
#include "rut/serve_loader.h"
#include "test.h"
#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/ws_terminate.h"  // WsMessageHandlerFn / WsFrameAction / WsOpcode
#endif
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <arpa/inet.h>
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

TEST(serve_loader, failed_listener_parse_resets_poisoned_endpoint_and_owner_is_reusable) {
    const std::string dir = "/tmp/rut_serve_loader_failed_listener_reset";
    const std::string path =
        write_file(dir, "app.rut", "listen 127.0.0.1 :80\nroute GET \"/\" { return 200 }\n");

    LoadedProgram program;
    program.has_listener = true;
    program.listener = {ListenerAddress::IPv4Exact, ListenerTransport::Tls, 9443u, 0xcb007109u};
    LoadError err;
    CHECK_FALSE(load_rut_program(path.c_str(), program, err));
    CHECK(err.stage == LoadStage::Parse);
    CHECK(err.has_diag);
    REQUIRE(program.src_map != nullptr);
    CHECK_GT(program.src_map_len, 0u);
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);

    // A failed load owns its mapped source until the caller releases the
    // partial program. Clean it before reusing the same owner.
    program.destroy();
    CHECK(program.src_map == nullptr);
    CHECK_EQ(program.src_map_len, 0u);

    write_file(dir,
               "app.rut",
               "listen 203.0.113.9:65535\n"
               "route GET \"/\" { return 200 }\n");
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 65535u);
    CHECK_EQ(program.listener.ipv4_host, 0xcb007109u);
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, exact_ipv4_listener_metadata_survives_frontend_and_source_lifetimes) {
    const std::string dir = "/tmp/rut_serve_loader_exact_listener";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "listen 127.0.0.1:0\n"
                                        "route GET \"/\" { return 200 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 0u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    REQUIRE_EQ(program.config.route_count, 1u);

    // load_rut_program has already destroyed AST/HIR/MIR. Remove every remaining
    // compiler/source owner and prove the process-start endpoint is an inline,
    // owned ListenerSpec rather than a view into any of them.
    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 0u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);

    program.destroy();
    CHECK(!program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);

    // Reuse the same owner for the legacy spelling. Load entry and HIR copy must
    // replace, not retain, the prior exact address metadata.
    write_file(dir,
               "app.rut",
               "listen :0\n"
               "route GET \"/\" { return 200 }\n");
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 0u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, nginx_exact_loopback_generated_source_owns_listener_and_reuses_cleanly) {
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_listener";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8080; "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    REQUIRE_EQ(program.config.route_count, 3u);
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    program.destroy();

    {
        char nginx_source[] =
            "server { listen *:8081; "
            "location / { proxy_pass http://127.0.0.1:9001; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'z');
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8081u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, nginx_exact_loopback_no_content_output_is_owned_and_reuses_cleanly) {
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_no_content";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8080; "
            "location = /static { return 204; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError err;
    const auto check_root_forward_inventory = [&](u16 expected_backend_port) {
        REQUIRE_EQ(program.config.route_count, 3u);
        u32 head_count = 0u;
        u32 get_count = 0u;
        u32 any_count = 0u;
        for (u32 i = 0u; i < program.config.route_count; i++) {
            const RouteEntry& route = program.config.routes[i];
            CHECK_EQ(route.path_len, 1u);
            CHECK_EQ(route.path[0], '/');
            CHECK(route.action == RouteAction::JitHandler);
            CHECK_FALSE(route.needs_req_body);
            if (route.method == kRouteMethodHead) head_count++;
            if (route.method == kRouteMethodGet) get_count++;
            if (route.method == kRouteMethodAny) any_count++;
        }
        CHECK_EQ(head_count, 1u);
        CHECK_EQ(get_count, 1u);
        CHECK_EQ(any_count, 1u);

        static constexpr u8 kRoot[] = {'/'};
        const RouteEntry* head = program.config.match(kRoot, 1u, kRouteMethodHead);
        const RouteEntry* get = program.config.match(kRoot, 1u, kRouteMethodGet);
        const RouteEntry* post = program.config.match(kRoot, 1u, kRouteMethodPost);
        REQUIRE(head != nullptr);
        REQUIRE(get != nullptr);
        REQUIRE(post != nullptr);
        CHECK_NE(head, get);
        CHECK_NE(head, post);
        CHECK_NE(get, post);
        CHECK_EQ(head->method, kRouteMethodHead);
        CHECK_EQ(get->method, kRouteMethodGet);
        CHECK_EQ(post->method, kRouteMethodAny);
        CHECK(head->action == RouteAction::JitHandler);
        CHECK(get->action == RouteAction::JitHandler);
        CHECK(post->action == RouteAction::JitHandler);

        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7f000001u);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_backend_port);
    };
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_root_forward_inventory(9000u);
    REQUIRE_EQ(program.config.exact_strict_local_response_binding_count, 1u);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    CHECK_NE(program.config.pre_route_policy_id(kRouteMethodTrace), 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodOptions], 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodConnect], 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodAny], 0u);
    const auto exact = program.config.match_exact_strict_local_response_views(
        lit_str("/static"), lit_str("/static"), kRouteMethodGet);
    REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
    REQUIRE(program.config.strict_local_response_policy_id_is_owned(exact.policy_id));
    const auto& policy = program.config.strict_local_response_policies[exact.policy_id - 1u];
    CHECK_EQ(strict_local_response_policy_profile(policy),
             StrictLocalResponseProfile::NoContent204);
    CHECK_EQ(policy.status_code, 204u);
    CHECK(policy.reason.eq(lit_str("No Content")));
    CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK_EQ(policy.content_type.len, 0u);
    CHECK_EQ(policy.body.len, 0u);
    CHECK(program.config.strict_local_response_bytes_owned(policy.content_type));
    CHECK(program.config.strict_local_response_bytes_owned(policy.body));

    // Remove every source/frontend owner while preserving the process-owned
    // endpoint, routing table and normalized exact action.
    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_root_forward_inventory(9000u);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    const auto retained = program.config.match_exact_strict_local_response_views(
        lit_str("/static"), lit_str("/static"), kRouteMethodGet);
    REQUIRE(retained.state == ExactStrictLocalResponseMatchState::Match);
    REQUIRE(program.config.strict_local_response_policy_id_is_owned(retained.policy_id));
    CHECK_EQ(strict_local_response_policy_profile(
                 program.config.strict_local_response_policies[retained.policy_id - 1u]),
             StrictLocalResponseProfile::NoContent204);

    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.exact_strict_local_response_binding_count, 0u);

    // Reuse the same owner for a converter-generated wildcard root proxy with
    // no exact action; neither address nor action inventory may survive.
    {
        char nginx_source[] =
            "server { listen *:8081; "
            "location / { proxy_pass http://127.0.0.1:9001; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'z', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'w');
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8081u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.exact_strict_local_response_binding_count, 0u);
    CHECK_FALSE(program.config.has_exact_strict_local_response_inventory());
    check_root_forward_inventory(9001u);
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, nginx_exact_loopback_bodyful_output_is_owned_and_reuses_cleanly) {
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_bodyful";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8082; "
            "location = /static { return 200 \"successor-static\"; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError err;
    const auto check_root_inventory = [&](u16 expected_backend_port) {
        REQUIRE_EQ(program.config.route_count, 3u);
        u32 head_count = 0u;
        u32 get_count = 0u;
        u32 any_count = 0u;
        for (u32 i = 0u; i < program.config.route_count; i++) {
            const RouteEntry& route = program.config.routes[i];
            CHECK_EQ(route.path_len, 1u);
            CHECK_EQ(route.path[0], '/');
            CHECK(route.action == RouteAction::JitHandler);
            CHECK_FALSE(route.needs_req_body);
            if (route.method == kRouteMethodHead) head_count++;
            if (route.method == kRouteMethodGet) get_count++;
            if (route.method == kRouteMethodAny) any_count++;
        }
        CHECK_EQ(head_count, 1u);
        CHECK_EQ(get_count, 1u);
        CHECK_EQ(any_count, 1u);
        static constexpr u8 kRoot[] = {'/'};
        const RouteEntry* head = program.config.match(kRoot, 1u, kRouteMethodHead);
        const RouteEntry* get = program.config.match(kRoot, 1u, kRouteMethodGet);
        const RouteEntry* post = program.config.match(kRoot, 1u, kRouteMethodPost);
        REQUIRE(head != nullptr);
        REQUIRE(get != nullptr);
        REQUIRE(post != nullptr);
        CHECK_EQ(head->method, kRouteMethodHead);
        CHECK_EQ(get->method, kRouteMethodGet);
        CHECK_EQ(post->method, kRouteMethodAny);
        CHECK_NE(head, get);
        CHECK_NE(head, post);
        CHECK_NE(get, post);

        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7f000001u);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_backend_port);
    };
    const auto check_exact_bodyful = [&] {
        REQUIRE_EQ(program.config.exact_strict_local_response_binding_count, 1u);
        REQUIRE(program.config.strict_local_response_table_is_valid());
        const auto exact = program.config.match_exact_strict_local_response_views(
            lit_str("/static"), lit_str("/static"), kRouteMethodGet);
        REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
        REQUIRE(program.config.strict_local_response_policy_id_is_owned(exact.policy_id));
        const auto& binding = program.config.exact_strict_local_response_bindings[0];
        CHECK_EQ(binding.method, kRouteMethodAny);
        CHECK_EQ(binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{binding.path, binding.path_len}.eq(lit_str("/static"))));
        const auto& policy = program.config.strict_local_response_policies[exact.policy_id - 1u];
        CHECK_EQ(strict_local_response_policy_profile(policy),
                 StrictLocalResponseProfile::Representation200);
        CHECK_EQ(policy.status_code, 200u);
        CHECK(policy.version == StrictLocalResponseVersion::Http11);
        CHECK(policy.reason.eq(lit_str("OK")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.date == StrictLocalResponseDate::Current);
        CHECK(policy.content_type.eq(lit_str("text/plain")));
        CHECK(policy.connection == StrictLocalResponseConnection::Request);
        CHECK(policy.head_mode == StrictLocalResponseHeadMode::SuppressBody);
        CHECK(policy.body.eq(lit_str("successor-static")));
        CHECK(program.config.strict_local_response_bytes_owned(policy.reason));
        CHECK(program.config.strict_local_response_bytes_owned(policy.server));
        CHECK(program.config.strict_local_response_bytes_owned(policy.content_type));
        CHECK(program.config.strict_local_response_bytes_owned(policy.body));
        CHECK(program.config
                  .match_exact_strict_local_response_views(
                      lit_str("/"), lit_str("/"), kRouteMethodGet)
                  .state == ExactStrictLocalResponseMatchState::Miss);
    };

    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8082u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    CHECK_NE(program.config.pre_route_policy_id(kRouteMethodTrace), 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodOptions], 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodConnect], 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodAny], 0u);
    check_root_inventory(9000u);
    check_exact_bodyful();

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 8082u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_root_inventory(9000u);
    check_exact_bodyful();

    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.exact_strict_local_response_binding_count, 0u);

    {
        char nginx_source[] =
            "server { listen *:8083; "
            "location / { proxy_pass http://127.0.0.1:9001; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'z', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'w');
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8083u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.exact_strict_local_response_binding_count, 0u);
    CHECK_FALSE(program.config.has_exact_strict_local_response_inventory());
    // TRACE and CONNECT share the same owned 405 policy; OPTIONS and the
    // method-omitted fallback own the two distinct 400 profiles.
    REQUIRE_EQ(program.config.strict_local_response_policy_count, 3u);
    REQUIRE(program.config.strict_local_response_table_is_valid());
    for (u32 i = 0u; i < program.config.strict_local_response_policy_count; i++) {
        const auto& policy = program.config.strict_local_response_policies[i];
        CHECK_NE(strict_local_response_policy_profile(policy),
                 StrictLocalResponseProfile::Representation200);
        CHECK_FALSE(policy.body.eq(lit_str("successor-static")));
    }
    check_root_inventory(9001u);
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, nginx_exact_loopback_fixed_302_output_is_owned_and_reuses_cleanly) {
    static constexpr char kRedirectBody[] =
        "<html>\r\n"
        "<head><title>302 Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>302 Found</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kRedirectBody) - 1u == 145u);
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_302";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8084; "
            "location = /old { return 302 http://redirect.example/new; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        REQUIRE_EQ(lowered.value().len, 5913u);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError error;
    const auto check_root_inventory = [&](u16 expected_backend_port) {
        REQUIRE_EQ(program.config.route_count, 3u);
        u32 head_count = 0u;
        u32 get_count = 0u;
        u32 any_count = 0u;
        for (u32 i = 0u; i < program.config.route_count; i++) {
            const RouteEntry& route = program.config.routes[i];
            CHECK_EQ(route.path_len, 1u);
            CHECK_EQ(route.path[0], '/');
            CHECK(route.action == RouteAction::JitHandler);
            CHECK_FALSE(route.needs_req_body);
            if (route.method == kRouteMethodHead) head_count++;
            if (route.method == kRouteMethodGet) get_count++;
            if (route.method == kRouteMethodAny) any_count++;
        }
        CHECK_EQ(head_count, 1u);
        CHECK_EQ(get_count, 1u);
        CHECK_EQ(any_count, 1u);
        static constexpr u8 kRoot[] = {'/'};
        const RouteEntry* head = program.config.match(kRoot, 1u, kRouteMethodHead);
        const RouteEntry* get = program.config.match(kRoot, 1u, kRouteMethodGet);
        const RouteEntry* post = program.config.match(kRoot, 1u, kRouteMethodPost);
        REQUIRE(head != nullptr);
        REQUIRE(get != nullptr);
        REQUIRE(post != nullptr);
        CHECK_EQ(head->method, kRouteMethodHead);
        CHECK_EQ(get->method, kRouteMethodGet);
        CHECK_EQ(post->method, kRouteMethodAny);
        CHECK_NE(head, get);
        CHECK_NE(head, post);
        CHECK_NE(get, post);

        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7f000001u);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_backend_port);
    };
    const auto find_linked_redirect_policy_id = [&](u16& policy_id) {
        policy_id = 0u;
        u32 redirect_returns = 0u;
        for (u32 i = 0u; i < program.rir.module.func_count; i++) {
            const auto& function = program.rir.module.functions[i];
            if (function.http_method != kRouteMethodGet || !function.route_pattern.eq(lit_str("/")))
                continue;
            for (u32 block = 0u; block < function.block_count; block++) {
                for (u32 instruction = 0u; instruction < function.blocks[block].inst_count;
                     instruction++) {
                    const auto& inst = function.blocks[block].insts[instruction];
                    if (inst.op != rir::Opcode::RetRedirect) continue;
                    redirect_returns++;
                    REQUIRE_GT(inst.imm.i32_val, 0);
                    REQUIRE_LE(static_cast<u32>(inst.imm.i32_val),
                               program.rir.module.redirect_policy_count);
                    policy_id = static_cast<u16>(inst.imm.i32_val);
                }
            }
        }
        REQUIRE_EQ(redirect_returns, 1u);
        REQUIRE_NE(policy_id, 0u);
        REQUIRE(program.config.redirect_policy_id_is_valid(policy_id));
    };
    const auto check_redirect = [&](u16 policy_id) {
        REQUIRE(program.config.redirect_policy_id_is_valid(policy_id));
        const auto& policy = program.config.redirect_policies[policy_id - 1u];
        CHECK(program.config.redirect_policy_strings_are_owned(policy));
        CHECK(policy.scheme == RedirectPolicyScheme::Http);
        CHECK(policy.authority == RedirectPolicyAuthority::Static);
        CHECK(policy.port == RedirectPolicyPort::Omit);
        CHECK(policy.path == RedirectPolicyPath::Static);
        CHECK(policy.query == RedirectPolicyQuery::Discard);
        CHECK(policy.date == RedirectPolicyDate::Current);
        CHECK(policy.connection == RedirectPolicyConnection::Close);
        CHECK(policy.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
        CHECK_EQ(policy.status_code, 302u);
        CHECK(policy.reason.eq(lit_str("Moved Temporarily")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK(policy.static_authority.eq(lit_str("redirect.example")));
        CHECK(policy.target_path.eq(lit_str("/new")));
        CHECK(policy.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u}));
    };

    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8084u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    CHECK_NE(program.config.pre_route_policy_id(kRouteMethodTrace), 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodOptions], 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodConnect], 0u);
    CHECK_NE(program.config.unmatched_policy_ids[kRouteMethodAny], 0u);
    REQUIRE_EQ(program.rir.module.redirect_policy_count, 1u);
    REQUIRE_EQ(program.config.redirect_policy_count, 1u);
    check_root_inventory(9000u);
    u16 redirect_policy_id = 0u;
    find_linked_redirect_policy_id(redirect_policy_id);
    check_redirect(redirect_policy_id);

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0u;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 8084u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_root_inventory(9000u);
    check_redirect(redirect_policy_id);

    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);

    {
        char nginx_source[] =
            "server { listen *:8085; "
            "location / { proxy_pass http://127.0.0.1:9001; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'z', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'w');
    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8085u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.rir.module.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);
    for (const auto& stale : program.config.redirect_policies) {
        CHECK(stale.scheme == RedirectPolicyScheme::Invalid);
        CHECK(stale.authority == RedirectPolicyAuthority::Invalid);
        CHECK(stale.port == RedirectPolicyPort::Invalid);
        CHECK(stale.path == RedirectPolicyPath::Invalid);
        CHECK(stale.query == RedirectPolicyQuery::Invalid);
        CHECK(stale.date == RedirectPolicyDate::Invalid);
        CHECK(stale.connection == RedirectPolicyConnection::Invalid);
        CHECK(stale.header_order == RedirectPolicyHeaderOrder::Invalid);
        CHECK_EQ(stale.status_code, 0u);
        CHECK(stale.reason.ptr == nullptr);
        CHECK_EQ(stale.reason.len, 0u);
        CHECK(stale.server.ptr == nullptr);
        CHECK_EQ(stale.server.len, 0u);
        CHECK(stale.content_type.ptr == nullptr);
        CHECK_EQ(stale.content_type.len, 0u);
        CHECK(stale.static_authority.ptr == nullptr);
        CHECK_EQ(stale.static_authority.len, 0u);
        CHECK(stale.target_path.ptr == nullptr);
        CHECK_EQ(stale.target_path.len, 0u);
        CHECK(stale.body.ptr == nullptr);
        CHECK_EQ(stale.body.len, 0u);
    }
    check_root_inventory(9001u);
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, issue351_exact_5945_byte_redirect_output_is_owned_and_reuses_cleanly) {
    static constexpr char kRedirectBody[] =
        "<html>\r\n"
        "<head><title>301 Moved Permanently</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>301 Moved Permanently</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kRedirectBody) - 1u == 169u);
    char nginx_source[] =
        "server { listen 127.0.0.1:65535; location / { proxy_pass "
        "http://255.255.255.255:65535; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
    REQUIRE(parsed);
    auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    REQUIRE_EQ(lowered.value().len, 5945u);
    REQUIRE_EQ(lowered.value().len + 1u, nginx::RutSource::kCapacity);
    REQUIRE_EQ(lowered.value().data[lowered.value().len], '\0');
    std::string generated(lowered.value().data, lowered.value().len);
    REQUIRE_EQ(generated.rfind("listen 127.0.0.1:65535\n", 0u), 0u);
    memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

    const std::string dir = "/tmp/rut_serve_loader_issue351_exact_301";
    const std::string path = write_file(dir, "app.rut", generated.c_str());
    REQUIRE_EQ(std::filesystem::file_size(path), 5945u);
    std::fill(generated.begin(), generated.end(), 'y');
    memset(lowered.value().data, 'z', lowered.value().len);
    lowered.value().len = 0u;
    LoadedProgram program;
    LoadError error;
    const auto check_root_inventory = [&](u32 expected_address, u16 expected_port) {
        REQUIRE_EQ(program.config.route_count, 3u);
        u32 head_count = 0u;
        u32 get_count = 0u;
        u32 any_count = 0u;
        for (u32 i = 0u; i < program.config.route_count; i++) {
            const RouteEntry& route = program.config.routes[i];
            CHECK_EQ(route.path_len, 1u);
            CHECK_EQ(route.path[0], '/');
            CHECK(route.action == RouteAction::JitHandler);
            CHECK_FALSE(route.needs_req_body);
            if (route.method == kRouteMethodHead) head_count++;
            if (route.method == kRouteMethodGet) get_count++;
            if (route.method == kRouteMethodAny) any_count++;
        }
        CHECK_EQ(head_count, 1u);
        CHECK_EQ(get_count, 1u);
        CHECK_EQ(any_count, 1u);
        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), expected_address);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_port);
    };
    REQUIRE(load_rut_program(path.c_str(), program, error));
    REQUIRE(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(program.listener.port, 65535u);
    CHECK(rir::verify_module(program.rir.module).ok);
    check_root_inventory(0xffffffffu, 65535u);
    REQUIRE_EQ(program.config.redirect_policy_count, 1u);

    u16 redirect_id = 0u;
    u32 redirect_returns = 0u;
    for (u32 function = 0u; function < program.rir.module.func_count; function++) {
        const auto& rir_function = program.rir.module.functions[function];
        for (u32 block = 0u; block < rir_function.block_count; block++) {
            for (u32 instruction = 0u; instruction < rir_function.blocks[block].inst_count;
                 instruction++) {
                const auto& inst = rir_function.blocks[block].insts[instruction];
                if (inst.op != rir::Opcode::RetRedirect) continue;
                REQUIRE_GT(inst.imm.i32_val, 0);
                redirect_returns++;
                redirect_id = static_cast<u16>(inst.imm.i32_val);
            }
        }
    }
    REQUIRE_EQ(redirect_returns, 1u);
    REQUIRE(program.config.redirect_policy_id_is_valid(redirect_id));
    const auto redirect_is_owned_and_canonical = [&]() {
        if (!program.config.redirect_policy_id_is_valid(redirect_id)) return false;
        const auto& policy = program.config.redirect_policies[redirect_id - 1u];
        return program.config.redirect_policy_strings_are_owned(policy) &&
               policy.scheme == RedirectPolicyScheme::Http &&
               policy.authority == RedirectPolicyAuthority::Static &&
               policy.port == RedirectPolicyPort::Omit &&
               policy.path == RedirectPolicyPath::Static &&
               policy.query == RedirectPolicyQuery::Discard &&
               policy.date == RedirectPolicyDate::Current &&
               policy.connection == RedirectPolicyConnection::Close &&
               policy.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation &&
               policy.status_code == 301u && policy.reason.eq(lit_str("Moved Permanently")) &&
               policy.server.eq(lit_str("nginx/1.29.7")) &&
               policy.content_type.eq(lit_str("text/html")) &&
               policy.static_authority.eq(lit_str("redirect.example")) &&
               policy.target_path.eq(lit_str("/new")) &&
               policy.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u});
    };
    REQUIRE(redirect_is_owned_and_canonical());

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0u;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(program.listener.port, 65535u);
    CHECK(redirect_is_owned_and_canonical());
    check_root_inventory(0xffffffffu, 65535u);
    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);

    {
        char wildcard_source[] =
            "server { listen *:8085; location / { proxy_pass http://127.0.0.1:9001; } }";
        const auto wildcard_parsed = nginx::parse({wildcard_source, sizeof(wildcard_source) - 1u});
        REQUIRE(wildcard_parsed);
        const auto wildcard_lowered = nginx::lower_to_rut(wildcard_parsed.value());
        REQUIRE(wildcard_lowered);
        generated.assign(wildcard_lowered.value().data, wildcard_lowered.value().len);
        memset(wildcard_source, 'w', sizeof(wildcard_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'q');
    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.listener.port, 8085u);
    CHECK_EQ(program.rir.module.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);
    for (const auto& stale : program.config.redirect_policies) {
        CHECK(stale.scheme == RedirectPolicyScheme::Invalid);
        CHECK(stale.authority == RedirectPolicyAuthority::Invalid);
        CHECK(stale.port == RedirectPolicyPort::Invalid);
        CHECK(stale.path == RedirectPolicyPath::Invalid);
        CHECK(stale.query == RedirectPolicyQuery::Invalid);
        CHECK(stale.date == RedirectPolicyDate::Invalid);
        CHECK(stale.connection == RedirectPolicyConnection::Invalid);
        CHECK(stale.header_order == RedirectPolicyHeaderOrder::Invalid);
        CHECK_EQ(stale.status_code, 0u);
        for (Str value : {stale.reason,
                          stale.server,
                          stale.content_type,
                          stale.static_authority,
                          stale.target_path,
                          stale.body}) {
            CHECK(value.ptr == nullptr);
            CHECK_EQ(value.len, 0u);
        }
    }
    check_root_inventory(0x7f000001u, 9001u);
    program.destroy();
    std::filesystem::remove(path);
    std::filesystem::remove(dir);
}

TEST(serve_loader,
     nginx_exact_loopback_prefix_root_replacement_output_is_owned_and_reuses_cleanly) {
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_prefix_root_replacement";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8086; location /service/ { proxy_pass "
            "http://127.0.0.1:9000/; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        REQUIRE_EQ(lowered.value().len, 3358u);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError error;
    const auto check_upstream = [&](u16 expected_port) {
        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7f000001u);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_port);
    };
    const auto check_prefix_route = [&]() {
        REQUIRE_EQ(program.config.route_count, 1u);
        const RouteEntry& route = program.config.routes[0];
        CHECK_EQ(route.method, kRouteMethodAny);
        CHECK_EQ(route.path_len, 8u);
        CHECK((Str{reinterpret_cast<const char*>(route.path), route.path_len}.eq(
            lit_str("/service"))));
        CHECK(route.action == RouteAction::JitHandler);
        CHECK_FALSE(route.needs_req_body);
        static constexpr u8 kService[] = {'/', 's', 'e', 'r', 'v', 'i', 'c', 'e'};
        const RouteEntry* matched =
            program.config.match(kService, sizeof(kService), kRouteMethodGet);
        REQUIRE(matched != nullptr);
        CHECK_EQ(matched, &route);
    };
    const auto check_transform = [&](u16 transform_id) {
        REQUIRE(program.config.target_transform_id_is_valid(transform_id));
        const auto& transform = program.config.target_transforms[transform_id - 1u];
        CHECK(transform.strip_prefix.eq(lit_str("/service/")));
        CHECK(transform.replace_prefix.eq(lit_str("/")));
        const uintptr_t pool = reinterpret_cast<uintptr_t>(program.config.target_transform_bytes);
        const uintptr_t pool_end = pool + program.config.target_transform_bytes_used;
        for (Str value : {transform.strip_prefix, transform.replace_prefix}) {
            const uintptr_t address = reinterpret_cast<uintptr_t>(value.ptr);
            CHECK_GE(address, pool);
            CHECK_LE(address, pool_end);
            CHECK_LE(value.len, pool_end - address);
        }
    };
    const auto check_redirect = [&](u16 policy_id) {
        REQUIRE(program.config.redirect_policy_id_is_valid(policy_id));
        const auto& policy = program.config.redirect_policies[policy_id - 1u];
        CHECK(program.config.redirect_policy_strings_are_owned(policy));
        CHECK(policy.scheme == RedirectPolicyScheme::Http);
        CHECK(policy.authority == RedirectPolicyAuthority::RequestHost);
        CHECK(policy.port == RedirectPolicyPort::ActualListener);
        CHECK(policy.path == RedirectPolicyPath::Static);
        CHECK(policy.query == RedirectPolicyQuery::PreserveRaw);
        CHECK(policy.date == RedirectPolicyDate::Current);
        CHECK(policy.connection == RedirectPolicyConnection::Close);
        CHECK(policy.header_order == RedirectPolicyHeaderOrder::LocationThenConnection);
        CHECK_EQ(policy.status_code, 301u);
        CHECK(policy.reason.eq(lit_str("Moved Permanently")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK_EQ(policy.static_authority.len, 0u);
        CHECK(policy.target_path.eq(lit_str("/service/")));
        CHECK_EQ(policy.body.len, 169u);
    };
    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8086u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_upstream(9000u);
    check_prefix_route();
    REQUIRE_EQ(program.config.target_transform_count, 1u);
    REQUIRE_EQ(program.config.target_transform_bytes_used, 10u);
    REQUIRE_EQ(program.config.redirect_policy_count, 1u);
    u16 transform_id = 0u;
    u16 redirect_id = 0u;
    u32 forward_count = 0u;
    u32 redirect_count = 0u;
    REQUIRE_EQ(program.rir.module.func_count, 1u);
    CHECK(program.rir.module.functions[0].route_pattern.eq(lit_str("/service")));
    for (u32 block = 0u; block < program.rir.module.functions[0].block_count; block++) {
        const auto& rir_block = program.rir.module.functions[0].blocks[block];
        for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
            const auto& inst = rir_block.insts[instruction];
            if (inst.op == rir::Opcode::RetRedirect) {
                redirect_count++;
                REQUIRE_GT(inst.imm.i32_val, 0);
                REQUIRE_LE(static_cast<u32>(inst.imm.i32_val),
                           program.rir.module.redirect_policy_count);
                redirect_id = static_cast<u16>(inst.imm.i32_val);
            }
            if (inst.op != rir::Opcode::RetForwardBundle) continue;
            forward_count++;
            REQUIRE_GT(instruction, 0u);
            const auto& transform = rir_block.insts[instruction - 1u];
            REQUIRE(transform.op == rir::Opcode::ReqSetTargetTransform);
            REQUIRE_GT(transform.imm.i32_val, 0);
            REQUIRE_LE(static_cast<u32>(transform.imm.i32_val),
                       program.rir.module.target_transform_count);
            transform_id = static_cast<u16>(transform.imm.i32_val);
        }
    }
    REQUIRE_EQ(redirect_count, 1u);
    REQUIRE_EQ(forward_count, 1u);
    REQUIRE_NE(redirect_id, 0u);
    REQUIRE_NE(transform_id, 0u);
    check_transform(transform_id);
    check_redirect(redirect_id);

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0u;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 8086u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_upstream(9000u);
    check_prefix_route();
    check_transform(transform_id);
    check_redirect(redirect_id);

    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.target_transform_count, 0u);
    CHECK_EQ(program.config.target_transform_bytes_used, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);

    {
        char nginx_source[] =
            "server { listen *:8087; location / { proxy_pass http://127.0.0.1:9001; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'z', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'w');
    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8087u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    REQUIRE_EQ(program.config.route_count, 3u);
    for (u32 i = 0u; i < program.config.route_count; i++) {
        CHECK_EQ(program.config.routes[i].path_len, 1u);
        CHECK_EQ(program.config.routes[i].path[0], '/');
    }
    check_upstream(9001u);
    CHECK_EQ(program.rir.module.target_transform_count, 0u);
    CHECK_EQ(program.config.target_transform_count, 0u);
    CHECK_EQ(program.config.target_transform_bytes_used, 0u);
    for (const auto& stale : program.config.target_transforms) {
        CHECK(stale.strip_prefix.ptr == nullptr);
        CHECK_EQ(stale.strip_prefix.len, 0u);
        CHECK(stale.replace_prefix.ptr == nullptr);
        CHECK_EQ(stale.replace_prefix.len, 0u);
    }
    CHECK_EQ(program.rir.module.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);
    for (const auto& stale : program.config.redirect_policies) {
        CHECK(stale.scheme == RedirectPolicyScheme::Invalid);
        CHECK(stale.authority == RedirectPolicyAuthority::Invalid);
        CHECK(stale.port == RedirectPolicyPort::Invalid);
        CHECK(stale.path == RedirectPolicyPath::Invalid);
        CHECK(stale.query == RedirectPolicyQuery::Invalid);
        CHECK(stale.date == RedirectPolicyDate::Invalid);
        CHECK(stale.connection == RedirectPolicyConnection::Invalid);
        CHECK(stale.header_order == RedirectPolicyHeaderOrder::Invalid);
        CHECK_EQ(stale.status_code, 0u);
        for (Str value : {stale.reason,
                          stale.server,
                          stale.content_type,
                          stale.static_authority,
                          stale.target_path,
                          stale.body}) {
            CHECK(value.ptr == nullptr);
            CHECK_EQ(value.len, 0u);
        }
    }
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, nginx_exact_loopback_fixed_replacement_output_is_owned_and_reuses_cleanly) {
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_fixed_replacement";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8088; location /api/ { proxy_pass "
            "http://127.0.0.1:9002/v1/; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        REQUIRE_EQ(lowered.value().len, 3345u);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError error;
    const auto check_upstream = [&](u16 expected_port) {
        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7f000001u);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_port);
    };
    const auto check_prefix_route = [&]() {
        REQUIRE_EQ(program.config.route_count, 1u);
        const RouteEntry& route = program.config.routes[0];
        CHECK_EQ(route.method, kRouteMethodAny);
        CHECK_EQ(route.path_len, 4u);
        CHECK((Str{reinterpret_cast<const char*>(route.path), route.path_len}.eq(lit_str("/api"))));
        CHECK(route.action == RouteAction::JitHandler);
        CHECK_FALSE(route.needs_req_body);
        static constexpr u8 kApi[] = {'/', 'a', 'p', 'i'};
        const RouteEntry* matched = program.config.match(kApi, sizeof(kApi), kRouteMethodGet);
        REQUIRE(matched != nullptr);
        CHECK_EQ(matched, &route);
    };
    const auto check_transform = [&](u16 transform_id) {
        REQUIRE(program.config.target_transform_id_is_valid(transform_id));
        const auto& transform = program.config.target_transforms[transform_id - 1u];
        CHECK(transform.strip_prefix.eq(lit_str("/api/")));
        CHECK(transform.replace_prefix.eq(lit_str("/v1/")));
        const uintptr_t pool = reinterpret_cast<uintptr_t>(program.config.target_transform_bytes);
        const uintptr_t pool_end = pool + program.config.target_transform_bytes_used;
        for (Str value : {transform.strip_prefix, transform.replace_prefix}) {
            const uintptr_t address = reinterpret_cast<uintptr_t>(value.ptr);
            CHECK_GE(address, pool);
            CHECK_LE(address, pool_end);
            CHECK_LE(value.len, pool_end - address);
        }
    };
    const auto check_redirect = [&](u16 policy_id) {
        REQUIRE(program.config.redirect_policy_id_is_valid(policy_id));
        const auto& policy = program.config.redirect_policies[policy_id - 1u];
        CHECK(program.config.redirect_policy_strings_are_owned(policy));
        CHECK(policy.scheme == RedirectPolicyScheme::Http);
        CHECK(policy.authority == RedirectPolicyAuthority::RequestHost);
        CHECK(policy.port == RedirectPolicyPort::ActualListener);
        CHECK(policy.path == RedirectPolicyPath::Static);
        CHECK(policy.query == RedirectPolicyQuery::PreserveRaw);
        CHECK(policy.date == RedirectPolicyDate::Current);
        CHECK(policy.connection == RedirectPolicyConnection::Close);
        CHECK(policy.header_order == RedirectPolicyHeaderOrder::LocationThenConnection);
        CHECK_EQ(policy.status_code, 301u);
        CHECK(policy.reason.eq(lit_str("Moved Permanently")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK_EQ(policy.static_authority.len, 0u);
        CHECK(policy.target_path.eq(lit_str("/api/")));
        CHECK_EQ(policy.body.len, 169u);
    };
    const auto str_is_owned_by = [](Str value, const char* pool, u32 used) {
        if (value.ptr == nullptr || value.len == 0u || value.len > used) return false;
        const uintptr_t begin = reinterpret_cast<uintptr_t>(pool);
        const uintptr_t address = reinterpret_cast<uintptr_t>(value.ptr);
        return address >= begin && address - begin < used && value.len <= used - (address - begin);
    };
    const auto check_forward_policies = [&](u16 request_policy_id, u16 bundle_id) {
        CHECK_EQ(request_policy_id, static_cast<u16>(RequestPolicyId::Http11FixedStrip));
        CHECK(request_policy_is_supported(request_policy_id));
        REQUIRE(program.config.policy_bundle_id_is_valid(bundle_id));
        const auto& bundle = program.config.policy_bundles[bundle_id - 1u];
        REQUIRE(program.config.response_policy_id_is_valid(bundle.response_policy_id));
        REQUIRE(program.config.failure_policy_id_is_valid(bundle.failure_policy_id));
        CHECK_EQ(bundle.timeout_failure_policy_id, 0u);
        CHECK_EQ(bundle.response_read_timeout_seconds, 0u);
        CHECK(bundle.response_buffering == ForwardResponseBufferingMode::None);
        REQUIRE_EQ(program.config.response_policy_count, 1u);
        REQUIRE_EQ(program.config.failure_policy_count, 1u);

        const auto& response = program.config.response_policies[bundle.response_policy_id - 1u];
        CHECK(response.version == ResponsePolicyVersion::Http11);
        CHECK(response.framing == ResponsePolicyFraming::ContentLength);
        CHECK(response.connection == ResponsePolicyConnection::Request);
        CHECK(response.date == ResponsePolicyDate::Current);
        CHECK(response.head_mode == ResponsePolicyHeadMode::Reject);
        CHECK(response.server.eq(lit_str("nginx/1.29.7")));
        CHECK(str_is_owned_by(response.server,
                              program.config.response_policy_bytes,
                              program.config.response_policy_bytes_used));
        REQUIRE_EQ(response.hide_header_count, 3u);
        static constexpr Str kHidden[] = {lit_str("Date"), lit_str("Server"), lit_str("X-Pad")};
        for (u32 i = 0u; i < response.hide_header_count; i++) {
            CHECK(response.hide_headers[i].eq(kHidden[i]));
            CHECK(str_is_owned_by(response.hide_headers[i],
                                  program.config.response_policy_bytes,
                                  program.config.response_policy_bytes_used));
        }
        for (u32 i = response.hide_header_count; i < kMaxResponsePolicyHideHeaders; i++) {
            CHECK(response.hide_headers[i].ptr == nullptr);
            CHECK_EQ(response.hide_headers[i].len, 0u);
        }

        const auto& failure = program.config.failure_policies[bundle.failure_policy_id - 1u];
        CHECK(failure.version == ForwardFailurePolicyVersion::Http11);
        CHECK_EQ(failure.status_code, 502u);
        CHECK(failure.date == ForwardFailurePolicyDate::Current);
        CHECK(failure.connection == ForwardFailurePolicyConnection::Request);
        CHECK(failure.head_mode == FailurePolicyHeadMode::Reject);
        CHECK(failure.reason.eq(lit_str("Bad Gateway")));
        CHECK(failure.content_type.eq(lit_str("text/html")));
        CHECK(failure.server.eq(lit_str("nginx/1.29.7")));
        static constexpr char kFailureBody[] =
            "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n"
            "<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n"
            "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n";
        CHECK(failure.body.eq({kFailureBody, sizeof(kFailureBody) - 1u}));
        for (Str value : {failure.reason, failure.content_type, failure.server, failure.body})
            CHECK(str_is_owned_by(value,
                                  program.config.failure_policy_bytes,
                                  program.config.failure_policy_bytes_used));
    };

    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8088u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_upstream(9002u);
    check_prefix_route();
    REQUIRE_EQ(program.config.target_transform_count, 1u);
    REQUIRE_EQ(program.config.target_transform_bytes_used, 9u);
    REQUIRE_EQ(program.config.redirect_policy_count, 1u);
    REQUIRE_EQ(program.config.policy_bundle_count, 1u);
    u16 transform_id = 0u;
    u16 redirect_id = 0u;
    u16 request_policy_id = 0u;
    u16 bundle_id = 0u;
    u32 forward_count = 0u;
    u32 redirect_count = 0u;
    REQUIRE_EQ(program.rir.module.func_count, 1u);
    CHECK(program.rir.module.functions[0].route_pattern.eq(lit_str("/api")));
    for (u32 block = 0u; block < program.rir.module.functions[0].block_count; block++) {
        const auto& rir_block = program.rir.module.functions[0].blocks[block];
        for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
            const auto& inst = rir_block.insts[instruction];
            if (inst.op == rir::Opcode::RetRedirect) {
                redirect_count++;
                REQUIRE_GT(inst.imm.i32_val, 0);
                REQUIRE_LE(static_cast<u32>(inst.imm.i32_val),
                           program.rir.module.redirect_policy_count);
                redirect_id = static_cast<u16>(inst.imm.i32_val);
            }
            if (inst.op != rir::Opcode::RetForwardBundle) continue;
            forward_count++;
            REQUIRE_EQ(inst.operand_count, 3u);
            const auto find_const_i32 = [&](rir::ValueId value, i32& result) {
                for (u32 candidate_block = 0u;
                     candidate_block < program.rir.module.functions[0].block_count;
                     candidate_block++) {
                    const auto& block_to_search =
                        program.rir.module.functions[0].blocks[candidate_block];
                    for (u32 candidate_inst = 0u; candidate_inst < block_to_search.inst_count;
                         candidate_inst++) {
                        const auto& candidate = block_to_search.insts[candidate_inst];
                        if (candidate.op != rir::Opcode::ConstI32 || candidate.result != value)
                            continue;
                        result = candidate.imm.i32_val;
                        return true;
                    }
                }
                return false;
            };
            i32 upstream_id = -1;
            i32 request_id = -1;
            i32 actual_bundle_id = -1;
            REQUIRE(find_const_i32(inst.operand(0), upstream_id));
            REQUIRE(find_const_i32(inst.operand(1), request_id));
            REQUIRE(find_const_i32(inst.operand(2), actual_bundle_id));
            CHECK_EQ(upstream_id, 0);
            REQUIRE_GT(request_id, 0);
            REQUIRE_LE(request_id, 0xffff);
            REQUIRE_GT(actual_bundle_id, 0);
            REQUIRE_LE(static_cast<u32>(actual_bundle_id), program.rir.module.policy_bundle_count);
            request_policy_id = static_cast<u16>(request_id);
            bundle_id = static_cast<u16>(actual_bundle_id);
            REQUIRE_GT(instruction, 0u);
            const auto& transform = rir_block.insts[instruction - 1u];
            REQUIRE(transform.op == rir::Opcode::ReqSetTargetTransform);
            REQUIRE_GT(transform.imm.i32_val, 0);
            REQUIRE_LE(static_cast<u32>(transform.imm.i32_val),
                       program.rir.module.target_transform_count);
            transform_id = static_cast<u16>(transform.imm.i32_val);
        }
    }
    REQUIRE_EQ(redirect_count, 1u);
    REQUIRE_EQ(forward_count, 1u);
    REQUIRE_NE(redirect_id, 0u);
    REQUIRE_NE(transform_id, 0u);
    REQUIRE_NE(request_policy_id, 0u);
    REQUIRE_NE(bundle_id, 0u);
    check_transform(transform_id);
    check_redirect(redirect_id);
    check_forward_policies(request_policy_id, bundle_id);

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0u;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 8088u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_upstream(9002u);
    check_prefix_route();
    check_transform(transform_id);
    check_redirect(redirect_id);
    check_forward_policies(request_policy_id, bundle_id);

    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    CHECK_EQ(program.config.target_transform_count, 0u);
    CHECK_EQ(program.config.target_transform_bytes_used, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);

    {
        char nginx_source[] =
            "server { listen *:8089; location / { proxy_pass http://127.0.0.1:9003; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'z', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'w');
    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8089u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    REQUIRE_EQ(program.config.route_count, 3u);
    for (u32 i = 0u; i < program.config.route_count; i++) {
        CHECK_EQ(program.config.routes[i].path_len, 1u);
        CHECK_EQ(program.config.routes[i].path[0], '/');
    }
    check_upstream(9003u);
    CHECK_EQ(program.rir.module.target_transform_count, 0u);
    CHECK_EQ(program.config.target_transform_count, 0u);
    CHECK_EQ(program.config.target_transform_bytes_used, 0u);
    for (const auto& stale : program.config.target_transforms) {
        CHECK(stale.strip_prefix.ptr == nullptr);
        CHECK_EQ(stale.strip_prefix.len, 0u);
        CHECK(stale.replace_prefix.ptr == nullptr);
        CHECK_EQ(stale.replace_prefix.len, 0u);
    }
    CHECK_EQ(program.rir.module.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);
    for (const auto& stale : program.config.redirect_policies) {
        CHECK(stale.scheme == RedirectPolicyScheme::Invalid);
        CHECK(stale.authority == RedirectPolicyAuthority::Invalid);
        CHECK(stale.port == RedirectPolicyPort::Invalid);
        CHECK(stale.path == RedirectPolicyPath::Invalid);
        CHECK(stale.query == RedirectPolicyQuery::Invalid);
        CHECK(stale.date == RedirectPolicyDate::Invalid);
        CHECK(stale.connection == RedirectPolicyConnection::Invalid);
        CHECK(stale.header_order == RedirectPolicyHeaderOrder::Invalid);
        CHECK_EQ(stale.status_code, 0u);
        for (Str value : {stale.reason,
                          stale.server,
                          stale.content_type,
                          stale.static_authority,
                          stale.target_path,
                          stale.body}) {
            CHECK(value.ptr == nullptr);
            CHECK_EQ(value.len, 0u);
        }
    }
    program.destroy();
    std::filesystem::remove(path);
}

TEST(serve_loader, nginx_exact_loopback_api_no_uri_output_is_owned_and_reuses_cleanly) {
    const std::string dir = "/tmp/rut_serve_loader_nginx_exact_api_no_uri";
    const std::string path = dir + "/app.rut";
    std::string generated;
    {
        char nginx_source[] =
            "server { listen 127.0.0.1:8090; location /api/ { proxy_pass "
            "http://127.0.0.1:9004; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        REQUIRE_EQ(lowered.value().len, 3244u);
        generated.assign(lowered.value().data, lowered.value().len);
        CHECK(generated.find("target_transform") == std::string::npos);
        CHECK(generated.find("strip_prefix") == std::string::npos);
        CHECK(generated.find("replace_prefix") == std::string::npos);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'y');

    LoadedProgram program;
    LoadError error;
    const auto check_upstream = [&](u16 expected_port) {
        REQUIRE_EQ(program.config.upstream_count, 1u);
        const UpstreamTarget& upstream = program.config.upstreams[0];
        CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
        REQUIRE_EQ(upstream.addr_count, 1u);
        CHECK_EQ(upstream.addrs[0].sin_family, AF_INET);
        CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7f000001u);
        CHECK_EQ(ntohs(upstream.addrs[0].sin_port), expected_port);
    };
    const auto check_prefix_route = [&]() {
        REQUIRE_EQ(program.config.route_count, 1u);
        const RouteEntry& route = program.config.routes[0];
        CHECK_EQ(route.method, kRouteMethodAny);
        CHECK_EQ(route.path_len, 4u);
        CHECK((Str{reinterpret_cast<const char*>(route.path), route.path_len}.eq(lit_str("/api"))));
        CHECK(route.action == RouteAction::JitHandler);
        CHECK_FALSE(route.needs_req_body);
        static constexpr u8 kApi[] = {'/', 'a', 'p', 'i'};
        const RouteEntry* matched = program.config.match(kApi, sizeof(kApi), kRouteMethodGet);
        REQUIRE(matched != nullptr);
        CHECK_EQ(matched, &route);
    };
    const auto check_root_routes = [&]() {
        REQUIRE_EQ(program.config.route_count, 3u);
        u32 head_count = 0u;
        u32 get_count = 0u;
        u32 any_count = 0u;
        for (u32 i = 0u; i < program.config.route_count; i++) {
            const RouteEntry& route = program.config.routes[i];
            CHECK_EQ(route.path_len, 1u);
            CHECK_EQ(route.path[0], '/');
            CHECK(route.action == RouteAction::JitHandler);
            CHECK_FALSE(route.needs_req_body);
            if (route.method == kRouteMethodHead) head_count++;
            if (route.method == kRouteMethodGet) get_count++;
            if (route.method == kRouteMethodAny) any_count++;
        }
        CHECK_EQ(head_count, 1u);
        CHECK_EQ(get_count, 1u);
        CHECK_EQ(any_count, 1u);

        static constexpr u8 kRoot[] = {'/'};
        const RouteEntry* head = program.config.match(kRoot, 1u, kRouteMethodHead);
        const RouteEntry* get = program.config.match(kRoot, 1u, kRouteMethodGet);
        const RouteEntry* post = program.config.match(kRoot, 1u, kRouteMethodPost);
        REQUIRE(head != nullptr);
        REQUIRE(get != nullptr);
        REQUIRE(post != nullptr);
        CHECK_NE(head, get);
        CHECK_NE(head, post);
        CHECK_NE(get, post);
        CHECK_EQ(head->method, kRouteMethodHead);
        CHECK_EQ(get->method, kRouteMethodGet);
        CHECK_EQ(post->method, kRouteMethodAny);
        CHECK(head->action == RouteAction::JitHandler);
        CHECK(get->action == RouteAction::JitHandler);
        CHECK(post->action == RouteAction::JitHandler);
        CHECK_FALSE(head->needs_req_body);
        CHECK_FALSE(get->needs_req_body);
        CHECK_FALSE(post->needs_req_body);
    };
    const auto check_no_transform = [&]() {
        CHECK_EQ(program.config.target_transform_count, 0u);
        CHECK_EQ(program.config.target_transform_bytes_used, 0u);
        for (const auto& stale : program.config.target_transforms) {
            CHECK(stale.strip_prefix.ptr == nullptr);
            CHECK_EQ(stale.strip_prefix.len, 0u);
            CHECK(stale.replace_prefix.ptr == nullptr);
            CHECK_EQ(stale.replace_prefix.len, 0u);
        }
    };
    const auto check_redirect = [&](u16 policy_id) {
        REQUIRE(program.config.redirect_policy_id_is_valid(policy_id));
        const auto& policy = program.config.redirect_policies[policy_id - 1u];
        CHECK(program.config.redirect_policy_strings_are_owned(policy));
        CHECK(policy.scheme == RedirectPolicyScheme::Http);
        CHECK(policy.authority == RedirectPolicyAuthority::RequestHost);
        CHECK(policy.port == RedirectPolicyPort::ActualListener);
        CHECK(policy.path == RedirectPolicyPath::Static);
        CHECK(policy.query == RedirectPolicyQuery::PreserveRaw);
        CHECK(policy.date == RedirectPolicyDate::Current);
        CHECK(policy.connection == RedirectPolicyConnection::Close);
        CHECK(policy.header_order == RedirectPolicyHeaderOrder::LocationThenConnection);
        CHECK_EQ(policy.status_code, 301u);
        CHECK(policy.reason.eq(lit_str("Moved Permanently")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK_EQ(policy.static_authority.len, 0u);
        CHECK(policy.target_path.eq(lit_str("/api/")));
        CHECK_EQ(policy.body.len, 169u);
    };
    const auto str_is_owned_by = [](Str value, const char* pool, u32 used) {
        if (value.ptr == nullptr || value.len == 0u || value.len > used) return false;
        const uintptr_t begin = reinterpret_cast<uintptr_t>(pool);
        const uintptr_t address = reinterpret_cast<uintptr_t>(value.ptr);
        return address >= begin && address - begin < used && value.len <= used - (address - begin);
    };
    const auto check_forward_policies = [&](u16 request_policy_id, u16 bundle_id) {
        CHECK_EQ(request_policy_id, static_cast<u16>(RequestPolicyId::Http11FixedStrip));
        CHECK(request_policy_is_supported(request_policy_id));
        REQUIRE(program.config.policy_bundle_id_is_valid(bundle_id));
        const auto& bundle = program.config.policy_bundles[bundle_id - 1u];
        REQUIRE(program.config.response_policy_id_is_valid(bundle.response_policy_id));
        REQUIRE(program.config.failure_policy_id_is_valid(bundle.failure_policy_id));
        CHECK_EQ(bundle.timeout_failure_policy_id, 0u);
        CHECK_EQ(bundle.response_read_timeout_seconds, 0u);
        CHECK(bundle.response_buffering == ForwardResponseBufferingMode::None);
        REQUIRE_EQ(program.config.response_policy_count, 1u);
        REQUIRE_EQ(program.config.failure_policy_count, 1u);

        const auto& response = program.config.response_policies[bundle.response_policy_id - 1u];
        CHECK(response.version == ResponsePolicyVersion::Http11);
        CHECK(response.framing == ResponsePolicyFraming::ContentLength);
        CHECK(response.connection == ResponsePolicyConnection::Request);
        CHECK(response.date == ResponsePolicyDate::Current);
        CHECK(response.head_mode == ResponsePolicyHeadMode::Reject);
        CHECK(response.server.eq(lit_str("nginx/1.29.7")));
        CHECK(str_is_owned_by(response.server,
                              program.config.response_policy_bytes,
                              program.config.response_policy_bytes_used));
        REQUIRE_EQ(response.hide_header_count, 3u);
        static constexpr Str kHidden[] = {lit_str("Date"), lit_str("Server"), lit_str("X-Pad")};
        for (u32 i = 0u; i < response.hide_header_count; i++) {
            CHECK(response.hide_headers[i].eq(kHidden[i]));
            CHECK(str_is_owned_by(response.hide_headers[i],
                                  program.config.response_policy_bytes,
                                  program.config.response_policy_bytes_used));
        }

        const auto& failure = program.config.failure_policies[bundle.failure_policy_id - 1u];
        CHECK(failure.version == ForwardFailurePolicyVersion::Http11);
        CHECK_EQ(failure.status_code, 502u);
        CHECK(failure.date == ForwardFailurePolicyDate::Current);
        CHECK(failure.connection == ForwardFailurePolicyConnection::Request);
        CHECK(failure.head_mode == FailurePolicyHeadMode::Reject);
        CHECK(failure.reason.eq(lit_str("Bad Gateway")));
        CHECK(failure.content_type.eq(lit_str("text/html")));
        CHECK(failure.server.eq(lit_str("nginx/1.29.7")));
        static constexpr char kFailureBody[] =
            "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n"
            "<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n"
            "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n";
        CHECK(failure.body.eq({kFailureBody, sizeof(kFailureBody) - 1u}));
        for (Str value : {failure.reason, failure.content_type, failure.server, failure.body})
            CHECK(str_is_owned_by(value,
                                  program.config.failure_policy_bytes,
                                  program.config.failure_policy_bytes_used));
    };
    const auto check_inactive_forward_storage = [&](u32 expected_response_count,
                                                    u32 expected_failure_count,
                                                    u32 expected_bundle_count) {
        REQUIRE_EQ(program.config.response_policy_count, expected_response_count);
        REQUIRE_EQ(program.config.failure_policy_count, expected_failure_count);
        REQUIRE_EQ(program.config.policy_bundle_count, expected_bundle_count);
        u32 expected_response_bytes = 0u;
        for (u32 policy = 0u; policy < program.config.response_policy_count; policy++) {
            const auto& active_response = program.config.response_policies[policy];
            expected_response_bytes += active_response.server.len;
            for (u32 i = 0u; i < active_response.hide_header_count; i++)
                expected_response_bytes += active_response.hide_headers[i].len;
        }
        CHECK_EQ(program.config.response_policy_bytes_used, expected_response_bytes);
        u32 expected_failure_bytes = 0u;
        for (u32 policy = 0u; policy < program.config.failure_policy_count; policy++) {
            const auto& active_failure = program.config.failure_policies[policy];
            expected_failure_bytes += active_failure.reason.len + active_failure.content_type.len +
                                      active_failure.server.len + active_failure.body.len;
        }
        CHECK_EQ(program.config.failure_policy_bytes_used, expected_failure_bytes);

        for (u32 i = program.config.response_policy_count; i < kMaxResponsePolicies; i++) {
            const auto& stale = program.config.response_policies[i];
            CHECK(stale.version == ResponsePolicyVersion::Invalid);
            CHECK(stale.framing == ResponsePolicyFraming::Invalid);
            CHECK(stale.connection == ResponsePolicyConnection::Invalid);
            CHECK(stale.date == ResponsePolicyDate::Invalid);
            CHECK(stale.head_mode == ResponsePolicyHeadMode::Reject);
            CHECK(stale.server.ptr == nullptr);
            CHECK_EQ(stale.server.len, 0u);
            CHECK_EQ(stale.hide_header_count, 0u);
            for (const Str value : stale.hide_headers) {
                CHECK(value.ptr == nullptr);
                CHECK_EQ(value.len, 0u);
            }
        }
        for (u32 i = program.config.failure_policy_count; i < kMaxForwardFailurePolicies; i++) {
            const auto& stale = program.config.failure_policies[i];
            CHECK(stale.version == ForwardFailurePolicyVersion::Invalid);
            CHECK_EQ(stale.status_code, 0u);
            CHECK(stale.date == ForwardFailurePolicyDate::Invalid);
            CHECK(stale.connection == ForwardFailurePolicyConnection::Invalid);
            CHECK(stale.head_mode == FailurePolicyHeadMode::Reject);
            for (const Str value : {stale.reason, stale.content_type, stale.server, stale.body}) {
                CHECK(value.ptr == nullptr);
                CHECK_EQ(value.len, 0u);
            }
        }
        for (u32 i = program.config.policy_bundle_count; i < RouteConfig::kMaxForwardPolicyBundles;
             i++) {
            const auto& stale = program.config.policy_bundles[i];
            CHECK_EQ(stale.response_policy_id, 0u);
            CHECK_EQ(stale.failure_policy_id, 0u);
            CHECK_EQ(stale.timeout_failure_policy_id, 0u);
            CHECK_EQ(stale.response_read_timeout_seconds, 0u);
            CHECK(stale.response_buffering == ForwardResponseBufferingMode::None);
        }
    };
    const auto check_root_forward_bundle = [&](u16 request_policy_id,
                                               u16 bundle_id,
                                               bool suppress_body,
                                               bool buffered) {
        CHECK_EQ(request_policy_id, static_cast<u16>(RequestPolicyId::Http11FixedStrip));
        CHECK(request_policy_is_supported(request_policy_id));
        REQUIRE(request_policy_version(request_policy_id) != nullptr);
        CHECK_EQ(std::string(request_policy_version(request_policy_id)), "HTTP/1.1");
        REQUIRE(program.config.policy_bundle_id_is_valid(bundle_id));
        const auto& bundle = program.config.policy_bundles[bundle_id - 1u];
        REQUIRE(program.config.response_policy_id_is_valid(bundle.response_policy_id));
        REQUIRE(program.config.failure_policy_id_is_valid(bundle.failure_policy_id));
        CHECK_EQ(bundle.response_read_timeout_seconds, buffered ? 60u : 0u);
        CHECK(bundle.response_buffering ==
              (buffered ? ForwardResponseBufferingMode::CompleteContentLength
                        : ForwardResponseBufferingMode::None));

        const auto& response = program.config.response_policies[bundle.response_policy_id - 1u];
        CHECK(response.version == ResponsePolicyVersion::Http11);
        CHECK(response.framing == ResponsePolicyFraming::ContentLength);
        CHECK(response.connection == ResponsePolicyConnection::Request);
        CHECK(response.date == ResponsePolicyDate::Current);
        CHECK(response.head_mode == (suppress_body ? ResponsePolicyHeadMode::SuppressBody
                                                   : ResponsePolicyHeadMode::Reject));
        CHECK(response.server.eq(lit_str("nginx/1.29.7")));
        CHECK(str_is_owned_by(response.server,
                              program.config.response_policy_bytes,
                              program.config.response_policy_bytes_used));
        REQUIRE_EQ(response.hide_header_count, 3u);
        static constexpr Str kHidden[] = {lit_str("Date"), lit_str("Server"), lit_str("X-Pad")};
        for (u32 i = 0u; i < response.hide_header_count; i++) {
            CHECK(response.hide_headers[i].eq(kHidden[i]));
            CHECK(str_is_owned_by(response.hide_headers[i],
                                  program.config.response_policy_bytes,
                                  program.config.response_policy_bytes_used));
        }

        static constexpr char kBadGatewayBody[] =
            "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n"
            "<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n"
            "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n";
        const auto& failure = program.config.failure_policies[bundle.failure_policy_id - 1u];
        CHECK(failure.version == ForwardFailurePolicyVersion::Http11);
        CHECK_EQ(failure.status_code, 502u);
        CHECK(failure.date == ForwardFailurePolicyDate::Current);
        CHECK(failure.connection == ForwardFailurePolicyConnection::Request);
        CHECK(failure.head_mode == (suppress_body ? FailurePolicyHeadMode::SuppressBody
                                                  : FailurePolicyHeadMode::Reject));
        CHECK(failure.reason.eq(lit_str("Bad Gateway")));
        CHECK(failure.content_type.eq(lit_str("text/html")));
        CHECK(failure.server.eq(lit_str("nginx/1.29.7")));
        CHECK(failure.body.eq({kBadGatewayBody, sizeof(kBadGatewayBody) - 1u}));
        for (const Str value : {failure.reason, failure.content_type, failure.server, failure.body})
            CHECK(str_is_owned_by(value,
                                  program.config.failure_policy_bytes,
                                  program.config.failure_policy_bytes_used));

        if (!buffered) {
            CHECK_EQ(bundle.timeout_failure_policy_id, 0u);
            return;
        }
        REQUIRE(
            program.config.timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id));
        static constexpr char kGatewayTimeoutBody[] =
            "<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n"
            "<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n"
            "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n";
        const auto& timeout =
            program.config.failure_policies[bundle.timeout_failure_policy_id - 1u];
        CHECK(timeout.version == ForwardFailurePolicyVersion::Http11);
        CHECK_EQ(timeout.status_code, 504u);
        CHECK(timeout.date == ForwardFailurePolicyDate::Current);
        CHECK(timeout.connection == ForwardFailurePolicyConnection::Request);
        CHECK(timeout.head_mode == FailurePolicyHeadMode::Reject);
        CHECK(timeout.reason.eq(lit_str("Gateway Time-out")));
        CHECK(timeout.content_type.eq(lit_str("text/html")));
        CHECK(timeout.server.eq(lit_str("nginx/1.29.7")));
        CHECK(timeout.body.eq({kGatewayTimeoutBody, sizeof(kGatewayTimeoutBody) - 1u}));
        for (const Str value : {timeout.reason, timeout.content_type, timeout.server, timeout.body})
            CHECK(str_is_owned_by(value,
                                  program.config.failure_policy_bytes,
                                  program.config.failure_policy_bytes_used));
    };

    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
    CHECK_EQ(program.listener.port, 8090u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_upstream(9004u);
    check_prefix_route();
    REQUIRE_EQ(program.rir.module.target_transform_count, 0u);
    check_no_transform();
    REQUIRE_EQ(program.config.redirect_policy_count, 1u);
    REQUIRE_EQ(program.config.policy_bundle_count, 1u);

    u16 redirect_id = 0u;
    u16 request_policy_id = 0u;
    u16 bundle_id = 0u;
    u32 redirect_count = 0u;
    u32 forward_count = 0u;
    bool saw_transform = false;
    REQUIRE_EQ(program.rir.module.func_count, 1u);
    CHECK(program.rir.module.functions[0].route_pattern.eq(lit_str("/api")));
    const auto find_const_i32 = [&](rir::ValueId value, i32& result) {
        const auto& function = program.rir.module.functions[0];
        for (u32 block = 0u; block < function.block_count; block++) {
            const auto& candidate_block = function.blocks[block];
            for (u32 instruction = 0u; instruction < candidate_block.inst_count; instruction++) {
                const auto& candidate = candidate_block.insts[instruction];
                if (candidate.op == rir::Opcode::ConstI32 && candidate.result == value) {
                    result = candidate.imm.i32_val;
                    return true;
                }
            }
        }
        return false;
    };
    for (u32 block = 0u; block < program.rir.module.functions[0].block_count; block++) {
        const auto& rir_block = program.rir.module.functions[0].blocks[block];
        for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
            const auto& inst = rir_block.insts[instruction];
            if (inst.op == rir::Opcode::ReqSetTargetTransform) saw_transform = true;
            if (inst.op == rir::Opcode::RetRedirect) {
                redirect_count++;
                REQUIRE_GT(inst.imm.i32_val, 0);
                redirect_id = static_cast<u16>(inst.imm.i32_val);
            }
            if (inst.op != rir::Opcode::RetForwardBundle) continue;
            forward_count++;
            REQUIRE_EQ(inst.operand_count, 3u);
            i32 upstream_id = -1;
            i32 request_id = -1;
            i32 actual_bundle_id = -1;
            REQUIRE(find_const_i32(inst.operand(0), upstream_id));
            REQUIRE(find_const_i32(inst.operand(1), request_id));
            REQUIRE(find_const_i32(inst.operand(2), actual_bundle_id));
            CHECK_EQ(upstream_id, 0);
            REQUIRE_GT(request_id, 0);
            REQUIRE_LE(request_id, 0xffff);
            REQUIRE_GT(actual_bundle_id, 0);
            REQUIRE_LE(static_cast<u32>(actual_bundle_id), program.rir.module.policy_bundle_count);
            request_policy_id = static_cast<u16>(request_id);
            bundle_id = static_cast<u16>(actual_bundle_id);
        }
    }
    REQUIRE_EQ(redirect_count, 1u);
    REQUIRE_EQ(forward_count, 1u);
    REQUIRE_FALSE(saw_transform);
    REQUIRE_NE(redirect_id, 0u);
    REQUIRE_NE(request_policy_id, 0u);
    REQUIRE_NE(bundle_id, 0u);
    check_redirect(redirect_id);
    check_forward_policies(request_policy_id, bundle_id);

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0u;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(program.listener.port, 8090u);
    CHECK_EQ(program.listener.ipv4_host, 0x7f000001u);
    check_upstream(9004u);
    check_prefix_route();
    check_no_transform();
    check_redirect(redirect_id);
    check_forward_policies(request_policy_id, bundle_id);

    program.destroy();
    CHECK_FALSE(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(program.listener.port, 8080u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    check_no_transform();
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);

    {
        char nginx_source[] =
            "server { listen *:8091; location / { proxy_pass http://127.0.0.1:9005; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated.assign(lowered.value().data, lowered.value().len);
        memset(nginx_source, 'z', sizeof(nginx_source) - 1u);
    }
    write_file(dir, "app.rut", generated.c_str());
    std::fill(generated.begin(), generated.end(), 'w');
    REQUIRE(load_rut_program(path.c_str(), program, error));
    CHECK(program.has_listener);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(program.listener.port, 8091u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    check_upstream(9005u);
    check_root_routes();
    CHECK_EQ(program.rir.module.target_transform_count, 0u);
    check_no_transform();
    CHECK_EQ(program.rir.module.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);
    for (const auto& stale : program.config.redirect_policies) {
        CHECK(stale.scheme == RedirectPolicyScheme::Invalid);
        CHECK(stale.authority == RedirectPolicyAuthority::Invalid);
        CHECK(stale.port == RedirectPolicyPort::Invalid);
        CHECK(stale.path == RedirectPolicyPath::Invalid);
        CHECK(stale.query == RedirectPolicyQuery::Invalid);
        CHECK(stale.date == RedirectPolicyDate::Invalid);
        CHECK(stale.connection == RedirectPolicyConnection::Invalid);
        CHECK(stale.header_order == RedirectPolicyHeaderOrder::Invalid);
        CHECK_EQ(stale.status_code, 0u);
        for (Str value : {stale.reason,
                          stale.server,
                          stale.content_type,
                          stale.static_authority,
                          stale.target_path,
                          stale.body}) {
            CHECK(value.ptr == nullptr);
            CHECK_EQ(value.len, 0u);
        }
    }
    for (u32 i = program.config.route_count; i < RouteConfig::kMaxRoutes; i++) {
        CHECK_EQ(program.config.routes[i].path_len, 0u);
        CHECK_EQ(program.config.routes[i].path[0], '\0');
    }

    REQUIRE_EQ(program.rir.module.func_count, 3u);
    u32 root_head_count = 0u;
    u32 root_get_count = 0u;
    u32 root_any_count = 0u;
    u32 root_forward_count = 0u;
    u16 root_request_policy_id = 0u;
    u16 root_head_bundle_id = 0u;
    u16 root_get_bundle_id = 0u;
    u16 root_any_bundle_id = 0u;
    for (u32 function_index = 0u; function_index < program.rir.module.func_count;
         function_index++) {
        const auto& function = program.rir.module.functions[function_index];
        CHECK(function.route_pattern.eq(lit_str("/")));
        if (function.http_method == kRouteMethodHead) root_head_count++;
        if (function.http_method == kRouteMethodGet) root_get_count++;
        if (function.http_method == kRouteMethodAny) root_any_count++;
        const auto find_root_const_i32 = [&](rir::ValueId value, i32& result) {
            for (u32 block = 0u; block < function.block_count; block++) {
                const auto& candidate_block = function.blocks[block];
                for (u32 instruction = 0u; instruction < candidate_block.inst_count;
                     instruction++) {
                    const auto& candidate = candidate_block.insts[instruction];
                    if (candidate.op == rir::Opcode::ConstI32 && candidate.result == value) {
                        result = candidate.imm.i32_val;
                        return true;
                    }
                }
            }
            return false;
        };
        u32 function_forward_count = 0u;
        for (u32 block = 0u; block < function.block_count; block++) {
            const auto& rir_block = function.blocks[block];
            for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
                const auto& inst = rir_block.insts[instruction];
                CHECK(inst.op != rir::Opcode::ReqSetTargetTransform);
                if (inst.op != rir::Opcode::RetForwardBundle) continue;
                function_forward_count++;
                root_forward_count++;
                REQUIRE_EQ(inst.operand_count, 3u);
                i32 upstream_id = -1;
                i32 request_id = -1;
                i32 actual_bundle_id = -1;
                REQUIRE(find_root_const_i32(inst.operand(0), upstream_id));
                REQUIRE(find_root_const_i32(inst.operand(1), request_id));
                REQUIRE(find_root_const_i32(inst.operand(2), actual_bundle_id));
                CHECK_EQ(upstream_id, 0);
                CHECK_EQ(request_id, static_cast<i32>(RequestPolicyId::Http11FixedStrip));
                REQUIRE_GT(actual_bundle_id, 0);
                REQUIRE_LE(static_cast<u32>(actual_bundle_id),
                           program.rir.module.policy_bundle_count);
                if (root_request_policy_id == 0u) {
                    root_request_policy_id = static_cast<u16>(request_id);
                } else {
                    CHECK_EQ(request_id, root_request_policy_id);
                }
                u16* method_bundle_id = nullptr;
                if (function.http_method == kRouteMethodHead)
                    method_bundle_id = &root_head_bundle_id;
                if (function.http_method == kRouteMethodGet) method_bundle_id = &root_get_bundle_id;
                if (function.http_method == kRouteMethodAny) method_bundle_id = &root_any_bundle_id;
                REQUIRE(method_bundle_id != nullptr);
                REQUIRE_EQ(*method_bundle_id, 0u);
                *method_bundle_id = static_cast<u16>(actual_bundle_id);
            }
        }
        REQUIRE_EQ(function_forward_count, 1u);
    }
    CHECK_EQ(root_head_count, 1u);
    CHECK_EQ(root_get_count, 1u);
    CHECK_EQ(root_any_count, 1u);
    REQUIRE_EQ(root_forward_count, 3u);
    REQUIRE_NE(root_request_policy_id, 0u);
    REQUIRE_NE(root_head_bundle_id, 0u);
    REQUIRE_NE(root_get_bundle_id, 0u);
    REQUIRE_NE(root_any_bundle_id, 0u);
    CHECK_NE(root_head_bundle_id, root_get_bundle_id);
    CHECK_NE(root_head_bundle_id, root_any_bundle_id);
    CHECK_NE(root_get_bundle_id, root_any_bundle_id);
    check_root_forward_bundle(root_request_policy_id, root_head_bundle_id, true, false);
    check_root_forward_bundle(root_request_policy_id, root_get_bundle_id, false, true);
    check_root_forward_bundle(root_request_policy_id, root_any_bundle_id, false, false);
    check_inactive_forward_storage(2u, 3u, 3u);

    program.engine.shutdown();
    program.jit_inited = false;
    program.rir.destroy();
    REQUIRE(program.src_map != nullptr);
    REQUIRE_EQ(munmap(program.src_map, program.src_map_len), 0);
    program.src_map = nullptr;
    program.src_map_len = 0u;
    REQUIRE(std::filesystem::remove(path));
    CHECK(program.listener.valid());
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(program.listener.port, 8091u);
    CHECK_EQ(program.listener.ipv4_host, 0u);
    check_upstream(9005u);
    check_root_routes();
    check_no_transform();
    check_root_forward_bundle(root_request_policy_id, root_head_bundle_id, true, false);
    check_root_forward_bundle(root_request_policy_id, root_get_bundle_id, false, true);
    check_root_forward_bundle(root_request_policy_id, root_any_bundle_id, false, false);
    check_inactive_forward_storage(2u, 3u, 3u);
    CHECK_EQ(program.config.redirect_policy_count, 0u);
    CHECK_EQ(program.config.redirect_policy_bytes_used, 0u);
    program.destroy();
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
