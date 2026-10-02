#include "deferred_preflight_fixture.h"
#include "framing_selection_preflight_fixture.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/native_program.h"
#include "rut/runtime/cache_table.h"
#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace rut;
namespace {
struct Source {
    char path[80] = "/tmp/rut native source-XXXXXX";
    int fd = mkstemp(path);
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
jit::HandlerResult invoke(const RouteEntry& route, const char* request) {
    jit::HandlerCtx ctx{};
    return jit::HandlerResult::unpack(route.fn(nullptr,
                                               &ctx,
                                               reinterpret_cast<const u8*>(request),
                                               static_cast<u32>(strlen(request)),
                                               nullptr));
}
bool load(Source& source, NativeProgram& p, u8 opt = 2) {
    char error[512];
    bool ok = load_native_program(source.path, p, error, sizeof(error), opt);
    if (!ok) fprintf(stderr, "%s\n", error);
    return ok;
}
}  // namespace

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
TEST(native_program, websocket_regex_handler_survives_compiler_exit) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { frame in\n"
                      "guard !frame.text.matches(re\".*badword.*\") else { frame.drop() }\n"
                      "frame.forward() } }\n"));
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
