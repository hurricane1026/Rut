#include "deferred_preflight_fixture.h"
#include "framing_selection_preflight_fixture.h"
#include "rs256_fixture.h"
#include "rut/jit/native_helper_symbols.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/native_program.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/ebpf_plan.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"

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
bool load(Source& source, NativeProgram& p, u8 opt = 2) {
    char error[512];
    bool ok = load_native_program(source.path, p, error, sizeof(error), opt);
    if (!ok) fprintf(stderr, "%s\n", error);
    return ok;
}
}  // namespace

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

TEST(native_program, links_with_closed_stderr) {
    Source source;
    REQUIRE(source.append("route GET \"/\" { return 200 }\n"));
    Program owner;
    REQUIRE(owner.p);
    const int saved_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    REQUIRE(saved_stderr >= 0);
    REQUIRE_EQ(close(STDERR_FILENO), 0);
    const bool loaded = load(source, *owner.p);
    const bool restored = dup2(saved_stderr, STDERR_FILENO) == STDERR_FILENO;
    close(saved_stderr);
    REQUIRE(restored);
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
TEST(native_program, websocket_rewrite_survives_compiler_exit_and_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { frame in "
                      "frame.forward(\"native\\0text\") } }\n"));
    Program owner;
    REQUIRE(owner.p);
    REQUIRE(load(source, *owner.p));
    REQUIRE_EQ(unlink(source.path), 0);
    const auto& route = owner.p->config.routes[0];
    REQUIRE_EQ(route.ws_forward_text.len, 11u);
    CHECK(memcmp(route.ws_forward_text.ptr, "native\0text", 11) == 0);
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

TEST(native_program, websocket_affixes_survive_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { frame in\n"
                      "guard !frame.fromClient || (frame.text.hasPrefix(\"a\\0\") && "
                      "frame.text.hasSuffix(\"\\u{20ac}\")) else { frame.drop() }\n"
                      "frame.forward() } }\n"));
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
                      "route GET \"/ws\" { return websocket(backend) { frame in\n"
                      "guard !frame.fromClient || (frame.text.contains(\"a\\0\") && "
                      "!frame.text.contains(\"\\u{20ac}\")) else { frame.drop() }\n"
                      "frame.forward() } }\n"));
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
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { frame in frame.close(1008, "
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
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\nroute GET \"/ws\" { return "
                      "websocket(backend) { frame in\n"
                      "guard frame.text != \"a\" else { frame.close(1008, \"a\\0\\u{20ac}\") }\n"
                      "guard frame.text != \"b\" else { frame.close(1009) }\n"
                      "guard frame.text != \"c\" else { frame.close(1011, \"third\") }\n"
                      "guard frame.text != \"d\" else { frame.close(4001, \"fourth\") }\n"
                      "frame.close(1000, \"default\") } }\n"));
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
    REQUIRE_EQ(config.rs256_configuration_count, 1u);
    REQUIRE(config.rs256);
    auto* connection = owner.arena.alloc_t<ConnectionBase>();
    REQUIRE(connection);
    connection->request_config = &config;
    connection->shard_id = 2;
    SlicePool pool;
    REQUIRE(pool.init(32));
    connection->json_arena.backend.pool = &pool;
    char token[4096];
    Str signed_token = fixture.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, token);
    REQUIRE(signed_token.len);
    auto run = [&]() {
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
            jit::HandlerResult::unpack(config.routes[0].fn(connection,
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
    signed_token = fixture.sign(test::Rs256Fixture::header, test::Rs256Fixture::claims, token);
    CHECK_EQ(run(), 200u);
    connection->json_arena.destroy();
    pool.destroy();
}

TEST(native_program, websocket_guard_text_policies_survive_source_removal) {
    Source source;
    REQUIRE(
        source.append("upstream backend at \"127.0.0.1:9999\"\n"
                      "route GET \"/ws\" { return websocket(backend) { frame in\n"
                      " guard frame.text != \"a\" else { frame.forward(\"one\\0\\u{20ac}\") }\n"
                      " guard frame.text != \"b\" else { frame.forward(\"\") }\n"
                      " guard frame.text != \"c\" else { frame.forward(\"third\") }\n"
                      " guard frame.text != \"d\" else { frame.forward(\"fourth\") }\n"
                      " frame.forward(\"default\") } }\n"));
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
