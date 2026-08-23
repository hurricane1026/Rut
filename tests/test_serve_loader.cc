// Tests for the .rut program loader (src/serve_loader.cc): the bridge that
// compiles a source file end to end (lex -> parse -> analyze -> MIR -> RIR ->
// JIT) into a RouteConfig, plus its fail-closed error reporting.

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

}  // namespace

TEST(serve_loader, status_routes_load) {
    const std::string dir = "/tmp/rut_serve_loader_status";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "route GET \"/\" { return 200 }\n"
                                        "route GET \"/health\" { return 204 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    // Both routes registered into the config the shards will serve.
    CHECK_EQ(program.config.route_count, 2u);
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

TEST(serve_loader, source_listener_metadata_is_owned_by_loaded_program) {
    const std::string dir = "/tmp/rut_serve_loader_listener";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "listen :0\n"
                                        "route GET \"/\" { return 200 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK(program.has_listener);
    CHECK_EQ(program.listener.port, 0u);
    CHECK(program.listener.address == ListenerAddress::IPv4Wildcard);
    CHECK(program.listener.transport == ListenerTransport::Cleartext);
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
