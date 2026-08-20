#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "rut/runtime/listener.h"
#include "test.h"

#include <memory>

using namespace rut;

namespace {

static bool is_error(const FrontendResult<nginx::Server>& result,
                     FrontendError code,
                     u32 line,
                     u32 col,
                     Str detail = {}) {
    if (result) return false;
    const Diagnostic& diagnostic = result.error();
    if (diagnostic.code != code || diagnostic.span.line != line || diagnostic.span.col != col)
        return false;
    return detail.empty() || diagnostic.detail.eq(detail);
}

static const rir::Instruction* find_ret_forward(const rir::Function& function) {
    for (u32 bi = 0; bi < function.block_count; bi++) {
        const auto& block = function.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            if (block.insts[ii].op == rir::Opcode::RetForward) return &block.insts[ii];
        }
    }
    return nullptr;
}

static bool find_const_i32(const rir::Function& function, rir::ValueId value, i32& out) {
    for (u32 bi = 0; bi < function.block_count; bi++) {
        const auto& block = function.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& instruction = block.insts[ii];
            if (instruction.op == rir::Opcode::ConstI32 && instruction.result == value) {
                out = instruction.imm.i32_val;
                return true;
            }
        }
    }
    return false;
}

struct RirGuard {
    FrontendRirModule& module;
    ~RirGuard() { module.destroy(); }
};

}  // namespace

TEST(nginx_parser, parses_minimal_server_and_spans) {
    const char source[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / {\n"
        "    proxy_pass http://127.0.0.1:9000;\n"
        "  }\n"
        "}\n";
    const auto result = nginx::parse({source, sizeof(source) - 1});
    REQUIRE(result);
    CHECK_EQ(result.value().listen.port, 8080);
    CHECK_EQ(result.value().listen.span.line, 2);
    CHECK_EQ(result.value().listen.span.col, 3);
    CHECK(result.value().location.path.eq(lit_str("/")));
    CHECK_EQ(result.value().location.path_span.line, 3);
    CHECK_EQ(result.value().location.span.line, 3);
    CHECK_EQ(result.value().location.proxy_pass.address[0], 127);
    CHECK_EQ(result.value().location.proxy_pass.address[3], 1);
    CHECK_EQ(result.value().location.proxy_pass.port, 9000);
    CHECK_EQ(result.value().location.proxy_pass.span.line, 4);
}

TEST(nginx_parser, accepts_comments_whitespace_and_boundaries) {
    const char source[] =
        "# leading\nserver{ listen 1; # listen\n"
        "location\t/\n{ proxy_pass http://0.0.0.0:65535; } } # trailing\n";
    const auto result = nginx::parse({source, sizeof(source) - 1});
    REQUIRE(result);
    CHECK_EQ(result.value().listen.port, 1);
    CHECK_EQ(result.value().location.proxy_pass.port, 65535);
    CHECK_EQ(result.value().location.proxy_pass.address[0], 0);
    CHECK_EQ(result.value().location.proxy_pass.address[3], 0);
}

TEST(nginx_parser, rejects_missing_and_duplicate_directives) {
    const char no_listen[] = "server { location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({no_listen, sizeof(no_listen) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 1, lit_str("missing listen")));

    const char duplicate_listen[] =
        "server { listen 8080; listen 8081; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({duplicate_listen, sizeof(duplicate_listen) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 23, lit_str("duplicate listen")));

    const char no_location[] = "server { listen 8080; }";
    CHECK(is_error(nginx::parse({no_location, sizeof(no_location) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 1, lit_str("missing location")));

    const char duplicate_location[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location / { proxy_pass http://127.0.0.1:2; } }";
    CHECK(is_error(nginx::parse({duplicate_location, sizeof(duplicate_location) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 69, lit_str("duplicate location")));

    const char no_proxy[] = "server { listen 8080; location / { } }";
    CHECK(is_error(nginx::parse({no_proxy, sizeof(no_proxy) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 36, lit_str("missing proxy_pass")));

    const char duplicate_proxy[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; proxy_pass http://127.0.0.1:2; } }";
    CHECK(is_error(nginx::parse({duplicate_proxy, sizeof(duplicate_proxy) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 67, lit_str("duplicate proxy_pass")));
}

TEST(nginx_parser, rejects_unknown_directives_and_multiple_servers) {
    const char unknown_server[] = "server { listen 8080; worker_processes 1; }";
    CHECK(is_error(nginx::parse({unknown_server, sizeof(unknown_server) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 23,
                   lit_str("unknown server directive")));

    const char unknown_location[] = "server { listen 8080; location / { return 200; } }";
    CHECK(is_error(nginx::parse({unknown_location, sizeof(unknown_location) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 36,
                   lit_str("unknown location directive")));

    const char second_server[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } } server { listen 8081; }";
    CHECK(is_error(nginx::parse({second_server, sizeof(second_server) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 71,
                   lit_str("multiple servers are unsupported")));
}

TEST(nginx_parser, rejects_missing_braces_and_semicolons) {
    const char missing_server_brace[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; }";
    CHECK(is_error(nginx::parse({missing_server_brace, sizeof(missing_server_brace) - 1}),
                   FrontendError::UnexpectedEof, 1, 68,
                   lit_str("missing '}' for server")));

    const char missing_location_brace[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; ";
    CHECK(is_error(nginx::parse({missing_location_brace, sizeof(missing_location_brace) - 1}),
                   FrontendError::UnexpectedEof, 1, 67,
                   lit_str("missing '}' for location")));

    const char missing_listen_semicolon[] =
        "server { listen 8080 location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({missing_listen_semicolon,
                                 sizeof(missing_listen_semicolon) - 1}),
                   FrontendError::UnexpectedToken, 1, 22,
                   lit_str("expected ';' after listen")));

    const char missing_proxy_semicolon[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1 } }";
    CHECK(is_error(nginx::parse({missing_proxy_semicolon,
                                 sizeof(missing_proxy_semicolon) - 1}),
                   FrontendError::UnexpectedToken, 1, 66,
                   lit_str("expected ';' after proxy_pass")));

    const char missing_final_semicolon[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1";
    CHECK(is_error(nginx::parse({missing_final_semicolon,
                                 sizeof(missing_final_semicolon) - 1}),
                   FrontendError::UnexpectedEof, 1, 65,
                   lit_str("expected ';' after proxy_pass")));
}

TEST(nginx_parser, rejects_out_of_scope_contexts_and_values) {
    const char wrappers[] = "http { server { listen 8080; } }";
    CHECK(is_error(nginx::parse({wrappers, sizeof(wrappers) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 1));

    const char bad_path[] =
        "server { listen 8080; location /api { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({bad_path, sizeof(bad_path) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 32,
                   lit_str("only location / is supported")));

    const char dns[] =
        "server { listen 8080; location / { proxy_pass http://backend:1; } }";
    CHECK(is_error(nginx::parse({dns, sizeof(dns) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 47,
                   lit_str("only literal IPv4 HTTP upstreams are supported")));

    const char suffix[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1/api; } }";
    CHECK(is_error(nginx::parse({suffix, sizeof(suffix) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 47,
                   lit_str("proxy_pass URI suffixes are unsupported")));
}

TEST(nginx_parser, rejects_invalid_ports_ip_and_trailing_tokens) {
    const char port[] = "server { listen 0; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({port, sizeof(port) - 1}),
                   FrontendError::InvalidInteger, 1, 17, lit_str("invalid listen port")));

    const char ip[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.256:1; } }";
    CHECK(is_error(nginx::parse({ip, sizeof(ip) - 1}), FrontendError::InvalidInteger, 1, 47,
                   lit_str("invalid upstream IPv4 address or port")));

    const char upstream_port[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:65536; } }";
    CHECK(is_error(nginx::parse({upstream_port, sizeof(upstream_port) - 1}),
                   FrontendError::InvalidInteger, 1, 47,
                   lit_str("invalid upstream IPv4 address or port")));

    const char trailing[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } } junk";
    CHECK(is_error(nginx::parse({trailing, sizeof(trailing) - 1}),
                   FrontendError::UnexpectedToken, 1, 71,
                   lit_str("trailing unexpected tokens")));

    const char too_large[] =
        "server { listen 65536; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({too_large, sizeof(too_large) - 1}),
                   FrontendError::InvalidInteger, 1, 17, lit_str("invalid listen port")));
}

TEST(nginx_parser, rejects_modifiers_variables_and_non_http_upstreams) {
    const char modifiers[][80] = {
        "server { listen 8080; location = / { proxy_pass http://127.0.0.1:1; } }",
        "server { listen 8080; location ^~ / { proxy_pass http://127.0.0.1:1; } }",
        "server { listen 8080; location ~ / { proxy_pass http://127.0.0.1:1; } }",
        "server { listen 8080; location ~* / { proxy_pass http://127.0.0.1:1; } }",
    };
    for (u32 i = 0; i < 4; i++) {
        CHECK(is_error(nginx::parse({modifiers[i], sizeof(modifiers[i]) - 1}),
                       FrontendError::UnsupportedSyntax, 1, 32,
                       lit_str("location modifiers are unsupported")));
    }

    const char variable[] =
        "server { listen $port; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({variable, sizeof(variable) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 17,
                   lit_str("variables are unsupported")));

    const char proxy_variable[] =
        "server { listen 8080; location / { proxy_pass http://$backend:1; } }";
    CHECK(is_error(nginx::parse({proxy_variable, sizeof(proxy_variable) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 47,
                   lit_str("variables are unsupported")));

    const char https[] =
        "server { listen 8080; location / { proxy_pass https://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({https, sizeof(https) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 47,
                   lit_str("only literal IPv4 HTTP upstreams are supported")));
}

TEST(nginx_parser, reports_missing_listen_semicolon_at_brace) {
    const char source[] = "server { listen 8080 }";
    const auto result = nginx::parse({source, sizeof(source) - 1});
    REQUIRE(!result);
    CHECK_EQ(result.error().code, FrontendError::UnexpectedToken);
    CHECK_EQ(result.error().span.line, 1);
    CHECK_EQ(result.error().span.col, 22);
    CHECK(result.error().detail.eq(lit_str("expected ';' after listen")));
}

static nginx::Server canonical_server() {
    nginx::Server server{};
    server.listen.port = 8080;
    server.listen.span = Span{0, 13, 1, 1};
    server.location.path = lit_str("/");
    server.location.path_span = Span{22, 23, 1, 23};
    server.location.span = server.location.path_span;
    server.location.proxy_pass.address[0] = 127;
    server.location.proxy_pass.address[1] = 0;
    server.location.proxy_pass.address[2] = 0;
    server.location.proxy_pass.address[3] = 1;
    server.location.proxy_pass.port = 9000;
    server.location.proxy_pass.span = Span{26, 52, 1, 26};
    server.span = Span{0, 54, 1, 1};
    return server;
}

TEST(nginx_converter, lowers_canonical_model_to_stable_rut_source) {
    const auto result = nginx::lower_to_rut(canonical_server());
    REQUIRE(result);
    static constexpr char kExpected[] =
        "listen :8080\n"
        "upstream nginx_upstream at \"127.0.0.1:9000\"\n"
        "route \"/\" {\n"
        "    return forward(nginx_upstream, request_policy: {\n"
        "        version: \"HTTP/1.1\",\n"
        "        host: \"upstream\",\n"
        "        connection: \"omit\",\n"
        "        strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", \"Upgrade\"]\n"
        "    }, response_policy: {\n"
        "        version: \"HTTP/1.1\",\n"
        "        framing: \"content_length\",\n"
        "        connection: \"request\",\n"
        "        server: \"nginx/1.29.7\",\n"
        "        date: \"current\",\n"
        "        hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n"
        "    })\n"
        "}\n";
    CHECK_EQ(result.value().len, static_cast<u32>(sizeof(kExpected) - 1));
    CHECK(result.value().view().eq({kExpected, sizeof(kExpected) - 1}));
}

TEST(nginx_converter, formatting_and_comments_do_not_change_lowering) {
    const char compact[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    const char formatted[] =
        "# same model\n"
        "server {\n"
        "  listen 8080; # wildcard cleartext\n"
        "  location\t/ {\n"
        "    proxy_pass http://127.0.0.1:9000;\n"
        "  }\n"
        "}\n";
    auto compact_parsed = nginx::parse({compact, sizeof(compact) - 1});
    auto formatted_parsed = nginx::parse({formatted, sizeof(formatted) - 1});
    REQUIRE(compact_parsed);
    REQUIRE(formatted_parsed);
    auto compact_lowered = nginx::lower_to_rut(compact_parsed.value());
    auto formatted_lowered = nginx::lower_to_rut(formatted_parsed.value());
    REQUIRE(compact_lowered);
    REQUIRE(formatted_lowered);
    CHECK(compact_lowered.value().view().eq(formatted_lowered.value().view()));
}

TEST(nginx_converter, emitted_source_reaches_rir_with_source_metadata) {
    auto lowered = nginx::lower_to_rut(canonical_server());
    REQUIRE(lowered);
    auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->items.len, 3u);
    CHECK(ast_owned->items[0].kind == AstItemKind::Listen);
    CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE(hir_owned->has_listener);
    CHECK_EQ(hir_owned->listener.port, 8080u);
    // Listener declarations are startup metadata rather than RIR route state;
    // exercise the same source-to-startup resolution boundary used by main.
    ListenerSpec source_listener{};
    source_listener.port = hir_owned->listener.port;
    auto resolved_listener = resolve_listener_spec(true, source_listener, false, 0);
    REQUIRE(resolved_listener);
    CHECK_EQ(resolved_listener.value().port, 8080u);
    REQUIRE_EQ(hir_owned->upstreams.len, 1u);
    CHECK(hir_owned->upstreams[0].name.eq(lit_str("nginx_upstream")));
    CHECK(hir_owned->upstreams[0].has_address);
    CHECK_EQ(hir_owned->upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(hir_owned->upstreams[0].port, 9000u);
    REQUIRE_EQ(hir_owned->response_policies.len, 1u);
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    REQUIRE_EQ(mir_owned->upstreams.len, 1u);
    CHECK_EQ(mir_owned->upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(mir_owned->upstreams[0].port, 9000u);
    REQUIRE_EQ(mir_owned->response_policies.len, 1u);
    REQUIRE_EQ(mir_owned->functions.len, 1u);
    CHECK_EQ(mir_owned->functions[0].method, 0u);
    CHECK(mir_owned->functions[0].path.eq(lit_str("/")));
    CHECK_EQ(mir_owned->functions[0].blocks[0].term.forward_request_policy_id, 1u);
    CHECK(request_policy_is_supported(
        mir_owned->functions[0].blocks[0].term.forward_request_policy_id));
    const char* request_version = request_policy_version(
        mir_owned->functions[0].blocks[0].term.forward_request_policy_id);
    REQUIRE(request_version != nullptr);
    const Str request_version_str{request_version, 8};
    CHECK(request_version_str.eq(lit_str("HTTP/1.1")));
    CHECK_EQ(mir_owned->functions[0].blocks[0].term.forward_response_policy_id, 1u);

    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir_owned, rir));
    REQUIRE_EQ(rir.module.upstream_count, 1u);
    CHECK(rir.module.upstreams[0].name.eq(lit_str("nginx_upstream")));
    CHECK(rir.module.upstreams[0].has_address);
    CHECK_EQ(rir.module.upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(rir.module.upstreams[0].port, 9000u);
    REQUIRE_EQ(rir.module.response_policy_count, 1u);
    const auto& response_policy = rir.module.response_policies[0];
    CHECK(response_policy.version == ResponsePolicyVersion::Http11);
    CHECK(response_policy.framing == ResponsePolicyFraming::ContentLength);
    CHECK(response_policy.connection == ResponsePolicyConnection::Request);
    CHECK(response_policy.date == ResponsePolicyDate::Current);
    CHECK(response_policy.server.eq(lit_str("nginx/1.29.7")));
    REQUIRE_EQ(response_policy.hide_header_count, 3u);
    CHECK(response_policy.hide_headers[0].eq(lit_str("Date")));
    CHECK(response_policy.hide_headers[1].eq(lit_str("Server")));
    CHECK(response_policy.hide_headers[2].eq(lit_str("X-Pad")));

    REQUIRE_EQ(rir.module.func_count, 1u);
    const auto& function = rir.module.functions[0];
    CHECK(function.route_pattern.eq(lit_str("/")));
    CHECK_EQ(function.http_method, 0u);
    const auto* ret = find_ret_forward(function);
    REQUIRE(ret != nullptr);
    REQUIRE_EQ(ret->operand_count, 3u);
    i32 upstream_id = -1;
    i32 request_policy_id = -1;
    i32 response_policy_id = -1;
    REQUIRE(find_const_i32(function, ret->operand(0), upstream_id));
    REQUIRE(find_const_i32(function, ret->operand(1), request_policy_id));
    REQUIRE(find_const_i32(function, ret->operand(2), response_policy_id));
    CHECK_EQ(upstream_id, 0);
    CHECK_EQ(request_policy_id, 1);
    CHECK_EQ(response_policy_id, 1);
}

TEST(nginx_converter, rejects_forged_invalid_models_without_output) {
    auto invalid_listen = canonical_server();
    invalid_listen.listen.port = 0;
    auto bad_listen = nginx::lower_to_rut(invalid_listen);
    CHECK(!bad_listen);
    if (!bad_listen) {
        CHECK_EQ(bad_listen.error().code, FrontendError::InvalidInteger);
        CHECK_EQ(bad_listen.error().span.line, 1u);
    }

    auto invalid_upstream = canonical_server();
    invalid_upstream.location.proxy_pass.port = 0;
    auto bad_upstream = nginx::lower_to_rut(invalid_upstream);
    CHECK(!bad_upstream);
    if (!bad_upstream) CHECK_EQ(bad_upstream.error().code, FrontendError::InvalidInteger);

    auto invalid_path = canonical_server();
    invalid_path.location.path = lit_str("/api");
    auto bad_path = nginx::lower_to_rut(invalid_path);
    CHECK(!bad_path);
    if (!bad_path) CHECK_EQ(bad_path.error().code, FrontendError::UnsupportedSyntax);

    auto null_path = canonical_server();
    null_path.location.path = {nullptr, 1};
    auto bad_null_path = nginx::lower_to_rut(null_path);
    CHECK(!bad_null_path);
    if (!bad_null_path) CHECK_EQ(bad_null_path.error().code, FrontendError::UnsupportedSyntax);
}

int main(int argc, char** argv) { return rut::test::run_all(argc, argv); }
