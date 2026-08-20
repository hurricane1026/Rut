#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "rut/compiler/verifier.h"
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

static const rir::Instruction* find_ret_forward_bundle(const rir::Function& function) {
    for (u32 bi = 0; bi < function.block_count; bi++) {
        const auto& block = function.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            if (block.insts[ii].op == rir::Opcode::RetForwardBundle)
                return &block.insts[ii];
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
    CHECK_FALSE(result.value().location.proxy_pass.has_uri);
    CHECK_EQ(result.value().location.proxy_pass.uri.len, 0u);
    CHECK_EQ(result.value().location.proxy_pass.span.line, 4);
}

TEST(nginx_parser, parses_api_location_and_proxy_uri_with_spans) {
    const char source[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/;\n"
        "  }\n"
        "}\n";
    const auto result = nginx::parse({source, sizeof(source) - 1});
    REQUIRE(result);
    const auto& location = result.value().location;
    CHECK(location.path.eq(lit_str("/api/")));
    CHECK_EQ(location.path_span.line, 3u);
    CHECK_EQ(location.proxy_pass.port, 9000u);
    CHECK(location.proxy_pass.has_uri);
    CHECK(location.proxy_pass.uri.eq(lit_str("/")));
    CHECK_EQ(location.proxy_pass.uri_span.line, 4u);
    CHECK_EQ(location.proxy_pass.uri_span.start + 1, location.proxy_pass.uri_span.end);
    CHECK_LT(location.proxy_pass.uri_span.end, location.proxy_pass.span.end);
}

TEST(nginx_parser, rejects_unmatched_location_and_proxy_uri_shapes) {
    const char root_with_uri[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1/; } }";
    CHECK(is_error(nginx::parse({root_with_uri, sizeof(root_with_uri) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 65,
                   lit_str("location / cannot use a proxy_pass URI")));

    const char api_without_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({api_without_uri, sizeof(api_without_uri) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 32,
                   lit_str("location /api/ requires proxy_pass URI /")));

    const char api_without_trailing_slash[] =
        "server { listen 8080; location /api { proxy_pass http://127.0.0.1:1/; } }";
    CHECK(is_error(nginx::parse({api_without_trailing_slash,
                                 sizeof(api_without_trailing_slash) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 32,
                   lit_str("only location / or /api/ is supported")));

    const char other_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/v1; } }";
    CHECK(is_error(nginx::parse({other_uri, sizeof(other_uri) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 51,
                   lit_str("proxy_pass URI suffixes are unsupported")));

    const char variable_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/$x; } }";
    CHECK(is_error(nginx::parse({variable_uri, sizeof(variable_uri) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 51,
                   lit_str("variables are unsupported")));

    const char query_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/?x; } }";
    CHECK(is_error(nginx::parse({query_uri, sizeof(query_uri) - 1}),
                   FrontendError::UnsupportedSyntax, 1, 51,
                   lit_str("proxy_pass URI suffixes are unsupported")));

    const char fragment_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/#x; } }";
    const auto fragment_result = nginx::parse({fragment_uri, sizeof(fragment_uri) - 1});
    CHECK_FALSE(fragment_result);
    if (!fragment_result) {
        CHECK_EQ(fragment_result.error().code, FrontendError::UnexpectedEof);
        CHECK_EQ(fragment_result.error().span.line, 1u);
        CHECK(fragment_result.error().detail.eq(lit_str("expected ';' after proxy_pass")));
    }
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
                   lit_str("only location / or /api/ is supported")));

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

static nginx::Server api_server() {
    nginx::Server server = canonical_server();
    server.location.path = lit_str("/api/");
    server.location.path_span = Span{22, 27, 1, 23};
    static constexpr char kProxyUri[] = "/";
    server.location.proxy_pass.has_uri = true;
    server.location.proxy_pass.uri = {kProxyUri, 1};
    server.location.proxy_pass.uri_span = Span{53, 54, 1, 54};
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
        "    }, failure_policy: {\n"
        "        version: \"HTTP/1.1\",\n"
        "        status: 502,\n"
        "        reason: \"Bad Gateway\",\n"
        "        content_type: \"text/html\",\n"
        "        server: \"nginx/1.29.7\",\n"
        "        date: \"current\",\n"
        "        connection: \"request\",\n"
        "        body: b\"<html>\\r\\n<head><title>502 Bad Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "    })\n"
        "}\n";
    CHECK_EQ(result.value().len, static_cast<u32>(sizeof(kExpected) - 1));
    CHECK(result.value().view().eq({kExpected, sizeof(kExpected) - 1}));
}

TEST(nginx_converter, lowers_api_model_to_stable_target_transform_source) {
    const auto result = nginx::lower_to_rut(api_server());
    REQUIRE(result);
    static constexpr char kExpected[] =
        "listen :8080\n"
        "upstream nginx_upstream at \"127.0.0.1:9000\"\n"
        "route \"/api\" {\n"
        "    if req.method == GET && req.pathOnly == \"/api\" {\n"
        "        return redirect({scheme: \"http\", authority: \"request_host\", port: \"actual_listener\",\n"
        "            path: \"static\", query: \"preserve_raw\", date: \"current\", connection: \"close\",\n"
        "            status: 301, reason: \"Moved Permanently\", server: \"nginx/1.29.7\",\n"
        "            content_type: \"text/html\", target_path: \"/api/\", body: b\"<html>\\r\\n"
        "<head><title>301 Moved Permanently</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>301 Moved Permanently</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n\"})\n"
        "    } else {\n"
        "        return forward(nginx_upstream, target_transform: {\n"
        "            strip_prefix: \"/api/\",\n"
        "            replace_prefix: \"/\"\n"
        "        }, request_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            host: \"upstream\",\n"
        "            connection: \"omit\",\n"
        "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", \"Upgrade\"]\n"
        "        }, response_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            framing: \"content_length\",\n"
        "            connection: \"request\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n"
        "        }, failure_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            status: 502,\n"
        "            reason: \"Bad Gateway\",\n"
        "            content_type: \"text/html\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            connection: \"request\",\n"
        "            body: b\"<html>\\r\\n<head><title>502 Bad Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "        })\n"
        "    }\n"
        "}\n";
    CHECK_EQ(result.value().len, static_cast<u32>(sizeof(kExpected) - 1));
    CHECK_GT(result.value().len, 1024u);
    CHECK_LT(result.value().len, nginx::RutSource::kCapacity);
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
    REQUIRE_EQ(hir_owned->failure_policies.len, 1u);
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    REQUIRE_EQ(mir_owned->upstreams.len, 1u);
    CHECK_EQ(mir_owned->upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(mir_owned->upstreams[0].port, 9000u);
    REQUIRE_EQ(mir_owned->response_policies.len, 1u);
    REQUIRE_EQ(mir_owned->failure_policies.len, 1u);
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

    REQUIRE_EQ(rir.module.failure_policy_count, 1u);
    const auto& failure_policy = rir.module.failure_policies[0];
    CHECK(failure_policy.version == ForwardFailurePolicyVersion::Http11);
    CHECK_EQ(failure_policy.status_code, 502u);
    CHECK(failure_policy.date == ForwardFailurePolicyDate::Current);
    CHECK(failure_policy.connection == ForwardFailurePolicyConnection::Request);
    CHECK(failure_policy.reason.eq(lit_str("Bad Gateway")));
    CHECK(failure_policy.content_type.eq(lit_str("text/html")));
    CHECK(failure_policy.server.eq(lit_str("nginx/1.29.7")));
    static constexpr char kFailureBody[] =
        "<html>\r\n"
        "<head><title>502 Bad Gateway</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>502 Bad Gateway</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    CHECK_EQ(failure_policy.body.len, 157u);
    CHECK_EQ(failure_policy.body.len, static_cast<u32>(sizeof(kFailureBody) - 1));
    CHECK(failure_policy.body.eq({kFailureBody, sizeof(kFailureBody) - 1}));

    REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);

    REQUIRE_EQ(rir.module.func_count, 1u);
    const auto& function = rir.module.functions[0];
    CHECK(function.route_pattern.eq(lit_str("/")));
    CHECK_EQ(function.http_method, 0u);
    const auto* ret = find_ret_forward_bundle(function);
    REQUIRE(ret != nullptr);
    REQUIRE_EQ(ret->operand_count, 3u);
    i32 upstream_id = -1;
    i32 request_policy_id = -1;
    i32 bundle_id = -1;
    REQUIRE(find_const_i32(function, ret->operand(0), upstream_id));
    REQUIRE(find_const_i32(function, ret->operand(1), request_policy_id));
    REQUIRE(find_const_i32(function, ret->operand(2), bundle_id));
    CHECK_EQ(upstream_id, 0);
    CHECK_EQ(request_policy_id, 1);
    CHECK_EQ(bundle_id, 1);
}

TEST(nginx_converter, emitted_api_source_reaches_rir_with_target_transform) {
    auto lowered = nginx::lower_to_rut(api_server());
    REQUIRE(lowered);
    auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE_EQ(hir_owned->routes.len, 1u);
    CHECK_EQ(hir_owned->routes[0].control.kind, HirControlKind::If);
    const auto& hir_redirect = hir_owned->routes[0].control.then_term;
    const auto& hir_forward = hir_owned->routes[0].control.else_term;
    CHECK(hir_redirect.kind == HirTerminatorKind::Redirect);
    CHECK_EQ(hir_redirect.redirect_policy_id, 1u);
    REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
    REQUIRE(hir_forward.has_forward_target_transform);
    CHECK(hir_forward.forward_target_transform.strip_prefix.eq(lit_str("/api/")));
    CHECK(hir_forward.forward_target_transform.replace_prefix.eq(lit_str("/")));
    CHECK_EQ(hir_forward.forward_request_policy_id, 1u);
    CHECK_EQ(hir_forward.forward_response_policy_id, 1u);
    CHECK_EQ(hir_forward.forward_failure_policy_id, 1u);

    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    CHECK(mir_owned->functions[0].path.eq(lit_str("/api")));
    bool mir_redirect = false;
    bool mir_forward = false;
    for (u32 bi = 0; bi < mir_owned->functions[0].blocks.len; bi++) {
        const auto& term = mir_owned->functions[0].blocks[bi].term;
        if (term.kind == MirTerminatorKind::Redirect) {
            mir_redirect = true;
            CHECK_EQ(term.redirect_policy_id, 1u);
        }
        if (term.kind == MirTerminatorKind::ForwardUpstream) {
            mir_forward = true;
            CHECK(term.has_forward_target_transform);
            CHECK_EQ(term.forward_request_policy_id, 1u);
            CHECK_EQ(term.forward_response_policy_id, 1u);
            CHECK_EQ(term.forward_failure_policy_id, 1u);
        }
    }
    CHECK(mir_redirect);
    CHECK(mir_forward);

    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir_owned, rir));
    auto verified = rir::verify_module(rir.module);
    REQUIRE(verified.ok);
    REQUIRE_EQ(rir.module.target_transform_count, 1u);
    CHECK(rir.module.target_transforms[0].strip_prefix.eq(lit_str("/api/")));
    CHECK(rir.module.target_transforms[0].replace_prefix.eq(lit_str("/")));
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    const auto& redirect = rir.module.redirect_policies[0];
    CHECK(redirect.scheme == RedirectPolicyScheme::Http);
    CHECK(redirect.authority == RedirectPolicyAuthority::RequestHost);
    CHECK(redirect.port == RedirectPolicyPort::ActualListener);
    CHECK(redirect.path == RedirectPolicyPath::Static);
    CHECK(redirect.query == RedirectPolicyQuery::PreserveRaw);
    CHECK(redirect.date == RedirectPolicyDate::Current);
    CHECK(redirect.connection == RedirectPolicyConnection::Close);
    CHECK_EQ(redirect.status_code, 301u);
    CHECK(redirect.reason.eq(lit_str("Moved Permanently")));
    CHECK(redirect.server.eq(lit_str("nginx/1.29.7")));
    CHECK(redirect.content_type.eq(lit_str("text/html")));
    CHECK(redirect.target_path.eq(lit_str("/api/")));
    static constexpr char kRedirectBody[] =
        "<html>\r\n"
        "<head><title>301 Moved Permanently</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>301 Moved Permanently</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    CHECK(redirect.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1}));
    REQUIRE_EQ(rir.module.response_policy_count, 1u);
    REQUIRE_EQ(rir.module.failure_policy_count, 1u);
    REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);

    const auto& function = rir.module.functions[0];
    CHECK(function.route_pattern.eq(lit_str("/api")));
    CHECK_EQ(function.http_method, 0u);
    bool saw_branch = false;
    bool saw_redirect = false;
    bool saw_forward = false;
    for (u32 bi = 0; bi < function.block_count; bi++) {
        const auto& block = function.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            const auto& instruction = block.insts[ii];
            if (instruction.op == rir::Opcode::Br) saw_branch = true;
            if (instruction.op == rir::Opcode::RetRedirect) {
                saw_redirect = true;
                CHECK_EQ(instruction.operand_count, 0u);
                CHECK_EQ(instruction.imm.i32_val, 1);
            }
            if (instruction.op != rir::Opcode::RetForwardBundle) continue;
            saw_forward = true;
            REQUIRE_EQ(instruction.operand_count, 3u);
            i32 upstream_id = -1;
            i32 request_policy_id = -1;
            i32 bundle_id = -1;
            REQUIRE(find_const_i32(function, instruction.operand(0), upstream_id));
            REQUIRE(find_const_i32(function, instruction.operand(1), request_policy_id));
            REQUIRE(find_const_i32(function, instruction.operand(2), bundle_id));
            CHECK_EQ(upstream_id, 0);
            CHECK_EQ(request_policy_id, 1);
            CHECK_EQ(bundle_id, 1);
            REQUIRE(ii > 0);
            CHECK_EQ(block.insts[ii - 1].op, rir::Opcode::ReqSetTargetTransform);
            CHECK_EQ(block.insts[ii - 1].imm.i32_val, 1);
        }
    }
    CHECK(saw_branch);
    CHECK(saw_redirect);
    CHECK(saw_forward);
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

    auto api_without_uri = api_server();
    api_without_uri.location.proxy_pass.has_uri = false;
    api_without_uri.location.proxy_pass.uri = {};
    auto bad_api_without_uri = nginx::lower_to_rut(api_without_uri);
    CHECK(!bad_api_without_uri);
    if (!bad_api_without_uri)
        CHECK_EQ(bad_api_without_uri.error().code, FrontendError::UnsupportedSyntax);

    auto root_with_uri = canonical_server();
    static constexpr char kSlash[] = "/";
    root_with_uri.location.proxy_pass.has_uri = true;
    root_with_uri.location.proxy_pass.uri = {kSlash, 1};
    auto bad_root_with_uri = nginx::lower_to_rut(root_with_uri);
    CHECK(!bad_root_with_uri);
    if (!bad_root_with_uri)
        CHECK_EQ(bad_root_with_uri.error().code, FrontendError::UnsupportedSyntax);

    auto null_uri = api_server();
    null_uri.location.proxy_pass.uri = {nullptr, 1};
    auto bad_null_uri = nginx::lower_to_rut(null_uri);
    CHECK(!bad_null_uri);
    if (!bad_null_uri) CHECK_EQ(bad_null_uri.error().code, FrontendError::UnsupportedSyntax);

    auto invalid_uri = api_server();
    static constexpr char kBadUri[] = "/v1";
    invalid_uri.location.proxy_pass.uri = {kBadUri, 3};
    auto bad_uri = nginx::lower_to_rut(invalid_uri);
    CHECK(!bad_uri);
    if (!bad_uri) CHECK_EQ(bad_uri.error().code, FrontendError::UnsupportedSyntax);

    auto stale_uri_view = canonical_server();
    stale_uri_view.location.proxy_pass.uri = {kSlash, 1};
    auto bad_stale_uri_view = nginx::lower_to_rut(stale_uri_view);
    CHECK(!bad_stale_uri_view);
    if (!bad_stale_uri_view)
        CHECK_EQ(bad_stale_uri_view.error().code, FrontendError::UnsupportedSyntax);
}

int main(int argc, char** argv) { return rut::test::run_all(argc, argv); }
