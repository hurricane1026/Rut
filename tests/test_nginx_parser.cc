#include "rut/nginx/parser.h"
#include "test.h"

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

int main(int argc, char** argv) { return rut::test::run_all(argc, argv); }
