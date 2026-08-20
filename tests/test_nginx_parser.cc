#include "rut/nginx/parser.h"
#include "test.h"

using namespace rut;

namespace {

static bool is_error(const FrontendResult<nginx::Server>& result,
                     FrontendError code,
                     u32 line,
                     u32 col) {
    return !result && result.error().code == code && result.error().span.line == line &&
           result.error().span.col == col;
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
    const auto missing_listen = nginx::parse({no_listen, sizeof(no_listen) - 1});
    CHECK(!missing_listen);
    CHECK(missing_listen.error().detail.eq(lit_str("missing listen")));

    const char duplicate[] =
        "server { listen 8080; listen 8081; location / { proxy_pass http://127.0.0.1:1; } }";
    const auto duplicate_listen = nginx::parse({duplicate, sizeof(duplicate) - 1});
    CHECK(duplicate_listen.error().detail.eq(lit_str("duplicate listen")));

    const char no_proxy[] = "server { listen 8080; location / { } }";
    const auto missing_proxy = nginx::parse({no_proxy, sizeof(no_proxy) - 1});
    CHECK(missing_proxy.error().detail.eq(lit_str("missing proxy_pass")));
}

TEST(nginx_parser, rejects_out_of_scope_contexts_and_values) {
    const char wrappers[] = "http { server { listen 8080; } }";
    CHECK(is_error(nginx::parse({wrappers, sizeof(wrappers) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   1));

    const char bad_path[] =
        "server { listen 8080; location /api { proxy_pass http://127.0.0.1:1; } }";
    CHECK(nginx::parse({bad_path, sizeof(bad_path) - 1}).error().detail.eq(
        lit_str("only location / is supported")));

    const char dns[] =
        "server { listen 8080; location / { proxy_pass http://backend:1; } }";
    CHECK(nginx::parse({dns, sizeof(dns) - 1}).error().detail.eq(
        lit_str("only literal IPv4 HTTP upstreams are supported")));

    const char suffix[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1/api; } }";
    CHECK(nginx::parse({suffix, sizeof(suffix) - 1}).error().detail.eq(
        lit_str("only literal IPv4 HTTP upstreams are supported")));
}

TEST(nginx_parser, rejects_invalid_ports_ip_and_trailing_tokens) {
    const char port[] = "server { listen 0; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({port, sizeof(port) - 1}), FrontendError::UnexpectedToken, 1, 17));

    const char ip[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.256:1; } }";
    CHECK(nginx::parse({ip, sizeof(ip) - 1}).error().detail.eq(
        lit_str("only literal IPv4 HTTP upstreams are supported")));

    const char trailing[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } } junk";
    const auto trailing_result = nginx::parse({trailing, sizeof(trailing) - 1});
    REQUIRE(!trailing_result);
    CHECK_EQ(trailing_result.error().code, FrontendError::UnexpectedToken);
    CHECK_EQ(trailing_result.error().span.line, 1);
    CHECK_GT(trailing_result.error().span.col, 1);
    CHECK(trailing_result.error().detail.eq(lit_str("trailing unexpected tokens")));

    const char too_large[] =
        "server { listen 65536; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(nginx::parse({too_large, sizeof(too_large) - 1}).error().detail.eq(
        lit_str("invalid listen port")));
}

TEST(nginx_parser, rejects_modifiers_variables_and_non_http_upstreams) {
    const char modifier[] =
        "server { listen 8080; location ^~ / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(nginx::parse({modifier, sizeof(modifier) - 1}).error().detail.eq(
        lit_str("location modifiers are unsupported")));

    const char variable[] =
        "server { listen $port; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(nginx::parse({variable, sizeof(variable) - 1}).error().detail.eq(
        lit_str("variables are unsupported")));

    const char https[] =
        "server { listen 8080; location / { proxy_pass https://127.0.0.1:1; } }";
    CHECK(nginx::parse({https, sizeof(https) - 1}).error().detail.eq(
        lit_str("only literal IPv4 HTTP upstreams are supported")));
}

int main(int argc, char** argv) { return rut::test::run_all(argc, argv); }
