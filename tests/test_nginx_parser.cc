#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/verifier.h"
#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "rut/runtime/compile_to_config.h"
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
    CHECK_FALSE(result.value().location.proxy_read_timeout.present);
    CHECK_EQ(result.value().location.proxy_read_timeout.milliseconds, 0u);
    CHECK_EQ(result.value().location.proxy_read_timeout.span.start, 0u);
    CHECK_EQ(result.value().location.proxy_read_timeout.span.end, 0u);
    CHECK_EQ(result.value().location.proxy_read_timeout.span.line, 1u);
    CHECK_EQ(result.value().location.proxy_read_timeout.span.col, 1u);
    CHECK_EQ(result.value().location.proxy_read_timeout.value_span.start, 0u);
    CHECK_EQ(result.value().location.proxy_read_timeout.value_span.end, 0u);
    CHECK_EQ(result.value().location.proxy_read_timeout.value_span.line, 1u);
    CHECK_EQ(result.value().location.proxy_read_timeout.value_span.col, 1u);
}

TEST(nginx_parser, parses_bounded_proxy_read_timeout_in_either_directive_order) {
    const char timeout_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / {\n"
        "    proxy_read_timeout 1s;\n"
        "    proxy_pass http://127.0.0.1:9000;\n"
        "  }\n"
        "}\n";
    const auto first = nginx::parse({timeout_first, sizeof(timeout_first) - 1});
    REQUIRE(first);
    const auto& first_timeout = first.value().location.proxy_read_timeout;
    REQUIRE(first_timeout.present);
    CHECK_EQ(first_timeout.milliseconds, 1000u);
    const char* first_keyword = strstr(timeout_first, "proxy_read_timeout");
    const char* first_value = strstr(first_keyword, "1s");
    const char* first_semicolon = strchr(first_value, ';');
    REQUIRE(first_keyword != nullptr);
    REQUIRE(first_value != nullptr);
    REQUIRE(first_semicolon != nullptr);
    CHECK_EQ(first_timeout.span.start, static_cast<u32>(first_keyword - timeout_first));
    CHECK_EQ(first_timeout.span.end, static_cast<u32>(first_semicolon - timeout_first + 1));
    CHECK_EQ(first_timeout.span.line, 4u);
    CHECK_EQ(first_timeout.span.col, 5u);
    CHECK_EQ(first_timeout.value_span.start, static_cast<u32>(first_value - timeout_first));
    CHECK_EQ(first_timeout.value_span.end, static_cast<u32>(first_value - timeout_first + 2));
    CHECK_EQ(first_timeout.value_span.line, 4u);
    CHECK_EQ(first_timeout.value_span.col, 24u);

    const char timeout_last[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; "
        "proxy_read_timeout 63s; } }";
    const auto last = nginx::parse({timeout_last, sizeof(timeout_last) - 1});
    REQUIRE(last);
    const auto& last_timeout = last.value().location.proxy_read_timeout;
    REQUIRE(last_timeout.present);
    CHECK_EQ(last_timeout.milliseconds, 63000u);
    const char* last_keyword = strstr(timeout_last, "proxy_read_timeout");
    const char* last_value = strstr(last_keyword, "63s");
    const char* last_semicolon = strchr(last_value, ';');
    REQUIRE(last_keyword != nullptr);
    REQUIRE(last_value != nullptr);
    REQUIRE(last_semicolon != nullptr);
    CHECK_EQ(last_timeout.span.start, static_cast<u32>(last_keyword - timeout_last));
    CHECK_EQ(last_timeout.span.end, static_cast<u32>(last_semicolon - timeout_last + 1));
    CHECK_EQ(last_timeout.value_span.start, static_cast<u32>(last_value - timeout_last));
    CHECK_EQ(last_timeout.value_span.end, static_cast<u32>(last_value - timeout_last + 3));
}

TEST(nginx_parser, rejects_proxy_read_timeout_bad_arity_and_bounded_values) {
    struct Vector {
        const char* source;
        FrontendError code;
        const char* at;
        Str detail;
    };
    const Vector vectors[] = {
        {"server { listen 8080; location / { proxy_read_timeout; proxy_pass "
         "http://127.0.0.1:1; } }",
         FrontendError::UnexpectedToken,
         ";",
         lit_str("proxy_read_timeout requires a value")},
        {"server { listen 8080; location / { proxy_read_timeout 1s } }",
         FrontendError::UnexpectedToken,
         "}",
         lit_str("expected ';' after proxy_read_timeout")},
        {"server { listen 8080; location / { proxy_read_timeout 1s proxy_pass "
         "http://127.0.0.1:1; } }",
         FrontendError::UnexpectedToken,
         "proxy_pass",
         lit_str("expected ';' after proxy_read_timeout")},
        {"server { listen 8080; location / { proxy_read_timeout 1s extra; proxy_pass "
         "http://127.0.0.1:1; } }",
         FrontendError::UnexpectedToken,
         "extra",
         lit_str("proxy_read_timeout accepts exactly one value")},
        {"server { listen 8080; location / { proxy_read_timeout 0s; proxy_pass "
         "http://127.0.0.1:1; } }",
         FrontendError::UnsupportedSyntax,
         "0s",
         lit_str("only proxy_read_timeout 1s through 63s is supported")},
        {"server { listen 8080; location / { proxy_read_timeout 64s; proxy_pass "
         "http://127.0.0.1:1; } }",
         FrontendError::UnsupportedSyntax,
         "64s",
         lit_str("only proxy_read_timeout 1s through 63s is supported")},
        {"server { listen 8080; location / { proxy_read_timeout 42949672960s; proxy_pass "
         "http://127.0.0.1:1; } }",
         FrontendError::UnsupportedSyntax,
         "42949672960s",
         lit_str("only proxy_read_timeout 1s through 63s is supported")},
        {"server { listen 8080; location / { proxy_read_timeout "
         "999999999999999999999999999999999999999999999999999999999999999999999999s; "
         "proxy_pass http://127.0.0.1:1; } }",
         FrontendError::UnsupportedSyntax,
         "999999999999999999999999999999999999999999999999999999999999999999999999s",
         lit_str("only proxy_read_timeout 1s through 63s is supported")},
    };
    for (const auto& vector : vectors) {
        const Str source{vector.source, static_cast<u32>(strlen(vector.source))};
        const auto result = nginx::parse(source);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, vector.code);
        CHECK(result.error().detail.eq(vector.detail));
        const char* keyword = strstr(vector.source, "proxy_read_timeout");
        REQUIRE(keyword != nullptr);
        const char* expected = strstr(keyword, vector.at);
        REQUIRE(expected != nullptr);
        CHECK_EQ(result.error().span.start, static_cast<u32>(expected - vector.source));
    }

    const char missing_value_eof[] = "server { listen 8080; location / { proxy_read_timeout";
    const auto missing_value_result =
        nginx::parse({missing_value_eof, sizeof(missing_value_eof) - 1});
    REQUIRE_FALSE(missing_value_result);
    CHECK_EQ(missing_value_result.error().code, FrontendError::UnexpectedEof);
    CHECK_EQ(missing_value_result.error().span.start, sizeof(missing_value_eof) - 1);
    CHECK(missing_value_result.error().detail.eq(lit_str("proxy_read_timeout requires a value")));

    const char missing_semicolon_eof[] = "server { listen 8080; location / { proxy_read_timeout 1s";
    const auto missing_semicolon_result =
        nginx::parse({missing_semicolon_eof, sizeof(missing_semicolon_eof) - 1});
    REQUIRE_FALSE(missing_semicolon_result);
    CHECK_EQ(missing_semicolon_result.error().code, FrontendError::UnexpectedEof);
    CHECK_EQ(missing_semicolon_result.error().span.start, sizeof(missing_semicolon_eof) - 1);
    CHECK(missing_semicolon_result.error().detail.eq(
        lit_str("expected ';' after proxy_read_timeout")));

    const char duplicate[] =
        "server { listen 8080; location / { proxy_read_timeout 1s; proxy_pass "
        "http://127.0.0.1:1; proxy_read_timeout 2s; } }";
    const auto duplicate_result = nginx::parse({duplicate, sizeof(duplicate) - 1});
    REQUIRE_FALSE(duplicate_result);
    CHECK_EQ(duplicate_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(duplicate_result.error().detail.eq(lit_str("duplicate proxy_read_timeout")));
    const char* second = strstr(strstr(duplicate, "proxy_read_timeout") + 1, "proxy_read_timeout");
    REQUIRE(second != nullptr);
    CHECK_EQ(duplicate_result.error().span.start, static_cast<u32>(second - duplicate));
}

TEST(nginx_parser, rejects_excluded_and_invalid_proxy_read_timeout_forms) {
    struct Vector {
        const char* value;
        FrontendError code;
        Str detail;
    };
    const Vector vectors[] = {
        {"1",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"1000ms",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"1m",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"1m30s",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"\"1s\"",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"'1s'",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"\\1s",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"1\\s",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"\"1\\s\"",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"01s",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_read_timeout value form is unsupported")},
        {"1.5s", FrontendError::InvalidInteger, lit_str("invalid proxy_read_timeout value")},
        {"$timeout", FrontendError::InvalidInteger, lit_str("invalid proxy_read_timeout value")},
    };
    for (const auto& vector : vectors) {
        char source[256]{};
        const int source_len =
            snprintf(source,
                     sizeof(source),
                     "server { listen 8080; location / { proxy_read_timeout %s; proxy_pass "
                     "http://127.0.0.1:1; } }",
                     vector.value);
        REQUIRE_GT(source_len, 0);
        const auto result = nginx::parse({source, static_cast<u32>(source_len)});
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, vector.code);
        CHECK(result.error().detail.eq(vector.detail));
        const char* value = strstr(source, vector.value);
        REQUIRE(value != nullptr);
        CHECK_EQ(result.error().span.start, static_cast<u32>(value - source));
    }
}

TEST(nginx_parser, rejects_proxy_read_timeout_outside_exact_root_location_context) {
    const char server_level[] =
        "server { listen 8080; proxy_read_timeout 1s; location / { proxy_pass "
        "http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({server_level, sizeof(server_level) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   23,
                   lit_str("proxy_read_timeout is unsupported at server level")));

    const char wrapped[] =
        "http { server { listen 8080; location / { proxy_read_timeout 1s; proxy_pass "
        "http://127.0.0.1:1; } } }";
    CHECK(is_error(nginx::parse({wrapped, sizeof(wrapped) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   1,
                   lit_str("http/events wrappers are unsupported")));

    const char nested[] =
        "server { listen 8080; location / { location /nested { proxy_read_timeout 1s; } "
        "proxy_pass http://127.0.0.1:1; } }";
    const auto nested_result = nginx::parse({nested, sizeof(nested) - 1});
    REQUIRE_FALSE(nested_result);
    CHECK_EQ(nested_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(nested_result.error().detail.eq(lit_str("nested locations are unsupported")));
    CHECK_EQ(nested_result.error().span.start,
             static_cast<u32>(strstr(strstr(nested, "location") + 1, "location") - nested));

    const char transformed[] =
        "server { listen 8080; location /api/ { proxy_read_timeout 1s; proxy_pass "
        "http://127.0.0.1:1/; } }";
    const auto transformed_result = nginx::parse({transformed, sizeof(transformed) - 1});
    REQUIRE_FALSE(transformed_result);
    CHECK_EQ(transformed_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(transformed_result.error().detail.eq(
        lit_str("proxy_read_timeout is unsupported in transformed locations")));
    CHECK_EQ(transformed_result.error().span.start,
             static_cast<u32>(strstr(transformed, "proxy_read_timeout") - transformed));

    const char other_location[] =
        "server { listen 8080; location /other { proxy_read_timeout 1s; proxy_pass "
        "http://127.0.0.1:1; } }";
    const auto other_result = nginx::parse({other_location, sizeof(other_location) - 1});
    REQUIRE_FALSE(other_result);
    CHECK_EQ(other_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(other_result.error().detail.eq(lit_str("only location / or /api/ is supported")));
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
                   FrontendError::UnsupportedSyntax,
                   1,
                   65,
                   lit_str("location / cannot use a proxy_pass URI")));

    const char api_without_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({api_without_uri, sizeof(api_without_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   32,
                   lit_str("location /api/ requires proxy_pass URI /")));

    const char api_without_trailing_slash[] =
        "server { listen 8080; location /api { proxy_pass http://127.0.0.1:1/; } }";
    CHECK(
        is_error(nginx::parse({api_without_trailing_slash, sizeof(api_without_trailing_slash) - 1}),
                 FrontendError::UnsupportedSyntax,
                 1,
                 32,
                 lit_str("only location / or /api/ is supported")));

    const char other_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/v1; } }";
    CHECK(is_error(nginx::parse({other_uri, sizeof(other_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   51,
                   lit_str("proxy_pass URI suffixes are unsupported")));

    const char variable_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/$x; } }";
    CHECK(is_error(nginx::parse({variable_uri, sizeof(variable_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   51,
                   lit_str("variables are unsupported")));

    const char query_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/?x; } }";
    CHECK(is_error(nginx::parse({query_uri, sizeof(query_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   51,
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
                   FrontendError::UnsupportedSyntax,
                   1,
                   1,
                   lit_str("missing listen")));

    const char duplicate_listen[] =
        "server { listen 8080; listen 8081; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({duplicate_listen, sizeof(duplicate_listen) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   23,
                   lit_str("duplicate listen")));

    const char no_location[] = "server { listen 8080; }";
    CHECK(is_error(nginx::parse({no_location, sizeof(no_location) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   1,
                   lit_str("missing location")));

    const char duplicate_location[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location / { "
        "proxy_pass http://127.0.0.1:2; } }";
    CHECK(is_error(nginx::parse({duplicate_location, sizeof(duplicate_location) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   69,
                   lit_str("duplicate location")));

    const char no_proxy[] = "server { listen 8080; location / { } }";
    CHECK(is_error(nginx::parse({no_proxy, sizeof(no_proxy) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   36,
                   lit_str("missing proxy_pass")));

    const char duplicate_proxy[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; proxy_pass "
        "http://127.0.0.1:2; } }";
    CHECK(is_error(nginx::parse({duplicate_proxy, sizeof(duplicate_proxy) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   67,
                   lit_str("duplicate proxy_pass")));
}

TEST(nginx_parser, rejects_unknown_directives_and_multiple_servers) {
    const char unknown_server[] = "server { listen 8080; worker_processes 1; }";
    CHECK(is_error(nginx::parse({unknown_server, sizeof(unknown_server) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   23,
                   lit_str("unknown server directive")));

    const char unknown_location[] = "server { listen 8080; location / { return 200; } }";
    CHECK(is_error(nginx::parse({unknown_location, sizeof(unknown_location) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   36,
                   lit_str("unknown location directive")));

    const char second_server[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } } server { listen "
        "8081; }";
    CHECK(is_error(nginx::parse({second_server, sizeof(second_server) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   71,
                   lit_str("multiple servers are unsupported")));
}

TEST(nginx_parser, rejects_missing_braces_and_semicolons) {
    const char missing_server_brace[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; }";
    CHECK(is_error(nginx::parse({missing_server_brace, sizeof(missing_server_brace) - 1}),
                   FrontendError::UnexpectedEof,
                   1,
                   68,
                   lit_str("missing '}' for server")));

    const char missing_location_brace[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; ";
    CHECK(is_error(nginx::parse({missing_location_brace, sizeof(missing_location_brace) - 1}),
                   FrontendError::UnexpectedEof,
                   1,
                   67,
                   lit_str("missing '}' for location")));

    const char missing_listen_semicolon[] =
        "server { listen 8080 location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({missing_listen_semicolon, sizeof(missing_listen_semicolon) - 1}),
                   FrontendError::UnexpectedToken,
                   1,
                   22,
                   lit_str("expected ';' after listen")));

    const char missing_proxy_semicolon[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1 } }";
    CHECK(is_error(nginx::parse({missing_proxy_semicolon, sizeof(missing_proxy_semicolon) - 1}),
                   FrontendError::UnexpectedToken,
                   1,
                   66,
                   lit_str("expected ';' after proxy_pass")));

    const char missing_final_semicolon[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1";
    CHECK(is_error(nginx::parse({missing_final_semicolon, sizeof(missing_final_semicolon) - 1}),
                   FrontendError::UnexpectedEof,
                   1,
                   65,
                   lit_str("expected ';' after proxy_pass")));
}

TEST(nginx_parser, rejects_out_of_scope_contexts_and_values) {
    const char wrappers[] = "http { server { listen 8080; } }";
    CHECK(is_error(
        nginx::parse({wrappers, sizeof(wrappers) - 1}), FrontendError::UnsupportedSyntax, 1, 1));

    const char bad_path[] =
        "server { listen 8080; location /api { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({bad_path, sizeof(bad_path) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   32,
                   lit_str("only location / or /api/ is supported")));

    const char dns[] = "server { listen 8080; location / { proxy_pass http://backend:1; } }";
    CHECK(is_error(nginx::parse({dns, sizeof(dns) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   47,
                   lit_str("only literal IPv4 HTTP upstreams are supported")));

    const char suffix[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1/api; } }";
    CHECK(is_error(nginx::parse({suffix, sizeof(suffix) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   47,
                   lit_str("proxy_pass URI suffixes are unsupported")));
}

TEST(nginx_parser, rejects_invalid_ports_ip_and_trailing_tokens) {
    const char port[] = "server { listen 0; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({port, sizeof(port) - 1}),
                   FrontendError::InvalidInteger,
                   1,
                   17,
                   lit_str("invalid listen port")));

    const char ip[] = "server { listen 8080; location / { proxy_pass http://127.0.0.256:1; } }";
    CHECK(is_error(nginx::parse({ip, sizeof(ip) - 1}),
                   FrontendError::InvalidInteger,
                   1,
                   47,
                   lit_str("invalid upstream IPv4 address or port")));

    const char upstream_port[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:65536; } }";
    CHECK(is_error(nginx::parse({upstream_port, sizeof(upstream_port) - 1}),
                   FrontendError::InvalidInteger,
                   1,
                   47,
                   lit_str("invalid upstream IPv4 address or port")));

    const char trailing[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } } junk";
    CHECK(is_error(nginx::parse({trailing, sizeof(trailing) - 1}),
                   FrontendError::UnexpectedToken,
                   1,
                   71,
                   lit_str("trailing unexpected tokens")));

    const char too_large[] =
        "server { listen 65536; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({too_large, sizeof(too_large) - 1}),
                   FrontendError::InvalidInteger,
                   1,
                   17,
                   lit_str("invalid listen port")));
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
                       FrontendError::UnsupportedSyntax,
                       1,
                       32,
                       lit_str("location modifiers are unsupported")));
    }

    const char variable[] =
        "server { listen $port; location / { proxy_pass http://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({variable, sizeof(variable) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   17,
                   lit_str("variables are unsupported")));

    const char proxy_variable[] =
        "server { listen 8080; location / { proxy_pass http://$backend:1; } }";
    CHECK(is_error(nginx::parse({proxy_variable, sizeof(proxy_variable) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   47,
                   lit_str("variables are unsupported")));

    const char https[] = "server { listen 8080; location / { proxy_pass https://127.0.0.1:1; } }";
    CHECK(is_error(nginx::parse({https, sizeof(https) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   47,
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
        "unmatched OPTIONS { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 400, reason: \"Bad Request\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>400 Bad "
        "Request</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
        "unmatched CONNECT { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
        "unmatched { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 400, reason: \"Bad Request\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"<html>\\r\\n<head><title>400 Bad "
        "Request</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
        "route HEAD \"/\" {\n"
        "    return forward(nginx_upstream, request_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            host: \"upstream\",\n"
        "            connection: \"omit\",\n"
        "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
        "\"Upgrade\"]\n"
        "        },\n"
        "        response_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            framing: \"content_length\",\n"
        "            connection: \"request\",\n"
        "            head_mode: \"suppress_body\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n"
        "        },\n"
        "        failure_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            status: 502,\n"
        "            reason: \"Bad Gateway\",\n"
        "            content_type: \"text/html\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            connection: \"request\",\n"
        "            head_mode: \"suppress_body\",\n"
        "            body: b\"<html>\\r\\n<head><title>502 Bad "
        "Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad "
        "Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</"
        "html>\\r\\n\"\n"
        "        }\n"
        "    )\n"
        "}\n"
        "route GET \"/\" {\n"
        "    return forward(nginx_upstream, request_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            host: \"upstream\",\n"
        "            connection: \"omit\",\n"
        "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
        "\"Upgrade\"]\n"
        "        },\n"
        "        response_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            framing: \"content_length\",\n"
        "            connection: \"request\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n"
        "        },\n"
        "        failure_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            status: 502,\n"
        "            reason: \"Bad Gateway\",\n"
        "            content_type: \"text/html\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            connection: \"request\",\n"
        "            body: b\"<html>\\r\\n<head><title>502 Bad "
        "Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad "
        "Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</"
        "html>\\r\\n\"\n"
        "        },\n"
        "        timeout_failure_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            status: 504,\n"
        "            reason: \"Gateway Time-out\",\n"
        "            content_type: \"text/html\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            connection: \"request\",\n"
        "            body: b\"<html>\\r\\n<head><title>504 Gateway Time-out</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>504 Gateway Time-out</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n"
        "</html>\\r\\n\"\n"
        "        },\n"
        "        response_read_timeout: 60s,\n"
        "        response_buffering: \"complete_content_length\"\n"
        "    )\n"
        "}\n"
        "route \"/\" {\n"
        "    return forward(nginx_upstream, request_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            host: \"upstream\",\n"
        "            connection: \"omit\",\n"
        "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
        "\"Upgrade\"]\n"
        "        },\n"
        "        response_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            framing: \"content_length\",\n"
        "            connection: \"request\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n"
        "        },\n"
        "        failure_policy: {\n"
        "            version: \"HTTP/1.1\",\n"
        "            status: 502,\n"
        "            reason: \"Bad Gateway\",\n"
        "            content_type: \"text/html\",\n"
        "            server: \"nginx/1.29.7\",\n"
        "            date: \"current\",\n"
        "            connection: \"request\",\n"
        "            body: b\"<html>\\r\\n<head><title>502 Bad "
        "Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad "
        "Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</"
        "html>\\r\\n\"\n"
        "        }\n"
        "    )\n"
        "}\n";
    CHECK_EQ(result.value().len, static_cast<u32>(sizeof(kExpected) - 1));
    CHECK_LT(result.value().len, nginx::RutSource::kCapacity);
    CHECK(result.value().view().eq({kExpected, sizeof(kExpected) - 1}));
}

TEST(nginx_converter, lowers_api_model_to_stable_target_transform_source) {
    const auto result = nginx::lower_to_rut(api_server());
    REQUIRE(result);
    static constexpr char kExpected[] =
        "listen :8080\n"
        "upstream nginx_upstream at \"127.0.0.1:9000\"\n"
        "unmatched OPTIONS { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 400, reason: \"Bad Request\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>400 Bad "
        "Request</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
        "unmatched CONNECT { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
        "unmatched { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 400, reason: \"Bad Request\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"<html>\\r\\n<head><title>400 Bad "
        "Request</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
        "route \"/api\" {\n"
        "    if req.method == GET && req.pathOnly == \"/api\" {\n"
        "        return redirect({scheme: \"http\", authority: \"request_host\", port: "
        "\"actual_listener\",\n"
        "            path: \"static\", query: \"preserve_raw\", date: \"current\", connection: "
        "\"close\",\n"
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
        "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
        "\"Upgrade\"]\n"
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
        "            body: b\"<html>\\r\\n<head><title>502 Bad "
        "Gateway</title></head>\\r\\n<body>\\r\\n<center><h1>502 Bad "
        "Gateway</h1></center>\\r\\n<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</"
        "html>\\r\\n\"\n"
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

TEST(nginx_converter, root_maximum_ports_fit_bounded_source_capacity) {
    auto model = canonical_server();
    model.listen.port = 65535;
    model.location.proxy_pass.port = 65535;
    const auto lowered = nginx::lower_to_rut(model);
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 4899u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    CHECK_EQ(lexed.value().tokens.len, 530u);
}

// These checks prove only converter golden output and compiler/config ownership.
// Behavioral equivalence requires the separate nginx-vs-generated-RUT
// differentials. In particular, pipelined validated-failure successors remain
// excluded by #276, as do the converter's other documented client/config bounds.
TEST(nginx_converter, emitted_source_reaches_rir_with_source_metadata) {
    auto lowered = nginx::lower_to_rut(canonical_server());
    REQUIRE(lowered);
    auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->items.len, 8u);
    CHECK(ast_owned->items[0].kind == AstItemKind::Listen);
    CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
    CHECK(ast_owned->items[1].kind == AstItemKind::Upstream);
    CHECK(ast_owned->items[2].kind == AstItemKind::Unmatched);
    CHECK(ast_owned->items[3].kind == AstItemKind::Unmatched);
    CHECK(ast_owned->items[4].kind == AstItemKind::Unmatched);
    CHECK(ast_owned->items[5].kind == AstItemKind::Route);
    CHECK(ast_owned->items[6].kind == AstItemKind::Route);
    CHECK(ast_owned->items[7].kind == AstItemKind::Route);
    const u8 expected_route_methods[] = {
        static_cast<u8>(TokenType::KwHead), static_cast<u8>(TokenType::KwGet), 0};
    for (u32 i = 0; i < 3; i++) {
        const auto& route = ast_owned->items[5 + i].route;
        CHECK(route.path.eq(lit_str("/")));
        CHECK_EQ(route.method_is_any, i == 2);
        if (i != 2) CHECK_EQ(route.method, expected_route_methods[i]);
        REQUIRE_EQ(route.statements.len, 1u);
        const AstStatement& forward = *route.statements[0];
        CHECK(forward.kind == AstStmtKind::ForwardUpstream);
        CHECK(forward.has_forward_request_policy);
        CHECK_EQ(forward.forward_request_policy_id, 1u);
        CHECK(request_policy_is_supported(forward.forward_request_policy_id));
        CHECK(
            complete_content_length_request_policy_is_admitted(forward.forward_request_policy_id));
        CHECK_EQ(strcmp(request_policy_version(forward.forward_request_policy_id), "HTTP/1.1"), 0);
        CHECK(forward.has_forward_response_policy);
        CHECK(forward.has_forward_failure_policy);
        CHECK_EQ(forward.forward_timeout_failure_policy_id, i == 1 ? 3u : 0u);
        CHECK_EQ(forward.has_forward_timeout_failure_policy, i == 1);
        CHECK_EQ(forward.forward_response_read_timeout_seconds, i == 1 ? 60u : 0u);
        CHECK_EQ(forward.has_forward_response_read_timeout, i == 1);
        CHECK(forward.forward_response_buffering ==
              (i == 1 ? ForwardResponseBufferingMode::CompleteContentLength
                      : ForwardResponseBufferingMode::None));
        CHECK_EQ(forward.has_forward_response_buffering, i == 1);
    }
    REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 3u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodAny], 3u);
    for (u32 slot = 0; slot < kRouteMethodSlots; slot++)
        CHECK_EQ(ast_owned->unmatched_policy_ids[slot],
                 slot == kRouteMethodOptions   ? 1u
                 : slot == kRouteMethodConnect ? 2u
                 : slot == kRouteMethodAny     ? 3u
                                               : 0u);
    static constexpr char kBadRequestBody[] =
        "<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n"
        "<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n</html>\r\n";
    static constexpr char kNotAllowedBody[] =
        "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n"
        "<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n</html>\r\n";
    const auto check_unmatched_policy = [&](const auto& policy,
                                            u16 status,
                                            const char* reason,
                                            const char* body,
                                            StrictLocalResponseHeadMode head_mode) {
        CHECK_EQ(policy.version, StrictLocalResponseVersion::Http11);
        CHECK_EQ(policy.status_code, status);
        CHECK_EQ(policy.date, StrictLocalResponseDate::Current);
        CHECK_EQ(policy.connection, StrictLocalResponseConnection::Request);
        CHECK_EQ(policy.head_mode, head_mode);
        CHECK(policy.reason.eq({reason, static_cast<u32>(strlen(reason))}));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK(policy.body.eq({body, static_cast<u32>(strlen(body))}));
    };
    check_unmatched_policy(ast_owned->strict_local_response_policies[0],
                           400,
                           "Bad Request",
                           kBadRequestBody,
                           StrictLocalResponseHeadMode::Reject);
    check_unmatched_policy(ast_owned->strict_local_response_policies[1],
                           405,
                           "Not Allowed",
                           kNotAllowedBody,
                           StrictLocalResponseHeadMode::Reject);
    check_unmatched_policy(ast_owned->strict_local_response_policies[2],
                           400,
                           "Bad Request",
                           kBadRequestBody,
                           StrictLocalResponseHeadMode::SuppressBody);
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE(hir_owned->has_listener);
    CHECK_EQ(hir_owned->listener.port, 8080u);
    REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 3u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodAny], 3u);
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
    REQUIRE_EQ(hir_owned->response_policies.len, 2u);
    REQUIRE_EQ(hir_owned->failure_policies.len, 3u);
    REQUIRE_EQ(hir_owned->routes.len, 3u);
    CHECK_EQ(hir_owned->routes[0].method, kRouteMethodHead);
    CHECK_EQ(hir_owned->routes[1].method, kRouteMethodGet);
    CHECK_EQ(hir_owned->routes[2].method, kRouteMethodAny);
    for (u32 i = 0; i < hir_owned->routes.len; i++) {
        REQUIRE(hir_owned->routes[i].control.kind == HirControlKind::Direct);
        const auto& term = hir_owned->routes[i].control.direct_term;
        CHECK_EQ(term.kind, HirTerminatorKind::ForwardUpstream);
        CHECK_EQ(term.forward_request_policy_id, 1u);
    }
    CHECK_EQ(hir_owned->routes[0].control.direct_term.forward_response_policy_id, 1u);
    CHECK_EQ(hir_owned->routes[0].control.direct_term.forward_failure_policy_id, 1u);
    CHECK_EQ(hir_owned->routes[1].control.direct_term.forward_response_policy_id, 2u);
    CHECK_EQ(hir_owned->routes[1].control.direct_term.forward_failure_policy_id, 2u);
    CHECK_EQ(hir_owned->routes[2].control.direct_term.forward_response_policy_id, 2u);
    CHECK_EQ(hir_owned->routes[2].control.direct_term.forward_failure_policy_id, 2u);
    CHECK_EQ(hir_owned->routes[1].control.direct_term.forward_timeout_failure_policy_id, 3u);
    CHECK_EQ(hir_owned->routes[1].control.direct_term.forward_response_read_timeout_seconds, 60u);
    CHECK(hir_owned->routes[1].control.direct_term.forward_response_buffering ==
          ForwardResponseBufferingMode::CompleteContentLength);
    CHECK_EQ(hir_owned->routes[0].control.direct_term.forward_timeout_failure_policy_id, 0u);
    CHECK_EQ(hir_owned->routes[2].control.direct_term.forward_timeout_failure_policy_id, 0u);
    CHECK_EQ(hir_owned->routes[0].control.direct_term.forward_response_read_timeout_seconds, 0u);
    CHECK_EQ(hir_owned->routes[2].control.direct_term.forward_response_read_timeout_seconds, 0u);
    CHECK(hir_owned->routes[0].control.direct_term.forward_response_buffering ==
          ForwardResponseBufferingMode::None);
    CHECK(hir_owned->routes[2].control.direct_term.forward_response_buffering ==
          ForwardResponseBufferingMode::None);
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    REQUIRE_EQ(mir_owned->upstreams.len, 1u);
    CHECK_EQ(mir_owned->upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(mir_owned->upstreams[0].port, 9000u);
    REQUIRE_EQ(mir_owned->response_policies.len, 2u);
    REQUIRE_EQ(mir_owned->failure_policies.len, 3u);
    REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 3u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodAny], 3u);
    REQUIRE_EQ(mir_owned->functions.len, 3u);
    CHECK_EQ(mir_owned->functions[0].method, kRouteMethodHead);
    CHECK_EQ(mir_owned->functions[1].method, kRouteMethodGet);
    CHECK_EQ(mir_owned->functions[2].method, kRouteMethodAny);
    for (u32 fi = 0; fi < mir_owned->functions.len; fi++)
        CHECK(mir_owned->functions[fi].path.eq(lit_str("/")));
    CHECK(request_policy_is_supported(1));
    const char* request_version = request_policy_version(1);
    REQUIRE(request_version != nullptr);
    const Str request_version_str{request_version, 8};
    CHECK(request_version_str.eq(lit_str("HTTP/1.1")));
    for (u32 fi = 0; fi < mir_owned->functions.len; fi++) {
        const auto& function = mir_owned->functions[fi];
        REQUIRE_EQ(function.blocks.len, 1u);
        const auto& term = function.blocks[0].term;
        CHECK_EQ(term.kind, MirTerminatorKind::ForwardUpstream);
        CHECK_EQ(term.forward_request_policy_id, 1u);
        CHECK_EQ(term.forward_response_policy_id, fi == 0 ? 1u : 2u);
        CHECK_EQ(term.forward_failure_policy_id, fi == 0 ? 1u : 2u);
        CHECK_EQ(term.forward_timeout_failure_policy_id, fi == 1 ? 3u : 0u);
        CHECK_EQ(term.forward_response_read_timeout_seconds, fi == 1 ? 60u : 0u);
        CHECK(term.forward_response_buffering ==
              (fi == 1 ? ForwardResponseBufferingMode::CompleteContentLength
                       : ForwardResponseBufferingMode::None));
    }

    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir_owned, rir));
    REQUIRE_EQ(rir.module.upstream_count, 1u);
    REQUIRE_EQ(rir.module.strict_local_response_policy_count, 3u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK_EQ(rir.module.strict_local_response_policies[0].status_code, 400u);
    CHECK_EQ(rir.module.strict_local_response_policies[1].status_code, 405u);
    CHECK_EQ(rir.module.strict_local_response_policies[2].status_code, 400u);
    CHECK(rir.module.strict_local_response_policies[0].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    CHECK(rir.module.strict_local_response_policies[1].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    CHECK(rir.module.strict_local_response_policies[2].head_mode ==
          StrictLocalResponseHeadMode::SuppressBody);
    CHECK(rir.module.upstreams[0].name.eq(lit_str("nginx_upstream")));
    CHECK(rir.module.upstreams[0].has_address);
    CHECK_EQ(rir.module.upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(rir.module.upstreams[0].port, 9000u);
    REQUIRE_EQ(rir.module.response_policy_count, 2u);
    const auto& response_policy = rir.module.response_policies[0];
    CHECK(response_policy.version == ResponsePolicyVersion::Http11);
    CHECK(response_policy.framing == ResponsePolicyFraming::ContentLength);
    CHECK(response_policy.connection == ResponsePolicyConnection::Request);
    CHECK(response_policy.head_mode == ResponsePolicyHeadMode::SuppressBody);
    CHECK(response_policy.date == ResponsePolicyDate::Current);
    CHECK(response_policy.server.eq(lit_str("nginx/1.29.7")));
    REQUIRE_EQ(response_policy.hide_header_count, 3u);
    CHECK(response_policy.hide_headers[0].eq(lit_str("Date")));
    CHECK(response_policy.hide_headers[1].eq(lit_str("Server")));
    CHECK(response_policy.hide_headers[2].eq(lit_str("X-Pad")));
    CHECK(rir.module.response_policies[1].head_mode == ResponsePolicyHeadMode::Reject);

    REQUIRE_EQ(rir.module.failure_policy_count, 3u);
    const auto& failure_policy = rir.module.failure_policies[0];
    CHECK(failure_policy.version == ForwardFailurePolicyVersion::Http11);
    CHECK_EQ(failure_policy.status_code, 502u);
    CHECK(failure_policy.date == ForwardFailurePolicyDate::Current);
    CHECK(failure_policy.connection == ForwardFailurePolicyConnection::Request);
    CHECK(failure_policy.head_mode == FailurePolicyHeadMode::SuppressBody);
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
    CHECK(rir.module.failure_policies[1].head_mode == FailurePolicyHeadMode::Reject);
    CHECK_EQ(rir.module.failure_policies[2].status_code, 504u);
    CHECK(rir.module.failure_policies[2].reason.eq(lit_str("Gateway Time-out")));
    CHECK(rir.module.failure_policies[2].content_type.eq(lit_str("text/html")));
    CHECK(rir.module.failure_policies[2].server.eq(lit_str("nginx/1.29.7")));
    CHECK(rir.module.failure_policies[2].date == ForwardFailurePolicyDate::Current);
    CHECK(rir.module.failure_policies[2].connection == ForwardFailurePolicyConnection::Request);
    CHECK(rir.module.failure_policies[2].head_mode == FailurePolicyHeadMode::Reject);
    CHECK_EQ(rir.module.failure_policies[2].body.len, 167u);

    REQUIRE_EQ(rir.module.policy_bundle_count, 3u);
    CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(rir.module.policy_bundles[0].response_read_timeout_seconds, 0u);
    CHECK(rir.module.policy_bundles[0].response_buffering == ForwardResponseBufferingMode::None);
    CHECK_EQ(rir.module.policy_bundles[1].response_policy_id, 2u);
    CHECK_EQ(rir.module.policy_bundles[1].failure_policy_id, 2u);
    CHECK_EQ(rir.module.policy_bundles[2].response_policy_id, 2u);
    CHECK_EQ(rir.module.policy_bundles[2].failure_policy_id, 2u);
    CHECK_EQ(rir.module.policy_bundles[1].timeout_failure_policy_id, 3u);
    CHECK_EQ(rir.module.policy_bundles[1].response_read_timeout_seconds, 60u);
    CHECK(rir.module.policy_bundles[1].response_buffering ==
          ForwardResponseBufferingMode::CompleteContentLength);

    REQUIRE_EQ(rir.module.func_count, 3u);
    for (u32 fi = 0; fi < rir.module.func_count; fi++) {
        const auto& function = rir.module.functions[fi];
        CHECK(function.route_pattern.eq(lit_str("/")));
        CHECK_EQ(function.http_method,
                 fi == 0   ? kRouteMethodHead
                 : fi == 1 ? kRouteMethodGet
                           : kRouteMethodAny);
        u32 ret_count = 0;
        for (u32 bi = 0; bi < function.block_count; bi++) {
            const auto& block = function.blocks[bi];
            for (u32 ii = 0; ii < block.inst_count; ii++) {
                const auto& instruction = block.insts[ii];
                if (instruction.op != rir::Opcode::RetForwardBundle) continue;
                ret_count++;
                REQUIRE_EQ(instruction.operand_count, 3u);
                i32 upstream_id = -1;
                i32 request_policy_id = -1;
                i32 bundle_id = -1;
                REQUIRE(find_const_i32(function, instruction.operand(0), upstream_id));
                REQUIRE(find_const_i32(function, instruction.operand(1), request_policy_id));
                REQUIRE(find_const_i32(function, instruction.operand(2), bundle_id));
                CHECK_EQ(upstream_id, 0);
                CHECK_EQ(request_policy_id, 1);
                CHECK_EQ(bundle_id, fi == 0 ? 1 : fi == 1 ? 2 : 3);
            }
        }
        CHECK_EQ(ret_count, 1u);
    }

    RouteConfig populated{};
    REQUIRE(populate_route_config(populated, rir.module));
    REQUIRE_EQ(populated.response_policy_count, 2u);
    REQUIRE_EQ(populated.failure_policy_count, 3u);
    REQUIRE_EQ(populated.policy_bundle_count, 3u);
    REQUIRE_EQ(populated.strict_local_response_policy_count, 3u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated.unmatched_policy_table_is_valid());
    CHECK_EQ(populated.strict_local_response_policies[0].body.len, 157u);
    CHECK_EQ(populated.strict_local_response_policies[1].body.len, 157u);
    CHECK_EQ(populated.strict_local_response_policies[2].body.len, 157u);
    CHECK(populated.strict_local_response_policies[0].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    CHECK(populated.strict_local_response_policies[1].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    CHECK(populated.strict_local_response_policies[2].head_mode ==
          StrictLocalResponseHeadMode::SuppressBody);
    CHECK(populated.response_policies[0].head_mode == ResponsePolicyHeadMode::SuppressBody);
    CHECK(populated.response_policies[1].head_mode == ResponsePolicyHeadMode::Reject);
    CHECK(populated.failure_policies[0].head_mode == FailurePolicyHeadMode::SuppressBody);
    CHECK(populated.failure_policies[1].head_mode == FailurePolicyHeadMode::Reject);
    CHECK_EQ(populated.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(populated.policy_bundles[0].failure_policy_id, 1u);
    CHECK_EQ(populated.policy_bundles[1].response_policy_id, 2u);
    CHECK_EQ(populated.policy_bundles[1].failure_policy_id, 2u);
    CHECK_EQ(populated.policy_bundles[2].response_policy_id, 2u);
    CHECK_EQ(populated.policy_bundles[2].failure_policy_id, 2u);
    CHECK_EQ(populated.policy_bundles[1].timeout_failure_policy_id, 3u);
    CHECK_EQ(populated.policy_bundles[1].response_read_timeout_seconds, 60u);
    CHECK(populated.policy_bundles[1].response_buffering ==
          ForwardResponseBufferingMode::CompleteContentLength);
}

TEST(nginx_converter, emitted_api_source_reaches_rir_with_target_transform) {
    auto lowered = nginx::lower_to_rut(api_server());
    REQUIRE(lowered);
    auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 3u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodAny], 3u);
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 3u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodAny], 3u);
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
    REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 3u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodAny], 3u);
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
    REQUIRE_EQ(rir.module.strict_local_response_policy_count, 3u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodAny], 3u);
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
    RouteConfig populated{};
    REQUIRE(populate_route_config(populated, rir.module));
    REQUIRE_EQ(populated.strict_local_response_policy_count, 3u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodOptions], 1u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodConnect], 2u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated.unmatched_policy_table_is_valid());
    CHECK_EQ(populated.policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(populated.policy_bundles[0].response_read_timeout_seconds, 0u);
    CHECK(populated.policy_bundles[0].response_buffering == ForwardResponseBufferingMode::None);
}

TEST(nginx_converter, rejects_parsed_proxy_read_timeout_before_lowering) {
    const char source[] =
        "server { listen 8080; location / { proxy_read_timeout 1s; proxy_pass "
        "http://127.0.0.1:9000; } }";
    const auto parsed = nginx::parse({source, sizeof(source) - 1});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE_FALSE(lowered);
    CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
    CHECK(lowered.error().detail.eq(lit_str("proxy_read_timeout lowering is not implemented")));
    CHECK_EQ(lowered.error().span.start,
             static_cast<u32>(strstr(source, "proxy_read_timeout") - source));
}

TEST(nginx_converter, rejects_forged_proxy_read_timeout_model_inconsistencies) {
    auto valid_present = canonical_server();
    valid_present.location.proxy_read_timeout.present = true;
    valid_present.location.proxy_read_timeout.milliseconds = 1000;
    valid_present.location.span = Span{20, 54, 1, 21};
    valid_present.location.proxy_read_timeout.span = Span{24, 52, 1, 25};
    valid_present.location.proxy_read_timeout.value_span = Span{43, 45, 1, 44};
    valid_present.listen.port = 0;
    auto guarded_first = nginx::lower_to_rut(valid_present);
    REQUIRE_FALSE(guarded_first);
    CHECK_EQ(guarded_first.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(guarded_first.error().span.start, 24u);
    CHECK(
        guarded_first.error().detail.eq(lit_str("proxy_read_timeout lowering is not implemented")));

    auto api_present = valid_present;
    api_present.listen.port = 8080;
    api_present.location.path = lit_str("/api/");
    api_present.location.path_span = Span{22, 27, 1, 23};
    auto bad_api_present = nginx::lower_to_rut(api_present);
    REQUIRE_FALSE(bad_api_present);
    CHECK_EQ(bad_api_present.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_api_present.error().span.start, 22u);
    CHECK(bad_api_present.error().detail.eq(lit_str("invalid proxy_read_timeout location model")));

    auto other_present = valid_present;
    other_present.listen.port = 8080;
    other_present.location.path = lit_str("/other");
    other_present.location.path_span = Span{22, 28, 1, 23};
    auto bad_other_present = nginx::lower_to_rut(other_present);
    REQUIRE_FALSE(bad_other_present);
    CHECK_EQ(bad_other_present.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_other_present.error().span.start, 22u);
    CHECK(
        bad_other_present.error().detail.eq(lit_str("invalid proxy_read_timeout location model")));

    auto null_present = valid_present;
    null_present.listen.port = 8080;
    null_present.location.path = {nullptr, 1};
    auto bad_null_present = nginx::lower_to_rut(null_present);
    REQUIRE_FALSE(bad_null_present);
    CHECK_EQ(bad_null_present.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_null_present.error().span.start, 22u);
    CHECK(bad_null_present.error().detail.eq(lit_str("invalid proxy_read_timeout location model")));

    const u32 invalid_milliseconds[] = {0, 999, 1500, 64000};
    for (const u32 milliseconds : invalid_milliseconds) {
        auto invalid = valid_present;
        invalid.listen.port = 8080;
        invalid.location.proxy_read_timeout.milliseconds = milliseconds;
        auto result = nginx::lower_to_rut(invalid);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK_EQ(result.error().span.start, 43u);
        CHECK(result.error().detail.eq(lit_str("invalid proxy_read_timeout milliseconds")));
    }

    auto default_directive_span = valid_present;
    default_directive_span.listen.port = 8080;
    default_directive_span.location.proxy_read_timeout.span = {};
    auto bad_directive_span = nginx::lower_to_rut(default_directive_span);
    REQUIRE_FALSE(bad_directive_span);
    CHECK_EQ(bad_directive_span.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_directive_span.error().span.start, default_directive_span.location.span.start);
    CHECK(bad_directive_span.error().detail.eq(lit_str("invalid proxy_read_timeout spans")));

    auto escaped_value_span = valid_present;
    escaped_value_span.listen.port = 8080;
    escaped_value_span.location.proxy_read_timeout.value_span = Span{50, 53, 1, 51};
    auto bad_value_span = nginx::lower_to_rut(escaped_value_span);
    REQUIRE_FALSE(bad_value_span);
    CHECK_EQ(bad_value_span.error().code, FrontendError::UnsupportedSyntax);
    CHECK(bad_value_span.error().detail.eq(lit_str("invalid proxy_read_timeout spans")));

    auto absent_with_value = canonical_server();
    absent_with_value.location.proxy_read_timeout.milliseconds = 1000;
    auto bad_absent_value = nginx::lower_to_rut(absent_with_value);
    REQUIRE_FALSE(bad_absent_value);
    CHECK_EQ(bad_absent_value.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_absent_value.error().span.start, absent_with_value.location.span.start);
    CHECK(bad_absent_value.error().detail.eq(lit_str("invalid absent proxy_read_timeout model")));

    auto absent_with_span = canonical_server();
    absent_with_span.location.proxy_read_timeout.span = Span{24, 52, 1, 25};
    auto bad_absent_span = nginx::lower_to_rut(absent_with_span);
    REQUIRE_FALSE(bad_absent_span);
    CHECK_EQ(bad_absent_span.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_absent_span.error().span.start, 24u);

    auto absent_with_value_span = canonical_server();
    absent_with_value_span.location.proxy_read_timeout.value_span = Span{43, 45, 1, 44};
    auto bad_absent_value_span = nginx::lower_to_rut(absent_with_value_span);
    REQUIRE_FALSE(bad_absent_value_span);
    CHECK_EQ(bad_absent_value_span.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_absent_value_span.error().span.start, 43u);
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
