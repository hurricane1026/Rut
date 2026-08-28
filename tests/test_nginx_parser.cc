#include "rut/common/strict_local_response.h"
#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/rir_printer.h"
#include "rut/compiler/verifier.h"
#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/listener.h"
#include "test.h"
#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

using namespace rut;

static_assert(nginx::kMaxExactLocalReturnPathLen == kMaxExactStrictLocalResponsePathLen);
static_assert(sizeof(void*) == 8u, "Rut's supported loader/compiler data model is 64-bit");
static_assert(sizeof(u32) == 4u && alignof(u32) == 4u,
              "RutSource layout evidence requires the supported 32-bit u32 model");
static_assert(std::is_standard_layout_v<nginx::RutSource>);
static_assert(std::is_trivially_copyable_v<nginx::RutSource>);
static_assert(alignof(nginx::RutSource) == alignof(u32));
static_assert(offsetof(nginx::RutSource, len) == 5948u);
static_assert(sizeof(nginx::RutSource) == 5952u);

TEST(nginx_converter, rut_source_capacity_layout_zero_reserve_and_copy_ownership) {
    static_assert(nginx::RutSource::kCapacity == 5946u);
    nginx::RutSource original{};
    original.len = nginx::RutSource::kCapacity - 1u;
    memset(original.data, 'x', original.len);
    REQUIRE_EQ(original.data[original.len], '\0');
    CHECK_EQ(original.view().len, 5945u);
    CHECK_EQ(original.view().ptr, original.data);
    CHECK_LT(original.len, nginx::RutSource::kCapacity);
    static constexpr u32 kInvalidPayloadLength = 5946u;
    CHECK_FALSE(kInvalidPayloadLength < nginx::RutSource::kCapacity);

    nginx::RutSource copied = original;
    memset(original.data, 'y', original.len);
    original.len = 0u;
    CHECK_EQ(copied.len, 5945u);
    CHECK_EQ(copied.view().ptr, copied.data);
    CHECK_EQ(copied.data[0], 'x');
    CHECK_EQ(copied.data[copied.len - 1u], 'x');
    CHECK_EQ(copied.data[copied.len], '\0');
}

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

static bool str_is_in_owned_pool(Str value, const char* pool, u32 used) {
    if (value.ptr == nullptr || value.len == 0 || pool == nullptr || value.len > used) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(pool);
    const uintptr_t ptr = reinterpret_cast<uintptr_t>(value.ptr);
    return ptr >= begin && ptr - begin < used && value.len <= used - (ptr - begin);
}

static u32 count_text(const std::string& source, const std::string& needle) {
    if (needle.empty()) return 0;
    u32 count = 0;
    for (size_t offset = 0;;) {
        offset = source.find(needle, offset);
        if (offset == std::string::npos) return count;
        count++;
        offset += needle.size();
    }
}

static u32 count_route_declarations(const std::string& source) {
    return (source.rfind("route ", 0u) == 0u ? 1u : 0u) + count_text(source, "\nroute ");
}

static u32 count_upstream_declarations(const std::string& source) {
    return (source.rfind("upstream ", 0u) == 0u ? 1u : 0u) + count_text(source, "\nupstream ");
}

static bool validate_static_query_proxy_generated_source_fields(const std::string& source,
                                                                u16 listen_port,
                                                                u16 upstream_port) {
    const std::string listener = "listen :" + std::to_string(listen_port) + "\n";
    const std::string upstream =
        "upstream nginx_upstream at \"127.0.0.1:" + std::to_string(upstream_port) + "\"\n";
    static constexpr char kTransform[] =
        "            strip_prefix: \"/api/\",\n"
        "            replace_prefix: \"/v1/?fixed=1\"\n";
    return count_text(source, listener) == 1u && count_text(source, upstream) == 1u &&
           count_text(source, "route \"/api\" {\n") == 1u &&
           count_text(source, "    if req.method == GET && req.pathOnly == \"/api\" {\n") == 1u &&
           count_text(source, "target_path: \"/api/\"") == 1u &&
           count_text(source, kTransform) == 1u && count_text(source, "strip_prefix:") == 1u &&
           count_text(source, "replace_prefix:") == 1u &&
           count_text(source, "/v1/?fixed=1") == 1u &&
           count_text(source, "return forward(nginx_upstream, target_transform: {") == 1u &&
           count_text(source, "query: \"preserve_raw\"") == 1u &&
           count_text(source, "host: \"upstream\"") == 1u && count_text(source, "route \"") == 1u &&
           source.find("route \"/api?") == std::string::npos &&
           source.find("route \"/api/") == std::string::npos &&
           source.find("req.host") == std::string::npos &&
           source.find("req.headers") == std::string::npos &&
           source.find("route raw") == std::string::npos &&
           source.find("req.rawTarget") == std::string::npos &&
           source.find("path: \"raw\"") == std::string::npos &&
           source.find("set_path:") == std::string::npos &&
           source.find("proxy_pass") == std::string::npos &&
           source.find("nginx.conf") == std::string::npos &&
           source.find("nginx::") == std::string::npos &&
           source.find("nginx_compat") == std::string::npos &&
           source.find("workaround") == std::string::npos;
}

static bool validate_static_query_proxy_generated_source(const std::string& source,
                                                         u16 listen_port,
                                                         u16 upstream_port) {
    return validate_static_query_proxy_generated_source_fields(
               source, listen_port, upstream_port) &&
           count_route_declarations(source) == 1u &&
           source.find("\nroute exact ") == std::string::npos &&
           source.rfind("route exact ", 0u) != 0u;
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
    CHECK_FALSE(result.value().exact_local_return.present);
    CHECK_EQ(result.value().exact_local_return.path.ptr, nullptr);
    CHECK_EQ(result.value().exact_local_return.path.len, 0u);
    CHECK_EQ(result.value().exact_local_return.response.status, 0u);
    CHECK_FALSE(result.value().exact_no_content_return.present);
    CHECK_EQ(result.value().exact_no_content_return.path.ptr, nullptr);
    CHECK_EQ(result.value().exact_no_content_return.path.len, 0u);
    CHECK_EQ(result.value().exact_no_content_return.response.status, 0u);
    CHECK_EQ(result.value().exact_no_content_return.path_span.start, 0u);
    CHECK_EQ(result.value().exact_no_content_return.path_span.end, 0u);
    CHECK_EQ(result.value().exact_no_content_return.path_span.line, 1u);
    CHECK_EQ(result.value().exact_no_content_return.path_span.col, 1u);
    CHECK_EQ(result.value().exact_no_content_return.span.start, 0u);
    CHECK_EQ(result.value().exact_no_content_return.span.end, 0u);
    CHECK_EQ(result.value().exact_no_content_return.span.line, 1u);
    CHECK_EQ(result.value().exact_no_content_return.span.col, 1u);
    CHECK_EQ(result.value().exact_no_content_return.response.status_span.start, 0u);
    CHECK_EQ(result.value().exact_no_content_return.response.status_span.end, 0u);
    CHECK_EQ(result.value().exact_no_content_return.response.status_span.line, 1u);
    CHECK_EQ(result.value().exact_no_content_return.response.status_span.col, 1u);
    CHECK_EQ(result.value().exact_no_content_return.response.span.start, 0u);
    CHECK_EQ(result.value().exact_no_content_return.response.span.end, 0u);
    CHECK_EQ(result.value().exact_no_content_return.response.span.line, 1u);
    CHECK_EQ(result.value().exact_no_content_return.response.span.col, 1u);
    CHECK_FALSE(result.value().exact_absolute_redirect.present);
    CHECK_EQ(result.value().exact_absolute_redirect.path.ptr, nullptr);
    CHECK_EQ(result.value().exact_absolute_redirect.path.len, 0u);
    CHECK_EQ(result.value().exact_absolute_redirect.response.status, 0u);
    CHECK_EQ(result.value().exact_absolute_redirect.response.status_lexeme.ptr, nullptr);
    CHECK_EQ(result.value().exact_absolute_redirect.response.status_lexeme.len, 0u);
    CHECK(result.value().pre_route_trace.profile ==
          nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
    CHECK_EQ(result.value().pre_route_trace.span.start, result.value().span.start);
    CHECK_EQ(result.value().pre_route_trace.span.end, result.value().span.end);
    CHECK_EQ(result.value().pre_route_trace.span.line, result.value().span.line);
    CHECK_EQ(result.value().pre_route_trace.span.col, result.value().span.col);
}

TEST(nginx_parser, parses_root_proxy_and_exact_local_return_in_either_order) {
    const char root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 200 \"successor-static\"; }\n"
        "}\n";
    const char exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /static { return 200 \"successor-static\"; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    auto check = [&](const char* source, u32 len, u32 root_line, u32 exact_line) {
        const auto result = nginx::parse({source, len});
        REQUIRE(result);
        const auto& server = result.value();
        CHECK(server.location.path.eq(lit_str("/")));
        CHECK_EQ(server.location.span.line, root_line);
        CHECK_EQ(server.location.proxy_pass.port, 9000u);
        REQUIRE(server.exact_local_return.present);
        CHECK(server.exact_local_return.path.eq(lit_str("/static")));
        CHECK_EQ(server.exact_local_return.span.line, exact_line);
        CHECK_EQ(server.exact_local_return.response.status, 200u);
        CHECK(server.exact_local_return.response.body.eq(lit_str("successor-static")));
        CHECK_EQ(server.exact_local_return.response.body_span.line, exact_line);
        CHECK_GE(server.exact_local_return.response.body.ptr, source);
        CHECK_LT(server.exact_local_return.response.body.ptr, source + len);
        CHECK_EQ(server.exact_local_return.response.body_span.end -
                     server.exact_local_return.response.body_span.start,
                 server.exact_local_return.response.body.len);
        CHECK_FALSE(server.exact_no_content_return.present);
        CHECK_EQ(server.exact_no_content_return.path.ptr, nullptr);
        CHECK_EQ(server.exact_no_content_return.path.len, 0u);
        CHECK_EQ(server.exact_no_content_return.response.status, 0u);
        REQUIRE(server.pre_route_trace.profile ==
                nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);
    };
    check(root_first, sizeof(root_first) - 1u, 3, 4);
    check(exact_first, sizeof(exact_first) - 1u, 4, 3);
}

TEST(nginx_parser, models_exact_no_content_return_in_either_order_with_source_provenance) {
    const char root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 204; }\n"
        "}\n";
    const char exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /static { return 204; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    const char root_first_multiline[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static {\n"
        "    return\n"
        "      204 # separated status comment\n"
        "      ;\n"
        "  }\n"
        "}\n";
    const char exact_first_multiline[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /static {\n"
        "    return # separated directive comment\n"
        "      204\n"
        "      # separated terminator comment\n"
        "      ;\n"
        "  }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";

    const auto check = [&](const char* source, u32 len, u32 root_line, u32 exact_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& location = server.exact_no_content_return;
        const auto& response = location.response;
        const char* server_start = strstr(source, "server {");
        const char* server_end = strrchr(source, '}');
        const char* root_start = strstr(source, "location / {");
        const char* root_end = strchr(root_start, '}');
        const char* root_path = strchr(root_start, '/');
        const char* exact_start = strstr(source, "location = /static");
        const char* exact_end = strchr(exact_start, '}');
        const char* exact_path = strstr(exact_start, "/static");
        const char* return_start = strstr(exact_start, "return");
        const char* status = strstr(return_start, "204");
        const char* return_end = strchr(status, ';');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_end != nullptr);
        REQUIRE(root_start != nullptr);
        REQUIRE(root_end != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(exact_start != nullptr);
        REQUIRE(exact_end != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(return_start != nullptr);
        REQUIRE(return_end != nullptr);
        REQUIRE(status != nullptr);
        const auto offset = [&](const char* ptr) { return static_cast<u32>(ptr - source); };
        const auto column = [&](const char* ptr) {
            const char* line_start = ptr;
            while (line_start != source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(ptr - line_start + 1);
        };
        const auto line = [&](const char* ptr) {
            u32 result = 1;
            for (const char* it = source; it != ptr; ++it) {
                if (*it == '\n') ++result;
            }
            return result;
        };
        const auto check_default_span = [&](Span span) {
            CHECK_EQ(span.start, 0u);
            CHECK_EQ(span.end, 0u);
            CHECK_EQ(span.line, 1u);
            CHECK_EQ(span.col, 1u);
        };

        CHECK_EQ(server.span.start, offset(server_start));
        CHECK_EQ(server.span.end, offset(server_end + 1));
        CHECK_EQ(server.span.line, line(server_start));
        CHECK_EQ(server.span.col, column(server_start));
        CHECK_EQ(server.location.path.ptr, root_path);
        CHECK_EQ(server.location.path_span.start, offset(root_path));
        CHECK_EQ(server.location.path_span.end, offset(root_path + 1));
        CHECK_EQ(server.location.path_span.line, root_line);
        CHECK_EQ(server.location.path_span.col, column(root_path));
        CHECK_EQ(server.location.span.start, offset(root_start));
        CHECK_EQ(server.location.span.end, offset(root_end + 1));
        CHECK_EQ(server.location.span.line, root_line);
        CHECK_EQ(server.location.span.col, column(root_start));

        REQUIRE(location.present);
        CHECK(location.path.eq(lit_str("/static")));
        CHECK_EQ(location.path.ptr, exact_path);
        CHECK_EQ(location.path_span.start, offset(exact_path));
        CHECK_EQ(location.path_span.end, offset(exact_path + 7));
        CHECK_EQ(location.path_span.line, exact_line);
        CHECK_EQ(location.path_span.col, column(exact_path));
        CHECK_EQ(location.span.start, offset(exact_start));
        CHECK_EQ(location.span.end, offset(exact_end + 1));
        CHECK_EQ(location.span.line, exact_line);
        CHECK_EQ(location.span.col, column(exact_start));
        CHECK_EQ(response.status, 204u);
        CHECK_EQ(response.status_span.start, offset(status));
        CHECK_EQ(response.status_span.end, offset(status + 3));
        CHECK_EQ(response.status_span.line, line(status));
        CHECK_EQ(response.status_span.col, column(status));
        CHECK_EQ(response.span.start, offset(return_start));
        CHECK_EQ(response.span.end, offset(return_end + 1));
        CHECK_EQ(response.span.line, line(return_start));
        CHECK_EQ(response.span.col, column(return_start));
        CHECK_EQ(memcmp(source + response.status_span.start, "204", 3), 0);
        CHECK_LE(server.span.start, location.span.start);
        CHECK_LE(location.span.end, server.span.end);
        CHECK_LE(location.span.start, location.path_span.start);
        CHECK_LE(location.path_span.end, location.span.end);
        CHECK_LE(location.span.start, response.span.start);
        CHECK_LE(response.span.end, location.span.end);
        CHECK_LE(response.span.start, response.status_span.start);
        CHECK_LE(response.status_span.end, response.span.end);

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        CHECK_EQ(
            reinterpret_cast<uintptr_t>(server.location.path.ptr) - server.location.path_span.start,
            source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(location.path.ptr) - location.path_span.start,
                 source_base);

        CHECK_FALSE(server.exact_local_return.present);
        CHECK_EQ(server.exact_local_return.path.ptr, nullptr);
        CHECK_EQ(server.exact_local_return.response.status, 0u);
        check_default_span(server.exact_local_return.span);
        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK_EQ(server.exact_absolute_redirect.path.ptr, nullptr);
        CHECK_EQ(server.exact_absolute_redirect.response.status, 0u);
        check_default_span(server.exact_absolute_redirect.span);
    };
    check(root_first, sizeof(root_first) - 1u, 3u, 4u);
    check(exact_first, sizeof(exact_first) - 1u, 4u, 3u);
    check(root_first_multiline, sizeof(root_first_multiline) - 1u, 3u, 4u);
    check(exact_first_multiline, sizeof(exact_first_multiline) - 1u, 9u, 3u);
}

TEST(nginx_parser, models_bounded_exact_no_content_path_in_either_order) {
    const char root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /healthz { return 204; }\n"
        "}\n";
    const char exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /healthz { return 204; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";

    const auto check = [&](const char* source, u32 len, u32 exact_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& location = server.exact_no_content_return;
        const auto& response = location.response;
        const char* exact_start = strstr(source, "location = /healthz");
        REQUIRE(exact_start != nullptr);
        const char* exact_path = strstr(exact_start, "/healthz");
        const char* exact_end = strchr(exact_start, '}');
        const char* return_start = strstr(exact_start, "return 204");
        REQUIRE(return_start != nullptr);
        const char* status = strstr(return_start, "204");
        const char* return_end = strchr(return_start, ';');
        const char* root_start = strstr(source, "location / {");
        REQUIRE(root_start != nullptr);
        const char* root_path = strchr(root_start, '/');
        REQUIRE(exact_path != nullptr);
        REQUIRE(exact_end != nullptr);
        REQUIRE(status != nullptr);
        REQUIRE(return_end != nullptr);
        REQUIRE(root_path != nullptr);
        const auto offset = [&](const char* ptr) { return static_cast<u32>(ptr - source); };
        const auto column = [&](const char* ptr) {
            const char* line_start = ptr;
            while (line_start != source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(ptr - line_start + 1);
        };

        REQUIRE(location.present);
        CHECK(location.path.eq(lit_str("/healthz")));
        CHECK_EQ(location.path.ptr, exact_path);
        CHECK_EQ(location.path_span.start, offset(exact_path));
        CHECK_EQ(location.path_span.end, offset(exact_path + 8));
        CHECK_EQ(location.path_span.line, exact_line);
        CHECK_EQ(location.path_span.col, column(exact_path));
        CHECK_EQ(location.span.start, offset(exact_start));
        CHECK_EQ(location.span.end, offset(exact_end + 1));
        CHECK_EQ(location.span.line, exact_line);
        CHECK_EQ(location.span.col, column(exact_start));
        CHECK_EQ(response.status, 204u);
        CHECK_EQ(response.status_span.start, offset(status));
        CHECK_EQ(response.status_span.end, offset(status + 3));
        CHECK_EQ(response.status_span.line, exact_line);
        CHECK_EQ(response.status_span.col, column(status));
        CHECK_EQ(memcmp(source + response.status_span.start, "204", 3), 0);
        CHECK_EQ(response.span.start, offset(return_start));
        CHECK_EQ(response.span.end, offset(return_end + 1));
        CHECK_EQ(response.span.line, exact_line);
        CHECK_EQ(response.span.col, column(return_start));

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        CHECK_EQ(reinterpret_cast<uintptr_t>(location.path.ptr) - location.path_span.start,
                 source_base);
        CHECK_EQ(
            reinterpret_cast<uintptr_t>(server.location.path.ptr) - server.location.path_span.start,
            source_base);
        CHECK_EQ(server.location.path.ptr, root_path);
        CHECK_FALSE(server.exact_local_return.present);
        CHECK_FALSE(server.exact_absolute_redirect.present);
    };

    check(root_first, sizeof(root_first) - 1u, 4u);
    check(exact_first, sizeof(exact_first) - 1u, 3u);
}

TEST(nginx_parser, accepts_bounded_clean_exact_no_content_path_grammar) {
    const char* paths[] = {
        "/healthz",
        "/healthz/",
        "/api/v1",
        "/A-Z_a.z~9/more_2/",
        "/old/",
        "/static",
    };
    for (const char* path : paths) {
        char source[384]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = %s { return 204; } }",
                                 path);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        const auto& action = parsed.value().exact_no_content_return;
        REQUIRE(action.present);
        const Str expected{path, static_cast<u32>(strlen(path))};
        CHECK(action.path.eq(expected));
        CHECK_EQ(action.path.ptr, source + action.path_span.start);
        CHECK_EQ(action.path_span.end - action.path_span.start, action.path.len);
        CHECK_EQ(action.response.status, 204u);
        CHECK_FALSE(parsed.value().exact_local_return.present);
        CHECK_FALSE(parsed.value().exact_absolute_redirect.present);
    }
}

TEST(nginx_parser, enforces_bounded_clean_exact_no_content_path_capacity) {
    char maximum[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    maximum[0] = '/';
    memset(maximum + 1, 'a', nginx::kMaxExactLocalReturnPathLen - 1u);
    maximum[nginx::kMaxExactLocalReturnPathLen] = '\0';
    char source[512]{};
    int len = snprintf(source,
                       sizeof(source),
                       "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                       "location = %s { return 204; } }",
                       maximum);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto accepted = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE(accepted);
    CHECK_EQ(accepted.value().exact_no_content_return.path.len, nginx::kMaxExactLocalReturnPathLen);
    CHECK_EQ(accepted.value().exact_no_content_return.path.ptr,
             source + accepted.value().exact_no_content_return.path_span.start);

    char oversized[nginx::kMaxExactLocalReturnPathLen + 2u]{};
    oversized[0] = '/';
    memset(oversized + 1, 'a', nginx::kMaxExactLocalReturnPathLen);
    oversized[nginx::kMaxExactLocalReturnPathLen + 1u] = '\0';
    len = snprintf(source,
                   sizeof(source),
                   "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                   "location = %s { return 204; } }",
                   oversized);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto rejected = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    const char* path = strstr(source, oversized);
    REQUIRE(path != nullptr);
    CHECK_EQ(rejected.error().span.start, static_cast<u32>(path - source));
    CHECK_EQ(rejected.error().span.end - rejected.error().span.start,
             nginx::kMaxExactLocalReturnPathLen + 1u);
}

TEST(nginx_parser, rejects_excluded_exact_no_content_path_shapes_and_reserved_action) {
    struct Vector {
        const char* path;
        Str detail;
    };
    const Vector vectors[] = {
        {"/", lit_str("exact local return path is outside the bounded clean profile")},
        {"healthz", lit_str("exact local return path is outside the bounded clean profile")},
        {"//healthz", lit_str("exact local return path is outside the bounded clean profile")},
        {"/healthz//", lit_str("exact local return path is outside the bounded clean profile")},
        {"/a//b", lit_str("exact local return path is outside the bounded clean profile")},
        {"/.", lit_str("exact local return path is outside the bounded clean profile")},
        {"/..", lit_str("exact local return path is outside the bounded clean profile")},
        {"/a/./b", lit_str("exact local return path is outside the bounded clean profile")},
        {"/a/../b", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health%7A", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health?x=1", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health$uri", lit_str("variables are unsupported")},
        {"\"/healthz\"", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health\\z", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health:z", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health*z", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health\x01z", lit_str("exact local return path is outside the bounded clean profile")},
        {"/h\xc3\xa9", lit_str("exact local return path is outside the bounded clean profile")},
    };
    for (const auto& vector : vectors) {
        char source[384]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = %s { return 204; } }",
                                 vector.path);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(parsed);
        CHECK_EQ(parsed.error().code, FrontendError::UnsupportedSyntax);
        CHECK(parsed.error().detail.eq(vector.detail));
        const char* exact = strstr(source, "location = ");
        REQUIRE(exact != nullptr);
        const char* path = exact + strlen("location = ");
        CHECK_EQ(parsed.error().span.start, static_cast<u32>(path - source));
        CHECK_EQ(parsed.error().span.end - parsed.error().span.start,
                 static_cast<u32>(strlen(vector.path)));
    }

    const char reserved[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 204; } }";
    const auto reserved_result = nginx::parse({reserved, sizeof(reserved) - 1u});
    REQUIRE_FALSE(reserved_result);
    CHECK_EQ(reserved_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(
        reserved_result.error().detail.eq(lit_str("only redirect status 301 or 302 is supported")));
    const char* status = strstr(reserved, "204");
    REQUIRE(status != nullptr);
    CHECK_EQ(reserved_result.error().span.start, static_cast<u32>(status - reserved));
    CHECK_EQ(reserved_result.error().span.end, static_cast<u32>(status - reserved + 3));
}

TEST(nginx_parser, models_one_internal_exact_local_body_space_in_either_order) {
    const char root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 200 \"hello world\"; }\n"
        "}\n";
    const char exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /static { return 200 \"hello world\"; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";

    const auto check = [&](const char* source, u32 len, u32 root_line, u32 exact_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& location = server.exact_local_return;
        const auto& response = location.response;

        const char* server_start = strstr(source, "server {");
        const char* server_end = strrchr(source, '}');
        const char* root_start = strstr(source, "location / {");
        const char* root_end = strchr(root_start, '}');
        const char* root_path = strchr(root_start, '/');
        const char* exact_start = strstr(source, "location = /static");
        const char* exact_end = strchr(exact_start, '}');
        const char* exact_path = strstr(exact_start, "/static");
        const char* response_start = strstr(exact_start, "return 200");
        const char* response_end = strchr(response_start, ';');
        const char* body_lexeme = strstr(response_start, "\"hello world\"");
        REQUIRE(server_start != nullptr);
        REQUIRE(server_end != nullptr);
        REQUIRE(root_start != nullptr);
        REQUIRE(root_end != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(exact_start != nullptr);
        REQUIRE(exact_end != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(response_start != nullptr);
        REQUIRE(response_end != nullptr);
        REQUIRE(body_lexeme != nullptr);
        const char* body = body_lexeme + 1;
        const auto offset = [&](const char* ptr) { return static_cast<u32>(ptr - source); };
        const auto column = [&](const char* ptr) {
            const char* line_start = ptr;
            while (line_start != source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(ptr - line_start + 1);
        };

        CHECK_EQ(server.span.start, offset(server_start));
        CHECK_EQ(server.span.end, offset(server_end + 1));
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, 1u);
        CHECK(server.location.path.eq(lit_str("/")));
        CHECK_EQ(server.location.path.ptr, root_path);
        CHECK_EQ(server.location.path_span.start, offset(root_path));
        CHECK_EQ(server.location.path_span.end, offset(root_path + 1));
        CHECK_EQ(server.location.path_span.line, root_line);
        CHECK_EQ(server.location.path_span.col, column(root_path));
        CHECK_EQ(server.location.span.start, offset(root_start));
        CHECK_EQ(server.location.span.end, offset(root_end + 1));
        CHECK_EQ(server.location.span.line, root_line);
        CHECK_EQ(server.location.span.col, column(root_start));
        CHECK_EQ(server.location.proxy_pass.port, 9000u);
        REQUIRE(location.present);
        CHECK(location.path.eq(lit_str("/static")));
        CHECK_EQ(location.path.ptr, exact_path);
        CHECK_EQ(location.path_span.start, offset(exact_path));
        CHECK_EQ(location.path_span.end, offset(exact_path + sizeof("/static") - 1u));
        CHECK_EQ(location.path_span.line, exact_line);
        CHECK_EQ(location.path_span.col, column(exact_path));
        CHECK_EQ(location.span.start, offset(exact_start));
        CHECK_EQ(location.span.end, offset(exact_end + 1));
        CHECK_EQ(location.span.line, exact_line);
        CHECK_EQ(location.span.col, column(exact_start));
        CHECK_EQ(response.status, 200u);
        CHECK_EQ(response.span.start, offset(response_start));
        CHECK_EQ(response.span.end, offset(response_end + 1));
        CHECK_EQ(response.span.line, exact_line);
        CHECK_EQ(response.span.col, column(response_start));
        CHECK(response.body.eq(lit_str("hello world")));
        CHECK_EQ(response.body.ptr, body);
        CHECK_EQ(response.body_span.start, offset(body));
        CHECK_EQ(response.body_span.end, offset(body + sizeof("hello world") - 1u));
        CHECK_EQ(response.body_span.line, exact_line);
        CHECK_EQ(response.body_span.col, column(body));
        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);

        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK(strstr(lowered.value().data, "body: b\"hello world\"") != nullptr);
    };

    check(root_first, sizeof(root_first) - 1u, 3u, 4u);
    check(exact_first, sizeof(exact_first) - 1u, 4u, 3u);
}

TEST(nginx_parser, models_multiple_internal_exact_local_body_spaces_in_either_order) {
    const char adjacent_root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 200 \"hello  world\"; }\n"
        "}\n";
    const char adjacent_exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /static { return 200 \"hello  world\"; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    const char separated_root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 200 \"hello world again\"; }\n"
        "}\n";
    const char separated_exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /static { return 200 \"hello world again\"; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    struct Vector {
        const char* source;
        u32 source_len;
        const char* expected_body;
        u32 expected_body_len;
        u32 root_line;
        u32 exact_line;
    };
    const Vector vectors[] = {
        {adjacent_root_first,
         sizeof(adjacent_root_first) - 1u,
         "hello  world",
         sizeof("hello  world") - 1u,
         3u,
         4u},
        {adjacent_exact_first,
         sizeof(adjacent_exact_first) - 1u,
         "hello  world",
         sizeof("hello  world") - 1u,
         4u,
         3u},
        {separated_root_first,
         sizeof(separated_root_first) - 1u,
         "hello world again",
         sizeof("hello world again") - 1u,
         3u,
         4u},
        {separated_exact_first,
         sizeof(separated_exact_first) - 1u,
         "hello world again",
         sizeof("hello world again") - 1u,
         4u,
         3u},
    };

    for (const auto& vector : vectors) {
        const auto parsed = nginx::parse({vector.source, vector.source_len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& root = server.location;
        const auto& exact = server.exact_local_return;
        const auto& response = exact.response;

        const char* server_start = strstr(vector.source, "server {");
        const char* server_end = strrchr(vector.source, '}');
        const char* root_start = strstr(vector.source, "location / {");
        const char* root_end = strchr(root_start, '}');
        const char* root_path = strchr(root_start, '/');
        const char* exact_start = strstr(vector.source, "location = /static");
        const char* exact_end = strchr(exact_start, '}');
        const char* exact_path = strstr(exact_start, "/static");
        const char* response_start = strstr(exact_start, "return 200");
        const char* response_end = strchr(response_start, ';');
        const char* opening_quote = strchr(response_start, '"');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_end != nullptr);
        REQUIRE(root_start != nullptr);
        REQUIRE(root_end != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(exact_start != nullptr);
        REQUIRE(exact_end != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(response_start != nullptr);
        REQUIRE(response_end != nullptr);
        REQUIRE(opening_quote != nullptr);
        const char* body = opening_quote + 1;
        REQUIRE_EQ(body[vector.expected_body_len], '"');
        const auto offset = [&](const char* ptr) { return static_cast<u32>(ptr - vector.source); };
        const auto column = [&](const char* ptr) {
            const char* line_start = ptr;
            while (line_start != vector.source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(ptr - line_start + 1);
        };

        CHECK_EQ(server.span.start, offset(server_start));
        CHECK_EQ(server.span.end, offset(server_end + 1));
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, 1u);
        CHECK(root.path.eq(lit_str("/")));
        CHECK_EQ(root.path.ptr, root_path);
        CHECK_EQ(root.path_span.start, offset(root_path));
        CHECK_EQ(root.path_span.end, offset(root_path + 1));
        CHECK_EQ(root.path_span.line, vector.root_line);
        CHECK_EQ(root.path_span.col, column(root_path));
        CHECK_EQ(root.span.start, offset(root_start));
        CHECK_EQ(root.span.end, offset(root_end + 1));
        CHECK_EQ(root.span.line, vector.root_line);
        CHECK_EQ(root.span.col, column(root_start));
        REQUIRE(exact.present);
        CHECK(exact.path.eq(lit_str("/static")));
        CHECK_EQ(exact.path.ptr, exact_path);
        CHECK_EQ(exact.path_span.start, offset(exact_path));
        CHECK_EQ(exact.path_span.end, offset(exact_path + sizeof("/static") - 1u));
        CHECK_EQ(exact.path_span.line, vector.exact_line);
        CHECK_EQ(exact.path_span.col, column(exact_path));
        CHECK_EQ(exact.span.start, offset(exact_start));
        CHECK_EQ(exact.span.end, offset(exact_end + 1));
        CHECK_EQ(exact.span.line, vector.exact_line);
        CHECK_EQ(exact.span.col, column(exact_start));
        CHECK_EQ(response.status, 200u);
        CHECK_EQ(response.span.start, offset(response_start));
        CHECK_EQ(response.span.end, offset(response_end + 1));
        CHECK_EQ(response.span.line, vector.exact_line);
        CHECK_EQ(response.span.col, column(response_start));
        CHECK(response.body.eq({vector.expected_body, vector.expected_body_len}));
        CHECK_EQ(response.body.ptr, body);
        CHECK_EQ(response.body_span.start, offset(body));
        CHECK_EQ(response.body_span.end, offset(body + vector.expected_body_len));
        CHECK_EQ(response.body_span.line, vector.exact_line);
        CHECK_EQ(response.body_span.col, column(body));
        CHECK_EQ(reinterpret_cast<uintptr_t>(root.path.ptr) - root.path_span.start,
                 reinterpret_cast<uintptr_t>(vector.source));
        CHECK_EQ(reinterpret_cast<uintptr_t>(exact.path.ptr) - exact.path_span.start,
                 reinterpret_cast<uintptr_t>(vector.source));
        CHECK_EQ(reinterpret_cast<uintptr_t>(response.body.ptr) - response.body_span.start,
                 reinterpret_cast<uintptr_t>(vector.source));

        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        char expected_literal[64]{};
        const int expected_literal_len = snprintf(expected_literal,
                                                  sizeof(expected_literal),
                                                  "body: b\"%.*s\"",
                                                  static_cast<int>(vector.expected_body_len),
                                                  vector.expected_body);
        REQUIRE_GT(expected_literal_len, 0);
        REQUIRE_LT(static_cast<u32>(expected_literal_len),
                   static_cast<u32>(sizeof(expected_literal)));
        CHECK(strstr(lowered.value().data, expected_literal) != nullptr);
    }
}

TEST(nginx_parser, bounds_one_internal_exact_local_body_space_at_64_raw_bytes) {
    char accepted_body[nginx::kMaxLocalReturnBodyLen + 1u]{};
    memset(accepted_body, 'a', 31u);
    accepted_body[31] = ' ';
    memset(accepted_body + 32, 'b', 32u);
    accepted_body[nginx::kMaxLocalReturnBodyLen] = '\0';

    char accepted_source[512]{};
    const int accepted_len =
        snprintf(accepted_source,
                 sizeof(accepted_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = /static { return 200 \"%s\"; } }",
                 accepted_body);
    REQUIRE_GT(accepted_len, 0);
    REQUIRE_LT(static_cast<u32>(accepted_len), static_cast<u32>(sizeof(accepted_source)));
    const auto accepted = nginx::parse({accepted_source, static_cast<u32>(accepted_len)});
    REQUIRE(accepted);
    const auto& accepted_response = accepted.value().exact_local_return.response;
    CHECK_EQ(accepted_response.body.len, nginx::kMaxLocalReturnBodyLen);
    CHECK(accepted_response.body.eq({accepted_body, nginx::kMaxLocalReturnBodyLen}));
    CHECK_EQ(accepted_response.body_span.end - accepted_response.body_span.start,
             nginx::kMaxLocalReturnBodyLen);

    char rejected_body[nginx::kMaxLocalReturnBodyLen + 2u]{};
    memset(rejected_body, 'a', 32u);
    rejected_body[32] = ' ';
    memset(rejected_body + 33, 'b', 32u);
    rejected_body[nginx::kMaxLocalReturnBodyLen + 1u] = '\0';
    char rejected_source[512]{};
    const int rejected_len =
        snprintf(rejected_source,
                 sizeof(rejected_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = /static { return 200 \"%s\"; } }",
                 rejected_body);
    REQUIRE_GT(rejected_len, 0);
    REQUIRE_LT(static_cast<u32>(rejected_len), static_cast<u32>(sizeof(rejected_source)));
    const auto rejected = nginx::parse({rejected_source, static_cast<u32>(rejected_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
    const char* return_directive = strstr(rejected_source, "return 200");
    REQUIRE(return_directive != nullptr);
    const char* opening_quote = strchr(return_directive, '"');
    REQUIRE(opening_quote != nullptr);
    CHECK_EQ(rejected.error().span.start, static_cast<u32>(opening_quote - rejected_source));
    CHECK_EQ(
        rejected.error().span.end,
        static_cast<u32>(opening_quote - rejected_source) + nginx::kMaxLocalReturnBodyLen + 3u);
}

TEST(nginx_parser, bounds_multiple_internal_exact_local_body_spaces_at_64_raw_bytes) {
    char accepted_body[nginx::kMaxLocalReturnBodyLen + 1u]{};
    memset(accepted_body, 'a', nginx::kMaxLocalReturnBodyLen);
    for (u32 i = 1; i + 1u < nginx::kMaxLocalReturnBodyLen; i += 2u) accepted_body[i] = ' ';
    accepted_body[2] = ' ';
    accepted_body[32] = ' ';
    accepted_body[nginx::kMaxLocalReturnBodyLen] = '\0';

    char accepted_source[512]{};
    const int accepted_len =
        snprintf(accepted_source,
                 sizeof(accepted_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = /static { return 200 \"%s\"; } }",
                 accepted_body);
    REQUIRE_GT(accepted_len, 0);
    REQUIRE_LT(static_cast<u32>(accepted_len), static_cast<u32>(sizeof(accepted_source)));
    const auto accepted = nginx::parse({accepted_source, static_cast<u32>(accepted_len)});
    REQUIRE(accepted);
    const auto& accepted_response = accepted.value().exact_local_return.response;
    CHECK_EQ(accepted_response.body.len, nginx::kMaxLocalReturnBodyLen);
    CHECK(accepted_response.body.eq({accepted_body, nginx::kMaxLocalReturnBodyLen}));
    CHECK_EQ(accepted_response.body_span.end - accepted_response.body_span.start,
             nginx::kMaxLocalReturnBodyLen);

    char rejected_body[nginx::kMaxLocalReturnBodyLen + 2u]{};
    memset(rejected_body, 'b', nginx::kMaxLocalReturnBodyLen + 1u);
    for (u32 i = 1; i < nginx::kMaxLocalReturnBodyLen; i += 2u) rejected_body[i] = ' ';
    rejected_body[2] = ' ';
    rejected_body[32] = ' ';
    rejected_body[nginx::kMaxLocalReturnBodyLen + 1u] = '\0';
    char rejected_source[512]{};
    const int rejected_len =
        snprintf(rejected_source,
                 sizeof(rejected_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = /static { return 200 \"%s\"; } }",
                 rejected_body);
    REQUIRE_GT(rejected_len, 0);
    REQUIRE_LT(static_cast<u32>(rejected_len), static_cast<u32>(sizeof(rejected_source)));
    const auto rejected = nginx::parse({rejected_source, static_cast<u32>(rejected_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
    const char* return_directive = strstr(rejected_source, "return 200");
    REQUIRE(return_directive != nullptr);
    const char* opening_quote = strchr(return_directive, '"');
    REQUIRE(opening_quote != nullptr);
    CHECK_EQ(rejected.error().span.start, static_cast<u32>(opening_quote - rejected_source));
    CHECK_EQ(
        rejected.error().span.end,
        static_cast<u32>(opening_quote - rejected_source) + nginx::kMaxLocalReturnBodyLen + 3u);
}

TEST(nginx_parser, rejects_excluded_contextual_exact_local_body_forms_at_complete_spans) {
    static constexpr char kPrefix[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 ";
    static constexpr char kSuffix[] = "; } }";
    static constexpr char kControl[] = {'a', '\x01', 'b'};
    static constexpr char kNul[] = {'a', '\0', 'b'};
    static constexpr char kNonAscii[] = {'a', static_cast<char>(0x80), 'b'};
    struct Vector {
        const char* body;
        u32 len;
    };
    const Vector vectors[] = {
        {" hello", sizeof(" hello") - 1u},
        {"hello ", sizeof("hello ") - 1u},
        {"hello\tworld", sizeof("hello\tworld") - 1u},
        {"hello\rworld", sizeof("hello\rworld") - 1u},
        {"hello\nworld", sizeof("hello\nworld") - 1u},
        {"hello\fworld", sizeof("hello\fworld") - 1u},
        {"hello\vworld", sizeof("hello\vworld") - 1u},
        {kControl, sizeof(kControl)},
        {kNul, sizeof(kNul)},
        {kNonAscii, sizeof(kNonAscii)},
        {"hello\\\"world", sizeof("hello\\\"world") - 1u},
        {"hello\\\\world", sizeof("hello\\\\world") - 1u},
        {"$variable", sizeof("$variable") - 1u},
        {"hello#world", sizeof("hello#world") - 1u},
        {"hello{world", sizeof("hello{world") - 1u},
        {"hello}world", sizeof("hello}world") - 1u},
        {"hello;world", sizeof("hello;world") - 1u},
        {"", 0u},
    };

    for (const auto& vector : vectors) {
        char source[512]{};
        u32 used = 0;
        memcpy(source + used, kPrefix, sizeof(kPrefix) - 1u);
        used += sizeof(kPrefix) - 1u;
        const u32 opening_quote = used;
        source[used++] = '"';
        memcpy(source + used, vector.body, vector.len);
        used += vector.len;
        source[used++] = '"';
        const u32 quoted_end = used;
        memcpy(source + used, kSuffix, sizeof(kSuffix) - 1u);
        used += sizeof(kSuffix) - 1u;

        const auto rejected = nginx::parse({source, used});
        REQUIRE_FALSE(rejected);
        CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
        CHECK(rejected.error().detail.eq(
            lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
        CHECK_EQ(rejected.error().span.start, opening_quote);
        CHECK_EQ(rejected.error().span.end, quoted_end);
        CHECK_EQ(rejected.error().span.line, 1u);
        CHECK_EQ(rejected.error().span.col, opening_quote + 1u);
    }

    char unterminated[512]{};
    u32 unterminated_len = 0;
    memcpy(unterminated + unterminated_len, kPrefix, sizeof(kPrefix) - 1u);
    unterminated_len += sizeof(kPrefix) - 1u;
    const u32 unterminated_start = unterminated_len;
    static constexpr char kUnterminatedTail[] = "\"hello world; } }";
    memcpy(unterminated + unterminated_len, kUnterminatedTail, sizeof(kUnterminatedTail) - 1u);
    unterminated_len += sizeof(kUnterminatedTail) - 1u;
    const auto missing_quote = nginx::parse({unterminated, unterminated_len});
    REQUIRE_FALSE(missing_quote);
    CHECK_EQ(missing_quote.error().code, FrontendError::UnsupportedSyntax);
    CHECK(missing_quote.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
    CHECK_EQ(missing_quote.error().span.start, unterminated_start);
    CHECK_EQ(missing_quote.error().span.end, unterminated_len);

    char final_backslash[512]{};
    u32 final_backslash_len = 0;
    memcpy(final_backslash + final_backslash_len, kPrefix, sizeof(kPrefix) - 1u);
    final_backslash_len += sizeof(kPrefix) - 1u;
    const u32 final_backslash_start = final_backslash_len;
    static constexpr char kFinalBackslashTail[] = {'"', 'h', 'e', 'l', 'l', 'o', '\\'};
    memcpy(final_backslash + final_backslash_len, kFinalBackslashTail, sizeof(kFinalBackslashTail));
    final_backslash_len += sizeof(kFinalBackslashTail);
    REQUIRE_EQ(final_backslash_len,
               static_cast<u32>(sizeof(kPrefix) - 1u + sizeof(kFinalBackslashTail)));
    REQUIRE_EQ(final_backslash[final_backslash_len - 1u], '\\');
    REQUIRE_EQ(final_backslash[final_backslash_len], '\0');
    const auto final_backslash_result = nginx::parse({final_backslash, final_backslash_len});
    REQUIRE_FALSE(final_backslash_result);
    CHECK_EQ(final_backslash_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(final_backslash_result.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
    CHECK_EQ(final_backslash_result.error().span.start, final_backslash_start);
    CHECK_EQ(final_backslash_result.error().span.end, final_backslash_len);

    char escaped_quote_eof[512]{};
    u32 escaped_quote_eof_len = 0;
    memcpy(escaped_quote_eof + escaped_quote_eof_len, kPrefix, sizeof(kPrefix) - 1u);
    escaped_quote_eof_len += sizeof(kPrefix) - 1u;
    const u32 escaped_quote_eof_start = escaped_quote_eof_len;
    static constexpr char kEscapedQuoteEofTail[] = {
        '"', 'h', 'e', 'l', 'l', 'o', '\\', '"', 'w', 'o', 'r', 'l', 'd'};
    memcpy(escaped_quote_eof + escaped_quote_eof_len,
           kEscapedQuoteEofTail,
           sizeof(kEscapedQuoteEofTail));
    escaped_quote_eof_len += sizeof(kEscapedQuoteEofTail);
    REQUIRE_EQ(escaped_quote_eof_len,
               static_cast<u32>(sizeof(kPrefix) - 1u + sizeof(kEscapedQuoteEofTail)));
    REQUIRE_EQ(escaped_quote_eof[escaped_quote_eof_start + 6u], '\\');
    REQUIRE_EQ(escaped_quote_eof[escaped_quote_eof_start + 7u], '"');
    REQUIRE_EQ(escaped_quote_eof[escaped_quote_eof_len], '\0');
    const auto escaped_quote_eof_result = nginx::parse({escaped_quote_eof, escaped_quote_eof_len});
    REQUIRE_FALSE(escaped_quote_eof_result);
    CHECK_EQ(escaped_quote_eof_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(escaped_quote_eof_result.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
    CHECK_EQ(escaped_quote_eof_result.error().span.start, escaped_quote_eof_start);
    CHECK_EQ(escaped_quote_eof_result.error().span.end, escaped_quote_eof_len);

    const char unquoted[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 hello world; } }";
    const auto unquoted_result = nginx::parse({unquoted, sizeof(unquoted) - 1u});
    REQUIRE_FALSE(unquoted_result);
    CHECK_EQ(unquoted_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(unquoted_result.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
    const char* unquoted_body = strstr(unquoted, "hello world");
    REQUIRE(unquoted_body != nullptr);
    CHECK_EQ(unquoted_result.error().span.start, static_cast<u32>(unquoted_body - unquoted));
    CHECK_EQ(unquoted_result.error().span.end,
             static_cast<u32>(unquoted_body - unquoted + sizeof("hello") - 1u));

    const char extra[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"hello world\" extra; } }";
    const auto extra_result = nginx::parse({extra, sizeof(extra) - 1u});
    REQUIRE_FALSE(extra_result);
    CHECK_EQ(extra_result.error().code, FrontendError::UnexpectedToken);
    CHECK(extra_result.error().detail.eq(lit_str("return accepts exactly status and body")));
    const char* extra_token = strstr(extra, "extra;");
    REQUIRE(extra_token != nullptr);
    CHECK_EQ(extra_result.error().span.start, static_cast<u32>(extra_token - extra));
    CHECK_EQ(extra_result.error().span.end,
             static_cast<u32>(extra_token - extra + sizeof("extra") - 1u));

    const char embedded_quote[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"hello\"world\"; } }";
    const auto embedded_quote_result = nginx::parse({embedded_quote, sizeof(embedded_quote) - 1u});
    REQUIRE_FALSE(embedded_quote_result);
    CHECK_EQ(embedded_quote_result.error().code, FrontendError::UnexpectedToken);
    CHECK(
        embedded_quote_result.error().detail.eq(lit_str("return accepts exactly status and body")));
    const char* quote_tail = strstr(embedded_quote, "world\"");
    REQUIRE(quote_tail != nullptr);
    CHECK_EQ(embedded_quote_result.error().span.start,
             static_cast<u32>(quote_tail - embedded_quote));
    CHECK_EQ(embedded_quote_result.error().span.end,
             static_cast<u32>(quote_tail - embedded_quote + sizeof("world\"") - 1u));
}

TEST(nginx_parser, parses_bounded_clean_exact_local_return_path_in_either_order) {
    const char root_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /healthz { return 200 \"successor-static\"; }\n"
        "}\n";
    const char exact_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location = /healthz { return 200 \"successor-static\"; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";

    const auto check = [&](const char* source, u32 len, u32 root_line, u32 exact_line) {
        const auto result = nginx::parse({source, len});
        REQUIRE(result);
        const auto& server = result.value();

        const char* server_start = strstr(source, "server {");
        const char* server_end = strrchr(source, '}');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_end != nullptr);
        const char* listen_start = strstr(source, "listen 8080");
        REQUIRE(listen_start != nullptr);
        const char* listen_end = strchr(listen_start, ';');
        REQUIRE(listen_end != nullptr);
        const char* root_start = strstr(source, "location / {");
        REQUIRE(root_start != nullptr);
        const char* root_end = strchr(root_start, '}');
        const char* root_path = strchr(root_start, '/');
        const char* proxy_start = strstr(root_start, "proxy_pass http://127.0.0.1:9000");
        REQUIRE(root_end != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(proxy_start != nullptr);
        const char* proxy_end = strchr(proxy_start, ';');
        REQUIRE(proxy_end != nullptr);
        const char* exact_start = strstr(source, "location = /healthz");
        REQUIRE(exact_start != nullptr);
        const char* exact_end = strchr(exact_start, '}');
        const char* exact_path = strstr(exact_start, "/healthz");
        const char* response_start = strstr(exact_start, "return 200");
        REQUIRE(exact_end != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(response_start != nullptr);
        const char* response_end = strchr(response_start, ';');
        const char* body_start = strstr(response_start, "successor-static");
        REQUIRE(response_end != nullptr);
        REQUIRE(body_start != nullptr);

        const auto offset = [&](const char* ptr) { return static_cast<u32>(ptr - source); };
        const auto column = [&](const char* ptr) {
            const char* line_start = ptr;
            while (line_start != source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(ptr - line_start + 1);
        };
        const auto check_default_span = [&](Span span) {
            CHECK_EQ(span.start, 0u);
            CHECK_EQ(span.end, 0u);
            CHECK_EQ(span.line, 1u);
            CHECK_EQ(span.col, 1u);
        };

        CHECK_EQ(server.span.start, offset(server_start));
        CHECK_EQ(server.span.end, offset(server_end + 1));
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, column(server_start));
        CHECK_EQ(server.listen.port, 8080u);
        CHECK_EQ(server.listen.span.start, offset(listen_start));
        CHECK_EQ(server.listen.span.end, offset(listen_end + 1));
        CHECK_EQ(server.listen.span.line, 2u);
        CHECK_EQ(server.listen.span.col, column(listen_start));

        CHECK(server.location.path.eq(lit_str("/")));
        CHECK_EQ(server.location.path.ptr, root_path);
        CHECK_EQ(server.location.path_span.start, offset(root_path));
        CHECK_EQ(server.location.path_span.end, offset(root_path + 1));
        CHECK_EQ(server.location.path_span.line, root_line);
        CHECK_EQ(server.location.path_span.col, column(root_path));
        CHECK_EQ(server.location.span.start, offset(root_start));
        CHECK_EQ(server.location.span.end, offset(root_end + 1));
        CHECK_EQ(server.location.span.line, root_line);
        CHECK_EQ(server.location.span.col, column(root_start));
        CHECK_EQ(server.location.proxy_pass.address[0], 127u);
        CHECK_EQ(server.location.proxy_pass.address[1], 0u);
        CHECK_EQ(server.location.proxy_pass.address[2], 0u);
        CHECK_EQ(server.location.proxy_pass.address[3], 1u);
        CHECK_EQ(server.location.proxy_pass.port, 9000u);
        CHECK_FALSE(server.location.proxy_pass.has_uri);
        CHECK_EQ(server.location.proxy_pass.uri.ptr, nullptr);
        CHECK_EQ(server.location.proxy_pass.uri.len, 0u);
        check_default_span(server.location.proxy_pass.uri_span);
        CHECK_EQ(server.location.proxy_pass.span.start, offset(proxy_start));
        CHECK_EQ(server.location.proxy_pass.span.end, offset(proxy_end + 1));
        CHECK_EQ(server.location.proxy_pass.span.line, root_line);
        CHECK_EQ(server.location.proxy_pass.span.col, column(proxy_start));
        CHECK_FALSE(server.location.proxy_read_timeout.present);
        CHECK_EQ(server.location.proxy_read_timeout.milliseconds, 0u);
        check_default_span(server.location.proxy_read_timeout.span);
        check_default_span(server.location.proxy_read_timeout.value_span);

        REQUIRE(server.exact_local_return.present);
        const auto& location = server.exact_local_return;
        CHECK(location.path.eq(lit_str("/healthz")));
        CHECK_EQ(location.path.ptr, exact_path);
        CHECK_EQ(location.path_span.start, offset(exact_path));
        CHECK_EQ(location.path_span.end, offset(exact_path + sizeof("/healthz") - 1u));
        CHECK_EQ(location.path_span.line, exact_line);
        CHECK_EQ(location.path_span.col, column(exact_path));
        CHECK_EQ(location.span.start, offset(exact_start));
        CHECK_EQ(location.span.end, offset(exact_end + 1));
        CHECK_EQ(location.span.line, exact_line);
        CHECK_EQ(location.span.col, column(exact_start));
        CHECK_EQ(location.response.status, 200u);
        CHECK_EQ(location.response.span.start, offset(response_start));
        CHECK_EQ(location.response.span.end, offset(response_end + 1));
        CHECK_EQ(location.response.span.line, exact_line);
        CHECK_EQ(location.response.span.col, column(response_start));
        CHECK(location.response.body.eq(lit_str("successor-static")));
        CHECK_EQ(location.response.body.ptr, body_start);
        CHECK_EQ(location.response.body_span.start, offset(body_start));
        CHECK_EQ(location.response.body_span.end,
                 offset(body_start + sizeof("successor-static") - 1u));
        CHECK_EQ(location.response.body_span.line, exact_line);
        CHECK_EQ(location.response.body_span.col, column(body_start));

        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK_EQ(server.exact_absolute_redirect.path.ptr, nullptr);
        CHECK_EQ(server.exact_absolute_redirect.path.len, 0u);
        check_default_span(server.exact_absolute_redirect.path_span);
        check_default_span(server.exact_absolute_redirect.span);
        CHECK_EQ(server.exact_absolute_redirect.response.status, 0u);
        CHECK_EQ(server.exact_absolute_redirect.response.status_lexeme.ptr, nullptr);
        CHECK_EQ(server.exact_absolute_redirect.response.status_lexeme.len, 0u);
        check_default_span(server.exact_absolute_redirect.response.status_span);
        CHECK_EQ(server.exact_absolute_redirect.response.target.ptr, nullptr);
        CHECK_EQ(server.exact_absolute_redirect.response.target.len, 0u);
        check_default_span(server.exact_absolute_redirect.response.target_span);
        CHECK_EQ(server.exact_absolute_redirect.response.authority.ptr, nullptr);
        CHECK_EQ(server.exact_absolute_redirect.response.authority.len, 0u);
        check_default_span(server.exact_absolute_redirect.response.authority_span);
        CHECK_EQ(server.exact_absolute_redirect.response.path.ptr, nullptr);
        CHECK_EQ(server.exact_absolute_redirect.response.path.len, 0u);
        check_default_span(server.exact_absolute_redirect.response.path_span);
        check_default_span(server.exact_absolute_redirect.response.span);

        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);
    };
    check(root_first, sizeof(root_first) - 1u, 3u, 4u);
    check(exact_first, sizeof(exact_first) - 1u, 4u, 3u);
}

TEST(nginx_parser, accepts_bounded_clean_exact_local_return_path_grammar) {
    const char* paths[] = {
        "/healthz/",
        "/api/v1",
        "/A-Z_a.z~9/more_2/",
        "/old/",
        "/static",
    };
    for (const char* path : paths) {
        char source[384]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = %s { return 200 \"x\"; } }",
                                 path);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        const Str expected{path, static_cast<u32>(strlen(path))};
        CHECK(parsed.value().exact_local_return.path.eq(expected));
        CHECK_FALSE(parsed.value().exact_absolute_redirect.present);
    }
}

TEST(nginx_parser, enforces_bounded_clean_exact_local_return_path_capacity) {
    char maximum[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    maximum[0] = '/';
    memset(maximum + 1, 'a', nginx::kMaxExactLocalReturnPathLen - 1u);
    maximum[nginx::kMaxExactLocalReturnPathLen] = '\0';
    char source[512]{};
    int len = snprintf(source,
                       sizeof(source),
                       "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                       "location = %s { return 200 \"x\"; } }",
                       maximum);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto accepted = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE(accepted);
    CHECK_EQ(accepted.value().exact_local_return.path.len, nginx::kMaxExactLocalReturnPathLen);

    char oversized[nginx::kMaxExactLocalReturnPathLen + 2u]{};
    oversized[0] = '/';
    memset(oversized + 1, 'a', nginx::kMaxExactLocalReturnPathLen);
    oversized[nginx::kMaxExactLocalReturnPathLen + 1u] = '\0';
    len = snprintf(source,
                   sizeof(source),
                   "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                   "location = %s { return 200 \"x\"; } }",
                   oversized);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto rejected = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    const char* path = strstr(source, oversized);
    REQUIRE(path != nullptr);
    CHECK_EQ(rejected.error().span.start, static_cast<u32>(path - source));
    CHECK_EQ(rejected.error().span.end - rejected.error().span.start,
             nginx::kMaxExactLocalReturnPathLen + 1u);
}

TEST(nginx_parser, rejects_non_clean_exact_local_return_path_shapes) {
    struct Vector {
        const char* path;
        Str detail;
    };
    const Vector vectors[] = {
        {"/", lit_str("exact local return path is outside the bounded clean profile")},
        {"healthz", lit_str("exact local return path is outside the bounded clean profile")},
        {"//healthz", lit_str("exact local return path is outside the bounded clean profile")},
        {"/healthz//", lit_str("exact local return path is outside the bounded clean profile")},
        {"/a//b", lit_str("exact local return path is outside the bounded clean profile")},
        {"/.", lit_str("exact local return path is outside the bounded clean profile")},
        {"/..", lit_str("exact local return path is outside the bounded clean profile")},
        {"/a/./b", lit_str("exact local return path is outside the bounded clean profile")},
        {"/a/../b", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health%7A", lit_str("exact local return path is outside the bounded clean profile")},
        // Query matching belongs to runtime location selection, not nginx config
        // path syntax in this bounded parser profile.
        {"/health?x=1", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health$uri", lit_str("variables are unsupported")},
        {"\"/healthz\"", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health\\z", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health:z", lit_str("exact local return path is outside the bounded clean profile")},
        {"/health*z", lit_str("exact local return path is outside the bounded clean profile")},
    };
    for (const auto& vector : vectors) {
        char source[384]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = %s { return 200 \"x\"; } }",
                                 vector.path);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto result = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(vector.detail));
        const char* exact = strstr(source, "location = ");
        REQUIRE(exact != nullptr);
        const char* path = exact + strlen("location = ");
        CHECK_EQ(static_cast<u32>(strlen(vector.path)),
                 static_cast<u32>(strcspn(path, " \t\r\n{};#")));
        CHECK_EQ(result.error().span.start, static_cast<u32>(path - source));
        CHECK_EQ(result.error().span.end - result.error().span.start,
                 static_cast<u32>(strlen(vector.path)));
    }

    const char adjacent_fragment[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz#fragment\n { return 200 \"x\"; } }";
    const auto fragment = nginx::parse({adjacent_fragment, sizeof(adjacent_fragment) - 1u});
    REQUIRE_FALSE(fragment);
    CHECK_EQ(fragment.error().code, FrontendError::UnsupportedSyntax);
    CHECK(fragment.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    const char* fragment_path = strstr(adjacent_fragment, "/healthz");
    REQUIRE(fragment_path != nullptr);
    CHECK_EQ(fragment.error().span.start, static_cast<u32>(fragment_path - adjacent_fragment));
    CHECK_EQ(fragment.error().span.end - fragment.error().span.start,
             static_cast<u32>(strlen("/healthz")));

    char control_path[] = "/health\x01z";
    char control_source[384]{};
    const int control_len =
        snprintf(control_source,
                 sizeof(control_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = %s { return 200 \"x\"; } }",
                 control_path);
    REQUIRE_GT(control_len, 0);
    const auto control = nginx::parse({control_source, static_cast<u32>(control_len)});
    REQUIRE_FALSE(control);
    CHECK_EQ(control.error().code, FrontendError::UnsupportedSyntax);
    CHECK(control.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    const char* control_at = strstr(control_source, "/health");
    REQUIRE(control_at != nullptr);
    CHECK_EQ(control.error().span.start, static_cast<u32>(control_at - control_source));
    CHECK_EQ(control.error().span.end - control.error().span.start, 9u);

    const char non_ascii_path[] = {'/', 'h', static_cast<char>(0xc3), static_cast<char>(0xa9), 0};
    char non_ascii_source[384]{};
    const int non_ascii_len =
        snprintf(non_ascii_source,
                 sizeof(non_ascii_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = %s { return 200 \"x\"; } }",
                 non_ascii_path);
    REQUIRE_GT(non_ascii_len, 0);
    const auto non_ascii = nginx::parse({non_ascii_source, static_cast<u32>(non_ascii_len)});
    REQUIRE_FALSE(non_ascii);
    CHECK_EQ(non_ascii.error().code, FrontendError::UnsupportedSyntax);
    CHECK(non_ascii.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    const char* non_ascii_at = strstr(non_ascii_source, "/h");
    REQUIRE(non_ascii_at != nullptr);
    CHECK_EQ(non_ascii.error().span.start, static_cast<u32>(non_ascii_at - non_ascii_source));
    CHECK_EQ(non_ascii.error().span.end - non_ascii.error().span.start, 4u);

    const char whitespace[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /health z { return 200 \"x\"; } }";
    const auto whitespace_result = nginx::parse({whitespace, sizeof(whitespace) - 1u});
    REQUIRE_FALSE(whitespace_result);
    CHECK_EQ(whitespace_result.error().code, FrontendError::UnexpectedToken);
    CHECK(whitespace_result.error().detail.eq(lit_str("expected '{' after exact location path")));
    const char* whitespace_marker = strstr(whitespace, " z ");
    REQUIRE(whitespace_marker != nullptr);
    const char* whitespace_at = whitespace_marker + 1;
    CHECK_EQ(whitespace_result.error().span.start, static_cast<u32>(whitespace_at - whitespace));

    const char brace_open[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /health{z { return 200 \"x\"; } }";
    const auto brace_open_result = nginx::parse({brace_open, sizeof(brace_open) - 1u});
    REQUIRE_FALSE(brace_open_result);
    CHECK_EQ(brace_open_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(brace_open_result.error().detail.eq(lit_str("unknown exact location directive")));
    const char* brace_open_marker = strstr(brace_open, "{z");
    REQUIRE(brace_open_marker != nullptr);
    const char* brace_open_at = brace_open_marker + 1;
    CHECK_EQ(brace_open_result.error().span.start, static_cast<u32>(brace_open_at - brace_open));

    const char brace_close[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /health}z { return 200 \"x\"; } }";
    const auto brace_close_result = nginx::parse({brace_close, sizeof(brace_close) - 1u});
    REQUIRE_FALSE(brace_close_result);
    CHECK_EQ(brace_close_result.error().code, FrontendError::UnexpectedToken);
    CHECK(brace_close_result.error().detail.eq(lit_str("expected '{' after exact location path")));
    const char* brace_close_at = strstr(brace_close, "}z");
    REQUIRE(brace_close_at != nullptr);
    CHECK_EQ(brace_close_result.error().span.start, static_cast<u32>(brace_close_at - brace_close));
}

TEST(nginx_parser, keeps_old_reserved_for_exact_absolute_redirect) {
    for (const u16 status : {301u, 302u}) {
        char source[320]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = /old { return %u "
                                 "http://redirect.example/new; } }",
                                 static_cast<unsigned>(status));
        REQUIRE_GT(len, 0);
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        CHECK_FALSE(parsed.value().exact_local_return.present);
        REQUIRE(parsed.value().exact_absolute_redirect.present);
        CHECK(parsed.value().exact_absolute_redirect.path.eq(lit_str("/old")));
        CHECK_EQ(parsed.value().exact_absolute_redirect.response.status, status);
    }

    const char local_shape[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 200 \"x\"; } }";
    const auto rejected = nginx::parse({local_shape, sizeof(local_shape) - 1u});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(lit_str("only redirect status 301 or 302 is supported")));
    const char* status = strstr(local_shape, "200");
    REQUIRE(status != nullptr);
    CHECK_EQ(rejected.error().span.start, static_cast<u32>(status - local_shape));
}

TEST(nginx_parser, accepts_exact_local_return_64_byte_body_boundary) {
    static constexpr char kBody[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static_assert(sizeof(kBody) - 1u == nginx::kMaxLocalReturnBodyLen);
    char source[512]{};
    const int len = snprintf(source,
                             sizeof(source),
                             "server { listen 8080; location / { proxy_pass "
                             "http://127.0.0.1:9000; } location = /static { return 200 \"%s\"; } }",
                             kBody);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto result = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE(result);
    CHECK_EQ(result.value().exact_local_return.response.body.len, nginx::kMaxLocalReturnBodyLen);
    CHECK(result.value().exact_local_return.response.body.eq(lit_str(kBody)));
}

TEST(nginx_parser, parses_bounded_301_and_302_absolute_redirect_in_either_order) {
    const auto check =
        [&](char* source, u32 len, u32 root_line, u32 exact_line, u16 expected_status) {
            const auto result = nginx::parse({source, len});
            REQUIRE(result);
            const auto& server = result.value();
            CHECK(server.location.path.eq(lit_str("/")));
            CHECK_EQ(server.location.span.line, root_line);
            CHECK_FALSE(server.exact_local_return.present);
            REQUIRE(server.exact_absolute_redirect.present);
            const auto& location = server.exact_absolute_redirect;
            const auto& response = location.response;
            CHECK(location.path.eq(lit_str("/old")));
            CHECK_EQ(location.path_span.line, exact_line);
            CHECK_EQ(location.span.line, exact_line);
            CHECK_EQ(response.status, expected_status);
            const Str expected_lexeme = expected_status == 301 ? lit_str("301") : lit_str("302");
            CHECK(response.status_lexeme.eq(expected_lexeme));
            CHECK_EQ(response.status_span.line, exact_line);
            CHECK_EQ(response.status_span.end - response.status_span.start,
                     response.status_lexeme.len);
            CHECK(response.target.eq(lit_str("http://redirect.example/new")));
            CHECK(response.authority.eq(lit_str("redirect.example")));
            CHECK(response.path.eq(lit_str("/new")));
            CHECK_EQ(response.target_span.line, exact_line);
            CHECK_EQ(response.authority_span.line, exact_line);
            CHECK_EQ(response.path_span.line, exact_line);
            CHECK_GE(location.path.ptr, source);
            CHECK_LT(location.path.ptr, source + len);
            CHECK_GE(response.target.ptr, source);
            CHECK_LT(response.target.ptr, source + len);
            CHECK_GE(response.status_lexeme.ptr, source);
            CHECK_LT(response.status_lexeme.ptr, source + len);
            CHECK_EQ(response.status_lexeme.ptr, source + response.status_span.start);
            CHECK_EQ(response.authority.ptr, response.target.ptr + 7);
            CHECK_EQ(response.path.ptr, response.authority.ptr + response.authority.len);
            CHECK_EQ(response.target_span.end - response.target_span.start, response.target.len);
            CHECK_EQ(response.authority_span.end - response.authority_span.start,
                     response.authority.len);
            CHECK_EQ(response.path_span.end - response.path_span.start, response.path.len);
            CHECK_EQ(response.authority_span.start, response.target_span.start + 7u);
            CHECK_EQ(response.path_span.end, response.target_span.end);
            REQUIRE(server.pre_route_trace.profile ==
                    nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
            CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
            CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        };
    for (const u16 status : {301u, 302u}) {
        char root_first[256]{};
        const int root_len = snprintf(root_first,
                                      sizeof(root_first),
                                      "server {\n  listen 8080;\n  location / { proxy_pass "
                                      "http://127.0.0.1:9000; }\n  location = /old { return %u "
                                      "http://redirect.example/new; }\n}\n",
                                      static_cast<unsigned>(status));
        REQUIRE_GT(root_len, 0);
        REQUIRE_LT(static_cast<u32>(root_len), static_cast<u32>(sizeof(root_first)));
        check(root_first, static_cast<u32>(root_len), 3u, 4u, status);

        char exact_first[256]{};
        const int exact_len = snprintf(exact_first,
                                       sizeof(exact_first),
                                       "server {\n  listen 8080;\n  location = /old { return %u "
                                       "http://redirect.example/new; }\n  location / { proxy_pass "
                                       "http://127.0.0.1:9000; }\n}\n",
                                       static_cast<unsigned>(status));
        REQUIRE_GT(exact_len, 0);
        REQUIRE_LT(static_cast<u32>(exact_len), static_cast<u32>(sizeof(exact_first)));
        check(exact_first, static_cast<u32>(exact_len), 4u, 3u, status);
    }
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
    CHECK(other_result.error().detail.eq(
        lit_str("location path is outside the bounded clean proxy profile")));
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
    CHECK(result.value().pre_route_trace.profile ==
          nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
    CHECK_EQ(result.value().pre_route_trace.span.start, result.value().span.start);
    CHECK_EQ(result.value().pre_route_trace.span.end, result.value().span.end);
    CHECK_EQ(result.value().pre_route_trace.span.line, result.value().span.line);
    CHECK_EQ(result.value().pre_route_trace.span.col, result.value().span.col);
}

TEST(nginx_parser, parses_bounded_clean_proxy_location_with_exact_source_provenance) {
    const char root_uri[] =
        "server {\n"
        "  listen 8080;\n"
        "\n"
        "    location /service/ {\n"
        "      proxy_pass http://127.0.0.1:9000/;\n"
        "    }\n"
        "}\n";
    const char replacement_uri[] =
        "server { listen 8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";

    const auto root_result = nginx::parse({root_uri, sizeof(root_uri) - 1u});
    const auto replacement_result = nginx::parse({replacement_uri, sizeof(replacement_uri) - 1u});
    REQUIRE(root_result);
    REQUIRE(replacement_result);

    const auto& server = root_result.value();
    const auto& location = server.location;
    const char* location_keyword = strstr(root_uri, "location");
    const char* path = strstr(root_uri, "/service/");
    const char* closing_brace = strstr(strstr(root_uri, "proxy_pass"), "}");
    REQUIRE(location_keyword != nullptr);
    REQUIRE(path != nullptr);
    REQUIRE(closing_brace != nullptr);
    CHECK(location.path.eq(lit_str("/service/")));
    CHECK_EQ(location.path.ptr, path);
    CHECK_EQ(location.path.ptr, root_uri + location.path_span.start);
    CHECK_EQ(location.path_span.end - location.path_span.start, location.path.len);
    CHECK_EQ(location.path_span.line, 4u);
    CHECK_EQ(location.path_span.col, 14u);
    CHECK_EQ(location.span.start, static_cast<u32>(location_keyword - root_uri));
    CHECK_EQ(location.span.end, static_cast<u32>(closing_brace - root_uri + 1));
    CHECK_EQ(location.span.line, 4u);
    CHECK_EQ(location.span.col, 5u);
    CHECK_GE(location.path.ptr, root_uri);
    CHECK_LE(location.path.ptr + location.path.len, root_uri + sizeof(root_uri) - 1u);
    REQUIRE(location.proxy_pass.has_uri);
    CHECK(location.proxy_pass.uri.eq(lit_str("/")));
    CHECK_EQ(location.proxy_pass.uri.ptr, root_uri + location.proxy_pass.uri_span.start);
    CHECK_EQ(location.proxy_pass.uri_span.end - location.proxy_pass.uri_span.start,
             location.proxy_pass.uri.len);

    const auto& replacement = replacement_result.value().location;
    CHECK(replacement.path.eq(lit_str("/service/")));
    REQUIRE(replacement.proxy_pass.has_uri);
    CHECK(replacement.proxy_pass.uri.eq(lit_str("/v1/")));
    CHECK_EQ(replacement.path.ptr, replacement_uri + replacement.path_span.start);
    CHECK_EQ(replacement.proxy_pass.uri.ptr,
             replacement_uri + replacement.proxy_pass.uri_span.start);
}

TEST(nginx_parser, enforces_bounded_clean_proxy_location_capacity) {
    static_assert(nginx::kMaxProxyLocationPathLen == 63u);
    static_assert(nginx::kMaxProxyLocationPathLen + 1u == ConnectionBase::kMaxReqPathLen);
    static_assert(nginx::kMaxProxyLocationPathLen < RouteEntry::kMaxPathLen);
    static_assert(nginx::kMaxProxyLocationPathLen <= kMaxForwardTargetTransformPrefixLen);
    char accepted_path[nginx::kMaxProxyLocationPathLen + 1u]{};
    accepted_path[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxProxyLocationPathLen; i++) accepted_path[i] = 'a';
    accepted_path[nginx::kMaxProxyLocationPathLen - 1u] = '/';

    char accepted_source[256]{};
    const int accepted_len = snprintf(accepted_source,
                                      sizeof(accepted_source),
                                      "server { listen 8080; location %s { proxy_pass "
                                      "http://127.0.0.1:9000/; } }",
                                      accepted_path);
    REQUIRE_GT(accepted_len, 0);
    REQUIRE_LT(static_cast<u32>(accepted_len), static_cast<u32>(sizeof(accepted_source)));
    const auto accepted = nginx::parse({accepted_source, static_cast<u32>(accepted_len)});
    REQUIRE(accepted);
    const auto& accepted_location = accepted.value().location;
    const char* accepted_keyword = strstr(accepted_source, "location");
    const char* accepted_closing_brace = strstr(strstr(accepted_source, "proxy_pass"), "}");
    REQUIRE(accepted_keyword != nullptr);
    REQUIRE(accepted_closing_brace != nullptr);
    CHECK_EQ(accepted_location.path.len, nginx::kMaxProxyLocationPathLen);
    CHECK_EQ(accepted_location.path.ptr, accepted_source + accepted_location.path_span.start);
    CHECK_EQ(accepted_location.path_span.end - accepted_location.path_span.start,
             nginx::kMaxProxyLocationPathLen);
    CHECK_EQ(accepted_location.path_span.line, 1u);
    CHECK_EQ(accepted_location.path_span.col, 32u);
    CHECK_EQ(accepted_location.span.start, static_cast<u32>(accepted_keyword - accepted_source));
    CHECK_EQ(accepted_location.span.end,
             static_cast<u32>(accepted_closing_brace - accepted_source + 1));
    CHECK_EQ(accepted_location.span.line, 1u);
    CHECK_EQ(accepted_location.span.col, 23u);

    char rejected_path[nginx::kMaxProxyLocationPathLen + 2u]{};
    rejected_path[0] = '/';
    for (u32 i = 1; i < nginx::kMaxProxyLocationPathLen; i++) rejected_path[i] = 'a';
    rejected_path[nginx::kMaxProxyLocationPathLen] = '/';

    char rejected_source[256]{};
    const int rejected_len = snprintf(rejected_source,
                                      sizeof(rejected_source),
                                      "server { listen 8080; location %s { proxy_pass "
                                      "http://127.0.0.1:9000/; } }",
                                      rejected_path);
    REQUIRE_GT(rejected_len, 0);
    REQUIRE_LT(static_cast<u32>(rejected_len), static_cast<u32>(sizeof(rejected_source)));
    const auto rejected = nginx::parse({rejected_source, static_cast<u32>(rejected_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(
        lit_str("location path is outside the bounded clean proxy profile")));
    CHECK_EQ(rejected.error().span.start,
             static_cast<u32>(strstr(rejected_source, rejected_path) - rejected_source));
    CHECK_EQ(rejected.error().span.end - rejected.error().span.start,
             nginx::kMaxProxyLocationPathLen + 1u);
}

TEST(nginx_parser, rejects_non_clean_proxy_location_shapes) {
    struct Rejection {
        const char* path;
        u32 len;
        Str detail;
    };
    static constexpr Rejection kRejected[] = {
        {"service/", 8, lit_str("location path is outside the bounded clean proxy profile")},
        {"/service", 8, lit_str("location path is outside the bounded clean proxy profile")},
        {"//service/", 10, lit_str("location path is outside the bounded clean proxy profile")},
        {"/service//x/", 12, lit_str("location path is outside the bounded clean proxy profile")},
        {"/./", 3, lit_str("location path is outside the bounded clean proxy profile")},
        {"/../", 4, lit_str("location path is outside the bounded clean proxy profile")},
        {"/a/../b/", 8, lit_str("location path is outside the bounded clean proxy profile")},
        {"/%41/", 5, lit_str("location path is outside the bounded clean proxy profile")},
        {"/service/?x=1", 13, lit_str("location path is outside the bounded clean proxy profile")},
        {"/a\\b/", 5, lit_str("location path is outside the bounded clean proxy profile")},
        {"/a\"b/", 5, lit_str("location path is outside the bounded clean proxy profile")},
        {"/a'b/", 5, lit_str("location path is outside the bounded clean proxy profile")},
        {"/a:b/", 5, lit_str("location path is outside the bounded clean proxy profile")},
        {"/a\x01"
         "b/",
         5,
         lit_str("location path is outside the bounded clean proxy profile")},
        {"/a\xC3\xA9/", 5, lit_str("location path is outside the bounded clean proxy profile")},
        {"/service/$x/", 12, lit_str("variables are unsupported")},
    };

    for (const auto& vector : kRejected) {
        char source[256]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location %.*s { proxy_pass "
                                 "http://127.0.0.1:1/; } }",
                                 static_cast<int>(vector.len),
                                 vector.path);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto result = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(vector.detail));
        const char* path = strstr(source, "location ") + 9;
        CHECK_EQ(result.error().span.start, static_cast<u32>(path - source));
    }

    const char whitespace[] =
        "server { listen 8080; location /a b/ { proxy_pass http://127.0.0.1:1/; } }";
    const auto whitespace_result = nginx::parse({whitespace, sizeof(whitespace) - 1u});
    REQUIRE_FALSE(whitespace_result);
    CHECK_EQ(whitespace_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(whitespace_result.error().detail.eq(
        lit_str("location path is outside the bounded clean proxy profile")));

    const char fragment[] =
        "server { listen 8080; location \"/service/#fragment\" { proxy_pass "
        "http://127.0.0.1:1/; } }";
    const auto fragment_result = nginx::parse({fragment, sizeof(fragment) - 1u});
    REQUIRE_FALSE(fragment_result);
    CHECK_EQ(fragment_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(fragment_result.error().detail.eq(
        lit_str("location path is outside the bounded clean proxy profile")));

    const char all_unreserved[] =
        "server { listen 8080; location /AZaz09-._~/ { proxy_pass http://127.0.0.1:1/; } }";
    REQUIRE(nginx::parse({all_unreserved, sizeof(all_unreserved) - 1u}));
}

TEST(nginx_parser, parsed_generic_proxy_location_reaches_ordinary_rut_lowering) {
    const char service[] =
        "server { listen 8080; location /service/ { proxy_pass http://127.0.0.1:9000/; } }";
    const auto parsed = nginx::parse({service, sizeof(service) - 1u});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK(strstr(lowered.value().data, "route \"/service\" {") != nullptr);
    CHECK(strstr(lowered.value().data, "if req.method == GET && req.pathOnly == \"/service\"") !=
          nullptr);
    CHECK(strstr(lowered.value().data, "target_path: \"/service/\"") != nullptr);
    CHECK(strstr(lowered.value().data, "strip_prefix: \"/service/\"") != nullptr);
    CHECK(strstr(lowered.value().data, "replace_prefix: \"/\"") != nullptr);
    const char* path = strstr(service, "/service/");
    REQUIRE(path != nullptr);
    CHECK_EQ(parsed.value().location.path_span.start, static_cast<u32>(path - service));
    CHECK_EQ(parsed.value().location.path_span.end - parsed.value().location.path_span.start, 9u);

    const char service_without_uri[] =
        "server { listen 8080; location /service/ { proxy_pass http://127.0.0.1:9000; } }";
    const auto missing_uri = nginx::parse({service_without_uri, sizeof(service_without_uri) - 1u});
    REQUIRE(missing_uri);
    CHECK_FALSE(missing_uri.value().location.proxy_pass.has_uri);
    const auto missing_uri_lowered = nginx::lower_to_rut(missing_uri.value());
    REQUIRE(missing_uri_lowered);
    CHECK_EQ(missing_uri_lowered.value().len, 3247u);
    CHECK(strstr(missing_uri_lowered.value().data, "route \"/service\" {") != nullptr);
    CHECK(strstr(missing_uri_lowered.value().data, "target_transform:") == nullptr);
    const char* missing_uri_path = strstr(service_without_uri, "/service/");
    REQUIRE(missing_uri_path != nullptr);
    CHECK_EQ(missing_uri.value().location.path_span.start,
             static_cast<u32>(missing_uri_path - service_without_uri));
    CHECK_EQ(
        missing_uri.value().location.path_span.end - missing_uri.value().location.path_span.start,
        9u);

    const char api[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/; } }";
    const char formatted_api[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/;\n"
        "  }\n"
        "}\n";
    const auto legacy_parsed = nginx::parse({api, sizeof(api) - 1u});
    const auto formatted_legacy_parsed = nginx::parse({formatted_api, sizeof(formatted_api) - 1u});
    REQUIRE(legacy_parsed);
    REQUIRE(formatted_legacy_parsed);
    const auto legacy_lowered = nginx::lower_to_rut(legacy_parsed.value());
    const auto formatted_legacy_lowered = nginx::lower_to_rut(formatted_legacy_parsed.value());
    REQUIRE(legacy_lowered);
    REQUIRE(formatted_legacy_lowered);
    CHECK(legacy_lowered.value().view().eq(formatted_legacy_lowered.value().view()));
}

TEST(nginx_parser, parses_bounded_clean_non_root_proxy_uri_with_source_provenance) {
    const char compact[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/v1/; } }";
    const char formatted[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/;\n"
        "  }\n"
        "}\n";

    const auto compact_result = nginx::parse({compact, sizeof(compact) - 1u});
    const auto formatted_result = nginx::parse({formatted, sizeof(formatted) - 1u});
    REQUIRE(compact_result);
    REQUIRE(formatted_result);

    const auto check =
        [&](const nginx::Server& server, const char* source, u32 source_len, u32 line) {
            const auto& proxy = server.location.proxy_pass;
            REQUIRE(proxy.has_uri);
            CHECK(proxy.uri.eq(lit_str("/v1/")));
            CHECK_EQ(proxy.uri.ptr, source + proxy.uri_span.start);
            CHECK_EQ(proxy.uri_span.end - proxy.uri_span.start, proxy.uri.len);
            CHECK_EQ(proxy.uri_span.line, line);
            CHECK_GE(proxy.uri.ptr, source);
            CHECK_LE(proxy.uri.ptr + proxy.uri.len, source + source_len);
            CHECK_LT(proxy.uri_span.end, proxy.span.end);
        };
    check(compact_result.value(), compact, sizeof(compact) - 1u, 1u);
    check(formatted_result.value(), formatted, sizeof(formatted) - 1u, 4u);

    const auto& compact_proxy = compact_result.value().location.proxy_pass;
    const auto& formatted_proxy = formatted_result.value().location.proxy_pass;
    CHECK_EQ(compact_proxy.port, formatted_proxy.port);
    CHECK(compact_proxy.uri.eq(formatted_proxy.uri));
    CHECK_NE(compact_proxy.uri.ptr, formatted_proxy.uri.ptr);
    CHECK_NE(compact_proxy.uri_span.start, formatted_proxy.uri_span.start);
}

TEST(nginx_parser, models_static_query_proxy_uri_in_either_server_directive_order) {
    const char listen_first[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/?fixed=1;\n"
        "  }\n"
        "}\n";
    const char location_first[] =
        "server {\n"
        "  location /api/ { proxy_pass http://127.0.0.1:9000/v1/?fixed=1; }\n"
        "  listen 8080;\n"
        "}\n";

    const auto check = [&](const char* source, u32 source_len, u32 expected_line) {
        const auto parsed = nginx::parse({source, source_len});
        REQUIRE(parsed);
        const auto& proxy = parsed.value().location.proxy_pass;
        const char* replacement = strstr(source, "/v1/?fixed=1");
        REQUIRE(replacement != nullptr);
        REQUIRE(proxy.has_uri);
        CHECK(proxy.uri.eq(lit_str("/v1/?fixed=1")));
        CHECK_EQ(proxy.uri.ptr, replacement);
        CHECK_EQ(proxy.uri.ptr, source + proxy.uri_span.start);
        CHECK_EQ(proxy.uri_span.end - proxy.uri_span.start, proxy.uri.len);
        CHECK_EQ(proxy.uri_span.line, expected_line);
        const char* line_start = replacement;
        while (line_start != source && line_start[-1] != '\n') --line_start;
        CHECK_EQ(proxy.uri_span.col, static_cast<u32>(replacement - line_start + 1u));
        CHECK_LT(proxy.uri_span.end, proxy.span.end);
        CHECK_GE(proxy.uri.ptr, source);
        CHECK_LE(proxy.uri.ptr + proxy.uri.len, source + source_len);
    };
    check(listen_first, sizeof(listen_first) - 1u, 4u);
    check(location_first, sizeof(location_first) - 1u, 2u);
}

TEST(nginx_parser, accepts_bounded_static_query_grammar_and_root_replacement_path) {
    static constexpr const char* kAccepted[] = {
        "/?a",    // Three-byte minimum and a one-byte query.
        "/?=",    // `=` is allowed as the complete one-byte query.
        "/?&",    // `&` is allowed as the complete one-byte query.
        "/?=&",   // Both query separators may be adjacent.
        "/?x=1",  // Root replacement path with the requested static query.
        "/?x=1&y=two",
        "/v1/?AZaz09._~-=&",
    };
    for (const char* uri : kAccepted) {
        char source[256]{};
        const int source_len = snprintf(source,
                                        sizeof(source),
                                        "server { listen 8080; location /api/ { proxy_pass "
                                        "http://127.0.0.1:9000%s; } }",
                                        uri);
        REQUIRE_GT(source_len, 0);
        REQUIRE_LT(static_cast<u32>(source_len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(source_len)});
        REQUIRE(parsed);
        const auto& proxy = parsed.value().location.proxy_pass;
        const u32 uri_len = static_cast<u32>(strlen(uri));
        CHECK((proxy.uri.eq({uri, uri_len})));
        CHECK_EQ(proxy.uri.ptr, source + proxy.uri_span.start);
        CHECK_EQ(proxy.uri_span.end - proxy.uri_span.start, uri_len);
    }
}

TEST(nginx_parser, enforces_complete_static_query_proxy_uri_capacity) {
    static_assert(nginx::kMaxProxyPassUriLen == 128u);
    char accepted_uri[nginx::kMaxProxyPassUriLen + 1u]{};
    accepted_uri[0] = '/';
    accepted_uri[1] = '?';
    for (u32 i = 2; i < nginx::kMaxProxyPassUriLen; i++) accepted_uri[i] = 'a';

    char accepted_source[512]{};
    const int accepted_len = snprintf(accepted_source,
                                      sizeof(accepted_source),
                                      "server { listen 8080; location /api/ { proxy_pass "
                                      "http://127.0.0.1:9000%s; } }",
                                      accepted_uri);
    REQUIRE_GT(accepted_len, 0);
    REQUIRE_LT(static_cast<u32>(accepted_len), static_cast<u32>(sizeof(accepted_source)));
    const auto accepted = nginx::parse({accepted_source, static_cast<u32>(accepted_len)});
    REQUIRE(accepted);
    CHECK_EQ(accepted.value().location.proxy_pass.uri.len, nginx::kMaxProxyPassUriLen);
    CHECK_EQ(accepted.value().location.proxy_pass.uri.ptr,
             accepted_source + accepted.value().location.proxy_pass.uri_span.start);

    char rejected_uri[nginx::kMaxProxyPassUriLen + 2u]{};
    rejected_uri[0] = '/';
    rejected_uri[1] = '?';
    for (u32 i = 2; i <= nginx::kMaxProxyPassUriLen; i++) rejected_uri[i] = 'b';

    char rejected_source[512]{};
    const int rejected_len = snprintf(rejected_source,
                                      sizeof(rejected_source),
                                      "server { listen 8080; location /api/ { proxy_pass "
                                      "http://127.0.0.1:9000%s; } }",
                                      rejected_uri);
    REQUIRE_GT(rejected_len, 0);
    REQUIRE_LT(static_cast<u32>(rejected_len), static_cast<u32>(sizeof(rejected_source)));
    const auto rejected = nginx::parse({rejected_source, static_cast<u32>(rejected_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(
        rejected.error().detail.eq(lit_str("proxy_pass URI is outside the bounded clean profile")));
    CHECK_EQ(rejected.error().span.end - rejected.error().span.start,
             nginx::kMaxProxyPassUriLen + 1u);
}

TEST(nginx_parser, rejects_excluded_static_query_bytes_and_invalid_query_paths) {
    struct Rejection {
        const char* uri;
        u32 len;
    };
    const char control[] = {'/', '?', '\x01'};
    const char nul[] = {'/', '?', '\0'};
    const char del[] = {'/', '?', static_cast<char>(0x7f)};
    const char non_ascii[] = {'/', '?', static_cast<char>(0x80)};
    const Rejection rejected[] = {
        {"/?", 2},
        {"/?a?b", 5},
        {"/?a#fragment", 12},
        {"/?%", 3},
        {"/?+", 3},
        {"/?/", 3},
        {"/?:", 3},
        {"/?$request_uri", 14},
        {"/?'", 3},
        {"/?\"", 3},
        {"/?\\", 3},
        {"/? ", 3},
        {"/?\t", 3},
        {control, sizeof(control)},
        {nul, sizeof(nul)},
        {del, sizeof(del)},
        {non_ascii, sizeof(non_ascii)},
        {"//?x", 4},
        {"/./?x", 5},
        {"/../?x", 6},
        {"/v1?x", 5},
        {"/%41/?x", 7},
    };
    static constexpr char kPrefix[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000";
    static constexpr char kSuffix[] = "; } }";

    for (const auto& vector : rejected) {
        char source[512]{};
        const u32 prefix_len = sizeof(kPrefix) - 1u;
        const u32 suffix_len = sizeof(kSuffix) - 1u;
        REQUIRE_LE(prefix_len + vector.len + suffix_len, static_cast<u32>(sizeof(source)));
        memcpy(source, kPrefix, prefix_len);
        memcpy(source + prefix_len, vector.uri, vector.len);
        memcpy(source + prefix_len + vector.len, kSuffix, suffix_len);
        const auto parsed = nginx::parse({source, prefix_len + vector.len + suffix_len});
        REQUIRE_FALSE(parsed);
    }

    // nginx's existing path-only clean profile never admitted generic RUT's
    // historical `$` byte. The new query branch must not broaden that profile.
    const char path_variable[] =
        "server { listen 8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/$/; } }";
    const auto path_variable_result = nginx::parse({path_variable, sizeof(path_variable) - 1u});
    REQUIRE_FALSE(path_variable_result);
    CHECK_EQ(path_variable_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(path_variable_result.error().detail.eq(lit_str("variables are unsupported")));

    const char retained_path_only[] =
        "server { listen 8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/AZaz09-._~/; } }";
    const auto retained = nginx::parse({retained_path_only, sizeof(retained_path_only) - 1u});
    REQUIRE(retained);
    CHECK(retained.value().location.proxy_pass.uri.eq(lit_str("/AZaz09-._~/")));
}

TEST(nginx_parser, enforces_bounded_clean_proxy_uri_capacity) {
    static_assert(nginx::kMaxProxyPassUriLen == 128u);
    char accepted_uri[nginx::kMaxProxyPassUriLen + 1u]{};
    accepted_uri[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxProxyPassUriLen; i++) accepted_uri[i] = 'a';
    accepted_uri[nginx::kMaxProxyPassUriLen - 1u] = '/';

    char accepted_source[512]{};
    const int accepted_len = snprintf(accepted_source,
                                      sizeof(accepted_source),
                                      "server { listen 8080; location /api/ { proxy_pass "
                                      "http://127.0.0.1:9000%s; } }",
                                      accepted_uri);
    REQUIRE_GT(accepted_len, 0);
    REQUIRE_LT(static_cast<u32>(accepted_len), static_cast<u32>(sizeof(accepted_source)));
    const auto accepted = nginx::parse({accepted_source, static_cast<u32>(accepted_len)});
    REQUIRE(accepted);
    CHECK_EQ(accepted.value().location.proxy_pass.uri.len, nginx::kMaxProxyPassUriLen);
    CHECK_EQ(accepted.value().location.proxy_pass.uri.ptr,
             accepted_source + accepted.value().location.proxy_pass.uri_span.start);

    char rejected_uri[nginx::kMaxProxyPassUriLen + 2u]{};
    rejected_uri[0] = '/';
    for (u32 i = 1; i < nginx::kMaxProxyPassUriLen; i++) rejected_uri[i] = 'a';
    rejected_uri[nginx::kMaxProxyPassUriLen] = '/';

    char rejected_source[512]{};
    const int rejected_len = snprintf(rejected_source,
                                      sizeof(rejected_source),
                                      "server { listen 8080; location /api/ { proxy_pass "
                                      "http://127.0.0.1:9000%s; } }",
                                      rejected_uri);
    REQUIRE_GT(rejected_len, 0);
    REQUIRE_LT(static_cast<u32>(rejected_len), static_cast<u32>(sizeof(rejected_source)));
    const auto rejected = nginx::parse({rejected_source, static_cast<u32>(rejected_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(
        rejected.error().detail.eq(lit_str("proxy_pass URI is outside the bounded clean profile")));
    CHECK_EQ(rejected.error().span.start,
             static_cast<u32>(strstr(rejected_source, rejected_uri) - rejected_source));
    CHECK_EQ(rejected.error().span.end - rejected.error().span.start,
             nginx::kMaxProxyPassUriLen + 1u);
}

TEST(nginx_parser, rejects_unmatched_location_and_proxy_uri_shapes) {
    const char root_with_uri[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1/; } }";
    CHECK(is_error(nginx::parse({root_with_uri, sizeof(root_with_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   65,
                   lit_str("location / cannot use a proxy_pass URI")));

    const char root_with_non_root_uri[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1/v1/; } }";
    CHECK(is_error(nginx::parse({root_with_non_root_uri, sizeof(root_with_non_root_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   65,
                   lit_str("location / cannot use a proxy_pass URI")));

    const char api_without_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1; } }";
    const auto parsed_api_without_uri =
        nginx::parse({api_without_uri, sizeof(api_without_uri) - 1u});
    REQUIRE(parsed_api_without_uri);
    CHECK_FALSE(parsed_api_without_uri.value().location.proxy_pass.has_uri);
    const auto lowered_api_without_uri = nginx::lower_to_rut(parsed_api_without_uri.value());
    REQUIRE(lowered_api_without_uri);
    CHECK_EQ(lowered_api_without_uri.value().len, 3232u);
    CHECK(strstr(lowered_api_without_uri.value().data, "route \"/api\" {") != nullptr);
    CHECK(strstr(lowered_api_without_uri.value().data, "target_transform:") == nullptr);

    const char api_without_trailing_slash[] =
        "server { listen 8080; location /api { proxy_pass http://127.0.0.1:1/; } }";
    CHECK(
        is_error(nginx::parse({api_without_trailing_slash, sizeof(api_without_trailing_slash) - 1}),
                 FrontendError::UnsupportedSyntax,
                 1,
                 32,
                 lit_str("location path is outside the bounded clean proxy profile")));

    const char missing_trailing_slash[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/v1; } }";
    CHECK(is_error(nginx::parse({missing_trailing_slash, sizeof(missing_trailing_slash) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   69,
                   lit_str("proxy_pass URI is outside the bounded clean profile")));

    const char variable_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/$x; } }";
    CHECK(is_error(nginx::parse({variable_uri, sizeof(variable_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   51,
                   lit_str("variables are unsupported")));

    const char empty_query_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/?; } }";
    CHECK(is_error(nginx::parse({empty_query_uri, sizeof(empty_query_uri) - 1}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   69,
                   lit_str("proxy_pass URI is outside the bounded clean profile")));

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

TEST(nginx_parser, rejects_non_clean_proxy_uri_replacement_forms) {
    struct Rejection {
        const char* uri;
        u32 len;
    };
    static constexpr Rejection kRejected[] = {
        {"//v1/", 5},
        {"/v1//x/", 7},
        {"/./", 3},
        {"/../", 4},
        {"/a/../b/", 8},
        {"/%41/", 5},
        {"/v1?x=1", 7},
        {"/a\\b/", 5},
        {"/a\"b/", 5},
        {"/a'b/", 5},
        {"/a:b/", 5},
        {"/a\x01"
         "b/",
         5},
        {"/a\xC3\xA9/", 5},
    };

    for (const auto& vector : kRejected) {
        char source[256]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location /api/ { proxy_pass "
                                 "http://127.0.0.1:1%.*s; } }",
                                 static_cast<int>(vector.len),
                                 vector.uri);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto result = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(
            lit_str("proxy_pass URI is outside the bounded clean profile")));
        const char* uri = strstr(source, "http://127.0.0.1:1") + 18;
        CHECK_EQ(result.error().span.start, static_cast<u32>(uri - source));
        CHECK_EQ(result.error().span.end - result.error().span.start, vector.len);
    }

    const char whitespace[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/a b/; } }";
    const auto whitespace_result = nginx::parse({whitespace, sizeof(whitespace) - 1u});
    REQUIRE_FALSE(whitespace_result);
    CHECK_EQ(whitespace_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(whitespace_result.error().detail.eq(
        lit_str("proxy_pass URI is outside the bounded clean profile")));

    const char fragment[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/v1/#fragment";
    const auto fragment_result = nginx::parse({fragment, sizeof(fragment) - 1u});
    REQUIRE_FALSE(fragment_result);
    CHECK_EQ(fragment_result.error().code, FrontendError::UnexpectedEof);
    CHECK(fragment_result.error().detail.eq(lit_str("expected ';' after proxy_pass")));

    const char variable[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/$uri/; } }";
    CHECK(is_error(nginx::parse({variable, sizeof(variable) - 1u}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   51,
                   lit_str("variables are unsupported")));

    const char non_absolute[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1v1/; } }";
    CHECK(is_error(nginx::parse({non_absolute, sizeof(non_absolute) - 1u}),
                   FrontendError::InvalidInteger,
                   1,
                   51,
                   lit_str("invalid upstream IPv4 address or port")));
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

TEST(nginx_parser, rejects_unsupported_exact_local_return_shapes) {
    struct Vector {
        const char* source;
        FrontendError code;
        Str detail;
    };
    const Vector vectors[] = {
        {"server { listen 8080; location = /static { return 200 \"x\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("exact location requires a root proxy fallback")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200 \"x\"; } location /api/ { proxy_pass http://127.0.0.1:2/; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("third location is unsupported")},
        {"server { listen 8080; location = /static { return 200 \"x\"; } location = /static { "
         "return 200 \"y\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("duplicate exact location")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { proxy_pass http://127.0.0.1:2; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_pass is unsupported in exact locations")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { } }",
         FrontendError::UnsupportedSyntax,
         lit_str("missing return directive in exact location")},
        {"server { listen 8080; location / { return 200 \"x\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("return is unsupported in proxy locations")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/ { return 200 \"x\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("exact local return path is outside the bounded clean profile")},
        {"server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:1/; } location = "
         "/static { return 200 \"x\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("exact location requires location / proxy fallback")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { location /nested { return 200 \"x\"; } } }",
         FrontendError::UnsupportedSyntax,
         lit_str("nested locations are unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 201 \"x\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return; } }",
         FrontendError::UnexpectedToken,
         lit_str("return requires status and body")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200; } }",
         FrontendError::UnexpectedToken,
         lit_str("return requires a literal body")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200 \"x\" extra; } }",
         FrontendError::UnexpectedToken,
         lit_str("return accepts exactly status and body")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200 $body; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200 \"$body\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200 successor-static; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 200 \"x\"; return 200 \"y\"; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("duplicate return directive")},
    };
    for (const auto& vector : vectors) {
        const auto result = nginx::parse({vector.source, static_cast<u32>(strlen(vector.source))});
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, vector.code);
        CHECK(result.error().detail.eq(vector.detail));
    }

    static constexpr char kTooLong[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static_assert(sizeof(kTooLong) - 1u == nginx::kMaxLocalReturnBodyLen + 1u);
    char source[512]{};
    const int len = snprintf(source,
                             sizeof(source),
                             "server { listen 8080; location / { proxy_pass "
                             "http://127.0.0.1:1; } location = /static { return 200 \"%s\"; } }",
                             kTooLong);
    REQUIRE_GT(len, 0);
    const auto too_long = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE_FALSE(too_long);
    CHECK_EQ(too_long.error().code, FrontendError::UnsupportedSyntax);
    CHECK(too_long.error().detail.eq(
        lit_str("return body must match the bounded 1..64-byte safe quoted ASCII grammar")));
}

TEST(nginx_parser, rejects_unbounded_or_malformed_exact_no_content_return_shapes) {
    struct Vector {
        const char* source;
        const char* marker;
        u32 marker_len;
        FrontendError code;
        Str detail;
    };
    const Vector vectors[] = {
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204 \"body\"; } }",
         "\"body\"",
         6,
         FrontendError::UnsupportedSyntax,
         lit_str("return 204 body or target is unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204 \"\"; } }",
         "\"\"",
         2,
         FrontendError::UnsupportedSyntax,
         lit_str("return 204 body or target is unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204 $x; } }",
         "$x",
         2,
         FrontendError::UnsupportedSyntax,
         lit_str("variables are unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204 target; } }",
         "target",
         6,
         FrontendError::UnsupportedSyntax,
         lit_str("return 204 body or target is unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204 extra; } }",
         "extra",
         5,
         FrontendError::UnsupportedSyntax,
         lit_str("return 204 body or target is unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204; extra; } }",
         "extra",
         5,
         FrontendError::UnsupportedSyntax,
         lit_str("unknown exact location directive")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204; return 204; } }",
         "return 204; }",
         6,
         FrontendError::UnsupportedSyntax,
         lit_str("duplicate return directive")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 205; } }",
         "205",
         3,
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 201; } }",
         "201",
         3,
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 0204; } }",
         "0204",
         4,
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204x; } }",
         "204x",
         4,
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return +204; } }",
         "+204",
         4,
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return $status; } }",
         "$status",
         7,
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { return 204#adjacent\n; } }",
         "204",
         3,
         FrontendError::UnsupportedSyntax,
         lit_str("return 204 status adjacent comment is unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/$static { return 204; } }",
         "/$static",
         8,
         FrontendError::UnsupportedSyntax,
         lit_str("variables are unsupported")},
        {"server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
         "/static { location /nested { return 204; } } }",
         "location /nested",
         8,
         FrontendError::UnsupportedSyntax,
         lit_str("nested locations are unsupported")},
    };

    for (const auto& vector : vectors) {
        const u32 len = static_cast<u32>(strlen(vector.source));
        const auto parsed = nginx::parse({vector.source, len});
        REQUIRE_FALSE(parsed);
        const char* marker = strstr(vector.source, vector.marker);
        REQUIRE(marker != nullptr);
        CHECK_EQ(parsed.error().code, vector.code);
        CHECK(parsed.error().detail.eq(vector.detail));
        CHECK_EQ(parsed.error().span.start, static_cast<u32>(marker - vector.source));
        CHECK_EQ(parsed.error().span.end,
                 static_cast<u32>(marker - vector.source) + vector.marker_len);
        CHECK_EQ(parsed.error().span.line, 1u);
        CHECK_EQ(parsed.error().span.col, static_cast<u32>(marker - vector.source) + 1u);
    }

    const char missing_semicolon[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
        "/static { return 204 } }";
    const auto missing_semicolon_result =
        nginx::parse({missing_semicolon, sizeof(missing_semicolon) - 1u});
    REQUIRE_FALSE(missing_semicolon_result);
    const char* return_start = strstr(missing_semicolon, "return 204");
    REQUIRE(return_start != nullptr);
    const char* exact_close = strchr(return_start, '}');
    REQUIRE(exact_close != nullptr);
    CHECK_EQ(missing_semicolon_result.error().code, FrontendError::UnexpectedToken);
    CHECK(missing_semicolon_result.error().detail.eq(lit_str("expected ';' after return 204")));
    CHECK_EQ(missing_semicolon_result.error().span.start,
             static_cast<u32>(exact_close - missing_semicolon));
    CHECK_EQ(missing_semicolon_result.error().span.end,
             static_cast<u32>(exact_close - missing_semicolon + 1));

    const char eof_after_status[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
        "/static { return 204";
    const auto eof_result = nginx::parse({eof_after_status, sizeof(eof_after_status) - 1u});
    REQUIRE_FALSE(eof_result);
    CHECK_EQ(eof_result.error().code, FrontendError::UnexpectedEof);
    CHECK(eof_result.error().detail.eq(lit_str("expected ';' after return 204")));
    CHECK_EQ(eof_result.error().span.start, sizeof(eof_after_status) - 1u);
    CHECK_EQ(eof_result.error().span.end, sizeof(eof_after_status) - 1u);

    const char missing_return[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
        "/static { } }";
    const auto missing_return_result = nginx::parse({missing_return, sizeof(missing_return) - 1u});
    REQUIRE_FALSE(missing_return_result);
    CHECK_EQ(missing_return_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(missing_return_result.error().detail.eq(
        lit_str("missing return directive in exact location")));

    const char status_200_without_body[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = "
        "/static { return 200; } }";
    const auto status_200_result =
        nginx::parse({status_200_without_body, sizeof(status_200_without_body) - 1u});
    REQUIRE_FALSE(status_200_result);
    CHECK_EQ(status_200_result.error().code, FrontendError::UnexpectedToken);
    CHECK(status_200_result.error().detail.eq(lit_str("return requires a literal body")));

    const char no_fallback[] = "server { listen 8080; location = /static { return 204; } }";
    const auto no_fallback_result = nginx::parse({no_fallback, sizeof(no_fallback) - 1u});
    REQUIRE_FALSE(no_fallback_result);
    CHECK_EQ(no_fallback_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(no_fallback_result.error().detail.eq(
        lit_str("exact location requires a root proxy fallback")));

    const char unsupported_modifier[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location ^~ "
        "/static { return 204; } }";
    const auto modifier_result =
        nginx::parse({unsupported_modifier, sizeof(unsupported_modifier) - 1u});
    REQUIRE_FALSE(modifier_result);
    CHECK_EQ(modifier_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(modifier_result.error().detail.eq(lit_str("location modifiers are unsupported")));
}

TEST(nginx_parser, rejects_broader_exact_absolute_redirect_shapes) {
    struct Vector {
        const char* exact;
        FrontendError code;
        Str detail;
    };
    const Vector vectors[] = {
        {"location = /older { return 301 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only return status 200 is supported")},
        {"location = /old { return 300 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect status 301 or 302 is supported")},
        {"location = /old { return 303 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect status 301 or 302 is supported")},
        {"location = /old { return 307 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect status 301 or 302 is supported")},
        {"location = /old { return 308 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect status 301 or 302 is supported")},
        {"location = /old { return 3010 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect status 301 or 302 is supported")},
        {"location = /old { return 200 http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect status 301 or 302 is supported")},
        {"location = /old { return 301 /new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 \"http://redirect.example/new\"; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 http://$host/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 https://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 http://other.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 http://redirect.example/other; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 http://redirect.example:80/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 http://redirect.example/new?x=1; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return 301 \"http://redirect.example/new#fragment\"; }",
         FrontendError::UnsupportedSyntax,
         lit_str("only redirect target http://redirect.example/new is supported")},
        {"location = /old { return; }",
         FrontendError::UnexpectedToken,
         lit_str("return requires status and target")},
        {"location = /old { return 301; }",
         FrontendError::UnexpectedToken,
         lit_str("return requires an absolute target")},
        {"location = /old { return 301 http://redirect.example/new extra; }",
         FrontendError::UnexpectedToken,
         lit_str("return accepts exactly status and target")},
        {"location = /old { }",
         FrontendError::UnsupportedSyntax,
         lit_str("missing return directive in exact location")},
        {"location = /old { return 301 http://redirect.example/new; return 301 "
         "http://redirect.example/new; }",
         FrontendError::UnsupportedSyntax,
         lit_str("duplicate return directive")},
        {"location = /old { proxy_pass http://127.0.0.1:2; }",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_pass is unsupported in exact locations")},
        {"location = /old { return 301 http://redirect.example/new; proxy_pass "
         "http://127.0.0.1:2; }",
         FrontendError::UnsupportedSyntax,
         lit_str("proxy_pass is unsupported in exact locations")},
        {"location = /old { location /nested { return 301 "
         "http://redirect.example/new; } }",
         FrontendError::UnsupportedSyntax,
         lit_str("nested locations are unsupported")},
        {"location = /old { add_header X-Test value; }",
         FrontendError::UnsupportedSyntax,
         lit_str("unknown exact location directive")},
        {"location = /old { return 301 http://redirect.example/new; add_header X-Test value; }",
         FrontendError::UnsupportedSyntax,
         lit_str("unknown exact location directive")},
    };
    static constexpr char kPrefix[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } ";
    for (const auto& vector : vectors) {
        char source[512]{};
        const int len = snprintf(source, sizeof(source), "%s%s }", kPrefix, vector.exact);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto result = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, vector.code);
        CHECK(result.error().detail.eq(vector.detail));

        // Every rejected 301 shape remains rejected after changing only its
        // status to the newly parsed 302. This reuses one closed-shape matrix
        // for target, arity, duplicate, nested, and sibling constraints.
        for (char* status = strstr(source, "301"); status != nullptr;
             status = strstr(status + 3, "301")) {
            memcpy(status, "302", 3);
        }
        if (strstr(vector.exact, "301") != nullptr) {
            const auto as_302 = nginx::parse({source, static_cast<u32>(len)});
            REQUIRE_FALSE(as_302);
            CHECK_EQ(as_302.error().code, vector.code);
            CHECK(as_302.error().detail.eq(vector.detail));
        }
    }

    struct SpanVector {
        const char* exact;
        const char* offending;
    };
    const SpanVector span_vectors[] = {
        {"location = /older { return 301 http://redirect.example/new; }", "301"},
        {"location = /old { return 303 http://redirect.example/new; }", "303"},
        {"location = /old { return 301 https://redirect.example/new; }",
         "https://redirect.example/new"},
        {"location = /old { add_header X-Test value; }", "add_header"},
    };
    for (const auto& vector : span_vectors) {
        char source[512]{};
        const int len = snprintf(source, sizeof(source), "%s%s }", kPrefix, vector.exact);
        REQUIRE_GT(len, 0);
        const auto result = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(result);
        const char* offending = strstr(source, vector.offending);
        REQUIRE(offending != nullptr);
        CHECK_EQ(result.error().span.start, static_cast<u32>(offending - source));
        CHECK_EQ(result.error().span.end - result.error().span.start,
                 static_cast<u32>(strlen(vector.offending)));
    }

    const char exact_only[] =
        "server { listen 8080; location = /old { return 301 "
        "http://redirect.example/new; } }";
    CHECK(is_error(nginx::parse({exact_only, sizeof(exact_only) - 1u}),
                   FrontendError::UnsupportedSyntax,
                   1,
                   23,
                   lit_str("exact location requires a root proxy fallback")));

    const char two_exact[] =
        "server { listen 8080; location = /static { return 200 \"x\"; } location = /old { "
        "return 301 http://redirect.example/new; } }";
    const auto duplicate = nginx::parse({two_exact, sizeof(two_exact) - 1u});
    REQUIRE_FALSE(duplicate);
    CHECK_EQ(duplicate.error().code, FrontendError::UnsupportedSyntax);
    CHECK(duplicate.error().detail.eq(lit_str("duplicate exact location")));

    const char third[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:1; } location = /old "
        "{ return 301 http://redirect.example/new; } location /api/ { proxy_pass "
        "http://127.0.0.1:2/; } }";
    const auto third_result = nginx::parse({third, sizeof(third) - 1u});
    REQUIRE_FALSE(third_result);
    CHECK_EQ(third_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(third_result.error().detail.eq(lit_str("third location is unsupported")));
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
                   lit_str("return is unsupported in proxy locations")));

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
                   lit_str("location path is outside the bounded clean proxy profile")));

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
                   65,
                   lit_str("proxy_pass URI is outside the bounded clean profile")));
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

    const char ip_with_clean_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.256:1/v1/; } }";
    CHECK(is_error(nginx::parse({ip_with_clean_uri, sizeof(ip_with_clean_uri) - 1u}),
                   FrontendError::InvalidInteger,
                   1,
                   51,
                   lit_str("invalid upstream IPv4 address or port")));

    const char port_with_clean_uri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:65536/v1/; } }";
    CHECK(is_error(nginx::parse({port_with_clean_uri, sizeof(port_with_clean_uri) - 1u}),
                   FrontendError::InvalidInteger,
                   1,
                   51,
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
    const char* const modifiers[] = {
        "server { listen 8080; location ^~ /service/ { proxy_pass http://127.0.0.1:1/; } }",
        "server { listen 8080; location ~ /service/ { proxy_pass http://127.0.0.1:1/; } }",
        "server { listen 8080; location ~* /service/ { proxy_pass http://127.0.0.1:1/; } }",
        "server { listen 8080; location @named { proxy_pass http://127.0.0.1:1; } }",
    };
    for (u32 i = 0; i < 4; i++) {
        CHECK(is_error(nginx::parse({modifiers[i], static_cast<u32>(strlen(modifiers[i]))}),
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
    server.pre_route_trace.profile = nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405;
    server.pre_route_trace.span = server.span;
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

TEST(nginx_converter, lowers_bounded_clean_exact_no_content_paths) {
    struct Vector {
        const char* path;
        const char* route;
        u32 expected_length;
    };
    const Vector vectors[] = {
        {"/x", "route exact slash_normalized GET \"/x\" { return local_response({", 5551u},
        {"/healthz",
         "route exact slash_normalized GET \"/healthz\" { return local_response({",
         5557u},
        {"/status",
         "route exact slash_normalized GET \"/status\" { return local_response({",
         5556u},
        {"/health/check",
         "route exact slash_normalized GET \"/health/check\" { return local_response({",
         5562u},
        {"/health/check/",
         "route exact slash_normalized GET \"/health/check/\" { return local_response({",
         5563u},
    };
    for (const auto& vector : vectors) {
        char source[256]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = %s { return 204; } }",
                                 vector.path);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        REQUIRE(parsed.value().exact_no_content_return.present);
        CHECK(parsed.value().exact_no_content_return.path.eq(
            {vector.path, static_cast<u32>(strlen(vector.path))}));

        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, vector.expected_length);
        const char* route = strstr(lowered.value().data, vector.route);
        REQUIRE(route != nullptr);
        CHECK(strstr(route + 1, vector.route) == nullptr);
        CHECK(strstr(route, "status: 204, reason: \"No Content\"") != nullptr);
        CHECK(strstr(route, "content_type: \"\", connection: \"request\"") != nullptr);
        CHECK(strstr(route, "head_mode: \"suppress_body\", body: b\"\"") != nullptr);
        CHECK(strstr(lowered.value().data, "nginx.conf") == nullptr);
        CHECK(strstr(lowered.value().data, "proxy_pass") == nullptr);
        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        REQUIRE_EQ(ast.value()->exact_strict_local_response_bindings.len, 1u);
        CHECK_EQ(ast.value()->exact_strict_local_response_bindings[0].path_len,
                 strlen(vector.path));
        delete ast.value();
    }
}

TEST(nginx_converter, validates_exact_no_content_return_before_dynamic_reads) {
    static constexpr char kRootFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204; } }";
    static constexpr char kExactFirst[] =
        "server { listen 8080; location = /static { return 204; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kLocalSource[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"successor-static\"; } }";
    static constexpr char kRedirectSource[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    const auto root_first = nginx::parse({kRootFirst, sizeof(kRootFirst) - 1u});
    const auto exact_first = nginx::parse({kExactFirst, sizeof(kExactFirst) - 1u});
    const auto local = nginx::parse({kLocalSource, sizeof(kLocalSource) - 1u});
    const auto redirect = nginx::parse({kRedirectSource, sizeof(kRedirectSource) - 1u});
    REQUIRE(root_first);
    REQUIRE(exact_first);
    REQUIRE(local);
    REQUIRE(redirect);

    const auto expect_rejected = [&](const nginx::Server& model, Str detail, Span expected_span) {
        const auto lowered = nginx::lower_to_rut(model);
        REQUIRE_FALSE(lowered);
        CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
        CHECK(lowered.error().detail.eq(detail));
        CHECK_EQ(lowered.error().span.start, expected_span.start);
        CHECK_EQ(lowered.error().span.end, expected_span.end);
        CHECK_EQ(lowered.error().span.line, expected_span.line);
        CHECK_EQ(lowered.error().span.col, expected_span.col);
    };

    for (const nginx::Server* model : {&root_first.value(), &exact_first.value()}) {
        REQUIRE(nginx::lower_to_rut(*model));

        auto forged = *model;
        forged.exact_no_content_return.present = false;
        expect_rejected(forged,
                        lit_str("invalid absent exact no-content return model"),
                        model->exact_no_content_return.response.span);

        for (const uintptr_t address : {uintptr_t{1}, UINTPTR_MAX}) {
            forged = *model;
            forged.exact_no_content_return.path.ptr = reinterpret_cast<const char*>(address);
            expect_rejected(forged,
                            lit_str("invalid exact no-content return path provenance"),
                            forged.exact_no_content_return.path_span);

            forged = *model;
            forged.location.path.ptr = reinterpret_cast<const char*>(address);
            expect_rejected(forged,
                            lit_str("invalid exact no-content return fallback provenance"),
                            forged.location.path_span);

            forged = *model;
            forged.exact_local_return.path.ptr = reinterpret_cast<const char*>(address);
            expect_rejected(
                forged, lit_str("multiple exact semantic actions are unsupported"), model->span);

            forged = *model;
            forged.exact_local_return.response.body.ptr = reinterpret_cast<const char*>(address);
            expect_rejected(
                forged, lit_str("multiple exact semantic actions are unsupported"), model->span);

            forged = *model;
            forged.exact_absolute_redirect.response.status_lexeme.ptr =
                reinterpret_cast<const char*>(address);
            expect_rejected(
                forged, lit_str("multiple exact semantic actions are unsupported"), model->span);

            forged = *model;
            forged.exact_absolute_redirect.response.target.ptr =
                reinterpret_cast<const char*>(address);
            expect_rejected(
                forged, lit_str("multiple exact semantic actions are unsupported"), model->span);
        }

        forged = *model;
        forged.exact_no_content_return.path.len = 0;
        expect_rejected(forged,
                        lit_str("invalid bounded exact no-content return path model"),
                        forged.exact_no_content_return.path_span);
        forged.exact_no_content_return.path.len = UINT32_MAX;
        expect_rejected(forged,
                        lit_str("invalid bounded exact no-content return path model"),
                        forged.exact_no_content_return.path_span);

        forged = *model;
        forged.exact_no_content_return.response.status = 205;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return status"),
                        forged.exact_no_content_return.response.status_span);

        forged = *model;
        forged.exact_no_content_return.span = {};
        expect_rejected(
            forged, lit_str("invalid exact no-content return location span"), model->span);

        forged = *model;
        forged.exact_no_content_return.path_span = {};
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path span"),
                        forged.exact_no_content_return.span);

        forged = *model;
        forged.exact_no_content_return.response.span = {};
        expect_rejected(forged,
                        lit_str("invalid exact no-content return directive span"),
                        forged.exact_no_content_return.span);

        forged = *model;
        forged.exact_no_content_return.response.status_span = {};
        expect_rejected(forged,
                        lit_str("invalid exact no-content return status span"),
                        forged.exact_no_content_return.response.span);

        forged = *model;
        forged.exact_no_content_return.path_span.end--;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path span"),
                        forged.exact_no_content_return.path_span);

        forged = *model;
        forged.exact_no_content_return.response.status_span.end++;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return status span"),
                        forged.exact_no_content_return.response.status_span);

        forged = *model;
        forged.span.start++;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return location span"),
                        forged.exact_no_content_return.span);

        forged = *model;
        forged.span.end = forged.exact_no_content_return.span.end - 1u;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return location span"),
                        forged.exact_no_content_return.span);

        forged = *model;
        forged.exact_no_content_return.span.end =
            forged.exact_no_content_return.response.span.end - 1u;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return directive span"),
                        forged.exact_no_content_return.response.span);

        forged = *model;
        forged.exact_no_content_return.response.span.start =
            forged.exact_no_content_return.path_span.end;
        forged.exact_no_content_return.response.span.col =
            forged.exact_no_content_return.path_span.col + forged.exact_no_content_return.path.len;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return directive span"),
                        forged.exact_no_content_return.response.span);

        forged = *model;
        forged.exact_no_content_return.response.status_span.end =
            forged.exact_no_content_return.response.span.end;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return status span"),
                        forged.exact_no_content_return.response.status_span);

        forged = *model;
        forged.location.path.len = 2u;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return fallback provenance"),
                        forged.location.path_span);

        forged = *model;
        forged.exact_no_content_return.response.status_span.start =
            forged.exact_no_content_return.response.span.start;
        forged.exact_no_content_return.response.status_span.end =
            forged.exact_no_content_return.response.span.start + 3u;
        forged.exact_no_content_return.response.status_span.line =
            forged.exact_no_content_return.response.span.line;
        forged.exact_no_content_return.response.status_span.col =
            forged.exact_no_content_return.response.span.col;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return status span"),
                        forged.exact_no_content_return.response.status_span);

        forged = *model;
        forged.exact_no_content_return.span.line++;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path span"),
                        forged.exact_no_content_return.path_span);

        forged = *model;
        forged.exact_no_content_return.path_span.col++;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path span"),
                        forged.exact_no_content_return.path_span);

        forged = *model;
        forged.exact_no_content_return.response.span.col++;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return directive span"),
                        forged.exact_no_content_return.response.span);

        forged = *model;
        forged.exact_no_content_return.response.status_span.col++;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return status span"),
                        forged.exact_no_content_return.response.status_span);

        char independent_source[sizeof(kRootFirst)]{};
        memcpy(independent_source, kRootFirst, sizeof(kRootFirst));
        forged = *model;
        forged.exact_no_content_return.path.ptr =
            independent_source + forged.exact_no_content_return.path_span.start;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path provenance"),
                        forged.exact_no_content_return.path_span);

        forged = *model;
        forged.location.path.ptr = independent_source + forged.location.path_span.start;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path provenance"),
                        forged.exact_no_content_return.path_span);

        forged = *model;
        forged.exact_local_return = local.value().exact_local_return;
        expect_rejected(forged,
                        lit_str("multiple exact semantic actions are unsupported"),
                        forged.exact_local_return.span);

        forged = *model;
        forged.exact_absolute_redirect = redirect.value().exact_absolute_redirect;
        expect_rejected(forged,
                        lit_str("multiple exact semantic actions are unsupported"),
                        forged.exact_absolute_redirect.span);

        forged = *model;
        forged.pre_route_trace.profile = static_cast<nginx::ImplicitPreRouteProfile>(0xff);
        expect_rejected(
            forged, lit_str("invalid pre-route TRACE profile model"), forged.pre_route_trace.span);

        forged = *model;
        forged.location.proxy_read_timeout.present = true;
        forged.location.proxy_read_timeout.milliseconds = 1;
        expect_rejected(forged, lit_str("invalid proxy_read_timeout spans"), model->location.span);
    }

    // A completely absent/default action has no inventory and leaves every
    // pre-existing canonical conversion behavior unchanged.
    const auto default_lowered = nginx::lower_to_rut(canonical_server());
    REQUIRE(default_lowered);

    auto present_only = canonical_server();
    present_only.exact_no_content_return.present = true;
    expect_rejected(present_only,
                    lit_str("invalid bounded exact no-content return path model"),
                    present_only.span);

    const auto expect_absent_dirty = [&](const nginx::Server& dirty, Span expected_span) {
        expect_rejected(
            dirty, lit_str("invalid absent exact no-content return model"), expected_span);
    };

    auto dirty = canonical_server();
    dirty.exact_no_content_return.path.ptr = reinterpret_cast<const char*>(uintptr_t{1});
    expect_absent_dirty(dirty, dirty.span);
    dirty = canonical_server();
    dirty.exact_no_content_return.path.len = 7;
    expect_absent_dirty(dirty, dirty.span);
    dirty = canonical_server();
    dirty.exact_no_content_return.path_span = Span{4, 11, 1, 5};
    expect_absent_dirty(dirty, dirty.exact_no_content_return.path_span);
    dirty = canonical_server();
    dirty.exact_no_content_return.span = Span{4, 20, 1, 5};
    expect_absent_dirty(dirty, dirty.exact_no_content_return.span);
    dirty = canonical_server();
    dirty.exact_no_content_return.response.status = 204;
    expect_absent_dirty(dirty, dirty.span);
    dirty = canonical_server();
    dirty.exact_no_content_return.response.status_span = Span{12, 15, 1, 13};
    expect_absent_dirty(dirty, dirty.exact_no_content_return.response.status_span);
    dirty = canonical_server();
    dirty.exact_no_content_return.response.span = Span{5, 16, 1, 6};
    expect_absent_dirty(dirty, dirty.exact_no_content_return.response.span);
}

TEST(nginx_converter, exact_no_content_return_rejects_mutated_source_literals_and_delimiters) {
    static constexpr char kCanonical[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204; } }";
    struct Mutation {
        const char* needle;
        u32 offset;
        char replacement;
        Str detail;
        u8 span_kind;
    };
    const Mutation mutations[] = {
        {"/static",
         1u,
         '%',
         lit_str("exact local return path is outside the bounded clean profile"),
         0u},
        {"location / {", 9u, 'x', lit_str("invalid exact no-content return fallback path"), 3u},
        {"204", 2u, '5', lit_str("invalid exact no-content return status literal"), 1u},
        {"return", 0u, 'x', lit_str("invalid exact no-content return directive delimiter"), 2u},
        {"return 204", 6u, 'x', lit_str("invalid exact no-content return directive delimiter"), 2u},
        {"204;", 3u, ':', lit_str("invalid exact no-content return directive delimiter"), 2u},
    };
    for (const auto& mutation : mutations) {
        char source[sizeof(kCanonical)]{};
        memcpy(source, kCanonical, sizeof(kCanonical));
        const auto parsed = nginx::parse({source, sizeof(source) - 1u});
        REQUIRE(parsed);
        char* byte = strstr(source, mutation.needle);
        REQUIRE(byte != nullptr);
        byte[mutation.offset] = mutation.replacement;
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK(lowered.error().detail.eq(mutation.detail));
        const auto& action = parsed.value().exact_no_content_return;
        const Span expected = mutation.span_kind == 0u   ? action.path_span
                              : mutation.span_kind == 1u ? action.response.status_span
                              : mutation.span_kind == 2u ? action.response.span
                                                         : parsed.value().location.path_span;
        CHECK_EQ(lowered.error().span.start, expected.start);
        CHECK_EQ(lowered.error().span.end, expected.end);
    }

    static constexpr char kSeparated[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204  # separated comment\n ; } }";
    for (const char replacement : {'#', 'x'}) {
        char source[sizeof(kSeparated)]{};
        memcpy(source, kSeparated, sizeof(kSeparated));
        const auto parsed = nginx::parse({source, sizeof(source) - 1u});
        REQUIRE(parsed);
        char* status = strstr(source, "204  #");
        REQUIRE(status != nullptr);
        status[3] = replacement;
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK(lowered.error().detail.eq(
            lit_str("invalid exact no-content return directive delimiter")));
        CHECK_EQ(lowered.error().span.start,
                 parsed.value().exact_no_content_return.response.span.start);
        CHECK_EQ(lowered.error().span.end,
                 parsed.value().exact_no_content_return.response.span.end);
    }

    // `/old` remains reserved for the distinct absolute-redirect semantic
    // action even if a forged caller mutates a genuinely parsed clean path.
    char reserved_source[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /xld { return 204; } }";
    const auto reserved_model = nginx::parse({reserved_source, sizeof(reserved_source) - 1u});
    REQUIRE(reserved_model);
    char* reserved_path = strstr(reserved_source, "/xld");
    REQUIRE(reserved_path != nullptr);
    reserved_path[1] = 'o';
    const auto reserved_lowered = nginx::lower_to_rut(reserved_model.value());
    REQUIRE_FALSE(reserved_lowered);
    CHECK_EQ(reserved_lowered.error().code, FrontendError::UnsupportedSyntax);
    CHECK(reserved_lowered.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    CHECK_EQ(reserved_lowered.error().span.start,
             reserved_model.value().exact_no_content_return.path_span.start);
    CHECK_EQ(reserved_lowered.error().span.end,
             reserved_model.value().exact_no_content_return.path_span.end);
}

TEST(nginx_converter, exact_no_content_return_rejects_forged_location_shell) {
    static constexpr char kCanonical[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204; } }";
    struct Mutation {
        u32 offset;
        char replacement;
        u8 span_kind;
    };
    // Offsets are relative to the exact location's complete semantic span:
    // `location = /static { return 204; }`.
    const Mutation mutations[] = {
        {1u, 'x', 0u},   // location keyword
        {8u, 'x', 0u},   // keyword lexer delimiter
        {8u, '#', 0u},   // unterminated pre-`=` comment
        {9u, 'x', 0u},   // exact `=` token
        {10u, '=', 0u},  // second `=` instead of the required gap
        {10u, '#', 0u},  // unterminated pre-path comment
        {18u, '#', 2u},  // Stage 2 excluded adjacent-path comment
        {19u, '#', 0u},  // reviewer reproducer: `return 204;` becomes comment text
        {20u, '#', 1u},  // unterminated comment in the pre-response gap
        {32u, '#', 0u},  // unterminated post-response comment
        {33u, 'x', 0u},  // exact closing `}`
    };
    for (const auto& mutation : mutations) {
        char source[sizeof(kCanonical)]{};
        memcpy(source, kCanonical, sizeof(kCanonical));
        const auto parsed = nginx::parse({source, sizeof(source) - 1u});
        REQUIRE(parsed);
        const auto& action = parsed.value().exact_no_content_return;
        REQUIRE_LT(mutation.offset, action.span.end - action.span.start);
        source[action.span.start + mutation.offset] = mutation.replacement;
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
        const Str expected_detail =
            mutation.span_kind == 1u ? lit_str("invalid exact no-content return pre-response gap")
            : mutation.span_kind == 2u
                ? lit_str("exact local return path is outside the bounded clean profile")
                : lit_str("invalid exact no-content return location shell");
        CHECK(lowered.error().detail.eq(expected_detail));
        const Span expected = mutation.span_kind == 1u   ? action.response.span
                              : mutation.span_kind == 2u ? action.path_span
                                                         : action.span;
        CHECK_EQ(lowered.error().span.start, expected.start);
        CHECK_EQ(lowered.error().span.end, expected.end);
        CHECK_EQ(lowered.error().span.line, expected.line);
        CHECK_EQ(lowered.error().span.col, expected.col);
    }

    const auto parsed = nginx::parse({kCanonical, sizeof(kCanonical) - 1u});
    REQUIRE(parsed);
    auto forged = parsed.value();
    forged.exact_no_content_return.span.start++;
    forged.exact_no_content_return.span.col++;
    auto lowered = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(lowered);
    CHECK(lowered.error().detail.eq(lit_str("invalid exact no-content return location shell")));
    CHECK_EQ(lowered.error().span.start, forged.exact_no_content_return.span.start);
    CHECK_EQ(lowered.error().span.end, forged.exact_no_content_return.span.end);

    forged = parsed.value();
    forged.exact_no_content_return.span.end--;
    lowered = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(lowered);
    CHECK(lowered.error().detail.eq(lit_str("invalid exact no-content return location shell")));
    CHECK_EQ(lowered.error().span.start, forged.exact_no_content_return.span.start);
    CHECK_EQ(lowered.error().span.end, forged.exact_no_content_return.span.end);

    char adjacent_source[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static \n { return 204; } }";
    const auto adjacent_model = nginx::parse({adjacent_source, sizeof(adjacent_source) - 1u});
    REQUIRE(adjacent_model);
    const Span adjacent_path = adjacent_model.value().exact_no_content_return.path_span;
    REQUIRE_EQ(adjacent_source[adjacent_path.end], ' ');
    adjacent_source[adjacent_path.end] = '#';
    const auto adjacent_lowered = nginx::lower_to_rut(adjacent_model.value());
    REQUIRE_FALSE(adjacent_lowered);
    CHECK_EQ(adjacent_lowered.error().code, FrontendError::UnsupportedSyntax);
    CHECK(adjacent_lowered.error().detail.eq(
        lit_str("exact local return path is outside the bounded clean profile")));
    CHECK_EQ(adjacent_lowered.error().span.start, adjacent_path.start);
    CHECK_EQ(adjacent_lowered.error().span.end, adjacent_path.end);
    CHECK_EQ(adjacent_lowered.error().span.line, adjacent_path.line);
    CHECK_EQ(adjacent_lowered.error().span.col, adjacent_path.col);
}

TEST(nginx_converter, lowers_parsed_bounded_exact_local_path_in_either_order) {
    const char* fragments[] = {
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz { return 200 \"successor-static\"; } }",
        "server { listen 8080; location = /healthz { return 200 \"successor-static\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }",
    };
    for (const char* source : fragments) {
        const auto parsed = nginx::parse({source, static_cast<u32>(strlen(source))});
        REQUIRE(parsed);
        REQUIRE(parsed.value().exact_local_return.present);
        const Span genuine_path_span = parsed.value().exact_local_return.path_span;
        CHECK_EQ(parsed.value().exact_local_return.path.ptr, source + genuine_path_span.start);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        static constexpr char kGolden[] =
            "route exact slash_normalized \"/healthz\" { return local_response({\n"
            "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: \"nginx/1.29.7\",\n"
            "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
            "  head_mode: \"suppress_body\", body: b\"successor-static\"\n"
            "}) }\n";
        REQUIRE_GE(lowered.value().len, static_cast<u32>(sizeof(kGolden) - 1u));
        const Str suffix{lowered.value().data + lowered.value().len - sizeof(kGolden) + 1u,
                         sizeof(kGolden) - 1u};
        CHECK(suffix.eq({kGolden, sizeof(kGolden) - 1u}));
    }

    const auto root_first = nginx::parse({fragments[0], static_cast<u32>(strlen(fragments[0]))});
    const auto exact_first = nginx::parse({fragments[1], static_cast<u32>(strlen(fragments[1]))});
    REQUIRE(root_first);
    REQUIRE(exact_first);
    const auto root_lowered = nginx::lower_to_rut(root_first.value());
    const auto exact_lowered = nginx::lower_to_rut(exact_first.value());
    REQUIRE(root_lowered);
    REQUIRE(exact_lowered);
    CHECK_EQ(root_lowered.value().len, 5571u);
    CHECK(root_lowered.value().view().eq(exact_lowered.value().view()));
}

TEST(nginx_converter, lowers_one_internal_exact_local_body_space_to_stable_rut) {
    static constexpr char kRootFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"hello world\"; } }";
    static constexpr char kExactFirst[] =
        "server { listen 8080; location = /static { return 200 \"hello world\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kLegacySafe[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"hello-world\"; } }";
    const auto root_parsed = nginx::parse({kRootFirst, sizeof(kRootFirst) - 1u});
    const auto exact_parsed = nginx::parse({kExactFirst, sizeof(kExactFirst) - 1u});
    const auto safe_parsed = nginx::parse({kLegacySafe, sizeof(kLegacySafe) - 1u});
    REQUIRE(root_parsed);
    REQUIRE(exact_parsed);
    REQUIRE(safe_parsed);
    const auto root_lowered = nginx::lower_to_rut(root_parsed.value());
    const auto exact_lowered = nginx::lower_to_rut(exact_parsed.value());
    const auto safe_lowered = nginx::lower_to_rut(safe_parsed.value());
    REQUIRE(root_lowered);
    REQUIRE(exact_lowered);
    REQUIRE(safe_lowered);
    CHECK(root_lowered.value().view().eq(exact_lowered.value().view()));
    REQUIRE_EQ(root_lowered.value().len, safe_lowered.value().len);

    static constexpr char kBodyLiteral[] = "body: b\"hello world\"";
    const char* literal = strstr(root_lowered.value().data, kBodyLiteral);
    REQUIRE(literal != nullptr);
    CHECK(strstr(literal + sizeof(kBodyLiteral) - 1u, kBodyLiteral) == nullptr);
    const char* safe_literal = strstr(safe_lowered.value().data, "body: b\"hello-world\"");
    REQUIRE(safe_literal != nullptr);
    const u32 literal_offset = static_cast<u32>(literal - root_lowered.value().data);
    REQUIRE_EQ(literal_offset, static_cast<u32>(safe_literal - safe_lowered.value().data));
    const u32 body_prefix_end = literal_offset + static_cast<u32>(sizeof("body: b\"") - 1u);
    CHECK((Str{root_lowered.value().data, body_prefix_end}.eq(
        {safe_lowered.value().data, body_prefix_end})));
    const u32 body_end = literal_offset + sizeof(kBodyLiteral) - 1u;
    const u32 safe_body_end = literal_offset + sizeof("body: b\"hello-world\"") - 1u;
    REQUIRE_EQ(body_end, safe_body_end);
    CHECK((Str{root_lowered.value().data + body_end, root_lowered.value().len - body_end}.eq(
        {safe_lowered.value().data + safe_body_end, safe_lowered.value().len - safe_body_end})));

    static constexpr char kGolden[] =
        "route exact slash_normalized \"/static\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"hello world\"\n"
        "}) }\n";
    REQUIRE_GE(root_lowered.value().len, static_cast<u32>(sizeof(kGolden) - 1u));
    CHECK((Str{root_lowered.value().data + root_lowered.value().len - sizeof(kGolden) + 1u,
               sizeof(kGolden) - 1u}
               .eq({kGolden, sizeof(kGolden) - 1u})));
}

TEST(nginx_converter, emits_clean_trailing_slash_and_multisegment_exact_local_paths) {
    const char* paths[] = {"/healthz/", "/health/check", "/old/"};
    const char* routes[] = {"route exact slash_normalized \"/healthz/\"",
                            "route exact slash_normalized \"/health/check\"",
                            "route exact slash_normalized \"/old/\""};
    for (u32 i = 0; i < 3; i++) {
        char source[256]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen 8080; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } location = %s { return 200 \"ok\"; } }",
                                 paths[i]);
        REQUIRE_GT(len, 0);
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK(strstr(lowered.value().data, routes[i]) != nullptr);
        CHECK(strstr(lowered.value().data, "body: b\"ok\"") != nullptr);
        CHECK(strstr(lowered.value().data, "route exact \"") == nullptr);
    }
}

TEST(nginx_converter, lowers_exact_local_return_in_either_declaration_order_to_stable_rut) {
    const char root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"successor-static\"; } }";
    const char exact_first[] =
        "server { listen 8080; location = /static { return 200 \"successor-static\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto root_parsed = nginx::parse({root_first, sizeof(root_first) - 1u});
    const auto exact_parsed = nginx::parse({exact_first, sizeof(exact_first) - 1u});
    REQUIRE(root_parsed);
    REQUIRE(exact_parsed);
    const auto root_lowered = nginx::lower_to_rut(root_parsed.value());
    const auto exact_lowered = nginx::lower_to_rut(exact_parsed.value());
    const auto legacy = nginx::lower_to_rut(canonical_server());
    REQUIRE(root_lowered);
    REQUIRE(exact_lowered);
    REQUIRE(legacy);
    CHECK(root_lowered.value().view().eq(exact_lowered.value().view()));
    const std::string generated(root_lowered.value().data, root_lowered.value().len);
    const auto count = [&](const char* literal) {
        u32 occurrences = 0;
        for (size_t offset = 0;;) {
            offset = generated.find(literal, offset);
            if (offset == std::string::npos) return occurrences;
            occurrences++;
            offset += strlen(literal);
        }
    };
    CHECK_EQ(count("route exact slash_normalized \"/static\" { return local_response({"), 1u);
    CHECK_EQ(count("route exact "), 1u);
    CHECK_EQ(count("/static"), 1u);
    CHECK_EQ(count("body: b\"successor-static\""), 1u);
    CHECK_EQ(count("return forward(nginx_upstream"), 3u);
    CHECK_EQ(count("route exact \"/static\""), 0u);
    CHECK_EQ(count("route exact slash_normalized GET \"/static\""), 0u);
    CHECK_EQ(count("/static?"), 0u);
    CHECK_EQ(count("exact-local.example"), 0u);
    CHECK_EQ(count("proxy_pass"), 0u);
    CHECK_EQ(count("nginx.conf"), 0u);
    CHECK_EQ(count("nginx::"), 0u);
    CHECK_EQ(count("nginx_compat"), 0u);
    CHECK_EQ(count("workaround"), 0u);

    static constexpr char kExactGolden[] =
        "route exact slash_normalized \"/static\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"successor-static\"\n"
        "}) }\n";
    static constexpr char kTraceGolden[] =
        "pre_route TRACE { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n";
    const u32 common_prefix_len =
        static_cast<u32>(strlen("listen :8080\nupstream nginx_upstream at \"127.0.0.1:9000\"\n"));
    REQUIRE_EQ(root_lowered.value().len,
               legacy.value().len + static_cast<u32>(sizeof(kExactGolden) - 1u));
    CHECK((Str{root_lowered.value().data, common_prefix_len}.eq(
        Str{legacy.value().data, common_prefix_len})));
    CHECK((Str{root_lowered.value().data + common_prefix_len, sizeof(kTraceGolden) - 1u}.eq(
        {kTraceGolden, sizeof(kTraceGolden) - 1u})));
    const u32 suffix_len =
        legacy.value().len - common_prefix_len - static_cast<u32>(sizeof(kTraceGolden) - 1u);
    CHECK(
        (Str{root_lowered.value().data + common_prefix_len + sizeof(kTraceGolden) - 1u, suffix_len}
             .eq({legacy.value().data + common_prefix_len + sizeof(kTraceGolden) - 1u,
                  suffix_len})));
    CHECK((Str{root_lowered.value().data + root_lowered.value().len -
                   static_cast<u32>(sizeof(kExactGolden) - 1u),
               sizeof(kExactGolden) - 1u}
               .eq({kExactGolden, sizeof(kExactGolden) - 1u})));
}

TEST(nginx_converter, exact_local_return_maximum_body_fits_bounded_source) {
    static constexpr char kBody[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static_assert(sizeof(kBody) - 1u == nginx::kMaxLocalReturnBodyLen);
    char source[512]{};
    const int len =
        snprintf(source,
                 sizeof(source),
                 "server { listen 65535; location / { proxy_pass "
                 "http://255.255.255.255:65535; } location = /static { return 200 \"%s\"; } }",
                 kBody);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto parsed = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5626u);
    CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
}

TEST(nginx_converter, exact_local_return_maximum_path_and_body_fit_bounded_source) {
    static constexpr char kBody[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    static_assert(sizeof(kBody) - 1u == nginx::kMaxLocalReturnBodyLen);
    char path[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    path[0] = '/';
    for (u32 i = 1; i < nginx::kMaxExactLocalReturnPathLen; i++) path[i] = 'p';
    char source[512]{};
    const int len =
        snprintf(source,
                 sizeof(source),
                 "server { listen 65535; location / { proxy_pass "
                 "http://255.255.255.255:65535; } location = %s { return 200 \"%s\"; } }",
                 path,
                 kBody);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto parsed = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5681u);
    CHECK_EQ(nginx::RutSource::kCapacity - lowered.value().len, 265u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();
}

TEST(nginx_converter, normalized_exact_local_return_maximum_path_and_body_fit_bounded_source) {
    static constexpr char kBody[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    static_assert(sizeof(kBody) - 1u == nginx::kMaxLocalReturnBodyLen);
    char path[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    path[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxExactLocalReturnPathLen; i++) path[i] = 'p';
    path[nginx::kMaxExactLocalReturnPathLen - 1u] = '/';
    char source[512]{};
    const int len =
        snprintf(source,
                 sizeof(source),
                 "server { listen 65535; location / { proxy_pass "
                 "http://255.255.255.255:65535; } location = %s { return 200 \"%s\"; } }",
                 path,
                 kBody);
    REQUIRE_GT(len, 0);
    REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
    const auto parsed = nginx::parse({source, static_cast<u32>(len)});
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().exact_local_return.path.len, nginx::kMaxExactLocalReturnPathLen);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5681u);
    CHECK_EQ(nginx::RutSource::kCapacity - lowered.value().len, 265u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    CHECK(strstr(lowered.value().data, "route exact slash_normalized \"") != nullptr);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();
}

TEST(nginx_converter, multiple_space_maximum_path_and_body_keep_exact_source_capacity) {
    char body[nginx::kMaxLocalReturnBodyLen + 1u]{};
    memset(body, 'a', nginx::kMaxLocalReturnBodyLen);
    for (u32 i = 1; i + 1u < nginx::kMaxLocalReturnBodyLen; i += 2u) body[i] = ' ';
    body[2] = ' ';
    body[32] = ' ';
    body[nginx::kMaxLocalReturnBodyLen] = '\0';

    struct Vector {
        bool trailing_slash;
        u32 expected_len;
    };
    const Vector vectors[] = {{false, 5681u}, {true, 5681u}};
    for (const auto& vector : vectors) {
        char path[nginx::kMaxExactLocalReturnPathLen + 1u]{};
        path[0] = '/';
        for (u32 i = 1; i < nginx::kMaxExactLocalReturnPathLen; i++) path[i] = 'p';
        if (vector.trailing_slash) path[nginx::kMaxExactLocalReturnPathLen - 1u] = '/';

        char source[512]{};
        const int len =
            snprintf(source,
                     sizeof(source),
                     "server { listen 65535; location / { proxy_pass "
                     "http://255.255.255.255:65535; } location = %s { return 200 \"%s\"; } }",
                     path,
                     body);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        REQUIRE_EQ(parsed.value().exact_local_return.response.body.len,
                   nginx::kMaxLocalReturnBodyLen);
        CHECK(parsed.value().exact_local_return.response.body.eq(
            {body, nginx::kMaxLocalReturnBodyLen}));
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, vector.expected_len);
        CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
        CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
        const char* emitted_body = strstr(lowered.value().data, body);
        REQUIRE(emitted_body != nullptr);
        CHECK((Str{emitted_body, nginx::kMaxLocalReturnBodyLen}.eq(
            {body, nginx::kMaxLocalReturnBodyLen})));
        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        delete ast.value();
    }
}

TEST(nginx_converter, rejects_forged_exact_local_return_model_inconsistencies) {
    static constexpr char kSource[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz { return 200 \"successor-static\"; } }";
    const auto parsed = nginx::parse({kSource, sizeof(kSource) - 1u});
    REQUIRE(parsed);
    const auto expect_rejected = [&](const nginx::Server& model, Str detail, Span expected_span) {
        const auto result = nginx::lower_to_rut(model);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(detail));
        CHECK_EQ(result.error().span.start, expected_span.start);
        CHECK_EQ(result.error().span.end, expected_span.end);
        CHECK_EQ(result.error().span.line, expected_span.line);
        CHECK_EQ(result.error().span.col, expected_span.col);
    };
    const auto expect_rejected_at_model_span = [&](const nginx::Server& model, Str detail) {
        expect_rejected(model, detail, model.span);
    };

    auto absent_status = canonical_server();
    absent_status.exact_local_return.response.status = 200;
    expect_rejected_at_model_span(absent_status,
                                  lit_str("invalid absent exact local return model"));
    auto absent_path = canonical_server();
    absent_path.exact_local_return.path = lit_str("/static");
    expect_rejected_at_model_span(absent_path, lit_str("invalid absent exact local return model"));
    auto missing_presence = parsed.value();
    missing_presence.exact_local_return.present = false;
    expect_rejected(missing_presence,
                    lit_str("invalid absent exact local return model"),
                    missing_presence.exact_local_return.span);
    auto present_only = canonical_server();
    present_only.exact_local_return.present = true;
    expect_rejected_at_model_span(present_only,
                                  lit_str("invalid bounded exact local return path model"));

    auto wrong_path = parsed.value();
    wrong_path.exact_local_return.path = lit_str("/other");
    expect_rejected(wrong_path,
                    lit_str("invalid exact local return path span"),
                    wrong_path.exact_local_return.path_span);
    auto short_path = parsed.value();
    short_path.exact_local_return.path.len--;
    expect_rejected(short_path,
                    lit_str("invalid exact local return path span"),
                    short_path.exact_local_return.path_span);
    auto null_path = parsed.value();
    null_path.exact_local_return.path.ptr = nullptr;
    expect_rejected(null_path,
                    lit_str("invalid exact local return path provenance"),
                    null_path.exact_local_return.path_span);
    auto wrong_status = parsed.value();
    wrong_status.exact_local_return.response.status = 201;
    expect_rejected(wrong_status,
                    lit_str("invalid exact local return status"),
                    wrong_status.exact_local_return.response.span);

    auto empty_body = parsed.value();
    empty_body.exact_local_return.response.body.len = 0;
    expect_rejected(empty_body,
                    lit_str("invalid exact local return body"),
                    empty_body.exact_local_return.response.body_span);
    auto null_body = parsed.value();
    null_body.exact_local_return.response.body.ptr = nullptr;
    expect_rejected(null_body,
                    lit_str("invalid exact local return body provenance"),
                    null_body.exact_local_return.response.body_span);
    static constexpr char kTooLong[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    auto long_body = parsed.value();
    long_body.exact_local_return.response.body = {kTooLong, sizeof(kTooLong) - 1u};
    expect_rejected(long_body,
                    lit_str("invalid exact local return body"),
                    long_body.exact_local_return.response.body_span);
    auto unsafe_body = parsed.value();
    unsafe_body.exact_local_return.response.body = lit_str("two words");
    expect_rejected(unsafe_body,
                    lit_str("invalid exact local return body span"),
                    unsafe_body.exact_local_return.response.body_span);

    auto bad_location_span = parsed.value();
    bad_location_span.exact_local_return.span = {};
    expect_rejected(bad_location_span,
                    lit_str("invalid exact local return location span"),
                    bad_location_span.span);
    auto outside_server_span = parsed.value();
    outside_server_span.exact_local_return.span.end = outside_server_span.span.end + 1u;
    expect_rejected(outside_server_span,
                    lit_str("invalid exact local return location span"),
                    outside_server_span.exact_local_return.span);
    auto bad_path_length = parsed.value();
    bad_path_length.exact_local_return.path_span.end++;
    expect_rejected(bad_path_length,
                    lit_str("invalid exact local return path span"),
                    bad_path_length.exact_local_return.path_span);
    auto bad_response_span = parsed.value();
    bad_response_span.exact_local_return.response.span = {};
    expect_rejected(bad_response_span,
                    lit_str("invalid exact local return response span"),
                    bad_response_span.exact_local_return.span);
    auto bad_body_span = parsed.value();
    bad_body_span.exact_local_return.response.body_span.end++;
    expect_rejected(bad_body_span,
                    lit_str("invalid exact local return body span"),
                    bad_body_span.exact_local_return.response.body_span);

    auto api_fallback = parsed.value();
    api_fallback.location = api_server().location;
    api_fallback.pre_route_trace = {};
    expect_rejected(api_fallback,
                    lit_str("invalid exact local return fallback provenance"),
                    api_fallback.location.path_span);

    auto missing_trace = parsed.value();
    missing_trace.pre_route_trace = {};
    expect_rejected(
        missing_trace, lit_str("missing pre-route TRACE model"), missing_trace.location.span);
    auto missing_root_trace = canonical_server();
    missing_root_trace.pre_route_trace = {};
    expect_rejected(missing_root_trace,
                    lit_str("missing pre-route TRACE model"),
                    missing_root_trace.location.span);
    auto unknown_trace_profile = parsed.value();
    unknown_trace_profile.pre_route_trace.profile =
        static_cast<nginx::ImplicitPreRouteProfile>(0xff);
    expect_rejected(unknown_trace_profile,
                    lit_str("invalid pre-route TRACE profile model"),
                    unknown_trace_profile.pre_route_trace.span);
    auto bad_trace_start = parsed.value();
    bad_trace_start.pre_route_trace.span.start++;
    expect_rejected(bad_trace_start,
                    lit_str("invalid pre-route TRACE spans"),
                    bad_trace_start.pre_route_trace.span);
    auto bad_trace_end = parsed.value();
    bad_trace_end.pre_route_trace.span.end++;
    expect_rejected(bad_trace_end,
                    lit_str("invalid pre-route TRACE spans"),
                    bad_trace_end.pre_route_trace.span);
    auto bad_trace_line = parsed.value();
    bad_trace_line.pre_route_trace.span.line++;
    expect_rejected(bad_trace_line,
                    lit_str("invalid pre-route TRACE spans"),
                    bad_trace_line.pre_route_trace.span);
    auto bad_trace_col = parsed.value();
    bad_trace_col.pre_route_trace.span.col++;
    expect_rejected(bad_trace_col,
                    lit_str("invalid pre-route TRACE spans"),
                    bad_trace_col.pre_route_trace.span);
    auto absent_trace_inventory = canonical_server();
    absent_trace_inventory.pre_route_trace.profile = nginx::ImplicitPreRouteProfile::None;
    absent_trace_inventory.pre_route_trace.span = canonical_server().span;
    expect_rejected(absent_trace_inventory,
                    lit_str("invalid absent pre-route TRACE model"),
                    absent_trace_inventory.pre_route_trace.span);
    auto api_unknown_trace = api_server();
    api_unknown_trace.pre_route_trace.profile = static_cast<nginx::ImplicitPreRouteProfile>(0xff);
    expect_rejected(api_unknown_trace,
                    lit_str("invalid pre-route TRACE profile model"),
                    api_unknown_trace.pre_route_trace.span);
    auto api_bad_trace_start = api_server();
    api_bad_trace_start.pre_route_trace.span.start++;
    expect_rejected(api_bad_trace_start,
                    lit_str("invalid pre-route TRACE spans"),
                    api_bad_trace_start.pre_route_trace.span);
    auto api_bad_trace_end = api_server();
    api_bad_trace_end.pre_route_trace.span.end++;
    expect_rejected(api_bad_trace_end,
                    lit_str("invalid pre-route TRACE spans"),
                    api_bad_trace_end.pre_route_trace.span);
    auto api_bad_trace_line = api_server();
    api_bad_trace_line.pre_route_trace.span.line++;
    expect_rejected(api_bad_trace_line,
                    lit_str("invalid pre-route TRACE spans"),
                    api_bad_trace_line.pre_route_trace.span);
    auto api_bad_trace_col = api_server();
    api_bad_trace_col.pre_route_trace.span.col++;
    expect_rejected(api_bad_trace_col,
                    lit_str("invalid pre-route TRACE spans"),
                    api_bad_trace_col.pre_route_trace.span);
    auto api_absent_trace_inventory = api_server();
    api_absent_trace_inventory.pre_route_trace.profile = nginx::ImplicitPreRouteProfile::None;
    api_absent_trace_inventory.pre_route_trace.span = api_server().span;
    expect_rejected(api_absent_trace_inventory,
                    lit_str("invalid absent pre-route TRACE model"),
                    api_absent_trace_inventory.pre_route_trace.span);
}

TEST(nginx_converter, validates_exact_local_return_before_dynamic_reads_and_later_models) {
    char source[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz { return 200 \"hello  world again\"; } }";
    const auto parsed = nginx::parse({source, sizeof(source) - 1u});
    REQUIRE(parsed);
    const auto expect_rejected = [&](const nginx::Server& model, Str detail, Span span) {
        char source_before[sizeof(source)]{};
        memcpy(source_before, source, sizeof(source));
        const auto result = nginx::lower_to_rut(model);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(detail));
        CHECK_EQ(result.error().span.start, span.start);
        CHECK_EQ(result.error().span.end, span.end);
        CHECK_EQ(result.error().span.line, span.line);
        CHECK_EQ(result.error().span.col, span.col);
        CHECK_EQ(memcmp(source, source_before, sizeof(source)), 0);
    };

    const Span path_span = parsed.value().exact_local_return.path_span;
    const Span body_span = parsed.value().exact_local_return.response.body_span;
    const Span location_span = parsed.value().exact_local_return.span;
    const Span response_span = parsed.value().exact_local_return.response.span;
    const Span fallback_path_span = parsed.value().location.path_span;

    auto forged = parsed.value();
    forged.location.path.ptr = nullptr;
    expect_rejected(
        forged, lit_str("invalid exact local return fallback provenance"), fallback_path_span);
    for (const uintptr_t address : {uintptr_t{1}, UINTPTR_MAX}) {
        forged = parsed.value();
        forged.location.path.ptr = reinterpret_cast<const char*>(address);
        expect_rejected(
            forged, lit_str("invalid exact local return fallback provenance"), fallback_path_span);
    }

    static constexpr char kExternalFallback[] = "/";
    forged = parsed.value();
    forged.location.path = {kExternalFallback, sizeof(kExternalFallback) - 1u};
    expect_rejected(
        forged, lit_str("invalid exact local return fallback provenance"), fallback_path_span);
    char reconstructed_source[sizeof(source)]{};
    memcpy(reconstructed_source, source, sizeof(source));
    forged = parsed.value();
    forged.location.path.ptr = reconstructed_source + fallback_path_span.start;
    expect_rejected(
        forged, lit_str("invalid exact local return fallback provenance"), fallback_path_span);

    for (const uintptr_t address : {uintptr_t{1}, UINTPTR_MAX}) {
        forged = parsed.value();
        forged.exact_local_return.path.ptr = reinterpret_cast<const char*>(address);
        expect_rejected(forged, lit_str("invalid exact local return path provenance"), path_span);
        forged = parsed.value();
        forged.exact_local_return.response.body.ptr = reinterpret_cast<const char*>(address);
        expect_rejected(forged, lit_str("invalid exact local return body provenance"), body_span);
    }

    static constexpr char kExternalPath[] = "/healthz";
    static constexpr char kExternalBody[] = "hello  world again";
    forged = parsed.value();
    forged.exact_local_return.path = {kExternalPath, sizeof(kExternalPath) - 1u};
    expect_rejected(forged, lit_str("invalid exact local return path provenance"), path_span);
    forged = parsed.value();
    forged.exact_local_return.response.body = {kExternalBody, sizeof(kExternalBody) - 1u};
    expect_rejected(forged, lit_str("invalid exact local return body provenance"), body_span);
    char reconstructed_path[sizeof(kExternalPath)]{};
    char reconstructed_body[sizeof(kExternalBody)]{};
    memcpy(reconstructed_path, kExternalPath, sizeof(kExternalPath));
    memcpy(reconstructed_body, kExternalBody, sizeof(kExternalBody));
    forged = parsed.value();
    forged.exact_local_return.path = {reconstructed_path, sizeof(kExternalPath) - 1u};
    expect_rejected(forged, lit_str("invalid exact local return path provenance"), path_span);
    forged = parsed.value();
    forged.exact_local_return.response.body = {reconstructed_body, sizeof(kExternalBody) - 1u};
    expect_rejected(forged, lit_str("invalid exact local return body provenance"), body_span);

    forged = parsed.value();
    forged.exact_local_return.span = {};
    expect_rejected(forged, lit_str("invalid exact local return location span"), forged.span);
    forged = parsed.value();
    forged.exact_local_return.path_span = {};
    expect_rejected(forged, lit_str("invalid exact local return path span"), location_span);
    forged = parsed.value();
    forged.exact_local_return.response.span = {};
    expect_rejected(forged, lit_str("invalid exact local return response span"), location_span);
    forged = parsed.value();
    forged.exact_local_return.response.body_span = {};
    expect_rejected(forged, lit_str("invalid exact local return body span"), response_span);

    forged = parsed.value();
    forged.exact_local_return.path_span.start = forged.exact_local_return.span.start - 1u;
    expect_rejected(forged,
                    lit_str("invalid exact local return path span"),
                    forged.exact_local_return.path_span);
    forged = parsed.value();
    forged.exact_local_return.response.span.start = forged.exact_local_return.path_span.end;
    expect_rejected(forged,
                    lit_str("invalid exact local return response span"),
                    forged.exact_local_return.response.span);
    forged = parsed.value();
    forged.exact_local_return.response.body_span.start =
        forged.exact_local_return.response.span.start;
    expect_rejected(forged,
                    lit_str("invalid exact local return body span"),
                    forged.exact_local_return.response.body_span);
    forged = parsed.value();
    forged.exact_local_return.path_span.end++;
    expect_rejected(forged,
                    lit_str("invalid exact local return path span"),
                    forged.exact_local_return.path_span);
    forged = parsed.value();
    forged.exact_local_return.response.body_span.end++;
    expect_rejected(forged,
                    lit_str("invalid exact local return body span"),
                    forged.exact_local_return.response.body_span);

    forged = parsed.value();
    forged.exact_local_return.span.line++;
    forged.exact_local_return.path_span.line++;
    forged.exact_local_return.response.span.line++;
    forged.exact_local_return.response.body_span.line++;
    expect_rejected(forged,
                    lit_str("invalid exact local return source positions"),
                    forged.exact_local_return.span);
    forged = parsed.value();
    forged.exact_local_return.path_span.line++;
    expect_rejected(forged,
                    lit_str("invalid exact local return path source position"),
                    forged.exact_local_return.path_span);
    forged = parsed.value();
    forged.exact_local_return.response.span.line++;
    forged.exact_local_return.response.body_span.line++;
    expect_rejected(forged,
                    lit_str("invalid exact local return response source position"),
                    forged.exact_local_return.response.span);
    forged = parsed.value();
    forged.exact_local_return.response.body_span.line++;
    expect_rejected(forged,
                    lit_str("invalid exact local return body source position"),
                    forged.exact_local_return.response.body_span);
    forged = parsed.value();
    forged.exact_local_return.path_span.col++;
    expect_rejected(forged,
                    lit_str("invalid exact local return path span"),
                    forged.exact_local_return.path_span);
    forged = parsed.value();
    forged.exact_local_return.response.body_span.col++;
    expect_rejected(forged,
                    lit_str("invalid exact local return body span"),
                    forged.exact_local_return.response.body_span);

    char* opening_quote = source + body_span.start - 1u;
    const char saved_opening_quote = *opening_quote;
    REQUIRE_EQ(saved_opening_quote, '"');
    *opening_quote = 'x';
    expect_rejected(
        parsed.value(), lit_str("invalid exact local return body delimiters"), body_span);
    *opening_quote = saved_opening_quote;

    char* closing_quote = source + body_span.end;
    const char saved_closing_quote = *closing_quote;
    REQUIRE_EQ(saved_closing_quote, '"');
    *closing_quote = 'x';
    expect_rejected(
        parsed.value(), lit_str("invalid exact local return body delimiters"), body_span);
    *closing_quote = saved_closing_quote;

    char* path = source + path_span.start;
    const char saved_path_byte = path[0];
    path[0] = 'x';
    expect_rejected(
        parsed.value(), lit_str("invalid bounded exact local return path model"), path_span);
    path[0] = saved_path_byte;

    static constexpr char kControlPath[] = {'/', 'a', '\x01', 'b', '\0'};
    static constexpr char kNonAsciiPath[] = {'/', 'a', static_cast<char>(0x80), 'b', '\0'};
    struct ForgedPathCase {
        const char* clean;
        const char* invalid;
        u32 len;
    };
    const ForgedPathCase forged_path_cases[] = {
        {"/xab", "//ab", 4},
        {"/a/ab", "/a//b", 5},
        {"/a/x/b", "/a/./b", 6},
        {"/a/xx/b", "/a/../b", 7},
        {"/a-b", "/a%b", 4},
        {"/a-b", "/a?b", 4},
        {"/a-b", "/a b", 4},
        {"/a-b", kControlPath, sizeof(kControlPath) - 1u},
        {"/a-b", kNonAsciiPath, sizeof(kNonAsciiPath) - 1u},
        {"/a/b", "/a//", 4},
    };
    for (const auto& path_case : forged_path_cases) {
        char forged_source[512]{};
        const int forged_source_len =
            snprintf(forged_source,
                     sizeof(forged_source),
                     "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                     "location = %s { return 200 \"successor-static\"; } }",
                     path_case.clean);
        REQUIRE_GT(forged_source_len, 0);
        const auto clean_parsed =
            nginx::parse({forged_source, static_cast<u32>(forged_source_len)});
        REQUIRE(clean_parsed);
        REQUIRE_EQ(clean_parsed.value().exact_local_return.path.len, path_case.len);
        const Span forged_path_span = clean_parsed.value().exact_local_return.path_span;
        memcpy(forged_source + forged_path_span.start, path_case.invalid, path_case.len);
        expect_rejected(clean_parsed.value(),
                        lit_str("invalid bounded exact local return path model"),
                        forged_path_span);
    }

    char* body = source + body_span.start;
    const char saved_body_byte = body[0];
    body[0] = '$';
    expect_rejected(parsed.value(), lit_str("invalid exact local return body"), body_span);
    body[0] = saved_body_byte;

    body[0] = ' ';
    expect_rejected(parsed.value(), lit_str("invalid exact local return body"), body_span);
    body[0] = saved_body_byte;

    const char saved_last_body_byte = body[body_span.end - body_span.start - 1u];
    body[body_span.end - body_span.start - 1u] = ' ';
    expect_rejected(parsed.value(), lit_str("invalid exact local return body"), body_span);
    body[body_span.end - body_span.start - 1u] = saved_last_body_byte;

    const char saved_second_space_byte = body[1];
    body[1] = ' ';
    const auto adjacent_spaces = nginx::lower_to_rut(parsed.value());
    REQUIRE(adjacent_spaces);
    CHECK(strstr(adjacent_spaces.value().data, "body: b\"h llo  world again\"") != nullptr);
    body[1] = saved_second_space_byte;

    char separated_source[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz { return 200 \"hello world again\"; } }";
    const auto separated = nginx::parse({separated_source, sizeof(separated_source) - 1u});
    REQUIRE(separated);
    const auto separated_lowered = nginx::lower_to_rut(separated.value());
    REQUIRE(separated_lowered);
    CHECK(strstr(separated_lowered.value().data, "body: b\"hello world again\"") != nullptr);

    static constexpr char kControl = '\x01';
    static constexpr char kNonAscii = static_cast<char>(0x80);
    const char unsafe_body_bytes[] = {
        '\t', kControl, kNonAscii, '\\', '$', '#', '{', '}', ';', '"'};
    const char saved_unsafe_byte = body[1];
    for (const char unsafe : unsafe_body_bytes) {
        body[1] = unsafe;
        expect_rejected(parsed.value(), lit_str("invalid exact local return body"), body_span);
    }
    body[1] = saved_unsafe_byte;

    char old_source[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /oldx { return 200 \"successor-static\"; } }";
    const auto old_parsed = nginx::parse({old_source, sizeof(old_source) - 1u});
    REQUIRE(old_parsed);
    auto old_model = old_parsed.value();
    old_model.exact_local_return.path.len--;
    old_model.exact_local_return.path_span.end--;
    expect_rejected(old_model,
                    lit_str("invalid bounded exact local return path model"),
                    old_model.exact_local_return.path_span);

    char maximum_path[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    maximum_path[0] = '/';
    for (u32 i = 1; i < nginx::kMaxExactLocalReturnPathLen; i++) maximum_path[i] = 'a';
    char maximum_source[512]{};
    const int maximum_source_len =
        snprintf(maximum_source,
                 sizeof(maximum_source),
                 "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
                 "location = %s { return 200 \"successor-static\"; } }",
                 maximum_path);
    REQUIRE_GT(maximum_source_len, 0);
    const auto maximum_parsed =
        nginx::parse({maximum_source, static_cast<u32>(maximum_source_len)});
    REQUIRE(maximum_parsed);
    auto oversized = maximum_parsed.value();
    oversized.exact_local_return.path.len++;
    oversized.exact_local_return.path_span.end++;
    expect_rejected(oversized,
                    lit_str("invalid bounded exact local return path model"),
                    oversized.exact_local_return.path_span);

    forged = parsed.value();
    forged.exact_local_return.path.ptr = reinterpret_cast<const char*>(uintptr_t{1});
    forged.location.proxy_read_timeout.present = true;
    forged.location.proxy_read_timeout.milliseconds = 1;
    forged.listen.port = 0;
    forged.location.proxy_pass.port = 0;
    expect_rejected(forged, lit_str("invalid exact local return path provenance"), path_span);
    forged = parsed.value();
    forged.exact_local_return.response.status = 201;
    forged.location.proxy_read_timeout.present = true;
    forged.listen.port = 0;
    forged.location.proxy_pass.port = 0;
    expect_rejected(forged, lit_str("invalid exact local return status"), response_span);
}

TEST(nginx_converter, lowers_exact_absolute_redirect_in_either_order_to_stable_rut) {
    static constexpr char kRootFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/old { return 301 http://redirect.example/new; } }";
    static constexpr char kExactFirst[] =
        "server { listen 8080; location = /old { return 301 http://redirect.example/new; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto root_parsed = nginx::parse({kRootFirst, sizeof(kRootFirst) - 1u});
    const auto exact_parsed = nginx::parse({kExactFirst, sizeof(kExactFirst) - 1u});
    REQUIRE(root_parsed);
    REQUIRE(exact_parsed);
    const auto root_lowered = nginx::lower_to_rut(root_parsed.value());
    const auto exact_lowered = nginx::lower_to_rut(exact_parsed.value());
    const auto legacy = nginx::lower_to_rut(canonical_server());
    REQUIRE(root_lowered);
    REQUIRE(exact_lowered);
    REQUIRE(legacy);
    CHECK(root_lowered.value().view().eq(exact_lowered.value().view()));

    static constexpr char kRedirectPrefix[] =
        "route GET \"/\" {\n"
        "    if req.pathOnly == \"/old\" {\n"
        "        return redirect({scheme: \"http\", authority: \"static\", static_authority: "
        "\"redirect.example\", port: \"omit\",\n"
        "            path: \"static\", query: \"discard\", date: \"current\", connection: "
        "\"close\",\n"
        "            header_order: \"connection_then_location\", status: 301, reason: \"Moved "
        "Permanently\",\n"
        "            server: \"nginx/1.29.7\", content_type: \"text/html\", target_path: "
        "\"/new\", body: b\"<html>\\r\\n"
        "<head><title>301 Moved Permanently</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>301 Moved Permanently</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n\"})\n"
        "    } else {\n"
        "        return ";
    static constexpr char kConditionalClose[] = "    }\n}\n";
    const char* redirect_route = strstr(root_lowered.value().data, "route GET \"/\" {");
    REQUIRE(redirect_route != nullptr);
    CHECK((Str{redirect_route, sizeof(kRedirectPrefix) - 1u}.eq(
        {kRedirectPrefix, sizeof(kRedirectPrefix) - 1u})));
    CHECK_EQ(strstr(root_lowered.value().data, "authority: \"request_host\""), nullptr);
    CHECK_EQ(strstr(root_lowered.value().data, "port: \"actual_listener\""), nullptr);
    CHECK_EQ(strstr(root_lowered.value().data, "query: \"preserve_raw\""), nullptr);

    const char* generated_forward = strstr(redirect_route, "forward(nginx_upstream");
    const char* generated_any = strstr(redirect_route, "route \"/\" {");
    const char* legacy_get = strstr(legacy.value().data, "route GET \"/\" {");
    REQUIRE(generated_forward != nullptr);
    REQUIRE(generated_any != nullptr);
    REQUIRE(legacy_get != nullptr);
    const char* legacy_forward = strstr(legacy_get, "forward(nginx_upstream");
    const char* legacy_any = strstr(legacy_get, "route \"/\" {");
    REQUIRE(legacy_forward != nullptr);
    REQUIRE(legacy_any != nullptr);
    const u32 canonical_forward_len = static_cast<u32>(legacy_any - legacy_forward - 2);
    CHECK((
        Str{generated_forward, canonical_forward_len}.eq({legacy_forward, canonical_forward_len})));
    const char* generated_close = generated_forward + canonical_forward_len;
    REQUIRE_EQ(static_cast<u32>(generated_any - generated_close),
               static_cast<u32>(sizeof(kConditionalClose) - 1u));
    CHECK((Str{generated_close, sizeof(kConditionalClose) - 1u}.eq(
        {kConditionalClose, sizeof(kConditionalClose) - 1u})));
    const u32 generated_suffix_len =
        static_cast<u32>(root_lowered.value().data + root_lowered.value().len - generated_any);
    const u32 legacy_suffix_len =
        static_cast<u32>(legacy.value().data + legacy.value().len - legacy_any);
    REQUIRE_EQ(generated_suffix_len, legacy_suffix_len);
    CHECK((Str{generated_any, generated_suffix_len}.eq({legacy_any, legacy_suffix_len})));

    const u32 generated_prefix_len = static_cast<u32>(redirect_route - root_lowered.value().data);
    const u32 legacy_prefix_len = static_cast<u32>(legacy_get - legacy.value().data);
    REQUIRE_EQ(generated_prefix_len, legacy_prefix_len);
    CHECK((Str{root_lowered.value().data, generated_prefix_len}.eq(
        {legacy.value().data, legacy_prefix_len})));
    CHECK_EQ(root_lowered.value().len, 5928u);
}

TEST(nginx_converter, lowers_exact_302_absolute_redirect_to_exact_stable_rut) {
    static constexpr char kRootFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/old { return 302 http://redirect.example/new; } }";
    static constexpr char kExactFirst[] =
        "server { listen 8080; location = /old { return 302 http://redirect.example/new; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto root_parsed = nginx::parse({kRootFirst, sizeof(kRootFirst) - 1u});
    const auto exact_parsed = nginx::parse({kExactFirst, sizeof(kExactFirst) - 1u});
    REQUIRE(root_parsed);
    REQUIRE(exact_parsed);
    const auto root_lowered = nginx::lower_to_rut(root_parsed.value());
    const auto exact_lowered = nginx::lower_to_rut(exact_parsed.value());
    const auto legacy = nginx::lower_to_rut(canonical_server());
    REQUIRE(root_lowered);
    REQUIRE(exact_lowered);
    REQUIRE(legacy);
    CHECK(root_lowered.value().view().eq(exact_lowered.value().view()));

    static constexpr char kRedirectGolden[] =
        "route GET \"/\" {\n"
        "    if req.pathOnly == \"/old\" {\n"
        "        return redirect({scheme: \"http\", authority: \"static\", static_authority: "
        "\"redirect.example\", port: \"omit\",\n"
        "            path: \"static\", query: \"discard\", date: \"current\", connection: "
        "\"close\",\n"
        "            header_order: \"connection_then_location\", status: 302, reason: \"Moved "
        "Temporarily\",\n"
        "            server: \"nginx/1.29.7\", content_type: \"text/html\", target_path: "
        "\"/new\", body: b\"<html>\\r\\n"
        "<head><title>302 Found</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>302 Found</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n\"})\n"
        "    } else {\n"
        "        return ";
    static constexpr char kConditionalClose[] = "    }\n}\n";

    const char* generated_route = strstr(root_lowered.value().data, "route GET \"/\" {");
    const char* generated_forward =
        generated_route == nullptr ? nullptr : strstr(generated_route, "forward(nginx_upstream");
    const char* generated_any =
        generated_forward == nullptr ? nullptr : strstr(generated_forward, "route \"/\" {");
    const char* legacy_get = strstr(legacy.value().data, "route GET \"/\" {");
    const char* legacy_forward =
        legacy_get == nullptr ? nullptr : strstr(legacy_get, "forward(nginx_upstream");
    const char* legacy_any =
        legacy_forward == nullptr ? nullptr : strstr(legacy_forward, "route \"/\" {");
    REQUIRE(generated_route != nullptr);
    REQUIRE(generated_forward != nullptr);
    REQUIRE(generated_any != nullptr);
    REQUIRE(legacy_get != nullptr);
    REQUIRE(legacy_forward != nullptr);
    REQUIRE(legacy_any != nullptr);

    // These adjacent exact partitions cover every generated byte. The
    // fallback action is compared to the canonical GET action whose complete
    // hard-coded golden is checked separately; only the conditional close is
    // new syntax around it.
    const u32 prefix_len = static_cast<u32>(generated_route - root_lowered.value().data);
    const u32 legacy_prefix_len = static_cast<u32>(legacy_get - legacy.value().data);
    REQUIRE_EQ(prefix_len, legacy_prefix_len);
    CHECK((Str{root_lowered.value().data, prefix_len}.eq({legacy.value().data, prefix_len})));
    REQUIRE_EQ(static_cast<u32>(generated_forward - generated_route),
               static_cast<u32>(sizeof(kRedirectGolden) - 1u));
    CHECK((Str{generated_route, sizeof(kRedirectGolden) - 1u}.eq(
        {kRedirectGolden, sizeof(kRedirectGolden) - 1u})));
    const u32 canonical_forward_len = static_cast<u32>(legacy_any - legacy_forward - 2);
    CHECK((
        Str{generated_forward, canonical_forward_len}.eq({legacy_forward, canonical_forward_len})));
    const char* generated_close = generated_forward + canonical_forward_len;
    REQUIRE_EQ(static_cast<u32>(generated_any - generated_close),
               static_cast<u32>(sizeof(kConditionalClose) - 1u));
    CHECK((Str{generated_close, sizeof(kConditionalClose) - 1u}.eq(
        {kConditionalClose, sizeof(kConditionalClose) - 1u})));
    const u32 generated_suffix_len =
        static_cast<u32>(root_lowered.value().data + root_lowered.value().len - generated_any);
    const u32 legacy_suffix_len =
        static_cast<u32>(legacy.value().data + legacy.value().len - legacy_any);
    REQUIRE_EQ(generated_suffix_len, legacy_suffix_len);
    CHECK((Str{generated_any, generated_suffix_len}.eq({legacy_any, legacy_suffix_len})));
    CHECK_EQ(root_lowered.value().len, 5904u);
}

TEST(nginx_converter, lowers_parsed_302_and_rejects_forged_status_provenance) {
    static constexpr char kRootFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/old { return 302 http://redirect.example/new; } }";
    static constexpr char kExactFirst[] =
        "server { listen 8080; location = /old { return 302 "
        "http://redirect.example/new; } location / { proxy_pass http://127.0.0.1:9000; } }";

    const auto expect_not_lowered = [&](const nginx::Server& model, Str detail, Span span) {
        const auto result = nginx::lower_to_rut(model);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(detail));
        CHECK_EQ(result.error().span.start, span.start);
        CHECK_EQ(result.error().span.end, span.end);
    };
    for (const Str source :
         {Str{kRootFirst, sizeof(kRootFirst) - 1u}, Str{kExactFirst, sizeof(kExactFirst) - 1u}}) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        const auto& response = parsed.value().exact_absolute_redirect.response;
        REQUIRE_EQ(response.status, 302u);
        REQUIRE(response.status_lexeme.eq(lit_str("302")));
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, 5904u);
    }

    const auto parsed = nginx::parse({kRootFirst, sizeof(kRootFirst) - 1u});
    REQUIRE(parsed);
    const auto& accepted = parsed.value();
    const Span status_span = accepted.exact_absolute_redirect.response.status_span;
    auto forged = accepted;

    // A numeric/borrowed-lexeme mismatch must not be reinterpreted as either
    // supported redirect status.
    forged.exact_absolute_redirect.response.status = 301;
    expect_not_lowered(
        forged, lit_str("invalid exact absolute redirect status lexeme"), status_span);

    forged = accepted;
    forged.exact_absolute_redirect.response.status = 303;
    expect_not_lowered(forged, lit_str("invalid exact absolute redirect status"), status_span);

    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme = lit_str("302");
    expect_not_lowered(
        forged, lit_str("invalid exact absolute redirect status provenance"), status_span);

    char reconstructed_status[] = "302";
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme = {reconstructed_status,
                                                             sizeof(reconstructed_status) - 1u};
    expect_not_lowered(
        forged, lit_str("invalid exact absolute redirect status provenance"), status_span);

    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme.ptr++;
    expect_not_lowered(
        forged, lit_str("invalid exact absolute redirect status provenance"), status_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme.len--;
    expect_not_lowered(
        forged, lit_str("invalid exact absolute redirect status provenance"), status_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme = {nullptr, 3};
    expect_not_lowered(
        forged, lit_str("invalid exact absolute redirect status provenance"), status_span);

    forged = accepted;
    forged.exact_absolute_redirect.response.status_span.start--;
    forged.exact_absolute_redirect.response.status_span.end--;
    forged.exact_absolute_redirect.response.status_span.col--;
    expect_not_lowered(forged,
                       lit_str("invalid exact absolute redirect status provenance"),
                       forged.exact_absolute_redirect.response.status_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.status_span = {};
    expect_not_lowered(forged,
                       lit_str("invalid exact absolute redirect status span"),
                       accepted.exact_absolute_redirect.response.span);
}

TEST(nginx_converter, rejects_forged_exact_absolute_redirect_inventory) {
    static constexpr char kRedirectSource[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/old { return 301 http://redirect.example/new; } }";
    static constexpr char kLocalSource[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/static { return 200 \"successor-static\"; } }";
    const auto redirect = nginx::parse({kRedirectSource, sizeof(kRedirectSource) - 1u});
    const auto local = nginx::parse({kLocalSource, sizeof(kLocalSource) - 1u});
    REQUIRE(redirect);
    REQUIRE(local);
    const auto expect_rejected = [&](const nginx::Server& model, Str detail, Span span = {}) {
        const auto result = nginx::lower_to_rut(model);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(detail));
        if (span.start < span.end) {
            CHECK_EQ(result.error().span.start, span.start);
            CHECK_EQ(result.error().span.end, span.end);
        }
    };

    auto missing_presence = redirect.value();
    missing_presence.exact_absolute_redirect.present = false;
    expect_rejected(missing_presence,
                    lit_str("invalid absent exact absolute redirect model"),
                    redirect.value().exact_absolute_redirect.span);

    const auto expect_absent_dirty = [&](const nginx::Server& model, Span span = {}) {
        expect_rejected(model, lit_str("invalid absent exact absolute redirect model"), span);
    };
    auto dirty = canonical_server();
    dirty.exact_absolute_redirect.path.ptr = "/old";
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.path.len = 4;
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.path_span = Span{1, 5, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.path_span);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.span = Span{1, 5, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.span);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.status = 301;
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.status_lexeme.ptr = "301";
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.status_lexeme.len = 3;
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.status_span = Span{1, 4, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.response.status_span);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.target.ptr = "http://redirect.example/new";
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.target.len = 27;
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.target_span = Span{1, 28, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.response.target_span);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.authority.ptr = "redirect.example";
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.authority.len = 16;
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.authority_span = Span{1, 17, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.response.authority_span);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.path.ptr = "/new";
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.path.len = 4;
    expect_absent_dirty(dirty);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.path_span = Span{1, 5, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.response.path_span);
    dirty = canonical_server();
    dirty.exact_absolute_redirect.response.span = Span{1, 5, 1, 2};
    expect_absent_dirty(dirty, dirty.exact_absolute_redirect.response.span);

    auto present_only = canonical_server();
    present_only.exact_absolute_redirect.present = true;
    expect_rejected(present_only, lit_str("invalid exact absolute redirect location span"));

    auto both_actions = redirect.value();
    both_actions.exact_local_return = local.value().exact_local_return;
    expect_rejected(both_actions,
                    lit_str("multiple exact semantic actions are unsupported"),
                    both_actions.exact_local_return.span);
    auto dirty_second_action = redirect.value();
    dirty_second_action.exact_local_return.response.status = 200;
    expect_rejected(dirty_second_action,
                    lit_str("multiple exact semantic actions are unsupported"));

    const auto& accepted = redirect.value();
    auto forged = accepted;
    forged.exact_absolute_redirect.path = lit_str("/bad");
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect location path provenance"),
                    accepted.exact_absolute_redirect.path_span);
    forged = accepted;
    forged.exact_absolute_redirect.path = {nullptr, 4};
    expect_rejected(forged, lit_str("invalid exact absolute redirect location path provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.status = 302;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect status lexeme"),
                    accepted.exact_absolute_redirect.response.status_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme = lit_str("301");
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect status provenance"),
                    accepted.exact_absolute_redirect.response.status_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme.ptr =
        accepted.exact_absolute_redirect.response.target.ptr;
    expect_rejected(forged, lit_str("invalid exact absolute redirect status provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme.len--;
    expect_rejected(forged, lit_str("invalid exact absolute redirect status provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.status_lexeme = {nullptr, 3};
    expect_rejected(forged, lit_str("invalid exact absolute redirect status provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.target = lit_str("http://redirect.example/bad");
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect target provenance"),
                    accepted.exact_absolute_redirect.response.target_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.target.len--;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.target = {nullptr, 27};
    expect_rejected(forged, lit_str("invalid exact absolute redirect target provenance"));

    forged = accepted;
    forged.exact_absolute_redirect.response.authority = lit_str("redirect.example");
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect authority provenance"),
                    accepted.exact_absolute_redirect.response.authority_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.authority.ptr =
        accepted.exact_absolute_redirect.response.target.ptr + 8;
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.authority.len--;
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.authority = {nullptr, 16};
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.path = lit_str("/new");
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect target path provenance"),
                    accepted.exact_absolute_redirect.response.path_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.path.ptr =
        accepted.exact_absolute_redirect.response.target.ptr + 22;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.path.len--;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path provenance"));
    forged = accepted;
    forged.exact_absolute_redirect.response.path = {nullptr, 4};
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path provenance"));

    forged = accepted;
    forged.span = {};
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect location span"),
                    accepted.exact_absolute_redirect.span);
    forged = accepted;
    forged.exact_absolute_redirect.span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect location span"));
    forged = accepted;
    forged.exact_absolute_redirect.span.end = forged.span.end + 1u;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect location span"),
                    forged.exact_absolute_redirect.span);
    forged = accepted;
    forged.exact_absolute_redirect.span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect location span"));

    forged = accepted;
    forged.exact_absolute_redirect.path_span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect location path span"));
    forged = accepted;
    forged.exact_absolute_redirect.path_span.end++;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect location path span"),
                    forged.exact_absolute_redirect.path_span);
    forged = accepted;
    forged.exact_absolute_redirect.path_span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect location path span"));

    forged = accepted;
    forged.exact_absolute_redirect.response.span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect response span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.span.end = forged.exact_absolute_redirect.span.end + 1u;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect response span"),
                    forged.exact_absolute_redirect.response.span);
    forged = accepted;
    forged.exact_absolute_redirect.response.span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect response span"));

    forged = accepted;
    forged.exact_absolute_redirect.response.status_span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect status span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.status_span.end++;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect status span"),
                    forged.exact_absolute_redirect.response.status_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.status_span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect status span"));

    forged = accepted;
    forged.exact_absolute_redirect.response.target_span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect target span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.target_span.end--;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect target span"),
                    forged.exact_absolute_redirect.response.target_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.target_span.start =
        forged.exact_absolute_redirect.response.status_span.end;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.target_span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target span"));

    forged = accepted;
    forged.exact_absolute_redirect.response.authority_span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.authority_span.start++;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect authority span"),
                    forged.exact_absolute_redirect.response.authority_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.authority_span.end++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.authority_span.line++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.authority_span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect authority span"));

    forged = accepted;
    forged.exact_absolute_redirect.response.path_span = {};
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.path_span.start--;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect target path span"),
                    forged.exact_absolute_redirect.response.path_span);
    forged = accepted;
    forged.exact_absolute_redirect.response.path_span.end--;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.path_span.line++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path span"));
    forged = accepted;
    forged.exact_absolute_redirect.response.path_span.col++;
    expect_rejected(forged, lit_str("invalid exact absolute redirect target path span"));

    forged = accepted;
    forged.location = api_server().location;
    expect_rejected(forged,
                    lit_str("invalid exact absolute redirect fallback provenance"),
                    forged.location.path_span);

    char mutable_source[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/old { return 301 http://redirect.example/new; } }";
    const auto mutable_parsed = nginx::parse({mutable_source, sizeof(mutable_source) - 1u});
    REQUIRE(mutable_parsed);
    char* status_byte = strstr(mutable_source, "301");
    REQUIRE(status_byte != nullptr);
    status_byte[2] = '2';
    expect_rejected(mutable_parsed.value(),
                    lit_str("invalid exact absolute redirect status lexeme"),
                    mutable_parsed.value().exact_absolute_redirect.response.status_span);
}

TEST(nginx_converter, lowers_canonical_model_to_stable_rut_source) {
    const auto result = nginx::lower_to_rut(canonical_server());
    REQUIRE(result);
    static constexpr char kExpected[] =
        "listen :8080\n"
        "upstream nginx_upstream at \"127.0.0.1:9000\"\n"
        "pre_route TRACE { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
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

    // The bounded no-content action is one fixed GET-only strict route appended
    // to the independently fixed root program above. Both nginx declaration
    // orders must equal this complete source byte-for-byte.
    static constexpr char kNoContentExactGolden[] =
        "route exact slash_normalized GET \"/static\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 204, reason: \"No Content\", server: "
        "\"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"\"\n"
        "}) }\n";
    nginx::RutSource no_content_golden{};
    memcpy(no_content_golden.data, kExpected, sizeof(kExpected) - 1u);
    memcpy(no_content_golden.data + sizeof(kExpected) - 1u,
           kNoContentExactGolden,
           sizeof(kNoContentExactGolden) - 1u);
    no_content_golden.len =
        static_cast<u32>(sizeof(kExpected) + sizeof(kNoContentExactGolden) - 2u);
    const char no_content_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204; } }";
    const char no_content_exact_first[] =
        "server { listen 8080; location = /static { return 204; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const char no_content_root_first_multiline[] =
        "server {\n  listen 8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static {\n    return\n      204 # separated\n      ;\n  }\n}\n";
    const char no_content_exact_first_multiline[] =
        "server {\n  listen 8080;\n"
        "  location = /static { return # separated\n 204\n # terminator\n ; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n}\n";
    const char* const no_content_lexer_whitespace[] = {
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return\f204; } }",
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return\v204; } }",
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204\f; } }",
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204\v; } }",
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location\f=\v/static\f{\vreturn\f204\v;\f} }",
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; }\n"
        "location # keyword gap\n = # equals gap\n /static # path gap\n "
        "{ # response gap\n return 204; # closing gap\n } }",
    };
    const auto no_content_root_model =
        nginx::parse({no_content_root_first, sizeof(no_content_root_first) - 1u});
    const auto no_content_exact_model =
        nginx::parse({no_content_exact_first, sizeof(no_content_exact_first) - 1u});
    const auto no_content_root_multiline_model = nginx::parse(
        {no_content_root_first_multiline, sizeof(no_content_root_first_multiline) - 1u});
    const auto no_content_exact_multiline_model = nginx::parse(
        {no_content_exact_first_multiline, sizeof(no_content_exact_first_multiline) - 1u});
    REQUIRE(no_content_root_model);
    REQUIRE(no_content_exact_model);
    REQUIRE(no_content_root_multiline_model);
    REQUIRE(no_content_exact_multiline_model);
    const auto no_content_root = nginx::lower_to_rut(no_content_root_model.value());
    const auto no_content_exact = nginx::lower_to_rut(no_content_exact_model.value());
    const auto no_content_root_multiline =
        nginx::lower_to_rut(no_content_root_multiline_model.value());
    const auto no_content_exact_multiline =
        nginx::lower_to_rut(no_content_exact_multiline_model.value());
    REQUIRE(no_content_root);
    REQUIRE(no_content_exact);
    REQUIRE(no_content_root_multiline);
    REQUIRE(no_content_exact_multiline);
    CHECK(no_content_root.value().view().eq(no_content_golden.view()));
    CHECK(no_content_exact.value().view().eq(no_content_golden.view()));
    CHECK(no_content_root_multiline.value().view().eq(no_content_golden.view()));
    CHECK(no_content_exact_multiline.value().view().eq(no_content_golden.view()));
    for (const char* source : no_content_lexer_whitespace) {
        const auto model = nginx::parse({source, static_cast<u32>(strlen(source))});
        REQUIRE(model);
        const auto lowered = nginx::lower_to_rut(model.value());
        REQUIRE(lowered);
        CHECK(lowered.value().view().eq(no_content_golden.view()));
    }
    CHECK(no_content_root.value().view().eq(no_content_exact.value().view()));
    CHECK_EQ(no_content_root.value().len, 5556u);
    const char* exact_route =
        strstr(no_content_root.value().data, "route exact slash_normalized GET \"/static\"");
    REQUIRE(exact_route != nullptr);
    CHECK(strstr(exact_route + 1, "route exact slash_normalized GET \"/static\"") == nullptr);
    CHECK(strstr(no_content_root.value().data, "route exact GET \"/static\"") == nullptr);
    const char* root_route = strstr(no_content_root.value().data, "route GET \"/\"");
    REQUIRE(root_route != nullptr);
    CHECK(strstr(root_route + 1, "route GET \"/\"") == nullptr);
    CHECK(strstr(no_content_root.value().data, "route exact \"/static\"") == nullptr);
    CHECK(strstr(no_content_root.value().data, "return 204") == nullptr);
    CHECK(strstr(no_content_root.value().data, "nginx.conf") == nullptr);
    CHECK(strstr(no_content_root.value().data, "proxy_pass") == nullptr);

    // The generalized bodyless action substitutes only the validated path in
    // the same ordinary-RUT binding. Pin the entire generated program for both
    // nginx declaration orders and for a comment/whitespace-equivalent source.
    static constexpr char kHealthzNoContentExactGolden[] =
        "route exact slash_normalized GET \"/healthz\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 204, reason: \"No Content\", server: "
        "\"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"\"\n"
        "}) }\n";
    nginx::RutSource healthz_no_content_golden{};
    memcpy(healthz_no_content_golden.data, kExpected, sizeof(kExpected) - 1u);
    memcpy(healthz_no_content_golden.data + sizeof(kExpected) - 1u,
           kHealthzNoContentExactGolden,
           sizeof(kHealthzNoContentExactGolden) - 1u);
    healthz_no_content_golden.len =
        static_cast<u32>(sizeof(kExpected) + sizeof(kHealthzNoContentExactGolden) - 2u);
    const char healthz_no_content_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz { return 204; } }";
    const char healthz_no_content_exact_first[] =
        "server { listen 8080; location = /healthz { return 204; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const char healthz_no_content_formatted[] =
        "# equivalent source\nserver {\n  listen 8080;\n"
        "  location = /healthz # exact path\n  { return # action\n 204 ; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n}\n";
    for (const char* source : {healthz_no_content_root_first,
                               healthz_no_content_exact_first,
                               healthz_no_content_formatted}) {
        const auto model = nginx::parse({source, static_cast<u32>(strlen(source))});
        REQUIRE(model);
        const auto lowered = nginx::lower_to_rut(model.value());
        REQUIRE(lowered);
        CHECK(lowered.value().view().eq(healthz_no_content_golden.view()));
        CHECK_EQ(lowered.value().len, 5557u);
    }

    struct CleanNoContentGolden {
        const char* path;
        const char* selector;
        u32 length;
    };
    const CleanNoContentGolden clean_no_content_goldens[] = {
        {"/health/check", "route exact slash_normalized GET \"/health/check\"", 5562u},
        {"/health/check/", "route exact slash_normalized GET \"/health/check/\"", 5563u},
    };
    for (const auto& vector : clean_no_content_goldens) {
        char source[256]{};
        const int source_len = snprintf(source,
                                        sizeof(source),
                                        "server { listen 8080; location / { proxy_pass "
                                        "http://127.0.0.1:9000; } location = %s { return 204; } }",
                                        vector.path);
        REQUIRE_GT(source_len, 0);
        REQUIRE_LT(static_cast<u32>(source_len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(source_len)});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, vector.length);
        CHECK(strstr(lowered.value().data, vector.selector) != nullptr);
    }

    // The complete /healthz source is a fixed root-program golden plus this
    // independently fixed exact binding. Both declaration orders must match
    // every byte, not merely the exact-route suffix.
    static constexpr char kHealthzExactGolden[] =
        "route exact slash_normalized \"/healthz\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"successor-static\"\n"
        "}) }\n";
    nginx::RutSource healthz_golden{};
    memcpy(healthz_golden.data, kExpected, sizeof(kExpected) - 1u);
    memcpy(healthz_golden.data + sizeof(kExpected) - 1u,
           kHealthzExactGolden,
           sizeof(kHealthzExactGolden) - 1u);
    healthz_golden.len = static_cast<u32>(sizeof(kExpected) + sizeof(kHealthzExactGolden) - 2u);
    const char healthz_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /healthz { return 200 \"successor-static\"; } }";
    const char healthz_exact_first[] =
        "server { listen 8080; location = /healthz { return 200 \"successor-static\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto healthz_root_model =
        nginx::parse({healthz_root_first, sizeof(healthz_root_first) - 1u});
    const auto healthz_exact_model =
        nginx::parse({healthz_exact_first, sizeof(healthz_exact_first) - 1u});
    REQUIRE(healthz_root_model);
    REQUIRE(healthz_exact_model);
    const auto healthz_root = nginx::lower_to_rut(healthz_root_model.value());
    const auto healthz_exact = nginx::lower_to_rut(healthz_exact_model.value());
    REQUIRE(healthz_root);
    REQUIRE(healthz_exact);
    CHECK(healthz_root.value().view().eq(healthz_golden.view()));
    CHECK(healthz_exact.value().view().eq(healthz_golden.view()));

    // Multiple internal spaces remain literal bytes in the same ordinary-RUT
    // exact response. Each representative body and both nginx declaration
    // orders must equal an independently assembled whole-source golden. The
    // order-dependent nginx spans stay in the borrowed model and do not leak
    // into canonical generated source.
    struct MultipleSpaceGoldenVector {
        const char* body;
        const char* root_first;
        const char* exact_first;
        const char* root_listen_port;
        const char* root_upstream_port;
        const char* exact_listen_port;
        const char* exact_upstream_port;
    };
    const MultipleSpaceGoldenVector multiple_space_vectors[] = {
        {"hello  world",
         "server { listen 8081; location / { proxy_pass http://127.0.0.1:9001; } "
         "location = /static { return 200 \"hello  world\"; } }",
         "server { listen 8082; location = /static { return 200 \"hello  world\"; } "
         "location / { proxy_pass http://127.0.0.1:9002; } }",
         "8081",
         "9001",
         "8082",
         "9002"},
        {"hello world again",
         "server { listen 8083; location / { proxy_pass http://127.0.0.1:9003; } "
         "location = /static { return 200 \"hello world again\"; } }",
         "server { listen 8084; location = /static { return 200 \"hello world again\"; } "
         "location / { proxy_pass http://127.0.0.1:9004; } }",
         "8083",
         "9003",
         "8084",
         "9004"},
    };
    for (const auto& vector : multiple_space_vectors) {
        char exact_golden[512]{};
        const int exact_golden_len =
            snprintf(exact_golden,
                     sizeof(exact_golden),
                     "route exact slash_normalized \"/static\" { return local_response({\n"
                     "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: "
                     "\"nginx/1.29.7\",\n"
                     "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
                     "  head_mode: \"suppress_body\", body: b\"%s\"\n"
                     "}) }\n",
                     vector.body);
        REQUIRE_GT(exact_golden_len, 0);
        REQUIRE_LT(static_cast<u32>(exact_golden_len), static_cast<u32>(sizeof(exact_golden)));
        const auto assemble_golden =
            [&](nginx::RutSource& golden, const char* listen_port, const char* upstream_port) {
                memcpy(golden.data, kExpected, sizeof(kExpected) - 1u);
                char* listen_metadata = strstr(golden.data, "listen :8080");
                char* upstream_metadata = strstr(golden.data, "127.0.0.1:9000");
                REQUIRE(listen_metadata != nullptr);
                REQUIRE(upstream_metadata != nullptr);
                memcpy(listen_metadata + sizeof("listen :") - 1u, listen_port, 4u);
                memcpy(upstream_metadata + sizeof("127.0.0.1:") - 1u, upstream_port, 4u);
                memcpy(golden.data + sizeof(kExpected) - 1u,
                       exact_golden,
                       static_cast<u32>(exact_golden_len));
                golden.len = static_cast<u32>(sizeof(kExpected) - 1u + exact_golden_len);
            };
        nginx::RutSource root_golden{};
        nginx::RutSource exact_order_golden{};
        assemble_golden(root_golden, vector.root_listen_port, vector.root_upstream_port);
        assemble_golden(exact_order_golden, vector.exact_listen_port, vector.exact_upstream_port);

        const auto root_model =
            nginx::parse({vector.root_first, static_cast<u32>(strlen(vector.root_first))});
        const auto exact_model =
            nginx::parse({vector.exact_first, static_cast<u32>(strlen(vector.exact_first))});
        REQUIRE(root_model);
        REQUIRE(exact_model);
        CHECK_NE(root_model.value().location.span.start, exact_model.value().location.span.start);
        CHECK_NE(root_model.value().exact_local_return.span.start,
                 exact_model.value().exact_local_return.span.start);
        const auto root_lowered = nginx::lower_to_rut(root_model.value());
        const auto exact_lowered = nginx::lower_to_rut(exact_model.value());
        REQUIRE(root_lowered);
        REQUIRE(exact_lowered);
        CHECK(root_lowered.value().view().eq(root_golden.view()));
        CHECK(exact_lowered.value().view().eq(exact_order_golden.view()));
        const u32 metadata_len = static_cast<u32>(
            strlen("listen :8081\nupstream nginx_upstream at \"127.0.0.1:9001\"\n"));
        REQUIRE_EQ(root_lowered.value().len, exact_lowered.value().len);
        CHECK(
            (Str{root_lowered.value().data + metadata_len, root_lowered.value().len - metadata_len}
                 .eq({exact_lowered.value().data + metadata_len,
                      exact_lowered.value().len - metadata_len})));
    }

    // A meaningful trailing slash remains part of the exact key while using
    // the same normalized nginx selection view. Both declaration orders still
    // lower to one entire byte-stable source.
    static constexpr char kNormalizedExactGolden[] =
        "route exact slash_normalized \"/health/check/\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"successor-static\"\n"
        "}) }\n";
    nginx::RutSource normalized_golden{};
    memcpy(normalized_golden.data, kExpected, sizeof(kExpected) - 1u);
    memcpy(normalized_golden.data + sizeof(kExpected) - 1u,
           kNormalizedExactGolden,
           sizeof(kNormalizedExactGolden) - 1u);
    normalized_golden.len =
        static_cast<u32>(sizeof(kExpected) + sizeof(kNormalizedExactGolden) - 2u);
    const char normalized_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /health/check/ { return 200 \"successor-static\"; } }";
    const char normalized_exact_first[] =
        "server { listen 8080; location = /health/check/ { return 200 \"successor-static\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto normalized_root_model =
        nginx::parse({normalized_root_first, sizeof(normalized_root_first) - 1u});
    const auto normalized_exact_model =
        nginx::parse({normalized_exact_first, sizeof(normalized_exact_first) - 1u});
    REQUIRE(normalized_root_model);
    REQUIRE(normalized_exact_model);
    const auto normalized_root = nginx::lower_to_rut(normalized_root_model.value());
    const auto normalized_exact = nginx::lower_to_rut(normalized_exact_model.value());
    REQUIRE(normalized_root);
    REQUIRE(normalized_exact);
    CHECK(normalized_root.value().view().eq(normalized_golden.view()));
    CHECK(normalized_exact.value().view().eq(normalized_golden.view()));
}

TEST(nginx_converter, lowers_api_model_to_stable_target_transform_source) {
    // Generation/golden evidence only: this does not claim nginx equivalence
    // or mark the broader /api/ TRACE row SUPPORTED before differential proof.
    const auto result = nginx::lower_to_rut(api_server());
    REQUIRE(result);
    static constexpr char kExpected[] =
        "listen :8080\n"
        "upstream nginx_upstream at \"127.0.0.1:9000\"\n"
        "pre_route TRACE { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
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

TEST(nginx_converter, lowers_service_root_replacement_to_full_byte_stable_source) {
    const char source[] =
        "server { listen 8080; location /service/ { proxy_pass http://127.0.0.1:9000/; } }";
    const auto parsed = nginx::parse({source, sizeof(source) - 1u});
    REQUIRE(parsed);
    const auto result = nginx::lower_to_rut(parsed.value());
    REQUIRE(result);
    static constexpr char kExpected[] =
        "listen :8080\n"
        "upstream nginx_upstream at \"127.0.0.1:9000\"\n"
        "pre_route TRACE { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n"
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
        "route \"/service\" {\n"
        "    if req.method == GET && req.pathOnly == \"/service\" {\n"
        "        return redirect({scheme: \"http\", authority: \"request_host\", port: "
        "\"actual_listener\",\n"
        "            path: \"static\", query: \"preserve_raw\", date: \"current\", connection: "
        "\"close\",\n"
        "            status: 301, reason: \"Moved Permanently\", server: \"nginx/1.29.7\",\n"
        "            content_type: \"text/html\", target_path: \"/service/\", body: b\"<html>\\r\\n"
        "<head><title>301 Moved Permanently</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>301 Moved Permanently</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n\"})\n"
        "    } else {\n"
        "        return forward(nginx_upstream, target_transform: {\n"
        "            strip_prefix: \"/service/\",\n"
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
    CHECK_EQ(result.value().len, static_cast<u32>(sizeof(kExpected) - 1u));
    CHECK_EQ(result.value().len, 3349u);
    CHECK(result.value().view().eq({kExpected, sizeof(kExpected) - 1u}));

    const char replacement_source[] =
        "server { listen 8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    const auto replacement_parsed =
        nginx::parse({replacement_source, sizeof(replacement_source) - 1u});
    REQUIRE(replacement_parsed);
    const auto replacement = nginx::lower_to_rut(replacement_parsed.value());
    REQUIRE(replacement);
    CHECK(strstr(replacement.value().data, "route \"/service\" {") != nullptr);
    CHECK(strstr(replacement.value().data, "target_path: \"/service/\"") != nullptr);
    CHECK(strstr(replacement.value().data, "strip_prefix: \"/service/\"") != nullptr);
    CHECK(strstr(replacement.value().data, "replace_prefix: \"/v1/\"") != nullptr);
    CHECK_EQ(replacement.value().len, result.value().len + 3u);
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

    const char api_compact[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/; } }";
    const char api_formatted[] =
        "# same transformed model\n"
        "server {\n"
        "  listen 8080;\n"
        "  location\t/api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/; # URI replacement\n"
        "  }\n"
        "}\n";
    auto api_compact_parsed = nginx::parse({api_compact, sizeof(api_compact) - 1});
    auto api_formatted_parsed = nginx::parse({api_formatted, sizeof(api_formatted) - 1});
    REQUIRE(api_compact_parsed);
    REQUIRE(api_formatted_parsed);
    auto api_compact_lowered = nginx::lower_to_rut(api_compact_parsed.value());
    auto api_formatted_lowered = nginx::lower_to_rut(api_formatted_parsed.value());
    REQUIRE(api_compact_lowered);
    REQUIRE(api_formatted_lowered);
    CHECK(api_compact_lowered.value().view().eq(api_formatted_lowered.value().view()));

    const char v1_compact[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/v1/; } }";
    const char v1_formatted[] =
        "# same non-root transformed model\n"
        "server {\n"
        "  listen 8080;\n"
        "  location\t/api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/; # clean replacement URI\n"
        "  }\n"
        "}\n";
    auto v1_compact_parsed = nginx::parse({v1_compact, sizeof(v1_compact) - 1u});
    auto v1_formatted_parsed = nginx::parse({v1_formatted, sizeof(v1_formatted) - 1u});
    REQUIRE(v1_compact_parsed);
    REQUIRE(v1_formatted_parsed);
    auto v1_compact_lowered = nginx::lower_to_rut(v1_compact_parsed.value());
    auto v1_formatted_lowered = nginx::lower_to_rut(v1_formatted_parsed.value());
    REQUIRE(v1_compact_lowered);
    REQUIRE(v1_formatted_lowered);
    CHECK(v1_compact_lowered.value().view().eq(v1_formatted_lowered.value().view()));
}

TEST(nginx_converter, root_maximum_ports_fit_bounded_source_capacity) {
    auto model = canonical_server();
    model.listen.port = 65535;
    model.location.proxy_pass.address[0] = 255;
    model.location.proxy_pass.address[1] = 255;
    model.location.proxy_pass.address[2] = 255;
    model.location.proxy_pass.address[3] = 255;
    model.location.proxy_pass.port = 65535;
    const auto lowered = nginx::lower_to_rut(model);
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5308u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    CHECK_GT(lexed.value().tokens.len, 530u);
}

TEST(nginx_converter, exact_no_content_maximum_ports_fit_existing_source_capacity) {
    static constexpr char kSource[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } "
        "location = /static { return 204; } }";
    const auto parsed = nginx::parse({kSource, sizeof(kSource) - 1u});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5564u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
    CHECK_EQ(nginx::RutSource::kCapacity - lowered.value().len, 382u);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();
}

TEST(nginx_converter, bounded_exact_no_content_maximum_paths_fit_existing_source_capacity) {
    static_assert(nginx::kMaxExactLocalReturnPathLen == 62u);
    static_assert(nginx::RutSource::kCapacity == 5946u);
    char paths[2][nginx::kMaxExactLocalReturnPathLen + 1u]{};
    paths[0][0] = '/';
    paths[1][0] = '/';
    for (u32 i = 1; i < nginx::kMaxExactLocalReturnPathLen; i++) {
        paths[0][i] = 'a';
        paths[1][i] = i + 1u == nginx::kMaxExactLocalReturnPathLen ? '/' : 'b';
    }
    const u32 expected_lengths[] = {5619u, 5619u};
    const u32 expected_headroom[] = {327u, 327u};
    const char* expected_selectors[] = {"route exact slash_normalized GET \"/aaaa",
                                        "route exact slash_normalized GET \"/bbbb"};
    for (u32 vector = 0; vector < 2u; vector++) {
        char source[256]{};
        const int source_len =
            snprintf(source,
                     sizeof(source),
                     "server { listen 65535; location / { proxy_pass "
                     "http://255.255.255.255:65535; } location = %s { return 204; } }",
                     paths[vector]);
        REQUIRE_GT(source_len, 0);
        REQUIRE_LT(static_cast<u32>(source_len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(source_len)});
        REQUIRE(parsed);
        REQUIRE_EQ(parsed.value().exact_no_content_return.path.len,
                   nginx::kMaxExactLocalReturnPathLen);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_lengths[vector]);
        CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
        CHECK_EQ(nginx::RutSource::kCapacity - lowered.value().len, expected_headroom[vector]);
        CHECK(strstr(lowered.value().data, expected_selectors[vector]) != nullptr);
        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        REQUIRE_EQ(ast.value()->exact_strict_local_response_bindings.len, 1u);
        CHECK_EQ(ast.value()->exact_strict_local_response_bindings[0].path_len,
                 nginx::kMaxExactLocalReturnPathLen);
        CHECK_EQ(ast.value()->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        delete ast.value();
    }
}

TEST(nginx_converter, exact_redirect_maximum_ports_fit_bounded_source_capacity) {
    char source[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } location = "
        "/old { return 301 http://redirect.example/new; } }";
    const auto parsed = nginx::parse({source, sizeof(source) - 1u});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5936u);
    CHECK_EQ(nginx::RutSource::kCapacity - lowered.value().len, 10u);
    CHECK_EQ(lowered.value().data[lowered.value().len], '\0');
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
}

TEST(nginx_converter, exact_302_redirect_maximum_ports_fit_bounded_source_capacity) {
    char source[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } location = "
        "/old { return 302 http://redirect.example/new; } }";
    const auto parsed = nginx::parse({source, sizeof(source) - 1u});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 5912u);
    CHECK_EQ(lowered.value().len + 1u, 5913u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();
}

TEST(nginx_converter, api_maximum_ports_fit_bounded_source_capacity) {
    auto model = api_server();
    model.listen.port = 65535;
    model.location.proxy_pass.address[0] = 255;
    model.location.proxy_pass.address[1] = 255;
    model.location.proxy_pass.address[2] = 255;
    model.location.proxy_pass.address[3] = 255;
    model.location.proxy_pass.port = 65535;
    const auto lowered = nginx::lower_to_rut(model);
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 3341u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
}

TEST(nginx_converter, clean_proxy_uri_maximum_fits_strict_existing_source_capacity) {
    static_assert(nginx::kMaxProxyPassUriLen == 128u);
    static_assert(nginx::RutSource::kCapacity == 5946u);
    char uri[nginx::kMaxProxyPassUriLen + 1u]{};
    uri[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxProxyPassUriLen; i++) uri[i] = 'a';
    uri[nginx::kMaxProxyPassUriLen - 1u] = '/';

    char source[512]{};
    const int source_len = snprintf(source,
                                    sizeof(source),
                                    "server { listen 65535; location /api/ { proxy_pass "
                                    "http://255.255.255.255:65535%s; } }",
                                    uri);
    REQUIRE_GT(source_len, 0);
    REQUIRE_LT(static_cast<u32>(source_len), static_cast<u32>(sizeof(source)));
    const auto parsed = nginx::parse({source, static_cast<u32>(source_len)});
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().location.proxy_pass.uri.len, nginx::kMaxProxyPassUriLen);

    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 3468u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();
}

TEST(nginx_converter, maximum_clean_location_and_uri_fit_strict_existing_source_capacity) {
    static_assert(nginx::kMaxProxyLocationPathLen == 63u);
    static_assert(nginx::kMaxProxyPassUriLen == 128u);
    static_assert(nginx::RutSource::kCapacity == 5946u);
    char path[nginx::kMaxProxyLocationPathLen + 1u]{};
    path[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxProxyLocationPathLen; i++) path[i] = 'a';
    path[nginx::kMaxProxyLocationPathLen - 1u] = '/';
    char uri[nginx::kMaxProxyPassUriLen + 1u]{};
    uri[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxProxyPassUriLen; i++) uri[i] = 'b';
    uri[nginx::kMaxProxyPassUriLen - 1u] = '/';

    char source[1024]{};
    const int source_len = snprintf(source,
                                    sizeof(source),
                                    "server { listen 65535; location %s { proxy_pass "
                                    "http://255.255.255.255:65535%s; } }",
                                    path,
                                    uri);
    REQUIRE_GT(source_len, 0);
    REQUIRE_LT(static_cast<u32>(source_len), static_cast<u32>(sizeof(source)));
    const auto parsed = nginx::parse({source, static_cast<u32>(source_len)});
    REQUIRE(parsed);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 3700u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();
}

TEST(nginx_converter, maximum_static_query_uri_fits_strict_existing_source_capacity) {
    static_assert(nginx::kMaxProxyLocationPathLen == 63u);
    static_assert(nginx::kMaxProxyPassUriLen == 128u);
    static_assert(nginx::RutSource::kCapacity == 5946u);
    char path[nginx::kMaxProxyLocationPathLen + 1u]{};
    path[0] = '/';
    for (u32 i = 1; i + 1u < nginx::kMaxProxyLocationPathLen; i++) path[i] = 'p';
    path[nginx::kMaxProxyLocationPathLen - 1u] = '/';
    char uri[nginx::kMaxProxyPassUriLen + 1u]{};
    uri[0] = '/';
    uri[1] = '?';
    for (u32 i = 2; i < nginx::kMaxProxyPassUriLen; i++) uri[i] = 'q';

    char source[1024]{};
    const int source_len = snprintf(source,
                                    sizeof(source),
                                    "server { listen 65535; location %s { proxy_pass "
                                    "http://255.255.255.255:65535%s; } }",
                                    path,
                                    uri);
    REQUIRE_GT(source_len, 0);
    REQUIRE_LT(static_cast<u32>(source_len), static_cast<u32>(sizeof(source)));
    const auto parsed = nginx::parse({source, static_cast<u32>(source_len)});
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().location.proxy_pass.uri.len, nginx::kMaxProxyPassUriLen);
    const auto lowered = nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    CHECK_EQ(lowered.value().len, 3700u);
    CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
    const std::string generated(lowered.value().data, lowered.value().len);
    CHECK_EQ(count_text(generated, "strip_prefix:"), 1u);
    CHECK_EQ(count_text(generated, "replace_prefix:"), 1u);
    static constexpr char kMarker[] = "            replace_prefix: \"";
    const char* marker = strstr(lowered.value().data, kMarker);
    REQUIRE(marker != nullptr);
    const char* emitted_uri = marker + sizeof(kMarker) - 1u;
    CHECK((Str{emitted_uri, nginx::kMaxProxyPassUriLen}.eq({uri, nginx::kMaxProxyPassUriLen})));
    CHECK_EQ(emitted_uri[nginx::kMaxProxyPassUriLen], '"');
    const auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    delete ast.value();

    char oversized_uri[nginx::kMaxProxyPassUriLen + 2u]{};
    oversized_uri[0] = '/';
    oversized_uri[1] = '?';
    for (u32 i = 2; i <= nginx::kMaxProxyPassUriLen; i++) oversized_uri[i] = 'r';
    char oversized_source[512]{};
    const int oversized_len = snprintf(oversized_source,
                                       sizeof(oversized_source),
                                       "server { listen 8080; location /api/ { proxy_pass "
                                       "http://127.0.0.1:9000%s; } }",
                                       oversized_uri);
    REQUIRE_GT(oversized_len, 0);
    REQUIRE_LT(static_cast<u32>(oversized_len), static_cast<u32>(sizeof(oversized_source)));
    const auto rejected = nginx::parse({oversized_source, static_cast<u32>(oversized_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(rejected.error().span.end - rejected.error().span.start,
             nginx::kMaxProxyPassUriLen + 1u);
}

TEST(nginx_converter, emitted_no_content_source_reaches_independent_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    uintptr_t nginx_begin = 0;
    uintptr_t nginx_end = 0;
    uintptr_t rut_begin = 0;
    uintptr_t rut_end = 0;
    {
        char nginx_source[] =
            "server { listen 8080; location = /static { return 204; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        nginx_begin = reinterpret_cast<uintptr_t>(nginx_source);
        nginx_end = nginx_begin + sizeof(nginx_source);
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        rut_begin = reinterpret_cast<uintptr_t>(lowered.value().data);
        rut_end = rut_begin + lowered.value().len;
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 10u);
        CHECK(ast_owned->items[9].kind == AstItemKind::ExactStrictLocalResponse);
        REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 5u);
        const auto& ast_binding = ast_owned->exact_strict_local_response_bindings[0];
        CHECK_EQ(ast_binding.method, kRouteMethodGet);
        CHECK_EQ(ast_binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{ast_binding.path, ast_binding.path_len}.eq(lit_str("/static"))));
        CHECK_EQ(ast_binding.policy_id, 5u);
        const auto& ast_policy = ast_owned->strict_local_response_policies[4];
        CHECK_EQ(strict_local_response_policy_profile(ast_policy),
                 StrictLocalResponseProfile::NoContent204);

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->routes.len, 3u);
        REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodGet);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK_EQ(strict_local_response_policy_profile(hir_owned->strict_local_response_policies[4]),
                 StrictLocalResponseProfile::NoContent204);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        REQUIRE_EQ(mir_owned->exact_strict_local_response_bindings.len, 1u);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodGet);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        for (u32 i = 0; i < mir_owned->functions.len; i++)
            CHECK(mir_owned->functions[i].path.eq(lit_str("/")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.func_count, 3u);
        REQUIRE_EQ(rir.module.upstream_count, 1u);
        REQUIRE_EQ(rir.module.exact_strict_local_response_binding_count, 1u);
        REQUIRE_EQ(rir.module.strict_local_response_policy_count, 5u);
        CHECK_EQ(rir.module.exact_strict_local_response_bindings[0].method, kRouteMethodGet);
        CHECK_EQ(rir.module.exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK_EQ(strict_local_response_policy_profile(rir.module.strict_local_response_policies[4]),
                 StrictLocalResponseProfile::NoContent204);
        char printed_storage[65536]{};
        rir::PrintBuf printed;
        printed.init(printed_storage, sizeof(printed_storage), -1);
        rir::print_module(printed, rir.module);
        REQUIRE_FALSE(printed.overflow);
        const std::string printed_text(printed.data, printed.len);
        CHECK_NE(printed_text.find("local_response#5: version=HTTP/1.1, status=204, "
                                   "reason=\"No Content\", server=\"nginx/1.29.7\", "
                                   "content_type=\"\", date=current, connection=request, "
                                   "head_mode=suppress_body, body=b\"\" (len=0)"),
                 std::string::npos);
        CHECK_NE(
            printed_text.find("exact:\n  GET slash_normalized \"/static\" -> local_response#5"),
            std::string::npos);
        u32 root_route_count = 0;
        size_t root_route_pos = 0;
        while ((root_route_pos = printed_text.find("  route: /\n", root_route_pos)) !=
               std::string::npos) {
            root_route_count++;
            root_route_pos++;
        }
        CHECK_EQ(root_route_count, 3u);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    REQUIRE(populated->strict_local_response_table_is_valid());
    REQUIRE_EQ(populated->strict_local_response_policy_count, 4u);
    REQUIRE_EQ(populated->route_count, 0u);
    REQUIRE_EQ(populated->upstream_count, 1u);
    REQUIRE_EQ(populated->upstreams[0].addr_count, 1u);
    CHECK((Str{populated->upstreams[0].name, populated->upstreams[0].name_len}.eq(
        lit_str("nginx_upstream"))));
    CHECK_EQ(ntohs(populated->upstreams[0].addrs[0].sin_port), 9000u);
    CHECK_EQ(ntohl(populated->upstreams[0].addrs[0].sin_addr.s_addr), 0x7f000001u);
    REQUIRE_EQ(populated->exact_strict_local_response_binding_count, 1u);
    const auto& binding = populated->exact_strict_local_response_bindings[0];
    CHECK_EQ(binding.method, kRouteMethodGet);
    CHECK_EQ(binding.path_view, ExactPathView::SlashNormalized);
    CHECK((Str{binding.path, binding.path_len}.eq(lit_str("/static"))));
    const auto exact = populated->match_exact_strict_local_response_views(
        lit_str("/static"), lit_str("/static"), kRouteMethodGet);
    REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
    const u16 policy_id = exact.policy_id;
    REQUIRE_EQ(policy_id, 4u);
    CHECK(populated
              ->match_exact_strict_local_response_views(
                  lit_str("/static"), lit_str("/static"), kRouteMethodHead)
              .state == ExactStrictLocalResponseMatchState::Miss);
    CHECK(populated
              ->match_exact_strict_local_response_views(
                  lit_str("/static/"), lit_str("/static/"), kRouteMethodGet)
              .state == ExactStrictLocalResponseMatchState::Miss);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(policy_id));
    const auto& policy = populated->strict_local_response_policies[policy_id - 1u];
    CHECK_EQ(strict_local_response_policy_profile(policy),
             StrictLocalResponseProfile::NoContent204);
    CHECK(policy.version == StrictLocalResponseVersion::Http11);
    CHECK_EQ(policy.status_code, 204u);
    CHECK(policy.reason.eq(lit_str("No Content")));
    CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(policy.date == StrictLocalResponseDate::Current);
    CHECK(policy.connection == StrictLocalResponseConnection::Request);
    CHECK(policy.head_mode == StrictLocalResponseHeadMode::SuppressBody);
    CHECK_EQ(policy.content_type.len, 0u);
    CHECK_EQ(policy.body.len, 0u);
    CHECK(populated->strict_local_response_bytes_owned(policy.content_type));
    CHECK(populated->strict_local_response_bytes_owned(policy.body));

    const auto outside_destroyed_sources = [&](Str value) {
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(value.ptr);
        return ptr < nginx_begin || ptr >= nginx_end;
    };
    const auto outside_generated_source = [&](Str value) {
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(value.ptr);
        return ptr < rut_begin || ptr >= rut_end;
    };
    CHECK(outside_destroyed_sources({binding.path, binding.path_len}));
    CHECK(outside_generated_source({binding.path, binding.path_len}));
    CHECK(outside_destroyed_sources(policy.reason));
    CHECK(outside_generated_source(policy.reason));
    CHECK(outside_destroyed_sources(policy.server));
    CHECK(outside_generated_source(policy.server));
    CHECK(outside_destroyed_sources(policy.content_type));
    CHECK(outside_generated_source(policy.content_type));
    CHECK(outside_destroyed_sources(policy.body));
    CHECK(outside_generated_source(policy.body));
}

TEST(nginx_converter, emitted_no_content_paths_are_owned_with_normalized_selection) {
    const std::string maximum_path = "/A-Z_a.z~9/more_2/" + std::string(44u, 'R');
    REQUIRE_EQ(maximum_path.size(), nginx::kMaxExactLocalReturnPathLen);
    const std::string sources[] = {
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } location = "
        "/healthz { return 204; } }",
        "server { listen 8080; location = /healthz { return 204; } location / { proxy_pass "
        "http://127.0.0.1:9000; } }",
        "server { listen 8080; location = " + maximum_path +
            " { return 204; } location / { proxy_pass http://127.0.0.1:9000; } }",
    };
    for (size_t source_index = 0u; source_index < std::size(sources); source_index++) {
        const std::string& original = sources[source_index];
        const std::string expected_path = source_index < 2u ? "/healthz" : maximum_path;
        auto populated = std::make_unique<RouteConfig>();
        uintptr_t nginx_begin = 0;
        uintptr_t nginx_end = 0;
        uintptr_t rut_begin = 0;
        uintptr_t rut_end = 0;
        {
            std::string nginx_source = original;
            nginx_begin = reinterpret_cast<uintptr_t>(nginx_source.data());
            nginx_end = nginx_begin + nginx_source.size();
            const auto parsed =
                nginx::parse({nginx_source.data(), static_cast<u32>(nginx_source.size())});
            REQUIRE(parsed);
            auto lowered = nginx::lower_to_rut(parsed.value());
            REQUIRE(lowered);
            rut_begin = reinterpret_cast<uintptr_t>(lowered.value().data);
            rut_end = rut_begin + sizeof(lowered.value().data);
            const std::string expected_route =
                "route exact slash_normalized GET \"" + expected_path + "\"";
            CHECK(strstr(lowered.value().data, expected_route.c_str()) != nullptr);
            CHECK(strstr(lowered.value().data, "route exact GET \"") == nullptr);
            std::fill(nginx_source.begin(), nginx_source.end(), 'x');

            const auto lexed = lex(lowered.value().view());
            REQUIRE(lexed);
            const auto ast = parse_file(lexed.value());
            REQUIRE(ast);
            std::unique_ptr<AstFile> ast_owned(ast.value());
            REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
            REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 5u);
            const auto& ast_binding = ast_owned->exact_strict_local_response_bindings[0];
            CHECK_EQ(ast_binding.method, kRouteMethodGet);
            CHECK_EQ(ast_binding.path_view, ExactPathView::SlashNormalized);
            CHECK((Str{ast_binding.path, ast_binding.path_len}.eq(
                {expected_path.data(), static_cast<u32>(expected_path.size())})));
            CHECK_EQ(
                strict_local_response_policy_profile(ast_owned->strict_local_response_policies[4]),
                StrictLocalResponseProfile::NoContent204);

            const auto hir = analyze_file(*ast_owned);
            REQUIRE(hir);
            std::unique_ptr<HirModule> hir_owned(hir.value());
            REQUIRE_EQ(hir_owned->routes.len, 3u);
            REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
            CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodGet);
            CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].path_view,
                     ExactPathView::SlashNormalized);

            const auto mir = build_mir(*hir_owned);
            REQUIRE(mir);
            std::unique_ptr<MirModule> mir_owned(mir.value());
            REQUIRE_EQ(mir_owned->functions.len, 3u);
            REQUIRE_EQ(mir_owned->exact_strict_local_response_bindings.len, 1u);
            CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodGet);
            CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].path_view,
                     ExactPathView::SlashNormalized);

            FrontendRirModule rir{};
            RirGuard rir_guard{rir};
            REQUIRE(lower_to_rir(*mir_owned, rir));
            REQUIRE(rir::verify_module(rir.module).ok);
            REQUIRE_EQ(rir.module.func_count, 3u);
            REQUIRE_EQ(rir.module.upstream_count, 1u);
            REQUIRE_EQ(rir.module.exact_strict_local_response_binding_count, 1u);
            REQUIRE_EQ(rir.module.strict_local_response_policy_count, 5u);
            CHECK_EQ(rir.module.exact_strict_local_response_bindings[0].method, kRouteMethodGet);
            CHECK_EQ(rir.module.exact_strict_local_response_bindings[0].path_view,
                     ExactPathView::SlashNormalized);
            char printed_storage[65536]{};
            rir::PrintBuf printed;
            printed.init(printed_storage, sizeof(printed_storage), -1);
            rir::print_module(printed, rir.module);
            REQUIRE_FALSE(printed.overflow);
            const std::string printed_text(printed.data, printed.len);
            CHECK_NE(printed_text.find("exact:\n  GET slash_normalized \"" + expected_path +
                                       "\" -> local_response#5"),
                     std::string::npos);
            CHECK_NE(printed_text.find("status=204, reason=\"No Content\""), std::string::npos);
            REQUIRE(populate_route_config(*populated, rir.module));
            memset(lowered.value().data, 'y', sizeof(lowered.value().data));
        }

        REQUIRE(populated->strict_local_response_table_is_valid());
        REQUIRE_EQ(populated->route_count, 0u);
        REQUIRE_EQ(populated->upstream_count, 1u);
        CHECK_EQ(ntohs(populated->upstreams[0].addrs[0].sin_port), 9000u);
        REQUIRE_EQ(populated->exact_strict_local_response_binding_count, 1u);
        const auto& binding = populated->exact_strict_local_response_bindings[0];
        CHECK_EQ(binding.method, kRouteMethodGet);
        CHECK_EQ(binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{binding.path, binding.path_len}.eq(
            {expected_path.data(), static_cast<u32>(expected_path.size())})));
        const auto select = [&](Str raw, u8 method) {
            char normalized_storage[kMaxExactPathViewLen]{};
            u32 normalized_len = 0u;
            const auto normalized_result = normalize_exact_path_slashes(
                raw, normalized_storage, sizeof(normalized_storage), &normalized_len);
            if (normalized_result == ExactPathNormalizationResult::OutputOverflow) {
                const u16 raw_policy = populated->match_exact_strict_local_response(raw, method);
                return ExactStrictLocalResponseMatchResult{
                    raw_policy == 0u ? ExactStrictLocalResponseMatchState::Miss
                                     : ExactStrictLocalResponseMatchState::Match,
                    raw_policy};
            }
            if (normalized_result != ExactPathNormalizationResult::Success)
                return ExactStrictLocalResponseMatchResult{
                    ExactStrictLocalResponseMatchState::InvalidInput, 0u};
            return populated->match_exact_strict_local_response_views(
                raw, {normalized_storage, normalized_len}, method);
        };
        const std::string query = expected_path + "?x=1";
        const auto query_match =
            select({query.data(), static_cast<u32>(query.size())}, kRouteMethodGet);
        REQUIRE(query_match.state == ExactStrictLocalResponseMatchState::Match);
        const u16 policy_id = query_match.policy_id;
        REQUIRE_NE(policy_id, 0u);
        const Str literal = {expected_path.data(), static_cast<u32>(expected_path.size())};
        const auto literal_match = select(literal, kRouteMethodGet);
        CHECK(literal_match.state == ExactStrictLocalResponseMatchState::Match);
        CHECK_EQ(literal_match.policy_id, policy_id);
        CHECK(select(literal, kRouteMethodHead).state == ExactStrictLocalResponseMatchState::Miss);
        const std::string slash_extension = expected_path + "/";
        const Str slash_extension_view = {slash_extension.data(),
                                          static_cast<u32>(slash_extension.size())};
        CHECK(select(slash_extension_view, kRouteMethodGet).state ==
              ExactStrictLocalResponseMatchState::Miss);
        std::string neighbor = expected_path;
        neighbor.back() = neighbor.back() == 'R' ? 'S' : 'y';
        const Str neighbor_view = {neighbor.data(), static_cast<u32>(neighbor.size())};
        CHECK(select(neighbor_view, kRouteMethodGet).state ==
              ExactStrictLocalResponseMatchState::Miss);
        CHECK(select(lit_str("/"), kRouteMethodGet).state ==
              ExactStrictLocalResponseMatchState::Miss);
        if (source_index == 2u) {
            std::string doubled = expected_path;
            doubled.insert(doubled.find('/', 1u), "/");
            const auto doubled_match =
                select({doubled.data(), static_cast<u32>(doubled.size())}, kRouteMethodGet);
            CHECK(doubled_match.state == ExactStrictLocalResponseMatchState::Match);
            CHECK_EQ(doubled_match.policy_id, policy_id);
        }
        REQUIRE(populated->strict_local_response_policy_id_is_owned(policy_id));
        const auto& policy = populated->strict_local_response_policies[policy_id - 1u];
        CHECK_EQ(strict_local_response_policy_profile(policy),
                 StrictLocalResponseProfile::NoContent204);
        CHECK_EQ(policy.status_code, 204u);
        CHECK(policy.reason.eq(lit_str("No Content")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.content_type.empty());
        CHECK(policy.body.empty());
        const uintptr_t path_address = reinterpret_cast<uintptr_t>(binding.path);
        CHECK(path_address < nginx_begin || path_address >= nginx_end);
        CHECK(path_address < rut_begin || path_address >= rut_end);
    }
}

TEST(nginx_converter, emitted_exact_source_reaches_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    {
        char nginx_source[] =
            "server { listen 8080; location = /a/b { return 200 \"successor-static\"; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 10u);
        CHECK(ast_owned->items[2].kind == AstItemKind::PreRoute);
        CHECK(ast_owned->items[9].kind == AstItemKind::ExactStrictLocalResponse);
        REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(ast_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
        CHECK(ast_owned->strict_local_response_policies[0].body.eq(
            lit_str("<html>\r\n<head><title>405 Not Allowed</title></head>\r\n"
                    "<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n"
                    "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n")));
        const auto& ast_binding = ast_owned->exact_strict_local_response_bindings[0];
        CHECK_EQ(ast_binding.method, kRouteMethodAny);
        CHECK_EQ(ast_binding.policy_id, 5u);
        CHECK_EQ(ast_binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{ast_binding.path, ast_binding.path_len}.eq(lit_str("/a/b"))));
        const auto& ast_policy = ast_owned->strict_local_response_policies[4];
        CHECK(ast_policy.version == StrictLocalResponseVersion::Http11);
        CHECK_EQ(ast_policy.status_code, 200u);
        CHECK(ast_policy.reason.eq(lit_str("OK")));
        CHECK(ast_policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(ast_policy.date == StrictLocalResponseDate::Current);
        CHECK(ast_policy.content_type.eq(lit_str("text/plain")));
        CHECK(ast_policy.connection == StrictLocalResponseConnection::Request);
        CHECK(ast_policy.head_mode == StrictLocalResponseHeadMode::SuppressBody);
        CHECK(ast_policy.body.eq(lit_str("successor-static")));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->routes.len, 3u);
        REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(hir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].policy_id, 5u);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        REQUIRE_EQ(mir_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(mir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        for (u32 i = 0; i < mir_owned->functions.len; i++)
            CHECK(mir_owned->functions[i].path.eq(lit_str("/")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.func_count, 3u);
        REQUIRE_EQ(rir.module.exact_strict_local_response_binding_count, 1u);
        REQUIRE_EQ(rir.module.strict_local_response_policy_count, 5u);
        const auto& rir_binding = rir.module.exact_strict_local_response_bindings[0];
        CHECK_EQ(rir_binding.method, kRouteMethodAny);
        CHECK_EQ(rir_binding.policy_id, 5u);
        CHECK_EQ(rir_binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{rir_binding.path, rir_binding.path_len}.eq(lit_str("/a/b"))));
        for (u32 i = 1; i < kMaxExactStrictLocalResponseBindings; i++)
            CHECK(exact_strict_local_response_binding_is_neutral(
                rir.module.exact_strict_local_response_bindings[i]));
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    // nginx/source/compiler storage above has either been overwritten or
    // destroyed. Resolve runtime IDs only now: installation may semantically
    // deduplicate source policy IDs (TRACE and unmatched CONNECT are equal).
    REQUIRE(populated->strict_local_response_table_is_valid());
    // Exact policies are installed as dispatch metadata rather than executable
    // route functions. The three root fallbacks remain RIR functions above;
    // production dispatch consults this owned exact table before that prefix
    // route table is entered.
    REQUIRE_EQ(populated->route_count, 0u);
    const u16 trace_id = populated->pre_route_policy_id(kRouteMethodTrace);
    REQUIRE_NE(trace_id, 0u);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(trace_id));
    CHECK_EQ(trace_id, populated->unmatched_policy_ids[kRouteMethodConnect]);
    const auto& trace_policy = populated->strict_local_response_policies[trace_id - 1u];
    CHECK(trace_policy.version == StrictLocalResponseVersion::Http11);
    CHECK_EQ(trace_policy.status_code, 405u);
    CHECK(trace_policy.reason.eq(lit_str("Not Allowed")));
    CHECK(trace_policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(trace_policy.date == StrictLocalResponseDate::Current);
    CHECK(trace_policy.content_type.eq(lit_str("text/html")));
    CHECK(trace_policy.connection == StrictLocalResponseConnection::Request);
    CHECK(trace_policy.head_mode == StrictLocalResponseHeadMode::Reject);
    static constexpr char kDecodedTraceBody[] =
        "<html>\r\n"
        "<head><title>405 Not Allowed</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>405 Not Allowed</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kDecodedTraceBody) - 1u == 157u);
    CHECK(trace_policy.body.eq({kDecodedTraceBody, sizeof(kDecodedTraceBody) - 1u}));
    REQUIRE_EQ(populated->exact_strict_local_response_binding_count, 1u);
    CHECK_EQ(populated->exact_strict_local_response_bindings[0].path_view,
             ExactPathView::SlashNormalized);
    CHECK((Str{populated->exact_strict_local_response_bindings[0].path,
               populated->exact_strict_local_response_bindings[0].path_len}
               .eq(lit_str("/a/b"))));
    const auto match = [&](Str raw, Str normalized) {
        return populated->match_exact_strict_local_response_views(raw, normalized, kRouteMethodGet);
    };
    const auto exact = match(lit_str("/a/b"), lit_str("/a/b"));
    REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
    const u16 exact_id = exact.policy_id;
    REQUIRE_EQ(exact_id, 4u);
    const auto query = match(lit_str("/a/b?x=1"), lit_str("/a/b"));
    CHECK(query.state == ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(query.policy_id, exact_id);
    const auto doubled = match(lit_str("/a//b"), lit_str("/a/b"));
    CHECK(doubled.state == ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(doubled.policy_id, exact_id);
    CHECK(match(lit_str("/a/b/"), lit_str("/a/b/")).state ==
          ExactStrictLocalResponseMatchState::Miss);
    CHECK(match(lit_str("/a/c"), lit_str("/a/c")).state ==
          ExactStrictLocalResponseMatchState::Miss);
    CHECK(match(lit_str("/"), lit_str("/")).state == ExactStrictLocalResponseMatchState::Miss);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(exact_id));
    const auto& owned_policy = populated->strict_local_response_policies[exact_id - 1u];
    CHECK(owned_policy.body.eq(lit_str("successor-static")));
    CHECK(owned_policy.server.eq(lit_str("nginx/1.29.7")));
}

TEST(nginx_converter, emitted_body_space_exact_source_reaches_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    {
        char nginx_source[] =
            "server { listen 8080; location = /static { return 200 \"hello world\"; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 10u);
        CHECK(ast_owned->items[2].kind == AstItemKind::PreRoute);
        CHECK(ast_owned->items[9].kind == AstItemKind::ExactStrictLocalResponse);
        REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(ast_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
        CHECK(ast_owned->strict_local_response_policies[0].body.eq(
            lit_str("<html>\r\n<head><title>405 Not Allowed</title></head>\r\n"
                    "<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n"
                    "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n")));
        const auto& ast_binding = ast_owned->exact_strict_local_response_bindings[0];
        CHECK_EQ(ast_binding.method, kRouteMethodAny);
        CHECK_EQ(ast_binding.policy_id, 5u);
        CHECK_EQ(ast_binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{ast_binding.path, ast_binding.path_len}.eq(lit_str("/static"))));
        const auto& ast_policy = ast_owned->strict_local_response_policies[4];
        CHECK(ast_policy.version == StrictLocalResponseVersion::Http11);
        CHECK_EQ(ast_policy.status_code, 200u);
        CHECK(ast_policy.reason.eq(lit_str("OK")));
        CHECK(ast_policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(ast_policy.date == StrictLocalResponseDate::Current);
        CHECK(ast_policy.content_type.eq(lit_str("text/plain")));
        CHECK(ast_policy.connection == StrictLocalResponseConnection::Request);
        CHECK(ast_policy.head_mode == StrictLocalResponseHeadMode::SuppressBody);
        CHECK(ast_policy.body.eq(lit_str("hello world")));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->routes.len, 3u);
        REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(hir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].policy_id, 5u);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK((Str{hir_owned->exact_strict_local_response_bindings[0].path,
                   hir_owned->exact_strict_local_response_bindings[0].path_len}
                   .eq(lit_str("/static"))));
        CHECK(hir_owned->strict_local_response_policies[4].body.eq(lit_str("hello world")));

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        REQUIRE_EQ(mir_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(mir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK((Str{mir_owned->exact_strict_local_response_bindings[0].path,
                   mir_owned->exact_strict_local_response_bindings[0].path_len}
                   .eq(lit_str("/static"))));
        CHECK(mir_owned->strict_local_response_policies[4].body.eq(lit_str("hello world")));
        for (u32 i = 0; i < mir_owned->functions.len; i++)
            CHECK(mir_owned->functions[i].path.eq(lit_str("/")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.func_count, 3u);
        REQUIRE_EQ(rir.module.exact_strict_local_response_binding_count, 1u);
        REQUIRE_EQ(rir.module.strict_local_response_policy_count, 5u);
        const auto& rir_binding = rir.module.exact_strict_local_response_bindings[0];
        CHECK_EQ(rir_binding.method, kRouteMethodAny);
        CHECK_EQ(rir_binding.policy_id, 5u);
        CHECK_EQ(rir_binding.path_view, ExactPathView::SlashNormalized);
        CHECK((Str{rir_binding.path, rir_binding.path_len}.eq(lit_str("/static"))));
        CHECK(rir.module.strict_local_response_policies[4].body.eq(lit_str("hello world")));
        for (u32 i = 1; i < kMaxExactStrictLocalResponseBindings; i++)
            CHECK(exact_strict_local_response_binding_is_neutral(
                rir.module.exact_strict_local_response_bindings[i]));
        char printed_storage[65536]{};
        rir::PrintBuf printed;
        printed.init(printed_storage, sizeof(printed_storage), -1);
        rir::print_module(printed, rir.module);
        REQUIRE_FALSE(printed.overflow);
        CHECK_NE(std::string(printed.data, printed.len).find("body=b\"hello world\" (len=11)"),
                 std::string::npos);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    // nginx/source/compiler storage above has either been overwritten or
    // destroyed. Resolve runtime IDs only now: installation may semantically
    // deduplicate source policy IDs (TRACE and unmatched CONNECT are equal).
    REQUIRE(populated->strict_local_response_table_is_valid());
    // Exact policies are installed as dispatch metadata rather than executable
    // route functions. The three root fallbacks remain RIR functions above;
    // production dispatch consults this owned exact table before that prefix
    // route table is entered.
    REQUIRE_EQ(populated->route_count, 0u);
    const u16 trace_id = populated->pre_route_policy_id(kRouteMethodTrace);
    REQUIRE_NE(trace_id, 0u);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(trace_id));
    CHECK_EQ(trace_id, populated->unmatched_policy_ids[kRouteMethodConnect]);
    const auto& trace_policy = populated->strict_local_response_policies[trace_id - 1u];
    CHECK(trace_policy.version == StrictLocalResponseVersion::Http11);
    CHECK_EQ(trace_policy.status_code, 405u);
    CHECK(trace_policy.reason.eq(lit_str("Not Allowed")));
    CHECK(trace_policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(trace_policy.date == StrictLocalResponseDate::Current);
    CHECK(trace_policy.content_type.eq(lit_str("text/html")));
    CHECK(trace_policy.connection == StrictLocalResponseConnection::Request);
    CHECK(trace_policy.head_mode == StrictLocalResponseHeadMode::Reject);
    static constexpr char kDecodedTraceBody[] =
        "<html>\r\n"
        "<head><title>405 Not Allowed</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>405 Not Allowed</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kDecodedTraceBody) - 1u == 157u);
    CHECK(trace_policy.body.eq({kDecodedTraceBody, sizeof(kDecodedTraceBody) - 1u}));
    REQUIRE_EQ(populated->exact_strict_local_response_binding_count, 1u);
    CHECK_EQ(populated->exact_strict_local_response_bindings[0].path_view,
             ExactPathView::SlashNormalized);
    CHECK((Str{populated->exact_strict_local_response_bindings[0].path,
               populated->exact_strict_local_response_bindings[0].path_len}
               .eq(lit_str("/static"))));
    const auto match = [&](Str raw, Str normalized) {
        return populated->match_exact_strict_local_response_views(raw, normalized, kRouteMethodGet);
    };
    const auto exact = match(lit_str("/static"), lit_str("/static"));
    REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
    const u16 exact_id = exact.policy_id;
    REQUIRE_EQ(exact_id, 4u);
    const auto query = match(lit_str("/static?x=1"), lit_str("/static"));
    CHECK(query.state == ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(query.policy_id, exact_id);
    CHECK(match(lit_str("/static/"), lit_str("/static/")).state ==
          ExactStrictLocalResponseMatchState::Miss);
    CHECK(match(lit_str("/stat"), lit_str("/stat")).state ==
          ExactStrictLocalResponseMatchState::Miss);
    CHECK(match(lit_str("/"), lit_str("/")).state == ExactStrictLocalResponseMatchState::Miss);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(exact_id));
    const auto& owned_policy = populated->strict_local_response_policies[exact_id - 1u];
    CHECK(owned_policy.body.eq(lit_str("hello world")));
    CHECK_EQ(owned_policy.body.len, 11u);
    CHECK(owned_policy.server.eq(lit_str("nginx/1.29.7")));
}

TEST(nginx_converter, emitted_multiple_space_body_reaches_independent_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    uintptr_t nginx_source_begin = 0;
    uintptr_t nginx_source_end = 0;
    uintptr_t rut_source_begin = 0;
    uintptr_t rut_source_end = 0;
    {
        char nginx_source[] =
            "server { listen 8080; location = /static { return 200 \"hello  world\"; } "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        nginx_source_begin = reinterpret_cast<uintptr_t>(nginx_source);
        nginx_source_end = nginx_source_begin + sizeof(nginx_source);
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        rut_source_begin = reinterpret_cast<uintptr_t>(lowered.value().data);
        rut_source_end = rut_source_begin + lowered.value().len;
        CHECK(strstr(lowered.value().data, "body: b\"hello  world\"") != nullptr);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 10u);
        CHECK(ast_owned->items[9].kind == AstItemKind::ExactStrictLocalResponse);
        REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(ast_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(ast_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK((Str{ast_owned->exact_strict_local_response_bindings[0].path,
                   ast_owned->exact_strict_local_response_bindings[0].path_len}
                   .eq(lit_str("/static"))));
        CHECK(ast_owned->strict_local_response_policies[4].body.eq(lit_str("hello  world")));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(hir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK(hir_owned->strict_local_response_policies[4].body.eq(lit_str("hello  world")));

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->exact_strict_local_response_bindings.len, 1u);
        REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 5u);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(mir_owned->exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK(mir_owned->strict_local_response_policies[4].body.eq(lit_str("hello  world")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.exact_strict_local_response_binding_count, 1u);
        REQUIRE_EQ(rir.module.strict_local_response_policy_count, 5u);
        CHECK_EQ(rir.module.exact_strict_local_response_bindings[0].method, kRouteMethodAny);
        CHECK_EQ(rir.module.exact_strict_local_response_bindings[0].path_view,
                 ExactPathView::SlashNormalized);
        CHECK(rir.module.strict_local_response_policies[4].body.eq(lit_str("hello  world")));
        char printed_storage[65536]{};
        rir::PrintBuf printed;
        printed.init(printed_storage, sizeof(printed_storage), -1);
        rir::print_module(printed, rir.module);
        REQUIRE_FALSE(printed.overflow);
        CHECK_NE(std::string(printed.data, printed.len).find("body=b\"hello  world\" (len=12)"),
                 std::string::npos);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    REQUIRE(populated->strict_local_response_table_is_valid());
    REQUIRE_EQ(populated->route_count, 0u);
    REQUIRE_EQ(populated->exact_strict_local_response_binding_count, 1u);
    const auto& binding = populated->exact_strict_local_response_bindings[0];
    CHECK_EQ(binding.method, kRouteMethodAny);
    CHECK_EQ(binding.path_view, ExactPathView::SlashNormalized);
    CHECK((Str{binding.path, binding.path_len}.eq(lit_str("/static"))));
    const auto match = [&](Str raw, Str normalized) {
        return populated->match_exact_strict_local_response_views(raw, normalized, kRouteMethodGet);
    };
    const auto exact = match(lit_str("/static"), lit_str("/static"));
    REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
    const u16 exact_id = exact.policy_id;
    REQUIRE_EQ(exact_id, 4u);
    const auto query = match(lit_str("/static?x=1"), lit_str("/static"));
    CHECK(query.state == ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(query.policy_id, exact_id);
    CHECK(match(lit_str("/static/"), lit_str("/static/")).state ==
          ExactStrictLocalResponseMatchState::Miss);
    CHECK(match(lit_str("/stat"), lit_str("/stat")).state ==
          ExactStrictLocalResponseMatchState::Miss);
    CHECK(match(lit_str("/"), lit_str("/")).state == ExactStrictLocalResponseMatchState::Miss);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(exact_id));
    const auto& owned_policy = populated->strict_local_response_policies[exact_id - 1u];
    CHECK(owned_policy.body.eq(lit_str("hello  world")));
    CHECK_EQ(owned_policy.body.len, 12u);
    CHECK(populated->strict_local_response_bytes_owned(owned_policy.body));
    const uintptr_t body_address = reinterpret_cast<uintptr_t>(owned_policy.body.ptr);
    CHECK(body_address < nginx_source_begin || body_address >= nginx_source_end);
    CHECK(body_address < rut_source_begin || body_address >= rut_source_end);
}

TEST(nginx_converter, emitted_normalized_exact_source_reaches_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    {
        char nginx_source[] =
            "server { listen 8080; location = /health/check/ { return 200 "
            "\"successor-static\"; } location / { proxy_pass http://127.0.0.1:9000; } }";
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK(strstr(lowered.value().data, "route exact slash_normalized \"/health/check/\"") !=
              nullptr);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 10u);
        REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
        const auto& ast_binding = ast_owned->exact_strict_local_response_bindings[0];
        CHECK_EQ(ast_binding.path_view, ExactPathView::SlashNormalized);
        CHECK_EQ(ast_binding.method, kRouteMethodAny);
        CHECK_EQ(ast_binding.policy_id, 5u);
        CHECK((Str{ast_binding.path, ast_binding.path_len}.eq(lit_str("/health/check/"))));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
        const auto& hir_binding = hir_owned->exact_strict_local_response_bindings[0];
        CHECK_EQ(hir_binding.path_view, ExactPathView::SlashNormalized);
        CHECK_EQ(hir_binding.method, kRouteMethodAny);
        CHECK_EQ(hir_binding.policy_id, 5u);
        CHECK((Str{hir_binding.path, hir_binding.path_len}.eq(lit_str("/health/check/"))));

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->exact_strict_local_response_bindings.len, 1u);
        const auto& mir_binding = mir_owned->exact_strict_local_response_bindings[0];
        CHECK_EQ(mir_binding.path_view, ExactPathView::SlashNormalized);
        CHECK_EQ(mir_binding.method, kRouteMethodAny);
        CHECK_EQ(mir_binding.policy_id, 5u);
        CHECK((Str{mir_binding.path, mir_binding.path_len}.eq(lit_str("/health/check/"))));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.exact_strict_local_response_binding_count, 1u);
        const auto& rir_binding = rir.module.exact_strict_local_response_bindings[0];
        CHECK_EQ(rir_binding.path_view, ExactPathView::SlashNormalized);
        CHECK_EQ(rir_binding.method, kRouteMethodAny);
        CHECK_EQ(rir_binding.policy_id, 5u);
        CHECK((Str{rir_binding.path, rir_binding.path_len}.eq(lit_str("/health/check/"))));
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    // All nginx/frontend/compiler/RIR storage above is gone. The owned inline
    // binding retains the normalized view and directly controls matching;
    // zero means dispatch continues to the ordinary root fallback functions.
    REQUIRE(populated->strict_local_response_table_is_valid());
    REQUIRE_EQ(populated->exact_strict_local_response_binding_count, 1u);
    const auto& binding = populated->exact_strict_local_response_bindings[0];
    CHECK_EQ(binding.path_view, ExactPathView::SlashNormalized);
    CHECK_EQ(binding.method, kRouteMethodAny);
    CHECK((Str{binding.path, binding.path_len}.eq(lit_str("/health/check/"))));
    const auto match = [&](Str raw, Str normalized) {
        return populated->match_exact_strict_local_response_views(raw, normalized, kRouteMethodGet);
    };
    const auto exact = match(lit_str("/health/check/"), lit_str("/health/check/"));
    REQUIRE(exact.state == ExactStrictLocalResponseMatchState::Match);
    const u16 exact_id = exact.policy_id;
    REQUIRE_NE(exact_id, 0u);
    const auto query = match(lit_str("/health/check/?x=1"), lit_str("/health/check/"));
    CHECK(query.state == ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(query.policy_id, exact_id);
    const auto repeated = match(lit_str("/health/check//"), lit_str("/health/check/"));
    CHECK(repeated.state == ExactStrictLocalResponseMatchState::Match);
    CHECK_EQ(repeated.policy_id, exact_id);
    const auto no_slash = match(lit_str("/health/check"), lit_str("/health/check"));
    CHECK(no_slash.state == ExactStrictLocalResponseMatchState::Miss);
    CHECK_EQ(no_slash.policy_id, 0u);
    const auto root = match(lit_str("/"), lit_str("/"));
    CHECK(root.state == ExactStrictLocalResponseMatchState::Miss);
    CHECK_EQ(root.policy_id, 0u);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(exact_id));
    const auto& policy = populated->strict_local_response_policies[exact_id - 1u];
    CHECK_EQ(policy.status_code, 200u);
    CHECK(policy.body.eq(lit_str("successor-static")));
}

TEST(nginx_converter, emitted_exact_redirect_reaches_owned_runtime_config) {
    static constexpr char kDecodedRedirectBody[] =
        "<html>\r\n"
        "<head><title>301 Moved Permanently</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>301 Moved Permanently</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kDecodedRedirectBody) - 1u == 169u);
    static constexpr char kDecodedBadGatewayBody[] =
        "<html>\r\n"
        "<head><title>502 Bad Gateway</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>502 Bad Gateway</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static constexpr char kDecodedGatewayTimeoutBody[] =
        "<html>\r\n"
        "<head><title>504 Gateway Time-out</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>504 Gateway Time-out</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static constexpr char kDecodedTraceBody[] =
        "<html>\r\n"
        "<head><title>405 Not Allowed</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>405 Not Allowed</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static constexpr char kDecodedBadRequestBody[] =
        "<html>\r\n"
        "<head><title>400 Bad Request</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>400 Bad Request</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kDecodedBadGatewayBody) - 1u == 157u);
    static_assert(sizeof(kDecodedGatewayTimeoutBody) - 1u == 167u);
    static_assert(sizeof(kDecodedTraceBody) - 1u == 157u);
    static_assert(sizeof(kDecodedBadRequestBody) - 1u == 157u);
    auto populated = std::make_unique<RouteConfig>();
    {
        nginx::RutSource lowered_source{};
        {
            char nginx_source[] =
                "server { listen 8080; location = /old { return 301 "
                "http://redirect.example/new; } location / { proxy_pass "
                "http://127.0.0.1:9000; } }";
            auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
            REQUIRE(parsed);
            auto lowered = nginx::lower_to_rut(parsed.value());
            REQUIRE(lowered);
            lowered_source = lowered.value();
        }
        auto lexed = lex(lowered_source.view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 9u);
        REQUIRE_EQ(ast_owned->redirect_policies.len, 1u);
        const auto& ast_redirect = ast_owned->redirect_policies[0];
        CHECK(ast_redirect.authority == RedirectPolicyAuthority::Static);
        CHECK(ast_redirect.port == RedirectPolicyPort::Omit);
        CHECK(ast_redirect.path == RedirectPolicyPath::Static);
        CHECK(ast_redirect.query == RedirectPolicyQuery::Discard);
        CHECK(ast_redirect.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
        CHECK(ast_redirect.static_authority.eq(lit_str("redirect.example")));
        CHECK(ast_redirect.target_path.eq(lit_str("/new")));
        CHECK(ast_redirect.body.eq({kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->routes.len, 3u);
        CHECK_EQ(hir_owned->routes[0].method, kRouteMethodHead);
        CHECK_EQ(hir_owned->routes[1].method, kRouteMethodGet);
        CHECK_EQ(hir_owned->routes[2].method, kRouteMethodAny);
        const auto& get = hir_owned->routes[1];
        CHECK(get.path.eq(lit_str("/")));
        CHECK(get.forward_preflight_mode == ForwardPreflightMode::AfterCanonicalSelection);
        REQUIRE(get.control.kind == HirControlKind::If);
        REQUIRE(get.control.cond.kind == HirExprKind::Eq);
        REQUIRE(get.control.cond.lhs != nullptr);
        REQUIRE(get.control.cond.rhs != nullptr);
        CHECK(get.control.cond.lhs->kind == HirExprKind::ReqPathOnly);
        CHECK(get.control.cond.rhs->kind == HirExprKind::StrLit);
        CHECK(get.control.cond.rhs->str_value.eq(lit_str("/old")));
        CHECK(get.control.then_term.kind == HirTerminatorKind::Redirect);
        CHECK_EQ(get.control.then_term.redirect_policy_id, 1u);
        CHECK(get.control.else_term.kind == HirTerminatorKind::ForwardUpstream);
        CHECK_EQ(get.control.else_term.forward_request_policy_id, 1u);
        CHECK_EQ(get.control.else_term.forward_response_policy_id, 2u);
        CHECK_EQ(get.control.else_term.forward_failure_policy_id, 2u);
        CHECK_EQ(get.control.else_term.forward_timeout_failure_policy_id, 3u);
        CHECK_EQ(get.control.else_term.forward_response_read_timeout_seconds, 60u);
        CHECK(get.control.else_term.forward_response_buffering ==
              ForwardResponseBufferingMode::CompleteContentLength);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        CHECK_EQ(mir_owned->functions[1].method, kRouteMethodGet);
        CHECK(mir_owned->functions[1].path.eq(lit_str("/")));
        CHECK(mir_owned->functions[1].forward_preflight_mode ==
              ForwardPreflightMode::AfterCanonicalSelection);
        bool mir_redirect = false;
        bool mir_forward = false;
        for (u32 bi = 0; bi < mir_owned->functions[1].blocks.len; bi++) {
            const auto& term = mir_owned->functions[1].blocks[bi].term;
            if (term.kind == MirTerminatorKind::Redirect) {
                mir_redirect = true;
                CHECK_EQ(term.redirect_policy_id, 1u);
            }
            if (term.kind == MirTerminatorKind::ForwardUpstream) {
                mir_forward = true;
                CHECK_EQ(term.forward_request_policy_id, 1u);
                CHECK_EQ(term.forward_response_policy_id, 2u);
                CHECK_EQ(term.forward_failure_policy_id, 2u);
                CHECK_EQ(term.forward_timeout_failure_policy_id, 3u);
                CHECK_EQ(term.forward_response_read_timeout_seconds, 60u);
                CHECK(term.forward_response_buffering ==
                      ForwardResponseBufferingMode::CompleteContentLength);
            }
        }
        CHECK(mir_redirect);
        CHECK(mir_forward);

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
        const auto& rir_redirect = rir.module.redirect_policies[0];
        CHECK(rir_redirect.authority == RedirectPolicyAuthority::Static);
        CHECK(rir_redirect.port == RedirectPolicyPort::Omit);
        CHECK(rir_redirect.query == RedirectPolicyQuery::Discard);
        CHECK(rir_redirect.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
        CHECK(rir_redirect.static_authority.eq(lit_str("redirect.example")));
        CHECK(rir_redirect.target_path.eq(lit_str("/new")));
        CHECK(rir_redirect.body.eq({kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
        REQUIRE_EQ(rir.module.response_policy_count, 2u);
        REQUIRE_EQ(rir.module.failure_policy_count, 3u);
        REQUIRE_EQ(rir.module.policy_bundle_count, 3u);
        const auto& get_bundle = rir.module.policy_bundles[1];
        CHECK_EQ(get_bundle.response_policy_id, 2u);
        CHECK_EQ(get_bundle.failure_policy_id, 2u);
        CHECK_EQ(get_bundle.timeout_failure_policy_id, 3u);
        CHECK_EQ(get_bundle.response_read_timeout_seconds, 60u);
        CHECK(get_bundle.response_buffering == ForwardResponseBufferingMode::CompleteContentLength);
        REQUIRE_EQ(rir.module.func_count, 3u);
        const auto& function = rir.module.functions[1];
        CHECK_EQ(function.http_method, kRouteMethodGet);
        CHECK(function.route_pattern.eq(lit_str("/")));
        CHECK(function.forward_preflight_mode == ForwardPreflightMode::AfterCanonicalSelection);
        CHECK_EQ(function.preflight_forward_policy_bundle_id, 2u);
        REQUIRE_EQ(function.block_count, 3u);
        REQUIRE_EQ(function.blocks[0].inst_count, 4u);
        CHECK_EQ(function.blocks[0].insts[0].op, rir::Opcode::ReqPathOnly);
        CHECK_EQ(function.blocks[0].insts[1].op, rir::Opcode::ConstStr);
        CHECK(function.blocks[0].insts[1].imm.str_val.eq(lit_str("/old")));
        CHECK_EQ(function.blocks[0].insts[2].op, rir::Opcode::CmpEq);
        CHECK_EQ(function.blocks[0].insts[3].op, rir::Opcode::Br);
        REQUIRE_EQ(function.blocks[1].inst_count, 1u);
        CHECK_EQ(function.blocks[1].insts[0].op, rir::Opcode::RetRedirect);
        CHECK_EQ(function.blocks[1].insts[0].imm.i32_val, 1);
        REQUIRE_EQ(function.blocks[2].inst_count, 4u);
        CHECK_EQ(function.blocks[2].insts[3].op, rir::Opcode::RetForwardBundle);
        bool saw_path_only = false;
        bool saw_old = false;
        bool saw_branch = false;
        bool saw_redirect = false;
        bool saw_forward = false;
        for (u32 bi = 0; bi < function.block_count; bi++) {
            const auto& block = function.blocks[bi];
            for (u32 ii = 0; ii < block.inst_count; ii++) {
                const auto& instruction = block.insts[ii];
                if (instruction.op == rir::Opcode::ReqPathOnly) saw_path_only = true;
                if (instruction.op == rir::Opcode::ConstStr &&
                    instruction.imm.str_val.eq(lit_str("/old")))
                    saw_old = true;
                if (instruction.op == rir::Opcode::Br) saw_branch = true;
                if (instruction.op == rir::Opcode::RetRedirect) {
                    saw_redirect = true;
                    CHECK_EQ(instruction.imm.i32_val, 1);
                }
                if (instruction.op == rir::Opcode::RetForwardBundle) {
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
                    CHECK_EQ(bundle_id, 2);
                }
            }
        }
        CHECK(saw_path_only);
        CHECK(saw_old);
        CHECK(saw_branch);
        CHECK(saw_redirect);
        CHECK(saw_forward);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered_source.data, 'y', lowered_source.len);
    }

    REQUIRE_EQ(populated->redirect_policy_count, 1u);
    REQUIRE(populated->redirect_policy_id_is_valid(1u));
    const auto& owned = populated->redirect_policies[0];
    CHECK(populated->redirect_policy_strings_are_owned(owned));
    CHECK(owned.authority == RedirectPolicyAuthority::Static);
    CHECK(owned.port == RedirectPolicyPort::Omit);
    CHECK(owned.path == RedirectPolicyPath::Static);
    CHECK(owned.query == RedirectPolicyQuery::Discard);
    CHECK(owned.date == RedirectPolicyDate::Current);
    CHECK(owned.connection == RedirectPolicyConnection::Close);
    CHECK(owned.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
    CHECK_EQ(owned.status_code, 301u);
    CHECK(owned.reason.eq(lit_str("Moved Permanently")));
    CHECK(owned.server.eq(lit_str("nginx/1.29.7")));
    CHECK(owned.content_type.eq(lit_str("text/html")));
    CHECK(owned.static_authority.eq(lit_str("redirect.example")));
    CHECK(owned.target_path.eq(lit_str("/new")));
    CHECK(owned.body.eq({kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
    const Str redirect_fields[] = {owned.reason,
                                   owned.server,
                                   owned.content_type,
                                   owned.static_authority,
                                   owned.target_path,
                                   owned.body};
    for (Str field : redirect_fields)
        CHECK(str_is_in_owned_pool(
            field, populated->redirect_policy_bytes, populated->redirect_policy_bytes_used));

    REQUIRE_EQ(populated->response_policy_count, 2u);
    static constexpr Str kHiddenHeaders[] = {lit_str("Date"), lit_str("Server"), lit_str("X-Pad")};
    for (u32 i = 0; i < populated->response_policy_count; i++) {
        REQUIRE(populated->response_policy_id_is_valid(static_cast<u16>(i + 1u)));
        const auto& policy = populated->response_policies[i];
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(str_is_in_owned_pool(policy.server,
                                   populated->response_policy_bytes,
                                   populated->response_policy_bytes_used));
        REQUIRE_EQ(policy.hide_header_count, 3u);
        for (u32 header = 0; header < policy.hide_header_count; header++) {
            CHECK(policy.hide_headers[header].eq(kHiddenHeaders[header]));
            CHECK(str_is_in_owned_pool(policy.hide_headers[header],
                                       populated->response_policy_bytes,
                                       populated->response_policy_bytes_used));
        }
    }

    REQUIRE_EQ(populated->failure_policy_count, 3u);
    for (u32 i = 0; i < populated->failure_policy_count; i++) {
        if (i == 2)
            REQUIRE(populated->timeout_failure_policy_id_is_valid(static_cast<u16>(i + 1u)));
        else
            REQUIRE(populated->failure_policy_id_is_valid(static_cast<u16>(i + 1u)));
        const auto& policy = populated->failure_policies[i];
        const bool timeout = i == 2;
        CHECK_EQ(policy.status_code, timeout ? 504u : 502u);
        CHECK(policy.reason.eq(timeout ? lit_str("Gateway Time-out") : lit_str("Bad Gateway")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.body.eq(
            timeout ? Str{kDecodedGatewayTimeoutBody, sizeof(kDecodedGatewayTimeoutBody) - 1u}
                    : Str{kDecodedBadGatewayBody, sizeof(kDecodedBadGatewayBody) - 1u}));
        const Str fields[] = {policy.reason, policy.content_type, policy.server, policy.body};
        for (Str field : fields)
            CHECK(str_is_in_owned_pool(
                field, populated->failure_policy_bytes, populated->failure_policy_bytes_used));
    }

    REQUIRE_EQ(populated->policy_bundle_count, 3u);
    for (u16 id = 1; id <= 3; id++) REQUIRE(populated->policy_bundle_id_is_valid(id));
    const auto& head_bundle = populated->policy_bundles[0];
    CHECK_EQ(head_bundle.response_policy_id, 1u);
    CHECK_EQ(head_bundle.failure_policy_id, 1u);
    CHECK_EQ(head_bundle.timeout_failure_policy_id, 0u);
    CHECK_EQ(head_bundle.response_read_timeout_seconds, 0u);
    CHECK(head_bundle.response_buffering == ForwardResponseBufferingMode::None);
    const auto& get_bundle = populated->policy_bundles[1];
    CHECK_EQ(get_bundle.response_policy_id, 2u);
    CHECK_EQ(get_bundle.failure_policy_id, 2u);
    CHECK_EQ(get_bundle.timeout_failure_policy_id, 3u);
    CHECK_EQ(get_bundle.response_read_timeout_seconds, 60u);
    CHECK(get_bundle.response_buffering == ForwardResponseBufferingMode::CompleteContentLength);
    const auto& any_bundle = populated->policy_bundles[2];
    CHECK_EQ(any_bundle.response_policy_id, 2u);
    CHECK_EQ(any_bundle.failure_policy_id, 2u);
    CHECK_EQ(any_bundle.timeout_failure_policy_id, 0u);
    CHECK_EQ(any_bundle.response_read_timeout_seconds, 0u);
    CHECK(any_bundle.response_buffering == ForwardResponseBufferingMode::None);

    REQUIRE_EQ(populated->strict_local_response_policy_count, 3u);
    CHECK_EQ(populated->pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodConnect], 1u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated->strict_local_response_table_is_valid());
    for (u16 id = 1; id <= populated->strict_local_response_policy_count; id++) {
        REQUIRE(populated->strict_local_response_policy_id_is_owned(id));
        const auto& policy = populated->strict_local_response_policies[id - 1];
        const bool bad_request = policy.status_code == 400;
        CHECK(policy.reason.eq(bad_request ? lit_str("Bad Request") : lit_str("Not Allowed")));
        CHECK(policy.content_type.eq(lit_str("text/html")));
        CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(policy.body.eq(bad_request
                                 ? Str{kDecodedBadRequestBody, sizeof(kDecodedBadRequestBody) - 1u}
                                 : Str{kDecodedTraceBody, sizeof(kDecodedTraceBody) - 1u}));
        const Str fields[] = {policy.reason, policy.content_type, policy.server, policy.body};
        for (Str field : fields)
            CHECK(str_is_in_owned_pool(field,
                                       populated->strict_local_response_bytes,
                                       populated->strict_local_response_bytes_used));
    }

    REQUIRE_EQ(populated->upstream_count, 1u);
    const auto& upstream = populated->upstreams[0];
    CHECK((Str{upstream.name, upstream.name_len}.eq(lit_str("nginx_upstream"))));
    CHECK_EQ(upstream.addr_count, 1u);
    CHECK_EQ(ntohl(upstream.addrs[0].sin_addr.s_addr), 0x7F000001u);
    CHECK_EQ(ntohs(upstream.addrs[0].sin_port), 9000u);
    // Ordinary route handlers remain JIT functions; populate_route_config
    // owns their policy inventory without publishing a competing static route.
    // Route paths and upstream names are inline arrays rather than borrowed
    // Str fields; request-policy 1 is an enum-only fixed strip profile.
    CHECK_EQ(populated->route_count, 0u);
}

TEST(nginx_converter, emitted_exact_302_redirect_reaches_owned_runtime_config) {
    static constexpr char kDecodedRedirectBody[] =
        "<html>\r\n"
        "<head><title>302 Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>302 Found</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kDecodedRedirectBody) - 1u == 145u);
    auto populated = std::make_unique<RouteConfig>();
    {
        nginx::RutSource generated{};
        {
            char nginx_source[] =
                "server { listen 8080; location = /old { return 302 "
                "http://redirect.example/new; } location / { proxy_pass "
                "http://127.0.0.1:9000; } }";
            const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
            REQUIRE(parsed);
            const auto lowered = nginx::lower_to_rut(parsed.value());
            REQUIRE(lowered);
            generated = lowered.value();
            memset(nginx_source, 'x', sizeof(nginx_source) - 1u);
        }

        const auto lexed = lex(generated.view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 9u);
        REQUIRE_EQ(ast_owned->redirect_policies.len, 1u);
        const auto& ast_policy = ast_owned->redirect_policies[0];
        CHECK_EQ(ast_policy.status_code, 302u);
        CHECK(ast_policy.reason.eq(lit_str("Moved Temporarily")));
        CHECK(ast_policy.body.eq({kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
        CHECK(ast_policy.scheme == RedirectPolicyScheme::Http);
        CHECK(ast_policy.authority == RedirectPolicyAuthority::Static);
        CHECK(ast_policy.port == RedirectPolicyPort::Omit);
        CHECK(ast_policy.path == RedirectPolicyPath::Static);
        CHECK(ast_policy.query == RedirectPolicyQuery::Discard);
        CHECK(ast_policy.date == RedirectPolicyDate::Current);
        CHECK(ast_policy.connection == RedirectPolicyConnection::Close);
        CHECK(ast_policy.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
        CHECK(ast_policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(ast_policy.content_type.eq(lit_str("text/html")));
        CHECK(ast_policy.static_authority.eq(lit_str("redirect.example")));
        CHECK(ast_policy.target_path.eq(lit_str("/new")));

        const auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->redirect_policies.len, 1u);
        CHECK_EQ(hir_owned->redirect_policies[0].status_code, 302u);
        CHECK(hir_owned->redirect_policies[0].reason.eq(lit_str("Moved Temporarily")));
        CHECK(hir_owned->redirect_policies[0].body.eq(
            {kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
        REQUIRE_EQ(hir_owned->routes.len, 3u);
        const auto& get = hir_owned->routes[1];
        CHECK_EQ(get.method, kRouteMethodGet);
        CHECK(get.path.eq(lit_str("/")));
        CHECK(get.forward_preflight_mode == ForwardPreflightMode::AfterCanonicalSelection);
        REQUIRE(get.control.kind == HirControlKind::If);
        REQUIRE(get.control.cond.kind == HirExprKind::Eq);
        REQUIRE(get.control.cond.lhs != nullptr);
        REQUIRE(get.control.cond.rhs != nullptr);
        CHECK(get.control.cond.lhs->kind == HirExprKind::ReqPathOnly);
        CHECK(get.control.cond.rhs->kind == HirExprKind::StrLit);
        CHECK(get.control.cond.rhs->str_value.eq(lit_str("/old")));
        CHECK(get.control.then_term.kind == HirTerminatorKind::Redirect);
        CHECK_EQ(get.control.then_term.redirect_policy_id, 1u);
        CHECK(get.control.else_term.kind == HirTerminatorKind::ForwardUpstream);
        CHECK_EQ(get.control.else_term.forward_request_policy_id, 1u);
        CHECK_EQ(get.control.else_term.forward_response_policy_id, 2u);
        CHECK_EQ(get.control.else_term.forward_failure_policy_id, 2u);
        CHECK_EQ(get.control.else_term.forward_timeout_failure_policy_id, 3u);
        CHECK_EQ(get.control.else_term.forward_response_read_timeout_seconds, 60u);
        CHECK(get.control.else_term.forward_response_buffering ==
              ForwardResponseBufferingMode::CompleteContentLength);

        const auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->redirect_policies.len, 1u);
        CHECK_EQ(mir_owned->redirect_policies[0].status_code, 302u);
        CHECK(mir_owned->redirect_policies[0].reason.eq(lit_str("Moved Temporarily")));
        CHECK(mir_owned->redirect_policies[0].body.eq(
            {kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        CHECK_EQ(mir_owned->functions[1].method, kRouteMethodGet);
        CHECK(mir_owned->functions[1].path.eq(lit_str("/")));
        CHECK(mir_owned->functions[1].forward_preflight_mode ==
              ForwardPreflightMode::AfterCanonicalSelection);
        bool saw_redirect = false;
        bool saw_forward = false;
        for (u32 bi = 0; bi < mir_owned->functions[1].blocks.len; bi++) {
            const auto& term = mir_owned->functions[1].blocks[bi].term;
            if (term.kind == MirTerminatorKind::Redirect) {
                saw_redirect = true;
                CHECK_EQ(term.redirect_policy_id, 1u);
            }
            if (term.kind == MirTerminatorKind::ForwardUpstream) {
                saw_forward = true;
                CHECK_EQ(term.forward_request_policy_id, 1u);
                CHECK_EQ(term.forward_response_policy_id, 2u);
                CHECK_EQ(term.forward_failure_policy_id, 2u);
                CHECK_EQ(term.forward_timeout_failure_policy_id, 3u);
                CHECK_EQ(term.forward_response_read_timeout_seconds, 60u);
                CHECK(term.forward_response_buffering ==
                      ForwardResponseBufferingMode::CompleteContentLength);
            }
        }
        CHECK(saw_redirect);
        CHECK(saw_forward);

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
        const auto& rir_policy = rir.module.redirect_policies[0];
        CHECK_EQ(rir_policy.status_code, 302u);
        CHECK(rir_policy.reason.eq(lit_str("Moved Temporarily")));
        CHECK(rir_policy.body.eq({kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
        CHECK(rir_policy.scheme == RedirectPolicyScheme::Http);
        CHECK(rir_policy.authority == RedirectPolicyAuthority::Static);
        CHECK(rir_policy.port == RedirectPolicyPort::Omit);
        CHECK(rir_policy.path == RedirectPolicyPath::Static);
        CHECK(rir_policy.query == RedirectPolicyQuery::Discard);
        CHECK(rir_policy.date == RedirectPolicyDate::Current);
        CHECK(rir_policy.connection == RedirectPolicyConnection::Close);
        CHECK(rir_policy.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
        CHECK(rir_policy.server.eq(lit_str("nginx/1.29.7")));
        CHECK(rir_policy.content_type.eq(lit_str("text/html")));
        CHECK(rir_policy.static_authority.eq(lit_str("redirect.example")));
        CHECK(rir_policy.target_path.eq(lit_str("/new")));
        REQUIRE_EQ(rir.module.policy_bundle_count, 3u);
        const auto& get_bundle = rir.module.policy_bundles[1];
        CHECK_EQ(get_bundle.response_policy_id, 2u);
        CHECK_EQ(get_bundle.failure_policy_id, 2u);
        CHECK_EQ(get_bundle.timeout_failure_policy_id, 3u);
        CHECK_EQ(get_bundle.response_read_timeout_seconds, 60u);
        CHECK(get_bundle.response_buffering == ForwardResponseBufferingMode::CompleteContentLength);
        REQUIRE_EQ(rir.module.func_count, 3u);
        const auto& function = rir.module.functions[1];
        CHECK_EQ(function.http_method, kRouteMethodGet);
        CHECK(function.route_pattern.eq(lit_str("/")));
        CHECK(function.forward_preflight_mode == ForwardPreflightMode::AfterCanonicalSelection);
        CHECK_EQ(function.preflight_forward_policy_bundle_id, 2u);
        REQUIRE_EQ(function.block_count, 3u);
        REQUIRE_EQ(function.blocks[1].inst_count, 1u);
        CHECK_EQ(function.blocks[1].insts[0].op, rir::Opcode::RetRedirect);
        CHECK_EQ(function.blocks[1].insts[0].imm.i32_val, 1);
        REQUIRE_EQ(function.blocks[2].inst_count, 4u);
        CHECK_EQ(function.blocks[2].insts[3].op, rir::Opcode::RetForwardBundle);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(generated.data, 'y', generated.len);
    }

    REQUIRE_EQ(populated->redirect_policy_count, 1u);
    REQUIRE(populated->redirect_policy_id_is_valid(1u));
    const auto& owned = populated->redirect_policies[0];
    CHECK(populated->redirect_policy_strings_are_owned(owned));
    CHECK_EQ(owned.status_code, 302u);
    CHECK(owned.scheme == RedirectPolicyScheme::Http);
    CHECK(owned.authority == RedirectPolicyAuthority::Static);
    CHECK(owned.port == RedirectPolicyPort::Omit);
    CHECK(owned.path == RedirectPolicyPath::Static);
    CHECK(owned.query == RedirectPolicyQuery::Discard);
    CHECK(owned.date == RedirectPolicyDate::Current);
    CHECK(owned.connection == RedirectPolicyConnection::Close);
    CHECK(owned.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
    CHECK(owned.reason.eq(lit_str("Moved Temporarily")));
    CHECK(owned.server.eq(lit_str("nginx/1.29.7")));
    CHECK(owned.content_type.eq(lit_str("text/html")));
    CHECK(owned.static_authority.eq(lit_str("redirect.example")));
    CHECK(owned.target_path.eq(lit_str("/new")));
    CHECK(owned.body.eq({kDecodedRedirectBody, sizeof(kDecodedRedirectBody) - 1u}));
    const Str owned_fields[] = {owned.reason,
                                owned.server,
                                owned.content_type,
                                owned.static_authority,
                                owned.target_path,
                                owned.body};
    for (Str field : owned_fields)
        CHECK(str_is_in_owned_pool(
            field, populated->redirect_policy_bytes, populated->redirect_policy_bytes_used));
    REQUIRE_EQ(populated->policy_bundle_count, 3u);
    const auto& owned_get_bundle = populated->policy_bundles[1];
    CHECK_EQ(owned_get_bundle.response_policy_id, 2u);
    CHECK_EQ(owned_get_bundle.failure_policy_id, 2u);
    CHECK_EQ(owned_get_bundle.timeout_failure_policy_id, 3u);
    CHECK_EQ(owned_get_bundle.response_read_timeout_seconds, 60u);
    CHECK(owned_get_bundle.response_buffering ==
          ForwardResponseBufferingMode::CompleteContentLength);
    CHECK_EQ(populated->route_count, 0u);
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
    REQUIRE_EQ(ast_owned->items.len, 9u);
    CHECK(ast_owned->items[0].kind == AstItemKind::Listen);
    CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
    CHECK(ast_owned->items[1].kind == AstItemKind::Upstream);
    CHECK(ast_owned->items[2].kind == AstItemKind::PreRoute);
    CHECK(ast_owned->items[3].kind == AstItemKind::Unmatched);
    CHECK(ast_owned->items[4].kind == AstItemKind::Unmatched);
    CHECK(ast_owned->items[5].kind == AstItemKind::Unmatched);
    CHECK(ast_owned->items[6].kind == AstItemKind::Route);
    CHECK(ast_owned->items[7].kind == AstItemKind::Route);
    CHECK(ast_owned->items[8].kind == AstItemKind::Route);
    const u8 expected_route_methods[] = {
        static_cast<u8>(TokenType::KwHead), static_cast<u8>(TokenType::KwGet), 0};
    for (u32 i = 0; i < 3; i++) {
        const auto& route = ast_owned->items[6 + i].route;
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
    REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 4u);
    CHECK_EQ(ast_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodAny], 4u);
    for (u32 slot = 0; slot < kRouteMethodSlots; slot++)
        CHECK_EQ(ast_owned->unmatched_policy_ids[slot],
                 slot == kRouteMethodOptions   ? 2u
                 : slot == kRouteMethodConnect ? 3u
                 : slot == kRouteMethodAny     ? 4u
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
    check_unmatched_policy(ast_owned->strict_local_response_policies[1],
                           400,
                           "Bad Request",
                           kBadRequestBody,
                           StrictLocalResponseHeadMode::Reject);
    check_unmatched_policy(ast_owned->strict_local_response_policies[2],
                           405,
                           "Not Allowed",
                           kNotAllowedBody,
                           StrictLocalResponseHeadMode::Reject);
    check_unmatched_policy(ast_owned->strict_local_response_policies[3],
                           400,
                           "Bad Request",
                           kBadRequestBody,
                           StrictLocalResponseHeadMode::SuppressBody);
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE(hir_owned->has_listener);
    CHECK_EQ(hir_owned->listener.port, 8080u);
    REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 4u);
    CHECK_EQ(hir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodAny], 4u);
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
    REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 4u);
    CHECK_EQ(mir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodAny], 4u);
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
    REQUIRE_EQ(rir.module.strict_local_response_policy_count, 4u);
    CHECK_EQ(rir.module.pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodAny], 4u);
    CHECK_EQ(rir.module.strict_local_response_policies[1].status_code, 400u);
    CHECK_EQ(rir.module.strict_local_response_policies[2].status_code, 405u);
    CHECK_EQ(rir.module.strict_local_response_policies[3].status_code, 400u);
    CHECK_EQ(rir.module.strict_local_response_policies[0].status_code, 405u);
    CHECK(rir.module.strict_local_response_policies[0].reason.eq(lit_str("Not Allowed")));
    CHECK(rir.module.strict_local_response_policies[0].server.eq(lit_str("nginx/1.29.7")));
    CHECK(rir.module.strict_local_response_policies[0].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    static constexpr char kTraceBody[] =
        "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n"
        "<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n</body>\r\n</html>\r\n";
    CHECK(rir.module.strict_local_response_policies[0].body.eq(
        {kTraceBody, sizeof(kTraceBody) - 1u}));
    CHECK(rir.module.strict_local_response_policies[1].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    CHECK(rir.module.strict_local_response_policies[2].head_mode ==
          StrictLocalResponseHeadMode::Reject);
    CHECK(rir.module.strict_local_response_policies[3].head_mode ==
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
    CHECK_EQ(populated.pre_route_policy_id(kRouteMethodTrace), 1u);
    REQUIRE(populated.strict_local_response_policy_id_is_owned(1u));
    CHECK_EQ(populated.strict_local_response_policies[0].status_code, 405u);
    CHECK(populated.strict_local_response_policies[0].reason.eq(lit_str("Not Allowed")));
    CHECK(populated.strict_local_response_policies[0].server.eq(lit_str("nginx/1.29.7")));
    CHECK(
        populated.strict_local_response_policies[0].body.eq({kTraceBody, sizeof(kTraceBody) - 1u}));
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodConnect], 1u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated.strict_local_response_table_is_valid());
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

TEST(nginx_converter, root_pre_route_trace_policy_remains_owned_after_frontend_lifetimes) {
    auto populated = std::make_unique<RouteConfig>();
    {
        char nginx_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } }";
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 9u);
        CHECK(ast_owned->items[2].kind == AstItemKind::PreRoute);
        CHECK_EQ(ast_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->upstreams.len, 1u);
        REQUIRE_EQ(hir_owned->routes.len, 3u);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        for (u32 i = 0; i < mir_owned->functions.len; i++)
            CHECK(mir_owned->functions[i].path.eq(lit_str("/")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.upstream_count, 1u);
        REQUIRE_EQ(rir.module.func_count, 3u);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    // Source and all AST/HIR/MIR/RIR storage are gone. Runtime IDs are resolved
    // only now because the TRACE and CONNECT policies semantically deduplicate.
    REQUIRE(populated->strict_local_response_table_is_valid());
    const u16 trace_id = populated->pre_route_policy_id(kRouteMethodTrace);
    REQUIRE_NE(trace_id, 0u);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(trace_id));
    CHECK_EQ(trace_id, populated->unmatched_policy_ids[kRouteMethodConnect]);
    const auto& policy = populated->strict_local_response_policies[trace_id - 1u];
    CHECK(policy.version == StrictLocalResponseVersion::Http11);
    CHECK_EQ(policy.status_code, 405u);
    CHECK(policy.reason.eq(lit_str("Not Allowed")));
    CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(policy.date == StrictLocalResponseDate::Current);
    CHECK(policy.content_type.eq(lit_str("text/html")));
    CHECK(policy.connection == StrictLocalResponseConnection::Request);
    CHECK(policy.head_mode == StrictLocalResponseHeadMode::Reject);
    static constexpr char kTraceBody[] =
        "<html>\r\n"
        "<head><title>405 Not Allowed</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>405 Not Allowed</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kTraceBody) - 1u == 157u);
    CHECK(policy.body.eq({kTraceBody, sizeof(kTraceBody) - 1u}));
}

TEST(nginx_converter, emitted_api_source_reaches_rir_with_target_transform) {
    // Frontend/ownership evidence only: nginx equivalence and SUPPORTED status
    // require the separate pinned-nginx differential increment.
    auto lowered = nginx::lower_to_rut(api_server());
    REQUIRE(lowered);
    auto lexed = lex(lowered.value().view());
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 4u);
    CHECK_EQ(ast_owned->items[2].kind, AstItemKind::PreRoute);
    CHECK_EQ(ast_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(ast_owned->unmatched_policy_ids[kRouteMethodAny], 4u);
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 4u);
    CHECK_EQ(hir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(hir_owned->unmatched_policy_ids[kRouteMethodAny], 4u);
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
    REQUIRE_EQ(mir_owned->strict_local_response_policies.len, 4u);
    CHECK_EQ(mir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(mir_owned->unmatched_policy_ids[kRouteMethodAny], 4u);
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
    REQUIRE_EQ(rir.module.strict_local_response_policy_count, 4u);
    CHECK_EQ(rir.module.pre_route_policy_ids[kRouteMethodTrace], 1u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodConnect], 3u);
    CHECK_EQ(rir.module.unmatched_policy_ids[kRouteMethodAny], 4u);
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
    CHECK_EQ(populated.pre_route_policy_id(kRouteMethodTrace), 1u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodConnect], 1u);
    CHECK_EQ(populated.unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated.strict_local_response_table_is_valid());
    CHECK_EQ(populated.policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(populated.policy_bundles[0].response_read_timeout_seconds, 0u);
    CHECK(populated.policy_bundles[0].response_buffering == ForwardResponseBufferingMode::None);
}

TEST(nginx_converter, emitted_generic_non_root_replacement_reaches_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    {
        char nginx_source[] =
            "server { listen 8080; location /service/ { proxy_pass "
            "http://127.0.0.1:9000/v1/; } }";
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 7u);
        REQUIRE(ast_owned->items[6].kind == AstItemKind::Route);
        CHECK(ast_owned->items[6].route.path.eq(lit_str("/service")));
        REQUIRE_EQ(ast_owned->items[6].route.statements.len, 1u);
        const AstStatement* ast_if = ast_owned->items[6].route.statements[0];
        REQUIRE(ast_if != nullptr);
        REQUIRE(ast_if->kind == AstStmtKind::If);
        const AstStatement* ast_forward = ast_if->else_stmt;
        REQUIRE(ast_forward != nullptr);
        if (ast_forward->kind == AstStmtKind::Block) {
            REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
            ast_forward = ast_forward->block_stmts[0];
        }
        REQUIRE(ast_forward != nullptr);
        REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
        REQUIRE(ast_forward->has_forward_target_transform);
        CHECK(ast_forward->forward_target_transform.strip_prefix.eq(lit_str("/service/")));
        CHECK(ast_forward->forward_target_transform.replace_prefix.eq(lit_str("/v1/")));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->routes.len, 1u);
        CHECK(hir_owned->routes[0].path.eq(lit_str("/service")));
        REQUIRE(hir_owned->routes[0].control.kind == HirControlKind::If);
        const auto& hir_redirect = hir_owned->routes[0].control.then_term;
        const auto& hir_forward = hir_owned->routes[0].control.else_term;
        CHECK(hir_redirect.kind == HirTerminatorKind::Redirect);
        CHECK_EQ(hir_redirect.redirect_policy_id, 1u);
        REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
        REQUIRE(hir_forward.has_forward_target_transform);
        CHECK(hir_forward.forward_target_transform.strip_prefix.eq(lit_str("/service/")));
        CHECK(hir_forward.forward_target_transform.replace_prefix.eq(lit_str("/v1/")));
        CHECK_EQ(hir_forward.forward_request_policy_id, 1u);
        CHECK_EQ(hir_forward.forward_response_policy_id, 1u);
        CHECK_EQ(hir_forward.forward_failure_policy_id, 1u);
        CHECK_EQ(hir_forward.forward_timeout_failure_policy_id, 0u);
        CHECK_EQ(hir_forward.forward_response_read_timeout_seconds, 0u);
        CHECK(hir_forward.forward_response_buffering == ForwardResponseBufferingMode::None);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 1u);
        CHECK(mir_owned->functions[0].path.eq(lit_str("/service")));
        const MirTerminator* mir_redirect = nullptr;
        const MirTerminator* mir_forward = nullptr;
        for (u32 bi = 0; bi < mir_owned->functions[0].blocks.len; bi++) {
            const auto& term = mir_owned->functions[0].blocks[bi].term;
            if (term.kind == MirTerminatorKind::Redirect) mir_redirect = &term;
            if (term.kind == MirTerminatorKind::ForwardUpstream) mir_forward = &term;
        }
        REQUIRE(mir_redirect != nullptr);
        REQUIRE(mir_forward != nullptr);
        CHECK_EQ(mir_redirect->redirect_policy_id, 1u);
        REQUIRE(mir_forward->has_forward_target_transform);
        CHECK(mir_forward->forward_target_transform.strip_prefix.eq(lit_str("/service/")));
        CHECK(mir_forward->forward_target_transform.replace_prefix.eq(lit_str("/v1/")));
        CHECK_EQ(mir_forward->forward_request_policy_id, 1u);
        CHECK_EQ(mir_forward->forward_response_policy_id, 1u);
        CHECK_EQ(mir_forward->forward_failure_policy_id, 1u);
        CHECK_EQ(mir_forward->forward_timeout_failure_policy_id, 0u);
        CHECK_EQ(mir_forward->forward_response_read_timeout_seconds, 0u);
        CHECK(mir_forward->forward_response_buffering == ForwardResponseBufferingMode::None);

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.target_transform_count, 1u);
        CHECK(rir.module.target_transforms[0].strip_prefix.eq(lit_str("/service/")));
        CHECK(rir.module.target_transforms[0].replace_prefix.eq(lit_str("/v1/")));
        REQUIRE_EQ(rir.module.response_policy_count, 1u);
        REQUIRE_EQ(rir.module.failure_policy_count, 1u);
        REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
        CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
        CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);
        CHECK_EQ(rir.module.policy_bundles[0].timeout_failure_policy_id, 0u);
        CHECK_EQ(rir.module.policy_bundles[0].response_read_timeout_seconds, 0u);
        CHECK(rir.module.policy_bundles[0].response_buffering ==
              ForwardResponseBufferingMode::None);
        REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
        CHECK(rir.module.redirect_policies[0].target_path.eq(lit_str("/service/")));
        REQUIRE_EQ(rir.module.func_count, 1u);
        CHECK(rir.module.functions[0].route_pattern.eq(lit_str("/service")));

        bool saw_redirect = false;
        bool saw_transform_before_forward = false;
        for (u32 bi = 0; bi < rir.module.functions[0].block_count; bi++) {
            const auto& block = rir.module.functions[0].blocks[bi];
            for (u32 ii = 0; ii < block.inst_count; ii++) {
                if (block.insts[ii].op == rir::Opcode::RetRedirect) saw_redirect = true;
                if (block.insts[ii].op != rir::Opcode::RetForwardBundle) continue;
                REQUIRE(ii > 0);
                CHECK_EQ(block.insts[ii - 1].op, rir::Opcode::ReqSetTargetTransform);
                CHECK_EQ(block.insts[ii - 1].imm.i32_val, 1);
                saw_transform_before_forward = true;
            }
        }
        CHECK(saw_redirect);
        CHECK(saw_transform_before_forward);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    // nginx source, generated source, and AST/HIR/MIR/RIR storage are gone.
    // Route registration is the later JIT-engine stage; populate_route_config owns
    // the policy tables and leaves route_count empty by design. The route path was
    // asserted at every frontend/RIR stage above.
    REQUIRE_EQ(populated->route_count, 0u);
    REQUIRE_EQ(populated->target_transform_count, 1u);
    REQUIRE_EQ(populated->target_transform_bytes_used, 13u);
    const auto& transform = populated->target_transforms[0];
    CHECK(transform.strip_prefix.eq(lit_str("/service/")));
    CHECK(transform.replace_prefix.eq(lit_str("/v1/")));
    CHECK(str_is_in_owned_pool(transform.strip_prefix,
                               populated->target_transform_bytes,
                               populated->target_transform_bytes_used));
    CHECK(str_is_in_owned_pool(transform.replace_prefix,
                               populated->target_transform_bytes,
                               populated->target_transform_bytes_used));
    REQUIRE_EQ(populated->response_policy_count, 1u);
    REQUIRE_EQ(populated->failure_policy_count, 1u);
    REQUIRE_EQ(populated->policy_bundle_count, 1u);
    CHECK_EQ(populated->policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(populated->policy_bundles[0].failure_policy_id, 1u);
    CHECK_EQ(populated->policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(populated->policy_bundles[0].response_read_timeout_seconds, 0u);
    CHECK(populated->policy_bundles[0].response_buffering == ForwardResponseBufferingMode::None);
    REQUIRE_EQ(populated->redirect_policy_count, 1u);
    CHECK(populated->redirect_policies[0].target_path.eq(lit_str("/service/")));
    CHECK(populated->redirect_policy_strings_are_owned(populated->redirect_policies[0]));
    CHECK(populated->redirect_policy_string_is_owned(populated->redirect_policies[0].target_path));
}

TEST(nginx_converter, emitted_static_query_replacement_reaches_owned_runtime_config) {
    auto populated = std::make_unique<RouteConfig>();
    uintptr_t nginx_begin = 0;
    uintptr_t nginx_end = 0;
    uintptr_t generated_begin = 0;
    uintptr_t generated_end = 0;
    {
        char nginx_source[] =
            "server { listen 8080; location /api/ { proxy_pass "
            "http://127.0.0.1:9000/v1/?fixed=1; } }";
        nginx_begin = reinterpret_cast<uintptr_t>(nginx_source);
        nginx_end = nginx_begin + sizeof(nginx_source);
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated_begin = reinterpret_cast<uintptr_t>(lowered.value().data);
        generated_end = generated_begin + lowered.value().len;
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 7u);
        REQUIRE(ast_owned->items[6].kind == AstItemKind::Route);
        CHECK(ast_owned->items[6].route.path.eq(lit_str("/api")));
        REQUIRE_EQ(ast_owned->items[6].route.statements.len, 1u);
        const AstStatement* ast_if = ast_owned->items[6].route.statements[0];
        REQUIRE(ast_if != nullptr);
        REQUIRE(ast_if->kind == AstStmtKind::If);
        const AstStatement* ast_forward = ast_if->else_stmt;
        REQUIRE(ast_forward != nullptr);
        if (ast_forward->kind == AstStmtKind::Block) {
            REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
            ast_forward = ast_forward->block_stmts[0];
        }
        REQUIRE(ast_forward != nullptr);
        REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
        REQUIRE(ast_forward->has_forward_target_transform);
        CHECK(ast_forward->forward_target_transform.strip_prefix.eq(lit_str("/api/")));
        CHECK(ast_forward->forward_target_transform.replace_prefix.eq(lit_str("/v1/?fixed=1")));

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE_EQ(hir_owned->routes.len, 1u);
        CHECK(hir_owned->routes[0].path.eq(lit_str("/api")));
        REQUIRE(hir_owned->routes[0].control.kind == HirControlKind::If);
        const auto& hir_redirect = hir_owned->routes[0].control.then_term;
        const auto& hir_forward = hir_owned->routes[0].control.else_term;
        CHECK(hir_redirect.kind == HirTerminatorKind::Redirect);
        CHECK_EQ(hir_redirect.redirect_policy_id, 1u);
        REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
        REQUIRE(hir_forward.has_forward_target_transform);
        CHECK(hir_forward.forward_target_transform.strip_prefix.eq(lit_str("/api/")));
        CHECK(hir_forward.forward_target_transform.replace_prefix.eq(lit_str("/v1/?fixed=1")));
        CHECK_EQ(hir_forward.forward_request_policy_id, 1u);
        CHECK_EQ(hir_forward.forward_response_policy_id, 1u);
        CHECK_EQ(hir_forward.forward_failure_policy_id, 1u);
        CHECK_EQ(hir_forward.forward_timeout_failure_policy_id, 0u);
        CHECK_EQ(hir_forward.forward_response_read_timeout_seconds, 0u);
        CHECK(hir_forward.forward_response_buffering == ForwardResponseBufferingMode::None);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 1u);
        CHECK(mir_owned->functions[0].path.eq(lit_str("/api")));
        const MirTerminator* mir_redirect = nullptr;
        const MirTerminator* mir_forward = nullptr;
        for (u32 bi = 0; bi < mir_owned->functions[0].blocks.len; bi++) {
            const auto& term = mir_owned->functions[0].blocks[bi].term;
            if (term.kind == MirTerminatorKind::Redirect) mir_redirect = &term;
            if (term.kind == MirTerminatorKind::ForwardUpstream) mir_forward = &term;
        }
        REQUIRE(mir_redirect != nullptr);
        REQUIRE(mir_forward != nullptr);
        CHECK_EQ(mir_redirect->redirect_policy_id, 1u);
        REQUIRE(mir_forward->has_forward_target_transform);
        CHECK(mir_forward->forward_target_transform.strip_prefix.eq(lit_str("/api/")));
        CHECK(mir_forward->forward_target_transform.replace_prefix.eq(lit_str("/v1/?fixed=1")));
        CHECK_EQ(mir_forward->forward_request_policy_id, 1u);
        CHECK_EQ(mir_forward->forward_response_policy_id, 1u);
        CHECK_EQ(mir_forward->forward_failure_policy_id, 1u);
        CHECK_EQ(mir_forward->forward_timeout_failure_policy_id, 0u);

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.target_transform_count, 1u);
        CHECK(rir.module.target_transforms[0].strip_prefix.eq(lit_str("/api/")));
        CHECK(rir.module.target_transforms[0].replace_prefix.eq(lit_str("/v1/?fixed=1")));
        REQUIRE_EQ(rir.module.response_policy_count, 1u);
        REQUIRE_EQ(rir.module.failure_policy_count, 1u);
        REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
        CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
        CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);
        CHECK_EQ(rir.module.policy_bundles[0].timeout_failure_policy_id, 0u);
        REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
        CHECK(rir.module.redirect_policies[0].target_path.eq(lit_str("/api/")));
        REQUIRE_EQ(rir.module.func_count, 1u);
        CHECK(rir.module.functions[0].route_pattern.eq(lit_str("/api")));

        bool saw_redirect = false;
        bool saw_bound_transform = false;
        for (u32 bi = 0; bi < rir.module.functions[0].block_count; bi++) {
            const auto& block = rir.module.functions[0].blocks[bi];
            for (u32 ii = 0; ii < block.inst_count; ii++) {
                if (block.insts[ii].op == rir::Opcode::RetRedirect) saw_redirect = true;
                if (block.insts[ii].op != rir::Opcode::RetForwardBundle) continue;
                REQUIRE(ii > 0);
                CHECK_EQ(block.insts[ii - 1].op, rir::Opcode::ReqSetTargetTransform);
                CHECK_EQ(block.insts[ii - 1].imm.i32_val, 1);
                REQUIRE_EQ(block.insts[ii].operand_count, 3u);
                i32 upstream_id = -1;
                i32 request_policy_id = -1;
                i32 bundle_id = -1;
                REQUIRE(find_const_i32(
                    rir.module.functions[0], block.insts[ii].operand(0), upstream_id));
                REQUIRE(find_const_i32(
                    rir.module.functions[0], block.insts[ii].operand(1), request_policy_id));
                REQUIRE(
                    find_const_i32(rir.module.functions[0], block.insts[ii].operand(2), bundle_id));
                CHECK_EQ(upstream_id, 0);
                CHECK_EQ(request_policy_id, 1);
                CHECK_EQ(bundle_id, 1);
                saw_bound_transform = true;
            }
        }
        CHECK(saw_redirect);
        CHECK(saw_bound_transform);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    // Borrowed nginx/generated text and every AST/HIR/MIR/RIR allocation are
    // gone. The retained transform must be the RouteConfig-owned copy.
    REQUIRE_EQ(populated->route_count, 0u);
    REQUIRE_EQ(populated->target_transform_count, 1u);
    REQUIRE_EQ(populated->target_transform_bytes_used, 17u);
    const auto& transform = populated->target_transforms[0];
    CHECK(transform.strip_prefix.eq(lit_str("/api/")));
    CHECK(transform.replace_prefix.eq(lit_str("/v1/?fixed=1")));
    CHECK(str_is_in_owned_pool(transform.strip_prefix,
                               populated->target_transform_bytes,
                               populated->target_transform_bytes_used));
    CHECK(str_is_in_owned_pool(transform.replace_prefix,
                               populated->target_transform_bytes,
                               populated->target_transform_bytes_used));
    for (Str value : {transform.strip_prefix, transform.replace_prefix}) {
        const uintptr_t address = reinterpret_cast<uintptr_t>(value.ptr);
        CHECK(address < nginx_begin || address >= nginx_end);
        CHECK(address < generated_begin || address >= generated_end);
    }
    REQUIRE_EQ(populated->response_policy_count, 1u);
    REQUIRE_EQ(populated->failure_policy_count, 1u);
    REQUIRE_EQ(populated->policy_bundle_count, 1u);
    CHECK_EQ(populated->policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(populated->policy_bundles[0].failure_policy_id, 1u);
    CHECK_EQ(populated->policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(populated->policy_bundles[0].response_read_timeout_seconds, 0u);
    CHECK(populated->policy_bundles[0].response_buffering == ForwardResponseBufferingMode::None);
    REQUIRE_EQ(populated->redirect_policy_count, 1u);
    CHECK(populated->redirect_policies[0].target_path.eq(lit_str("/api/")));
    CHECK(populated->redirect_policy_strings_are_owned(populated->redirect_policies[0]));
}

TEST(nginx_converter, api_pre_route_trace_policy_remains_owned_after_frontend_lifetimes) {
    auto populated = std::make_unique<RouteConfig>();
    {
        char nginx_source[] =
            "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/; } }";
        auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        CHECK(parsed.value().pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);

        auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        CHECK_EQ(hir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);

        auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        CHECK_EQ(mir_owned->pre_route_policy_ids[kRouteMethodTrace], 1u);

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.pre_route_policy_ids[kRouteMethodTrace], 1u);
        REQUIRE_EQ(rir.module.target_transform_count, 1u);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    REQUIRE(populated->strict_local_response_table_is_valid());
    const u16 trace_id = populated->pre_route_policy_id(kRouteMethodTrace);
    REQUIRE_NE(trace_id, 0u);
    REQUIRE(populated->strict_local_response_policy_id_is_owned(trace_id));
    CHECK_EQ(trace_id, populated->unmatched_policy_ids[kRouteMethodConnect]);
    const auto& policy = populated->strict_local_response_policies[trace_id - 1u];
    CHECK(policy.version == StrictLocalResponseVersion::Http11);
    CHECK_EQ(policy.status_code, 405u);
    CHECK(policy.reason.eq(lit_str("Not Allowed")));
    CHECK(policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(policy.date == StrictLocalResponseDate::Current);
    CHECK(policy.content_type.eq(lit_str("text/html")));
    CHECK(policy.connection == StrictLocalResponseConnection::Request);
    CHECK(policy.head_mode == StrictLocalResponseHeadMode::Reject);
    static constexpr char kTraceBody[] =
        "<html>\r\n"
        "<head><title>405 Not Allowed</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>405 Not Allowed</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kTraceBody) - 1u == 157u);
    CHECK_EQ(policy.body.len, 157u);
    CHECK(policy.body.eq({kTraceBody, sizeof(kTraceBody) - 1u}));
    REQUIRE_EQ(populated->target_transform_count, 1u);
    CHECK(populated->target_transforms[0].strip_prefix.eq(lit_str("/api/")));
    CHECK(populated->target_transforms[0].replace_prefix.eq(lit_str("/")));
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
    CHECK_EQ(bad_api_present.error().span.start, 26u);
    CHECK(bad_api_present.error().detail.eq(lit_str("invalid proxy location spans")));

    auto other_present = valid_present;
    other_present.listen.port = 8080;
    other_present.location.path = lit_str("/other");
    other_present.location.path_span = Span{22, 28, 1, 23};
    auto bad_other_present = nginx::lower_to_rut(other_present);
    REQUIRE_FALSE(bad_other_present);
    CHECK_EQ(bad_other_present.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_other_present.error().span.start, 26u);
    CHECK(bad_other_present.error().detail.eq(lit_str("invalid proxy location spans")));

    auto null_present = valid_present;
    null_present.listen.port = 8080;
    null_present.location.path = {nullptr, 1};
    auto bad_null_present = nginx::lower_to_rut(null_present);
    REQUIRE_FALSE(bad_null_present);
    CHECK_EQ(bad_null_present.error().code, FrontendError::UnsupportedSyntax);
    CHECK_EQ(bad_null_present.error().span.start, 22u);
    CHECK(bad_null_present.error().detail.eq(lit_str("invalid proxy_pass source provenance")));

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

TEST(nginx_converter, rejects_forged_non_root_proxy_uri_before_reading_untrusted_bytes) {
    char source[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/;\n"
        "  }\n"
        "}\n";
    const auto parsed = nginx::parse({source, sizeof(source) - 1u});
    REQUIRE(parsed);
    const nginx::Server accepted = parsed.value();
    const Span accepted_uri_span = accepted.location.proxy_pass.uri_span;
    const auto expect_rejected = [&](const nginx::Server& model, Str detail, Span span = {}) {
        const auto result = nginx::lower_to_rut(model);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(detail));
        if (span.start < span.end) {
            CHECK_EQ(result.error().span.start, span.start);
            CHECK_EQ(result.error().span.end, span.end);
            CHECK_EQ(result.error().span.line, span.line);
            CHECK_EQ(result.error().span.col, span.col);
        }
    };

    auto forged = accepted;
    forged.location.path.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    expect_rejected(
        forged, lit_str("invalid proxy_pass source provenance"), accepted.location.path_span);

    forged = accepted;
    forged.location.path.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    forged.location.proxy_read_timeout.present = true;
    forged.location.proxy_read_timeout.milliseconds = 1000;
    forged.location.proxy_read_timeout.span = accepted.location.proxy_pass.span;
    forged.location.proxy_read_timeout.value_span = accepted.location.proxy_pass.uri_span;
    expect_rejected(
        forged, lit_str("invalid proxy_pass source provenance"), accepted.location.path_span);

    forged = accepted;
    forged.location.proxy_pass.uri = lit_str("/v1/");
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"));

    char reconstructed[] = "/v1/";
    forged = accepted;
    forged.location.proxy_pass.uri = {reconstructed, sizeof(reconstructed) - 1u};
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"));

    forged = accepted;
    forged.location.proxy_pass.uri = {nullptr, 4};
    expect_rejected(forged, lit_str("invalid bounded proxy_pass URI model"));

    forged = accepted;
    forged.location.proxy_pass.uri = {reinterpret_cast<const char*>(static_cast<uintptr_t>(1)), 4};
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"), accepted_uri_span);

    forged = accepted;
    forged.location.proxy_pass.uri.ptr++;
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"));

    forged = accepted;
    forged.location.proxy_pass.uri.len--;
    expect_rejected(forged, lit_str("invalid proxy location spans"));

    forged = accepted;
    forged.location.proxy_pass.uri.len = nginx::kMaxProxyPassUriLen + 1u;
    expect_rejected(forged, lit_str("invalid bounded proxy_pass URI model"));

    forged = accepted;
    forged.location.proxy_pass.uri_span.start--;
    forged.location.proxy_pass.uri_span.end--;
    forged.location.proxy_pass.uri_span.col--;
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"));

    forged = accepted;
    forged.location.proxy_pass.uri_span.end--;
    expect_rejected(forged, lit_str("invalid proxy location spans"));

    forged = accepted;
    forged.location.proxy_pass.uri_span.start = forged.location.proxy_pass.span.start - 1u;
    expect_rejected(forged, lit_str("invalid proxy location spans"));

    forged = accepted;
    forged.location.proxy_pass.uri_span.line++;
    expect_rejected(forged, lit_str("invalid proxy location source positions"));

    forged = accepted;
    forged.location.proxy_pass.uri_span.col++;
    expect_rejected(forged, lit_str("invalid proxy location spans"));

    forged = accepted;
    forged.location.proxy_pass.span.line++;
    forged.location.proxy_pass.uri_span.line++;
    expect_rejected(forged, lit_str("invalid proxy location source positions"));

    forged = accepted;
    forged.location.span.line++;
    forged.location.path_span.line++;
    forged.location.proxy_pass.span.line++;
    forged.location.proxy_pass.uri_span.line++;
    expect_rejected(forged, lit_str("invalid proxy location source positions"));

    forged = accepted;
    forged.location.proxy_pass.span.end = accepted_uri_span.end;
    expect_rejected(forged, lit_str("invalid proxy location spans"));

    static constexpr char kExternalLocation[] = "/api/";
    forged = accepted;
    forged.location.path = {kExternalLocation, sizeof(kExternalLocation) - 1u};
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"));

    forged = accepted;
    forged.span.end = forged.location.proxy_pass.span.start;
    forged.pre_route_trace.span.end = forged.span.end;
    expect_rejected(forged, lit_str("invalid proxy location spans"));

    auto legacy_slash = api_server();
    const Span legacy_uri_span = legacy_slash.location.proxy_pass.uri_span;
    legacy_slash.location.proxy_pass.uri.ptr =
        reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    expect_rejected(legacy_slash, lit_str("invalid proxy_pass URI provenance"), legacy_uri_span);

    char* uri = source + accepted_uri_span.start;
    REQUIRE((Str{uri, 4}.eq(lit_str("/v1/"))));
    uri[1] = '%';
    expect_rejected(accepted, lit_str("invalid bounded proxy_pass URI model"));
    uri[1] = 'v';
    uri[3] = 'x';
    expect_rejected(accepted, lit_str("invalid bounded proxy_pass URI model"));
}

TEST(nginx_converter, lowers_static_query_proxy_uri_to_exact_guarded_ordinary_rut_source) {
    char canonical_source[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/?fixed=1;\n"
        "  }\n"
        "}\n";
    char location_first_source[] =
        "server {\n"
        "  location /api/ { proxy_pass http://127.0.0.1:19000/v1/?fixed=1; }\n"
        "  listen 18080;\n"
        "}\n";
    const auto parsed = nginx::parse({canonical_source, sizeof(canonical_source) - 1u});
    const auto location_first =
        nginx::parse({location_first_source, sizeof(location_first_source) - 1u});
    REQUIRE(parsed);
    REQUIRE(location_first);
    const nginx::Server model = parsed.value();
    const auto& proxy = model.location.proxy_pass;
    const Span uri_span = proxy.uri_span;
    REQUIRE(proxy.uri.eq(lit_str("/v1/?fixed=1")));
    REQUIRE_EQ(proxy.uri.ptr, canonical_source + uri_span.start);
    REQUIRE_EQ(uri_span.end - uri_span.start, proxy.uri.len);

    const auto canonical_lowered = nginx::lower_to_rut(model);
    const auto location_first_lowered = nginx::lower_to_rut(location_first.value());
    REQUIRE(canonical_lowered);
    REQUIRE(location_first_lowered);
    const std::string canonical(canonical_lowered.value().data, canonical_lowered.value().len);
    const std::string alternate(location_first_lowered.value().data,
                                location_first_lowered.value().len);
    REQUIRE(validate_static_query_proxy_generated_source(canonical, 8080u, 9000u));
    REQUIRE(validate_static_query_proxy_generated_source(alternate, 18080u, 19000u));
    CHECK_EQ(canonical_lowered.value().len, 3344u);

    // The complete golden is the existing byte-locked `/api/ -> /` source with
    // exactly its one public replacement value widened. This covers every byte
    // while keeping the historical path-only golden authoritative and unchanged.
    const auto slash_lowered = nginx::lower_to_rut(api_server());
    REQUIRE(slash_lowered);
    std::string expected(slash_lowered.value().data, slash_lowered.value().len);
    static constexpr char kSlashReplacement[] = "            replace_prefix: \"/\"\n";
    static constexpr char kQueryReplacement[] = "            replace_prefix: \"/v1/?fixed=1\"\n";
    const size_t replacement_offset = expected.find(kSlashReplacement);
    REQUIRE_NE(replacement_offset, std::string::npos);
    CHECK_EQ(expected.find(kSlashReplacement, replacement_offset + 1u), std::string::npos);
    expected.replace(replacement_offset, sizeof(kSlashReplacement) - 1u, kQueryReplacement);
    CHECK_EQ(expected, canonical);
    CHECK_EQ(canonical_lowered.value().len, slash_lowered.value().len + sizeof("v1/?fixed=1") - 1u);

    // Declaration order is semantically irrelevant. Normalize only the two
    // independently chosen ports before requiring the complete generated bytes.
    std::string normalized = alternate;
    const auto replace_once = [&](const std::string& from, const std::string& to) {
        const size_t offset = normalized.find(from);
        REQUIRE_NE(offset, std::string::npos);
        CHECK_EQ(normalized.find(from, offset + from.size()), std::string::npos);
        normalized.replace(offset, from.size(), to);
    };
    replace_once("listen :18080\n", "listen :8080\n");
    replace_once("127.0.0.1:19000\"\n", "127.0.0.1:9000\"\n");
    CHECK_EQ(normalized, canonical);

    // The source-shape validator is fail-closed for every tempting workaround.
    const auto mutation_rejected = [&](const char* suffix) {
        CHECK_FALSE(validate_static_query_proxy_generated_source(canonical + suffix, 8080u, 9000u));
    };
    mutation_rejected("route \"/api?fixed=1\" { return forward(nginx_upstream) }\n");
    mutation_rejected("route \"/api/\" { return forward(nginx_upstream) }\n");
    mutation_rejected(
        "route \"/host\" { if req.host == \"client.example\" { return "
        "forward(nginx_upstream) } }\n");
    mutation_rejected(
        "route \"/dup\" { return forward(nginx_upstream, target_transform: {\n"
        "            strip_prefix: \"/api/\",\n"
        "            replace_prefix: \"/v1/?fixed=1\"\n"
        "        }) }\n");
    mutation_rejected("# nginx_compat workaround\n");

    // `route exact` is the compiler's Raw-default exact-selector syntax. Both
    // forms intentionally preserve every prior field/forbidden-marker guard;
    // only the new complete route inventory/view checks reject them.
    static constexpr char kRawGetRoute[] =
        "route exact GET \"/api/users?x=1\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 404, reason: \"Not Found\", server: \"rut\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"raw-get\"\n"
        "}) }\n";
    static constexpr char kRawAnyRoute[] =
        "route exact \"/api/users?x=1\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 404, reason: \"Not Found\", server: \"rut\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"raw-any\"\n"
        "}) }\n";
    const auto raw_route_mutation_rejected = [&](const char* suffix) {
        const std::string mutated = canonical + suffix;
        CHECK(validate_static_query_proxy_generated_source_fields(mutated, 8080u, 9000u));
        CHECK_EQ(count_text(mutated, "route \""), 1u);
        CHECK_EQ(count_route_declarations(mutated), 2u);
        CHECK_EQ(count_text(mutated, "\nroute exact "), 1u);
        CHECK_FALSE(validate_static_query_proxy_generated_source(mutated, 8080u, 9000u));
    };
    raw_route_mutation_rejected(kRawGetRoute);
    raw_route_mutation_rejected(kRawAnyRoute);

    const auto expect_rejected = [&](const nginx::Server& candidate, Str detail, Span span) {
        const auto lowered = nginx::lower_to_rut(candidate);
        REQUIRE_FALSE(lowered);
        CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
        CHECK(lowered.error().detail.eq(detail));
        CHECK_EQ(lowered.error().span.start, span.start);
        CHECK_EQ(lowered.error().span.end, span.end);
        CHECK_EQ(lowered.error().span.line, span.line);
        CHECK_EQ(lowered.error().span.col, span.col);
    };

    // Copying the semantic model preserves its exact borrowed view and now
    // lowers through the shared parser/model replacement grammar.
    const nginx::Server copied = model;
    CHECK_EQ(copied.location.proxy_pass.uri.ptr, proxy.uri.ptr);
    CHECK_EQ(copied.location.proxy_pass.uri_span.start, uri_span.start);
    const auto copied_lowered = nginx::lower_to_rut(copied);
    REQUIRE(copied_lowered);
    CHECK(copied_lowered.value().view().eq(canonical_lowered.value().view()));

    static constexpr char kExternalIdentical[] = "/v1/?fixed=1";
    auto forged = model;
    forged.location.proxy_pass.uri = {kExternalIdentical, sizeof(kExternalIdentical) - 1u};
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"), uri_span);

    forged = model;
    forged.location.proxy_pass.uri.ptr++;
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"), uri_span);

    forged = model;
    forged.location.proxy_pass.uri.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    forged.listen.port = 0;
    forged.location.proxy_pass.port = 0;
    expect_rejected(forged, lit_str("invalid proxy_pass URI provenance"), uri_span);

    forged = model;
    forged.location.proxy_pass.uri_span.start++;
    forged.location.proxy_pass.uri_span.col++;
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);

    char* replacement = canonical_source + uri_span.start;
    replacement[5] = '%';
    auto invalid_grammar = model;
    invalid_grammar.listen.port = 0;
    invalid_grammar.location.proxy_pass.port = 0;
    expect_rejected(invalid_grammar, lit_str("invalid bounded proxy_pass URI model"), uri_span);
    replacement[5] = 'f';
    replacement[6] = '?';
    expect_rejected(invalid_grammar, lit_str("invalid bounded proxy_pass URI model"), uri_span);
    replacement[6] = 'i';
    replacement[4] = '/';
    expect_rejected(model, lit_str("invalid bounded proxy_pass URI model"), uri_span);
    replacement[4] = '?';
}

TEST(nginx_converter, validates_generic_proxy_location_before_dynamic_reads_and_timeout) {
    char source[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /service/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/;\n"
        "  }\n"
        "}\n";
    const auto parsed = nginx::parse({source, sizeof(source) - 1u});
    REQUIRE(parsed);
    const nginx::Server accepted = parsed.value();
    const auto expect_rejected = [&](const nginx::Server& model, Str detail, Span span = {}) {
        const auto result = nginx::lower_to_rut(model);
        REQUIRE_FALSE(result);
        CHECK_EQ(result.error().code, FrontendError::UnsupportedSyntax);
        CHECK(result.error().detail.eq(detail));
        if (span.start < span.end) {
            CHECK_EQ(result.error().span.start, span.start);
            CHECK_EQ(result.error().span.end, span.end);
            CHECK_EQ(result.error().span.line, span.line);
            CHECK_EQ(result.error().span.col, span.col);
        }
    };
    const auto with_timeout = [&](nginx::Server model) {
        model.location.proxy_read_timeout.present = true;
        model.location.proxy_read_timeout.milliseconds = 1000;
        model.location.proxy_read_timeout.span = model.location.proxy_pass.span;
        model.location.proxy_read_timeout.value_span = model.location.proxy_pass.uri_span;
        return model;
    };

    auto forged = accepted;
    forged.location.path.ptr = nullptr;
    expect_rejected(
        forged, lit_str("invalid proxy_pass source provenance"), accepted.location.path_span);

    forged = with_timeout(accepted);
    forged.location.path.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    forged.listen.port = 0;
    forged.location.proxy_pass.port = 0;
    expect_rejected(
        forged, lit_str("invalid proxy_pass source provenance"), accepted.location.path_span);

    forged = accepted;
    forged.location.path.ptr = reinterpret_cast<const char*>(UINTPTR_MAX);
    expect_rejected(
        forged, lit_str("invalid proxy_pass source provenance"), accepted.location.path_span);

    forged = accepted;
    forged.location.proxy_pass.uri.ptr = nullptr;
    expect_rejected(forged,
                    lit_str("invalid bounded proxy_pass URI model"),
                    accepted.location.proxy_pass.uri_span);

    forged = with_timeout(accepted);
    forged.location.proxy_pass.uri.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    forged.listen.port = 0;
    forged.location.proxy_pass.port = 0;
    expect_rejected(forged,
                    lit_str("invalid proxy_pass URI provenance"),
                    accepted.location.proxy_pass.uri_span);

    forged = accepted;
    forged.location.proxy_pass.uri.ptr = reinterpret_cast<const char*>(UINTPTR_MAX);
    expect_rejected(forged,
                    lit_str("invalid proxy_pass URI provenance"),
                    accepted.location.proxy_pass.uri_span);

    forged = accepted;
    forged.location.span.end = forged.span.end + 1u;
    expect_rejected(forged, lit_str("invalid proxy location spans"), forged.location.span);

    forged = accepted;
    forged.location.path_span.end--;
    expect_rejected(forged, lit_str("invalid proxy location spans"), forged.location.path_span);

    forged = accepted;
    forged.location.path_span.start = forged.location.span.start - 1u;
    expect_rejected(forged, lit_str("invalid proxy location spans"), forged.location.path_span);

    forged = accepted;
    forged.location.path_span.end = forged.location.proxy_pass.span.start;
    forged.location.path.len = forged.location.path_span.end - forged.location.path_span.start;
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.span);

    forged = accepted;
    forged.location.proxy_pass.span.start = forged.location.span.start - 1u;
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.span);

    forged = accepted;
    forged.location.proxy_pass.uri_span.start = forged.location.proxy_pass.span.start - 1u;
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);

    forged = accepted;
    forged.location.proxy_pass.uri_span.end--;
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);

    forged = accepted;
    forged.location.proxy_pass.uri_span = {};
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.span);

    forged = accepted;
    forged.location.span.line++;
    forged.location.path_span.line++;
    forged.location.proxy_pass.span.line++;
    forged.location.proxy_pass.uri_span.line++;
    expect_rejected(
        forged, lit_str("invalid proxy location source positions"), forged.location.span);

    forged = accepted;
    forged.location.path_span.line++;
    expect_rejected(
        forged, lit_str("invalid proxy location source positions"), forged.location.path_span);

    forged = accepted;
    forged.location.path_span.col++;
    expect_rejected(forged, lit_str("invalid proxy location spans"), forged.location.path_span);

    forged = accepted;
    forged.location.proxy_pass.span.line++;
    forged.location.proxy_pass.uri_span.line++;
    expect_rejected(forged,
                    lit_str("invalid proxy location source positions"),
                    forged.location.proxy_pass.span);

    forged = accepted;
    forged.location.proxy_pass.uri_span.line++;
    expect_rejected(forged,
                    lit_str("invalid proxy location source positions"),
                    forged.location.proxy_pass.uri_span);

    forged = accepted;
    forged.location.proxy_pass.uri_span.col++;
    expect_rejected(
        forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);

    static constexpr char kExternalPath[] = "/service/";
    forged = accepted;
    forged.location.path = {kExternalPath, sizeof(kExternalPath) - 1u};
    expect_rejected(forged,
                    lit_str("invalid proxy_pass URI provenance"),
                    accepted.location.proxy_pass.uri_span);

    static constexpr char kExternalUri[] = "/v1/";
    forged = accepted;
    forged.location.proxy_pass.uri = {kExternalUri, sizeof(kExternalUri) - 1u};
    expect_rejected(forged,
                    lit_str("invalid proxy_pass URI provenance"),
                    accepted.location.proxy_pass.uri_span);

    forged = with_timeout(accepted);
    forged.location.path.len = nginx::kMaxProxyLocationPathLen + 1u;
    expect_rejected(forged, lit_str("invalid bounded proxy location path model"));

    forged = accepted;
    forged.location.proxy_pass.has_uri = false;
    forged.location.proxy_pass.uri = {};
    forged.location.proxy_pass.uri_span = {};
    expect_rejected(
        forged, lit_str("invalid upstream endpoint model"), accepted.location.proxy_pass.span);

    auto legacy_generic = api_server();
    static constexpr char kFiveByteGeneric[] = "/abc/";
    legacy_generic.location.path = {kFiveByteGeneric, sizeof(kFiveByteGeneric) - 1u};
    expect_rejected(legacy_generic, lit_str("invalid historical /api/ proxy model"));

    const char five_byte[] =
        "server { listen 8080; location /abc/ { proxy_pass http://127.0.0.1:9000/; } }";
    const auto five_byte_parsed = nginx::parse({five_byte, sizeof(five_byte) - 1u});
    REQUIRE(five_byte_parsed);
    REQUIRE(nginx::lower_to_rut(five_byte_parsed.value()));
    forged = five_byte_parsed.value();
    forged.location.path.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    expect_rejected(forged,
                    lit_str("invalid proxy_pass source provenance"),
                    five_byte_parsed.value().location.path_span);

    char parsed_api_source[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/; } }";
    const auto parsed_api = nginx::parse({parsed_api_source, sizeof(parsed_api_source) - 1u});
    REQUIRE(parsed_api);
    REQUIRE(nginx::lower_to_rut(parsed_api.value()));
    forged = parsed_api.value();
    forged.location.path.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    expect_rejected(forged,
                    lit_str("invalid proxy_pass source provenance"),
                    parsed_api.value().location.path_span);
    forged = parsed_api.value();
    forged.location.proxy_pass.uri.ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(1));
    expect_rejected(forged,
                    lit_str("invalid proxy_pass URI provenance"),
                    parsed_api.value().location.proxy_pass.uri_span);

    char* path = source + accepted.location.path_span.start;
    REQUIRE((Str{path, accepted.location.path.len}.eq(lit_str("/service/"))));
    path[1] = '%';
    expect_rejected(accepted, lit_str("invalid bounded proxy location path model"));
    path[1] = 's';
    path[accepted.location.path.len - 1u] = 'x';
    expect_rejected(accepted, lit_str("invalid bounded proxy location path model"));
}

TEST(nginx_converter, lowers_clean_non_root_proxy_uri_to_full_byte_stable_source) {
    const char formatted[] =
        "server {\n"
        "  listen 8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/;\n"
        "  }\n"
        "}\n";
    const char compact[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000/v1/; } }";
    const auto formatted_parsed = nginx::parse({formatted, sizeof(formatted) - 1u});
    const auto compact_parsed = nginx::parse({compact, sizeof(compact) - 1u});
    REQUIRE(formatted_parsed);
    REQUIRE(compact_parsed);
    REQUIRE(formatted_parsed.value().location.proxy_pass.uri.eq(lit_str("/v1/")));

    const auto formatted_lowered = nginx::lower_to_rut(formatted_parsed.value());
    const auto compact_lowered = nginx::lower_to_rut(compact_parsed.value());
    const auto slash_lowered = nginx::lower_to_rut(api_server());
    REQUIRE(formatted_lowered);
    REQUIRE(compact_lowered);
    REQUIRE(slash_lowered);
    CHECK(formatted_lowered.value().view().eq(compact_lowered.value().view()));

    // The existing `/api/ -> /` hard-coded golden proves the complete baseline.
    // These adjacent prefix/replacement/suffix partitions cover every output byte
    // and prove that this increment changes only the ordinary-RUT replacement value.
    static constexpr char kMarker[] = "            replace_prefix: \"";
    const char* slash_marker = strstr(slash_lowered.value().data, kMarker);
    const char* v1_marker = strstr(formatted_lowered.value().data, kMarker);
    REQUIRE(slash_marker != nullptr);
    REQUIRE(v1_marker != nullptr);
    const char* slash_replacement = slash_marker + sizeof(kMarker) - 1u;
    const char* v1_replacement = v1_marker + sizeof(kMarker) - 1u;
    const u32 prefix_len = static_cast<u32>(slash_replacement - slash_lowered.value().data);
    CHECK_EQ(prefix_len, static_cast<u32>(v1_replacement - formatted_lowered.value().data));
    CHECK((Str{formatted_lowered.value().data, prefix_len}.eq(
        {slash_lowered.value().data, prefix_len})));
    CHECK((Str{v1_replacement, 4}.eq(lit_str("/v1/"))));
    REQUIRE_EQ(slash_replacement[0], '/');
    const char* slash_suffix = slash_replacement + 1;
    const char* v1_suffix = v1_replacement + 4;
    const u32 slash_suffix_len =
        static_cast<u32>(slash_lowered.value().data + slash_lowered.value().len - slash_suffix);
    const u32 v1_suffix_len = static_cast<u32>(formatted_lowered.value().data +
                                               formatted_lowered.value().len - v1_suffix);
    REQUIRE_EQ(v1_suffix_len, slash_suffix_len);
    CHECK((Str{v1_suffix, v1_suffix_len}.eq({slash_suffix, slash_suffix_len})));
    CHECK_EQ(formatted_lowered.value().len, slash_lowered.value().len + 3u);
    CHECK_EQ(formatted_lowered.value().len, 3336u);
    CHECK_LT(formatted_lowered.value().len, nginx::RutSource::kCapacity);
}

TEST(nginx_parser, parses_explicit_ipv4_wildcard_listen_with_exact_spans_and_lifetime) {
    char listen_first[] =
        "server {\n"
        "  listen 0.0.0.0:8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    char location_first[] =
        "server {\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  listen 0.0.0.0:8080;\n"
        "}\n";

    const auto check = [&](char* source, u32 len, u32 expected_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const char* directive = strstr(source, "listen 0.0.0.0:8080");
        REQUIRE(directive != nullptr);
        const char* semicolon = strchr(directive, ';');
        REQUIRE(semicolon != nullptr);
        const auto& listen = parsed.value().listen;
        const char* endpoint = directive + strlen("listen ");
        CHECK(listen.address == ListenerAddress::IPv4Wildcard);
        CHECK_EQ(listen.ipv4_host, 0u);
        CHECK_EQ(listen.port, 8080u);
        CHECK(listen.value.eq(lit_str("0.0.0.0:8080")));
        CHECK_EQ(listen.value.ptr, endpoint);
        CHECK_EQ(listen.value_span.start, static_cast<u32>(endpoint - source));
        CHECK_EQ(listen.value_span.end, static_cast<u32>(semicolon - source));
        CHECK_EQ(listen.value_span.line, expected_line);
        CHECK_EQ(listen.value_span.col, 10u);
        CHECK_EQ(listen.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(listen.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(listen.span.line, expected_line);
        CHECK_EQ(listen.span.col, 3u);

        // The endpoint view borrows source, while the normalized address/port
        // and provenance spans remain usable after that source is gone.
        const nginx::Listen retained = listen;
        memset(source, 'x', len);
        CHECK(retained.address == ListenerAddress::IPv4Wildcard);
        CHECK_EQ(retained.ipv4_host, 0u);
        CHECK_EQ(retained.port, 8080u);
        CHECK_EQ(retained.value_span.start, static_cast<u32>(endpoint - source));
        CHECK_EQ(retained.value_span.end, static_cast<u32>(semicolon - source));
        CHECK_EQ(retained.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(retained.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(retained.span.line, expected_line);
        CHECK_EQ(retained.span.col, 3u);
    };
    check(listen_first, sizeof(listen_first) - 1u, 2u);
    check(location_first, sizeof(location_first) - 1u, 3u);

    struct Boundary {
        const char* token;
        u16 port;
    };
    const Boundary boundaries[] = {{"0.0.0.0:1", 1u}, {"0.0.0.0:65535", 65535u}};
    for (const auto& boundary : boundaries) {
        char source[160]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen %s; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } }",
                                 boundary.token);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        CHECK_EQ(parsed.value().listen.port, boundary.port);
        const char* directive = strstr(source, "listen ");
        const char* semicolon = directive == nullptr ? nullptr : strchr(directive, ';');
        REQUIRE(directive != nullptr);
        REQUIRE(semicolon != nullptr);
        CHECK_EQ(parsed.value().listen.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(parsed.value().listen.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(parsed.value().listen.span.line, 1u);
        CHECK_EQ(parsed.value().listen.span.col, 10u);
    }
}

TEST(nginx_parser, parses_asterisk_ipv4_wildcard_listen_with_exact_spans_and_lifetime) {
    char listen_first[] =
        "server {\n"
        "  listen *:8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    char location_first[] =
        "server {\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  listen *:8080;\n"
        "}\n";

    const auto check = [&](char* source, u32 len, u32 expected_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const char* directive = strstr(source, "listen *:8080");
        REQUIRE(directive != nullptr);
        const char* semicolon = strchr(directive, ';');
        REQUIRE(semicolon != nullptr);
        const auto& listen = parsed.value().listen;
        const char* endpoint = directive + strlen("listen ");
        CHECK(listen.address == ListenerAddress::IPv4Wildcard);
        CHECK_EQ(listen.ipv4_host, 0u);
        CHECK_EQ(listen.port, 8080u);
        CHECK(listen.value.eq(lit_str("*:8080")));
        CHECK_EQ(listen.value.ptr, endpoint);
        CHECK_EQ(listen.value_span.start, static_cast<u32>(endpoint - source));
        CHECK_EQ(listen.value_span.end, static_cast<u32>(semicolon - source));
        CHECK_EQ(listen.value_span.line, expected_line);
        CHECK_EQ(listen.value_span.col, 10u);
        CHECK_EQ(listen.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(listen.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(listen.span.line, expected_line);
        CHECK_EQ(listen.span.col, 3u);

        const nginx::Listen retained = listen;
        memset(source, 'x', len);
        CHECK(retained.address == ListenerAddress::IPv4Wildcard);
        CHECK_EQ(retained.ipv4_host, 0u);
        CHECK_EQ(retained.port, 8080u);
        CHECK_EQ(retained.value_span.start, static_cast<u32>(endpoint - source));
        CHECK_EQ(retained.value_span.end, static_cast<u32>(semicolon - source));
        CHECK_EQ(retained.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(retained.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(retained.span.line, expected_line);
        CHECK_EQ(retained.span.col, 3u);
    };
    check(listen_first, sizeof(listen_first) - 1u, 2u);
    check(location_first, sizeof(location_first) - 1u, 3u);

    struct Boundary {
        const char* token;
        u16 port;
    };
    const Boundary boundaries[] = {{"*:1", 1u}, {"*:65535", 65535u}};
    for (const auto& boundary : boundaries) {
        char source[160]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen %s; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } }",
                                 boundary.token);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        CHECK_EQ(parsed.value().listen.port, boundary.port);
        const char* directive = strstr(source, "listen ");
        const char* semicolon = directive == nullptr ? nullptr : strchr(directive, ';');
        REQUIRE(directive != nullptr);
        REQUIRE(semicolon != nullptr);
        CHECK_EQ(parsed.value().listen.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(parsed.value().listen.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(parsed.value().listen.span.line, 1u);
        CHECK_EQ(parsed.value().listen.span.col, 10u);
    }
}

TEST(nginx_parser, parses_exact_loopback_listen_with_endpoint_provenance_and_owned_lowering) {
    char listen_first[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    char location_first[] =
        "server {\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  listen 127.0.0.1:8080;\n"
        "}\n";
    std::string generated[2];

    const auto check = [&](char* source, u32 len, u32 expected_line, std::string& output) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const char* directive = strstr(source, "listen 127.0.0.1:8080");
        REQUIRE(directive != nullptr);
        const char* endpoint = directive + strlen("listen ");
        const char* semicolon = strchr(endpoint, ';');
        REQUIRE(semicolon != nullptr);
        const auto& listener = parsed.value().listen;
        CHECK(listener.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(listener.ipv4_host, 0x7f000001u);
        CHECK_EQ(listener.port, 8080u);
        CHECK(listener.value.eq(lit_str("127.0.0.1:8080")));
        CHECK_EQ(listener.value.ptr, endpoint);
        CHECK_EQ(listener.value_span.start, static_cast<u32>(endpoint - source));
        CHECK_EQ(listener.value_span.end, static_cast<u32>(semicolon - source));
        CHECK_EQ(listener.value_span.line, expected_line);
        CHECK_EQ(listener.value_span.col, 10u);
        CHECK_EQ(listener.span.start, static_cast<u32>(directive - source));
        CHECK_EQ(listener.span.end, static_cast<u32>(semicolon - source + 1u));
        CHECK_EQ(listener.span.line, expected_line);
        CHECK_EQ(listener.span.col, 3u);

        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        output.assign(lowered.value().data, lowered.value().len);
        const nginx::Listen retained = listener;
        memset(source, 'x', len);
        CHECK(retained.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.port, 8080u);
        CHECK_EQ(retained.value_span.start, static_cast<u32>(endpoint - source));
        CHECK_EQ(retained.value_span.end, static_cast<u32>(semicolon - source));
        CHECK_EQ(output.rfind("listen 127.0.0.1:8080\n", 0u), 0u);
    };
    check(listen_first, sizeof(listen_first) - 1u, 2u, generated[0]);
    check(location_first, sizeof(location_first) - 1u, 3u, generated[1]);
    CHECK_EQ(generated[0], generated[1]);

    struct Boundary {
        const char* endpoint;
        u16 port;
    };
    const Boundary boundaries[] = {
        {"127.0.0.1:1", 1u}, {"127.0.0.1:00001", 1u}, {"127.0.0.1:65535", 65535u}};
    for (const auto& boundary : boundaries) {
        char source[160]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { listen %s; location / { proxy_pass "
                                 "http://127.0.0.1:9000; } }",
                                 boundary.endpoint);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE(parsed);
        CHECK(parsed.value().listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(parsed.value().listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(parsed.value().listen.port, boundary.port);
        CHECK(parsed.value().listen.value.eq(
            {boundary.endpoint, static_cast<u32>(strlen(boundary.endpoint))}));
    }
}

TEST(nginx_parser, issue348_combines_exact_loopback_no_content_and_root_proxy_with_provenance) {
    char exact_then_root[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location = /static { return 204; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    char root_then_exact[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 204; }\n"
        "}\n";

    const auto check = [&](char* source, u32 len, u32 exact_line, u32 root_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& listener = server.listen;
        const auto& root = server.location;
        const auto& proxy = root.proxy_pass;
        const auto& exact = server.exact_no_content_return;
        const auto& response = exact.response;

        const char* server_start = strstr(source, "server {");
        const char* server_close = strrchr(source, '}');
        const char* listen_start = strstr(source, "listen 127.0.0.1:8080");
        const char* listen_endpoint = listen_start == nullptr ? nullptr : listen_start + 7u;
        const char* listen_semicolon =
            listen_endpoint == nullptr ? nullptr : strchr(listen_endpoint, ';');
        const char* root_start = strstr(source, "location / {");
        const char* root_close = root_start == nullptr ? nullptr : strchr(root_start, '}');
        const char* root_path = root_start == nullptr ? nullptr : strchr(root_start, '/');
        const char* proxy_start =
            root_start == nullptr ? nullptr : strstr(root_start, "proxy_pass");
        const char* proxy_semicolon = proxy_start == nullptr ? nullptr : strchr(proxy_start, ';');
        const char* exact_start = strstr(source, "location = /static");
        const char* exact_close = exact_start == nullptr ? nullptr : strchr(exact_start, '}');
        const char* exact_path = exact_start == nullptr ? nullptr : strstr(exact_start, "/static");
        const char* return_start = exact_start == nullptr ? nullptr : strstr(exact_start, "return");
        const char* status = return_start == nullptr ? nullptr : strstr(return_start, "204");
        const char* return_semicolon = status == nullptr ? nullptr : strchr(status, ';');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_close != nullptr);
        REQUIRE(listen_start != nullptr);
        REQUIRE(listen_endpoint != nullptr);
        REQUIRE(listen_semicolon != nullptr);
        REQUIRE(root_start != nullptr);
        REQUIRE(root_close != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(proxy_start != nullptr);
        REQUIRE(proxy_semicolon != nullptr);
        REQUIRE(exact_start != nullptr);
        REQUIRE(exact_close != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(return_start != nullptr);
        REQUIRE(status != nullptr);
        REQUIRE(return_semicolon != nullptr);

        const auto offset = [&](const char* pointer) { return static_cast<u32>(pointer - source); };
        const auto line = [&](const char* pointer) {
            u32 result = 1u;
            for (const char* cursor = source; cursor != pointer; ++cursor) {
                if (*cursor == '\n') result++;
            }
            return result;
        };
        const auto column = [&](const char* pointer) {
            const char* line_start = pointer;
            while (line_start != source && line_start[-1] != '\n') line_start--;
            return static_cast<u32>(pointer - line_start + 1u);
        };
        const auto check_span = [&](Span span, const char* start, const char* end) {
            CHECK_EQ(span.start, offset(start));
            CHECK_EQ(span.end, offset(end));
            CHECK_EQ(span.line, line(start));
            CHECK_EQ(span.col, column(start));
        };

        check_span(server.span, server_start, server_close + 1u);
        CHECK_EQ(server.span.start, 0u);
        CHECK_EQ(server.span.end, len - 1u);
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, 1u);

        CHECK(listener.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(listener.ipv4_host, 0x7f000001u);
        CHECK_EQ(listener.port, 8080u);
        CHECK(listener.value.eq(lit_str("127.0.0.1:8080")));
        CHECK_EQ(listener.value.ptr, listen_endpoint);
        check_span(listener.value_span, listen_endpoint, listen_semicolon);
        check_span(listener.span, listen_start, listen_semicolon + 1u);
        CHECK_EQ(listener.span.line, 2u);
        CHECK_EQ(listener.span.col, 3u);
        CHECK_EQ(listener.value_span.line, 2u);
        CHECK_EQ(listener.value_span.col, 10u);

        CHECK(root.path.eq(lit_str("/")));
        CHECK_EQ(root.path.ptr, root_path);
        check_span(root.path_span, root_path, root_path + 1u);
        check_span(root.span, root_start, root_close + 1u);
        CHECK_EQ(root.span.line, root_line);
        CHECK_EQ(root.path_span.line, root_line);
        CHECK_EQ(root.span.col, 3u);
        CHECK_EQ(root.path_span.col, column(root_path));
        CHECK_EQ(proxy.address[0], 127u);
        CHECK_EQ(proxy.address[1], 0u);
        CHECK_EQ(proxy.address[2], 0u);
        CHECK_EQ(proxy.address[3], 1u);
        CHECK_EQ(proxy.port, 9000u);
        CHECK_FALSE(proxy.has_uri);
        CHECK_EQ(proxy.uri.ptr, nullptr);
        CHECK_EQ(proxy.uri.len, 0u);
        check_span(proxy.span, proxy_start, proxy_semicolon + 1u);
        CHECK_EQ(proxy.span.line, root_line);
        CHECK_EQ(proxy.span.col, column(proxy_start));

        REQUIRE(exact.present);
        CHECK(exact.path.eq(lit_str("/static")));
        CHECK_EQ(exact.path.ptr, exact_path);
        check_span(exact.path_span, exact_path, exact_path + 7u);
        check_span(exact.span, exact_start, exact_close + 1u);
        CHECK_EQ(exact.span.line, exact_line);
        CHECK_EQ(exact.path_span.line, exact_line);
        CHECK_EQ(exact.span.col, 3u);
        CHECK_EQ(exact.path_span.col, column(exact_path));
        CHECK_EQ(response.status, 204u);
        check_span(response.status_span, status, status + 3u);
        check_span(response.span, return_start, return_semicolon + 1u);
        CHECK_EQ(response.status_span.line, exact_line);
        CHECK_EQ(response.span.line, exact_line);
        CHECK_EQ(response.status_span.col, column(status));
        CHECK_EQ(response.span.col, column(return_start));

        CHECK_FALSE(server.exact_local_return.present);
        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        CHECK_EQ(reinterpret_cast<uintptr_t>(listener.value.ptr) - listener.value_span.start,
                 source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(root.path.ptr) - root.path_span.start, source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(exact.path.ptr) - exact.path_span.start, source_base);

        const auto expect_rejected =
            [&](const nginx::Server& candidate, Str detail, Span expected_span) {
                const auto lowered = nginx::lower_to_rut(candidate);
                REQUIRE_FALSE(lowered);
                CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
                CHECK(lowered.error().detail.eq(detail));
                CHECK_EQ(lowered.error().span.start, expected_span.start);
                CHECK_EQ(lowered.error().span.end, expected_span.end);
                CHECK_EQ(lowered.error().span.line, expected_span.line);
                CHECK_EQ(lowered.error().span.col, expected_span.col);
            };
        const auto valid_lowering = nginx::lower_to_rut(server);
        REQUIRE(valid_lowering);
        CHECK(valid_lowering.value()
                  .view()
                  .slice(0u, strlen("listen 127.0.0.1:8080\n"))
                  .eq(lit_str("listen 127.0.0.1:8080\n")));
        CHECK(strstr(valid_lowering.value().data, "route exact slash_normalized GET \"/static\"") !=
              nullptr);

        std::vector<char> independent_source(source, source + len);
        auto forged = server;
        forged.listen.value.ptr = independent_source.data() + forged.listen.value_span.start;
        expect_rejected(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.exact_no_content_return.path.ptr =
            independent_source.data() + forged.exact_no_content_return.path_span.start;
        expect_rejected(forged,
                        lit_str("invalid exact no-content return path provenance"),
                        forged.exact_no_content_return.path_span);

        forged = server;
        forged.listen.address = ListenerAddress::IPv4Wildcard;
        expect_rejected(forged, lit_str("invalid model listen address"), forged.listen.span);

        forged = server;
        forged.listen.ipv4_host = 0u;
        expect_rejected(forged, lit_str("invalid model listen address"), forged.listen.span);

        forged = server;
        forged.listen.port = 8081u;
        expect_rejected(
            forged, lit_str("invalid exact listen endpoint model"), forged.listen.value_span);

        char bodyful_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
            "location = /body { return 200 \"ok\"; } }";
        const auto bodyful = nginx::parse({bodyful_source, sizeof(bodyful_source) - 1u});
        REQUIRE(bodyful);
        forged = server;
        forged.exact_local_return = bodyful.value().exact_local_return;
        expect_rejected(forged,
                        lit_str("multiple exact semantic actions are unsupported"),
                        forged.exact_local_return.span);

        char redirect_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
            "location = /old { return 301 http://redirect.example/new; } }";
        const auto redirect = nginx::parse({redirect_source, sizeof(redirect_source) - 1u});
        REQUIRE(redirect);
        forged = server;
        forged.exact_absolute_redirect = redirect.value().exact_absolute_redirect;
        expect_rejected(forged,
                        lit_str("multiple exact semantic actions are unsupported"),
                        forged.exact_absolute_redirect.span);

        const nginx::Server retained = server;
        const Span retained_server_span = server.span;
        const Span retained_listener_span = listener.span;
        const Span retained_listener_value_span = listener.value_span;
        const Span retained_root_span = root.span;
        const Span retained_proxy_span = proxy.span;
        const Span retained_exact_span = exact.span;
        const Span retained_exact_path_span = exact.path_span;
        const Span retained_response_span = response.span;
        const Span retained_status_span = response.status_span;
        memset(source, 'x', len);
        CHECK(valid_lowering.value()
                  .view()
                  .slice(0u, strlen("listen 127.0.0.1:8080\n"))
                  .eq(lit_str("listen 127.0.0.1:8080\n")));
        CHECK(strstr(valid_lowering.value().data, "route exact slash_normalized GET \"/static\"") !=
              nullptr);
        CHECK(retained.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.listen.port, 8080u);
        CHECK_EQ(retained.location.proxy_pass.address[0], 127u);
        CHECK_EQ(retained.location.proxy_pass.address[1], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[2], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[3], 1u);
        CHECK_EQ(retained.location.proxy_pass.port, 9000u);
        CHECK(retained.exact_no_content_return.present);
        CHECK_EQ(retained.exact_no_content_return.response.status, 204u);
        const auto check_retained_span = [&](Span actual, Span expected) {
            CHECK_EQ(actual.start, expected.start);
            CHECK_EQ(actual.end, expected.end);
            CHECK_EQ(actual.line, expected.line);
            CHECK_EQ(actual.col, expected.col);
        };
        check_retained_span(retained.span, retained_server_span);
        check_retained_span(retained.listen.span, retained_listener_span);
        check_retained_span(retained.listen.value_span, retained_listener_value_span);
        check_retained_span(retained.location.span, retained_root_span);
        check_retained_span(retained.location.proxy_pass.span, retained_proxy_span);
        check_retained_span(retained.exact_no_content_return.span, retained_exact_span);
        check_retained_span(retained.exact_no_content_return.path_span, retained_exact_path_span);
        check_retained_span(retained.exact_no_content_return.response.span, retained_response_span);
        check_retained_span(retained.exact_no_content_return.response.status_span,
                            retained_status_span);
        CHECK_EQ(retained.pre_route_trace.span.start, retained_server_span.start);
        CHECK_EQ(retained.pre_route_trace.span.end, retained_server_span.end);
    };

    check(exact_then_root, sizeof(exact_then_root) - 1u, 3u, 4u);
    check(root_then_exact, sizeof(root_then_exact) - 1u, 4u, 3u);

    char maximum_path[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    maximum_path[0] = '/';
    memset(maximum_path + 1u, 'a', nginx::kMaxExactLocalReturnPathLen - 1u);
    char maximum_source[512]{};
    const int maximum_len =
        snprintf(maximum_source,
                 sizeof(maximum_source),
                 "server { listen 127.0.0.1:65535; location = %s { return 204; } "
                 "location / { proxy_pass http://255.255.255.255:65535; } }",
                 maximum_path);
    REQUIRE_GT(maximum_len, 0);
    REQUIRE_LT(static_cast<u32>(maximum_len), static_cast<u32>(sizeof(maximum_source)));
    const auto maximum = nginx::parse({maximum_source, static_cast<u32>(maximum_len)});
    REQUIRE(maximum);
    const char* maximum_listen = strstr(maximum_source, "listen 127.0.0.1:65535");
    const char* maximum_endpoint =
        maximum_listen == nullptr ? nullptr : maximum_listen + strlen("listen ");
    const char* maximum_listen_end =
        maximum_endpoint == nullptr ? nullptr : strchr(maximum_endpoint, ';');
    const char* maximum_exact = strstr(maximum_source, "location = /");
    const char* maximum_exact_path =
        maximum_exact == nullptr ? nullptr : strchr(maximum_exact, '/');
    const char* maximum_exact_end = maximum_exact == nullptr ? nullptr : strchr(maximum_exact, '}');
    const char* maximum_return =
        maximum_exact == nullptr ? nullptr : strstr(maximum_exact, "return");
    const char* maximum_status =
        maximum_return == nullptr ? nullptr : strstr(maximum_return, "204");
    const char* maximum_return_end =
        maximum_status == nullptr ? nullptr : strchr(maximum_status, ';');
    const char* maximum_root = strstr(maximum_source, "location / {");
    const char* maximum_root_path = maximum_root == nullptr ? nullptr : strchr(maximum_root, '/');
    const char* maximum_root_end = maximum_root == nullptr ? nullptr : strchr(maximum_root, '}');
    const char* maximum_proxy =
        maximum_root == nullptr ? nullptr : strstr(maximum_root, "proxy_pass");
    const char* maximum_proxy_end = maximum_proxy == nullptr ? nullptr : strchr(maximum_proxy, ';');
    REQUIRE(maximum_listen != nullptr);
    REQUIRE(maximum_endpoint != nullptr);
    REQUIRE(maximum_listen_end != nullptr);
    REQUIRE(maximum_exact != nullptr);
    REQUIRE(maximum_exact_path != nullptr);
    REQUIRE(maximum_exact_end != nullptr);
    REQUIRE(maximum_return != nullptr);
    REQUIRE(maximum_status != nullptr);
    REQUIRE(maximum_return_end != nullptr);
    REQUIRE(maximum_root != nullptr);
    REQUIRE(maximum_root_path != nullptr);
    REQUIRE(maximum_root_end != nullptr);
    REQUIRE(maximum_proxy != nullptr);
    REQUIRE(maximum_proxy_end != nullptr);
    const auto maximum_offset = [&](const char* pointer) {
        return static_cast<u32>(pointer - maximum_source);
    };
    const auto check_maximum_span = [&](Span span, const char* start, const char* end) {
        CHECK_EQ(span.start, maximum_offset(start));
        CHECK_EQ(span.end, maximum_offset(end));
        CHECK_EQ(span.line, 1u);
        CHECK_EQ(span.col, maximum_offset(start) + 1u);
    };
    CHECK_EQ(maximum.value().span.start, 0u);
    CHECK_EQ(maximum.value().span.end, static_cast<u32>(maximum_len));
    CHECK_EQ(maximum.value().span.line, 1u);
    CHECK_EQ(maximum.value().span.col, 1u);
    CHECK_EQ(maximum.value().listen.port, 65535u);
    CHECK(maximum.value().listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(maximum.value().listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(maximum.value().listen.value.ptr,
             maximum_source + maximum.value().listen.value_span.start);
    CHECK_EQ(maximum.value().listen.value_span.end - maximum.value().listen.value_span.start,
             strlen("127.0.0.1:65535"));
    check_maximum_span(maximum.value().listen.value_span, maximum_endpoint, maximum_listen_end);
    check_maximum_span(maximum.value().listen.span, maximum_listen, maximum_listen_end + 1u);
    CHECK(maximum.value().location.path.eq(lit_str("/")));
    CHECK_EQ(maximum.value().location.path.ptr,
             maximum_source + maximum.value().location.path_span.start);
    check_maximum_span(
        maximum.value().location.path_span, maximum_root_path, maximum_root_path + 1u);
    check_maximum_span(maximum.value().location.span, maximum_root, maximum_root_end + 1u);
    CHECK_EQ(maximum.value().location.proxy_pass.address[0], 255u);
    CHECK_EQ(maximum.value().location.proxy_pass.address[1], 255u);
    CHECK_EQ(maximum.value().location.proxy_pass.address[2], 255u);
    CHECK_EQ(maximum.value().location.proxy_pass.address[3], 255u);
    CHECK_EQ(maximum.value().location.proxy_pass.port, 65535u);
    check_maximum_span(
        maximum.value().location.proxy_pass.span, maximum_proxy, maximum_proxy_end + 1u);
    REQUIRE(maximum.value().exact_no_content_return.present);
    CHECK_EQ(maximum.value().exact_no_content_return.path.len, nginx::kMaxExactLocalReturnPathLen);
    CHECK_EQ(maximum.value().exact_no_content_return.path.ptr,
             maximum_source + maximum.value().exact_no_content_return.path_span.start);
    CHECK_EQ(maximum.value().exact_no_content_return.path_span.end -
                 maximum.value().exact_no_content_return.path_span.start,
             nginx::kMaxExactLocalReturnPathLen);
    check_maximum_span(maximum.value().exact_no_content_return.path_span,
                       maximum_exact_path,
                       maximum_exact_path + nginx::kMaxExactLocalReturnPathLen);
    check_maximum_span(
        maximum.value().exact_no_content_return.span, maximum_exact, maximum_exact_end + 1u);
    CHECK_EQ(maximum.value().exact_no_content_return.response.status, 204u);
    CHECK_EQ(maximum.value().exact_no_content_return.response.status_span.end -
                 maximum.value().exact_no_content_return.response.status_span.start,
             3u);
    check_maximum_span(maximum.value().exact_no_content_return.response.span,
                       maximum_return,
                       maximum_return_end + 1u);
    check_maximum_span(maximum.value().exact_no_content_return.response.status_span,
                       maximum_status,
                       maximum_status + 3u);
    CHECK(maximum.value().pre_route_trace.profile ==
          nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
    CHECK_EQ(maximum.value().pre_route_trace.span.start, maximum.value().span.start);
    CHECK_EQ(maximum.value().pre_route_trace.span.end, maximum.value().span.end);
    const auto maximum_lowering = nginx::lower_to_rut(maximum.value());
    REQUIRE(maximum_lowering);
    CHECK_LT(maximum_lowering.value().len, nginx::RutSource::kCapacity);
    CHECK(maximum_lowering.value()
              .view()
              .slice(0u, strlen("listen 127.0.0.1:65535\n"))
              .eq(lit_str("listen 127.0.0.1:65535\n")));
    CHECK(strstr(maximum_lowering.value().data, "route exact slash_normalized GET \"") != nullptr);
}

TEST(nginx_parser,
     issue349_combines_exact_loopback_bodyful_return_and_root_proxy_with_provenance_fail_closed) {
    char exact_then_root[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location = /static { return 200 \"successor-static\"; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    char root_then_exact[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /static { return 200 \"successor-static\"; }\n"
        "}\n";

    const auto check = [&](char* source, u32 len, u32 exact_line, u32 root_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& listener = server.listen;
        const auto& root = server.location;
        const auto& proxy = root.proxy_pass;
        const auto& exact = server.exact_local_return;
        const auto& response = exact.response;

        const char* server_start = strstr(source, "server {");
        const char* server_close = strrchr(source, '}');
        const char* listen_start = strstr(source, "listen 127.0.0.1:8080");
        const char* listen_endpoint = listen_start == nullptr ? nullptr : listen_start + 7u;
        const char* listen_semicolon =
            listen_endpoint == nullptr ? nullptr : strchr(listen_endpoint, ';');
        const char* root_start = strstr(source, "location / {");
        const char* root_close = root_start == nullptr ? nullptr : strchr(root_start, '}');
        const char* root_path = root_start == nullptr ? nullptr : strchr(root_start, '/');
        const char* proxy_start =
            root_start == nullptr ? nullptr : strstr(root_start, "proxy_pass");
        const char* proxy_semicolon = proxy_start == nullptr ? nullptr : strchr(proxy_start, ';');
        const char* exact_start = strstr(source, "location = /static");
        const char* exact_close = exact_start == nullptr ? nullptr : strchr(exact_start, '}');
        const char* exact_path = exact_start == nullptr ? nullptr : strstr(exact_start, "/static");
        const char* return_start = exact_start == nullptr ? nullptr : strstr(exact_start, "return");
        const char* status = return_start == nullptr ? nullptr : strstr(return_start, "200");
        const char* body = status == nullptr ? nullptr : strstr(status, "successor-static");
        const char* return_semicolon = body == nullptr ? nullptr : strchr(body, ';');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_close != nullptr);
        REQUIRE(listen_start != nullptr);
        REQUIRE(listen_endpoint != nullptr);
        REQUIRE(listen_semicolon != nullptr);
        REQUIRE(root_start != nullptr);
        REQUIRE(root_close != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(proxy_start != nullptr);
        REQUIRE(proxy_semicolon != nullptr);
        REQUIRE(exact_start != nullptr);
        REQUIRE(exact_close != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(return_start != nullptr);
        REQUIRE(status != nullptr);
        REQUIRE(body != nullptr);
        REQUIRE(return_semicolon != nullptr);

        const auto offset = [&](const char* pointer) { return static_cast<u32>(pointer - source); };
        const auto line = [&](const char* pointer) {
            u32 result = 1u;
            for (const char* cursor = source; cursor != pointer; ++cursor) {
                if (*cursor == '\n') result++;
            }
            return result;
        };
        const auto column = [&](const char* pointer) {
            const char* line_start = pointer;
            while (line_start != source && line_start[-1] != '\n') line_start--;
            return static_cast<u32>(pointer - line_start + 1u);
        };
        const auto check_span = [&](Span span, const char* start, const char* end) {
            CHECK_EQ(span.start, offset(start));
            CHECK_EQ(span.end, offset(end));
            CHECK_EQ(span.line, line(start));
            CHECK_EQ(span.col, column(start));
        };

        check_span(server.span, server_start, server_close + 1u);
        CHECK_EQ(server.span.start, 0u);
        CHECK_EQ(server.span.end, len - 1u);
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, 1u);

        CHECK(listener.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(listener.ipv4_host, 0x7f000001u);
        CHECK_EQ(listener.port, 8080u);
        CHECK(listener.value.eq(lit_str("127.0.0.1:8080")));
        CHECK_EQ(listener.value.ptr, listen_endpoint);
        check_span(listener.value_span, listen_endpoint, listen_semicolon);
        check_span(listener.span, listen_start, listen_semicolon + 1u);
        CHECK_EQ(listener.span.line, 2u);
        CHECK_EQ(listener.span.col, 3u);
        CHECK_EQ(listener.value_span.line, 2u);
        CHECK_EQ(listener.value_span.col, 10u);

        CHECK(root.path.eq(lit_str("/")));
        CHECK_EQ(root.path.ptr, root_path);
        check_span(root.path_span, root_path, root_path + 1u);
        check_span(root.span, root_start, root_close + 1u);
        CHECK_EQ(root.span.line, root_line);
        CHECK_EQ(root.span.col, 3u);
        CHECK_EQ(root.path_span.line, root_line);
        CHECK_EQ(proxy.address[0], 127u);
        CHECK_EQ(proxy.address[1], 0u);
        CHECK_EQ(proxy.address[2], 0u);
        CHECK_EQ(proxy.address[3], 1u);
        CHECK_EQ(proxy.port, 9000u);
        CHECK_FALSE(proxy.has_uri);
        CHECK_EQ(proxy.uri.ptr, nullptr);
        CHECK_EQ(proxy.uri.len, 0u);
        check_span(proxy.span, proxy_start, proxy_semicolon + 1u);
        CHECK_EQ(proxy.span.line, root_line);
        CHECK_EQ(proxy.span.col, column(proxy_start));

        REQUIRE(exact.present);
        CHECK(exact.path.eq(lit_str("/static")));
        CHECK_EQ(exact.path.ptr, exact_path);
        check_span(exact.path_span, exact_path, exact_path + 7u);
        check_span(exact.span, exact_start, exact_close + 1u);
        CHECK_EQ(exact.span.line, exact_line);
        CHECK_EQ(exact.span.col, 3u);
        CHECK_EQ(exact.path_span.line, exact_line);
        CHECK_EQ(response.status, 200u);
        CHECK(response.body.eq(lit_str("successor-static")));
        CHECK_EQ(response.body.ptr, body);
        check_span(response.body_span, body, body + sizeof("successor-static") - 1u);
        check_span(response.span, return_start, return_semicolon + 1u);
        CHECK_EQ(response.body_span.line, exact_line);
        CHECK_EQ(response.body_span.col, column(body));
        CHECK_EQ(response.span.line, exact_line);
        CHECK_EQ(response.span.col, column(return_start));
        CHECK_LT(exact.path.len, nginx::kMaxExactLocalReturnPathLen);
        CHECK_LT(response.body.len, nginx::kMaxLocalReturnBodyLen);

        CHECK_FALSE(server.exact_no_content_return.present);
        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        CHECK_EQ(reinterpret_cast<uintptr_t>(listener.value.ptr) - listener.value_span.start,
                 source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(root.path.ptr) - root.path_span.start, source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(exact.path.ptr) - exact.path_span.start, source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(response.body.ptr) - response.body_span.start,
                 source_base);
        CHECK_GE(listener.value_span.start, listener.span.start);
        CHECK_LE(listener.value_span.end, listener.span.end);
        CHECK_GE(root.path_span.start, root.span.start);
        CHECK_LE(proxy.span.end, root.span.end);
        CHECK_GE(exact.path_span.start, exact.span.start);
        CHECK_GE(response.span.start, exact.path_span.end);
        CHECK_LE(response.span.end, exact.span.end);
        CHECK_GT(response.body_span.start, response.span.start);
        CHECK_LT(response.body_span.end, response.span.end);

        const auto expect_rejected =
            [&](const nginx::Server& candidate, Str detail, Span expected_span) {
                const auto lowered = nginx::lower_to_rut(candidate);
                REQUIRE_FALSE(lowered);
                CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
                CHECK(lowered.error().detail.eq(detail));
                CHECK_EQ(lowered.error().span.start, expected_span.start);
                CHECK_EQ(lowered.error().span.end, expected_span.end);
                CHECK_EQ(lowered.error().span.line, expected_span.line);
                CHECK_EQ(lowered.error().span.col, expected_span.col);
            };
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK(lowered.value()
                  .view()
                  .slice(0u, strlen("listen 127.0.0.1:8080\n"))
                  .eq(lit_str("listen 127.0.0.1:8080\n")));
        CHECK(strstr(lowered.value().data,
                     "route exact slash_normalized \"/static\" { return local_response({") !=
              nullptr);

        std::vector<char> independent_source(source, source + len);
        auto forged = server;
        forged.listen.value.ptr = independent_source.data() + forged.listen.value_span.start;
        CHECK_NE(forged.listen.value.ptr, server.listen.value.ptr);
        expect_rejected(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.exact_local_return.path.ptr =
            independent_source.data() + forged.exact_local_return.path_span.start;
        CHECK_NE(forged.exact_local_return.path.ptr, server.exact_local_return.path.ptr);
        expect_rejected(forged,
                        lit_str("invalid exact local return path provenance"),
                        forged.exact_local_return.path_span);

        forged = server;
        forged.exact_local_return.response.body.ptr =
            independent_source.data() + forged.exact_local_return.response.body_span.start;
        CHECK_NE(forged.exact_local_return.response.body.ptr,
                 server.exact_local_return.response.body.ptr);
        expect_rejected(forged,
                        lit_str("invalid exact local return body provenance"),
                        forged.exact_local_return.response.body_span);

        forged = server;
        forged.listen.address = ListenerAddress::IPv4Wildcard;
        CHECK(forged.listen.address != server.listen.address);
        expect_rejected(forged, lit_str("invalid model listen address"), forged.listen.span);

        forged = server;
        forged.listen.ipv4_host = 0u;
        CHECK_NE(forged.listen.ipv4_host, server.listen.ipv4_host);
        expect_rejected(forged, lit_str("invalid model listen address"), forged.listen.span);

        forged = server;
        forged.listen.port = 8081u;
        CHECK_NE(forged.listen.port, server.listen.port);
        expect_rejected(
            forged, lit_str("invalid exact listen endpoint model"), forged.listen.value_span);

        forged = server;
        forged.exact_local_return.response.body.len--;
        CHECK_NE(forged.exact_local_return.response.body.len,
                 server.exact_local_return.response.body.len);
        expect_rejected(forged,
                        lit_str("invalid exact local return body span"),
                        forged.exact_local_return.response.body_span);

        forged = server;
        forged.exact_local_return.response.status = 201u;
        CHECK_NE(forged.exact_local_return.response.status,
                 server.exact_local_return.response.status);
        expect_rejected(forged,
                        lit_str("invalid exact local return status"),
                        forged.exact_local_return.response.span);

        char no_content_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
            "location = /empty { return 204; } }";
        const auto no_content = nginx::parse({no_content_source, sizeof(no_content_source) - 1u});
        REQUIRE(no_content);
        forged = server;
        forged.exact_no_content_return = no_content.value().exact_no_content_return;
        REQUIRE(forged.exact_no_content_return.present);
        expect_rejected(forged,
                        lit_str("multiple exact semantic actions are unsupported"),
                        forged.exact_local_return.span);

        char redirect_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
            "location = /old { return 301 http://redirect.example/new; } }";
        const auto redirect = nginx::parse({redirect_source, sizeof(redirect_source) - 1u});
        REQUIRE(redirect);
        forged = server;
        forged.exact_absolute_redirect = redirect.value().exact_absolute_redirect;
        REQUIRE(forged.exact_absolute_redirect.present);
        expect_rejected(forged,
                        lit_str("multiple exact semantic actions are unsupported"),
                        forged.exact_local_return.span);

        const nginx::Server retained = server;
        const Span retained_server_span = server.span;
        const Span retained_listener_span = listener.span;
        const Span retained_listener_value_span = listener.value_span;
        const Span retained_root_span = root.span;
        const Span retained_root_path_span = root.path_span;
        const Span retained_proxy_span = proxy.span;
        const Span retained_exact_span = exact.span;
        const Span retained_exact_path_span = exact.path_span;
        const Span retained_response_span = response.span;
        const Span retained_body_span = response.body_span;
        memset(source, 'x', len);
        CHECK(retained.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.listen.port, 8080u);
        CHECK_EQ(retained.location.proxy_pass.address[0], 127u);
        CHECK_EQ(retained.location.proxy_pass.address[1], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[2], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[3], 1u);
        CHECK_EQ(retained.location.proxy_pass.port, 9000u);
        CHECK_FALSE(retained.location.proxy_pass.has_uri);
        CHECK(retained.exact_local_return.present);
        CHECK_EQ(retained.exact_local_return.path.len, 7u);
        CHECK_EQ(retained.exact_local_return.response.status, 200u);
        CHECK_EQ(retained.exact_local_return.response.body.len, sizeof("successor-static") - 1u);
        CHECK_FALSE(retained.exact_no_content_return.present);
        CHECK_FALSE(retained.exact_absolute_redirect.present);
        const auto check_retained_span = [&](Span actual, Span expected) {
            CHECK_EQ(actual.start, expected.start);
            CHECK_EQ(actual.end, expected.end);
            CHECK_EQ(actual.line, expected.line);
            CHECK_EQ(actual.col, expected.col);
        };
        check_retained_span(retained.span, retained_server_span);
        check_retained_span(retained.listen.span, retained_listener_span);
        check_retained_span(retained.listen.value_span, retained_listener_value_span);
        check_retained_span(retained.location.span, retained_root_span);
        check_retained_span(retained.location.path_span, retained_root_path_span);
        check_retained_span(retained.location.proxy_pass.span, retained_proxy_span);
        check_retained_span(retained.exact_local_return.span, retained_exact_span);
        check_retained_span(retained.exact_local_return.path_span, retained_exact_path_span);
        check_retained_span(retained.exact_local_return.response.span, retained_response_span);
        check_retained_span(retained.exact_local_return.response.body_span, retained_body_span);
        CHECK_EQ(retained.pre_route_trace.span.start, retained_server_span.start);
        CHECK_EQ(retained.pre_route_trace.span.end, retained_server_span.end);
    };

    check(exact_then_root, sizeof(exact_then_root) - 1u, 3u, 4u);
    check(root_then_exact, sizeof(root_then_exact) - 1u, 4u, 3u);

    char maximum_path[nginx::kMaxExactLocalReturnPathLen + 1u]{};
    maximum_path[0] = '/';
    memset(maximum_path + 1u, 'p', nginx::kMaxExactLocalReturnPathLen - 1u);
    char maximum_body[nginx::kMaxLocalReturnBodyLen + 1u]{};
    memset(maximum_body, 'b', nginx::kMaxLocalReturnBodyLen);
    char maximum_source[768]{};
    const int maximum_len =
        snprintf(maximum_source,
                 sizeof(maximum_source),
                 "server { listen 127.0.0.1:65535; location = %s { return 200 \"%s\"; } "
                 "location / { proxy_pass http://255.255.255.255:65535; } }",
                 maximum_path,
                 maximum_body);
    REQUIRE_GT(maximum_len, 0);
    REQUIRE_LT(static_cast<u32>(maximum_len), static_cast<u32>(sizeof(maximum_source)));
    const auto maximum = nginx::parse({maximum_source, static_cast<u32>(maximum_len)});
    REQUIRE(maximum);
    const auto& maximum_server = maximum.value();
    const auto& maximum_exact = maximum_server.exact_local_return;
    const auto& maximum_response = maximum_exact.response;
    const char* maximum_listen = strstr(maximum_source, "listen 127.0.0.1:65535");
    const char* maximum_endpoint = maximum_listen == nullptr ? nullptr : maximum_listen + 7u;
    const char* maximum_listen_end =
        maximum_endpoint == nullptr ? nullptr : strchr(maximum_endpoint, ';');
    const char* maximum_exact_start = strstr(maximum_source, "location = /");
    const char* maximum_exact_path =
        maximum_exact_start == nullptr ? nullptr : strchr(maximum_exact_start, '/');
    const char* maximum_return =
        maximum_exact_start == nullptr ? nullptr : strstr(maximum_exact_start, "return 200");
    const char* maximum_body_start =
        maximum_return == nullptr ? nullptr : strstr(maximum_return, maximum_body);
    const char* maximum_return_end =
        maximum_body_start == nullptr ? nullptr : strchr(maximum_body_start, ';');
    const char* maximum_exact_end =
        maximum_exact_start == nullptr ? nullptr : strchr(maximum_exact_start, '}');
    const char* maximum_root = strstr(maximum_source, "location / {");
    const char* maximum_root_path = maximum_root == nullptr ? nullptr : strchr(maximum_root, '/');
    const char* maximum_proxy =
        maximum_root == nullptr ? nullptr : strstr(maximum_root, "proxy_pass");
    const char* maximum_proxy_end = maximum_proxy == nullptr ? nullptr : strchr(maximum_proxy, ';');
    const char* maximum_root_end = maximum_root == nullptr ? nullptr : strchr(maximum_root, '}');
    REQUIRE(maximum_listen != nullptr);
    REQUIRE(maximum_endpoint != nullptr);
    REQUIRE(maximum_listen_end != nullptr);
    REQUIRE(maximum_exact_start != nullptr);
    REQUIRE(maximum_exact_path != nullptr);
    REQUIRE(maximum_return != nullptr);
    REQUIRE(maximum_body_start != nullptr);
    REQUIRE(maximum_return_end != nullptr);
    REQUIRE(maximum_exact_end != nullptr);
    REQUIRE(maximum_root != nullptr);
    REQUIRE(maximum_root_path != nullptr);
    REQUIRE(maximum_proxy != nullptr);
    REQUIRE(maximum_proxy_end != nullptr);
    REQUIRE(maximum_root_end != nullptr);
    const auto maximum_offset = [&](const char* pointer) {
        return static_cast<u32>(pointer - maximum_source);
    };
    const auto check_maximum_span = [&](Span span, const char* start, const char* end) {
        CHECK_EQ(span.start, maximum_offset(start));
        CHECK_EQ(span.end, maximum_offset(end));
        CHECK_EQ(span.line, 1u);
        CHECK_EQ(span.col, maximum_offset(start) + 1u);
    };
    CHECK_EQ(maximum_server.span.start, 0u);
    CHECK_EQ(maximum_server.span.end, static_cast<u32>(maximum_len));
    CHECK_EQ(maximum_server.span.line, 1u);
    CHECK_EQ(maximum_server.span.col, 1u);
    CHECK(maximum_server.listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(maximum_server.listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(maximum_server.listen.port, 65535u);
    CHECK_EQ(maximum_server.listen.value.ptr,
             maximum_source + maximum_server.listen.value_span.start);
    check_maximum_span(maximum_server.listen.value_span, maximum_endpoint, maximum_listen_end);
    check_maximum_span(maximum_server.listen.span, maximum_listen, maximum_listen_end + 1u);
    CHECK(maximum_server.location.path.eq(lit_str("/")));
    CHECK_EQ(maximum_server.location.path.ptr,
             maximum_source + maximum_server.location.path_span.start);
    check_maximum_span(
        maximum_server.location.path_span, maximum_root_path, maximum_root_path + 1u);
    check_maximum_span(maximum_server.location.span, maximum_root, maximum_root_end + 1u);
    CHECK_EQ(maximum_server.location.proxy_pass.address[0], 255u);
    CHECK_EQ(maximum_server.location.proxy_pass.address[1], 255u);
    CHECK_EQ(maximum_server.location.proxy_pass.address[2], 255u);
    CHECK_EQ(maximum_server.location.proxy_pass.address[3], 255u);
    CHECK_EQ(maximum_server.location.proxy_pass.port, 65535u);
    CHECK_FALSE(maximum_server.location.proxy_pass.has_uri);
    check_maximum_span(
        maximum_server.location.proxy_pass.span, maximum_proxy, maximum_proxy_end + 1u);
    REQUIRE(maximum_exact.present);
    CHECK_EQ(maximum_exact.path.len, nginx::kMaxExactLocalReturnPathLen);
    CHECK_EQ(maximum_exact.path.ptr, maximum_source + maximum_exact.path_span.start);
    CHECK(maximum_exact.path.eq({maximum_path, nginx::kMaxExactLocalReturnPathLen}));
    check_maximum_span(maximum_exact.path_span,
                       maximum_exact_path,
                       maximum_exact_path + nginx::kMaxExactLocalReturnPathLen);
    check_maximum_span(maximum_exact.span, maximum_exact_start, maximum_exact_end + 1u);
    CHECK_EQ(maximum_response.status, 200u);
    CHECK_EQ(maximum_response.body.len, nginx::kMaxLocalReturnBodyLen);
    CHECK_EQ(maximum_response.body.ptr, maximum_source + maximum_response.body_span.start);
    CHECK(maximum_response.body.eq({maximum_body, nginx::kMaxLocalReturnBodyLen}));
    check_maximum_span(maximum_response.body_span,
                       maximum_body_start,
                       maximum_body_start + nginx::kMaxLocalReturnBodyLen);
    check_maximum_span(maximum_response.span, maximum_return, maximum_return_end + 1u);
    CHECK_FALSE(maximum_server.exact_no_content_return.present);
    CHECK_FALSE(maximum_server.exact_absolute_redirect.present);
    CHECK(maximum_server.pre_route_trace.profile ==
          nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
    CHECK_EQ(maximum_server.pre_route_trace.span.start, maximum_server.span.start);
    CHECK_EQ(maximum_server.pre_route_trace.span.end, maximum_server.span.end);
    CHECK_EQ(maximum_server.pre_route_trace.span.line, maximum_server.span.line);
    CHECK_EQ(maximum_server.pre_route_trace.span.col, maximum_server.span.col);
    CHECK_GE(maximum_server.listen.value_span.start, maximum_server.listen.span.start);
    CHECK_LE(maximum_server.listen.value_span.end, maximum_server.listen.span.end);
    CHECK_GE(maximum_server.location.path_span.start, maximum_server.location.span.start);
    CHECK_LE(maximum_server.location.proxy_pass.span.end, maximum_server.location.span.end);
    CHECK_GE(maximum_exact.path_span.start, maximum_exact.span.start);
    CHECK_GE(maximum_response.span.start, maximum_exact.path_span.end);
    CHECK_LE(maximum_response.span.end, maximum_exact.span.end);
    CHECK_GT(maximum_response.body_span.start, maximum_response.span.start);
    CHECK_LT(maximum_response.body_span.end, maximum_response.span.end);
    const uintptr_t maximum_source_base = reinterpret_cast<uintptr_t>(maximum_source);
    CHECK_EQ(reinterpret_cast<uintptr_t>(maximum_server.listen.value.ptr) -
                 maximum_server.listen.value_span.start,
             maximum_source_base);
    CHECK_EQ(reinterpret_cast<uintptr_t>(maximum_server.location.path.ptr) -
                 maximum_server.location.path_span.start,
             maximum_source_base);
    CHECK_EQ(reinterpret_cast<uintptr_t>(maximum_exact.path.ptr) - maximum_exact.path_span.start,
             maximum_source_base);
    CHECK_EQ(
        reinterpret_cast<uintptr_t>(maximum_response.body.ptr) - maximum_response.body_span.start,
        maximum_source_base);
    const auto maximum_lowering = nginx::lower_to_rut(maximum_server);
    REQUIRE(maximum_lowering);
    CHECK_LT(maximum_lowering.value().len, nginx::RutSource::kCapacity);
    CHECK(maximum_lowering.value()
              .view()
              .slice(0u, strlen("listen 127.0.0.1:65535\n"))
              .eq(lit_str("listen 127.0.0.1:65535\n")));
    CHECK(strstr(maximum_lowering.value().data, "255.255.255.255:65535") != nullptr);
    CHECK(strstr(maximum_lowering.value().data, maximum_path) != nullptr);
    CHECK(strstr(maximum_lowering.value().data, maximum_body) != nullptr);
}

TEST(nginx_parser,
     issue350_combines_exact_loopback_fixed_302_redirect_with_provenance_and_capacity_boundary) {
    char exact_then_root[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location = /old { return 302 http://redirect.example/new; }\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "}\n";
    char root_then_exact[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location / { proxy_pass http://127.0.0.1:9000; }\n"
        "  location = /old { return 302 http://redirect.example/new; }\n"
        "}\n";

    const auto check = [&](char* source, u32 len, u32 exact_line, u32 root_line) {
        const auto parsed = nginx::parse({source, len});
        REQUIRE(parsed);
        const auto& server = parsed.value();
        const auto& listener = server.listen;
        const auto& root = server.location;
        const auto& proxy = root.proxy_pass;
        const auto& exact = server.exact_absolute_redirect;
        const auto& response = exact.response;

        const char* server_start = strstr(source, "server {");
        const char* server_close = strrchr(source, '}');
        const char* listen_start = strstr(source, "listen 127.0.0.1:8080");
        const char* listen_value = listen_start == nullptr ? nullptr : listen_start + 7u;
        const char* listen_semicolon =
            listen_value == nullptr ? nullptr : strchr(listen_value, ';');
        const char* root_start = strstr(source, "location / {");
        const char* root_close = root_start == nullptr ? nullptr : strchr(root_start, '}');
        const char* root_path = root_start == nullptr ? nullptr : strchr(root_start, '/');
        const char* proxy_start =
            root_start == nullptr ? nullptr : strstr(root_start, "proxy_pass");
        const char* proxy_semicolon = proxy_start == nullptr ? nullptr : strchr(proxy_start, ';');
        const char* exact_start = strstr(source, "location = /old");
        const char* exact_close = exact_start == nullptr ? nullptr : strchr(exact_start, '}');
        const char* exact_path = exact_start == nullptr ? nullptr : strstr(exact_start, "/old");
        const char* return_start = exact_start == nullptr ? nullptr : strstr(exact_start, "return");
        const char* status = return_start == nullptr ? nullptr : strstr(return_start, "302");
        const char* target =
            status == nullptr ? nullptr : strstr(status, "http://redirect.example/new");
        const char* authority = target == nullptr ? nullptr : target + 7u;
        const char* target_path = authority == nullptr ? nullptr : authority + 16u;
        const char* return_semicolon = target == nullptr ? nullptr : strchr(target, ';');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_close != nullptr);
        REQUIRE(listen_start != nullptr);
        REQUIRE(listen_value != nullptr);
        REQUIRE(listen_semicolon != nullptr);
        REQUIRE(root_start != nullptr);
        REQUIRE(root_close != nullptr);
        REQUIRE(root_path != nullptr);
        REQUIRE(proxy_start != nullptr);
        REQUIRE(proxy_semicolon != nullptr);
        REQUIRE(exact_start != nullptr);
        REQUIRE(exact_close != nullptr);
        REQUIRE(exact_path != nullptr);
        REQUIRE(return_start != nullptr);
        REQUIRE(status != nullptr);
        REQUIRE(target != nullptr);
        REQUIRE(authority != nullptr);
        REQUIRE(target_path != nullptr);
        REQUIRE(return_semicolon != nullptr);

        const auto offset = [&](const char* pointer) { return static_cast<u32>(pointer - source); };
        const auto line = [&](const char* pointer) {
            u32 result = 1u;
            for (const char* cursor = source; cursor != pointer; ++cursor) {
                if (*cursor == '\n') result++;
            }
            return result;
        };
        const auto column = [&](const char* pointer) {
            const char* line_start = pointer;
            while (line_start != source && line_start[-1] != '\n') line_start--;
            return static_cast<u32>(pointer - line_start + 1u);
        };
        const auto check_span = [&](Span span, const char* start, const char* end) {
            CHECK_EQ(span.start, offset(start));
            CHECK_EQ(span.end, offset(end));
            CHECK_EQ(span.line, line(start));
            CHECK_EQ(span.col, column(start));
        };

        check_span(server.span, server_start, server_close + 1u);
        CHECK_EQ(server.span.start, 0u);
        CHECK_EQ(server.span.end, len - 1u);
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, 1u);

        CHECK(listener.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(listener.ipv4_host, 0x7f000001u);
        CHECK_EQ(listener.port, 8080u);
        CHECK(listener.value.eq(lit_str("127.0.0.1:8080")));
        CHECK_EQ(listener.value.ptr, listen_value);
        check_span(listener.value_span, listen_value, listen_semicolon);
        check_span(listener.span, listen_start, listen_semicolon + 1u);
        CHECK_EQ(listener.span.line, 2u);
        CHECK_EQ(listener.span.col, 3u);
        CHECK_EQ(listener.value_span.line, 2u);
        CHECK_EQ(listener.value_span.col, 10u);

        CHECK(root.path.eq(lit_str("/")));
        CHECK_EQ(root.path.ptr, root_path);
        check_span(root.path_span, root_path, root_path + 1u);
        check_span(root.span, root_start, root_close + 1u);
        CHECK_EQ(root.span.line, root_line);
        CHECK_EQ(root.span.col, 3u);
        CHECK_EQ(root.path_span.line, root_line);
        CHECK_EQ(root.path_span.col, column(root_path));
        CHECK_EQ(proxy.address[0], 127u);
        CHECK_EQ(proxy.address[1], 0u);
        CHECK_EQ(proxy.address[2], 0u);
        CHECK_EQ(proxy.address[3], 1u);
        CHECK_EQ(proxy.port, 9000u);
        CHECK_FALSE(proxy.has_uri);
        CHECK_EQ(proxy.uri.ptr, nullptr);
        CHECK_EQ(proxy.uri.len, 0u);
        CHECK_EQ(proxy.uri_span.start, 0u);
        CHECK_EQ(proxy.uri_span.end, 0u);
        check_span(proxy.span, proxy_start, proxy_semicolon + 1u);
        CHECK_EQ(proxy.span.line, root_line);
        CHECK_EQ(proxy.span.col, column(proxy_start));

        REQUIRE(exact.present);
        CHECK(exact.path.eq(lit_str("/old")));
        CHECK_EQ(exact.path.ptr, exact_path);
        check_span(exact.path_span, exact_path, exact_path + 4u);
        check_span(exact.span, exact_start, exact_close + 1u);
        CHECK_EQ(exact.span.line, exact_line);
        CHECK_EQ(exact.span.col, 3u);
        CHECK_EQ(exact.path_span.line, exact_line);
        CHECK_EQ(response.status, 302u);
        CHECK(response.status_lexeme.eq(lit_str("302")));
        CHECK_EQ(response.status_lexeme.ptr, status);
        check_span(response.status_span, status, status + 3u);
        CHECK(response.target.eq(lit_str("http://redirect.example/new")));
        CHECK_EQ(response.target.ptr, target);
        check_span(response.target_span, target, target + 27u);
        CHECK(response.authority.eq(lit_str("redirect.example")));
        CHECK_EQ(response.authority.ptr, authority);
        check_span(response.authority_span, authority, authority + 16u);
        CHECK(response.path.eq(lit_str("/new")));
        CHECK_EQ(response.path.ptr, target_path);
        check_span(response.path_span, target_path, target_path + 4u);
        check_span(response.span, return_start, return_semicolon + 1u);
        CHECK_EQ(response.span.line, exact_line);
        CHECK_EQ(response.span.col, column(return_start));
        CHECK_EQ(response.status_span.line, exact_line);
        CHECK_EQ(response.target_span.line, exact_line);
        // The model represents the fixed HTTP scheme and query-discard profile
        // through the complete query-free target plus its authority/path views.
        CHECK((Str{response.target.ptr, 7u}.eq(lit_str("http://"))));
        CHECK_EQ(memchr(response.target.ptr, '?', response.target.len), nullptr);

        CHECK_FALSE(server.exact_local_return.present);
        CHECK_FALSE(server.exact_no_content_return.present);
        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        CHECK_EQ(reinterpret_cast<uintptr_t>(listener.value.ptr) - listener.value_span.start,
                 source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(root.path.ptr) - root.path_span.start, source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(exact.path.ptr) - exact.path_span.start, source_base);
        CHECK_EQ(
            reinterpret_cast<uintptr_t>(response.status_lexeme.ptr) - response.status_span.start,
            source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(response.target.ptr) - response.target_span.start,
                 source_base);
        CHECK_EQ(
            reinterpret_cast<uintptr_t>(response.authority.ptr) - response.authority_span.start,
            source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(response.path.ptr) - response.path_span.start,
                 source_base);
        CHECK_GE(listener.value_span.start, listener.span.start);
        CHECK_LE(listener.value_span.end, listener.span.end);
        CHECK_GE(root.path_span.start, root.span.start);
        CHECK_LE(proxy.span.end, root.span.end);
        CHECK_GE(exact.path_span.start, exact.span.start);
        CHECK_GE(response.span.start, exact.path_span.end);
        CHECK_LE(response.span.end, exact.span.end);
        CHECK_GT(response.status_span.start, response.span.start);
        CHECK_GT(response.target_span.start, response.status_span.end);
        CHECK_LT(response.target_span.end, response.span.end);
        CHECK_GE(response.authority_span.start, response.target_span.start);
        CHECK_LE(response.path_span.end, response.target_span.end);

        const auto expect_rejected = [&](const nginx::Server& candidate,
                                         FrontendError code,
                                         Str detail,
                                         Span expected_span) {
            const auto lowered = nginx::lower_to_rut(candidate);
            REQUIRE_FALSE(lowered);
            CHECK_EQ(lowered.error().code, code);
            CHECK(lowered.error().detail.eq(detail));
            CHECK_EQ(lowered.error().span.start, expected_span.start);
            CHECK_EQ(lowered.error().span.end, expected_span.end);
            CHECK_EQ(lowered.error().span.line, expected_span.line);
            CHECK_EQ(lowered.error().span.col, expected_span.col);
        };
        const auto expect_unsupported =
            [&](const nginx::Server& candidate, Str detail, Span expected_span) {
                expect_rejected(candidate, FrontendError::UnsupportedSyntax, detail, expected_span);
            };
        const auto accepted = nginx::lower_to_rut(server);
        REQUIRE(accepted);
        CHECK_EQ(accepted.value().len, 5913u);
        CHECK(accepted.value()
                  .view()
                  .slice(0u, strlen("listen 127.0.0.1:8080\n"))
                  .eq(lit_str("listen 127.0.0.1:8080\n")));

        std::vector<char> independent_source(source, source + len);
        auto forged = server;
        forged.listen.value.ptr = independent_source.data() + forged.listen.value_span.start;
        CHECK_NE(forged.listen.value.ptr, server.listen.value.ptr);
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.location.path.ptr = independent_source.data() + forged.location.path_span.start;
        CHECK_NE(forged.location.path.ptr, server.location.path.ptr);
        // The redirect validator derives its source base from the fallback.
        // Moving only that borrow therefore makes the retained exact path the
        // first field that disagrees with the derived base.
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect location path provenance"),
                           forged.exact_absolute_redirect.path_span);

        forged = server;
        forged.exact_absolute_redirect.path.ptr =
            independent_source.data() + forged.exact_absolute_redirect.path_span.start;
        CHECK_NE(forged.exact_absolute_redirect.path.ptr, server.exact_absolute_redirect.path.ptr);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect location path provenance"),
                           forged.exact_absolute_redirect.path_span);

        forged = server;
        forged.exact_absolute_redirect.response.target.ptr =
            independent_source.data() + forged.exact_absolute_redirect.response.target_span.start;
        CHECK_NE(forged.exact_absolute_redirect.response.target.ptr,
                 server.exact_absolute_redirect.response.target.ptr);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect target provenance"),
                           forged.exact_absolute_redirect.response.target_span);

        forged = server;
        forged.exact_absolute_redirect.response.status_lexeme.ptr =
            independent_source.data() + forged.exact_absolute_redirect.response.status_span.start;
        CHECK_NE(forged.exact_absolute_redirect.response.status_lexeme.ptr,
                 server.exact_absolute_redirect.response.status_lexeme.ptr);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect status provenance"),
                           forged.exact_absolute_redirect.response.status_span);

        forged = server;
        forged.listen.address = ListenerAddress::IPv4Wildcard;
        CHECK(forged.listen.address != server.listen.address);
        expect_unsupported(forged, lit_str("invalid model listen address"), forged.listen.span);

        forged = server;
        forged.listen.ipv4_host = 0u;
        CHECK_NE(forged.listen.ipv4_host, server.listen.ipv4_host);
        expect_unsupported(forged, lit_str("invalid model listen address"), forged.listen.span);

        forged = server;
        forged.listen.port = 8081u;
        CHECK_NE(forged.listen.port, server.listen.port);
        expect_unsupported(
            forged, lit_str("invalid exact listen endpoint model"), forged.listen.value_span);

        forged = server;
        forged.location.proxy_pass.has_uri = true;
        forged.location.proxy_pass.uri = lit_str("/");
        forged.location.proxy_pass.uri_span = forged.location.proxy_pass.span;
        REQUIRE(forged.location.proxy_pass.has_uri);
        expect_unsupported(
            forged, lit_str("invalid proxy_pass URI state"), forged.location.proxy_pass.span);

        // Proxy address and non-zero port are semantic values, not source
        // borrows in the current model. These are valid alternate upstreams;
        // the generic exact-listener composition must not hard-code the oracle
        // endpoint merely to admit status 302.
        forged = server;
        forged.location.proxy_pass.address[0] = 126u;
        CHECK_NE(forged.location.proxy_pass.address[0], server.location.proxy_pass.address[0]);
        const auto alternate_address = nginx::lower_to_rut(forged);
        REQUIRE(alternate_address);
        CHECK(strstr(alternate_address.value().data, "126.0.0.1:9000") != nullptr);

        forged = server;
        forged.location.proxy_pass.port = 9001u;
        CHECK_NE(forged.location.proxy_pass.port, server.location.proxy_pass.port);
        const auto alternate_port = nginx::lower_to_rut(forged);
        REQUIRE(alternate_port);
        CHECK(strstr(alternate_port.value().data, "127.0.0.1:9001") != nullptr);

        forged = server;
        forged.exact_absolute_redirect.response.status = 303u;
        CHECK_NE(forged.exact_absolute_redirect.response.status,
                 server.exact_absolute_redirect.response.status);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect status"),
                           forged.exact_absolute_redirect.response.status_span);

        forged = server;
        forged.exact_absolute_redirect.response.status = 301u;
        CHECK_NE(forged.exact_absolute_redirect.response.status,
                 server.exact_absolute_redirect.response.status);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect status lexeme"),
                           forged.exact_absolute_redirect.response.status_span);

        forged = server;
        forged.exact_absolute_redirect.response.target.len--;
        CHECK_NE(forged.exact_absolute_redirect.response.target.len,
                 server.exact_absolute_redirect.response.target.len);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect target provenance"),
                           forged.exact_absolute_redirect.response.target_span);

        forged = server;
        forged.exact_absolute_redirect.response.authority.ptr++;
        CHECK_NE(forged.exact_absolute_redirect.response.authority.ptr,
                 server.exact_absolute_redirect.response.authority.ptr);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect authority provenance"),
                           forged.exact_absolute_redirect.response.authority_span);

        forged = server;
        forged.exact_absolute_redirect.response.path.ptr--;
        CHECK_NE(forged.exact_absolute_redirect.response.path.ptr,
                 server.exact_absolute_redirect.response.path.ptr);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect target path provenance"),
                           forged.exact_absolute_redirect.response.path_span);

        forged = server;
        forged.listen.value_span.end--;
        CHECK_NE(forged.listen.value_span.end, server.listen.value_span.end);
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.exact_absolute_redirect.span = {};
        expect_unsupported(
            forged, lit_str("invalid exact absolute redirect location span"), forged.span);

        forged = server;
        forged.exact_absolute_redirect.response.status_span.end++;
        CHECK_NE(forged.exact_absolute_redirect.response.status_span.end,
                 server.exact_absolute_redirect.response.status_span.end);
        expect_unsupported(forged,
                           lit_str("invalid exact absolute redirect status span"),
                           forged.exact_absolute_redirect.response.status_span);

        char local_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
            "location = /static { return 200 \"ok\"; } }";
        const auto local = nginx::parse({local_source, sizeof(local_source) - 1u});
        REQUIRE(local);
        forged = server;
        forged.exact_local_return = local.value().exact_local_return;
        REQUIRE(forged.exact_local_return.present);
        expect_unsupported(forged,
                           lit_str("multiple exact semantic actions are unsupported"),
                           forged.exact_local_return.span);

        char no_content_source[] =
            "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
            "location = /empty { return 204; } }";
        const auto no_content = nginx::parse({no_content_source, sizeof(no_content_source) - 1u});
        REQUIRE(no_content);
        forged = server;
        forged.exact_no_content_return = no_content.value().exact_no_content_return;
        REQUIRE(forged.exact_no_content_return.present);
        expect_unsupported(forged,
                           lit_str("multiple exact semantic actions are unsupported"),
                           forged.exact_absolute_redirect.span);

        const nginx::Server retained = server;
        const Span retained_server_span = server.span;
        const Span retained_listener_span = listener.span;
        const Span retained_listener_value_span = listener.value_span;
        const Span retained_root_span = root.span;
        const Span retained_root_path_span = root.path_span;
        const Span retained_proxy_span = proxy.span;
        const Span retained_exact_span = exact.span;
        const Span retained_exact_path_span = exact.path_span;
        const Span retained_response_span = response.span;
        const Span retained_status_span = response.status_span;
        const Span retained_target_span = response.target_span;
        const Span retained_authority_span = response.authority_span;
        const Span retained_target_path_span = response.path_span;
        memset(source, 'x', len);
        CHECK(retained.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.listen.port, 8080u);
        CHECK_EQ(retained.location.path.len, 1u);
        CHECK_EQ(retained.location.proxy_pass.address[0], 127u);
        CHECK_EQ(retained.location.proxy_pass.address[1], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[2], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[3], 1u);
        CHECK_EQ(retained.location.proxy_pass.port, 9000u);
        CHECK_FALSE(retained.location.proxy_pass.has_uri);
        CHECK(retained.exact_absolute_redirect.present);
        CHECK_EQ(retained.exact_absolute_redirect.path.len, 4u);
        CHECK_EQ(retained.exact_absolute_redirect.response.status, 302u);
        CHECK_EQ(retained.exact_absolute_redirect.response.status_lexeme.len, 3u);
        CHECK_EQ(retained.exact_absolute_redirect.response.target.len, 27u);
        CHECK_EQ(retained.exact_absolute_redirect.response.authority.len, 16u);
        CHECK_EQ(retained.exact_absolute_redirect.response.path.len, 4u);
        CHECK_FALSE(retained.exact_local_return.present);
        CHECK_FALSE(retained.exact_no_content_return.present);
        const auto check_retained_span = [&](Span actual, Span expected) {
            CHECK_EQ(actual.start, expected.start);
            CHECK_EQ(actual.end, expected.end);
            CHECK_EQ(actual.line, expected.line);
            CHECK_EQ(actual.col, expected.col);
        };
        check_retained_span(retained.span, retained_server_span);
        check_retained_span(retained.listen.span, retained_listener_span);
        check_retained_span(retained.listen.value_span, retained_listener_value_span);
        check_retained_span(retained.location.span, retained_root_span);
        check_retained_span(retained.location.path_span, retained_root_path_span);
        check_retained_span(retained.location.proxy_pass.span, retained_proxy_span);
        check_retained_span(retained.exact_absolute_redirect.span, retained_exact_span);
        check_retained_span(retained.exact_absolute_redirect.path_span, retained_exact_path_span);
        check_retained_span(retained.exact_absolute_redirect.response.span, retained_response_span);
        check_retained_span(retained.exact_absolute_redirect.response.status_span,
                            retained_status_span);
        check_retained_span(retained.exact_absolute_redirect.response.target_span,
                            retained_target_span);
        check_retained_span(retained.exact_absolute_redirect.response.authority_span,
                            retained_authority_span);
        check_retained_span(retained.exact_absolute_redirect.response.path_span,
                            retained_target_path_span);
        CHECK_EQ(retained.pre_route_trace.span.start, retained_server_span.start);
        CHECK_EQ(retained.pre_route_trace.span.end, retained_server_span.end);
        // Every Str above is now dangling by design; only scalar lengths and
        // spans are inspected after this explicit lifetime boundary.
    };

    check(exact_then_root, sizeof(exact_then_root) - 1u, 3u, 4u);
    check(root_then_exact, sizeof(root_then_exact) - 1u, 4u, 3u);

    static constexpr u32 kWildcardListenPrefixLen = sizeof("listen :") - 1u;
    static constexpr u32 kExactListenPrefixLen = sizeof("listen 127.0.0.1:") - 1u;
    static constexpr u32 kExactListenerDelta = kExactListenPrefixLen - kWildcardListenPrefixLen;
    static_assert(kWildcardListenPrefixLen == 8u);
    static_assert(kExactListenPrefixLen == 17u);
    static_assert(kExactListenerDelta == 9u);
    static_assert(nginx::RutSource::kCapacity == 5946u);

    const auto check_wildcard_at_length = [&](Str source, u32 expected_length, u32& actual_length) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        CHECK(parsed.value().listen.address == ListenerAddress::IPv4Wildcard);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_length);
        actual_length = lowered.value().len;
        CHECK(lowered.value().view().slice(0u, kWildcardListenPrefixLen).eq(lit_str("listen :")));
    };
    const auto check_exact_redirect = [&](Str source,
                                          u16 expected_status,
                                          u16 expected_listener_port,
                                          u32 expected_upstream_ipv4,
                                          u16 expected_upstream_port,
                                          u32 expected_length) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        CHECK(parsed.value().listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(parsed.value().listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(parsed.value().listen.port, expected_listener_port);
        CHECK_EQ(parsed.value().exact_absolute_redirect.response.status, expected_status);
        const auto& address = parsed.value().location.proxy_pass.address;
        const u32 upstream_ipv4 = static_cast<u32>(address[0]) << 24u |
                                  static_cast<u32>(address[1]) << 16u |
                                  static_cast<u32>(address[2]) << 8u | static_cast<u32>(address[3]);
        CHECK_EQ(upstream_ipv4, expected_upstream_ipv4);
        CHECK_EQ(parsed.value().location.proxy_pass.port, expected_upstream_port);
        CHECK_FALSE(parsed.value().location.proxy_pass.has_uri);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(expected_status == 301u || expected_status == 302u);
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_length);
        CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
        CHECK_EQ(lowered.value().data[lowered.value().len], '\0');
        CHECK(lowered.value()
                  .view()
                  .slice(0u, strlen("listen 127.0.0.1:"))
                  .eq(lit_str("listen 127.0.0.1:")));
    };

    static constexpr char kRepresentativeWildcard302[] =
        "server { listen 8080; location = /old { return 302 "
        "http://redirect.example/new; } location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kRepresentativeExact302[] =
        "server { listen 127.0.0.1:8080; location = /old { return 302 "
        "http://redirect.example/new; } location / { proxy_pass http://127.0.0.1:9000; } }";
    u32 representative_wildcard_302 = 0u;
    check_wildcard_at_length({kRepresentativeWildcard302, sizeof(kRepresentativeWildcard302) - 1u},
                             5904u,
                             representative_wildcard_302);
    const u32 representative_exact_302 = representative_wildcard_302 + kExactListenerDelta;
    CHECK_EQ(representative_exact_302, 5913u);
    CHECK_LT(representative_exact_302, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - representative_exact_302, 33u);
    check_exact_redirect({kRepresentativeExact302, sizeof(kRepresentativeExact302) - 1u},
                         302u,
                         8080u,
                         0x7f000001u,
                         9000u,
                         5913u);

    static constexpr char kMaximumWildcard302[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } "
        "location = /old { return 302 http://redirect.example/new; } }";
    static constexpr char kMaximumExact302[] =
        "server { listen 127.0.0.1:65535; location / { proxy_pass "
        "http://255.255.255.255:65535; } location = /old { return 302 "
        "http://redirect.example/new; } }";
    u32 maximum_wildcard_302 = 0u;
    check_wildcard_at_length(
        {kMaximumWildcard302, sizeof(kMaximumWildcard302) - 1u}, 5912u, maximum_wildcard_302);
    const u32 maximum_exact_302 = maximum_wildcard_302 + kExactListenerDelta;
    CHECK_EQ(maximum_exact_302, 5921u);
    CHECK_LT(maximum_exact_302, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum_exact_302, 25u);
    check_exact_redirect({kMaximumExact302, sizeof(kMaximumExact302) - 1u},
                         302u,
                         65535u,
                         0xffffffffu,
                         65535u,
                         5921u);

    static constexpr char kRepresentativeWildcard301[] =
        "server { listen 8080; location = /old { return 301 "
        "http://redirect.example/new; } location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kRepresentativeExact301[] =
        "server { listen 127.0.0.1:8080; location = /old { return 301 "
        "http://redirect.example/new; } location / { proxy_pass http://127.0.0.1:9000; } }";
    u32 representative_wildcard_301 = 0u;
    check_wildcard_at_length({kRepresentativeWildcard301, sizeof(kRepresentativeWildcard301) - 1u},
                             5928u,
                             representative_wildcard_301);
    const u32 representative_exact_301 = representative_wildcard_301 + kExactListenerDelta;
    CHECK_EQ(representative_exact_301, 5937u);
    CHECK_LT(representative_exact_301, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - representative_exact_301, 9u);
    check_exact_redirect({kRepresentativeExact301, sizeof(kRepresentativeExact301) - 1u},
                         301u,
                         8080u,
                         0x7f000001u,
                         9000u,
                         5937u);

    static constexpr char kMaximumWildcard301[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    static constexpr char kMaximumExact301[] =
        "server { listen 127.0.0.1:65535; location / { proxy_pass "
        "http://255.255.255.255:65535; } location = /old { return 301 "
        "http://redirect.example/new; } }";
    u32 maximum_wildcard_301 = 0u;
    check_wildcard_at_length(
        {kMaximumWildcard301, sizeof(kMaximumWildcard301) - 1u}, 5936u, maximum_wildcard_301);
    const u32 maximum_exact_301 = maximum_wildcard_301 + kExactListenerDelta;
    CHECK_EQ(maximum_exact_301, 5945u);
    CHECK_EQ(maximum_exact_301 + 1u, 5946u);
    CHECK_EQ(maximum_exact_301 + 1u, nginx::RutSource::kCapacity);
    CHECK_LT(maximum_exact_301, nginx::RutSource::kCapacity);
    check_exact_redirect({kMaximumExact301, sizeof(kMaximumExact301) - 1u},
                         301u,
                         65535u,
                         0xffffffffu,
                         65535u,
                         5945u);

    const auto maximum_wildcard_301_model =
        nginx::parse({kMaximumWildcard301, sizeof(kMaximumWildcard301) - 1u});
    REQUIRE(maximum_wildcard_301_model);
    const auto maximum_wildcard_301_source =
        nginx::lower_to_rut(maximum_wildcard_301_model.value());
    REQUIRE(maximum_wildcard_301_source);
    REQUIRE_EQ(maximum_wildcard_301_source.value().len, 5936u);
    std::string projected(maximum_wildcard_301_source.value().data,
                          maximum_wildcard_301_source.value().len);
    static constexpr char kWildcardListener[] = "listen :65535";
    static constexpr char kExactListener[] = "listen 127.0.0.1:65535";
    REQUIRE_EQ(projected.rfind(kWildcardListener, 0u), 0u);
    REQUIRE_EQ(count_text(projected, kWildcardListener), 1u);
    REQUIRE_EQ(count_text(projected, kExactListener), 0u);
    projected.replace(0u, sizeof(kWildcardListener) - 1u, kExactListener);
    REQUIRE_EQ(projected.size(), 5945u);
    CHECK_EQ(projected.back(), '\n');
    CHECK_EQ(count_text(projected, kWildcardListener), 0u);
    CHECK_EQ(count_text(projected, kExactListener), 1u);

    const auto projected_lexed = lex({projected.data(), static_cast<u32>(projected.size())});
    REQUIRE(projected_lexed);
    const auto projected_parsed = parse_file(projected_lexed.value());
    REQUIRE(projected_parsed);
    std::unique_ptr<AstFile> projected_ast(projected_parsed.value());
    REQUIRE_GT(projected_ast->items.len, 0u);
    REQUIRE(projected_ast->items[0].kind == AstItemKind::Listen);
    CHECK(projected_ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(projected_ast->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(projected_ast->items[0].listen.port, 65535u);
    const auto projected_analyzed = analyze_file(*projected_ast);
    REQUIRE(projected_analyzed);
    std::unique_ptr<HirModule> projected_hir(projected_analyzed.value());
    REQUIRE(projected_hir->has_listener);
    CHECK(projected_hir->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(projected_hir->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(projected_hir->listener.port, 65535u);
    const auto projected_mir_result = build_mir(*projected_hir);
    REQUIRE(projected_mir_result);
    std::unique_ptr<MirModule> projected_mir(projected_mir_result.value());
    FrontendRirModule projected_rir{};
    RirGuard projected_rir_guard{projected_rir};
    REQUIRE(lower_to_rir(*projected_mir, projected_rir));
    CHECK(rir::verify_module(projected_rir.module).ok);
    CHECK_EQ(projected_rir.module.redirect_policy_count, 1u);

    // Isolate the existing invalid-upstream-port diagnostic with a coherent
    // wildcard source; the exact composition guard intentionally precedes it.
    const auto wildcard_for_port =
        nginx::parse({kRepresentativeWildcard302, sizeof(kRepresentativeWildcard302) - 1u});
    REQUIRE(wildcard_for_port);
    auto zero_upstream_port = wildcard_for_port.value();
    zero_upstream_port.location.proxy_pass.port = 0u;
    const auto rejected_zero_port = nginx::lower_to_rut(zero_upstream_port);
    REQUIRE_FALSE(rejected_zero_port);
    CHECK_EQ(rejected_zero_port.error().code, FrontendError::InvalidInteger);
    CHECK(rejected_zero_port.error().detail.eq(lit_str("invalid model upstream port")));
    CHECK_EQ(rejected_zero_port.error().span.start,
             zero_upstream_port.location.proxy_pass.span.start);
    CHECK_EQ(rejected_zero_port.error().span.end, zero_upstream_port.location.proxy_pass.span.end);
    CHECK_EQ(rejected_zero_port.error().span.line,
             zero_upstream_port.location.proxy_pass.span.line);
    CHECK_EQ(rejected_zero_port.error().span.col, zero_upstream_port.location.proxy_pass.span.col);
}

TEST(nginx_parser,
     issue353_combines_exact_loopback_clean_prefix_root_replacement_with_provenance_capacity) {
    char listen_then_location[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location /service/ {\n"
        "    proxy_pass http://127.0.0.1:9000/;\n"
        "  }\n"
        "}\n";
    char location_then_listen[] =
        "server {\n"
        "  location /service/ {\n"
        "    proxy_pass http://127.0.0.1:9000/;\n"
        "  }\n"
        "  listen 127.0.0.1:8080;\n"
        "}\n";

    const auto check = [&](char* source,
                           u32 source_len,
                           u32 listen_line,
                           u32 location_line,
                           u32 proxy_line) {
        const auto parsed = nginx::parse({source, source_len});
        REQUIRE(parsed);
        const nginx::Server server = parsed.value();
        const auto& listener = server.listen;
        const auto& location = server.location;
        const auto& proxy = location.proxy_pass;
        const char* server_start = strstr(source, "server {");
        const char* server_close = strrchr(source, '}');
        const char* listen_start = strstr(source, "listen 127.0.0.1:8080");
        const char* listen_value = listen_start == nullptr ? nullptr : listen_start + 7u;
        const char* listen_semicolon =
            listen_value == nullptr ? nullptr : strchr(listen_value, ';');
        const char* location_start = strstr(source, "location /service/");
        const char* location_path =
            location_start == nullptr ? nullptr : strstr(location_start, "/service/");
        const char* location_close =
            location_start == nullptr ? nullptr : strchr(location_start, '}');
        const char* proxy_start =
            location_start == nullptr ? nullptr : strstr(location_start, "proxy_pass");
        const char* proxy_target =
            proxy_start == nullptr ? nullptr : strstr(proxy_start, "http://127.0.0.1:9000/");
        const char* proxy_uri =
            proxy_target == nullptr ? nullptr : proxy_target + strlen("http://127.0.0.1:9000");
        const char* proxy_semicolon = proxy_target == nullptr ? nullptr : strchr(proxy_target, ';');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_close != nullptr);
        REQUIRE(listen_start != nullptr);
        REQUIRE(listen_value != nullptr);
        REQUIRE(listen_semicolon != nullptr);
        REQUIRE(location_start != nullptr);
        REQUIRE(location_path != nullptr);
        REQUIRE(location_close != nullptr);
        REQUIRE(proxy_start != nullptr);
        REQUIRE(proxy_target != nullptr);
        REQUIRE(proxy_uri != nullptr);
        REQUIRE(proxy_semicolon != nullptr);

        const auto offset = [&](const char* pointer) { return static_cast<u32>(pointer - source); };
        const auto line = [&](const char* pointer) {
            u32 result = 1u;
            for (const char* cursor = source; cursor != pointer; ++cursor) {
                if (*cursor == '\n') result++;
            }
            return result;
        };
        const auto column = [&](const char* pointer) {
            const char* line_start = pointer;
            while (line_start != source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(pointer - line_start + 1u);
        };
        const auto check_span = [&](Span span, const char* start, const char* end) {
            CHECK_EQ(span.start, offset(start));
            CHECK_EQ(span.end, offset(end));
            CHECK_EQ(span.line, line(start));
            CHECK_EQ(span.col, column(start));
        };

        check_span(server.span, server_start, server_close + 1u);
        CHECK_EQ(server.span.start, 0u);
        CHECK_EQ(server.span.end, source_len - 1u);
        CHECK_EQ(server.span.line, 1u);
        CHECK_EQ(server.span.col, 1u);
        CHECK(listener.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(listener.ipv4_host, 0x7f000001u);
        CHECK_EQ(listener.port, 8080u);
        CHECK(listener.value.eq(lit_str("127.0.0.1:8080")));
        CHECK_EQ(listener.value.ptr, listen_value);
        check_span(listener.span, listen_start, listen_semicolon + 1u);
        check_span(listener.value_span, listen_value, listen_semicolon);
        CHECK_EQ(listener.span.line, listen_line);
        CHECK_EQ(listener.span.col, 3u);
        CHECK_EQ(listener.value_span.line, listen_line);
        CHECK_EQ(listener.value_span.col, 10u);

        CHECK(location.path.eq(lit_str("/service/")));
        CHECK_EQ(location.path.ptr, location_path);
        check_span(location.span, location_start, location_close + 1u);
        check_span(location.path_span, location_path, location_path + strlen("/service/"));
        CHECK_EQ(location.span.line, location_line);
        CHECK_EQ(location.span.col, 3u);
        CHECK_EQ(location.path_span.line, location_line);
        CHECK_EQ(location.path_span.col, 12u);
        CHECK_EQ(proxy.address[0], 127u);
        CHECK_EQ(proxy.address[1], 0u);
        CHECK_EQ(proxy.address[2], 0u);
        CHECK_EQ(proxy.address[3], 1u);
        CHECK_EQ(proxy.port, 9000u);
        REQUIRE(proxy.has_uri);
        CHECK(proxy.uri.eq(lit_str("/")));
        CHECK_EQ(proxy.uri.ptr, proxy_uri);
        check_span(proxy.span, proxy_start, proxy_semicolon + 1u);
        check_span(proxy.uri_span, proxy_uri, proxy_uri + 1u);
        CHECK_EQ(proxy.span.line, proxy_line);
        CHECK_EQ(proxy.span.col, 5u);
        CHECK_EQ(proxy.uri_span.line, proxy_line);
        CHECK_EQ(proxy.uri_span.col, column(proxy_uri));
        CHECK_EQ(static_cast<u32>(proxy_semicolon - proxy_target),
                 static_cast<u32>(strlen("http://127.0.0.1:9000/")));

        CHECK_FALSE(location.proxy_read_timeout.present);
        CHECK_EQ(location.proxy_read_timeout.milliseconds, 0u);
        CHECK_EQ(location.proxy_read_timeout.span.start, 0u);
        CHECK_EQ(location.proxy_read_timeout.value_span.start, 0u);
        CHECK_FALSE(server.exact_local_return.present);
        CHECK_FALSE(server.exact_no_content_return.present);
        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        CHECK_EQ(reinterpret_cast<uintptr_t>(listener.value.ptr) - listener.value_span.start,
                 source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(location.path.ptr) - location.path_span.start,
                 source_base);
        CHECK_EQ(reinterpret_cast<uintptr_t>(proxy.uri.ptr) - proxy.uri_span.start, source_base);
        CHECK_GE(listener.value_span.start, listener.span.start);
        CHECK_LE(listener.value_span.end, listener.span.end);
        CHECK_GE(location.path_span.start, location.span.start);
        CHECK_LT(location.path_span.end, proxy.span.start);
        CHECK_GE(proxy.uri_span.start, proxy.span.start);
        CHECK_LT(proxy.uri_span.end, proxy.span.end);
        // ProxyPass intentionally retains normalized endpoint scalars rather than a complete
        // endpoint borrow. The directive span pins the full target's source extent, while only
        // the explicit replacement URI participates in common-source borrow validation.
        CHECK_EQ(proxy.span.start, offset(proxy_start));
        CHECK_EQ(proxy.span.end, offset(proxy_semicolon + 1u));

        const auto expect_rejected = [&](const nginx::Server& candidate,
                                         FrontendError code,
                                         Str detail,
                                         Span expected_span) {
            const auto lowered = nginx::lower_to_rut(candidate);
            REQUIRE_FALSE(lowered);
            CHECK_EQ(lowered.error().code, code);
            CHECK(lowered.error().detail.eq(detail));
            CHECK_EQ(lowered.error().span.start, expected_span.start);
            CHECK_EQ(lowered.error().span.end, expected_span.end);
            CHECK_EQ(lowered.error().span.line, expected_span.line);
            CHECK_EQ(lowered.error().span.col, expected_span.col);
        };
        const auto expect_unsupported =
            [&](const nginx::Server& candidate, Str detail, Span expected_span) {
                expect_rejected(candidate, FrontendError::UnsupportedSyntax, detail, expected_span);
            };
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, 3358u);
        CHECK(lowered.value()
                  .view()
                  .slice(0u, sizeof("listen 127.0.0.1:8080") - 1u)
                  .eq(lit_str("listen 127.0.0.1:8080")));

        std::vector<char> independent_source(source, source + source_len);
        auto forged = server;
        forged.listen.value.ptr = independent_source.data() + forged.listen.value_span.start;
        CHECK_NE(forged.listen.value.ptr, listener.value.ptr);
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.location.path.ptr = independent_source.data() + forged.location.path_span.start;
        CHECK_NE(forged.location.path.ptr, location.path.ptr);
        expect_unsupported(forged,
                           lit_str("invalid proxy_pass URI provenance"),
                           forged.location.proxy_pass.uri_span);

        forged = server;
        forged.location.proxy_pass.uri.ptr =
            independent_source.data() + forged.location.proxy_pass.uri_span.start;
        CHECK_NE(forged.location.proxy_pass.uri.ptr, proxy.uri.ptr);
        expect_unsupported(forged,
                           lit_str("invalid proxy_pass URI provenance"),
                           forged.location.proxy_pass.uri_span);

        forged = server;
        forged.location.path.ptr = independent_source.data() + forged.location.path_span.start;
        forged.location.proxy_pass.uri.ptr =
            independent_source.data() + forged.location.proxy_pass.uri_span.start;
        CHECK_NE(forged.location.path.ptr, location.path.ptr);
        CHECK_NE(forged.location.proxy_pass.uri.ptr, proxy.uri.ptr);
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.listen.address = ListenerAddress::IPv4Wildcard;
        CHECK(forged.listen.address != listener.address);
        expect_unsupported(forged, lit_str("invalid model listen address"), forged.listen.span);
        forged = server;
        forged.listen.ipv4_host = 0u;
        CHECK_NE(forged.listen.ipv4_host, listener.ipv4_host);
        expect_unsupported(forged, lit_str("invalid model listen address"), forged.listen.span);
        forged = server;
        forged.listen.port = 8081u;
        CHECK_NE(forged.listen.port, listener.port);
        expect_unsupported(
            forged, lit_str("invalid exact listen endpoint model"), forged.listen.value_span);

        forged = server;
        forged.location.path.len--;
        forged.location.path_span.end--;
        CHECK_NE(forged.location.path.len, location.path.len);
        expect_unsupported(forged,
                           lit_str("invalid bounded proxy location path model"),
                           forged.location.path_span);
        forged = server;
        forged.location.proxy_pass.uri.len++;
        CHECK_NE(forged.location.proxy_pass.uri.len, proxy.uri.len);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);
        forged = server;
        forged.location.proxy_pass.uri_span.end++;
        CHECK_NE(forged.location.proxy_pass.uri_span.end, proxy.uri_span.end);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);
        forged = server;
        forged.location.proxy_pass.has_uri = false;
        forged.location.proxy_pass.uri = {};
        forged.location.proxy_pass.uri_span = {};
        expect_unsupported(
            forged, lit_str("invalid upstream endpoint model"), forged.location.proxy_pass.span);

        forged = server;
        forged.location.proxy_read_timeout.present = true;
        forged.location.proxy_read_timeout.milliseconds = 1000u;
        forged.location.proxy_read_timeout.span = proxy.span;
        forged.location.proxy_read_timeout.value_span = proxy.uri_span;
        expect_unsupported(forged,
                           lit_str("invalid proxy_read_timeout location model"),
                           forged.location.path_span);

        const char saved_listen = *listen_start;
        *const_cast<char*>(listen_start) = 'L';
        CHECK_NE(*listen_start, saved_listen);
        expect_unsupported(
            server, lit_str("invalid listen source provenance"), listener.value_span);
        *const_cast<char*>(listen_start) = saved_listen;
        const char saved_path = location_path[1];
        *const_cast<char*>(location_path + 1u) = '%';
        CHECK_NE(location_path[1], saved_path);
        expect_unsupported(
            server, lit_str("invalid bounded proxy location path model"), location.path_span);
        *const_cast<char*>(location_path + 1u) = saved_path;
        const char saved_uri = *proxy_uri;
        *const_cast<char*>(proxy_uri) = 'x';
        CHECK_NE(*proxy_uri, saved_uri);
        expect_unsupported(server, lit_str("invalid bounded proxy_pass URI model"), proxy.uri_span);
        *const_cast<char*>(proxy_uri) = saved_uri;

        const nginx::Server retained = server;
        const Span retained_server_span = server.span;
        const Span retained_listener_span = listener.span;
        const Span retained_listener_value_span = listener.value_span;
        const Span retained_location_span = location.span;
        const Span retained_path_span = location.path_span;
        const Span retained_proxy_span = proxy.span;
        const Span retained_uri_span = proxy.uri_span;
        memset(source, 'x', source_len);
        CHECK(retained.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.listen.port, 8080u);
        CHECK_EQ(retained.location.path.len, 9u);
        CHECK_EQ(retained.location.proxy_pass.address[0], 127u);
        CHECK_EQ(retained.location.proxy_pass.address[1], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[2], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[3], 1u);
        CHECK_EQ(retained.location.proxy_pass.port, 9000u);
        CHECK(retained.location.proxy_pass.has_uri);
        CHECK_EQ(retained.location.proxy_pass.uri.len, 1u);
        CHECK_FALSE(retained.location.proxy_read_timeout.present);
        CHECK_FALSE(retained.exact_local_return.present);
        CHECK_FALSE(retained.exact_no_content_return.present);
        CHECK_FALSE(retained.exact_absolute_redirect.present);
        const auto check_retained_span = [&](Span actual, Span expected) {
            CHECK_EQ(actual.start, expected.start);
            CHECK_EQ(actual.end, expected.end);
            CHECK_EQ(actual.line, expected.line);
            CHECK_EQ(actual.col, expected.col);
        };
        check_retained_span(retained.span, retained_server_span);
        check_retained_span(retained.listen.span, retained_listener_span);
        check_retained_span(retained.listen.value_span, retained_listener_value_span);
        check_retained_span(retained.location.span, retained_location_span);
        check_retained_span(retained.location.path_span, retained_path_span);
        check_retained_span(retained.location.proxy_pass.span, retained_proxy_span);
        check_retained_span(retained.location.proxy_pass.uri_span, retained_uri_span);
        CHECK_EQ(retained.pre_route_trace.span.start, retained_server_span.start);
        CHECK_EQ(retained.pre_route_trace.span.end, retained_server_span.end);
        // All retained Str values are dangling here by design; only copied scalar and span
        // metadata is inspected after the explicit lifetime boundary.
    };

    check(listen_then_location, sizeof(listen_then_location) - 1u, 2u, 3u, 4u);
    check(location_then_listen, sizeof(location_then_listen) - 1u, 5u, 2u, 3u);

    // Parser-level literal/delimiter mutations prove no partial model is manufactured from a
    // misspelled directive or missing semicolon. Endpoint bytes are parsed into scalars and are
    // intentionally not misrepresented as a retained endpoint borrow.
    struct Malformed {
        const char* source;
        const char* offending;
        FrontendError code;
        Str detail;
    };
    const Malformed malformed[] = {
        {"server { listen 127.0.0.1:8080; locatiox /service/ { proxy_pass "
         "http://127.0.0.1:9000/; } }",
         "locatiox",
         FrontendError::UnsupportedSyntax,
         lit_str("unknown server directive")},
        {"server { listen 127.0.0.1:8080; location /service/ { proxy_pasx "
         "http://127.0.0.1:9000/; } }",
         "proxy_pasx",
         FrontendError::UnsupportedSyntax,
         lit_str("unknown location directive")},
        {"server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
         "http://127.0.0.1:9000/ } }",
         "} }",
         FrontendError::UnexpectedToken,
         lit_str("expected ';' after proxy_pass")},
    };
    for (const auto& vector : malformed) {
        const auto rejected =
            nginx::parse({vector.source, static_cast<u32>(strlen(vector.source))});
        REQUIRE_FALSE(rejected);
        const char* offending = strstr(vector.source, vector.offending);
        REQUIRE(offending != nullptr);
        const u32 offending_len =
            vector.offending[0] == '}' ? 1u : static_cast<u32>(strlen(vector.offending));
        CHECK_EQ(rejected.error().code, vector.code);
        CHECK(rejected.error().detail.eq(vector.detail));
        CHECK_EQ(rejected.error().span.start, static_cast<u32>(offending - vector.source));
        CHECK_EQ(rejected.error().span.end,
                 static_cast<u32>(offending - vector.source) + offending_len);
        CHECK_EQ(rejected.error().span.line, 1u);
        CHECK_EQ(rejected.error().span.col, static_cast<u32>(offending - vector.source + 1u));
    }

    static constexpr char kNonRootReplacement[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    const auto non_root_replacement =
        nginx::parse({kNonRootReplacement, sizeof(kNonRootReplacement) - 1u});
    REQUIRE(non_root_replacement);
    REQUIRE(non_root_replacement.value().location.proxy_pass.has_uri);
    CHECK(non_root_replacement.value().location.proxy_pass.uri.eq(lit_str("/v1/")));
    const auto non_root_rejected = nginx::lower_to_rut(non_root_replacement.value());
    REQUIRE_FALSE(non_root_rejected);
    CHECK_EQ(non_root_rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(non_root_rejected.error().detail.eq(
        lit_str("exact listen requires the minimal root proxy profile")));
    CHECK_EQ(non_root_rejected.error().span.start, non_root_replacement.value().listen.span.start);
    CHECK_EQ(non_root_rejected.error().span.end, non_root_replacement.value().listen.span.end);

    static constexpr char kConfiguredQuery[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/?fixed=1; } }";
    const auto configured_query = nginx::parse({kConfiguredQuery, sizeof(kConfiguredQuery) - 1u});
    REQUIRE(configured_query);
    REQUIRE(configured_query.value().location.proxy_pass.has_uri);
    CHECK(configured_query.value().location.proxy_pass.uri.eq(lit_str("/?fixed=1")));
    const auto configured_query_rejected = nginx::lower_to_rut(configured_query.value());
    REQUIRE_FALSE(configured_query_rejected);
    CHECK_EQ(configured_query_rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(configured_query_rejected.error().detail.eq(
        lit_str("exact listen requires the minimal root proxy profile")));
    CHECK_EQ(configured_query_rejected.error().span.start,
             configured_query.value().listen.span.start);
    CHECK_EQ(configured_query_rejected.error().span.end, configured_query.value().listen.span.end);

    static constexpr char kTrueNoUri[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000; } }";
    const auto no_uri = nginx::parse({kTrueNoUri, sizeof(kTrueNoUri) - 1u});
    REQUIRE(no_uri);
    CHECK_FALSE(no_uri.value().location.proxy_pass.has_uri);
    const auto no_uri_lowered = nginx::lower_to_rut(no_uri.value());
    REQUIRE(no_uri_lowered);
    CHECK_EQ(no_uri_lowered.value().len, 3256u);
    CHECK_EQ(count_text(std::string(no_uri_lowered.value().data, no_uri_lowered.value().len),
                        "target_transform:"),
             0u);

    static constexpr char kExtraAction[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/; } location = /static { return 204; } }";
    const auto extra_action = nginx::parse({kExtraAction, sizeof(kExtraAction) - 1u});
    REQUIRE_FALSE(extra_action);
    CHECK_EQ(extra_action.error().code, FrontendError::UnsupportedSyntax);
    CHECK(extra_action.error().detail.eq(
        lit_str("exact location requires location / proxy fallback")));
    const char* extra_path = strstr(kExtraAction, "/service/");
    REQUIRE(extra_path != nullptr);
    CHECK_EQ(extra_action.error().span.start, static_cast<u32>(extra_path - kExtraAction));
    CHECK_EQ(extra_action.error().span.end,
             static_cast<u32>(extra_path - kExtraAction + strlen("/service/")));

    static constexpr u32 kWildcardListenPrefixLen = sizeof("listen :") - 1u;
    static constexpr u32 kExactListenPrefixLen = sizeof("listen 127.0.0.1:") - 1u;
    static constexpr u32 kExactListenerDelta = kExactListenPrefixLen - kWildcardListenPrefixLen;
    static_assert(kWildcardListenPrefixLen == 8u);
    static_assert(kExactListenPrefixLen == 17u);
    static_assert(kExactListenerDelta == 9u);
    static_assert(nginx::RutSource::kCapacity == 5946u);

    const auto check_wildcard = [&](Str source, u32 expected_length, u32& actual_length) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        CHECK(parsed.value().listen.address == ListenerAddress::IPv4Wildcard);
        REQUIRE(parsed.value().location.proxy_pass.has_uri);
        CHECK(parsed.value().location.proxy_pass.uri.eq(lit_str("/")));
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_length);
        CHECK(lowered.value().view().slice(0u, kWildcardListenPrefixLen).eq(lit_str("listen :")));
        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        delete ast.value();
        actual_length = lowered.value().len;
    };
    const auto check_exact = [&](Str source,
                                 u16 listener_port,
                                 u32 path_len,
                                 u32 upstream_ipv4,
                                 u16 upstream_port,
                                 u32 expected_length) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        const auto& server = parsed.value();
        CHECK(server.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(server.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(server.listen.port, listener_port);
        CHECK_EQ(server.location.path.len, path_len);
        REQUIRE(server.location.proxy_pass.has_uri);
        CHECK(server.location.proxy_pass.uri.eq(lit_str("/")));
        const auto& address = server.location.proxy_pass.address;
        const u32 actual_ipv4 = static_cast<u32>(address[0]) << 24u |
                                static_cast<u32>(address[1]) << 16u |
                                static_cast<u32>(address[2]) << 8u | static_cast<u32>(address[3]);
        CHECK_EQ(actual_ipv4, upstream_ipv4);
        CHECK_EQ(server.location.proxy_pass.port, upstream_port);
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        if (expected_length != 0u) CHECK_EQ(lowered.value().len, expected_length);
        CHECK(lowered.value()
                  .view()
                  .slice(0u, sizeof("listen 127.0.0.1:") - 1u)
                  .eq(lit_str("listen 127.0.0.1:")));
    };

    static constexpr char kRepresentativeWildcard[] =
        "server { listen 8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/; } }";
    static constexpr char kRepresentativeExact[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/; } }";
    u32 representative_wildcard = 0u;
    check_wildcard({kRepresentativeWildcard, sizeof(kRepresentativeWildcard) - 1u},
                   3349u,
                   representative_wildcard);
    const u32 representative_exact = representative_wildcard + kExactListenerDelta;
    CHECK_EQ(representative_exact, 3358u);
    CHECK_LT(representative_exact, nginx::RutSource::kCapacity);
    check_exact({kRepresentativeExact, sizeof(kRepresentativeExact) - 1u},
                8080u,
                9u,
                0x7f000001u,
                9000u,
                representative_exact);
    static constexpr char kMinimumExact[] =
        "server { listen 127.0.0.1:1; location /a/ { proxy_pass "
        "http://127.0.0.1:1/; } }";
    check_exact({kMinimumExact, sizeof(kMinimumExact) - 1u}, 1u, 3u, 0x7f000001u, 1u, 0u);

    char maximum_path[nginx::kMaxProxyLocationPathLen + 1u]{};
    maximum_path[0] = '/';
    for (u32 i = 1u; i + 1u < nginx::kMaxProxyLocationPathLen; i++) maximum_path[i] = 'a';
    maximum_path[nginx::kMaxProxyLocationPathLen - 1u] = '/';
    char maximum_wildcard_source[512]{};
    char maximum_exact_source[512]{};
    const int maximum_wildcard_source_len =
        snprintf(maximum_wildcard_source,
                 sizeof(maximum_wildcard_source),
                 "server { listen 65535; location %s { proxy_pass "
                 "http://255.255.255.255:65535/; } }",
                 maximum_path);
    const int maximum_exact_source_len =
        snprintf(maximum_exact_source,
                 sizeof(maximum_exact_source),
                 "server { listen 127.0.0.1:65535; location %s { proxy_pass "
                 "http://255.255.255.255:65535/; } }",
                 maximum_path);
    REQUIRE_GT(maximum_wildcard_source_len, 0);
    REQUIRE_GT(maximum_exact_source_len, 0);
    REQUIRE_LT(static_cast<u32>(maximum_wildcard_source_len),
               static_cast<u32>(sizeof(maximum_wildcard_source)));
    REQUIRE_LT(static_cast<u32>(maximum_exact_source_len),
               static_cast<u32>(sizeof(maximum_exact_source)));
    u32 maximum_wildcard = 0u;
    check_wildcard({maximum_wildcard_source, static_cast<u32>(maximum_wildcard_source_len)},
                   3573u,
                   maximum_wildcard);
    const u32 maximum_exact = maximum_wildcard + kExactListenerDelta;
    CHECK_EQ(maximum_exact, 3582u);
    CHECK_LT(maximum_exact, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum_exact, 2364u);
    check_exact({maximum_exact_source, static_cast<u32>(maximum_exact_source_len)},
                65535u,
                nginx::kMaxProxyLocationPathLen,
                0xffffffffu,
                65535u,
                maximum_exact);

    // Endpoint address and non-zero port are normalized semantic scalars, not provenance. A
    // coherent wildcard model proves alternate scalars remain generic, while port zero retains
    // its established diagnostic independently of the exact-listener composition guard.
    const auto wildcard_model =
        nginx::parse({kRepresentativeWildcard, sizeof(kRepresentativeWildcard) - 1u});
    REQUIRE(wildcard_model);
    auto alternate_endpoint = wildcard_model.value();
    alternate_endpoint.location.proxy_pass.address[0] = 126u;
    alternate_endpoint.location.proxy_pass.port = 9001u;
    const auto alternate_lowered = nginx::lower_to_rut(alternate_endpoint);
    REQUIRE(alternate_lowered);
    CHECK(strstr(alternate_lowered.value().data, "126.0.0.1:9001") != nullptr);
    auto zero_port = wildcard_model.value();
    zero_port.location.proxy_pass.port = 0u;
    const auto zero_port_rejected = nginx::lower_to_rut(zero_port);
    REQUIRE_FALSE(zero_port_rejected);
    CHECK_EQ(zero_port_rejected.error().code, FrontendError::InvalidInteger);
    CHECK(zero_port_rejected.error().detail.eq(lit_str("invalid model upstream port")));
    CHECK_EQ(zero_port_rejected.error().span.start, zero_port.location.proxy_pass.span.start);
    CHECK_EQ(zero_port_rejected.error().span.end, zero_port.location.proxy_pass.span.end);
    CHECK_EQ(zero_port_rejected.error().span.line, zero_port.location.proxy_pass.span.line);
    CHECK_EQ(zero_port_rejected.error().span.col, zero_port.location.proxy_pass.span.col);
}

TEST(nginx_parser,
     issue354_combines_exact_loopback_fixed_non_root_replacement_with_provenance_capacity) {
    char listen_then_location[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/;\n"
        "  }\n"
        "}\n";
    char location_then_listen[] =
        "server {\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000/v1/;\n"
        "  }\n"
        "  listen 127.0.0.1:8080;\n"
        "}\n";

    const auto check = [&](char* source,
                           u32 source_len,
                           u32 listen_line,
                           u32 location_line,
                           u32 proxy_line) {
        const auto parsed = nginx::parse({source, source_len});
        REQUIRE(parsed);
        const nginx::Server server = parsed.value();
        const auto& listener = server.listen;
        const auto& location = server.location;
        const auto& proxy = location.proxy_pass;
        const char* server_start = strstr(source, "server {");
        const char* server_close = strrchr(source, '}');
        const char* listen_start = strstr(source, "listen 127.0.0.1:8080");
        const char* listen_value = listen_start == nullptr ? nullptr : listen_start + 7u;
        const char* listen_semicolon =
            listen_value == nullptr ? nullptr : strchr(listen_value, ';');
        const char* location_start = strstr(source, "location /api/");
        const char* location_path =
            location_start == nullptr ? nullptr : strstr(location_start, "/api/");
        const char* location_close =
            location_start == nullptr ? nullptr : strchr(location_start, '}');
        const char* proxy_start =
            location_start == nullptr ? nullptr : strstr(location_start, "proxy_pass");
        const char* proxy_target =
            proxy_start == nullptr ? nullptr : strstr(proxy_start, "http://127.0.0.1:9000/v1/");
        const char* proxy_uri =
            proxy_target == nullptr ? nullptr : proxy_target + strlen("http://127.0.0.1:9000");
        const char* proxy_semicolon = proxy_target == nullptr ? nullptr : strchr(proxy_target, ';');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_close != nullptr);
        REQUIRE(listen_start != nullptr);
        REQUIRE(listen_value != nullptr);
        REQUIRE(listen_semicolon != nullptr);
        REQUIRE(location_start != nullptr);
        REQUIRE(location_path != nullptr);
        REQUIRE(location_close != nullptr);
        REQUIRE(proxy_start != nullptr);
        REQUIRE(proxy_target != nullptr);
        REQUIRE(proxy_uri != nullptr);
        REQUIRE(proxy_semicolon != nullptr);

        const auto offset = [&](const char* pointer) { return static_cast<u32>(pointer - source); };
        const auto line = [&](const char* pointer) {
            u32 result = 1u;
            for (const char* cursor = source; cursor != pointer; ++cursor) {
                if (*cursor == '\n') result++;
            }
            return result;
        };
        const auto column = [&](const char* pointer) {
            const char* line_start = pointer;
            while (line_start != source && line_start[-1] != '\n') --line_start;
            return static_cast<u32>(pointer - line_start + 1u);
        };
        const auto span_matches = [&](Span span, const char* start, const char* end) {
            return span.start == offset(start) && span.end == offset(end) &&
                   span.line == line(start) && span.col == column(start);
        };

        REQUIRE(span_matches(server.span, server_start, server_close + 1u));
        REQUIRE(span_matches(listener.span, listen_start, listen_semicolon + 1u));
        REQUIRE(span_matches(listener.value_span, listen_value, listen_semicolon));
        REQUIRE(span_matches(location.span, location_start, location_close + 1u));
        REQUIRE(span_matches(location.path_span, location_path, location_path + strlen("/api/")));
        REQUIRE(span_matches(proxy.span, proxy_start, proxy_semicolon + 1u));
        REQUIRE(span_matches(proxy.uri_span, proxy_uri, proxy_uri + strlen("/v1/")));
        REQUIRE_EQ(server.span.start, 0u);
        REQUIRE_EQ(server.span.end, source_len - 1u);
        REQUIRE_EQ(server.span.line, 1u);
        REQUIRE_EQ(server.span.col, 1u);
        REQUIRE_EQ(listener.span.line, listen_line);
        REQUIRE_EQ(listener.span.col, 3u);
        REQUIRE_EQ(listener.value_span.line, listen_line);
        REQUIRE_EQ(listener.value_span.col, 10u);
        REQUIRE_EQ(location.span.line, location_line);
        REQUIRE_EQ(location.span.col, 3u);
        REQUIRE_EQ(location.path_span.line, location_line);
        REQUIRE_EQ(location.path_span.col, 12u);
        REQUIRE_EQ(proxy.span.line, proxy_line);
        REQUIRE_EQ(proxy.span.col, 5u);
        REQUIRE_EQ(proxy.uri_span.line, proxy_line);
        REQUIRE_EQ(proxy.uri_span.col, column(proxy_uri));

        REQUIRE_GE(listener.value_span.start, listener.span.start);
        REQUIRE_LE(listener.value_span.end, listener.span.end);
        REQUIRE_GE(location.path_span.start, location.span.start);
        REQUIRE_LT(location.path_span.end, proxy.span.start);
        REQUIRE_GE(proxy.uri_span.start, proxy.span.start);
        REQUIRE_LT(proxy.uri_span.end, proxy.span.end);
        REQUIRE_EQ(listener.value.len, listener.value_span.end - listener.value_span.start);
        REQUIRE_EQ(location.path.len, location.path_span.end - location.path_span.start);
        REQUIRE_EQ(proxy.uri.len, proxy.uri_span.end - proxy.uri_span.start);
        REQUIRE(listener.value.ptr != nullptr);
        REQUIRE(location.path.ptr != nullptr);
        REQUIRE(proxy.uri.ptr != nullptr);
        REQUIRE_EQ(listener.value.ptr, listen_value);
        REQUIRE_EQ(location.path.ptr, location_path);
        REQUIRE_EQ(proxy.uri.ptr, proxy_uri);
        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        const uintptr_t listener_source_base =
            reinterpret_cast<uintptr_t>(listener.value.ptr) - listener.value_span.start;
        const uintptr_t path_source_base =
            reinterpret_cast<uintptr_t>(location.path.ptr) - location.path_span.start;
        const uintptr_t uri_source_base =
            reinterpret_cast<uintptr_t>(proxy.uri.ptr) - proxy.uri_span.start;
        REQUIRE_EQ(listener_source_base, source_base);
        REQUIRE_EQ(path_source_base, source_base);
        REQUIRE_EQ(uri_source_base, source_base);
        REQUIRE_EQ(listener_source_base, path_source_base);
        REQUIRE_EQ(path_source_base, uri_source_base);

        CHECK(listener.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(listener.ipv4_host, 0x7f000001u);
        CHECK_EQ(listener.port, 8080u);
        CHECK(listener.value.eq(lit_str("127.0.0.1:8080")));

        CHECK(location.path.eq(lit_str("/api/")));
        CHECK_EQ(proxy.address[0], 127u);
        CHECK_EQ(proxy.address[1], 0u);
        CHECK_EQ(proxy.address[2], 0u);
        CHECK_EQ(proxy.address[3], 1u);
        CHECK_EQ(proxy.port, 9000u);
        REQUIRE(proxy.has_uri);
        CHECK(proxy.uri.eq(lit_str("/v1/")));
        CHECK_EQ(static_cast<u32>(proxy_semicolon - proxy_target),
                 static_cast<u32>(strlen("http://127.0.0.1:9000/v1/")));

        CHECK_FALSE(location.proxy_read_timeout.present);
        CHECK_EQ(location.proxy_read_timeout.milliseconds, 0u);
        CHECK_EQ(location.proxy_read_timeout.span.start, 0u);
        CHECK_EQ(location.proxy_read_timeout.value_span.start, 0u);
        CHECK_FALSE(server.exact_local_return.present);
        CHECK_FALSE(server.exact_no_content_return.present);
        CHECK_FALSE(server.exact_absolute_redirect.present);
        CHECK(server.pre_route_trace.profile ==
              nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        CHECK_EQ(server.pre_route_trace.span.start, server.span.start);
        CHECK_EQ(server.pre_route_trace.span.end, server.span.end);
        CHECK_EQ(server.pre_route_trace.span.line, server.span.line);
        CHECK_EQ(server.pre_route_trace.span.col, server.span.col);

        // ProxyPass stores the endpoint only as normalized scalars. The complete directive span
        // pins its source extent, while path, URI, and listener token are the actual borrows.
        CHECK_EQ(proxy.span.start, offset(proxy_start));
        CHECK_EQ(proxy.span.end, offset(proxy_semicolon + 1u));

        const auto expect_rejected = [&](const nginx::Server& candidate,
                                         FrontendError code,
                                         Str detail,
                                         Span expected_span) {
            const auto lowered = nginx::lower_to_rut(candidate);
            REQUIRE_FALSE(lowered);
            CHECK_EQ(lowered.error().code, code);
            CHECK(lowered.error().detail.eq(detail));
            CHECK_EQ(lowered.error().span.start, expected_span.start);
            CHECK_EQ(lowered.error().span.end, expected_span.end);
            CHECK_EQ(lowered.error().span.line, expected_span.line);
            CHECK_EQ(lowered.error().span.col, expected_span.col);
        };
        const auto expect_unsupported =
            [&](const nginx::Server& candidate, Str detail, Span expected_span) {
                expect_rejected(candidate, FrontendError::UnsupportedSyntax, detail, expected_span);
            };
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, 3345u);
        CHECK(lowered.value()
                  .view()
                  .slice(0u, sizeof("listen 127.0.0.1:8080") - 1u)
                  .eq(lit_str("listen 127.0.0.1:8080")));

        std::vector<char> independent_source(source, source + source_len);
        auto forged = server;
        forged.listen.value.ptr = independent_source.data() + forged.listen.value_span.start;
        CHECK_NE(forged.listen.value.ptr, listener.value.ptr);
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.location.path.ptr = independent_source.data() + forged.location.path_span.start;
        CHECK_NE(forged.location.path.ptr, location.path.ptr);
        expect_unsupported(forged,
                           lit_str("invalid proxy_pass URI provenance"),
                           forged.location.proxy_pass.uri_span);

        forged = server;
        forged.location.proxy_pass.uri.ptr =
            independent_source.data() + forged.location.proxy_pass.uri_span.start;
        CHECK_NE(forged.location.proxy_pass.uri.ptr, proxy.uri.ptr);
        expect_unsupported(forged,
                           lit_str("invalid proxy_pass URI provenance"),
                           forged.location.proxy_pass.uri_span);

        forged = server;
        forged.location.path.ptr = independent_source.data() + forged.location.path_span.start;
        forged.location.proxy_pass.uri.ptr =
            independent_source.data() + forged.location.proxy_pass.uri_span.start;
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);

        forged = server;
        forged.listen.value_span.end--;
        CHECK_NE(forged.listen.value_span.end, listener.value_span.end);
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), forged.listen.value_span);
        forged = server;
        forged.location.path_span.end--;
        CHECK_NE(forged.location.path_span.end, location.path_span.end);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.path_span);
        forged = server;
        forged.location.proxy_pass.uri_span.end--;
        CHECK_NE(forged.location.proxy_pass.uri_span.end, proxy.uri_span.end);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);
        forged = server;
        forged.location.span.line++;
        forged.location.path_span.line++;
        forged.location.proxy_pass.span.line++;
        forged.location.proxy_pass.uri_span.line++;
        CHECK_NE(forged.location.span.line, location.span.line);
        expect_unsupported(
            forged, lit_str("invalid proxy location source positions"), forged.location.span);
        forged = server;
        forged.location.proxy_pass.uri_span.col++;
        CHECK_NE(forged.location.proxy_pass.uri_span.col, proxy.uri_span.col);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);

        forged = server;
        forged.listen.address = ListenerAddress::IPv4Wildcard;
        CHECK(forged.listen.address != listener.address);
        expect_unsupported(forged, lit_str("invalid model listen address"), forged.listen.span);
        forged = server;
        forged.listen.ipv4_host = 0u;
        CHECK_NE(forged.listen.ipv4_host, listener.ipv4_host);
        expect_unsupported(forged, lit_str("invalid model listen address"), forged.listen.span);
        forged = server;
        forged.listen.port = 8081u;
        CHECK_NE(forged.listen.port, listener.port);
        expect_unsupported(
            forged, lit_str("invalid exact listen endpoint model"), forged.listen.value_span);
        forged = server;
        forged.listen.port = 0u;
        CHECK_NE(forged.listen.port, listener.port);
        expect_rejected(forged,
                        FrontendError::InvalidInteger,
                        lit_str("invalid model listen port"),
                        forged.listen.span);

        // These endpoint fields are semantic scalars, not source borrows. A different non-zero
        // endpoint remains a coherent model and preserves the fixed exact composition.
        forged = server;
        forged.location.proxy_pass.address[0] = 126u;
        forged.location.proxy_pass.port = 9001u;
        CHECK_NE(forged.location.proxy_pass.address[0], proxy.address[0]);
        CHECK_NE(forged.location.proxy_pass.port, proxy.port);
        const auto alternate_endpoint = nginx::lower_to_rut(forged);
        REQUIRE(alternate_endpoint);
        CHECK(strstr(alternate_endpoint.value().data, "126.0.0.1:9001") != nullptr);

        forged = server;
        forged.location.path.len--;
        CHECK_NE(forged.location.path.len, location.path.len);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.path_span);
        forged = server;
        forged.location.path.len--;
        forged.location.path_span.end--;
        CHECK_NE(forged.location.path.len, location.path.len);
        CHECK_NE(forged.location.path_span.end, location.path_span.end);
        expect_unsupported(forged,
                           lit_str("invalid bounded proxy location path model"),
                           forged.location.path_span);
        forged = server;
        forged.location.proxy_pass.uri.len--;
        CHECK_NE(forged.location.proxy_pass.uri.len, proxy.uri.len);
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.proxy_pass.uri_span);
        forged = server;
        forged.location.proxy_pass.uri.len--;
        forged.location.proxy_pass.uri_span.end--;
        CHECK_NE(forged.location.proxy_pass.uri.len, proxy.uri.len);
        CHECK_NE(forged.location.proxy_pass.uri_span.end, proxy.uri_span.end);
        expect_unsupported(forged,
                           lit_str("invalid bounded proxy_pass URI model"),
                           forged.location.proxy_pass.uri_span);
        forged = server;
        forged.location.proxy_pass.has_uri = false;
        CHECK_NE(forged.location.proxy_pass.has_uri, proxy.has_uri);
        expect_unsupported(
            forged, lit_str("invalid proxy_pass URI state"), forged.location.proxy_pass.span);
        forged = server;
        forged.location.proxy_pass.uri = {};
        forged.location.proxy_pass.uri_span = {};
        CHECK_NE(forged.location.proxy_pass.uri.len, proxy.uri.len);
        CHECK_NE(forged.location.proxy_pass.uri_span.end, proxy.uri_span.end);
        expect_unsupported(forged,
                           lit_str("invalid bounded proxy_pass URI model"),
                           forged.location.proxy_pass.uri_span);

        forged = server;
        forged.location.proxy_read_timeout.present = true;
        forged.location.proxy_read_timeout.milliseconds = 1000u;
        forged.location.proxy_read_timeout.span = proxy.span;
        forged.location.proxy_read_timeout.value_span = proxy.uri_span;
        CHECK_NE(forged.location.proxy_read_timeout.present, location.proxy_read_timeout.present);
        expect_unsupported(forged,
                           lit_str("invalid proxy_read_timeout location model"),
                           forged.location.path_span);
        forged = server;
        forged.exact_no_content_return.response.status = 204u;
        CHECK_NE(forged.exact_no_content_return.response.status,
                 server.exact_no_content_return.response.status);
        expect_unsupported(
            forged, lit_str("invalid absent exact no-content return model"), forged.span);
        forged = server;
        forged.exact_local_return.response.status = 200u;
        CHECK_NE(forged.exact_local_return.response.status,
                 server.exact_local_return.response.status);
        expect_unsupported(forged, lit_str("invalid absent exact local return model"), forged.span);
        forged = server;
        forged.exact_absolute_redirect.response.status = 302u;
        CHECK_NE(forged.exact_absolute_redirect.response.status,
                 server.exact_absolute_redirect.response.status);
        expect_unsupported(
            forged, lit_str("invalid absent exact absolute redirect model"), forged.span);

        const char saved_listen = *listen_start;
        *const_cast<char*>(listen_start) = 'L';
        CHECK_NE(*listen_start, saved_listen);
        expect_unsupported(
            server, lit_str("invalid listen source provenance"), listener.value_span);
        *const_cast<char*>(listen_start) = saved_listen;
        const char saved_path = location_path[1];
        *const_cast<char*>(location_path + 1u) = '%';
        CHECK_NE(location_path[1], saved_path);
        expect_unsupported(
            server, lit_str("invalid bounded proxy location path model"), location.path_span);
        *const_cast<char*>(location_path + 1u) = saved_path;
        const char saved_uri = proxy_uri[1];
        *const_cast<char*>(proxy_uri + 1u) = '%';
        CHECK_NE(proxy_uri[1], saved_uri);
        expect_unsupported(server, lit_str("invalid bounded proxy_pass URI model"), proxy.uri_span);
        *const_cast<char*>(proxy_uri + 1u) = saved_uri;

        const nginx::Server retained = server;
        const Span retained_server_span = server.span;
        const Span retained_listener_span = listener.span;
        const Span retained_listener_value_span = listener.value_span;
        const Span retained_location_span = location.span;
        const Span retained_path_span = location.path_span;
        const Span retained_proxy_span = proxy.span;
        const Span retained_uri_span = proxy.uri_span;
        memset(source, 'x', source_len);
        CHECK(retained.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.listen.port, 8080u);
        CHECK_EQ(retained.location.path.len, 5u);
        CHECK_EQ(retained.location.proxy_pass.address[0], 127u);
        CHECK_EQ(retained.location.proxy_pass.address[1], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[2], 0u);
        CHECK_EQ(retained.location.proxy_pass.address[3], 1u);
        CHECK_EQ(retained.location.proxy_pass.port, 9000u);
        CHECK(retained.location.proxy_pass.has_uri);
        CHECK_EQ(retained.location.proxy_pass.uri.len, 4u);
        CHECK_FALSE(retained.location.proxy_read_timeout.present);
        CHECK_FALSE(retained.exact_local_return.present);
        CHECK_FALSE(retained.exact_no_content_return.present);
        CHECK_FALSE(retained.exact_absolute_redirect.present);
        const auto check_retained_span = [&](Span actual, Span expected) {
            CHECK_EQ(actual.start, expected.start);
            CHECK_EQ(actual.end, expected.end);
            CHECK_EQ(actual.line, expected.line);
            CHECK_EQ(actual.col, expected.col);
        };
        check_retained_span(retained.span, retained_server_span);
        check_retained_span(retained.listen.span, retained_listener_span);
        check_retained_span(retained.listen.value_span, retained_listener_value_span);
        check_retained_span(retained.location.span, retained_location_span);
        check_retained_span(retained.location.path_span, retained_path_span);
        check_retained_span(retained.location.proxy_pass.span, retained_proxy_span);
        check_retained_span(retained.location.proxy_pass.uri_span, retained_uri_span);
        CHECK_EQ(retained.pre_route_trace.span.start, retained_server_span.start);
        CHECK_EQ(retained.pre_route_trace.span.end, retained_server_span.end);
        // Borrowed Str values are dangling after this point and are deliberately not read.
    };

    check(listen_then_location, sizeof(listen_then_location) - 1u, 2u, 3u, 4u);
    check(location_then_listen, sizeof(location_then_listen) - 1u, 5u, 2u, 3u);

    struct Malformed {
        const char* source;
        const char* offending;
        FrontendError code;
        Str detail;
    };
    const Malformed malformed[] = {
        {"server { listen 127.0.0.1:8080; locatiox /api/ { proxy_pass "
         "http://127.0.0.1:9000/v1/; } }",
         "locatiox",
         FrontendError::UnsupportedSyntax,
         lit_str("unknown server directive")},
        {"server { listen 127.0.0.1:8080; location /api/ { proxy_pasx "
         "http://127.0.0.1:9000/v1/; } }",
         "proxy_pasx",
         FrontendError::UnsupportedSyntax,
         lit_str("unknown location directive")},
        {"server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
         "http://127.0.0.1:9000/v1/ } }",
         "} }",
         FrontendError::UnexpectedToken,
         lit_str("expected ';' after proxy_pass")},
    };
    for (const auto& vector : malformed) {
        const auto rejected =
            nginx::parse({vector.source, static_cast<u32>(strlen(vector.source))});
        REQUIRE_FALSE(rejected);
        const char* offending = strstr(vector.source, vector.offending);
        REQUIRE(offending != nullptr);
        const u32 offending_len =
            vector.offending[0] == '}' ? 1u : static_cast<u32>(strlen(vector.offending));
        CHECK_EQ(rejected.error().code, vector.code);
        CHECK(rejected.error().detail.eq(vector.detail));
        CHECK_EQ(rejected.error().span.start, static_cast<u32>(offending - vector.source));
        CHECK_EQ(rejected.error().span.end,
                 static_cast<u32>(offending - vector.source) + offending_len);
        CHECK_EQ(rejected.error().span.line, 1u);
        CHECK_EQ(rejected.error().span.col, static_cast<u32>(offending - vector.source + 1u));
    }

    static constexpr char kConfiguredQuery[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/?fixed=1; } }";
    const auto configured_query = nginx::parse({kConfiguredQuery, sizeof(kConfiguredQuery) - 1u});
    REQUIRE(configured_query);
    REQUIRE(configured_query.value().location.proxy_pass.has_uri);
    CHECK(configured_query.value().location.proxy_pass.uri.eq(lit_str("/v1/?fixed=1")));
    CHECK_EQ(configured_query.value().location.path.len, 5u);
    CHECK_EQ(configured_query.value().location.proxy_pass.uri.len, 12u);
    const auto configured_query_rejected = nginx::lower_to_rut(configured_query.value());
    REQUIRE_FALSE(configured_query_rejected);
    CHECK_EQ(configured_query_rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(configured_query_rejected.error().detail.eq(
        lit_str("exact listen requires the minimal root proxy profile")));
    CHECK_EQ(configured_query_rejected.error().span.start,
             configured_query.value().listen.span.start);
    CHECK_EQ(configured_query_rejected.error().span.end, configured_query.value().listen.span.end);

    static constexpr char kTrueNoUri[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000; } }";
    const auto no_uri = nginx::parse({kTrueNoUri, sizeof(kTrueNoUri) - 1u});
    REQUIRE(no_uri);
    CHECK_FALSE(no_uri.value().location.proxy_pass.has_uri);
    const auto no_uri_lowered = nginx::lower_to_rut(no_uri.value());
    REQUIRE(no_uri_lowered);
    CHECK_EQ(no_uri_lowered.value().len, 3244u);
    CHECK_EQ(count_text(std::string(no_uri_lowered.value().data, no_uri_lowered.value().len),
                        "target_transform:"),
             0u);

    static constexpr char kExplicitV1[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    const auto explicit_v1 = nginx::parse({kExplicitV1, sizeof(kExplicitV1) - 1u});
    REQUIRE(explicit_v1);
    const auto explicit_v1_lowered = nginx::lower_to_rut(explicit_v1.value());
    REQUIRE(explicit_v1_lowered);
    CHECK_EQ(explicit_v1_lowered.value().len, 3345u);
    CHECK_NE(no_uri_lowered.value().len, explicit_v1_lowered.value().len);
    CHECK_NE(std::string(no_uri_lowered.value().data, no_uri_lowered.value().len),
             std::string(explicit_v1_lowered.value().data, explicit_v1_lowered.value().len));
    CHECK_EQ(
        count_text(std::string(explicit_v1_lowered.value().data, explicit_v1_lowered.value().len),
                   "target_transform:"),
        1u);

    static constexpr u32 kWildcardListenPrefixLen = sizeof("listen :") - 1u;
    static constexpr u32 kExactListenPrefixLen = sizeof("listen 127.0.0.1:") - 1u;
    static constexpr u32 kExactListenerDelta = kExactListenPrefixLen - kWildcardListenPrefixLen;
    static_assert(kWildcardListenPrefixLen == 8u);
    static_assert(kExactListenPrefixLen == 17u);
    static_assert(kExactListenerDelta == 9u);
    static_assert(nginx::RutSource::kCapacity == 5946u);

    const auto check_wildcard = [&](Str source, u32 expected_length, u32& actual_length) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        CHECK(parsed.value().listen.address == ListenerAddress::IPv4Wildcard);
        CHECK(parsed.value().location.path.eq(lit_str("/api/")));
        REQUIRE(parsed.value().location.proxy_pass.has_uri);
        CHECK(parsed.value().location.proxy_pass.uri.eq(lit_str("/v1/")));
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_length);
        CHECK(lowered.value().view().slice(0u, kWildcardListenPrefixLen).eq(lit_str("listen :")));
        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        delete ast.value();
        actual_length = lowered.value().len;
    };
    const auto check_exact = [&](Str source,
                                 u16 listener_port,
                                 u32 upstream_ipv4,
                                 u16 upstream_port,
                                 u32 expected_length) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        const auto& server = parsed.value();
        CHECK(server.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(server.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(server.listen.port, listener_port);
        CHECK(server.location.path.eq(lit_str("/api/")));
        CHECK(server.location.proxy_pass.uri.eq(lit_str("/v1/")));
        const auto& address = server.location.proxy_pass.address;
        const u32 actual_ipv4 = static_cast<u32>(address[0]) << 24u |
                                static_cast<u32>(address[1]) << 16u |
                                static_cast<u32>(address[2]) << 8u | static_cast<u32>(address[3]);
        CHECK_EQ(actual_ipv4, upstream_ipv4);
        CHECK_EQ(server.location.proxy_pass.port, upstream_port);
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_length);
        CHECK(lowered.value()
                  .view()
                  .slice(0u, sizeof("listen 127.0.0.1:") - 1u)
                  .eq(lit_str("listen 127.0.0.1:")));
        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        delete ast.value();
    };

    static constexpr char kRepresentativeWildcard[] =
        "server { listen 8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    static constexpr char kRepresentativeExact[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    u32 representative_wildcard = 0u;
    check_wildcard({kRepresentativeWildcard, sizeof(kRepresentativeWildcard) - 1u},
                   3336u,
                   representative_wildcard);
    const u32 representative_exact_projection = representative_wildcard + kExactListenerDelta;
    CHECK_EQ(representative_exact_projection, 3345u);
    CHECK_LT(representative_exact_projection, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - representative_exact_projection, 2601u);
    check_exact({kRepresentativeExact, sizeof(kRepresentativeExact) - 1u},
                8080u,
                0x7f000001u,
                9000u,
                3345u);

    static constexpr char kMaximumWildcard[] =
        "server { listen 65535; location /api/ { proxy_pass "
        "http://255.255.255.255:65535/v1/; } }";
    static constexpr char kMaximumExact[] =
        "server { listen 127.0.0.1:65535; location /api/ { proxy_pass "
        "http://255.255.255.255:65535/v1/; } }";
    u32 maximum_wildcard = 0u;
    check_wildcard({kMaximumWildcard, sizeof(kMaximumWildcard) - 1u}, 3344u, maximum_wildcard);
    const u32 maximum_exact_projection = maximum_wildcard + kExactListenerDelta;
    CHECK_EQ(maximum_exact_projection, 3353u);
    CHECK_LT(maximum_exact_projection, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum_exact_projection, 2593u);
    check_exact({kMaximumExact, sizeof(kMaximumExact) - 1u}, 65535u, 0xffffffffu, 65535u, 3353u);

    // A coherent wildcard counterpart isolates the scalar port-zero contract; the exact listener
    // guard intentionally runs before this downstream validation in the combined model.
    const auto wildcard_model =
        nginx::parse({kRepresentativeWildcard, sizeof(kRepresentativeWildcard) - 1u});
    REQUIRE(wildcard_model);
    auto alternate_endpoint = wildcard_model.value();
    alternate_endpoint.location.proxy_pass.address[0] = 126u;
    alternate_endpoint.location.proxy_pass.port = 9001u;
    const auto alternate_lowered = nginx::lower_to_rut(alternate_endpoint);
    REQUIRE(alternate_lowered);
    CHECK(strstr(alternate_lowered.value().data, "126.0.0.1:9001") != nullptr);
    auto zero_port = wildcard_model.value();
    zero_port.location.proxy_pass.port = 0u;
    const auto zero_port_rejected = nginx::lower_to_rut(zero_port);
    REQUIRE_FALSE(zero_port_rejected);
    CHECK_EQ(zero_port_rejected.error().code, FrontendError::InvalidInteger);
    CHECK(zero_port_rejected.error().detail.eq(lit_str("invalid model upstream port")));
    CHECK_EQ(zero_port_rejected.error().span.start, zero_port.location.proxy_pass.span.start);
    CHECK_EQ(zero_port_rejected.error().span.end, zero_port.location.proxy_pass.span.end);
    CHECK_EQ(zero_port_rejected.error().span.line, zero_port.location.proxy_pass.span.line);
    CHECK_EQ(zero_port_rejected.error().span.col, zero_port.location.proxy_pass.span.col);
}

TEST(nginx_converter,
     issue355_models_exact_loopback_non_root_no_uri_with_provenance_and_boundaries) {
    char listen_first[] =
        "server {\n"
        "  listen 127.0.0.1:8080;\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000;\n"
        "  }\n"
        "}\n";
    char location_first[] =
        "server {\n"
        "  location /api/ {\n"
        "    proxy_pass http://127.0.0.1:9000;\n"
        "  }\n"
        "  listen 127.0.0.1:8080;\n"
        "}\n";

    const auto check = [&](char* source, u32 source_len, u32 listen_line, u32 location_line) {
        const auto parsed = nginx::parse({source, source_len});
        REQUIRE(parsed);
        const nginx::Server& server = parsed.value();
        const nginx::Listen& listener = server.listen;
        const nginx::Location& location = server.location;
        const nginx::ProxyPass& proxy = location.proxy_pass;
        const char* server_start = strstr(source, "server");
        const char* server_close = strrchr(source, '}');
        const char* listen_start = strstr(source, "listen");
        const char* listen_value = strstr(listen_start, "127.0.0.1:8080");
        const char* listen_semicolon = strchr(listen_value, ';');
        const char* location_start = strstr(source, "location");
        const char* location_path = strstr(location_start, "/api/");
        const char* proxy_start = strstr(location_start, "proxy_pass");
        const char* endpoint = strstr(proxy_start, "http://127.0.0.1:9000");
        const char* proxy_semicolon = strchr(endpoint, ';');
        const char* location_close = strchr(proxy_semicolon, '}');
        REQUIRE(server_start != nullptr);
        REQUIRE(server_close != nullptr);
        REQUIRE(listen_start != nullptr);
        REQUIRE(listen_value != nullptr);
        REQUIRE(listen_semicolon != nullptr);
        REQUIRE(location_start != nullptr);
        REQUIRE(location_path != nullptr);
        REQUIRE(proxy_start != nullptr);
        REQUIRE(endpoint != nullptr);
        REQUIRE(proxy_semicolon != nullptr);
        REQUIRE(location_close != nullptr);

        const auto line = [&](const char* pointer) {
            u32 result = 1u;
            for (const char* cursor = source; cursor < pointer; cursor++)
                if (*cursor == '\n') result++;
            return result;
        };
        const auto col = [&](const char* pointer) {
            const char* cursor = pointer;
            while (cursor != source && cursor[-1] != '\n') cursor--;
            return static_cast<u32>(pointer - cursor + 1u);
        };
        const auto check_span = [&](Span span, const char* start, const char* end) {
            REQUIRE_EQ(span.start, static_cast<u32>(start - source));
            REQUIRE_EQ(span.end, static_cast<u32>(end - source));
            REQUIRE_EQ(span.line, line(start));
            REQUIRE_EQ(span.col, col(start));
        };
        check_span(server.span, server_start, server_close + 1u);
        check_span(listener.span, listen_start, listen_semicolon + 1u);
        check_span(listener.value_span, listen_value, listen_semicolon);
        check_span(location.span, location_start, location_close + 1u);
        check_span(location.path_span, location_path, location_path + 5u);
        check_span(proxy.span, proxy_start, proxy_semicolon + 1u);
        CHECK_EQ(listener.span.line, listen_line);
        CHECK_EQ(location.span.line, location_line);
        CHECK_EQ(proxy.span.line, location_line + 1u);

        REQUIRE(listener.address == ListenerAddress::IPv4Exact);
        REQUIRE_EQ(listener.ipv4_host, 0x7f000001u);
        REQUIRE_EQ(listener.port, 8080u);
        REQUIRE(listener.value.eq(lit_str("127.0.0.1:8080")));
        REQUIRE(location.path.eq(lit_str("/api/")));
        REQUIRE_EQ(proxy.address[0], 127u);
        REQUIRE_EQ(proxy.address[1], 0u);
        REQUIRE_EQ(proxy.address[2], 0u);
        REQUIRE_EQ(proxy.address[3], 1u);
        REQUIRE_EQ(proxy.port, 9000u);
        REQUIRE_FALSE(proxy.has_uri);
        REQUIRE_EQ(proxy.uri.ptr, nullptr);
        REQUIRE_EQ(proxy.uri.len, 0u);
        REQUIRE_EQ(proxy.uri_span.start, 0u);
        REQUIRE_EQ(proxy.uri_span.end, 0u);
        REQUIRE_EQ(proxy.uri_span.line, 1u);
        REQUIRE_EQ(proxy.uri_span.col, 1u);
        REQUIRE_FALSE(location.proxy_read_timeout.present);
        REQUIRE_FALSE(server.exact_local_return.present);
        REQUIRE_FALSE(server.exact_no_content_return.present);
        REQUIRE_FALSE(server.exact_absolute_redirect.present);
        REQUIRE(server.pre_route_trace.profile ==
                nginx::ImplicitPreRouteProfile::Nginx1297PreLocationTrace405);
        REQUIRE_EQ(server.pre_route_trace.span.start, server.span.start);
        REQUIRE_EQ(server.pre_route_trace.span.end, server.span.end);

        const uintptr_t source_base = reinterpret_cast<uintptr_t>(source);
        REQUIRE_EQ(reinterpret_cast<uintptr_t>(listener.value.ptr) - listener.value_span.start,
                   source_base);
        REQUIRE_EQ(reinterpret_cast<uintptr_t>(location.path.ptr) - location.path_span.start,
                   source_base);
        REQUIRE_GE(location.path_span.start, location.span.start);
        REQUIRE_LT(location.path_span.end, proxy.span.start);
        REQUIRE_LT(proxy.span.end, location.span.end);

        const auto expect_unsupported =
            [&](const nginx::Server& candidate, Str detail, Span expected_span) {
                const auto lowered = nginx::lower_to_rut(candidate);
                REQUIRE_FALSE(lowered);
                CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
                CHECK(lowered.error().detail.eq(detail));
                CHECK_EQ(lowered.error().span.start, expected_span.start);
                CHECK_EQ(lowered.error().span.end, expected_span.end);
                CHECK_EQ(lowered.error().span.line, expected_span.line);
                CHECK_EQ(lowered.error().span.col, expected_span.col);
            };
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, 3244u);
        const std::string generated(lowered.value().data, lowered.value().len);
        CHECK_EQ(count_text(generated, "return forward(nginx_upstream, request_policy: {"), 1u);
        CHECK_EQ(count_text(generated, "target_transform:"), 0u);
        CHECK_EQ(count_text(generated, "strip_prefix:"), 0u);
        CHECK_EQ(count_text(generated, "replace_prefix:"), 0u);

        std::vector<char> independent(source, source + source_len);
        auto forged = server;
        forged.listen.value.ptr = independent.data() + listener.value_span.start;
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), listener.value_span);
        forged = server;
        forged.location.path.ptr = independent.data() + location.path_span.start;
        expect_unsupported(
            forged, lit_str("invalid listen source provenance"), listener.value_span);

        forged = server;
        forged.location.path_span.end--;
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.path_span);
        forged = server;
        forged.location.span.start++;
        forged.location.span.col++;
        CHECK_EQ(forged.location.path_span.start - forged.location.span.start, 8u);
        expect_unsupported(forged, lit_str("invalid proxy location spans"), forged.location.span);
        forged = server;
        forged.location.span.line++;
        expect_unsupported(
            forged, lit_str("invalid proxy location spans"), forged.location.path_span);
        forged = server;
        forged.location.proxy_pass.span.end--;
        expect_unsupported(
            forged, lit_str("invalid proxy location source syntax"), forged.location.span);

        forged = server;
        forged.location.proxy_pass.has_uri = true;
        expect_unsupported(forged,
                           lit_str("invalid bounded proxy_pass URI model"),
                           forged.location.proxy_pass.uri_span);
        forged = server;
        forged.location.proxy_pass.uri.ptr = source + proxy.span.start;
        expect_unsupported(
            forged, lit_str("invalid proxy_pass URI state"), forged.location.proxy_pass.span);
        forged = server;
        forged.location.proxy_pass.uri.len = 1u;
        expect_unsupported(
            forged, lit_str("invalid proxy_pass URI state"), forged.location.proxy_pass.span);
        forged = server;
        forged.location.proxy_pass.uri_span = proxy.span;
        expect_unsupported(
            forged, lit_str("invalid proxy_pass URI state"), forged.location.proxy_pass.span);

        forged = server;
        forged.location.proxy_pass.address[3] = 2u;
        expect_unsupported(
            forged, lit_str("invalid upstream endpoint model"), forged.location.proxy_pass.span);
        forged = server;
        forged.location.proxy_pass.port = 9001u;
        expect_unsupported(
            forged, lit_str("invalid upstream endpoint model"), forged.location.proxy_pass.span);
        forged = server;
        forged.listen.port = 8081u;
        expect_unsupported(
            forged, lit_str("invalid exact listen endpoint model"), forged.listen.value_span);

        forged = server;
        forged.location.proxy_read_timeout.milliseconds = 1000u;
        expect_unsupported(
            forged, lit_str("invalid absent proxy_read_timeout model"), forged.location.span);
        forged = server;
        forged.exact_no_content_return.response.status = 204u;
        expect_unsupported(
            forged, lit_str("invalid absent exact no-content return model"), forged.span);
        forged = server;
        forged.exact_local_return.response.status = 200u;
        expect_unsupported(forged, lit_str("invalid absent exact local return model"), forged.span);
        forged = server;
        forged.exact_absolute_redirect.response.status = 302u;
        expect_unsupported(
            forged, lit_str("invalid absent exact absolute redirect model"), forged.span);

        const char saved_proxy_keyword = *proxy_start;
        *const_cast<char*>(proxy_start) = 'P';
        expect_unsupported(server, lit_str("invalid proxy_pass source syntax"), proxy.span);
        *const_cast<char*>(proxy_start) = saved_proxy_keyword;
        const char saved_location_keyword = *location_start;
        *const_cast<char*>(location_start) = 'L';
        expect_unsupported(server, lit_str("invalid proxy location source syntax"), location.span);
        *const_cast<char*>(location_start) = saved_location_keyword;
        const char saved_proxy_semicolon = *proxy_semicolon;
        *const_cast<char*>(proxy_semicolon) = ':';
        expect_unsupported(server, lit_str("invalid proxy_pass source syntax"), proxy.span);
        *const_cast<char*>(proxy_semicolon) = saved_proxy_semicolon;
        const char saved_location_close = *location_close;
        *const_cast<char*>(location_close) = ';';
        expect_unsupported(server, lit_str("invalid proxy location source syntax"), location.span);
        *const_cast<char*>(location_close) = saved_location_close;
        const char saved_endpoint = endpoint[sizeof("http://127.0.0.1:") - 1u];
        *const_cast<char*>(endpoint + sizeof("http://127.0.0.1:") - 1u) = '8';
        expect_unsupported(server, lit_str("invalid upstream endpoint model"), proxy.span);
        *const_cast<char*>(endpoint + sizeof("http://127.0.0.1:") - 1u) = saved_endpoint;
        const char saved_path = location_path[1];
        *const_cast<char*>(location_path + 1u) = '%';
        expect_unsupported(
            server, lit_str("invalid bounded proxy location path model"), location.path_span);
        *const_cast<char*>(location_path + 1u) = saved_path;

        const nginx::Server retained = server;
        const Span retained_server_span = server.span;
        const Span retained_listener_span = listener.span;
        const Span retained_path_span = location.path_span;
        const Span retained_proxy_span = proxy.span;
        memset(source, 'x', source_len);
        CHECK(retained.listen.address == ListenerAddress::IPv4Exact);
        CHECK_EQ(retained.listen.ipv4_host, 0x7f000001u);
        CHECK_EQ(retained.listen.port, 8080u);
        CHECK_EQ(retained.location.path.len, 5u);
        CHECK_EQ(retained.location.proxy_pass.address[0], 127u);
        CHECK_EQ(retained.location.proxy_pass.address[3], 1u);
        CHECK_EQ(retained.location.proxy_pass.port, 9000u);
        CHECK_FALSE(retained.location.proxy_pass.has_uri);
        CHECK_EQ(retained.location.proxy_pass.uri.ptr, nullptr);
        CHECK_EQ(retained.location.proxy_pass.uri.len, 0u);
        CHECK_EQ(retained.location.proxy_pass.uri_span.start, 0u);
        CHECK_EQ(retained.location.proxy_pass.uri_span.end, 0u);
        CHECK_EQ(retained.span.start, retained_server_span.start);
        CHECK_EQ(retained.span.end, retained_server_span.end);
        CHECK_EQ(retained.listen.span.start, retained_listener_span.start);
        CHECK_EQ(retained.listen.span.end, retained_listener_span.end);
        CHECK_EQ(retained.location.path_span.start, retained_path_span.start);
        CHECK_EQ(retained.location.path_span.end, retained_path_span.end);
        CHECK_EQ(retained.location.proxy_pass.span.start, retained_proxy_span.start);
        CHECK_EQ(retained.location.proxy_pass.span.end, retained_proxy_span.end);
        // Borrowed listener/path bytes are invalid after overwrite and are not read.
    };

    check(listen_first, sizeof(listen_first) - 1u, 2u, 3u);
    check(location_first, sizeof(location_first) - 1u, 5u, 2u);

    const auto check_boundary = [&](Str source, u32 expected_path_len, u32 expected_source_len) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        const auto& server = parsed.value();
        CHECK_EQ(server.location.path.len, expected_path_len);
        CHECK_FALSE(server.location.proxy_pass.has_uri);
        CHECK_EQ(server.location.proxy_pass.uri.ptr, nullptr);
        CHECK_EQ(server.location.proxy_pass.uri.len, 0u);
        CHECK_EQ(server.location.proxy_pass.uri_span.start, 0u);
        CHECK_EQ(server.location.proxy_pass.uri_span.end, 0u);
        const auto lowered = nginx::lower_to_rut(server);
        REQUIRE(lowered);
        CHECK_EQ(lowered.value().len, expected_source_len);
        CHECK_LT(lowered.value().len, nginx::RutSource::kCapacity);
        const std::string generated(lowered.value().data, lowered.value().len);
        CHECK_EQ(count_text(generated, "target_transform:"), 0u);
        CHECK_EQ(count_text(generated, "strip_prefix:"), 0u);
        CHECK_EQ(count_text(generated, "replace_prefix:"), 0u);
    };
    static constexpr char kMinimum[] =
        "server { listen 127.0.0.1:1; location /a/ { proxy_pass "
        "http://0.0.0.0:1; } }";
    check_boundary({kMinimum, sizeof(kMinimum) - 1u}, 3u, 3230u);
    char max_path[nginx::kMaxProxyLocationPathLen + 1u]{};
    max_path[0] = '/';
    memset(max_path + 1u, 'a', nginx::kMaxProxyLocationPathLen - 2u);
    max_path[nginx::kMaxProxyLocationPathLen - 1u] = '/';
    char maximum[512]{};
    const int maximum_len = snprintf(maximum,
                                     sizeof(maximum),
                                     "server { listen 127.0.0.1:65535; location %s { proxy_pass "
                                     "http://255.255.255.255:65535; } }",
                                     max_path);
    REQUIRE_GT(maximum_len, 0);
    REQUIRE_LT(static_cast<u32>(maximum_len), static_cast<u32>(sizeof(maximum)));
    check_boundary(
        {maximum, static_cast<u32>(maximum_len)}, nginx::kMaxProxyLocationPathLen, 3426u);

    char over_path[nginx::kMaxProxyLocationPathLen + 2u]{};
    over_path[0] = '/';
    memset(over_path + 1u, 'a', nginx::kMaxProxyLocationPathLen - 1u);
    over_path[nginx::kMaxProxyLocationPathLen] = '/';
    char over_limit[512]{};
    const int over_limit_len = snprintf(over_limit,
                                        sizeof(over_limit),
                                        "server { listen 8080; location %s { proxy_pass "
                                        "http://127.0.0.1:9000; } }",
                                        over_path);
    REQUIRE_GT(over_limit_len, 0);
    const auto rejected = nginx::parse({over_limit, static_cast<u32>(over_limit_len)});
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::UnsupportedSyntax);
    CHECK(rejected.error().detail.eq(
        lit_str("location path is outside the bounded clean proxy profile")));
}

TEST(nginx_converter, issue355_exact_loopback_api_no_uri_has_canonical_no_transform_golden) {
    char listen_first[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000; } }";
    char location_first[] =
        "server { location /api/ { proxy_pass http://127.0.0.1:9000; } "
        "listen 127.0.0.1:8080; }";
    const auto lower = [](char* source, u32 len) -> FrontendResult<nginx::RutSource> {
        const auto parsed = nginx::parse({source, len});
        if (!parsed) return core::make_unexpected(parsed.error());
        return nginx::lower_to_rut(parsed.value());
    };
    const auto first = lower(listen_first, sizeof(listen_first) - 1u);
    const auto second = lower(location_first, sizeof(location_first) - 1u);
    REQUIRE(first);
    REQUIRE(second);
    REQUIRE_EQ(first.value().len, 3244u);
    REQUIRE_EQ(second.value().len, 3244u);
    const std::string exact(first.value().data, first.value().len);
    REQUIRE_EQ(exact, std::string(second.value().data, second.value().len));

    // The accepted no-URI source is the fixed /api/ -> /v1/ program with exactly the complete
    // target-transform kwarg removed. This full-byte relation pins every other emitted byte and
    // prevents an empty replacement or a hidden path rewrite from standing in for absence.
    char replacement_source[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    const auto replacement = lower(replacement_source, sizeof(replacement_source) - 1u);
    REQUIRE(replacement);
    REQUIRE_EQ(replacement.value().len, 3345u);
    std::string expected(replacement.value().data, replacement.value().len);
    static constexpr char kTransform[] =
        " target_transform: {\n"
        "            strip_prefix: \"/api/\",\n"
        "            replace_prefix: \"/v1/\"\n"
        "        },";
    const size_t transform = expected.find(kTransform);
    REQUIRE_NE(transform, std::string::npos);
    REQUIRE_EQ(expected.find(kTransform, transform + sizeof(kTransform) - 1u), std::string::npos);
    expected.erase(transform, sizeof(kTransform) - 1u);
    REQUIRE_EQ(expected, exact);

    memset(listen_first, 'x', sizeof(listen_first) - 1u);
    memset(location_first, 'y', sizeof(location_first) - 1u);
    memset(replacement_source, 'z', sizeof(replacement_source) - 1u);
    CHECK_EQ(std::string(first.value().data, first.value().len), exact);
    CHECK_EQ(std::string(second.value().data, second.value().len), exact);

    static constexpr char kMaximum[] =
        "server { listen 127.0.0.1:65535; location /api/ { proxy_pass "
        "http://255.255.255.255:65535; } }";
    const auto maximum_parsed = nginx::parse({kMaximum, sizeof(kMaximum) - 1u});
    REQUIRE(maximum_parsed);
    const auto maximum = nginx::lower_to_rut(maximum_parsed.value());
    REQUIRE(maximum);
    CHECK_EQ(maximum.value().len, 3252u);
    CHECK_LT(maximum.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum.value().len, 2694u);
    CHECK_EQ(
        count_text(std::string(maximum.value().data, maximum.value().len), "target_transform:"),
        0u);

    static constexpr char kWildcardNoUri[] =
        "server { listen 8080; location /api/ { proxy_pass http://127.0.0.1:9000; } }";
    const auto wildcard_parsed = nginx::parse({kWildcardNoUri, sizeof(kWildcardNoUri) - 1u});
    REQUIRE(wildcard_parsed);
    const auto wildcard_lowered = nginx::lower_to_rut(wildcard_parsed.value());
    REQUIRE(wildcard_lowered);
    CHECK_EQ(wildcard_lowered.value().len, 3235u);
    CHECK_EQ(count_text(std::string(wildcard_lowered.value().data, wildcard_lowered.value().len),
                        "target_transform:"),
             0u);

    const auto listener_is_canonical = [](const std::string& source) {
        return source.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(source, "listen 127.0.0.1:8080\n") == 1u &&
               source.find("listen :") == std::string::npos &&
               source.find("127.0.0.2") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& source) {
        return count_upstream_declarations(source) == 1u &&
               count_text(source, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_is_canonical = [](const std::string& source) {
        return count_text(source, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(source, "pre_route TRACE") == 1u;
    };
    const auto route_is_canonical = [](const std::string& source) {
        return count_route_declarations(source) == 1u &&
               count_text(source, "route \"/api\" {\n") == 1u &&
               count_text(source, "if req.method == GET && req.pathOnly == \"/api\" {") == 1u &&
               count_text(source, "return redirect({scheme: \"http\"") == 1u &&
               count_text(source, "path: \"static\", query: \"preserve_raw\"") == 1u &&
               count_text(source, "target_path: \"/api/\"") == 1u &&
               count_text(source, "return forward(nginx_upstream,") == 1u;
    };
    const auto has_no_transform = [](const std::string& source) {
        return source.find("target_transform") == std::string::npos &&
               source.find("strip_prefix") == std::string::npos &&
               source.find("replace_prefix") == std::string::npos &&
               source.find("set_path") == std::string::npos;
    };
    const auto region_equals = [](const std::string& source,
                                  const char* begin_marker,
                                  const char* end_marker,
                                  const char* expected_region) {
        const size_t begin = source.find(begin_marker);
        if (begin == std::string::npos ||
            source.find(begin_marker, begin + strlen(begin_marker)) != std::string::npos)
            return false;
        const size_t end = source.find(end_marker, begin + strlen(begin_marker));
        return end != std::string::npos && strlen(expected_region) == end - begin &&
               source.compare(begin, end - begin, expected_region) == 0;
    };
    const auto request_policy_is_canonical = [&](const std::string& source) {
        static constexpr char kExpected[] =
            "request_policy: {\n"
            "            version: \"HTTP/1.1\",\n"
            "            host: \"upstream\",\n"
            "            connection: \"omit\",\n"
            "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
            "\"Upgrade\"]\n";
        return count_text(source, "request_policy: {") == 1u &&
               region_equals(source, "request_policy: {", "        }, response_policy:", kExpected);
    };
    const auto response_policy_is_canonical = [&](const std::string& source) {
        static constexpr char kExpected[] =
            "response_policy: {\n"
            "            version: \"HTTP/1.1\",\n"
            "            framing: \"content_length\",\n"
            "            connection: \"request\",\n"
            "            server: \"nginx/1.29.7\",\n"
            "            date: \"current\",\n"
            "            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n";
        return count_text(source, "response_policy: {") == 1u &&
               region_equals(source, "response_policy: {", "        }, failure_policy:", kExpected);
    };
    const auto failure_policy_is_canonical = [&](const std::string& source) {
        static constexpr char kExpected[] =
            "failure_policy: {\n"
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
            "html>\\r\\n\"\n";
        return count_text(source, "failure_policy: {") == 1u &&
               region_equals(source, "failure_policy: {", "        })\n", kExpected);
    };
    const auto unmatched_is_canonical = [](const std::string& source) {
        return count_text(source, "\nunmatched ") == 3u &&
               count_text(source,
                          "unmatched OPTIONS { return local_response({\n"
                          "  version: \"HTTP/1.1\", status: 400,") == 1u &&
               count_text(source,
                          "unmatched CONNECT { return local_response({\n"
                          "  version: \"HTTP/1.1\", status: 405,") == 1u &&
               count_text(source,
                          "\nunmatched { return local_response({\n"
                          "  version: \"HTTP/1.1\", status: 400,") == 1u;
    };
    const auto timeout_is_canonical = [](const std::string& source) {
        return source.find("timeout_failure_policy:") == std::string::npos &&
               source.find("response_read_timeout:") == std::string::npos &&
               source.find("response_buffering:") == std::string::npos;
    };
    const auto has_no_hook = [](const std::string& source) {
        for (const char* marker : {"nginx.conf",
                                   "nginx::",
                                   "nginx_compat",
                                   "workaround",
                                   "bind_address",
                                   "local_address",
                                   "req.listener",
                                   "address_condition"})
            if (source.find(marker) != std::string::npos) return false;
        return true;
    };
    const auto source_is_canonical = [&](const std::string& source) {
        return listener_is_canonical(source) && upstream_is_canonical(source) &&
               pre_route_is_canonical(source) && route_is_canonical(source) &&
               has_no_transform(source) && request_policy_is_canonical(source) &&
               response_policy_is_canonical(source) && failure_policy_is_canonical(source) &&
               unmatched_is_canonical(source) && timeout_is_canonical(source) &&
               has_no_hook(source);
    };
    REQUIRE(source_is_canonical(exact));

    const auto replace_unique = [&](std::string source, Str before, Str after) {
        const std::string needle(before.ptr, before.len);
        const size_t offset = source.find(needle);
        if (needle.empty() || before.eq(after) || offset == std::string::npos ||
            source.find(needle, offset + needle.size()) != std::string::npos) {
            CHECK(false);
            return std::string{};
        }
        source.replace(offset, needle.size(), after.ptr, after.len);
        CHECK_FALSE(source.empty());
        CHECK_NE(source, exact);
        return source;
    };
    enum class Guard : u8 {
        Listener,
        Upstream,
        PreRoute,
        Route,
        Transform,
        Request,
        Response,
        Failure,
        Unmatched,
        Timeout,
    };
    const auto check_isolated = [&](const std::string& candidate, Guard rejected) {
        REQUIRE_FALSE(candidate.empty());
        const bool guards[] = {listener_is_canonical(candidate),
                               upstream_is_canonical(candidate),
                               pre_route_is_canonical(candidate),
                               route_is_canonical(candidate),
                               has_no_transform(candidate),
                               request_policy_is_canonical(candidate),
                               response_policy_is_canonical(candidate),
                               failure_policy_is_canonical(candidate),
                               unmatched_is_canonical(candidate),
                               timeout_is_canonical(candidate)};
        for (u32 i = 0u; i < std::size(guards); i++)
            CHECK_EQ(guards[i], i != static_cast<u32>(rejected));
        CHECK(has_no_hook(candidate));
        CHECK_FALSE(source_is_canonical(candidate));
    };
    const struct {
        Str before;
        Str after;
        Guard rejected;
    } structure_mutations[] = {
        {lit_str("listen 127.0.0.1:8080\n"), lit_str("listen 127.0.0.2:8080\n"), Guard::Listener},
        {lit_str("127.0.0.1:9000"), lit_str("127.0.0.1:9001"), Guard::Upstream},
        {lit_str("pre_route TRACE {"), lit_str("pre_route TRACX {"), Guard::PreRoute},
        {lit_str("route \"/api\" {"), lit_str("route \"/apx\" {"), Guard::Route},
        {lit_str("query: \"preserve_raw\""), lit_str("query: \"discard\""), Guard::Route},
        {lit_str("target_path: \"/api/\""), lit_str("target_path: \"/apx/\""), Guard::Route},
        {lit_str("return forward(nginx_upstream, request_policy: {"),
         lit_str("return forwarX(nginx_upstream, request_policy: {"),
         Guard::Route},
        {lit_str("host: \"upstream\""), lit_str("host: \"upstreaX\""), Guard::Request},
        {lit_str("framing: \"content_length\""),
         lit_str("framing: \"content_lengtx\""),
         Guard::Response},
        {lit_str("status: 502,"), lit_str("status: 503,"), Guard::Failure},
        {lit_str("unmatched OPTIONS { return local_response({\n"
                 "  version: \"HTTP/1.1\", status: 400,"),
         lit_str("unmatched OPTIONS { return local_response({\n"
                 "  version: \"HTTP/1.1\", status: 401,"),
         Guard::Unmatched},
        {lit_str("unmatched CONNECT { return local_response({\n"
                 "  version: \"HTTP/1.1\", status: 405,"),
         lit_str("unmatched CONNECT { return local_response({\n"
                 "  version: \"HTTP/1.1\", status: 406,"),
         Guard::Unmatched},
        {lit_str("\nunmatched { return local_response({\n"
                 "  version: \"HTTP/1.1\", status: 400,"),
         lit_str("\nunmatched { return local_response({\n"
                 "  version: \"HTTP/1.1\", status: 401,"),
         Guard::Unmatched},
    };
    for (const auto& mutation : structure_mutations)
        check_isolated(replace_unique(exact, mutation.before, mutation.after), mutation.rejected);
    static constexpr char kInjectedTransform[] =
        "return forward(nginx_upstream, target_transform: {\n"
        "            strip_prefix: \"/api/\",\n"
        "            replace_prefix: \"/\"\n"
        "        }, request_policy: {";
    check_isolated(replace_unique(exact,
                                  lit_str("return forward(nginx_upstream, request_policy: {"),
                                  {kInjectedTransform, sizeof(kInjectedTransform) - 1u}),
                   Guard::Transform);
    check_isolated(exact + "// response_read_timeout: forbidden\n", Guard::Timeout);
    check_isolated(exact + "// set_path marker\n", Guard::Transform);
    for (const char* marker : {"nginx.conf",
                               "nginx::",
                               "nginx_compat",
                               "workaround",
                               "bind_address",
                               "local_address",
                               "req.listener",
                               "address_condition"}) {
        const std::string hook = exact + "// " + marker + " marker\n";
        REQUIRE_NE(hook, exact);
        CHECK(listener_is_canonical(hook));
        CHECK(upstream_is_canonical(hook));
        CHECK(pre_route_is_canonical(hook));
        CHECK(route_is_canonical(hook));
        CHECK(has_no_transform(hook));
        CHECK(request_policy_is_canonical(hook));
        CHECK(response_policy_is_canonical(hook));
        CHECK(failure_policy_is_canonical(hook));
        CHECK(unmatched_is_canonical(hook));
        CHECK_FALSE(has_no_hook(hook));
        CHECK_FALSE(source_is_canonical(hook));
        const auto hook_lexed = lex({hook.data(), static_cast<u32>(hook.size())});
        REQUIRE(hook_lexed);
        const auto hook_parsed = parse_file(hook_lexed.value());
        REQUIRE(hook_parsed);
        delete hook_parsed.value();
    }
    const std::string harmless = exact + "// canonical byte equality witness\n";
    REQUIRE(source_is_canonical(harmless));
    REQUIRE_NE(harmless, exact);

    const auto lexed = lex({exact.data(), static_cast<u32>(exact.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast->items[0].listen.port, 8080u);
    const AstRouteDecl* ast_route = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++)
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.path.eq(lit_str("/api")))
            ast_route = &ast->items[i].route;
    REQUIRE(ast_route != nullptr);
    REQUIRE_EQ(ast_route->statements.len, 1u);
    const AstStatement& ast_if = *ast_route->statements[0];
    REQUIRE(ast_if.kind == AstStmtKind::If);
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.else_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    CHECK(ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u].target_path.eq(
        lit_str("/api/")));
    const AstStatement* ast_forward = ast_if.else_stmt;
    if (ast_forward->kind == AstStmtKind::Block) {
        REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
        ast_forward = ast_forward->block_stmts[0];
    }
    REQUIRE(ast_forward != nullptr);
    REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
    CHECK_FALSE(ast_forward->has_forward_target_transform);
    CHECK_EQ(ast_forward->forward_target_transform.strip_prefix.ptr, nullptr);
    CHECK_EQ(ast_forward->forward_target_transform.replace_prefix.ptr, nullptr);
    REQUIRE(ast_forward->has_forward_request_policy);
    REQUIRE(ast_forward->has_forward_response_policy);
    REQUIRE(ast_forward->has_forward_failure_policy);

    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir->listener.ipv4_host, 0x7f000001u);
    REQUIRE_EQ(hir->routes.len, 1u);
    const HirRoute& hir_route = hir->routes[0];
    CHECK(hir_route.path.eq(lit_str("/api")));
    REQUIRE(hir_route.control.kind == HirControlKind::If);
    REQUIRE(hir_route.control.then_term.kind == HirTerminatorKind::Redirect);
    const HirTerminator& hir_forward = hir_route.control.else_term;
    REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
    CHECK_FALSE(hir_forward.has_forward_target_transform);
    CHECK_EQ(hir_forward.forward_target_transform.strip_prefix.ptr, nullptr);
    CHECK_EQ(hir_forward.forward_target_transform.replace_prefix.ptr, nullptr);
    REQUIRE_NE(hir_forward.forward_request_policy_id, 0u);
    REQUIRE_NE(hir_forward.forward_response_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_response_policy_id, hir->response_policies.len);
    REQUIRE_NE(hir_forward.forward_failure_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_failure_policy_id, hir->failure_policies.len);

    const auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());
    const MirTerminator* mir_forward = nullptr;
    for (u32 block = 0u; block < mir->functions[0].blocks.len; block++)
        if (mir->functions[0].blocks[block].term.kind == MirTerminatorKind::ForwardUpstream)
            mir_forward = &mir->functions[0].blocks[block].term;
    REQUIRE(mir_forward != nullptr);
    CHECK_FALSE(mir_forward->has_forward_target_transform);
    REQUIRE_NE(mir_forward->forward_request_policy_id, 0u);
    REQUIRE_NE(mir_forward->forward_response_policy_id, 0u);
    REQUIRE_NE(mir_forward->forward_failure_policy_id, 0u);

    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.target_transform_count, 0u);
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    REQUIRE_EQ(rir.module.response_policy_count, 1u);
    REQUIRE_EQ(rir.module.failure_policy_count, 1u);
    REQUIRE_EQ(rir.module.policy_bundle_count, 1u);
    CHECK(rir.module.redirect_policies[0].target_path.eq(lit_str("/api/")));
    CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);
    bool saw_forward = false;
    bool saw_transform = false;
    for (u32 block = 0u; block < rir.module.functions[0].block_count; block++) {
        const auto& rir_block = rir.module.functions[0].blocks[block];
        for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
            const auto& inst = rir_block.insts[instruction];
            if (inst.op == rir::Opcode::ReqSetTargetTransform) saw_transform = true;
            if (inst.op != rir::Opcode::RetForwardBundle) continue;
            saw_forward = true;
            REQUIRE_EQ(inst.operand_count, 3u);
            i32 upstream_id = -1;
            i32 request_policy_id = -1;
            i32 bundle_id = -1;
            REQUIRE(find_const_i32(rir.module.functions[0], inst.operand(0), upstream_id));
            REQUIRE(find_const_i32(rir.module.functions[0], inst.operand(1), request_policy_id));
            REQUIRE(find_const_i32(rir.module.functions[0], inst.operand(2), bundle_id));
            CHECK_EQ(upstream_id, 0);
            CHECK_EQ(request_policy_id, static_cast<i32>(RequestPolicyId::Http11FixedStrip));
            CHECK_EQ(bundle_id, 1);
        }
    }
    CHECK(saw_forward);
    CHECK_FALSE(saw_transform);
}

TEST(nginx_converter,
     issue356_exact_loopback_complete_clean_no_uri_prefix_class_is_generic_and_owned) {
    const auto make_source = [](const std::string& path,
                                bool listen_first,
                                const char* listen_port = "8080",
                                const char* upstream = "127.0.0.1:9000") {
        const std::string listener = "  listen 127.0.0.1:" + std::string(listen_port) + ";\n";
        const std::string location =
            "  location " + path + " {\n    proxy_pass http://" + upstream + ";\n  }\n";
        return "server {\n" + (listen_first ? listener + location : location + listener) + "}\n";
    };
    const auto lower = [](std::string& source) -> FrontendResult<nginx::RutSource> {
        const auto parsed = nginx::parse({source.data(), static_cast<u32>(source.size())});
        if (!parsed) return core::make_unexpected(parsed.error());
        return nginx::lower_to_rut(parsed.value());
    };
    const auto count = [](const std::string& source, const std::string& needle) {
        u32 result = 0u;
        for (size_t offset = 0u;;) {
            offset = source.find(needle, offset);
            if (offset == std::string::npos) return result;
            result++;
            offset += needle.size();
        }
    };
    const auto validate_shape = [&](const std::string& source,
                                    const std::string& path,
                                    u32 expected_len,
                                    const std::string& listener,
                                    const std::string& upstream) {
        REQUIRE_EQ(source.size(), expected_len);
        REQUIRE_EQ(source.rfind(listener, 0u), 0u);
        CHECK_EQ(count(source, listener), 1u);
        CHECK_EQ(count(source, upstream), 1u);
        const std::string route = path.substr(0u, path.size() - 1u);
        CHECK_EQ(count(source, "route \"" + route + "\" {\n"), 1u);
        CHECK_EQ(count(source, "req.pathOnly == \"" + route + "\""), 1u);
        CHECK_EQ(count(source, "target_path: \"" + path + "\""), 1u);
        CHECK_EQ(count(source, "return forward(nginx_upstream, request_policy: {"), 1u);
        CHECK_EQ(count(source, "target_transform:"), 0u);
        CHECK_EQ(count(source, "strip_prefix:"), 0u);
        CHECK_EQ(count(source, "replace_prefix:"), 0u);
        CHECK_EQ(count(source, "set_path"), 0u);
        CHECK_EQ(count(source, "pre_route TRACE"), 1u);
        CHECK_EQ(count_route_declarations(source), 1u);
        for (const char* marker : {"nginx.conf",
                                   "nginx::",
                                   "nginx_compat",
                                   "workaround",
                                   "bind_address",
                                   "local_address",
                                   "req.listener",
                                   "address_condition"})
            CHECK_EQ(source.find(marker), std::string::npos);
    };
    const auto lower_both =
        [&](const std::string& path, u32 expected_len, std::string& canonical_output) {
            std::string first_source = make_source(path, true);
            std::string second_source = make_source(path, false);
            const auto first = lower(first_source);
            const auto second = lower(second_source);
            REQUIRE(first);
            REQUIRE(second);
            REQUIRE_EQ(first.value().len, expected_len);
            REQUIRE_EQ(second.value().len, expected_len);
            CHECK_EQ(first.value().data[first.value().len], '\0');
            CHECK_EQ(second.value().data[second.value().len], '\0');
            const std::string first_rut(first.value().data, first.value().len);
            const std::string second_rut(second.value().data, second.value().len);
            REQUIRE_EQ(first_rut, second_rut);
            validate_shape(first_rut,
                           path,
                           expected_len,
                           "listen 127.0.0.1:8080\n",
                           "upstream nginx_upstream at \"127.0.0.1:9000\"\n");
            const nginx::RutSource owned = first.value();
            std::fill(first_source.begin(), first_source.end(), 'x');
            std::fill(second_source.begin(), second_source.end(), 'y');
            CHECK_EQ(std::string(owned.data, owned.len), first_rut);
            CHECK_EQ(owned.data[owned.len], '\0');
            canonical_output = first_rut;
        };

    std::string p3;
    std::string api;
    std::string service;
    lower_both("/a/", 3238u, p3);
    lower_both("/api/", 3244u, api);
    lower_both("/service/", 3256u, service);
    std::string p63 = "/" + std::string(61u, 'p') + "/";
    REQUIRE_EQ(p63.size(), 63u);
    std::string p63_rut;
    lower_both(p63, 3418u, p63_rut);
    std::string nested = "/";
    for (u32 i = 0u; i < 29u; i++) nested += "a/";
    nested += "bbb/";
    REQUIRE_EQ(nested.size(), 63u);
    std::string nested_rut;
    lower_both(nested, 3418u, nested_rut);
    CHECK_NE(p3, api);
    CHECK_NE(api, service);
    CHECK_NE(p63_rut, nested_rut);
    CHECK_EQ(p63_rut.size(), 3244u + 3u * (63u - 5u));

    // The generic P63 program is mechanically the closed /api/ program with exactly the two
    // route-key occurrences and the one redirect-target occurrence changed.  This pins every
    // policy and control-flow byte while keeping the dynamic path evidence explicit.
    std::string api_as_p63 = api;
    const std::string route = p63.substr(0u, p63.size() - 1u);
    const auto replace_exactly_once =
        [&](std::string& value, const std::string& from, const std::string& to) {
            const size_t offset = from.empty() ? std::string::npos : value.find(from);
            REQUIRE_FALSE(from.empty());
            REQUIRE_NE(from, to);
            REQUIRE_NE(offset, std::string::npos);
            REQUIRE_EQ(value.find(from, offset + from.size()), std::string::npos);
            value.replace(offset, from.size(), to);
        };
    replace_exactly_once(api_as_p63, "route \"/api\" {", "route \"" + route + "\" {");
    replace_exactly_once(
        api_as_p63, "req.pathOnly == \"/api\"", "req.pathOnly == \"" + route + "\"");
    replace_exactly_once(api_as_p63, "target_path: \"/api/\"", "target_path: \"" + p63 + "\"");
    REQUIRE_EQ(api_as_p63, p63_rut);

    const auto exact_region = [](const std::string& candidate,
                                 const std::string& canonical,
                                 const char* begin_marker,
                                 const char* end_marker) {
        const size_t candidate_begin = candidate.find(begin_marker);
        const size_t canonical_begin = canonical.find(begin_marker);
        if (candidate_begin == std::string::npos || canonical_begin == std::string::npos ||
            candidate.find(begin_marker, candidate_begin + strlen(begin_marker)) !=
                std::string::npos ||
            canonical.find(begin_marker, canonical_begin + strlen(begin_marker)) !=
                std::string::npos)
            return false;
        const size_t candidate_end = candidate.find(end_marker, candidate_begin);
        const size_t canonical_end = canonical.find(end_marker, canonical_begin);
        return candidate_end != std::string::npos && canonical_end != std::string::npos &&
               candidate_end - candidate_begin == canonical_end - canonical_begin &&
               candidate.compare(candidate_begin,
                                 candidate_end - candidate_begin,
                                 canonical,
                                 canonical_begin,
                                 canonical_end - canonical_begin) == 0;
    };
    const auto pre_route_is_canonical = [&](const std::string& candidate) {
        return count(candidate, "pre_route TRACE") == 1u &&
               exact_region(candidate, p63_rut, "pre_route TRACE", "route \"");
    };
    const auto redirect_is_canonical = [&](const std::string& candidate) {
        return count(candidate, "return redirect({scheme: \"http\"") == 1u &&
               count(candidate, "authority: \"request_host\", port: \"actual_listener\"") == 1u &&
               count(candidate, "path: \"static\", query: \"preserve_raw\"") == 1u &&
               count(candidate, "target_path: \"" + p63 + "\"") == 1u &&
               count(candidate, "status: 301, reason: \"Moved Permanently\"") == 1u;
    };
    const auto request_policy_is_canonical = [&](const std::string& candidate) {
        return count(candidate, "request_policy: {") == 1u &&
               exact_region(candidate, p63_rut, "request_policy: {", "        }, response_policy:");
    };
    const auto response_policy_is_canonical = [&](const std::string& candidate) {
        return count(candidate, "response_policy: {") == 1u &&
               exact_region(candidate, p63_rut, "response_policy: {", "        }, failure_policy:");
    };
    const auto failure_policy_is_canonical = [&](const std::string& candidate) {
        return count(candidate, "failure_policy: {") == 1u &&
               exact_region(candidate, p63_rut, "failure_policy: {", "        })\n");
    };
    const auto unmatched_is_canonical = [&](const std::string& candidate) {
        const size_t candidate_begin = candidate.find("\nunmatched OPTIONS");
        const size_t canonical_begin = p63_rut.find("\nunmatched OPTIONS");
        return candidate_begin != std::string::npos && canonical_begin != std::string::npos &&
               count(candidate, "\nunmatched ") == 3u &&
               candidate.substr(candidate_begin) == p63_rut.substr(canonical_begin);
    };
    const auto timeout_is_canonical = [](const std::string& candidate) {
        return candidate.find("timeout_failure_policy:") == std::string::npos &&
               candidate.find("response_read_timeout:") == std::string::npos &&
               candidate.find("response_buffering:") == std::string::npos;
    };

    const auto generic_p63_shape = [&](const std::string& candidate) {
        if (count(candidate, "route \"" + route + "\" {\n") != 1u ||
            count(candidate, "req.pathOnly == \"" + route + "\"") != 1u ||
            count(candidate, "target_path: \"" + p63 + "\"") != 1u ||
            count(candidate, "return forward(nginx_upstream, request_policy: {") != 1u ||
            candidate.find("target_transform") != std::string::npos ||
            candidate.find("strip_prefix") != std::string::npos ||
            candidate.find("replace_prefix") != std::string::npos ||
            !pre_route_is_canonical(candidate) || !redirect_is_canonical(candidate) ||
            !request_policy_is_canonical(candidate) || !response_policy_is_canonical(candidate) ||
            !failure_policy_is_canonical(candidate) || !unmatched_is_canonical(candidate) ||
            !timeout_is_canonical(candidate))
            return false;
        for (const char* marker : {"nginx.conf",
                                   "nginx::",
                                   "nginx_compat",
                                   "workaround",
                                   "bind_address",
                                   "local_address",
                                   "req.listener",
                                   "address_condition"})
            if (candidate.find(marker) != std::string::npos) return false;
        return true;
    };
    REQUIRE(generic_p63_shape(p63_rut));
    const auto replace_unique =
        [](std::string value, const std::string& from, const std::string& to) {
            const size_t offset = from.empty() ? std::string::npos : value.find(from);
            if (from.empty() || from == to || offset == std::string::npos ||
                value.find(from, offset + from.size()) != std::string::npos)
                return std::string{};
            value.replace(offset, from.size(), to);
            return value;
        };
    std::string alternate_route = route;
    alternate_route.back() = 'q';
    const std::string injected_transform =
        "return forward(nginx_upstream, target_transform: {\n"
        "            strip_prefix: \"" +
        p63 +
        "\",\n"
        "            replace_prefix: \"/\"\n"
        "        }, request_policy: {";
    const std::string mutations[] = {
        replace_unique(p63_rut,
                       "pre_route TRACE { return local_response({\n"
                       "  version: \"HTTP/1.1\", status: 405,",
                       "pre_route TRACE { return local_response({\n"
                       "  version: \"HTTP/1.1\", status: 406,"),
        replace_unique(
            p63_rut, "route \"" + route + "\" {\n", "route \"" + alternate_route + "\" {\n"),
        replace_unique(p63_rut,
                       "req.pathOnly == \"" + route + "\"",
                       "req.pathOnly == \"" + alternate_route + "\""),
        replace_unique(
            p63_rut, "target_path: \"" + p63 + "\"", "target_path: \"" + alternate_route + "/\""),
        replace_unique(
            p63_rut, "return forward(nginx_upstream, request_policy: {", injected_transform),
        replace_unique(
            p63_rut,
            "request_policy: {\n",
            "request_policy: {\n            // structurally noncanonical request policy\n"),
        replace_unique(p63_rut,
                       "hide_headers: [\"Date\", \"Server\", \"X-Pad\"]",
                       "hide_headers: [\"Date\", \"Server\", \"X-Foo\"]"),
        replace_unique(
            p63_rut,
            "failure_policy: {\n",
            "failure_policy: {\n            // structurally noncanonical failure policy\n"),
        replace_unique(p63_rut,
                       "unmatched OPTIONS { return local_response({\n"
                       "  version: \"HTTP/1.1\", status: 400,",
                       "unmatched OPTIONS { return local_response({\n"
                       "  version: \"HTTP/1.1\", status: 401,"),
        p63_rut + "// response_read_timeout: forbidden\n",
        p63_rut + "// nginx_compat workaround marker\n",
    };
    for (const auto& mutation : mutations) {
        REQUIRE_FALSE(mutation.empty());
        REQUIRE_NE(mutation, p63_rut);
        CHECK_FALSE(generic_p63_shape(mutation));
        const auto mutation_lexed = lex({mutation.data(), static_cast<u32>(mutation.size())});
        REQUIRE(mutation_lexed);
        const auto mutation_parsed = parse_file(mutation_lexed.value());
        REQUIRE(mutation_parsed);
        delete mutation_parsed.value();
    }

    std::string maximum_source = make_source(p63, true, "65535", "255.255.255.255:65535");
    const auto maximum = lower(maximum_source);
    REQUIRE(maximum);
    REQUIRE_EQ(maximum.value().len, 3426u);
    CHECK_LT(maximum.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum.value().len, 2520u);
    CHECK_EQ(maximum.value().data[maximum.value().len], '\0');
    validate_shape(std::string(maximum.value().data, maximum.value().len),
                   p63,
                   3426u,
                   "listen 127.0.0.1:65535\n",
                   "upstream nginx_upstream at \"255.255.255.255:65535\"\n");

    const std::string p64 = "/" + std::string(62u, 'p') + "/";
    REQUIRE_EQ(p64.size(), 64u);
    std::string over_limit = make_source(p64, true);
    const auto over_limit_parsed =
        nginx::parse({over_limit.data(), static_cast<u32>(over_limit.size())});
    REQUIRE_FALSE(over_limit_parsed);
    CHECK_EQ(over_limit_parsed.error().code, FrontendError::UnsupportedSyntax);
    CHECK(over_limit_parsed.error().detail.eq(
        lit_str("location path is outside the bounded clean proxy profile")));

    std::string wildcard =
        "server { listen 8080; location /service/ { proxy_pass http://127.0.0.1:9000; } }";
    const auto wildcard_parsed = nginx::parse({wildcard.data(), static_cast<u32>(wildcard.size())});
    REQUIRE(wildcard_parsed);
    const auto wildcard_lowered = nginx::lower_to_rut(wildcard_parsed.value());
    REQUIRE(wildcard_lowered);
    REQUIRE_EQ(wildcard_lowered.value().len, 3247u);
    CHECK_EQ(count(std::string(wildcard_lowered.value().data, wildcard_lowered.value().len),
                   "target_transform:"),
             0u);
    std::string explicit_uri =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/; } }";
    const auto explicit_lowered = lower(explicit_uri);
    REQUIRE(explicit_lowered);
    REQUIRE_EQ(explicit_lowered.value().len, 3358u);
    CHECK_EQ(count(std::string(explicit_lowered.value().data, explicit_lowered.value().len),
                   "target_transform:"),
             1u);
    CHECK_NE(std::string(explicit_lowered.value().data, explicit_lowered.value().len), service);

    std::string frontend_source = make_source(nested, true);
    const auto nginx_parsed =
        nginx::parse({frontend_source.data(), static_cast<u32>(frontend_source.size())});
    REQUIRE(nginx_parsed);
    auto forged = nginx_parsed.value();
    std::string independent = frontend_source;
    forged.location.path.ptr = independent.data() + forged.location.path_span.start;
    auto rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid listen source provenance")));
    forged = nginx_parsed.value();
    forged.location.path_span.end--;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid proxy location spans")));
    forged = nginx_parsed.value();
    forged.location.proxy_pass.has_uri = true;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid bounded proxy_pass URI model")));
    forged = nginx_parsed.value();
    forged.location.proxy_read_timeout.milliseconds = 1u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid absent proxy_read_timeout model")));
    forged = nginx_parsed.value();
    forged.exact_no_content_return.response.status = 204u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid absent exact no-content return model")));
    const u32 path_byte = nginx_parsed.value().location.path_span.start + 1u;
    REQUIRE_LT(path_byte, frontend_source.size());
    const char saved_path_byte = frontend_source[path_byte];
    frontend_source[path_byte] = '%';
    rejected = nginx::lower_to_rut(nginx_parsed.value());
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid bounded proxy location path model")));
    frontend_source[path_byte] = saved_path_byte;

    const auto lexed = lex({p63_rut.data(), static_cast<u32>(p63_rut.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0x7f000001u);
    const AstRouteDecl* ast_route = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++)
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.path.eq({p63.data(), 62u}))
            ast_route = &ast->items[i].route;
    REQUIRE(ast_route != nullptr);
    REQUIRE_EQ(ast_route->statements.len, 1u);
    REQUIRE(ast_route->statements[0]->kind == AstStmtKind::If);
    const AstStatement& ast_if = *ast_route->statements[0];
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    const auto& ast_redirect = ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u];
    CHECK(ast_redirect.scheme == RedirectPolicyScheme::Http);
    CHECK(ast_redirect.authority == RedirectPolicyAuthority::RequestHost);
    CHECK(ast_redirect.port == RedirectPolicyPort::ActualListener);
    CHECK(ast_redirect.path == RedirectPolicyPath::Static);
    CHECK(ast_redirect.query == RedirectPolicyQuery::PreserveRaw);
    CHECK(ast_redirect.date == RedirectPolicyDate::Current);
    CHECK(ast_redirect.connection == RedirectPolicyConnection::Close);
    CHECK(ast_redirect.header_order == RedirectPolicyHeaderOrder::LocationThenConnection);
    CHECK_EQ(ast_redirect.status_code, 301u);
    CHECK(ast_redirect.reason.eq(lit_str("Moved Permanently")));
    CHECK(ast_redirect.server.eq(lit_str("nginx/1.29.7")));
    CHECK(ast_redirect.content_type.eq(lit_str("text/html")));
    CHECK(ast_redirect.target_path.eq({p63.data(), 63u}));
    const AstStatement* ast_forward = ast_route->statements[0]->else_stmt;
    if (ast_forward->kind == AstStmtKind::Block) {
        REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
        ast_forward = ast_forward->block_stmts[0];
    }
    REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
    CHECK_FALSE(ast_forward->has_forward_target_transform);
    REQUIRE(ast_forward->has_forward_request_policy);
    REQUIRE(ast_forward->has_forward_response_policy);
    REQUIRE(ast_forward->has_forward_failure_policy);
    REQUIRE_NE(ast_forward->forward_response_policy_id, 0u);
    REQUIRE_LE(ast_forward->forward_response_policy_id, ast->response_policies.len);
    REQUIRE_NE(ast_forward->forward_failure_policy_id, 0u);
    REQUIRE_LE(ast_forward->forward_failure_policy_id, ast->failure_policies.len);
    CHECK(response_policy_spec_valid(
        ast->response_policies[ast_forward->forward_response_policy_id - 1u]));
    CHECK(forward_failure_policy_spec_valid(
        ast->failure_policies[ast_forward->forward_failure_policy_id - 1u]));
    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Exact);
    REQUIRE_EQ(hir->routes.len, 1u);
    CHECK(hir->routes[0].path.eq({p63.data(), 62u}));
    REQUIRE(hir->routes[0].control.kind == HirControlKind::If);
    REQUIRE(hir->routes[0].control.then_term.kind == HirTerminatorKind::Redirect);
    REQUIRE_NE(hir->routes[0].control.then_term.redirect_policy_id, 0u);
    REQUIRE_LE(hir->routes[0].control.then_term.redirect_policy_id, hir->redirect_policies.len);
    const auto& hir_redirect =
        hir->redirect_policies[hir->routes[0].control.then_term.redirect_policy_id - 1u];
    CHECK(hir_redirect.target_path.eq({p63.data(), 63u}));
    const HirTerminator& hir_forward = hir->routes[0].control.else_term;
    REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
    CHECK_FALSE(hir_forward.has_forward_target_transform);
    REQUIRE_NE(hir_forward.forward_request_policy_id, 0u);
    REQUIRE_NE(hir_forward.forward_response_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_response_policy_id, hir->response_policies.len);
    REQUIRE_NE(hir_forward.forward_failure_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_failure_policy_id, hir->failure_policies.len);
    CHECK(response_policy_spec_valid(
        hir->response_policies[hir_forward.forward_response_policy_id - 1u]));
    CHECK(forward_failure_policy_spec_valid(
        hir->failure_policies[hir_forward.forward_failure_policy_id - 1u]));
    const auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());
    REQUIRE_EQ(mir->functions.len, 1u);
    const MirTerminator* mir_forward = nullptr;
    for (u32 block = 0u; block < mir->functions[0].blocks.len; block++)
        if (mir->functions[0].blocks[block].term.kind == MirTerminatorKind::ForwardUpstream)
            mir_forward = &mir->functions[0].blocks[block].term;
    REQUIRE(mir_forward != nullptr);
    CHECK_FALSE(mir_forward->has_forward_target_transform);
    CHECK_EQ(mir_forward->forward_request_policy_id, hir_forward.forward_request_policy_id);
    CHECK_EQ(mir_forward->forward_response_policy_id, hir_forward.forward_response_policy_id);
    CHECK_EQ(mir_forward->forward_failure_policy_id, hir_forward.forward_failure_policy_id);
    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.func_count, 1u);
    CHECK(rir.module.functions[0].route_pattern.eq({p63.data(), 62u}));
    CHECK_EQ(rir.module.target_transform_count, 0u);
    CHECK_EQ(rir.module.redirect_policy_count, 1u);
    CHECK_EQ(rir.module.response_policy_count, 1u);
    CHECK_EQ(rir.module.failure_policy_count, 1u);
    CHECK_EQ(rir.module.policy_bundle_count, 1u);
    CHECK(rir.module.redirect_policies[0].target_path.eq({p63.data(), 63u}));
    CHECK(redirect_policy_spec_valid(rir.module.redirect_policies[0]));
    CHECK(response_policy_spec_valid(rir.module.response_policies[0]));
    CHECK(forward_failure_policy_spec_valid(rir.module.failure_policies[0]));
    CHECK_EQ(rir.module.policy_bundles[0].response_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].failure_policy_id, 1u);
    CHECK_EQ(rir.module.policy_bundles[0].timeout_failure_policy_id, 0u);
    CHECK_EQ(rir.module.policy_bundles[0].response_read_timeout_seconds, 0u);
    CHECK(rir.module.policy_bundles[0].response_buffering == ForwardResponseBufferingMode::None);
    bool saw_forward = false;
    u32 saw_redirect = 0u;
    for (u32 block = 0u; block < rir.module.functions[0].block_count; block++) {
        const auto& rir_block = rir.module.functions[0].blocks[block];
        for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
            const auto& inst = rir_block.insts[instruction];
            CHECK(inst.op != rir::Opcode::ReqSetTargetTransform);
            if (inst.op == rir::Opcode::RetRedirect) {
                saw_redirect++;
                CHECK_EQ(inst.imm.i32_val, 1);
            }
            if (inst.op != rir::Opcode::RetForwardBundle) continue;
            saw_forward = true;
            REQUIRE_EQ(inst.operand_count, 3u);
            i32 upstream_id = -1;
            i32 request_policy_id = -1;
            i32 bundle_id = -1;
            REQUIRE(find_const_i32(rir.module.functions[0], inst.operand(0), upstream_id));
            REQUIRE(find_const_i32(rir.module.functions[0], inst.operand(1), request_policy_id));
            REQUIRE(find_const_i32(rir.module.functions[0], inst.operand(2), bundle_id));
            CHECK_EQ(upstream_id, 0);
            CHECK_EQ(request_policy_id, static_cast<i32>(RequestPolicyId::Http11FixedStrip));
            CHECK_EQ(bundle_id, 1);
        }
    }
    CHECK(saw_forward);
    CHECK_EQ(saw_redirect, 1u);
}

TEST(nginx_converter, issue357_wildcard_complete_clean_no_uri_prefix_class_is_canonical_and_owned) {
    struct Boundary {
        std::string path;
        const char* listen_port;
        const char* upstream;
        u16 port;
        u32 wildcard_len;
    };
    const std::string p63 = "/" + std::string(61u, 'p') + "/";
    std::string nested = "/";
    for (u32 i = 0u; i < 29u; i++) nested += "a/";
    nested += "bbb/";
    REQUIRE_EQ(p63.size(), nginx::kMaxProxyLocationPathLen);
    REQUIRE_EQ(nested.size(), nginx::kMaxProxyLocationPathLen);
    const Boundary boundaries[] = {{"/a/", "8080", "127.0.0.1:9000", 8080u, 3229u},
                                   {"/api/", "8080", "127.0.0.1:9000", 8080u, 3235u},
                                   {"/service/", "8080", "127.0.0.1:9000", 8080u, 3247u},
                                   {p63, "8080", "127.0.0.1:9000", 8080u, 3409u},
                                   {nested, "8080", "127.0.0.1:9000", 8080u, 3409u},
                                   {p63, "65535", "255.255.255.255:65535", 65535u, 3417u}};
    const auto make_source = [](const std::string& endpoint,
                                const std::string& path,
                                const std::string& upstream,
                                bool listen_first) {
        const std::string listener = "  listen " + endpoint + ";\n";
        const std::string location =
            "  location " + path + " {\n    proxy_pass http://" + upstream + ";\n  }\n";
        return "server {\n" + (listen_first ? listener + location : location + listener) + "}\n";
    };
    const auto validate_source =
        [&](const std::string& source, const Boundary& boundary, const std::string& canonical) {
            const std::string route = boundary.path.substr(0u, boundary.path.size() - 1u);
            const std::string listener = "listen :" + std::string(boundary.listen_port) + "\n";
            const std::string upstream =
                "upstream nginx_upstream at \"" + std::string(boundary.upstream) + "\"\n";
            if (source.size() != boundary.wildcard_len || source.rfind(listener, 0u) != 0u ||
                count_text(source, listener) != 1u || count_upstream_declarations(source) != 1u ||
                count_text(source, upstream) != 1u || count_text(source, "pre_route TRACE") != 1u ||
                count_route_declarations(source) != 1u ||
                count_text(source, "route \"" + route + "\" {\n") != 1u ||
                count_text(source, "req.pathOnly == \"" + route + "\"") != 1u ||
                count_text(source, "return redirect({scheme: \"http\"") != 1u ||
                count_text(source, "path: \"static\", query: \"preserve_raw\"") != 1u ||
                count_text(source, "target_path: \"" + boundary.path + "\"") != 1u ||
                count_text(source, "return forward(nginx_upstream, request_policy: {") != 1u ||
                count_text(source, "request_policy: {") != 1u ||
                count_text(source, "host: \"upstream\"") != 1u ||
                count_text(source, "connection: \"omit\"") != 1u ||
                count_text(source,
                           "strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
                           "\"Upgrade\"]") != 1u ||
                count_text(source, "response_policy: {") != 1u ||
                count_text(source, "framing: \"content_length\"") != 1u ||
                count_text(source, "hide_headers: [\"Date\", \"Server\", \"X-Pad\"]") != 1u ||
                count_text(source, "failure_policy: {") != 1u ||
                count_text(source, "status: 502,") != 1u ||
                count_text(source, "reason: \"Bad Gateway\"") != 1u ||
                count_text(source, "unmatched OPTIONS") != 1u ||
                count_text(source, "unmatched CONNECT") != 1u ||
                count_text(source, "\nunmatched {") != 1u ||
                count_text(source,
                           "unmatched OPTIONS { return local_response({\n"
                           "  version: \"HTTP/1.1\", status: 400,") != 1u ||
                count_text(source,
                           "unmatched CONNECT { return local_response({\n"
                           "  version: \"HTTP/1.1\", status: 405,") != 1u ||
                count_text(source,
                           "\nunmatched { return local_response({\n"
                           "  version: \"HTTP/1.1\", status: 400,") != 1u ||
                source.find("target_transform") != std::string::npos ||
                source.find("strip_prefix") != std::string::npos ||
                source.find("replace_prefix") != std::string::npos ||
                source.find("set_path") != std::string::npos)
                return false;
            for (const char* marker : {"nginx.conf",
                                       "nginx::",
                                       "nginx_compat",
                                       "workaround",
                                       "bind_address",
                                       "local_address",
                                       "req.listener",
                                       "address_condition"})
                if (source.find(marker) != std::string::npos) return false;
            return canonical.empty() || source == canonical;
        };

    std::string p63_canonical;
    for (const auto& boundary : boundaries) {
        const std::string exact_endpoint = "127.0.0.1:" + std::string(boundary.listen_port);
        std::string exact_source =
            make_source(exact_endpoint, boundary.path, boundary.upstream, true);
        const auto exact_parsed =
            nginx::parse({exact_source.data(), static_cast<u32>(exact_source.size())});
        REQUIRE(exact_parsed);
        const auto exact_lowered = nginx::lower_to_rut(exact_parsed.value());
        REQUIRE(exact_lowered);
        REQUIRE_EQ(exact_lowered.value().len, boundary.wildcard_len + 9u);
        const std::string exact_rut(exact_lowered.value().data, exact_lowered.value().len);
        REQUIRE_EQ(exact_rut.rfind("listen 127.0.0.1:", 0u), 0u);
        REQUIRE_EQ(count_text(exact_rut, "listen 127.0.0.1:"), 1u);
        std::string exact_as_wildcard = exact_rut;
        exact_as_wildcard.erase(strlen("listen "), strlen("127.0.0.1"));
        REQUIRE_EQ(exact_as_wildcard.size(), boundary.wildcard_len);

        std::string canonical;
        const std::string endpoints[] = {boundary.listen_port,
                                         "0.0.0.0:" + std::string(boundary.listen_port),
                                         "*:" + std::string(boundary.listen_port)};
        for (const std::string& endpoint : endpoints) {
            for (const bool listen_first : {true, false}) {
                std::string nginx_source =
                    make_source(endpoint, boundary.path, boundary.upstream, listen_first);
                const auto parsed =
                    nginx::parse({nginx_source.data(), static_cast<u32>(nginx_source.size())});
                REQUIRE(parsed);
                const nginx::Server& server = parsed.value();
                REQUIRE(server.listen.address == ListenerAddress::IPv4Wildcard);
                CHECK_EQ(server.listen.ipv4_host, 0u);
                CHECK_EQ(server.listen.port, boundary.port);
                REQUIRE(server.listen.value.ptr != nullptr);
                REQUIRE_EQ(server.listen.value.len, endpoint.size());
                REQUIRE_EQ(server.listen.value_span.end - server.listen.value_span.start,
                           endpoint.size());
                REQUIRE_GE(server.listen.value_span.start, server.listen.span.start);
                REQUIRE_LE(server.listen.value_span.end, server.listen.span.end);
                REQUIRE_EQ(server.listen.value.ptr,
                           nginx_source.data() + server.listen.value_span.start);
                CHECK(server.listen.value.eq({endpoint.data(), static_cast<u32>(endpoint.size())}));
                REQUIRE(server.location.path.ptr != nullptr);
                REQUIRE_EQ(server.location.path.len, boundary.path.size());
                REQUIRE_EQ(server.location.path_span.end - server.location.path_span.start,
                           boundary.path.size());
                REQUIRE_GE(server.location.path_span.start, server.location.span.start);
                REQUIRE_LE(server.location.path_span.end, server.location.span.end);
                REQUIRE_EQ(server.location.path.ptr,
                           nginx_source.data() + server.location.path_span.start);
                CHECK(server.location.path.eq(
                    {boundary.path.data(), static_cast<u32>(boundary.path.size())}));
                CHECK_FALSE(server.location.proxy_pass.has_uri);
                CHECK_EQ(server.location.proxy_pass.uri.ptr, nullptr);
                CHECK_EQ(server.location.proxy_pass.uri.len, 0u);
                CHECK_EQ(server.location.proxy_pass.uri_span.start, 0u);
                CHECK_EQ(server.location.proxy_pass.uri_span.end, 0u);

                const auto lowered = nginx::lower_to_rut(server);
                REQUIRE(lowered);
                REQUIRE_EQ(lowered.value().len, boundary.wildcard_len);
                REQUIRE_EQ(lowered.value().data[lowered.value().len], '\0');
                const std::string rut(lowered.value().data, lowered.value().len);
                if (canonical.empty())
                    canonical = rut;
                else
                    REQUIRE_EQ(rut, canonical);
                REQUIRE(validate_source(rut, boundary, canonical));
                const nginx::RutSource owned = lowered.value();
                std::fill(nginx_source.begin(), nginx_source.end(), 'x');
                CHECK_EQ(std::string(owned.data, owned.len), canonical);
                CHECK_EQ(owned.data[owned.len], '\0');
            }
        }
        REQUIRE_EQ(canonical, exact_as_wildcard);
        if (boundary.path == p63 && boundary.port == 8080u && p63_canonical.empty())
            p63_canonical = canonical;
    }

    REQUIRE_FALSE(p63_canonical.empty());
    CHECK_EQ(p63_canonical.size(), 3409u);
    CHECK_EQ(nginx::RutSource::kCapacity, 5946u);
    CHECK_EQ(nginx::RutSource::kCapacity - 3417u, 2529u);
    CHECK_EQ(nginx::RutSource::kCapacity - 1u - 3417u, 2528u);
    const auto replace_unique =
        [](std::string value, const std::string& from, const std::string& to) {
            const size_t offset = from.empty() ? std::string::npos : value.find(from);
            if (from.empty() || from == to || offset == std::string::npos ||
                value.find(from, offset + from.size()) != std::string::npos)
                return std::string{};
            value.replace(offset, from.size(), to);
            return value;
        };
    Boundary p63_boundary{p63, "8080", "127.0.0.1:9000", 8080u, 3409u};
    const std::string p63_route = p63.substr(0u, p63.size() - 1u);
    std::string alternate_route = p63_route;
    alternate_route.back() = 'q';
    const std::string mutations[] = {
        replace_unique(p63_canonical, "listen :8080", "listen 0.0.0.0:8080"),
        replace_unique(
            p63_canonical, "route \"" + p63_route + "\" {", "route \"" + alternate_route + "\" {"),
        replace_unique(p63_canonical,
                       "target_path: \"" + p63 + "\"",
                       "target_path: \"" + alternate_route + "/\""),
        replace_unique(p63_canonical,
                       "return forward(nginx_upstream, request_policy: {",
                       "return forward(nginx_upstream, target_transform: {\n"
                       "            strip_prefix: \"" +
                           p63 +
                           "\", replace_prefix: \"/\"\n"
                           "        }, request_policy: {"),
        replace_unique(p63_canonical,
                       "strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
                       "\"Upgrade\"]",
                       "strip_headers: [\"Keep-Alive\", \"TE\", \"Expect\", \"Upgrade\"]"),
        replace_unique(p63_canonical,
                       "hide_headers: [\"Date\", \"Server\", \"X-Pad\"]",
                       "hide_headers: [\"Date\", \"Server\", \"X-Foo\"]"),
        replace_unique(p63_canonical, "reason: \"Bad Gateway\"", "reason: \"Bad Gatewax\""),
        replace_unique(p63_canonical,
                       "unmatched OPTIONS { return local_response({\n"
                       "  version: \"HTTP/1.1\", status: 400,",
                       "unmatched OPTIONS { return local_response({\n"
                       "  version: \"HTTP/1.1\", status: 401,"),
        p63_canonical + "// nginx_compat workaround\n",
    };
    for (u32 mutation_index = 0u; mutation_index < std::size(mutations); mutation_index++) {
        const std::string& mutation = mutations[mutation_index];
        REQUIRE_FALSE(mutation.empty());
        REQUIRE_NE(mutation, p63_canonical);
        CHECK_FALSE(validate_source(mutation, p63_boundary, {}));
        // The first candidate deliberately uses the ordinary-RUT spelling which
        // must be written as `listen :PORT`; the public parser rejects the
        // noncanonical 0.0.0.0 alias.  All semantic candidates below remain
        // valid ordinary RUT and are rejected by the structural inventory.
        if (mutation_index == 0u || mutation_index == 4u) continue;
        const auto lexed = lex({mutation.data(), static_cast<u32>(mutation.size())});
        REQUIRE(lexed);
        const auto parsed = parse_file(lexed.value());
        REQUIRE(parsed);
        delete parsed.value();
    }

    std::string provenance_source = make_source("*:8080", p63, "127.0.0.1:9000", true);
    const auto provenance_parsed =
        nginx::parse({provenance_source.data(), static_cast<u32>(provenance_source.size())});
    REQUIRE(provenance_parsed);
    auto forged = provenance_parsed.value();
    std::string independent = provenance_source;
    forged.listen.value.ptr = independent.data() + forged.listen.value_span.start;
    auto rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid listen source provenance")));
    forged = provenance_parsed.value();
    forged.listen.port = 8081u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid wildcard listen endpoint model")));
    forged = provenance_parsed.value();
    forged.listen.value_span.end--;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid listen source provenance")));
    forged = provenance_parsed.value();
    forged.location.path.ptr = independent.data() + forged.location.path_span.start;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid listen source provenance")));
    forged = provenance_parsed.value();
    forged.location.proxy_pass.has_uri = true;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid bounded proxy_pass URI model")));
    forged = provenance_parsed.value();
    forged.location.proxy_read_timeout.milliseconds = 1u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid absent proxy_read_timeout model")));

    auto legacy = provenance_parsed.value();
    legacy.listen.value = {};
    legacy.listen.value_span = {};
    const auto legacy_lowered = nginx::lower_to_rut(legacy);
    REQUIRE(legacy_lowered);
    CHECK_EQ(legacy_lowered.value().len, 3409u);
    CHECK_EQ(std::string(legacy_lowered.value().data, legacy_lowered.value().len), p63_canonical);

    const auto lexed = lex({p63_canonical.data(), static_cast<u32>(p63_canonical.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0u);
    CHECK_EQ(ast->items[0].listen.port, 8080u);
    const AstRouteDecl* ast_route = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++)
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.path.eq({p63_route.data(), static_cast<u32>(p63_route.size())}))
            ast_route = &ast->items[i].route;
    REQUIRE(ast_route != nullptr);
    REQUIRE_EQ(ast_route->statements.len, 1u);
    REQUIRE(ast_route->statements[0]->kind == AstStmtKind::If);
    const AstStatement& ast_if = *ast_route->statements[0];
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    CHECK(ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u].target_path.eq(
        {p63.data(), static_cast<u32>(p63.size())}));
    const AstStatement* ast_forward = ast_if.else_stmt;
    if (ast_forward->kind == AstStmtKind::Block) {
        REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
        ast_forward = ast_forward->block_stmts[0];
    }
    REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
    CHECK_FALSE(ast_forward->has_forward_target_transform);
    REQUIRE(ast_forward->has_forward_request_policy);
    REQUIRE(ast_forward->has_forward_response_policy);
    REQUIRE(ast_forward->has_forward_failure_policy);

    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Wildcard);
    CHECK_EQ(hir->listener.ipv4_host, 0u);
    CHECK_EQ(hir->listener.port, 8080u);
    REQUIRE_EQ(hir->routes.len, 1u);
    CHECK(hir->routes[0].path.eq({p63_route.data(), static_cast<u32>(p63_route.size())}));
    REQUIRE(hir->routes[0].control.kind == HirControlKind::If);
    REQUIRE(hir->routes[0].control.then_term.kind == HirTerminatorKind::Redirect);
    REQUIRE(hir->routes[0].control.else_term.kind == HirTerminatorKind::ForwardUpstream);
    CHECK_FALSE(hir->routes[0].control.else_term.has_forward_target_transform);

    const auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());
    REQUIRE_EQ(mir->functions.len, 1u);
    const MirTerminator* mir_forward = nullptr;
    for (u32 block = 0u; block < mir->functions[0].blocks.len; block++)
        if (mir->functions[0].blocks[block].term.kind == MirTerminatorKind::ForwardUpstream)
            mir_forward = &mir->functions[0].blocks[block].term;
    REQUIRE(mir_forward != nullptr);
    CHECK_FALSE(mir_forward->has_forward_target_transform);

    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.func_count, 1u);
    CHECK_EQ(rir.module.target_transform_count, 0u);
    CHECK_EQ(rir.module.redirect_policy_count, 1u);
    CHECK_EQ(rir.module.response_policy_count, 1u);
    CHECK_EQ(rir.module.failure_policy_count, 1u);
    CHECK_EQ(rir.module.policy_bundle_count, 1u);
    CHECK(
        rir.module.redirect_policies[0].target_path.eq({p63.data(), static_cast<u32>(p63.size())}));
    u32 redirect_count = 0u;
    u32 forward_count = 0u;
    for (u32 block = 0u; block < rir.module.functions[0].block_count; block++) {
        const auto& rir_block = rir.module.functions[0].blocks[block];
        for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
            const auto& inst = rir_block.insts[instruction];
            CHECK(inst.op != rir::Opcode::ReqSetTargetTransform);
            if (inst.op == rir::Opcode::RetRedirect) redirect_count++;
            if (inst.op == rir::Opcode::RetForwardBundle) forward_count++;
        }
    }
    CHECK_EQ(redirect_count, 1u);
    CHECK_EQ(forward_count, 1u);
    auto populated = std::make_unique<RouteConfig>();
    REQUIRE(populate_route_config(*populated, rir.module));
    CHECK_EQ(populated->target_transform_count, 0u);
    CHECK_EQ(populated->target_transform_bytes_used, 0u);
    CHECK_EQ(populated->redirect_policy_count, 1u);
    CHECK_EQ(populated->response_policy_count, 1u);
    CHECK_EQ(populated->failure_policy_count, 1u);
    CHECK_EQ(populated->policy_bundle_count, 1u);
}

TEST(nginx_converter,
     issue353_exact_loopback_prefix_root_replacement_has_canonical_ordinary_rut_golden) {
    char exact_first[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/; } }";
    char exact_location_first[] =
        "server { location /service/ { proxy_pass http://127.0.0.1:9000/; } "
        "listen 127.0.0.1:8080; }";
    char wildcard_first[] =
        "server { listen 8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/; } }";
    char wildcard_location_first[] =
        "server { location /service/ { proxy_pass http://127.0.0.1:9000/; } listen 8080; }";

    const auto lower = [](char* source, u32 len) -> FrontendResult<nginx::RutSource> {
        const auto parsed = nginx::parse({source, len});
        if (!parsed) return core::make_unexpected(parsed.error());
        return nginx::lower_to_rut(parsed.value());
    };
    const auto exact_a = lower(exact_first, sizeof(exact_first) - 1u);
    const auto exact_b = lower(exact_location_first, sizeof(exact_location_first) - 1u);
    const auto wildcard_a = lower(wildcard_first, sizeof(wildcard_first) - 1u);
    const auto wildcard_b = lower(wildcard_location_first, sizeof(wildcard_location_first) - 1u);
    REQUIRE(exact_a);
    REQUIRE(exact_b);
    REQUIRE(wildcard_a);
    REQUIRE(wildcard_b);
    CHECK_EQ(exact_a.value().len, 3358u);
    CHECK_EQ(exact_b.value().len, 3358u);
    CHECK_EQ(wildcard_a.value().len, 3349u);
    CHECK_EQ(wildcard_b.value().len, 3349u);
    const std::string exact(exact_a.value().data, exact_a.value().len);
    const std::string exact_other(exact_b.value().data, exact_b.value().len);
    const std::string wildcard(wildcard_a.value().data, wildcard_a.value().len);
    const std::string wildcard_other(wildcard_b.value().data, wildcard_b.value().len);
    REQUIRE_EQ(exact, exact_other);
    REQUIRE_EQ(wildcard, wildcard_other);
    std::string wildcard_as_exact = wildcard;
    REQUIRE_EQ(wildcard_as_exact.rfind("listen :8080\n", 0u), 0u);
    wildcard_as_exact.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(wildcard_as_exact, exact);

    memset(exact_first, 'x', sizeof(exact_first) - 1u);
    memset(exact_location_first, 'y', sizeof(exact_location_first) - 1u);
    memset(wildcard_first, 'z', sizeof(wildcard_first) - 1u);
    memset(wildcard_location_first, 'w', sizeof(wildcard_location_first) - 1u);
    CHECK_EQ(std::string(exact_a.value().data, exact_a.value().len), exact);
    CHECK_EQ(std::string(exact_b.value().data, exact_b.value().len), exact);

    char maximum_path[nginx::kMaxProxyLocationPathLen + 1u]{};
    maximum_path[0] = '/';
    for (u32 i = 1u; i + 1u < nginx::kMaxProxyLocationPathLen; i++) maximum_path[i] = 'a';
    maximum_path[nginx::kMaxProxyLocationPathLen - 1u] = '/';
    char maximum_exact_source[512]{};
    char maximum_wildcard_source[512]{};
    const int maximum_exact_len = snprintf(maximum_exact_source,
                                           sizeof(maximum_exact_source),
                                           "server { listen 127.0.0.1:65535; location %s { "
                                           "proxy_pass http://255.255.255.255:65535/; } }",
                                           maximum_path);
    const int maximum_wildcard_len = snprintf(maximum_wildcard_source,
                                              sizeof(maximum_wildcard_source),
                                              "server { listen 65535; location %s { proxy_pass "
                                              "http://255.255.255.255:65535/; } }",
                                              maximum_path);
    REQUIRE_GT(maximum_exact_len, 0);
    REQUIRE_GT(maximum_wildcard_len, 0);
    const auto maximum_exact_parsed =
        nginx::parse({maximum_exact_source, static_cast<u32>(maximum_exact_len)});
    const auto maximum_wildcard_parsed =
        nginx::parse({maximum_wildcard_source, static_cast<u32>(maximum_wildcard_len)});
    REQUIRE(maximum_exact_parsed);
    REQUIRE(maximum_wildcard_parsed);
    const auto maximum_exact = nginx::lower_to_rut(maximum_exact_parsed.value());
    const auto maximum_wildcard = nginx::lower_to_rut(maximum_wildcard_parsed.value());
    REQUIRE(maximum_exact);
    REQUIRE(maximum_wildcard);
    CHECK_EQ(maximum_exact.value().len, 3582u);
    CHECK_EQ(maximum_wildcard.value().len, 3573u);
    CHECK_LT(maximum_exact.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum_exact.value().len, 2364u);
    std::string maximum_expected(maximum_wildcard.value().data, maximum_wildcard.value().len);
    REQUIRE_EQ(maximum_expected.rfind("listen :65535\n", 0u), 0u);
    maximum_expected.replace(0u, strlen("listen :65535"), "listen 127.0.0.1:65535");
    CHECK_EQ(maximum_expected, std::string(maximum_exact.value().data, maximum_exact.value().len));

    const auto listener_is_canonical = [](const std::string& source) {
        return source.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(source, "listen 127.0.0.1:8080\n") == 1u &&
               ((source.rfind("listen ", 0u) == 0u ? 1u : 0u) + count_text(source, "\nlisten ")) ==
                   1u &&
               source.find("listen :") == std::string::npos &&
               source.find("127.0.0.2") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& source) {
        return count_upstream_declarations(source) == 1u &&
               count_text(source, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_is_canonical = [](const std::string& source) {
        return count_text(source, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(source, "pre_route TRACE") == 1u &&
               count_text(source, "status: 405, reason: \"Not Allowed\"") >= 1u;
    };
    const auto prefix_route_is_canonical = [](const std::string& source) {
        return count_route_declarations(source) == 1u &&
               count_text(source, "route \"/service\" {\n") == 1u &&
               count_text(source, "if req.method == GET && req.pathOnly == \"/service\" {") == 1u &&
               count_text(source, "return redirect({scheme: \"http\"") == 1u &&
               count_text(source, "authority: \"request_host\", port: \"actual_listener\"") == 1u &&
               count_text(source, "path: \"static\", query: \"preserve_raw\"") == 1u &&
               count_text(source, "target_path: \"/service/\"") == 1u &&
               count_text(source, "return forward(nginx_upstream, target_transform: {") == 1u &&
               count_text(source, "strip_prefix: \"/service/\"") == 1u &&
               count_text(source, "replace_prefix: \"/\"") == 1u;
    };
    const auto has_no_nginx_hook = [](const std::string& source) {
        return source.find("nginx.conf") == std::string::npos &&
               source.find("nginx::") == std::string::npos &&
               source.find("nginx_compat") == std::string::npos &&
               source.find("workaround") == std::string::npos &&
               source.find("bind_address") == std::string::npos;
    };
    const auto source_is_canonical = [&](const std::string& source) {
        return listener_is_canonical(source) && upstream_is_canonical(source) &&
               pre_route_is_canonical(source) && prefix_route_is_canonical(source) &&
               has_no_nginx_hook(source);
    };
    REQUIRE(source_is_canonical(exact));
    const auto replace_unique = [&](std::string source, Str before, Str after) {
        const std::string needle(before.ptr, before.len);
        const size_t offset = source.find(needle);
        if (needle.empty() || before.eq(after) || offset == std::string::npos ||
            source.find(needle, offset + needle.size()) != std::string::npos) {
            CHECK(false);
            return std::string{};
        }
        source.replace(offset, needle.size(), after.ptr, after.len);
        CHECK_NE(source, exact);
        return source;
    };
    const auto check_isolated = [&](const std::string& candidate,
                                    bool listener_ok,
                                    bool upstream_ok,
                                    bool pre_route_ok,
                                    bool route_ok) {
        CHECK_EQ(listener_is_canonical(candidate), listener_ok);
        CHECK_EQ(upstream_is_canonical(candidate), upstream_ok);
        CHECK_EQ(pre_route_is_canonical(candidate), pre_route_ok);
        CHECK_EQ(prefix_route_is_canonical(candidate), route_ok);
        CHECK(has_no_nginx_hook(candidate));
        CHECK_FALSE(source_is_canonical(candidate));
    };
    check_isolated(
        replace_unique(
            exact, lit_str("listen 127.0.0.1:8080\n"), lit_str("listen 127.0.0.2:8080\n")),
        false,
        true,
        true,
        true);
    check_isolated(replace_unique(exact, lit_str("127.0.0.1:9000"), lit_str("127.0.0.1:9001")),
                   true,
                   false,
                   true,
                   true);
    check_isolated(replace_unique(exact,
                                  lit_str("pre_route TRACE { return local_response({\n"),
                                  lit_str("pre_route TRACX { return local_response({\n")),
                   true,
                   true,
                   false,
                   true);
    const struct {
        Str before;
        Str after;
    } route_mutations[] = {
        {lit_str("route \"/service\" {\n"), lit_str("route \"/servicx\" {\n")},
        {lit_str("req.pathOnly == \"/service\""), lit_str("req.pathOnly == \"/servicx\"")},
        {lit_str("query: \"preserve_raw\""), lit_str("query: \"discard\"")},
        {lit_str("return redirect({scheme: \"http\""),
         lit_str("return redirecX({scheme: \"http\"")},
        {lit_str("target_path: \"/service/\""), lit_str("target_path: \"/servicx/\"")},
        {lit_str("return forward(nginx_upstream, target_transform: {"),
         lit_str("return forwarX(nginx_upstream, target_transform: {")},
        {lit_str("strip_prefix: \"/service/\""), lit_str("strip_prefix: \"/servicx/\"")},
        {lit_str("replace_prefix: \"/\""), lit_str("replace_prefix: \"/x\"")},
    };
    for (const auto& mutation : route_mutations)
        check_isolated(
            replace_unique(exact, mutation.before, mutation.after), true, true, true, false);

    const std::string hook = exact + "// nginx_compat workaround marker\n";
    REQUIRE_NE(hook, exact);
    CHECK(listener_is_canonical(hook));
    CHECK(upstream_is_canonical(hook));
    CHECK(pre_route_is_canonical(hook));
    CHECK(prefix_route_is_canonical(hook));
    CHECK_FALSE(has_no_nginx_hook(hook));
    CHECK_FALSE(source_is_canonical(hook));
    const auto hook_lexed = lex({hook.data(), static_cast<u32>(hook.size())});
    REQUIRE(hook_lexed);
    const auto hook_ast = parse_file(hook_lexed.value());
    REQUIRE(hook_ast);
    delete hook_ast.value();

    const std::string harmless = exact + "// canonical byte equality witness\n";
    REQUIRE_NE(harmless, exact);
    REQUIRE(source_is_canonical(harmless));
    const auto harmless_lexed = lex({harmless.data(), static_cast<u32>(harmless.size())});
    REQUIRE(harmless_lexed);
    const auto harmless_ast = parse_file(harmless_lexed.value());
    REQUIRE(harmless_ast);
    delete harmless_ast.value();

    const auto lexed = lex({exact.data(), static_cast<u32>(exact.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast->items[0].listen.port, 8080u);
    const AstRouteDecl* ast_route = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++)
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.path.eq(lit_str("/service")))
            ast_route = &ast->items[i].route;
    REQUIRE(ast_route != nullptr);
    REQUIRE_EQ(ast_route->statements.len, 1u);
    REQUIRE(ast_route->statements[0] != nullptr);
    const AstStatement& ast_if = *ast_route->statements[0];
    REQUIRE(ast_if.kind == AstStmtKind::If);
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.else_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE(ast_if.then_stmt->has_redirect_policy);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    const auto& ast_redirect = ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u];
    CHECK(ast_redirect.authority == RedirectPolicyAuthority::RequestHost);
    CHECK(ast_redirect.port == RedirectPolicyPort::ActualListener);
    CHECK(ast_redirect.query == RedirectPolicyQuery::PreserveRaw);
    CHECK(ast_redirect.target_path.eq(lit_str("/service/")));
    const AstStatement* ast_forward = ast_if.else_stmt;
    if (ast_forward->kind == AstStmtKind::Block) {
        REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
        ast_forward = ast_forward->block_stmts[0];
    }
    REQUIRE(ast_forward != nullptr);
    REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
    REQUIRE(ast_forward->has_forward_target_transform);
    CHECK(ast_forward->forward_target_transform.strip_prefix.eq(lit_str("/service/")));
    CHECK(ast_forward->forward_target_transform.replace_prefix.eq(lit_str("/")));
    REQUIRE(ast_forward->has_forward_request_policy);
    REQUIRE_NE(ast_forward->forward_request_policy_id, 0u);
    REQUIRE(ast_forward->has_forward_response_policy);
    REQUIRE_NE(ast_forward->forward_response_policy_id, 0u);
    REQUIRE_LE(ast_forward->forward_response_policy_id, ast->response_policies.len);
    REQUIRE(ast_forward->has_forward_failure_policy);
    REQUIRE_NE(ast_forward->forward_failure_policy_id, 0u);
    REQUIRE_LE(ast_forward->forward_failure_policy_id, ast->failure_policies.len);

    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir->listener.port, 8080u);
    REQUIRE_EQ(hir->routes.len, 1u);
    const HirRoute& hir_route = hir->routes[0];
    CHECK(hir_route.path.eq(lit_str("/service")));
    REQUIRE(hir_route.control.kind == HirControlKind::If);
    REQUIRE(hir_route.control.then_term.kind == HirTerminatorKind::Redirect);
    const u16 redirect_id = hir_route.control.then_term.redirect_policy_id;
    REQUIRE_NE(redirect_id, 0u);
    REQUIRE_LE(redirect_id, hir->redirect_policies.len);
    const auto& hir_redirect = hir->redirect_policies[redirect_id - 1u];
    CHECK(hir_redirect.authority == RedirectPolicyAuthority::RequestHost);
    CHECK(hir_redirect.port == RedirectPolicyPort::ActualListener);
    CHECK(hir_redirect.query == RedirectPolicyQuery::PreserveRaw);
    CHECK(hir_redirect.target_path.eq(lit_str("/service/")));
    const auto& hir_forward = hir_route.control.else_term;
    REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
    REQUIRE(hir_forward.has_forward_target_transform);
    CHECK(hir_forward.forward_target_transform.strip_prefix.eq(lit_str("/service/")));
    CHECK(hir_forward.forward_target_transform.replace_prefix.eq(lit_str("/")));
    REQUIRE_NE(hir_forward.forward_request_policy_id, 0u);
    REQUIRE_NE(hir_forward.forward_response_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_response_policy_id, hir->response_policies.len);
    REQUIRE_NE(hir_forward.forward_failure_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_failure_policy_id, hir->failure_policies.len);
}

TEST(nginx_converter, issue354_exact_loopback_fixed_replacement_has_canonical_ordinary_rut_golden) {
    char exact_first[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    char exact_location_first[] =
        "server { location /api/ { proxy_pass http://127.0.0.1:9000/v1/; } "
        "listen 127.0.0.1:8080; }";
    char wildcard_first[] =
        "server { listen 8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    char wildcard_location_first[] =
        "server { location /api/ { proxy_pass http://127.0.0.1:9000/v1/; } listen 8080; }";

    const auto lower = [](char* source, u32 len) -> FrontendResult<nginx::RutSource> {
        const auto parsed = nginx::parse({source, len});
        if (!parsed) return core::make_unexpected(parsed.error());
        return nginx::lower_to_rut(parsed.value());
    };
    const auto exact_a = lower(exact_first, sizeof(exact_first) - 1u);
    const auto exact_b = lower(exact_location_first, sizeof(exact_location_first) - 1u);
    const auto wildcard_a = lower(wildcard_first, sizeof(wildcard_first) - 1u);
    const auto wildcard_b = lower(wildcard_location_first, sizeof(wildcard_location_first) - 1u);
    REQUIRE(exact_a);
    REQUIRE(exact_b);
    REQUIRE(wildcard_a);
    REQUIRE(wildcard_b);
    CHECK_EQ(exact_a.value().len, 3345u);
    CHECK_EQ(exact_b.value().len, 3345u);
    CHECK_EQ(wildcard_a.value().len, 3336u);
    CHECK_EQ(wildcard_b.value().len, 3336u);
    const std::string exact(exact_a.value().data, exact_a.value().len);
    const std::string exact_other(exact_b.value().data, exact_b.value().len);
    const std::string wildcard(wildcard_a.value().data, wildcard_a.value().len);
    const std::string wildcard_other(wildcard_b.value().data, wildcard_b.value().len);
    REQUIRE_EQ(exact, exact_other);
    REQUIRE_EQ(wildcard, wildcard_other);
    std::string wildcard_as_exact = wildcard;
    REQUIRE_EQ(wildcard_as_exact.rfind("listen :8080\n", 0u), 0u);
    wildcard_as_exact.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(wildcard_as_exact, exact);

    memset(exact_first, 'x', sizeof(exact_first) - 1u);
    memset(exact_location_first, 'y', sizeof(exact_location_first) - 1u);
    memset(wildcard_first, 'z', sizeof(wildcard_first) - 1u);
    memset(wildcard_location_first, 'w', sizeof(wildcard_location_first) - 1u);
    CHECK_EQ(std::string(exact_a.value().data, exact_a.value().len), exact);
    CHECK_EQ(std::string(exact_b.value().data, exact_b.value().len), exact);

    static constexpr char kMaximumExactSource[] =
        "server { listen 127.0.0.1:65535; location /api/ { proxy_pass "
        "http://255.255.255.255:65535/v1/; } }";
    static constexpr char kMaximumWildcardSource[] =
        "server { listen 65535; location /api/ { proxy_pass "
        "http://255.255.255.255:65535/v1/; } }";
    const auto maximum_exact_parsed =
        nginx::parse({kMaximumExactSource, sizeof(kMaximumExactSource) - 1u});
    const auto maximum_wildcard_parsed =
        nginx::parse({kMaximumWildcardSource, sizeof(kMaximumWildcardSource) - 1u});
    REQUIRE(maximum_exact_parsed);
    REQUIRE(maximum_wildcard_parsed);
    const auto maximum_exact = nginx::lower_to_rut(maximum_exact_parsed.value());
    const auto maximum_wildcard = nginx::lower_to_rut(maximum_wildcard_parsed.value());
    REQUIRE(maximum_exact);
    REQUIRE(maximum_wildcard);
    CHECK_EQ(maximum_exact.value().len, 3353u);
    CHECK_EQ(maximum_wildcard.value().len, 3344u);
    CHECK_LT(maximum_exact.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum_exact.value().len, 2593u);
    std::string maximum_expected(maximum_wildcard.value().data, maximum_wildcard.value().len);
    REQUIRE_EQ(maximum_expected.rfind("listen :65535\n", 0u), 0u);
    maximum_expected.replace(0u, strlen("listen :65535"), "listen 127.0.0.1:65535");
    CHECK_EQ(maximum_expected, std::string(maximum_exact.value().data, maximum_exact.value().len));

    const auto expect_exact_listener_rejected = [&](Str source) {
        const auto parsed = nginx::parse(source);
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK_EQ(lowered.error().code, FrontendError::UnsupportedSyntax);
        CHECK(lowered.error().detail.eq(
            lit_str("exact listen requires the minimal root proxy profile")));
        CHECK_EQ(lowered.error().span.start, parsed.value().listen.span.start);
        CHECK_EQ(lowered.error().span.end, parsed.value().listen.span.end);
        CHECK_EQ(lowered.error().span.line, parsed.value().listen.span.line);
        CHECK_EQ(lowered.error().span.col, parsed.value().listen.span.col);
    };
    static constexpr char kAlternateUri[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v2/; } }";
    static constexpr char kAlternatePath[] =
        "server { listen 127.0.0.1:8080; location /service/ { proxy_pass "
        "http://127.0.0.1:9000/v1/; } }";
    static constexpr char kConfiguredQuery[] =
        "server { listen 127.0.0.1:8080; location /api/ { proxy_pass "
        "http://127.0.0.1:9000/v1/?fixed=1; } }";
    expect_exact_listener_rejected({kAlternateUri, sizeof(kAlternateUri) - 1u});
    expect_exact_listener_rejected({kAlternatePath, sizeof(kAlternatePath) - 1u});
    expect_exact_listener_rejected({kConfiguredQuery, sizeof(kConfiguredQuery) - 1u});

    char maximum_path[nginx::kMaxProxyLocationPathLen + 1u]{};
    maximum_path[0] = '/';
    for (u32 i = 1u; i + 1u < nginx::kMaxProxyLocationPathLen; i++) maximum_path[i] = 'a';
    maximum_path[nginx::kMaxProxyLocationPathLen - 1u] = '/';
    char maximum_uri[nginx::kMaxProxyPassUriLen + 1u]{};
    maximum_uri[0] = '/';
    for (u32 i = 1u; i + 1u < nginx::kMaxProxyPassUriLen; i++) maximum_uri[i] = 'b';
    maximum_uri[nginx::kMaxProxyPassUriLen - 1u] = '/';
    char excluded_path[512]{};
    const int excluded_path_len = snprintf(excluded_path,
                                           sizeof(excluded_path),
                                           "server { listen 127.0.0.1:8080; location %s { "
                                           "proxy_pass http://127.0.0.1:9000/v1/; } }",
                                           maximum_path);
    REQUIRE_GT(excluded_path_len, 0);
    REQUIRE_LT(static_cast<u32>(excluded_path_len), static_cast<u32>(sizeof(excluded_path)));
    expect_exact_listener_rejected({excluded_path, static_cast<u32>(excluded_path_len)});
    char excluded_uri[512]{};
    const int excluded_uri_len = snprintf(excluded_uri,
                                          sizeof(excluded_uri),
                                          "server { listen 127.0.0.1:8080; location /api/ { "
                                          "proxy_pass http://127.0.0.1:9000%s; } }",
                                          maximum_uri);
    REQUIRE_GT(excluded_uri_len, 0);
    REQUIRE_LT(static_cast<u32>(excluded_uri_len), static_cast<u32>(sizeof(excluded_uri)));
    expect_exact_listener_rejected({excluded_uri, static_cast<u32>(excluded_uri_len)});

    const auto listener_is_canonical = [](const std::string& source) {
        return source.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(source, "listen 127.0.0.1:8080\n") == 1u &&
               ((source.rfind("listen ", 0u) == 0u ? 1u : 0u) + count_text(source, "\nlisten ")) ==
                   1u &&
               source.find("listen :") == std::string::npos &&
               source.find("127.0.0.2") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& source) {
        return count_upstream_declarations(source) == 1u &&
               count_text(source, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_is_canonical = [](const std::string& source) {
        return count_text(source, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(source, "pre_route TRACE") == 1u &&
               count_text(source, "status: 405, reason: \"Not Allowed\"") >= 1u;
    };
    const auto prefix_route_is_canonical = [](const std::string& source) {
        return count_route_declarations(source) == 1u &&
               count_text(source, "route \"/api\" {\n") == 1u &&
               count_text(source, "if req.method == GET && req.pathOnly == \"/api\" {") == 1u &&
               count_text(source, "return redirect({scheme: \"http\"") == 1u &&
               count_text(source, "authority: \"request_host\", port: \"actual_listener\"") == 1u &&
               count_text(source, "path: \"static\", query: \"preserve_raw\"") == 1u &&
               count_text(source, "target_path: \"/api/\"") == 1u &&
               count_text(source, "return forward(nginx_upstream, target_transform: {") == 1u &&
               count_text(source, "strip_prefix: \"/api/\"") == 1u &&
               count_text(source, "replace_prefix: \"/v1/\"") == 1u;
    };
    const auto region_equals = [](const std::string& source,
                                  const char* begin_marker,
                                  const char* end_marker,
                                  const char* expected) {
        const size_t begin = source.find(begin_marker);
        if (begin == std::string::npos ||
            source.find(begin_marker, begin + strlen(begin_marker)) != std::string::npos)
            return false;
        const size_t end = source.find(end_marker, begin + strlen(begin_marker));
        return end != std::string::npos && source.compare(begin, end - begin, expected) == 0 &&
               strlen(expected) == end - begin;
    };
    const auto request_policy_is_canonical = [&](const std::string& source) {
        static constexpr char kExpected[] =
            "request_policy: {\n"
            "            version: \"HTTP/1.1\",\n"
            "            host: \"upstream\",\n"
            "            connection: \"omit\",\n"
            "            strip_headers: [\"Connection\", \"Keep-Alive\", \"TE\", \"Expect\", "
            "\"Upgrade\"]\n";
        return count_text(source, "request_policy: {") == 1u &&
               region_equals(source, "request_policy: {", "        }, response_policy:", kExpected);
    };
    const auto response_policy_is_canonical = [&](const std::string& source) {
        static constexpr char kExpected[] =
            "response_policy: {\n"
            "            version: \"HTTP/1.1\",\n"
            "            framing: \"content_length\",\n"
            "            connection: \"request\",\n"
            "            server: \"nginx/1.29.7\",\n"
            "            date: \"current\",\n"
            "            hide_headers: [\"Date\", \"Server\", \"X-Pad\"]\n";
        return count_text(source, "response_policy: {") == 1u &&
               region_equals(source, "response_policy: {", "        }, failure_policy:", kExpected);
    };
    const auto failure_policy_is_canonical = [&](const std::string& source) {
        static constexpr char kExpected[] =
            "failure_policy: {\n"
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
            "html>\\r\\n\"\n";
        return count_text(source, "failure_policy: {") == 1u &&
               region_equals(source, "failure_policy: {", "        })\n", kExpected);
    };
    const auto timeout_policy_is_canonical = [](const std::string& source) {
        return source.find("timeout_failure_policy:") == std::string::npos &&
               source.find("response_read_timeout:") == std::string::npos &&
               source.find("response_buffering:") == std::string::npos;
    };
    const auto make_unmatched = [](const char* selector,
                                   u16 status,
                                   const char* reason,
                                   const char* head_mode,
                                   const char* body) {
        return std::string(selector) + " { return local_response({\n" +
               "  version: \"HTTP/1.1\", status: " + std::to_string(status) + ", reason: \"" +
               reason + "\", server: \"nginx/1.29.7\",\n" +
               "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n" +
               "  head_mode: \"" + head_mode + "\", body: b\"" + body + "\"\n}) }\n";
    };
    const auto unmatched_policies_are_canonical = [&](const std::string& source) {
        static constexpr char kBadRequestBody[] =
            "<html>\\r\\n<head><title>400 Bad Request</title></head>\\r\\n"
            "<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n"
            "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n";
        static constexpr char kNotAllowedBody[] =
            "<html>\\r\\n<head><title>405 Not Allowed</title></head>\\r\\n"
            "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
            "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n";
        const std::string options =
            make_unmatched("unmatched OPTIONS", 400u, "Bad Request", "reject", kBadRequestBody);
        const std::string connect =
            make_unmatched("unmatched CONNECT", 405u, "Not Allowed", "reject", kNotAllowedBody);
        const std::string any =
            make_unmatched("unmatched", 400u, "Bad Request", "suppress_body", kBadRequestBody);
        return count_text(source, "\nunmatched ") == 3u &&
               count_text(source, "unmatched OPTIONS {") == 1u &&
               count_text(source, "unmatched CONNECT {") == 1u &&
               count_text(source, "\nunmatched {") == 1u && count_text(source, options) == 1u &&
               count_text(source, connect) == 1u && count_text(source, any) == 1u;
    };
    const auto has_no_nginx_hook = [](const std::string& source) {
        return source.find("nginx.conf") == std::string::npos &&
               source.find("nginx::") == std::string::npos &&
               source.find("nginx_compat") == std::string::npos &&
               source.find("workaround") == std::string::npos &&
               source.find("bind_address") == std::string::npos &&
               source.find("local_address") == std::string::npos &&
               source.find("req.listener") == std::string::npos &&
               source.find("address_condition") == std::string::npos;
    };
    const auto source_is_canonical = [&](const std::string& source) {
        return listener_is_canonical(source) && upstream_is_canonical(source) &&
               pre_route_is_canonical(source) && prefix_route_is_canonical(source) &&
               request_policy_is_canonical(source) && response_policy_is_canonical(source) &&
               failure_policy_is_canonical(source) && timeout_policy_is_canonical(source) &&
               unmatched_policies_are_canonical(source) && has_no_nginx_hook(source);
    };
    REQUIRE(request_policy_is_canonical(exact));
    REQUIRE(response_policy_is_canonical(exact));
    REQUIRE(failure_policy_is_canonical(exact));
    REQUIRE(timeout_policy_is_canonical(exact));
    REQUIRE(unmatched_policies_are_canonical(exact));
    REQUIRE(source_is_canonical(exact));
    const auto replace_unique = [&](std::string source, Str before, Str after) {
        const std::string needle(before.ptr, before.len);
        const size_t offset = source.find(needle);
        if (needle.empty() || before.eq(after) || offset == std::string::npos ||
            source.find(needle, offset + needle.size()) != std::string::npos) {
            CHECK(false);
            return std::string{};
        }
        source.replace(offset, needle.size(), after.ptr, after.len);
        CHECK_FALSE(source.empty());
        CHECK_NE(source, exact);
        return source;
    };
    const auto check_isolated = [&](const std::string& candidate,
                                    bool listener_ok,
                                    bool upstream_ok,
                                    bool pre_route_ok,
                                    bool route_ok,
                                    bool hook_ok = true) {
        REQUIRE_FALSE(candidate.empty());
        CHECK_EQ(listener_is_canonical(candidate), listener_ok);
        CHECK_EQ(upstream_is_canonical(candidate), upstream_ok);
        CHECK_EQ(pre_route_is_canonical(candidate), pre_route_ok);
        CHECK_EQ(prefix_route_is_canonical(candidate), route_ok);
        CHECK_EQ(has_no_nginx_hook(candidate), hook_ok);
        CHECK_FALSE(source_is_canonical(candidate));
    };
    check_isolated(
        replace_unique(
            exact, lit_str("listen 127.0.0.1:8080\n"), lit_str("listen 127.0.0.2:8080\n")),
        false,
        true,
        true,
        true);
    check_isolated(replace_unique(exact, lit_str("127.0.0.1:9000"), lit_str("127.0.0.1:9001")),
                   true,
                   false,
                   true,
                   true);
    check_isolated(replace_unique(exact,
                                  lit_str("pre_route TRACE { return local_response({\n"),
                                  lit_str("pre_route TRACX { return local_response({\n")),
                   true,
                   true,
                   false,
                   true);
    const struct {
        Str before;
        Str after;
    } route_mutations[] = {
        {lit_str("route \"/api\" {\n"), lit_str("route \"/apx\" {\n")},
        {lit_str("req.pathOnly == \"/api\""), lit_str("req.pathOnly == \"/apx\"")},
        {lit_str("return redirect({scheme: \"http\""),
         lit_str("return redirecX({scheme: \"http\"")},
        {lit_str("query: \"preserve_raw\""), lit_str("query: \"discard\"")},
        {lit_str("target_path: \"/api/\""), lit_str("target_path: \"/apx/\"")},
        {lit_str("return forward(nginx_upstream, target_transform: {"),
         lit_str("return forwarX(nginx_upstream, target_transform: {")},
        {lit_str("strip_prefix: \"/api/\""), lit_str("strip_prefix: \"/apx/\"")},
        {lit_str("replace_prefix: \"/v1/\""), lit_str("replace_prefix: \"/v2/\"")},
    };
    for (const auto& mutation : route_mutations)
        check_isolated(
            replace_unique(exact, mutation.before, mutation.after), true, true, true, false);

    const auto check_policy_isolated = [&](const std::string& candidate,
                                           bool request_ok,
                                           bool response_ok,
                                           bool failure_ok,
                                           bool timeout_ok,
                                           bool unmatched_ok) {
        REQUIRE_FALSE(candidate.empty());
        REQUIRE_NE(candidate, exact);
        CHECK(listener_is_canonical(candidate));
        CHECK(upstream_is_canonical(candidate));
        CHECK(pre_route_is_canonical(candidate));
        CHECK(prefix_route_is_canonical(candidate));
        CHECK_EQ(request_policy_is_canonical(candidate), request_ok);
        CHECK_EQ(response_policy_is_canonical(candidate), response_ok);
        CHECK_EQ(failure_policy_is_canonical(candidate), failure_ok);
        CHECK_EQ(timeout_policy_is_canonical(candidate), timeout_ok);
        CHECK_EQ(unmatched_policies_are_canonical(candidate), unmatched_ok);
        CHECK(has_no_nginx_hook(candidate));
        CHECK_FALSE(source_is_canonical(candidate));
    };
    check_policy_isolated(
        replace_unique(exact, lit_str("host: \"upstream\""), lit_str("host: \"upstreaX\"")),
        false,
        true,
        true,
        true,
        true);
    check_policy_isolated(
        replace_unique(
            exact, lit_str("framing: \"content_length\""), lit_str("framing: \"content_lengtx\"")),
        true,
        false,
        true,
        true,
        true);
    check_policy_isolated(replace_unique(exact, lit_str("status: 502,"), lit_str("status: 503,")),
                          true,
                          true,
                          false,
                          true,
                          true);
    const std::string timeout_policy =
        exact + "// timeout_failure_policy: forbidden in the unbuffered profile\n";
    check_policy_isolated(timeout_policy, true, true, true, false, true);
    check_policy_isolated(replace_unique(exact,
                                         lit_str("unmatched OPTIONS { return local_response({\n"
                                                 "  version: \"HTTP/1.1\", status: 400,"),
                                         lit_str("unmatched OPTIONS { return local_response({\n"
                                                 "  version: \"HTTP/1.1\", status: 401,")),
                          true,
                          true,
                          true,
                          true,
                          false);
    check_policy_isolated(replace_unique(exact,
                                         lit_str("unmatched CONNECT { return local_response({\n"
                                                 "  version: \"HTTP/1.1\", status: 405,"),
                                         lit_str("unmatched CONNECT { return local_response({\n"
                                                 "  version: \"HTTP/1.1\", status: 406,")),
                          true,
                          true,
                          true,
                          true,
                          false);
    check_policy_isolated(replace_unique(exact,
                                         lit_str("\nunmatched { return local_response({\n"
                                                 "  version: \"HTTP/1.1\", status: 400,"),
                                         lit_str("\nunmatched { return local_response({\n"
                                                 "  version: \"HTTP/1.1\", status: 401,")),
                          true,
                          true,
                          true,
                          true,
                          false);

    const char* hook_markers[] = {
        "nginx.conf",
        "nginx::",
        "nginx_compat",
        "workaround",
        "local_address",
        "req.listener",
        "address_condition",
        "bind_address",
    };
    for (const char* marker : hook_markers) {
        const std::string hook = exact + "// " + marker + " marker\n";
        REQUIRE_NE(hook, exact);
        CHECK(listener_is_canonical(hook));
        CHECK(upstream_is_canonical(hook));
        CHECK(pre_route_is_canonical(hook));
        CHECK(prefix_route_is_canonical(hook));
        CHECK(request_policy_is_canonical(hook));
        CHECK(response_policy_is_canonical(hook));
        CHECK(failure_policy_is_canonical(hook));
        CHECK(timeout_policy_is_canonical(hook));
        CHECK(unmatched_policies_are_canonical(hook));
        CHECK_FALSE(has_no_nginx_hook(hook));
        CHECK_FALSE(source_is_canonical(hook));
        const auto hook_lexed = lex({hook.data(), static_cast<u32>(hook.size())});
        REQUIRE(hook_lexed);
        const auto hook_ast = parse_file(hook_lexed.value());
        REQUIRE(hook_ast);
        delete hook_ast.value();
    }

    const std::string harmless = exact + "// canonical byte equality witness\n";
    REQUIRE_NE(harmless, exact);
    REQUIRE(source_is_canonical(harmless));
    const auto harmless_lexed = lex({harmless.data(), static_cast<u32>(harmless.size())});
    REQUIRE(harmless_lexed);
    const auto harmless_ast = parse_file(harmless_lexed.value());
    REQUIRE(harmless_ast);
    delete harmless_ast.value();

    const auto lexed = lex({exact.data(), static_cast<u32>(exact.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast->items[0].listen.port, 8080u);
    const AstRouteDecl* ast_route = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++)
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.path.eq(lit_str("/api")))
            ast_route = &ast->items[i].route;
    REQUIRE(ast_route != nullptr);
    REQUIRE_EQ(ast_route->statements.len, 1u);
    REQUIRE(ast_route->statements[0] != nullptr);
    const AstStatement& ast_if = *ast_route->statements[0];
    REQUIRE(ast_if.kind == AstStmtKind::If);
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.else_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE(ast_if.then_stmt->has_redirect_policy);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    const auto& ast_redirect = ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u];
    CHECK(ast_redirect.authority == RedirectPolicyAuthority::RequestHost);
    CHECK(ast_redirect.port == RedirectPolicyPort::ActualListener);
    CHECK(ast_redirect.query == RedirectPolicyQuery::PreserveRaw);
    CHECK(ast_redirect.target_path.eq(lit_str("/api/")));
    const AstStatement* ast_forward = ast_if.else_stmt;
    if (ast_forward->kind == AstStmtKind::Block) {
        REQUIRE_EQ(ast_forward->block_stmts.len, 1u);
        ast_forward = ast_forward->block_stmts[0];
    }
    REQUIRE(ast_forward != nullptr);
    REQUIRE(ast_forward->kind == AstStmtKind::ForwardUpstream);
    REQUIRE(ast_forward->has_forward_target_transform);
    CHECK(ast_forward->forward_target_transform.strip_prefix.eq(lit_str("/api/")));
    CHECK(ast_forward->forward_target_transform.replace_prefix.eq(lit_str("/v1/")));
    REQUIRE(ast_forward->has_forward_request_policy);
    REQUIRE_NE(ast_forward->forward_request_policy_id, 0u);
    REQUIRE(ast_forward->has_forward_response_policy);
    REQUIRE_NE(ast_forward->forward_response_policy_id, 0u);
    REQUIRE_LE(ast_forward->forward_response_policy_id, ast->response_policies.len);
    REQUIRE(ast_forward->has_forward_failure_policy);
    REQUIRE_NE(ast_forward->forward_failure_policy_id, 0u);
    REQUIRE_LE(ast_forward->forward_failure_policy_id, ast->failure_policies.len);

    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir->listener.port, 8080u);
    REQUIRE_EQ(hir->routes.len, 1u);
    const HirRoute& hir_route = hir->routes[0];
    CHECK(hir_route.path.eq(lit_str("/api")));
    REQUIRE(hir_route.control.kind == HirControlKind::If);
    REQUIRE(hir_route.control.then_term.kind == HirTerminatorKind::Redirect);
    const u16 redirect_id = hir_route.control.then_term.redirect_policy_id;
    REQUIRE_NE(redirect_id, 0u);
    REQUIRE_LE(redirect_id, hir->redirect_policies.len);
    const auto& hir_redirect = hir->redirect_policies[redirect_id - 1u];
    CHECK(hir_redirect.authority == RedirectPolicyAuthority::RequestHost);
    CHECK(hir_redirect.port == RedirectPolicyPort::ActualListener);
    CHECK(hir_redirect.query == RedirectPolicyQuery::PreserveRaw);
    CHECK(hir_redirect.target_path.eq(lit_str("/api/")));
    const auto& hir_forward = hir_route.control.else_term;
    REQUIRE(hir_forward.kind == HirTerminatorKind::ForwardUpstream);
    REQUIRE(hir_forward.has_forward_target_transform);
    CHECK(hir_forward.forward_target_transform.strip_prefix.eq(lit_str("/api/")));
    CHECK(hir_forward.forward_target_transform.replace_prefix.eq(lit_str("/v1/")));
    REQUIRE_NE(hir_forward.forward_request_policy_id, 0u);
    REQUIRE_NE(hir_forward.forward_response_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_response_policy_id, hir->response_policies.len);
    REQUIRE_NE(hir_forward.forward_failure_policy_id, 0u);
    REQUIRE_LE(hir_forward.forward_failure_policy_id, hir->failure_policies.len);
    CHECK_EQ(hir_forward.forward_timeout_failure_policy_id, 0u);
    CHECK_EQ(hir_forward.forward_response_read_timeout_seconds, 0u);
    CHECK(hir_forward.forward_response_buffering == ForwardResponseBufferingMode::None);
}

TEST(nginx_parser, rejects_non_loopback_and_malformed_exact_listen_endpoints) {
    struct Rejection {
        const char* fragment;
        const char* offending;
        FrontendError code;
        Str detail;
    };
    const Rejection rejections[] = {
        {"listen 127.0.0.1:;",
         "127.0.0.1:",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1:0;",
         "127.0.0.1:0",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1:65536;",
         "127.0.0.1:65536",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1:-1;",
         "127.0.0.1:-1",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1:+1;",
         "127.0.0.1:+1",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1:$port;",
         "127.0.0.1:$port",
         FrontendError::UnsupportedSyntax,
         lit_str("variables are unsupported")},
        {"listen 127.0.0.1:184467440737095516161844674407370955161;",
         "127.0.0.1:184467440737095516161844674407370955161",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.2:8080;",
         "127.0.0.2:8080",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.00.0.1:8080;",
         "127.00.0.1:8080",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 0127.0.0.1:8080;",
         "0127.0.0.1:8080",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1 :8080;",
         "127.0.0.1",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen 127.0.0.1: 8080;",
         "127.0.0.1:",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen \"127.0.0.1:8080\";",
         "\"127.0.0.1:8080\"",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen localhost:8080;",
         "localhost:8080",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen [::1]:8080;",
         "[::1]:8080",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {"listen unix:/tmp/nginx.sock;",
         "unix:/tmp/nginx.sock",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
    };
    for (const auto& rejection : rejections) {
        char source[320]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { %s location / { proxy_pass "
                                 "http://127.0.0.1:9000; } }",
                                 rejection.fragment);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(parsed);
        const char* offending = strstr(source, rejection.offending);
        REQUIRE(offending != nullptr);
        CHECK_EQ(parsed.error().code, rejection.code);
        CHECK(parsed.error().detail.eq(rejection.detail));
        CHECK_EQ(parsed.error().span.start, static_cast<u32>(offending - source));
        CHECK_EQ(parsed.error().span.end,
                 static_cast<u32>(offending - source + strlen(rejection.offending)));
        CHECK_EQ(parsed.error().span.line, 1u);
        CHECK_EQ(parsed.error().span.col, static_cast<u32>(offending - source + 1u));
    }

    const char comment_split[] =
        "server { listen 127.0.0.# split endpoint\n"
        "1:8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto comment_result = nginx::parse({comment_split, sizeof(comment_split) - 1u});
    REQUIRE_FALSE(comment_result);
    const char* comment_offending = strstr(comment_split, "127.0.0.");
    REQUIRE(comment_offending != nullptr);
    CHECK_EQ(comment_result.error().code, FrontendError::InvalidInteger);
    CHECK(comment_result.error().detail.eq(lit_str("invalid listen port")));
    CHECK_EQ(comment_result.error().span.start,
             static_cast<u32>(comment_offending - comment_split));
    CHECK_EQ(comment_result.error().span.end,
             static_cast<u32>(comment_offending - comment_split + strlen("127.0.0.")));
    CHECK_EQ(comment_result.error().span.line, 1u);
    CHECK_EQ(comment_result.error().span.col,
             static_cast<u32>(comment_offending - comment_split + 1u));

    const char option[] =
        "server { listen 127.0.0.1:8080 default_server; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto option_result = nginx::parse({option, sizeof(option) - 1u});
    REQUIRE_FALSE(option_result);
    const char* option_token = strstr(option, "default_server");
    REQUIRE(option_token != nullptr);
    CHECK_EQ(option_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(option_result.error().detail.eq(lit_str("listen options are unsupported")));
    CHECK_EQ(option_result.error().span.start, static_cast<u32>(option_token - option));
    CHECK_EQ(option_result.error().span.end,
             static_cast<u32>(option_token - option + strlen("default_server")));

    const char duplicate[] =
        "server { listen 127.0.0.1:8080; listen 8081; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto duplicate_result = nginx::parse({duplicate, sizeof(duplicate) - 1u});
    REQUIRE_FALSE(duplicate_result);
    CHECK_EQ(duplicate_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(duplicate_result.error().detail.eq(lit_str("duplicate listen")));
}

TEST(nginx_parser, rejects_other_explicit_listen_shapes_without_partial_model) {
    struct Rejection {
        const char* listen_fragment;
        FrontendError code;
    };
    const Rejection rejections[] = {
        {"listen 0.0.0.0:;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:0;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:65536;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:-1;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:+1;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:port;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:184467440737095516161844674407370955161;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:0.0.0.0:8080;", FrontendError::InvalidInteger},
        {"listen 0.0.0.1:8080;", FrontendError::InvalidInteger},
        {"listen 0.0.0:8080;", FrontendError::InvalidInteger},
        {"listen 00.0.0.0:8080;", FrontendError::InvalidInteger},
        {"listen 0.00.0.0:8080;", FrontendError::InvalidInteger},
        {"listen localhost:8080;", FrontendError::InvalidInteger},
        {"listen [::]:8080;", FrontendError::InvalidInteger},
        {"listen unix:/tmp/nginx.sock;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:$port;", FrontendError::UnsupportedSyntax},
        {"listen $address:8080;", FrontendError::UnsupportedSyntax},
        {"listen 0.0.$octet.0:8080;", FrontendError::UnsupportedSyntax},
        {"listen 0.0.0.0 : 8080;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0: 8080;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:8080 default_server;", FrontendError::UnsupportedSyntax},
        {"listen 0.0.0.0:8080 ssl;", FrontendError::UnsupportedSyntax},
        {"listen 0.0.0.0:8080 reuseport;", FrontendError::UnsupportedSyntax},
        {"listen 0.0.0.0:8080 backlog=128;", FrontendError::UnsupportedSyntax},
        {"listen 0.0.0.0:8080garbage;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:8080:extra;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:8080 extra;", FrontendError::UnsupportedSyntax},
        {"listen \"0.0.0.0:8080\";", FrontendError::InvalidInteger},
    };
    for (const auto& rejection : rejections) {
        char source[256]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { %s location / { proxy_pass "
                                 "http://127.0.0.1:9000; } }",
                                 rejection.listen_fragment);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(parsed);
        CHECK_MSG(parsed.error().code == rejection.code, rejection.listen_fragment);
        CHECK_LT(parsed.error().span.start, static_cast<u32>(len));
        CHECK_LE(parsed.error().span.end, static_cast<u32>(len));
        CHECK_FALSE(parsed.error().detail.empty());
    }

    // Attribute representative failures to the complete offending lexer token,
    // including exact source coordinates and diagnostic detail. A failed parse
    // exposes no semantic model that could be passed to lower_to_rut.
    struct Attribution {
        const char* source;
        const char* offending;
        FrontendError code;
        Str detail;
    };
    static constexpr char kInvalidWildcardPort[] =
        "server { listen 0.0.0.0:65536; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kVariableWildcardPort[] =
        "server { listen 0.0.0.0:$port; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kWildcardOption[] =
        "server { listen 0.0.0.0:8080 ssl; location / { proxy_pass "
        "http://127.0.0.1:9000; } }";
    static constexpr char kSplitWildcard[] =
        "server { listen 0.0.0.0 : 8080; location / { proxy_pass "
        "http://127.0.0.1:9000; } }";
    static constexpr char kMissingSemicolon[] =
        "server { listen 0.0.0.0:8080 location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kOverflowListen[] =
        "server { listen 184467440737095516161844674407370955161; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kOverflowUpstream[] =
        "server { listen 8080; location / { proxy_pass "
        "http://127.0.0.1:184467440737095516161844674407370955161; } }";
    const Attribution attributions[] = {
        {kInvalidWildcardPort,
         "0.0.0.0:65536",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {kVariableWildcardPort,
         "0.0.0.0:$port",
         FrontendError::UnsupportedSyntax,
         lit_str("variables are unsupported")},
        {kWildcardOption,
         "ssl",
         FrontendError::UnsupportedSyntax,
         lit_str("listen options are unsupported")},
        {kSplitWildcard, "0.0.0.0", FrontendError::InvalidInteger, lit_str("invalid listen port")},
        {kMissingSemicolon,
         "location",
         FrontendError::UnexpectedToken,
         lit_str("expected ';' after listen")},
        {kOverflowListen,
         "184467440737095516161844674407370955161",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {kOverflowUpstream,
         "http://127.0.0.1:184467440737095516161844674407370955161",
         FrontendError::InvalidInteger,
         lit_str("invalid upstream IPv4 address or port")},
    };
    for (const auto& attribution : attributions) {
        const u32 source_len = static_cast<u32>(strlen(attribution.source));
        const auto parsed = nginx::parse({attribution.source, source_len});
        REQUIRE_FALSE(parsed);
        const char* offending = strstr(attribution.source, attribution.offending);
        REQUIRE(offending != nullptr);
        const u32 start = static_cast<u32>(offending - attribution.source);
        const u32 end = start + static_cast<u32>(strlen(attribution.offending));
        CHECK_EQ(parsed.error().code, attribution.code);
        CHECK(parsed.error().detail.eq(attribution.detail));
        CHECK_EQ(parsed.error().span.start, start);
        CHECK_EQ(parsed.error().span.end, end);
        CHECK_EQ(parsed.error().span.line, 1u);
        CHECK_EQ(parsed.error().span.col, start + 1u);
    }

    const char duplicate[] =
        "server { listen 0.0.0.0:8080; listen 8081; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto duplicate_result = nginx::parse({duplicate, sizeof(duplicate) - 1u});
    REQUIRE_FALSE(duplicate_result);
    CHECK_EQ(duplicate_result.error().code, FrontendError::UnsupportedSyntax);
    CHECK(duplicate_result.error().detail.eq(lit_str("duplicate listen")));
}

TEST(nginx_parser, rejects_non_exact_asterisk_listen_shapes_without_partial_model) {
    struct Rejection {
        const char* listen_fragment;
        FrontendError code;
    };
    const Rejection rejections[] = {
        {"listen *;", FrontendError::InvalidInteger},
        {"listen *:;", FrontendError::InvalidInteger},
        {"listen *::80;", FrontendError::InvalidInteger},
        {"listen * :8080;", FrontendError::InvalidInteger},
        {"listen * : 8080;", FrontendError::InvalidInteger},
        {"listen *: 8080;", FrontendError::InvalidInteger},
        {"listen *:\t8080;", FrontendError::InvalidInteger},
        {"listen *:-1;", FrontendError::InvalidInteger},
        {"listen *:+1;", FrontendError::InvalidInteger},
        {"listen *:0;", FrontendError::InvalidInteger},
        {"listen *:65536;", FrontendError::InvalidInteger},
        {"listen *:184467440737095516161844674407370955161;", FrontendError::InvalidInteger},
        {"listen *:*:8080;", FrontendError::InvalidInteger},
        {"listen *:*:*:8080;", FrontendError::InvalidInteger},
        {"listen 0.0.0.0:*:8080;", FrontendError::InvalidInteger},
        {"listen 0.0.0.1:8080;", FrontendError::InvalidInteger},
        {"listen [::]:8080;", FrontendError::InvalidInteger},
        {"listen localhost:8080;", FrontendError::InvalidInteger},
        {"listen unix:/tmp/nginx.sock;", FrontendError::InvalidInteger},
        {"listen *:$port;", FrontendError::UnsupportedSyntax},
        {"listen $address:8080;", FrontendError::UnsupportedSyntax},
        {"listen *:8080 default_server;", FrontendError::UnsupportedSyntax},
        {"listen *:8080 ssl;", FrontendError::UnsupportedSyntax},
        {"listen *:8080 reuseport;", FrontendError::UnsupportedSyntax},
        {"listen *:8080 backlog=128;", FrontendError::UnsupportedSyntax},
        {"listen *:8080 so_keepalive=on;", FrontendError::UnsupportedSyntax},
        {"listen *:8080garbage;", FrontendError::InvalidInteger},
        {"listen *:8080:extra;", FrontendError::InvalidInteger},
        {"listen \"*:8080\";", FrontendError::InvalidInteger},
    };
    for (const auto& rejection : rejections) {
        char source[256]{};
        const int len = snprintf(source,
                                 sizeof(source),
                                 "server { %s location / { proxy_pass "
                                 "http://127.0.0.1:9000; } }",
                                 rejection.listen_fragment);
        REQUIRE_GT(len, 0);
        REQUIRE_LT(static_cast<u32>(len), static_cast<u32>(sizeof(source)));
        const auto parsed = nginx::parse({source, static_cast<u32>(len)});
        REQUIRE_FALSE(parsed);
        CHECK_MSG(parsed.error().code == rejection.code, rejection.listen_fragment);
        CHECK_LT(parsed.error().span.start, static_cast<u32>(len));
        CHECK_LE(parsed.error().span.end, static_cast<u32>(len));
        CHECK_FALSE(parsed.error().detail.empty());
    }

    struct Attribution {
        const char* source;
        const char* offending;
        FrontendError code;
        Str detail;
    };
    static constexpr char kInvalidPort[] =
        "server { listen *:65536; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kVariablePort[] =
        "server { listen *:$port; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kOption[] =
        "server { listen *:8080 ssl; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kSplit[] =
        "server { listen * :8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kMissingSemicolon[] =
        "server { listen *:8080 location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kOverflowListen[] =
        "server { listen 184467440737095516161844674407370955161; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kOverflowUpstream[] =
        "server { listen *:8080; location / { proxy_pass "
        "http://127.0.0.1:184467440737095516161844674407370955161; } }";
    const Attribution attributions[] = {
        {kInvalidPort, "*:65536", FrontendError::InvalidInteger, lit_str("invalid listen port")},
        {kVariablePort,
         "*:$port",
         FrontendError::UnsupportedSyntax,
         lit_str("variables are unsupported")},
        {kOption,
         "ssl",
         FrontendError::UnsupportedSyntax,
         lit_str("listen options are unsupported")},
        {kSplit, "*", FrontendError::InvalidInteger, lit_str("invalid listen port")},
        {kMissingSemicolon,
         "location",
         FrontendError::UnexpectedToken,
         lit_str("expected ';' after listen")},
        {kOverflowListen,
         "184467440737095516161844674407370955161",
         FrontendError::InvalidInteger,
         lit_str("invalid listen port")},
        {kOverflowUpstream,
         "http://127.0.0.1:184467440737095516161844674407370955161",
         FrontendError::InvalidInteger,
         lit_str("invalid upstream IPv4 address or port")},
    };
    for (const auto& attribution : attributions) {
        const u32 source_len = static_cast<u32>(strlen(attribution.source));
        const auto parsed = nginx::parse({attribution.source, source_len});
        REQUIRE_FALSE(parsed);
        const char* offending = strstr(attribution.source, attribution.offending);
        REQUIRE(offending != nullptr);
        const u32 start = static_cast<u32>(offending - attribution.source);
        const u32 end = start + static_cast<u32>(strlen(attribution.offending));
        CHECK_EQ(parsed.error().code, attribution.code);
        CHECK(parsed.error().detail.eq(attribution.detail));
        CHECK_EQ(parsed.error().span.start, start);
        CHECK_EQ(parsed.error().span.end, end);
        CHECK_EQ(parsed.error().span.line, 1u);
        CHECK_EQ(parsed.error().span.col, start + 1u);
    }

    const char duplicate_after[] =
        "server { listen *:8080; listen 8081; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const char duplicate_before[] =
        "server { listen 8081; listen *:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    for (const auto* source : {duplicate_after, duplicate_before}) {
        const auto parsed = nginx::parse({source, static_cast<u32>(strlen(source))});
        REQUIRE_FALSE(parsed);
        CHECK_EQ(parsed.error().code, FrontendError::UnsupportedSyntax);
        CHECK(parsed.error().detail.eq(lit_str("duplicate listen")));
    }
}

TEST(nginx_converter, explicit_ipv4_wildcard_listen_has_port_only_golden) {
    static constexpr char kCanonicalTraceHook[] =
        "pre_route TRACE { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 405, reason: \"Not Allowed\", server: "
        "\"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/html\", connection: \"request\",\n"
        "  head_mode: \"reject\", body: b\"<html>\\r\\n<head><title>405 Not "
        "Allowed</title></head>\\r\\n"
        "<body>\\r\\n<center><h1>405 Not Allowed</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n</body>\\r\\n</html>\\r\\n\"\n"
        "}) }\n";
    static constexpr char kPortFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kWildcardFirst[] =
        "server { listen 0.0.0.0:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kAsteriskFirst[] =
        "server { listen *:8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kPortLast[] =
        "server { location / { proxy_pass http://127.0.0.1:9000; } listen 8080; }";
    static constexpr char kWildcardLast[] =
        "server { location / { proxy_pass http://127.0.0.1:9000; } "
        "listen 0.0.0.0:8080; }";
    static constexpr char kAsteriskLast[] =
        "server { location / { proxy_pass http://127.0.0.1:9000; } listen *:8080; }";
    const char* const sources[] = {
        kPortFirst, kWildcardFirst, kAsteriskFirst, kPortLast, kWildcardLast, kAsteriskLast};
    std::string generated[6];
    nginx::Server port_model{};
    nginx::Server wildcard_model{};
    nginx::Server asterisk_model{};
    for (u32 i = 0; i < 6u; i++) {
        const auto parsed = nginx::parse({sources[i], static_cast<u32>(strlen(sources[i]))});
        REQUIRE(parsed);
        CHECK_EQ(parsed.value().listen.port, 8080u);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated[i].assign(lowered.value().data, lowered.value().len);
        if (i == 0u) port_model = parsed.value();
        if (i == 1u) wildcard_model = parsed.value();
        if (i == 2u) asterisk_model = parsed.value();
    }
    const std::string& canonical = generated[0];
    for (u32 i = 0; i < 6u; i++) CHECK_EQ(generated[i], canonical);

    // Complete byte equality above is independent from this structural/profile
    // validator. Mutations below isolate each guard while retaining all others.
    const auto listener_inventory_is_canonical = [](const std::string& candidate) {
        return candidate.rfind("listen :8080\n", 0u) == 0u &&
               count_text(candidate, "listen :8080\n") == 1u &&
               count_text(candidate, "listen :") == 1u;
    };
    const auto upstream_inventory_is_canonical = [](const std::string& candidate) {
        return count_text(candidate, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u &&
               count_upstream_declarations(candidate) == 1u;
    };
    const auto pre_route_inventory_is_canonical = [](const std::string& candidate) {
        return count_text(candidate, kCanonicalTraceHook) == 1u &&
               ((candidate.rfind("pre_route ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\npre_route ")) == 1u;
    };
    const auto fixed_inventory_is_canonical = [&](const std::string& candidate) {
        return upstream_inventory_is_canonical(candidate) &&
               pre_route_inventory_is_canonical(candidate);
    };
    const auto route_inventory_is_canonical = [](const std::string& candidate) {
        return count_route_declarations(candidate) == 3u &&
               count_text(candidate, "route HEAD \"/\" {") == 1u &&
               count_text(candidate, "route GET \"/\" {") == 1u &&
               count_text(candidate, "\nroute \"/\" {") == 1u;
    };
    const auto has_no_address_workaround = [](const std::string& candidate) {
        return candidate.find("0.0.0.0") == std::string::npos &&
               candidate.find("*:") == std::string::npos &&
               candidate.find("bind_address") == std::string::npos &&
               candidate.find("local_address") == std::string::npos &&
               candidate.find("req.listener") == std::string::npos;
    };
    const auto has_no_nginx_hook = [](const std::string& candidate) {
        return candidate.find("nginx.conf") == std::string::npos &&
               candidate.find("nginx::") == std::string::npos &&
               candidate.find("nginx_compat") == std::string::npos &&
               candidate.find("workaround") == std::string::npos;
    };
    const auto source_has_canonical_structure = [&](const std::string& candidate) {
        return listener_inventory_is_canonical(candidate) &&
               fixed_inventory_is_canonical(candidate) && route_inventory_is_canonical(candidate) &&
               has_no_address_workaround(candidate) && has_no_nginx_hook(candidate);
    };
    REQUIRE(listener_inventory_is_canonical(canonical));
    REQUIRE_EQ(count_text(canonical, "upstream nginx_upstream at \"127.0.0.1:9000\"\n"), 1u);
    REQUIRE_EQ(count_upstream_declarations(canonical), 1u);
    REQUIRE_EQ(count_text(canonical, "pre_route TRACE {"), 1u);
    REQUIRE(upstream_inventory_is_canonical(canonical));
    REQUIRE(pre_route_inventory_is_canonical(canonical));
    REQUIRE(fixed_inventory_is_canonical(canonical));
    REQUIRE(route_inventory_is_canonical(canonical));
    REQUIRE(has_no_address_workaround(canonical));
    REQUIRE(has_no_nginx_hook(canonical));
    REQUIRE(source_has_canonical_structure(canonical));

    std::string wrong_listener = canonical;
    const size_t listener_offset = wrong_listener.find("listen :8080\n");
    REQUIRE_NE(listener_offset, std::string::npos);
    wrong_listener.replace(listener_offset, strlen("listen :8080"), "listen :8081");
    CHECK_NE(wrong_listener, canonical);
    CHECK_EQ(count_text(wrong_listener, "listen :8081\n"), 1u);
    CHECK_FALSE(listener_inventory_is_canonical(wrong_listener));
    CHECK(fixed_inventory_is_canonical(wrong_listener));
    CHECK(route_inventory_is_canonical(wrong_listener));
    CHECK(has_no_address_workaround(wrong_listener));
    CHECK(has_no_nginx_hook(wrong_listener));
    CHECK_FALSE(source_has_canonical_structure(wrong_listener));

    static constexpr char kCanonicalUpstream[] = "upstream nginx_upstream at \"127.0.0.1:9000\"\n";
    static constexpr char kChangedUpstream[] = "upstream nginx_upstream at \"127.0.0.1:9001\"\n";
    REQUIRE_EQ(count_text(canonical, kCanonicalUpstream), 1u);
    REQUIRE_EQ(count_text(canonical, kChangedUpstream), 0u);
    const size_t upstream_offset = canonical.find(kCanonicalUpstream);
    REQUIRE_NE(upstream_offset, std::string::npos);
    REQUIRE_EQ(
        canonical.find(kCanonicalUpstream, upstream_offset + sizeof(kCanonicalUpstream) - 1u),
        std::string::npos);
    std::string wrong_upstream = canonical;
    wrong_upstream.replace(upstream_offset, sizeof(kCanonicalUpstream) - 1u, kChangedUpstream);
    CHECK_NE(wrong_upstream, canonical);
    CHECK_EQ(count_text(wrong_upstream, kCanonicalUpstream), 0u);
    CHECK_EQ(count_text(wrong_upstream, kChangedUpstream), 1u);
    CHECK_EQ(count_upstream_declarations(wrong_upstream), 1u);
    CHECK(listener_inventory_is_canonical(wrong_upstream));
    CHECK_FALSE(upstream_inventory_is_canonical(wrong_upstream));
    CHECK(pre_route_inventory_is_canonical(wrong_upstream));
    CHECK(route_inventory_is_canonical(wrong_upstream));
    CHECK(has_no_address_workaround(wrong_upstream));
    CHECK(has_no_nginx_hook(wrong_upstream));
    CHECK_FALSE(fixed_inventory_is_canonical(wrong_upstream));
    CHECK_FALSE(source_has_canonical_structure(wrong_upstream));

    REQUIRE_EQ(count_text(canonical, kCanonicalTraceHook), 1u);
    std::string changed_trace_hook(kCanonicalTraceHook);
    static constexpr char kCanonicalStatus[] = "status: 405";
    static constexpr char kChangedStatus[] = "status: 400";
    const size_t changed_status_offset = changed_trace_hook.find(kCanonicalStatus);
    REQUIRE_NE(changed_status_offset, std::string::npos);
    REQUIRE_EQ(changed_trace_hook.find(kCanonicalStatus,
                                       changed_status_offset + sizeof(kCanonicalStatus) - 1u),
               std::string::npos);
    changed_trace_hook.replace(
        changed_status_offset, sizeof(kCanonicalStatus) - 1u, kChangedStatus);
    REQUIRE_NE(changed_trace_hook, std::string(kCanonicalTraceHook));
    REQUIRE_EQ(count_text(changed_trace_hook, kCanonicalStatus), 0u);
    REQUIRE_EQ(count_text(changed_trace_hook, kChangedStatus), 1u);
    REQUIRE_EQ(count_text(canonical, changed_trace_hook), 0u);
    const size_t trace_hook_offset = canonical.find(kCanonicalTraceHook);
    REQUIRE_NE(trace_hook_offset, std::string::npos);
    REQUIRE_EQ(
        canonical.find(kCanonicalTraceHook, trace_hook_offset + sizeof(kCanonicalTraceHook) - 1u),
        std::string::npos);
    std::string wrong_pre_route = canonical;
    wrong_pre_route.replace(
        trace_hook_offset, sizeof(kCanonicalTraceHook) - 1u, changed_trace_hook);
    CHECK_NE(wrong_pre_route, canonical);
    CHECK_EQ(count_text(wrong_pre_route, kCanonicalTraceHook), 0u);
    CHECK_EQ(count_text(wrong_pre_route, changed_trace_hook), 1u);
    CHECK_EQ((wrong_pre_route.rfind("pre_route ", 0u) == 0u ? 1u : 0u) +
                 count_text(wrong_pre_route, "\npre_route "),
             1u);
    const auto wrong_pre_route_lexed =
        lex({wrong_pre_route.data(), static_cast<u32>(wrong_pre_route.size())});
    REQUIRE(wrong_pre_route_lexed);
    const auto wrong_pre_route_parsed = parse_file(wrong_pre_route_lexed.value());
    REQUIRE(wrong_pre_route_parsed);
    std::unique_ptr<AstFile> wrong_pre_route_ast(wrong_pre_route_parsed.value());
    CHECK_NE(wrong_pre_route_ast->pre_route_policy_ids[kRouteMethodTrace], 0u);
    CHECK(listener_inventory_is_canonical(wrong_pre_route));
    CHECK(upstream_inventory_is_canonical(wrong_pre_route));
    CHECK_FALSE(pre_route_inventory_is_canonical(wrong_pre_route));
    CHECK(route_inventory_is_canonical(wrong_pre_route));
    CHECK(has_no_address_workaround(wrong_pre_route));
    CHECK(has_no_nginx_hook(wrong_pre_route));
    CHECK_FALSE(fixed_inventory_is_canonical(wrong_pre_route));
    CHECK_FALSE(source_has_canonical_structure(wrong_pre_route));

    const std::string address_workaround = canonical + "# bind address 0.0.0.0\n";
    CHECK_NE(address_workaround, canonical);
    CHECK_EQ(count_text(address_workaround, "0.0.0.0"), 1u);
    CHECK(listener_inventory_is_canonical(address_workaround));
    CHECK(fixed_inventory_is_canonical(address_workaround));
    CHECK(route_inventory_is_canonical(address_workaround));
    CHECK_FALSE(has_no_address_workaround(address_workaround));
    CHECK(has_no_nginx_hook(address_workaround));
    CHECK_FALSE(source_has_canonical_structure(address_workaround));

    const std::string asterisk_workaround = canonical + "# bind address *:8080\n";
    CHECK_NE(asterisk_workaround, canonical);
    CHECK_EQ(count_text(asterisk_workaround, "*:8080"), 1u);
    CHECK(listener_inventory_is_canonical(asterisk_workaround));
    CHECK(fixed_inventory_is_canonical(asterisk_workaround));
    CHECK(route_inventory_is_canonical(asterisk_workaround));
    CHECK_FALSE(has_no_address_workaround(asterisk_workaround));
    CHECK(has_no_nginx_hook(asterisk_workaround));
    CHECK_FALSE(source_has_canonical_structure(asterisk_workaround));

    const std::string extra_route =
        canonical + "route \"/wildcard\" { return forward(nginx_upstream) }\n";
    CHECK_NE(extra_route, canonical);
    CHECK_EQ(count_route_declarations(extra_route), 4u);
    CHECK(listener_inventory_is_canonical(extra_route));
    CHECK(fixed_inventory_is_canonical(extra_route));
    CHECK_FALSE(route_inventory_is_canonical(extra_route));
    CHECK(has_no_address_workaround(extra_route));
    CHECK(has_no_nginx_hook(extra_route));
    CHECK_FALSE(source_has_canonical_structure(extra_route));

    const std::string nginx_hook = canonical + "# nginx_compat wildcard-listen workaround\n";
    CHECK_NE(nginx_hook, canonical);
    CHECK_EQ(count_text(nginx_hook, "nginx_compat"), 1u);
    CHECK_EQ(count_text(nginx_hook, "workaround"), 1u);
    CHECK(listener_inventory_is_canonical(nginx_hook));
    CHECK(fixed_inventory_is_canonical(nginx_hook));
    CHECK(route_inventory_is_canonical(nginx_hook));
    CHECK(has_no_address_workaround(nginx_hook));
    CHECK_FALSE(has_no_nginx_hook(nginx_hook));
    CHECK_FALSE(source_has_canonical_structure(nginx_hook));

    wildcard_model.listen.port = 0;
    const auto forged = nginx::lower_to_rut(wildcard_model);
    REQUIRE_FALSE(forged);
    CHECK_EQ(forged.error().code, FrontendError::InvalidInteger);
    CHECK(forged.error().detail.eq(lit_str("invalid model listen port")));

    asterisk_model.listen.port = 0;
    const auto forged_asterisk = nginx::lower_to_rut(asterisk_model);
    REQUIRE_FALSE(forged_asterisk);
    CHECK_EQ(forged_asterisk.error().code, FrontendError::InvalidInteger);
    CHECK(forged_asterisk.error().detail.eq(lit_str("invalid model listen port")));

    wildcard_model.listen.port = 8081u;
    const auto mismatched_wildcard = nginx::lower_to_rut(wildcard_model);
    REQUIRE_FALSE(mismatched_wildcard);
    CHECK_EQ(mismatched_wildcard.error().code, FrontendError::UnsupportedSyntax);
    CHECK(mismatched_wildcard.error().detail.eq(lit_str("invalid wildcard listen endpoint model")));

    port_model.listen.port = 8081u;
    const auto mismatched_port_only = nginx::lower_to_rut(port_model);
    REQUIRE_FALSE(mismatched_port_only);
    CHECK_EQ(mismatched_port_only.error().code, FrontendError::UnsupportedSyntax);
    CHECK(
        mismatched_port_only.error().detail.eq(lit_str("invalid wildcard listen endpoint model")));

    asterisk_model.listen.port = 8081u;
    const auto mismatched_asterisk = nginx::lower_to_rut(asterisk_model);
    REQUIRE_FALSE(mismatched_asterisk);
    CHECK_EQ(mismatched_asterisk.error().code, FrontendError::UnsupportedSyntax);
    CHECK(mismatched_asterisk.error().detail.eq(lit_str("invalid wildcard listen endpoint model")));
}

TEST(nginx_converter, parser_wildcard_listener_rejects_source_and_cross_source_forgery) {
    char mutated_source[] =
        "server { listen 0.0.0.0:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto parsed = nginx::parse({mutated_source, sizeof(mutated_source) - 1u});
    REQUIRE(parsed);
    char* endpoint = strstr(mutated_source, "0.0.0.0:8080");
    REQUIRE(endpoint != nullptr);
    REQUIRE_EQ(memcmp(endpoint, "0.0.0.0", strlen("0.0.0.0")), 0);
    memcpy(endpoint, "0.0.0.1", strlen("0.0.0.1"));
    REQUIRE_EQ(memcmp(endpoint, "0.0.0.1", strlen("0.0.0.1")), 0);
    const auto mutated = nginx::lower_to_rut(parsed.value());
    REQUIRE_FALSE(mutated);
    CHECK_EQ(mutated.error().code, FrontendError::UnsupportedSyntax);
    CHECK(mutated.error().detail.eq(lit_str("invalid wildcard listen endpoint model")));

    char source_a[] = "server { listen *:8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    char source_b[] = "server { listen *:8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    const auto parsed_a = nginx::parse({source_a, sizeof(source_a) - 1u});
    REQUIRE(parsed_a);
    auto cross_source = parsed_a.value();
    const char* endpoint_b = strstr(source_b, "*:8080");
    REQUIRE(endpoint_b != nullptr);
    REQUIRE_NE(endpoint_b, cross_source.listen.value.ptr);
    cross_source.listen.value.ptr = endpoint_b;
    const auto crossed = nginx::lower_to_rut(cross_source);
    REQUIRE_FALSE(crossed);
    CHECK_EQ(crossed.error().code, FrontendError::UnsupportedSyntax);
    CHECK(crossed.error().detail.eq(lit_str("invalid listen source provenance")));
}

TEST(nginx_converter, exact_loopback_listen_has_bounded_ordinary_rut_golden_and_validation) {
    static constexpr char kExactFirst[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kExactLast[] =
        "server { location / { proxy_pass http://127.0.0.1:9000; } "
        "listen 127.0.0.1:8080; }";
    static constexpr char kWildcardFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kWildcardLast[] =
        "server { location / { proxy_pass http://127.0.0.1:9000; } listen 8080; }";
    const char* const sources[] = {kExactFirst, kExactLast, kWildcardFirst, kWildcardLast};
    std::string generated[4];
    nginx::Server exact_model{};
    for (u32 i = 0; i < 4u; i++) {
        const auto parsed = nginx::parse({sources[i], static_cast<u32>(strlen(sources[i]))});
        REQUIRE(parsed);
        const auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        generated[i].assign(lowered.value().data, lowered.value().len);
        if (i == 0u) exact_model = parsed.value();
    }
    REQUIRE_EQ(generated[0], generated[1]);
    REQUIRE_EQ(generated[2], generated[3]);
    REQUIRE_NE(generated[0], generated[2]);
    std::string expected_exact = generated[2];
    REQUIRE_EQ(expected_exact.rfind("listen :8080\n", 0u), 0u);
    expected_exact.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(generated[0], expected_exact);
    const std::string& canonical = generated[0];

    const auto listener_inventory_is_canonical = [](const std::string& candidate) {
        return candidate.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(candidate, "listen 127.0.0.1:8080\n") == 1u &&
               ((candidate.rfind("listen ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\nlisten ")) == 1u &&
               candidate.find("listen :") == std::string::npos;
    };
    const auto upstream_inventory_is_canonical = [](const std::string& candidate) {
        return count_upstream_declarations(candidate) == 1u &&
               count_text(candidate, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_inventory_is_canonical = [](const std::string& candidate) {
        const size_t pre_route = candidate.find("pre_route TRACE {");
        const size_t pre_route_end = candidate.find("}) }\n", pre_route);
        return pre_route != std::string::npos && pre_route_end != std::string::npos &&
               count_text(candidate.substr(pre_route, pre_route_end - pre_route), "status: 405") ==
                   1u &&
               ((candidate.rfind("pre_route ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\npre_route ")) == 1u;
    };
    const auto route_inventory_is_canonical = [](const std::string& candidate) {
        return count_route_declarations(candidate) == 3u &&
               count_text(candidate, "route HEAD \"/\" {") == 1u &&
               count_text(candidate, "route GET \"/\" {") == 1u &&
               count_text(candidate, "\nroute \"/\" {") == 1u;
    };
    const auto has_no_nginx_hook_or_address_workaround = [](const std::string& candidate) {
        return candidate.find("nginx.conf") == std::string::npos &&
               candidate.find("nginx::") == std::string::npos &&
               candidate.find("nginx_compat") == std::string::npos &&
               candidate.find("workaround") == std::string::npos &&
               candidate.find("bind_address") == std::string::npos &&
               candidate.find("local_address") == std::string::npos &&
               candidate.find("req.listener") == std::string::npos;
    };
    const auto source_is_canonical = [&](const std::string& candidate) {
        return listener_inventory_is_canonical(candidate) &&
               upstream_inventory_is_canonical(candidate) &&
               pre_route_inventory_is_canonical(candidate) &&
               route_inventory_is_canonical(candidate) &&
               has_no_nginx_hook_or_address_workaround(candidate);
    };
    REQUIRE(listener_inventory_is_canonical(canonical));
    REQUIRE(upstream_inventory_is_canonical(canonical));
    REQUIRE(pre_route_inventory_is_canonical(canonical));
    REQUIRE(route_inventory_is_canonical(canonical));
    REQUIRE(has_no_nginx_hook_or_address_workaround(canonical));
    REQUIRE(source_is_canonical(canonical));

    std::string wrong_listener = canonical;
    REQUIRE_EQ(count_text(wrong_listener, "listen 127.0.0.1:8080\n"), 1u);
    wrong_listener.replace(0u, strlen("listen 127.0.0.1:8080"), "listen 127.0.0.2:8080");
    CHECK_NE(wrong_listener, canonical);
    CHECK_FALSE(listener_inventory_is_canonical(wrong_listener));
    CHECK(upstream_inventory_is_canonical(wrong_listener));
    CHECK(pre_route_inventory_is_canonical(wrong_listener));
    CHECK(route_inventory_is_canonical(wrong_listener));
    CHECK(has_no_nginx_hook_or_address_workaround(wrong_listener));
    CHECK_FALSE(source_is_canonical(wrong_listener));

    const std::string extra_listener = canonical + "listen :8081\n";
    CHECK_NE(extra_listener, canonical);
    CHECK_FALSE(listener_inventory_is_canonical(extra_listener));
    CHECK(upstream_inventory_is_canonical(extra_listener));
    CHECK(pre_route_inventory_is_canonical(extra_listener));
    CHECK(route_inventory_is_canonical(extra_listener));
    CHECK(has_no_nginx_hook_or_address_workaround(extra_listener));
    CHECK_FALSE(source_is_canonical(extra_listener));

    std::string wrong_upstream = canonical;
    const size_t upstream_port = wrong_upstream.find("127.0.0.1:9000");
    REQUIRE_NE(upstream_port, std::string::npos);
    REQUIRE_EQ(wrong_upstream.find("127.0.0.1:9000", upstream_port + 1u), std::string::npos);
    wrong_upstream.replace(upstream_port, strlen("127.0.0.1:9000"), "127.0.0.1:9001");
    CHECK_NE(wrong_upstream, canonical);
    CHECK(listener_inventory_is_canonical(wrong_upstream));
    CHECK_FALSE(upstream_inventory_is_canonical(wrong_upstream));
    CHECK(pre_route_inventory_is_canonical(wrong_upstream));
    CHECK(route_inventory_is_canonical(wrong_upstream));
    CHECK(has_no_nginx_hook_or_address_workaround(wrong_upstream));
    CHECK_FALSE(source_is_canonical(wrong_upstream));

    std::string wrong_pre_route = canonical;
    const size_t pre_route_offset = wrong_pre_route.find("pre_route TRACE {");
    REQUIRE_NE(pre_route_offset, std::string::npos);
    const size_t trace_status = wrong_pre_route.find("status: 405", pre_route_offset);
    REQUIRE_NE(trace_status, std::string::npos);
    const size_t pre_route_end = wrong_pre_route.find("}) }\n", pre_route_offset);
    REQUIRE_NE(pre_route_end, std::string::npos);
    REQUIRE_LT(trace_status, pre_route_end);
    REQUIRE_EQ(
        count_text(wrong_pre_route.substr(pre_route_offset, pre_route_end - pre_route_offset),
                   "status: 405"),
        1u);
    wrong_pre_route.replace(trace_status, strlen("status: 405"), "status: 400");
    CHECK_NE(wrong_pre_route, canonical);
    CHECK(listener_inventory_is_canonical(wrong_pre_route));
    CHECK(upstream_inventory_is_canonical(wrong_pre_route));
    CHECK_FALSE(pre_route_inventory_is_canonical(wrong_pre_route));
    CHECK(route_inventory_is_canonical(wrong_pre_route));
    CHECK(has_no_nginx_hook_or_address_workaround(wrong_pre_route));
    CHECK_FALSE(source_is_canonical(wrong_pre_route));

    const std::string extra_route = canonical + "route \"/extra\" { return 400 }\n";
    CHECK_NE(extra_route, canonical);
    CHECK(listener_inventory_is_canonical(extra_route));
    CHECK(upstream_inventory_is_canonical(extra_route));
    CHECK(pre_route_inventory_is_canonical(extra_route));
    CHECK_FALSE(route_inventory_is_canonical(extra_route));
    CHECK(has_no_nginx_hook_or_address_workaround(extra_route));
    CHECK_FALSE(source_is_canonical(extra_route));

    const std::string workaround = canonical + "# nginx_compat bind_address workaround\n";
    CHECK_NE(workaround, canonical);
    CHECK(listener_inventory_is_canonical(workaround));
    CHECK(upstream_inventory_is_canonical(workaround));
    CHECK(pre_route_inventory_is_canonical(workaround));
    CHECK(route_inventory_is_canonical(workaround));
    CHECK_FALSE(has_no_nginx_hook_or_address_workaround(workaround));
    CHECK_FALSE(source_is_canonical(workaround));

    const auto lexed = lex({canonical.data(), static_cast<u32>(canonical.size())});
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->items.len, 9u);
    REQUIRE(ast_owned->items[0].kind == AstItemKind::Listen);
    CHECK(ast_owned->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast_owned->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
    const auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE(hir_owned->has_listener);
    CHECK(hir_owned->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir_owned->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir_owned->listener.port, 8080u);
    const auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    REQUIRE_EQ(mir_owned->functions.len, 3u);
    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir_owned, rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.func_count, 3u);
    REQUIRE_EQ(rir.module.upstream_count, 1u);

    auto forged = exact_model;
    forged.listen.port = 0u;
    auto rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK_EQ(rejected.error().code, FrontendError::InvalidInteger);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen port")));

    forged = exact_model;
    forged.listen.address = static_cast<ListenerAddress>(0xff);
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen address")));
    forged = exact_model;
    forged.listen.address = ListenerAddress::IPv4Wildcard;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen address")));
    forged = exact_model;
    forged.listen.address = ListenerAddress::IPv4Wildcard;
    forged.listen.ipv4_host = 0u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid wildcard listen endpoint model")));
    forged = exact_model;
    forged.listen.ipv4_host = 0u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen address")));
    forged = exact_model;
    forged.listen.ipv4_host = 0x7f000002u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen address")));
    forged = exact_model;
    forged.listen.span.end = forged.listen.span.start;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen spans")));
    forged = exact_model;
    forged.listen.value_span = {};
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid model listen spans")));
    forged = exact_model;
    forged.listen.value.ptr++;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid listen source provenance")));
    forged = exact_model;
    forged.listen.port = 8081u;
    rejected = nginx::lower_to_rut(forged);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(lit_str("invalid exact listen endpoint model")));

    static constexpr char kNonRoot[] =
        "server { listen 127.0.0.1:8080; "
        "location /api/ { proxy_pass http://127.0.0.1:9000/v2/; } }";
    const auto non_root = nginx::parse({kNonRoot, sizeof(kNonRoot) - 1u});
    REQUIRE(non_root);
    rejected = nginx::lower_to_rut(non_root.value());
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().detail.eq(
        lit_str("exact listen requires the minimal root proxy profile")));

    static constexpr char kExact301[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    const auto exact_301 = nginx::parse({kExact301, sizeof(kExact301) - 1u});
    REQUIRE(exact_301);
    const auto accepted_301 = nginx::lower_to_rut(exact_301.value());
    REQUIRE(accepted_301);
    CHECK_EQ(accepted_301.value().len, 5937u);
    CHECK_EQ(accepted_301.value().data[accepted_301.value().len], '\0');
    CHECK_EQ(memcmp(accepted_301.value().data,
                    "listen 127.0.0.1:8080\n",
                    sizeof("listen 127.0.0.1:8080\n") - 1u),
             0);

    static constexpr char kExact302[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 302 http://redirect.example/new; } }";
    const auto exact_302 = nginx::parse({kExact302, sizeof(kExact302) - 1u});
    REQUIRE(exact_302);
    const auto accepted_302 = nginx::lower_to_rut(exact_302.value());
    REQUIRE(accepted_302);
    CHECK_EQ(accepted_302.value().len, 5913u);

    static constexpr char kNonRootBodyful[] =
        "server { listen 127.0.0.1:8080; "
        "location = /static { return 200 \"successor-static\"; } "
        "location /api/ { proxy_pass http://127.0.0.1:9000/v1/; } }";
    const auto non_root_bodyful = nginx::parse({kNonRootBodyful, sizeof(kNonRootBodyful) - 1u});
    REQUIRE_FALSE(non_root_bodyful);
    CHECK_EQ(non_root_bodyful.error().code, FrontendError::UnsupportedSyntax);
    CHECK(non_root_bodyful.error().detail.eq(
        lit_str("exact location requires location / proxy fallback")));
    const char* non_root_path = strstr(kNonRootBodyful, "/api/");
    REQUIRE(non_root_path != nullptr);
    CHECK_EQ(non_root_bodyful.error().span.start,
             static_cast<u32>(non_root_path - kNonRootBodyful));
    CHECK_EQ(non_root_bodyful.error().span.end,
             static_cast<u32>(non_root_path - kNonRootBodyful + strlen("/api/")));
    CHECK_EQ(non_root_bodyful.error().span.line, 1u);
    CHECK_EQ(non_root_bodyful.error().span.col,
             static_cast<u32>(non_root_path - kNonRootBodyful + 1u));

    static constexpr char kMaximumRoot[] =
        "server { listen 127.0.0.1:65535; "
        "location / { proxy_pass http://255.255.255.255:65535; } }";
    const auto maximum_root = nginx::parse({kMaximumRoot, sizeof(kMaximumRoot) - 1u});
    REQUIRE(maximum_root);
    const auto maximum_lowered = nginx::lower_to_rut(maximum_root.value());
    REQUIRE(maximum_lowered);
    CHECK_LT(maximum_lowered.value().len, nginx::RutSource::kCapacity);
    CHECK(maximum_lowered.value()
              .view()
              .slice(0, strlen("listen 127.0.0.1:65535\n"))
              .eq(lit_str("listen 127.0.0.1:65535\n")));
}

TEST(nginx_converter, issue348_exact_loopback_no_content_has_canonical_ordinary_rut_golden) {
    static constexpr char kNoContentRoute[] =
        "route exact slash_normalized GET \"/static\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 204, reason: \"No Content\", server: "
        "\"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"\"\n"
        "}) }\n";
    char exact_first[] =
        "server { listen 127.0.0.1:8080; location = /static { return 204; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    char exact_root_first[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204; } }";
    static constexpr char kWildcardFirst[] =
        "server { listen 8080; location = /static { return 204; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    static constexpr char kWildcardRootFirst[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 204; } }";

    const auto exact_first_parsed = nginx::parse({exact_first, sizeof(exact_first) - 1u});
    const auto exact_root_first_parsed =
        nginx::parse({exact_root_first, sizeof(exact_root_first) - 1u});
    REQUIRE(exact_first_parsed);
    REQUIRE(exact_root_first_parsed);
    const auto exact_first_lowered = nginx::lower_to_rut(exact_first_parsed.value());
    const auto exact_root_first_lowered = nginx::lower_to_rut(exact_root_first_parsed.value());
    char wildcard_first[sizeof(kWildcardFirst)]{};
    char wildcard_root_first[sizeof(kWildcardRootFirst)]{};
    memcpy(wildcard_first, kWildcardFirst, sizeof(kWildcardFirst));
    memcpy(wildcard_root_first, kWildcardRootFirst, sizeof(kWildcardRootFirst));
    const auto wildcard_first_parsed = nginx::parse({wildcard_first, sizeof(wildcard_first) - 1u});
    const auto wildcard_root_first_parsed =
        nginx::parse({wildcard_root_first, sizeof(wildcard_root_first) - 1u});
    REQUIRE(wildcard_first_parsed);
    REQUIRE(wildcard_root_first_parsed);
    const auto wildcard_first_lowered = nginx::lower_to_rut(wildcard_first_parsed.value());
    const auto wildcard_root_first_lowered =
        nginx::lower_to_rut(wildcard_root_first_parsed.value());
    REQUIRE(exact_first_lowered);
    REQUIRE(exact_root_first_lowered);
    REQUIRE(wildcard_first_lowered);
    REQUIRE(wildcard_root_first_lowered);

    const std::string exact_first_source(exact_first_lowered.value().data,
                                         exact_first_lowered.value().len);
    const std::string exact_root_first_source(exact_root_first_lowered.value().data,
                                              exact_root_first_lowered.value().len);
    const std::string wildcard_first_source(wildcard_first_lowered.value().data,
                                            wildcard_first_lowered.value().len);
    const std::string wildcard_root_first_source(wildcard_root_first_lowered.value().data,
                                                 wildcard_root_first_lowered.value().len);
    REQUIRE_EQ(exact_first_source, exact_root_first_source);
    REQUIRE_EQ(wildcard_first_source, wildcard_root_first_source);
    std::string expected_exact = wildcard_first_source;
    REQUIRE_EQ(expected_exact.rfind("listen :8080\n", 0u), 0u);
    expected_exact.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(exact_first_source, expected_exact);

    // RutSource is an owned value: invalidating every nginx input after
    // lowering cannot alter the generated ordinary-RUT bytes.
    memset(exact_first, 'x', sizeof(exact_first) - 1u);
    memset(exact_root_first, 'y', sizeof(exact_root_first) - 1u);
    memset(wildcard_first, 'z', sizeof(wildcard_first) - 1u);
    memset(wildcard_root_first, 'w', sizeof(wildcard_root_first) - 1u);
    CHECK_EQ(std::string(exact_first_lowered.value().data, exact_first_lowered.value().len),
             expected_exact);
    CHECK_EQ(
        std::string(exact_root_first_lowered.value().data, exact_root_first_lowered.value().len),
        expected_exact);

    const auto listener_is_canonical = [](const std::string& candidate) {
        return candidate.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(candidate, "listen 127.0.0.1:8080\n") == 1u &&
               ((candidate.rfind("listen ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\nlisten ")) == 1u &&
               candidate.find("listen :") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& candidate) {
        return count_upstream_declarations(candidate) == 1u &&
               count_text(candidate, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto policies_are_canonical = [](const std::string& candidate) {
        const size_t pre_route = candidate.find("pre_route TRACE {");
        const size_t pre_route_end = candidate.find("}) }\n", pre_route);
        return pre_route != std::string::npos && pre_route_end != std::string::npos &&
               ((candidate.rfind("pre_route ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\npre_route ")) == 1u &&
               count_text(candidate, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(candidate.substr(pre_route, pre_route_end - pre_route), "status: 405") ==
                   1u &&
               count_text(candidate.substr(pre_route, pre_route_end - pre_route),
                          "reason: \"Not Allowed\"") == 1u &&
               count_text(candidate, "unmatched OPTIONS {") == 1u &&
               count_text(candidate, "unmatched CONNECT {") == 1u &&
               count_text(candidate, "\nunmatched { return local_response({\n") == 1u;
    };
    const auto routes_are_canonical = [](const std::string& candidate) {
        return count_route_declarations(candidate) == 4u &&
               count_text(candidate, "route HEAD \"/\" {") == 1u &&
               count_text(candidate, "route GET \"/\" {") == 1u &&
               count_text(candidate, "\nroute \"/\" {") == 1u &&
               count_text(candidate, kNoContentRoute) == 1u;
    };
    const auto has_no_nginx_hook_or_workaround = [](const std::string& candidate) {
        return candidate.find("nginx.conf") == std::string::npos &&
               candidate.find("nginx::") == std::string::npos &&
               candidate.find("nginx_compat") == std::string::npos &&
               candidate.find("workaround") == std::string::npos &&
               candidate.find("bind_address") == std::string::npos &&
               candidate.find("local_address") == std::string::npos &&
               candidate.find("req.listener") == std::string::npos;
    };
    const auto source_is_canonical = [&](const std::string& candidate) {
        return listener_is_canonical(candidate) && upstream_is_canonical(candidate) &&
               policies_are_canonical(candidate) && routes_are_canonical(candidate) &&
               has_no_nginx_hook_or_workaround(candidate);
    };
    REQUIRE(listener_is_canonical(expected_exact));
    REQUIRE(upstream_is_canonical(expected_exact));
    REQUIRE(policies_are_canonical(expected_exact));
    REQUIRE(routes_are_canonical(expected_exact));
    REQUIRE(has_no_nginx_hook_or_workaround(expected_exact));
    REQUIRE(source_is_canonical(expected_exact));

    std::string wrong_listener = expected_exact;
    REQUIRE_EQ(count_text(wrong_listener, "listen 127.0.0.1:8080\n"), 1u);
    wrong_listener.replace(0u, strlen("listen 127.0.0.1:8080"), "listen :8080");
    CHECK_NE(wrong_listener, expected_exact);
    CHECK_FALSE(listener_is_canonical(wrong_listener));
    CHECK(upstream_is_canonical(wrong_listener));
    CHECK(policies_are_canonical(wrong_listener));
    CHECK(routes_are_canonical(wrong_listener));
    CHECK_FALSE(source_is_canonical(wrong_listener));

    std::string wrong_upstream = expected_exact;
    static constexpr char kCanonicalUpstream[] = "upstream nginx_upstream at \"127.0.0.1:9000\"\n";
    static constexpr char kChangedUpstream[] = "upstream nginx_upstream at \"127.0.0.1:9001\"\n";
    REQUIRE_EQ(count_text(wrong_upstream, kCanonicalUpstream), 1u);
    REQUIRE_EQ(count_text(wrong_upstream, kChangedUpstream), 0u);
    const size_t upstream = wrong_upstream.find(kCanonicalUpstream);
    REQUIRE_NE(upstream, std::string::npos);
    wrong_upstream.replace(upstream, sizeof(kCanonicalUpstream) - 1u, kChangedUpstream);
    CHECK_NE(wrong_upstream, expected_exact);
    CHECK_EQ(count_text(wrong_upstream, kCanonicalUpstream), 0u);
    CHECK_EQ(count_text(wrong_upstream, kChangedUpstream), 1u);
    CHECK_EQ(count_upstream_declarations(wrong_upstream), 1u);
    CHECK(listener_is_canonical(wrong_upstream));
    CHECK_FALSE(upstream_is_canonical(wrong_upstream));
    CHECK(policies_are_canonical(wrong_upstream));
    CHECK(routes_are_canonical(wrong_upstream));
    CHECK_FALSE(source_is_canonical(wrong_upstream));

    std::string wrong_pre_route = expected_exact;
    const size_t pre_route = wrong_pre_route.find("pre_route TRACE {");
    const size_t pre_route_end = wrong_pre_route.find("}) }\n", pre_route);
    const size_t trace_status = wrong_pre_route.find("status: 405", pre_route);
    REQUIRE_NE(pre_route, std::string::npos);
    REQUIRE_NE(pre_route_end, std::string::npos);
    REQUIRE_NE(trace_status, std::string::npos);
    REQUIRE_LT(trace_status, pre_route_end);
    wrong_pre_route.replace(trace_status, strlen("status: 405"), "status: 400");
    CHECK_NE(wrong_pre_route, expected_exact);
    CHECK(listener_is_canonical(wrong_pre_route));
    CHECK(upstream_is_canonical(wrong_pre_route));
    CHECK_FALSE(policies_are_canonical(wrong_pre_route));
    CHECK(routes_are_canonical(wrong_pre_route));
    CHECK_FALSE(source_is_canonical(wrong_pre_route));

    std::string wrong_action = expected_exact;
    const size_t action = wrong_action.find(kNoContentRoute);
    REQUIRE_NE(action, std::string::npos);
    const size_t action_status = wrong_action.find("status: 204", action);
    REQUIRE_NE(action_status, std::string::npos);
    REQUIRE_LT(action_status, action + sizeof(kNoContentRoute) - 1u);
    wrong_action.replace(action_status, strlen("status: 204"), "status: 200");
    CHECK_NE(wrong_action, expected_exact);
    CHECK(listener_is_canonical(wrong_action));
    CHECK(upstream_is_canonical(wrong_action));
    CHECK(policies_are_canonical(wrong_action));
    CHECK_FALSE(routes_are_canonical(wrong_action));
    CHECK_FALSE(source_is_canonical(wrong_action));

    const auto lexed = lex({expected_exact.data(), static_cast<u32>(expected_exact.size())});
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->items.len, 10u);
    REQUIRE(ast_owned->items[0].kind == AstItemKind::Listen);
    CHECK(ast_owned->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast_owned->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
    REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
    CHECK_EQ(ast_owned->exact_strict_local_response_bindings[0].path_view,
             ExactPathView::SlashNormalized);
    const auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE(hir_owned->has_listener);
    CHECK(hir_owned->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir_owned->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir_owned->listener.port, 8080u);
    REQUIRE_EQ(hir_owned->routes.len, 3u);
    REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
}

TEST(nginx_converter, issue349_exact_loopback_bodyful_has_canonical_ordinary_rut_golden) {
    static constexpr char kBodyfulRoute[] =
        "route exact slash_normalized \"/static\" { return local_response({\n"
        "  version: \"HTTP/1.1\", status: 200, reason: \"OK\", server: \"nginx/1.29.7\",\n"
        "  date: \"current\", content_type: \"text/plain\", connection: \"request\",\n"
        "  head_mode: \"suppress_body\", body: b\"successor-static\"\n"
        "}) }\n";
    char exact_first[] =
        "server { listen 127.0.0.1:8080; "
        "location = /static { return 200 \"successor-static\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    char exact_root_first[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"successor-static\"; } }";
    char wildcard_first[] =
        "server { listen 8080; location = /static { return 200 \"successor-static\"; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    char wildcard_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /static { return 200 \"successor-static\"; } }";

    const auto exact_first_parsed = nginx::parse({exact_first, sizeof(exact_first) - 1u});
    const auto exact_root_first_parsed =
        nginx::parse({exact_root_first, sizeof(exact_root_first) - 1u});
    const auto wildcard_first_parsed = nginx::parse({wildcard_first, sizeof(wildcard_first) - 1u});
    const auto wildcard_root_first_parsed =
        nginx::parse({wildcard_root_first, sizeof(wildcard_root_first) - 1u});
    REQUIRE(exact_first_parsed);
    REQUIRE(exact_root_first_parsed);
    REQUIRE(wildcard_first_parsed);
    REQUIRE(wildcard_root_first_parsed);
    const auto exact_first_lowered = nginx::lower_to_rut(exact_first_parsed.value());
    const auto exact_root_first_lowered = nginx::lower_to_rut(exact_root_first_parsed.value());
    const auto wildcard_first_lowered = nginx::lower_to_rut(wildcard_first_parsed.value());
    const auto wildcard_root_first_lowered =
        nginx::lower_to_rut(wildcard_root_first_parsed.value());
    REQUIRE(exact_first_lowered);
    REQUIRE(exact_root_first_lowered);
    REQUIRE(wildcard_first_lowered);
    REQUIRE(wildcard_root_first_lowered);
    const std::string exact(exact_first_lowered.value().data, exact_first_lowered.value().len);
    const std::string exact_other(exact_root_first_lowered.value().data,
                                  exact_root_first_lowered.value().len);
    const std::string wildcard(wildcard_first_lowered.value().data,
                               wildcard_first_lowered.value().len);
    const std::string wildcard_other(wildcard_root_first_lowered.value().data,
                                     wildcard_root_first_lowered.value().len);
    REQUIRE_EQ(exact, exact_other);
    REQUIRE_EQ(wildcard, wildcard_other);
    std::string wildcard_with_exact_listener = wildcard;
    REQUIRE_EQ(wildcard_with_exact_listener.rfind("listen :8080\n", 0u), 0u);
    wildcard_with_exact_listener.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(exact, wildcard_with_exact_listener);

    memset(exact_first, 'x', sizeof(exact_first) - 1u);
    memset(exact_root_first, 'y', sizeof(exact_root_first) - 1u);
    memset(wildcard_first, 'z', sizeof(wildcard_first) - 1u);
    memset(wildcard_root_first, 'w', sizeof(wildcard_root_first) - 1u);
    CHECK_EQ(std::string(exact_first_lowered.value().data, exact_first_lowered.value().len), exact);
    CHECK_EQ(
        std::string(exact_root_first_lowered.value().data, exact_root_first_lowered.value().len),
        exact);

    const auto listener_is_canonical = [](const std::string& candidate) {
        return candidate.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(candidate, "listen 127.0.0.1:8080\n") == 1u &&
               ((candidate.rfind("listen ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\nlisten ")) == 1u &&
               candidate.find("listen :") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& candidate) {
        return count_upstream_declarations(candidate) == 1u &&
               count_text(candidate, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_is_canonical = [](const std::string& candidate) {
        const size_t begin = candidate.find("pre_route TRACE {");
        const size_t end = candidate.find("}) }\n", begin);
        return begin != std::string::npos && end != std::string::npos &&
               ((candidate.rfind("pre_route ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\npre_route ")) == 1u &&
               count_text(candidate, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(candidate.substr(begin, end - begin), "status: 405") == 1u &&
               count_text(candidate.substr(begin, end - begin), "reason: \"Not Allowed\"") == 1u &&
               count_text(candidate, "unmatched OPTIONS {") == 1u &&
               count_text(candidate, "unmatched CONNECT {") == 1u &&
               count_text(candidate, "\nunmatched { return local_response({\n") == 1u;
    };
    const auto exact_action_is_canonical = [](const std::string& candidate) {
        return count_text(candidate, kBodyfulRoute) == 1u &&
               count_text(candidate, "route exact slash_normalized ") == 1u &&
               count_text(candidate, "status: 200, reason: \"OK\"") == 1u &&
               count_text(candidate, "body: b\"successor-static\"") == 1u;
    };
    const auto root_routes_are_canonical = [](const std::string& candidate) {
        return count_route_declarations(candidate) == 4u &&
               count_text(candidate, "route HEAD \"/\" {") == 1u &&
               count_text(candidate, "route GET \"/\" {") == 1u &&
               count_text(candidate, "\nroute \"/\" {") == 1u &&
               count_text(candidate, "return forward(nginx_upstream, request_policy: {") == 3u &&
               count_text(candidate, "        response_policy: {") == 3u &&
               count_text(candidate, "        failure_policy: {") == 3u &&
               count_text(candidate, "        timeout_failure_policy: {") == 1u &&
               count_text(candidate, "        response_read_timeout: 60s,") == 1u &&
               count_text(candidate, "        response_buffering: \"complete_content_length\"") ==
                   1u;
    };
    const auto has_no_nginx_hook = [](const std::string& candidate) {
        return candidate.find("nginx.conf") == std::string::npos &&
               candidate.find("nginx::") == std::string::npos &&
               candidate.find("nginx_compat") == std::string::npos &&
               candidate.find("workaround") == std::string::npos &&
               candidate.find("bind_address") == std::string::npos &&
               candidate.find("req.listener") == std::string::npos;
    };
    const auto source_is_canonical = [&](const std::string& candidate) {
        return listener_is_canonical(candidate) && upstream_is_canonical(candidate) &&
               pre_route_is_canonical(candidate) && exact_action_is_canonical(candidate) &&
               root_routes_are_canonical(candidate) && has_no_nginx_hook(candidate);
    };
    REQUIRE(source_is_canonical(exact));

    const auto replace_unique = [&](std::string source, Str before, Str after) {
        const std::string needle(before.ptr, before.len);
        const size_t offset = source.find(needle);
        if (offset == std::string::npos ||
            source.find(needle, offset + needle.size()) != std::string::npos) {
            CHECK(false);
            return std::string{};
        }
        source.replace(offset, needle.size(), after.ptr, after.len);
        return source;
    };
    const auto check_isolated = [&](const std::string& candidate,
                                    bool listener_ok,
                                    bool upstream_ok,
                                    bool pre_route_ok,
                                    bool exact_ok,
                                    bool root_ok) {
        CHECK_NE(candidate, exact);
        CHECK_EQ(listener_is_canonical(candidate), listener_ok);
        CHECK_EQ(upstream_is_canonical(candidate), upstream_ok);
        CHECK_EQ(pre_route_is_canonical(candidate), pre_route_ok);
        CHECK_EQ(exact_action_is_canonical(candidate), exact_ok);
        CHECK_EQ(root_routes_are_canonical(candidate), root_ok);
        CHECK(has_no_nginx_hook(candidate));
        CHECK_FALSE(source_is_canonical(candidate));
    };
    check_isolated(
        replace_unique(exact, lit_str("listen 127.0.0.1:8080\n"), lit_str("listen :8080\n")),
        false,
        true,
        true,
        true,
        true);
    check_isolated(replace_unique(exact, lit_str("127.0.0.1:9000"), lit_str("127.0.0.1:9001")),
                   true,
                   false,
                   true,
                   true,
                   true);
    check_isolated(replace_unique(exact,
                                  lit_str("pre_route TRACE { return local_response({\n"
                                          "  version: \"HTTP/1.1\", status: 405"),
                                  lit_str("pre_route TRACE { return local_response({\n"
                                          "  version: \"HTTP/1.1\", status: 404")),
                   true,
                   true,
                   false,
                   true,
                   true);
    check_isolated(replace_unique(exact, lit_str("\"/static\""), lit_str("\"/statix\"")),
                   true,
                   true,
                   true,
                   false,
                   true);
    check_isolated(
        replace_unique(
            exact, lit_str("status: 200, reason: \"OK\""), lit_str("status: 201, reason: \"OK\"")),
        true,
        true,
        true,
        false,
        true);
    check_isolated(
        replace_unique(
            exact, lit_str("body: b\"successor-static\""), lit_str("body: b\"successor-statiX\"")),
        true,
        true,
        true,
        false,
        true);
    check_isolated(
        replace_unique(
            exact,
            lit_str("route exact slash_normalized \"/static\" { return local_response({"),
            lit_str("route exact slash_normalized \"/static\" { return local_responsX({")),
        true,
        true,
        true,
        false,
        true);
    check_isolated(replace_unique(exact, lit_str("route GET \"/\""), lit_str("route POST \"/\"")),
                   true,
                   true,
                   true,
                   true,
                   false);

    const std::string harmless_difference = exact + "// canonical equality witness\n";
    REQUIRE_NE(harmless_difference, exact);
    REQUIRE(source_is_canonical(harmless_difference));
    const auto harmless_lexed =
        lex({harmless_difference.data(), static_cast<u32>(harmless_difference.size())});
    REQUIRE(harmless_lexed);
    const auto harmless_ast = parse_file(harmless_lexed.value());
    REQUIRE(harmless_ast);
    delete harmless_ast.value();

    const std::string hook_comment = exact + "// nginx_compat workaround marker\n";
    REQUIRE_NE(hook_comment, exact);
    CHECK(listener_is_canonical(hook_comment));
    CHECK(upstream_is_canonical(hook_comment));
    CHECK(pre_route_is_canonical(hook_comment));
    CHECK(exact_action_is_canonical(hook_comment));
    CHECK(root_routes_are_canonical(hook_comment));
    CHECK_FALSE(has_no_nginx_hook(hook_comment));
    CHECK_FALSE(source_is_canonical(hook_comment));
    const auto hook_lexed = lex({hook_comment.data(), static_cast<u32>(hook_comment.size())});
    REQUIRE(hook_lexed);
    const auto hook_ast = parse_file(hook_lexed.value());
    REQUIRE(hook_ast);
    delete hook_ast.value();

    const auto lexed = lex({exact.data(), static_cast<u32>(exact.size())});
    REQUIRE(lexed);
    const auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    REQUIRE_EQ(ast_owned->items.len, 10u);
    REQUIRE(ast_owned->items[0].kind == AstItemKind::Listen);
    CHECK(ast_owned->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast_owned->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
    REQUIRE_EQ(ast_owned->exact_strict_local_response_bindings.len, 1u);
    const auto& ast_binding = ast_owned->exact_strict_local_response_bindings[0];
    CHECK_EQ(ast_binding.method, kRouteMethodAny);
    CHECK_EQ(ast_binding.path_view, ExactPathView::SlashNormalized);
    CHECK((Str{ast_binding.path, ast_binding.path_len}.eq(lit_str("/static"))));
    REQUIRE_EQ(ast_owned->strict_local_response_policies.len, 5u);
    REQUIRE_NE(ast_binding.policy_id, 0u);
    REQUIRE_LE(ast_binding.policy_id, ast_owned->strict_local_response_policies.len);
    const auto& ast_policy = ast_owned->strict_local_response_policies[ast_binding.policy_id - 1u];
    CHECK_EQ(strict_local_response_profile(ast_policy.status_code),
             StrictLocalResponseProfile::Representation200);
    CHECK(ast_policy.reason.eq(lit_str("OK")));
    CHECK(ast_policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(ast_policy.content_type.eq(lit_str("text/plain")));
    CHECK(ast_policy.head_mode == StrictLocalResponseHeadMode::SuppressBody);
    CHECK(ast_policy.body.eq(lit_str("successor-static")));
    const auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    REQUIRE(hir_owned->has_listener);
    CHECK(hir_owned->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir_owned->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir_owned->listener.port, 8080u);
    REQUIRE_EQ(hir_owned->routes.len, 3u);
    REQUIRE_EQ(hir_owned->exact_strict_local_response_bindings.len, 1u);
    REQUIRE_EQ(hir_owned->strict_local_response_policies.len, 5u);
    const auto& hir_binding = hir_owned->exact_strict_local_response_bindings[0];
    CHECK_EQ(hir_binding.method, kRouteMethodAny);
    CHECK_EQ(hir_binding.path_view, ExactPathView::SlashNormalized);
    CHECK((Str{hir_binding.path, hir_binding.path_len}.eq(lit_str("/static"))));
    REQUIRE_NE(hir_binding.policy_id, 0u);
    REQUIRE_LE(hir_binding.policy_id, hir_owned->strict_local_response_policies.len);
    const auto& hir_policy = hir_owned->strict_local_response_policies[hir_binding.policy_id - 1u];
    CHECK_EQ(strict_local_response_profile(hir_policy.status_code),
             StrictLocalResponseProfile::Representation200);
    CHECK_EQ(hir_policy.status_code, 200u);
    CHECK(hir_policy.reason.eq(lit_str("OK")));
    CHECK(hir_policy.server.eq(lit_str("nginx/1.29.7")));
    CHECK(hir_policy.content_type.eq(lit_str("text/plain")));
    CHECK(hir_policy.head_mode == StrictLocalResponseHeadMode::SuppressBody);
    CHECK(hir_policy.body.eq(lit_str("successor-static")));
}

TEST(nginx_converter, issue350_exact_loopback_302_has_canonical_ordinary_rut_golden) {
    static constexpr char kRedirectBody[] =
        "<html>\r\n"
        "<head><title>302 Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>302 Found</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kRedirectBody) - 1u == 145u);
    static constexpr char kRedirectPrefix[] =
        "route GET \"/\" {\n"
        "    if req.pathOnly == \"/old\" {\n"
        "        return redirect({scheme: \"http\", authority: \"static\", static_authority: "
        "\"redirect.example\", port: \"omit\",\n"
        "            path: \"static\", query: \"discard\", date: \"current\", connection: "
        "\"close\",\n"
        "            header_order: \"connection_then_location\", status: 302, reason: \"Moved "
        "Temporarily\",\n"
        "            server: \"nginx/1.29.7\", content_type: \"text/html\", target_path: "
        "\"/new\", body: b\"<html>\\r\\n"
        "<head><title>302 Found</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>302 Found</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n\"})\n"
        "    } else {\n"
        "        return ";
    char exact_first[] =
        "server { listen 127.0.0.1:8080; "
        "location = /old { return 302 http://redirect.example/new; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    char root_first[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 302 http://redirect.example/new; } }";
    char wildcard_first[] =
        "server { listen 8080; location = /old { return 302 http://redirect.example/new; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    char wildcard_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 302 http://redirect.example/new; } }";

    const auto lower = [](char* source, u32 len) -> FrontendResult<nginx::RutSource> {
        const auto parsed = nginx::parse({source, len});
        if (!parsed) return core::make_unexpected(parsed.error());
        return nginx::lower_to_rut(parsed.value());
    };
    const auto exact_a = lower(exact_first, sizeof(exact_first) - 1u);
    const auto exact_b = lower(root_first, sizeof(root_first) - 1u);
    const auto wildcard_a = lower(wildcard_first, sizeof(wildcard_first) - 1u);
    const auto wildcard_b = lower(wildcard_root_first, sizeof(wildcard_root_first) - 1u);
    REQUIRE(exact_a);
    REQUIRE(exact_b);
    REQUIRE(wildcard_a);
    REQUIRE(wildcard_b);
    CHECK_EQ(exact_a.value().len, 5913u);
    CHECK_EQ(exact_b.value().len, 5913u);
    CHECK_EQ(wildcard_a.value().len, 5904u);
    CHECK_EQ(wildcard_b.value().len, 5904u);
    const std::string exact(exact_a.value().data, exact_a.value().len);
    const std::string exact_other(exact_b.value().data, exact_b.value().len);
    const std::string wildcard(wildcard_a.value().data, wildcard_a.value().len);
    const std::string wildcard_other(wildcard_b.value().data, wildcard_b.value().len);
    REQUIRE_EQ(exact, exact_other);
    REQUIRE_EQ(wildcard, wildcard_other);
    std::string wildcard_as_exact = wildcard;
    REQUIRE_EQ(wildcard_as_exact.rfind("listen :8080\n", 0u), 0u);
    wildcard_as_exact.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(wildcard_as_exact, exact);

    memset(exact_first, 'x', sizeof(exact_first) - 1u);
    memset(root_first, 'y', sizeof(root_first) - 1u);
    memset(wildcard_first, 'z', sizeof(wildcard_first) - 1u);
    memset(wildcard_root_first, 'w', sizeof(wildcard_root_first) - 1u);
    CHECK_EQ(std::string(exact_a.value().data, exact_a.value().len), exact);
    CHECK_EQ(std::string(exact_b.value().data, exact_b.value().len), exact);

    static constexpr char kMaximumExact[] =
        "server { listen 127.0.0.1:65535; location / { proxy_pass "
        "http://255.255.255.255:65535; } location = /old { return 302 "
        "http://redirect.example/new; } }";
    static constexpr char kMaximumWildcard[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } "
        "location = /old { return 302 http://redirect.example/new; } }";
    const auto maximum_exact_parsed = nginx::parse({kMaximumExact, sizeof(kMaximumExact) - 1u});
    const auto maximum_wildcard_parsed =
        nginx::parse({kMaximumWildcard, sizeof(kMaximumWildcard) - 1u});
    REQUIRE(maximum_exact_parsed);
    REQUIRE(maximum_wildcard_parsed);
    const auto maximum_exact = nginx::lower_to_rut(maximum_exact_parsed.value());
    const auto maximum_wildcard = nginx::lower_to_rut(maximum_wildcard_parsed.value());
    REQUIRE(maximum_exact);
    REQUIRE(maximum_wildcard);
    CHECK_EQ(maximum_exact.value().len, 5921u);
    CHECK_EQ(maximum_wildcard.value().len, 5912u);
    CHECK_LT(maximum_exact.value().len, nginx::RutSource::kCapacity);
    CHECK_EQ(nginx::RutSource::kCapacity - maximum_exact.value().len, 25u);
    std::string maximum_wildcard_as_exact(maximum_wildcard.value().data,
                                          maximum_wildcard.value().len);
    maximum_wildcard_as_exact.replace(0u, strlen("listen :65535"), "listen 127.0.0.1:65535");
    CHECK_EQ(maximum_wildcard_as_exact,
             std::string(maximum_exact.value().data, maximum_exact.value().len));

    const auto listener_is_canonical = [](const std::string& candidate) {
        return candidate.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(candidate, "listen 127.0.0.1:8080\n") == 1u &&
               ((candidate.rfind("listen ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\nlisten ")) == 1u &&
               candidate.find("listen :") == std::string::npos &&
               candidate.find("127.0.0.2") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& candidate) {
        return count_upstream_declarations(candidate) == 1u &&
               count_text(candidate, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_is_canonical = [](const std::string& candidate) {
        const size_t begin = candidate.find("pre_route TRACE {");
        const size_t end = candidate.find("}) }\n", begin);
        return begin != std::string::npos && end != std::string::npos &&
               ((candidate.rfind("pre_route ", 0u) == 0u ? 1u : 0u) +
                count_text(candidate, "\npre_route ")) == 1u &&
               count_text(candidate, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(candidate.substr(begin, end - begin), "status: 405") == 1u &&
               count_text(candidate.substr(begin, end - begin), "reason: \"Not Allowed\"") == 1u;
    };
    const auto redirect_is_canonical = [](const std::string& candidate) {
        return count_text(candidate, kRedirectPrefix) == 1u &&
               count_text(candidate, "if req.pathOnly == \"/old\"") == 1u &&
               count_text(candidate, "return redirect({") == 1u &&
               count_text(candidate, "query: \"discard\"") == 1u &&
               count_text(candidate, "status: 302, reason: \"Moved Temporarily\"") == 1u &&
               count_text(candidate, "static_authority: \"redirect.example\"") == 1u &&
               count_text(candidate, "target_path: \"/new\"") == 1u;
    };
    const auto root_is_canonical = [](const std::string& candidate) {
        return count_route_declarations(candidate) == 3u &&
               count_text(candidate, "route HEAD \"/\" {") == 1u &&
               count_text(candidate, "route GET \"/\" {") == 1u &&
               count_text(candidate, "\nroute \"/\" {") == 1u &&
               count_text(candidate, "return forward(nginx_upstream, request_policy: {") == 3u &&
               count_text(candidate, "    } else {\n        return forward(") == 1u;
    };
    const auto has_no_nginx_hook = [](const std::string& candidate) {
        return candidate.find("nginx.conf") == std::string::npos &&
               candidate.find("nginx::") == std::string::npos &&
               candidate.find("nginx_compat") == std::string::npos &&
               candidate.find("workaround") == std::string::npos &&
               candidate.find("bind_address") == std::string::npos;
    };
    const auto source_is_canonical = [&](const std::string& candidate) {
        return listener_is_canonical(candidate) && upstream_is_canonical(candidate) &&
               pre_route_is_canonical(candidate) && redirect_is_canonical(candidate) &&
               root_is_canonical(candidate) && has_no_nginx_hook(candidate);
    };
    CHECK(listener_is_canonical(exact));
    CHECK(upstream_is_canonical(exact));
    CHECK(pre_route_is_canonical(exact));
    CHECK_EQ(count_text(exact, kRedirectPrefix), 1u);
    CHECK_EQ(count_text(exact, "if req.pathOnly == \"/old\""), 1u);
    CHECK_EQ(count_text(exact, "return redirect({"), 1u);
    CHECK_EQ(count_text(exact, "query: \"discard\""), 1u);
    CHECK_EQ(count_text(exact, "status: 302, reason: \"Moved Temporarily\""), 1u);
    CHECK_EQ(count_text(exact, "static_authority: \"redirect.example\""), 1u);
    CHECK_EQ(count_text(exact, "target_path: \"/new\""), 1u);
    CHECK(redirect_is_canonical(exact));
    CHECK(root_is_canonical(exact));
    CHECK(has_no_nginx_hook(exact));
    REQUIRE(source_is_canonical(exact));

    const auto replace_unique = [&](std::string candidate, Str from, Str to) {
        const std::string needle(from.ptr, from.len);
        const size_t offset = candidate.find(needle);
        if (needle.empty() || from.eq(to) || offset == std::string::npos ||
            candidate.find(needle, offset + needle.size()) != std::string::npos) {
            CHECK(false);
            return std::string{};
        }
        candidate.replace(offset, needle.size(), to.ptr, to.len);
        CHECK_NE(candidate, exact);
        return candidate;
    };
    const auto check_isolated = [&](const std::string& candidate,
                                    bool listener_ok,
                                    bool upstream_ok,
                                    bool redirect_ok,
                                    bool root_ok) {
        REQUIRE_FALSE(candidate.empty());
        CHECK_EQ(listener_is_canonical(candidate), listener_ok);
        CHECK_EQ(upstream_is_canonical(candidate), upstream_ok);
        CHECK(pre_route_is_canonical(candidate));
        CHECK_EQ(redirect_is_canonical(candidate), redirect_ok);
        CHECK_EQ(root_is_canonical(candidate), root_ok);
        CHECK(has_no_nginx_hook(candidate));
        CHECK_FALSE(source_is_canonical(candidate));
    };
    check_isolated(
        replace_unique(
            exact, lit_str("listen 127.0.0.1:8080\n"), lit_str("listen 127.0.0.2:8080\n")),
        false,
        true,
        true,
        true);
    check_isolated(replace_unique(exact, lit_str("127.0.0.1:9000"), lit_str("127.0.0.1:9001")),
                   true,
                   false,
                   true,
                   true);
    check_isolated(
        replace_unique(exact, lit_str("return redirect({"), lit_str("return redirecX({")),
        true,
        true,
        false,
        true);
    check_isolated(replace_unique(exact,
                                  lit_str("status: 302, reason: \"Moved Temporarily\""),
                                  lit_str("status: 301, reason: \"Moved Temporarily\"")),
                   true,
                   true,
                   false,
                   true);
    check_isolated(replace_unique(exact,
                                  lit_str("static_authority: \"redirect.example\""),
                                  lit_str("static_authority: \"redirect.invalid\"")),
                   true,
                   true,
                   false,
                   true);
    check_isolated(
        replace_unique(exact, lit_str("target_path: \"/new\""), lit_str("target_path: \"/old\"")),
        true,
        true,
        false,
        true);
    check_isolated(
        replace_unique(exact, lit_str("query: \"discard\""), lit_str("query: \"preserve_raw\"")),
        true,
        true,
        false,
        true);
    check_isolated(replace_unique(exact,
                                  lit_str("    } else {\n        return forward("),
                                  lit_str("    } else {\n        return forwarX(")),
                   true,
                   true,
                   true,
                   false);

    const std::string hook = exact + "// nginx_compat workaround marker\n";
    REQUIRE_NE(hook, exact);
    CHECK(listener_is_canonical(hook));
    CHECK(upstream_is_canonical(hook));
    CHECK(pre_route_is_canonical(hook));
    CHECK(redirect_is_canonical(hook));
    CHECK(root_is_canonical(hook));
    CHECK_FALSE(has_no_nginx_hook(hook));
    CHECK_FALSE(source_is_canonical(hook));
    const auto hook_lexed = lex({hook.data(), static_cast<u32>(hook.size())});
    REQUIRE(hook_lexed);
    const auto hook_ast = parse_file(hook_lexed.value());
    REQUIRE(hook_ast);
    delete hook_ast.value();

    const std::string harmless = exact + "// canonical byte equality witness\n";
    REQUIRE_NE(harmless, exact);
    REQUIRE(source_is_canonical(harmless));
    const auto harmless_lexed = lex({harmless.data(), static_cast<u32>(harmless.size())});
    REQUIRE(harmless_lexed);
    const auto harmless_ast = parse_file(harmless_lexed.value());
    REQUIRE(harmless_ast);
    delete harmless_ast.value();

    const auto lexed = lex({exact.data(), static_cast<u32>(exact.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast->items[0].listen.port, 8080u);
    REQUIRE_EQ(ast->redirect_policies.len, 1u);
    const AstRouteDecl* ast_get = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++) {
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.method == static_cast<u8>(TokenType::KwGet) &&
            ast->items[i].route.path.eq(lit_str("/")))
            ast_get = &ast->items[i].route;
    }
    REQUIRE(ast_get != nullptr);
    REQUIRE_EQ(ast_get->statements.len, 1u);
    REQUIRE(ast_get->statements[0] != nullptr);
    const AstStatement& ast_if = *ast_get->statements[0];
    REQUIRE(ast_if.kind == AstStmtKind::If);
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.else_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE(ast_if.then_stmt->has_redirect_policy);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    REQUIRE(ast_if.else_stmt->kind == AstStmtKind::ForwardUpstream);
    const auto& ast_policy = ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u];
    CHECK_EQ(ast_policy.status_code, 302u);
    CHECK(ast_policy.reason.eq(lit_str("Moved Temporarily")));
    CHECK(ast_policy.static_authority.eq(lit_str("redirect.example")));
    CHECK(ast_policy.target_path.eq(lit_str("/new")));
    CHECK(ast_policy.query == RedirectPolicyQuery::Discard);
    CHECK(ast_policy.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
    CHECK(ast_policy.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u}));

    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir->listener.port, 8080u);
    REQUIRE_EQ(hir->routes.len, 3u);
    const HirRoute* hir_get = nullptr;
    for (u32 i = 0u; i < hir->routes.len; i++) {
        if (hir->routes[i].method == kRouteMethodGet && hir->routes[i].path.eq(lit_str("/")))
            hir_get = &hir->routes[i];
    }
    REQUIRE(hir_get != nullptr);
    REQUIRE(hir_get->control.kind == HirControlKind::If);
    REQUIRE(hir_get->control.cond.kind == HirExprKind::Eq);
    REQUIRE(hir_get->control.cond.rhs != nullptr);
    CHECK(hir_get->control.cond.rhs->kind == HirExprKind::StrLit);
    CHECK(hir_get->control.cond.rhs->str_value.eq(lit_str("/old")));
    REQUIRE(hir_get->control.then_term.kind == HirTerminatorKind::Redirect);
    const u16 hir_policy_id = hir_get->control.then_term.redirect_policy_id;
    REQUIRE_NE(hir_policy_id, 0u);
    REQUIRE_LE(hir_policy_id, hir->redirect_policies.len);
    REQUIRE(hir_get->control.else_term.kind == HirTerminatorKind::ForwardUpstream);
    const auto& hir_policy = hir->redirect_policies[hir_policy_id - 1u];
    CHECK_EQ(hir_policy.status_code, 302u);
    CHECK(hir_policy.reason.eq(lit_str("Moved Temporarily")));
    CHECK(hir_policy.static_authority.eq(lit_str("redirect.example")));
    CHECK(hir_policy.target_path.eq(lit_str("/new")));
    CHECK(hir_policy.query == RedirectPolicyQuery::Discard);
    CHECK(hir_policy.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u}));
}

TEST(nginx_converter, issue351_exact_loopback_301_has_canonical_ordinary_rut_golden) {
    static constexpr char kRedirectBody[] =
        "<html>\r\n"
        "<head><title>301 Moved Permanently</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>301 Moved Permanently</h1></center>\r\n"
        "<hr><center>nginx/1.29.7</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    static_assert(sizeof(kRedirectBody) - 1u == 169u);
    static constexpr char kRedirectPrefix[] =
        "route GET \"/\" {\n"
        "    if req.pathOnly == \"/old\" {\n"
        "        return redirect({scheme: \"http\", authority: \"static\", static_authority: "
        "\"redirect.example\", port: \"omit\",\n"
        "            path: \"static\", query: \"discard\", date: \"current\", connection: "
        "\"close\",\n"
        "            header_order: \"connection_then_location\", status: 301, reason: \"Moved "
        "Permanently\",\n"
        "            server: \"nginx/1.29.7\", content_type: \"text/html\", target_path: "
        "\"/new\", body: b\"<html>\\r\\n"
        "<head><title>301 Moved Permanently</title></head>\\r\\n"
        "<body>\\r\\n"
        "<center><h1>301 Moved Permanently</h1></center>\\r\\n"
        "<hr><center>nginx/1.29.7</center>\\r\\n"
        "</body>\\r\\n"
        "</html>\\r\\n\"})\n"
        "    } else {\n"
        "        return ";
    char exact_first[] =
        "server { listen 127.0.0.1:8080; "
        "location = /old { return 301 http://redirect.example/new; } "
        "location / { proxy_pass http://127.0.0.1:9000; } }";
    char root_first[] =
        "server { listen 127.0.0.1:8080; "
        "location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    char wildcard_first[] =
        "server { listen 8080; location = /old { return 301 "
        "http://redirect.example/new; } location / { proxy_pass http://127.0.0.1:9000; } }";
    char wildcard_root_first[] =
        "server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    const auto lower = [](char* source, u32 len) -> FrontendResult<nginx::RutSource> {
        const auto parsed = nginx::parse({source, len});
        if (!parsed) return core::make_unexpected(parsed.error());
        return nginx::lower_to_rut(parsed.value());
    };
    const auto exact_a = lower(exact_first, sizeof(exact_first) - 1u);
    const auto exact_b = lower(root_first, sizeof(root_first) - 1u);
    const auto wildcard_a = lower(wildcard_first, sizeof(wildcard_first) - 1u);
    const auto wildcard_b = lower(wildcard_root_first, sizeof(wildcard_root_first) - 1u);
    REQUIRE(exact_a);
    REQUIRE(exact_b);
    REQUIRE(wildcard_a);
    REQUIRE(wildcard_b);
    CHECK_EQ(exact_a.value().len, 5937u);
    CHECK_EQ(exact_b.value().len, 5937u);
    CHECK_EQ(wildcard_a.value().len, 5928u);
    CHECK_EQ(wildcard_b.value().len, 5928u);
    CHECK_EQ(exact_a.value().data[exact_a.value().len], '\0');
    const std::string exact(exact_a.value().data, exact_a.value().len);
    const std::string exact_other(exact_b.value().data, exact_b.value().len);
    const std::string wildcard(wildcard_a.value().data, wildcard_a.value().len);
    const std::string wildcard_other(wildcard_b.value().data, wildcard_b.value().len);
    REQUIRE_EQ(exact, exact_other);
    REQUIRE_EQ(wildcard, wildcard_other);
    std::string wildcard_as_exact = wildcard;
    REQUIRE_EQ(wildcard_as_exact.rfind("listen :8080\n", 0u), 0u);
    wildcard_as_exact.replace(0u, strlen("listen :8080"), "listen 127.0.0.1:8080");
    REQUIRE_EQ(wildcard_as_exact, exact);

    memset(exact_first, 'x', sizeof(exact_first) - 1u);
    memset(root_first, 'y', sizeof(root_first) - 1u);
    memset(wildcard_first, 'z', sizeof(wildcard_first) - 1u);
    memset(wildcard_root_first, 'w', sizeof(wildcard_root_first) - 1u);
    CHECK_EQ(std::string(exact_a.value().data, exact_a.value().len), exact);
    CHECK_EQ(std::string(exact_b.value().data, exact_b.value().len), exact);

    static constexpr char kMaximumExact[] =
        "server { listen 127.0.0.1:65535; location / { proxy_pass "
        "http://255.255.255.255:65535; } location = /old { return 301 "
        "http://redirect.example/new; } }";
    static constexpr char kMaximumWildcard[] =
        "server { listen 65535; location / { proxy_pass http://255.255.255.255:65535; } "
        "location = /old { return 301 http://redirect.example/new; } }";
    const auto maximum_exact_parsed = nginx::parse({kMaximumExact, sizeof(kMaximumExact) - 1u});
    const auto maximum_wildcard_parsed =
        nginx::parse({kMaximumWildcard, sizeof(kMaximumWildcard) - 1u});
    REQUIRE(maximum_exact_parsed);
    REQUIRE(maximum_wildcard_parsed);
    const auto maximum_exact = nginx::lower_to_rut(maximum_exact_parsed.value());
    const auto maximum_wildcard = nginx::lower_to_rut(maximum_wildcard_parsed.value());
    REQUIRE(maximum_exact);
    REQUIRE(maximum_wildcard);
    CHECK_EQ(maximum_exact.value().len, 5945u);
    CHECK_EQ(maximum_wildcard.value().len, 5936u);
    CHECK_EQ(maximum_exact.value().len + 1u, nginx::RutSource::kCapacity);
    CHECK_EQ(maximum_exact.value().data[maximum_exact.value().len], '\0');
    std::string maximum_wildcard_as_exact(maximum_wildcard.value().data,
                                          maximum_wildcard.value().len);
    maximum_wildcard_as_exact.replace(0u, strlen("listen :65535"), "listen 127.0.0.1:65535");
    REQUIRE_EQ(maximum_wildcard_as_exact,
               std::string(maximum_exact.value().data, maximum_exact.value().len));

    const auto listener_is_canonical = [](const std::string& source) {
        return source.rfind("listen 127.0.0.1:8080\n", 0u) == 0u &&
               count_text(source, "listen 127.0.0.1:8080\n") == 1u &&
               source.find("listen :") == std::string::npos;
    };
    const auto upstream_is_canonical = [](const std::string& source) {
        return count_upstream_declarations(source) == 1u &&
               count_text(source, "upstream nginx_upstream at \"127.0.0.1:9000\"\n") == 1u;
    };
    const auto pre_route_is_canonical = [](const std::string& source) {
        return count_text(source, "pre_route TRACE { return local_response({\n") == 1u &&
               count_text(source, "status: 405, reason: \"Not Allowed\"") == 2u;
    };
    const auto redirect_is_canonical = [&](const std::string& source) {
        return count_text(source, kRedirectPrefix) == 1u &&
               count_text(source, "if req.pathOnly == \"/old\"") == 1u &&
               count_text(source, "return redirect({") == 1u &&
               count_text(source, "query: \"discard\"") == 1u &&
               count_text(source, "status: 301, reason: \"Moved Permanently\"") == 1u &&
               count_text(source, "static_authority: \"redirect.example\"") == 1u &&
               count_text(source, "target_path: \"/new\"") == 1u;
    };
    const auto root_is_canonical = [](const std::string& source) {
        return count_route_declarations(source) == 3u &&
               count_text(source, "route HEAD \"/\" {") == 1u &&
               count_text(source, "route GET \"/\" {") == 1u &&
               count_text(source, "\nroute \"/\" {") == 1u &&
               count_text(source, "return forward(nginx_upstream, request_policy: {") == 3u &&
               count_text(source, "    } else {\n        return forward(") == 1u;
    };
    const auto has_no_nginx_hook = [](const std::string& source) {
        for (const char* marker : {"nginx.conf",
                                   "nginx::",
                                   "nginx_compat",
                                   "workaround",
                                   "bind_address",
                                   "local_address",
                                   "req.listener",
                                   "address_condition"})
            if (source.find(marker) != std::string::npos) return false;
        return true;
    };
    const auto source_is_canonical = [&](const std::string& source) {
        return listener_is_canonical(source) && upstream_is_canonical(source) &&
               pre_route_is_canonical(source) && redirect_is_canonical(source) &&
               root_is_canonical(source) && has_no_nginx_hook(source);
    };
    REQUIRE(source_is_canonical(exact));
    const auto replace_unique =
        [&](std::string source, const std::string& from, const std::string& to) -> std::string {
        const size_t offset = from.empty() ? std::string::npos : source.find(from);
        if (from.empty() || from == to || offset == std::string::npos ||
            source.find(from, offset + from.size()) != std::string::npos) {
            CHECK(false);
            return {};
        }
        source.replace(offset, from.size(), to);
        CHECK_NE(source, exact);
        return source;
    };
    const auto rejects_structure = [&](const std::string& candidate) {
        REQUIRE_FALSE(candidate.empty());
        CHECK_FALSE(source_is_canonical(candidate));
    };
    rejects_structure(replace_unique(exact, "listen 127.0.0.1:8080\n", "listen 127.0.0.2:8080\n"));
    rejects_structure(replace_unique(exact, "127.0.0.1:9000", "127.0.0.1:9001"));
    rejects_structure(replace_unique(exact, "pre_route TRACE {", "pre_route TRACX {"));
    rejects_structure(replace_unique(exact, "return redirect({", "return redirecX({"));
    rejects_structure(replace_unique(exact,
                                     "status: 301, reason: \"Moved Permanently\"",
                                     "status: 302, reason: \"Moved Permanently\""));
    rejects_structure(replace_unique(
        exact, "static_authority: \"redirect.example\"", "static_authority: \"other.example\""));
    rejects_structure(replace_unique(exact, "query: \"discard\"", "query: \"preserve_raw\""));
    rejects_structure(replace_unique(exact,
                                     "header_order: \"connection_then_location\"",
                                     "header_order: \"location_then_connection\""));
    rejects_structure(replace_unique(exact, "target_path: \"/new\"", "target_path: \"/old\""));
    rejects_structure(
        replace_unique(exact, "<h1>301 Moved Permanently</h1>", "<h1>301 Moved Permanentlx</h1>"));
    rejects_structure(replace_unique(
        exact, "    } else {\n        return forward(", "    } else {\n        return forwarX("));
    for (const char* marker : {"nginx.conf",
                               "nginx::",
                               "nginx_compat",
                               "workaround",
                               "bind_address",
                               "local_address",
                               "req.listener",
                               "address_condition"}) {
        const std::string candidate = exact + "// " + marker + " marker\n";
        CHECK(listener_is_canonical(candidate));
        CHECK(upstream_is_canonical(candidate));
        CHECK(pre_route_is_canonical(candidate));
        CHECK(redirect_is_canonical(candidate));
        CHECK(root_is_canonical(candidate));
        CHECK_FALSE(has_no_nginx_hook(candidate));
        const auto marker_lexed = lex({candidate.data(), static_cast<u32>(candidate.size())});
        REQUIRE(marker_lexed);
        const auto marker_parsed = parse_file(marker_lexed.value());
        REQUIRE(marker_parsed);
        delete marker_parsed.value();
    }

    const auto lexed = lex({exact.data(), static_cast<u32>(exact.size())});
    REQUIRE(lexed);
    const auto parsed = parse_file(lexed.value());
    REQUIRE(parsed);
    std::unique_ptr<AstFile> ast(parsed.value());
    REQUIRE_GT(ast->items.len, 0u);
    REQUIRE(ast->items[0].kind == AstItemKind::Listen);
    CHECK(ast->items[0].listen.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(ast->items[0].listen.ipv4_host, 0x7f000001u);
    CHECK_EQ(ast->items[0].listen.port, 8080u);
    REQUIRE_EQ(ast->redirect_policies.len, 1u);
    const AstRouteDecl* ast_get = nullptr;
    for (u32 i = 0u; i < ast->items.len; i++) {
        if (ast->items[i].kind == AstItemKind::Route &&
            ast->items[i].route.method == static_cast<u8>(TokenType::KwGet) &&
            ast->items[i].route.path.eq(lit_str("/")))
            ast_get = &ast->items[i].route;
    }
    REQUIRE(ast_get != nullptr);
    REQUIRE_EQ(ast_get->statements.len, 1u);
    REQUIRE(ast_get->statements[0] != nullptr);
    const AstStatement& ast_if = *ast_get->statements[0];
    REQUIRE(ast_if.kind == AstStmtKind::If);
    REQUIRE(ast_if.then_stmt != nullptr);
    REQUIRE(ast_if.else_stmt != nullptr);
    REQUIRE(ast_if.then_stmt->kind == AstStmtKind::Redirect);
    REQUIRE(ast_if.then_stmt->has_redirect_policy);
    REQUIRE_NE(ast_if.then_stmt->redirect_policy_id, 0u);
    REQUIRE_LE(ast_if.then_stmt->redirect_policy_id, ast->redirect_policies.len);
    REQUIRE(ast_if.else_stmt->kind == AstStmtKind::ForwardUpstream);
    const auto& ast_policy = ast->redirect_policies[ast_if.then_stmt->redirect_policy_id - 1u];
    CHECK_EQ(ast_policy.status_code, 301u);
    CHECK(ast_policy.reason.eq(lit_str("Moved Permanently")));
    CHECK(ast_policy.static_authority.eq(lit_str("redirect.example")));
    CHECK(ast_policy.target_path.eq(lit_str("/new")));
    CHECK(ast_policy.query == RedirectPolicyQuery::Discard);
    CHECK(ast_policy.header_order == RedirectPolicyHeaderOrder::ConnectionThenLocation);
    CHECK(ast_policy.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u}));

    const auto analyzed = analyze_file(*ast);
    REQUIRE(analyzed);
    std::unique_ptr<HirModule> hir(analyzed.value());
    REQUIRE(hir->has_listener);
    CHECK(hir->listener.address == ListenerAddress::IPv4Exact);
    CHECK_EQ(hir->listener.ipv4_host, 0x7f000001u);
    CHECK_EQ(hir->listener.port, 8080u);
    REQUIRE_EQ(hir->routes.len, 3u);
    const HirRoute* hir_get = nullptr;
    for (u32 i = 0u; i < hir->routes.len; i++)
        if (hir->routes[i].method == kRouteMethodGet && hir->routes[i].path.eq(lit_str("/")))
            hir_get = &hir->routes[i];
    REQUIRE(hir_get != nullptr);
    REQUIRE(hir_get->control.kind == HirControlKind::If);
    REQUIRE(hir_get->control.then_term.kind == HirTerminatorKind::Redirect);
    REQUIRE_NE(hir_get->control.then_term.redirect_policy_id, 0u);
    REQUIRE_LE(hir_get->control.then_term.redirect_policy_id, hir->redirect_policies.len);
    REQUIRE(hir_get->control.else_term.kind == HirTerminatorKind::ForwardUpstream);
    const auto& hir_policy =
        hir->redirect_policies[hir_get->control.then_term.redirect_policy_id - 1u];
    CHECK_EQ(hir_policy.status_code, 301u);
    CHECK(hir_policy.body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u}));

    const auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());
    REQUIRE_EQ(mir->functions.len, 3u);
    const MirFunction* mir_get = nullptr;
    for (u32 i = 0u; i < mir->functions.len; i++)
        if (mir->functions[i].method == kRouteMethodGet && mir->functions[i].path.eq(lit_str("/")))
            mir_get = &mir->functions[i];
    REQUIRE(mir_get != nullptr);
    bool mir_redirect = false;
    bool mir_forward = false;
    for (u32 block = 0u; block < mir_get->blocks.len; block++) {
        const auto& term = mir_get->blocks[block].term;
        if (term.kind == MirTerminatorKind::Redirect) {
            mir_redirect = true;
            CHECK_EQ(term.redirect_policy_id, hir_get->control.then_term.redirect_policy_id);
        }
        if (term.kind == MirTerminatorKind::ForwardUpstream) mir_forward = true;
    }
    CHECK(mir_redirect);
    CHECK(mir_forward);
    FrontendRirModule rir{};
    RirGuard rir_guard{rir};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.func_count, 3u);
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    REQUIRE_EQ(rir.module.upstream_count, 1u);
    u32 rir_redirects = 0u;
    u32 rir_forwards = 0u;
    for (u32 function = 0u; function < rir.module.func_count; function++) {
        for (u32 block = 0u; block < rir.module.functions[function].block_count; block++) {
            const auto& rir_block = rir.module.functions[function].blocks[block];
            for (u32 instruction = 0u; instruction < rir_block.inst_count; instruction++) {
                if (rir_block.insts[instruction].op == rir::Opcode::RetRedirect) rir_redirects++;
                if (rir_block.insts[instruction].op == rir::Opcode::RetForwardBundle)
                    rir_forwards++;
            }
        }
    }
    CHECK_EQ(rir_redirects, 1u);
    CHECK_EQ(rir_forwards, 3u);
    CHECK_EQ(rir.module.redirect_policies[0].status_code, 301u);
    CHECK(rir.module.redirect_policies[0].body.eq({kRedirectBody, sizeof(kRedirectBody) - 1u}));
}

TEST(nginx_converter, explicit_ipv4_wildcard_listener_survives_frontend_lifetimes) {
    auto populated = std::make_unique<RouteConfig>();
    ListenerSpec source_listener{};
    {
        char nginx_source[] =
            "server { listen 0.0.0.0:8080; "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 9u);
        REQUIRE(ast_owned->items[0].kind == AstItemKind::Listen);
        CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
        REQUIRE(ast_owned->items[1].kind == AstItemKind::Upstream);
        REQUIRE(ast_owned->items[2].kind == AstItemKind::PreRoute);
        for (u32 i = 6u; i < 9u; i++) {
            REQUIRE(ast_owned->items[i].kind == AstItemKind::Route);
            CHECK(ast_owned->items[i].route.path.eq(lit_str("/")));
        }

        const auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE(hir_owned->has_listener);
        source_listener.port = hir_owned->listener.port;
        REQUIRE_EQ(hir_owned->upstreams.len, 1u);
        REQUIRE_EQ(hir_owned->routes.len, 3u);

        const auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        for (u32 i = 0; i < mir_owned->functions.len; i++)
            CHECK(mir_owned->functions[i].path.eq(lit_str("/")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.func_count, 3u);
        REQUIRE_EQ(rir.module.upstream_count, 1u);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    const auto resolved = resolve_listener_spec(true, source_listener, false, 0u);
    REQUIRE(resolved);
    CHECK(resolved.value().address == ListenerAddress::IPv4Wildcard);
    CHECK(resolved.value().transport == ListenerTransport::Cleartext);
    CHECK_EQ(resolved.value().port, 8080u);
    REQUIRE_EQ(populated->response_policy_count, 2u);
    REQUIRE_EQ(populated->failure_policy_count, 3u);
    REQUIRE_EQ(populated->policy_bundle_count, 3u);
    REQUIRE_EQ(populated->strict_local_response_policy_count, 3u);
    CHECK_NE(populated->pre_route_policy_id(kRouteMethodTrace), 0u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodConnect], 1u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated->strict_local_response_table_is_valid());
}

TEST(nginx_converter, asterisk_ipv4_wildcard_listener_survives_frontend_lifetimes) {
    auto populated = std::make_unique<RouteConfig>();
    ListenerSpec source_listener{};
    {
        char nginx_source[] =
            "server { listen *:8080; "
            "location / { proxy_pass http://127.0.0.1:9000; } }";
        const auto parsed = nginx::parse({nginx_source, sizeof(nginx_source) - 1u});
        REQUIRE(parsed);
        auto lowered = nginx::lower_to_rut(parsed.value());
        REQUIRE(lowered);
        memset(nginx_source, 'x', sizeof(nginx_source) - 1u);

        const auto lexed = lex(lowered.value().view());
        REQUIRE(lexed);
        const auto ast = parse_file(lexed.value());
        REQUIRE(ast);
        std::unique_ptr<AstFile> ast_owned(ast.value());
        REQUIRE_EQ(ast_owned->items.len, 9u);
        REQUIRE(ast_owned->items[0].kind == AstItemKind::Listen);
        CHECK_EQ(ast_owned->items[0].listen.port, 8080u);
        REQUIRE(ast_owned->items[1].kind == AstItemKind::Upstream);
        REQUIRE(ast_owned->items[2].kind == AstItemKind::PreRoute);
        for (u32 i = 6u; i < 9u; i++) {
            REQUIRE(ast_owned->items[i].kind == AstItemKind::Route);
            CHECK(ast_owned->items[i].route.path.eq(lit_str("/")));
        }

        const auto hir = analyze_file(*ast_owned);
        REQUIRE(hir);
        std::unique_ptr<HirModule> hir_owned(hir.value());
        REQUIRE(hir_owned->has_listener);
        source_listener.port = hir_owned->listener.port;
        REQUIRE_EQ(hir_owned->upstreams.len, 1u);
        REQUIRE_EQ(hir_owned->routes.len, 3u);

        const auto mir = build_mir(*hir_owned);
        REQUIRE(mir);
        std::unique_ptr<MirModule> mir_owned(mir.value());
        REQUIRE_EQ(mir_owned->functions.len, 3u);
        for (u32 i = 0; i < mir_owned->functions.len; i++)
            CHECK(mir_owned->functions[i].path.eq(lit_str("/")));

        FrontendRirModule rir{};
        RirGuard rir_guard{rir};
        REQUIRE(lower_to_rir(*mir_owned, rir));
        REQUIRE(rir::verify_module(rir.module).ok);
        REQUIRE_EQ(rir.module.func_count, 3u);
        REQUIRE_EQ(rir.module.upstream_count, 1u);
        REQUIRE(populate_route_config(*populated, rir.module));
        memset(lowered.value().data, 'y', lowered.value().len);
    }

    const auto resolved = resolve_listener_spec(true, source_listener, false, 0u);
    REQUIRE(resolved);
    CHECK(resolved.value().address == ListenerAddress::IPv4Wildcard);
    CHECK(resolved.value().transport == ListenerTransport::Cleartext);
    CHECK_EQ(resolved.value().port, 8080u);
    REQUIRE_EQ(populated->response_policy_count, 2u);
    REQUIRE_EQ(populated->failure_policy_count, 3u);
    REQUIRE_EQ(populated->policy_bundle_count, 3u);
    REQUIRE_EQ(populated->strict_local_response_policy_count, 3u);
    CHECK_NE(populated->pre_route_policy_id(kRouteMethodTrace), 0u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodOptions], 2u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodConnect], 1u);
    CHECK_EQ(populated->unmatched_policy_ids[kRouteMethodAny], 3u);
    CHECK(populated->strict_local_response_table_is_valid());
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
