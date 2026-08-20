#include "rut/compiler/rir.h"
#include "rut/compiler/rir_printer.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/route_table.h"
#include "test.h"

using namespace rut;

namespace {

RedirectPolicySpec policy(Str body = lit_str("ok")) {
    RedirectPolicySpec result{};
    result.scheme = RedirectPolicyScheme::Http;
    result.authority = RedirectPolicyAuthority::RequestHost;
    result.port = RedirectPolicyPort::ActualListener;
    result.path = RedirectPolicyPath::Static;
    result.query = RedirectPolicyQuery::PreserveRaw;
    result.date = RedirectPolicyDate::Current;
    result.connection = RedirectPolicyConnection::Close;
    result.status_code = 301;
    result.reason = lit_str("Moved Permanently");
    result.server = lit_str("nginx/1.29.7");
    result.content_type = lit_str("text/html");
    result.target_path = lit_str("/api/");
    result.body = body;
    return result;
}

bool equal_bytes(const char* actual, u32 actual_len, const char* expected, u32 expected_len) {
    if (actual_len != expected_len) return false;
    for (u32 i = 0; i < actual_len; i++)
        if (actual[i] != expected[i]) return false;
    return true;
}

}  // namespace

TEST(redirect_policy, valid_pinned_shape_and_printer_are_deterministic) {
    char body[] = {'A', '\0', '\r', '\n', '"'};
    const auto spec = policy({body, sizeof(body)});
    CHECK(redirect_policy_spec_valid(spec));

    rir::Module mod{};
    mod.redirect_policy_count = 1;
    mod.redirect_policies[0] = spec;
    CHECK(redirect_policy_table_valid(mod.redirect_policies, mod.redirect_policy_count));

    char output[2048];
    rir::PrintBuf buf;
    buf.init(output, sizeof(output), -1);
    rir::print_module(buf, mod);
    static constexpr char expected[] =
        "redirect_policies: 1\n"
        "  redirect_policy#1: scheme=http, authority=request_host, port=actual_listener, "
        "path=static, query=preserve_raw, date=current, connection=close, status=301, "
        "reason=\"Moved Permanently\", server=\"nginx/1.29.7\", "
        "content_type=\"text/html\", target_path=\"/api/\", "
        "body=b\"A\\x00\\r\\n\\\"\" (len=5)\n";
    CHECK_FALSE(buf.overflow);
    CHECK(equal_bytes(buf.data, buf.len, expected, sizeof(expected) - 1));
}

TEST(redirect_policy, rejects_invalid_enum_status_text_path_and_body_forms) {
    char body[] = "ok";
    const auto valid = policy({body, 2});
    CHECK(redirect_policy_spec_valid(valid));

    auto invalid = valid;
    invalid.scheme = RedirectPolicyScheme::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.authority = RedirectPolicyAuthority::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.port = RedirectPolicyPort::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.path = RedirectPolicyPath::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.query = RedirectPolicyQuery::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.date = RedirectPolicyDate::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.connection = RedirectPolicyConnection::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.status_code = 299;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.status_code = 400;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));

    char control[] = {'o', 'k', '\r'};
    invalid = valid;
    invalid.reason = {control, sizeof(control)};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.server = {control, sizeof(control)};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.content_type = {control, sizeof(control)};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));

    char query_path[] = "/api/?x=1";
    invalid = valid;
    invalid.target_path = {query_path, sizeof(query_path) - 1};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.target_path = {nullptr, 1};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.body = {nullptr, 1};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.target_path = {nullptr, 0};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
}

TEST(redirect_policy, exact_field_count_and_aggregate_boundaries_are_bounded) {
    char max_body[kMaxRedirectBodyLen];
    for (u32 i = 0; i < kMaxRedirectBodyLen; i++) max_body[i] = static_cast<char>(i);
    CHECK(redirect_policy_spec_valid(policy({max_body, kMaxRedirectBodyLen})));

    char too_large_body[kMaxRedirectBodyLen + 1];
    const auto too_large = policy({too_large_body, kMaxRedirectBodyLen + 1});
    CHECK_FALSE(redirect_policy_spec_valid(too_large));

    char max_reason[kMaxRedirectReasonLen];
    char max_server[kMaxRedirectServerLen];
    char max_content_type[kMaxRedirectContentTypeLen];
    char max_path[kMaxRedirectTargetPathLen];
    for (u32 i = 0; i < kMaxRedirectReasonLen; i++) max_reason[i] = 'r';
    for (u32 i = 0; i < kMaxRedirectServerLen; i++) max_server[i] = 's';
    for (u32 i = 0; i < kMaxRedirectContentTypeLen; i++) max_content_type[i] = 'x';
    for (u32 i = 0; i < kMaxRedirectTargetPathLen; i++) max_path[i] = 'a';
    max_path[0] = '/';
    auto exact_fields = policy({nullptr, 0});
    exact_fields.reason = {max_reason, kMaxRedirectReasonLen};
    exact_fields.server = {max_server, kMaxRedirectServerLen};
    exact_fields.content_type = {max_content_type, kMaxRedirectContentTypeLen};
    exact_fields.target_path = {max_path, kMaxRedirectTargetPathLen};
    CHECK(redirect_policy_spec_valid(exact_fields));

    char bodies[4][kMaxRedirectBodyLen];
    RedirectPolicySpec exact[kMaxRedirectPolicies];
    for (u32 i = 0; i < 4; i++) {
        for (u32 j = 0; j < kMaxRedirectBodyLen; j++) bodies[i][j] = 'x';
        exact[i] = policy({bodies[i], kMaxRedirectBodyLen});
        exact[i].status_code = static_cast<u16>(300 + i);
        exact[i].target_path = i == 0 ? lit_str("/a/") : (i == 1 ? lit_str("/b/")
                                                                  : (i == 2 ? lit_str("/c/")
                                                                            : lit_str("/d/")));
    }
    exact[3].body.len = 3932;
    CHECK(redirect_policy_table_valid(exact, 4));

    rir::Module mod{};
    mod.redirect_policy_count = 4;
    for (u32 i = 0; i < 4; i++) mod.redirect_policies[i] = exact[i];
    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.redirect_policy_count, 4u);
    CHECK_EQ(cfg.redirect_policy_bytes_used, kRedirectPolicyBytes);
    CHECK(cfg.redirect_policy_id_is_valid(4));

    exact[3].body.len = 3933;
    CHECK_FALSE(redirect_policy_table_valid(exact, 4));
    rir::Module overflow_mod{};
    overflow_mod.redirect_policy_count = 4;
    for (u32 i = 0; i < 4; i++) overflow_mod.redirect_policies[i] = exact[i];
    RouteConfig overflow_cfg{};
    CHECK_FALSE(populate_route_config(overflow_cfg, overflow_mod));
    CHECK_EQ(overflow_cfg.redirect_policy_count, 0u);
    CHECK_EQ(overflow_cfg.redirect_policy_bytes_used, 0u);
    CHECK_FALSE(redirect_policy_table_valid(nullptr, kMaxRedirectPolicies + 1));

    char count_body[] = "";
    RouteConfig count_cfg{};
    for (u32 i = 0; i < kMaxRedirectPolicies; i++) {
        auto count_spec = policy({count_body, 0});
        count_spec.status_code = static_cast<u16>(300 + i);
        REQUIRE_EQ(count_cfg.add_redirect_policy(count_spec), i + 1);
    }
    CHECK_EQ(count_cfg.redirect_policy_count, kMaxRedirectPolicies);
    auto count_overflow = policy({count_body, 0});
    count_overflow.status_code = 399;
    CHECK_EQ(count_cfg.add_redirect_policy(count_overflow), 0u);
}

TEST(redirect_policy, duplicate_contract_and_owned_copy_are_explicit) {
    char reason[] = "Moved Permanently";
    char server[] = "nginx/1.29.7";
    char content_type[] = "text/html";
    char path[] = "/api/";
    char body[] = {'o', '\0', 'k'};
    RedirectPolicySpec spec = policy({body, sizeof(body)});
    spec.reason = {reason, sizeof(reason) - 1};
    spec.server = {server, sizeof(server) - 1};
    spec.content_type = {content_type, sizeof(content_type) - 1};
    spec.target_path = {path, sizeof(path) - 1};

    rir::Module owned_mod{};
    owned_mod.redirect_policy_count = 1;
    owned_mod.redirect_policies[0] = spec;
    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, owned_mod));
    REQUIRE_EQ(cfg.add_redirect_policy(spec), 1u);
    const u32 bytes = cfg.redirect_policy_bytes_used;
    CHECK_EQ(cfg.add_redirect_policy(spec), 1u);
    CHECK_EQ(cfg.redirect_policy_count, 1u);
    CHECK_EQ(cfg.redirect_policy_bytes_used, bytes);
    reason[0] = 'X';
    server[0] = 'X';
    content_type[0] = 'X';
    path[1] = 'X';
    body[0] = 'X';
    CHECK(cfg.redirect_policies[0].reason.eq(lit_str("Moved Permanently")));
    CHECK(cfg.redirect_policies[0].server.eq(lit_str("nginx/1.29.7")));
    CHECK(cfg.redirect_policies[0].content_type.eq(lit_str("text/html")));
    CHECK(cfg.redirect_policies[0].target_path.eq(lit_str("/api/")));
    static constexpr char expected_body[] = {'o', '\0', 'k'};
    CHECK(cfg.redirect_policies[0].body.eq({expected_body, sizeof(expected_body)}));

    rir::Module duplicate_mod{};
    duplicate_mod.redirect_policy_count = 2;
    duplicate_mod.redirect_policies[0] = spec;
    duplicate_mod.redirect_policies[1] = spec;
    RouteConfig duplicate_cfg{};
    CHECK_FALSE(populate_route_config(duplicate_cfg, duplicate_mod));
    CHECK_EQ(duplicate_cfg.redirect_policy_count, 0u);
    CHECK_EQ(duplicate_cfg.redirect_policy_bytes_used, 0u);
}

TEST(redirect_policy, invalid_population_is_atomic_and_preserves_unrelated_config) {
    char name[] = "existing";
    RouteConfig cfg{};
    REQUIRE(cfg.add_upstream(name, 0x7f000001u, 19000).has_value());
    char body[] = "ok";
    rir::Module mod{};
    mod.upstream_count = 1;
    mod.upstreams[0].name = {name, sizeof(name) - 1};
    mod.upstreams[0].has_address = false;
    mod.redirect_policy_count = 1;
    mod.redirect_policies[0] = policy({body, 2});
    mod.redirect_policies[0].target_path = {nullptr, 1};

    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.upstream_count, 1u);
    CHECK_EQ(cfg.redirect_policy_count, 0u);
    CHECK_EQ(cfg.redirect_policy_bytes_used, 0u);
}

TEST(redirect_policy, empty_table_is_transparent) {
    rir::Module mod{};
    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.redirect_policy_count, 0u);
    CHECK_EQ(cfg.redirect_policy_bytes_used, 0u);
    CHECK_FALSE(cfg.redirect_policy_id_is_valid(0));
    CHECK_FALSE(cfg.redirect_policy_id_is_valid(1));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
