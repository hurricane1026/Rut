#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_printer.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/route_table.h"
#include "test.h"
#include <memory>

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
    result.header_order = RedirectPolicyHeaderOrder::LocationThenConnection;
    result.status_code = 301;
    result.reason = lit_str("Moved Permanently");
    result.server = lit_str("nginx/1.29.7");
    result.content_type = lit_str("text/html");
    result.target_path = lit_str("/api/");
    result.body = body;
    return result;
}

RedirectPolicySpec fixed_policy(Str body = lit_str("ok")) {
    RedirectPolicySpec result = policy(body);
    result.authority = RedirectPolicyAuthority::Static;
    result.port = RedirectPolicyPort::Omit;
    result.query = RedirectPolicyQuery::Discard;
    result.header_order = RedirectPolicyHeaderOrder::ConnectionThenLocation;
    result.static_authority = lit_str("redirect.example");
    result.target_path = lit_str("/new");
    return result;
}

bool equal_bytes(const char* actual, u32 actual_len, const char* expected, u32 expected_len) {
    if (actual_len != expected_len) return false;
    for (u32 i = 0; i < actual_len; i++)
        if (actual[i] != expected[i]) return false;
    return true;
}

Str source_lit(const char* value) {
    u32 len = 0;
    while (value[len]) len++;
    return {value, len};
}

struct RedirectInventorySnapshot {
    RedirectPolicySpec policies[RouteConfig::kMaxRedirectPolicies];
    char bytes[RouteConfig::kRedirectPolicyBytesPoolBytes];
    u32 count = 0;
    u32 bytes_used = 0;
};

RedirectInventorySnapshot snapshot_redirect_inventory(const RouteConfig& cfg) {
    RedirectInventorySnapshot snapshot{};
    __builtin_memcpy(snapshot.policies, cfg.redirect_policies, sizeof(snapshot.policies));
    __builtin_memcpy(snapshot.bytes, cfg.redirect_policy_bytes, sizeof(snapshot.bytes));
    snapshot.count = cfg.redirect_policy_count;
    snapshot.bytes_used = cfg.redirect_policy_bytes_used;
    return snapshot;
}

bool redirect_inventory_matches(const RouteConfig& cfg, const RedirectInventorySnapshot& snapshot) {
    return cfg.redirect_policy_count == snapshot.count &&
           cfg.redirect_policy_bytes_used == snapshot.bytes_used &&
           __builtin_memcmp(cfg.redirect_policies, snapshot.policies, sizeof(snapshot.policies)) ==
               0 &&
           __builtin_memcmp(cfg.redirect_policy_bytes, snapshot.bytes, sizeof(snapshot.bytes)) == 0;
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
        "path=static, query=preserve_raw, date=current, connection=close, "
        "header_order=location_then_connection, status=301, "
        "reason=\"Moved Permanently\", server=\"nginx/1.29.7\", "
        "content_type=\"text/html\", static_authority=\"\", target_path=\"/api/\", "
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
    invalid.header_order = RedirectPolicyHeaderOrder::Invalid;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.header_order = static_cast<RedirectPolicyHeaderOrder>(0xff);
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.header_order = RedirectPolicyHeaderOrder::ConnectionThenLocation;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.authority = RedirectPolicyAuthority::Static;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.port = RedirectPolicyPort::Omit;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.query = RedirectPolicyQuery::Discard;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = valid;
    invalid.static_authority = lit_str("redirect.example");
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

TEST(redirect_policy, fixed_profile_is_closed_and_cross_products_fail) {
    CHECK_FALSE(redirect_policy_fixed_status_supported(300));
    CHECK(redirect_policy_fixed_status_supported(301));
    CHECK(redirect_policy_fixed_status_supported(302));
    CHECK_FALSE(redirect_policy_fixed_status_supported(303));
    CHECK_FALSE(redirect_policy_fixed_status_supported(307));
    CHECK_FALSE(redirect_policy_fixed_status_supported(308));
    CHECK_FALSE(redirect_policy_fixed_status_supported(399));

    const auto fixed = fixed_policy();
    CHECK(redirect_policy_spec_valid(fixed));
    auto fixed_302 = fixed;
    fixed_302.status_code = 302;
    fixed_302.reason = lit_str("Moved Temporarily");
    CHECK(redirect_policy_spec_valid(fixed_302));

    auto invalid = fixed;
    invalid.authority = RedirectPolicyAuthority::RequestHost;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed;
    invalid.port = RedirectPolicyPort::ActualListener;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed;
    invalid.query = RedirectPolicyQuery::PreserveRaw;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed;
    invalid.header_order = RedirectPolicyHeaderOrder::LocationThenConnection;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed;
    invalid.static_authority = {};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed;
    invalid.static_authority = lit_str("user@redirect.example");
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed;
    for (u16 status : {static_cast<u16>(300),
                       static_cast<u16>(303),
                       static_cast<u16>(307),
                       static_cast<u16>(308),
                       static_cast<u16>(399)}) {
        invalid = fixed;
        invalid.status_code = status;
        CHECK_FALSE(redirect_policy_spec_valid(invalid));
    }

    invalid = policy();
    invalid.status_code = 302;
    CHECK(redirect_policy_spec_valid(invalid));
    invalid.status_code = 399;
    CHECK(redirect_policy_spec_valid(invalid));

    invalid = fixed_302;
    invalid.authority = RedirectPolicyAuthority::RequestHost;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed_302;
    invalid.port = RedirectPolicyPort::ActualListener;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed_302;
    invalid.query = RedirectPolicyQuery::PreserveRaw;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed_302;
    invalid.header_order = RedirectPolicyHeaderOrder::LocationThenConnection;
    CHECK_FALSE(redirect_policy_spec_valid(invalid));
    invalid = fixed_302;
    invalid.static_authority = {};
    CHECK_FALSE(redirect_policy_spec_valid(invalid));

    invalid = policy();
    invalid.status_code = 399;
    CHECK(redirect_policy_spec_valid(invalid));
}

TEST(redirect_policy, fixed_302_dedup_ownership_and_forged_303_publication_are_transactional) {
    char reason[] = "Moved Temporarily";
    char body[] = "fixed-302";
    auto fixed_301 = fixed_policy();
    auto fixed_302 = fixed_policy({body, sizeof(body) - 1});
    fixed_302.status_code = 302;
    fixed_302.reason = {reason, sizeof(reason) - 1};

    RouteConfig cfg{};
    REQUIRE_EQ(cfg.add_redirect_policy(fixed_301), 1u);
    REQUIRE_EQ(cfg.add_redirect_policy(fixed_302), 2u);
    CHECK_EQ(cfg.add_redirect_policy(fixed_302), 2u);
    REQUIRE(cfg.redirect_policy_id_is_valid(1));
    REQUIRE(cfg.redirect_policy_id_is_valid(2));
    CHECK_NE(cfg.redirect_policies[0].status_code, cfg.redirect_policies[1].status_code);
    CHECK_NE(cfg.redirect_policies[1].reason.ptr, reason);
    CHECK_NE(cfg.redirect_policies[1].body.ptr, body);
    reason[0] = 'X';
    body[0] = 'X';
    CHECK(cfg.redirect_policies[1].reason.eq(lit_str("Moved Temporarily")));
    CHECK(cfg.redirect_policies[1].body.eq(lit_str("fixed-302")));

    const auto before = snapshot_redirect_inventory(cfg);
    auto fixed_303 = fixed_302;
    fixed_303.status_code = 303;
    CHECK_EQ(cfg.add_redirect_policy(fixed_303), 0u);
    CHECK(redirect_inventory_matches(cfg, before));

    rir::Module forged{};
    forged.redirect_policy_count = 1;
    forged.redirect_policies[0] = fixed_303;
    RouteConfig destination{};
    destination.redirect_policies[0].status_code = 777;
    destination.redirect_policy_bytes[0] = 'S';
    const auto destination_before = snapshot_redirect_inventory(destination);
    CHECK_FALSE(populate_route_config(destination, forged));
    CHECK(redirect_inventory_matches(destination, destination_before));
}

TEST(redirect_policy, static_authority_foundation_accepts_only_bounded_dns_ipv4_shape) {
    CHECK(redirect_policy_safe_static_authority(lit_str("redirect.example")));
    CHECK(redirect_policy_safe_static_authority(lit_str("127.0.0.1")));
    char preserved[] = "MiXeD-Case.Example9";
    char preserved_before[sizeof(preserved)];
    __builtin_memcpy(preserved_before, preserved, sizeof(preserved));
    CHECK(redirect_policy_safe_static_authority({preserved, sizeof(preserved) - 1}));
    CHECK_EQ(__builtin_memcmp(preserved, preserved_before, sizeof(preserved)), 0);

    char max_total[kMaxRedirectStaticAuthorityLen];
    u32 at = 0;
    const u32 max_total_labels[] = {63, 63, 63, 61};
    for (u32 label = 0; label < 4; label++) {
        if (label != 0) max_total[at++] = '.';
        for (u32 i = 0; i < max_total_labels[label]; i++) max_total[at++] = 'a';
    }
    REQUIRE_EQ(at, kMaxRedirectStaticAuthorityLen);
    CHECK(redirect_policy_safe_static_authority({max_total, at}));

    char too_long_total[kMaxRedirectStaticAuthorityLen + 1];
    at = 0;
    const u32 too_long_labels[] = {63, 63, 63, 62};
    for (u32 label = 0; label < 4; label++) {
        if (label != 0) too_long_total[at++] = '.';
        for (u32 i = 0; i < too_long_labels[label]; i++) too_long_total[at++] = 'a';
    }
    REQUIRE_EQ(at, kMaxRedirectStaticAuthorityLen + 1);
    CHECK_FALSE(redirect_policy_safe_static_authority({too_long_total, at}));

    char max_label[63];
    char too_long_label[64];
    for (u32 i = 0; i < sizeof(max_label); i++) max_label[i] = 'a';
    for (u32 i = 0; i < sizeof(too_long_label); i++) too_long_label[i] = 'a';
    CHECK(redirect_policy_safe_static_authority({max_label, sizeof(max_label)}));
    CHECK_FALSE(redirect_policy_safe_static_authority({too_long_label, sizeof(too_long_label)}));

    CHECK_FALSE(redirect_policy_safe_static_authority({nullptr, 0}));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str(".example")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example.")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("a..example")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("-example")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example-")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("a.-example")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example-.a")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("user@example.test")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example.test:8080")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("[::1]")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("exa%6dple.test")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("under_score.test")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("exa\"mple.test")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example,test")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example.test/path")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example.test?query")));
    CHECK_FALSE(redirect_policy_safe_static_authority(lit_str("example.test#fragment")));
    char crlf[] = {'e', 'x', '\r', '\n'};
    CHECK_FALSE(redirect_policy_safe_static_authority({crlf, sizeof(crlf)}));
}

TEST(redirect_policy, new_metadata_participates_in_equality) {
    const auto legacy = policy();
    auto different = legacy;
    different.header_order = RedirectPolicyHeaderOrder::ConnectionThenLocation;
    CHECK_FALSE(redirect_policy_spec_equal(legacy, different));
    different = legacy;
    different.static_authority = lit_str("redirect.example");
    CHECK_FALSE(redirect_policy_spec_equal(legacy, different));
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
        exact[i].target_path =
            i == 0 ? lit_str("/a/")
                   : (i == 1 ? lit_str("/b/") : (i == 2 ? lit_str("/c/") : lit_str("/d/")));
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
    CHECK(count_cfg.redirect_policy_id_is_valid(kMaxRedirectPolicies));
    CHECK_FALSE(count_cfg.redirect_policy_id_is_valid(kMaxRedirectPolicies + 1));
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
    CHECK(cfg.redirect_policies[0].static_authority.empty());
    CHECK_EQ(cfg.redirect_policies[0].header_order,
             RedirectPolicyHeaderOrder::LocationThenConnection);
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

TEST(redirect_policy, direct_add_and_runtime_validation_are_bounds_safe_and_atomic) {
    RouteConfig cfg{};
    REQUIRE_EQ(cfg.add_redirect_policy(policy()), 1u);
    REQUIRE(cfg.redirect_policy_id_is_valid(1));

    const auto valid_snapshot = snapshot_redirect_inventory(cfg);
    auto invalid = policy();
    invalid.static_authority = lit_str("redirect.example");
    CHECK_EQ(cfg.add_redirect_policy(invalid), 0u);
    CHECK(redirect_inventory_matches(cfg, valid_snapshot));

    cfg.redirect_policies[0].reason = {reinterpret_cast<const char*>(1), 1};
    const auto forged_pointer_snapshot = snapshot_redirect_inventory(cfg);
    CHECK_FALSE(cfg.redirect_policy_id_is_valid(1));
    CHECK_EQ(cfg.add_redirect_policy(policy()), 0u);
    CHECK(redirect_inventory_matches(cfg, forged_pointer_snapshot));

    RouteConfig forged_count{};
    forged_count.redirect_policy_count = kMaxRedirectPolicies + 1;
    forged_count.redirect_policies[0].reason = {reinterpret_cast<const char*>(1), 1};
    forged_count.redirect_policy_bytes[0] = 'C';
    const auto forged_count_snapshot = snapshot_redirect_inventory(forged_count);
    CHECK_FALSE(forged_count.redirect_policy_id_is_valid(kMaxRedirectPolicies + 1));
    CHECK_EQ(forged_count.add_redirect_policy(policy()), 0u);
    CHECK(redirect_inventory_matches(forged_count, forged_count_snapshot));

    RouteConfig forged_watermark{};
    forged_watermark.redirect_policy_count = 1;
    forged_watermark.redirect_policy_bytes_used = kRedirectPolicyBytes + 1;
    forged_watermark.redirect_policies[0].reason = {reinterpret_cast<const char*>(1), 1};
    forged_watermark.redirect_policy_bytes[0] = 'W';
    const auto forged_watermark_snapshot = snapshot_redirect_inventory(forged_watermark);
    CHECK_FALSE(forged_watermark.redirect_policy_id_is_valid(1));
    CHECK_EQ(forged_watermark.add_redirect_policy(policy()), 0u);
    CHECK(redirect_inventory_matches(forged_watermark, forged_watermark_snapshot));
}

TEST(redirect_policy, direct_table_rejection_preserves_sentinel_slots_and_pool) {
    RouteConfig cfg{};
    cfg.redirect_policies[0].status_code = 777;
    cfg.redirect_policies[kMaxRedirectPolicies - 1].status_code = 778;
    cfg.redirect_policy_bytes[0] = 'S';
    cfg.redirect_policy_bytes[kRedirectPolicyBytes - 1] = 'Z';
    const auto before = snapshot_redirect_inventory(cfg);

    auto invalid = policy();
    invalid.authority = RedirectPolicyAuthority::Static;
    invalid.static_authority = lit_str("redirect.example");
    CHECK_FALSE(cfg.add_redirect_policy_table(&invalid, 1));
    CHECK(redirect_inventory_matches(cfg, before));
    CHECK_FALSE(cfg.add_redirect_policy_table(&invalid, kMaxRedirectPolicies + 1));
    CHECK(redirect_inventory_matches(cfg, before));

    cfg.redirect_policy_count = kMaxRedirectPolicies + 1;
    const auto forged_count = snapshot_redirect_inventory(cfg);
    CHECK_FALSE(cfg.add_redirect_policy_table(nullptr, 0));
    CHECK(redirect_inventory_matches(cfg, forged_count));

    cfg.redirect_policy_count = 0;
    cfg.redirect_policy_bytes_used = kRedirectPolicyBytes + 1;
    const auto forged_watermark = snapshot_redirect_inventory(cfg);
    CHECK_FALSE(cfg.add_redirect_policy_table(nullptr, 0));
    CHECK(redirect_inventory_matches(cfg, forged_watermark));
}

TEST(redirect_policy, partial_fixed_profile_rejects_without_destination_mutation) {
    RedirectPolicySpec partial = policy();
    partial.authority = RedirectPolicyAuthority::Static;
    partial.static_authority = lit_str("redirect.example");
    partial.port = RedirectPolicyPort::Omit;
    partial.query = RedirectPolicyQuery::Discard;
    CHECK_FALSE(redirect_policy_spec_valid(partial));

    rir::Module mod{};
    mod.redirect_policy_count = 1;
    mod.redirect_policies[0] = partial;
    RouteConfig cfg{};
    cfg.redirect_policies[0].status_code = 777;
    cfg.redirect_policy_bytes[0] = 'P';
    const auto before = snapshot_redirect_inventory(cfg);
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK(redirect_inventory_matches(cfg, before));

    mod.redirect_policies[0] = policy();
    mod.redirect_policies[0].authority = static_cast<RedirectPolicyAuthority>(0xff);
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK(redirect_inventory_matches(cfg, before));
}

TEST(redirect_policy, invalid_population_is_atomic_and_preserves_unrelated_config) {
    char name[] = "existing";
    RouteConfig cfg{};
    REQUIRE(cfg.add_upstream(name, 0x7f000001u, 19000).has_value());
    cfg.redirect_policies[0].status_code = 777;
    cfg.redirect_policies[kMaxRedirectPolicies - 1].status_code = 778;
    cfg.redirect_policy_bytes[0] = 'S';
    cfg.redirect_policy_bytes[kRedirectPolicyBytes - 1] = 'Z';
    const auto before = snapshot_redirect_inventory(cfg);
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
    CHECK(cfg.upstreams[0].name_len == sizeof(name) - 1);
    CHECK_EQ(__builtin_memcmp(cfg.upstreams[0].name, name, sizeof(name) - 1), 0);
    CHECK(redirect_inventory_matches(cfg, before));
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

TEST(redirect_policy, publication_rejects_forged_ret_redirect_before_config_mutation) {
    rir::Module mod{};
    mod.redirect_policy_count = 1;
    mod.redirect_policies[0] = policy();

    rir::Instruction instruction{};
    instruction.op = rir::Opcode::RetRedirect;
    instruction.operand_count = 0;
    instruction.imm.i32_val = 2;
    rir::Block block{};
    block.insts = &instruction;
    block.inst_count = 1;
    rir::Function function{};
    function.blocks = &block;
    function.block_count = 1;
    mod.functions = &function;
    mod.func_count = 1;

    RouteConfig cfg{};
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.redirect_policy_count, 0u);
    CHECK_EQ(cfg.redirect_policy_bytes_used, 0u);

    instruction.imm.i32_val = 1;
    REQUIRE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.redirect_policy_count, 1u);
}

TEST(redirect_policy, source_redirect_reaches_owned_route_config) {
    const char source[] =
        "route GET \"/api\" { return redirect({"
        "scheme: \"http\", authority: \"request_host\", port: \"actual_listener\", "
        "path: \"static\", query: \"preserve_raw\", date: \"current\", "
        "connection: \"close\", status: 301, reason: \"Moved Permanently\", "
        "server: \"nginx/1.29.7\", content_type: \"text/html\", "
        "target_path: \"/api/\", body: b\"OK\\n\\x00\"}) }\n";
    auto lexed = lex(source_lit(source));
    REQUIRE(lexed);
    auto ast_result = parse_file(lexed.value());
    REQUIRE(ast_result);
    std::unique_ptr<AstFile> ast(ast_result.value());
    auto hir_result = analyze_file(*ast);
    REQUIRE(hir_result);
    std::unique_ptr<HirModule> hir(hir_result.value());
    auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());

    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    CHECK_EQ(rir.module.redirect_policies[0].header_order,
             RedirectPolicyHeaderOrder::LocationThenConnection);
    CHECK(rir.module.redirect_policies[0].static_authority.empty());
    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE_EQ(cfg.redirect_policy_count, 1u);
    CHECK_NE(cfg.redirect_policies[0].body.ptr, rir.module.redirect_policies[0].body.ptr);
    CHECK(equal_bytes(
        cfg.redirect_policies[0].body.ptr, cfg.redirect_policies[0].body.len, "OK\n\0", 4));
    CHECK(equal_bytes(cfg.redirect_policies[0].target_path.ptr,
                      cfg.redirect_policies[0].target_path.len,
                      "/api/",
                      5));
    rir.destroy();
}

TEST(redirect_policy, fixed_source_reaches_rir_and_owned_route_config) {
    const char source[] =
        "route GET \"/old\" { return redirect({"
        "scheme: \"http\", authority: \"static\", static_authority: \"redirect.example\", "
        "port: \"omit\", path: \"static\", query: \"discard\", date: \"current\", "
        "connection: \"close\", header_order: \"connection_then_location\", status: 301, "
        "reason: \"Moved Permanently\", server: \"nginx/1.29.7\", "
        "content_type: \"text/html\", target_path: \"/new\", body: b\"fixed\"}) }\n";
    auto lexed = lex(source_lit(source));
    REQUIRE(lexed);
    auto ast_result = parse_file(lexed.value());
    REQUIRE(ast_result);
    std::unique_ptr<AstFile> ast(ast_result.value());
    auto hir_result = analyze_file(*ast);
    REQUIRE(hir_result);
    std::unique_ptr<HirModule> hir(hir_result.value());
    auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());

    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    const auto& lowered = rir.module.redirect_policies[0];
    CHECK_EQ(lowered.authority, RedirectPolicyAuthority::Static);
    CHECK_EQ(lowered.port, RedirectPolicyPort::Omit);
    CHECK_EQ(lowered.query, RedirectPolicyQuery::Discard);
    CHECK_EQ(lowered.header_order, RedirectPolicyHeaderOrder::ConnectionThenLocation);
    CHECK(lowered.static_authority.eq(lit_str("redirect.example")));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE_EQ(cfg.redirect_policy_count, 1u);
    const auto& owned = cfg.redirect_policies[0];
    CHECK(redirect_policy_spec_valid(owned));
    CHECK_NE(owned.static_authority.ptr, lowered.static_authority.ptr);
    CHECK(owned.static_authority.eq(lit_str("redirect.example")));
    CHECK(owned.target_path.eq(lit_str("/new")));
    CHECK(owned.body.eq(lit_str("fixed")));
    rir.destroy();
}

TEST(redirect_policy, fixed_302_source_reaches_rir_and_owned_route_config) {
    const char source[] =
        "route GET \"/old\" { return redirect({"
        "scheme: \"http\", authority: \"static\", static_authority: \"redirect.example\", "
        "port: \"omit\", path: \"static\", query: \"discard\", date: \"current\", "
        "connection: \"close\", header_order: \"connection_then_location\", status: 302, "
        "reason: \"Moved Temporarily\", server: \"nginx/1.29.7\", "
        "content_type: \"text/html\", target_path: \"/new\", body: b\"fixed-302\"}) }\n";
    auto lexed = lex(source_lit(source));
    REQUIRE(lexed);
    auto ast_result = parse_file(lexed.value());
    REQUIRE(ast_result);
    std::unique_ptr<AstFile> ast(ast_result.value());
    auto hir_result = analyze_file(*ast);
    REQUIRE(hir_result);
    std::unique_ptr<HirModule> hir(hir_result.value());
    auto mir_result = build_mir(*hir);
    REQUIRE(mir_result);
    std::unique_ptr<MirModule> mir(mir_result.value());

    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(*mir, rir));
    REQUIRE(rir::verify_module(rir.module).ok);
    REQUIRE_EQ(rir.module.redirect_policy_count, 1u);
    CHECK_EQ(rir.module.redirect_policies[0].status_code, 302u);
    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(cfg.redirect_policy_id_is_valid(1));
    CHECK_EQ(cfg.redirect_policies[0].status_code, 302u);
    CHECK(cfg.redirect_policies[0].reason.eq(lit_str("Moved Temporarily")));
    CHECK(cfg.redirect_policies[0].body.eq(lit_str("fixed-302")));
    CHECK_NE(cfg.redirect_policies[0].reason.ptr, rir.module.redirect_policies[0].reason.ptr);
    rir.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
