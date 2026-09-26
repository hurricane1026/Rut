#include "rut/envoy/json.h"
#include "rut/envoy/parser.h"
#include "test.h"
#include <string>

using namespace rut;

namespace {

Str str(const std::string& s) {
    return Str{s.data(), static_cast<u32>(s.size())};
}

std::string to_string(Str s) {
    return std::string(s.ptr, s.len);
}

// The milestone bootstrap from docs/envoy-converter.md, split so each test
// can replace exactly one piece. Rendered with one JSON value per line so
// line numbers in diagnostics are stable and easy to assert.
struct Bootstrap {
    std::string top_extra;
    std::string static_extra;
    std::string listeners = R"([{
"name": "ingress",
"address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
"filter_chains": [{"filters": [{
"name": "envoy.filters.network.http_connection_manager",
"typed_config": {
"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
"stat_prefix": "ingress",
"codec_type": "HTTP1",
"generate_request_id": false,
"route_config": {"name": "local", "virtual_hosts": [{
"name": "all",
"domains": ["*"],
"routes": [{"match": {"prefix": "/"}, "route": {"cluster": "backend"}}]
}]},
"http_filters": [{"name": "envoy.filters.http.router",
"typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]
}}]}]
}])";
    std::string clusters = R"([{
"name": "backend",
"type": "STATIC",
"connect_timeout": "5s",
"load_assignment": {"cluster_name": "backend", "endpoints": [{"lb_endpoints": [{
"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9000}}}
}]}]}
}])";

    [[nodiscard]] std::string render() const {
        std::string out = "{\n";
        out += top_extra;
        out += "\"static_resources\": {\n";
        out += static_extra;
        out += "\"listeners\": " + listeners + ",\n";
        out += "\"clusters\": " + clusters + "\n";
        out += "}\n}\n";
        return out;
    }
};

// Replace the first occurrence of `from` with `to`; the test fails if absent.
bool replace(std::string* text, const std::string& from, const std::string& to) {
    const auto pos = text->find(from);
    if (pos == std::string::npos) return false;
    text->replace(pos, from.size(), to);
    return true;
}

struct Rejection {
    FrontendError code;
    std::string detail;
};

// Parse and expect a diagnostic with the given code whose detail contains
// `detail`. Returns the diagnostic span for position assertions. `_tc` is
// the calling test's context so failures are attributed to it.
Span expect_reject_impl(rut::test::TestCase* _tc,
                        const std::string& text,
                        FrontendError code,
                        const std::string& detail,
                        const char* label) {
    static envoy::JsonDocument doc;
    auto result = envoy::parse_bootstrap_json(str(text), doc);
    if (result) {
        rut::test::out("    case: ");
        rut::test::out(label);
        rut::test::out("\n");
        CHECK_MSG(false, "expected rejection but the bootstrap was accepted");
        return {};
    }
    const std::string got = to_string(result.error().detail);
    if (result.error().code != code || got.find(detail) == std::string::npos) {
        rut::test::out("    case: ");
        rut::test::out(label);
        rut::test::out("\n");
    }
    CHECK_EQ(static_cast<int>(result.error().code), static_cast<int>(code));
    CHECK_MSG(got.find(detail) != std::string::npos, got.c_str());
    return result.error().span;
}

#define expect_reject(text, code, detail) \
    expect_reject_impl(_tc, (text), (code), (detail), (detail))
#define expect_reject_labeled(text, code, detail, label) \
    expect_reject_impl(_tc, (text), (code), (detail), (label))

std::string line_at(const std::string& text, u32 line) {
    u32 current = 1;
    size_t start = 0;
    while (current < line) {
        start = text.find('\n', start);
        if (start == std::string::npos) return {};
        start++;
        current++;
    }
    const auto end = text.find('\n', start);
    return text.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

}  // namespace

// ── JSON document parser ─────────────────────────────────────────────

TEST(envoy_json, parses_milestone_document_with_spans_and_lookup) {
    const std::string text = Bootstrap{}.render();
    static envoy::JsonDocument doc;
    auto root = envoy::parse_json(str(text), doc);
    REQUIRE(root);
    CHECK_EQ(doc.root, root.value());
    const envoy::JsonNode& top = doc.at(root.value());
    CHECK(top.kind == envoy::JsonKind::Object);
    CHECK_EQ(top.child_count, 1u);
    CHECK_EQ(top.span.start, 0u);
    CHECK_EQ(top.span.end, static_cast<u32>(text.size() - 1u));
    CHECK_EQ(top.span.line, 1u);
    CHECK_EQ(top.span.col, 1u);

    const u32 resources = doc.member(root.value(), lit_str("static_resources"));
    REQUIRE_NE(resources, envoy::kJsonNoNode);
    CHECK(doc.at(resources).has_key);
    CHECK(doc.at(resources).key.eq(lit_str("static_resources")));
    CHECK_EQ(doc.at(resources).key_span.line, 2u);
    CHECK_EQ(doc.at(resources).key_span.col, 1u);
    CHECK_EQ(doc.member(root.value(), lit_str("staticResources")), envoy::kJsonNoNode);
    CHECK_EQ(doc.member(resources, lit_str("nope")), envoy::kJsonNoNode);
    CHECK_EQ(doc.member(envoy::kJsonNoNode, lit_str("x")), envoy::kJsonNoNode);

    const u32 listeners = doc.member(resources, lit_str("listeners"));
    REQUIRE_NE(listeners, envoy::kJsonNoNode);
    CHECK(doc.at(listeners).kind == envoy::JsonKind::Array);
    CHECK_EQ(doc.at(listeners).child_count, 1u);
    const u32 listener = doc.at(listeners).first_child;
    const u32 name = doc.member(listener, lit_str("name"));
    REQUIRE_NE(name, envoy::kJsonNoNode);
    CHECK(doc.at(name).is_plain());
    CHECK(doc.at(name).raw.eq(lit_str("ingress")));
    CHECK_EQ(doc.at(name).span.line, 4u);
    CHECK_EQ(doc.at(name).span.col, 9u);
    // The value span includes both quotes.
    CHECK_EQ(doc.at(name).span.end - doc.at(name).span.start, 9u);

    const u32 address = doc.member(listener, lit_str("address"));
    const u32 socket = doc.member(address, lit_str("socket_address"));
    const u32 port = doc.member(socket, lit_str("port_value"));
    REQUIRE_NE(port, envoy::kJsonNoNode);
    u32 port_value = 0;
    CHECK(envoy::json_u32(doc.at(port), &port_value));
    CHECK_EQ(port_value, 8080u);
    CHECK(doc.at(port).raw.eq(lit_str("8080")));
}

TEST(envoy_json, scalar_values_and_escapes) {
    static envoy::JsonDocument doc;
    const std::string text = R"({"a": true, "b": false, "c": null, "d": "x\ny", "e": "\u00e9"})";
    auto root = envoy::parse_json(str(text), doc);
    REQUIRE(root);
    CHECK_EQ(doc.at(root.value()).child_count, 5u);
    const u32 a = doc.member(root.value(), lit_str("a"));
    CHECK(doc.at(a).kind == envoy::JsonKind::Bool);
    CHECK(doc.at(a).bool_value);
    const u32 b = doc.member(root.value(), lit_str("b"));
    CHECK(doc.at(b).kind == envoy::JsonKind::Bool);
    CHECK_FALSE(doc.at(b).bool_value);
    CHECK(doc.at(doc.member(root.value(), lit_str("c"))).kind == envoy::JsonKind::Null);
    const u32 d = doc.member(root.value(), lit_str("d"));
    CHECK(doc.at(d).has_escape);
    CHECK_FALSE(doc.at(d).is_plain());
    CHECK(doc.at(d).raw.eq(lit_str("x\\ny")));
    CHECK(doc.at(doc.member(root.value(), lit_str("e"))).has_escape);
}

TEST(envoy_json, rejects_escaped_object_keys) {
    static envoy::JsonDocument doc;

    // A lone escaped key, no duplicate involved: rejected outright.
    {
        const std::string text = R"({"\u0061": 1})";
        auto result = envoy::parse_json(str(text), doc);
        REQUIRE_FALSE(result);
        CHECK(result.error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(result.error().detail).find("escaped object keys") != std::string::npos);
        CHECK_EQ(result.error().span.line, 1u);
        CHECK_EQ(result.error().span.col, 2u);
    }

    // An escaped spelling of a key that duplicates an earlier plain key:
    // rejected as an escaped key (at the second key's span), not merely as a
    // duplicate. Both names decode to "a", but the JSON layer never decodes
    // keys, so it refuses the escape instead of comparing decoded values.
    {
        const std::string text = R"({"a": 1, "\u0061": 2})";
        auto result = envoy::parse_json(str(text), doc);
        REQUIRE_FALSE(result);
        CHECK(result.error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(result.error().detail).find("escaped object keys") != std::string::npos);
        CHECK_EQ(result.error().span.line, 1u);
        CHECK_EQ(result.error().span.col, 10u);
    }
}

TEST(envoy_json, accepts_well_formed_utf8_and_surrogate_pairs) {
    static envoy::JsonDocument doc;
    // Raw (unescaped) UTF-8: 2-byte (e with acute), 3-byte (euro sign), and
    // 4-byte (a non-BMP emoji) sequences, plus an escaped surrogate pair
    // spelling the same non-BMP code point.
    const std::string text =
        "{\"a\": \"caf\xC3\xA9\", \"b\": \"\xE2\x82\xAC\", \"c\": \"\xF0\x9F\x98\x80\", "
        "\"d\": \"\\uD83D\\uDE00\"}";
    auto root = envoy::parse_json(str(text), doc);
    REQUIRE(root);
    CHECK_FALSE(doc.at(doc.member(root.value(), lit_str("a"))).has_escape);
    CHECK_FALSE(doc.at(doc.member(root.value(), lit_str("b"))).has_escape);
    CHECK_FALSE(doc.at(doc.member(root.value(), lit_str("c"))).has_escape);
    CHECK(doc.at(doc.member(root.value(), lit_str("d"))).has_escape);
}

TEST(envoy_json, rejects_malformed_utf8_and_lone_surrogates) {
    static envoy::JsonDocument doc;
    struct Case {
        const char* text;
        u32 line;
        u32 col;
    };
    const Case cases[] = {
        // Lone continuation byte.
        {"\"\x80\"", 1, 2},
        // Overlong 2-byte encoding of U+0000.
        {"\"\xC0\x80\"", 1, 2},
        // Truncated 2-byte sequence (closing quote where a continuation
        // byte was required).
        {"\"\xC3\"", 1, 3},
        // Truncated 3-byte sequence, cut off by the end of input.
        {"\"\xE2\x82", 1, 4},
        // Surrogate half D800 encoded directly in UTF-8 (0xED 0xA0 0x80):
        // the second byte is outside 0xED's restricted 0x80-0x9F range.
        {"\"\xED\xA0\x80\"", 1, 3},
        // Code point above U+10FFFF (0xF4 0x90 0x80 0x80 = U+110000): the
        // second byte is outside 0xF4's restricted 0x80-0x8F range.
        {"\"\xF4\x90\x80\x80\"", 1, 3},
        // Invalid lead bytes.
        {"\"\xF5\x80\x80\x80\"", 1, 2},
        {"\"\xFF\"", 1, 2},
        // High surrogate followed by a non-surrogate escape.
        {"\"\\uD800\\u0041\"", 1, 2},
        // High surrogate followed by a raw ASCII byte.
        {"\"\\uD800x\"", 1, 2},
        // Lone low surrogate.
        {"\"\\uDC00\"", 1, 2},
        // High surrogate at the end of the string with no pairing escape.
        {"\"\\uD800\"", 1, 2},
        // Two consecutive high surrogates.
        {"\"\\uD800\\uD801\"", 1, 2},
    };
    for (const Case& c : cases) {
        auto result =
            envoy::parse_json(Str{c.text, static_cast<u32>(__builtin_strlen(c.text))}, doc);
        CHECK_MSG(!result, c.text);
        if (result) continue;
        CHECK_MSG(result.error().code == FrontendError::UnexpectedChar, c.text);
        CHECK_MSG(result.error().span.line == c.line, c.text);
        CHECK_MSG(result.error().span.col == c.col, c.text);
    }
}

TEST(envoy_json, numbers) {
    static envoy::JsonDocument doc;
    const std::string text = R"([0, 65535, 4294967295, 4294967296, -1, 1.5, 1e3, 007])";
    auto root = envoy::parse_json(str(text), doc);
    // 007 has a leading zero: the whole text is rejected.
    REQUIRE_FALSE(root);
    CHECK(root.error().code == FrontendError::InvalidInteger);

    const std::string ok = R"([0, 65535, 4294967295, 4294967296, -1, 1.5, 1e3, 1E+2, 0.0])";
    root = envoy::parse_json(str(ok), doc);
    REQUIRE(root);
    CHECK_EQ(doc.at(root.value()).child_count, 9u);
    const bool expected[] = {true, true, true, false, false, false, false, false, false};
    u32 i = 0;
    for (u32 c = doc.at(root.value()).first_child; c != envoy::kJsonNoNode;
         c = doc.at(c).next_sibling, i++) {
        u32 value = 0;
        CHECK_EQ(envoy::json_u32(doc.at(c), &value), expected[i]);
    }
    CHECK_EQ(i, 9u);
}

TEST(envoy_json, rejects_malformed_text) {
    static envoy::JsonDocument doc;
    struct Case {
        const char* text;
        FrontendError code;
        u32 line;
        u32 col;
    };
    const Case cases[] = {
        {"", FrontendError::UnexpectedEof, 1, 1},
        {"   \n ", FrontendError::UnexpectedEof, 2, 2},
        {"{} x", FrontendError::UnexpectedChar, 1, 4},
        {"{\"a\": 1,}", FrontendError::UnexpectedChar, 1, 9},
        {"[1,]", FrontendError::UnexpectedChar, 1, 4},
        {"{a: 1}", FrontendError::UnexpectedChar, 1, 2},
        {"{\"a\" 1}", FrontendError::UnexpectedChar, 1, 6},
        {"{\"a\": 1 \"b\": 2}", FrontendError::UnexpectedChar, 1, 9},
        {"{\"a\": 1, \"a\": 2}", FrontendError::UnexpectedToken, 1, 10},
        {"\"abc", FrontendError::UnterminatedString, 1, 1},
        {"\"a\tb\"", FrontendError::UnexpectedChar, 1, 3},
        {"\"a\\qb\"", FrontendError::UnexpectedChar, 1, 4},
        {"\"\\u12G4\"", FrontendError::UnexpectedChar, 1, 6},
        {"// c\n{}", FrontendError::UnexpectedChar, 1, 1},
        {"{\"a\": tru}", FrontendError::UnexpectedChar, 1, 7},
        {"{\"a\": NaN}", FrontendError::UnexpectedChar, 1, 7},
        {"[1", FrontendError::UnexpectedEof, 1, 3},
        {"{\"a\": ", FrontendError::UnexpectedEof, 1, 7},
        {"-", FrontendError::InvalidInteger, 1, 2},
        {"1.", FrontendError::InvalidInteger, 1, 3},
        {"1e", FrontendError::InvalidInteger, 1, 3},
        {"01", FrontendError::InvalidInteger, 1, 2},
    };
    for (const Case& c : cases) {
        auto result =
            envoy::parse_json(Str{c.text, static_cast<u32>(__builtin_strlen(c.text))}, doc);
        CHECK_MSG(!result, c.text);
        if (result) continue;
        CHECK_MSG(result.error().code == c.code, c.text);
        CHECK_MSG(result.error().span.line == c.line, c.text);
        CHECK_MSG(result.error().span.col == c.col, c.text);
    }
}

TEST(envoy_json, bounded_depth_and_node_capacity) {
    static envoy::JsonDocument doc;
    std::string deep;
    for (u32 i = 0; i <= envoy::kMaxJsonDepth + 1u; i++) deep += '[';
    for (u32 i = 0; i <= envoy::kMaxJsonDepth + 1u; i++) deep += ']';
    auto result = envoy::parse_json(str(deep), doc);
    REQUIRE_FALSE(result);
    CHECK(result.error().code == FrontendError::TooManyItems);
    CHECK(to_string(result.error().detail).find("depth") != std::string::npos);

    std::string exact;
    for (u32 i = 0; i <= envoy::kMaxJsonDepth; i++) exact += '[';
    for (u32 i = 0; i <= envoy::kMaxJsonDepth; i++) exact += ']';
    CHECK(envoy::parse_json(str(exact), doc));

    std::string wide = "[";
    for (u32 i = 0; i < envoy::kMaxJsonNodes; i++) wide += i == 0 ? "0" : ",0";
    wide += "]";
    result = envoy::parse_json(str(wide), doc);
    REQUIRE_FALSE(result);
    CHECK(result.error().code == FrontendError::TooManyItems);
    CHECK(to_string(result.error().detail).find("capacity") != std::string::npos);

    std::string fits = "[";
    for (u32 i = 0; i < envoy::kMaxJsonNodes - 1u; i++) fits += i == 0 ? "0" : ",0";
    fits += "]";
    result = envoy::parse_json(str(fits), doc);
    REQUIRE(result);
    CHECK_EQ(doc.nodes.len, envoy::kMaxJsonNodes);
}

// PR #691 round 3: the duplicate-key scan in JsonDocument::member is a
// linear scan of prior members, quadratic in the number of members of one
// object. Worst-case keys share a long common prefix (so byte comparison
// cannot bail out early on the first byte) and are all the same length (so
// the length pre-check in Str::eq cannot bail out either). This exercises
// the object-member cap that bounds that scan independently of the overall
// node budget.
TEST(envoy_json, bounded_object_member_count) {
    static envoy::JsonDocument doc;
    const std::string prefix(230, 'a');

    std::string at_cap = "{";
    for (u32 i = 0; i < envoy::kMaxJsonObjectMembers; i++) {
        if (i) at_cap += ",";
        at_cap += "\"" + prefix + std::to_string(i) + "\":0";
    }
    at_cap += "}";
    auto result = envoy::parse_json(str(at_cap), doc);
    REQUIRE(result);
    CHECK_EQ(doc.at(doc.root).child_count, envoy::kMaxJsonObjectMembers);

    std::string over_cap = at_cap.substr(0, at_cap.size() - 1);
    over_cap += ",\"" + prefix + std::to_string(envoy::kMaxJsonObjectMembers) + "\":0}";
    result = envoy::parse_json(str(over_cap), doc);
    REQUIRE_FALSE(result);
    CHECK(result.error().code == FrontendError::TooManyItems);
    CHECK(to_string(result.error().detail).find("member") != std::string::npos);
}

// ── Envoy semantic model ─────────────────────────────────────────────

TEST(envoy_parser, accepts_milestone_bootstrap) {
    const std::string text = Bootstrap{}.render();
    static envoy::JsonDocument doc;
    auto result = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(result);
    const envoy::Bootstrap& b = result.value();
    CHECK_EQ(b.span.start, 0u);
    CHECK_EQ(b.span.end, static_cast<u32>(text.size() - 1u));

    CHECK(b.listener.name.eq(lit_str("ingress")));
    CHECK_EQ(b.listener.name_span.line, 4u);
    CHECK_EQ(b.listener.address.ipv4_host, 0u);
    CHECK_EQ(b.listener.address.port, 8080u);
    CHECK(b.listener.address.address_text.eq(lit_str("0.0.0.0")));
    CHECK_EQ(b.listener.address.address_span.line, 5u);
    CHECK_EQ(b.listener.address.port_span.line, 5u);
    CHECK_EQ(line_at(text, b.listener.address.span.line).find("\"address\""), 0u);
    CHECK(b.listener.filter_chain.filter_name.eq(
        lit_str("envoy.filters.network.http_connection_manager")));

    const envoy::HttpConnectionManager& hcm = b.listener.filter_chain.hcm;
    CHECK(hcm.stat_prefix.eq(lit_str("ingress")));
    CHECK_EQ(hcm.stat_prefix_span.line, 10u);
    CHECK(hcm.codec_type_present);
    CHECK(hcm.codec_type == envoy::CodecType::Http1);
    CHECK_EQ(hcm.codec_type_span.line, 11u);
    CHECK_EQ(hcm.generate_request_id_span.line, 12u);
    CHECK_EQ(hcm.type_url_span.line, 9u);
    CHECK(hcm.route_config.name.eq(lit_str("local")));
    CHECK(hcm.route_config.virtual_host.name.eq(lit_str("all")));
    CHECK_EQ(hcm.route_config.virtual_host.domains_span.line, 15u);
    CHECK(hcm.route_config.virtual_host.routes[0].match.prefix.eq(lit_str("/")));
    CHECK_EQ(hcm.route_config.virtual_host.routes[0].match.prefix_span.line, 16u);
    CHECK(hcm.route_config.virtual_host.routes[0].action.cluster.eq(lit_str("backend")));
    CHECK(hcm.router.name.eq(lit_str("envoy.filters.http.router")));
    CHECK(hcm.router.has_typed_config);
    CHECK_EQ(hcm.router.typed_config_span.line, 19u);

    CHECK(b.clusters[0].name.eq(lit_str("backend")));
    CHECK_EQ(b.clusters[0].name_span.line, 23u);
    CHECK(b.clusters[0].type_present);
    CHECK_EQ(b.clusters[0].type_span.line, 24u);
    CHECK_EQ(b.clusters[0].connect_timeout.milliseconds, 5000u);
    CHECK(b.clusters[0].connect_timeout.text.eq(lit_str("5s")));
    CHECK_EQ(b.clusters[0].connect_timeout.span.line, 25u);
    CHECK(b.clusters[0].load_assignment_name_present);
    // PR #692 round-12 review, ported: `load_assignment_name` retains the
    // parsed `load_assignment.cluster_name` value itself (not just the
    // presence bit), so lowering can revalidate it against `name` at use
    // time rather than trusting historical presence.
    CHECK(b.clusters[0].load_assignment_name.eq(lit_str("backend")));
    CHECK_EQ(b.clusters[0].endpoint.address.ipv4_host, 0x7f000001u);
    CHECK_EQ(b.clusters[0].endpoint.address.port, 9000u);
    CHECK_EQ(b.clusters[0].endpoint.address.address_span.line, 27u);
    CHECK_EQ(b.clusters[0].endpoint.span.line, 27u);
}

TEST(envoy_parser, accepts_camel_case_spellings_and_optional_fields) {
    Bootstrap b;
    std::string listeners = b.listeners;
    REQUIRE(replace(&listeners, "\"filter_chains\"", "\"filterChains\""));
    REQUIRE(replace(&listeners, "\"socket_address\"", "\"socketAddress\""));
    REQUIRE(replace(&listeners, "\"port_value\"", "\"portValue\""));
    REQUIRE(replace(&listeners, "\"typed_config\"", "\"typedConfig\""));
    REQUIRE(replace(&listeners, "\"stat_prefix\"", "\"statPrefix\""));
    REQUIRE(replace(&listeners, "\"generate_request_id\"", "\"generateRequestId\""));
    REQUIRE(replace(&listeners, "\"route_config\"", "\"routeConfig\""));
    REQUIRE(replace(&listeners, "\"virtual_hosts\"", "\"virtualHosts\""));
    REQUIRE(replace(&listeners, "\"http_filters\"", "\"httpFilters\""));
    REQUIRE(replace(&listeners, "\"codec_type\"", "\"codecType\""));
    // Optional pieces removed: listener name, route_config name, router
    // typed_config. codec_type and load_assignment.cluster_name are
    // required, so they stay, renamed to their camelCase spelling.
    REQUIRE(replace(&listeners, "\"name\": \"ingress\",\n", ""));
    REQUIRE(replace(&listeners, "\"name\": \"local\", ", ""));
    REQUIRE(replace(&listeners,
                    ",\n\"typed_config\": {\"@type\": "
                    "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\"}",
                    ""));
    b.listeners = listeners;
    std::string clusters = b.clusters;
    REQUIRE(replace(&clusters, "\"connect_timeout\"", "\"connectTimeout\""));
    REQUIRE(replace(&clusters, "\"load_assignment\"", "\"loadAssignment\""));
    REQUIRE(replace(&clusters, "\"lb_endpoints\"", "\"lbEndpoints\""));
    REQUIRE(replace(&clusters, "\"cluster_name\"", "\"clusterName\""));
    REQUIRE(replace(&clusters, "\"type\": \"STATIC\",\n", ""));
    REQUIRE(replace(&clusters, "\"5s\"", "\"1.250s\""));
    b.clusters = clusters;
    std::string text = b.render();
    REQUIRE(replace(&text, "\"static_resources\"", "\"staticResources\""));

    static envoy::JsonDocument doc;
    auto result = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(result);
    CHECK_EQ(result.value().listener.name.len, 0u);
    CHECK_EQ(result.value().listener.filter_chain.hcm.route_config.name.len, 0u);
    CHECK_FALSE(result.value().listener.filter_chain.hcm.router.has_typed_config);
    CHECK(result.value().listener.filter_chain.hcm.codec_type_present);
    CHECK(result.value().listener.filter_chain.hcm.codec_type == envoy::CodecType::Http1);
    CHECK_FALSE(result.value().clusters[0].type_present);
    CHECK(result.value().clusters[0].load_assignment_name_present);
    CHECK(result.value().clusters[0].load_assignment_name.eq(lit_str("backend")));
    CHECK_EQ(result.value().clusters[0].connect_timeout.milliseconds, 1250u);
    CHECK_EQ(result.value().listener.address.port, 8080u);
    CHECK_EQ(result.value().clusters[0].endpoint.address.port, 9000u);
}

TEST(envoy_parser, rejects_both_spellings_of_one_field) {
    Bootstrap b;
    REQUIRE(replace(&b.clusters,
                    "\"connect_timeout\": \"5s\",",
                    "\"connect_timeout\": \"5s\", \"connectTimeout\": \"5s\","));
    const std::string text = b.render();
    const Span span =
        expect_reject(text, FrontendError::UnexpectedToken, "both snake_case and camelCase");
    CHECK_EQ(span.line, 25u);
    CHECK_EQ(line_at(text, span.line).find("\"connectTimeout\""),
             static_cast<size_t>(span.col - 1u));
}

TEST(envoy_parser, rejects_unknown_fields_at_their_key) {
    struct Case {
        const char* from;
        const char* to;
    };
    const Case cases[] = {
        {"\"static_resources\": {", "\"admin\": {}, \"static_resources\": {"},
        {"\"static_resources\": {", "\"node\": {\"id\": \"x\"}, \"static_resources\": {"},
        {"\"static_resources\": {", "\"dynamic_resources\": {}, \"static_resources\": {"},
        {"\"listeners\": ", "\"secrets\": [], \"listeners\": "},
        {"\"name\": \"ingress\",", "\"name\": \"ingress\", \"listener_filters\": [],"},
        {"\"name\": \"ingress\",", "\"name\": \"ingress\", \"additional_addresses\": [],"},
        {"\"port_value\": 8080", "\"port_value\": 8080, \"protocol\": \"TCP\""},
        {"\"filter_chains\": [{", "\"filter_chains\": [{\"filter_chain_match\": {},"},
        {"\"filter_chains\": [{", "\"filter_chains\": [{\"transport_socket\": {},"},
        {"\"stat_prefix\": \"ingress\",", "\"stat_prefix\": \"ingress\", \"access_log\": [],"},
        {"\"stat_prefix\": \"ingress\",", "\"stat_prefix\": \"ingress\", \"tracing\": {},"},
        {"\"stat_prefix\": \"ingress\",",
         "\"stat_prefix\": \"ingress\", \"use_remote_address\": true,"},
        {"\"stat_prefix\": \"ingress\",", "\"stat_prefix\": \"ingress\", \"server_name\": \"x\","},
        {"\"name\": \"all\",", "\"name\": \"all\", \"request_headers_to_add\": [],"},
        {"\"match\": {\"prefix\": \"/\"}", "\"match\": {\"prefix\": \"/\", \"headers\": []}"},
        {"\"route\": {\"cluster\": \"backend\"}",
         "\"route\": {\"cluster\": \"backend\", \"prefix_rewrite\": \"/\"}"},
        {"\"route\": {\"cluster\": \"backend\"}",
         "\"route\": {\"cluster\": \"backend\", \"retry_policy\": {}}"},
        {"\"name\": \"backend\",", "\"name\": \"backend\", \"lb_policy\": \"ROUND_ROBIN\","},
        {"\"name\": \"backend\",", "\"name\": \"backend\", \"health_checks\": [],"},
        {"\"name\": \"backend\",", "\"name\": \"backend\", \"circuit_breakers\": {},"},
        {"\"name\": \"backend\",", "\"name\": \"backend\", \"transport_socket\": {},"},
        {"\"endpoints\": [{", "\"endpoints\": [{\"locality\": {},"},
        {"\"endpoint\": {", "\"load_balancing_weight\": 1, \"endpoint\": {"},
        {"\"endpoint\": {\"address\"", "\"endpoint\": {\"health_check_config\": {}, \"address\""},
    };
    for (const Case& c : cases) {
        std::string text = Bootstrap{}.render();
        REQUIRE_MSG(replace(&text, c.from, c.to), c.from);
        const Span span = expect_reject_labeled(
            text, FrontendError::UnsupportedSyntax, "unsupported field", c.to);
        // The diagnostic points at the key, not the enclosing object.
        const std::string line = line_at(text, span.line);
        CHECK_MSG(span.col >= 1u && span.col - 1u < line.size() && line[span.col - 1u] == '"',
                  c.to);
    }
}

TEST(envoy_parser, rejects_shapes_outside_the_milestone_boundary) {
    struct Case {
        const char* from;
        const char* to;
        FrontendError code;
        const char* detail;
    };
    const Case cases[] = {
        // Listener / address
        {"\"listeners\": [{",
         "\"listeners\": [{}, {",
         FrontendError::UnsupportedSyntax,
         "multiple listeners"},
        {"\"address\": {\"socket_address\"",
         "\"address\": {\"pipe\"",
         FrontendError::UnsupportedSyntax,
         "unsupported field"},
        {"\"address\": \"0.0.0.0\"",
         "\"address\": \"::\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"address\": \"0.0.0.0\"",
         "\"address\": \"localhost\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"address\": \"0.0.0.0\"",
         "\"address\": \"01.0.0.0\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"address\": \"0.0.0.0\"",
         "\"address\": \"256.0.0.0\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"address\": \"0.0.0.0\"",
         "\"address\": \"0.0.0\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"address\": \"0.0.0.0\"",
         "\"address\": \"0.0.0.0.\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"port_value\": 8080", "\"port_value\": 0", FrontendError::UnexpectedToken, "1..65535"},
        {"\"port_value\": 8080",
         "\"port_value\": 65536",
         FrontendError::UnexpectedToken,
         "1..65535"},
        {"\"port_value\": 8080",
         "\"port_value\": \"8080\"",
         FrontendError::UnexpectedToken,
         "integer"},
        {"\"port_value\": 8080",
         "\"port_value\": 8080.0",
         FrontendError::UnexpectedToken,
         "integer"},
        {", \"port_value\": 8080}", "}", FrontendError::UnexpectedEof, "port_value is required"},
        {"\"filter_chains\": [{",
         "\"filter_chains\": [{}, {",
         FrontendError::UnsupportedSyntax,
         "multiple filter chains"},
        // Network filter
        {"\"filters\": [{",
         "\"filters\": [{\"name\": \"envoy.filters.network.tcp_proxy\"}, {",
         FrontendError::UnsupportedSyntax,
         "additional network filters"},
        {"envoy.filters.network.http_connection_manager",
         "envoy.filters.network.tcp_proxy",
         FrontendError::UnsupportedSyntax,
         "HTTP connection manager"},
        {"http_connection_manager.v3.HttpConnectionManager",
         "http_connection_manager.v2.HttpConnectionManager",
         FrontendError::UnsupportedSyntax,
         "v3 HttpConnectionManager"},
        {"\"@type\": "
         "\"type.googleapis.com/"
         "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\",\n",
         "",
         FrontendError::UnexpectedEof,
         "@type"},
        {"\"stat_prefix\": \"ingress\",\n", "", FrontendError::UnexpectedEof, "stat_prefix"},
        {"\"stat_prefix\": \"ingress\"",
         "\"stat_prefix\": \"\"",
         FrontendError::UnexpectedToken,
         "stat_prefix"},
        {"\"codec_type\": \"HTTP1\",\n",
         "",
         FrontendError::UnexpectedEof,
         "codec_type is required"},
        {"\"codec_type\": \"HTTP1\"",
         "\"codec_type\": \"AUTO\"",
         FrontendError::UnsupportedSyntax,
         "AUTO permits downstream HTTP/2"},
        {"\"codec_type\": \"HTTP1\"",
         "\"codec_type\": \"HTTP2\"",
         FrontendError::UnsupportedSyntax,
         "codec_type"},
        {"\"codec_type\": \"HTTP1\"",
         "\"codec_type\": \"HTTP3\"",
         FrontendError::UnsupportedSyntax,
         "codec_type"},
        // generate_request_id
        {"\"generate_request_id\": false,\n",
         "",
         FrontendError::UnexpectedEof,
         "generate_request_id: false"},
        {"\"generate_request_id\": false",
         "\"generate_request_id\": true",
         FrontendError::UnsupportedSyntax,
         "x-request-id"},
        {"\"generate_request_id\": false",
         "\"generate_request_id\": \"false\"",
         FrontendError::UnexpectedToken,
         "boolean"},
        // Routes
        {"\"route_config\": {\"name\": \"local\", ",
         "\"rds\": {\"route_config_name\": \"x\"}, \"route_config\": {",
         FrontendError::UnsupportedSyntax,
         "unsupported field"},
        {"\"virtual_hosts\": [{",
         "\"virtual_hosts\": [{}, {",
         FrontendError::UnsupportedSyntax,
         "multiple virtual hosts"},
        {"\"name\": \"all\",\n", "", FrontendError::UnexpectedEof, "virtual host name"},
        {"\"domains\": [\"*\"]",
         "\"domains\": [\"example.com\"]",
         FrontendError::UnsupportedSyntax,
         "host matching"},
        {"\"domains\": [\"*\"]",
         "\"domains\": [\"*\", \"example.com\"]",
         FrontendError::UnsupportedSyntax,
         "host matching"},
        {"\"domains\": [\"*\"]", "\"domains\": []", FrontendError::UnexpectedEof, "domains"},
        // An empty route object ahead of the (still valid) existing route: no
        // longer "multiple routes are unsupported" now that route lists are
        // bounded, but the empty object itself is still missing its match.
        {"\"routes\": [{",
         "\"routes\": [{}, {",
         FrontendError::UnexpectedEof,
         "route match is required"},
        {"\"match\": {\"prefix\": \"/\"}", "\"match\": {}", FrontendError::UnexpectedEof, "prefix"},
        {"\"match\": {\"prefix\": \"/\"}",
         "\"match\": {\"prefix\": \"/\", \"path\": \"/\"}",
         FrontendError::UnexpectedToken,
         "exactly one of prefix or path"},
        {"\"prefix\": \"/\"",
         "\"prefix\": \"/api\"",
         FrontendError::UnsupportedSyntax,
         "prefixes ending in"},
        {"\"prefix\": \"/\"",
         "\"prefix\": \"\"",
         FrontendError::UnsupportedSyntax,
         "prefixes ending in"},
        {"\"prefix\": \"/\"",
         "\"prefix\": \"/a?b\"",
         FrontendError::UnsupportedSyntax,
         "excluding ?, #, and %"},
        {"\"route\": {\"cluster\": \"backend\"}",
         "\"route\": {\"weighted_clusters\": {}}",
         FrontendError::UnsupportedSyntax,
         "unsupported field"},
        {"\"route\": {\"cluster\": \"backend\"}",
         "\"route\": {\"cluster\": \"other\"}",
         FrontendError::UnexpectedToken,
         "declared cluster"},
        {"\"route\": {\"cluster\": \"backend\"}",
         "\"route\": {\"cluster\": \"\"}",
         FrontendError::UnexpectedToken,
         "route cluster"},
        // HTTP filters
        {"\"http_filters\": [{",
         "\"http_filters\": [{\"name\": \"envoy.filters.http.cors\"}, {",
         FrontendError::UnsupportedSyntax,
         "other than the router"},
        {"\"http_filters\": [{",
         "\"http_filters\": [{}, {",
         FrontendError::UnsupportedSyntax,
         "other than the router"},
        {"envoy.filters.http.router",
         "envoy.filters.http.lua",
         FrontendError::UnsupportedSyntax,
         "other than the router"},
        {"filters.http.router.v3.Router",
         "filters.http.router.v2.Router",
         FrontendError::UnsupportedSyntax,
         "v3 Router"},
        // Cluster
        // An empty cluster object ahead of the (still valid) existing
        // cluster: no longer "multiple clusters are unsupported" now that
        // cluster lists are bounded, but the empty object is missing its name.
        {"\"clusters\": [{",
         "\"clusters\": [{}, {",
         FrontendError::UnexpectedEof,
         "cluster name is required"},
        {"\"name\": \"backend\",\n", "", FrontendError::UnexpectedEof, "cluster name"},
        {"\"type\": \"STATIC\"",
         "\"type\": \"STRICT_DNS\"",
         FrontendError::UnsupportedSyntax,
         "STATIC"},
        {"\"type\": \"STATIC\"",
         "\"type\": \"ORIGINAL_DST\"",
         FrontendError::UnsupportedSyntax,
         "STATIC"},
        {"\"type\": \"STATIC\"", "\"type\": \"EDS\"", FrontendError::UnsupportedSyntax, "STATIC"},
        {"\"type\": \"STATIC\"", "\"type\": 0", FrontendError::UnexpectedToken, "cluster type"},
        {"\"connect_timeout\": \"5s\",\n", "", FrontendError::UnexpectedEof, "connect_timeout"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"0s\"",
         FrontendError::UnexpectedToken,
         "positive"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"0.000s\"",
         FrontendError::UnexpectedToken,
         "positive"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"5\"",
         FrontendError::UnexpectedToken,
         "s suffix"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"s\"",
         FrontendError::UnexpectedToken,
         "s suffix"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"5.s\"",
         FrontendError::UnexpectedToken,
         "s suffix"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"05s\"",
         FrontendError::UnexpectedToken,
         "s suffix"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"-5s\"",
         FrontendError::UnexpectedToken,
         "s suffix"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"5ms\"",
         FrontendError::UnexpectedToken,
         "s suffix"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"0.0001s\"",
         FrontendError::UnsupportedSyntax,
         "finer than milliseconds"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": \"4294968s\"",
         FrontendError::UnsupportedSyntax,
         "too large"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": 5",
         FrontendError::UnexpectedToken,
         "duration"},
        {"\"connect_timeout\": \"5s\"",
         "\"connect_timeout\": {\"seconds\": 5}",
         FrontendError::UnexpectedToken,
         "duration"},
        {"\"cluster_name\": \"backend\"",
         "\"cluster_name\": \"other\"",
         FrontendError::UnexpectedToken,
         "equal the cluster name"},
        {"\"cluster_name\": \"backend\"",
         "\"cluster_name\": \"\"",
         FrontendError::UnexpectedToken,
         "non-empty string"},
        {"\"cluster_name\": \"backend\", ",
         "",
         FrontendError::UnexpectedEof,
         "cluster_name is required"},
        {"\"load_assignment\": {\"cluster_name\": \"backend\", \"endpoints\": [{\"lb_endpoints\": "
         "[{\n"
         "\"endpoint\": {\"address\": {\"socket_address\": {\"address\": \"127.0.0.1\", "
         "\"port_value\": 9000}}}\n"
         "}]}]}",
         "\"load_assignment\": {\"cluster_name\": \"backend\"}",
         FrontendError::UnexpectedEof,
         "endpoints is required"},
        {"\"endpoints\": [{",
         "\"endpoints\": [{}, {",
         FrontendError::UnsupportedSyntax,
         "multiple localities"},
        {"\"lb_endpoints\": [{",
         "\"lb_endpoints\": [{}, {",
         FrontendError::UnsupportedSyntax,
         "multiple endpoints"},
        {"\"lb_endpoints\": [{\n\"endpoint\": {",
         "\"lb_endpoints\": [{\n\"endpoint\": {\"hostname\": \"x\",",
         FrontendError::UnsupportedSyntax,
         "unsupported field"},
        {"\"address\": \"127.0.0.1\"",
         "\"address\": \"127.0.0.1:9000\"",
         FrontendError::UnsupportedSyntax,
         "IPv4"},
        {"\"port_value\": 9000", "\"port_value\": -1", FrontendError::UnexpectedToken, "integer"},
        // Strings with escapes are never silently decoded.
        {"\"name\": \"backend\"",
         "\"name\": \"back\\u0065nd\"",
         FrontendError::UnsupportedSyntax,
         "escaped strings"},
        {"\"address\": \"127.0.0.1\"",
         "\"address\": \"127.0.0.\\u0031\"",
         FrontendError::UnsupportedSyntax,
         "escaped strings"},
        {"\"name\": \"backend\"",
         "\"na\\u006de\": \"backend\"",
         FrontendError::UnsupportedSyntax,
         "escaped object keys"},
    };
    for (const Case& c : cases) {
        std::string text = Bootstrap{}.render();
        REQUIRE_MSG(replace(&text, c.from, c.to), c.from);
        expect_reject_labeled(text, c.code, c.detail, c.to);
    }
}

TEST(envoy_parser, rejects_missing_required_containers_with_parent_span) {
    Bootstrap b;
    std::string text = "{}";
    Span span = expect_reject(text, FrontendError::UnexpectedEof, "static_resources is required");
    CHECK_EQ(span.line, 1u);
    CHECK_EQ(span.col, 1u);

    text = "[]";
    expect_reject(text, FrontendError::UnexpectedToken, "bootstrap must be a JSON object");

    text = "{\"static_resources\": {\"clusters\": []}}";
    span = expect_reject(text, FrontendError::UnexpectedEof, "listeners is required");
    CHECK_EQ(span.col, 22u);

    text = "{\"static_resources\": {\"listeners\": []}}";
    span = expect_reject(text, FrontendError::UnexpectedEof, "at least one listener");
    CHECK_EQ(span.col, 36u);

    text = "{\"static_resources\": {\"listeners\": {}}}";
    expect_reject(text, FrontendError::UnexpectedToken, "expected a JSON array");

    text = "{\"static_resources\": {\"listeners\": [1]}}";
    expect_reject(text, FrontendError::UnexpectedToken, "listener must be an object");

    text = b.render();
    REQUIRE(replace(&text, b.clusters, "[\"backend\"]"));
    expect_reject(text, FrontendError::UnexpectedToken, "cluster must be an object");

    text = b.render();
    REQUIRE(replace(
        &text,
        "\"routes\": [{\"match\": {\"prefix\": \"/\"}, \"route\": {\"cluster\": \"backend\"}}]",
        "\"routes\": [null]"));
    expect_reject(text, FrontendError::UnexpectedToken, "route must be an object");

    text = "{\"static_resources\": []}";
    expect_reject(text, FrontendError::UnexpectedToken, "static_resources must be an object");

    // Syntax errors surface as JSON diagnostics before any model check.
    text = b.render();
    REQUIRE(replace(&text, "\"port_value\": 8080}", "\"port_value\": 8080,}"));
    expect_reject(text, FrontendError::UnexpectedChar, "expected quoted key");
}

TEST(envoy_parser, name_length_is_bounded) {
    Bootstrap b;
    std::string long_name(envoy::kMaxEnvoyNameLen + 1u, 'a');
    std::string text = b.render();
    REQUIRE(replace(&text, "\"name\": \"backend\"", "\"name\": \"" + long_name + "\""));
    expect_reject(text, FrontendError::UnsupportedSyntax, "bounded length");

    std::string max_name(envoy::kMaxEnvoyNameLen, 'a');
    text = b.render();
    REQUIRE(replace(&text, "\"name\": \"backend\"", "\"name\": \"" + max_name + "\""));
    REQUIRE(replace(&text, "\"cluster\": \"backend\"", "\"cluster\": \"" + max_name + "\""));
    REQUIRE(
        replace(&text, "\"cluster_name\": \"backend\"", "\"cluster_name\": \"" + max_name + "\""));
    static envoy::JsonDocument doc;
    auto result = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(result);
    CHECK_EQ(result.value().clusters[0].name.len, envoy::kMaxEnvoyNameLen);
}

// ── Increment 2 fields: route timeout, router suppress_envoy_headers ──────

TEST(envoy_parser, route_timeout_accepts_zero_and_rejects_invalid_forms) {
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"route\": {\"cluster\": \"backend\", \"timeout\": \"0s\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.timeout_present);
        CHECK_EQ(action.timeout.milliseconds, 0u);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"route\": {\"cluster\": \"backend\", \"timeout\": \"15s\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.timeout_present);
        CHECK_EQ(action.timeout.milliseconds, 15000u);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"route\": {\"cluster\": \"backend\", \"timeout\": \"0.250s\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.timeout_present);
        CHECK_EQ(action.timeout.milliseconds, 250u);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"route\": {\"cluster\": \"backend\", \"timeout\": \"abc\"}"));
        expect_reject(b.render(), FrontendError::UnexpectedToken, "s suffix");
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"route\": {\"cluster\": \"backend\", \"timeout\": \"0.0001s\"}"));
        expect_reject(b.render(), FrontendError::UnsupportedSyntax, "finer than milliseconds");
    }
}

TEST(envoy_parser, suppress_envoy_headers_accepts_bool_and_camel_case) {
    static constexpr char kTypedConfig[] =
        "\"typed_config\": {\"@type\": "
        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\"}";
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        kTypedConfig,
                        "\"typed_config\": {\"@type\": "
                        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
                        "\"suppress_envoy_headers\": true}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouterFilter& router = result.value().listener.filter_chain.hcm.router;
        CHECK(router.suppress_envoy_headers_present);
        CHECK(router.suppress_envoy_headers);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        kTypedConfig,
                        "\"typed_config\": {\"@type\": "
                        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
                        "\"suppress_envoy_headers\": false}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouterFilter& router = result.value().listener.filter_chain.hcm.router;
        CHECK(router.suppress_envoy_headers_present);
        CHECK_FALSE(router.suppress_envoy_headers);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        kTypedConfig,
                        "\"typed_config\": {\"@type\": "
                        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
                        "\"suppressEnvoyHeaders\": true}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        CHECK(result.value().listener.filter_chain.hcm.router.suppress_envoy_headers);
    }
}

TEST(envoy_parser, suppress_envoy_headers_rejects_duplicate_and_non_bool) {
    static constexpr char kTypedConfig[] =
        "\"typed_config\": {\"@type\": "
        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\"}";
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        kTypedConfig,
                        "\"typed_config\": {\"@type\": "
                        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
                        "\"suppress_envoy_headers\": true, \"suppressEnvoyHeaders\": true}"));
        expect_reject(b.render(), FrontendError::UnexpectedToken, "both snake_case and camelCase");
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        kTypedConfig,
                        "\"typed_config\": {\"@type\": "
                        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
                        "\"suppress_envoy_headers\": \"true\"}"));
        expect_reject(b.render(), FrontendError::UnexpectedToken, "must be a boolean");
    }
}

// ── Increment 4: bounded route/cluster lists, `path`, direct_response,
//    redirect ─────────────────────────────────────────────────────────

namespace {

std::string forward_route_json(const std::string& match_field,
                               const std::string& match_value,
                               const std::string& cluster) {
    return "{\"match\": {\"" + match_field + "\": \"" + match_value +
           "\"}, \"route\": {\"cluster\": \"" + cluster + "\"}}";
}

std::string cluster_json(const std::string& name, u16 port) {
    return "{\"name\": \"" + name +
           "\", \"type\": \"STATIC\", \"connect_timeout\": \"5s\", \"load_assignment\": "
           "{\"cluster_name\": \"" +
           name +
           "\", \"endpoints\": [{\"lb_endpoints\": [{\"endpoint\": {\"address\": "
           "{\"socket_address\": {\"address\": \"127.0.0.1\", \"port_value\": " +
           std::to_string(port) + "}}}}]}]}}";
}

const char kDefaultRoutesJson[] =
    "\"routes\": [{\"match\": {\"prefix\": \"/\"}, \"route\": {\"cluster\": \"backend\"}}]";

}  // namespace

TEST(envoy_parser, route_match_accepts_prefix_and_path_forms) {
    {
        Bootstrap b;
        REQUIRE(replace(
            &b.listeners, "\"match\": {\"prefix\": \"/\"}", "\"match\": {\"path\": \"/healthz\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteMatch& match =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].match;
        CHECK(match.kind == envoy::RouteMatchKind::Path);
        CHECK(match.path.eq(lit_str("/healthz")));
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners, "\"prefix\": \"/\"", "\"prefix\": \"/api/\""));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteMatch& match =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].match;
        CHECK(match.kind == envoy::RouteMatchKind::Prefix);
        CHECK(match.prefix.eq(lit_str("/api/")));
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners, "\"prefix\": \"/\"", "\"prefix\": \"/\""));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        CHECK(result.value()
                  .listener.filter_chain.hcm.route_config.virtual_host.routes[0]
                  .match.kind == envoy::RouteMatchKind::Prefix);
    }
    {
        // "path" must start with "/".
        Bootstrap b;
        REQUIRE(replace(
            &b.listeners, "\"match\": {\"prefix\": \"/\"}", "\"match\": {\"path\": \"healthz\"}"));
        expect_reject(b.render(), FrontendError::UnsupportedSyntax, "must start with \"/\"");
    }
}

TEST(envoy_parser, routes_list_is_bounded_and_ordered) {
    Bootstrap b;
    std::string routes = "[";
    for (u32 i = 0; i < envoy::kMaxEnvoyRoutes; i++) {
        if (i != 0) routes += ", ";
        routes += forward_route_json("path", "/r" + std::to_string(i), "backend");
    }
    routes += "]";
    REQUIRE(replace(&b.listeners, kDefaultRoutesJson, "\"routes\": " + routes));
    {
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const FixedVec<envoy::Route, envoy::kMaxEnvoyRoutes>& parsed =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes;
        CHECK_EQ(parsed.len, envoy::kMaxEnvoyRoutes);
        for (u32 i = 0; i < envoy::kMaxEnvoyRoutes; i++)
            CHECK(parsed[i].match.path.eq(str("/r" + std::to_string(i))));
    }
    // A 9th route is rejected at its own span, not the array's.
    {
        std::string too_many = "[";
        for (u32 i = 0; i < envoy::kMaxEnvoyRoutes + 1u; i++) {
            if (i != 0) too_many += ", ";
            too_many += forward_route_json("path", "/r" + std::to_string(i), "backend");
        }
        too_many += "]";
        Bootstrap b2;
        REQUIRE(replace(&b2.listeners, kDefaultRoutesJson, "\"routes\": " + too_many));
        expect_reject(b2.render(), FrontendError::UnsupportedSyntax, "more than 8 routes");
    }
}

TEST(envoy_parser, clusters_list_is_bounded_ordered_and_unique) {
    Bootstrap b;
    std::string clusters = "[";
    for (u32 i = 0; i < envoy::kMaxEnvoyClusters; i++) {
        if (i != 0) clusters += ", ";
        clusters += cluster_json("backend" + std::to_string(i), static_cast<u16>(9000 + i));
    }
    clusters += "]";
    b.clusters = clusters;
    REQUIRE(replace(&b.listeners, "\"cluster\": \"backend\"", "\"cluster\": \"backend0\""));
    {
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const FixedVec<envoy::Cluster, envoy::kMaxEnvoyClusters>& parsed = result.value().clusters;
        CHECK_EQ(parsed.len, envoy::kMaxEnvoyClusters);
        for (u32 i = 0; i < envoy::kMaxEnvoyClusters; i++)
            CHECK(parsed[i].name.eq(str("backend" + std::to_string(i))));
    }
    // A 9th cluster is rejected at its own span, not the array's.
    {
        std::string too_many = "[";
        for (u32 i = 0; i < envoy::kMaxEnvoyClusters + 1u; i++) {
            if (i != 0) too_many += ", ";
            too_many += cluster_json("backend" + std::to_string(i), static_cast<u16>(9000 + i));
        }
        too_many += "]";
        Bootstrap b2;
        b2.clusters = too_many;
        REQUIRE(replace(&b2.listeners, "\"cluster\": \"backend\"", "\"cluster\": \"backend0\""));
        expect_reject(b2.render(), FrontendError::UnsupportedSyntax, "more than 8 clusters");
    }
    // Duplicate cluster names are rejected at the duplicate's own span.
    {
        Bootstrap b3;
        b3.clusters =
            "[" + cluster_json("backend", 9000) + ", " + cluster_json("backend", 9001) + "]";
        expect_reject(b3.render(), FrontendError::UnexpectedToken, "duplicate cluster name");
    }
}

TEST(envoy_parser, clusters_may_be_empty_or_omitted) {
    // A route table where every route is direct_response/redirect needs no
    // upstream cluster (docs/envoy-compatibility.md, "Allow local-only route
    // tables to omit clusters"); the parser admits an empty or omitted
    // `clusters` array and leaves "a Forward route needs a declared cluster"
    // to the converter (src/envoy/converter.cc).
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 200}"));
        b.clusters = "[]";
        static envoy::JsonDocument doc;
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        CHECK_EQ(result.value().clusters.len, 0u);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 200}"));
        std::string text = b.render();
        REQUIRE(replace(&text, ",\n\"clusters\": " + b.clusters + "\n", "\n"));
        static envoy::JsonDocument doc;
        auto result = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(result);
        CHECK_EQ(result.value().clusters.len, 0u);
    }
}

TEST(envoy_parser, route_action_models_direct_response) {
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 200}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.kind == envoy::RouteActionKind::DirectResponse);
        CHECK_EQ(action.direct_response.status, 200u);
        CHECK_FALSE(action.direct_response.has_body);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 404, \"body\": {\"inline_string\": "
                        "\"not found\"}}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.kind == envoy::RouteActionKind::DirectResponse);
        CHECK_EQ(action.direct_response.status, 404u);
        CHECK(action.direct_response.has_body);
        CHECK(action.direct_response.inline_string.eq(lit_str("not found")));
    }
    {
        // status is required.
        Bootstrap b;
        REQUIRE(replace(
            &b.listeners, "\"route\": {\"cluster\": \"backend\"}", "\"direct_response\": {}"));
        expect_reject(b.render(), FrontendError::UnexpectedEof, "status is required");
    }
    {
        // status must be in Envoy's documented 200..599 range (`gte: 200,
        // lt: 600`): 199 is rejected (Codex round-12 review).
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 199}"));
        expect_reject(b.render(), FrontendError::UnexpectedToken, "must be in 200..599");
    }
    {
        // 200 is the lower bound and is accepted.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 200}"));
        static envoy::JsonDocument doc;
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK_EQ(action.direct_response.status, 200u);
    }
    {
        // 599 is the upper bound and is accepted.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 599}"));
        static envoy::JsonDocument doc;
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK_EQ(action.direct_response.status, 599u);
    }
    {
        // 600 is rejected.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 600}"));
        expect_reject(b.render(), FrontendError::UnexpectedToken, "must be in 200..599");
    }
    {
        // Only body.inline_string is modeled.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 200, \"body\": {\"filename\": \"x\"}}"));
        expect_reject(b.render(), FrontendError::UnsupportedSyntax, "unsupported field");
    }
    {
        // The inline body is bounded.
        Bootstrap b;
        const std::string body(4097, 'a');
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"direct_response\": {\"status\": 200, \"body\": {\"inline_string\": \"" +
                            body + "\"}}"));
        expect_reject(b.render(), FrontendError::UnsupportedSyntax, "exceeds 4096 bytes");
    }
}

TEST(envoy_parser, route_action_models_redirect) {
    {
        Bootstrap b;
        REQUIRE(
            replace(&b.listeners,
                    "\"route\": {\"cluster\": \"backend\"}",
                    "\"redirect\": {\"path_redirect\": \"/new\", \"response_code\": \"FOUND\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.kind == envoy::RouteActionKind::Redirect);
        CHECK(action.redirect.path_redirect.eq(lit_str("/new")));
        CHECK_EQ(action.redirect.response_code, 302u);
    }
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"host_redirect\": \"example.com\", \"response_code\": "
                        "\"PERMANENT_REDIRECT\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.redirect.host_redirect.eq(lit_str("example.com")));
        CHECK_EQ(action.redirect.response_code, 308u);
    }
    {
        // response_code is optional: proto3 JSON omits a field left at its
        // enum's zero value, and RedirectResponseCode's zero value is
        // MOVED_PERMANENTLY (301, envoy.config.route.v3.RedirectAction). An
        // omitted response_code must default to 301, not be rejected.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"path_redirect\": \"/new\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        REQUIRE(action.kind == envoy::RouteActionKind::Redirect);
        CHECK(action.redirect.path_redirect.eq(lit_str("/new")));
        CHECK_EQ(action.redirect.response_code, 301u);
    }
    {
        // An explicitly-empty path_redirect is accepted, not rejected:
        // verified against Envoy v3 at the v1.39.1 tag, `RedirectAction.
        // path_redirect` has no `min_len` validate rule (only a
        // well_known_regex(HTTP_HEADER_VALUE), which matches empty), and
        // `RouteEntryImplBase::isRedirect()` (source/common/router/
        // config_impl.cc) treats an empty path_redirect_ the same as an
        // omitted one rather than rejecting the route. Match that leniency.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"path_redirect\": \"\", \"response_code\": \"FOUND\"}"));
        static envoy::JsonDocument doc;
        // The model borrows the JSON bytes, so the source must outlive the result.
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        REQUIRE(action.kind == envoy::RouteActionKind::Redirect);
        CHECK(action.redirect.path_redirect.eq(lit_str("")));
        CHECK_EQ(action.redirect.response_code, 302u);
    }
    {
        // response_code, when present, is still closed to the five Envoy
        // names.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"path_redirect\": \"/new\", \"response_code\": \"OK\"}"));
        expect_reject(b.render(), FrontendError::UnsupportedSyntax, "must be one of");
    }
    {
        // Only path_redirect, host_redirect, response_code are modeled.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"path_redirect\": \"/new\", \"response_code\": \"FOUND\", "
                        "\"https_redirect\": true}"));
        expect_reject(b.render(), FrontendError::UnsupportedSyntax, "unsupported field");
    }
    {
        // A raw DEL byte (0x7f) in path_redirect is accepted, not rejected
        // (Codex round-12 review). `path_redirect` requests
        // `well_known_regex: HTTP_HEADER_VALUE strict: false`, which Envoy's
        // protoc-gen-validate fork resolves to the loose pattern
        // `^[^\x00\x0A\x0D]*$` (module/checker.go's
        // regex_map["HEADER_STRING"]) -- DEL is explicitly not forbidden by
        // that pattern, unlike the strict HTTP_HEADER_VALUE pattern that
        // would reject it.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"path_redirect\": \"/a\x7f\", \"response_code\": "
                        "\"FOUND\"}"));
        static envoy::JsonDocument doc;
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.redirect.path_redirect.eq(lit_str("/a\x7f")));
    }
    {
        // Same acceptance for a raw DEL byte in host_redirect.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"host_redirect\": \"example.com\x7f\", "
                        "\"response_code\": \"FOUND\"}"));
        static envoy::JsonDocument doc;
        const std::string source_text = b.render();
        auto result = envoy::parse_bootstrap_json(str(source_text), doc);
        REQUIRE(result);
        const envoy::RouteAction& action =
            result.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        CHECK(action.redirect.host_redirect.eq(lit_str("example.com\x7f")));
    }
    {
        // A raw byte below 0x20 (e.g. 0x01) in path_redirect is unreachable:
        // it is already rejected by the generic JSON scanner's control-byte
        // check, independent of any header-specific validation (Codex
        // round-12 review).
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"path_redirect\": \"/a\x01\", \"response_code\": "
                        "\"FOUND\"}"));
        expect_reject(
            b.render(), FrontendError::UnexpectedChar, "control byte inside a JSON string");
    }
    {
        // Same rejection (via the generic JSON scanner) for host_redirect.
        Bootstrap b;
        REQUIRE(replace(&b.listeners,
                        "\"route\": {\"cluster\": \"backend\"}",
                        "\"redirect\": {\"host_redirect\": \"example.com\x01\", "
                        "\"response_code\": \"FOUND\"}"));
        expect_reject(
            b.render(), FrontendError::UnexpectedChar, "control byte inside a JSON string");
    }
}

TEST(envoy_parser, route_action_rejects_none_or_multiple) {
    {
        Bootstrap b;
        REQUIRE(replace(&b.listeners, "\"route\": {\"cluster\": \"backend\"}", ""));
        REQUIRE(replace(
            &b.listeners, "\"match\": {\"prefix\": \"/\"}, ", "\"match\": {\"prefix\": \"/\"}"));
        expect_reject(b.render(),
                      FrontendError::UnexpectedEof,
                      "only route actions with route, direct_response, or redirect");
    }
    {
        Bootstrap b;
        REQUIRE(replace(
            &b.listeners,
            "\"route\": {\"cluster\": \"backend\"}",
            "\"route\": {\"cluster\": \"backend\"}, \"direct_response\": {\"status\": 200}"));
        expect_reject(b.render(),
                      FrontendError::UnexpectedToken,
                      "exactly one of route, direct_response, or redirect");
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
