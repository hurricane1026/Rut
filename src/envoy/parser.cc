#include "rut/envoy/parser.h"

namespace rut::envoy {
namespace {

auto invalid(Span span, Str detail) {
    return frontend_error(FrontendError::UnexpectedToken, span, detail);
}

auto unsupported(Span span, Str detail) {
    return frontend_error(FrontendError::UnsupportedSyntax, span, detail);
}

auto missing(Span span, Str detail) {
    return frontend_error(FrontendError::UnexpectedEof, span, detail);
}

constexpr Str kHcmTypeUrl = lit_str(
    "type.googleapis.com/"
    "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager");
constexpr Str kRouterTypeUrl =
    lit_str("type.googleapis.com/envoy.extensions.filters.http.router.v3.Router");
constexpr Str kHcmFilterName = lit_str("envoy.filters.network.http_connection_manager");
constexpr Str kRouterFilterName = lit_str("envoy.filters.http.router");

// One supported proto3 JSON field with both accepted spellings. `camel` is
// empty when the proto field name has no underscore, so both spellings are
// the same token.
struct Field {
    Str snake;
    Str camel;
};

constexpr Field field(const char* snake,
                      u32 snake_len,
                      const char* camel = nullptr,
                      u32 camel_len = 0) {
    return Field{Str{snake, snake_len}, Str{camel, camel_len}};
}

#define RUT_FIELD(snake) field(snake, sizeof(snake) - 1u)
#define RUT_FIELD2(snake, camel) field(snake, sizeof(snake) - 1u, camel, sizeof(camel) - 1u)

constexpr Field kStaticResources = RUT_FIELD2("static_resources", "staticResources");
constexpr Field kListeners = RUT_FIELD("listeners");
constexpr Field kClusters = RUT_FIELD("clusters");
constexpr Field kName = RUT_FIELD("name");
constexpr Field kAddress = RUT_FIELD("address");
constexpr Field kFilterChains = RUT_FIELD2("filter_chains", "filterChains");
constexpr Field kSocketAddress = RUT_FIELD2("socket_address", "socketAddress");
constexpr Field kPortValue = RUT_FIELD2("port_value", "portValue");
constexpr Field kFilters = RUT_FIELD("filters");
constexpr Field kTypedConfig = RUT_FIELD2("typed_config", "typedConfig");
constexpr Field kTypeUrl = RUT_FIELD("@type");
constexpr Field kStatPrefix = RUT_FIELD2("stat_prefix", "statPrefix");
constexpr Field kCodecType = RUT_FIELD2("codec_type", "codecType");
constexpr Field kGenerateRequestId = RUT_FIELD2("generate_request_id", "generateRequestId");
constexpr Field kRouteConfig = RUT_FIELD2("route_config", "routeConfig");
constexpr Field kHttpFilters = RUT_FIELD2("http_filters", "httpFilters");
constexpr Field kVirtualHosts = RUT_FIELD2("virtual_hosts", "virtualHosts");
constexpr Field kDomains = RUT_FIELD("domains");
constexpr Field kRoutes = RUT_FIELD("routes");
constexpr Field kMatch = RUT_FIELD("match");
constexpr Field kRoute = RUT_FIELD("route");
constexpr Field kPrefix = RUT_FIELD("prefix");
constexpr Field kCluster = RUT_FIELD("cluster");
constexpr Field kType = RUT_FIELD("type");
constexpr Field kConnectTimeout = RUT_FIELD2("connect_timeout", "connectTimeout");
constexpr Field kLoadAssignment = RUT_FIELD2("load_assignment", "loadAssignment");
constexpr Field kClusterName = RUT_FIELD2("cluster_name", "clusterName");
constexpr Field kEndpoints = RUT_FIELD("endpoints");
constexpr Field kLbEndpoints = RUT_FIELD2("lb_endpoints", "lbEndpoints");
constexpr Field kEndpoint = RUT_FIELD("endpoint");
constexpr Field kTimeout = RUT_FIELD("timeout");
constexpr Field kSuppressEnvoyHeaders =
    RUT_FIELD2("suppress_envoy_headers", "suppressEnvoyHeaders");
constexpr Field kPath = RUT_FIELD("path");
constexpr Field kDirectResponse = RUT_FIELD2("direct_response", "directResponse");
constexpr Field kStatus = RUT_FIELD("status");
constexpr Field kBody = RUT_FIELD("body");
constexpr Field kInlineString = RUT_FIELD2("inline_string", "inlineString");
constexpr Field kRedirect = RUT_FIELD("redirect");
constexpr Field kPathRedirect = RUT_FIELD2("path_redirect", "pathRedirect");
constexpr Field kHostRedirect = RUT_FIELD2("host_redirect", "hostRedirect");
constexpr Field kResponseCode = RUT_FIELD2("response_code", "responseCode");

#undef RUT_FIELD
#undef RUT_FIELD2

// Route match text (`prefix` / `path`): printable ASCII excluding the
// reserved characters that would make a plain-string match ambiguous with
// query/fragment/percent-encoding, bounded to a small fixed length.
constexpr u32 kMaxRouteMatchLen = 64u;

bool route_match_byte_ok(char c) {
    const auto b = static_cast<unsigned char>(c);
    return b >= 0x21u && b <= 0x7eu && c != '?' && c != '#' && c != '%';
}

bool prefix_shape_ok(Str text) {
    if (text.eq(lit_str("/"))) return true;
    return text.len >= 2u && text.ptr[0] == '/' && text.ptr[text.len - 1u] == '/';
}

bool path_shape_ok(Str text) {
    return text.len >= 1u && text.ptr[0] == '/';
}

bool field_matches(const Field& f, Str key) {
    return key.eq(f.snake) || (f.camel.len != 0u && key.eq(f.camel));
}

class Parser {
public:
    explicit Parser(const JsonDocument& doc) : doc_(doc) {}

    FrontendResult<Bootstrap> run() {
        const u32 root = doc_.root;
        auto root_object = expect_object(root, lit_str("bootstrap must be a JSON object"));
        if (!root_object) return core::make_unexpected(root_object.error());
        const Field allowed[] = {kStaticResources};
        if (auto r = reject_unknown(root, allowed, 1u); !r) return core::make_unexpected(r.error());

        auto static_resources =
            required(root, kStaticResources, lit_str("static_resources is required"));
        if (!static_resources) return core::make_unexpected(static_resources.error());
        Bootstrap bootstrap{};
        bootstrap.span = doc_.at(root).span;
        if (auto r = parse_static_resources(static_resources.value(), &bootstrap); !r)
            return core::make_unexpected(r.error());
        for (const Route& route :
             bootstrap.listener.filter_chain.hcm.route_config.virtual_host.routes) {
            if (route.action.kind != RouteActionKind::Forward) continue;
            bool declared = false;
            for (const Cluster& cluster : bootstrap.clusters) {
                if (route.action.cluster.eq(cluster.name)) {
                    declared = true;
                    break;
                }
            }
            if (!declared)
                return invalid(route.action.cluster_span,
                               lit_str("route cluster does not name a declared cluster"));
        }
        return bootstrap;
    }

private:
    // ── Generic field helpers ────────────────────────────────────────

    FrontendResult<bool> expect_object(u32 node, Str detail) {
        if (node == kJsonNoNode || doc_.at(node).kind != JsonKind::Object)
            return invalid(node == kJsonNoNode ? Span{} : doc_.at(node).span, detail);
        return true;
    }

    FrontendResult<bool> expect_array(u32 node, Str detail) {
        if (node == kJsonNoNode || doc_.at(node).kind != JsonKind::Array)
            return invalid(doc_.at(node).span, detail);
        return true;
    }

    // Every member of `object` must match one of `allowed`; anything else is
    // an unsupported field pointing at its key. Escaped keys never reach
    // here: the JSON layer rejects them outright before a document exists.
    FrontendResult<bool> reject_unknown(u32 object, const Field* allowed, u32 allowed_len) {
        const JsonNode& parent = doc_.at(object);
        for (u32 child = parent.first_child; child != kJsonNoNode;
             child = doc_.at(child).next_sibling) {
            const JsonNode& member = doc_.at(child);
            bool known = false;
            for (u32 i = 0; i < allowed_len && !known; i++)
                known = field_matches(allowed[i], member.key);
            if (!known) return unsupported(member.key_span, lit_str("unsupported field"));
        }
        return true;
    }

    // Find a field by either spelling. Both spellings present is a duplicate.
    FrontendResult<u32> optional(u32 object, const Field& f) {
        const u32 snake = doc_.member(object, f.snake);
        const u32 camel = f.camel.len == 0u ? kJsonNoNode : doc_.member(object, f.camel);
        if (snake != kJsonNoNode && camel != kJsonNoNode)
            return invalid(doc_.at(camel).key_span,
                           lit_str("field given in both snake_case and camelCase"));
        return snake != kJsonNoNode ? snake : camel;
    }

    FrontendResult<u32> required(u32 object, const Field& f, Str detail) {
        auto node = optional(object, f);
        if (!node) return node;
        if (node.value() == kJsonNoNode) return missing(doc_.at(object).span, detail);
        return node;
    }

    // A single-element array: the milestone admits exactly one listener,
    // filter chain, filter, virtual host, route, http filter, locality and
    // endpoint.
    FrontendResult<u32> single_element(u32 array, Str empty_detail, Str many_detail) {
        auto ok = expect_array(array, lit_str("expected a JSON array"));
        if (!ok) return core::make_unexpected(ok.error());
        const JsonNode& node = doc_.at(array);
        if (node.child_count == 0u) return missing(node.span, empty_detail);
        if (node.child_count > 1u)
            return unsupported(doc_.at(doc_.at(node.first_child).next_sibling).span, many_detail);
        return node.first_child;
    }

    FrontendResult<Str> plain_string(u32 node, Str detail) {
        const JsonNode& n = doc_.at(node);
        if (n.kind != JsonKind::String) return invalid(n.span, detail);
        if (n.has_escape) return unsupported(n.span, lit_str("escaped strings are unsupported"));
        return n.raw;
    }

    FrontendResult<Str> name_string(u32 node, bool allow_empty, Str detail) {
        auto s = plain_string(node, detail);
        if (!s) return s;
        if (s.value().len == 0u && !allow_empty) return invalid(doc_.at(node).span, detail);
        if (s.value().len > kMaxEnvoyNameLen)
            return unsupported(doc_.at(node).span, lit_str("name exceeds the bounded length"));
        return s;
    }

    FrontendResult<bool> expect_type_url(u32 object, Str expected, Str detail, Span* out) {
        auto url = required(object, kTypeUrl, lit_str("typed_config requires @type"));
        if (!url) return core::make_unexpected(url.error());
        auto text = plain_string(url.value(), lit_str("@type must be a string"));
        if (!text) return core::make_unexpected(text.error());
        if (!text.value().eq(expected)) return unsupported(doc_.at(url.value()).span, detail);
        *out = doc_.at(url.value()).span;
        return true;
    }

    // ── Leaf value parsers ───────────────────────────────────────────

    FrontendResult<bool> parse_socket_address(u32 address_node, SocketAddress* out) {
        auto ok = expect_object(address_node, lit_str("address must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kSocketAddress};
        if (auto r = reject_unknown(address_node, allowed, 1u); !r) return r;
        auto socket = required(
            address_node, kSocketAddress, lit_str("only socket_address addresses are supported"));
        if (!socket) return core::make_unexpected(socket.error());
        ok = expect_object(socket.value(), lit_str("socket_address must be an object"));
        if (!ok) return ok;
        const Field allowed_socket[] = {kAddress, kPortValue};
        if (auto r = reject_unknown(socket.value(), allowed_socket, 2u); !r) return r;

        auto address =
            required(socket.value(), kAddress, lit_str("socket_address.address is required"));
        if (!address) return core::make_unexpected(address.error());
        auto text = plain_string(address.value(), lit_str("address must be a string"));
        if (!text) return core::make_unexpected(text.error());
        u32 host = 0;
        if (!parse_ipv4(text.value(), &host))
            return unsupported(doc_.at(address.value()).span,
                               lit_str("only dotted IPv4 literal addresses are supported"));

        auto port =
            required(socket.value(), kPortValue, lit_str("socket_address.port_value is required"));
        if (!port) return core::make_unexpected(port.error());
        u32 port_value = 0;
        if (!json_u32(doc_.at(port.value()), &port_value))
            return invalid(doc_.at(port.value()).span,
                           lit_str("port_value must be a non-negative integer"));
        if (port_value == 0u || port_value > 65535u)
            return invalid(doc_.at(port.value()).span, lit_str("port_value must be in 1..65535"));

        out->ipv4_host = host;
        out->port = static_cast<u16>(port_value);
        out->address_text = text.value();
        out->address_span = doc_.at(address.value()).span;
        out->port_span = doc_.at(port.value()).span;
        out->span = doc_.at(address_node).span;
        return true;
    }

    static bool parse_ipv4(Str text, u32* out) {
        u32 pos = 0;
        u32 address = 0;
        for (u32 octet = 0; octet < 4u; octet++) {
            const u32 start = pos;
            u32 value = 0;
            while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') {
                if (pos - start == 3u) return false;
                value = value * 10u + static_cast<u32>(text.ptr[pos] - '0');
                if (value > 255u) return false;
                pos++;
            }
            const u32 digits = pos - start;
            if (digits == 0u || (digits > 1u && text.ptr[start] == '0')) return false;
            if (octet < 3u) {
                if (pos >= text.len || text.ptr[pos] != '.') return false;
                pos++;
            }
            address = (address << 8u) | value;
        }
        if (pos != text.len) return false;
        *out = address;
        return true;
    }

    FrontendResult<bool> parse_duration(u32 node, Duration* out, bool allow_zero) {
        auto text = plain_string(node, lit_str("duration must be a string like \"5s\""));
        if (!text) return core::make_unexpected(text.error());
        const Str s = text.value();
        const Span span = doc_.at(node).span;
        if (s.len < 2u || s.ptr[s.len - 1u] != 's')
            return invalid(span, lit_str("duration must be decimal seconds with an s suffix"));
        u32 pos = 0;
        u64 seconds = 0;
        const u32 int_start = pos;
        while (pos < s.len - 1u && s.ptr[pos] >= '0' && s.ptr[pos] <= '9') {
            seconds = seconds * 10u + static_cast<u64>(s.ptr[pos] - '0');
            if (seconds > 0xffffffffu / 1000u)
                return unsupported(span, lit_str("duration is too large"));
            pos++;
        }
        const u32 int_digits = pos - int_start;
        if (int_digits == 0u || (int_digits > 1u && s.ptr[int_start] == '0'))
            return invalid(span, lit_str("duration must be decimal seconds with an s suffix"));
        u32 millis = 0;
        if (pos < s.len - 1u && s.ptr[pos] == '.') {
            pos++;
            u32 frac_digits = 0;
            u32 scale = 100;
            while (pos < s.len - 1u && s.ptr[pos] >= '0' && s.ptr[pos] <= '9') {
                if (frac_digits == 3u)
                    return unsupported(
                        span, lit_str("durations finer than milliseconds are unsupported"));
                millis += static_cast<u32>(s.ptr[pos] - '0') * scale;
                scale /= 10u;
                frac_digits++;
                pos++;
            }
            if (frac_digits == 0u)
                return invalid(span, lit_str("duration must be decimal seconds with an s suffix"));
        }
        if (pos != s.len - 1u)
            return invalid(span, lit_str("duration must be decimal seconds with an s suffix"));
        const u64 total = seconds * 1000u + millis;
        if (!allow_zero && total == 0u) return invalid(span, lit_str("duration must be positive"));
        if (total > 0xffffffffu) return unsupported(span, lit_str("duration is too large"));
        out->milliseconds = static_cast<u32>(total);
        out->text = s;
        out->span = span;
        return true;
    }

    // ── Resources ────────────────────────────────────────────────────

    FrontendResult<bool> parse_static_resources(u32 node, Bootstrap* out) {
        auto ok = expect_object(node, lit_str("static_resources must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kListeners, kClusters};
        if (auto r = reject_unknown(node, allowed, 2u); !r) return r;

        auto listeners =
            required(node, kListeners, lit_str("static_resources.listeners is required"));
        if (!listeners) return core::make_unexpected(listeners.error());
        auto listener = single_element(listeners.value(),
                                       lit_str("at least one listener is required"),
                                       lit_str("multiple listeners are unsupported"));
        if (!listener) return core::make_unexpected(listener.error());
        if (auto r = parse_listener(listener.value(), &out->listener); !r) return r;

        // Clusters are optional at the JSON level, both an omitted field and
        // an empty array: an Envoy bootstrap whose routes are all
        // `direct_response`/`redirect` needs no upstream cluster at all. The
        // converter's `validate` (src/envoy/converter.cc) requires a
        // declared cluster only once a route's action is known to be
        // `Forward`.
        auto clusters = optional(node, kClusters);
        if (!clusters) return core::make_unexpected(clusters.error());
        if (clusters.value() == kJsonNoNode) return true;
        return parse_clusters(clusters.value(), &out->clusters);
    }

    // A bounded, ordered list of clusters (`kMaxEnvoyClusters`); names must be
    // unique. The (kMaxEnvoyClusters + 1)th element is rejected at its own
    // span rather than the array's. An empty array is allowed (see
    // `parse_static_resources`); the resulting empty `out` fails later, at
    // the point a `Forward` route action needs a declared cluster.
    FrontendResult<bool> parse_clusters(u32 array, FixedVec<Cluster, kMaxEnvoyClusters>* out) {
        auto ok = expect_array(array, lit_str("expected a JSON array"));
        if (!ok) return core::make_unexpected(ok.error());
        const JsonNode& node = doc_.at(array);
        for (u32 child = node.first_child; child != kJsonNoNode;
             child = doc_.at(child).next_sibling) {
            if (out->full())
                return unsupported(doc_.at(child).span,
                                   lit_str("more than 8 clusters are unsupported"));
            Cluster cluster{};
            if (auto r = parse_cluster(child, &cluster); !r) return r;
            for (const Cluster& seen : *out) {
                if (seen.name.eq(cluster.name))
                    return invalid(cluster.name_span, lit_str("duplicate cluster name"));
            }
            out->push(cluster);
        }
        return true;
    }

    FrontendResult<bool> parse_listener(u32 node, Listener* out) {
        auto ok = expect_object(node, lit_str("listener must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kName, kAddress, kFilterChains};
        if (auto r = reject_unknown(node, allowed, 3u); !r) return r;
        out->span = doc_.at(node).span;

        auto name = optional(node, kName);
        if (!name) return core::make_unexpected(name.error());
        if (name.value() != kJsonNoNode) {
            auto text = name_string(name.value(), true, lit_str("listener name must be a string"));
            if (!text) return core::make_unexpected(text.error());
            out->name = text.value();
            out->name_span = doc_.at(name.value()).span;
        }

        auto address = required(node, kAddress, lit_str("listener address is required"));
        if (!address) return core::make_unexpected(address.error());
        if (auto r = parse_socket_address(address.value(), &out->address); !r) return r;

        auto chains = required(node, kFilterChains, lit_str("listener filter_chains is required"));
        if (!chains) return core::make_unexpected(chains.error());
        auto chain = single_element(chains.value(),
                                    lit_str("at least one filter chain is required"),
                                    lit_str("multiple filter chains are unsupported"));
        if (!chain) return core::make_unexpected(chain.error());
        return parse_filter_chain(chain.value(), &out->filter_chain);
    }

    FrontendResult<bool> parse_filter_chain(u32 node, FilterChain* out) {
        auto ok = expect_object(node, lit_str("filter chain must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kFilters};
        if (auto r = reject_unknown(node, allowed, 1u); !r) return r;
        out->span = doc_.at(node).span;

        auto filters = required(node, kFilters, lit_str("filter chain filters is required"));
        if (!filters) return core::make_unexpected(filters.error());
        auto filter = single_element(filters.value(),
                                     lit_str("at least one network filter is required"),
                                     lit_str("additional network filters are unsupported"));
        if (!filter) return core::make_unexpected(filter.error());
        const u32 f = filter.value();
        ok = expect_object(f, lit_str("network filter must be an object"));
        if (!ok) return ok;
        const Field allowed_filter[] = {kName, kTypedConfig};
        if (auto r = reject_unknown(f, allowed_filter, 2u); !r) return r;

        auto name = required(f, kName, lit_str("network filter name is required"));
        if (!name) return core::make_unexpected(name.error());
        auto text = name_string(name.value(), false, lit_str("filter name must be a string"));
        if (!text) return core::make_unexpected(text.error());
        if (!text.value().eq(kHcmFilterName))
            return unsupported(
                doc_.at(name.value()).span,
                lit_str("only the HTTP connection manager network filter is supported"));
        out->filter_name = text.value();
        out->filter_name_span = doc_.at(name.value()).span;

        auto typed = required(f, kTypedConfig, lit_str("network filter typed_config is required"));
        if (!typed) return core::make_unexpected(typed.error());
        return parse_hcm(typed.value(), &out->hcm);
    }

    FrontendResult<bool> parse_hcm(u32 node, HttpConnectionManager* out) {
        auto ok = expect_object(node, lit_str("typed_config must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {
            kTypeUrl, kStatPrefix, kCodecType, kGenerateRequestId, kRouteConfig, kHttpFilters};
        if (auto r = reject_unknown(node, allowed, 6u); !r) return r;
        out->span = doc_.at(node).span;
        if (auto r =
                expect_type_url(node,
                                kHcmTypeUrl,
                                lit_str("typed_config @type must be the v3 HttpConnectionManager"),
                                &out->type_url_span);
            !r)
            return r;

        auto stat_prefix = required(node, kStatPrefix, lit_str("stat_prefix is required"));
        if (!stat_prefix) return core::make_unexpected(stat_prefix.error());
        auto prefix_text = name_string(
            stat_prefix.value(), false, lit_str("stat_prefix must be a non-empty string"));
        if (!prefix_text) return core::make_unexpected(prefix_text.error());
        out->stat_prefix = prefix_text.value();
        out->stat_prefix_span = doc_.at(stat_prefix.value()).span;

        // codec_type must be explicit HTTP1. AUTO (the proto3 default, so
        // also the omitted-field behavior) makes Envoy sniff the connection
        // preface and serve downstream HTTP/2 on a plaintext listener; this
        // converter is HTTP/1-only and downstream HTTP/2 is out of scope
        // (docs/envoy-converter.md), so admitting AUTO would silently drop
        // support for h2c clients Envoy would have served.
        auto codec =
            required(node,
                     kCodecType,
                     lit_str("codec_type is required; only HTTP1 is supported (fix-it: add "
                             "\"codec_type\": \"HTTP1\")"));
        if (!codec) return core::make_unexpected(codec.error());
        auto text = plain_string(codec.value(), lit_str("codec_type must be a string"));
        if (!text) return core::make_unexpected(text.error());
        if (!text.value().eq(lit_str("HTTP1")))
            return unsupported(
                doc_.at(codec.value()).span,
                lit_str("only codec_type HTTP1 is supported; AUTO permits downstream HTTP/2, "
                        "which this converter does not implement"));
        out->codec_type = CodecType::Http1;
        out->codec_type_present = true;
        out->codec_type_span = doc_.at(codec.value()).span;

        auto gen = required(node,
                            kGenerateRequestId,
                            lit_str("generate_request_id: false is required; Rut does not generate "
                                    "x-request-id"));
        if (!gen) return core::make_unexpected(gen.error());
        const JsonNode& gen_node = doc_.at(gen.value());
        if (gen_node.kind != JsonKind::Bool)
            return invalid(gen_node.span, lit_str("generate_request_id must be a boolean"));
        if (gen_node.bool_value)
            return unsupported(gen_node.span,
                               lit_str("generate_request_id: true is unsupported; Rut does not "
                                       "generate x-request-id"));
        out->generate_request_id_span = gen_node.span;

        auto route_config =
            required(node, kRouteConfig, lit_str("inline route_config is required"));
        if (!route_config) return core::make_unexpected(route_config.error());
        if (auto r = parse_route_configuration(route_config.value(), &out->route_config); !r)
            return r;

        auto http_filters = required(node, kHttpFilters, lit_str("http_filters is required"));
        if (!http_filters) return core::make_unexpected(http_filters.error());
        auto filter = single_element(http_filters.value(),
                                     lit_str("http_filters must end with the router filter"),
                                     lit_str("HTTP filters other than the router are unsupported"));
        if (!filter) return core::make_unexpected(filter.error());
        return parse_router_filter(filter.value(), &out->router);
    }

    FrontendResult<bool> parse_router_filter(u32 node, RouterFilter* out) {
        auto ok = expect_object(node, lit_str("http filter must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kName, kTypedConfig};
        if (auto r = reject_unknown(node, allowed, 2u); !r) return r;
        out->span = doc_.at(node).span;

        auto name = required(node, kName, lit_str("http filter name is required"));
        if (!name) return core::make_unexpected(name.error());
        auto text = name_string(name.value(), false, lit_str("filter name must be a string"));
        if (!text) return core::make_unexpected(text.error());
        if (!text.value().eq(kRouterFilterName))
            return unsupported(doc_.at(name.value()).span,
                               lit_str("HTTP filters other than the router are unsupported"));
        out->name = text.value();
        out->name_span = doc_.at(name.value()).span;

        auto typed = optional(node, kTypedConfig);
        if (!typed) return core::make_unexpected(typed.error());
        if (typed.value() == kJsonNoNode) return true;
        ok = expect_object(typed.value(), lit_str("typed_config must be an object"));
        if (!ok) return ok;
        const Field allowed_typed[] = {kTypeUrl, kSuppressEnvoyHeaders};
        if (auto r = reject_unknown(typed.value(), allowed_typed, 2u); !r) return r;
        Span url_span{};
        if (auto r = expect_type_url(typed.value(),
                                     kRouterTypeUrl,
                                     lit_str("router typed_config @type must be the v3 Router"),
                                     &url_span);
            !r)
            return r;
        out->has_typed_config = true;
        out->typed_config_span = doc_.at(typed.value()).span;

        auto suppress = optional(typed.value(), kSuppressEnvoyHeaders);
        if (!suppress) return core::make_unexpected(suppress.error());
        if (suppress.value() != kJsonNoNode) {
            const JsonNode& node_value = doc_.at(suppress.value());
            if (node_value.kind != JsonKind::Bool)
                return invalid(node_value.span,
                               lit_str("suppress_envoy_headers must be a boolean"));
            out->suppress_envoy_headers = node_value.bool_value;
            out->suppress_envoy_headers_present = true;
            out->suppress_envoy_headers_span = node_value.span;
        }
        return true;
    }

    FrontendResult<bool> parse_route_configuration(u32 node, RouteConfiguration* out) {
        auto ok = expect_object(node, lit_str("route_config must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kName, kVirtualHosts};
        if (auto r = reject_unknown(node, allowed, 2u); !r) return r;
        out->span = doc_.at(node).span;

        auto name = optional(node, kName);
        if (!name) return core::make_unexpected(name.error());
        if (name.value() != kJsonNoNode) {
            auto text =
                name_string(name.value(), true, lit_str("route_config name must be a string"));
            if (!text) return core::make_unexpected(text.error());
            out->name = text.value();
            out->name_span = doc_.at(name.value()).span;
        }

        auto hosts = required(node, kVirtualHosts, lit_str("virtual_hosts is required"));
        if (!hosts) return core::make_unexpected(hosts.error());
        auto host = single_element(hosts.value(),
                                   lit_str("at least one virtual host is required"),
                                   lit_str("multiple virtual hosts are unsupported"));
        if (!host) return core::make_unexpected(host.error());
        return parse_virtual_host(host.value(), &out->virtual_host);
    }

    FrontendResult<bool> parse_virtual_host(u32 node, VirtualHost* out) {
        auto ok = expect_object(node, lit_str("virtual host must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kName, kDomains, kRoutes};
        if (auto r = reject_unknown(node, allowed, 3u); !r) return r;
        out->span = doc_.at(node).span;

        auto name = required(node, kName, lit_str("virtual host name is required"));
        if (!name) return core::make_unexpected(name.error());
        auto text = name_string(
            name.value(), false, lit_str("virtual host name must be a non-empty string"));
        if (!text) return core::make_unexpected(text.error());
        out->name = text.value();
        out->name_span = doc_.at(name.value()).span;

        auto domains = required(node, kDomains, lit_str("virtual host domains is required"));
        if (!domains) return core::make_unexpected(domains.error());
        auto domain =
            single_element(domains.value(),
                           lit_str("virtual host domains must not be empty"),
                           lit_str("host matching is unsupported; domains must be [\"*\"]"));
        if (!domain) return core::make_unexpected(domain.error());
        auto domain_text = plain_string(domain.value(), lit_str("domain must be a string"));
        if (!domain_text) return core::make_unexpected(domain_text.error());
        if (!domain_text.value().eq(lit_str("*")))
            return unsupported(doc_.at(domain.value()).span,
                               lit_str("host matching is unsupported; domains must be [\"*\"]"));
        out->domains_span = doc_.at(domains.value()).span;

        auto routes = required(node, kRoutes, lit_str("virtual host routes is required"));
        if (!routes) return core::make_unexpected(routes.error());
        return parse_routes(routes.value(), &out->routes);
    }

    // A bounded, ordered list of routes (`kMaxEnvoyRoutes`). Order is
    // preserved from the source array; the list is not checked for shadowing
    // here (that is a lowering-time concern, PR 8). The (kMaxEnvoyRoutes +
    // 1)th element is rejected at its own span rather than the array's.
    FrontendResult<bool> parse_routes(u32 array, FixedVec<Route, kMaxEnvoyRoutes>* out) {
        auto ok = expect_array(array, lit_str("expected a JSON array"));
        if (!ok) return core::make_unexpected(ok.error());
        const JsonNode& node = doc_.at(array);
        if (node.child_count == 0u)
            return missing(node.span, lit_str("at least one route is required"));
        for (u32 child = node.first_child; child != kJsonNoNode;
             child = doc_.at(child).next_sibling) {
            if (out->full())
                return unsupported(doc_.at(child).span,
                                   lit_str("more than 8 routes are unsupported"));
            Route route{};
            if (auto r = parse_route(child, &route); !r) return r;
            out->push(route);
        }
        return true;
    }

    FrontendResult<bool> parse_route(u32 node, Route* out) {
        auto ok = expect_object(node, lit_str("route must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kMatch, kRoute, kDirectResponse, kRedirect};
        if (auto r = reject_unknown(node, allowed, 4u); !r) return r;
        out->span = doc_.at(node).span;

        auto match = required(node, kMatch, lit_str("route match is required"));
        if (!match) return core::make_unexpected(match.error());
        if (auto r = parse_route_match(match.value(), &out->match); !r) return r;

        auto route_action = optional(node, kRoute);
        if (!route_action) return core::make_unexpected(route_action.error());
        auto direct_response = optional(node, kDirectResponse);
        if (!direct_response) return core::make_unexpected(direct_response.error());
        auto redirect = optional(node, kRedirect);
        if (!redirect) return core::make_unexpected(redirect.error());

        const u32 present = (route_action.value() != kJsonNoNode ? 1u : 0u) +
                            (direct_response.value() != kJsonNoNode ? 1u : 0u) +
                            (redirect.value() != kJsonNoNode ? 1u : 0u);
        if (present == 0u)
            return missing(
                doc_.at(node).span,
                lit_str("only route actions with route, direct_response, or redirect are "
                        "supported"));
        if (present > 1u)
            return invalid(
                doc_.at(node).span,
                lit_str("route must set exactly one of route, direct_response, or redirect"));

        if (route_action.value() != kJsonNoNode)
            return parse_forward_action(route_action.value(), &out->action);
        if (direct_response.value() != kJsonNoNode)
            return parse_direct_response_action(direct_response.value(), &out->action);
        return parse_redirect_action(redirect.value(), &out->action);
    }

    FrontendResult<bool> parse_route_match(u32 node, RouteMatch* out) {
        auto ok = expect_object(node, lit_str("route match must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kPrefix, kPath};
        if (auto r = reject_unknown(node, allowed, 2u); !r) return r;
        out->span = doc_.at(node).span;

        auto prefix = optional(node, kPrefix);
        if (!prefix) return core::make_unexpected(prefix.error());
        auto path = optional(node, kPath);
        if (!path) return core::make_unexpected(path.error());

        if (prefix.value() != kJsonNoNode && path.value() != kJsonNoNode)
            return invalid(doc_.at(path.value()).span,
                           lit_str("route match must set exactly one of prefix or path"));
        if (prefix.value() == kJsonNoNode && path.value() == kJsonNoNode)
            return missing(doc_.at(node).span,
                           lit_str("only prefix or path route matching is supported"));

        if (prefix.value() != kJsonNoNode) {
            auto text = plain_string(prefix.value(), lit_str("prefix must be a string"));
            if (!text) return core::make_unexpected(text.error());
            const Span span = doc_.at(prefix.value()).span;
            if (auto r = validate_route_match_bytes(text.value(), span); !r) return r;
            if (!prefix_shape_ok(text.value()))
                return unsupported(span,
                                   lit_str("only \"/\" or prefixes ending in \"/\" are supported"));
            out->kind = RouteMatchKind::Prefix;
            out->prefix = text.value();
            out->prefix_span = span;
            return true;
        }

        auto text = plain_string(path.value(), lit_str("path must be a string"));
        if (!text) return core::make_unexpected(text.error());
        const Span span = doc_.at(path.value()).span;
        if (auto r = validate_route_match_bytes(text.value(), span); !r) return r;
        if (!path_shape_ok(text.value()))
            return unsupported(span, lit_str("path must start with \"/\""));
        out->kind = RouteMatchKind::Path;
        out->path = text.value();
        out->path_span = span;
        return true;
    }

    FrontendResult<bool> validate_route_match_bytes(Str text, Span span) {
        if (text.len > kMaxRouteMatchLen)
            return unsupported(span, lit_str("route match value exceeds 64 bytes"));
        for (u32 i = 0; i < text.len; i++) {
            if (!route_match_byte_ok(text.ptr[i]))
                return unsupported(
                    span,
                    lit_str("route match value must be printable ASCII excluding ?, #, and %"));
        }
        return true;
    }

    FrontendResult<bool> parse_forward_action(u32 node, RouteAction* out) {
        auto ok = expect_object(node, lit_str("route action must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kCluster, kTimeout};
        if (auto r = reject_unknown(node, allowed, 2u); !r) return r;
        out->kind = RouteActionKind::Forward;
        out->span = doc_.at(node).span;

        auto cluster = required(node, kCluster, lit_str("route action cluster is required"));
        if (!cluster) return core::make_unexpected(cluster.error());
        auto cluster_text = name_string(
            cluster.value(), false, lit_str("route cluster must be a non-empty string"));
        if (!cluster_text) return core::make_unexpected(cluster_text.error());
        out->cluster = cluster_text.value();
        out->cluster_span = doc_.at(cluster.value()).span;

        auto timeout = optional(node, kTimeout);
        if (!timeout) return core::make_unexpected(timeout.error());
        if (timeout.value() != kJsonNoNode) {
            if (auto r = parse_duration(timeout.value(), &out->timeout, /*allow_zero=*/true); !r)
                return r;
            out->timeout_present = true;
        }
        return true;
    }

    FrontendResult<bool> parse_direct_response_action(u32 node, RouteAction* out) {
        auto ok = expect_object(node, lit_str("direct_response must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kStatus, kBody};
        if (auto r = reject_unknown(node, allowed, 2u); !r) return r;
        out->kind = RouteActionKind::DirectResponse;
        out->span = doc_.at(node).span;
        out->direct_response.span = doc_.at(node).span;

        auto status = required(node, kStatus, lit_str("direct_response status is required"));
        if (!status) return core::make_unexpected(status.error());
        u32 status_value = 0;
        if (!json_u32(doc_.at(status.value()), &status_value))
            return invalid(doc_.at(status.value()).span,
                           lit_str("direct_response status must be a non-negative integer"));
        // Envoy v3 at the v1.39.1 tag: `DirectResponseAction.status`
        // (api/envoy/config/route/v3/route_components.proto:1968-1969)
        // carries `(validate.rules).uint32 = {lt: 600 gte: 200}`, so the
        // valid range is 200..599, not 100..599 (Codex round-12 review).
        if (status_value < 200u || status_value > 599u)
            return invalid(doc_.at(status.value()).span,
                           lit_str("direct_response status must be in 200..599"));
        out->direct_response.status = static_cast<u16>(status_value);

        auto body = optional(node, kBody);
        if (!body) return core::make_unexpected(body.error());
        if (body.value() != kJsonNoNode) {
            ok = expect_object(body.value(), lit_str("direct_response body must be an object"));
            if (!ok) return ok;
            const Field allowed_body[] = {kInlineString};
            if (auto r = reject_unknown(body.value(), allowed_body, 1u); !r) return r;
            auto inline_string =
                required(body.value(), kInlineString, lit_str("body inline_string is required"));
            if (!inline_string) return core::make_unexpected(inline_string.error());
            auto text =
                plain_string(inline_string.value(), lit_str("inline_string must be a string"));
            if (!text) return core::make_unexpected(text.error());
            if (text.value().len > 4096u)
                return unsupported(doc_.at(inline_string.value()).span,
                                   lit_str("inline_string exceeds 4096 bytes"));
            out->direct_response.has_body = true;
            out->direct_response.inline_string = text.value();
        }
        return true;
    }

    FrontendResult<bool> parse_redirect_action(u32 node, RouteAction* out) {
        auto ok = expect_object(node, lit_str("redirect must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kPathRedirect, kHostRedirect, kResponseCode};
        if (auto r = reject_unknown(node, allowed, 3u); !r) return r;
        out->kind = RouteActionKind::Redirect;
        out->span = doc_.at(node).span;
        out->redirect.span = doc_.at(node).span;

        // `path_redirect` is not required to be non-empty. Verified against
        // Envoy v3 at the v1.39.1 tag: `RedirectAction.path_redirect`
        // (api/envoy/config/route/v3/route_components.proto) carries only
        // `(validate.rules).string = {well_known_regex: HTTP_HEADER_VALUE
        // strict: false}` — no `min_len` — and `well_known_regex` matches the
        // empty string. Router construction doesn't reject it either:
        // `RouteEntryImplBase::isRedirect()` (source/common/router/
        // config_impl.cc) treats an empty `path_redirect_` exactly like an
        // omitted one (both fall through to a bare status-code response with
        // no Location rewrite). Do not add a min-length check here; it would
        // reject a bootstrap Envoy itself accepts.
        //
        // Codex round-12 review: no additional byte-level filtering is
        // needed here either. `well_known_regex: HTTP_HEADER_VALUE` has two
        // patterns depending on `strict`: the *strict* (default) pattern
        // rejects 0x00-0x08, 0x0A-0x1F, and 0x7F, but `path_redirect` and
        // `host_redirect` both request `strict: false` above, which resolves
        // (Envoy's protoc-gen-validate fork, `module/checker.go`'s
        // `checkWellKnownRegex`/`regex_map["HEADER_STRING"]`) to the looser
        // pattern `^[^\x00\x0A\x0D]*$` — i.e. only NUL/LF/CR are forbidden,
        // and DEL (0x7F) is explicitly allowed. Those three forbidden bytes
        // are already unconditionally rejected for every JSON string in this
        // document, including these two fields, by the generic "control byte
        // inside a JSON string" check in the scanner (< 0x20, `json.cc`), so
        // there is no reachable gap to close: a raw DEL byte here is
        // correctly accepted, not rejected, and a raw byte in 0x00-0x1F
        // (e.g. 0x01) is already rejected upstream of this function.
        auto path_redirect = optional(node, kPathRedirect);
        if (!path_redirect) return core::make_unexpected(path_redirect.error());
        if (path_redirect.value() != kJsonNoNode) {
            auto text =
                plain_string(path_redirect.value(), lit_str("path_redirect must be a string"));
            if (!text) return core::make_unexpected(text.error());
            out->redirect.path_redirect = text.value();
        }

        auto host_redirect = optional(node, kHostRedirect);
        if (!host_redirect) return core::make_unexpected(host_redirect.error());
        if (host_redirect.value() != kJsonNoNode) {
            auto text =
                plain_string(host_redirect.value(), lit_str("host_redirect must be a string"));
            if (!text) return core::make_unexpected(text.error());
            out->redirect.host_redirect = text.value();
        }

        // `response_code` is optional: proto3 JSON omits a field left at its
        // enum's zero value, and `RedirectResponseCode`'s zero value is
        // `MOVED_PERMANENTLY` (301) (envoy.config.route.v3.RedirectAction).
        // An omitted field is therefore a valid, fully-specified redirect,
        // not a missing one.
        auto response_code = optional(node, kResponseCode);
        if (!response_code) return core::make_unexpected(response_code.error());
        u16 mapped = 301u;
        if (response_code.value() != kJsonNoNode) {
            auto code_text =
                plain_string(response_code.value(), lit_str("response_code must be a string"));
            if (!code_text) return core::make_unexpected(code_text.error());
            if (code_text.value().eq(lit_str("MOVED_PERMANENTLY"))) {
                mapped = 301u;
            } else if (code_text.value().eq(lit_str("FOUND"))) {
                mapped = 302u;
            } else if (code_text.value().eq(lit_str("SEE_OTHER"))) {
                mapped = 303u;
            } else if (code_text.value().eq(lit_str("TEMPORARY_REDIRECT"))) {
                mapped = 307u;
            } else if (code_text.value().eq(lit_str("PERMANENT_REDIRECT"))) {
                mapped = 308u;
            } else {
                return unsupported(doc_.at(response_code.value()).span,
                                   lit_str("response_code must be one of MOVED_PERMANENTLY, FOUND, "
                                           "SEE_OTHER, TEMPORARY_REDIRECT, PERMANENT_REDIRECT"));
            }
        }
        out->redirect.response_code = mapped;
        return true;
    }

    FrontendResult<bool> parse_cluster(u32 node, Cluster* out) {
        auto ok = expect_object(node, lit_str("cluster must be an object"));
        if (!ok) return ok;
        const Field allowed[] = {kName, kType, kConnectTimeout, kLoadAssignment};
        if (auto r = reject_unknown(node, allowed, 4u); !r) return r;
        out->span = doc_.at(node).span;

        auto name = required(node, kName, lit_str("cluster name is required"));
        if (!name) return core::make_unexpected(name.error());
        auto text =
            name_string(name.value(), false, lit_str("cluster name must be a non-empty string"));
        if (!text) return core::make_unexpected(text.error());
        out->name = text.value();
        out->name_span = doc_.at(name.value()).span;

        auto type = optional(node, kType);
        if (!type) return core::make_unexpected(type.error());
        if (type.value() != kJsonNoNode) {
            auto type_text = plain_string(type.value(), lit_str("cluster type must be a string"));
            if (!type_text) return core::make_unexpected(type_text.error());
            if (!type_text.value().eq(lit_str("STATIC")))
                return unsupported(doc_.at(type.value()).span,
                                   lit_str("only STATIC clusters are supported"));
            out->type_present = true;
            out->type_span = doc_.at(type.value()).span;
        }

        auto timeout =
            required(node, kConnectTimeout, lit_str("cluster connect_timeout is required"));
        if (!timeout) return core::make_unexpected(timeout.error());
        if (auto r = parse_duration(timeout.value(), &out->connect_timeout, /*allow_zero=*/false);
            !r)
            return r;

        auto assignment =
            required(node, kLoadAssignment, lit_str("cluster load_assignment is required"));
        if (!assignment) return core::make_unexpected(assignment.error());
        ok = expect_object(assignment.value(), lit_str("load_assignment must be an object"));
        if (!ok) return ok;
        const Field allowed_assignment[] = {kClusterName, kEndpoints};
        if (auto r = reject_unknown(assignment.value(), allowed_assignment, 2u); !r) return r;

        // ClusterLoadAssignment.cluster_name has `(validate.rules).string =
        // {min_len: 1}` in the v3 API (config/endpoint/v3/endpoint.proto), so
        // an omitted (empty-default) value fails Envoy's own validation; it
        // is required here too, not merely checked when present.
        auto assignment_name = required(
            assignment.value(), kClusterName, lit_str("load_assignment.cluster_name is required"));
        if (!assignment_name) return core::make_unexpected(assignment_name.error());
        auto name_text =
            name_string(assignment_name.value(),
                        false,
                        lit_str("load_assignment.cluster_name must be a non-empty string"));
        if (!name_text) return core::make_unexpected(name_text.error());
        if (!name_text.value().eq(out->name))
            return invalid(doc_.at(assignment_name.value()).span,
                           lit_str("load_assignment.cluster_name must equal the cluster name"));
        out->load_assignment_name_present = true;
        out->load_assignment_name = name_text.value();
        out->load_assignment_name_span = doc_.at(assignment_name.value()).span;

        auto endpoints = required(
            assignment.value(), kEndpoints, lit_str("load_assignment.endpoints is required"));
        if (!endpoints) return core::make_unexpected(endpoints.error());
        auto locality = single_element(endpoints.value(),
                                       lit_str("at least one endpoint is required"),
                                       lit_str("multiple localities are unsupported"));
        if (!locality) return core::make_unexpected(locality.error());
        ok = expect_object(locality.value(), lit_str("locality endpoints must be an object"));
        if (!ok) return ok;
        const Field allowed_locality[] = {kLbEndpoints};
        if (auto r = reject_unknown(locality.value(), allowed_locality, 1u); !r) return r;

        auto lb_endpoints =
            required(locality.value(), kLbEndpoints, lit_str("lb_endpoints is required"));
        if (!lb_endpoints) return core::make_unexpected(lb_endpoints.error());
        auto lb_endpoint = single_element(lb_endpoints.value(),
                                          lit_str("at least one endpoint is required"),
                                          lit_str("multiple endpoints are unsupported"));
        if (!lb_endpoint) return core::make_unexpected(lb_endpoint.error());
        ok = expect_object(lb_endpoint.value(), lit_str("lb endpoint must be an object"));
        if (!ok) return ok;
        const Field allowed_lb[] = {kEndpoint};
        if (auto r = reject_unknown(lb_endpoint.value(), allowed_lb, 1u); !r) return r;

        auto endpoint =
            required(lb_endpoint.value(), kEndpoint, lit_str("lb endpoint endpoint is required"));
        if (!endpoint) return core::make_unexpected(endpoint.error());
        ok = expect_object(endpoint.value(), lit_str("endpoint must be an object"));
        if (!ok) return ok;
        const Field allowed_endpoint[] = {kAddress};
        if (auto r = reject_unknown(endpoint.value(), allowed_endpoint, 1u); !r) return r;
        out->endpoint.span = doc_.at(endpoint.value()).span;

        auto address =
            required(endpoint.value(), kAddress, lit_str("endpoint address is required"));
        if (!address) return core::make_unexpected(address.error());
        return parse_socket_address(address.value(), &out->endpoint.address);
    }

    const JsonDocument& doc_;
};

}  // namespace

FrontendResult<Bootstrap> parse_bootstrap_json(Str source, JsonDocument& doc) {
    auto root = parse_json(source, doc);
    if (!root) return core::make_unexpected(root.error());
    return Parser(doc).run();
}

}  // namespace rut::envoy
