#pragma once

#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"
#include "rut/envoy/json.h"

namespace rut::envoy {

// Envoy v3 bootstrap semantic model for the first converter milestone
// (docs/envoy-converter.md, "Semantic model boundary for the first
// increment"). The model represents exactly one HTTP listener, one wildcard
// virtual host with one catch-all route, and one STATIC cluster with one IPv4
// endpoint. Every field outside that boundary is a source-located diagnostic.
//
// String values borrow the raw bytes of the JSON source; the document must
// stay readable while the model is used. Only escape-free strings are
// admitted, so a borrowed slice is always the literal value.

static constexpr u32 kMaxEnvoyNameLen = 128;

// Every proto3 JSON field is accepted in both its lowerCamelCase and its
// snake_case spelling. Both spellings present at once is a duplicate-field
// diagnostic.
struct SocketAddress {
    // Host byte order; 0 is the IPv4 wildcard.
    u32 ipv4_host = 0;
    u16 port = 0;
    Str address_text{};
    Span address_span{};
    Span port_span{};
    Span span{};
};

// Proto3 JSON `google.protobuf.Duration`: decimal seconds with an `s`
// suffix. The model admits whole seconds and up to three fractional digits.
struct Duration {
    u32 milliseconds = 0;
    Str text{};
    Span span{};
};

struct RouteMatch {
    // Exactly "/" in this increment.
    Str prefix{};
    Span prefix_span{};
    Span span{};
};

struct RouteAction {
    Str cluster{};
    Span cluster_span{};
    Span span{};
};

struct Route {
    RouteMatch match{};
    RouteAction action{};
    Span span{};
};

struct VirtualHost {
    Str name{};
    Span name_span{};
    // `domains` is exactly ["*"] in this increment; the span pins the array.
    Span domains_span{};
    Route route{};
    Span span{};
};

struct RouteConfiguration {
    Str name{};
    Span name_span{};
    VirtualHost virtual_host{};
    Span span{};
};

// `Auto` exists only to name the proto3 enum's zero value; the parser never
// accepts it. `codec_type` must be explicit `HTTP1`: `AUTO` (the default,
// including when the field is omitted) lets Envoy sniff the cleartext
// HTTP/2 preface on a plaintext listener, and this converter is HTTP/1-only.
enum class CodecType : u8 {
    Auto,
    Http1,
};

struct RouterFilter {
    Str name{};
    Span name_span{};
    bool has_typed_config = false;
    Span typed_config_span{};
    Span span{};
};

struct HttpConnectionManager {
    Str stat_prefix{};
    Span stat_prefix_span{};
    // Required; always CodecType::Http1 and codec_type_present == true after
    // a successful parse (see CodecType).
    CodecType codec_type = CodecType::Auto;
    bool codec_type_present = false;
    Span codec_type_span{};
    // Must be present and false: with the Envoy default (true) the upstream
    // request carries a random x-request-id that Rut does not generate.
    Span generate_request_id_span{};
    RouteConfiguration route_config{};
    RouterFilter router{};
    Span type_url_span{};
    Span span{};
};

struct FilterChain {
    Str filter_name{};
    Span filter_name_span{};
    HttpConnectionManager hcm{};
    Span span{};
};

struct Listener {
    Str name{};
    Span name_span{};
    SocketAddress address{};
    FilterChain filter_chain{};
    Span span{};
};

struct Endpoint {
    SocketAddress address{};
    Span span{};
};

struct Cluster {
    Str name{};
    Span name_span{};
    // `type` omitted means STATIC (proto3 enum default); an explicit value
    // must be "STATIC".
    bool type_present = false;
    Span type_span{};
    Duration connect_timeout{};
    // `load_assignment.cluster_name` is required (Envoy's v3
    // `ClusterLoadAssignment.cluster_name` has `min_len: 1`) and must equal
    // `name`; `load_assignment_name_present` is always true after a
    // successful parse and is kept for symmetry with the other
    // presence-tracking fields.
    bool load_assignment_name_present = false;
    Span load_assignment_name_span{};
    Endpoint endpoint{};
    Span span{};
};

struct Bootstrap {
    Listener listener{};
    Cluster cluster{};
    Span span{};
};

// Parse one complete Envoy v3 bootstrap in proto3 JSON encoding into the
// bounded semantic model. `doc` receives the JSON tree and must outlive the
// returned model; the model borrows `source` through it. Everything outside
// the milestone boundary fails closed with the offending field's span.
FrontendResult<Bootstrap> parse_bootstrap_json(Str source, JsonDocument& doc);

}  // namespace rut::envoy
