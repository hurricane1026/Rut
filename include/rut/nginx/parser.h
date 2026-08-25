#pragma once

#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"

namespace rut::nginx {

struct Listen {
    u16 port = 0;
    Span span{};
};

struct ProxyPass {
    u8 address[4]{};
    u16 port = 0;
    bool has_uri = false;
    Str uri{};
    Span uri_span{};
    Span span{};
};

struct ProxyReadTimeout {
    bool present = false;
    u32 milliseconds = 0;
    Span span{};
    Span value_span{};
};

// Existing bounded prefix-location proxy action. This remains separate from
// the exact local-return action below so source order cannot change their
// semantic roles.
struct Location {
    Str path{};
    Span path_span{};
    Span span{};
    ProxyPass proxy_pass{};
    ProxyReadTimeout proxy_read_timeout{};
};

// The nginx lexer currently has no quoted-string escape mode. Keep this first
// local-response slice honest and lossless: one non-empty, quote-delimited,
// token-safe printable ASCII body of at most 64 bytes, borrowed from source.
static constexpr u32 kMaxLocalReturnBodyLen = 64;

struct LocalReturn {
    u16 status = 0;
    Str body{};
    Span body_span{};
    Span span{};
};

struct ExactLocalReturnLocation {
    bool present = false;
    Str path{};
    Span path_span{};
    Span span{};
    LocalReturn response{};
};

// Closed canonical profiles for implicit nginx behavior that precedes route
// selection.  This is semantic-model metadata, not an nginx directive or a
// runtime mode; the converter owns every emitted policy byte for each profile.
enum class ImplicitPreRouteProfile : u8 {
    None,
    Nginx1297PreLocationTrace405,
};

// nginx rejects TRACE during request processing, before location selection, in
// the bounded root-proxy plus exact-local fragment. `span` is the exact source
// location whose accepted shape establishes that semantic fact.
struct ImplicitPreRouteTrace {
    ImplicitPreRouteProfile profile = ImplicitPreRouteProfile::None;
    Span span{};
};

struct Server {
    Span span{};
    Listen listen{};
    // `location` is always the proxy fallback, independent of declaration
    // order. `exact_local_return` is the optional exact selector/action.
    Location location{};
    ExactLocalReturnLocation exact_local_return{};
    ImplicitPreRouteTrace pre_route_trace{};
};

// Parse exactly one minimal nginx server fragment. The returned model borrows
// strings from source; the caller owns the source storage for its lifetime.
FrontendResult<Server> parse(Str source);

}  // namespace rut::nginx
