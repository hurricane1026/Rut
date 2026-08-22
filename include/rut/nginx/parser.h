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

struct Location {
    Str path{};
    Span path_span{};
    Span span{};
    ProxyPass proxy_pass{};
    ProxyReadTimeout proxy_read_timeout{};
};

struct Server {
    Span span{};
    Listen listen{};
    Location location{};
};

// Parse exactly one minimal nginx server fragment. The returned model borrows
// strings from source; the caller owns the source storage for its lifetime.
FrontendResult<Server> parse(Str source);

}  // namespace rut::nginx
