#pragma once

#include "core/expected.h"
#include "rut/runtime/listener.h"

#include <netinet/in.h>
#include <sys/socket.h>

namespace rut {

// Runtime identity of the listener that accepted a connection. This is
// process-owned startup state, not hot-reloadable RouteConfig state.
struct ListenerContext {
    ListenerAddress address = ListenerAddress::IPv4Wildcard;
    ListenerTransport transport = ListenerTransport::Cleartext;
    u16 port = 0;  // kernel-assigned port; zero is never a valid bound context

    bool valid() const {
        return port != 0 && address == ListenerAddress::IPv4Wildcard &&
               (transport == ListenerTransport::Cleartext || transport == ListenerTransport::Tls);
    }

    bool equivalent(const ListenerContext& other) const {
        return address == other.address && transport == other.transport && port == other.port;
    }
};

enum class ListenerContextError : u8 {
    GetSockName,
    UnsupportedAddress,
    UnsupportedTransport,
    InvalidBoundAddress,
};

// Derive the immutable runtime context from a successfully bound listener.
// The current socket creator is intentionally IPv4 wildcard only; callers
// must reject any other kernel result rather than guessing its authority.
inline core::Expected<ListenerContext, ListenerContextError> derive_listener_context(
    i32 fd, const ListenerSpec& declared) {
    if (declared.address != ListenerAddress::IPv4Wildcard)
        return core::make_unexpected(ListenerContextError::UnsupportedAddress);
    if (declared.transport != ListenerTransport::Cleartext &&
        declared.transport != ListenerTransport::Tls)
        return core::make_unexpected(ListenerContextError::UnsupportedTransport);

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) < 0)
        return core::make_unexpected(ListenerContextError::GetSockName);
    if (len < sizeof(sockaddr_in) || bound.sin_family != AF_INET || bound.sin_addr.s_addr != 0)
        return core::make_unexpected(ListenerContextError::InvalidBoundAddress);

    ListenerContext result{declared.address, declared.transport, ntohs(bound.sin_port)};
    if (!result.valid()) return core::make_unexpected(ListenerContextError::InvalidBoundAddress);
    return result;
}

}  // namespace rut
