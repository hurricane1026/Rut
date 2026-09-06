#pragma once

#include "core/expected.h"
#include "rut/runtime/listener.h"
#include "rut/runtime/socket.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut {

// Runtime identity of the listener that accepted a connection. This is
// process-owned startup state, not hot-reloadable RouteConfig state.
struct ListenerContext {
    ListenerAddress address = ListenerAddress::IPv4Wildcard;
    ListenerTransport transport = ListenerTransport::Cleartext;
    u16 port = 0;  // kernel-assigned port; zero is never a valid bound context
    u32 ipv4_host = 0;

    bool valid() const {
        return port != 0 && listener_address_valid(address, ipv4_host) &&
               listener_transport_valid(transport);
    }

    bool equivalent(const ListenerContext& other) const {
        return address == other.address && transport == other.transport && port == other.port &&
               ipv4_host == other.ipv4_host;
    }
};

enum class ListenerContextError : u8 {
    GetSockName,
    UnsupportedAddress,
    UnsupportedTransport,
    InvalidBoundAddress,
};

// Derive the immutable runtime context from a successfully bound listener.
// Address and port are kernel-observed. Transport is separately validated
// process metadata; getsockname() cannot distinguish cleartext from TLS.
inline core::Expected<ListenerContext, ListenerContextError> derive_listener_context(
    i32 fd, const ListenerSpec& declared, u16 requested_port) {
    if (!listener_address_valid(declared.address, declared.ipv4_host))
        return core::make_unexpected(ListenerContextError::UnsupportedAddress);
    if (!listener_transport_valid(declared.transport))
        return core::make_unexpected(ListenerContextError::UnsupportedTransport);

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) < 0)
        return core::make_unexpected(ListenerContextError::GetSockName);
    if (len < sizeof(sockaddr_in) || bound.sin_family != AF_INET)
        return core::make_unexpected(ListenerContextError::InvalidBoundAddress);

    const u16 bound_port = ntohs(bound.sin_port);
    const u32 bound_ipv4_host = ntohl(bound.sin_addr.s_addr);
    if ((requested_port != 0u && bound_port != requested_port) ||
        (declared.port != 0u && bound_port != declared.port))
        return core::make_unexpected(ListenerContextError::InvalidBoundAddress);
    if ((declared.address == ListenerAddress::IPv4Wildcard && bound_ipv4_host != 0u) ||
        (declared.address == ListenerAddress::IPv4Exact && bound_ipv4_host != declared.ipv4_host))
        return core::make_unexpected(ListenerContextError::InvalidBoundAddress);

    ListenerContext result{declared.address, declared.transport, bound_port, bound_ipv4_host};
    if (!result.valid()) return core::make_unexpected(ListenerContextError::InvalidBoundAddress);
    return result;
}

inline core::Expected<ListenerContext, ListenerContextError> derive_listener_context(
    i32 fd, const ListenerSpec& declared) {
    return derive_listener_context(fd, declared, declared.port);
}

// Bind one shard listener and derive its actual immutable context.  The first
// caller passes expected == nullptr; later SO_REUSEPORT shards pass the first
// context and must resolve to the same address/transport/port.  On every
// context failure this helper closes the just-created fd, leaving ownership
// with the caller only on success.
inline core::Expected<i32, Error> bind_listener_shard(const ListenerSpec& declared,
                                                      u16 requested_port,
                                                      const ListenerContext* expected,
                                                      ListenerContext* out_context) {
    if (out_context == nullptr)
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    *out_context = {};

    // Reject forged metadata before creating a socket so it can never degrade
    // to the legacy wildcard path. A valid but unequal expected context is
    // checked after bind and closes the newly-created fd on mismatch.
    if (!declared.valid() || (expected != nullptr && !expected->valid()))
        return core::make_unexpected(Error::make(EAFNOSUPPORT, Error::Source::Socket));

    auto fd_result = create_listen_socket(declared, requested_port);
    if (!fd_result) return fd_result;
    const i32 fd = fd_result.value();

    auto context = derive_listener_context(fd, declared, requested_port);
    if (!context) {
        close(fd);
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));
    }
    if (expected != nullptr && !context.value().equivalent(*expected)) {
        close(fd);
        return core::make_unexpected(Error::make(EADDRINUSE, Error::Source::Socket));
    }
    *out_context = context.value();
    return fd;
}

}  // namespace rut
