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
// The current socket creator is intentionally IPv4 wildcard only; callers
// must reject any other kernel result rather than guessing its authority.
inline core::Expected<ListenerContext, ListenerContextError> derive_listener_context(
    i32 fd, const ListenerSpec& declared) {
    if (!listener_address_valid(declared.address, declared.ipv4_host) ||
        declared.address != ListenerAddress::IPv4Wildcard)
        return core::make_unexpected(ListenerContextError::UnsupportedAddress);
    if (!listener_transport_valid(declared.transport))
        return core::make_unexpected(ListenerContextError::UnsupportedTransport);

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) < 0)
        return core::make_unexpected(ListenerContextError::GetSockName);
    if (len < sizeof(sockaddr_in) || bound.sin_family != AF_INET || bound.sin_addr.s_addr != 0)
        return core::make_unexpected(ListenerContextError::InvalidBoundAddress);

    ListenerContext result{declared.address, declared.transport, ntohs(bound.sin_port), 0u};
    if (!result.valid()) return core::make_unexpected(ListenerContextError::InvalidBoundAddress);
    return result;
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

    // Stage 1 carries exact-address metadata but deliberately does not activate
    // exact binding. Reject unsupported or forged metadata before creating a
    // socket so it can never degrade to the legacy wildcard path.
    if (!declared.valid() || declared.address != ListenerAddress::IPv4Wildcard ||
        (expected != nullptr &&
         (!expected->valid() || expected->address != ListenerAddress::IPv4Wildcard)))
        return core::make_unexpected(Error::make(EAFNOSUPPORT, Error::Source::Socket));

    auto fd_result = create_listen_socket(requested_port);
    if (!fd_result) return fd_result;
    const i32 fd = fd_result.value();

    auto context = derive_listener_context(fd, declared);
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
