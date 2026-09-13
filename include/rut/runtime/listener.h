#pragma once

#include "core/expected.h"
#include "rut/common/listener_address.h"
#include "rut/common/types.h"

namespace rut {

enum class ListenerTransport : u8 {
    Cleartext = 0,
    Tls = 1,
};

inline bool listener_transport_valid(ListenerTransport transport) {
    return transport == ListenerTransport::Cleartext || transport == ListenerTransport::Tls;
}

struct ListenerSpec {
    ListenerAddress address = ListenerAddress::IPv4Wildcard;
    ListenerTransport transport = ListenerTransport::Cleartext;
    u16 port = 8080;
    u32 ipv4_host = 0;

    bool valid() const {
        return listener_address_valid(address, ipv4_host) && listener_transport_valid(transport);
    }

    bool equivalent(const ListenerSpec& other) const {
        return address == other.address && transport == other.transport && port == other.port &&
               ipv4_host == other.ipv4_host;
    }
};

enum class ListenerResolutionError : u8 {
    ConflictingPorts,
    ConflictingTransport,
    InvalidListenerSpec,
};

// Resolve immutable startup listener metadata from the optional source
// declaration and optional explicit positional CLI port.  This is kept out of
// RouteConfig: listeners are restart-required process configuration, not
// hot-reloadable route state.
inline core::Expected<ListenerSpec, ListenerResolutionError> resolve_listener_spec(
    bool source_present,
    const ListenerSpec& source,
    bool cli_present,
    u16 cli_port,
    ListenerTransport cli_transport = ListenerTransport::Cleartext) {
    if (!listener_transport_valid(cli_transport) || (source_present && !source.valid()))
        return core::make_unexpected(ListenerResolutionError::InvalidListenerSpec);
    const bool cli_listener_present = cli_present || cli_transport == ListenerTransport::Tls;
    if (!source_present && !cli_listener_present) return ListenerSpec{};
    if (!source_present) {
        ListenerSpec result{};
        result.port = cli_present ? cli_port : ListenerSpec{}.port;
        result.transport = cli_transport;
        return result;
    }
    if (cli_listener_present && source.transport != cli_transport)
        return core::make_unexpected(ListenerResolutionError::ConflictingTransport);
    if (!cli_present) return source;
    ListenerSpec cli = source;
    cli.port = cli_port;
    if (!source.equivalent(cli))
        return core::make_unexpected(ListenerResolutionError::ConflictingPorts);
    return source;
}

}  // namespace rut
