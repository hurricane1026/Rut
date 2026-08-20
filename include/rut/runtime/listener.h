#pragma once

#include "core/expected.h"
#include "rut/common/types.h"

namespace rut {

// The first listener slice is deliberately explicit about the dimensions that
// are fixed by the supported declaration.  Adding another address family or
// transport later must be an intentional capability change, not an accidental
// interpretation of a port number.
enum class ListenerAddress : u8 {
    IPv4Wildcard,
};

enum class ListenerTransport : u8 {
    Cleartext,
    Tls,
};

struct ListenerSpec {
    ListenerAddress address = ListenerAddress::IPv4Wildcard;
    ListenerTransport transport = ListenerTransport::Cleartext;
    u16 port = 8080;

    bool equivalent(const ListenerSpec& other) const {
        return address == other.address && transport == other.transport && port == other.port;
    }
};

enum class ListenerResolutionError : u8 {
    ConflictingPorts,
    ConflictingTransport,
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
