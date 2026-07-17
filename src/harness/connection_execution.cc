#include "rut/harness/connection_execution.h"

#include <unistd.h>

namespace rut::harness {
namespace {

void close_owned_descriptors(Connection& connection) {
    const i32 descriptors[] = {connection.fd, connection.upstream_fd, connection.idle_return_fd};
    for (u32 i = 0; i < 3; i++) {
        if (descriptors[i] < 0) continue;
        bool duplicate = false;
        for (u32 j = 0; j < i; j++) {
            if (descriptors[j] == descriptors[i]) duplicate = true;
        }
        if (!duplicate) (void)::close(descriptors[i]);
    }
}

}  // namespace

ConnectionExecution::ConnectionExecution() {
    // The aggregate member is zero-initialized, including its descriptors.
    // Establish the descriptor sentinel before using the ownership-aware reset.
    connection.fd = -1;
    connection.upstream_fd = -1;
    connection.idle_return_fd = -1;
    reset();
}

void ConnectionExecution::reset(u32 peer_addr, u16 peer_port, u32 shard_id) {
    close_owned_descriptors(connection);
    connection.reset();
    connection.peer_addr = peer_addr;
    connection.peer_port = peer_port;
    connection.shard_id = shard_id;
}

u64 ConnectionExecution::invariant_violations() const {
    u64 violations = 0;
    if (connection.on_recv != nullptr || connection.on_send != nullptr ||
        connection.on_upstream_recv != nullptr || connection.on_upstream_send != nullptr)
        violations |= invariant_bit(ConnectionInvariant::CallbackSlotsClear);
    if (connection.pending_handler_fn != nullptr || connection.handler_ctx != nullptr)
        violations |= invariant_bit(ConnectionInvariant::NoPendingHandler);
    if (connection.pending_ops != 0)
        violations |= invariant_bit(ConnectionInvariant::NoPendingOperations);
    if (connection.yield_armed || connection.yield_timeout_armed)
        violations |= invariant_bit(ConnectionInvariant::NoArmedYield);
    if (connection.upstream_fd != -1)
        violations |= invariant_bit(ConnectionInvariant::NoUpstreamDescriptor);
    return violations;
}

void ConnectionExecution::destroy() {
    close_owned_descriptors(connection);
    connection.reset();
}

const char* connection_invariant_name(ConnectionInvariant invariant) {
    switch (invariant) {
        case ConnectionInvariant::CallbackSlotsClear:
            return "callback-slots-clear";
        case ConnectionInvariant::NoPendingHandler:
            return "no-pending-handler";
        case ConnectionInvariant::NoPendingOperations:
            return "no-pending-operations";
        case ConnectionInvariant::NoArmedYield:
            return "no-armed-yield";
        case ConnectionInvariant::NoUpstreamDescriptor:
            return "no-upstream-descriptor";
    }
    return "unknown";
}

}  // namespace rut::harness
