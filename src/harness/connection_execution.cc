#include "rut/harness/connection_execution.h"

namespace rut::harness {

void ConnectionExecution::reset(u32 peer_addr, u16 peer_port, u32 shard_id) {
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
