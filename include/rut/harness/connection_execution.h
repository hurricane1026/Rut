#pragma once

#include "rut/common/types.h"
#include "rut/runtime/connection.h"

namespace rut::harness {

enum class ConnectionInvariant : u8 {
    CallbackSlotsClear = 0,
    NoPendingHandler,
    NoPendingOperations,
    NoArmedYield,
    NoUpstreamDescriptor,
};

struct ConnectionExecution {
    Connection connection{};

    void reset(u32 peer_addr = 0, u16 peer_port = 0, u32 shard_id = 0);
    u64 invariant_violations() const;
    void destroy();
};

constexpr u64 invariant_bit(ConnectionInvariant invariant) {
    return u64{1} << static_cast<u8>(invariant);
}

const char* connection_invariant_name(ConnectionInvariant invariant);

}  // namespace rut::harness
