#pragma once

#include "rut/common/types.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/slice_pool.h"

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
    u8 send_storage[SlicePool::kSliceSize]{};

    ConnectionExecution();
    ConnectionExecution(const ConnectionExecution&) = delete;
    ConnectionExecution& operator=(const ConnectionExecution&) = delete;
    ConnectionExecution(ConnectionExecution&&) = delete;
    ConnectionExecution& operator=(ConnectionExecution&&) = delete;
    void reset(u32 peer_addr = 0, u16 peer_port = 0, u32 shard_id = 0);
    u64 invariant_violations() const;
    void destroy();
};

constexpr u64 invariant_bit(ConnectionInvariant invariant) {
    return u64{1} << static_cast<u8>(invariant);
}

const char* connection_invariant_name(ConnectionInvariant invariant);

}  // namespace rut::harness
