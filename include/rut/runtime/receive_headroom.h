#pragma once

#include "rut/runtime/connection.h"
#include "rut/runtime/slice_pool.h"

namespace rut {
// Call only after parser views and direct kernel borrowers have retired.
// Selected-buffer receives write elsewhere, so their outstanding CQEs do not
// borrow this application slice. Allocation failure leaves its ownership intact.
template <typename Pool>
bool reserve_request_receive_headroom(Pool& pool, Connection& conn, u32 minimum) {
    if (conn.recv_buf.write_avail() >= minimum) return true;
    const u32 used = conn.recv_buf.len();
    if (minimum > SlicePool::kBulkSliceSize || used > SlicePool::kBulkSliceSize - minimum)
        return false;
    u8* storage = pool.alloc_bulk();
    if (!storage) return false;
    if (used) __builtin_memcpy(storage, conn.recv_buf.data(), used);
    pool.free(conn.recv_slice);
    conn.bind_request_receive_buffer(storage, SlicePool::kBulkSliceSize);
    conn.recv_buf.commit(used);
    return true;
}
}  // namespace rut
