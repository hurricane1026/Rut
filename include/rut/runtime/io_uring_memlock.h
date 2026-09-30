#pragma once

// Locked-memory cost of one io_uring shard.
//
// On recent kernels the memory behind an io_uring instance (SQE array, SQ/CQ
// rings) and behind registered provided-buffer rings is charged to the
// per-user locked-memory account, limited by RLIMIT_MEMLOCK for processes
// without CAP_IPC_LOCK. The account is shared by every process of the user, and
// the charge does not show up in /proc (VmLck/VmPin stay 0). When the limit is
// exhausted io_uring_setup / IORING_REGISTER_PBUF_RING fail with ENOMEM.
//
// The functions take sizes as inputs (no globals) so ring sizing can change
// without touching the accounting. The formulas assume power-of-two entry
// counts (the kernel rounds requests up to one) and the default 64-byte SQE /
// 16-byte CQE layout; SQE128, CQE32 and NO_SQARRAY are not covered because Rut
// does not use them.

#include "rut/common/types.h"

#include <linux/io_uring.h>

namespace rut {

// SQ entries requested from io_uring_setup by IoUringBackend::init. The kernel
// sizes the CQ at twice this by default.
static constexpr u32 kIoUringSqEntries = 16384;
static constexpr u32 kIoUringCqEntries = kIoUringSqEntries * 2;
static_assert((kIoUringSqEntries & (kIoUringSqEntries - 1)) == 0,
              "io_uring SQ entries must be a power of two (the kernel rounds up)");

namespace iouring_memlock_detail {
static constexpr u64 kPage = 4096;
// Bytes before the CQE array in the shared ring mapping: params.cq_off.cqes as
// reported by the kernel (sizeof(struct io_rings) on x86-64, 64-byte cache lines:
// head/tail/mask/flags/overflow, each cache-line separated).
static constexpr u64 kRingsHeaderBytes = 320;
constexpr u64 round_up_page(u64 n) {
    return (n + kPage - 1) / kPage * kPage;
}
}  // namespace iouring_memlock_detail

// SQE array + shared SQ/CQ ring mapping (header + CQEs + SQ index array), each
// rounded up to pages as the kernel maps them.
constexpr u64 io_uring_ring_locked_bytes(u32 sq_entries, u32 cq_entries) {
    using namespace iouring_memlock_detail;
    const u64 sqes = round_up_page(static_cast<u64>(sq_entries) * sizeof(io_uring_sqe));
    const u64 rings =
        round_up_page(kRingsHeaderBytes + static_cast<u64>(cq_entries) * sizeof(io_uring_cqe) +
                      static_cast<u64>(sq_entries) * sizeof(u32));
    return sqes + rings;
}

// One registered provided-buffer ring: `entries` 16-byte io_uring_buf slots.
constexpr u64 io_uring_pbuf_ring_locked_bytes(u32 entries) {
    return iouring_memlock_detail::round_up_page(static_cast<u64>(entries) * 16);
}

// Total per-shard charge: the ring plus both provided-buffer rings.
// Measured reference (Linux 7.2.7): SQ 16384 / CQ 32768 with 2048 + 1024
// provided-buffer entries = 1652 KiB (1604 + 32 + 16). If the ring constants
// change and this drifts from the kernel's accounting, the tests will say so.
constexpr u64 io_uring_shard_locked_bytes(u32 sq_entries,
                                          u32 cq_entries,
                                          u32 pbuf_entries,
                                          u32 large_pbuf_entries) {
    return io_uring_ring_locked_bytes(sq_entries, cq_entries) +
           io_uring_pbuf_ring_locked_bytes(pbuf_entries) +
           io_uring_pbuf_ring_locked_bytes(large_pbuf_entries);
}

}  // namespace rut
