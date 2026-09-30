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
//
// The kernel allocates and charges each region in whole pages of the host page
// size (4 KiB on x86-64; 16 KiB or 64 KiB on some arm64 / ppc64 kernels), so
// every function takes `page_bytes`: pass sysconf(_SC_PAGESIZE) for an estimate
// of the running host.

#include "rut/common/types.h"

#include <linux/io_uring.h>

namespace rut {

// Ring sizes requested from io_uring_setup, derived from the per-shard
// connection capacity (IoUringBackend::init passes both to the kernel and the
// startup diagnostic feeds them to the charge functions below).
//
// CQ: 2 x capacity, rounded up to a power of two, within [2048, 65536]. Peak
// unconsumed completions measured at up to ~2 per live connection (burst of
// keep-alive connections, close burst, Connection: close churn, proxied
// requests), and the old fixed 16384 / 32768 pair had the same 2x ratio at the
// default capacity. A transiently full CQ is safe (the kernel parks the excess
// on its overflow list and wait() flushes it), just slower, so this is a
// sizing target, not a hard bound. 65536 is IORING_MAX_CQ_ENTRIES; larger
// requests fail EINVAL.
// SQ: 1024, independent of capacity. wait() submits everything queued each
// iteration and close-path cancels flush immediately, so occupancy is about
// one batch of events (measured peak 256 = kMaxEventsPerWait at every
// capacity), and the recv/accept arms flush and retry when it does fill (see
// IoUringBackend::get_sqe_flushing). 1024 leaves 4x headroom over the
// measured peak, i.e. four SQEs per event of a full batch.
static constexpr u32 kIoUringSqEntries = 1024;
static constexpr u32 kMinIoUringCqEntries = 2048;
static constexpr u32 kMaxIoUringCqEntries = 65536;

struct IoUringRingSizes {
    u32 sq_entries;
    u32 cq_entries;
};

constexpr u32 io_uring_next_pow2(u32 n) {
    u32 p = 1;
    while (p < n) p <<= 1;
    return p;
}

constexpr IoUringRingSizes io_uring_ring_sizes(u32 capacity) {
    // Widen before doubling so a huge capacity cannot wrap.
    const u64 want = static_cast<u64>(capacity) * 2;
    u32 cq = kMaxIoUringCqEntries;
    if (want < kMaxIoUringCqEntries) cq = io_uring_next_pow2(static_cast<u32>(want));
    if (cq < kMinIoUringCqEntries) cq = kMinIoUringCqEntries;
    return {kIoUringSqEntries, cq};
}

namespace iouring_memlock_detail {
constexpr u64 saturating_add(u64 a, u64 b) {
    const u64 max = ~u64(0);
    return b > max - a ? max : a + b;
}

constexpr u64 saturating_mul(u64 a, u64 b) {
    const u64 max = ~u64(0);
    return a != 0 && b > max / a ? max : a * b;
}

// Bytes before the CQE array in the shared ring mapping: params.cq_off.cqes as
// reported by the kernel (sizeof(struct io_rings) on x86-64, 64-byte cache lines:
// head/tail/mask/flags/overflow, each cache-line separated). Architectures with
// wider cache lines have a larger header; with power-of-two entry counts the
// CQE and SQ index arrays fill whole pages, so any header up to one page rounds
// to the same result.
static constexpr u64 kRingsHeaderBytes = 320;
constexpr u64 round_up_page(u64 n, u64 page_bytes) {
    return (n + page_bytes - 1) / page_bytes * page_bytes;
}
}  // namespace iouring_memlock_detail

// SQE array + shared SQ/CQ ring mapping (header + CQEs + SQ index array), each
// rounded up to pages as the kernel maps them.
constexpr u64 io_uring_ring_locked_bytes(u32 sq_entries, u32 cq_entries, u64 page_bytes) {
    using namespace iouring_memlock_detail;
    const u64 sqes = round_up_page(static_cast<u64>(sq_entries) * sizeof(io_uring_sqe), page_bytes);
    const u64 rings =
        round_up_page(kRingsHeaderBytes + static_cast<u64>(cq_entries) * sizeof(io_uring_cqe) +
                          static_cast<u64>(sq_entries) * sizeof(u32),
                      page_bytes);
    return sqes + rings;
}

// One registered provided-buffer ring: `entries` 16-byte io_uring_buf slots.
constexpr u64 io_uring_pbuf_ring_locked_bytes(u32 entries, u64 page_bytes) {
    return iouring_memlock_detail::round_up_page(static_cast<u64>(entries) * 16, page_bytes);
}

// Per-shard charge a shard cannot start without: the ring plus the primary
// provided-buffer ring (IoUringBackend::init fails on either). The large
// provided-buffer ring is optional -- setup_extra_buf_ring leaves it absent
// when registration fails and recvs fall back to the primary ring -- so it is
// excluded here and only counted by io_uring_shard_locked_bytes.
// Measured reference (Linux 7.2.7, 4 KiB pages): SQ 16384 / CQ 32768 with 2048
// provided-buffer entries = 1636 KiB (1604 + 32).
constexpr u64 io_uring_shard_required_locked_bytes(u32 sq_entries,
                                                   u32 cq_entries,
                                                   u32 pbuf_entries,
                                                   u64 page_bytes) {
    return io_uring_ring_locked_bytes(sq_entries, cq_entries, page_bytes) +
           io_uring_pbuf_ring_locked_bytes(pbuf_entries, page_bytes);
}

// Total per-shard charge with every ring registered: the required charge plus
// the optional large provided-buffer ring. This is what a limit should cover
// so no ring is silently skipped.
// Measured reference (Linux 7.2.7, 4 KiB pages): SQ 16384 / CQ 32768 with
// 2048 + 1024 provided-buffer entries = 1652 KiB (1604 + 32 + 16). If the ring
// constants change and this drifts from the kernel's accounting, the tests
// will say so.
constexpr u64 io_uring_shard_locked_bytes(
    u32 sq_entries, u32 cq_entries, u32 pbuf_entries, u32 large_pbuf_entries, u64 page_bytes) {
    return io_uring_shard_required_locked_bytes(sq_entries, cq_entries, pbuf_entries, page_bytes) +
           io_uring_pbuf_ring_locked_bytes(large_pbuf_entries, page_bytes);
}

// Minimum locked memory for sequential startup of all shards. Every shard
// needs its required rings, while each successful shard before the last can
// also retain its optional large ring before the final required allocation.
// Calculated in bytes so page-rounded charges are not mixed with KiB values;
// saturating arithmetic keeps diagnostics valid if sizing inputs grow beyond
// the u64 range.
constexpr u64 io_uring_startup_min_locked_bytes(u32 shard_count,
                                                u64 required_per_shard,
                                                u64 optional_per_shard) {
    using namespace iouring_memlock_detail;
    const u64 required = saturating_mul(required_per_shard, shard_count);
    const u64 earlier_optional =
        saturating_mul(optional_per_shard, shard_count == 0 ? 0 : shard_count - 1);
    return saturating_add(required, earlier_optional);
}

}  // namespace rut
