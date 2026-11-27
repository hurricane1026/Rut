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

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
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
// default capacity. This is a sizing target, not a bound. Single-shot
// completions that find the CQ full go to the kernel's overflow list (flushed
// by the next enter, which wait() issues when IORING_SQ_CQ_OVERFLOW is set) and
// are not lost, but a MULTISHOT recv or accept that fires into a full CQ (or
// behind a non-empty overflow list) posts one terminal CQE without F_MORE and is
// dead. Correctness rests on every such terminal being re-armed: downstream
// recv (generic accounting clears recv_armed; on_header_received re-arms on an
// incomplete request, on_response_sent after a complete one, plus
// handle_unhandled_recv and the mid-yield, boundary-deferred, pause and TLS
// paths) and accept (on_accept_terminated -> rearm_accept). A full CQ therefore
// costs extra re-arm SQEs, not connections. 65536 is IORING_MAX_CQ_ENTRIES;
// larger requests fail EINVAL.
// SQ: 1024, independent of capacity. wait() submits everything queued each
// iteration and close-path cancels flush immediately, so occupancy is about
// one batch of events (measured peak 256 = kMaxEventsPerWait at every
// capacity). A burst can still fill it (thousands of timeouts expiring in one
// timer tick each queue a send), so every submitter that cannot park its request
// flushes and retries when it does (IoUringBackend::get_sqe_flushing). 1024
// leaves 4x headroom over the measured peak.
static constexpr u32 kIoUringSqEntries = 1024;
static constexpr u32 kMinIoUringCqEntries = 2048;
static constexpr u32 kMaxIoUringCqEntries = 65536;

struct IoUringRingSizes {
    u32 sq_entries;
    u32 cq_entries;
};

// Smallest power of two >= n; saturates at 2^31 (the largest u32 power of two).
constexpr u32 io_uring_next_pow2(u32 n) {
    u32 p = 1;
    // RUT_INTEGER_RANGE: the shifted power of two starts below 2^31.
    while (p < n && p < (1u << 31)) p <<= 1;
    return p;
}

constexpr IoUringRingSizes io_uring_ring_sizes(u32 capacity) {
    const auto want = range_int(capacity).scaled_by<2>();
    u32 cq = io_uring_next_pow2(
        want.min(range_int<kMaxIoUringCqEntries, i64{kMaxIoUringCqEntries} + 1>{}).to<u32>());
    if (cq < kMinIoUringCqEntries) cq = kMinIoUringCqEntries;
    return {kIoUringSqEntries, cq};
}

namespace iouring_memlock_detail {
// RUT_INTEGER_RANGE: an unrepresentable estimate must remain above any finite limit.
constexpr u64 saturating_add(u64 a, u64 b) {
    u64 result = 0;
    return add_overflow(a, b, &result) ? ~u64(0) : result;
}

constexpr u64 saturating_mul(u64 a, u64 b) {
    u64 result = 0;
    return mul_overflow(a, b, &result) ? ~u64(0) : result;
}

// Bytes before the CQE array in the shared ring mapping: params.cq_off.cqes as
// reported by the kernel (sizeof(struct io_rings) on x86-64, 64-byte cache lines:
// head/tail/mask/flags/overflow, each cache-line separated). Architectures with
// wider cache lines have a larger header; with power-of-two entry counts the
// CQE and SQ index arrays fill whole pages, so any header up to one page rounds
// to the same result.
static constexpr i64 kRingsHeaderBytes = 320;
constexpr u64 round_up_page(u64 n, u64 page_bytes) {
    if (page_bytes == 0) return 0;
    const u64 remainder = n % page_bytes;
    if (remainder == 0) return n;
    const u64 increment = static_cast<u64>(__int128_t{page_bytes} - __int128_t{remainder});
    return iouring_memlock_detail::saturating_add(n, increment);
}
}  // namespace iouring_memlock_detail

// SQE array + shared SQ/CQ ring mapping (header + CQEs + SQ index array), each
// rounded up to pages as the kernel maps them.
constexpr u64 io_uring_ring_locked_bytes(u32 sq_entries, u32 cq_entries, u64 page_bytes) {
    using namespace iouring_memlock_detail;
    const auto kSq = range_int(sq_entries);
    const auto kCq = range_int(cq_entries);
    constexpr auto kHeader = range_int<kRingsHeaderBytes, kRingsHeaderBytes + 1>{};
    const auto kRings =
        kHeader + kCq.scaled_by<sizeof(io_uring_cqe)>() + kSq.scaled_by<sizeof(u32)>();
    const u64 sqes = round_up_page(kSq.scaled_by<sizeof(io_uring_sqe)>().to_u64(), page_bytes);
    const u64 rings = round_up_page(kRings.to_u64(), page_bytes);
    return saturating_add(sqes, rings);
}

// One registered provided-buffer ring: `entries` 16-byte io_uring_buf slots.
constexpr u64 io_uring_pbuf_ring_locked_bytes(u32 entries, u64 page_bytes) {
    return iouring_memlock_detail::round_up_page(
        range_int(entries).scaled_by<sizeof(io_uring_buf)>().to_u64(), page_bytes);
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
    return iouring_memlock_detail::saturating_add(
        io_uring_ring_locked_bytes(sq_entries, cq_entries, page_bytes),
        io_uring_pbuf_ring_locked_bytes(pbuf_entries, page_bytes));
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
    return iouring_memlock_detail::saturating_add(
        io_uring_shard_required_locked_bytes(sq_entries, cq_entries, pbuf_entries, page_bytes),
        io_uring_pbuf_ring_locked_bytes(large_pbuf_entries, page_bytes));
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
        saturating_mul(optional_per_shard,
                       shard_count == 0 ? 0 : static_cast<u64>(static_cast<i64>(shard_count) - 1));
    return saturating_add(required, earlier_optional);
}

}  // namespace rut
