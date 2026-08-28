#include "rut/runtime/access_log_live.h"
#include "test.h"
#include <atomic>
#include <cstring>
#include <limits>
#include <thread>

using namespace rut;

namespace {

AccessLogEntry live_entry(u64 sequence) {
    AccessLogEntry entry{};
    entry.timestamp_us = sequence;
    entry.duration_us = static_cast<u32>(sequence ^ 0xa5a5a5a5u);
    entry.req_size = static_cast<u32>(sequence);
    entry.resp_size = static_cast<u32>(sequence * 3u);
    entry.upstream_us = static_cast<u32>(sequence * 5u);
    entry.addr = static_cast<u32>(sequence ^ 0x0100007fu);
    entry.status = static_cast<u16>(200u + sequence % 300u);
    entry.method = static_cast<u8>(sequence % 10u);
    entry.shard_id = static_cast<u8>(sequence % 64u);
    for (u32 i = 0; i < sizeof(entry.path); i++)
        entry.path[i] = static_cast<char>('a' + (sequence + i) % 26u);
    for (u32 i = 0; i < sizeof(entry.upstream); i++)
        entry.upstream[i] = static_cast<char>('A' + (sequence + i) % 26u);
    entry.target_length = kAccessLogCompleteTargetMax;
    entry.target_state = AccessLogTargetState::Complete;
    return entry;
}

bool entry_is(const AccessLogEntry& actual, u64 sequence) {
    const AccessLogEntry expected = live_entry(sequence);
    return std::memcmp(&actual, &expected, sizeof(actual)) == 0;
}

bool peek_is(const LiveAccessLogPeek& peek, u64 position, u64 sequence) {
    return peek.valid && peek.entry != nullptr && peek.position == position &&
           entry_is(*peek.entry, sequence);
}

u64 entries_hash(const LiveAccessLogRing& ring) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(ring.entries);
    u64 hash = 1469598103934665603ull;
    for (u32 i = 0; i < sizeof(ring.entries); i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

}  // namespace

TEST(access_log_live, layout_and_empty_protocol_are_explicit) {
    static_assert(LiveAccessLogRing::kCapacity == 512u);
    static_assert(alignof(LiveAccessLogRing) == 64u);
    static_assert(offsetof(LiveAccessLogRing, published_pos) == 0u);
    static_assert(offsetof(LiveAccessLogRing, committed_pos) == 64u);
    static_assert(offsetof(LiveAccessLogRing, entries) == 128u);
    static_assert(sizeof(AccessLogEntry) == 192u);
    static_assert(sizeof(AccessLogRing) == 98432u);

    LiveAccessLogRing ring;
    ring.init();
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 0u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    const LiveAccessLogPeek empty = ring.peek();
    CHECK_FALSE(empty.valid);
    CHECK_EQ(empty.entry, nullptr);
    CHECK_EQ(empty.position, 0u);
    CHECK_FALSE(ring.commit(0u));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK_FALSE(ring.acknowledged({false, 0u}));
    CHECK_FALSE(ring.acknowledged({true, 1u}));
}

TEST(access_log_live, publish_peek_commit_and_ack_are_causal) {
    LiveAccessLogRing ring;
    ring.init();
    const AccessLogEntry entry = live_entry(17u);
    const LiveAccessLogPublishResult published = ring.try_publish(entry);
    CHECK(published.status == LiveAccessLogPublishStatus::Published);
    CHECK(published.ticket.valid);
    CHECK_EQ(published.ticket.end_position, 1u);
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 1u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK_FALSE(ring.acknowledged(published.ticket));

    const LiveAccessLogPeek first = ring.peek();
    CHECK(peek_is(first, 0u, 17u));
    const LiveAccessLogPeek repeated = ring.peek();
    CHECK(peek_is(repeated, 0u, 17u));
    CHECK_EQ(repeated.entry, first.entry);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK(ring.commit(first.position));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 1u);
    CHECK(ring.acknowledged(published.ticket));
    CHECK_FALSE(ring.peek().valid);

    AccessLogEntry corrupted = entry;
    corrupted.req_size++;
    CHECK_FALSE(entry_is(corrupted, 17u));
    CHECK_FALSE(peek_is(first, 1u, 17u));
    CHECK_FALSE(peek_is(first, 0u, 18u));
}

TEST(access_log_live, multiple_entries_remain_fifo) {
    LiveAccessLogRing ring;
    ring.init();
    LiveAccessLogTicket tickets[4];
    for (u64 sequence = 0; sequence < 4u; sequence++) {
        const auto result = ring.try_publish(live_entry(sequence));
        REQUIRE(result.status == LiveAccessLogPublishStatus::Published);
        tickets[sequence] = result.ticket;
    }
    for (u64 sequence = 0; sequence < 4u; sequence++) {
        const LiveAccessLogPeek peek = ring.peek();
        REQUIRE(peek_is(peek, sequence, sequence));
        CHECK_FALSE(ring.acknowledged(tickets[sequence]));
        REQUIRE(ring.commit(sequence));
        CHECK(ring.acknowledged(tickets[sequence]));
    }
    CHECK_FALSE(ring.peek().valid);
}

TEST(access_log_live, full_rejects_transactionally_then_one_commit_reopens_one_slot) {
    LiveAccessLogRing ring;
    ring.init();
    for (u64 sequence = 0; sequence < LiveAccessLogRing::kCapacity; sequence++) {
        const auto result = ring.try_publish(live_entry(sequence));
        REQUIRE(result.status == LiveAccessLogPublishStatus::Published);
        REQUIRE(result.ticket.valid);
        CHECK_EQ(result.ticket.end_position, sequence + 1u);
    }
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 512u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    const u64 before_hash = entries_hash(ring);
    const LiveAccessLogPeek before = ring.peek();
    REQUIRE(peek_is(before, 0u, 0u));

    const auto full = ring.try_publish(live_entry(9999u));
    CHECK(full.status == LiveAccessLogPublishStatus::Full);
    CHECK_FALSE(full.ticket.valid);
    CHECK_EQ(full.ticket.end_position, 0u);
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 512u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK_EQ(entries_hash(ring), before_hash);
    CHECK(peek_is(ring.peek(), 0u, 0u));

    REQUIRE(ring.commit(0u));
    const auto reopened = ring.try_publish(live_entry(512u));
    REQUIRE(reopened.status == LiveAccessLogPublishStatus::Published);
    CHECK(reopened.ticket.valid);
    CHECK_EQ(reopened.ticket.end_position, 513u);
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), 513u);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 1u);
    CHECK_NE(entries_hash(ring), before_hash);
}

TEST(access_log_live, commit_rejects_wrong_stale_future_and_empty_positions) {
    LiveAccessLogRing ring;
    ring.init();
    REQUIRE(ring.try_publish(live_entry(10u)).status == LiveAccessLogPublishStatus::Published);
    REQUIRE(ring.try_publish(live_entry(11u)).status == LiveAccessLogPublishStatus::Published);

    CHECK_FALSE(ring.commit(1u));
    CHECK_FALSE(ring.commit(std::numeric_limits<u64>::max()));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 0u);
    CHECK(peek_is(ring.peek(), 0u, 10u));
    REQUIRE(ring.commit(0u));
    CHECK_FALSE(ring.commit(0u));
    CHECK_FALSE(ring.commit(2u));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 1u);
    CHECK(peek_is(ring.peek(), 1u, 11u));
    REQUIRE(ring.commit(1u));
    CHECK_FALSE(ring.commit(2u));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 2u);
    CHECK_FALSE(ring.peek().valid);
}

TEST(access_log_live, wrap_tickets_zero_and_positions_remain_valid) {
    constexpr u64 kMax = std::numeric_limits<u64>::max();
    LiveAccessLogRing ring;
    ring.init_quiescent_empty(kMax - 1u);
    const auto first = ring.try_publish(live_entry(1u));
    const auto second = ring.try_publish(live_entry(2u));
    const auto third = ring.try_publish(live_entry(3u));
    REQUIRE(first.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(second.status == LiveAccessLogPublishStatus::Published);
    REQUIRE(third.status == LiveAccessLogPublishStatus::Published);
    CHECK(first.ticket.valid);
    CHECK(second.ticket.valid);
    CHECK(third.ticket.valid);
    CHECK_EQ(first.ticket.end_position, kMax);
    CHECK_EQ(second.ticket.end_position, 0u);
    CHECK_EQ(third.ticket.end_position, 1u);

    REQUIRE(peek_is(ring.peek(), kMax - 1u, 1u));
    CHECK_FALSE(ring.acknowledged(first.ticket));
    REQUIRE(ring.commit(kMax - 1u));
    CHECK(ring.acknowledged(first.ticket));
    CHECK_FALSE(ring.acknowledged(second.ticket));
    REQUIRE(peek_is(ring.peek(), kMax, 2u));
    REQUIRE(ring.commit(kMax));
    CHECK(ring.acknowledged(second.ticket));
    CHECK_FALSE(ring.acknowledged(third.ticket));
    REQUIRE(peek_is(ring.peek(), 0u, 3u));
    REQUIRE(ring.commit(0u));
    CHECK(ring.acknowledged(third.ticket));
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), 1u);
    CHECK_FALSE(ring.peek().valid);
}

TEST(access_log_live, acknowledgement_uses_unsigned_half_range_order) {
    constexpr u64 kHalf = u64{1} << 63u;
    LiveAccessLogRing ring;
    ring.init_quiescent_empty(0u);
    CHECK_FALSE(ring.acknowledged({false, 0u}));
    CHECK(ring.acknowledged({true, 0u}));
    CHECK(ring.acknowledged({true, std::numeric_limits<u64>::max()}));
    CHECK(ring.acknowledged({true, kHalf + 1u}));
    CHECK_FALSE(ring.acknowledged({true, kHalf}));
    CHECK_FALSE(ring.acknowledged({true, 1u}));
}

TEST(access_log_live, threaded_release_acquire_spsc_preserves_exact_order) {
    constexpr u64 kCount = 4096u;
    LiveAccessLogRing ring;
    ring.init();
    std::atomic<u32> ready{0u};
    std::atomic<bool> start{false};
    std::atomic<bool> abort{false};
    std::atomic<u64> final_ticket_end{0u};

    std::thread producer([&] {
        ready.fetch_add(1u, std::memory_order_release);
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (u64 sequence = 0u; sequence < kCount && !abort.load(std::memory_order_acquire);) {
            const auto result = ring.try_publish(live_entry(sequence));
            if (result.status == LiveAccessLogPublishStatus::Published) {
                if (!result.ticket.valid) {
                    abort.store(true, std::memory_order_release);
                    break;
                }
                final_ticket_end.store(result.ticket.end_position, std::memory_order_relaxed);
                sequence++;
            } else if (result.status == LiveAccessLogPublishStatus::Full) {
                std::this_thread::yield();
            } else {
                abort.store(true, std::memory_order_release);
            }
        }
    });

    std::thread consumer([&] {
        ready.fetch_add(1u, std::memory_order_release);
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (u64 sequence = 0u; sequence < kCount && !abort.load(std::memory_order_acquire);) {
            const LiveAccessLogPeek peek = ring.peek();
            if (!peek.valid) {
                std::this_thread::yield();
                continue;
            }
            if (!peek_is(peek, sequence, sequence) || !ring.commit(peek.position)) {
                abort.store(true, std::memory_order_release);
                break;
            }
            sequence++;
        }
    });

    while (ready.load(std::memory_order_acquire) != 2u) std::this_thread::yield();
    start.store(true, std::memory_order_release);
    producer.join();
    consumer.join();

    CHECK_FALSE(abort.load(std::memory_order_acquire));
    CHECK_EQ(ring.published_pos.load(std::memory_order_relaxed), kCount);
    CHECK_EQ(ring.committed_pos.load(std::memory_order_relaxed), kCount);
    const LiveAccessLogTicket final_ticket{true, final_ticket_end.load(std::memory_order_relaxed)};
    CHECK_EQ(final_ticket.end_position, kCount);
    CHECK(ring.acknowledged(final_ticket));
    CHECK_FALSE(ring.peek().valid);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
