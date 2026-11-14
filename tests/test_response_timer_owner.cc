#include "rut/common/types.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/io_uring_backend.h"
#include "test.h"

#include <linux/io_uring.h>

using namespace rut;

namespace {
struct Queue {
    IoUringBackend backend;
    u32 head = 0;
    u32 tail = 0;
    u32 mask = 3;
    u32 array[4]{};
    io_uring_sqe entries[4]{};
    Queue() {
        backend.connection_capacity = 1;
        backend.sq_head = &head;
        backend.sq_tail = &tail;
        backend.sq_ring_mask = &mask;
        backend.sq_array = array;
        backend.sq_entries = entries;
        backend.sq_ring_entries = 4;
        backend.disable_full_sq_flush = true;
    }
    void capacity(bool kAvailable) {
        head = 0;
        tail = kAvailable ? 0 : 4;
    }
};

// Independent contract: two obligations, a persistent generation counter and
// immutable borrowed storage. No production validity predicate drives it.
struct Oracle {
    u32 generation;
    u32 owners = 0;  // target=1, cancel=2
    bool cancelling = false;
};

void check(rut::test::TestCase* _tc, const Connection& c, const Oracle& expected) {
    CHECK_EQ(c.response_read_timer_generation, expected.generation);
    CHECK_EQ(c.response_read_timer_target_owned, (expected.owners & 1u) != 0);
    CHECK_EQ(c.response_read_timer_cancel_owned, (expected.owners & 2u) != 0);
    CHECK_EQ(c.response_read_timer_owner_generation, expected.owners ? expected.generation : 0u);
    CHECK_EQ(c.response_read_timer_phase,
             expected.owners == 0  ? ResponseReadTimerPhase::None
             : expected.cancelling ? ResponseReadTimerPhase::CancelPending
                                   : ResponseReadTimerPhase::Armed);
    CHECK_EQ(c.response_read_timer_timespec.tv_sec, expected.owners ? 1 : 0);
    CHECK_EQ(c.response_read_timer_timespec.tv_nsec, expected.owners ? 41'000'000 : 0);
    CHECK_EQ(c.response_read_timer_deadline_generation, expected.owners ? 17u : 0u);
    CHECK_EQ(c.response_read_timer_upstream_episode, expected.owners ? 23u : 0u);
    CHECK_EQ(c.response_read_timer_owner_is_neutral(), expected.owners == 0);
    CHECK(c.response_read_timer_owner_is_valid());
}

void replay(rut::test::TestCase* _tc, u32 trace, u32 origin) {
    Connection c{};
    c.reset();
    c.id = 0;
    c.response_read_timer_generation = origin;
    Queue queue;
    Oracle expected{origin};
    for (u32 step = 0; step < 4; ++step) {
        const u32 kAction = trace % 11;
        trace /= 11;
        const u32 kPending = queue.backend.pending;
        bool published = false;
        if (kAction < 2) {
            const bool kAvailable = kAction == 0;
            queue.capacity(kAvailable);
            const bool kAdmitted = kAvailable && expected.owners == 0 &&
                                   expected.generation < kResponseReadTimerGenerationMask;
            CHECK_EQ(queue.backend.add_response_read_timer(0, c, 1041, 17, 23), kAdmitted);
            if (kAdmitted) {
                ++expected.generation;
                expected.owners = 1;
                expected.cancelling = false;
                published = true;
                CHECK_EQ(queue.entries[0].opcode, IORING_OP_TIMEOUT);
                CHECK_EQ(queue.entries[0].addr,
                         reinterpret_cast<u64>(&c.response_read_timer_timespec));
                CHECK_EQ(queue.entries[0].user_data,
                         IoUringBackend::encode_user_data(
                             0, IoEventType::ResponseReadTimer, expected.generation));
            }
        } else if (kAction < 4) {
            const bool kAvailable = kAction == 2;
            queue.capacity(kAvailable);
            const bool kAdmitted = kAvailable && expected.owners == 1 && !expected.cancelling;
            CHECK_EQ(queue.backend.cancel_response_read_timer(0, c), kAdmitted);
            if (kAdmitted) {
                expected.owners |= 2;
                expected.cancelling = true;
                published = true;
                CHECK_EQ(queue.entries[0].opcode, IORING_OP_ASYNC_CANCEL);
                CHECK_EQ(queue.entries[0].addr,
                         IoUringBackend::encode_user_data(
                             0, IoEventType::ResponseReadTimer, expected.generation));
                CHECK_EQ(queue.entries[0].user_data,
                         IoUringBackend::encode_user_data(
                             0,
                             IoEventType::ResponseReadTimer,
                             expected.generation | kResponseReadTimerCancelBit));
            }
        } else if (kAction < 6) {
            const u32 kBit = kAction == 4 ? 1 : 2;
            const bool kAdmitted = (expected.owners & kBit) != 0;
            const u32 kTag = expected.generation | (kBit == 2 ? kResponseReadTimerCancelBit : 0u);
            CHECK_EQ(c.consume_response_read_timer_completion(kTag), kAdmitted);
            if (kAdmitted) expected.owners &= ~kBit;
        } else if (kAction == 6) {
            c.reset();
            c.id = 0;
        } else if (kAction == 7) {
            CHECK_EQ(c.clear_response_read_timer_owner(), expected.owners == 0);
        } else {
            // Wrong generation, zero identity, and stale cancel identity.
            const u32 kWrong = expected.generation == 1 ? 2 : 1;
            const u32 kTag =
                kAction == 9 ? 0u : kWrong | (kAction == 10 ? kResponseReadTimerCancelBit : 0u);
            CHECK_FALSE(c.consume_response_read_timer_completion(kTag));
        }
        CHECK_EQ(queue.backend.pending, kPending + (published ? 1u : 0u));
        check(_tc, c, expected);
    }
    // Drain any remaining obligations independently, after another reset.
    c.reset();
    check(_tc, c, expected);
    if (expected.owners & 1u) {
        CHECK(c.consume_response_read_timer_completion(expected.generation));
        expected.owners &= ~1u;
        check(_tc, c, expected);
    }
    if (expected.owners & 2u) {
        CHECK(c.consume_response_read_timer_completion(expected.generation |
                                                       kResponseReadTimerCancelBit));
        expected.owners &= ~2u;
        check(_tc, c, expected);
    }
    CHECK_FALSE(c.consume_response_read_timer_completion(expected.generation));
    CHECK_FALSE(c.consume_response_read_timer_completion(expected.generation |
                                                         kResponseReadTimerCancelBit));
}
}  // namespace

TEST(response_timer_owner, owner_guard_smoke) {
    // Arm, cancel, target, duplicate target; then drain the cancel owner.
    replay(_tc, 2u * 11 + 4u * 121 + 4u * 1331, 0);
    // Arm followed by an unowned generation, reset and a forbidden clear.
    replay(_tc, 8u * 11 + 6u * 121 + 7u * 1331, 0);
    replay(_tc, 7u * 11, 0);
}

TEST(response_timer_owner, bounded_owner_sequences) {
    const u32 kOrigins[] = {
        0, kResponseReadTimerGenerationMask - 1, kResponseReadTimerGenerationMask};
    for (const u32 kOrigin : kOrigins)
        for (u32 trace = 0; trace < 11u * 11u * 11u * 11u; ++trace) replay(_tc, trace, kOrigin);
}

TEST(response_timer_owner, generation_exhaustion) {
    Connection c{};
    c.reset();
    c.response_read_timer_generation = kResponseReadTimerGenerationMask;
    CHECK_FALSE(c.next_response_read_timer_generation());
    CHECK(c.response_read_timer_owner_is_neutral());
    c.reset();
    CHECK_EQ(c.response_read_timer_generation, kResponseReadTimerGenerationMask);
    CHECK_FALSE(c.next_response_read_timer_generation());
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
