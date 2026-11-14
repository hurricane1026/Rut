#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/timer_wheel.h"
#include "test.h"

using namespace rut;

namespace {
// Independent absolute tick oracle: tick() drains the CURRENT bucket before
// advancing. In particular add(0) fires on the next tick() call, add(1) on
// the following call. No wall-clock sleep or kernel timing is involved.
void replay(rut::test::TestCase* _tc, u32 sequence, u32 depth, u32 start) {
    TimerWheel wheel;
    wheel.init();
    wheel.cursor = start;
    Connection owners[2];
    bool armed[2]{};
    u64 due[2]{};
    u64 now = start;
    for (u32 i = 0; i < 2; ++i) {
        owners[i].reset();
        owners[i].id = i;
        owners[i].timer_node.init();
    }
    auto tick = [&]() {
        u32 seen[2]{};
        u32 count = wheel.tick([&](Connection* c) { ++seen[c->id]; });
        u32 expected_count = 0;
        for (u32 i = 0; i < 2; ++i) {
            bool expected = armed[i] && due[i] == now;
            CHECK_EQ(seen[i], expected ? 1u : 0u);
            if (expected) {
                armed[i] = false;
                ++expected_count;
            }
            CHECK_EQ(owners[i].timer_node.empty(), !armed[i]);
        }
        CHECK_EQ(count, expected_count);
        ++now;
        CHECK_EQ(wheel.cursor, static_cast<u32>(now));
    };
    // 9 actions: tick; remove either owner; arm/refresh either owner at
    // offsets 0, 1, 63. Repeated remove and re-arm exercise intrusive links.
    for (u32 step = 0; step < depth; ++step) {
        u32 action = sequence % 9;
        sequence /= 9;
        if (action == 0) {
            tick();
        } else if (action <= 2) {
            u32 i = action - 1;
            wheel.remove(&owners[i]);
            armed[i] = false;
            CHECK(owners[i].timer_node.empty());
        } else {
            u32 i = (action - 3) / 3;
            u32 delay_index = (action - 3) % 3;
            u32 delay = delay_index == 2 ? 63 : delay_index;
            owners[i].idle_trim_examined = true;
            if (armed[i])
                wheel.refresh(&owners[i], delay);
            else
                wheel.add(&owners[i], delay);
            armed[i] = true;
            due[i] = now + delay;
            CHECK_FALSE(owners[i].idle_trim_examined);
        }
    }
    for (u32 i = 0; i <= TimerWheel::kSlots; ++i) tick();
    CHECK_FALSE(armed[0]);
    CHECK_FALSE(armed[1]);
}
}  // namespace

TEST(timer_model, wheel_deadline_boundary_smoke) {
    replay(_tc, 3, 1, 63);
    replay(_tc, 5, 1, 63);
}

TEST(timer_model, bounded_wheel_sequences) {
    // Exhaust all length-4 traces (prefixes are checked along the way) at
    // ordinary, slot-wrap and u32 cursor-wrap origins.
    const u32 origins[] = {0u, 63u, 0xFFFFFFFEu};
    for (u32 start : origins)
        for (u32 trace = 0; trace < 9u * 9u * 9u * 9u; ++trace) replay(_tc, trace, 4, start);
}

TEST(timer_model, heap_matches_deadline_oracle) {
    epoll_yield::YieldHeap heap;
    REQUIRE(heap.init(64).has_value());
    // Equal deadlines, duplicate owner entries and removal of swapped tails.
    for (u32 pattern = 0; pattern < 256; ++pattern) {
        heap.clear();
        u64 due[8]{};
        bool present[8]{};
        for (u32 i = 0; i < 8; ++i) {
            due[i] = (pattern >> i) & 1u;
            present[i] = true;
            REQUIRE(heap.push(due[i], i + 1, i % 3));
        }
        u32 removed_owner = pattern % 3;
        u32 expected_removed = 0;
        for (u32 i = 0; i < 8; ++i)
            if (i % 3 == removed_owner) {
                present[i] = false;
                ++expected_removed;
            }
        CHECK_EQ(heap.remove_by_conn(removed_owner), expected_removed);
        while (!heap.empty()) {
            auto entry = heap.top();
            u32 i = entry.handler_gen - 1;
            REQUIRE(i < 8);
            CHECK(present[i]);
            CHECK_EQ(entry.conn_id, i % 3);
            CHECK_EQ(entry.deadline_ns, due[i]);
            for (u32 j = 0; j < 8; ++j)
                if (present[j]) CHECK(entry.deadline_ns <= due[j]);
            present[i] = false;
            heap.pop();
        }
        for (bool remains : present) CHECK_FALSE(remains);
    }
    heap.destroy();
}

TEST(timer_model, stale_uring_completion_preserves_successor) {
    IoUringEventLoop loop;
    REQUIRE(loop.init_slot_storage(64).has_value());
    REQUIRE(loop.pool.init(SlicePool::capacity_for_connections(64u), 0).has_value());
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    // No live descriptors, SQ or kernel are needed: exercise production CQE
    // dispatch with the two outstanding old/new timeout identities.
    c->yield_timer_gen = 2;
    c->yield_armed = true;
    c->yield_timeout_armed = true;
    c->pending_ops = 2;
    // A live fd prevents the closed-slot reclaim branch; this test never
    // submits I/O or closes the sentinel descriptor.
    c->fd = 12345;
    loop.dispatch(IoEvent{c->id, 1, 0, 0, IoEventType::HandlerTimer, 0, 0, 0});
    CHECK(c->yield_armed);
    CHECK(c->yield_timeout_armed);
    CHECK_EQ(c->pending_ops, 1u);
    loop.dispatch(IoEvent{c->id, 2, 0, 0, IoEventType::HandlerTimer, 0, 0, 0});
    CHECK_FALSE(c->yield_armed);
    CHECK_FALSE(c->yield_timeout_armed);
    CHECK_EQ(c->pending_ops, 0u);
    c->fd = -1;
    loop.pool.destroy();
    loop.destroy_slot_storage();
}

TEST(timer_model, epoll_disarm_removes_all_entries_and_preserves_peer) {
    EpollEventLoop loop;
    REQUIRE(loop.init_slot_storage(64).has_value());
    loop.timer.init();
    REQUIRE(loop.pool.init(SlicePool::capacity_for_connections(64u), 0).has_value());
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    c->yield_armed = true;
    c->yield_timer_gen = 9;
    loop.timer.add(c, 1);
    REQUIRE(loop.yield_heap.push(100, 1, c->id));
    REQUIRE(loop.yield_heap.push(200, 2, c->id));
    REQUIRE(loop.yield_heap.push(150, 1, (c->id + 1) % 64));
    loop.disarm_yield_timer(*c);
    CHECK_FALSE(c->yield_armed);
    CHECK_EQ(c->yield_timer_gen, 10u);
    CHECK(c->timer_node.empty());
    CHECK_EQ(loop.yield_heap.size, 1u);
    CHECK_EQ(loop.yield_heap.top().deadline_ns, 150u);
    loop.disarm_yield_timer(*c);
    CHECK_EQ(c->yield_timer_gen, 10u);
    loop.pool.destroy();
    loop.destroy_slot_storage();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
