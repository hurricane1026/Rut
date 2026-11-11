#include "test_helpers.h"
#include <memory>

namespace {
u32 calls = 0;
u32 order[512]{};
SmallLoop* closing_loop = nullptr;
Connection* closing_owner = nullptr;
Connection* replacing_owner = nullptr;

u64 rewait(void* raw, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    auto& conn = *static_cast<Connection*>(raw);
    if (calls < 512) order[calls] = conn.id;
    ++calls;
    if (closing_owner) {
        Connection* victim = closing_owner;
        closing_owner = nullptr;
        closing_loop->close_conn(*victim);
        if (replacing_owner) {
            auto* fresh = closing_loop->alloc_conn();
            fresh->fd = 43;
            ++fresh->handler_gen;  // a newly accepted request, not the retired wait
            fresh->handler_state = 1;
            fresh->pending_yield_kind = jit::YieldKind::Send;
            fresh->pending_handler_fn = &rewait;
            fresh->transition_to_exec_handler_wait();
            closing_loop->defer_jit_handler(*fresh);
            replacing_owner = fresh;
        }
    }
    return jit::HandlerResult::make_yield(ctx->state + 1, jit::YieldKind::Send).pack();
}

void publish(SmallLoop& loop, Connection& c, u32 id) {
    c.reset();
    c.id = id;
    c.fd = 42;
    c.handler_gen = 1;
    c.handler_state = 1;
    c.pending_yield_kind = jit::YieldKind::Send;
    c.pending_handler_fn = &rewait;
    c.transition_to_exec_handler_wait();
    loop.defer_jit_handler(c);
}

// Independent owner storage lets the CRTP queue be tested beyond the mock
// backend's 64 socket slots. These handlers never submit kernel operations.
struct Owners {
    SmallLoop loop;
    std::unique_ptr<Connection[]> nodes;
    u32 count;
    explicit Owners(u32 n) : nodes(std::make_unique<Connection[]>(n)), count(n) {
        loop.setup();
        calls = 0;
        for (u32 i = 0; i < n; ++i) publish(loop, nodes[i], i);
    }
    ~Owners() {
        loop.discard_ready_jit_handlers();
        for (u32 i = 0; i < count; ++i) loop.timer.remove(&nodes[i]);
    }
};
}  // namespace

TEST(wait_scheduler, batch_limit_and_fifo_at_64_65_and_129_owners) {
    for (u32 count : {64u, 65u, 129u}) {
        Owners owners(count);
        for (u32 turn = 0; turn < 3; ++turn) {
            const u32 before = calls;
            owners.loop.drain_ready_jit_handlers();
            CHECK_EQ(calls - before, 64u);
            CHECK(owners.loop.has_ready_jit_handlers());
        }
        for (u32 i = 0; i < calls; ++i) CHECK_EQ(order[i], i % count);
        for (u32 i = 0; i < count; ++i) {
            CHECK(owners.nodes[i].handler_state >= 2);
            CHECK(owners.nodes[i].jit_ready_queued);
        }
    }
}

TEST(wait_scheduler, peer_close_inside_detached_batch_cancels_resume) {
    SmallLoop loop;
    loop.setup();
    auto* first = loop.alloc_conn();
    auto* second = loop.alloc_conn();
    REQUIRE(first && second);
    const u32 first_id = first->id;
    const u32 second_id = second->id;
    publish(loop, *first, first_id);
    publish(loop, *second, second_id);
    closing_loop = &loop;
    closing_owner = second;
    replacing_owner = nullptr;
    calls = 0;
    loop.drain_ready_jit_handlers();
    CHECK_EQ(calls, 1u);
    CHECK_EQ(second->fd, -1);
    loop.discard_ready_jit_handlers();
    loop.close_conn(*first);
    closing_loop = nullptr;
}

TEST(wait_scheduler, peer_close_and_reuse_inside_batch_cannot_resume_new_generation) {
    SmallLoop loop;
    loop.setup();
    auto* first = loop.alloc_conn();
    auto* second = loop.alloc_conn();
    REQUIRE(first && second);
    const u32 first_id = first->id;
    const u32 second_id = second->id;
    publish(loop, *first, first_id);
    publish(loop, *second, second_id);
    closing_loop = &loop;
    closing_owner = second;
    replacing_owner = second;
    calls = 0;
    loop.drain_ready_jit_handlers();
    REQUIRE_EQ(replacing_owner, second);
    CHECK_EQ(calls, 1u);
    CHECK_EQ(second->handler_state, 1u);
    CHECK(second->jit_ready_queued);
    loop.drain_ready_jit_handlers();
    CHECK_EQ(calls, 3u);  // first's next wait and the new request each run once
    CHECK_EQ(second->handler_state, 2u);
    loop.close_conn(*first);
    loop.close_conn(*second);
    closing_loop = nullptr;
    replacing_owner = nullptr;
}

TEST(wait_scheduler, generation_or_continuation_change_invalidates_queued_resume) {
    for (bool change_generation : {false, true}) {
        Owners owners(1);
        if (change_generation)
            ++owners.nodes[0].handler_gen;
        else
            ++owners.nodes[0].handler_state;
        owners.loop.drain_ready_jit_handlers();
        CHECK_EQ(calls, 0u);
        CHECK(!owners.loop.has_ready_jit_handlers());
    }
}

TEST(wait_scheduler, kernel_send_cannot_steal_ready_queue_completion) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c);
    const u32 id = c->id;
    publish(loop, *c, id);
    calls = 0;
    loop.dispatch(make_ev(c->id, IoEventType::Send, 37));
    CHECK_EQ(calls, 0u);
    CHECK_EQ(c->handler_state, 1u);
    loop.drain_ready_jit_handlers();
    CHECK_EQ(calls, 1u);
    CHECK_EQ(c->jit_ctx()->resume_event_result, 0);
    loop.close_conn(*c);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
