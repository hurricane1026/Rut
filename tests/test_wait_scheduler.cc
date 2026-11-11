#include "test_helpers.h"
#include <memory>

#include <sys/socket.h>

namespace {
u32 calls = 0;
u32 order[512]{};
SmallLoop* closing_loop = nullptr;
Connection* closing_owner = nullptr;
Connection* replacing_owner = nullptr;
u32 real_response_calls = 0;
u32 real_response_order[129]{};
u32 real_response_expected[129]{};

u64 terminal_status(void* raw, jit::HandlerCtx*, const u8*, u32, void*) {
    const auto& conn = *static_cast<Connection*>(raw);
    if (real_response_calls < 129) real_response_order[real_response_calls] = conn.id;
    ++real_response_calls;
    return jit::HandlerResult::make_status(204).pack();
}

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

TEST(wait_scheduler, busy_fetch_does_not_pause_ready_handlers) {
    Owners owners(1);
    CHECK_FALSE(
        owners.loop.fetch_idle_pause_allowed(true, 0, owners.loop.has_ready_jit_handlers()));
    owners.loop.drain_ready_jit_handlers();
    CHECK_FALSE(
        owners.loop.fetch_idle_pause_allowed(true, 0, owners.loop.has_ready_jit_handlers()));
    owners.loop.drain_ready_jit_handlers();
    SmallLoop idle;
    idle.setup();
    CHECK(idle.fetch_idle_pause_allowed(true, 0, idle.has_ready_jit_handlers()));
}

TEST(wait_scheduler, terminal_response_send_failure_closes_owner) {
    SmallLoop loop;
    loop.setup();
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 42;
    loop.backend.fail_send = true;
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 204;

    handle_jit_outcome(&loop, *conn, outcome, nullptr, false, nullptr);

    CHECK_EQ(conn->fd, -1);
    CHECK_EQ(loop.send_submit_attempts, 1u);
}

TEST(wait_scheduler, epoll_ready_responses_survive_prefilled_completion_ring) {
#if defined(__linux__)
    constexpr u32 kOwners = 129;
    for (u32 prefill_count : {32u, EpollBackend::kPendingCap}) {
        auto* loop = create_real_loop();
        REQUIRE(loop != nullptr);
        REQUIRE(loop->init(0, -1, 0).has_value());
        i32 peers[kOwners];
        for (u32 i = 0; i < kOwners; ++i) peers[i] = -1;
        u8 byte = 'x';
        for (u32 i = 0; i < kOwners; ++i) {
            i32 sockets[2] = {-1, -1};
            REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
            peers[i] = sockets[1];
            Connection* conn = loop->alloc_conn();
            REQUIRE(conn != nullptr);
            real_response_expected[i] = conn->id;
            conn->fd = sockets[0];
            conn->handler_gen = 1;
            conn->handler_state = 1;
            conn->pending_yield_kind = jit::YieldKind::Send;
            conn->pending_handler_fn = &terminal_status;
            conn->transition_to_exec_handler_wait();
            loop->defer_jit_handler(*conn);
        }

        // Keep one real kernel readiness record competing with the synthetic ring.
        i32 kernel_sockets[2] = {-1, -1};
        REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, kernel_sockets), 0);
        Connection* kernel_owner = loop->alloc_conn();
        REQUIRE(kernel_owner != nullptr);
        kernel_owner->fd = kernel_sockets[0];
        REQUIRE(loop->backend.add_recv(kernel_owner->fd, kernel_owner->id));
        REQUIRE_EQ(send(kernel_sockets[1], &byte, 1, MSG_NOSIGNAL), 1);
        i32 second_kernel_sockets[2] = {-1, -1};
        REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, second_kernel_sockets), 0);
        Connection* second_kernel_owner = loop->alloc_conn();
        REQUIRE(second_kernel_owner != nullptr);
        second_kernel_owner->fd = second_kernel_sockets[0];
        REQUIRE(loop->backend.add_recv(second_kernel_owner->fd, second_kernel_owner->id));
        REQUIRE_EQ(send(second_kernel_sockets[1], &byte, 1, MSG_NOSIGNAL), 1);

        // Seed actual EpollBackend completions before ready owners begin replying.
        for (u32 i = 0; i < prefill_count; ++i) {
            Connection& conn = loop->conns[real_response_expected[i]];
            REQUIRE(loop->backend.add_send(conn.fd, conn.id, &byte, 1));
        }
        real_response_calls = 0;
        u32 polls = 0;
        u32 kernel_events = 0;
        u32 kernel_owner_events = 0;
        u32 second_kernel_owner_events = 0;
        u32 send_completions[kOwners]{};
        bool drained = false;
        for (u32 turn = 0; turn < 1024; ++turn) {
            if (loop->has_ready_jit_handlers()) loop->drain_ready_jit_handlers();
            bool active_send = false;
            for (u32 i = 0; i < kOwners; ++i) {
                const auto& state = loop->backend.send_state[real_response_expected[i]];
                active_send = active_send || state.remaining;
            }
            if (!loop->has_ready_jit_handlers() && !active_send && !loop->backend.pending_count) {
                drained = true;
                break;
            }
            (void)send(kernel_sockets[1], &byte, 1, MSG_NOSIGNAL);
            (void)send(second_kernel_sockets[1], &byte, 1, MSG_NOSIGNAL);
            IoEvent event{};
            const u32 count =
                loop->backend.wait(&event, 1, loop->conns, loop->connection_capacity, 0);
            CHECK_EQ(count, 1u);
            if (event.type == IoEventType::Send) {
                for (u32 i = 0; i < kOwners; ++i) {
                    if (event.conn_id == real_response_expected[i]) ++send_completions[i];
                }
            }
            if (event.type == IoEventType::Recv) {
                ++kernel_events;
                Connection* owner = event.conn_id == kernel_owner->id          ? kernel_owner
                                    : event.conn_id == second_kernel_owner->id ? second_kernel_owner
                                                                               : nullptr;
                REQUIRE(owner != nullptr);
                if (owner == kernel_owner)
                    ++kernel_owner_events;
                else
                    ++second_kernel_owner_events;
                owner->recv_buf.reset();
            }
            ++polls;
            CHECK_LE(loop->backend.pending_count, EpollBackend::kPendingCap);
        }
        CHECK(drained);
        CHECK_EQ(real_response_calls, kOwners);
        CHECK_GT(polls, 0u);
        CHECK_GT(kernel_events, 1u);
        CHECK_GT(kernel_owner_events, 0u);
        CHECK_GT(second_kernel_owner_events, 0u);
        for (u32 i = 0; i < kOwners; ++i)
            CHECK_EQ(real_response_order[i], real_response_expected[i]);
        for (u32 i = 0; i < kOwners; ++i)
            CHECK_EQ(send_completions[i], i < prefill_count ? 2u : 1u);

        while (loop->backend.pending_count) {
            IoEvent event{};
            CHECK_EQ(loop->backend.wait(&event, 1, loop->conns, loop->connection_capacity, 0), 1u);
        }
        for (u32 i = 0; i < kOwners; ++i) {
            char response[1024];
            ssize_t received = 0;
            for (;;) {
                const ssize_t n = recv(peers[i],
                                       response + received,
                                       sizeof(response) - static_cast<size_t>(received),
                                       0);
                if (n <= 0) break;
                received += n;
                if (static_cast<size_t>(received) == sizeof(response)) break;
            }
            CHECK_GT(received, 0);
            const u32 offset = i < prefill_count ? 1u : 0u;
            bool found_status = false;
            bool framed = false;
            for (u32 j = offset; j < static_cast<u32>(received); ++j) {
                if (j + 12u <= static_cast<u32>(received) &&
                    __builtin_memcmp(response + j, "HTTP/1.1 204", 12) == 0) {
                    found_status = true;
                }
                if (j + 4u <= static_cast<u32>(received) &&
                    __builtin_memcmp(response + j, "\r\n\r\n", 4) == 0)
                    framed = true;
            }
            CHECK(found_status);
            CHECK(framed);
        }
        loop->shutdown();
        close(kernel_sockets[1]);
        close(second_kernel_sockets[1]);
        for (i32 fd : peers)
            if (fd >= 0) close(fd);
        destroy_real_loop(loop);
    }
#endif
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
