#include "rut/runtime/response_body_pipe.h"
#include "rut/runtime/response_body_pipe_owner.h"
#include "test.h"
#include <initializer_list>

#include <string.h>
#ifdef __linux__
#include "rut/runtime/io_uring_backend.h"

#include <arpa/inet.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#endif

using namespace rut;

#ifdef __linux__
struct PipeFixture {
    ResponseBodyPipe pipe{};
    ~PipeFixture() { (void)pipe.close(); }
};

// Small real ring, deliberately separate from the production dispatcher: these
// tests prove kernel transfer/ownership behavior, not HTTP-state integration.
struct PipeTestRing {
    i32 fd = -1;
    io_uring_params params{};
    u8* sq = nullptr;
    u8* cq = nullptr;
    io_uring_sqe* entries = nullptr;
    u32 sq_size = 0, cq_size = 0, entries_size = 0;
    u32 pending = 0;

    ~PipeTestRing() {
        if (fd >= 0) ::close(fd);
        if (entries) munmap(entries, entries_size);
        if (cq) munmap(cq, cq_size);
        if (sq) munmap(sq, sq_size);
    }
    bool init() {
        params.flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
        fd = syscall(__NR_io_uring_setup, 8u, &params);
        if (fd < 0) return false;
        sq_size = params.sq_off.array + params.sq_entries * sizeof(u32);
        cq_size = params.cq_off.cqes + params.cq_entries * sizeof(io_uring_cqe);
        entries_size = params.sq_entries * sizeof(io_uring_sqe);
        auto map = [&](u32 size, u64 offset) -> u8* {
            void* result = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
            return result == MAP_FAILED ? nullptr : static_cast<u8*>(result);
        };
        sq = map(sq_size, IORING_OFF_SQ_RING);
        cq = map(cq_size, IORING_OFF_CQ_RING);
        entries = reinterpret_cast<io_uring_sqe*>(map(entries_size, IORING_OFF_SQES));
        if (!sq || !cq || !entries) return false;
        cpu_set_t affinity;
        if (sched_getaffinity(0, sizeof(affinity), &affinity) != 0) return false;
        return syscall(__NR_io_uring_register,
                       fd,
                       IORING_REGISTER_IOWQ_AFF,
                       &affinity,
                       sizeof(affinity)) == 0;
    }
    static u32* field(u8* base, u32 offset) { return reinterpret_cast<u32*>(base + offset); }
    bool submit(const io_uring_sqe& entry, bool flush = true) {
        u32* tail = field(sq, params.sq_off.tail);
        const u32 cursor = __atomic_load_n(tail, __ATOMIC_RELAXED);
        if (cursor - __atomic_load_n(field(sq, params.sq_off.head), __ATOMIC_ACQUIRE) >=
            params.sq_entries)
            return false;
        const u32 index = cursor & *field(sq, params.sq_off.ring_mask);
        entries[index] = entry;
        field(sq, params.sq_off.array)[index] = index;
        __atomic_store_n(tail, cursor + 1, __ATOMIC_RELEASE);
        ++pending;
        if (!flush) return true;
        const i32 submitted = syscall(__NR_io_uring_enter, fd, pending, 0u, 0u, nullptr, 0u);
        if (submitted != static_cast<i32>(pending)) return false;
        pending = 0;
        return true;
    }
    bool take(io_uring_cqe& result) {
        // Enter with min_complete=0 services cooperative task work without
        // hiding an unbounded wait in the test. poll only sleeps up to 10 ms.
        for (u32 tries = 0; tries < 200; ++tries) {
            if (syscall(__NR_io_uring_enter, fd, 0u, 0u, IORING_ENTER_GETEVENTS, nullptr, 0u) < 0)
                return false;
            u32* head = field(cq, params.cq_off.head);
            const u32 cursor = __atomic_load_n(head, __ATOMIC_RELAXED);
            if (cursor != __atomic_load_n(field(cq, params.cq_off.tail), __ATOMIC_ACQUIRE)) {
                auto* completions = reinterpret_cast<io_uring_cqe*>(cq + params.cq_off.cqes);
                result = completions[cursor & *field(cq, params.cq_off.ring_mask)];
                __atomic_store_n(head, cursor + 1, __ATOMIC_RELEASE);
                return true;
            }
            pollfd event{fd, POLLIN, 0};
            if (poll(&event, 1, 10) < 0 && errno != EINTR) return false;
        }
        return false;
    }
    // Borrow this fixture's ring mappings without transferring cleanup to b.
    void attach(IoUringBackend& b) {
        b.ring_fd = fd;
        b.connection_capacity = 1;
        b.sq_head = field(sq, params.sq_off.head);
        b.sq_tail = field(sq, params.sq_off.tail);
        b.sq_flags = field(sq, params.sq_off.flags);
        b.sq_ring_mask = field(sq, params.sq_off.ring_mask);
        b.sq_array = field(sq, params.sq_off.array);
        b.sq_entries = entries;
        b.sq_ring_entries = params.sq_entries;
        b.cq_head = field(cq, params.cq_off.head);
        b.cq_tail = field(cq, params.cq_off.tail);
        b.cq_ring_mask = field(cq, params.cq_off.ring_mask);
        b.cq_entries = reinterpret_cast<io_uring_cqe*>(cq + params.cq_off.cqes);
        b.cq_ring_entries = params.cq_entries;
    }
    static io_uring_sqe splice(i32 input, i32 output, u32 length, u64 token) {
        io_uring_sqe entry{};
        entry.opcode = IORING_OP_SPLICE;
        entry.fd = output;
        entry.splice_fd_in = input;
        entry.splice_off_in = ~u64{0};
        entry.off = ~u64{0};
        entry.len = length;
        entry.splice_flags = SPLICE_F_NONBLOCK;
        entry.user_data = token;
        return entry;
    }
};

struct PipeTestTcp {
    i32 listener = -1, sender = -1, receiver = -1;
    ~PipeTestTcp() {
        if (receiver >= 0) ::close(receiver);
        if (sender >= 0) ::close(sender);
        if (listener >= 0) ::close(listener);
    }
    bool init() {
        listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener < 0) return false;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            listen(listener, 1) != 0)
            return false;
        socklen_t length = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) != 0)
            return false;
        sender = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sender < 0 || connect(sender, reinterpret_cast<sockaddr*>(&address), length) != 0)
            return false;
        receiver = accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (receiver < 0) return false;
        return fcntl(sender, F_SETFL, O_NONBLOCK) == 0;
    }
};

TEST(response_body_pipe, real_uring_tcp_declared_bound_publication_and_eof) {
    PipeFixture f;
    PipeTestTcp origin, downstream;
    PipeTestRing ring;
    const bool initialized = ring.init();
    if (!initialized && ring.fd < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES))
        SKIP("io_uring unavailable or denied by sandbox");
    REQUIRE(initialized);
    REQUIRE(origin.init());
    REQUIRE(downstream.init());
    auto& p = f.pipe;
    REQUIRE(p.open(65536));
    REQUIRE_EQ(send(origin.sender, "bodyNEXT", 8, MSG_NOSIGNAL), 8);
    ResponseBodyPipe::Operation in{}, out{};
    REQUIRE(p.reserve_input(4, &in));
    REQUIRE(p.submit_input(in.serial));
    REQUIRE(ring.submit(PipeTestRing::splice(origin.receiver, p.write_fd, in.limit, in.serial)));
    CHECK(!p.close());
    io_uring_cqe completion{};
    REQUIRE(ring.take(completion));
    REQUIRE_EQ(completion.user_data, in.serial);
    REQUIRE_EQ(completion.res, 4);
    REQUIRE_EQ(completion.flags, 0u);
    REQUIRE(p.complete_input(in.serial, completion.res));
    // The following response bytes are still in the upstream socket.
    char next[4]{};
    REQUIRE_EQ(recv(origin.receiver, next, sizeof(next), 0), 4);
    CHECK_EQ(memcmp(next, "NEXT", 4), 0);
    REQUIRE(p.reserve_output(2, &out));
    REQUIRE(p.submit_output(out.serial));
    REQUIRE(ring.submit(PipeTestRing::splice(p.read_fd, downstream.sender, out.limit, out.serial)));
    REQUIRE(ring.take(completion));
    REQUIRE_EQ(completion.user_data, out.serial);
    REQUIRE_EQ(completion.res, 2);
    REQUIRE(p.complete_output(out.serial, completion.res));
    char body[4]{};
    REQUIRE_EQ(recv(downstream.receiver, body, sizeof(body), 0), 2);
    CHECK_EQ(memcmp(body, "bo", 2), 0);
    // Only the authorized prefix escaped. Fallback retains the exact suffix.
    CHECK_EQ(p.bytes, 2u);
    REQUIRE_EQ(p.drain_into(reinterpret_cast<u8*>(body), sizeof(body)), 2);
    CHECK_EQ(memcmp(body, "dy", 2), 0);
    REQUIRE_EQ(shutdown(origin.sender, SHUT_WR), 0);
    REQUIRE(p.reserve_input(4, &in));
    REQUIRE(p.submit_input(in.serial));
    REQUIRE(ring.submit(PipeTestRing::splice(origin.receiver, p.write_fd, in.limit, in.serial)));
    REQUIRE(ring.take(completion));
    REQUIRE_EQ(completion.user_data, in.serial);
    REQUIRE_EQ(completion.res, 0);
    REQUIRE(p.complete_input(in.serial, completion.res));
    REQUIRE(p.close());
}

TEST(response_body_pipe, real_uring_empty_origin_retry_and_queued_cancel) {
    PipeFixture f;
    PipeTestTcp origin;
    PipeTestRing ring;
    const bool initialized = ring.init();
    if (!initialized && ring.fd < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES))
        SKIP("io_uring unavailable or denied by sandbox");
    REQUIRE(initialized);
    REQUIRE(origin.init());
    auto& p = f.pipe;
    REQUIRE(p.open(65536));
    ResponseBodyPipe::Operation in{};
    REQUIRE(p.reserve_input(4, &in));
    REQUIRE(p.submit_input(in.serial));
    REQUIRE(ring.submit(PipeTestRing::splice(origin.receiver, p.write_fd, in.limit, in.serial)));
    io_uring_cqe completion{};
    REQUIRE(ring.take(completion));
    REQUIRE_EQ(completion.user_data, in.serial);
    REQUIRE_EQ(completion.res, -EAGAIN);
    REQUIRE(p.complete_input(in.serial, completion.res));
    CHECK_EQ(p.bytes, 0u);

    // A pending POLLIN is the nonblocking retry's readiness owner. Queue the
    // splice behind it to exercise cancellation before the worker can consume
    // bytes. This does not claim to cancel an already running blocking splice.
    constexpr u64 poll_token = u64{1} << 40;
    constexpr u64 cancel_token = u64{2} << 40;
    io_uring_sqe ready{};
    ready.opcode = IORING_OP_POLL_ADD;
    ready.fd = origin.receiver;
    ready.poll32_events = POLLIN;
    ready.flags = IOSQE_IO_LINK;
    ready.user_data = poll_token;
    REQUIRE(ring.submit(ready, /*flush=*/false));
    REQUIRE(p.reserve_input(4, &in));
    REQUIRE(p.submit_input(in.serial));
    REQUIRE(ring.submit(PipeTestRing::splice(origin.receiver, p.write_fd, in.limit, in.serial)));
    io_uring_sqe cancel{};
    cancel.opcode = IORING_OP_ASYNC_CANCEL;
    cancel.addr = poll_token;
    cancel.user_data = cancel_token;
    REQUIRE(ring.submit(cancel));
    CHECK(!p.close());
    bool saw_poll = false, saw_cancel = false, saw_target = false;
    for (u32 i = 0; i < 3; ++i) {
        REQUIRE(ring.take(completion));
        REQUIRE_EQ(completion.flags, 0u);
        if (completion.user_data == poll_token) {
            CHECK(!saw_poll);
            CHECK_EQ(completion.res, -ECANCELED);
            saw_poll = true;
        } else if (completion.user_data == cancel_token) {
            CHECK(!saw_cancel);
            CHECK_EQ(completion.res, 0);
            saw_cancel = true;
        } else {
            REQUIRE_EQ(completion.user_data, in.serial);
            CHECK(!saw_target);
            CHECK_EQ(completion.res, -ECANCELED);
            REQUIRE(p.complete_input(in.serial, completion.res));
            saw_target = true;
        }
    }
    CHECK(saw_poll && saw_cancel && saw_target);
    CHECK(!p.complete_input(in.serial, -ECANCELED));
    CHECK_EQ(p.bytes, 0u);
    REQUIRE(p.close());
}

TEST(response_body_pipe, backend_token_domains_and_full_serial) {
    for (u8 kind = 0; kind < static_cast<u8>(BodyPipeOperation::Count); ++kind) {
        for (u32 serial : {1u, 0x80000000u, UINT32_MAX}) {
            const BodyPipeToken source{
                kIoUserDataMaxConnId, serial, static_cast<BodyPipeOperation>(kind)};
            const u64 token = encode_body_pipe_token(source);
            BodyPipeToken decoded;
            REQUIRE(decode_body_pipe_token(token, &decoded));
            CHECK_EQ(decoded.conn_id, source.conn_id);
            CHECK_EQ(decoded.serial, serial);
            CHECK_EQ(decoded.operation, source.operation);
            UpstreamEventToken upstream;
            NonUpstreamUserData downstream;
            CHECK(!decode_upstream_event_token(token, &upstream));
            CHECK(!decode_non_upstream_user_data(token, &downstream));
        }
    }
    CHECK_EQ(encode_body_pipe_token({0, 0, BodyPipeOperation::Input}), kInvalidIoUserData);
    CHECK_EQ(encode_body_pipe_token({0x1000000, 1, BodyPipeOperation::Input}), kInvalidIoUserData);
    CHECK_EQ(encode_body_pipe_token({0, 1, BodyPipeOperation::Count}), kInvalidIoUserData);
    CHECK_EQ(encode_non_upstream_user_data({0, IoEventType::BodyPipeTransport, 1}),
             kInvalidIoUserData);
    CHECK_EQ(body_pipe_cancel_operation(BodyPipeOperation::CancelInput), BodyPipeOperation::Count);
}

TEST(response_body_pipe, backend_real_transfer_emits_neutral_transport_evidence) {
    PipeFixture f;
    PipeTestRing ring;
    PipeTestTcp origin, downstream;
    const bool initialized = ring.init();
    if (!initialized && ring.fd < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES))
        SKIP("io_uring unavailable or denied by sandbox");
    REQUIRE(initialized);
    REQUIRE(origin.init());
    REQUIRE(downstream.init());
    IoUringBackend backend{};
    ring.attach(backend);
    REQUIRE(f.pipe.open(65536));
    ResponseBodyPipe::Operation input{}, output{};
    REQUIRE(f.pipe.reserve_input(4, &input));
    CHECK(!backend.add_body_pipe_splice(origin.receiver, 0, f.pipe, true));
    CHECK_EQ(f.pipe.input.phase, ResponseBodyPipe::Phase::Reserved);
    REQUIRE(backend.bind_body_pipe_workers());
    REQUIRE_EQ(send(origin.sender, "testTAIL", 8, MSG_NOSIGNAL), 8);
    REQUIRE(backend.add_body_pipe_splice(origin.receiver, 0, f.pipe, true));
    CHECK(!backend.add_body_pipe_splice(origin.receiver, 0, f.pipe, true));
    CHECK(!f.pipe.rollback_input(input.serial));
    IoEvent event{};
    REQUIRE_EQ(backend.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.type, IoEventType::BodyPipeTransport);
    CHECK_EQ(event.aux, static_cast<u8>(BodyPipeOperation::Input));
    CHECK_EQ(event.non_upstream_generation, input.serial);
    CHECK_EQ(event.result, 4);
    CHECK_EQ(event.copy_witness, IoEventCopyWitness::None);
    CHECK_EQ(event.copy_begin, 0u);
    CHECK_EQ(event.copy_end, 0u);
    CHECK_EQ(event.upstream_episode, 0u);
    CHECK_EQ(event.has_buf, 0u);
    CHECK_EQ(event.more, 0u);
    // Backend decoding never commits application state by itself.
    CHECK_EQ(f.pipe.bytes, 0u);
    REQUIRE(f.pipe.complete_input(input.serial, event.result));
    REQUIRE(f.pipe.reserve_output(4, &output));
    REQUIRE(backend.add_body_pipe_splice(downstream.sender, 0, f.pipe, false));
    REQUIRE_EQ(backend.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.aux, static_cast<u8>(BodyPipeOperation::Output));
    CHECK_EQ(event.non_upstream_generation, output.serial);
    CHECK_EQ(event.result, 4);
    CHECK_EQ(f.pipe.bytes, 4u);
    REQUIRE(f.pipe.complete_output(output.serial, event.result));
    char bytes[4]{};
    REQUIRE_EQ(recv(downstream.receiver, bytes, 4, 0), 4);
    CHECK_EQ(memcmp(bytes, "test", 4), 0);
    REQUIRE_EQ(recv(origin.receiver, bytes, 4, 0), 4);
    CHECK_EQ(memcmp(bytes, "TAIL", 4), 0);
    REQUIRE(f.pipe.close());
}

TEST(response_body_pipe, backend_readiness_and_cancel_are_exact_separate_owners) {
    PipeTestRing ring;
    PipeTestTcp origin;
    const bool initialized = ring.init();
    if (!initialized && ring.fd < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES))
        SKIP("io_uring unavailable or denied by sandbox");
    REQUIRE(initialized);
    REQUIRE(origin.init());
    IoUringBackend backend{};
    ring.attach(backend);
    constexpr u32 serial = 0x80000005u;
    REQUIRE(backend.add_body_pipe_poll(origin.receiver, 0, serial, true));
    REQUIRE(backend.cancel_body_pipe(0, serial - 1, BodyPipeOperation::InputReady));
    IoEvent event{};
    REQUIRE_EQ(backend.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.aux, static_cast<u8>(BodyPipeOperation::CancelInputReady));
    CHECK_EQ(event.non_upstream_generation, serial - 1);
    CHECK_EQ(event.result, -ENOENT);
    REQUIRE(backend.cancel_body_pipe(0, serial, BodyPipeOperation::InputReady));
    bool saw_target = false, saw_cancel = false;
    for (u32 i = 0; i < 2; ++i) {
        REQUIRE_EQ(backend.wait(&event, 1, nullptr, 0), 1u);
        REQUIRE_EQ(event.type, IoEventType::BodyPipeTransport);
        CHECK_EQ(event.non_upstream_generation, serial);
        CHECK_EQ(event.copy_witness, IoEventCopyWitness::None);
        if (event.aux == static_cast<u8>(BodyPipeOperation::InputReady)) {
            CHECK(!saw_target);
            CHECK_EQ(event.result, -ECANCELED);
            saw_target = true;
        } else {
            CHECK_EQ(event.aux, static_cast<u8>(BodyPipeOperation::CancelInputReady));
            CHECK(!saw_cancel);
            CHECK_EQ(event.result, 0);
            saw_cancel = true;
        }
    }
    CHECK(saw_target && saw_cancel);
    REQUIRE(backend.add_body_pipe_poll(origin.receiver, 0, serial + 1, true));
    REQUIRE_EQ(send(origin.sender, "x", 1, MSG_NOSIGNAL), 1);
    REQUIRE_EQ(backend.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.aux, static_cast<u8>(BodyPipeOperation::InputReady));
    CHECK_EQ(event.non_upstream_generation, serial + 1);
    CHECK(event.result & POLLIN);
    REQUIRE(backend.add_body_pipe_poll(origin.sender, 0, serial + 2, false));
    REQUIRE_EQ(backend.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.aux, static_cast<u8>(BodyPipeOperation::OutputReady));
    CHECK(event.result & POLLOUT);
}

struct FakePipeBackend {
    IoUringBackend backend{};
    u32 sq_head = 0, sq_tail = 0, sq_mask = 1, sq_array[2]{};
    io_uring_sqe sqes[2]{};
    u32 cq_head = 0, cq_tail = 0, cq_mask = 1;
    io_uring_cqe cqes[2]{};
    FakePipeBackend() {
        backend.connection_capacity = 1;
        backend.body_pipe_workers_bound = true;
        backend.sq_head = &sq_head;
        backend.sq_tail = &sq_tail;
        backend.sq_ring_mask = &sq_mask;
        backend.sq_array = sq_array;
        backend.sq_entries = sqes;
        backend.sq_ring_entries = 2;
        backend.cq_head = &cq_head;
        backend.cq_tail = &cq_tail;
        backend.cq_ring_mask = &cq_mask;
        backend.cq_entries = cqes;
        backend.cq_ring_entries = 2;
    }
};

TEST(response_body_pipe, backend_sq_full_preserves_reservation_and_rejects_invalid_args) {
    FakePipeBackend f;
    PipeFixture storage;
    auto& b = f.backend;
    REQUIRE(storage.pipe.open(4096));
    ResponseBodyPipe::Operation op{};
    REQUIRE(storage.pipe.reserve_input(4, &op));
    CHECK(!b.add_body_pipe_splice(-1, 0, storage.pipe, true));
    CHECK(!b.add_body_pipe_splice(42, 1, storage.pipe, true));
    CHECK(!b.add_body_pipe_poll(42, 0, 0, true));
    CHECK(!b.cancel_body_pipe(0, 1, BodyPipeOperation::CancelInput));
    CHECK_EQ(f.sq_tail, 0u);
    f.sq_tail = 2;
    CHECK(!b.add_body_pipe_splice(42, 0, storage.pipe, true));
    CHECK(!b.add_body_pipe_poll(42, 0, 1, true));
    CHECK(!b.cancel_body_pipe(0, 1, BodyPipeOperation::Input));
    CHECK_EQ(storage.pipe.input.phase, ResponseBodyPipe::Phase::Reserved);
    CHECK_EQ(b.pending, 0u);
    REQUIRE(storage.pipe.rollback_input(op.serial));
    REQUIRE(storage.pipe.close());
}

TEST(response_body_pipe, backend_malformed_flags_or_identity_do_not_publish) {
    for (u32 flags : {IORING_CQE_F_BUFFER, IORING_CQE_F_MORE, IORING_CQE_F_NOTIF}) {
        FakePipeBackend f;
        f.cqes[0] = {encode_body_pipe_token({0, 1, BodyPipeOperation::Input}), 4, flags};
        f.cq_tail = 1;
        IoEvent event{};
        CHECK_EQ(f.backend.wait(&event, 1, nullptr, 0), 0u);
        CHECK_EQ(f.backend.failure_code(), EPROTO);
        CHECK_EQ(f.cq_head, 0u);
    }
    for (u64 invalid :
         {u64{kBodyPipeRawTag}, encode_body_pipe_token({1, 1, BodyPipeOperation::Output})}) {
        FakePipeBackend f;
        f.cqes[0] = {invalid, 4, 0};
        f.cq_tail = 1;
        IoEvent event{};
        CHECK_EQ(f.backend.wait(&event, 1, nullptr, 0), 0u);
        CHECK_EQ(f.backend.failure_code(), EPROTO);
    }
}

TEST(response_body_pipe, send_frame_preserves_logical_bytes_until_exact_acknowledgment) {
    ResponseBodyPipeOwner p{};
    REQUIRE(p.storage.open(4096));
    auto event = [](BodyPipeOperation op, u32 serial, i32 result) {
        IoEvent e{};
        e.type = IoEventType::BodyPipeTransport;
        e.aux = static_cast<u8>(op);
        e.non_upstream_generation = serial;
        e.result = result;
        return e;
    };
    ResponseBodyPipe::Operation in{}, out{};
    REQUIRE(p.storage.reserve_input(8, &in));
    REQUIRE(p.storage.submit_input(in.serial));
    REQUIRE(p.own_target(BodyPipeOperation::Input, in.serial));
    REQUIRE_EQ(write(p.storage.write_fd, "abcdefgh", 8), 8);
    REQUIRE(p.retire(event(BodyPipeOperation::Input, in.serial, 8)));
    REQUIRE(p.storage.reserve_output(8, &out));
    p.send = {out.serial, 8, 0, ResponseBodyPipeOwner::SendKind::Release, false};
    const u32 frame_serial = out.serial;
    REQUIRE(p.storage.submit_output(out.serial));
    REQUIRE(p.own_target(BodyPipeOperation::Output, out.serial));
    char bytes[8]{};
    REQUIRE_EQ(read(p.storage.read_fd, bytes, 3), 3);
    REQUIRE(p.retire(event(BodyPipeOperation::Output, out.serial, 3)));
    CHECK_EQ(p.storage.bytes, 5u);
    CHECK_EQ(p.send.completed, 3u);
    CHECK_EQ(p.logical_bytes(), 8u);
    CHECK(p.busy());
    CHECK(!p.acknowledge_send(frame_serial, 8));
    REQUIRE(p.storage.reserve_input(2, &in));
    REQUIRE(p.storage.submit_input(in.serial));
    REQUIRE(p.own_target(BodyPipeOperation::Input, in.serial));
    REQUIRE_EQ(write(p.storage.write_fd, "ij", 2), 2);
    REQUIRE(p.retire(event(BodyPipeOperation::Input, in.serial, 2)));
    CHECK_EQ(p.logical_bytes(), 10u);
    REQUIRE(p.storage.reserve_output(5, &out));
    REQUIRE(p.storage.submit_output(out.serial));
    REQUIRE(p.own_target(BodyPipeOperation::Output, out.serial));
    CHECK(!p.retire(event(BodyPipeOperation::Output, out.serial, 6)));
    REQUIRE_EQ(read(p.storage.read_fd, bytes, 5), 5);
    CHECK_EQ(memcmp(bytes, "defgh", 5), 0);
    REQUIRE(p.retire(event(BodyPipeOperation::Output, out.serial, 5)));
    CHECK_EQ(p.logical_bytes(), 10u);
    CHECK_EQ(p.send.completed, 8u);
    p.send.delivering = true;
    CHECK(!p.acknowledge_send(frame_serial + 1, 8));
    REQUIRE(p.acknowledge_send(frame_serial, 8));
    CHECK(!p.acknowledge_send(frame_serial, 8));
    CHECK_EQ(p.logical_bytes(), 2u);
    REQUIRE_EQ(p.storage.drain_into(reinterpret_cast<u8*>(bytes), sizeof(bytes)), 2);
    CHECK_EQ(memcmp(bytes, "ij", 2), 0);
    REQUIRE(p.storage.close());
}

TEST(response_body_pipe, flags_capacity_and_transactional_reservations) {
    PipeFixture f;
    auto& p = f.pipe;
    CHECK(!p.open(0));
    REQUIRE(p.open(65536));
    CHECK(p.capacity > 0 && p.capacity <= 65536);
    CHECK(fcntl(p.read_fd, F_GETFL) & O_NONBLOCK);
    CHECK(fcntl(p.write_fd, F_GETFL) & O_NONBLOCK);
    CHECK(fcntl(p.read_fd, F_GETFD) & FD_CLOEXEC);
    CHECK(fcntl(p.write_fd, F_GETFD) & FD_CLOEXEC);
    CHECK(!p.open(65536));
    ResponseBodyPipe::Operation op{};
    CHECK(!p.reserve_input(0, &op));
    REQUIRE(p.reserve_input(UINT32_MAX, &op));
    CHECK_EQ(op.limit, p.capacity);
    CHECK(!p.reserve_input(1, &op));
    CHECK(!p.close());
    CHECK(!p.rollback_input(op.serial + 1));
    REQUIRE(p.rollback_input(op.serial));
    REQUIRE(p.close());
    CHECK_EQ(p.read_fd, -1);
    CHECK_EQ(p.write_fd, -1);
}

TEST(response_body_pipe, partial_progress_and_stale_completions) {
    PipeFixture f;
    auto& p = f.pipe;
    REQUIRE(p.open(65536));
    ResponseBodyPipe::Operation in{}, out{};
    REQUIRE(p.reserve_input(12, &in));
    CHECK(!p.complete_input(in.serial, 12));
    REQUIRE(p.submit_input(in.serial));
    CHECK(!p.rollback_input(in.serial));
    CHECK(!p.complete_input(in.serial + 1, 12));
    CHECK(!p.complete_input(in.serial, 13));
    REQUIRE_EQ(write(p.write_fd, "abcdefghijkl", 12), 12);
    REQUIRE(p.complete_input(in.serial, 12));
    CHECK(!p.complete_input(in.serial, 12));
    CHECK_EQ(p.bytes, 12u);
    REQUIRE(p.reserve_output(5, &out));
    CHECK_EQ(out.limit, 5u);
    REQUIRE(p.submit_output(out.serial));
    REQUIRE(p.reserve_input(4, &in));
    REQUIRE(p.submit_input(in.serial));
    u8 data[16]{};
    CHECK_EQ(p.drain_into(data, sizeof(data)), -EBUSY);
    REQUIRE_EQ(read(p.read_fd, data, 3), 3);
    REQUIRE(p.complete_output(out.serial, 3));
    CHECK_EQ(p.bytes, 9u);
    REQUIRE_EQ(write(p.write_fd, "mnop", 4), 4);
    REQUIRE(p.complete_input(in.serial, 4));
    CHECK_EQ(p.bytes, 13u);
    REQUIRE_EQ(p.drain_into(data, sizeof(data)), 13);
    CHECK_EQ(memcmp(data, "defghijklmnop", 13), 0);
    CHECK_EQ(p.bytes, 0u);
    CHECK(!p.reserve_output(1, &out));
    REQUIRE(p.close());
}

TEST(response_body_pipe, cancellation_eof_retry_and_reopen_keep_identity) {
    PipeFixture f;
    auto& p = f.pipe;
    REQUIRE(p.open(65536));
    ResponseBodyPipe::Operation first{}, second{};
    REQUIRE(p.reserve_input(8, &first));
    REQUIRE(p.submit_input(first.serial));
    CHECK(!p.close());
    REQUIRE(p.complete_input(first.serial, -ECANCELED));
    REQUIRE(p.reserve_input(8, &second));
    CHECK(second.serial > first.serial);
    REQUIRE(p.submit_input(second.serial));
    CHECK(!p.complete_input(first.serial, 8));
    REQUIRE(p.complete_input(second.serial, -EAGAIN));
    REQUIRE(p.close());
    REQUIRE(p.open(65536));
    REQUIRE(p.reserve_input(8, &second));
    CHECK(second.serial > first.serial);
    REQUIRE(p.submit_input(second.serial));
    REQUIRE(p.complete_input(second.serial, 0));
    CHECK_EQ(p.bytes, 0u);
    p.sequence = UINT32_MAX - 1;
    REQUIRE(p.reserve_input(1, &second));
    CHECK_EQ(second.serial, UINT32_MAX);
    REQUIRE(p.submit_input(second.serial));
    REQUIRE(p.complete_input(second.serial, -ECANCELED));
    CHECK(!p.reserve_input(8, &second));
    REQUIRE(p.close());
}

TEST(response_body_pipe, publication_credit_errors_and_final_fd_release) {
    PipeFixture f;
    auto& p = f.pipe;
    REQUIRE(p.open(65536));
    const i32 read_fd = p.read_fd;
    const i32 write_fd = p.write_fd;
    ResponseBodyPipe::Operation in{}, out{}, old{};
    REQUIRE(p.reserve_input(8, &in));
    REQUIRE(p.submit_input(in.serial));
    REQUIRE_EQ(write(p.write_fd, "abcdefgh", 8), 8);
    REQUIRE(p.complete_input(in.serial, 8));
    CHECK(!p.reserve_output(0, &out));
    for (i32 error : {-EAGAIN, -ECANCELED}) {
        REQUIRE(p.reserve_output(3, &out));
        CHECK_EQ(out.limit, 3u);
        REQUIRE(p.submit_output(out.serial));
        CHECK(!p.rollback_output(out.serial));
        CHECK(!p.close());
        REQUIRE(p.complete_output(out.serial, error));
        CHECK_EQ(p.bytes, 8u);
        old = out;
    }
    REQUIRE(p.reserve_output(3, &out));
    REQUIRE(p.submit_output(out.serial));
    CHECK(!p.complete_output(old.serial, 3));
    CHECK(!p.complete_output(out.serial, 4));
    u8 data[8]{};
    REQUIRE_EQ(read(p.read_fd, data, 2), 2);
    REQUIRE(p.complete_output(out.serial, 2));
    CHECK_EQ(p.bytes, 6u);
    REQUIRE_EQ(p.drain_into(data, 3), 3);
    CHECK_EQ(memcmp(data, "cde", 3), 0);
    CHECK_EQ(p.bytes, 3u);
    REQUIRE(p.close());  // abort discards the unpublished suffix
    CHECK_EQ(fcntl(read_fd, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
    CHECK_EQ(fcntl(write_fd, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
}

TEST(response_body_pipe, logical_capacity_and_input_first_completion_order) {
    PipeFixture f;
    auto& p = f.pipe;
    REQUIRE(p.open(8));
    CHECK_EQ(p.capacity, 8u);  // the physical pipe is at least one page
    ResponseBodyPipe::Operation in{}, out{};
    REQUIRE(p.reserve_input(99, &in));
    CHECK_EQ(in.limit, 8u);
    REQUIRE(p.submit_input(in.serial));
    REQUIRE_EQ(write(p.write_fd, "abcd", 4), 4);
    REQUIRE(p.complete_input(in.serial, 4));
    REQUIRE(p.reserve_output(2, &out));
    REQUIRE(p.submit_output(out.serial));
    REQUIRE(p.reserve_input(99, &in));
    CHECK_EQ(in.limit, 4u);  // in-flight output does not grant early credit
    REQUIRE(p.submit_input(in.serial));
    REQUIRE_EQ(write(p.write_fd, "efgh", 4), 4);
    REQUIRE(p.complete_input(in.serial, 4));
    CHECK(!p.reserve_input(1, &in));
    u8 data[8]{};
    REQUIRE_EQ(read(p.read_fd, data, 2), 2);
    REQUIRE(p.complete_output(out.serial, 2));
    REQUIRE_EQ(p.drain_into(data, sizeof(data)), 6);
    CHECK_EQ(memcmp(data, "cdefgh", 6), 0);
    REQUIRE(p.close());
}

TEST(response_body_pipe, page_slot_exhaustion_can_migrate_before_publication) {
    PipeFixture f;
    auto& p = f.pipe;
    REQUIRE(p.open(8192));
    const long page_size = sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    const u32 slots = static_cast<u32>(fcntl(p.read_fd, F_GETPIPE_SZ) / page_size);
    REQUIRE(slots > 0 && slots <= 16);
    const size_t allocation = static_cast<size_t>(slots + 1) * page_size;
    auto* pages = static_cast<u8*>(
        mmap(nullptr, allocation, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(pages != MAP_FAILED);
    for (u32 i = 0; i < slots; ++i) {
        pages[i * page_size] = static_cast<u8>('a' + i);
        iovec piece{pages + i * page_size, 1};
        ResponseBodyPipe::Operation in{};
        REQUIRE(p.reserve_input(1, &in));
        REQUIRE(p.submit_input(in.serial));
        REQUIRE_EQ(vmsplice(p.write_fd, &piece, 1, SPLICE_F_NONBLOCK), 1);
        REQUIRE(p.complete_input(in.serial, 1));
    }
    CHECK(p.bytes < p.capacity);
    iovec extra{pages + slots * page_size, 1};
    ResponseBodyPipe::Operation in{};
    REQUIRE(p.reserve_input(1, &in));
    REQUIRE(p.submit_input(in.serial));
    CHECK_EQ(vmsplice(p.write_fd, &extra, 1, SPLICE_F_NONBLOCK), -1);
    CHECK_EQ(errno, EAGAIN);
    REQUIRE(p.complete_input(in.serial, -EAGAIN));
    u8 copied[16]{};
    REQUIRE_EQ(p.drain_into(copied, sizeof(copied)), static_cast<i32>(slots));
    for (u32 i = 0; i < slots; ++i) CHECK_EQ(copied[i], static_cast<u8>('a' + i));
    CHECK_EQ(p.bytes, 0u);
    REQUIRE(p.close());
    REQUIRE_EQ(munmap(pages, allocation), 0);
}

TEST(response_body_pipe, fd_exhaustion_leaves_empty_owner) {
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        rlimit limit{0, 0};
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(2);
        ResponseBodyPipe p{};
        if (p.open(65536) || p.active() || p.read_fd != -1 || p.write_fd != -1 || p.busy())
            _exit(3);
        _exit(0);
    }
    int status = 0;
    REQUIRE_EQ(waitpid(child, &status, 0), child);
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 0);
}
#else
TEST(response_body_pipe, unsupported_platform_is_neutral) {
    ResponseBodyPipe pipe{};
    CHECK(!pipe.open(65536));
    CHECK(!pipe.active());
    CHECK(pipe.close());
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
