#include "rut/runtime/response_body_pipe.h"
#include "test.h"
#include <initializer_list>

#include <string.h>
#ifdef __linux__
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
