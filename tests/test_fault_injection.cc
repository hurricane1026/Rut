#include "fault_injection.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/epoll_backend.h"
#include "rut/runtime/error.h"
#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

using namespace rut;
using rut::test_fault::fixed_clock_gettime;
using rut::test_fault::HeldEpollEventError;
using rut::test_fault::IoFaultConfig;
using rut::test_fault::ScopedHeldEpollEvent;
using rut::test_fault::ScopedIoFault;
using rut::test_fault::ScopedSyscallFault;
using rut::test_fault::single_recv_eintr;
using rut::test_fault::single_send_eintr;
using rut::test_fault::SyscallFaultConfig;

namespace {

struct timespec* opaque_null_timespec() {
    uintptr_t bits = 0;
#if defined(__GNUC__) || defined(__clang__)
    // Prevent compilers from optimizing the nullptr value away before the call site.
    // This keeps the wrapper under test from relying on compile-time nullness assumptions.
    asm volatile("" : "+r"(bits));
#endif
    return reinterpret_cast<struct timespec*>(bits);
}

}  // namespace

TEST(syscall_fault, close_and_fcntl_failures_are_injected) {
    i32 fd = dup(2);
    REQUIRE(fd >= 0);

    {
        IoFaultConfig fault_config;
        fault_config.fd = fd;
        fault_config.close_errno = EINTR;
        fault_config.close_failures = 1;
        ScopedIoFault fault(fault_config);
        CHECK_EQ(close(fd), -1);
        CHECK_EQ(errno, EINTR);
    }

    {
        IoFaultConfig fault_config;
        fault_config.fd = fd;
        fault_config.fcntl_errno = EINVAL;
        fault_config.fcntl_failures = 1;
        ScopedIoFault fault(fault_config);
        CHECK_EQ(fcntl(fd, F_GETFL, 0), -1);
        CHECK_EQ(errno, EINVAL);
    }

    close(fd);
}

TEST(syscall_fault, fcntl_pointer_args_are_forwarded) {
    i32 fd = open("/dev/null", O_RDONLY);
    REQUIRE(fd >= 0);

    struct flock lock;
    __builtin_memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;

    CHECK_EQ(fcntl(fd, F_GETLK, &lock), 0);
    CHECK_NE(lock.l_type, static_cast<short>(0));

    close(fd);
}

TEST(syscall_fault, fcntl_add_seals_arg_is_forwarded) {
#if !defined(F_ADD_SEALS) || !defined(F_SEAL_SHRINK) || !defined(SYS_memfd_create) || \
    !defined(MFD_ALLOW_SEALING)
    SKIP("memfd sealing unavailable");
#else
    i32 fd = static_cast<i32>(
        syscall(SYS_memfd_create, "rut_fault_seals", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (fd < 0 && (errno == ENOSYS || errno == EINVAL || errno == EPERM)) {
        SKIP("memfd sealing unsupported in this environment");
    }
    REQUIRE(fd >= 0);

    CHECK_EQ(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK), 0);

    close(fd);
#endif
}

TEST(syscall_fault, open_tmpfile_mode_arg_is_forwarded) {
#ifndef O_TMPFILE
    SKIP("O_TMPFILE unavailable");
#else
    i32 fd = open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0 && (errno == EOPNOTSUPP || errno == EISDIR || errno == EINVAL || errno == ENOSYS)) {
        SKIP("O_TMPFILE unsupported in this environment");
    }
    REQUIRE(fd >= 0);
    close(fd);
#endif
}

TEST(syscall_fault, timerfd_settime_failure_is_injected) {
    i32 fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    REQUIRE(fd >= 0);

    SyscallFaultConfig fault_config;
    fault_config.timerfd_settime_errno = EINVAL;
    fault_config.timerfd_settime_failures = 1;
    ScopedSyscallFault fault(fault_config);

    struct itimerspec ts;
    __builtin_memset(&ts, 0, sizeof(ts));
    ts.it_value.tv_sec = 1;
    CHECK_EQ(timerfd_settime(fd, 0, &ts, nullptr), -1);
    CHECK_EQ(errno, EINVAL);
    close(fd);
}

TEST(syscall_fault, mkstemp_and_unlink_failures_are_injected) {
    {
        char path[] = "/tmp/rut_fault_mkstemp_XXXXXX";
        SyscallFaultConfig fault_config;
        fault_config.mkstemp_errno = EACCES;
        fault_config.mkstemp_failures = 1;
        ScopedSyscallFault fault(fault_config);
        CHECK_EQ(mkstemp(path), -1);
        CHECK_EQ(errno, EACCES);
    }

    char path[] = "/tmp/rut_fault_unlink_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    close(fd);

    {
        SyscallFaultConfig fault_config;
        fault_config.unlink_errno = EACCES;
        fault_config.unlink_failures = 1;
        ScopedSyscallFault fault(fault_config);
        CHECK_EQ(unlink(path), -1);
        CHECK_EQ(errno, EACCES);
    }

    unlink(path);
}

TEST(syscall_fault, clock_gettime_fixed_time_is_injected_by_clock_id) {
    ScopedSyscallFault realtime_fault(fixed_clock_gettime(CLOCK_REALTIME, 1711123456, 789123000));
    CHECK_EQ(realtime_us(), 1711123456789123ULL);
    CHECK(monotonic_us() > 0);
}

TEST(io_fault, single_send_eintr_helper_injects_once) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    u8 data[4] = {'o', 'k', 'a', 'y'};
    {
        ScopedIoFault fault(single_send_eintr(fds[0]));
        errno = 0;
        CHECK_EQ(send(fds[0], data, sizeof(data), 0), -1);
        CHECK_EQ(errno, EINTR);
    }
    close(fds[0]);
    close(fds[1]);
}

TEST(io_fault, single_recv_eintr_helper_injects_once) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    const char data[] = "abc";
    auto recv_fault = single_recv_eintr(fds[1], data, sizeof(data) - 1);
    (void)recv_fault;

    u8 buf[4]{};
    errno = 0;
    CHECK_EQ(recv(fds[1], buf, sizeof(buf), 0), -1);
    CHECK_EQ(errno, EINTR);
    CHECK_EQ(recv(fds[1], buf, sizeof(buf), 0), 3);
    CHECK_EQ(memcmp(buf, data, 3), 0);

    close(fds[0]);
    close(fds[1]);
}

TEST(syscall_fault, clock_gettime_fixed_time_can_match_all_clock_ids) {
    const u64 fixed_us = monotonic_us() + 1000000ULL;
    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_fixed = true;
    fault_config.clock_gettime_sec = static_cast<time_t>(fixed_us / 1000000ULL);
    fault_config.clock_gettime_nsec = static_cast<long>((fixed_us % 1000000ULL) * 1000ULL);

    ScopedSyscallFault fault(fault_config);
    CHECK_EQ(realtime_us(), fixed_us);
    CHECK_EQ(monotonic_us(), fixed_us);
}

TEST(syscall_fault, clock_gettime_null_timespec_fails_with_efault) {
    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_fixed = true;
    fault_config.clock_gettime_sec = 42;
    fault_config.clock_gettime_nsec = 123456000;

    ScopedSyscallFault fault(fault_config);
    using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
    ClockGettimeFn injected_clock_gettime = &clock_gettime;
    errno = 0;
    CHECK_EQ(injected_clock_gettime(CLOCK_REALTIME, opaque_null_timespec()), -1);
    CHECK_EQ(errno, EFAULT);
}

TEST(syscall_fault, clock_gettime_invalid_timespec_fails_with_efault) {
    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_fixed = true;
    fault_config.clock_gettime_sec = 42;
    fault_config.clock_gettime_nsec = 123456000;

    ScopedSyscallFault fault(fault_config);
    using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
    ClockGettimeFn injected_clock_gettime = &clock_gettime;
    errno = 0;
    auto* invalid_ts = reinterpret_cast<struct timespec*>(static_cast<uintptr_t>(1));
    CHECK_EQ(injected_clock_gettime(CLOCK_REALTIME, invalid_ts), -1);
    CHECK_EQ(errno, EFAULT);
}

TEST(syscall_fault, clock_gettime_fixed_time_preserves_invalid_clock_errno) {
    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_fixed = true;
    fault_config.clock_gettime_sec = 42;
    fault_config.clock_gettime_nsec = 123456000;

    ScopedSyscallFault fault(fault_config);
    using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
    ClockGettimeFn injected_clock_gettime = &clock_gettime;
    struct timespec ts{};
    errno = 0;
    CHECK_EQ(injected_clock_gettime(static_cast<clockid_t>(-999999), &ts), -1);
    CHECK_EQ(errno, EINVAL);
}

TEST(syscall_fault, clock_gettime_fixed_time_validates_clock_before_null_timespec) {
    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_fixed = true;
    fault_config.clock_gettime_sec = 42;
    fault_config.clock_gettime_nsec = 123456000;

    ScopedSyscallFault fault(fault_config);
    using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
    ClockGettimeFn injected_clock_gettime = &clock_gettime;
    errno = 0;
    CHECK_EQ(injected_clock_gettime(static_cast<clockid_t>(-999999), opaque_null_timespec()), -1);
    CHECK_EQ(errno, EINVAL);
}

TEST(syscall_fault, clock_gettime_default_validates_clock_before_null_timespec) {
    using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
    ClockGettimeFn injected_clock_gettime = &clock_gettime;
    errno = 0;
    CHECK_EQ(injected_clock_gettime(static_cast<clockid_t>(-999999), opaque_null_timespec()), -1);
    CHECK_EQ(errno, EINVAL);
}

TEST(syscall_fault, clock_gettime_fixed_time_rejects_invalid_nsec) {
    using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
    ClockGettimeFn injected_clock_gettime = &clock_gettime;

    {
        SyscallFaultConfig fault_config;
        fault_config.clock_gettime_fixed = true;
        fault_config.clock_gettime_sec = 42;
        fault_config.clock_gettime_nsec = 1000000000L;
        ScopedSyscallFault fault(fault_config);
        struct timespec ts{};
        ts.tv_sec = 7;
        ts.tv_nsec = 8;
        errno = 0;
        CHECK_EQ(injected_clock_gettime(CLOCK_REALTIME, &ts), -1);
        CHECK_EQ(errno, EINVAL);
        CHECK_EQ(ts.tv_sec, 7);
        CHECK_EQ(ts.tv_nsec, 8);
    }

    {
        SyscallFaultConfig fault_config;
        fault_config.clock_gettime_fixed = true;
        fault_config.clock_gettime_sec = 42;
        fault_config.clock_gettime_nsec = -1;
        ScopedSyscallFault fault(fault_config);
        struct timespec ts{};
        ts.tv_sec = 7;
        ts.tv_nsec = 8;
        errno = 0;
        CHECK_EQ(injected_clock_gettime(CLOCK_REALTIME, &ts), -1);
        CHECK_EQ(errno, EINVAL);
        CHECK_EQ(ts.tv_sec, 7);
        CHECK_EQ(ts.tv_nsec, 8);
    }
}

TEST(syscall_fault, access_log_time_helpers_fail_closed_on_clock_error) {
    const u64 last_monotonic = monotonic_us();
    REQUIRE(last_monotonic != 0);

    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_errno = EIO;
    fault_config.clock_gettime_failures = 2;

    ScopedSyscallFault fault(fault_config);
    CHECK_EQ(realtime_us(), 0ULL);
    CHECK_EQ(monotonic_us(), last_monotonic);
}

TEST(syscall_fault, monotonic_us_clamps_first_success_after_clock_error) {
    const u64 last_monotonic = monotonic_us();
    REQUIRE(last_monotonic != 0);

    SyscallFaultConfig fault_config;
    fault_config.clock_gettime_errno = EIO;
    fault_config.clock_gettime_failures = 1;
    fault_config.clock_gettime_fixed = true;
    fault_config.clock_gettime_sec = static_cast<time_t>(last_monotonic / 1000000ULL + 10ULL);
    fault_config.clock_gettime_nsec = static_cast<long>((last_monotonic % 1000000ULL) * 1000ULL);

    ScopedSyscallFault fault(fault_config);
    const u64 failure_value = monotonic_us();
    CHECK_EQ(failure_value, last_monotonic);
    CHECK_GT(monotonic_us(), failure_value);
}

TEST(epoll_fault, init_reports_epoll_create_failure) {
    SyscallFaultConfig fault_config;
    fault_config.epoll_create1_errno = EMFILE;
    fault_config.epoll_create1_failures = 1;
    ScopedSyscallFault fault(fault_config);

    EpollBackend backend;
    auto rc = backend.init(0, -1);
    CHECK(!rc.has_value());
    CHECK_EQ(rc.error().code, EMFILE);
    CHECK(rc.error().source == Error::Source::Epoll);
    backend.shutdown();
}

TEST(epoll_fault, init_reports_timerfd_create_failure) {
    SyscallFaultConfig fault_config;
    fault_config.timerfd_create_errno = EMFILE;
    fault_config.timerfd_create_failures = 1;
    ScopedSyscallFault fault(fault_config);

    EpollBackend backend;
    auto rc = backend.init(0, -1);
    CHECK(!rc.has_value());
    CHECK_EQ(rc.error().code, EMFILE);
    CHECK(rc.error().source == Error::Source::Timerfd);
    backend.shutdown();
}

TEST(epoll_fault, init_reports_epoll_ctl_failure) {
    SyscallFaultConfig fault_config;
    fault_config.epoll_ctl_errno = EINVAL;
    fault_config.epoll_ctl_failures = 1;
    ScopedSyscallFault fault(fault_config);

    EpollBackend backend;
    auto rc = backend.init(0, -1);
    CHECK(!rc.has_value());
    CHECK_EQ(rc.error().code, EINVAL);
    CHECK(rc.error().source == Error::Source::Epoll);
    backend.shutdown();
}

TEST(epoll_fault, wait_retries_injected_eintr) {
    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.pending_completions[0] = {7, 123, 0, 0, IoEventType::Send, 0};
    backend.pending_count = 1;

    SyscallFaultConfig fault_config;
    fault_config.epoll_wait_eintrs = 1;
    ScopedSyscallFault fault(fault_config);

    IoEvent events[2];
    u32 n = backend.wait(events, 2, nullptr, 0);
    CHECK_EQ(n, 1u);
    CHECK_EQ(events[0].conn_id, 7u);
    CHECK_EQ(events[0].type, IoEventType::Send);
    backend.shutdown();
}

TEST(epoll_fault, held_raw_event_is_exact_one_shot_and_fails_closed) {
    struct FdGuard {
        i32 epoll_fds[2] = {-1, -1};
        i32 pipe_fds[2] = {-1, -1};
        ~FdGuard() {
            for (i32& fd : pipe_fds) {
                if (fd >= 0) close(fd);
            }
            for (i32& fd : epoll_fds) {
                if (fd >= 0) close(fd);
            }
        }
    } guard;

    guard.epoll_fds[0] = epoll_create1(EPOLL_CLOEXEC);
    REQUIRE_GE(guard.epoll_fds[0], 0);
    guard.epoll_fds[1] = epoll_create1(EPOLL_CLOEXEC);
    REQUIRE_GE(guard.epoll_fds[1], 0);
    REQUIRE_EQ(pipe2(guard.pipe_fds, O_NONBLOCK | O_CLOEXEC), 0);

    static constexpr u64 kRawData = 0x123456789abcdef0ull;
    struct epoll_event registration{};
    registration.events = EPOLLIN;
    registration.data.u64 = kRawData;
    REQUIRE_EQ(epoll_ctl(guard.epoll_fds[0], EPOLL_CTL_ADD, guard.pipe_fds[0], &registration), 0);
    REQUIRE_EQ(epoll_ctl(guard.epoll_fds[1], EPOLL_CTL_ADD, guard.pipe_fds[0], &registration), 0);
    const char byte = 'x';
    REQUIRE_EQ(write(guard.pipe_fds[1], &byte, 1), 1);

    {
        ScopedHeldEpollEvent invalid_target(-1);
        CHECK_FALSE(invalid_target.owns_state());
        CHECK(invalid_target.failed_closed());
        CHECK_EQ(invalid_target.error(), HeldEpollEventError::InvalidTargetFd);
    }
    {
        ScopedHeldEpollEvent owner(guard.epoll_fds[0]);
        REQUIRE(owner.owns_state());
        ScopedHeldEpollEvent nested(guard.epoll_fds[0]);
        CHECK_FALSE(nested.owns_state());
        CHECK(nested.failed_closed());
        CHECK_EQ(nested.error(), HeldEpollEventError::AlreadyOwned);
        CHECK_FALSE(owner.failed_closed());
    }
    {
        ScopedHeldEpollEvent duplicate_arm(guard.epoll_fds[0]);
        REQUIRE(duplicate_arm.arm_capture_once());
        CHECK_FALSE(duplicate_arm.arm_capture_once());
        CHECK_EQ(duplicate_arm.error(), HeldEpollEventError::DuplicateCaptureArm);
        CHECK_FALSE(duplicate_arm.capture_armed());
    }
    {
        ScopedHeldEpollEvent missing_capture(guard.epoll_fds[0]);
        CHECK_FALSE(missing_capture.replay_once());
        CHECK_EQ(missing_capture.error(), HeldEpollEventError::ReplayWithoutCapture);
    }
    {
        ScopedHeldEpollEvent wrong_fd(guard.epoll_fds[0]);
        REQUIRE(wrong_fd.arm_capture_once());
        struct epoll_event other_event{};
        REQUIRE_EQ(epoll_wait(guard.epoll_fds[1], &other_event, 1, 0), 1);
        CHECK_EQ(other_event.events & EPOLLIN, static_cast<u32>(EPOLLIN));
        CHECK_EQ(other_event.data.u64, kRawData);
        CHECK_EQ(wrong_fd.error(), HeldEpollEventError::WrongEpollFd);
        CHECK_FALSE(wrong_fd.capture_armed());
    }
    {
        ScopedHeldEpollEvent invalid_output(guard.epoll_fds[0]);
        REQUIRE(invalid_output.arm_capture_once());
        struct epoll_event events[2]{};
        REQUIRE_EQ(epoll_wait(guard.epoll_fds[0], events, 2, 0), 1);
        CHECK_EQ(events[0].data.u64, kRawData);
        CHECK_EQ(invalid_output.error(), HeldEpollEventError::InvalidWaitOutput);
        CHECK_FALSE(invalid_output.capture_armed());
    }
    {
        ScopedHeldEpollEvent duplicate_replay(guard.epoll_fds[0]);
        REQUIRE(duplicate_replay.arm_capture_once());
        struct epoll_event suppressed{};
        REQUIRE_EQ(epoll_wait(guard.epoll_fds[0], &suppressed, 1, 0), 0);
        REQUIRE(duplicate_replay.captured());
        REQUIRE(duplicate_replay.replay_once());
        CHECK_FALSE(duplicate_replay.replay_once());
        CHECK_EQ(duplicate_replay.error(), HeldEpollEventError::DuplicateReplayArm);
        CHECK_FALSE(duplicate_replay.replay_armed());
    }
    {
        ScopedHeldEpollEvent held(guard.epoll_fds[0]);
        REQUIRE(held.arm_capture_once());
        struct epoll_event suppressed{};
        REQUIRE_EQ(epoll_wait(guard.epoll_fds[0], &suppressed, 1, 0), 0);
        REQUIRE(held.captured());
        CHECK_FALSE(held.capture_armed());
        const u32 captured_events = held.captured_events();
        const u64 captured_data = held.captured_data();
        CHECK_EQ(captured_events & EPOLLIN, static_cast<u32>(EPOLLIN));
        CHECK_EQ(captured_data, kRawData);

        REQUIRE(held.replay_once());
        struct epoll_event replayed{};
        REQUIRE_EQ(epoll_wait(guard.epoll_fds[0], &replayed, 1, 0), 1);
        CHECK_EQ(replayed.events, captured_events);
        CHECK_EQ(replayed.data.u64, captured_data);
        CHECK(held.replay_consumed());
        CHECK_FALSE(held.replay_armed());
        CHECK_FALSE(held.failed_closed());
    }

    char observed = 0;
    REQUIRE_EQ(read(guard.pipe_fds[0], &observed, 1), 1);
    CHECK_EQ(observed, byte);
    REQUIRE_EQ(write(guard.pipe_fds[1], &byte, 1), 1);
    struct epoll_event transparent{};
    REQUIRE_EQ(epoll_wait(guard.epoll_fds[0], &transparent, 1, 0), 1);
    CHECK_EQ(transparent.data.u64, kRawData);
}

TEST(epoll_fault, accept4_failure_is_injected) {
    i32 fd = dup(2);
    REQUIRE(fd >= 0);

    SyscallFaultConfig fault_config;
    fault_config.accept4_errno = EMFILE;
    fault_config.accept4_failures = 1;
    ScopedSyscallFault fault(fault_config);

    CHECK_EQ(accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC), -1);
    CHECK_EQ(errno, EMFILE);
    close(fd);
}

TEST(epoll_fault, add_send_records_injected_partial_send) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    u8 data[8] = {'p', 'a', 'r', 't', 'i', 'a', 'l', '!'};
    IoFaultConfig fault_config;
    fault_config.fd = fds[0];
    fault_config.send_short_len = 3;
    fault_config.send_shorts = 1;
    ScopedIoFault fault(fault_config);

    CHECK(backend.add_send(fds[0], 0, data, sizeof(data)));
    if (backend.send_state[0].remaining > 0) {
        CHECK_EQ(backend.send_state[0].fd, fds[0]);
        CHECK_EQ(backend.send_state[0].offset, 3u);
        CHECK_EQ(backend.send_state[0].remaining, 5u);

        u8 received[8] = {};
        REQUIRE_EQ(recv(fds[1], received, sizeof(received), 0), 3);
        CHECK_EQ(memcmp(received, data, 3), 0);
    } else {
        REQUIRE_EQ(backend.pending_count, 1u);
        CHECK_EQ(backend.pending_completions[0].type, IoEventType::Send);
        CHECK_LT(backend.pending_completions[0].result, 0);
    }

    backend.shutdown();
    close(fds[0]);
    close(fds[1]);
}

TEST(epoll_fault, add_send_reports_injected_eagain_epoll_ctl_failure) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    u8 data[4] = {'f', 'a', 'i', 'l'};
    IoFaultConfig io_fault;
    io_fault.fd = fds[0];
    io_fault.send_eagains = 1;
    ScopedIoFault send_fault(io_fault);

    SyscallFaultConfig syscall_fault;
    syscall_fault.epoll_ctl_errno = EINVAL;
    syscall_fault.epoll_ctl_failures = 2;
    ScopedSyscallFault epoll_fault(syscall_fault);

    CHECK(backend.add_send(fds[0], 0, data, sizeof(data)));
    REQUIRE_EQ(backend.pending_count, 1u);
    CHECK_EQ(backend.pending_completions[0].type, IoEventType::Send);
    CHECK_EQ(backend.pending_completions[0].result, -EINVAL);
    CHECK_EQ(backend.send_state[0].remaining, 0u);

    backend.shutdown();
    close(fds[0]);
    close(fds[1]);
}

TEST(epoll_fault, add_connect_reports_injected_failure) {
    i32 fd = dup(2);
    REQUIRE(fd >= 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    IoFaultConfig fault_config;
    fault_config.fd = fd;
    fault_config.connect_errno = ECONNREFUSED;
    fault_config.connect_failures = 1;
    ScopedIoFault fault(fault_config);

    struct sockaddr_in a;
    __builtin_memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = __builtin_bswap16(19999);
    a.sin_addr.s_addr = __builtin_bswap32(0x7F000001);

    CHECK(backend.add_connect(fd, 0, &a, sizeof(a), 1));
    REQUIRE_EQ(backend.pending_count, 1u);
    CHECK_EQ(backend.pending_completions[0].type, IoEventType::UpstreamConnect);
    CHECK_EQ(backend.pending_completions[0].result, -ECONNREFUSED);

    backend.shutdown();
    close(fd);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
