#pragma once

#include "rut/common/types.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

namespace rut::test_fault {

inline constexpr int kNoIoFaultFd = -1;
inline constexpr int kMatchAllIoFds = -2;

struct FaultState {
    int mmap_fail_call = 0;
    int mmap_call_count = 0;
    bool mprotect_fail = false;

    int fake_socket_fd = -1;
    int socket_failures = 0;
    int iouring_connect_submit_failures = 0;
    int iouring_staged_send_submit_failures = 0;

    int recv_fd = -1;
    int recv_eintrs = 0;
    size_t recv_len = 0;
    u8 recv_data[512]{};
};

struct IoFaultConfig {
    int fd = kNoIoFaultFd;
    int poll_timeouts = 0;
    int poll_eintrs = 0;
    int poll_fatals = 0;
    int read_eintrs = 0;
    int read_fatals = 0;
    size_t read_short_len = 0;
    int read_shorts = 0;
    int write_eagains = 0;
    int write_eintrs = 0;
    int write_fatals = 0;
    size_t write_short_len = 0;
    int write_shorts = 0;
    int send_eagains = 0;
    int send_eintrs = 0;
    int send_fatals = 0;
    size_t send_short_len = 0;
    int send_shorts = 0;
    int connect_errno = 0;
    int connect_failures = 0;
    int close_errno = 0;
    int close_failures = 0;
    int fcntl_errno = 0;
    int fcntl_failures = 0;
};

inline IoFaultConfig io_fault_for_fd(int fd) {
    IoFaultConfig config;
    config.fd = fd;
    return config;
}

inline IoFaultConfig single_read_eintr(int fd) {
    IoFaultConfig config = io_fault_for_fd(fd);
    config.read_eintrs = 1;
    return config;
}

inline IoFaultConfig single_write_eintr(int fd) {
    IoFaultConfig config = io_fault_for_fd(fd);
    config.write_eintrs = 1;
    return config;
}

inline IoFaultConfig single_send_eintr(int fd) {
    IoFaultConfig config = io_fault_for_fd(fd);
    config.send_eintrs = 1;
    return config;
}

struct SyscallFaultConfig {
    int epoll_create1_errno = 0;
    int epoll_create1_failures = 0;
    int epoll_ctl_errno = 0;
    int epoll_ctl_failures = 0;
    int epoll_wait_eintrs = 0;
    int epoll_wait_errno = 0;
    int epoll_wait_failures = 0;
    int timerfd_create_errno = 0;
    int timerfd_create_failures = 0;
    int timerfd_settime_errno = 0;
    int timerfd_settime_failures = 0;
    int accept4_errno = 0;
    int accept4_failures = 0;
    int open_errno = 0;
    int open_failures = 0;
    int mkstemp_errno = 0;
    int mkstemp_failures = 0;
    int unlink_errno = 0;
    int unlink_failures = 0;
    int clock_gettime_errno = 0;
    int clock_gettime_failures = 0;
    bool clock_gettime_fixed = false;
    bool clock_gettime_match_all = true;
    clockid_t clock_gettime_clock_id = CLOCK_REALTIME;
    time_t clock_gettime_sec = 0;
    long clock_gettime_nsec = 0;
};

inline SyscallFaultConfig fixed_clock_gettime(clockid_t clock_id,
                                              time_t sec,
                                              long nsec,
                                              bool match_all = false) {
    SyscallFaultConfig config;
    config.clock_gettime_fixed = true;
    config.clock_gettime_match_all = match_all;
    config.clock_gettime_clock_id = clock_id;
    config.clock_gettime_sec = sec;
    config.clock_gettime_nsec = nsec;
    return config;
}

FaultState& state();
void reset();

class ScopedFaultState {
public:
    ScopedFaultState(const ScopedFaultState&) = delete;
    ScopedFaultState& operator=(const ScopedFaultState&) = delete;
    ~ScopedFaultState();

protected:
    ScopedFaultState();

private:
    FaultState previous_;
};

class ScopedMemoryFault : private ScopedFaultState {
public:
    explicit ScopedMemoryFault(int mmap_fail_call = 0, bool mprotect_fail = false);
};

class ScopedFakeSocket : private ScopedFaultState {
public:
    explicit ScopedFakeSocket(int fd);
};

class ScopedSocketFailure : private ScopedFaultState {
public:
    explicit ScopedSocketFailure(int failures = 1);
};

class ScopedIoUringSubmitFailure : private ScopedFaultState {
public:
    ScopedIoUringSubmitFailure(int connect_failures, int staged_send_failures = 0);
};

class ScopedRecvData : private ScopedFaultState {
public:
    ScopedRecvData(int fd, const char* data, size_t len, int eintrs = 0);
};

class ScopedIoFault {
public:
    explicit ScopedIoFault(const IoFaultConfig& config);
    ScopedIoFault(const ScopedIoFault&) = delete;
    ScopedIoFault& operator=(const ScopedIoFault&) = delete;
    ~ScopedIoFault();

    int remaining_read_eintrs() const;
    int remaining_write_eagains() const;
    int remaining_write_eintrs() const;
    int remaining_write_fatals() const;
    int remaining_send_eagains() const;
    int remaining_connect_failures() const;

private:
    IoFaultConfig previous_;
};

enum class HeldPositiveWriteError : uint8_t {
    None,
    InvalidTargetFd,
    InvalidPrefixLength,
    AlreadyOwned,
    InvalidWriteLength,
    PrefixWriteFailed,
    DuplicateRelease,
};

// Process-wide, fd-specific test seam for a real positive short write followed
// by one held matching write. The first target write reaches the kernel with
// strict_prefix bytes. The second target write stops before the kernel until
// release() is called. One owner is allowed; destruction releases and waits for
// an in-flight hold so no global state or blocked thread survives the scope.
class ScopedHeldPositiveWrite {
public:
    ScopedHeldPositiveWrite(int target_fd, size_t strict_prefix);
    ScopedHeldPositiveWrite(const ScopedHeldPositiveWrite&) = delete;
    ScopedHeldPositiveWrite& operator=(const ScopedHeldPositiveWrite&) = delete;
    ~ScopedHeldPositiveWrite();

    bool wait_until_held();
    bool release();
    bool wait_until_consumed();

    bool owns_state() const;
    bool prefix_consumed() const;
    bool held() const;
    bool released() const;
    bool consumed() const;
    bool failed_closed() const;
    HeldPositiveWriteError error() const;

private:
    HeldPositiveWriteError local_error_ = HeldPositiveWriteError::None;
};

class ScopedSyscallFault {
public:
    explicit ScopedSyscallFault(const SyscallFaultConfig& config);
    ScopedSyscallFault(const ScopedSyscallFault&) = delete;
    ScopedSyscallFault& operator=(const ScopedSyscallFault&) = delete;
    ~ScopedSyscallFault();

private:
    SyscallFaultConfig previous_;
};

// Test-only userspace hold/replay seam for one raw epoll record.  The captured
// record was produced by the real epoll_wait syscall; this scope merely keeps a
// copy after harvesting it and can return that copy through a later wrapper
// call.  It does not model a kernel event surviving EPOLL_CTL_DEL or close.
enum class HeldEpollEventError : uint8_t {
    None,
    InvalidTargetFd,
    AlreadyOwned,
    DuplicateCaptureArm,
    ReplayWithoutCapture,
    DuplicateReplayArm,
    WrongEpollFd,
    InvalidWaitOutput,
};

class ScopedHeldEpollEvent {
public:
    explicit ScopedHeldEpollEvent(int target_epoll_fd);
    ScopedHeldEpollEvent(const ScopedHeldEpollEvent&) = delete;
    ScopedHeldEpollEvent& operator=(const ScopedHeldEpollEvent&) = delete;
    ~ScopedHeldEpollEvent();

    bool arm_capture_once();
    bool replay_once();

    bool owns_state() const;
    bool capture_armed() const;
    bool captured() const;
    bool replay_armed() const;
    bool replay_consumed() const;
    bool failed_closed() const;
    HeldEpollEventError error() const;
    uint32_t captured_events() const;
    uint64_t captured_data() const;

private:
    HeldEpollEventError local_error_ = HeldEpollEventError::None;
};

inline ScopedRecvData single_recv_eintr(int fd, const char* data, size_t len) {
    return ScopedRecvData(fd, data, len, 1);
}

}  // namespace rut::test_fault
