#include "fault_injection.h"

#include <atomic>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace rut::test_fault {
namespace {

thread_local FaultState g_state{};

using MmapFn = void* (*)(void*, size_t, int, int, int, off_t);
using MprotectFn = int (*)(void*, size_t, int);
using SocketFn = int (*)(int, int, int);
using RecvFn = ssize_t (*)(int, void*, size_t, int);
using PollFn = int (*)(struct pollfd*, nfds_t, int);
using ReadFn = ssize_t (*)(int, void*, size_t);
using WriteFn = ssize_t (*)(int, const void*, size_t);
using SendFn = ssize_t (*)(int, const void*, size_t, int);
using ConnectFn = int (*)(int, const struct sockaddr*, socklen_t);
using CloseFn = int (*)(int);
using FcntlFn = int (*)(int, int, ...);
using EpollCreate1Fn = int (*)(int);
using EpollCtlFn = int (*)(int, int, int, struct epoll_event*);
using EpollWaitFn = int (*)(int, struct epoll_event*, int, int);
using TimerfdCreateFn = int (*)(int, int);
using TimerfdSettimeFn = int (*)(int, int, const struct itimerspec*, struct itimerspec*);
using Accept4Fn = int (*)(int, struct sockaddr*, socklen_t*, int);
using OpenFn = int (*)(const char*, int, ...);
using MkstempFn = int (*)(char*);
using UnlinkFn = int (*)(const char*);
using ClockGettimeFn = int (*)(clockid_t, struct timespec*);

MmapFn g_real_mmap = nullptr;
MprotectFn g_real_mprotect = nullptr;
SocketFn g_real_socket = nullptr;
RecvFn g_real_recv = nullptr;
PollFn g_real_poll = nullptr;
ReadFn g_real_read = nullptr;
WriteFn g_real_write = nullptr;
SendFn g_real_send = nullptr;
ConnectFn g_real_connect = nullptr;
CloseFn g_real_close = nullptr;
FcntlFn g_real_fcntl = nullptr;
EpollCreate1Fn g_real_epoll_create1 = nullptr;
EpollCtlFn g_real_epoll_ctl = nullptr;
EpollWaitFn g_real_epoll_wait = nullptr;
TimerfdCreateFn g_real_timerfd_create = nullptr;
TimerfdSettimeFn g_real_timerfd_settime = nullptr;
Accept4Fn g_real_accept4 = nullptr;
OpenFn g_real_open = nullptr;
MkstempFn g_real_mkstemp = nullptr;
UnlinkFn g_real_unlink = nullptr;
ClockGettimeFn g_real_clock_gettime = nullptr;
pthread_once_t g_syscall_once = PTHREAD_ONCE_INIT;

std::atomic<int> g_io_fault_fd{-1};
std::atomic<int> g_poll_timeout_count{0};
std::atomic<int> g_poll_eintr_count{0};
std::atomic<int> g_poll_fatal_count{0};
std::atomic<int> g_read_eintr_count{0};
std::atomic<int> g_read_fatal_count{0};
std::atomic<int> g_read_short_len{0};
std::atomic<int> g_read_short_count{0};
std::atomic<int> g_write_eagain_count{0};
std::atomic<int> g_write_eintr_count{0};
std::atomic<int> g_write_fatal_count{0};
std::atomic<int> g_write_short_len{0};
std::atomic<int> g_write_short_count{0};
std::atomic<int> g_send_eagain_count{0};
std::atomic<int> g_send_eintr_count{0};
std::atomic<int> g_send_fatal_count{0};
std::atomic<int> g_send_short_len{0};
std::atomic<int> g_send_short_count{0};
std::atomic<int> g_connect_errno{0};
std::atomic<int> g_connect_fail_count{0};
std::atomic<int> g_close_errno{0};
std::atomic<int> g_close_fail_count{0};
std::atomic<int> g_fcntl_errno{0};
std::atomic<int> g_fcntl_fail_count{0};

std::atomic<int> g_epoll_create1_errno{0};
std::atomic<int> g_epoll_create1_fail_count{0};
std::atomic<int> g_epoll_ctl_errno{0};
std::atomic<int> g_epoll_ctl_fail_count{0};
std::atomic<int> g_epoll_wait_eintr_count{0};
std::atomic<int> g_epoll_wait_errno{0};
std::atomic<int> g_epoll_wait_fail_count{0};
std::atomic<int> g_timerfd_create_errno{0};
std::atomic<int> g_timerfd_create_fail_count{0};
std::atomic<int> g_timerfd_settime_errno{0};
std::atomic<int> g_timerfd_settime_fail_count{0};
std::atomic<int> g_accept4_errno{0};
std::atomic<int> g_accept4_fail_count{0};
std::atomic<int> g_open_errno{0};
std::atomic<int> g_open_fail_count{0};
std::atomic<int> g_mkstemp_errno{0};
std::atomic<int> g_mkstemp_fail_count{0};
std::atomic<int> g_unlink_errno{0};
std::atomic<int> g_unlink_fail_count{0};
std::atomic<int> g_clock_gettime_errno{0};
std::atomic<int> g_clock_gettime_fail_count{0};
std::atomic<bool> g_clock_gettime_fixed{false};
std::atomic<bool> g_clock_gettime_match_all{true};
std::atomic<clockid_t> g_clock_gettime_clock_id{CLOCK_REALTIME};
std::atomic<long long> g_clock_gettime_sec{0};
std::atomic<long> g_clock_gettime_nsec{0};

void resolve_syscalls() {
    g_real_mmap = reinterpret_cast<MmapFn>(dlsym(RTLD_NEXT, "mmap"));
    g_real_mprotect = reinterpret_cast<MprotectFn>(dlsym(RTLD_NEXT, "mprotect"));
    g_real_socket = reinterpret_cast<SocketFn>(dlsym(RTLD_NEXT, "socket"));
    g_real_recv = reinterpret_cast<RecvFn>(dlsym(RTLD_NEXT, "recv"));
    g_real_poll = reinterpret_cast<PollFn>(dlsym(RTLD_NEXT, "poll"));
    g_real_read = reinterpret_cast<ReadFn>(dlsym(RTLD_NEXT, "read"));
    g_real_write = reinterpret_cast<WriteFn>(dlsym(RTLD_NEXT, "write"));
    g_real_send = reinterpret_cast<SendFn>(dlsym(RTLD_NEXT, "send"));
    g_real_connect = reinterpret_cast<ConnectFn>(dlsym(RTLD_NEXT, "connect"));
    g_real_close = reinterpret_cast<CloseFn>(dlsym(RTLD_NEXT, "close"));
    g_real_fcntl = reinterpret_cast<FcntlFn>(dlsym(RTLD_NEXT, "fcntl"));
    g_real_epoll_create1 = reinterpret_cast<EpollCreate1Fn>(dlsym(RTLD_NEXT, "epoll_create1"));
    g_real_epoll_ctl = reinterpret_cast<EpollCtlFn>(dlsym(RTLD_NEXT, "epoll_ctl"));
    g_real_epoll_wait = reinterpret_cast<EpollWaitFn>(dlsym(RTLD_NEXT, "epoll_wait"));
    g_real_timerfd_create = reinterpret_cast<TimerfdCreateFn>(dlsym(RTLD_NEXT, "timerfd_create"));
    g_real_timerfd_settime =
        reinterpret_cast<TimerfdSettimeFn>(dlsym(RTLD_NEXT, "timerfd_settime"));
    g_real_accept4 = reinterpret_cast<Accept4Fn>(dlsym(RTLD_NEXT, "accept4"));
    g_real_open = reinterpret_cast<OpenFn>(dlsym(RTLD_NEXT, "open"));
    g_real_mkstemp = reinterpret_cast<MkstempFn>(dlsym(RTLD_NEXT, "mkstemp"));
    g_real_unlink = reinterpret_cast<UnlinkFn>(dlsym(RTLD_NEXT, "unlink"));
    g_real_clock_gettime = reinterpret_cast<ClockGettimeFn>(dlsym(RTLD_NEXT, "clock_gettime"));
}

bool consume_fault(std::atomic<int>& counter) {
    int remaining = counter.load(std::memory_order_relaxed);
    while (remaining > 0) {
        if (counter.compare_exchange_weak(remaining, remaining - 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

IoFaultConfig current_io_fault_config() {
    IoFaultConfig config;
    config.fd = g_io_fault_fd.load(std::memory_order_relaxed);
    config.poll_timeouts = g_poll_timeout_count.load(std::memory_order_relaxed);
    config.poll_eintrs = g_poll_eintr_count.load(std::memory_order_relaxed);
    config.poll_fatals = g_poll_fatal_count.load(std::memory_order_relaxed);
    config.read_eintrs = g_read_eintr_count.load(std::memory_order_relaxed);
    config.read_fatals = g_read_fatal_count.load(std::memory_order_relaxed);
    config.read_short_len = static_cast<size_t>(g_read_short_len.load(std::memory_order_relaxed));
    config.read_shorts = g_read_short_count.load(std::memory_order_relaxed);
    config.write_eagains = g_write_eagain_count.load(std::memory_order_relaxed);
    config.write_eintrs = g_write_eintr_count.load(std::memory_order_relaxed);
    config.write_fatals = g_write_fatal_count.load(std::memory_order_relaxed);
    config.write_short_len = static_cast<size_t>(g_write_short_len.load(std::memory_order_relaxed));
    config.write_shorts = g_write_short_count.load(std::memory_order_relaxed);
    config.send_eagains = g_send_eagain_count.load(std::memory_order_relaxed);
    config.send_eintrs = g_send_eintr_count.load(std::memory_order_relaxed);
    config.send_fatals = g_send_fatal_count.load(std::memory_order_relaxed);
    config.send_short_len = static_cast<size_t>(g_send_short_len.load(std::memory_order_relaxed));
    config.send_shorts = g_send_short_count.load(std::memory_order_relaxed);
    config.connect_errno = g_connect_errno.load(std::memory_order_relaxed);
    config.connect_failures = g_connect_fail_count.load(std::memory_order_relaxed);
    config.close_errno = g_close_errno.load(std::memory_order_relaxed);
    config.close_failures = g_close_fail_count.load(std::memory_order_relaxed);
    config.fcntl_errno = g_fcntl_errno.load(std::memory_order_relaxed);
    config.fcntl_failures = g_fcntl_fail_count.load(std::memory_order_relaxed);
    return config;
}

void apply_io_fault_config(const IoFaultConfig& config) {
    g_io_fault_fd.store(config.fd, std::memory_order_relaxed);
    g_poll_timeout_count.store(config.poll_timeouts, std::memory_order_relaxed);
    g_poll_eintr_count.store(config.poll_eintrs, std::memory_order_relaxed);
    g_poll_fatal_count.store(config.poll_fatals, std::memory_order_relaxed);
    g_read_eintr_count.store(config.read_eintrs, std::memory_order_relaxed);
    g_read_fatal_count.store(config.read_fatals, std::memory_order_relaxed);
    g_read_short_len.store(static_cast<int>(config.read_short_len), std::memory_order_relaxed);
    g_read_short_count.store(config.read_shorts, std::memory_order_relaxed);
    g_write_eagain_count.store(config.write_eagains, std::memory_order_relaxed);
    g_write_eintr_count.store(config.write_eintrs, std::memory_order_relaxed);
    g_write_fatal_count.store(config.write_fatals, std::memory_order_relaxed);
    g_write_short_len.store(static_cast<int>(config.write_short_len), std::memory_order_relaxed);
    g_write_short_count.store(config.write_shorts, std::memory_order_relaxed);
    g_send_eagain_count.store(config.send_eagains, std::memory_order_relaxed);
    g_send_eintr_count.store(config.send_eintrs, std::memory_order_relaxed);
    g_send_fatal_count.store(config.send_fatals, std::memory_order_relaxed);
    g_send_short_len.store(static_cast<int>(config.send_short_len), std::memory_order_relaxed);
    g_send_short_count.store(config.send_shorts, std::memory_order_relaxed);
    g_connect_errno.store(config.connect_errno, std::memory_order_relaxed);
    g_connect_fail_count.store(config.connect_failures, std::memory_order_relaxed);
    g_close_errno.store(config.close_errno, std::memory_order_relaxed);
    g_close_fail_count.store(config.close_failures, std::memory_order_relaxed);
    g_fcntl_errno.store(config.fcntl_errno, std::memory_order_relaxed);
    g_fcntl_fail_count.store(config.fcntl_failures, std::memory_order_relaxed);
}

SyscallFaultConfig current_syscall_fault_config() {
    SyscallFaultConfig config;
    config.epoll_create1_errno = g_epoll_create1_errno.load(std::memory_order_relaxed);
    config.epoll_create1_failures = g_epoll_create1_fail_count.load(std::memory_order_relaxed);
    config.epoll_ctl_errno = g_epoll_ctl_errno.load(std::memory_order_relaxed);
    config.epoll_ctl_failures = g_epoll_ctl_fail_count.load(std::memory_order_relaxed);
    config.epoll_wait_eintrs = g_epoll_wait_eintr_count.load(std::memory_order_relaxed);
    config.epoll_wait_errno = g_epoll_wait_errno.load(std::memory_order_relaxed);
    config.epoll_wait_failures = g_epoll_wait_fail_count.load(std::memory_order_relaxed);
    config.timerfd_create_errno = g_timerfd_create_errno.load(std::memory_order_relaxed);
    config.timerfd_create_failures = g_timerfd_create_fail_count.load(std::memory_order_relaxed);
    config.timerfd_settime_errno = g_timerfd_settime_errno.load(std::memory_order_relaxed);
    config.timerfd_settime_failures = g_timerfd_settime_fail_count.load(std::memory_order_relaxed);
    config.accept4_errno = g_accept4_errno.load(std::memory_order_relaxed);
    config.accept4_failures = g_accept4_fail_count.load(std::memory_order_relaxed);
    config.open_errno = g_open_errno.load(std::memory_order_relaxed);
    config.open_failures = g_open_fail_count.load(std::memory_order_relaxed);
    config.mkstemp_errno = g_mkstemp_errno.load(std::memory_order_relaxed);
    config.mkstemp_failures = g_mkstemp_fail_count.load(std::memory_order_relaxed);
    config.unlink_errno = g_unlink_errno.load(std::memory_order_relaxed);
    config.unlink_failures = g_unlink_fail_count.load(std::memory_order_relaxed);
    config.clock_gettime_errno = g_clock_gettime_errno.load(std::memory_order_relaxed);
    config.clock_gettime_failures = g_clock_gettime_fail_count.load(std::memory_order_relaxed);
    config.clock_gettime_fixed = g_clock_gettime_fixed.load(std::memory_order_relaxed);
    config.clock_gettime_match_all = g_clock_gettime_match_all.load(std::memory_order_relaxed);
    config.clock_gettime_clock_id = g_clock_gettime_clock_id.load(std::memory_order_relaxed);
    config.clock_gettime_sec =
        static_cast<time_t>(g_clock_gettime_sec.load(std::memory_order_relaxed));
    config.clock_gettime_nsec = g_clock_gettime_nsec.load(std::memory_order_relaxed);
    return config;
}

void apply_syscall_fault_config(const SyscallFaultConfig& config) {
    g_epoll_create1_errno.store(config.epoll_create1_errno, std::memory_order_relaxed);
    g_epoll_create1_fail_count.store(config.epoll_create1_failures, std::memory_order_relaxed);
    g_epoll_ctl_errno.store(config.epoll_ctl_errno, std::memory_order_relaxed);
    g_epoll_ctl_fail_count.store(config.epoll_ctl_failures, std::memory_order_relaxed);
    g_epoll_wait_eintr_count.store(config.epoll_wait_eintrs, std::memory_order_relaxed);
    g_epoll_wait_errno.store(config.epoll_wait_errno, std::memory_order_relaxed);
    g_epoll_wait_fail_count.store(config.epoll_wait_failures, std::memory_order_relaxed);
    g_timerfd_create_errno.store(config.timerfd_create_errno, std::memory_order_relaxed);
    g_timerfd_create_fail_count.store(config.timerfd_create_failures, std::memory_order_relaxed);
    g_timerfd_settime_errno.store(config.timerfd_settime_errno, std::memory_order_relaxed);
    g_timerfd_settime_fail_count.store(config.timerfd_settime_failures, std::memory_order_relaxed);
    g_accept4_errno.store(config.accept4_errno, std::memory_order_relaxed);
    g_accept4_fail_count.store(config.accept4_failures, std::memory_order_relaxed);
    g_open_errno.store(config.open_errno, std::memory_order_relaxed);
    g_open_fail_count.store(config.open_failures, std::memory_order_relaxed);
    g_mkstemp_errno.store(config.mkstemp_errno, std::memory_order_relaxed);
    g_mkstemp_fail_count.store(config.mkstemp_failures, std::memory_order_relaxed);
    g_unlink_errno.store(config.unlink_errno, std::memory_order_relaxed);
    g_unlink_fail_count.store(config.unlink_failures, std::memory_order_relaxed);
    g_clock_gettime_errno.store(config.clock_gettime_errno, std::memory_order_relaxed);
    g_clock_gettime_fail_count.store(config.clock_gettime_failures, std::memory_order_relaxed);
    g_clock_gettime_fixed.store(config.clock_gettime_fixed, std::memory_order_relaxed);
    g_clock_gettime_match_all.store(config.clock_gettime_match_all, std::memory_order_relaxed);
    g_clock_gettime_clock_id.store(config.clock_gettime_clock_id, std::memory_order_relaxed);
    g_clock_gettime_sec.store(static_cast<long long>(config.clock_gettime_sec),
                              std::memory_order_relaxed);
    g_clock_gettime_nsec.store(config.clock_gettime_nsec, std::memory_order_relaxed);
}

int fail_errno_or_default(std::atomic<int>& configured_errno, int default_errno) {
    int err = configured_errno.load(std::memory_order_relaxed);
    return err != 0 ? err : default_errno;
}

bool io_fd_matches(int fd) {
    int fault_fd = g_io_fault_fd.load(std::memory_order_relaxed);
    return fault_fd == kMatchAllIoFds || (fault_fd >= 0 && fd == fault_fd);
}

enum class FcntlArgKind {
    None,
    Int,
    Pointer,
};

FcntlArgKind fcntl_arg_kind(int cmd) {
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
        case F_SETFD:
        case F_SETFL:
        case F_SETOWN:
        case F_SETSIG:
        case F_SETLEASE:
        case F_NOTIFY:
        case F_SETPIPE_SZ:
#ifdef F_ADD_SEALS
        case F_ADD_SEALS:
#endif
            return FcntlArgKind::Int;
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
#ifdef F_GETOWN_EX
        case F_GETOWN_EX:
#endif
#ifdef F_SETOWN_EX
        case F_SETOWN_EX:
#endif
#ifdef F_GET_RW_HINT
        case F_GET_RW_HINT:
#endif
#ifdef F_SET_RW_HINT
        case F_SET_RW_HINT:
#endif
#ifdef F_GET_FILE_RW_HINT
        case F_GET_FILE_RW_HINT:
#endif
#ifdef F_SET_FILE_RW_HINT
        case F_SET_FILE_RW_HINT:
#endif
#ifdef F_OFD_GETLK
        case F_OFD_GETLK:
#endif
#ifdef F_OFD_SETLK
        case F_OFD_SETLK:
#endif
#ifdef F_OFD_SETLKW
        case F_OFD_SETLKW:
#endif
            return FcntlArgKind::Pointer;
        default:
            return FcntlArgKind::None;
    }
}

bool open_flags_require_mode(int flags) {
    if ((flags & O_CREAT) != 0) return true;
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE) return true;
#endif
    return false;
}

bool is_null_ptr(const void* ptr) {
    uintptr_t bits = reinterpret_cast<uintptr_t>(ptr);
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : "+r"(bits));
#endif
    return bits == 0;
}

}  // namespace

FaultState& state() {
    return g_state;
}

void reset() {
    g_state = FaultState{};
}

ScopedFaultState::ScopedFaultState() : previous_(g_state) {}

ScopedFaultState::~ScopedFaultState() {
    g_state = previous_;
}

ScopedMemoryFault::ScopedMemoryFault(int mmap_fail_call, bool mprotect_fail) {
    g_state.mmap_fail_call = mmap_fail_call;
    g_state.mmap_call_count = 0;
    g_state.mprotect_fail = mprotect_fail;
}

ScopedFakeSocket::ScopedFakeSocket(int fd) {
    g_state.fake_socket_fd = fd;
}

ScopedRecvData::ScopedRecvData(int fd, const char* data, size_t len, int eintrs) {
    g_state.recv_fd = fd;
    g_state.recv_eintrs = eintrs;
    g_state.recv_len = len < sizeof(g_state.recv_data) ? len : sizeof(g_state.recv_data);
    for (size_t i = 0; i < g_state.recv_len; i++) {
        g_state.recv_data[i] = static_cast<u8>(data[i]);
    }
}

ScopedIoFault::ScopedIoFault(const IoFaultConfig& config) : previous_(current_io_fault_config()) {
    apply_io_fault_config(config);
}

ScopedIoFault::~ScopedIoFault() {
    apply_io_fault_config(previous_);
}

int ScopedIoFault::remaining_read_eintrs() const {
    return g_read_eintr_count.load(std::memory_order_relaxed);
}

int ScopedIoFault::remaining_write_eintrs() const {
    return g_write_eintr_count.load(std::memory_order_relaxed);
}

int ScopedIoFault::remaining_send_eagains() const {
    return g_send_eagain_count.load(std::memory_order_relaxed);
}

int ScopedIoFault::remaining_connect_failures() const {
    return g_connect_fail_count.load(std::memory_order_relaxed);
}

ScopedSyscallFault::ScopedSyscallFault(const SyscallFaultConfig& config)
    : previous_(current_syscall_fault_config()) {
    apply_syscall_fault_config(config);
}

ScopedSyscallFault::~ScopedSyscallFault() {
    apply_syscall_fault_config(previous_);
}

}  // namespace rut::test_fault

extern "C" void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    auto& state = rut::test_fault::state();
    if (state.mmap_fail_call > 0 && ++state.mmap_call_count == state.mmap_fail_call) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if (!rut::test_fault::g_real_mmap) {
        errno = ENOSYS;
        return MAP_FAILED;
    }
    return rut::test_fault::g_real_mmap(addr, len, prot, flags, fd, offset);
}

extern "C" int mprotect(void* addr, size_t len, int prot) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    auto& state = rut::test_fault::state();
    if (state.mprotect_fail) {
        errno = ENOMEM;
        return -1;
    }
    if (!rut::test_fault::g_real_mprotect) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_mprotect(addr, len, prot);
}

extern "C" int socket(int domain, int type, int protocol) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    auto& state = rut::test_fault::state();
    if (state.fake_socket_fd >= 0 && domain == AF_INET && (type & SOCK_STREAM) == SOCK_STREAM) {
        int fd = state.fake_socket_fd;
        state.fake_socket_fd = -1;
        return fd;
    }
    if (!rut::test_fault::g_real_socket) {
        return static_cast<int>(syscall(SYS_socket, domain, type, protocol));
    }
    return rut::test_fault::g_real_socket(domain, type, protocol);
}

extern "C" ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    auto& state = rut::test_fault::state();
    if (state.recv_fd >= 0 && sockfd == state.recv_fd) {
        if (state.recv_eintrs > 0) {
            state.recv_eintrs--;
            errno = EINTR;
            return -1;
        }
        const size_t n = len < state.recv_len ? len : state.recv_len;
        for (size_t i = 0; i < n; i++) {
            static_cast<rut::u8*>(buf)[i] = state.recv_data[i];
        }
        state.recv_fd = -1;
        state.recv_len = 0;
        return static_cast<ssize_t>(n);
    }
    if (!rut::test_fault::g_real_recv) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_recv(sockfd, buf, len, flags);
}

extern "C" int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (fds != nullptr && nfds == 1 && (fds[0].events & POLLOUT) != 0 &&
        rut::test_fault::io_fd_matches(fds[0].fd)) {
        if (rut::test_fault::consume_fault(rut::test_fault::g_poll_timeout_count)) return 0;
        if (rut::test_fault::consume_fault(rut::test_fault::g_poll_eintr_count)) {
            errno = EINTR;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_poll_fatal_count)) {
            errno = EINVAL;
            return -1;
        }
    }
    if (!rut::test_fault::g_real_poll) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_poll(fds, nfds, timeout);
}

extern "C" ssize_t read(int fd, void* buf, size_t count) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::io_fd_matches(fd)) {
        if (rut::test_fault::consume_fault(rut::test_fault::g_read_eintr_count)) {
            errno = EINTR;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_read_fatal_count)) {
            errno = EIO;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_read_short_count)) {
            int short_len = rut::test_fault::g_read_short_len.load(std::memory_order_relaxed);
            if (short_len > 0 && count > static_cast<size_t>(short_len)) {
                count = static_cast<size_t>(short_len);
            }
        }
    }
    if (!rut::test_fault::g_real_read) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_read(fd, buf, count);
}

extern "C" ssize_t write(int fd, const void* buf, size_t count) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::io_fd_matches(fd)) {
        if (rut::test_fault::consume_fault(rut::test_fault::g_write_eagain_count)) {
            errno = EAGAIN;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_write_eintr_count)) {
            errno = EINTR;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_write_fatal_count)) {
            errno = EPIPE;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_write_short_count)) {
            int short_len = rut::test_fault::g_write_short_len.load(std::memory_order_relaxed);
            if (short_len > 0 && count > static_cast<size_t>(short_len)) {
                count = static_cast<size_t>(short_len);
            }
        }
    }
    if (!rut::test_fault::g_real_write) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_write(fd, buf, count);
}

extern "C" ssize_t send(int fd, const void* buf, size_t len, int flags) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::io_fd_matches(fd)) {
        if (rut::test_fault::consume_fault(rut::test_fault::g_send_eintr_count)) {
            errno = EINTR;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_send_eagain_count)) {
            errno = EAGAIN;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_send_fatal_count)) {
            errno = EPIPE;
            return -1;
        }
        if (rut::test_fault::consume_fault(rut::test_fault::g_send_short_count)) {
            int short_len = rut::test_fault::g_send_short_len.load(std::memory_order_relaxed);
            if (short_len > 0 && len > static_cast<size_t>(short_len)) {
                len = static_cast<size_t>(short_len);
            }
        }
    }
    if (!rut::test_fault::g_real_send) {
        return static_cast<ssize_t>(syscall(SYS_sendto, fd, buf, len, flags, nullptr, 0));
    }
    return rut::test_fault::g_real_send(fd, buf, len, flags);
}

extern "C" int connect(int fd, const struct sockaddr* addr, socklen_t len) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::io_fd_matches(fd) &&
        rut::test_fault::consume_fault(rut::test_fault::g_connect_fail_count)) {
        errno =
            rut::test_fault::fail_errno_or_default(rut::test_fault::g_connect_errno, ECONNREFUSED);
        return -1;
    }
    if (!rut::test_fault::g_real_connect) {
        return static_cast<int>(syscall(SYS_connect, fd, addr, len));
    }
    return rut::test_fault::g_real_connect(fd, addr, len);
}

extern "C" int close(int fd) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::io_fd_matches(fd) &&
        rut::test_fault::consume_fault(rut::test_fault::g_close_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_close_errno, EINTR);
        return -1;
    }
    if (!rut::test_fault::g_real_close) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_close(fd);
}

extern "C" int fcntl(int fd, int cmd, ...) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    int int_arg = 0;
    void* pointer_arg = nullptr;
    auto arg_kind = rut::test_fault::fcntl_arg_kind(cmd);
    va_list ap;
    if (arg_kind == rut::test_fault::FcntlArgKind::Int) {
        va_start(ap, cmd);
        int_arg = va_arg(ap, int);
        va_end(ap);
    } else if (arg_kind == rut::test_fault::FcntlArgKind::Pointer) {
        va_start(ap, cmd);
        pointer_arg = va_arg(ap, void*);
        va_end(ap);
    }

    if (rut::test_fault::io_fd_matches(fd) &&
        rut::test_fault::consume_fault(rut::test_fault::g_fcntl_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_fcntl_errno, EINVAL);
        return -1;
    }
    if (!rut::test_fault::g_real_fcntl) {
        errno = ENOSYS;
        return -1;
    }
    if (arg_kind == rut::test_fault::FcntlArgKind::None) {
        return rut::test_fault::g_real_fcntl(fd, cmd);
    }
    if (arg_kind == rut::test_fault::FcntlArgKind::Pointer) {
        return rut::test_fault::g_real_fcntl(fd, cmd, pointer_arg);
    }
    return rut::test_fault::g_real_fcntl(fd, cmd, int_arg);
}

extern "C" int epoll_create1(int flags) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_epoll_create1_fail_count)) {
        errno =
            rut::test_fault::fail_errno_or_default(rut::test_fault::g_epoll_create1_errno, EMFILE);
        return -1;
    }
    if (!rut::test_fault::g_real_epoll_create1) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_epoll_create1(flags);
}

extern "C" int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_epoll_ctl_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_epoll_ctl_errno, EINVAL);
        return -1;
    }
    if (!rut::test_fault::g_real_epoll_ctl) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_epoll_ctl(epfd, op, fd, event);
}

extern "C" int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_epoll_wait_eintr_count)) {
        errno = EINTR;
        return -1;
    }
    if (rut::test_fault::consume_fault(rut::test_fault::g_epoll_wait_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_epoll_wait_errno, EINVAL);
        return -1;
    }
    if (!rut::test_fault::g_real_epoll_wait) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_epoll_wait(epfd, events, maxevents, timeout);
}

extern "C" int timerfd_create(int clockid, int flags) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_timerfd_create_fail_count)) {
        errno =
            rut::test_fault::fail_errno_or_default(rut::test_fault::g_timerfd_create_errno, EMFILE);
        return -1;
    }
    if (!rut::test_fault::g_real_timerfd_create) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_timerfd_create(clockid, flags);
}

extern "C" int timerfd_settime(int fd,
                               int flags,
                               const struct itimerspec* new_value,
                               struct itimerspec* old_value) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_timerfd_settime_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_timerfd_settime_errno,
                                                       EINVAL);
        return -1;
    }
    if (!rut::test_fault::g_real_timerfd_settime) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_timerfd_settime(fd, flags, new_value, old_value);
}

extern "C" int accept4(int fd, struct sockaddr* addr, socklen_t* len, int flags) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_accept4_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_accept4_errno, EAGAIN);
        return -1;
    }
    if (!rut::test_fault::g_real_accept4) {
        return static_cast<int>(syscall(SYS_accept4, fd, addr, len, flags));
    }
    return rut::test_fault::g_real_accept4(fd, addr, len, flags);
}

extern "C" int open(const char* path, int flags, ...) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    mode_t mode = 0;
    bool has_mode = rut::test_fault::open_flags_require_mode(flags);
    va_list ap;
    if (has_mode) {
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }

    if (rut::test_fault::consume_fault(rut::test_fault::g_open_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_open_errno, EACCES);
        return -1;
    }
    if (!rut::test_fault::g_real_open) {
        errno = ENOSYS;
        return -1;
    }
    if (has_mode) return rut::test_fault::g_real_open(path, flags, mode);
    return rut::test_fault::g_real_open(path, flags);
}

extern "C" int mkstemp(char* path) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_mkstemp_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_mkstemp_errno, EACCES);
        return -1;
    }
    if (!rut::test_fault::g_real_mkstemp) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_mkstemp(path);
}

extern "C" int unlink(const char* path) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
    if (rut::test_fault::consume_fault(rut::test_fault::g_unlink_fail_count)) {
        errno = rut::test_fault::fail_errno_or_default(rut::test_fault::g_unlink_errno, EACCES);
        return -1;
    }
    if (!rut::test_fault::g_real_unlink) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_unlink(path);
}

extern "C" int clock_gettime(clockid_t clockid, struct timespec* ts) {
    pthread_once(&rut::test_fault::g_syscall_once, rut::test_fault::resolve_syscalls);
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull-compare"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif
    const bool ts_is_null = ts == nullptr || rut::test_fault::is_null_ptr(ts);
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    if (ts_is_null) {
        errno = EFAULT;
        return -1;
    }
    if (rut::test_fault::consume_fault(rut::test_fault::g_clock_gettime_fail_count)) {
        errno =
            rut::test_fault::fail_errno_or_default(rut::test_fault::g_clock_gettime_errno, EINVAL);
        return -1;
    }
    const bool match_all =
        rut::test_fault::g_clock_gettime_match_all.load(std::memory_order_relaxed);
    const clockid_t configured_clock =
        rut::test_fault::g_clock_gettime_clock_id.load(std::memory_order_relaxed);
    if (rut::test_fault::g_clock_gettime_fixed.load(std::memory_order_relaxed) &&
        (match_all || configured_clock == clockid)) {
        if (syscall(SYS_clock_gettime, clockid, ts) != 0) {
            return -1;
        }
        const long configured_nsec =
            rut::test_fault::g_clock_gettime_nsec.load(std::memory_order_relaxed);
        if (configured_nsec < 0 || configured_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        ts->tv_sec = static_cast<time_t>(
            rut::test_fault::g_clock_gettime_sec.load(std::memory_order_relaxed));
        ts->tv_nsec = configured_nsec;
        return 0;
    }
    if (!rut::test_fault::g_real_clock_gettime) {
        errno = ENOSYS;
        return -1;
    }
    return rut::test_fault::g_real_clock_gettime(clockid, ts);
}
