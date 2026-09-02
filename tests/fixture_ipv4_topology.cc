#include "fixture_ipv4_topology.h"

#include "fixture_exact_input_file_lease.h"
#include "fixture_exact_input_mount_owner.h"
#include "fixture_private_directory_lease.h"
#include "fixture_privileged_listener.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RUT_PINNED_NGINX_IMAGE
#error "RUT_PINNED_NGINX_IMAGE must be provided by the build system"
#endif

namespace rut::test::ipv4_topology {
namespace {

using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr const char* kStageLabel = "rut.stage=358-stage2a2";
constexpr const char* kSidecarStage = "358-held-namespace-sidecar";
constexpr const char* kSidecarRole = "held-namespace-sidecar";
constexpr const char* kNginxStage = "358-nginx-lifecycle";
constexpr const char* kNginxRole = "nginx-pid1-sibling";

static const char* sidecar_revalidation_fault_name(HeldNamespaceSidecarRevalidationFault fault) {
    switch (fault) {
        case HeldNamespaceSidecarRevalidationFault::None:
            return "none";
        case HeldNamespaceSidecarRevalidationFault::Token:
            return "token";
        case HeldNamespaceSidecarRevalidationFault::Role:
            return "role";
        case HeldNamespaceSidecarRevalidationFault::Id:
            return "id";
        case HeldNamespaceSidecarRevalidationFault::ImageReference:
            return "image-reference";
        case HeldNamespaceSidecarRevalidationFault::ImageId:
            return "image-id";
        case HeldNamespaceSidecarRevalidationFault::NetworkMode:
            return "network-mode";
        case HeldNamespaceSidecarRevalidationFault::Pid:
            return "pid";
        case HeldNamespaceSidecarRevalidationFault::StartIdentity:
            return "start-identity";
        case HeldNamespaceSidecarRevalidationFault::NetworkNamespace:
            return "network-namespace";
        case HeldNamespaceSidecarRevalidationFault::Arguments:
            return "arguments";
        case HeldNamespaceSidecarRevalidationFault::ReadOnlyRoot:
            return "read-only-root";
        case HeldNamespaceSidecarRevalidationFault::CapabilityDrop:
            return "capability-drop";
        case HeldNamespaceSidecarRevalidationFault::NoNewPrivileges:
            return "no-new-privileges";
        case HeldNamespaceSidecarRevalidationFault::PublishedPorts:
            return "published-ports";
    }
    return "invalid";
}

struct CommandResult {
    bool started = false;
    bool timed_out = false;
    bool process_group_verified = false;
    int status = 0;
    std::string output;
};

struct DescendantProbe {
    pid_t pid = -1;
    pid_t pgid = -1;
    bool marker_received = false;
    bool same_pgid = false;
    bool alive_before_cleanup = false;
};

static bool exited_zero(const CommandResult& result) {
    return result.started && !result.timed_out && WIFEXITED(result.status) &&
           WEXITSTATUS(result.status) == 0;
}

static bool command_outcome_uncertain(const CommandResult& result) {
    return result.timed_out;
}

static std::string trim(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' '))
        value.pop_back();
    size_t first = 0;
    while (first < value.size() &&
           (value[first] == ' ' || value[first] == '\n' || value[first] == '\r'))
        first++;
    return value.substr(first);
}

static bool process_group_gone(pid_t pgid) {
    if (kill(-pgid, 0) == 0) return false;
    return errno == ESRCH;
}

[[noreturn]] static void runner_fail_stop(pid_t pgid, const char* reason) {
    dprintf(STDERR_FILENO,
            "fatal topology command cleanup failure (pgid %ld): %s\n",
            static_cast<long>(pgid),
            reason);
    // This is deliberately the only unbounded path: returning here could
    // orphan a same-uid command group.  SIGKILL is not catchable; once the
    // group is gone, terminate this runner rather than returning a normal
    // CommandResult.
    for (;;) {
        if (process_group_gone(pgid)) _exit(125);
        (void)kill(-pgid, SIGKILL);
        (void)usleep(10000);
    }
}

static bool terminate_group_bounded(pid_t pgid) {
    if (process_group_gone(pgid)) return true;
    (void)kill(-pgid, SIGTERM);
    const auto term_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (std::chrono::steady_clock::now() < term_deadline) {
        if (process_group_gone(pgid)) return true;
        (void)usleep(10000);
    }
    (void)kill(-pgid, SIGKILL);
    const auto kill_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    while (std::chrono::steady_clock::now() < kill_deadline) {
        if (process_group_gone(pgid)) return true;
        (void)usleep(10000);
    }
    return process_group_gone(pgid);
}

static void require_group_gone(pid_t pgid, const char* reason) {
    if (process_group_gone(pgid)) return;
    if (!terminate_group_bounded(pgid) || !process_group_gone(pgid)) runner_fail_stop(pgid, reason);
}

// Translation-unit-private evidence used only to prove that terminal cleanup
// replay does not issue another external command.
static std::int64_t exact_read_monotonic_ns();
static u64 command_invocation_count = 0;
static u64 observation_command_invocation_count = 0;
thread_local std::int64_t command_deadline_cap_ns = 0;

class CommandDeadlineScope {
public:
    explicit CommandDeadlineScope(std::int64_t deadline_ns) : previous_(command_deadline_cap_ns) {
        command_deadline_cap_ns = previous_ > 0 ? std::min(previous_, deadline_ns) : deadline_ns;
    }
    CommandDeadlineScope(const CommandDeadlineScope&) = delete;
    CommandDeadlineScope& operator=(const CommandDeadlineScope&) = delete;
    CommandDeadlineScope(CommandDeadlineScope&&) = delete;
    CommandDeadlineScope& operator=(CommandDeadlineScope&&) = delete;
    ~CommandDeadlineScope() { command_deadline_cap_ns = previous_; }
    void set(std::int64_t deadline_ns) { command_deadline_cap_ns = deadline_ns; }

private:
    std::int64_t previous_ = 0;
};

static bool run_command(const std::vector<std::string>& arguments,
                        CommandResult& result,
                        int timeout_ms = 15000,
                        bool report_success_as_timeout = false,
                        bool inject_descendant = false,
                        DescendantProbe* descendant_probe = nullptr,
                        size_t output_limit = 65536) {
    ++command_invocation_count;
    const std::int64_t invocation_now = exact_read_monotonic_ns();
    if (invocation_now <= 0 || timeout_ms <= 0 ||
        invocation_now > std::numeric_limits<std::int64_t>::max() -
                             static_cast<std::int64_t>(timeout_ms) * 1000000LL) {
        result = {};
        result.timed_out = true;
        return false;
    }
    const std::int64_t relative_deadline_ns =
        invocation_now + static_cast<std::int64_t>(timeout_ms) * 1000000LL;
    const std::int64_t deadline_ns = command_deadline_cap_ns > 0
                                         ? std::min(relative_deadline_ns, command_deadline_cap_ns)
                                         : relative_deadline_ns;
    if (invocation_now >= deadline_ns) {
        result = {};
        result.timed_out = true;
        return false;
    }
    const auto remaining_timeout_ms = [&]() {
        const std::int64_t now = exact_read_monotonic_ns();
        if (now <= 0 || now >= deadline_ns) return 0;
        const std::int64_t remaining_ns = deadline_ns - now;
        const std::int64_t remaining_ms = (remaining_ns + 999999LL) / 1000000LL;
        return static_cast<int>(std::min<std::int64_t>(remaining_ms, INT_MAX));
    };
    result = {};
    if (arguments.empty()) return false;
    int pipe_fds[2] = {-1, -1};
    if (pipe(pipe_fds) != 0) return false;
    int marker_fds[2] = {-1, -1};
    if (inject_descendant && pipe(marker_fds) != 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        if (marker_fds[0] != -1) close(marker_fds[0]);
        if (marker_fds[1] != -1) close(marker_fds[1]);
        return false;
    }
    if (child == 0) {
        (void)setpgid(0, 0);
        if (inject_descendant) {
            const pid_t descendant = fork();
            if (descendant == 0) {
                close(marker_fds[0]);
                struct {
                    pid_t pid;
                    pid_t pgid;
                } marker{getpid(), getpgrp()};
                const char* bytes = reinterpret_cast<const char*>(&marker);
                size_t written = 0;
                while (written < sizeof(marker)) {
                    const ssize_t count =
                        write(marker_fds[1], bytes + written, sizeof(marker) - written);
                    if (count > 0)
                        written += static_cast<size_t>(count);
                    else if (count < 0 && errno == EINTR)
                        continue;
                    else
                        _exit(126);
                }
                close(marker_fds[1]);
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                (void)usleep(5000000);
                _exit(0);
            }
            close(marker_fds[0]);
            close(marker_fds[1]);
        }
        close(pipe_fds[0]);
        (void)dup2(pipe_fds[1], STDOUT_FILENO);
        (void)dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(pipe_fds[1]);
    if (inject_descendant) close(marker_fds[1]);
    (void)setpgid(child, child);
    const int flags = fcntl(pipe_fds[0], F_GETFL, 0);
    (void)fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
    result.started = true;
    if (inject_descendant) {
        const int marker_timeout_ms = remaining_timeout_ms();
        if (marker_timeout_ms <= 0) {
            close(marker_fds[0]);
            if (!terminate_group_bounded(child))
                runner_fail_stop(child, "deadline marker PGID remained alive");
            close(pipe_fds[0]);
            result.timed_out = true;
            return false;
        }
        pollfd marker_descriptor{marker_fds[0], POLLIN, 0};
        if (poll(&marker_descriptor, 1, std::min(marker_timeout_ms, 1000)) <= 0) {
            close(marker_fds[0]);
            if (!terminate_group_bounded(child))
                runner_fail_stop(child, "descendant marker PGID remained alive");
            close(pipe_fds[0]);
            result.timed_out = exact_read_monotonic_ns() >= deadline_ns;
            return false;
        }
        const int marker_flags = fcntl(marker_fds[0], F_GETFL, 0);
        if (marker_flags < 0 || fcntl(marker_fds[0], F_SETFL, marker_flags | O_NONBLOCK) != 0) {
            close(marker_fds[0]);
            if (!terminate_group_bounded(child))
                runner_fail_stop(child, "marker descriptor setup PGID remained alive");
            close(pipe_fds[0]);
            return false;
        }
        struct {
            pid_t pid;
            pid_t pgid;
        } marker{};
        size_t received = 0;
        while (received < sizeof(marker)) {
            const ssize_t count = read(marker_fds[0],
                                       reinterpret_cast<char*>(&marker) + received,
                                       sizeof(marker) - received);
            if (count > 0)
                received += static_cast<size_t>(count);
            else if (count < 0 && errno == EINTR)
                continue;
            else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            else
                break;
        }
        close(marker_fds[0]);
        if (received != sizeof(marker) || marker.pid <= 0 || marker.pgid != child ||
            getpgid(marker.pid) != child || kill(marker.pid, 0) != 0) {
            if (!terminate_group_bounded(child))
                runner_fail_stop(child, "invalid descendant marker PGID remained alive");
            close(pipe_fds[0]);
            return false;
        }
        if (descendant_probe != nullptr) {
            descendant_probe->pid = marker.pid;
            descendant_probe->pgid = marker.pgid;
            descendant_probe->marker_received = true;
            descendant_probe->same_pgid = true;
        }
    }
    bool reaped = false;
    bool pipe_closed = false;
    while (!reaped || !pipe_closed) {
        char buffer[4096];
        for (;;) {
            const ssize_t count = read(pipe_fds[0], buffer, sizeof(buffer));
            if (count > 0) {
                if (result.output.size() + static_cast<size_t>(count) > output_limit) {
                    if (!terminate_group_bounded(child))
                        runner_fail_stop(child, "output limit PGID remained alive");
                    for (;;) {
                        const pid_t waited = waitpid(child, &result.status, 0);
                        if (waited == child) break;
                        if (waited < 0 && errno == EINTR) continue;
                        if (waited < 0 && errno == ECHILD) break;
                        if (waited < 0 && !terminate_group_bounded(child))
                            runner_fail_stop(child, "wait recovery PGID remained alive");
                        if (waited < 0) break;
                    }
                    require_group_gone(child, "output-limit PGID remained alive");
                    result.process_group_verified = true;
                    close(pipe_fds[0]);
                    result.timed_out = true;
                    return false;
                }
                result.output.append(buffer, static_cast<size_t>(count));
                continue;
            }
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) break;
            pipe_closed = count == 0 || (count < 0 && errno != EINTR);
            break;
        }
        if (!reaped) {
            const pid_t waited = waitpid(child, &result.status, WNOHANG);
            if (waited == child)
                reaped = true;
            else if (waited < 0 && errno != EINTR) {
                // The child is always our own process-group leader.  A
                // waitpid failure must not leave that group running.
                if (errno == ECHILD) {
                    // There is no valid child to wait for anymore.  The
                    // process-group liveness check is authoritative here.
                    if (!terminate_group_bounded(child))
                        runner_fail_stop(child, "ECHILD PGID remained alive");
                } else {
                    if (!terminate_group_bounded(child))
                        runner_fail_stop(child, "non-EINTR wait PGID remained alive");
                    // The bounded helper proved the group disappeared; do
                    // not attempt an invalid waitpid recovery.
                }
                require_group_gone(child, "wait-recovery PGID remained alive");
                result.process_group_verified = true;
                close(pipe_fds[0]);
                return false;
            }
        }
        if (reaped && pipe_closed) {
            if (exact_read_monotonic_ns() >= deadline_ns) result.timed_out = true;
            break;
        }
        if (exact_read_monotonic_ns() >= deadline_ns) {
            (void)kill(-child, SIGTERM);
            (void)usleep(100000);
            if (!reaped) (void)kill(-child, SIGKILL);
            while (!reaped) {
                const pid_t waited = waitpid(child, &result.status, 0);
                if (waited == child)
                    reaped = true;
                else if (waited < 0 && errno == EINTR)
                    continue;
                else if (waited < 0) {
                    // ECHILD means waitpid is no longer valid.  In either
                    // case, terminate and verify the complete PGID without
                    // issuing another invalid wait operation.
                    reaped = terminate_group_bounded(child);
                    if (!reaped) runner_fail_stop(child, "timeout PGID remained alive");
                }
            }
            result.timed_out = true;
            break;
        }
        const int poll_timeout_ms = remaining_timeout_ms();
        if (poll_timeout_ms <= 0) continue;
        pollfd descriptor{pipe_fds[0], POLLIN, 0};
        (void)poll(&descriptor, 1, std::min(poll_timeout_ms, 25));
    }
    if (descendant_probe != nullptr && descendant_probe->marker_received) {
        descendant_probe->alive_before_cleanup = kill(descendant_probe->pid, 0) == 0;
        if (!descendant_probe->alive_before_cleanup)
            runner_fail_stop(child, "descendant disappeared before cleanup checkpoint");
    }
    require_group_gone(child, "normal command completion PGID remained alive");
    result.process_group_verified = true;
    close(pipe_fds[0]);
    if (report_success_as_timeout && reaped && !result.timed_out && WIFEXITED(result.status) &&
        WEXITSTATUS(result.status) == 0) {
        result.timed_out = true;
        return false;
    }
    return reaped && !result.timed_out;
}

struct ExactReadCommandResult {
    bool started = false;
    bool deadline_exceeded = false;
    bool output_overflow = false;
    bool stdout_eof = false;
    bool stderr_eof = false;
    bool child_reaped = false;
    bool wait_status_valid = false;
    bool process_group_owned = false;
    bool process_group_gone = false;
    bool pidfd_opened = false;
    bool pidfd_identity_verified = false;
    bool pidfd_closed_after_group_gone = false;
    bool final_deadline_recorded = false;
    bool cleanup_completed_before_final_deadline = false;
    bool leader_exit_observed_before_group_cleanup = false;
    bool descendant_group_member_observed = false;
    bool supervisor_session_verified = false;
    bool supervisor_subreaper_verified = false;
    bool actual_exec_observed = false;
    bool subtree_confinement_installed = false;
    bool group_echild_observed = false;
    bool control_eof_cleanup = false;
    std::uint32_t adopted_reap_count = 0;
    int stdout_read_errno = 0;
    int stderr_read_errno = 0;
    ExactInputReadLaunchStage launch_failure_stage = ExactInputReadLaunchStage::None;
    int launch_errno = 0;
    int wait_status = 0;
    std::string resolved_executable;
    std::string stdout_bytes;
    std::string stderr_bytes;
};

enum class ExactReadRunnerFault : std::uint8_t {
    None,
    StdoutReadAfterBytes,
    ParentControlEof,
    StatusShort,
    StatusOversize,
    StatusMultiple,
    StatusBadMagic,
    StatusBadVersion,
    StatusReserved,
    StatusNoneStage,
    StatusPidfdOpenStage,
    StatusPidfdIdentityStage,
    StatusExecStatusProtocolStage,
    StatusUnknownStage,
    StatusZeroErrno,
    StatusNegativeErrno,
    StatusZeroBytePreExecDeath,
};

struct ExactReadExecFailureRecord {
    std::uint32_t magic;
    std::uint8_t version;
    std::uint8_t stage;
    std::uint8_t reserved[2];
    std::int32_t error_number;
};

struct ExactReadControlRecord {
    std::uint32_t magic;
    std::uint8_t version;
    std::uint8_t kind;
    std::uint8_t reserved[2];
    std::int64_t final_deadline_ns;
};

struct ExactReadSupervisorReceipt {
    std::uint32_t magic;
    std::uint8_t version;
    std::uint8_t kind;
    std::uint8_t stage;
    std::uint8_t reserved;
    std::int32_t error_number;
    std::int32_t worker_pid;
    std::int32_t wait_status;
    std::uint32_t flags;
    std::uint32_t reap_count;
};

static_assert(sizeof(ExactReadExecFailureRecord) == 12u);
static_assert(sizeof(ExactReadControlRecord) == 16u);
static_assert(sizeof(ExactReadSupervisorReceipt) == 28u);

constexpr std::uint32_t kExactReadExecFailureMagic = 0x45585246u;
constexpr std::uint32_t kExactReadControlMagic = 0x45585243u;
constexpr std::uint32_t kExactReadReceiptMagic = 0x45585252u;
constexpr std::uint8_t kExactReadProtocolVersion = 1u;
constexpr std::uint8_t kExactReadControlStart = 1u;
constexpr std::uint8_t kExactReadControlFinalize = 2u;
constexpr std::uint8_t kExactReadControlAbort = 3u;
constexpr std::uint8_t kExactReadReceiptLaunch = 1u;
constexpr std::uint8_t kExactReadReceiptTerminal = 2u;
constexpr std::uint32_t kExactReadFlagSession = 1u << 0;
constexpr std::uint32_t kExactReadFlagSubreaper = 1u << 1;
constexpr std::uint32_t kExactReadFlagGroup = 1u << 2;
constexpr std::uint32_t kExactReadFlagConfinement = 1u << 3;
constexpr std::uint32_t kExactReadFlagExec = 1u << 4;
constexpr std::uint32_t kExactReadFlagEchild = 1u << 5;
constexpr std::uint32_t kExactReadFlagLeaderExitedBeforeCleanup = 1u << 6;
constexpr std::uint32_t kExactReadFlagControlEof = 1u << 7;

static std::int64_t exact_read_monotonic_ns() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    constexpr std::int64_t kBillion = 1000000000LL;
    if (now.tv_sec > std::numeric_limits<std::int64_t>::max() / kBillion) return -1;
    return static_cast<std::int64_t>(now.tv_sec) * kBillion + now.tv_nsec;
}

static bool make_cloexec_pipe(int descriptors[2]) {
#ifdef SYS_pipe2
    return syscall(SYS_pipe2, descriptors, O_CLOEXEC) == 0;
#else
    (void)descriptors;
    errno = ENOSYS;
    return false;
#endif
}

static bool make_seqpacket_pair(int descriptors[2]) {
    return socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, descriptors) == 0;
}

static bool exact_read_send_datagram(int fd, const void* bytes, size_t size) {
    ssize_t sent;
    do {
        sent = send(fd, bytes, size, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == static_cast<ssize_t>(size);
}

[[noreturn]] static void report_exact_read_exec_failure(int status_fd,
                                                        ExactInputReadLaunchStage stage,
                                                        int error_number) {
    const ExactReadExecFailureRecord record{kExactReadExecFailureMagic,
                                            kExactReadProtocolVersion,
                                            static_cast<std::uint8_t>(stage),
                                            {0u, 0u},
                                            static_cast<std::int32_t>(error_number)};
    (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
    _exit(126);
}

static bool mark_child_descriptors_cloexec(int open_max) {
#if defined(SYS_close_range)
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
    if (syscall(SYS_close_range, 3u, UINT_MAX, CLOSE_RANGE_CLOEXEC) == 0) return true;
    if (errno != ENOSYS && errno != EINVAL) return false;
#endif
    if (open_max < 3) return false;
    for (int fd = 3; fd < open_max; ++fd) {
        const int flags = fcntl(fd, F_GETFD);
        if (flags < 0) {
            if (errno == EBADF) continue;
            return false;
        }
        if ((flags & FD_CLOEXEC) == 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) return false;
    }
    return true;
}

static bool pidfd_targets_exact_pid(int pidfd, pid_t pid) {
    char path[64];
    const int path_length = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
    if (path_length <= 0 || static_cast<size_t>(path_length) >= sizeof(path)) return false;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char bytes[512];
    const ssize_t count = read(fd, bytes, sizeof(bytes) - 1u);
    const int read_error = errno;
    close(fd);
    if (count < 0) {
        errno = read_error;
        return false;
    }
    bytes[count] = '\0';
    const char* marker = strstr(bytes, "Pid:\t");
    if (marker == nullptr) return false;
    char* end = nullptr;
    errno = 0;
    const long parsed = strtol(marker + 5, &end, 10);
    return errno == 0 && end != marker + 5 && parsed == static_cast<long>(pid);
}

static bool install_exact_read_subtree_confinement() {
    // The filter is inherited across fork, clone/clone3 (including
    // CLONE_PARENT), and exec.  CLONE_PARENT does not escape custody: it keeps
    // the inherited PGID and makes the new task a child of an already-owned
    // ancestor (ultimately this private-session subreaper).  Preventing every
    // setpgid/setsid transition is therefore the minimal confinement contract.
    const sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__aarch64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#else
#error "exact-read subtree confinement needs an audited native seccomp architecture"
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__) && defined(__X32_SYSCALL_BIT)
        // Compare the normalized syscall number so the x32 ABI cannot bypass
        // the group/session transition denial.
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~static_cast<unsigned>(__X32_SYSCALL_BIT)),
#endif
#ifdef SYS_setpgid
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setpgid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | static_cast<unsigned>(EPERM)),
#endif
#ifdef SYS_setsid
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setsid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | static_cast<unsigned>(EPERM)),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    const sock_fprog program{static_cast<unsigned short>(std::size(filter)),
                             const_cast<sock_filter*>(filter)};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

static std::string resolve_exact_read_executable(const std::string& requested) {
    if (requested.find('/') != std::string::npos) return requested;
    const char* raw_path = getenv("PATH");
    const std::string path = raw_path == nullptr ? "/usr/local/bin:/usr/bin:/bin" : raw_path;
    size_t begin = 0;
    while (begin <= path.size()) {
        const size_t end = path.find(':', begin);
        const std::string directory =
            path.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        const std::string candidate = (directory.empty() ? "." : directory) + "/" + requested;
        if (access(candidate.c_str(), X_OK) == 0) return candidate;
        if (end == std::string::npos) break;
        begin = end + 1u;
    }
    return requested;
}

static bool exact_read_valid_child_stage(std::uint8_t raw) {
    switch (static_cast<ExactInputReadLaunchStage>(raw)) {
        case ExactInputReadLaunchStage::ProcessGroup:
        case ExactInputReadLaunchStage::ParentDeathGuard:
        case ExactInputReadLaunchStage::StdoutDuplication:
        case ExactInputReadLaunchStage::StderrDuplication:
        case ExactInputReadLaunchStage::DescriptorCustody:
        case ExactInputReadLaunchStage::SubtreeConfinement:
        case ExactInputReadLaunchStage::Execute:
            return true;
        case ExactInputReadLaunchStage::None:
        case ExactInputReadLaunchStage::PidfdOpen:
        case ExactInputReadLaunchStage::PidfdIdentity:
        case ExactInputReadLaunchStage::ExecStatusProtocol:
            return false;
    }
    return false;
}

static bool exact_read_validate_exec_record(const ExactReadExecFailureRecord& record) {
    return record.magic == kExactReadExecFailureMagic &&
           record.version == kExactReadProtocolVersion && record.reserved[0] == 0u &&
           record.reserved[1] == 0u && exact_read_valid_child_stage(record.stage) &&
           record.error_number > 0;
}

[[noreturn]] static void exact_read_emit_fault(int status_fd, ExactReadRunnerFault fault) {
    ExactReadExecFailureRecord record{kExactReadExecFailureMagic,
                                      kExactReadProtocolVersion,
                                      static_cast<std::uint8_t>(ExactInputReadLaunchStage::Execute),
                                      {0u, 0u},
                                      ENOENT};
    switch (fault) {
        case ExactReadRunnerFault::StatusShort:
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record) - 1u);
            break;
        case ExactReadRunnerFault::StatusOversize: {
            std::array<unsigned char, sizeof(record) + 1u> bytes{};
            memcpy(bytes.data(), &record, sizeof(record));
            (void)exact_read_send_datagram(status_fd, bytes.data(), bytes.size());
            break;
        }
        case ExactReadRunnerFault::StatusMultiple:
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusBadMagic:
            record.magic++;
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusBadVersion:
            record.version++;
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusReserved:
            record.reserved[1] = 1u;
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusNoneStage:
            record.stage = static_cast<std::uint8_t>(ExactInputReadLaunchStage::None);
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusPidfdOpenStage:
            record.stage = static_cast<std::uint8_t>(ExactInputReadLaunchStage::PidfdOpen);
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusPidfdIdentityStage:
            record.stage = static_cast<std::uint8_t>(ExactInputReadLaunchStage::PidfdIdentity);
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusExecStatusProtocolStage:
            record.stage = static_cast<std::uint8_t>(ExactInputReadLaunchStage::ExecStatusProtocol);
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusUnknownStage:
            record.stage = 255u;
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusZeroErrno:
            record.error_number = 0;
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusNegativeErrno:
            record.error_number = -1;
            (void)exact_read_send_datagram(status_fd, &record, sizeof(record));
            break;
        case ExactReadRunnerFault::StatusZeroBytePreExecDeath:
            break;
        case ExactReadRunnerFault::None:
        case ExactReadRunnerFault::StdoutReadAfterBytes:
        case ExactReadRunnerFault::ParentControlEof:
            break;
    }
    _exit(126);
}

static bool exact_read_recv_control(int fd, ExactReadControlRecord& record, bool& eof) {
    eof = false;
    ssize_t count;
    do {
        count = recv(fd, &record, sizeof(record), MSG_TRUNC);
    } while (count < 0 && errno == EINTR);
    if (count == 0) {
        eof = true;
        return false;
    }
    if (count != static_cast<ssize_t>(sizeof(record)) || record.magic != kExactReadControlMagic ||
        record.version != kExactReadProtocolVersion || record.reserved[0] != 0u ||
        record.reserved[1] != 0u) {
        errno = EPROTO;
        return false;
    }
    return true;
}

[[noreturn]] static void exact_read_supervisor_fail_stop(pid_t worker,
                                                         std::int64_t deadline_ns,
                                                         const char* reason) {
    dprintf(STDERR_FILENO,
            "fatal exact-read supervisor settlement failure for private group %ld at %lld: %s\n",
            static_cast<long>(worker),
            static_cast<long long>(deadline_ns),
            reason);
    for (;;) {
        if (worker > 0) (void)kill(-worker, SIGKILL);
        for (;;) {
            int status = 0;
            const pid_t reaped = waitpid(-worker, &status, WNOHANG | __WALL);
            if (reaped > 0) continue;
            if (reaped < 0 && errno == ECHILD) _exit(125);
            if (reaped < 0 && errno == EINTR) continue;
            break;
        }
        (void)poll(nullptr, 0, 10);
    }
}

static bool exact_read_send_receipt(int fd, const ExactReadSupervisorReceipt& receipt) {
    return exact_read_send_datagram(fd, &receipt, sizeof(receipt));
}

[[noreturn]] static void run_exact_read_supervisor(int control_fd,
                                                   int report_fd,
                                                   int stdout_write,
                                                   int stderr_write,
                                                   const std::vector<char*>& child_argv,
                                                   const std::string& resolved_executable,
                                                   long raw_open_max,
                                                   ExactReadRunnerFault fault) {
    if (setsid() != getpid() || getsid(0) != getpid() || prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        _exit(121);
    }
    int subreaper = 0;
    if (prctl(PR_GET_CHILD_SUBREAPER, &subreaper) != 0 || subreaper != 1) _exit(121);
    struct sigaction action{};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, nullptr) != 0) _exit(121);

    ExactReadControlRecord start{};
    bool control_eof = false;
    if (!exact_read_recv_control(control_fd, start, control_eof) ||
        start.kind != kExactReadControlStart || start.final_deadline_ns <= 0) {
        _exit(122);
    }
    int status_pair[2] = {-1, -1};
    int barrier_pair[2] = {-1, -1};
    if (!make_seqpacket_pair(status_pair) || !make_seqpacket_pair(barrier_pair)) _exit(122);

    const pid_t worker = fork();
    if (worker < 0) _exit(122);
    if (worker == 0) {
        close(control_fd);
        close(report_fd);
        close(status_pair[0]);
        close(barrier_pair[0]);
        if (setpgid(0, 0) != 0)
            report_exact_read_exec_failure(
                status_pair[1], ExactInputReadLaunchStage::ProcessGroup, errno);
        const pid_t supervisor = getppid();
        if (supervisor <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != supervisor)
            report_exact_read_exec_failure(status_pair[1],
                                           ExactInputReadLaunchStage::ParentDeathGuard,
                                           errno == 0 ? EPIPE : errno);
        if (dup2(stdout_write, STDOUT_FILENO) < 0)
            report_exact_read_exec_failure(
                status_pair[1], ExactInputReadLaunchStage::StdoutDuplication, errno);
        if (dup2(stderr_write, STDERR_FILENO) < 0)
            report_exact_read_exec_failure(
                status_pair[1], ExactInputReadLaunchStage::StderrDuplication, errno);
        close(stdout_write);
        close(stderr_write);
        if (!mark_child_descriptors_cloexec(static_cast<int>(raw_open_max)))
            report_exact_read_exec_failure(
                status_pair[1], ExactInputReadLaunchStage::DescriptorCustody, errno);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
            !install_exact_read_subtree_confinement())
            report_exact_read_exec_failure(
                status_pair[1], ExactInputReadLaunchStage::SubtreeConfinement, errno);
        const unsigned char ready = 0xa5u;
        if (!exact_read_send_datagram(barrier_pair[1], &ready, sizeof(ready))) _exit(126);
        unsigned char release = 0;
        ssize_t received;
        do {
            received = recv(barrier_pair[1], &release, sizeof(release), MSG_TRUNC);
        } while (received < 0 && errno == EINTR);
        if (received != 1 || release != 0x5au) _exit(126);
        if (fault >= ExactReadRunnerFault::StatusShort)
            exact_read_emit_fault(status_pair[1], fault);
        execve(resolved_executable.c_str(), child_argv.data(), environ);
        report_exact_read_exec_failure(status_pair[1], ExactInputReadLaunchStage::Execute, errno);
    }

    close(status_pair[1]);
    close(barrier_pair[1]);
    close(stdout_write);
    close(stderr_write);
    if (setpgid(worker, worker) != 0 && errno != EACCES)
        exact_read_supervisor_fail_stop(worker, start.final_deadline_ns, "setpgid failed");
    if (getpgid(worker) != worker || getsid(worker) != getpid())
        exact_read_supervisor_fail_stop(
            worker, start.final_deadline_ns, "private worker PGID/SID verification failed");
#ifdef SYS_pidfd_open
    const int worker_pidfd = static_cast<int>(syscall(SYS_pidfd_open, worker, 0u));
#else
    errno = ENOSYS;
    const int worker_pidfd = -1;
#endif
    if (worker_pidfd < 0 || !pidfd_targets_exact_pid(worker_pidfd, worker))
        exact_read_supervisor_fail_stop(
            worker, start.final_deadline_ns, "worker pidfd authority failed");

    unsigned char ready = 0;
    const ssize_t ready_count = recv(barrier_pair[0], &ready, sizeof(ready), MSG_TRUNC);
    if (ready_count != 1 || ready != 0xa5u)
        exact_read_supervisor_fail_stop(
            worker, start.final_deadline_ns, "worker readiness protocol failed");
    if (ptrace(PTRACE_SEIZE,
               worker,
               nullptr,
               PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL) != 0)
        exact_read_supervisor_fail_stop(worker, start.final_deadline_ns, "ptrace seize failed");
    const unsigned char release = 0x5au;
    if (!exact_read_send_datagram(barrier_pair[0], &release, sizeof(release)))
        exact_read_supervisor_fail_stop(worker, start.final_deadline_ns, "worker release failed");
    close(barrier_pair[0]);

    bool exec_observed = false;
    bool exit_event_observed = false;
    bool status_eof = false;
    bool status_protocol_failure = false;
    bool launch_control_eof = false;
    unsigned status_datagrams = 0;
    ExactReadExecFailureRecord failure{};
    bool failure_valid = false;
    for (;;) {
        unsigned char control_probe = 0;
        const ssize_t control_count =
            recv(control_fd, &control_probe, sizeof(control_probe), MSG_PEEK | MSG_DONTWAIT);
        if (control_count == 0) {
            launch_control_eof = true;
            (void)kill(-worker, SIGKILL);
        } else if (control_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            launch_control_eof = true;
            (void)kill(-worker, SIGKILL);
        }
        for (;;) {
            ExactReadExecFailureRecord candidate{};
            const ssize_t count =
                recv(status_pair[0], &candidate, sizeof(candidate), MSG_DONTWAIT | MSG_TRUNC);
            if (count > 0) {
                ++status_datagrams;
                if (count != static_cast<ssize_t>(sizeof(candidate)) || status_datagrams != 1u ||
                    !exact_read_validate_exec_record(candidate)) {
                    status_protocol_failure = true;
                } else {
                    failure = candidate;
                    failure_valid = true;
                }
                continue;
            }
            if (count == 0) status_eof = true;
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                status_protocol_failure = true;
            break;
        }

        int trace_status = 0;
        const pid_t traced = waitpid(worker, &trace_status, WNOHANG | __WALL);
        if (traced == worker) {
            if (WIFSTOPPED(trace_status)) {
                const unsigned event = static_cast<unsigned>(trace_status) >> 16u;
                if (event == PTRACE_EVENT_EXEC) {
                    exec_observed = true;
                    if (ptrace(PTRACE_DETACH, worker, nullptr, nullptr) != 0)
                        exact_read_supervisor_fail_stop(
                            worker, start.final_deadline_ns, "ptrace detach failed");
                } else if (event == PTRACE_EVENT_EXIT) {
                    exit_event_observed = true;
                    if (ptrace(PTRACE_CONT, worker, nullptr, nullptr) != 0)
                        exact_read_supervisor_fail_stop(
                            worker, start.final_deadline_ns, "ptrace exit continuation failed");
                } else if (ptrace(PTRACE_CONT, worker, nullptr, nullptr) != 0) {
                    exact_read_supervisor_fail_stop(
                        worker, start.final_deadline_ns, "unexpected ptrace stop");
                }
            } else {
                exact_read_supervisor_fail_stop(
                    worker, start.final_deadline_ns, "worker reaped before terminal custody");
            }
        } else if (traced < 0 && errno != EINTR) {
            exact_read_supervisor_fail_stop(worker, start.final_deadline_ns, "ptrace wait failed");
        }

        if (exec_observed || exit_event_observed) break;
        if (exact_read_monotonic_ns() >= start.final_deadline_ns)
            exact_read_supervisor_fail_stop(
                worker, start.final_deadline_ns, "exec witness missed final deadline");
        (void)poll(nullptr, 0, 1);
    }
    if (exit_event_observed) {
        siginfo_t info{};
        for (;;) {
            if (waitid(static_cast<idtype_t>(3),
                       static_cast<id_t>(worker_pidfd),
                       &info,
                       WEXITED | WNOHANG | WNOWAIT) != 0) {
                if (errno == EINTR) continue;
                exact_read_supervisor_fail_stop(
                    worker, start.final_deadline_ns, "pre-exec exit witness failed");
            }
            if (info.si_pid == worker) break;
            if (exact_read_monotonic_ns() >= start.final_deadline_ns)
                exact_read_supervisor_fail_stop(
                    worker, start.final_deadline_ns, "pre-exec exit missed deadline");
            (void)poll(nullptr, 0, 1);
        }
    }
    while (!status_eof) {
        ExactReadExecFailureRecord candidate{};
        const ssize_t count =
            recv(status_pair[0], &candidate, sizeof(candidate), MSG_DONTWAIT | MSG_TRUNC);
        if (count == 0) {
            status_eof = true;
            break;
        }
        if (count > 0) {
            ++status_datagrams;
            if (count != static_cast<ssize_t>(sizeof(candidate)) || status_datagrams != 1u ||
                !exact_read_validate_exec_record(candidate)) {
                status_protocol_failure = true;
            } else {
                failure = candidate;
                failure_valid = true;
            }
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            status_protocol_failure = true;
            break;
        }
        if (exact_read_monotonic_ns() >= start.final_deadline_ns)
            exact_read_supervisor_fail_stop(
                worker, start.final_deadline_ns, "status EOF missed final deadline");
        if (!status_eof) (void)poll(nullptr, 0, 1);
    }
    close(status_pair[0]);

    ExactReadSupervisorReceipt launch{kExactReadReceiptMagic,
                                      kExactReadProtocolVersion,
                                      kExactReadReceiptLaunch,
                                      static_cast<std::uint8_t>(ExactInputReadLaunchStage::None),
                                      0u,
                                      0,
                                      worker,
                                      0,
                                      kExactReadFlagSession | kExactReadFlagSubreaper |
                                          kExactReadFlagGroup | kExactReadFlagConfinement,
                                      0u};
    if (exec_observed && !status_protocol_failure && status_datagrams == 0u) {
        launch.flags |= kExactReadFlagExec;
    } else if (failure_valid && !status_protocol_failure && status_datagrams == 1u) {
        launch.stage = failure.stage;
        launch.error_number = failure.error_number;
    } else {
        launch.stage = static_cast<std::uint8_t>(ExactInputReadLaunchStage::ExecStatusProtocol);
        launch.error_number = EPROTO;
    }
    if (!launch_control_eof && !exact_read_send_receipt(report_fd, launch))
        exact_read_supervisor_fail_stop(worker, start.final_deadline_ns, "launch receipt failed");

    ExactReadControlRecord terminal_request{};
    bool terminal_control_eof = launch_control_eof;
    if (!launch_control_eof &&
        (!exact_read_recv_control(control_fd, terminal_request, terminal_control_eof) ||
         (terminal_request.kind != kExactReadControlFinalize &&
          terminal_request.kind != kExactReadControlAbort) ||
         terminal_request.final_deadline_ns != start.final_deadline_ns)) {
        terminal_request.kind = kExactReadControlAbort;
    }
    close(control_fd);

    std::uint32_t terminal_flags = launch.flags;
    if (terminal_control_eof) terminal_flags |= kExactReadFlagControlEof;
    siginfo_t pre_cleanup{};
    if (waitid(static_cast<idtype_t>(3),
               static_cast<id_t>(worker_pidfd),
               &pre_cleanup,
               WEXITED | WNOHANG | WNOWAIT) == 0 &&
        pre_cleanup.si_pid == worker)
        terminal_flags |= kExactReadFlagLeaderExitedBeforeCleanup;

    (void)kill(-worker, SIGTERM);
    const std::int64_t grace_end =
        std::min<std::int64_t>(start.final_deadline_ns, exact_read_monotonic_ns() + 50000000LL);
    while (exact_read_monotonic_ns() < grace_end) (void)poll(nullptr, 0, 2);
    (void)kill(-worker, SIGKILL);

    std::uint32_t reap_count = 0;
    int leader_status = 0;
    bool leader_reaped = false;
    for (;;) {
        int status = 0;
        const pid_t reaped = waitpid(-worker, &status, WNOHANG | __WALL);
        if (reaped > 0) {
            ++reap_count;
            if (reaped == worker) {
                leader_reaped = true;
                leader_status = status;
            }
            continue;
        }
        if (reaped < 0 && errno == ECHILD) break;
        if (reaped < 0 && errno != EINTR)
            exact_read_supervisor_fail_stop(
                worker, start.final_deadline_ns, "authoritative group wait failed");
        if (exact_read_monotonic_ns() >= start.final_deadline_ns)
            exact_read_supervisor_fail_stop(
                worker, start.final_deadline_ns, "authoritative group ECHILD missed deadline");
        (void)poll(nullptr, 0, 1);
    }
    if (!leader_reaped || reap_count == 0u)
        exact_read_supervisor_fail_stop(
            worker, start.final_deadline_ns, "incomplete terminal group proof");
    close(worker_pidfd);
    terminal_flags |= kExactReadFlagEchild;
    const ExactReadSupervisorReceipt terminal{kExactReadReceiptMagic,
                                              kExactReadProtocolVersion,
                                              kExactReadReceiptTerminal,
                                              launch.stage,
                                              0u,
                                              launch.error_number,
                                              worker,
                                              leader_status,
                                              terminal_flags,
                                              reap_count};
    if (!exact_read_send_receipt(report_fd, terminal) && !terminal_control_eof) _exit(123);
    close(report_fd);
    _exit(0);
}

static bool exact_read_validate_receipt(const ExactReadSupervisorReceipt& receipt,
                                        std::uint8_t expected_kind) {
    return receipt.magic == kExactReadReceiptMagic &&
           receipt.version == kExactReadProtocolVersion && receipt.kind == expected_kind &&
           receipt.reserved == 0u && receipt.worker_pid > 0;
}

static bool run_exact_read_command_until(const std::vector<std::string>& arguments,
                                         size_t stdout_limit,
                                         std::int64_t final_deadline_ns,
                                         ExactReadCommandResult& result,
                                         ExactReadRunnerFault fault = ExactReadRunnerFault::None) {
    ++command_invocation_count;
    ++observation_command_invocation_count;
    result = {};
    const std::int64_t now_ns = exact_read_monotonic_ns();
    if (arguments.empty() || stdout_limit == 0u || now_ns <= 0 || final_deadline_ns <= now_ns)
        return false;
    const std::int64_t remaining_ms = (final_deadline_ns - now_ns) / 1000000LL;
    const std::int64_t cleanup_reserve_ns =
        std::min<std::int64_t>(200, std::max<std::int64_t>(50, remaining_ms / 2)) * 1000000LL;
    const std::int64_t begin_cleanup_ns = final_deadline_ns - cleanup_reserve_ns;
    result.final_deadline_recorded = true;

    const long raw_open_max = sysconf(_SC_OPEN_MAX);
    if (raw_open_max < 3 || raw_open_max > std::numeric_limits<int>::max()) {
        result.launch_failure_stage = ExactInputReadLaunchStage::DescriptorCustody;
        result.launch_errno = raw_open_max < 0 ? errno : EOVERFLOW;
        return false;
    }
    std::vector<char*> child_argv;
    child_argv.reserve(arguments.size() + 1u);
    for (const std::string& argument : arguments)
        child_argv.push_back(const_cast<char*>(argument.c_str()));
    child_argv.push_back(nullptr);
    result.resolved_executable = resolve_exact_read_executable(arguments.front());

    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int control_pair[2] = {-1, -1};
    int report_pair[2] = {-1, -1};
    if (!make_cloexec_pipe(stdout_pipe)) return false;
    if (!make_cloexec_pipe(stderr_pipe)) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        return false;
    }
    if (!make_seqpacket_pair(control_pair)) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        return false;
    }
    if (!make_seqpacket_pair(report_pair)) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        close(control_pair[0]);
        close(control_pair[1]);
        return false;
    }
    const pid_t supervisor = fork();
    if (supervisor < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        close(control_pair[0]);
        close(control_pair[1]);
        close(report_pair[0]);
        close(report_pair[1]);
        return false;
    }
    if (supervisor == 0) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        close(control_pair[0]);
        close(report_pair[0]);
        run_exact_read_supervisor(control_pair[1],
                                  report_pair[1],
                                  stdout_pipe[1],
                                  stderr_pipe[1],
                                  child_argv,
                                  result.resolved_executable,
                                  raw_open_max,
                                  fault);
    }
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    close(control_pair[1]);
    close(report_pair[1]);
#ifdef SYS_pidfd_open
    const int supervisor_pidfd = static_cast<int>(syscall(SYS_pidfd_open, supervisor, 0u));
#else
    errno = ENOSYS;
    const int supervisor_pidfd = -1;
#endif
    if (supervisor_pidfd < 0 || !pidfd_targets_exact_pid(supervisor_pidfd, supervisor)) {
        close(control_pair[0]);
        int ignored = 0;
        (void)waitpid(supervisor, &ignored, 0);
        if (supervisor_pidfd >= 0) close(supervisor_pidfd);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        close(report_pair[0]);
        return false;
    }
    result.pidfd_opened = true;
    result.pidfd_identity_verified = true;
    const ExactReadControlRecord start{kExactReadControlMagic,
                                       kExactReadProtocolVersion,
                                       kExactReadControlStart,
                                       {0u, 0u},
                                       final_deadline_ns};
    if (!exact_read_send_datagram(control_pair[0], &start, sizeof(start))) {
        close(control_pair[0]);
        close(supervisor_pidfd);
        int ignored = 0;
        (void)waitpid(supervisor, &ignored, 0);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        close(report_pair[0]);
        return false;
    }
    for (const int fd : {stdout_pipe[0], stderr_pipe[0], report_pair[0]}) {
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(control_pair[0]);
            int ignored = 0;
            while (waitpid(supervisor, &ignored, 0) < 0 && errno == EINTR) {
            }
            close(supervisor_pidfd);
            close(stdout_pipe[0]);
            close(stderr_pipe[0]);
            close(report_pair[0]);
            return false;
        }
    }

    constexpr size_t kStderrLimit = fixture_exact_input_file_lease::kMaximumInputBytes + 1u;
    bool injected_read_error = false;
    const auto drain = [&](int fd,
                           std::string& bytes,
                           size_t limit,
                           bool& eof,
                           int& read_error,
                           bool inject_error) {
        if (eof || read_error != 0 || result.output_overflow) return;
        char buffer[4096];
        for (;;) {
            const ssize_t count = read(fd, buffer, sizeof(buffer));
            if (count > 0) {
                const size_t available = static_cast<size_t>(count);
                const size_t remaining = bytes.size() <= limit ? limit - bytes.size() : 0u;
                const size_t retained = std::min(remaining, available);
                bytes.append(buffer, retained);
                if (available > remaining) {
                    result.output_overflow = true;
                    return;
                }
                if (inject_error && !injected_read_error && !bytes.empty()) {
                    injected_read_error = true;
                    read_error = EIO;
                    return;
                }
                continue;
            }
            if (count == 0) {
                eof = true;
                return;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            read_error = errno;
            return;
        }
    };

    bool launch_received = false;
    bool terminal_received = false;
    bool request_sent = false;
    bool control_closed = false;
    ExactReadSupervisorReceipt launch{};
    ExactReadSupervisorReceipt terminal{};
    while (!terminal_received) {
        drain(stdout_pipe[0],
              result.stdout_bytes,
              stdout_limit,
              result.stdout_eof,
              result.stdout_read_errno,
              fault == ExactReadRunnerFault::StdoutReadAfterBytes);
        drain(stderr_pipe[0],
              result.stderr_bytes,
              kStderrLimit,
              result.stderr_eof,
              result.stderr_read_errno,
              false);
        for (;;) {
            ExactReadSupervisorReceipt receipt{};
            const ssize_t count =
                recv(report_pair[0], &receipt, sizeof(receipt), MSG_DONTWAIT | MSG_TRUNC);
            if (count > 0) {
                if (count != static_cast<ssize_t>(sizeof(receipt))) {
                    result.launch_failure_stage = ExactInputReadLaunchStage::ExecStatusProtocol;
                    result.launch_errno = EPROTO;
                    continue;
                }
                if (!launch_received) {
                    if (!exact_read_validate_receipt(receipt, kExactReadReceiptLaunch)) {
                        result.launch_failure_stage = ExactInputReadLaunchStage::ExecStatusProtocol;
                        result.launch_errno = EPROTO;
                    } else {
                        launch = receipt;
                        launch_received = true;
                        result.started = (launch.flags & kExactReadFlagExec) != 0u;
                        result.actual_exec_observed = result.started;
                        result.supervisor_session_verified =
                            (launch.flags & kExactReadFlagSession) != 0u;
                        result.supervisor_subreaper_verified =
                            (launch.flags & kExactReadFlagSubreaper) != 0u;
                        result.process_group_owned = (launch.flags & kExactReadFlagGroup) != 0u;
                        result.subtree_confinement_installed =
                            (launch.flags & kExactReadFlagConfinement) != 0u;
                        if (!result.started) {
                            result.launch_failure_stage =
                                static_cast<ExactInputReadLaunchStage>(launch.stage);
                            result.launch_errno = launch.error_number;
                        }
                    }
                } else if (!exact_read_validate_receipt(receipt, kExactReadReceiptTerminal) ||
                           receipt.worker_pid != launch.worker_pid) {
                    result.launch_failure_stage = ExactInputReadLaunchStage::ExecStatusProtocol;
                    result.launch_errno = EPROTO;
                } else {
                    terminal = receipt;
                    terminal_received = true;
                }
                continue;
            }
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                result.launch_failure_stage = ExactInputReadLaunchStage::ExecStatusProtocol;
                result.launch_errno = errno;
            }
            break;
        }

        const bool stream_failure = result.output_overflow || result.stdout_read_errno != 0 ||
                                    result.stderr_read_errno != 0;
        const std::int64_t loop_now = exact_read_monotonic_ns();
        const bool observation_complete = launch_received && result.stdout_eof && result.stderr_eof;
        if (launch_received && !request_sent &&
            (stream_failure || observation_complete || loop_now >= begin_cleanup_ns)) {
            const ExactReadControlRecord request{kExactReadControlMagic,
                                                 kExactReadProtocolVersion,
                                                 stream_failure || loop_now >= begin_cleanup_ns
                                                     ? kExactReadControlAbort
                                                     : kExactReadControlFinalize,
                                                 {0u, 0u},
                                                 final_deadline_ns};
            if (loop_now >= begin_cleanup_ns && !observation_complete)
                result.deadline_exceeded = true;
            if (fault == ExactReadRunnerFault::ParentControlEof) {
                close(control_pair[0]);
                control_closed = true;
            } else if (!exact_read_send_datagram(control_pair[0], &request, sizeof(request))) {
                close(control_pair[0]);
                control_closed = true;
            }
            request_sent = true;
        }
        if (terminal_received) break;
        if (loop_now >= final_deadline_ns) {
            dprintf(STDERR_FILENO,
                    "fatal exact-read parent retained supervisor pidfd after final deadline\n");
            for (;;) {
                pollfd descriptor{report_pair[0], POLLIN, 0};
                (void)poll(&descriptor, 1, 1000);
            }
        }
        pollfd descriptors[4] = {{stdout_pipe[0], POLLIN | POLLHUP, 0},
                                 {stderr_pipe[0], POLLIN | POLLHUP, 0},
                                 {report_pair[0], POLLIN | POLLHUP, 0},
                                 {supervisor_pidfd, POLLIN, 0}};
        (void)poll(descriptors, 4, 5);
    }
    if (!control_closed) close(control_pair[0]);
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    close(report_pair[0]);

    int supervisor_status = 0;
    pid_t waited;
    do {
        waited = waitpid(supervisor, &supervisor_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != supervisor || !WIFEXITED(supervisor_status) ||
        WEXITSTATUS(supervisor_status) != 0) {
        for (;;) (void)poll(nullptr, 0, 1000);
    }

    result.child_reaped = terminal.reap_count > 0u;
    result.wait_status_valid = result.child_reaped;
    result.wait_status = terminal.wait_status;
    result.adopted_reap_count = terminal.reap_count;
    result.group_echild_observed = (terminal.flags & kExactReadFlagEchild) != 0u;
    result.process_group_gone = result.group_echild_observed;
    result.leader_exit_observed_before_group_cleanup =
        (terminal.flags & kExactReadFlagLeaderExitedBeforeCleanup) != 0u;
    result.descendant_group_member_observed = terminal.reap_count > 1u;
    result.control_eof_cleanup = (terminal.flags & kExactReadFlagControlEof) != 0u;
    result.cleanup_completed_before_final_deadline = exact_read_monotonic_ns() < final_deadline_ns;
    close(supervisor_pidfd);
    result.pidfd_closed_after_group_gone = result.group_echild_observed;
    return result.started && !result.deadline_exceeded && !result.output_overflow &&
           result.stdout_read_errno == 0 && result.stderr_read_errno == 0 &&
           result.cleanup_completed_before_final_deadline && result.group_echild_observed;
}

static bool run_exact_read_command(const std::vector<std::string>& arguments,
                                   size_t stdout_limit,
                                   int timeout_ms,
                                   ExactReadCommandResult& result,
                                   ExactReadRunnerFault fault = ExactReadRunnerFault::None) {
    const std::int64_t now_ns = exact_read_monotonic_ns();
    if (now_ns <= 0 || timeout_ms <= 0 ||
        timeout_ms > (std::numeric_limits<std::int64_t>::max() - now_ns) / 1000000LL) {
        result = {};
        return false;
    }
    return run_exact_read_command_until(arguments,
                                        stdout_limit,
                                        now_ns + static_cast<std::int64_t>(timeout_ms) * 1000000LL,
                                        result,
                                        fault);
}
static ExactInputReadOutcome classify_exact_read(const ExactReadCommandResult& result,
                                                 const std::string& expected) {
    if (!result.started) return ExactInputReadOutcome::CommandStartFailed;
    if (result.deadline_exceeded) return ExactInputReadOutcome::DeadlineExceeded;
    if (result.output_overflow) return ExactInputReadOutcome::OutputLimitExceeded;
    if (result.stdout_read_errno != 0 || result.stderr_read_errno != 0 || !result.stdout_eof ||
        !result.stderr_eof || !result.child_reaped || !result.wait_status_valid ||
        !result.process_group_gone)
        return ExactInputReadOutcome::StreamError;
    if (WIFSIGNALED(result.wait_status)) return ExactInputReadOutcome::ExitSignaled;
    if (!WIFEXITED(result.wait_status) || WEXITSTATUS(result.wait_status) != 0)
        return ExactInputReadOutcome::ExitNonzero;
    if (!result.stderr_bytes.empty()) return ExactInputReadOutcome::StderrNotEmpty;
    if (result.stdout_bytes != expected) return ExactInputReadOutcome::ByteMismatch;
    return ExactInputReadOutcome::Complete;
}

static void copy_exact_read_result(const ExactReadCommandResult& result,
                                   ExactInputReadObservation& observation) {
    observation.command_started = result.started;
    observation.stdout_eof = result.stdout_eof;
    observation.stderr_eof = result.stderr_eof;
    observation.child_reaped = result.child_reaped;
    observation.wait_status_valid = result.wait_status_valid;
    observation.process_group_owned = result.process_group_owned;
    observation.process_group_gone = result.process_group_gone;
    observation.pidfd_opened = result.pidfd_opened;
    observation.pidfd_identity_verified = result.pidfd_identity_verified;
    observation.pidfd_closed_after_group_gone = result.pidfd_closed_after_group_gone;
    observation.final_deadline_recorded = result.final_deadline_recorded;
    observation.cleanup_completed_before_final_deadline =
        result.cleanup_completed_before_final_deadline;
    observation.leader_exit_observed_before_group_cleanup =
        result.leader_exit_observed_before_group_cleanup;
    observation.descendant_group_member_observed = result.descendant_group_member_observed;
    observation.supervisor_session_verified = result.supervisor_session_verified;
    observation.supervisor_subreaper_verified = result.supervisor_subreaper_verified;
    observation.actual_exec_observed = result.actual_exec_observed;
    observation.subtree_confinement_installed = result.subtree_confinement_installed;
    observation.group_echild_observed = result.group_echild_observed;
    observation.control_eof_cleanup = result.control_eof_cleanup;
    observation.adopted_reap_count = result.adopted_reap_count;
    observation.deadline_exceeded = result.deadline_exceeded;
    observation.output_overflow = result.output_overflow;
    observation.stdout_read_errno = result.stdout_read_errno;
    observation.stderr_read_errno = result.stderr_read_errno;
    observation.launch_failure_stage = result.launch_failure_stage;
    observation.launch_errno = result.launch_errno;
    observation.wait_status = result.wait_status;
    observation.resolved_executable = result.resolved_executable;
    observation.stdout_bytes = result.stdout_bytes;
    observation.stderr_bytes = result.stderr_bytes;
}

static bool read_file(const std::string& path, std::string& output) {
    output.clear();
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buffer[4096];
    for (;;) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            if (output.size() + static_cast<size_t>(count) > 65536) {
                close(fd);
                return false;
            }
            output.append(buffer, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        const bool success = count == 0;
        close(fd);
        return success;
    }
}

static bool high_entropy_token(std::string& token) {
    std::array<unsigned char, 24> bytes{};
    if (getrandom(bytes.data(), bytes.size(), 0) != static_cast<ssize_t>(bytes.size()))
        return false;
    static constexpr char hex[] = "0123456789abcdef";
    token.clear();
    for (unsigned char byte : bytes) {
        token.push_back(hex[byte >> 4]);
        token.push_back(hex[byte & 15]);
    }
    return true;
}

struct TempDir {
    char path[64] = "/tmp/rut358-topology-XXXXXX";
    bool created = false;
    std::string manifest;
    bool create() {
        if (mkdtemp(path) == nullptr || chmod(path, 0700) != 0) return false;
        created = true;
        manifest = std::string(path) + "/manifest";
        return true;
    }
    ~TempDir() {
        if (!created) return;
        unlink(manifest.c_str());
        rmdir(path);
    }
};

struct Network {
    std::string name;
    std::string id;
    std::string subnet;
    std::string gateway;
    bool exists = false;
};

struct IPv4Range {
    u32 low = 0;
    u32 high = 0;
    unsigned prefix = 0;
};

struct NetworkPlan {
    std::string subnet;
    std::string gateway;
};

struct SubnetPlan {
    NetworkPlan network_a;
    NetworkPlan network_b;
};

struct Endpoint {
    std::string network_name;
    std::string network_id;
    std::string address;
    std::string cidr;
    std::string gateway;
};

static bool split_exact(const std::string& text,
                        char delimiter,
                        size_t expected,
                        std::vector<std::string>& fields) {
    fields.clear();
    size_t start = 0;
    for (;;) {
        const size_t end = text.find(delimiter, start);
        fields.push_back(text.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return fields.size() == expected;
}

static bool endpoint_equal(const Endpoint& left, const Endpoint& right) {
    return left.network_name == right.network_name && left.network_id == right.network_id &&
           left.address == right.address && left.cidr == right.cidr &&
           left.gateway == right.gateway;
}

static bool endpoint_set_equal(const std::vector<Endpoint>& expected,
                               const std::vector<Endpoint>& actual) {
    if (expected.size() != actual.size()) return false;
    for (const Endpoint& wanted : expected) {
        size_t matches = 0;
        for (const Endpoint& observed : actual)
            if (endpoint_equal(wanted, observed)) matches++;
        if (matches != 1) return false;
    }
    return true;
}

enum class JsonType { Null, Boolean, Number, String, Array, Object };

struct JsonValue {
    JsonType type = JsonType::Null;
    // Object members retain only their values: none of the five Docker fields
    // needs key lookup, while retaining values is sufficient to distinguish
    // an exposed-but-unpublished port (null) from a host binding (array).
    std::vector<JsonValue> children;
};

class BoundedJsonParser {
public:
    explicit BoundedJsonParser(const std::string& input) : input_(input) {}

    bool parse(JsonValue& value) {
        if (input_.empty() || input_.size() > kMaximumLength) return false;
        skip_whitespace();
        if (!parse_value(value, 0)) return false;
        skip_whitespace();
        return position_ == input_.size();
    }

private:
    static constexpr size_t kMaximumLength = 16384;
    static constexpr size_t kMaximumDepth = 32;
    static constexpr size_t kMaximumNodes = 4096;

    bool consume(char expected) {
        if (position_ == input_.size() || input_[position_] != expected) return false;
        ++position_;
        return true;
    }

    void skip_whitespace() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\n' || input_[position_] == '\r'))
            ++position_;
    }

    static bool hex_digit(char value) {
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
               (value >= 'A' && value <= 'F');
    }

    static unsigned hex_value(char value) {
        if (value >= '0' && value <= '9') return static_cast<unsigned>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<unsigned>(value - 'a' + 10);
        return static_cast<unsigned>(value - 'A' + 10);
    }

    bool unicode_escape(unsigned& code_unit) {
        if (position_ + 4 > input_.size()) return false;
        code_unit = 0;
        for (size_t count = 0; count < 4; ++count) {
            const char digit = input_[position_++];
            if (!hex_digit(digit)) return false;
            code_unit = code_unit * 16 + hex_value(digit);
        }
        return true;
    }

    bool raw_utf8() {
        const unsigned char first = static_cast<unsigned char>(input_[position_]);
        size_t continuation_count = 0;
        unsigned code_point = 0;
        unsigned minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            continuation_count = 1;
            code_point = first & 0x1f;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            continuation_count = 2;
            code_point = first & 0x0f;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            continuation_count = 3;
            code_point = first & 0x07;
            minimum = 0x10000;
        } else {
            return false;
        }
        if (position_ + continuation_count >= input_.size()) return false;
        ++position_;
        for (size_t count = 0; count < continuation_count; ++count) {
            const unsigned char next = static_cast<unsigned char>(input_[position_++]);
            if ((next & 0xc0) != 0x80) return false;
            code_point = (code_point << 6) | (next & 0x3f);
        }
        return code_point >= minimum && code_point <= 0x10ffff &&
               !(code_point >= 0xd800 && code_point <= 0xdfff);
    }

    bool parse_string() {
        if (!consume('"')) return false;
        while (position_ < input_.size()) {
            const unsigned char character = static_cast<unsigned char>(input_[position_++]);
            if (character == '"') return true;
            if (character < 0x20) return false;
            if (character == '\\') {
                if (position_ == input_.size()) return false;
                const char escape = input_[position_++];
                if (escape == '"' || escape == '\\' || escape == '/' || escape == 'b' ||
                    escape == 'f' || escape == 'n' || escape == 'r' || escape == 't')
                    continue;
                if (escape != 'u') return false;
                unsigned code_unit = 0;
                if (!unicode_escape(code_unit)) return false;
                if (code_unit >= 0xd800 && code_unit <= 0xdbff) {
                    if (position_ + 2 > input_.size() || input_[position_] != '\\' ||
                        input_[position_ + 1] != 'u')
                        return false;
                    position_ += 2;
                    unsigned low_surrogate = 0;
                    if (!unicode_escape(low_surrogate) || low_surrogate < 0xdc00 ||
                        low_surrogate > 0xdfff)
                        return false;
                } else if (code_unit >= 0xdc00 && code_unit <= 0xdfff) {
                    return false;
                }
                continue;
            }
            if (character >= 0x80) {
                --position_;
                if (!raw_utf8()) return false;
            }
        }
        return false;
    }

    bool literal(const char* expected) {
        const size_t length = std::strlen(expected);
        if (input_.compare(position_, length, expected) != 0) return false;
        position_ += length;
        return true;
    }

    bool number() {
        const size_t start = position_;
        if (position_ < input_.size() && input_[position_] == '-') ++position_;
        if (position_ == input_.size()) return false;
        if (input_[position_] == '0') {
            ++position_;
            if (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
                return false;
        } else {
            if (input_[position_] < '1' || input_[position_] > '9') return false;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9')
                ++position_;
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            const size_t fraction = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9')
                ++position_;
            if (fraction == position_) return false;
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-'))
                ++position_;
            const size_t exponent = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9')
                ++position_;
            if (exponent == position_) return false;
        }
        return position_ != start;
    }

    bool parse_array(JsonValue& value, size_t depth) {
        value.type = JsonType::Array;
        if (!consume('[')) return false;
        skip_whitespace();
        if (consume(']')) return true;
        for (;;) {
            JsonValue element;
            if (!parse_value(element, depth + 1)) return false;
            value.children.push_back(std::move(element));
            skip_whitespace();
            if (consume(']')) return true;
            if (!consume(',')) return false;
            skip_whitespace();
        }
    }

    bool parse_object(JsonValue& value, size_t depth) {
        value.type = JsonType::Object;
        if (!consume('{')) return false;
        skip_whitespace();
        if (consume('}')) return true;
        for (;;) {
            if (!parse_string()) return false;
            skip_whitespace();
            if (!consume(':')) return false;
            skip_whitespace();
            JsonValue member;
            if (!parse_value(member, depth + 1)) return false;
            value.children.push_back(std::move(member));
            skip_whitespace();
            if (consume('}')) return true;
            if (!consume(',')) return false;
            skip_whitespace();
        }
    }

    bool parse_value(JsonValue& value, size_t depth) {
        if (depth > kMaximumDepth || ++nodes_ > kMaximumNodes || position_ == input_.size())
            return false;
        const char first = input_[position_];
        if (first == '[') return parse_array(value, depth);
        if (first == '{') return parse_object(value, depth);
        if (first == '"') {
            value.type = JsonType::String;
            return parse_string();
        }
        if (first == 'n') {
            value.type = JsonType::Null;
            return literal("null");
        }
        if (first == 't') {
            value.type = JsonType::Boolean;
            return literal("true");
        }
        if (first == 'f') {
            value.type = JsonType::Boolean;
            return literal("false");
        }
        if (first == '-' || (first >= '0' && first <= '9')) {
            value.type = JsonType::Number;
            return number();
        }
        return false;
    }

    const std::string& input_;
    size_t position_ = 0;
    size_t nodes_ = 0;
};

static bool parse_json(const std::string& text, JsonValue& value) {
    return BoundedJsonParser(text).parse(value);
}

static bool string_array(const JsonValue& value, bool allow_null) {
    if (allow_null && value.type == JsonType::Null) return true;
    if (value.type != JsonType::Array) return false;
    return std::all_of(value.children.begin(), value.children.end(), [](const JsonValue& child) {
        return child.type == JsonType::String;
    });
}

static bool port_map(const JsonValue& value) {
    if (value.type == JsonType::Null) return true;
    if (value.type != JsonType::Object) return false;
    for (const JsonValue& binding : value.children) {
        if (binding.type == JsonType::Null) continue;
        if (binding.type != JsonType::Array) return false;
        for (const JsonValue& endpoint : binding.children) {
            if (endpoint.type != JsonType::Object ||
                !std::all_of(endpoint.children.begin(),
                             endpoint.children.end(),
                             [](const JsonValue& field) { return field.type == JsonType::String; }))
                return false;
        }
    }
    return true;
}

static bool no_published_ports(const JsonValue& port_bindings, const JsonValue& network_ports) {
    if (!port_map(port_bindings) || !port_map(network_ports)) return false;
    if (port_bindings.type == JsonType::Object && !port_bindings.children.empty()) return false;
    if (network_ports.type == JsonType::Null) return true;
    // Docker represents an image-declared but unpublished container port as a
    // null object member.  Any array, even an empty one, is not accepted as
    // affirmative proof that no host publication exists.
    return std::all_of(network_ports.children.begin(),
                       network_ports.children.end(),
                       [](const JsonValue& binding) { return binding.type == JsonType::Null; });
}

static bool no_published_ports(const std::string& port_bindings, const std::string& network_ports) {
    JsonValue parsed_bindings;
    JsonValue parsed_ports;
    return parse_json(port_bindings, parsed_bindings) && parse_json(network_ports, parsed_ports) &&
           no_published_ports(parsed_bindings, parsed_ports);
}

static bool lowercase_hex(const std::string& text, size_t expected_length) {
    if (text.size() != expected_length) return false;
    for (const char character : text)
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            return false;
    return true;
}

static bool full_container_id(const std::string& id) {
    return lowercase_hex(id, 64);
}

static bool sha256_identity(const std::string& identity) {
    return identity.size() == 71 && identity.compare(0, 7, "sha256:") == 0 &&
           lowercase_hex(identity.substr(7), 64);
}

static bool parse_exact_bool(const std::string& text, bool& value) {
    if (text == "true") {
        value = true;
        return true;
    }
    if (text == "false") {
        value = false;
        return true;
    }
    return false;
}

static bool parse_exact_pid(const std::string& text, pid_t& value) {
    if (text.empty() || !std::all_of(text.begin(), text.end(), [](char character) {
            return character >= '0' && character <= '9';
        }))
        return false;
    char* end = nullptr;
    errno = 0;
    const long parsed = strtol(text.c_str(), &end, 10);
    if (errno == ERANGE || end == text.c_str() || *end != '\0' || parsed < 0 ||
        static_cast<std::uintmax_t>(parsed) >
            static_cast<std::uintmax_t>(std::numeric_limits<pid_t>::max()))
        return false;
    value = static_cast<pid_t>(parsed);
    return static_cast<long>(value) == parsed;
}

static bool parse_sidecar_inspect_record(const std::string& record,
                                         HeldNamespaceSidecarSnapshot& snapshot,
                                         std::string& error) {
    std::vector<std::string> fields;
    if (!split_exact(trim(record), '|', 17, fields)) {
        error = "sidecar inspection record was malformed: expected exactly 17 fields";
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed_pid = strtol(fields[9].c_str(), &end, 10);
    const bool decimal_pid =
        !fields[9].empty() && std::all_of(fields[9].begin(), fields[9].end(), [](char character) {
            return character >= '0' && character <= '9';
        });
    if (!decimal_pid || errno == ERANGE || end == fields[9].c_str() || *end != '\0' ||
        parsed_pid < 0 ||
        static_cast<std::uintmax_t>(parsed_pid) >
            static_cast<std::uintmax_t>(std::numeric_limits<pid_t>::max())) {
        error = "sidecar inspection PID was malformed";
        return false;
    }
    const pid_t pid = static_cast<pid_t>(parsed_pid);
    if (static_cast<long>(pid) != parsed_pid) {
        error = "sidecar inspection PID was malformed";
        return false;
    }
    bool running = false;
    bool read_only = false;
    if (!parse_exact_bool(fields[8], running) || !parse_exact_bool(fields[12], read_only)) {
        error = "sidecar inspection boolean was malformed";
        return false;
    }
    std::array<JsonValue, 5> json_fields;
    const std::array<size_t, 5> json_indices{11, 13, 14, 15, 16};
    for (size_t offset = 0; offset < json_indices.size(); ++offset) {
        const size_t index = json_indices[offset];
        if (!parse_json(fields[index], json_fields[offset])) {
            error = "sidecar inspection JSON was malformed at field " + std::to_string(index);
            return false;
        }
    }
    if (!string_array(json_fields[0], false) || !port_map(json_fields[1]) ||
        !port_map(json_fields[2]) || !string_array(json_fields[3], true) ||
        !string_array(json_fields[4], true)) {
        error = "sidecar inspection JSON had an invalid Docker field type";
        return false;
    }
    snapshot = {};
    snapshot.id = fields[0];
    snapshot.name = fields[1].size() > 1 && fields[1][0] == '/' ? fields[1].substr(1) : fields[1];
    snapshot.pinned_image_reference = fields[2];
    snapshot.image_id = fields[3];
    snapshot.stage = fields[4];
    snapshot.token = fields[5];
    snapshot.role = fields[6];
    snapshot.network_mode = fields[7];
    snapshot.running = running;
    snapshot.pid = pid;
    snapshot.path = fields[10];
    snapshot.arguments_json = fields[11];
    snapshot.read_only_root = read_only;
    snapshot.no_published_ports = no_published_ports(json_fields[1], json_fields[2]);
    snapshot.capability_drop_all = fields[15] == "[\"ALL\"]";
    snapshot.no_new_privileges = fields[16] == "[\"no-new-privileges\"]";
    return true;
}

static bool sidecar_snapshot_equal(const HeldNamespaceSidecarSnapshot& left,
                                   const HeldNamespaceSidecarSnapshot& right) {
    return left.token == right.token && left.stage == right.stage && left.role == right.role &&
           left.name == right.name && left.id == right.id &&
           left.pinned_image_reference == right.pinned_image_reference &&
           left.expected_image_id == right.expected_image_id && left.image_id == right.image_id &&
           left.network_mode == right.network_mode && left.path == right.path &&
           left.arguments_json == right.arguments_json && left.pid == right.pid &&
           left.start == right.start && left.netns == right.netns &&
           left.host_netns == right.host_netns && left.running == right.running &&
           left.read_only_root == right.read_only_root &&
           left.capability_drop_all == right.capability_drop_all &&
           left.no_new_privileges == right.no_new_privileges &&
           left.no_published_ports == right.no_published_ports;
}

static bool sidecar_stopped_identity_equal(const HeldNamespaceSidecarSnapshot& stopped,
                                           const HeldNamespaceSidecarSnapshot& recorded) {
    return stopped.token == recorded.token && stopped.stage == recorded.stage &&
           stopped.role == recorded.role && stopped.name == recorded.name &&
           stopped.id == recorded.id &&
           stopped.pinned_image_reference == recorded.pinned_image_reference &&
           stopped.expected_image_id == recorded.expected_image_id &&
           stopped.image_id == recorded.image_id && stopped.network_mode == recorded.network_mode &&
           stopped.path == recorded.path && stopped.arguments_json == recorded.arguments_json &&
           !stopped.running && stopped.pid == 0 &&
           stopped.read_only_root == recorded.read_only_root &&
           stopped.capability_drop_all == recorded.capability_drop_all &&
           stopped.no_new_privileges == recorded.no_new_privileges &&
           stopped.no_published_ports == recorded.no_published_ports;
}

static std::string proc_hex(u32 value) {
    std::ostringstream text;
    text << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << ntohl(value);
    return text.str();
}

struct ProcIdentity {
    u64 start = 0;
    ino_t netns = 0;
};

static bool proc_identity(pid_t pid, ProcIdentity& identity, bool require_netns = true) {
    std::string stat_contents;
    if (!read_file("/proc/" + std::to_string(pid) + "/stat", stat_contents)) return false;
    const size_t end = stat_contents.rfind(") ");
    if (end == std::string::npos) return false;
    std::istringstream fields(stat_contents.substr(end + 2));
    char state = 0;
    long ignored = 0;
    if (!(fields >> state >> ignored >> ignored)) return false;
    for (int field = 6; field <= 22; field++) {
        std::string value;
        if (!(fields >> value)) return false;
        if (field == 22) {
            char* end = nullptr;
            identity.start = strtoull(value.c_str(), &end, 10);
            if (end == value.c_str() || *end != '\0') return false;
        }
    }
    struct stat status{};
    if (stat(("/proc/" + std::to_string(pid) + "/ns/net").c_str(), &status) != 0) {
        if (require_netns) return false;
        identity.netns = 0;
        return true;
    }
    identity.netns = status.st_ino;
    return identity.start != 0 && identity.netns != 0;
}

static bool parse_ipv4(const std::string& text, u32& value) {
    in_addr address{};
    if (inet_pton(AF_INET, text.c_str(), &address) != 1) return false;
    value = ntohl(address.s_addr);
    return true;
}

static bool format_ipv4(u32 value, std::string& text) {
    const in_addr address{htonl(value)};
    char printed[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &address, printed, sizeof(printed)) == nullptr) return false;
    text = printed;
    return true;
}

static bool parse_cidr_range(const std::string& text,
                             bool require_network_address,
                             IPv4Range& range) {
    const size_t slash = text.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 == text.size() ||
        text.find('/', slash + 1) != std::string::npos)
        return false;
    const std::string address_text = text.substr(0, slash);
    const std::string prefix_text = text.substr(slash + 1);
    if (prefix_text.size() > 1 && prefix_text[0] == '0') return false;
    for (const char character : prefix_text)
        if (character < '0' || character > '9') return false;
    char* end = nullptr;
    const unsigned long prefix = strtoul(prefix_text.c_str(), &end, 10);
    if (end == prefix_text.c_str() || *end != '\0' || prefix > 32) return false;
    u32 address = 0;
    std::string canonical_address;
    if (!parse_ipv4(address_text, address) || !format_ipv4(address, canonical_address) ||
        canonical_address != address_text)
        return false;
    const u32 mask = prefix == 0 ? 0u : 0xffffffffu << (32u - static_cast<u32>(prefix));
    range.low = address & mask;
    range.high = range.low | ~mask;
    range.prefix = static_cast<unsigned>(prefix);
    return !require_network_address || address == range.low;
}

static bool parse_cidr(const std::string& text, u32& low, u32& high) {
    IPv4Range range;
    if (!parse_cidr_range(text, true, range) || range.prefix == 0 || range.prefix > 30)
        return false;
    low = range.low;
    high = range.high;
    return true;
}

static bool ranges_overlap(const IPv4Range& left, const IPv4Range& right) {
    return left.low <= right.high && right.low <= left.high;
}

static bool private_rfc1918(const IPv4Range& range) {
    return (range.low >= 0x0a000000u && range.high <= 0x0affffffu) ||
           (range.low >= 0xac100000u && range.high <= 0xac1fffffu) ||
           (range.low >= 0xc0a80000u && range.high <= 0xc0a8ffffu);
}

static bool valid_network_plan(const NetworkPlan& plan, IPv4Range* parsed = nullptr) {
    IPv4Range subnet;
    u32 gateway = 0;
    std::string canonical_gateway;
    if (!parse_cidr_range(plan.subnet, true, subnet) || subnet.prefix != 28 ||
        !private_rfc1918(subnet) || !parse_ipv4(plan.gateway, gateway) ||
        !format_ipv4(gateway, canonical_gateway) || canonical_gateway != plan.gateway ||
        gateway != subnet.low + 1 || gateway >= subnet.high)
        return false;
    if (parsed != nullptr) *parsed = subnet;
    return true;
}

static bool valid_subnet_plan(const SubnetPlan& plan) {
    IPv4Range network_a;
    IPv4Range network_b;
    return valid_network_plan(plan.network_a, &network_a) &&
           valid_network_plan(plan.network_b, &network_b) && !ranges_overlap(network_a, network_b);
}

static bool network_plan_equal(const NetworkPlan& left, const NetworkPlan& right) {
    return left.subnet == right.subnet && left.gateway == right.gateway;
}

static bool subnet_plan_equal(const SubnetPlan& left, const SubnetPlan& right) {
    return network_plan_equal(left.network_a, right.network_a) &&
           network_plan_equal(left.network_b, right.network_b);
}

static const std::vector<SubnetPlan>& subnet_candidates() {
    static const std::vector<SubnetPlan> candidates = {
        SubnetPlan{NetworkPlan{"10.253.240.0/28", "10.253.240.1"},
                   NetworkPlan{"10.253.241.0/28", "10.253.241.1"}},
        SubnetPlan{NetworkPlan{"10.254.240.0/28", "10.254.240.1"},
                   NetworkPlan{"10.254.241.0/28", "10.254.241.1"}},
        SubnetPlan{NetworkPlan{"172.30.240.0/28", "172.30.240.1"},
                   NetworkPlan{"172.30.241.0/28", "172.30.241.1"}},
        SubnetPlan{NetworkPlan{"172.31.240.0/28", "172.31.240.1"},
                   NetworkPlan{"172.31.241.0/28", "172.31.241.1"}},
        SubnetPlan{NetworkPlan{"192.168.250.0/28", "192.168.250.1"},
                   NetworkPlan{"192.168.251.0/28", "192.168.251.1"}},
    };
    return candidates;
}

static bool select_subnet_plan(const std::vector<IPv4Range>& conflicts,
                               const std::vector<SubnetPlan>& candidates,
                               SubnetPlan& selected) {
    for (const SubnetPlan& candidate : candidates) {
        IPv4Range network_a;
        IPv4Range network_b;
        if (!valid_network_plan(candidate.network_a, &network_a) ||
            !valid_network_plan(candidate.network_b, &network_b) ||
            ranges_overlap(network_a, network_b))
            continue;
        bool collision = false;
        for (const IPv4Range& conflict : conflicts) {
            if (conflict.prefix == 0 && conflict.low == 0 && conflict.high == 0xffffffffu) continue;
            if (ranges_overlap(network_a, conflict) || ranges_overlap(network_b, conflict)) {
                collision = true;
                break;
            }
        }
        if (!collision) {
            selected = candidate;
            return true;
        }
    }
    return false;
}

static std::vector<std::string> network_create_argv(const NetworkPlan& plan,
                                                    const std::string& token,
                                                    const std::string& name) {
    return {"docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--subnet",
            plan.subnet,
            "--gateway",
            plan.gateway,
            "--label",
            kStageLabel,
            "--label",
            "rut.token=" + token,
            name};
}

static bool exact_network_create_argv(const std::vector<std::string>& argv,
                                      const NetworkPlan& plan,
                                      const std::string& token,
                                      const std::string& name) {
    const auto count = [&](const char* flag) {
        return static_cast<size_t>(std::count(argv.begin(), argv.end(), flag));
    };
    return count("--subnet") == 1 && count("--gateway") == 1 &&
           argv == network_create_argv(plan, token, name);
}

static bool route_type(const std::string& token) {
    return token == "unicast" || token == "local" || token == "broadcast" || token == "multicast" ||
           token == "throw" || token == "unreachable" || token == "prohibit" ||
           token == "blackhole" || token == "nat" || token == "anycast";
}

static bool parse_host_routes(const std::string& output,
                              std::vector<IPv4Range>& ranges,
                              std::string& error) {
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string token;
        std::vector<std::string> tokens;
        while (fields >> token) tokens.push_back(token);
        if (tokens.empty()) continue;
        size_t destination_index = route_type(tokens[0]) ? 1 : 0;
        if (destination_index >= tokens.size()) {
            error = "host route lacked a concrete IPv4 destination: " + line;
            return false;
        }
        std::string destination = tokens[destination_index];
        if (destination == "default") destination = "0.0.0.0/0";
        if (destination.find('/') == std::string::npos) destination += "/32";
        IPv4Range range;
        if (!parse_cidr_range(destination, true, range)) {
            error = "host route exposed malformed/noncanonical IPv4 destination: " + line;
            return false;
        }
        ranges.push_back(range);
    }
    return true;
}

static bool parse_interface_cidrs(const std::string& output,
                                  std::vector<IPv4Range>& ranges,
                                  std::string& error) {
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string token;
        bool found = false;
        while (fields >> token) {
            if (token != "inet") continue;
            std::string cidr;
            IPv4Range range;
            if (found || !(fields >> cidr)) {
                error = "host interface exposed malformed/noncanonical IPv4 CIDR: " + line;
                return false;
            }
            if (cidr.find('/') == std::string::npos) cidr += "/32";
            if (!parse_cidr_range(cidr, false, range)) {
                error = "host interface exposed malformed/noncanonical IPv4 CIDR: " + line;
                return false;
            }
            ranges.push_back(range);
            found = true;
        }
        if (!line.empty() && !found) {
            error = "host IPv4 interface record lacked an inet CIDR: " + line;
            return false;
        }
        fields.clear();
        fields.str(line);
        while (fields >> token) {
            if (token != "peer") continue;
            std::string peer;
            IPv4Range range;
            if (!(fields >> peer)) {
                error = "host interface exposed malformed/noncanonical IPv4 peer CIDR: " + line;
                return false;
            }
            if (peer.find('/') == std::string::npos) peer += "/32";
            if (!parse_cidr_range(peer, false, range)) {
                error = "host interface exposed malformed/noncanonical IPv4 peer CIDR: " + line;
                return false;
            }
            ranges.push_back(range);
        }
    }
    return true;
}

static bool collect_ipv4_conflicts(const std::string& ip_path,
                                   std::vector<IPv4Range>& conflicts,
                                   std::string& error) {
    static constexpr size_t kInventoryOutputLimit = 4u * 1024u * 1024u;
    CommandResult result;
    if (!run_command({ip_path, "-4", "-o", "route", "show", "table", "all"},
                     result,
                     15000,
                     false,
                     false,
                     nullptr,
                     kInventoryOutputLimit) ||
        !exited_zero(result) || !parse_host_routes(result.output, conflicts, error)) {
        if (error.empty())
            error = "concrete host IPv4 route collection failed: " + trim(result.output);
        return false;
    }
    if (!run_command({ip_path, "-4", "-o", "address", "show"},
                     result,
                     15000,
                     false,
                     false,
                     nullptr,
                     kInventoryOutputLimit) ||
        !exited_zero(result) || !parse_interface_cidrs(result.output, conflicts, error)) {
        if (error.empty())
            error = "host IPv4 interface CIDR collection failed: " + trim(result.output);
        return false;
    }

    if (!run_command({"docker", "network", "ls", "-q"},
                     result,
                     15000,
                     false,
                     false,
                     nullptr,
                     kInventoryOutputLimit) ||
        !exited_zero(result)) {
        error = "Docker network enumeration failed: " + trim(result.output);
        return false;
    }
    std::istringstream ids(result.output);
    std::string id;
    while (ids >> id) {
        CommandResult inspect;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{range .IPAM.Config}}{{println .Subnet}}{{end}}",
                          id},
                         inspect,
                         15000,
                         false,
                         false,
                         nullptr,
                         kInventoryOutputLimit) ||
            !exited_zero(inspect)) {
            error = "Docker network IPv4 subnet inspection failed for " + id + ": " +
                    trim(inspect.output);
            return false;
        }
        std::istringstream subnet_lines(inspect.output);
        std::string subnet;
        while (std::getline(subnet_lines, subnet)) {
            subnet = trim(subnet);
            if (subnet.empty() || subnet.find(':') != std::string::npos) continue;
            IPv4Range range;
            if (!parse_cidr_range(subnet, true, range)) {
                error = "Docker network exposed malformed/noncanonical IPv4 subnet: " + id + " " +
                        subnet;
                return false;
            }
            conflicts.push_back(range);
        }
    }
    return true;
}

static bool valid_gateway(const std::string& subnet, const std::string& gateway) {
    u32 low = 0, high = 0, value = 0;
    if (!parse_cidr(subnet, low, high) || !parse_ipv4(gateway, value)) return false;
    const u32 first_octet = value >> 24;
    return value > low && value < high && first_octet != 0 && first_octet != 127;
}

static bool choose_address(const std::string& subnet,
                           const std::string& gateway,
                           std::string& address) {
    u32 low = 0, high = 0, gateway_value = 0;
    if (!parse_cidr(subnet, low, high) || !valid_gateway(subnet, gateway) ||
        !parse_ipv4(gateway, gateway_value))
        return false;
    for (u32 candidate = low + 1; candidate < high; candidate++) {
        if (candidate == gateway_value || ((candidate >> 24) & 0xffu) == 127u ||
            ((candidate >> 24) & 0xffu) == 0u || candidate == low || candidate == high)
            continue;
        in_addr value{htonl(candidate)};
        char printed[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &value, printed, sizeof(printed)) != nullptr) {
            address = printed;
            return true;
        }
    }
    return false;
}

static bool container_netns_inode(const std::string& holder, ino_t& inode) {
    CommandResult result;
    if (!run_command({"docker", "exec", holder, "readlink", "/proc/1/ns/net"}, result) ||
        !exited_zero(result))
        return false;
    const std::string text = trim(result.output);
    const size_t left = text.find('[');
    const size_t right = text.find(']', left == std::string::npos ? left : left + 1);
    if (left == std::string::npos || right == std::string::npos || right <= left + 1) return false;
    char* end = nullptr;
    const std::string value_text = text.substr(left + 1, right - left - 1);
    const unsigned long long value = strtoull(value_text.c_str(), &end, 10);
    if (end == value_text.c_str() || *end != '\0' || value == 0) return false;
    inode = static_cast<ino_t>(value);
    return true;
}

enum class CleanupProgress : std::uint8_t {
    Active,
    SidecarSettled,
    HolderSettled,
    TopologySettled,
};

struct CleanupPhaseResult {
    bool settled = false;
    bool operation_ok = false;
    bool holder_settled = false;
    bool holder_removed = false;
    bool network_b_settled = false;
    bool network_b_removed = false;
    bool network_a_settled = false;
    bool network_a_removed = false;
};

struct CleanupEvidence {
    CleanupProgress progress = CleanupProgress::Active;
    bool sidecar_exists = false;
    bool holder_exists = false;
    bool network_a_exists = false;
    bool network_b_exists = false;
    bool sidecar_operation_ok = true;
    bool holder_operation_ok = true;
    bool topology_operation_ok = true;
    bool cleanup_reported_timeout_observed = false;
    bool sidecar_creation_may_have_mutated = false;
    bool holder_removal_may_have_mutated = false;
    u32 holder_remove_command_count = 0;
    u32 holder_remove_suppression_count = 0;
};

struct HolderCleanupIdentity {
    std::string id;
    std::string name;
    std::string image_reference;
    std::string image_id;
    std::string stage;
    std::string token;
    bool running = false;
    pid_t pid = -1;
    std::string path;
    std::string arguments_json;
    bool read_only_root = false;
    std::string port_bindings_json;
    std::string network_ports_json;
    std::string capability_drop_json;
    std::string security_options_json;
    std::string exposed_ports_json;
    std::string role;
    std::string generation;
};

struct SetupEventEvidence {
    u32 network_a_create_count = 0;
    u32 network_a_verify_count = 0;
    u32 network_b_create_count = 0;
    u32 network_b_verify_count = 0;
    u32 both_ipam_verify_count = 0;
    u32 holder_create_count = 0;
    u32 holder_attach_a_verify_count = 0;
    u32 holder_attach_b_count = 0;
};

struct RecreatedHolderOwner {
    HolderOnlyRecreationState state = HolderOnlyRecreationState::Ready;
    bool create_may_have_mutated = false;
    bool start_may_have_mutated = false;
    bool connect_b_may_have_mutated = false;
    bool removal_may_have_mutated = false;
    bool running_identity_validated = false;
    bool network_a_membership_proven_after_start = false;
    bool operation_ok = true;
    u32 state_visit_mask = 1u << static_cast<unsigned>(HolderOnlyRecreationState::Ready);
    HolderOnlyRecreationFailurePoint failure_point = HolderOnlyRecreationFailurePoint::None;
    std::string id;
    std::string image_id;
    pid_t pid = -1;
    u64 start = 0;
    u32 create_command_count = 0;
    u32 start_command_count = 0;
    u32 connect_b_command_count = 0;
    u32 remove_command_count = 0;
    HolderOnlyRecreationEvidence frozen_evidence;
};

// This owner intentionally never aliases the historical sidecar fields or the
// recreated holder owner.  It owns exactly one fresh sibling generation.
struct RecreatedSidecarOwner {
    RecreatedSidecarState state = RecreatedSidecarState::Ready;
    RecreatedSidecarFailurePoint failure_point = RecreatedSidecarFailurePoint::None;
    bool create_may_have_mutated = false;
    bool removal_may_have_mutated = false;
    bool cleanup_identity_fault = false;
    bool removal_suppression_armed = false;
    bool removal_suppression_consumed = false;
    bool operation_ok = true;
    u32 state_visit_mask = 1u << static_cast<unsigned>(RecreatedSidecarState::Ready);
    HeldTopologySnapshot topology;
    HeldNamespaceSidecarSnapshot snapshot;
    u32 create_command_count = 0;
    u32 remove_command_count = 0;
    u32 remove_suppression_count = 0;
    RecreatedSidecarEvidence frozen_evidence;
};

static bool topology_snapshot_equal(const HeldTopologySnapshot& left,
                                    const HeldTopologySnapshot& right);
static bool sidecar_snapshot_equal(const HeldNamespaceSidecarSnapshot& left,
                                   const HeldNamespaceSidecarSnapshot& right);

enum class GenerationReceiptCompositionState : std::uint8_t {
    Ready = 0,
    OldGenerationValidated,
    OldGenerationAbsent,
    NewGenerationCreated,
    NewGenerationValidated,
    Published,
    Unresolved,
};

struct GenerationReceiptCompositionOwner {
    GenerationReceiptCompositionState state = GenerationReceiptCompositionState::Ready;
    HeldNamespaceGenerationRotationReceipt receipt;
    HeldNamespaceGenerationRotationReceipt frozen_receipt;
    u32 state_visit_mask = 1u << static_cast<unsigned>(GenerationReceiptCompositionState::Ready);
};

static bool generation_receipt_composition_transition(GenerationReceiptCompositionOwner& owner,
                                                      GenerationReceiptCompositionState next) {
    const auto current = owner.state;
    bool allowed = false;
    switch (current) {
        case GenerationReceiptCompositionState::Ready:
            allowed = next == GenerationReceiptCompositionState::OldGenerationValidated;
            break;
        case GenerationReceiptCompositionState::OldGenerationValidated:
            allowed = next == GenerationReceiptCompositionState::OldGenerationAbsent;
            break;
        case GenerationReceiptCompositionState::OldGenerationAbsent:
            allowed = next == GenerationReceiptCompositionState::NewGenerationCreated;
            break;
        case GenerationReceiptCompositionState::NewGenerationCreated:
            allowed = next == GenerationReceiptCompositionState::NewGenerationValidated;
            break;
        case GenerationReceiptCompositionState::NewGenerationValidated:
            allowed = next == GenerationReceiptCompositionState::Published;
            break;
        case GenerationReceiptCompositionState::Published:
        case GenerationReceiptCompositionState::Unresolved:
            break;
    }
    if (!allowed) {
        if (current == GenerationReceiptCompositionState::Published ||
            current == GenerationReceiptCompositionState::Unresolved)
            return false;
        owner.state = GenerationReceiptCompositionState::Unresolved;
        owner.state_visit_mask |=
            1u << static_cast<unsigned>(GenerationReceiptCompositionState::Unresolved);
        return false;
    }
    owner.state = next;
    owner.state_visit_mask |= 1u << static_cast<unsigned>(next);
    return true;
}

static bool generation_receipt_composition_fail(GenerationReceiptCompositionOwner& owner) {
    if (owner.state == GenerationReceiptCompositionState::Published ||
        owner.state == GenerationReceiptCompositionState::Unresolved)
        return false;
    owner.state = GenerationReceiptCompositionState::Unresolved;
    owner.state_visit_mask |=
        1u << static_cast<unsigned>(GenerationReceiptCompositionState::Unresolved);
    return true;
}

static bool complete_rotation_topology_equal(const HeldTopologySnapshot& left,
                                             const HeldTopologySnapshot& right) {
    const auto& left_probe = left.probe_evidence;
    const auto& right_probe = right.probe_evidence;
    return topology_snapshot_equal(left, right) && left_probe.policy == right_probe.policy &&
           left_probe.selected_port_absence_checks == right_probe.selected_port_absence_checks &&
           left_probe.host_parent_af_inet_socket_calls ==
               right_probe.host_parent_af_inet_socket_calls &&
           left_probe.successful_refusal_probes == right_probe.successful_refusal_probes;
}

static bool generation_witness_absence_equal(const HeldNamespaceGenerationWitnessAbsence& left,
                                             const HeldNamespaceGenerationWitnessAbsence& right) {
    return left.container_id == right.container_id && left.pid == right.pid &&
           left.start == right.start && left.container_id_absent == right.container_id_absent &&
           left.process_identity_absent == right.process_identity_absent;
}

static bool generation_absence_equal(const HeldNamespaceOldGenerationAbsence& left,
                                     const HeldNamespaceOldGenerationAbsence& right) {
    return generation_witness_absence_equal(left.holder, right.holder) &&
           generation_witness_absence_equal(left.sidecar, right.sidecar) &&
           left.holder_name == right.holder_name && left.sidecar_name == right.sidecar_name &&
           left.holder_name_absent == right.holder_name_absent &&
           left.sidecar_name_absent == right.sidecar_name_absent && left.phase == right.phase;
}

static bool generation_receipt_equal(const HeldNamespaceGenerationRotationReceipt& left,
                                     const HeldNamespaceGenerationRotationReceipt& right) {
    return complete_rotation_topology_equal(left.old_generation.topology,
                                            right.old_generation.topology) &&
           sidecar_snapshot_equal(left.old_generation.sidecar, right.old_generation.sidecar) &&
           left.old_generation_phase == right.old_generation_phase &&
           generation_absence_equal(left.old_absence, right.old_absence) &&
           complete_rotation_topology_equal(left.new_generation.topology,
                                            right.new_generation.topology) &&
           sidecar_snapshot_equal(left.new_generation.sidecar, right.new_generation.sidecar) &&
           left.new_generation_created_phase == right.new_generation_created_phase &&
           left.new_generation_validated_phase == right.new_generation_validated_phase;
}

static bool generation_receipt_unpublished(const GenerationReceiptCompositionOwner& owner,
                                           bool phase3_recorded) {
    return owner.state == GenerationReceiptCompositionState::Unresolved &&
           owner.receipt.new_generation_created_phase ==
               (phase3_recorded ? HeldNamespaceGenerationRotationPhase::NewGenerationCreated
                                : HeldNamespaceGenerationRotationPhase::None) &&
           owner.receipt.new_generation_validated_phase ==
               HeldNamespaceGenerationRotationPhase::None &&
           owner.frozen_receipt.old_generation_phase ==
               HeldNamespaceGenerationRotationPhase::None &&
           owner.frozen_receipt.new_generation_created_phase ==
               HeldNamespaceGenerationRotationPhase::None &&
           owner.frozen_receipt.new_generation_validated_phase ==
               HeldNamespaceGenerationRotationPhase::None;
}

static bool recreated_sidecar_transition(RecreatedSidecarOwner& owner, RecreatedSidecarState next) {
    const RecreatedSidecarState current = owner.state;
    bool allowed = false;
    switch (current) {
        case RecreatedSidecarState::Ready:
            allowed = next == RecreatedSidecarState::CreateMayHaveMutated;
            break;
        case RecreatedSidecarState::CreateMayHaveMutated:
            allowed = next == RecreatedSidecarState::CreatedExactCleanupOnly ||
                      next == RecreatedSidecarState::Settled ||
                      next == RecreatedSidecarState::Unresolved;
            break;
        case RecreatedSidecarState::CreatedExactCleanupOnly:
            allowed = next == RecreatedSidecarState::Validated ||
                      next == RecreatedSidecarState::RemovalMayHaveMutated ||
                      next == RecreatedSidecarState::Unresolved;
            break;
        case RecreatedSidecarState::Validated:
            allowed = next == RecreatedSidecarState::StoppedExactCleanupOnly ||
                      next == RecreatedSidecarState::RemovalMayHaveMutated ||
                      next == RecreatedSidecarState::Unresolved;
            break;
        case RecreatedSidecarState::StoppedExactCleanupOnly:
            allowed = next == RecreatedSidecarState::RemovalMayHaveMutated ||
                      next == RecreatedSidecarState::Unresolved;
            break;
        case RecreatedSidecarState::RemovalMayHaveMutated:
            allowed = next == RecreatedSidecarState::RemovalMayHaveMutated ||
                      next == RecreatedSidecarState::Settled ||
                      next == RecreatedSidecarState::Unresolved;
            break;
        case RecreatedSidecarState::Settled:
        case RecreatedSidecarState::Unresolved:
            break;
    }
    if (!allowed) {
        if (current == RecreatedSidecarState::Settled ||
            current == RecreatedSidecarState::Unresolved)
            return false;
        owner.state = RecreatedSidecarState::Unresolved;
        owner.state_visit_mask |= 1u << static_cast<unsigned>(RecreatedSidecarState::Unresolved);
        return false;
    }
    owner.state = next;
    owner.state_visit_mask |= 1u << static_cast<unsigned>(next);
    return true;
}

static bool recreated_sidecar_transition_self_checks(std::string& error) {
    RecreatedSidecarOwner normal;
    for (const RecreatedSidecarState state : {RecreatedSidecarState::CreateMayHaveMutated,
                                              RecreatedSidecarState::CreatedExactCleanupOnly,
                                              RecreatedSidecarState::Validated,
                                              RecreatedSidecarState::RemovalMayHaveMutated,
                                              RecreatedSidecarState::Settled}) {
        if (!recreated_sidecar_transition(normal, state)) {
            error = "fresh-sidecar production transition rejected the normal path";
            return false;
        }
    }
    const u32 frozen_mask = normal.state_visit_mask;
    if (recreated_sidecar_transition(normal, RecreatedSidecarState::Validated) ||
        normal.state != RecreatedSidecarState::Settled || normal.state_visit_mask != frozen_mask) {
        error = "fresh-sidecar terminal transition was not frozen";
        return false;
    }
    RecreatedSidecarOwner backward;
    if (!recreated_sidecar_transition(backward, RecreatedSidecarState::CreateMayHaveMutated) ||
        !recreated_sidecar_transition(backward, RecreatedSidecarState::CreatedExactCleanupOnly) ||
        recreated_sidecar_transition(backward, RecreatedSidecarState::Ready) ||
        backward.state != RecreatedSidecarState::Unresolved) {
        error = "fresh-sidecar backward transition did not fail closed";
        return false;
    }
    RecreatedSidecarOwner stopped;
    for (const RecreatedSidecarState state : {RecreatedSidecarState::CreateMayHaveMutated,
                                              RecreatedSidecarState::CreatedExactCleanupOnly,
                                              RecreatedSidecarState::Validated,
                                              RecreatedSidecarState::StoppedExactCleanupOnly,
                                              RecreatedSidecarState::RemovalMayHaveMutated,
                                              RecreatedSidecarState::Settled}) {
        if (!recreated_sidecar_transition(stopped, state)) {
            error = "fresh-sidecar production transition rejected stopped cleanup-only flow";
            return false;
        }
    }
    RecreatedSidecarOwner no_object;
    if (!recreated_sidecar_transition(no_object, RecreatedSidecarState::CreateMayHaveMutated) ||
        !recreated_sidecar_transition(no_object, RecreatedSidecarState::Settled) ||
        no_object.state != RecreatedSidecarState::Settled) {
        error = "fresh-sidecar production transition rejected no-object settlement";
        return false;
    }
    return true;
}

static bool generation_receipt_composition_self_checks(std::string& error) {
    GenerationReceiptCompositionOwner normal;
    const std::array<GenerationReceiptCompositionState, 5> path{
        GenerationReceiptCompositionState::OldGenerationValidated,
        GenerationReceiptCompositionState::OldGenerationAbsent,
        GenerationReceiptCompositionState::NewGenerationCreated,
        GenerationReceiptCompositionState::NewGenerationValidated,
        GenerationReceiptCompositionState::Published};
    for (const auto state : path) {
        if (!generation_receipt_composition_transition(normal, state)) {
            error = "complete-generation receipt production transition rejected the normal path";
            return false;
        }
    }
    normal.frozen_receipt = normal.receipt;
    const u32 frozen_mask = normal.state_visit_mask;
    HeldNamespaceGenerationRotationReceipt probe_mutation = normal.frozen_receipt;
    ++probe_mutation.old_generation.topology.probe_evidence.selected_port_absence_checks;
    if (generation_receipt_composition_transition(
            normal, GenerationReceiptCompositionState::NewGenerationCreated) ||
        normal.state != GenerationReceiptCompositionState::Published ||
        normal.state_visit_mask != frozen_mask ||
        normal.frozen_receipt.old_generation_phase != HeldNamespaceGenerationRotationPhase::None ||
        generation_receipt_equal(normal.frozen_receipt, probe_mutation)) {
        error = "complete-generation receipt terminal transition was not frozen";
        return false;
    }
    GenerationReceiptCompositionOwner backward;
    if (!generation_receipt_composition_transition(
            backward, GenerationReceiptCompositionState::OldGenerationValidated) ||
        generation_receipt_composition_transition(backward,
                                                  GenerationReceiptCompositionState::Ready) ||
        backward.state != GenerationReceiptCompositionState::Unresolved) {
        error = "complete-generation receipt backward transition did not fail closed";
        return false;
    }
    GenerationReceiptCompositionOwner unresolved;
    if (!generation_receipt_composition_transition(
            unresolved, GenerationReceiptCompositionState::OldGenerationValidated) ||
        !generation_receipt_composition_transition(
            unresolved, GenerationReceiptCompositionState::OldGenerationAbsent) ||
        generation_receipt_composition_transition(
            unresolved, GenerationReceiptCompositionState::NewGenerationValidated) ||
        unresolved.state != GenerationReceiptCompositionState::Unresolved ||
        generation_receipt_composition_transition(unresolved,
                                                  GenerationReceiptCompositionState::Published)) {
        error = "complete-generation receipt unresolved state was not terminal";
        return false;
    }
    return true;
}

enum class PureHolderRetirementFault : std::uint8_t {
    None,
    HolderId,
    HolderName,
    HolderPid,
    HolderStart,
    NetworkIdentity,
    NetworkIpam,
    PreRemovalMembership,
    RemovalSuppressedHolderRunning,
    RemovalTimeoutHolderPresent,
    RemovalTimeoutHolderAbsent,
    RemovalRecoveryUncertain,
    RemovalRecoveryHolderStopped,
    HolderIdAbsence,
    HolderNameAbsence,
    ProcessAbsence,
    RetainedNetworkIdentity,
    RetainedNetworkIpam,
    RetainedNetworkMembership,
};

struct PureHolderRetirementState {
    CleanupProgress progress = CleanupProgress::SidecarSettled;
    bool sidecar_exists = false;
    bool sidecar_mutation_uncertain = false;
    bool holder_exists = true;
    bool holder_removal_uncertain = false;
    bool holder_stopped = false;
    bool operation_ok = true;
    u32 observation_count = 0;
    u32 holder_remove_count = 0;
    u32 network_remove_count = 0;
    HeldNamespaceOldGenerationAbsence absence;
    CleanupPhaseResult frozen;
};

static CleanupPhaseResult pure_holder_retirement_transition(PureHolderRetirementState& state,
                                                            PureHolderRetirementFault fault,
                                                            std::string& error) {
    error.clear();
    if (state.progress >= CleanupProgress::HolderSettled) return state.frozen;
    if (state.progress != CleanupProgress::SidecarSettled || state.sidecar_exists ||
        state.sidecar_mutation_uncertain) {
        error = "pure holder retirement rejected unsettled sidecar authority";
        return {false, false};
    }

    if (state.holder_removal_uncertain) {
        ++state.observation_count;
        if (fault == PureHolderRetirementFault::RemovalRecoveryUncertain) {
            error = "pure holder retirement recovery observation was uncertain";
            state.operation_ok = false;
            return {false, false};
        }
        if (fault == PureHolderRetirementFault::RemovalRecoveryHolderStopped)
            state.holder_stopped = true;
        if (state.holder_stopped) {
            error = "pure stopped holder recovery was rejected before another removal";
            state.operation_ok = false;
            return {false, false};
        }
        if (!state.holder_exists) state.holder_removal_uncertain = false;
    }

    ++state.observation_count;
    const bool pre_removal_fault = fault == PureHolderRetirementFault::HolderId ||
                                   fault == PureHolderRetirementFault::HolderName ||
                                   fault == PureHolderRetirementFault::HolderPid ||
                                   fault == PureHolderRetirementFault::HolderStart ||
                                   fault == PureHolderRetirementFault::NetworkIdentity ||
                                   fault == PureHolderRetirementFault::NetworkIpam ||
                                   fault == PureHolderRetirementFault::PreRemovalMembership;
    if (pre_removal_fault) {
        error = "pure holder retirement pre-removal revalidation rejected mutation";
        state.operation_ok = false;
        return {false, false};
    }

    CleanupPhaseResult result;
    if (state.holder_exists) {
        if (fault == PureHolderRetirementFault::RemovalSuppressedHolderRunning) {
            state.holder_removal_uncertain = true;
            state.operation_ok = false;
            error = "pure holder removal was suppressed with exact running holder retained";
            return {false, false};
        }
        ++state.holder_remove_count;
        if (fault == PureHolderRetirementFault::RemovalTimeoutHolderPresent) {
            state.holder_removal_uncertain = true;
            state.operation_ok = false;
            error = "pure holder retirement outcome was uncertain with exact holder retained";
            return {false, false};
        }
        state.holder_exists = false;
        result.holder_removed = fault != PureHolderRetirementFault::RemovalTimeoutHolderAbsent;
        if (fault == PureHolderRetirementFault::RemovalTimeoutHolderAbsent)
            state.operation_ok = false;
    }

    ++state.observation_count;
    if (fault == PureHolderRetirementFault::HolderIdAbsence ||
        fault == PureHolderRetirementFault::HolderNameAbsence ||
        fault == PureHolderRetirementFault::ProcessAbsence) {
        error = "pure holder retirement rejected incomplete old witness absence";
        state.operation_ok = false;
        return {false, false};
    }
    state.absence.holder = {std::string(64, 'c'), 100, 1000, true, true};
    state.absence.holder_name = "rut358-holder-pure";
    state.absence.holder_name_absent = true;

    ++state.observation_count;
    if (fault == PureHolderRetirementFault::RetainedNetworkIdentity ||
        fault == PureHolderRetirementFault::RetainedNetworkIpam ||
        fault == PureHolderRetirementFault::RetainedNetworkMembership) {
        error = "pure holder retirement rejected retained-network mutation";
        state.operation_ok = false;
        return {false, false};
    }
    state.progress = CleanupProgress::HolderSettled;
    result.settled = true;
    result.operation_ok = state.operation_ok;
    result.holder_settled = true;
    state.frozen = result;
    return result;
}

static bool pure_holder_retirement_self_checks(std::string& error) {
    {
        PureHolderRetirementState illegal;
        illegal.progress = CleanupProgress::Active;
        const CleanupPhaseResult result =
            pure_holder_retirement_transition(illegal, PureHolderRetirementFault::None, error);
        if (result.settled || result.operation_ok || illegal.observation_count != 0u ||
            illegal.holder_remove_count != 0u) {
            error = "pure holder retirement accepted a pre-sidecar call";
            return false;
        }
    }
    {
        PureHolderRetirementState uncertain_sidecar;
        uncertain_sidecar.sidecar_mutation_uncertain = true;
        const CleanupPhaseResult result = pure_holder_retirement_transition(
            uncertain_sidecar, PureHolderRetirementFault::None, error);
        if (result.settled || result.operation_ok || uncertain_sidecar.observation_count != 0u ||
            uncertain_sidecar.holder_remove_count != 0u) {
            error = "pure holder retirement accepted uncertain sidecar authority";
            return false;
        }
    }
    for (PureHolderRetirementFault fault : {PureHolderRetirementFault::HolderId,
                                            PureHolderRetirementFault::HolderName,
                                            PureHolderRetirementFault::HolderPid,
                                            PureHolderRetirementFault::HolderStart,
                                            PureHolderRetirementFault::NetworkIdentity,
                                            PureHolderRetirementFault::NetworkIpam,
                                            PureHolderRetirementFault::PreRemovalMembership}) {
        PureHolderRetirementState mutation;
        const CleanupPhaseResult result = pure_holder_retirement_transition(mutation, fault, error);
        if (result.settled || result.operation_ok || mutation.holder_remove_count != 0u ||
            mutation.network_remove_count != 0u) {
            error = "pure holder retirement accepted a pre-removal identity/topology mutation";
            return false;
        }
    }
    for (PureHolderRetirementFault fault : {PureHolderRetirementFault::HolderIdAbsence,
                                            PureHolderRetirementFault::HolderNameAbsence,
                                            PureHolderRetirementFault::ProcessAbsence,
                                            PureHolderRetirementFault::RetainedNetworkIdentity,
                                            PureHolderRetirementFault::RetainedNetworkIpam,
                                            PureHolderRetirementFault::RetainedNetworkMembership}) {
        PureHolderRetirementState mutation;
        const CleanupPhaseResult result = pure_holder_retirement_transition(mutation, fault, error);
        if (result.settled || result.operation_ok || mutation.holder_remove_count != 1u ||
            mutation.network_remove_count != 0u || mutation.holder_exists) {
            error = "pure holder retirement accepted incomplete absence/retained-network proof";
            return false;
        }
    }
    {
        PureHolderRetirementState suppressed;
        CleanupPhaseResult result = pure_holder_retirement_transition(
            suppressed, PureHolderRetirementFault::RemovalSuppressedHolderRunning, error);
        if (result.settled || result.operation_ok || !suppressed.holder_exists ||
            !suppressed.holder_removal_uncertain || suppressed.holder_remove_count != 0u ||
            suppressed.network_remove_count != 0u) {
            error = "pure suppressed holder removal claimed a real command or lost retry authority";
            return false;
        }
        result =
            pure_holder_retirement_transition(suppressed, PureHolderRetirementFault::None, error);
        if (!result.settled || result.operation_ok || suppressed.holder_exists ||
            suppressed.holder_remove_count != 1u || suppressed.network_remove_count != 0u) {
            error = "pure suppressed running holder recovery did not perform one exact retry";
            return false;
        }
    }
    {
        PureHolderRetirementState timeout;
        CleanupPhaseResult result = pure_holder_retirement_transition(
            timeout, PureHolderRetirementFault::RemovalTimeoutHolderPresent, error);
        if (result.settled || result.operation_ok || !timeout.holder_exists ||
            !timeout.holder_removal_uncertain || timeout.holder_remove_count != 1u ||
            timeout.network_remove_count != 0u) {
            error = "pure holder retirement timeout did not retain exact retry authority";
            return false;
        }
        const u32 observations_before = timeout.observation_count;
        result = pure_holder_retirement_transition(
            timeout, PureHolderRetirementFault::RemovalRecoveryUncertain, error);
        if (result.settled || result.operation_ok || !timeout.holder_exists ||
            timeout.holder_remove_count != 1u ||
            timeout.observation_count != observations_before + 1u) {
            error = "pure holder retirement uncertain recovery did not fail closed";
            return false;
        }
        result = pure_holder_retirement_transition(timeout, PureHolderRetirementFault::None, error);
        if (!result.settled || result.operation_ok || timeout.holder_exists ||
            timeout.holder_remove_count != 2u || timeout.network_remove_count != 0u) {
            error = "pure holder retirement bounded exact-ID retry did not settle";
            return false;
        }
    }
    {
        PureHolderRetirementState timeout_absent;
        const CleanupPhaseResult first = pure_holder_retirement_transition(
            timeout_absent, PureHolderRetirementFault::RemovalTimeoutHolderAbsent, error);
        if (!first.settled || first.operation_ok || timeout_absent.holder_exists ||
            timeout_absent.holder_remove_count != 1u || timeout_absent.network_remove_count != 0u ||
            timeout_absent.absence.phase != HeldNamespaceGenerationRotationPhase::None) {
            error = "pure holder timeout recovery did not bind exact absence evidence";
            return false;
        }
        const PureHolderRetirementState frozen = timeout_absent;
        std::string replay_error = "stale";
        const CleanupPhaseResult replay = pure_holder_retirement_transition(
            timeout_absent, PureHolderRetirementFault::HolderId, replay_error);
        if (!replay.settled || replay.operation_ok || !replay_error.empty() ||
            timeout_absent.observation_count != frozen.observation_count ||
            timeout_absent.holder_remove_count != frozen.holder_remove_count ||
            timeout_absent.network_remove_count != 0u) {
            error = "pure holder retirement replay was not frozen/inert";
            return false;
        }
    }
    {
        PureHolderRetirementState stopped;
        CleanupPhaseResult result = pure_holder_retirement_transition(
            stopped, PureHolderRetirementFault::RemovalTimeoutHolderPresent, error);
        if (result.settled || result.operation_ok || !stopped.holder_exists ||
            stopped.holder_stopped || !stopped.holder_removal_uncertain ||
            stopped.holder_remove_count != 1u) {
            error = "pure holder timeout did not preserve exact recovery authority";
            return false;
        }
        result = pure_holder_retirement_transition(
            stopped, PureHolderRetirementFault::RemovalRecoveryHolderStopped, error);
        if (result.settled || result.operation_ok || !stopped.holder_exists ||
            !stopped.holder_stopped || stopped.holder_remove_count != 1u ||
            stopped.network_remove_count != 0u) {
            error = "pure stopped holder recovery reached another removal";
            return false;
        }
        result = pure_holder_retirement_transition(stopped, PureHolderRetirementFault::None, error);
        if (result.settled || result.operation_ok || !stopped.holder_exists ||
            stopped.holder_remove_count != 1u || stopped.network_remove_count != 0u) {
            error = "pure stopped holder recovery was not persistently fail-closed";
            return false;
        }
    }
    {
        PureHolderRetirementState success;
        const CleanupPhaseResult result =
            pure_holder_retirement_transition(success, PureHolderRetirementFault::None, error);
        if (!result.settled || !result.operation_ok || !result.holder_settled ||
            !result.holder_removed || success.progress != CleanupProgress::HolderSettled ||
            success.holder_exists || success.holder_remove_count != 1u ||
            success.network_remove_count != 0u || !success.absence.holder.container_id_absent ||
            !success.absence.holder.process_identity_absent ||
            !success.absence.holder_name_absent) {
            error = "pure holder retirement success lacked monotonic exact evidence";
            return false;
        }
        const u32 observations = success.observation_count;
        const CleanupPhaseResult replay = pure_holder_retirement_transition(
            success, PureHolderRetirementFault::RetainedNetworkMembership, error);
        if (!replay.settled || !replay.operation_ok || !replay.holder_removed || !error.empty() ||
            success.observation_count != observations || success.holder_remove_count != 1u ||
            success.network_remove_count != 0u) {
            error = "pure clean holder retirement replay was not frozen/inert";
            return false;
        }
    }
    return true;
}

enum class TopologySettlementEvent : std::uint8_t {
    Holder,
    NetworkB,
    NetworkA,
};

using TopologySettlementCallback = bool (*)(void*, TopologySettlementEvent, bool, std::string&);

static bool cleanup_evidence_equal(const CleanupEvidence& left, const CleanupEvidence& right) {
    return left.progress == right.progress && left.sidecar_exists == right.sidecar_exists &&
           left.holder_exists == right.holder_exists &&
           left.network_a_exists == right.network_a_exists &&
           left.network_b_exists == right.network_b_exists &&
           left.sidecar_operation_ok == right.sidecar_operation_ok &&
           left.holder_operation_ok == right.holder_operation_ok &&
           left.topology_operation_ok == right.topology_operation_ok &&
           left.cleanup_reported_timeout_observed == right.cleanup_reported_timeout_observed &&
           left.sidecar_creation_may_have_mutated == right.sidecar_creation_may_have_mutated &&
           left.holder_removal_may_have_mutated == right.holder_removal_may_have_mutated &&
           left.holder_remove_command_count == right.holder_remove_command_count &&
           left.holder_remove_suppression_count == right.holder_remove_suppression_count;
}

static bool cleanup_phase_result_equal(const CleanupPhaseResult& left,
                                       const CleanupPhaseResult& right) {
    return left.settled == right.settled && left.operation_ok == right.operation_ok &&
           left.holder_settled == right.holder_settled &&
           left.holder_removed == right.holder_removed &&
           left.network_b_settled == right.network_b_settled &&
           left.network_b_removed == right.network_b_removed &&
           left.network_a_settled == right.network_a_settled &&
           left.network_a_removed == right.network_a_removed;
}

static bool setup_event_evidence_equal(const SetupEventEvidence& left,
                                       const SetupEventEvidence& right) {
    return left.network_a_create_count == right.network_a_create_count &&
           left.network_a_verify_count == right.network_a_verify_count &&
           left.network_b_create_count == right.network_b_create_count &&
           left.network_b_verify_count == right.network_b_verify_count &&
           left.both_ipam_verify_count == right.both_ipam_verify_count &&
           left.holder_create_count == right.holder_create_count &&
           left.holder_attach_a_verify_count == right.holder_attach_a_verify_count &&
           left.holder_attach_b_count == right.holder_attach_b_count;
}

static bool proc_tcp_port_absent(const std::string& table, u16 port) {
    std::ostringstream port_hex;
    port_hex << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << port;
    std::istringstream lines(table);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string index;
        std::string local_endpoint;
        if (!(fields >> index >> local_endpoint)) continue;
        const size_t colon = local_endpoint.rfind(':');
        if (colon != std::string::npos && local_endpoint.substr(colon + 1u) == port_hex.str())
            return false;
    }
    return true;
}

class Fixture {
public:
    explicit Fixture(std::string token) : token_(std::move(token)) {
        network_a_.name = "rut358-a-" + token_;
        network_b_.name = "rut358-b-" + token_;
        holder_name_ = "rut358-holder-" + token_;
        sidecar_name_ = "rut358-sidecar-" + token_;
    }
    ~Fixture() {
        std::string ignored;
        (void)cleanup(ignored);
    }

    const std::string& token() const { return token_; }
    const std::string& holder_name() const { return holder_name_; }
    const std::string& sidecar_name() const { return sidecar_name_; }
    const Network& network_a() const { return network_a_; }
    const Network& network_b() const { return network_b_; }
    const std::string& positive_ip() const { return positive_ip_; }
    const std::string& guard_ip() const { return guard_ip_; }
    pid_t holder_pid() const { return holder_pid_; }
    u64 holder_start() const { return holder_start_; }
    const std::string& holder_id() const { return holder_id_; }
    const HeldNamespaceSidecarSnapshot& sidecar_snapshot() const { return sidecar_snapshot_; }
    const HeldNamespaceOldGenerationAbsence& holder_retirement_absence() const {
        return holder_retirement_absence_;
    }
    void set_expected_sidecar_image_id(std::string image_id) {
        expected_sidecar_image_id_ = std::move(image_id);
    }
    void set_sidecar_revalidation_fault(HeldNamespaceSidecarRevalidationFault fault) {
        sidecar_revalidation_fault_ = fault;
    }
    void clear_uncertain_sidecar_inspection_fault() {
        uncertain_sidecar_inspection_failure_ = false;
    }
    bool arm_holder_removal_suppression_once(std::string& error) {
        if (cleanup_progress_ != CleanupProgress::SidecarSettled || sidecar_exists_ ||
            sidecar_creation_may_have_mutated_ || !holder_exists_ || !topology_verified_ ||
            holder_removal_suppression_armed_ || holder_removal_suppression_consumed_) {
            error = "holder removal suppression lacked exact live settled-sidecar authority";
            return false;
        }
        holder_removal_suppression_armed_ = true;
        return true;
    }
    bool sidecar_exists() const { return sidecar_exists_; }
    bool cleanup_reported_timeout_observed() const { return cleanup_reported_timeout_observed_; }
    CleanupEvidence cleanup_evidence() const {
        return {cleanup_progress_,
                sidecar_exists_,
                holder_exists_,
                network_a_.exists,
                network_b_.exists,
                sidecar_settlement_operation_ok_,
                holder_settlement_operation_ok_,
                topology_settlement_operation_ok_,
                cleanup_reported_timeout_observed_,
                sidecar_creation_may_have_mutated_,
                holder_removal_may_have_mutated_,
                holder_remove_command_count_,
                holder_remove_suppression_count_};
    }
    const SetupEventEvidence& setup_event_evidence() const { return setup_event_evidence_; }
    HeldTopologySnapshot current_topology_snapshot() const { return topology_snapshot(); }
    bool recreate_holder_only(HolderOnlyRecreationFailurePoint failure_point, std::string& error);
    bool cleanup_recreated_holder(std::string& error);
    HolderOnlyRecreationEvidence holder_only_recreation_evidence() const;
    void transition_recreated_holder(HolderOnlyRecreationState state);
    bool recreate_sidecar(RecreatedSidecarFailurePoint failure_point, std::string& error);
    bool cleanup_recreated_sidecar(std::string& error);
    bool revalidate_recreated_sidecar_for_rotation(HeldNamespaceSidecarSnapshot& snapshot,
                                                   bool inject_mutation,
                                                   std::string& error);
    bool terminate_recreated_sidecar_unexpectedly(std::string& error);
    void clear_recreated_sidecar_cleanup_fault() {
        recreated_sidecar_.cleanup_identity_fault = false;
    }
    RecreatedSidecarEvidence recreated_sidecar_evidence() const;
    void transition_recreated_sidecar(RecreatedSidecarState state);
    bool build_current_generation_topology(HeldTopologySnapshot& topology, std::string& error);
    bool build_recreated_holder_topology(HeldTopologySnapshot& topology, std::string& error);

    bool set_subnet_plan(const SubnetPlan& plan) {
        if (!valid_subnet_plan(plan)) return false;
        network_a_.subnet = plan.network_a.subnet;
        network_a_.gateway = plan.network_a.gateway;
        network_b_.subnet = plan.network_b.subnet;
        network_b_.gateway = plan.network_b.gateway;
        return true;
    }

    bool create_networks(FailurePoint point, std::string& error) {
        if (!create_network(network_a_, point, error)) return false;
        if (point == FailurePoint::AfterNetworkACreated) return injected(error);
        if (!verify_network(network_a_, error)) return false;
        ++setup_event_evidence_.network_a_verify_count;
        if (point == FailurePoint::AfterNetworkAVerified) return injected(error);
        if (!create_network(network_b_, point, error)) return false;
        if (point == FailurePoint::AfterNetworkBCreated) return injected(error);
        if (!verify_network(network_b_, error)) return false;
        ++setup_event_evidence_.network_b_verify_count;
        if (point == FailurePoint::AfterNetworkBVerified) return injected(error);
        u32 low_a = 0, high_a = 0, low_b = 0, high_b = 0;
        if (!parse_cidr(network_a_.subnet, low_a, high_a) ||
            !parse_cidr(network_b_.subnet, low_b, high_b) || (low_a <= high_b && low_b <= high_a) ||
            !choose_address(network_a_.subnet, network_a_.gateway, positive_ip_) ||
            !choose_address(network_b_.subnet, network_b_.gateway, guard_ip_) ||
            positive_ip_ == guard_ip_) {
            error = "Docker-managed IPAM was overlapping or did not provide valid addresses";
            return false;
        }
        ++setup_event_evidence_.both_ipam_verify_count;
        if (point == FailurePoint::AfterBothIpamVerified) return injected(error);
        return true;
    }

    bool create_holder(FailurePoint point, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "run",
                          "--pull=never",
                          "--detach",
                          "--name",
                          holder_name_,
                          "--network",
                          network_a_.name,
                          "--ip",
                          positive_ip_,
                          "--cap-drop",
                          "ALL",
                          "--security-opt",
                          "no-new-privileges",
                          "--read-only",
                          "--tmpfs",
                          "/tmp:rw,noexec,nosuid,size=1m",
                          "--entrypoint",
                          "/bin/sleep",
                          "--label",
                          kStageLabel,
                          "--label",
                          "rut.token=" + token_,
                          RUT_PINNED_NGINX_IMAGE,
                          "infinity"},
                         result) ||
            !exited_zero(result)) {
            error = "inert pinned-image holder creation failed: " + trim(result.output);
            discover_holder();
            return false;
        }
        holder_exists_ = true;
        if (!discover_holder()) {
            error = "holder was created but exact ID/PID discovery failed";
            return false;
        }
        ++setup_event_evidence_.holder_create_count;
        if (point == FailurePoint::AfterHolderCreated) return injected(error);
        return true;
    }

    bool attach_holder(FailurePoint point, std::string& error) {
        if (!verify_membership(network_a_, error)) {
            error = "holder attachment to bridge A was not exact: " + error;
            return false;
        }
        ++setup_event_evidence_.holder_attach_a_verify_count;
        if (point == FailurePoint::AfterHolderAttachedA) return injected(error);
        CommandResult result;
        if (!run_command(
                {"docker", "network", "connect", "--ip", guard_ip_, network_b_.name, holder_name_},
                result) ||
            !exited_zero(result)) {
            error = "holder attachment to bridge B failed: " + trim(result.output);
            return false;
        }
        ++setup_event_evidence_.holder_attach_b_count;
        if (point == FailurePoint::AfterHolderAttachedB) return injected(error);
        return true;
    }

    bool verify_holder_endpoint_associations(std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.Name}}|{{.Id}}|{{index .Config.Labels \"rut.stage\"}}|{{index "
                          ".Config.Labels \"rut.token\"}} {{range $name,$v := "
                          ".NetworkSettings.Networks}}{{$name}}|{{$v.NetworkID}}|{{$v.IPAddress}}|{"
                          "{$v.Gateway}} {{end}}",
                          holder_id_},
                         result) ||
            !exited_zero(result)) {
            error = "holder membership inspection failed: " + trim(result.output);
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string metadata;
        std::vector<std::string> metadata_fields;
        if (!(fields >> metadata) || !split_exact(metadata, '|', 4, metadata_fields) ||
            metadata_fields[0] != "/" + holder_name_ || metadata_fields[1] != holder_id_ ||
            metadata_fields[2] != "358-stage2a2" || metadata_fields[3] != token_) {
            error = "holder name/labels were not exact";
            return false;
        }
        std::vector<Endpoint> actual;
        std::string endpoint_text;
        while (fields >> endpoint_text) {
            std::vector<std::string> endpoint_fields;
            if (!split_exact(endpoint_text, '|', 4, endpoint_fields)) {
                error = "holder endpoint association was malformed";
                return false;
            }
            const Network* network =
                endpoint_fields[0] == network_a_.name
                    ? &network_a_
                    : (endpoint_fields[0] == network_b_.name ? &network_b_ : nullptr);
            if (network == nullptr) {
                error = "holder exposed an unexpected network endpoint";
                return false;
            }
            const size_t slash = network->subnet.find('/');
            if (slash == std::string::npos) {
                error = "verified network subnet was malformed";
                return false;
            }
            actual.push_back({endpoint_fields[0],
                              endpoint_fields[1],
                              endpoint_fields[2],
                              endpoint_fields[2] + network->subnet.substr(slash),
                              endpoint_fields[3]});
        }
        const std::vector<Endpoint> expected = {
            {network_a_.name,
             network_a_.id,
             positive_ip_,
             positive_ip_ + network_a_.subnet.substr(network_a_.subnet.find('/')),
             network_a_.gateway},
            {network_b_.name,
             network_b_.id,
             guard_ip_,
             guard_ip_ + network_b_.subnet.substr(network_b_.subnet.find('/')),
             network_b_.gateway}};
        if (!endpoint_set_equal(expected, actual)) {
            error = "holder endpoint associations were not exact";
            return false;
        }
        std::vector<Endpoint> swapped = actual;
        if (swapped.size() == 2) {
            std::swap(swapped[0].network_id, swapped[1].network_id);
            if (endpoint_set_equal(expected, swapped)) {
                error = "endpoint cross-swap mutation was accepted";
                return false;
            }
        }
        if (!verify_membership(network_a_, error) || !verify_membership(network_b_, error))
            return false;
        return true;
    }

    bool verify_topology(FailurePoint point, std::string& error) {
        if (!verify_holder_endpoint_associations(error)) return false;
        CommandResult result;
        if (!run_command(
                {"docker",
                 "inspect",
                 "-f",
                 "{{.Path}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.PortBindings}}"
                 " {{.HostConfig.SecurityOpt}} {{json .HostConfig.CapDrop}} "
                 "{{json .Config.ExposedPorts}} {{json .NetworkSettings.Ports}}",
                 holder_name_},
                result) ||
            !exited_zero(result)) {
            error = "holder was not inert/read-only/capability-dropped with no published ports";
            return false;
        }
        std::istringstream security_fields(trim(result.output));
        std::string path, readonly, bindings, security, cap_drop, exposed, network_ports;
        if (!(security_fields >> path >> readonly >> bindings >> security >> cap_drop >> exposed >>
              network_ports) ||
            path != "/bin/sleep" || readonly != "true" ||
            !no_published_ports(bindings, network_ports) || security != "[no-new-privileges]" ||
            cap_drop != "[\"ALL\"]" || exposed == "null") {
            error = "holder security/port publication fields were not exact";
            return false;
        }
        ProcIdentity holder_identity{};
        ProcIdentity host_identity{};
        if (!proc_identity(holder_pid_, holder_identity, false) ||
            !container_netns_inode(holder_name_, holder_identity.netns) ||
            !proc_identity(getpid(), host_identity) ||
            holder_identity.netns == host_identity.netns ||
            holder_identity.start != holder_start_) {
            error = "holder PID/start-time/netns identity was not stable or distinct from host";
            return false;
        }
        std::string tcp;
        if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/tcp", tcp)) {
            error = "holder /proc/net/tcp was unavailable";
            return false;
        }
        std::string routes;
        if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/route", routes)) {
            error = "holder /proc/net/route was unavailable";
            return false;
        }
        u32 low_a = 0, high_a = 0, low_b = 0, high_b = 0;
        if (!parse_cidr(network_a_.subnet, low_a, high_a) ||
            !parse_cidr(network_b_.subnet, low_b, high_b)) {
            error = "holder route validation saw malformed subnet";
            return false;
        }
        const u32 mask_a = ~(high_a ^ low_a);
        const u32 mask_b = ~(high_b ^ low_b);
        bool route_a = false, route_b = false;
        std::istringstream route_lines(routes);
        std::string route_line;
        std::getline(route_lines, route_line);  // header
        while (std::getline(route_lines, route_line)) {
            std::istringstream route_fields(route_line);
            std::string iface, destination, gateway, flags, refs, use, metric, mask;
            if (!(route_fields >> iface >> destination >> gateway >> flags >> refs >> use >>
                  metric >> mask))
                continue;
            route_a = route_a || (destination == proc_hex(low_a) && mask == proc_hex(mask_a));
            route_b = route_b || (destination == proc_hex(low_b) && mask == proc_hex(mask_b));
        }
        if (!route_a || !route_b) {
            error = "holder routes did not contain both exact Docker-managed subnets";
            return false;
        }
        if (tcp.find(":0000") != std::string::npos) {
            // The selected port is checked by probe_port_absent below; this
            // branch only rejects an obviously malformed proc table.
        }
        topology_verified_ = true;
        if (point == FailurePoint::AfterTopologyVerified) return injected(error);
        return true;
    }

    bool probe_port_absent(u16 port, std::string& error) {
        return probe_port_absent_in("tcp", port, error);
    }

    bool probe_tcp6_port_absent(u16 port, std::string& error) {
        return probe_port_absent_in("tcp6", port, error);
    }

private:
    bool probe_port_absent_in(const char* table, u16 port, std::string& error) {
        std::string tcp;
        if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/" + table, tcp)) {
            error = std::string("holder /proc/net/") + table + " read failed";
            return false;
        }
        if (proc_tcp_port_absent(tcp, port)) return true;
        error = std::string("selected probe port appeared in holder /proc/net/") + table;
        return false;
    }

public:
    bool probe_refused(const std::string& address, u16 port, std::string& error) {
        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            error = "probe socket creation failed";
            return false;
        }
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port);
        if (inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) != 1 ||
            connect(fd, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == 0) {
            close(fd);
            error = "probe unexpectedly connected";
            return false;
        }
        int connect_error = errno;
        if (connect_error == EINPROGRESS) {
            pollfd descriptor{fd, POLLOUT, 0};
            const int ready = poll(&descriptor, 1, 2000);
            if (ready <= 0) {
                close(fd);
                error = ready == 0 ? "probe timed out" : "probe poll failed";
                return false;
            }
            socklen_t length = sizeof(connect_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &connect_error, &length) != 0) {
                close(fd);
                error = "probe SO_ERROR failed";
                return false;
            }
        }
        close(fd);
        if (connect_error != ECONNREFUSED) {
            error =
                "probe returned errno " + std::to_string(connect_error) + ", expected ECONNREFUSED";
            return false;
        }
        return true;
    }

    bool create_sidecar(HeldNamespaceSidecarFailurePoint point, std::string& error) {
        return create_sidecar_impl(point, {}, nullptr, error);
    }

    bool create_exact_input_mount_sidecar(const std::string& source,
                                          const fixture_exact_input_file_lease::Identity& identity,
                                          std::vector<std::string>& argv_evidence,
                                          HeldNamespaceSidecarFailurePoint point,
                                          std::string& error) {
        const std::string destination = kExactInputMountDestination;
        const auto forbidden = [](const std::string& value) {
            return value.empty() || value.find_first_of(",|#;\n\r\t ") != std::string::npos;
        };
        char canonical[PATH_MAX]{};
        if (forbidden(source) || forbidden(destination) || source[0] != '/' ||
            destination[0] != '/' || realpath(source.c_str(), canonical) == nullptr ||
            source != canonical || identity.inode == 0u || identity.device == 0u) {
            error = "exact input mount source/destination was not canonical and delimiter-safe";
            return false;
        }
        const std::string user = std::to_string(identity.uid) + ":" + std::to_string(identity.gid);
        const std::string mount = "type=bind,src=" + source + ",dst=" + destination +
                                  ",readonly,bind-propagation=rprivate";
        return create_sidecar_impl(
            point, {"--user", user, "--mount", mount}, &argv_evidence, error);
    }

    bool disconnect_network_b_for_mount_test(std::string& error) {
        if (!sidecar_exists_ || cleanup_progress_ != CleanupProgress::Active ||
            !verify_network(network_b_, error) || !validate_holder(error)) {
            if (error.empty()) error = "test disconnect lacked exact holder/network authority";
            return false;
        }
        CommandResult result;
        if (!run_command({"docker", "network", "disconnect", network_b_.id, holder_id_}, result) ||
            !exited_zero(result)) {
            error = "test disconnect of exact network B failed: " + trim(result.output);
            return false;
        }
        network_b_test_disconnected_ = true;
        return true;
    }

    bool restore_network_b_for_mount_test(std::string& error) {
        if (!network_b_test_disconnected_) return true;
        if (cleanup_progress_ != CleanupProgress::SidecarSettled || sidecar_exists_ ||
            sidecar_creation_may_have_mutated_ || !validate_holder(error) ||
            !verify_network(network_b_, error)) {
            if (error.empty())
                error = "test reconnect lacked exact sidecar absence/holder/network authority";
            return false;
        }
        CommandResult result;
        if (!run_command(
                {"docker", "network", "connect", "--ip", guard_ip_, network_b_.id, holder_id_},
                result) ||
            !exited_zero(result)) {
            error = "test reconnect of exact network B failed: " + trim(result.output);
            return false;
        }
        network_b_test_disconnected_ = false;
        if (!verify_topology(FailurePoint::None, error)) {
            error = "test reconnect did not restore exact topology: " + error;
            return false;
        }
        return true;
    }

private:
    bool create_sidecar_impl(HeldNamespaceSidecarFailurePoint point,
                             const std::vector<std::string>& extra_arguments,
                             std::vector<std::string>* argv_evidence,
                             std::string& error) {
        CommandResult result;
        const bool reported_timeout =
            point == HeldNamespaceSidecarFailurePoint::CreateReportedTimeout ||
            point == HeldNamespaceSidecarFailurePoint::CreateReportedTimeoutRecoveryUnavailable;
        if (point == HeldNamespaceSidecarFailurePoint::CreateReportedTimeoutRecoveryUnavailable)
            uncertain_sidecar_inspection_failure_ = true;
        std::vector<std::string> create_arguments = {"docker",
                                                     "run",
                                                     "--pull=never",
                                                     "--detach",
                                                     "--name",
                                                     sidecar_name_,
                                                     "--network",
                                                     "container:" + holder_id_,
                                                     "--cap-drop",
                                                     "ALL",
                                                     "--security-opt",
                                                     "no-new-privileges",
                                                     "--read-only",
                                                     "--tmpfs",
                                                     "/tmp:rw,noexec,nosuid,size=1m",
                                                     "--entrypoint",
                                                     "/bin/sleep",
                                                     "--label",
                                                     std::string("rut.stage=") + kSidecarStage,
                                                     "--label",
                                                     "rut.token=" + token_,
                                                     "--label",
                                                     std::string("rut.role=") + kSidecarRole,
                                                     RUT_PINNED_NGINX_IMAGE,
                                                     "infinity"};
        create_arguments.insert(
            create_arguments.end() - 2, extra_arguments.begin(), extra_arguments.end());
        if (argv_evidence != nullptr) *argv_evidence = create_arguments;
        // From this boundary onward Docker may have accepted the unique-name
        // create even when command/recovery evidence is incomplete.
        sidecar_creation_may_have_mutated_ = true;
        if (point == HeldNamespaceSidecarFailurePoint::CreateSuppressedNoObject) {
            error = "injected sidecar create suppression with no Docker object";
            return false;
        }
        if (!run_command(create_arguments, result, 15000, reported_timeout) ||
            !exited_zero(result)) {
            if (reported_timeout && result.timed_out && WIFEXITED(result.status) &&
                WEXITSTATUS(result.status) == 0) {
                HeldNamespaceSidecarSnapshot recovered;
                std::string recovery_error;
                if (inspect_uncertain_sidecar(sidecar_name_, recovered, recovery_error)) {
                    sidecar_exists_ = true;
                    sidecar_id_ = recovered.id;
                    sidecar_snapshot_ = recovered;
                    error =
                        "injected sidecar actual-success/reported-timeout; recovered exact "
                        "identity";
                } else {
                    error = "sidecar creation reported timeout and exact recovery failed: " +
                            recovery_error;
                }
            } else {
                error = "held-namespace sidecar creation failed: " + trim(result.output);
                discover_sidecar_after_failed_create();
            }
            return false;
        }
        sidecar_id_ = trim(result.output);
        if (!full_container_id(sidecar_id_)) {
            sidecar_id_.clear();
            error = "sidecar creation did not return one full container ID";
            return false;
        }
        sidecar_exists_ = true;
        if (point == HeldNamespaceSidecarFailurePoint::AfterCreate)
            return injected_sidecar("after create", error);
        HeldNamespaceSidecarSnapshot discovered;
        if (!inspect_sidecar(sidecar_id_, discovered, error)) return false;
        sidecar_snapshot_ = discovered;
        if (point == HeldNamespaceSidecarFailurePoint::AfterDiscovery)
            return injected_sidecar("after discovery", error);
        HeldTopologySnapshot topology = topology_snapshot();
        if (!validate_held_namespace_sidecar_snapshot(topology, sidecar_snapshot_, error))
            return false;
        if (!verify_sidecar_uniqueness(error)) return false;
        if (point == HeldNamespaceSidecarFailurePoint::AfterVerification)
            return injected_sidecar("after verification", error);
        cleanup_reported_timeout_ =
            point == HeldNamespaceSidecarFailurePoint::CleanupReportedTimeout;
        return true;
    }

public:
    bool revalidate_sidecar_identity(std::string& error) {
        HeldNamespaceSidecarSnapshot current;
        if (!inspect_sidecar(sidecar_id_, current, error) ||
            !validate_held_namespace_sidecar_snapshot(topology_snapshot(), current, error) ||
            !sidecar_snapshot_equal(current, sidecar_snapshot_)) {
            if (error.empty()) error = "sidecar immutable identity/security changed";
            return false;
        }
        return true;
    }

    bool terminate_sidecar_unexpectedly(std::string& error) {
        if (!sidecar_exists_ || sidecar_id_.empty()) {
            error = "cannot inject unexpected sidecar death without exact identity";
            return false;
        }
        CommandResult result;
        if (!run_command({"docker", "kill", sidecar_id_}, result) || !exited_zero(result)) {
            error = "unexpected sidecar death injection failed: " + trim(result.output);
            return false;
        }
        HeldNamespaceSidecarSnapshot stopped;
        std::string inspect_error;
        if (!inspect_sidecar(sidecar_id_, stopped, inspect_error) ||
            !sidecar_stopped_identity_equal(stopped, sidecar_snapshot_)) {
            error = "unexpected sidecar death did not yield the exact stopped immutable identity";
            if (!inspect_error.empty()) error += ": " + inspect_error;
            return false;
        }
        ProcIdentity possibly_live{};
        if (proc_identity(sidecar_snapshot_.pid, possibly_live, false) &&
            possibly_live.start == sidecar_snapshot_.start) {
            error = "unexpected sidecar death left the recorded /proc identity live";
            return false;
        }
        unexpected_sidecar_death_verified_ = true;
        error =
            "verified unexpected sidecar death: exact stopped identity and no live /proc witness";
        return true;
    }

    bool disappear_sidecar_before_cleanup(std::string& error) {
        if (!sidecar_exists_ || sidecar_id_.empty()) {
            error = "cannot inject sidecar disappearance without exact identity";
            return false;
        }
        CommandResult result;
        if (!run_command({"docker", "rm", "-f", sidecar_id_}, result) || !exited_zero(result)) {
            error = "sidecar disappearance injection failed: " + trim(result.output);
            return false;
        }
        std::string absent_error;
        if (!prove_sidecar_absent(absent_error)) {
            error = "sidecar disappearance injection lacked exact absence proof: " + absent_error;
            return false;
        }
        return true;
    }

    bool disappear_holder_before_cleanup(std::string& error) {
        if (cleanup_progress_ != CleanupProgress::SidecarSettled || sidecar_exists_ ||
            sidecar_creation_may_have_mutated_ || !holder_exists_ || holder_id_.empty() ||
            !validate_holder(error)) {
            if (error.empty())
                error = "cannot inject holder disappearance without settled sidecar/exact identity";
            return false;
        }
        CommandResult result;
        if (!run_command({"docker", "rm", "-f", holder_id_}, result) || !exited_zero(result)) {
            error = "holder disappearance injection failed: " + trim(result.output);
            return false;
        }
        if (!run_command({"docker", "inspect", holder_id_}, result) || exited_zero(result)) {
            error = "holder disappearance lacked exact ID absence proof";
            return false;
        }
        if (!run_command(
                {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + holder_name_ + "$"},
                result) ||
            !exited_zero(result) || !trim(result.output).empty()) {
            error = "holder disappearance lacked exact name absence proof";
            return false;
        }
        holder_exists_ = false;
        holder_disappearance_operation_failure_ = true;
        return true;
    }

    CleanupPhaseResult cleanup_sidecar_phase(std::string& error) {
        if (cleanup_progress_ >= CleanupProgress::SidecarSettled) return {true, true};

        bool operation_ok = true;
        if (!sidecar_exists_ && sidecar_creation_may_have_mutated_) {
            std::string recovery_error;
            if (!recover_uncertain_sidecar_or_prove_absence(recovery_error)) {
                sidecar_settlement_operation_ok_ = false;
                if (!error.empty()) error += "; ";
                error += recovery_error;
                return {false, false};
            }
        }
        if (sidecar_exists_) {
            std::string sidecar_error;
            if (!cleanup_sidecar(sidecar_error)) {
                operation_ok = false;
                if (!sidecar_error.empty()) {
                    if (!error.empty()) error += "; ";
                    error += sidecar_error;
                }
                // A holder must never be released while a sibling container
                // might still be attached to its network namespace.
                if (sidecar_exists_) {
                    sidecar_settlement_operation_ok_ = false;
                    return {false, false};
                }
            }
        }
        cleanup_progress_ = CleanupProgress::SidecarSettled;
        sidecar_settlement_operation_ok_ = sidecar_settlement_operation_ok_ && operation_ok;
        return {true, operation_ok};
    }

    CleanupPhaseResult cleanup_holder_phase(std::string& error) {
        return cleanup_holder_phase_impl(error, true);
    }

private:
    CleanupPhaseResult cleanup_holder_phase_impl(std::string& error,
                                                 bool require_retained_topology) {
        if (cleanup_progress_ >= CleanupProgress::HolderSettled) return frozen_holder_settlement_;
        if (cleanup_progress_ != CleanupProgress::SidecarSettled || sidecar_exists_ ||
            sidecar_creation_may_have_mutated_) {
            if (!error.empty()) error += "; ";
            error += "refusing holder retirement before exact sidecar settlement";
            return {false, false};
        }
        if (require_retained_topology && !topology_verified_) {
            if (!error.empty()) error += "; ";
            error += "refusing holder-only retirement without verified retained topology";
            return {false, false};
        }

        CleanupPhaseResult result;
        bool operation_ok = !holder_disappearance_operation_failure_;
        if (holder_disappearance_operation_failure_) {
            if (!error.empty()) error += "; ";
            error += "holder disappeared before identity-safe cleanup";
        }

        bool recovery_identity_validated = false;
        if (holder_exists_ && holder_removal_may_have_mutated_) {
            bool exact_id_present = false;
            std::string recovery_error;
            if (prove_holder_absent(recovery_error, &exact_id_present)) {
                holder_exists_ = false;
                holder_removal_may_have_mutated_ = false;
                operation_ok = false;
            } else if (!exact_id_present) {
                if (!error.empty()) error += "; ";
                error += "uncertain holder retirement recovery failed closed: " + recovery_error;
                holder_settlement_operation_ok_ = false;
                return {false, false};
            } else if (!validate_holder(recovery_error)) {
                if (!error.empty()) error += "; ";
                error +=
                    "uncertain holder immutable identity recovery failed closed: " + recovery_error;
                holder_settlement_operation_ok_ = false;
                return {false, false};
            } else {
                recovery_identity_validated = true;
            }
        }

        if (holder_exists_) {
            std::string validation_error;
            bool validation_ok = recovery_identity_validated || validate_holder(validation_error);
            if (require_retained_topology) {
                validation_ok = validation_ok && verify_network(network_a_, validation_error) &&
                                verify_network(network_b_, validation_error) &&
                                verify_topology(FailurePoint::None, validation_error);
            }
            if (!validation_ok) {
                if (!error.empty()) error += "; ";
                error += validation_error.empty()
                             ? "holder retirement pre-removal revalidation failed"
                             : validation_error;
                holder_settlement_operation_ok_ = false;
                return {false, false};
            }

            if (holder_removal_suppression_armed_ && !holder_removal_suppression_consumed_) {
                // This seam is deliberately consumed only after the same full
                // live identity/topology validation that guards a real rm.
                // It launches no process: the retained running generation is
                // marked uncertain so the next call must recover it by ID.
                holder_removal_suppression_armed_ = false;
                holder_removal_suppression_consumed_ = true;
                holder_removal_may_have_mutated_ = true;
                ++holder_remove_suppression_count_;
                holder_settlement_operation_ok_ = false;
                if (!error.empty()) error += "; ";
                error += "injected holder removal suppression with exact running holder retained";
                return {false, false};
            }

            CommandResult removal;
            holder_removal_may_have_mutated_ = true;
            ++holder_remove_command_count_;
            const bool command_ok = run_command({"docker", "rm", "-f", holder_id_}, removal);
            if (!command_ok || !exited_zero(removal)) {
                operation_ok = false;
                if (!error.empty()) error += "; ";
                error += removal.timed_out
                             ? "holder retirement outcome was uncertain"
                             : "holder retirement command failed: " + trim(removal.output);
            } else {
                result.holder_removed = true;
            }
        }

        if (!holder_exists_ && holder_id_.empty() && !require_retained_topology) {
            cleanup_progress_ = CleanupProgress::HolderSettled;
            frozen_holder_settlement_ = {true, operation_ok, true};
            holder_settlement_operation_ok_ = holder_settlement_operation_ok_ && operation_ok;
            frozen_holder_settlement_.operation_ok = holder_settlement_operation_ok_;
            return frozen_holder_settlement_;
        }

        std::string absence_error;
        if (!prove_holder_absent(absence_error)) {
            if (!error.empty()) error += "; ";
            error += "holder retirement absence proof failed: " + absence_error;
            holder_settlement_operation_ok_ = false;
            // Exact ID/name/PID/start and both network identities remain
            // recorded.  A bounded retry first revalidates them and never
            // creates a same-name replacement from this state.
            return {false, false};
        }
        holder_exists_ = false;
        holder_removal_may_have_mutated_ = false;

        std::string retained_error;
        if (require_retained_topology && !verify_retained_networks_after_holder(retained_error)) {
            if (!error.empty()) error += "; ";
            error += "post-holder retained network proof failed: " + retained_error;
            holder_settlement_operation_ok_ = false;
            return {false, false};
        }

        cleanup_progress_ = CleanupProgress::HolderSettled;
        holder_settlement_operation_ok_ = holder_settlement_operation_ok_ && operation_ok;
        frozen_holder_settlement_ = result;
        frozen_holder_settlement_.settled = true;
        frozen_holder_settlement_.operation_ok = holder_settlement_operation_ok_;
        frozen_holder_settlement_.holder_settled = true;
        return frozen_holder_settlement_;
    }

public:
    CleanupPhaseResult cleanup_topology_phase(std::string& error,
                                              TopologySettlementCallback callback = nullptr,
                                              void* callback_context = nullptr) {
        if (cleanup_progress_ == CleanupProgress::TopologySettled)
            return {true, topology_settlement_operation_ok_, true, false, true, false, true, false};
        if (cleanup_progress_ < CleanupProgress::SidecarSettled || sidecar_exists_ ||
            sidecar_creation_may_have_mutated_) {
            if (!error.empty()) error += "; ";
            error += "refusing holder/network cleanup before exact sidecar settlement";
            return {false, false};
        }
        if (recreated_sidecar_started_ &&
            recreated_sidecar_.state != RecreatedSidecarState::Settled) {
            if (!error.empty()) error += "; ";
            error += "refusing retained-network cleanup before recreated sidecar settlement";
            return {false, false};
        }
        if (recreated_holder_started_ &&
            recreated_holder_.state != HolderOnlyRecreationState::Settled) {
            if (!error.empty()) error += "; ";
            error += "refusing retained-network cleanup before recreated holder settlement";
            return {false, false};
        }

        CleanupPhaseResult phase_result;
        const CleanupPhaseResult holder = cleanup_holder_phase_impl(error, topology_verified_);
        if (!holder.settled) return holder;
        phase_result.holder_settled = true;
        phase_result.holder_removed = holder.holder_removed;
        bool operation_ok = holder.operation_ok;
        const auto notify = [&](TopologySettlementEvent event, bool removed) {
            if (callback == nullptr) return true;
            if (callback(callback_context, event, removed, error)) return true;
            phase_result.operation_ok = operation_ok;
            return false;
        };
        if (!notify(TopologySettlementEvent::Holder, phase_result.holder_removed))
            return phase_result;
        if (network_b_.exists) {
            if (network_b_.id.empty()) {
                if (!timeout_recovery_ || !discover_network(network_b_)) {
                    error = "refusing network B cleanup without recorded identity";
                    operation_ok = false;
                }
            }
            if (!verify_network(network_b_, error))
                operation_ok = false;
            else if (!remove_network(network_b_, error))
                operation_ok = false;
            else
                phase_result.network_b_removed = true;
        }
        phase_result.network_b_settled = !network_b_.exists;
        if (phase_result.network_b_settled &&
            !notify(TopologySettlementEvent::NetworkB, phase_result.network_b_removed))
            return phase_result;
        if (network_a_.exists) {
            if (network_a_.id.empty()) {
                if (!timeout_recovery_ || !discover_network(network_a_)) {
                    error = "refusing network A cleanup without recorded identity";
                    operation_ok = false;
                }
            }
            if (!verify_network(network_a_, error))
                operation_ok = false;
            else if (!remove_network(network_a_, error))
                operation_ok = false;
            else
                phase_result.network_a_removed = true;
        }
        phase_result.network_a_settled = !network_a_.exists;
        if (phase_result.network_a_settled &&
            !notify(TopologySettlementEvent::NetworkA, phase_result.network_a_removed))
            return phase_result;
        topology_settlement_operation_ok_ = topology_settlement_operation_ok_ && operation_ok;
        const bool settled = !holder_exists_ && !network_b_.exists && !network_a_.exists;
        if (settled) cleanup_progress_ = CleanupProgress::TopologySettled;
        phase_result.settled = settled;
        phase_result.operation_ok = operation_ok;
        return phase_result;
    }

    bool cleanup(std::string& error) {
        const CleanupPhaseResult sidecar = cleanup_sidecar_phase(error);
        if (!sidecar.settled) return false;
        if (recreated_sidecar_started_ &&
            recreated_sidecar_.state != RecreatedSidecarState::Settled &&
            !cleanup_recreated_sidecar(error))
            return false;
        if (recreated_holder_started_ &&
            recreated_holder_.state != HolderOnlyRecreationState::Settled &&
            !cleanup_recreated_holder(error))
            return false;
        const CleanupPhaseResult topology = cleanup_topology_phase(error);
        return sidecar.operation_ok && topology.settled && topology.operation_ok;
    }

private:
    bool injected(std::string& error) {
        error = "injected boundary failure";
        return false;
    }

    bool injected_sidecar(const char* boundary, std::string& error) {
        error = std::string("injected held-namespace sidecar failure ") + boundary;
        return false;
    }

    HeldTopologySnapshot topology_snapshot() const {
        HeldTopologySnapshot snapshot;
        snapshot.token = token_;
        snapshot.network_a_name = network_a_.name;
        snapshot.network_a_id = network_a_.id;
        snapshot.network_a_subnet = network_a_.subnet;
        snapshot.network_a_gateway = network_a_.gateway;
        snapshot.network_b_name = network_b_.name;
        snapshot.network_b_id = network_b_.id;
        snapshot.network_b_subnet = network_b_.subnet;
        snapshot.network_b_gateway = network_b_.gateway;
        snapshot.holder_name = holder_name_;
        snapshot.holder_id = holder_id_;
        snapshot.positive_ip = positive_ip_;
        snapshot.guard_ip = guard_ip_;
        snapshot.holder_pid = holder_pid_;
        snapshot.holder_start = holder_start_;
        ProcIdentity holder_identity{};
        if (proc_identity(holder_pid_, holder_identity, false) &&
            holder_identity.start == holder_start_ &&
            container_netns_inode(holder_name_, holder_identity.netns))
            snapshot.holder_netns = holder_identity.netns;
        return snapshot;
    }

    bool inspect_sidecar(const std::string& reference,
                         HeldNamespaceSidecarSnapshot& snapshot,
                         std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.Image}}|{{index "
                          ".Config.Labels \"rut.stage\"}}|{{index .Config.Labels "
                          "\"rut.token\"}}|{{index .Config.Labels \"rut.role\"}}|{{"
                          ".HostConfig.NetworkMode}}|{{.State.Running}}|{{.State.Pid}}|{{"
                          ".Path}}|{{json .Args}}|{{.HostConfig.ReadonlyRootfs}}|{{json "
                          ".HostConfig.PortBindings}}|{{json .NetworkSettings.Ports}}|{{json "
                          ".HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}",
                          reference},
                         result) ||
            !exited_zero(result)) {
            error = "sidecar inspection failed: " + trim(result.output);
            return false;
        }
        std::string record = trim(result.output);
        if (sidecar_revalidation_fault_ != HeldNamespaceSidecarRevalidationFault::None) {
            std::vector<std::string> fields;
            if (!split_exact(record, '|', 17, fields)) {
                error = "sidecar revalidation fault could not split the trusted inspect record";
                return false;
            }
            switch (sidecar_revalidation_fault_) {
                case HeldNamespaceSidecarRevalidationFault::Token:
                    fields[5] = "wrong";
                    break;
                case HeldNamespaceSidecarRevalidationFault::Role:
                    fields[6] = "wrong";
                    break;
                case HeldNamespaceSidecarRevalidationFault::Id:
                    fields[0] = std::string(64, 'd');
                    break;
                case HeldNamespaceSidecarRevalidationFault::ImageReference:
                    fields[2] = "nginx:latest";
                    break;
                case HeldNamespaceSidecarRevalidationFault::ImageId:
                    fields[3] = "sha256:" + std::string(64, 'd');
                    break;
                case HeldNamespaceSidecarRevalidationFault::NetworkMode:
                    fields[7] = "bridge";
                    break;
                case HeldNamespaceSidecarRevalidationFault::Pid:
                    fields[9] = std::to_string(holder_pid_);
                    break;
                case HeldNamespaceSidecarRevalidationFault::Arguments:
                    fields[11] = "[\"wrong\"]";
                    break;
                case HeldNamespaceSidecarRevalidationFault::ReadOnlyRoot:
                    fields[12] = "false";
                    break;
                case HeldNamespaceSidecarRevalidationFault::CapabilityDrop:
                    fields[15] = "[]";
                    break;
                case HeldNamespaceSidecarRevalidationFault::NoNewPrivileges:
                    fields[16] = "[]";
                    break;
                case HeldNamespaceSidecarRevalidationFault::PublishedPorts:
                    fields[13] = "{\"80/tcp\":[{\"HostPort\":\"80\"}]}";
                    break;
                case HeldNamespaceSidecarRevalidationFault::StartIdentity:
                case HeldNamespaceSidecarRevalidationFault::NetworkNamespace:
                case HeldNamespaceSidecarRevalidationFault::None:
                    break;
            }
            record.clear();
            for (size_t index = 0; index < fields.size(); ++index) {
                if (index != 0) record += '|';
                record += fields[index];
            }
        }
        if (!parse_sidecar_inspect_record(record, snapshot, error)) return false;
        snapshot.expected_image_id = expected_sidecar_image_id_;
        if (snapshot.running && snapshot.pid > 1) {
            ProcIdentity identity{};
            ProcIdentity host_identity{};
            if (!proc_identity(snapshot.pid, identity, false) ||
                !container_netns_inode(snapshot.name, identity.netns) ||
                !proc_identity(getpid(), host_identity)) {
                error = "sidecar PID/start/netns discovery failed";
                return false;
            }
            snapshot.start = identity.start;
            snapshot.netns = identity.netns;
            snapshot.host_netns = host_identity.netns;
        }
        if (sidecar_revalidation_fault_ == HeldNamespaceSidecarRevalidationFault::StartIdentity)
            ++snapshot.start;
        if (sidecar_revalidation_fault_ == HeldNamespaceSidecarRevalidationFault::NetworkNamespace)
            ++snapshot.netns;
        return true;
    }

    bool inspect_uncertain_sidecar(const std::string& reference,
                                   HeldNamespaceSidecarSnapshot& snapshot,
                                   std::string& error) {
        if (uncertain_sidecar_inspection_failure_) {
            error = "injected sidecar recovery inspection failure";
            return false;
        }
        return inspect_sidecar(reference, snapshot, error);
    }

    bool recover_uncertain_sidecar_or_prove_absence(std::string& error) {
        HeldNamespaceSidecarSnapshot discovered;
        std::string inspect_error;
        if (inspect_uncertain_sidecar(sidecar_name_, discovered, inspect_error)) {
            std::string semantic_error;
            const bool ownership_exact =
                discovered.name == sidecar_name_ && discovered.token == token_ &&
                discovered.stage == kSidecarStage && discovered.role == kSidecarRole &&
                discovered.pinned_image_reference == RUT_PINNED_NGINX_IMAGE &&
                discovered.expected_image_id == expected_sidecar_image_id_ &&
                discovered.image_id == expected_sidecar_image_id_;
            if (!ownership_exact || !validate_held_namespace_sidecar_snapshot(
                                        topology_snapshot(), discovered, semantic_error)) {
                error =
                    "refusing uncertain sidecar recovery because exact ownership/identity "
                    "was not established";
                if (!semantic_error.empty()) error += ": " + semantic_error;
                return false;
            }
            sidecar_id_ = discovered.id;
            sidecar_snapshot_ = discovered;
            sidecar_exists_ = true;
            if (!verify_sidecar_uniqueness(error)) {
                sidecar_exists_ = false;
                sidecar_id_.clear();
                sidecar_snapshot_ = {};
                return false;
            }
            return true;
        }

        std::string absent_error;
        if (prove_sidecar_absent(absent_error)) {
            sidecar_creation_may_have_mutated_ = false;
            return true;
        }
        error = "sidecar creation state remains unresolved after failed recovery inspection: " +
                inspect_error;
        if (!absent_error.empty()) error += "; " + absent_error;
        return false;
    }

    void discover_sidecar_after_failed_create() {
        HeldNamespaceSidecarSnapshot discovered;
        std::string ignored;
        if (!inspect_sidecar(sidecar_name_, discovered, ignored)) return;
        sidecar_exists_ = true;
        sidecar_id_ = discovered.id;
        sidecar_snapshot_ = discovered;
    }

    bool verify_sidecar_uniqueness(std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "ps",
                          "-aq",
                          "--no-trunc",
                          "--filter",
                          "label=rut.token=" + token_,
                          "--filter",
                          std::string("label=rut.role=") + kSidecarRole},
                         result) ||
            !exited_zero(result) || trim(result.output) != sidecar_id_) {
            error = "token/role-labelled sidecar cardinality or exact ID was not one";
            return false;
        }
        return true;
    }

    bool prove_sidecar_absent(std::string& error) {
        CommandResult result;
        if (!sidecar_id_.empty()) {
            if (!run_command({"docker", "inspect", sidecar_id_}, result) || exited_zero(result)) {
                error = "exact sidecar ID did not provably disappear";
                return false;
            }
        }
        if (!run_command(
                {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + sidecar_name_ + "$"},
                result) ||
            !exited_zero(result) || !trim(result.output).empty()) {
            error = "exact sidecar name did not provably disappear";
            return false;
        }
        if (!run_command({"docker",
                          "ps",
                          "-aq",
                          "--filter",
                          "label=rut.token=" + token_,
                          "--filter",
                          std::string("label=rut.role=") + kSidecarRole},
                         result) ||
            !exited_zero(result) || !trim(result.output).empty()) {
            error = "token/role-labelled sidecar residue remains";
            return false;
        }
        const bool rotation_witness_recorded =
            full_container_id(sidecar_id_) && sidecar_snapshot_.id == sidecar_id_ &&
            sidecar_snapshot_.name == sidecar_name_ && sidecar_snapshot_.pid > 1 &&
            sidecar_snapshot_.start != 0u;
        if (!rotation_witness_recorded) return true;
        ProcIdentity current{};
        if (proc_identity(sidecar_snapshot_.pid, current, false)) {
            if (current.start == sidecar_snapshot_.start) {
                error = "exact old sidecar PID/start process witness remains";
                return false;
            }
        } else {
            errno = 0;
            if (kill(sidecar_snapshot_.pid, 0) == 0 || errno == EPERM) {
                error = "old sidecar process witness could not be authoritatively inspected";
                return false;
            }
            if (errno != ESRCH) {
                error = "old sidecar process absence probe failed";
                return false;
            }
        }
        holder_retirement_absence_.sidecar = {
            sidecar_id_, sidecar_snapshot_.pid, sidecar_snapshot_.start, true, true};
        holder_retirement_absence_.sidecar_name = sidecar_name_;
        holder_retirement_absence_.sidecar_name_absent = true;
        finalize_old_generation_absence_if_complete();
        return true;
    }

    bool cleanup_sidecar(std::string& error) {
        HeldNamespaceSidecarSnapshot current;
        std::string inspect_error;
        if (!inspect_sidecar(
                sidecar_id_.empty() ? sidecar_name_ : sidecar_id_, current, inspect_error)) {
            std::string absent_error;
            if (sidecar_id_.empty() || !prove_sidecar_absent(absent_error)) {
                error = inspect_error;
                if (!absent_error.empty()) error += "; " + absent_error;
                return false;
            }
            sidecar_exists_ = false;
            sidecar_creation_may_have_mutated_ = false;
            error = "sidecar disappeared before identity-safe cleanup";
            return false;
        }
        const bool had_discovered_snapshot = !sidecar_snapshot_.image_id.empty();
        const std::string recorded_image_id =
            had_discovered_snapshot ? sidecar_snapshot_.image_id : current.image_id;
        const bool ownership_exact =
            !sidecar_id_.empty() && current.id == sidecar_id_ && current.name == sidecar_name_ &&
            current.token == token_ && current.stage == kSidecarStage &&
            current.role == kSidecarRole &&
            current.pinned_image_reference == RUT_PINNED_NGINX_IMAGE &&
            current.expected_image_id == expected_sidecar_image_id_ &&
            current.image_id == expected_sidecar_image_id_ && current.image_id == recorded_image_id;
        if (!ownership_exact) {
            error = "refusing sidecar deletion because immutable identity/ownership changed";
            return false;
        }
        std::string semantic_error;
        const HeldTopologySnapshot topology = topology_snapshot();
        const bool expected_stopped_identity =
            unexpected_sidecar_death_verified_ && had_discovered_snapshot &&
            sidecar_stopped_identity_equal(current, sidecar_snapshot_);
        const bool semantic_exact =
            expected_stopped_identity ||
            (validate_held_namespace_sidecar_snapshot(topology, current, semantic_error) &&
             (!had_discovered_snapshot || sidecar_snapshot_equal(current, sidecar_snapshot_)));
        if (!semantic_exact && semantic_error.empty())
            semantic_error = "sidecar PID/start/netns/security evidence changed before cleanup";
        if (!semantic_exact) {
            error =
                "refusing sidecar deletion after exact revalidation rejection: " + semantic_error;
            return false;
        }
        // Freeze the exact old process witness before removal even when an
        // earlier injected boundary returned before the public snapshot was
        // published.  Generation-name reuse later depends on this authority.
        if (!had_discovered_snapshot) sidecar_snapshot_ = current;

        CommandResult result;
        const bool command_ok = run_command(
            {"docker", "rm", "-f", sidecar_id_}, result, 15000, cleanup_reported_timeout_);
        if (cleanup_reported_timeout_ && result.timed_out && WIFEXITED(result.status) &&
            WEXITSTATUS(result.status) == 0)
            cleanup_reported_timeout_observed_ = true;
        std::string absent_error;
        if ((!command_ok || !exited_zero(result)) && !result.timed_out) {
            error = "sidecar cleanup command failed: " + trim(result.output);
            return false;
        }
        if (!prove_sidecar_absent(absent_error)) {
            error = "sidecar cleanup disappearance proof failed: " + absent_error;
            return false;
        }
        sidecar_exists_ = false;
        sidecar_creation_may_have_mutated_ = false;
        cleanup_reported_timeout_ = false;
        return true;
    }

    bool create_network(Network& network, FailurePoint point, std::string& error) {
        CommandResult result;
        const bool reported_timeout =
            point == FailurePoint::AfterNetworkACreationReportedTimeout && &network == &network_a_;
        const NetworkPlan plan{network.subnet, network.gateway};
        if (!valid_network_plan(plan) ||
            !run_command(
                network_create_argv(plan, token_, network.name), result, 15000, reported_timeout) ||
            !exited_zero(result)) {
            error = "network creation failed: " + trim(result.output);
            if (reported_timeout && result.timed_out) {
                timeout_recovery_ = true;
                network.exists = true;
                if (!discover_network(network))
                    error += "; timeout recovery discovery failed";
                else
                    error = "injected actual-success/reported-timeout; recovered exact network ID";
            }
            return false;
        }
        network.exists = true;
        network.id = trim(result.output);
        if (network.id.empty() || network.id.find('\n') != std::string::npos) {
            error = "network creation returned no exact ID";
            return false;
        }
        if (&network == &network_a_)
            ++setup_event_evidence_.network_a_create_count;
        else if (&network == &network_b_)
            ++setup_event_evidence_.network_b_create_count;
        if (point == FailurePoint::AfterNetworkACreated && &network == &network_a_) {
            return injected(error);
        }
        if (point == FailurePoint::AfterNetworkBCreated && &network == &network_b_) {
            return injected(error);
        }
        return true;
    }

    bool verify_network(Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{.Id}} {{.Name}} {{.Driver}} {{.Scope}} {{(index .IPAM.Config "
                          "0).Subnet}} {{(index .IPAM.Config 0).Gateway}} {{index .Labels "
                          "\"rut.stage\"}} {{index .Labels \"rut.token\"}}",
                          network.name},
                         result) ||
            !exited_zero(result)) {
            error = "network inspection failed: " + trim(result.output);
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string id, name, driver, scope, subnet, gateway, stage, token;
        if (!(fields >> id >> name >> driver >> scope >> subnet >> gateway >> stage >> token) ||
            id.empty() || id != network.id || name != network.name || driver != "bridge" ||
            scope != "local" || stage != "358-stage2a2" || token != token_ ||
            subnet != network.subnet || gateway != network.gateway ||
            !valid_gateway(network.subnet, network.gateway)) {
            error = "network ID/name/driver/scope/IPAM/labels were not exact";
            return false;
        }
        return true;
    }

    bool discover_network(Network& network) {
        CommandResult result;
        if (!run_command({"docker", "network", "inspect", "-f", "{{.Id}}", network.name}, result) ||
            !exited_zero(result))
            return false;
        network.id = trim(result.output);
        network.exists = !network.id.empty() && network.id.find('\n') == std::string::npos;
        return network.exists;
    }

    bool inspect_holder_cleanup_identity(const std::string& reference,
                                         HolderCleanupIdentity& identity,
                                         std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.Image}}|{{index .Config.Labels "
                          "\"rut.stage\"}}|{{index .Config.Labels \"rut.token\"}}|{{.State."
                          "Running}}|{{.State.Pid}}|{{.Path}}|{{json .Args}}|{{.HostConfig."
                          "ReadonlyRootfs}}|{{json .HostConfig.PortBindings}}|{{json "
                          ".NetworkSettings.Ports}}|{{json .HostConfig.CapDrop}}|{{json "
                          ".HostConfig.SecurityOpt}}|{{json .Config.ExposedPorts}}|"
                          "{{index .Config.Labels \"rut.role\"}}|{{index .Config.Labels "
                          "\"rut.generation\"}}",
                          reference},
                         result) ||
            !exited_zero(result)) {
            error = "holder immutable identity inspection failed: " + trim(result.output);
            return false;
        }
        std::vector<std::string> fields;
        if (!split_exact(trim(result.output), '|', 18, fields) ||
            !parse_exact_bool(fields[6], identity.running) ||
            !parse_exact_pid(fields[7], identity.pid) ||
            !parse_exact_bool(fields[10], identity.read_only_root)) {
            error = "holder immutable identity inspection was malformed";
            return false;
        }
        identity.id = fields[0];
        identity.name =
            fields[1].size() > 1u && fields[1][0] == '/' ? fields[1].substr(1u) : std::string();
        identity.image_reference = fields[2];
        identity.image_id = fields[3];
        identity.stage = fields[4];
        identity.token = fields[5];
        identity.path = fields[8];
        identity.arguments_json = fields[9];
        identity.port_bindings_json = fields[11];
        identity.network_ports_json = fields[12];
        identity.capability_drop_json = fields[13];
        identity.security_options_json = fields[14];
        identity.exposed_ports_json = fields[15];
        identity.role = fields[16];
        identity.generation = fields[17];
        return true;
    }

    bool holder_immutable_identity_exact(const HolderCleanupIdentity& identity,
                                         std::string& error) const {
        const bool exact =
            full_container_id(identity.id) && identity.id == holder_id_ &&
            identity.name == holder_name_ && identity.stage == "358-stage2a2" &&
            identity.token == token_ && identity.image_reference == RUT_PINNED_NGINX_IMAGE &&
            sha256_identity(identity.image_id) && identity.image_id == holder_image_id_ &&
            identity.path == "/bin/sleep" && identity.arguments_json == "[\"infinity\"]" &&
            identity.read_only_root &&
            no_published_ports(identity.port_bindings_json, identity.network_ports_json) &&
            identity.capability_drop_json == "[\"ALL\"]" &&
            identity.security_options_json == "[\"no-new-privileges\"]" &&
            identity.exposed_ports_json != "null";
        if (!exact)
            error = "refusing holder deletion because exact immutable identity/config changed";
        return exact;
    }

    bool discover_holder() {
        HolderCleanupIdentity identity;
        std::string error;
        if (!inspect_holder_cleanup_identity(holder_name_, identity, error) ||
            !full_container_id(identity.id) || identity.name != holder_name_ ||
            identity.stage != "358-stage2a2" || identity.token != token_ ||
            identity.image_reference != RUT_PINNED_NGINX_IMAGE ||
            !sha256_identity(identity.image_id))
            return false;
        holder_id_ = identity.id;
        holder_image_id_ = identity.image_id;
        holder_pid_ = identity.pid;
        holder_exists_ = true;
        if (holder_pid_ <= 0) return true;
        ProcIdentity process_identity{};
        if (proc_identity(holder_pid_, process_identity, false))
            holder_start_ = process_identity.start;
        return true;
    }

    bool validate_holder(std::string& error) {
        HolderCleanupIdentity identity;
        const std::string reference = holder_id_.empty() ? holder_name_ : holder_id_;
        if (!inspect_holder_cleanup_identity(reference, identity, error)) return false;
        if (holder_id_.empty() && timeout_recovery_) {
            holder_id_ = identity.id;
            holder_image_id_ = identity.image_id;
        }
        if (holder_id_.empty()) {
            error = "refusing holder deletion without recorded identity";
            return false;
        }
        if (!holder_immutable_identity_exact(identity, error)) return false;
        if (!identity.running) {
            if (identity.pid != 0) {
                error = "refusing stopped holder recovery with nonzero Docker PID";
                return false;
            }
            error = "refusing stopped holder recovery without a live exact process identity";
            return false;
        }
        if (identity.pid != holder_pid_) {
            error = "refusing holder deletion because exact running PID changed";
            return false;
        }
        ProcIdentity process_identity{};
        if (holder_pid_ <= 1 || holder_start_ == 0u ||
            !proc_identity(holder_pid_, process_identity, false) ||
            process_identity.start != holder_start_) {
            error = "refusing holder deletion because exact PID/start identity changed";
            return false;
        }
        return true;
    }

    bool prove_holder_absent(std::string& error, bool* exact_id_present = nullptr) {
        if (exact_id_present != nullptr) *exact_id_present = false;
        if (holder_id_.empty() || holder_name_.empty() || holder_pid_ <= 1 || holder_start_ == 0u) {
            error = "holder absence proof lacked exact recorded ID/name/PID/start authority";
            return false;
        }
        CommandResult result;
        if (!run_command({"docker", "ps", "-aq", "--no-trunc", "--filter", "id=" + holder_id_},
                         result) ||
            !exited_zero(result)) {
            error = "exact old holder ID absence inspection was uncertain";
            return false;
        }
        const std::string matching_id = trim(result.output);
        if (!matching_id.empty()) {
            if (matching_id != holder_id_) {
                error = "exact old holder ID absence inspection returned an unexpected identity";
                return false;
            }
            if (exact_id_present != nullptr) *exact_id_present = true;
            error = "exact old holder ID did not provably disappear";
            return false;
        }
        if (!run_command(
                {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + holder_name_ + "$"},
                result) ||
            !exited_zero(result) || !trim(result.output).empty()) {
            error = "exact old holder stable name did not provably disappear";
            return false;
        }
        ProcIdentity current{};
        if (proc_identity(holder_pid_, current, false)) {
            if (current.start == holder_start_) {
                error = "exact old holder PID/start process witness remains";
                return false;
            }
        } else {
            errno = 0;
            if (kill(holder_pid_, 0) == 0 || errno == EPERM) {
                error = "old holder process witness could not be authoritatively inspected";
                return false;
            }
            if (errno != ESRCH) {
                error = "old holder process absence probe failed";
                return false;
            }
        }
        holder_retirement_absence_.holder = {holder_id_, holder_pid_, holder_start_, true, true};
        holder_retirement_absence_.holder_name = holder_name_;
        holder_retirement_absence_.holder_name_absent = true;
        finalize_old_generation_absence_if_complete();
        return true;
    }

    void finalize_old_generation_absence_if_complete() {
        const auto exact = [](const HeldNamespaceGenerationWitnessAbsence& witness) {
            return full_container_id(witness.container_id) && witness.pid > 1 &&
                   witness.start != 0u && witness.container_id_absent &&
                   witness.process_identity_absent;
        };
        if (exact(holder_retirement_absence_.holder) && exact(holder_retirement_absence_.sidecar) &&
            holder_retirement_absence_.holder_name == holder_name_ &&
            holder_retirement_absence_.sidecar_name == sidecar_name_ &&
            holder_retirement_absence_.holder_name_absent &&
            holder_retirement_absence_.sidecar_name_absent) {
            holder_retirement_absence_.phase =
                HeldNamespaceGenerationRotationPhase::OldGenerationAbsent;
        }
    }

    bool remove_network(Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker", "network", "rm", network.name}, result) ||
            !exited_zero(result)) {
            error = "network cleanup failed for " + network.name + ": " + trim(result.output);
            return false;
        }
        network.exists = false;
        return true;
    }

    bool verify_membership(const Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{.Id}}|{{.Name}} {{range $id,$v := "
                          ".Containers}}{{$id}}|{{$v.Name}}|{{$v.IPv4Address}} {{end}}",
                          network.name},
                         result) ||
            !exited_zero(result)) {
            error = "network/container membership was not bidirectionally verified";
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string network_header;
        std::vector<std::string> header_fields;
        if (!(fields >> network_header) || !split_exact(network_header, '|', 2, header_fields) ||
            header_fields[0] != network.id || header_fields[1] != network.name) {
            error = "network identity was not exact during reciprocal membership verification";
            return false;
        }
        std::string member;
        size_t count = 0;
        const size_t slash = network.subnet.find('/');
        const std::string expected_address =
            network.name == network_a_.name ? positive_ip_ : guard_ip_;
        if (slash == std::string::npos) {
            error = "network reciprocal subnet was malformed";
            return false;
        }
        while (fields >> member) {
            std::vector<std::string> member_fields;
            if (!split_exact(member, '|', 3, member_fields) || member_fields[0] != holder_id_ ||
                member_fields[1] != holder_name_ ||
                member_fields[2] != expected_address + network.subnet.substr(slash)) {
                error = "network reciprocal endpoint association was not exact";
                return false;
            }
            ++count;
        }
        if (count != 1) {
            error = "network had unexpected container membership count";
            return false;
        }
        return true;
    }

    bool verify_empty_membership(const Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{.Id}}|{{.Name}} {{range $id,$v := .Containers}}{{$id}}|{{$v.Name}}|{{"
                          "$v.IPv4Address}} {{end}}",
                          network.name},
                         result) ||
            !exited_zero(result)) {
            error = "retained network membership inspection failed";
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string network_header;
        std::vector<std::string> header_fields;
        std::string unexpected_member;
        if (!(fields >> network_header) || !split_exact(network_header, '|', 2, header_fields) ||
            header_fields[0] != network.id || header_fields[1] != network.name ||
            (fields >> unexpected_member)) {
            error = "retained network identity/membership was not exactly empty";
            return false;
        }
        return true;
    }

    bool verify_retained_networks_after_holder(std::string& error) {
        std::string expected_positive;
        std::string expected_guard;
        if (!network_a_.exists || !network_b_.exists || !verify_network(network_a_, error) ||
            !verify_network(network_b_, error) ||
            !choose_address(network_a_.subnet, network_a_.gateway, expected_positive) ||
            !choose_address(network_b_.subnet, network_b_.gateway, expected_guard) ||
            expected_positive != positive_ip_ || expected_guard != guard_ip_) {
            if (error.empty())
                error = "retained network/IPAM addressing plan changed after holder retirement";
            return false;
        }
        if (!verify_empty_membership(network_a_, error) ||
            !verify_empty_membership(network_b_, error))
            return false;
        return true;
    }

    std::string token_;
    std::string holder_name_;
    std::string sidecar_name_;
    Network network_a_;
    Network network_b_;
    std::string positive_ip_;
    std::string guard_ip_;
    std::string holder_id_;
    std::string holder_image_id_;
    pid_t holder_pid_ = -1;
    u64 holder_start_ = 0;
    bool holder_exists_ = false;
    bool timeout_recovery_ = false;
    std::string sidecar_id_;
    std::string expected_sidecar_image_id_;
    HeldNamespaceSidecarSnapshot sidecar_snapshot_;
    bool sidecar_exists_ = false;
    bool sidecar_creation_may_have_mutated_ = false;
    bool uncertain_sidecar_inspection_failure_ = false;
    bool cleanup_reported_timeout_ = false;
    bool cleanup_reported_timeout_observed_ = false;
    bool unexpected_sidecar_death_verified_ = false;
    bool holder_disappearance_operation_failure_ = false;
    bool holder_removal_may_have_mutated_ = false;
    bool holder_removal_suppression_armed_ = false;
    bool holder_removal_suppression_consumed_ = false;
    u32 holder_remove_command_count_ = 0;
    u32 holder_remove_suppression_count_ = 0;
    SetupEventEvidence setup_event_evidence_;
    bool network_b_test_disconnected_ = false;
    bool topology_verified_ = false;
    CleanupProgress cleanup_progress_ = CleanupProgress::Active;
    bool sidecar_settlement_operation_ok_ = true;
    bool holder_settlement_operation_ok_ = true;
    bool topology_settlement_operation_ok_ = true;
    CleanupPhaseResult frozen_holder_settlement_;
    HeldNamespaceOldGenerationAbsence holder_retirement_absence_;
    RecreatedHolderOwner recreated_holder_;
    bool recreated_holder_started_ = false;
    RecreatedSidecarOwner recreated_sidecar_;
    bool recreated_sidecar_started_ = false;
    HeldNamespaceSidecarRevalidationFault sidecar_revalidation_fault_ =
        HeldNamespaceSidecarRevalidationFault::None;
};

void Fixture::transition_recreated_holder(HolderOnlyRecreationState state) {
    recreated_holder_.state = state;
    recreated_holder_.state_visit_mask |= 1u << static_cast<unsigned>(state);
}

bool Fixture::recreate_holder_only(HolderOnlyRecreationFailurePoint failure_point,
                                   std::string& error) {
    error.clear();
    if (recreated_holder_started_ || cleanup_progress_ != CleanupProgress::HolderSettled ||
        sidecar_exists_ || holder_exists_) {
        error = "holder-only recreation lacked settled old holder/sidecar authority";
        return false;
    }
    const auto witness_exact = [](const HeldNamespaceGenerationWitnessAbsence& witness) {
        return full_container_id(witness.container_id) && witness.pid > 1 && witness.start != 0u &&
               witness.container_id_absent && witness.process_identity_absent;
    };
    if (holder_retirement_absence_.phase !=
            HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
        !witness_exact(holder_retirement_absence_.holder) ||
        !witness_exact(holder_retirement_absence_.sidecar) ||
        holder_retirement_absence_.holder_name != holder_name_ ||
        holder_retirement_absence_.sidecar_name != sidecar_name_ ||
        !holder_retirement_absence_.holder_name_absent ||
        !holder_retirement_absence_.sidecar_name_absent) {
        error = "holder-only recreation lacked exact old holder/sidecar absence authority";
        return false;
    }
    if (!verify_retained_networks_after_holder(error)) {
        error = "holder-only recreation retained-network precondition failed: " + error;
        return false;
    }
    CommandResult collision;
    if (!run_command(
            {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + holder_name_ + "$"},
            collision) ||
        !exited_zero(collision) || !trim(collision.output).empty()) {
        error = "holder-only recreation stable-name collision was rejected";
        return false;
    }

    recreated_holder_started_ = true;
    RecreatedHolderOwner& fresh = recreated_holder_;
    fresh.failure_point = failure_point;
    const auto immutable_exact = [&](const HolderCleanupIdentity& identity, bool running) {
        return full_container_id(identity.id) && identity.id == fresh.id &&
               identity.id != holder_retirement_absence_.holder.container_id &&
               identity.id != holder_retirement_absence_.sidecar.container_id &&
               identity.name == holder_name_ && identity.stage == "358-stage2a2" &&
               identity.token == token_ && identity.role == "holder-recreated" &&
               identity.generation == "holder-only-1" &&
               identity.image_reference == RUT_PINNED_NGINX_IMAGE &&
               sha256_identity(identity.image_id) && identity.image_id == fresh.image_id &&
               identity.path == "/bin/sleep" && identity.arguments_json == "[\"infinity\"]" &&
               identity.read_only_root &&
               no_published_ports(identity.port_bindings_json, identity.network_ports_json) &&
               identity.capability_drop_json == "[\"ALL\"]" &&
               identity.security_options_json == "[\"no-new-privileges\"]" &&
               identity.exposed_ports_json != "null" && identity.running == running &&
               (running ? identity.pid > 1 : identity.pid == 0);
    };
    const auto inspect_exact = [&](bool running, HolderCleanupIdentity& identity) {
        std::string inspect_error;
        if (!inspect_holder_cleanup_identity(fresh.id, identity, inspect_error) ||
            !immutable_exact(identity, running)) {
            error = "recreated holder immutable identity was not exact";
            if (!inspect_error.empty()) error += ": " + inspect_error;
            transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
            return false;
        }
        return true;
    };
    const auto verify_stopped_network_a_config = [&]() {
        CommandResult inspect;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.HostConfig.NetworkMode}} {{range $name,$v := "
                          ".NetworkSettings.Networks}}{{$name}}|{{json $v.NetworkID}}|{{json "
                          "$v.IPAMConfig.IPv4Address}}|{{json $v.EndpointID}}|{{json "
                          "$v.IPAddress}}|{{json $v.Gateway}} {{end}}",
                          fresh.id},
                         inspect) ||
            !exited_zero(inspect)) {
            error = "recreated stopped holder network configuration inspection failed";
            return false;
        }
        const std::string inspect_record = trim(inspect.output);
        std::istringstream fields(inspect_record);
        std::string network_mode;
        std::string network;
        std::string extra;
        std::vector<std::string> parts;
        // A stopped container has exact configured network/IPAM authority but
        // deliberately no active endpoint identity or assigned wire address.
        const std::string quoted_positive_ip = "\"" + positive_ip_ + "\"";
        if (!(fields >> network_mode >> network) || (fields >> extra) ||
            network_mode != network_a_.id || !split_exact(network, '|', 6, parts) ||
            parts[0] != network_a_.name || parts[1] != "\"\"" || parts[2] != quoted_positive_ip ||
            parts[3] != "\"\"" || parts[4] != "\"\"" || parts[5] != "\"\"") {
            constexpr std::size_t kMaxDiagnosticRecord = 512u;
            const std::string bounded_record =
                inspect_record.substr(0u, std::min(inspect_record.size(), kMaxDiagnosticRecord));
            error = "recreated stopped holder exact network-A/static-IP config was not exact: " +
                    bounded_record;
            if (inspect_record.size() > kMaxDiagnosticRecord) error += "...";
            return false;
        }
        return true;
    };
    const auto verify_memberships = [&](bool require_b) {
        if (!fresh.running_identity_validated || fresh.pid <= 1 || fresh.start == 0u) {
            error = "refusing recreated-holder membership proof before running PID/start authority";
            return false;
        }
        CommandResult inspect;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.Name}}|{{.Id}}|{{index .Config.Labels \"rut.role\"}}|{{index "
                          ".Config.Labels \"rut.generation\"}} {{range $name,$v := "
                          ".NetworkSettings.Networks}}{{$name}}|{{$v.NetworkID}}|{{$v.IPAddress}}|"
                          "{{$v.Gateway}} {{end}}",
                          fresh.id},
                         inspect) ||
            !exited_zero(inspect)) {
            error = "recreated holder endpoint inspection failed: " + trim(inspect.output);
            return false;
        }
        std::istringstream fields(trim(inspect.output));
        std::string metadata;
        std::vector<std::string> metadata_fields;
        if (!(fields >> metadata) || !split_exact(metadata, '|', 4, metadata_fields) ||
            metadata_fields[0] != "/" + holder_name_ || metadata_fields[1] != fresh.id ||
            metadata_fields[2] != "holder-recreated" || metadata_fields[3] != "holder-only-1") {
            error = "recreated holder endpoint metadata was not exact";
            return false;
        }
        std::vector<Endpoint> actual;
        std::string endpoint;
        while (fields >> endpoint) {
            std::vector<std::string> parts;
            if (!split_exact(endpoint, '|', 4, parts)) {
                error = "recreated holder endpoint record was malformed";
                return false;
            }
            const Network* network = parts[0] == network_a_.name
                                         ? &network_a_
                                         : (parts[0] == network_b_.name ? &network_b_ : nullptr);
            if (network == nullptr || network->subnet.find('/') == std::string::npos) {
                error = "recreated holder exposed an unexpected endpoint";
                return false;
            }
            actual.push_back({parts[0],
                              parts[1],
                              parts[2],
                              parts[2] + network->subnet.substr(network->subnet.find('/')),
                              parts[3]});
        }
        std::vector<Endpoint> expected{
            {network_a_.name,
             network_a_.id,
             positive_ip_,
             positive_ip_ + network_a_.subnet.substr(network_a_.subnet.find('/')),
             network_a_.gateway}};
        if (require_b)
            expected.push_back({network_b_.name,
                                network_b_.id,
                                guard_ip_,
                                guard_ip_ + network_b_.subnet.substr(network_b_.subnet.find('/')),
                                network_b_.gateway});
        if (!endpoint_set_equal(expected, actual)) {
            error = "recreated holder endpoint set was not exact";
            return false;
        }
        for (const auto& expected_endpoint : expected) {
            const Network& network =
                expected_endpoint.network_name == network_a_.name ? network_a_ : network_b_;
            CommandResult reverse;
            if (!run_command({"docker",
                              "network",
                              "inspect",
                              "-f",
                              "{{.Id}}|{{.Name}} {{range $id,$v := .Containers}}{{$id}}|{{"
                              "$v.Name}}|{{$v.IPv4Address}} {{end}}",
                              network.id},
                             reverse) ||
                !exited_zero(reverse)) {
                error = "recreated holder reverse membership inspection failed";
                return false;
            }
            std::istringstream reverse_fields(trim(reverse.output));
            std::string header;
            std::string member;
            std::vector<std::string> header_parts;
            std::vector<std::string> member_parts;
            if (!(reverse_fields >> header) || !split_exact(header, '|', 2, header_parts) ||
                header_parts[0] != network.id || header_parts[1] != network.name ||
                !(reverse_fields >> member) || !split_exact(member, '|', 3, member_parts) ||
                member_parts[0] != fresh.id || member_parts[1] != holder_name_ ||
                member_parts[2] != expected_endpoint.cidr || (reverse_fields >> member)) {
                error = "recreated holder reverse membership was not exactly singleton";
                return false;
            }
        }
        return true;
    };

    transition_recreated_holder(HolderOnlyRecreationState::CreateMayHaveMutated);
    fresh.create_may_have_mutated = true;
    ++fresh.create_command_count;
    CommandResult create;
    const bool create_reported_timeout =
        failure_point == HolderOnlyRecreationFailurePoint::CreateReportedTimeout;
    const bool create_ok = run_command({"docker",
                                        "create",
                                        "--pull=never",
                                        "--name",
                                        holder_name_,
                                        "--network",
                                        network_a_.id,
                                        "--ip",
                                        positive_ip_,
                                        "--cap-drop",
                                        "ALL",
                                        "--security-opt",
                                        "no-new-privileges",
                                        "--read-only",
                                        "--tmpfs",
                                        "/tmp:rw,noexec,nosuid,size=1m",
                                        "--entrypoint",
                                        "/bin/sleep",
                                        "--label",
                                        kStageLabel,
                                        "--label",
                                        "rut.token=" + token_,
                                        "--label",
                                        "rut.role=holder-recreated",
                                        "--label",
                                        "rut.generation=holder-only-1",
                                        RUT_PINNED_NGINX_IMAGE,
                                        "infinity"},
                                       create,
                                       15000,
                                       create_reported_timeout);
    fresh.id = trim(create.output);
    fresh.image_id = holder_image_id_;
    if (create.timed_out && !full_container_id(fresh.id)) {
        HolderCleanupIdentity recovered;
        std::string recovery_error;
        if (inspect_holder_cleanup_identity(holder_name_, recovered, recovery_error) &&
            full_container_id(recovered.id) &&
            recovered.id != holder_retirement_absence_.holder.container_id &&
            recovered.id != holder_retirement_absence_.sidecar.container_id &&
            recovered.name == holder_name_ && recovered.stage == "358-stage2a2" &&
            recovered.token == token_ && recovered.role == "holder-recreated" &&
            recovered.generation == "holder-only-1" &&
            recovered.image_reference == RUT_PINNED_NGINX_IMAGE &&
            recovered.image_id == holder_image_id_ && !recovered.running && recovered.pid == 0 &&
            recovered.path == "/bin/sleep" && recovered.arguments_json == "[\"infinity\"]" &&
            recovered.read_only_root &&
            no_published_ports(recovered.port_bindings_json, recovered.network_ports_json) &&
            recovered.capability_drop_json == "[\"ALL\"]" &&
            recovered.security_options_json == "[\"no-new-privileges\"]") {
            fresh.id = recovered.id;
            fresh.image_id = recovered.image_id;
        }
    }
    if ((!create_ok && !create.timed_out) || !full_container_id(fresh.id)) {
        transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        fresh.operation_ok = false;
        error = "recreated holder create outcome could not be adopted by exact full ID";
        return false;
    }
    HolderCleanupIdentity identity;
    if (!inspect_exact(false, identity) || !verify_stopped_network_a_config()) return false;
    fresh.image_id = identity.image_id;
    fresh.create_may_have_mutated = false;
    transition_recreated_holder(HolderOnlyRecreationState::CreatedStoppedCleanupOnly);
    if (!create_ok || create.timed_out) fresh.operation_ok = false;

    transition_recreated_holder(HolderOnlyRecreationState::StartMayHaveMutated);
    fresh.start_may_have_mutated = true;
    ++fresh.start_command_count;
    CommandResult start;
    const bool start_ok =
        run_command({"docker", "start", fresh.id},
                    start,
                    15000,
                    failure_point == HolderOnlyRecreationFailurePoint::StartReportedTimeout);
    if (!start_ok && !start.timed_out) {
        std::string stopped_error;
        HolderCleanupIdentity stopped;
        if (inspect_holder_cleanup_identity(fresh.id, stopped, stopped_error) &&
            immutable_exact(stopped, false)) {
            fresh.start_may_have_mutated = false;
            transition_recreated_holder(HolderOnlyRecreationState::CreatedStoppedCleanupOnly);
        } else {
            transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        }
        fresh.operation_ok = false;
        error = "recreated holder start failed; stopped exact holder is cleanup-only";
        return false;
    }
    std::string running_inspect_error;
    if (!inspect_holder_cleanup_identity(fresh.id, identity, running_inspect_error) ||
        !immutable_exact(identity, identity.running)) {
        transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        fresh.operation_ok = false;
        error = "recreated holder start recovery identity was ambiguous";
        return false;
    }
    if (!identity.running) {
        fresh.start_may_have_mutated = false;
        transition_recreated_holder(HolderOnlyRecreationState::CreatedStoppedCleanupOnly);
        fresh.operation_ok = false;
        error = "recreated holder remained stopped after start and is cleanup-only";
        return false;
    }
    ProcIdentity process{};
    if (!proc_identity(identity.pid, process, false) || process.start == 0u ||
        (identity.pid == holder_retirement_absence_.holder.pid &&
         process.start == holder_retirement_absence_.holder.start) ||
        (identity.pid == holder_retirement_absence_.sidecar.pid &&
         process.start == holder_retirement_absence_.sidecar.start)) {
        transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        fresh.operation_ok = false;
        error = "recreated holder running A identity/process witness was not exact";
        return false;
    }
    fresh.pid = identity.pid;
    fresh.start = process.start;
    fresh.running_identity_validated = true;
    if (!verify_memberships(false)) {
        transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        fresh.operation_ok = false;
        return false;
    }
    fresh.network_a_membership_proven_after_start = true;
    fresh.start_may_have_mutated = false;
    transition_recreated_holder(HolderOnlyRecreationState::RunningExactNetworkA);
    if (start.timed_out) fresh.operation_ok = false;

    transition_recreated_holder(HolderOnlyRecreationState::NetworkBConnectMayHaveMutated);
    fresh.connect_b_may_have_mutated = true;
    ++fresh.connect_b_command_count;
    CommandResult connect;
    const bool connect_ok = run_command(
        {"docker", "network", "connect", "--ip", guard_ip_, network_b_.id, fresh.id},
        connect,
        15000,
        failure_point == HolderOnlyRecreationFailurePoint::NetworkBConnectReportedTimeout);
    if ((!connect_ok && !connect.timed_out) || !inspect_exact(true, identity) ||
        !verify_memberships(true)) {
        fresh.operation_ok = false;
        if (fresh.state != HolderOnlyRecreationState::Unresolved)
            transition_recreated_holder(HolderOnlyRecreationState::RunningExactNetworkA);
        if (error.empty()) error = "recreated holder B-connect did not yield exact A+B topology";
        return false;
    }
    fresh.connect_b_may_have_mutated = false;
    transition_recreated_holder(HolderOnlyRecreationState::RunningExactNetworksAB);
    if (connect.timed_out) fresh.operation_ok = false;
    if (!verify_network(network_a_, error) || !verify_network(network_b_, error) ||
        !inspect_exact(true, identity) || !verify_memberships(true)) {
        transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        fresh.operation_ok = false;
        return false;
    }
    transition_recreated_holder(HolderOnlyRecreationState::Validated);
    fresh.frozen_evidence = holder_only_recreation_evidence();
    return true;
}

HolderOnlyRecreationEvidence Fixture::holder_only_recreation_evidence() const {
    if (recreated_holder_.state == HolderOnlyRecreationState::Settled &&
        recreated_holder_.frozen_evidence.holder_id == recreated_holder_.id)
        return recreated_holder_.frozen_evidence;
    HolderOnlyRecreationEvidence evidence;
    evidence.complete_generation = false;
    evidence.state = recreated_holder_.state;
    evidence.old_absence = holder_retirement_absence_;
    evidence.network_a_name = network_a_.name;
    evidence.network_a_id = network_a_.id;
    evidence.network_a_subnet = network_a_.subnet;
    evidence.network_a_gateway = network_a_.gateway;
    evidence.network_b_name = network_b_.name;
    evidence.network_b_id = network_b_.id;
    evidence.network_b_subnet = network_b_.subnet;
    evidence.network_b_gateway = network_b_.gateway;
    evidence.positive_ip = positive_ip_;
    evidence.guard_ip = guard_ip_;
    evidence.holder_name = holder_name_;
    evidence.holder_id = recreated_holder_.id;
    evidence.image_id = recreated_holder_.image_id;
    evidence.holder_pid = recreated_holder_.pid;
    evidence.holder_start = recreated_holder_.start;
    evidence.exact_network_a =
        recreated_holder_.state >= HolderOnlyRecreationState::RunningExactNetworkA &&
        recreated_holder_.state != HolderOnlyRecreationState::Unresolved;
    evidence.exact_network_b =
        recreated_holder_.state >= HolderOnlyRecreationState::RunningExactNetworksAB &&
        recreated_holder_.state != HolderOnlyRecreationState::Unresolved;
    evidence.exact_security = recreated_holder_.state == HolderOnlyRecreationState::Validated;
    evidence.network_a_membership_proven_after_start =
        recreated_holder_.network_a_membership_proven_after_start;
    evidence.old_authority_frozen = holder_retirement_absence_.phase ==
                                    HeldNamespaceGenerationRotationPhase::OldGenerationAbsent;
    evidence.operation_ok = recreated_holder_.operation_ok;
    evidence.state_visit_mask = recreated_holder_.state_visit_mask;
    evidence.create_command_count = recreated_holder_.create_command_count;
    evidence.start_command_count = recreated_holder_.start_command_count;
    evidence.connect_b_command_count = recreated_holder_.connect_b_command_count;
    evidence.remove_command_count = recreated_holder_.remove_command_count;
    return evidence;
}

bool Fixture::cleanup_recreated_holder(std::string& error) {
    if (!recreated_holder_started_) return true;
    RecreatedHolderOwner& fresh = recreated_holder_;
    if (fresh.state == HolderOnlyRecreationState::Settled) return true;
    if (recreated_sidecar_started_ && recreated_sidecar_.state != RecreatedSidecarState::Settled) {
        if (!error.empty()) error += "; ";
        error += "refusing recreated holder cleanup before recreated sidecar settlement";
        return false;
    }
    if (fresh.state == HolderOnlyRecreationState::Unresolved || !full_container_id(fresh.id)) {
        if (!error.empty()) error += "; ";
        error += "recreated holder ownership is unresolved; refusing deletion/network release";
        return false;
    }
    HolderCleanupIdentity identity;
    std::string inspect_error;
    const bool present = inspect_holder_cleanup_identity(fresh.id, identity, inspect_error);
    const bool immutable_exact =
        present && identity.id == fresh.id && identity.name == holder_name_ &&
        identity.stage == "358-stage2a2" && identity.token == token_ &&
        identity.role == "holder-recreated" && identity.generation == "holder-only-1" &&
        identity.image_reference == RUT_PINNED_NGINX_IMAGE && identity.image_id == fresh.image_id &&
        identity.path == "/bin/sleep" && identity.arguments_json == "[\"infinity\"]" &&
        identity.read_only_root &&
        no_published_ports(identity.port_bindings_json, identity.network_ports_json) &&
        identity.capability_drop_json == "[\"ALL\"]" &&
        identity.security_options_json == "[\"no-new-privileges\"]" &&
        identity.exposed_ports_json != "null";
    if (!present && fresh.removal_may_have_mutated) {
        CommandResult name;
        if (!run_command(
                {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + holder_name_ + "$"},
                name) ||
            !exited_zero(name) || !trim(name.output).empty()) {
            transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
            error = "recreated holder removal recovery could not prove exact name absence";
            return false;
        }
    } else if (!immutable_exact) {
        transition_recreated_holder(HolderOnlyRecreationState::Unresolved);
        error = "recreated holder cleanup immutable identity changed; refusing deletion";
        return false;
    }
    if (present) {
        transition_recreated_holder(HolderOnlyRecreationState::RemovalMayHaveMutated);
        fresh.removal_may_have_mutated = true;
        ++fresh.remove_command_count;
        CommandResult removal;
        const bool removal_ok = run_command(
            {"docker", "rm", "-f", fresh.id},
            removal,
            15000,
            fresh.failure_point == HolderOnlyRecreationFailurePoint::CleanupReportedTimeout);
        if ((!removal_ok || !exited_zero(removal)) && !removal.timed_out) {
            fresh.operation_ok = false;
            error = "recreated holder exact-ID removal did not settle";
            return false;
        }
        if (removal.timed_out) fresh.operation_ok = false;
    }
    CommandResult id_absence;
    CommandResult name_absence;
    if (!run_command({"docker", "ps", "-aq", "--no-trunc", "--filter", "id=" + fresh.id},
                     id_absence) ||
        !exited_zero(id_absence) || !trim(id_absence.output).empty() ||
        !run_command(
            {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + holder_name_ + "$"},
            name_absence) ||
        !exited_zero(name_absence) || !trim(name_absence.output).empty()) {
        error = "recreated holder exact ID/name absence proof failed";
        return false;
    }
    if (fresh.pid > 1 && fresh.start != 0u) {
        ProcIdentity process{};
        if (proc_identity(fresh.pid, process, false) && process.start == fresh.start) {
            error = "recreated holder PID/start witness remains after removal";
            return false;
        }
    }
    fresh.removal_may_have_mutated = false;
    if (!verify_retained_networks_after_holder(inspect_error)) {
        error = "recreated holder cleanup did not retain exact empty networks: " + inspect_error;
        return false;
    }
    transition_recreated_holder(HolderOnlyRecreationState::Settled);
    fresh.frozen_evidence = {};
    fresh.frozen_evidence = holder_only_recreation_evidence();
    return true;
}

void Fixture::transition_recreated_sidecar(RecreatedSidecarState state) {
    (void)recreated_sidecar_transition(recreated_sidecar_, state);
}

bool Fixture::build_current_generation_topology(HeldTopologySnapshot& topology,
                                                std::string& error) {
    if (!holder_exists_ || cleanup_progress_ != CleanupProgress::Active ||
        !full_container_id(holder_id_) || holder_pid_ <= 1 || holder_start_ == 0u ||
        !validate_holder(error) || !verify_topology(FailurePoint::None, error) ||
        !verify_network(network_a_, error) || !verify_network(network_b_, error)) {
        if (error.empty())
            error = "old-generation topology lacked validated holder/network authority";
        return false;
    }

    ProcIdentity before{};
    ProcIdentity host{};
    ino_t before_container_netns = 0;
    const bool before_ok = proc_identity(holder_pid_, before, false);
    const bool container_netns_ok = container_netns_inode(holder_id_, before_container_netns);
    // Host netns visibility is optional. Exact-container readlink is the
    // authoritative namespace witness; compare the host inode when visible.
    const bool host_ok = proc_identity(getpid(), host, false);
    if (!before_ok || before.start != holder_start_ || !container_netns_ok ||
        before_container_netns == 0u || !host_ok ||
        (host.netns != 0u && before_container_netns == host.netns) ||
        (before.netns != 0u && before.netns != before_container_netns)) {
        error = "old-generation PID/start/netns authority mismatch";
        return false;
    }

    static constexpr u16 kProbePort = 41857;
    std::string tcp;
    std::string tcp6;
    if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/tcp", tcp) ||
        !read_file("/proc/" + std::to_string(holder_pid_) + "/net/tcp6", tcp6) ||
        !proc_tcp_port_absent(tcp, kProbePort) || !proc_tcp_port_absent(tcp6, kProbePort)) {
        error = "old-generation PID-scoped tcp/tcp6 selected-port absence probe failed";
        return false;
    }
    HeldTopologyProbeEvidence probe;
    probe.policy = HeldTopologyProbePolicy::RequireHostRefusalProbes;
    ++probe.selected_port_absence_checks;
    for (const std::string* address : {&positive_ip_, &guard_ip_}) {
        ++probe.host_parent_af_inet_socket_calls;
        if (!probe_refused(*address, kProbePort, error)) return false;
        ++probe.successful_refusal_probes;
    }

    ProcIdentity after{};
    ProcIdentity after_host{};
    ino_t after_container_netns = 0;
    const bool after_ok = proc_identity(holder_pid_, after, false);
    const bool after_container_netns_ok = container_netns_inode(holder_id_, after_container_netns);
    const bool after_host_ok = proc_identity(getpid(), after_host, false);
    if (!after_ok || after.start != holder_start_ || !after_container_netns_ok ||
        after_container_netns != before_container_netns || !after_host_ok ||
        (after_host.netns != 0u && after_container_netns == after_host.netns) ||
        (after.netns != 0u && after.netns != after_container_netns)) {
        error = "old-generation PID/start/netns changed across read-only topology probes";
        return false;
    }
    std::string probe_error;
    if (!validate_held_topology_probe_evidence(
            probe, HeldTopologyProbePolicy::RequireHostRefusalProbes, probe_error)) {
        error = probe_error;
        return false;
    }

    topology = {};
    topology.token = token_;
    topology.network_a_name = network_a_.name;
    topology.network_a_id = network_a_.id;
    topology.network_a_subnet = network_a_.subnet;
    topology.network_a_gateway = network_a_.gateway;
    topology.network_b_name = network_b_.name;
    topology.network_b_id = network_b_.id;
    topology.network_b_subnet = network_b_.subnet;
    topology.network_b_gateway = network_b_.gateway;
    topology.holder_name = holder_name_;
    topology.holder_id = holder_id_;
    topology.positive_ip = positive_ip_;
    topology.guard_ip = guard_ip_;
    topology.holder_pid = holder_pid_;
    topology.holder_start = holder_start_;
    topology.holder_netns = before_container_netns;
    topology.probe_evidence = probe;
    return true;
}

bool Fixture::build_recreated_holder_topology(HeldTopologySnapshot& topology, std::string& error) {
    const RecreatedHolderOwner& holder = recreated_holder_;
    if (!recreated_holder_started_ || holder.state != HolderOnlyRecreationState::Validated ||
        !full_container_id(holder.id) || holder.pid <= 1 || holder.start == 0u ||
        !verify_network(network_a_, error) || !verify_network(network_b_, error)) {
        if (error.empty()) error = "fresh-holder probe lacked validated holder/network authority";
        return false;
    }
    HolderCleanupIdentity identity;
    if (!inspect_holder_cleanup_identity(holder.id, identity, error) || identity.id != holder.id ||
        identity.name != holder_name_ || identity.stage != "358-stage2a2" ||
        identity.token != token_ || identity.role != "holder-recreated" ||
        identity.generation != "holder-only-1" || !identity.running || identity.pid != holder.pid ||
        identity.image_reference != RUT_PINNED_NGINX_IMAGE ||
        identity.image_id != holder.image_id || identity.path != "/bin/sleep" ||
        identity.arguments_json != "[\"infinity\"]" || !identity.read_only_root ||
        !no_published_ports(identity.port_bindings_json, identity.network_ports_json) ||
        identity.capability_drop_json != "[\"ALL\"]" ||
        identity.security_options_json != "[\"no-new-privileges\"]" ||
        identity.exposed_ports_json == "null") {
        if (error.empty()) error = "fresh holder immutable running identity was not exact";
        return false;
    }
    ProcIdentity before{};
    ProcIdentity host{};
    ino_t before_container_netns = 0;
    // The host may expose /proc/<pid>/stat while denying its ns/net symlink.
    // Bracket netns with the same exact-container readlink source on both sides,
    // and cross-check the host inode whenever proc_identity could observe it.
    const bool before_ok = proc_identity(holder.pid, before, false);
    const bool container_netns_ok = container_netns_inode(holder.id, before_container_netns);
    const bool host_ok = proc_identity(getpid(), host, false);
    if (!before_ok || before.start != holder.start || !container_netns_ok || !host_ok ||
        before_container_netns == 0u ||
        (host.netns != 0u && before_container_netns == host.netns) ||
        (before.netns != 0u && before.netns != before_container_netns)) {
        error = "fresh holder initial PID/start/netns authority mismatch: pid=" +
                std::to_string(holder.pid) + " expected-start=" + std::to_string(holder.start) +
                " observed-start=" + std::to_string(before.start) +
                " proc-netns=" + std::to_string(before.netns) +
                " container-netns=" + std::to_string(before_container_netns) +
                " host-netns=" + std::to_string(host.netns) +
                " before-ok=" + std::to_string(before_ok ? 1 : 0) +
                " container-netns-ok=" + std::to_string(container_netns_ok ? 1 : 0) +
                " host-ok=" + std::to_string(host_ok ? 1 : 0) +
                " host-netns-visible=" + std::to_string(host.netns != 0u ? 1 : 0);
        return false;
    }

    CommandResult endpoints;
    if (!run_command({"docker",
                      "inspect",
                      "-f",
                      "{{range $name,$v := .NetworkSettings.Networks}}{{$name}}|{{"
                      "$v.NetworkID}}|{{$v.IPAddress}}|{{$v.Gateway}} {{end}}",
                      holder.id},
                     endpoints) ||
        !exited_zero(endpoints)) {
        error = "fresh holder A+B endpoint inspection failed";
        return false;
    }
    std::istringstream endpoint_fields(trim(endpoints.output));
    std::vector<Endpoint> actual;
    std::string endpoint;
    while (endpoint_fields >> endpoint) {
        std::vector<std::string> parts;
        if (!split_exact(endpoint, '|', 4, parts)) {
            error = "fresh holder endpoint record was malformed";
            return false;
        }
        const Network* network = parts[0] == network_a_.name
                                     ? &network_a_
                                     : (parts[0] == network_b_.name ? &network_b_ : nullptr);
        if (network == nullptr) {
            error = "fresh holder exposed an unexpected endpoint";
            return false;
        }
        actual.push_back({parts[0],
                          parts[1],
                          parts[2],
                          parts[2] + network->subnet.substr(network->subnet.find('/')),
                          parts[3]});
    }
    const std::vector<Endpoint> expected = {
        {network_a_.name,
         network_a_.id,
         positive_ip_,
         positive_ip_ + network_a_.subnet.substr(network_a_.subnet.find('/')),
         network_a_.gateway},
        {network_b_.name,
         network_b_.id,
         guard_ip_,
         guard_ip_ + network_b_.subnet.substr(network_b_.subnet.find('/')),
         network_b_.gateway}};
    if (!endpoint_set_equal(expected, actual)) {
        error = "fresh holder active A+B endpoint set was not exact";
        return false;
    }
    for (const auto& expected_endpoint : expected) {
        const Network& network =
            expected_endpoint.network_name == network_a_.name ? network_a_ : network_b_;
        CommandResult reverse;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{.Id}}|{{.Name}} {{range $id,$v := .Containers}}{{$id}}|{{"
                          "$v.Name}}|{{$v.IPv4Address}} {{end}}",
                          network.id},
                         reverse) ||
            !exited_zero(reverse)) {
            error = "fresh holder reverse membership inspection failed";
            return false;
        }
        std::istringstream reverse_fields(trim(reverse.output));
        std::string header;
        std::string member;
        std::vector<std::string> header_parts;
        std::vector<std::string> member_parts;
        if (!(reverse_fields >> header) || !split_exact(header, '|', 2, header_parts) ||
            header_parts[0] != network.id || header_parts[1] != network.name ||
            !(reverse_fields >> member) || !split_exact(member, '|', 3, member_parts) ||
            member_parts[0] != holder.id || member_parts[1] != holder_name_ ||
            member_parts[2] != expected_endpoint.cidr || (reverse_fields >> member)) {
            error = "fresh holder reverse membership was not exactly singleton";
            return false;
        }
    }

    static constexpr u16 kProbePort = 41857;
    std::string tcp;
    std::string tcp6;
    if (!read_file("/proc/" + std::to_string(holder.pid) + "/net/tcp", tcp) ||
        !read_file("/proc/" + std::to_string(holder.pid) + "/net/tcp6", tcp6) ||
        !proc_tcp_port_absent(tcp, kProbePort) || !proc_tcp_port_absent(tcp6, kProbePort)) {
        error = "fresh holder PID-scoped tcp/tcp6 selected-port absence probe failed";
        return false;
    }
    HeldTopologyProbeEvidence probe;
    probe.policy = HeldTopologyProbePolicy::RequireHostRefusalProbes;
    ++probe.selected_port_absence_checks;
    for (const std::string* address : {&positive_ip_, &guard_ip_}) {
        ++probe.host_parent_af_inet_socket_calls;
        if (!probe_refused(*address, kProbePort, error)) return false;
        ++probe.successful_refusal_probes;
    }
    ProcIdentity after{};
    const bool after_ok = proc_identity(holder.pid, after, false);
    ino_t after_container_netns = 0;
    const bool after_container_netns_ok = container_netns_inode(holder.id, after_container_netns);
    if (!after_ok || after.start != holder.start || !after_container_netns_ok ||
        after_container_netns != before_container_netns ||
        (after.netns != 0u && after.netns != after_container_netns)) {
        error = "fresh holder PID/start/netns changed across read-only topology probes: pid=" +
                std::to_string(holder.pid) + " expected-start=" + std::to_string(holder.start) +
                " before-start=" + std::to_string(before.start) +
                " after-start=" + std::to_string(after.start) +
                " before-netns=" + std::to_string(before_container_netns) +
                " after-netns=" + std::to_string(after_container_netns) +
                " before-proc-netns=" + std::to_string(before.netns) +
                " after-proc-netns=" + std::to_string(after.netns) +
                " after-ok=" + std::to_string(after_ok ? 1 : 0) +
                " after-container-netns-ok=" + std::to_string(after_container_netns_ok ? 1 : 0);
        return false;
    }
    std::string probe_error;
    if (!validate_held_topology_probe_evidence(
            probe, HeldTopologyProbePolicy::RequireHostRefusalProbes, probe_error)) {
        error = probe_error;
        return false;
    }
    topology = {};
    topology.token = token_;
    topology.network_a_name = network_a_.name;
    topology.network_a_id = network_a_.id;
    topology.network_a_subnet = network_a_.subnet;
    topology.network_a_gateway = network_a_.gateway;
    topology.network_b_name = network_b_.name;
    topology.network_b_id = network_b_.id;
    topology.network_b_subnet = network_b_.subnet;
    topology.network_b_gateway = network_b_.gateway;
    topology.holder_name = holder_name_;
    topology.holder_id = holder.id;
    topology.positive_ip = positive_ip_;
    topology.guard_ip = guard_ip_;
    topology.holder_pid = holder.pid;
    topology.holder_start = holder.start;
    topology.holder_netns = before_container_netns;
    topology.probe_evidence = probe;
    return true;
}

bool Fixture::recreate_sidecar(RecreatedSidecarFailurePoint failure_point, std::string& error) {
    error.clear();
    if (recreated_sidecar_started_ || cleanup_progress_ != CleanupProgress::HolderSettled ||
        recreated_holder_.state != HolderOnlyRecreationState::Validated) {
        error = "fresh sidecar recreation lacked separate validated-holder authority";
        return false;
    }
    const auto exact_absence = [](const HeldNamespaceGenerationWitnessAbsence& witness) {
        return full_container_id(witness.container_id) && witness.pid > 1 && witness.start != 0u &&
               witness.container_id_absent && witness.process_identity_absent;
    };
    if (holder_retirement_absence_.phase !=
            HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
        !exact_absence(holder_retirement_absence_.holder) ||
        !exact_absence(holder_retirement_absence_.sidecar) ||
        holder_retirement_absence_.sidecar_name != sidecar_name_ ||
        !holder_retirement_absence_.sidecar_name_absent) {
        error = "fresh sidecar recreation lacked frozen old-sidecar ID/name/PID/start absence";
        return false;
    }
    HeldTopologySnapshot fresh_topology;
    if (!build_recreated_holder_topology(fresh_topology, error)) return false;
    CommandResult collision;
    if (!run_command(
            {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + sidecar_name_ + "$"},
            collision) ||
        !exited_zero(collision) || !trim(collision.output).empty()) {
        error = "fresh sidecar stable-name collision was rejected before create";
        return false;
    }

    recreated_sidecar_started_ = true;
    RecreatedSidecarOwner& fresh = recreated_sidecar_;
    fresh.failure_point = failure_point;
    fresh.topology = fresh_topology;
    transition_recreated_sidecar(RecreatedSidecarState::CreateMayHaveMutated);
    fresh.create_may_have_mutated = true;
    const auto prove_no_object = [&]() {
        CommandResult absent;
        return run_command({"docker",
                            "ps",
                            "-aq",
                            "--no-trunc",
                            "--filter",
                            "name=^/" + sidecar_name_ + "$"},
                           absent) &&
               exited_zero(absent) && trim(absent.output).empty() &&
               run_command({"docker",
                            "ps",
                            "-aq",
                            "--no-trunc",
                            "--filter",
                            "label=rut.token=" + token_,
                            "--filter",
                            std::string("label=rut.role=") + kSidecarRole},
                           absent) &&
               exited_zero(absent) && trim(absent.output).empty();
    };
    if (failure_point == RecreatedSidecarFailurePoint::CreateSuppressedNoObject) {
        fresh.operation_ok = false;
        if (!prove_no_object()) {
            transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
            error = "suppressed fresh sidecar create could not prove no Docker object";
            return false;
        }
        fresh.create_may_have_mutated = false;
        transition_recreated_sidecar(RecreatedSidecarState::Settled);
        fresh.frozen_evidence = recreated_sidecar_evidence();
        error = "injected fresh sidecar create suppression with no Docker object";
        return false;
    }

    std::vector<std::string> argv = {"docker",
                                     "run",
                                     "--pull=never",
                                     "--detach",
                                     "--name",
                                     sidecar_name_,
                                     "--network",
                                     "container:" + recreated_holder_.id,
                                     "--cap-drop",
                                     "ALL",
                                     "--security-opt",
                                     "no-new-privileges",
                                     "--read-only",
                                     "--tmpfs",
                                     "/tmp:rw,noexec,nosuid,size=1m",
                                     "--entrypoint",
                                     "/bin/sleep",
                                     "--label",
                                     std::string("rut.stage=") + kSidecarStage,
                                     "--label",
                                     "rut.token=" + token_,
                                     "--label",
                                     std::string("rut.role=") + kSidecarRole,
                                     RUT_PINNED_NGINX_IMAGE,
                                     "infinity"};
    ++fresh.create_command_count;
    CommandResult create;
    const bool create_ok = run_command(
        argv, create, 15000, failure_point == RecreatedSidecarFailurePoint::CreateReportedTimeout);
    std::string reference = trim(create.output);
    if (!full_container_id(reference)) reference = sidecar_name_;
    HeldNamespaceSidecarSnapshot snapshot;
    std::string inspect_error;
    const bool inspected = inspect_sidecar(reference, snapshot, inspect_error);
    if (!inspected && !create_ok && !create.timed_out && prove_no_object()) {
        fresh.operation_ok = false;
        fresh.create_may_have_mutated = false;
        transition_recreated_sidecar(RecreatedSidecarState::Settled);
        fresh.frozen_evidence = recreated_sidecar_evidence();
        error = "fresh sidecar create failed with no Docker object";
        return false;
    }
    if (!inspected) {
        transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
        fresh.operation_ok = false;
        error = "fresh sidecar create outcome could not be adopted exactly";
        if (!inspect_error.empty()) error += ": " + inspect_error;
        return false;
    }
    fresh.snapshot = snapshot;
    const bool immutable_config =
        full_container_id(snapshot.id) && snapshot.id != recreated_holder_.id &&
        snapshot.id != holder_retirement_absence_.holder.container_id &&
        snapshot.id != holder_retirement_absence_.sidecar.container_id &&
        snapshot.name == sidecar_name_ && snapshot.token == token_ &&
        snapshot.stage == kSidecarStage && snapshot.role == kSidecarRole &&
        snapshot.pinned_image_reference == RUT_PINNED_NGINX_IMAGE &&
        snapshot.expected_image_id == recreated_holder_.image_id &&
        snapshot.image_id == recreated_holder_.image_id &&
        snapshot.network_mode == "container:" + recreated_holder_.id &&
        snapshot.path == "/bin/sleep" && snapshot.arguments_json == "[\"infinity\"]" &&
        snapshot.read_only_root && snapshot.capability_drop_all && snapshot.no_new_privileges &&
        snapshot.no_published_ports;
    if (!create_ok && !create.timed_out && immutable_config && !snapshot.running &&
        snapshot.pid == 0) {
        fresh.operation_ok = false;
        fresh.create_may_have_mutated = false;
        transition_recreated_sidecar(RecreatedSidecarState::CreatedExactCleanupOnly);
        error = "fresh sidecar create failed after exact stopped object creation; cleanup-only";
        return false;
    }
    const bool distinct_process =
        !(snapshot.pid == recreated_holder_.pid && snapshot.start == recreated_holder_.start) &&
        !(snapshot.pid == holder_retirement_absence_.holder.pid &&
          snapshot.start == holder_retirement_absence_.holder.start) &&
        !(snapshot.pid == holder_retirement_absence_.sidecar.pid &&
          snapshot.start == holder_retirement_absence_.sidecar.start);
    std::string semantic_error;
    if (!immutable_config || !snapshot.running || snapshot.pid <= 1 || snapshot.start == 0u ||
        !distinct_process || snapshot.netns != fresh_topology.holder_netns ||
        snapshot.netns == snapshot.host_netns ||
        !validate_held_namespace_sidecar_snapshot(fresh_topology, snapshot, semantic_error)) {
        transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
        fresh.operation_ok = false;
        error = "fresh sidecar exact identity/config/netns validation failed";
        if (!semantic_error.empty()) error += ": " + semantic_error;
        return false;
    }
    CommandResult unique;
    if (!run_command({"docker",
                      "ps",
                      "-aq",
                      "--no-trunc",
                      "--filter",
                      "label=rut.token=" + token_,
                      "--filter",
                      std::string("label=rut.role=") + kSidecarRole},
                     unique) ||
        !exited_zero(unique) || trim(unique.output) != snapshot.id) {
        transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
        fresh.operation_ok = false;
        error = "fresh sidecar token/role cardinality was not exactly one";
        return false;
    }
    fresh.create_may_have_mutated = false;
    transition_recreated_sidecar(RecreatedSidecarState::CreatedExactCleanupOnly);
    if (create.timed_out) fresh.operation_ok = false;
    transition_recreated_sidecar(RecreatedSidecarState::Validated);
    if (failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation)
        fresh.cleanup_identity_fault = true;
    if (failure_point == RecreatedSidecarFailurePoint::SuppressFirstRemoval)
        fresh.removal_suppression_armed = true;
    if (failure_point == RecreatedSidecarFailurePoint::UnexpectedDeath)
        return terminate_recreated_sidecar_unexpectedly(error);
    return true;
}

bool Fixture::revalidate_recreated_sidecar_for_rotation(HeldNamespaceSidecarSnapshot& snapshot,
                                                        bool inject_mutation,
                                                        std::string& error) {
    if (!recreated_sidecar_started_ ||
        recreated_sidecar_.state != RecreatedSidecarState::Validated ||
        !full_container_id(recreated_sidecar_.snapshot.id)) {
        error = "fresh sidecar lacked exact validated authority for the second receipt bracket";
        return false;
    }
    HeldNamespaceSidecarSnapshot current;
    const HeldNamespaceSidecarRevalidationFault previous_fault = sidecar_revalidation_fault_;
    sidecar_revalidation_fault_ = inject_mutation
                                      ? HeldNamespaceSidecarRevalidationFault::NetworkMode
                                      : HeldNamespaceSidecarRevalidationFault::None;
    const bool inspected = inspect_sidecar(recreated_sidecar_.snapshot.id, current, error);
    sidecar_revalidation_fault_ = previous_fault;
    if (!inspected) return false;
    ino_t exact_netns = 0;
    if (!container_netns_inode(recreated_sidecar_.snapshot.id, exact_netns) || exact_netns == 0u ||
        exact_netns != current.netns) {
        error = "fresh sidecar second bracket lacked exact full-ID netns authority";
        return false;
    }
    current.netns = exact_netns;
    std::string semantic_error;
    if (!validate_held_namespace_sidecar_snapshot(
            recreated_sidecar_.topology, current, semantic_error) ||
        !sidecar_snapshot_equal(current, recreated_sidecar_.snapshot)) {
        error = "fresh sidecar second receipt bracket differed from exact authority";
        if (!semantic_error.empty()) error += ": " + semantic_error;
        return false;
    }
    snapshot = current;
    return true;
}

bool Fixture::terminate_recreated_sidecar_unexpectedly(std::string& error) {
    RecreatedSidecarOwner& fresh = recreated_sidecar_;
    if (!recreated_sidecar_started_ || fresh.state != RecreatedSidecarState::Validated ||
        !full_container_id(fresh.snapshot.id)) {
        error = "fresh sidecar death injection lacked exact validated identity";
        return false;
    }
    CommandResult killed;
    if (!run_command({"docker", "kill", fresh.snapshot.id}, killed) || !exited_zero(killed)) {
        error = "fresh sidecar death injection failed";
        return false;
    }
    HeldNamespaceSidecarSnapshot stopped;
    std::string inspect_error;
    if (!inspect_sidecar(fresh.snapshot.id, stopped, inspect_error) ||
        !sidecar_stopped_identity_equal(stopped, fresh.snapshot)) {
        transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
        error = "fresh sidecar death did not yield exact stopped cleanup authority";
        return false;
    }
    ProcIdentity process{};
    if (proc_identity(fresh.snapshot.pid, process, false) &&
        process.start == fresh.snapshot.start) {
        transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
        error = "fresh sidecar death retained its PID/start witness";
        return false;
    }
    fresh.operation_ok = false;
    transition_recreated_sidecar(RecreatedSidecarState::StoppedExactCleanupOnly);
    error = "injected fresh sidecar unexpected death; exact stopped identity is cleanup-only";
    return false;
}

RecreatedSidecarEvidence Fixture::recreated_sidecar_evidence() const {
    if (recreated_sidecar_.state == RecreatedSidecarState::Settled &&
        recreated_sidecar_.frozen_evidence.state == RecreatedSidecarState::Settled)
        return recreated_sidecar_.frozen_evidence;
    RecreatedSidecarEvidence evidence;
    evidence.complete_generation = false;
    evidence.state = recreated_sidecar_.state;
    evidence.old_absence = holder_retirement_absence_;
    evidence.holder = holder_only_recreation_evidence();
    evidence.fresh_topology = recreated_sidecar_.topology;
    evidence.sidecar = recreated_sidecar_.snapshot;
    evidence.fresh_probe_pid_start_scoped =
        recreated_sidecar_.topology.holder_pid == recreated_holder_.pid &&
        recreated_sidecar_.topology.holder_start == recreated_holder_.start &&
        recreated_sidecar_.topology.probe_evidence.selected_port_absence_checks == 1u;
    evidence.shared_non_host_netns =
        recreated_sidecar_.snapshot.netns != 0u &&
        recreated_sidecar_.snapshot.netns == recreated_sidecar_.topology.holder_netns &&
        recreated_sidecar_.snapshot.netns != recreated_sidecar_.snapshot.host_netns;
    evidence.operation_ok = recreated_sidecar_.operation_ok;
    evidence.state_visit_mask = recreated_sidecar_.state_visit_mask;
    evidence.create_command_count = recreated_sidecar_.create_command_count;
    evidence.remove_command_count = recreated_sidecar_.remove_command_count;
    evidence.remove_suppression_count = recreated_sidecar_.remove_suppression_count;
    return evidence;
}

bool Fixture::cleanup_recreated_sidecar(std::string& error) {
    if (!recreated_sidecar_started_) return true;
    RecreatedSidecarOwner& fresh = recreated_sidecar_;
    if (fresh.state == RecreatedSidecarState::Settled) return true;
    if (fresh.state == RecreatedSidecarState::Unresolved || !full_container_id(fresh.snapshot.id)) {
        if (!error.empty()) error += "; ";
        error += "fresh sidecar ownership is unresolved; refusing downstream cleanup";
        return false;
    }
    HeldNamespaceSidecarSnapshot current;
    std::string inspect_error;
    const bool present = inspect_sidecar(fresh.snapshot.id, current, inspect_error);
    const auto prove_absent = [&]() {
        CommandResult absent;
        if (!run_command({"docker", "inspect", fresh.snapshot.id}, absent) || exited_zero(absent) ||
            !run_command(
                {"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + sidecar_name_ + "$"},
                absent) ||
            !exited_zero(absent) || !trim(absent.output).empty() ||
            !run_command({"docker",
                          "ps",
                          "-aq",
                          "--no-trunc",
                          "--filter",
                          "label=rut.token=" + token_,
                          "--filter",
                          std::string("label=rut.role=") + kSidecarRole},
                         absent) ||
            !exited_zero(absent) || !trim(absent.output).empty())
            return false;
        ProcIdentity process{};
        return !proc_identity(fresh.snapshot.pid, process, false) ||
               process.start != fresh.snapshot.start;
    };
    if (!present) {
        if (!fresh.removal_may_have_mutated || !prove_absent()) {
            transition_recreated_sidecar(RecreatedSidecarState::Unresolved);
            error = "fresh sidecar absence lacked exact removal authority";
            return false;
        }
    } else {
        if (fresh.cleanup_identity_fault) current.network_mode = "bridge";
        std::string semantic_error;
        const bool running_exact =
            validate_held_namespace_sidecar_snapshot(fresh.topology, current, semantic_error) &&
            sidecar_snapshot_equal(current, fresh.snapshot);
        const bool stopped_exact = sidecar_stopped_identity_equal(current, fresh.snapshot);
        if (!running_exact && !stopped_exact) {
            error = "fresh sidecar cleanup identity/config/netns mutation was rejected";
            return false;
        }
        if (fresh.removal_suppression_armed && !fresh.removal_suppression_consumed) {
            fresh.removal_suppression_armed = false;
            fresh.removal_suppression_consumed = true;
            fresh.removal_may_have_mutated = true;
            fresh.operation_ok = false;
            ++fresh.remove_suppression_count;
            transition_recreated_sidecar(RecreatedSidecarState::RemovalMayHaveMutated);
            error = "injected fresh sidecar removal suppression with exact object retained";
            return false;
        }
        transition_recreated_sidecar(RecreatedSidecarState::RemovalMayHaveMutated);
        fresh.removal_may_have_mutated = true;
        ++fresh.remove_command_count;
        CommandResult removal;
        const bool removal_ok = run_command(
            {"docker", "rm", "-f", fresh.snapshot.id},
            removal,
            15000,
            fresh.failure_point == RecreatedSidecarFailurePoint::CleanupReportedTimeout);
        if ((!removal_ok || !exited_zero(removal)) && !removal.timed_out) {
            fresh.operation_ok = false;
            error = "fresh sidecar exact-ID removal failed";
            return false;
        }
        if (removal.timed_out) fresh.operation_ok = false;
        if (!prove_absent()) {
            error = "fresh sidecar exact ID/name/process absence proof failed";
            return false;
        }
    }
    fresh.removal_may_have_mutated = false;
    transition_recreated_sidecar(RecreatedSidecarState::Settled);
    fresh.frozen_evidence = {};
    fresh.frozen_evidence = recreated_sidecar_evidence();
    return true;
}

static bool write_manifest(const TempDir& temp, const Fixture& fixture) {
    const int fd = open(temp.manifest.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const std::string contents =
        "token=" + fixture.token() + "\nnetwork_a=" + fixture.network_a().name +
        "\nnetwork_b=" + fixture.network_b().name + "\nholder=" + fixture.holder_name() +
        "\nsidecar=" + fixture.sidecar_name() + "\n";
    size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = write(fd, contents.data() + offset, contents.size() - offset);
        if (count > 0)
            offset += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else {
            close(fd);
            return false;
        }
    }
    return close(fd) == 0;
}

static bool preflight(Fixture& fixture, std::string& error) {
#ifndef __linux__
    error = "Linux is required";
    return false;
#else
    CommandResult result;
    if (!run_command({"docker", "info"}, result) || !exited_zero(result)) {
        error = "Docker daemon/permissions unavailable: " + trim(result.output);
        return false;
    }
    if (!run_command({"docker", "image", "inspect", "-f", "{{.Id}}", RUT_PINNED_NGINX_IMAGE},
                     result) ||
        !exited_zero(result)) {
        error = "exact pinned image unavailable: " + trim(result.output);
        return false;
    }
    const std::string expected_image_id = trim(result.output);
    if (!sha256_identity(expected_image_id) ||
        result.output.find('\n') != result.output.rfind('\n')) {
        error = "pinned image inspection did not return one full sha256 image ID";
        return false;
    }
    fixture.set_expected_sidecar_image_id(expected_image_id);
    std::string ip_path;
    for (const char* candidate : {"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"})
        if (access(candidate, X_OK) == 0) {
            ip_path = candidate;
            break;
        }
    if (ip_path.empty()) {
        error = "host ip capability is unavailable";
        return false;
    }
    for (const std::string& name : {fixture.network_a().name,
                                    fixture.network_b().name,
                                    fixture.holder_name(),
                                    fixture.sidecar_name()}) {
        if (run_command({"docker", "inspect", name}, result) && exited_zero(result)) {
            error = "exact target name already exists: " + name;
            return false;
        }
    }
    std::vector<IPv4Range> conflicts;
    if (!collect_ipv4_conflicts(ip_path, conflicts, error)) return false;
    SubnetPlan plan;
    if (!select_subnet_plan(conflicts, subnet_candidates(), plan)) {
        error = "no collision-free RFC1918 /28 topology subnet pair is available";
        return false;
    }
    if (!fixture.set_subnet_plan(plan)) {
        error = "selected topology subnet pair failed exact plan validation";
        return false;
    }
    return true;
#endif
}

struct ParsedMount {
    std::string type;
    std::string source;
    std::string destination;
    std::string mode;
    std::string propagation;
    bool read_only = false;
};

struct ParsedMountInspect {
    std::string id;
    std::string name;
    std::string user;
    std::string network_mode;
    std::vector<ParsedMount> requested;
    std::vector<ParsedMount> realized;
};

static bool decimal_size(const std::string& text, size_t& value) {
    if (text.empty() || (text.size() > 1 && text[0] == '0') ||
        !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
        return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = strtoull(text.c_str(), &end, 10);
    if (errno == ERANGE || end == text.c_str() || *end != '\0' ||
        parsed > std::numeric_limits<size_t>::max())
        return false;
    value = static_cast<size_t>(parsed);
    return true;
}

static bool split_mount_list(const std::string& text,
                             bool requested,
                             std::vector<ParsedMount>& mounts,
                             std::string& error) {
    mounts.clear();
    if (text.empty()) return true;
    size_t begin = 0;
    while (begin < text.size()) {
        const size_t end = text.find(';', begin);
        if (end == std::string::npos || end == begin) {
            error = "mount inspection list lacked exact record terminator";
            return false;
        }
        std::vector<std::string> fields;
        if (!split_exact(text.substr(begin, end - begin), '|', requested ? 5u : 6u, fields)) {
            error = "mount inspection record field count was not exact";
            return false;
        }
        bool boolean = false;
        const size_t bool_index = requested ? 3u : 4u;
        if (!parse_exact_bool(fields[bool_index], boolean)) {
            error = "mount inspection read-only field was malformed";
            return false;
        }
        ParsedMount mount;
        mount.type = fields[0];
        mount.source = fields[1];
        mount.destination = fields[2];
        mount.mode = requested ? std::string{} : fields[3];
        mount.read_only = requested ? boolean : !boolean;
        mount.propagation = fields[requested ? 4u : 5u];
        mounts.push_back(std::move(mount));
        begin = end + 1;
    }
    return true;
}

static bool path_shadows(const std::string& candidate, const std::string& target) {
    if (candidate == target) return true;
    if (candidate == "/") return true;
    const auto ancestor = [](const std::string& left, const std::string& right) {
        return left.size() < right.size() && right.compare(0, left.size(), left) == 0 &&
               left.back() != '/' && right[left.size()] == '/';
    };
    return ancestor(candidate, target) || ancestor(target, candidate);
}

static bool canonical_absolute_mount_destination(const std::string& path) {
    if (path.empty() || path[0] != '/' || (path.size() > 1u && path.back() == '/')) return false;
    size_t begin = 1u;
    while (begin < path.size()) {
        const size_t end = path.find('/', begin);
        const size_t length = (end == std::string::npos ? path.size() : end) - begin;
        if (length == 0u || (length == 1u && path[begin] == '.') ||
            (length == 2u && path[begin] == '.' && path[begin + 1u] == '.'))
            return false;
        if (end == std::string::npos) break;
        begin = end + 1u;
    }
    return true;
}

static bool validate_mount_inspect_record(const std::string& record,
                                          const std::string& expected_id,
                                          const std::string& expected_name,
                                          const std::string& expected_user,
                                          const std::string& expected_network_mode,
                                          const std::string& expected_source,
                                          ParsedMountInspect& parsed,
                                          std::string& error) {
    const size_t first = record.find('#');
    const size_t second = first == std::string::npos ? first : record.find('#', first + 1);
    if (first == std::string::npos || second == std::string::npos ||
        record.find('#', second + 1) != std::string::npos) {
        error = "mount inspect envelope was malformed";
        return false;
    }
    std::vector<std::string> prefix;
    if (!split_exact(record.substr(0, first), '|', 5, prefix)) {
        error = "mount inspect identity prefix was malformed";
        return false;
    }
    size_t requested_count = 0;
    if (!decimal_size(prefix[4], requested_count) || requested_count != 1u) {
        error = "HostConfig requested mount cardinality was not exactly one";
        return false;
    }
    parsed = {};
    parsed.id = prefix[0];
    parsed.name = prefix[1].size() > 1 && prefix[1][0] == '/' ? prefix[1].substr(1) : prefix[1];
    parsed.user = prefix[2];
    parsed.network_mode = prefix[3];
    if (parsed.id != expected_id || parsed.name != expected_name || parsed.user != expected_user ||
        parsed.network_mode != expected_network_mode) {
        error = "mount inspect container identity/user/network mode changed";
        return false;
    }
    if (!split_mount_list(
            record.substr(first + 1, second - first - 1), true, parsed.requested, error) ||
        !split_mount_list(record.substr(second + 1), false, parsed.realized, error) ||
        parsed.requested.size() != requested_count) {
        if (error.empty()) error = "requested mount record cardinality differed from typed count";
        return false;
    }
    const ParsedMount& requested = parsed.requested.front();
    if (requested.type != "bind" || requested.source != expected_source ||
        requested.destination != kExactInputMountDestination || !requested.read_only ||
        requested.propagation != "rprivate") {
        error = "requested HostConfig bind mount semantics were not exact";
        return false;
    }
    size_t exact_target_count = 0;
    for (const ParsedMount& mount : parsed.realized) {
        if (!canonical_absolute_mount_destination(mount.destination)) {
            error = "realized mount destination was not canonical and absolute";
            return false;
        }
        if (mount.destination == kExactInputMountDestination) {
            ++exact_target_count;
            if (mount.type != "bind" || mount.source != expected_source || mount.mode != "" ||
                !mount.read_only || mount.propagation != "rprivate") {
                error = "realized exact-target bind mount semantics were not exact";
                return false;
            }
        } else if (path_shadows(mount.destination, kExactInputMountDestination)) {
            error = "realized mount shadowed the exact nginx.conf target";
            return false;
        }
    }
    if (exact_target_count != 1u) {
        error = "realized exact nginx.conf target cardinality was not one";
        return false;
    }
    return true;
}

static std::string mount_record(const std::string& id,
                                const std::string& name,
                                const std::string& user,
                                const std::string& network,
                                const std::string& source,
                                const std::string& realized_extra = {}) {
    return id + "|/" + name + "|" + user + "|" + network + "|1#bind|" + source + "|" +
           kExactInputMountDestination + "|true|rprivate;#bind|" + source + "|" +
           kExactInputMountDestination + "||false|rprivate;" + realized_extra;
}

static bool mount_parser_self_checks(std::uint32_t& rejections, std::string& error) {
    const std::string id(64, 'a');
    const std::string name = "rut358-sidecar-test";
    const std::string user = "1000:1000";
    const std::string network = "container:" + std::string(64, 'b');
    const std::string source = "/tmp/rut358-test/nginx.conf";
    ParsedMountInspect parsed;
    const std::string valid =
        mount_record(id, name, user, network, source, "volume|cache|/var/cache/nginx|z|true|;");
    if (!validate_mount_inspect_record(valid, id, name, user, network, source, parsed, error) ||
        parsed.realized.size() != 2u) {
        error = "valid mount parser/unrelated-image-mount evidence was rejected: " + error;
        return false;
    }
    std::vector<std::string> mutations;
    const auto replace_once = [&](const std::string& from, const std::string& to) {
        std::string changed = valid;
        const size_t at = changed.find(from);
        if (at == std::string::npos) return std::string{};
        changed.replace(at, from.size(), to);
        return changed;
    };
    mutations.push_back(replace_once(id, std::string(64, 'c')));
    mutations.push_back(replace_once("/" + name, "/wrong"));
    mutations.push_back(replace_once(user, "0:0"));
    mutations.push_back(replace_once(network, "bridge"));
    mutations.push_back(replace_once("|1#", "|2#"));
    mutations.push_back(replace_once("#bind|", "#volume|"));
    mutations.push_back(replace_once("#bind|" + source, "#bind|/tmp/wrong"));
    mutations.push_back(
        replace_once("|" + std::string(kExactInputMountDestination) + "|true|rprivate;#",
                     "|/etc/nginx/wrong|true|rprivate;#"));
    mutations.push_back(replace_once("|true|rprivate;#", "|false|rprivate;#"));
    mutations.push_back(replace_once("|true|rprivate;#", "|true|shared;#"));
    mutations.push_back(replace_once(
        "|1#bind|",
        "|2#bind|" + source + "|" + kExactInputMountDestination + "|true|rprivate;bind|"));
    const size_t realized = valid.find("#bind|", valid.find('#') + 1);
    if (realized == std::string::npos) {
        error = "valid mount mutation seed lacked realized record";
        return false;
    }
    const auto mutate_realized = [&](const std::string& from, const std::string& to) {
        std::string changed = valid;
        const size_t at = changed.find(from, realized);
        if (at == std::string::npos) return std::string{};
        changed.replace(at, from.size(), to);
        return changed;
    };
    mutations.push_back(mutate_realized("bind|", "volume|"));
    mutations.push_back(mutate_realized(source, "/tmp/wrong"));
    mutations.push_back(mutate_realized(kExactInputMountDestination, "/etc/nginx/wrong"));
    mutations.push_back(mutate_realized("||false|", "|ro|false|"));
    mutations.push_back(mutate_realized("|false|rprivate;", "|true|rprivate;"));
    mutations.push_back(mutate_realized("|rprivate;", "|shared;"));
    mutations.push_back(valid + "bind|other|/etc/nginx|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/etc/nginx/nginx.conf/child|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/etc/nginx//nginx.conf|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/etc/nginx/./|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/etc/nginx/../nginx|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/etc/nginx/nginx.conf/../other|ro|false|rprivate;");
    mutations.push_back(valid + "bind|other|/etc/nginx/|ro|false|rprivate;");
    mutations.push_back(valid + "bind|" + source + "|" + kExactInputMountDestination +
                        "||false|rprivate;");
    mutations.push_back(valid.substr(0, valid.size() - 1));
    mutations.push_back("malformed");
    rejections = 0;
    for (const std::string& mutation : mutations) {
        ParsedMountInspect ignored;
        std::string rejected;
        if (mutation.empty() || validate_mount_inspect_record(
                                    mutation, id, name, user, network, source, ignored, rejected)) {
            error = "mount parser field/duplicate/shadow mutation was accepted";
            return false;
        }
        ++rejections;
    }
    return true;
}

static bool docker_user_namespace_preflight(std::string& error) {
    CommandResult result;
    if (!run_command({"docker", "info", "-f", "{{json .SecurityOptions}}"}, result) ||
        !exited_zero(result)) {
        error = "Docker security-mode preflight failed: " + trim(result.output);
        return false;
    }
    const std::string security = trim(result.output);
    JsonValue parsed;
    if (!parse_json(security, parsed) || !string_array(parsed, false)) {
        error = "Docker security-mode preflight was malformed";
        return false;
    }
    if (security.find("rootless") != std::string::npos ||
        security.find("userns") != std::string::npos) {
        error = "rootless or userns-remapped Docker is unsupported for exact credential proof";
        return false;
    }
    return true;
}

static bool proc_credentials_exact(pid_t pid, std::uint64_t uid, std::uint64_t gid) {
    std::string status;
    if (!read_file("/proc/" + std::to_string(pid) + "/status", status)) return false;
    std::istringstream lines(status);
    std::string line;
    bool uid_ok = false;
    bool gid_ok = false;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string label;
        unsigned long long a = 0, b = 0, c = 0, d = 0;
        if (!(fields >> label >> a >> b >> c >> d)) continue;
        if (label == "Uid:") uid_ok = a == uid && b == uid && c == uid && d == uid;
        if (label == "Gid:") gid_ok = a == gid && b == gid && c == gid && d == gid;
    }
    return uid_ok && gid_ok;
}

static bool bracketed_proc_credentials_exact(Fixture& fixture,
                                             std::uint64_t uid,
                                             std::uint64_t gid,
                                             bool inject_boundary_death,
                                             std::string& error) {
    if (!fixture.revalidate_sidecar_identity(error)) {
        error = "pre-read exact sidecar identity proof failed: " + error;
        return false;
    }
    const HeldNamespaceSidecarSnapshot before = fixture.sidecar_snapshot();
    const bool credentials_ok = proc_credentials_exact(before.pid, uid, gid);
    if (inject_boundary_death) {
        std::string death_error;
        if (!fixture.terminate_sidecar_unexpectedly(death_error)) {
            error = "credential-boundary death injection failed: " + death_error;
            return false;
        }
    }
    if (!fixture.revalidate_sidecar_identity(error)) {
        error = "post-read exact sidecar identity proof failed: " + error;
        return false;
    }
    const HeldNamespaceSidecarSnapshot after = fixture.sidecar_snapshot();
    if (!sidecar_snapshot_equal(before, after)) {
        error = "sidecar identity changed across /proc credential observation";
        return false;
    }
    if (!credentials_ok) {
        error = "actual sidecar /proc credentials did not equal exact file UID:GID";
        return false;
    }
    return true;
}

static bool exact_input_mount_argv(const std::vector<std::string>& argv,
                                   const std::string& source,
                                   const fixture_exact_input_file_lease::Identity& identity) {
    const std::string user = std::to_string(identity.uid) + ":" + std::to_string(identity.gid);
    const std::string mount = "type=bind,src=" + source + ",dst=" + kExactInputMountDestination +
                              ",readonly,bind-propagation=rprivate";
    const auto exact_pair = [&](const std::string& option, const std::string& value) {
        size_t count = 0;
        for (size_t index = 0; index + 1 < argv.size(); ++index)
            if (argv[index] == option && argv[index + 1] == value) ++count;
        return count == 1u;
    };
    return argv.size() >= 4u && argv[0] == "docker" && argv[1] == "run" &&
           argv[argv.size() - 2] == RUT_PINNED_NGINX_IMAGE && argv.back() == "infinity" &&
           exact_pair("--user", user) && exact_pair("--mount", mount) &&
           std::count(argv.begin(), argv.end(), "--user") == 1 &&
           std::count(argv.begin(), argv.end(), "--mount") == 1 &&
           std::find(argv.begin(), argv.end(), "-v") == argv.end() &&
           std::find(argv.begin(), argv.end(), "--volume") == argv.end();
}

static bool inspect_exact_mount(Fixture& fixture,
                                const std::string& source,
                                const fixture_exact_input_file_lease::Identity& identity,
                                ParsedMountInspect& parsed,
                                std::string& error) {
    CommandResult result;
    const std::string format =
        "{{.Id}}|{{.Name}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{len "
        ".HostConfig.Mounts}}#{{range .HostConfig.Mounts}}{{.Type}}|{{.Source}}|{{.Target}}|"
        "{{.ReadOnly}}|{{.BindOptions.Propagation}};{{end}}#{{range .Mounts}}{{.Type}}|"
        "{{.Source}}|{{.Destination}}|{{.Mode}}|{{.RW}}|{{.Propagation}};{{end}}";
    if (!run_command({"docker", "inspect", "-f", format, fixture.sidecar_snapshot().id}, result) ||
        !exited_zero(result)) {
        error = "exact input mount inspection command failed: " + trim(result.output);
        return false;
    }
    const std::string user = std::to_string(identity.uid) + ":" + std::to_string(identity.gid);
    return validate_mount_inspect_record(trim(result.output),
                                         fixture.sidecar_snapshot().id,
                                         fixture.sidecar_name(),
                                         user,
                                         "container:" + fixture.holder_id(),
                                         source,
                                         parsed,
                                         error);
}

struct NginxSiblingLease {
    std::string name;
    std::string id;
    std::string cgroup_path;
    pid_t master_pid = -1;
    pid_t worker_pid = -1;
    int master_pidfd = -1;
    int worker_pidfd = -1;
    bool mutation_may_have_occurred = false;
    bool exists = false;
    bool running = false;
    bool operation_failed = false;
};

static int remaining_command_ms(std::int64_t limit_ns) {
    const std::int64_t now = exact_read_monotonic_ns();
    if (now <= 0 || now >= limit_ns) return 0;
    const std::int64_t remaining = limit_ns - now;
    const std::int64_t rounded = (remaining + 999999LL) / 1000000LL;
    return static_cast<int>(std::min<std::int64_t>(rounded, 30000LL));
}

static bool run_command_before(const std::vector<std::string>& argv,
                               std::int64_t limit_ns,
                               CommandResult& result,
                               bool reported_timeout = false,
                               size_t output_limit = 65536u) {
    const int timeout_ms = remaining_command_ms(limit_ns);
    if (timeout_ms <= 0) {
        result = {};
        result.timed_out = true;
        return false;
    }
    return run_command(argv, result, timeout_ms, reported_timeout, false, nullptr, output_limit);
}

static bool parse_positive_pid(const std::string& text, pid_t& pid) {
    char* end = nullptr;
    errno = 0;
    const long value = strtol(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' || value <= 1 ||
        value > std::numeric_limits<pid_t>::max())
        return false;
    pid = static_cast<pid_t>(value);
    return true;
}

static bool proc_status_scalar(pid_t pid, const char* wanted, std::int64_t& value) {
    std::string status;
    if (!read_file("/proc/" + std::to_string(pid) + "/status", status)) return false;
    std::istringstream lines(status);
    std::string line;
    std::size_t matches = 0u;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string label;
        long long parsed = 0;
        if ((fields >> label >> parsed) && label == wanted) {
            value = parsed;
            ++matches;
        }
    }
    return matches == 1u;
}

static bool proc_nspid_exact(pid_t pid, bool master) {
    std::string status;
    if (!read_file("/proc/" + std::to_string(pid) + "/status", status)) return false;
    std::istringstream lines(status);
    std::string line;
    std::size_t matches = 0u;
    bool exact = false;
    while (std::getline(lines, line)) {
        if (line.rfind("NSpid:", 0u) != 0u) continue;
        ++matches;
        std::istringstream values(line.substr(6u));
        long long value = 0;
        long long last = 0;
        std::size_t count = 0u;
        while (values >> value) {
            last = value;
            ++count;
        }
        exact = count >= 2u && (master ? last == 1 : last > 1);
    }
    return matches == 1u && exact;
}

static bool read_unified_cgroup(pid_t pid, std::string& path) {
    std::string value;
    if (!read_file("/proc/" + std::to_string(pid) + "/cgroup", value)) return false;
    std::istringstream lines(value);
    std::string line;
    std::size_t count = 0u;
    while (std::getline(lines, line)) {
        if (line.rfind("0::/", 0u) != 0u || line.find('\0') != std::string::npos) return false;
        path = line.substr(3u);
        ++count;
    }
    return count == 1u && !path.empty() && path[0] == '/' && path.find("..") == std::string::npos;
}

static bool unified_cgroup_preflight() {
    std::string self_path;
    std::string controllers;
    return read_unified_cgroup(getpid(), self_path) &&
           read_file("/sys/fs/cgroup/cgroup.controllers", controllers) && !controllers.empty();
}

static bool exact_cgroup_members(const std::string& path,
                                 pid_t expected_master,
                                 pid_t& worker,
                                 std::string& error) {
    std::string contents;
    if (!read_file("/sys/fs/cgroup" + path + "/cgroup.procs", contents)) {
        error = "unified cgroup membership is unavailable";
        return false;
    }
    std::istringstream lines(contents);
    std::string line;
    std::vector<pid_t> members;
    while (std::getline(lines, line)) {
        pid_t parsed = -1;
        if (!parse_positive_pid(line, parsed) ||
            std::find(members.begin(), members.end(), parsed) != members.end()) {
            error = "cgroup.procs was malformed or duplicated";
            return false;
        }
        members.push_back(parsed);
    }
    if (members.size() != 2u ||
        std::find(members.begin(), members.end(), expected_master) == members.end()) {
        error = "nginx cgroup membership was not exactly master plus one worker";
        return false;
    }
    worker = members[0] == expected_master ? members[1] : members[0];
    std::int64_t ppid = 0;
    if (!proc_status_scalar(worker, "PPid:", ppid) || ppid != expected_master) {
        error = "nginx worker was not the direct child of the master";
        return false;
    }
    return true;
}

static bool same_proc_namespace(pid_t left, pid_t right, const char* name) {
    struct stat a{};
    struct stat b{};
    return stat(("/proc/" + std::to_string(left) + "/ns/" + name).c_str(), &a) == 0 &&
           stat(("/proc/" + std::to_string(right) + "/ns/" + name).c_str(), &b) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static bool distinct_proc_namespace(pid_t left, pid_t right, const char* name) {
    struct stat a{};
    struct stat b{};
    return stat(("/proc/" + std::to_string(left) + "/ns/" + name).c_str(), &a) == 0 &&
           stat(("/proc/" + std::to_string(right) + "/ns/" + name).c_str(), &b) == 0 &&
           (a.st_dev != b.st_dev || a.st_ino != b.st_ino);
}

static bool same_proc_executable(pid_t left, pid_t right) {
    struct stat a{};
    struct stat b{};
    return stat(("/proc/" + std::to_string(left) + "/exe").c_str(), &a) == 0 &&
           stat(("/proc/" + std::to_string(right) + "/exe").c_str(), &b) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static bool proc_executable_is_nginx(pid_t pid) {
    struct stat running{};
    struct stat image{};
    return stat(("/proc/" + std::to_string(pid) + "/exe").c_str(), &running) == 0 &&
           stat(("/proc/" + std::to_string(pid) + "/root/usr/sbin/nginx").c_str(), &image) == 0 &&
           running.st_dev == image.st_dev && running.st_ino == image.st_ino;
}

static bool proc_socket_inodes(pid_t pid, std::vector<std::uint64_t>& inodes) {
    const std::string directory = "/proc/" + std::to_string(pid) + "/fd";
    DIR* opened = opendir(directory.c_str());
    if (opened == nullptr) return false;
    bool ok = true;
    while (dirent* entry = readdir(opened)) {
        if (entry->d_name[0] == '.') continue;
        const std::string path = directory + "/" + entry->d_name;
        std::array<char, 256> target{};
        const ssize_t size = readlink(path.c_str(), target.data(), target.size() - 1u);
        if (size < 0) {
            if (errno == ENOENT) continue;
            ok = false;
            break;
        }
        target[static_cast<std::size_t>(size)] = '\0';
        const std::string value(target.data());
        if (value.rfind("socket:[", 0u) != 0u || value.back() != ']') continue;
        const std::string number = value.substr(8u, value.size() - 9u);
        char* end = nullptr;
        errno = 0;
        const unsigned long long inode = strtoull(number.c_str(), &end, 10);
        if (errno != 0 || end == number.c_str() || *end != '\0' || inode == 0u) {
            ok = false;
            break;
        }
        if (std::find(inodes.begin(), inodes.end(), inode) == inodes.end()) inodes.push_back(inode);
    }
    closedir(opened);
    return ok;
}

using NginxProcTcpTable = fixture_privileged_listener::ProcTcpTable;

static bool nginx_proc_unsigned(std::string_view text, int base, u64 maximum, u64& value) {
    if (text.empty()) return false;
    value = 0u;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value, base);
    return parsed.ec == std::errc{} && parsed.ptr == end && value <= maximum;
}

static bool nginx_proc_signed_ssthresh(std::string_view text) {
    std::int64_t value = 0;
    if (text.empty()) return false;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value, 10);
    return parsed.ec == std::errc{} && parsed.ptr == end && value >= -1 &&
           value <= std::numeric_limits<std::int32_t>::max();
}

template <std::size_t Size>
static bool nginx_proc_tokens(std::string_view line,
                              std::array<std::string_view, Size>& tokens,
                              std::size_t& count) {
    count = 0u;
    std::size_t cursor = 0u;
    while (cursor < line.size()) {
        while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t')) ++cursor;
        if (cursor == line.size()) break;
        const std::size_t begin = cursor;
        while (cursor < line.size() && line[cursor] != ' ' && line[cursor] != '\t') ++cursor;
        if (count == tokens.size() || cursor - begin > 64u) return false;
        tokens[count++] = line.substr(begin, cursor - begin);
    }
    return true;
}

static bool nginx_proc_exact_hex(std::string_view text, std::size_t width, u64& value) {
    return text.size() == width && width <= 16u &&
           nginx_proc_unsigned(text, 16, std::numeric_limits<u64>::max(), value);
}

static bool nginx_proc_hex_pair(std::string_view text,
                                std::size_t left_width,
                                std::size_t right_width,
                                u64 left_maximum = std::numeric_limits<u64>::max(),
                                u64 right_maximum = std::numeric_limits<u64>::max()) {
    if (text.size() != left_width + right_width + 1u || text[left_width] != ':') return false;
    u64 left = 0u;
    u64 right = 0u;
    return nginx_proc_exact_hex(text.substr(0u, left_width), left_width, left) &&
           nginx_proc_exact_hex(text.substr(left_width + 1u), right_width, right) &&
           left <= left_maximum && right <= right_maximum;
}

static bool nginx_proc_endpoint(std::string_view text,
                                std::size_t address_width,
                                u32& ipv4,
                                u16& port) {
    if ((address_width != 8u && address_width != 32u) || text.size() != address_width + 5u ||
        text[address_width] != ':')
        return false;
    u64 parsed_port = 0u;
    if (!nginx_proc_exact_hex(text.substr(address_width + 1u), 4u, parsed_port)) return false;
    port = static_cast<u16>(parsed_port);
    ipv4 = 0u;
    if (address_width == 8u) {
        u64 raw = 0u;
        if (!nginx_proc_exact_hex(text.substr(0u, address_width), address_width, raw)) return false;
        const u32 value = static_cast<u32>(raw);
        ipv4 = ((value & 0x000000ffu) << 24u) | ((value & 0x0000ff00u) << 8u) |
               ((value & 0x00ff0000u) >> 8u) | ((value & 0xff000000u) >> 24u);
        return true;
    }
    u64 half = 0u;
    return nginx_proc_exact_hex(text.substr(0u, 16u), 16u, half) &&
           nginx_proc_exact_hex(text.substr(16u, 16u), 16u, half);
}

static bool parse_nginx_proc_net_tcp(const std::string& contents,
                                     std::size_t address_width,
                                     NginxProcTcpTable& table) {
    table = {};
    if (contents.empty() || contents.size() > fixture_privileged_listener::kMaxProcBytes ||
        contents.back() != '\n' || contents.find('\0') != std::string::npos ||
        (address_width != 8u && address_width != 32u))
        return false;

    std::size_t offset = 0u;
    std::size_t line_number = 0u;
    while (offset < contents.size()) {
        const std::size_t newline = contents.find('\n', offset);
        if (newline == std::string::npos || newline - offset > 512u) return false;
        const std::string_view line(contents.data() + offset, newline - offset);
        offset = newline + 1u;
        std::array<std::string_view, 18u> tokens{};
        std::size_t count = 0u;
        if (!nginx_proc_tokens(line, tokens, count)) return false;
        if (line_number++ == 0u) {
            if (count != 12u || tokens[0] != "sl" || tokens[1] != "local_address" ||
                (tokens[2] != "remote_address" && tokens[2] != "rem_address") ||
                tokens[3] != "st" || tokens[4] != "tx_queue" || tokens[5] != "rx_queue" ||
                tokens[6] != "tr" || tokens[7] != "tm->when" || tokens[8] != "retrnsmt" ||
                tokens[9] != "uid" || tokens[10] != "timeout" || tokens[11] != "inode")
                return false;
            continue;
        }
        if (count < 12u || table.count == table.rows.size()) return false;
        u64 slot = 0u;
        if (tokens[0].size() < 2u || tokens[0].back() != ':' ||
            !nginx_proc_unsigned(tokens[0].substr(0u, tokens[0].size() - 1u),
                                 10,
                                 std::numeric_limits<u32>::max(),
                                 slot))
            return false;
        fixture_privileged_listener::ProcTcpRecord row{};
        u32 remote_ipv4 = 0u;
        u16 remote_port = 0u;
        u64 state = 0u;
        u64 ignored = 0u;
        if (!nginx_proc_endpoint(tokens[1], address_width, row.local_ipv4, row.local_port) ||
            !nginx_proc_endpoint(tokens[2], address_width, remote_ipv4, remote_port) ||
            !nginx_proc_exact_hex(tokens[3], 2u, state) || state == 0u || state > 0x0cu ||
            !nginx_proc_hex_pair(tokens[4], 8u, 8u) ||
            !nginx_proc_hex_pair(tokens[5], 2u, 8u, 4u) ||
            !nginx_proc_exact_hex(tokens[6], 8u, ignored) ||
            !nginx_proc_unsigned(tokens[7], 10, std::numeric_limits<u32>::max(), ignored) ||
            !nginx_proc_unsigned(
                tokens[8], 10, std::numeric_limits<std::int32_t>::max(), ignored) ||
            !nginx_proc_unsigned(tokens[9], 10, std::numeric_limits<u64>::max(), row.inode) ||
            !nginx_proc_unsigned(
                tokens[10], 10, std::numeric_limits<std::int32_t>::max(), ignored) ||
            !nginx_proc_exact_hex(tokens[11], sizeof(void*) * 2u, ignored))
            return false;
        row.state = static_cast<std::uint8_t>(state);
        const bool short_kernel_row = row.state == 0x06u;
        if (short_kernel_row) {
            if (count != 12u) return false;
        } else {
            if (count != 17u ||
                !nginx_proc_unsigned(tokens[12], 10, std::numeric_limits<u64>::max(), ignored) ||
                !nginx_proc_unsigned(tokens[13], 10, std::numeric_limits<u64>::max(), ignored) ||
                !nginx_proc_unsigned(tokens[14], 10, std::numeric_limits<u32>::max(), ignored) ||
                !nginx_proc_unsigned(tokens[15], 10, std::numeric_limits<u32>::max(), ignored) ||
                !nginx_proc_signed_ssthresh(tokens[16]))
                return false;
        }
        table.rows[table.count++] = row;
    }
    return true;
}

static bool strict_tcp6_port_absent(const std::string& contents, u16 port) {
    NginxProcTcpTable table;
    if (!parse_nginx_proc_net_tcp(contents, 32u, table)) return false;
    for (std::size_t index = 0u; index < table.count; ++index)
        if (table.rows[index].local_port == port) return false;
    return true;
}

static bool strict_exact_nginx_listener(const NginxProcTcpTable& table,
                                        u32 positive,
                                        u32 guard,
                                        const std::vector<std::uint64_t>& process_socket_inodes,
                                        fixture_privileged_listener::ListenerEvidence& listener,
                                        fixture_privileged_listener::Diagnostic& diagnostic) {
    std::size_t selected_rows = 0u;
    u64 selected_inode = 0u;
    for (std::size_t index = 0u; index < table.count; ++index) {
        const auto& row = table.rows[index];
        if (row.local_port != kExactInputTopologyBuilderPort) continue;
        ++selected_rows;
        if (row.local_ipv4 != positive || row.state != 0x0au || row.inode == 0u ||
            std::find(process_socket_inodes.begin(), process_socket_inodes.end(), row.inode) ==
                process_socket_inodes.end())
            return false;
        selected_inode = row.inode;
    }
    if (selected_rows != 1u || selected_inode == 0u) return false;
    return fixture_privileged_listener::classify_listener_evidence(
        table,
        fixture_privileged_listener::ListenerPlan{positive, guard, kExactInputTopologyBuilderPort},
        std::vector<u64>{selected_inode},
        fixture_privileged_listener::ListenerEvidenceKind::ExactPositive,
        listener,
        diagnostic);
}

static bool nginx_samples_stable(const ExactInputNginxProcessSample& first,
                                 const ExactInputNginxProcessSample& second) {
    return first.complete && second.complete && first.bracket_start_nanoseconds > 0 &&
           first.bracket_end_nanoseconds >= first.bracket_start_nanoseconds &&
           second.bracket_start_nanoseconds - first.bracket_end_nanoseconds >= 250000000LL &&
           second.bracket_end_nanoseconds >= second.bracket_start_nanoseconds &&
           first.container_identity_verified && first.source_revalidated && first.mount_verified &&
           first.topology_verified && first.cgroup_exact && first.pidfile_exact &&
           first.tcp_exact && first.tcp6_port_absent && first.end_container_identity_verified &&
           first.end_source_revalidated && first.end_mount_verified &&
           first.end_topology_verified && first.end_cgroup_exact && first.end_pidfile_exact &&
           first.end_process_socket_owned && second.container_identity_verified &&
           second.source_revalidated && second.mount_verified && second.topology_verified &&
           second.cgroup_exact && second.pidfile_exact && second.tcp_exact &&
           second.tcp6_port_absent && second.end_container_identity_verified &&
           second.end_source_revalidated && second.end_mount_verified &&
           second.end_topology_verified && second.end_cgroup_exact && second.end_pidfile_exact &&
           second.end_process_socket_owned && first.master_pid == second.master_pid &&
           first.worker_pid == second.worker_pid && first.master_start == second.master_start &&
           first.worker_start == second.worker_start && first.master_pid == first.end_master_pid &&
           first.worker_pid == first.end_worker_pid &&
           first.master_start == first.end_master_start &&
           first.worker_start == first.end_worker_start &&
           second.master_pid == second.end_master_pid &&
           second.worker_pid == second.end_worker_pid &&
           second.master_start == second.end_master_start &&
           second.worker_start == second.end_worker_start && first.listener_inode != 0u &&
           first.listener_inode == second.listener_inode;
}

static bool nginx_graceful_cleanup_complete(const ExactInputNginxLifecycleObservation& value) {
    return !value.operation_failed && value.quit_attempted && value.quit_only &&
           !value.term_attempted && !value.kill_attempted && !value.force_remove_attempted &&
           !value.uncertain_cleanup && value.stopped_exit_zero && value.cgroup_empty_after_stop &&
           value.removed_nonforce && value.exact_absence;
}

static bool mountinfo_entry(pid_t pid,
                            const std::string& destination,
                            std::uint64_t& mount_id,
                            bool& read_only,
                            bool& tmpfs) {
    std::string contents;
    if (!read_file("/proc/" + std::to_string(pid) + "/mountinfo", contents)) return false;
    std::istringstream lines(contents);
    std::string line;
    std::size_t matches = 0u;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string id, parent, device, root, point, options, token;
        if (!(fields >> id >> parent >> device >> root >> point >> options)) return false;
        bool separator = false;
        std::string filesystem;
        while (fields >> token) {
            if (token == "-") {
                separator = true;
                if (!(fields >> filesystem)) return false;
                break;
            }
        }
        if (!separator || point != destination) continue;
        char* end = nullptr;
        errno = 0;
        const unsigned long long parsed = strtoull(id.c_str(), &end, 10);
        if (errno != 0 || end == id.c_str() || *end != '\0' || parsed == 0u) return false;
        mount_id = parsed;
        read_only = options == "ro" || options.rfind("ro,", 0u) == 0u ||
                    options.find(",ro,") != std::string::npos ||
                    (options.size() > 3u && options.compare(options.size() - 3u, 3u, ",ro") == 0);
        tmpfs = filesystem == "tmpfs";
        ++matches;
    }
    return matches == 1u;
}

static bool exact_nginx_create_argv(const std::vector<std::string>& argv,
                                    const std::string& name,
                                    const std::string& token,
                                    const std::string& holder_id,
                                    const std::string& source,
                                    const std::string& credentials) {
    const std::string mount = "type=bind,src=" + source + ",dst=" + kExactInputMountDestination +
                              ",readonly,bind-propagation=rprivate";
    const std::string global =
        "daemon off; master_process on; worker_processes 1; pid /tmp/rut-" + token + "-nginx.pid;";
    const std::vector<std::string> expected = {
        "docker",
        "create",
        "--pull=never",
        "--name",
        name,
        "--label",
        std::string("rut.stage=") + kNginxStage,
        "--label",
        "rut.token=" + token,
        "--label",
        std::string("rut.role=") + kNginxRole,
        "--network",
        "container:" + holder_id,
        "--user",
        credentials,
        "--workdir",
        "/",
        "--env",
        "LC_ALL=C",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--restart",
        "no",
        "--stop-signal",
        "SIGQUIT",
        "--mount",
        mount,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=" +
            credentials.substr(0u, credentials.find(':')) +
            ",gid=" + credentials.substr(credentials.find(':') + 1u),
        "--tmpfs",
        "/var/cache/nginx:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=" +
            credentials.substr(0u, credentials.find(':')) +
            ",gid=" + credentials.substr(credentials.find(':') + 1u),
        "--tmpfs",
        "/var/log/nginx:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=" +
            credentials.substr(0u, credentials.find(':')) +
            ",gid=" + credentials.substr(credentials.find(':') + 1u),
        "--entrypoint",
        "/usr/sbin/nginx",
        RUT_PINNED_NGINX_IMAGE,
        "-c",
        kExactInputMountDestination,
        "-e",
        "stderr",
        "-g",
        global};
    return argv == expected && std::find(argv.begin(), argv.end(), "--rm") == argv.end() &&
           std::find(argv.begin(), argv.end(), "--privileged") == argv.end() &&
           std::find(argv.begin(), argv.end(), "-p") == argv.end() &&
           std::find(argv.begin(), argv.end(), "--publish") == argv.end() &&
           std::find(argv.begin(), argv.end(), "-v") == argv.end();
}

struct ExactInputMountOwner {
    explicit ExactInputMountOwner(std::string token_value, std::string bytes_value)
        : bytes(std::move(bytes_value)), fixture(std::move(token_value)) {
        receipt.manifest_not_applicable = true;
    }

    ~ExactInputMountOwner() {
        if ((mutated || recovery_required) && !settled) {
            dprintf(STDERR_FILENO,
                    "fatal exact-input mount owner destruction before settlement: phase=%u "
                    "error=%s\n",
                    static_cast<unsigned>(receipt.diagnostic.phase),
                    receipt.diagnostic.message.c_str());
            abort();
        }
    }

    std::string bytes;
    Fixture fixture;
    fixture_private_directory_lease::PrivateDirectoryLease directory;
    fixture_exact_input_file_lease::ExactInputFileLease input;
    ExactInputMountOptions options;
    ExactInputMountState state = ExactInputMountState::Empty;
    ExactInputMountSnapshot snapshot;
    ExactInputMountRecoveryReceipt receipt;
    ExactInputReadObservation read_observation;
    ExactInputMountDiagnostic read_diagnostic;
    ExactInputWriteRefusalObservation write_refusal_observation;
    ExactInputMountDiagnostic write_refusal_diagnostic;
    ExactInputNginxLifecycleObservation nginx_lifecycle_observation;
    ExactInputMountDiagnostic nginx_lifecycle_diagnostic;
    NginxSiblingLease nginx_sibling;
    std::vector<std::string> sidecar_argv;
    HeldNamespaceSidecarSnapshot registered_sidecar;
    ParsedMountInspect registered_mount;
    bool mutated = false;
    bool recovery_required = false;
    bool settled = false;
    bool topology_complete = false;
    bool disconnect_injected = false;
    bool restore_consumed = false;
    bool sidecar_fault_consumed = false;
    bool sidecar_disappearance_consumed = false;
    bool holder_disappearance_consumed = false;
    bool topology_settlement_fault_consumed = false;
    bool operation_failed = false;
    bool read_attempted = false;
    bool write_refusal_attempted = false;
    bool nginx_lifecycle_attempted = false;
    bool nginx_unresolved_fault_consumed = false;
    HeldTopologySnapshot builder_baseline;
};

struct NginxInspectEvidence {
    std::string id;
    pid_t pid = -1;
    int exit_code = -1;
    bool running = false;
};

static bool topology_snapshot_equal(const HeldTopologySnapshot& left,
                                    const HeldTopologySnapshot& right);

static bool contains_exact_json_string(const std::string& json, const std::string& value) {
    const std::string needle = "\"" + value + "\"";
    const size_t first = json.find(needle);
    return first != std::string::npos &&
           json.find(needle, first + needle.size()) == std::string::npos;
}

static bool nginx_auto_remove_disabled(const std::string& value) {
    bool auto_remove = true;
    return parse_exact_bool(value, auto_remove) && !auto_remove;
}

static bool tmpfs_option_exact_enough(const std::string& options,
                                      const std::string& uid,
                                      const std::string& gid,
                                      const char* size) {
    const std::array<std::string, 8> required{"rw",
                                              "noexec",
                                              "nosuid",
                                              "nodev",
                                              std::string("size=") + size,
                                              "mode=0700",
                                              "uid=" + uid,
                                              "gid=" + gid};
    for (const std::string& token : required)
        if (options.find(token) == std::string::npos) return false;
    return true;
}

static bool inspect_nginx_sibling(ExactInputMountOwner& owner,
                                  NginxInspectEvidence& evidence,
                                  std::string& error,
                                  std::int64_t deadline_ns) {
    const std::string target =
        owner.nginx_sibling.id.empty() ? owner.nginx_sibling.name : owner.nginx_sibling.id;
    const std::string format =
        "{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.Image}}|{{index .Config.Labels \"rut.stage\"}}|"
        "{{index .Config.Labels \"rut.token\"}}|{{index .Config.Labels \"rut.role\"}}|"
        "{{.HostConfig.NetworkMode}}|{{.Config.User}}|{{.Config.WorkingDir}}|{{json .Config.Env}}|"
        "{{.Path}}|{{json .Args}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|"
        "{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}|"
        "{{json .Config.ExposedPorts}}|{{json .NetworkSettings.Ports}}|"
        "{{.HostConfig.RestartPolicy.Name}}|{{.Config.StopSignal}}|"
        "{{index .HostConfig.Tmpfs \"/tmp\"}}|{{index .HostConfig.Tmpfs \"/var/cache/nginx\"}}|"
        "{{index .HostConfig.Tmpfs \"/var/log/nginx\"}}|{{.State.Running}}|{{.State.Pid}}|"
        "{{.State.ExitCode}}|{{len .HostConfig.Mounts}}|{{range .HostConfig.Mounts}}"
        "{{.Type}}#{{.Source}}#{{.Target}}#{{.ReadOnly}}#{{.BindOptions.Propagation}};{{end}}|"
        "{{len .Mounts}}|{{range .Mounts}}{{.Type}}#{{.Source}}#{{.Destination}}#{{.RW}}#"
        "{{.Propagation}};{{end}}|{{.HostConfig.Privileged}}|{{.Config.Tty}}|"
        "{{.Config.OpenStdin}}|{{.Config.AttachStdin}}|{{json .HostConfig.CapAdd}}|"
        "{{.HostConfig.AutoRemove}}";
    CommandResult result;
    if (!run_command_before({"docker", "inspect", "-f", format, target}, deadline_ns, result) ||
        !exited_zero(result)) {
        error = "nginx sibling inspection failed: " + trim(result.output);
        return false;
    }
    std::vector<std::string> fields;
    if (!split_exact(trim(result.output), '|', 37u, fields)) {
        error = "nginx sibling inspection record was malformed";
        return false;
    }
    bool running = false;
    pid_t pid = -1;
    char* exit_end = nullptr;
    errno = 0;
    const long exit_code = strtol(fields[26].c_str(), &exit_end, 10);
    const auto& identity = owner.input.identity();
    const std::string uid = std::to_string(identity.uid);
    const std::string gid = std::to_string(identity.gid);
    const std::string credentials = uid + ":" + gid;
    const std::string expected_args =
        "[\"-c\",\"/etc/nginx/nginx.conf\",\"-e\",\"stderr\",\"-g\",\"daemon off; "
        "master_process on; worker_processes 1; pid /tmp/rut-" +
        owner.fixture.token() + "-nginx.pid;\"]";
    const std::string requested =
        "bind#" + owner.input.path() + "#" + kExactInputMountDestination + "#true#rprivate;";
    const std::string realized_prefix =
        "bind#" + owner.input.path() + "#" + kExactInputMountDestination + "#false#rprivate;";
    if (!parse_exact_bool(fields[24], running) ||
        (running && !parse_positive_pid(fields[25], pid)) || (!running && fields[25] != "0") ||
        errno != 0 || exit_end == fields[26].c_str() || *exit_end != '\0' || exit_code < 0 ||
        fields[0].size() != 64u || !full_container_id(fields[0]) ||
        fields[1] != "/" + owner.nginx_sibling.name ||
        (!owner.nginx_sibling.id.empty() && fields[0] != owner.nginx_sibling.id) ||
        fields[2] != RUT_PINNED_NGINX_IMAGE || fields[3] != owner.registered_sidecar.image_id ||
        fields[4] != kNginxStage || fields[5] != owner.fixture.token() || fields[6] != kNginxRole ||
        fields[7] != "container:" + owner.fixture.holder_id() || fields[8] != credentials ||
        fields[9] != "/" || !contains_exact_json_string(fields[10], "LC_ALL=C") ||
        fields[11] != "/usr/sbin/nginx" || fields[12] != expected_args || fields[13] != "true" ||
        fields[14] != "[\"ALL\"]" || fields[15] != "[\"no-new-privileges\"]" ||
        !no_published_ports(fields[16], fields[18]) || fields[17] == "null" || fields[19] != "no" ||
        fields[20] != "SIGQUIT" || !tmpfs_option_exact_enough(fields[21], uid, gid, "1m") ||
        !tmpfs_option_exact_enough(fields[22], uid, gid, "4m") ||
        !tmpfs_option_exact_enough(fields[23], uid, gid, "4m") || fields[27] != "1" ||
        fields[28] != requested || fields[29] != "1" || fields[30] != realized_prefix ||
        fields[31] != "false" || fields[32] != "false" || fields[33] != "false" ||
        fields[34] != "false" || fields[35] != "null" || !nginx_auto_remove_disabled(fields[36])) {
        error = "nginx sibling immutable/security/mount/tmpfs identity was not exact";
        return false;
    }
    evidence.id = fields[0];
    evidence.running = running;
    evidence.pid = pid;
    evidence.exit_code = static_cast<int>(exit_code);
    return true;
}

static bool nginx_live_mounts_exact(ExactInputMountOwner& owner,
                                    pid_t master,
                                    bool& same_mount_instance,
                                    std::string& error) {
    const auto& identity = owner.input.identity();
    struct stat source{};
    struct stat mounted{};
    if (fstat(owner.input.descriptor(), &source) != 0 ||
        stat(("/proc/" + std::to_string(master) + "/root" + kExactInputMountDestination).c_str(),
             &mounted) != 0 ||
        source.st_dev != mounted.st_dev || source.st_ino != mounted.st_ino ||
        mounted.st_uid != identity.uid || mounted.st_gid != identity.gid) {
        error = "live nginx bind did not retain the exact source inode/credentials";
        return false;
    }
    std::uint64_t nginx_mount_id = 0u;
    std::uint64_t sidecar_mount_id = 0u;
    bool nginx_ro = false, sidecar_ro = false, nginx_tmp = false, sidecar_tmp = false;
    const bool nginx_mount =
        mountinfo_entry(master, kExactInputMountDestination, nginx_mount_id, nginx_ro, nginx_tmp);
    const bool sidecar_mount = mountinfo_entry(owner.registered_sidecar.pid,
                                               kExactInputMountDestination,
                                               sidecar_mount_id,
                                               sidecar_ro,
                                               sidecar_tmp);
    if (!nginx_mount || !sidecar_mount || !nginx_ro || !sidecar_ro) {
        std::ostringstream detail;
        detail << "live nginx/sidecar bind mount evidence was not exact and read-only: nginx="
               << nginx_mount << "/" << nginx_ro << "/" << nginx_tmp << "/" << nginx_mount_id
               << " sidecar=" << sidecar_mount << "/" << sidecar_ro << "/" << sidecar_tmp << "/"
               << sidecar_mount_id;
        error = detail.str();
        return false;
    }
    // Mount IDs are scoped to a mount namespace and can numerically collide.
    // A shared instance requires both the same namespace and the same local ID.
    if (!distinct_proc_namespace(master, owner.registered_sidecar.pid, "mnt")) {
        error = "nginx sibling did not own an independently verified mount namespace";
        return false;
    }
    same_mount_instance = false;
    if (same_mount_instance) {
        error = "nginx sibling unexpectedly shared the sidecar mount instance";
        return false;
    }
    for (const char* destination_text : {"/tmp", "/var/cache/nginx", "/var/log/nginx"}) {
        const std::string destination(destination_text);
        std::uint64_t id = 0u;
        bool ro = false;
        bool tmpfs = false;
        struct stat status{};
        if (!mountinfo_entry(master, destination, id, ro, tmpfs) || ro || !tmpfs ||
            stat(("/proc/" + std::to_string(master) + "/root" + destination).c_str(), &status) !=
                0 ||
            status.st_uid != identity.uid || status.st_gid != identity.gid ||
            (status.st_mode & 0777u) != 0700u) {
            error = "live nginx tmpfs ownership/mode/type was not exact";
            return false;
        }
    }
    return true;
}

static bool revalidate_nginx_sample_end(ExactInputMountOwner& owner,
                                        ExactInputNginxProcessSample& sample,
                                        const std::string& expected_cgroup,
                                        std::int64_t deadline_ns,
                                        std::string& error) {
    fixture_exact_input_file_lease::Diagnostic source_diagnostic;
    if (!owner.input.revalidate(source_diagnostic)) {
        error = "exact input source/OFD changed at nginx sample end";
        return false;
    }
    sample.end_source_revalidated = true;
    if (!owner.fixture.revalidate_sidecar_identity(error) ||
        !owner.fixture.verify_topology(FailurePoint::None, error) ||
        !topology_snapshot_equal(owner.builder_baseline,
                                 owner.fixture.current_topology_snapshot())) {
        if (error.empty()) error = "sidecar/topology identity changed at nginx sample end";
        return false;
    }
    sample.end_topology_verified = true;

    NginxInspectEvidence inspect;
    if (!inspect_nginx_sibling(owner, inspect, error, deadline_ns) || !inspect.running ||
        inspect.id != owner.nginx_sibling.id || inspect.pid != sample.master_pid) {
        if (error.empty()) error = "container identity changed at nginx sample end";
        return false;
    }
    sample.end_container_identity_verified = true;
    sample.end_master_pid = inspect.pid;

    ProcIdentity master{};
    ProcIdentity worker_identity{};
    pid_t worker = -1;
    std::string master_cgroup;
    std::string worker_cgroup;
    if (!proc_identity(inspect.pid, master) || master.start != sample.master_start ||
        master.netns != owner.builder_baseline.holder_netns ||
        !proc_credentials_exact(
            inspect.pid, owner.input.identity().uid, owner.input.identity().gid) ||
        !proc_nspid_exact(inspect.pid, true) || !read_unified_cgroup(inspect.pid, master_cgroup) ||
        master_cgroup != expected_cgroup ||
        !exact_cgroup_members(master_cgroup, inspect.pid, worker, error) ||
        worker != sample.worker_pid || !proc_identity(worker, worker_identity) ||
        worker_identity.start != sample.worker_start || worker_identity.netns != master.netns ||
        !proc_credentials_exact(worker, owner.input.identity().uid, owner.input.identity().gid) ||
        !proc_nspid_exact(worker, false) || !read_unified_cgroup(worker, worker_cgroup) ||
        worker_cgroup != master_cgroup || !same_proc_namespace(inspect.pid, worker, "pid") ||
        !same_proc_namespace(inspect.pid, worker, "mnt") ||
        !same_proc_namespace(inspect.pid, worker, "net") ||
        !same_proc_executable(inspect.pid, worker) || !proc_executable_is_nginx(inspect.pid) ||
        !pidfd_targets_exact_pid(owner.nginx_sibling.master_pidfd, inspect.pid) ||
        !pidfd_targets_exact_pid(owner.nginx_sibling.worker_pidfd, worker)) {
        if (error.empty())
            error = "nginx process/pidfd/cgroup/namespace identity changed at sample end";
        return false;
    }
    sample.end_cgroup_exact = true;
    sample.end_worker_pid = worker;
    sample.end_master_start = master.start;
    sample.end_worker_start = worker_identity.start;

    bool same_mount = true;
    if (!nginx_live_mounts_exact(owner, inspect.pid, same_mount, error)) return false;
    sample.end_mount_verified = true;
    const std::string pidfile = "/proc/" + std::to_string(inspect.pid) + "/root/tmp/rut-" +
                                owner.fixture.token() + "-nginx.pid";
    std::string pid_bytes;
    if (!read_file(pidfile, pid_bytes) || pid_bytes != "1\n") {
        error = "nginx pidfile changed at sample end";
        return false;
    }
    sample.end_pidfile_exact = true;
    std::vector<std::uint64_t> sockets;
    if (!proc_socket_inodes(inspect.pid, sockets) || !proc_socket_inodes(worker, sockets) ||
        std::find(sockets.begin(), sockets.end(), sample.listener_inode) == sockets.end()) {
        error = "nginx listener ownership changed at sample end";
        return false;
    }
    sample.end_process_socket_owned = true;
    sample.bracket_end_nanoseconds = exact_read_monotonic_ns();
    sample.monotonic_nanoseconds = sample.bracket_end_nanoseconds;
    if (sample.bracket_end_nanoseconds < sample.bracket_start_nanoseconds ||
        sample.bracket_end_nanoseconds >= deadline_ns) {
        error = "nginx sample end bracket exceeded its phase deadline";
        return false;
    }
    return true;
}

static bool capture_nginx_sample(ExactInputMountOwner& owner,
                                 ExactInputNginxProcessSample& sample,
                                 std::int64_t deadline_ns,
                                 bool first,
                                 std::string& error) {
    sample = {};
    sample.bracket_start_nanoseconds = exact_read_monotonic_ns();
    if (sample.bracket_start_nanoseconds <= 0 || sample.bracket_start_nanoseconds >= deadline_ns) {
        error = "nginx process sample exceeded its phase deadline";
        return false;
    }
    fixture_exact_input_file_lease::Diagnostic source_diagnostic;
    if (!owner.input.revalidate(source_diagnostic)) {
        error = "exact input source/OFD changed during nginx sample";
        return false;
    }
    sample.source_revalidated = true;
    if (!owner.fixture.verify_topology(FailurePoint::None, error) ||
        !topology_snapshot_equal(owner.builder_baseline,
                                 owner.fixture.current_topology_snapshot())) {
        if (error.empty()) error = "nginx sample topology changed";
        return false;
    }
    sample.topology_verified = true;
    NginxInspectEvidence inspect;
    if (!inspect_nginx_sibling(owner, inspect, error, deadline_ns) || !inspect.running)
        return false;
    sample.container_identity_verified = true;
    sample.master_pid = inspect.pid;
    ProcIdentity master{};
    if (!proc_identity(inspect.pid, master) ||
        master.netns != owner.builder_baseline.holder_netns ||
        !proc_credentials_exact(
            inspect.pid, owner.input.identity().uid, owner.input.identity().gid) ||
        !proc_nspid_exact(inspect.pid, true)) {
        error = "nginx master PID/start/credentials/netns/NSpid evidence was not exact";
        return false;
    }
    sample.master_start = master.start;
    std::string cgroup;
    pid_t worker = -1;
    if (!read_unified_cgroup(inspect.pid, cgroup) ||
        cgroup.find(owner.nginx_sibling.id) == std::string::npos ||
        !exact_cgroup_members(cgroup, inspect.pid, worker, error)) {
        if (error.empty()) error = "unified cgroup proof is unsupported";
        return false;
    }
    sample.cgroup_exact = true;
    sample.worker_pid = worker;
    ProcIdentity worker_identity{};
    std::string worker_cgroup;
    if (!proc_identity(worker, worker_identity) || worker_identity.netns != master.netns ||
        !proc_credentials_exact(worker, owner.input.identity().uid, owner.input.identity().gid) ||
        !proc_nspid_exact(worker, false) || !read_unified_cgroup(worker, worker_cgroup) ||
        worker_cgroup != cgroup || !same_proc_namespace(inspect.pid, worker, "pid") ||
        !same_proc_namespace(inspect.pid, worker, "mnt") ||
        !same_proc_namespace(inspect.pid, worker, "net") ||
        !same_proc_executable(inspect.pid, worker) || !proc_executable_is_nginx(inspect.pid)) {
        error = "nginx worker executable/credential/cgroup/namespace identity was not exact";
        return false;
    }
    sample.worker_start = worker_identity.start;
    if (first) {
#ifdef SYS_pidfd_open
        owner.nginx_sibling.master_pidfd =
            static_cast<int>(syscall(SYS_pidfd_open, inspect.pid, 0u));
        owner.nginx_sibling.worker_pidfd = static_cast<int>(syscall(SYS_pidfd_open, worker, 0u));
#else
        errno = ENOSYS;
#endif
        if (owner.nginx_sibling.master_pidfd < 0 || owner.nginx_sibling.worker_pidfd < 0 ||
            !pidfd_targets_exact_pid(owner.nginx_sibling.master_pidfd, inspect.pid) ||
            !pidfd_targets_exact_pid(owner.nginx_sibling.worker_pidfd, worker)) {
            error = "nginx master/worker pidfd identity proof is unavailable";
            return false;
        }
        owner.nginx_sibling.master_pid = inspect.pid;
        owner.nginx_sibling.worker_pid = worker;
        owner.nginx_sibling.cgroup_path = cgroup;
    } else if (owner.nginx_sibling.master_pid != inspect.pid ||
               owner.nginx_sibling.worker_pid != worker ||
               !pidfd_targets_exact_pid(owner.nginx_sibling.master_pidfd, inspect.pid) ||
               !pidfd_targets_exact_pid(owner.nginx_sibling.worker_pidfd, worker) ||
               owner.nginx_sibling.cgroup_path != cgroup) {
        error = "nginx pidfd/process-set identity drifted between samples";
        return false;
    }
    bool same_mount = true;
    if (!nginx_live_mounts_exact(owner, inspect.pid, same_mount, error)) return false;
    sample.mount_verified = true;
    const std::string pidfile = "/proc/" + std::to_string(inspect.pid) + "/root/tmp/rut-" +
                                owner.fixture.token() + "-nginx.pid";
    std::string pid_bytes;
    if (!read_file(pidfile, pid_bytes) || pid_bytes != "1\n") {
        error = "nginx pidfile did not contain exact container PID 1";
        return false;
    }
    sample.pidfile_exact = true;
    std::vector<std::uint64_t> sockets;
    if (!proc_socket_inodes(inspect.pid, sockets) || !proc_socket_inodes(worker, sockets)) {
        error = "nginx process socket ownership scan failed";
        return false;
    }
    std::string tcp;
    std::string tcp6;
    if (!read_file("/proc/" + std::to_string(inspect.pid) + "/net/tcp", tcp) ||
        !read_file("/proc/" + std::to_string(inspect.pid) + "/net/tcp6", tcp6)) {
        error = "nginx namespace TCP/TCP6 tables were unavailable";
        return false;
    }
    u32 positive = 0u, guard = 0u;
    NginxProcTcpTable table;
    fixture_privileged_listener::Diagnostic parser_diagnostic;
    fixture_privileged_listener::ListenerEvidence listener;
    if (!parse_ipv4(owner.builder_baseline.positive_ip, positive) ||
        !parse_ipv4(owner.builder_baseline.guard_ip, guard) ||
        !parse_nginx_proc_net_tcp(tcp, 8u, table)) {
        error = "nginx TCP table or listener plan was rejected";
        return false;
    }
    if (!strict_exact_nginx_listener(
            table, positive, guard, sockets, listener, parser_diagnostic) ||
        listener.child_owned_inode == 0u ||
        !strict_tcp6_port_absent(tcp6, kExactInputTopologyBuilderPort)) {
        error = "nginx exact IPv4 listener/TCP6 absence evidence was rejected";
        return false;
    }
    sample.tcp_exact = true;
    sample.tcp6_port_absent = true;
    sample.listener_inode = listener.child_owned_inode;
    if (!revalidate_nginx_sample_end(owner, sample, cgroup, deadline_ns, error)) return false;
    sample.complete = true;
    return true;
}

static bool nginx_sibling_absent(ExactInputMountOwner& owner,
                                 std::int64_t deadline_ns,
                                 std::string& error) {
    CommandResult result;
    if (!owner.nginx_sibling.id.empty()) {
        if (!run_command_before(
                {"docker", "inspect", owner.nginx_sibling.id}, deadline_ns, result) ||
            exited_zero(result)) {
            if (result.timed_out) {
                error = "exact nginx sibling ID absence remained uncertain";
                return false;
            }
        }
    }
    if (!run_command_before({"docker",
                             "ps",
                             "-aq",
                             "--no-trunc",
                             "--filter",
                             "name=^/" + owner.nginx_sibling.name + "$"},
                            deadline_ns,
                            result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "nginx sibling name absence was not proven";
        return false;
    }
    if (!run_command_before({"docker",
                             "ps",
                             "-aq",
                             "--no-trunc",
                             "--filter",
                             "label=rut.token=" + owner.fixture.token(),
                             "--filter",
                             std::string("label=rut.role=") + kNginxRole},
                            deadline_ns,
                            result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "nginx token/role absence was not proven";
        return false;
    }
    return true;
}

static bool cgroup_empty(const std::string& path) {
    std::string contents;
    if (path.empty()) return false;
    const std::string file = "/sys/fs/cgroup" + path + "/cgroup.procs";
    if (read_file(file, contents)) return trim(contents).empty();
    const std::string directory = "/sys/fs/cgroup" + path;
    return access(directory.c_str(), F_OK) != 0 && errno == ENOENT;
}

static void close_nginx_pidfds(NginxSiblingLease& lease) {
    if (lease.master_pidfd >= 0) close(lease.master_pidfd);
    if (lease.worker_pidfd >= 0) close(lease.worker_pidfd);
    lease.master_pidfd = -1;
    lease.worker_pidfd = -1;
}

static void owner_failure(ExactInputMountOwner& owner,
                          ExactInputMountDiagnostic& diagnostic,
                          ExactInputMountPhase phase,
                          const std::string& message,
                          int error_number = 0);

static bool topology_snapshot_equal(const HeldTopologySnapshot& left,
                                    const HeldTopologySnapshot& right) {
    return left.token == right.token && left.network_a_name == right.network_a_name &&
           left.network_a_id == right.network_a_id &&
           left.network_a_subnet == right.network_a_subnet &&
           left.network_a_gateway == right.network_a_gateway &&
           left.network_b_name == right.network_b_name && left.network_b_id == right.network_b_id &&
           left.network_b_subnet == right.network_b_subnet &&
           left.network_b_gateway == right.network_b_gateway &&
           left.holder_name == right.holder_name && left.holder_id == right.holder_id &&
           left.positive_ip == right.positive_ip && left.guard_ip == right.guard_ip &&
           left.holder_pid == right.holder_pid && left.holder_start == right.holder_start &&
           left.holder_netns == right.holder_netns;
}

static bool valid_builder_topology(const HeldTopologySnapshot& snapshot, std::string& error) {
    u32 positive = 0;
    u32 guard = 0;
    std::string canonical_positive;
    std::string canonical_guard;
    if (!lowercase_hex(snapshot.token, 48u) || snapshot.holder_pid <= 1 ||
        snapshot.holder_start == 0u || snapshot.holder_netns == 0u ||
        !parse_ipv4(snapshot.positive_ip, positive) || !format_ipv4(positive, canonical_positive) ||
        canonical_positive != snapshot.positive_ip || !parse_ipv4(snapshot.guard_ip, guard) ||
        !format_ipv4(guard, canonical_guard) || canonical_guard != snapshot.guard_ip ||
        positive == 0u || guard == 0u || positive == guard || (positive >> 24u) == 127u ||
        (guard >> 24u) == 127u) {
        error = "builder topology request was not canonical, nonloopback, distinct and live";
        return false;
    }
    return true;
}

static bool fresh_builder_identity(Fixture& fixture,
                                   const HeldTopologySnapshot& baseline,
                                   HeldTopologySnapshot& snapshot,
                                   std::string& error) {
    if (!fixture.verify_topology(FailurePoint::None, error)) return false;
    snapshot = fixture.current_topology_snapshot();
    if (!valid_builder_topology(snapshot, error) || !topology_snapshot_equal(baseline, snapshot)) {
        if (error.empty()) error = "builder topology identity drifted from bracket A";
        return false;
    }
    return true;
}

static bool capture_builder_bracket(ExactInputMountOwner& owner,
                                    ExactInputBuilderBracketEvidence& evidence,
                                    ExactInputMountFailurePoint bracket_fault,
                                    ExactInputMountDiagnostic& diagnostic) {
    std::string error;
    HeldTopologySnapshot bracket;
    if (!owner.fixture.verify_topology(FailurePoint::None, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Topology, error);
        return false;
    }
    bracket = owner.fixture.current_topology_snapshot();
    if (!valid_builder_topology(bracket, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::InputBuilder, error);
        return false;
    }
    evidence.topology_verified = true;
    const bool is_a = owner.builder_baseline.token.empty();
    if (is_a) owner.builder_baseline = bracket;
    if (owner.options.failure_point == bracket_fault) ++bracket.holder_start;
    if (!topology_snapshot_equal(owner.builder_baseline, bracket)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::InputBuilder,
                      "builder whole topology bracket differed from bracket A");
        return false;
    }
    evidence.snapshot_equal_to_a = true;

    const auto enclosed = [&](ExactInputMountFailurePoint fault,
                              bool (Fixture::*operation)(u16, std::string&),
                              bool& observed,
                              bool& pre_equal,
                              bool& post_equal) {
        HeldTopologySnapshot before;
        HeldTopologySnapshot after;
        if (!fresh_builder_identity(owner.fixture, owner.builder_baseline, before, error))
            return false;
        pre_equal = true;
        if (!(owner.fixture.*operation)(kExactInputTopologyBuilderPort, error)) return false;
        observed = true;
        if (!fresh_builder_identity(owner.fixture, owner.builder_baseline, after, error))
            return false;
        if (owner.options.failure_point == fault) ++after.holder_start;
        post_equal = topology_snapshot_equal(owner.builder_baseline, after);
        if (!post_equal) error = "builder observation topology bracket drifted";
        return post_equal;
    };
    if (!enclosed(ExactInputMountFailurePoint::BuilderRejectTcpBracket,
                  &Fixture::probe_port_absent,
                  evidence.tcp_absence_verified,
                  evidence.tcp_absence_pre_equal,
                  evidence.tcp_absence_post_equal) ||
        !enclosed(ExactInputMountFailurePoint::BuilderRejectTcp6Bracket,
                  &Fixture::probe_tcp6_port_absent,
                  evidence.tcp6_absence_verified,
                  evidence.tcp6_absence_pre_equal,
                  evidence.tcp6_absence_post_equal)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::InputBuilder, error);
        return false;
    }

    const auto enclosed_refusal = [&](ExactInputMountFailurePoint fault,
                                      const std::string& address,
                                      bool& observed,
                                      bool& pre_equal,
                                      bool& post_equal) {
        HeldTopologySnapshot before;
        HeldTopologySnapshot after;
        if (!fresh_builder_identity(owner.fixture, owner.builder_baseline, before, error))
            return false;
        pre_equal = true;
        if (!owner.fixture.probe_refused(address, kExactInputTopologyBuilderPort, error))
            return false;
        observed = true;
        if (!fresh_builder_identity(owner.fixture, owner.builder_baseline, after, error))
            return false;
        if (owner.options.failure_point == fault) ++after.holder_start;
        post_equal = topology_snapshot_equal(owner.builder_baseline, after);
        if (!post_equal) error = "builder refusal-probe topology bracket drifted";
        return post_equal;
    };
    if (!enclosed_refusal(ExactInputMountFailurePoint::BuilderRejectPositiveProbeBracket,
                          owner.builder_baseline.positive_ip,
                          evidence.positive_refusal_verified,
                          evidence.positive_refusal_pre_equal,
                          evidence.positive_refusal_post_equal) ||
        !enclosed_refusal(ExactInputMountFailurePoint::BuilderRejectGuardProbeBracket,
                          owner.builder_baseline.guard_ip,
                          evidence.guard_refusal_verified,
                          evidence.guard_refusal_pre_equal,
                          evidence.guard_refusal_post_equal)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::InputBuilder, error);
        return false;
    }
    HeldTopologySnapshot final_snapshot;
    if (!fresh_builder_identity(owner.fixture, owner.builder_baseline, final_snapshot, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::InputBuilder, error);
        return false;
    }
    return true;
}

static bool mount_inspect_equal(const ParsedMountInspect& left, const ParsedMountInspect& right) {
    const auto mount_equal = [](const ParsedMount& a, const ParsedMount& b) {
        return a.type == b.type && a.source == b.source && a.destination == b.destination &&
               a.mode == b.mode && a.propagation == b.propagation && a.read_only == b.read_only;
    };
    const auto list_equal = [&](const std::vector<ParsedMount>& a,
                                const std::vector<ParsedMount>& b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), mount_equal);
    };
    return left.id == right.id && left.name == right.name && left.user == right.user &&
           left.network_mode == right.network_mode && list_equal(left.requested, right.requested) &&
           list_equal(left.realized, right.realized);
}

static ExactInputReadOutcome capture_input_read_bracket(ExactInputMountOwner& owner,
                                                        bool before,
                                                        ExactInputReadObservation& observation,
                                                        std::string& error,
                                                        int& error_number) {
    fixture_exact_input_file_lease::Diagnostic file_diagnostic;
    if (before && owner.options.failure_point ==
                      ExactInputMountFailurePoint::InputReadRejectSourceRevalidation) {
        error = "injected exact input source revalidation rejection";
        return ExactInputReadOutcome::SourceRevalidationFailed;
    }
    if (!owner.input.revalidate(file_diagnostic)) {
        error = "exact input source revalidation failed at input-read bracket";
        error_number = file_diagnostic.error_number;
        return ExactInputReadOutcome::SourceRevalidationFailed;
    }
    if (before)
        observation.pre_source_revalidated = true;
    else
        observation.post_source_revalidated = true;

    if (!owner.fixture.revalidate_sidecar_identity(error)) {
        error = "exact sidecar identity failed at input-read bracket: " + error;
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    const HeldNamespaceSidecarSnapshot first = owner.fixture.sidecar_snapshot();
    if (!sidecar_snapshot_equal(first, owner.registered_sidecar)) {
        error = "input-read sidecar differed from the registered immutable snapshot";
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    if (before)
        observation.pre_container_identity = true;
    else
        observation.post_container_identity = true;
    observation.registered_identity_matched = true;

    ParsedMountInspect mount;
    if (!inspect_exact_mount(
            owner.fixture, owner.input.path(), owner.input.identity(), mount, error)) {
        error = "exact mount/Config.User inspection failed at input-read bracket: " + error;
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    if (!mount_inspect_equal(mount, owner.registered_mount)) {
        error = "input-read mount/Config.User differed from the registered snapshot";
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    if (before)
        observation.pre_mount_inspected = true;
    else
        observation.post_mount_inspected = true;
    observation.registered_mount_matched = true;

    const auto& identity = owner.input.identity();
    if (!proc_credentials_exact(first.pid, identity.uid, identity.gid)) {
        error = "actual sidecar /proc credentials failed at input-read bracket";
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    if (!owner.fixture.revalidate_sidecar_identity(error)) {
        error = "post-/proc exact sidecar identity failed at input-read bracket: " + error;
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    const HeldNamespaceSidecarSnapshot second = owner.fixture.sidecar_snapshot();
    if (!sidecar_snapshot_equal(first, second) ||
        !sidecar_snapshot_equal(second, owner.registered_sidecar)) {
        error = "sidecar PID/start/netns identity changed across input-read /proc evidence";
        return ExactInputReadOutcome::ContainerIdentityFailed;
    }
    if (before)
        observation.pre_proc_credentials = true;
    else
        observation.post_proc_credentials = true;
    return ExactInputReadOutcome::Complete;
}

static bool exact_write_source_bracket_equal(const ExactInputWriteSourceBracket& left,
                                             const ExactInputWriteSourceBracket& right) {
    return left.source_revalidated == right.source_revalidated &&
           left.source_bytes_revalidated == right.source_bytes_revalidated &&
           left.retained_ofd_revalidated == right.retained_ofd_revalidated &&
           left.container_identity_revalidated == right.container_identity_revalidated &&
           left.mount_revalidated == right.mount_revalidated &&
           left.proc_credentials_revalidated == right.proc_credentials_revalidated &&
           left.registered_identity_matched == right.registered_identity_matched &&
           left.registered_mount_matched == right.registered_mount_matched &&
           left.source_path == right.source_path && left.source_device == right.source_device &&
           left.source_inode == right.source_inode && left.source_mode == right.source_mode &&
           left.source_uid == right.source_uid && left.source_gid == right.source_gid &&
           left.source_size == right.source_size && left.source_links == right.source_links &&
           left.source_mtime_seconds == right.source_mtime_seconds &&
           left.source_mtime_nanoseconds == right.source_mtime_nanoseconds &&
           left.source_ctime_seconds == right.source_ctime_seconds &&
           left.source_ctime_nanoseconds == right.source_ctime_nanoseconds;
}

static bool capture_write_refusal_bracket(ExactInputMountOwner& owner,
                                          ExactInputMountFailurePoint rejection,
                                          ExactInputWriteSourceBracket& bracket,
                                          std::string& error,
                                          int& error_number) {
    if (owner.options.failure_point == rejection) {
        error = "injected write-refusal bracket rejection";
        return false;
    }
    fixture_exact_input_file_lease::Diagnostic file_diagnostic;
    if (!owner.input.revalidate(file_diagnostic)) {
        error = "exact source/OFD/bytes revalidation failed at write-refusal bracket";
        error_number = file_diagnostic.error_number;
        return false;
    }
    bracket.source_revalidated = true;
    bracket.source_bytes_revalidated = true;
    bracket.retained_ofd_revalidated = true;

    struct stat descriptor_stat{};
    struct stat path_stat{};
    if (fstat(owner.input.descriptor(), &descriptor_stat) != 0 ||
        lstat(owner.input.path().c_str(), &path_stat) != 0) {
        error_number = errno;
        error = "source metadata capture failed at write-refusal bracket";
        return false;
    }
    const auto& expected = owner.input.identity();
    const auto exact_stat = [&](const struct stat& value) {
        return static_cast<std::uint64_t>(value.st_dev) == expected.device &&
               static_cast<std::uint64_t>(value.st_ino) == expected.inode &&
               static_cast<std::uint64_t>(value.st_mode) == expected.mode &&
               static_cast<std::uint64_t>(value.st_uid) == expected.uid &&
               static_cast<std::uint64_t>(value.st_gid) == expected.gid &&
               static_cast<std::uint64_t>(value.st_size) == expected.size &&
               static_cast<std::uint64_t>(value.st_nlink) == expected.links;
    };
    if (!exact_stat(descriptor_stat) || !exact_stat(path_stat) ||
        descriptor_stat.st_mtim.tv_sec != path_stat.st_mtim.tv_sec ||
        descriptor_stat.st_mtim.tv_nsec != path_stat.st_mtim.tv_nsec ||
        descriptor_stat.st_ctim.tv_sec != path_stat.st_ctim.tv_sec ||
        descriptor_stat.st_ctim.tv_nsec != path_stat.st_ctim.tv_nsec) {
        error = "source path/descriptor metadata differed at write-refusal bracket";
        return false;
    }
    bracket.source_path = owner.input.path();
    bracket.source_device = expected.device;
    bracket.source_inode = expected.inode;
    bracket.source_mode = expected.mode;
    bracket.source_uid = expected.uid;
    bracket.source_gid = expected.gid;
    bracket.source_size = expected.size;
    bracket.source_links = expected.links;
    bracket.source_mtime_seconds = descriptor_stat.st_mtim.tv_sec;
    bracket.source_mtime_nanoseconds = descriptor_stat.st_mtim.tv_nsec;
    bracket.source_ctime_seconds = descriptor_stat.st_ctim.tv_sec;
    bracket.source_ctime_nanoseconds = descriptor_stat.st_ctim.tv_nsec;

    if (!owner.fixture.revalidate_sidecar_identity(error)) {
        error = "exact sidecar identity failed at write-refusal bracket: " + error;
        return false;
    }
    const HeldNamespaceSidecarSnapshot first = owner.fixture.sidecar_snapshot();
    if (!sidecar_snapshot_equal(first, owner.registered_sidecar)) {
        error = "write-refusal sidecar differed from registered immutable snapshot";
        return false;
    }
    bracket.container_identity_revalidated = true;
    bracket.registered_identity_matched = true;

    ParsedMountInspect mount;
    if (!inspect_exact_mount(
            owner.fixture, owner.input.path(), owner.input.identity(), mount, error)) {
        error = "exact mount/Config.User inspection failed at write-refusal bracket: " + error;
        return false;
    }
    if (!mount_inspect_equal(mount, owner.registered_mount)) {
        error = "write-refusal mount/Config.User differed from registered snapshot";
        return false;
    }
    bracket.mount_revalidated = true;
    bracket.registered_mount_matched = true;

    if (!proc_credentials_exact(first.pid, expected.uid, expected.gid)) {
        error = "actual sidecar /proc credentials failed at write-refusal bracket";
        return false;
    }
    if (!owner.fixture.revalidate_sidecar_identity(error)) {
        error = "post-/proc sidecar identity failed at write-refusal bracket: " + error;
        return false;
    }
    const HeldNamespaceSidecarSnapshot second = owner.fixture.sidecar_snapshot();
    if (!sidecar_snapshot_equal(first, second) ||
        !sidecar_snapshot_equal(second, owner.registered_sidecar)) {
        error = "sidecar identity changed across write-refusal /proc evidence";
        return false;
    }
    bracket.proc_credentials_revalidated = true;
    return true;
}

static bool exact_supervisor_command_complete(const ExactReadCommandResult& result) {
    return result.started && result.stdout_eof && result.stderr_eof && result.child_reaped &&
           result.wait_status_valid && result.process_group_owned && result.process_group_gone &&
           result.pidfd_opened && result.pidfd_identity_verified &&
           result.pidfd_closed_after_group_gone && result.final_deadline_recorded &&
           result.cleanup_completed_before_final_deadline && result.supervisor_session_verified &&
           result.supervisor_subreaper_verified && result.actual_exec_observed &&
           result.subtree_confinement_installed && result.group_echild_observed &&
           result.adopted_reap_count > 0u && !result.deadline_exceeded && !result.output_overflow &&
           result.stdout_read_errno == 0 && result.stderr_read_errno == 0;
}

static ExactInputWriteRefusalOutcome classify_write_control(const ExactReadCommandResult& result) {
    if (!result.started) return ExactInputWriteRefusalOutcome::CommandStartFailed;
    if (result.deadline_exceeded) return ExactInputWriteRefusalOutcome::DeadlineExceeded;
    if (result.output_overflow) return ExactInputWriteRefusalOutcome::OutputLimitExceeded;
    if (!exact_supervisor_command_complete(result))
        return ExactInputWriteRefusalOutcome::StreamError;
    if (WIFSIGNALED(result.wait_status)) return ExactInputWriteRefusalOutcome::ExitSignaled;
    if (!WIFEXITED(result.wait_status) || WEXITSTATUS(result.wait_status) != 0)
        return ExactInputWriteRefusalOutcome::ControlExitNonzero;
    if (!result.stdout_bytes.empty() || !result.stderr_bytes.empty())
        return ExactInputWriteRefusalOutcome::ControlOutputMismatch;
    return ExactInputWriteRefusalOutcome::Complete;
}

static ExactInputWriteRefusalOutcome classify_write_target(const ExactReadCommandResult& result,
                                                           const std::string& expected_stderr) {
    if (!result.started) return ExactInputWriteRefusalOutcome::CommandStartFailed;
    if (result.deadline_exceeded) return ExactInputWriteRefusalOutcome::DeadlineExceeded;
    if (result.output_overflow) return ExactInputWriteRefusalOutcome::OutputLimitExceeded;
    if (!exact_supervisor_command_complete(result))
        return ExactInputWriteRefusalOutcome::StreamError;
    if (WIFSIGNALED(result.wait_status)) return ExactInputWriteRefusalOutcome::ExitSignaled;
    if (!WIFEXITED(result.wait_status)) return ExactInputWriteRefusalOutcome::TargetWrongExit;
    if (WEXITSTATUS(result.wait_status) == 0)
        return ExactInputWriteRefusalOutcome::TargetUnexpectedSuccess;
    if (WEXITSTATUS(result.wait_status) != 1) return ExactInputWriteRefusalOutcome::TargetWrongExit;
    if (!result.stdout_bytes.empty()) return ExactInputWriteRefusalOutcome::TargetStdoutNotEmpty;
    if (result.stderr_bytes != expected_stderr)
        return ExactInputWriteRefusalOutcome::TargetStderrMismatch;
    return ExactInputWriteRefusalOutcome::Complete;
}

static bool write_refusal_self_checks_impl(std::uint32_t& mutation_rejections,
                                           ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    mutation_rejections = 0u;
    ExactReadCommandResult valid;
    valid.started = valid.stdout_eof = valid.stderr_eof = valid.child_reaped = true;
    valid.wait_status_valid = valid.process_group_owned = valid.process_group_gone = true;
    valid.pidfd_opened = valid.pidfd_identity_verified = true;
    valid.pidfd_closed_after_group_gone = valid.final_deadline_recorded = true;
    valid.cleanup_completed_before_final_deadline = true;
    valid.supervisor_session_verified = valid.supervisor_subreaper_verified = true;
    valid.actual_exec_observed = valid.subtree_confinement_installed = true;
    valid.group_echild_observed = true;
    valid.adopted_reap_count = 1u;
    const std::string expected =
        "dd: failed to open '/etc/nginx/nginx.conf': Read-only file system\n";
    ExactReadCommandResult target = valid;
    target.wait_status = 1 << 8;
    target.stderr_bytes = expected;
    if (classify_write_control(valid) != ExactInputWriteRefusalOutcome::Complete ||
        classify_write_target(target, expected) != ExactInputWriteRefusalOutcome::Complete) {
        diagnostic = {ExactInputMountPhase::WriteRefusalObservation,
                      0,
                      "valid write-refusal classifier seed was rejected"};
        return false;
    }
    const auto control_rejects = [&](ExactReadCommandResult changed,
                                     ExactInputWriteRefusalOutcome expected_outcome) {
        if (classify_write_control(changed) != expected_outcome) return false;
        ++mutation_rejections;
        return true;
    };
    ExactReadCommandResult changed = valid;
    changed.wait_status = 23 << 8;
    if (!control_rejects(changed, ExactInputWriteRefusalOutcome::ControlExitNonzero)) return false;
    changed = valid;
    changed.stderr_bytes = "unexpected";
    if (!control_rejects(changed, ExactInputWriteRefusalOutcome::ControlOutputMismatch))
        return false;
    changed = valid;
    changed.deadline_exceeded = true;
    if (!control_rejects(changed, ExactInputWriteRefusalOutcome::DeadlineExceeded)) return false;
    changed = valid;
    changed.wait_status = SIGUSR1;
    if (!control_rejects(changed, ExactInputWriteRefusalOutcome::ExitSignaled)) return false;
    changed = valid;
    changed.stdout_read_errno = EIO;
    if (!control_rejects(changed, ExactInputWriteRefusalOutcome::StreamError)) return false;
    changed = valid;
    changed.group_echild_observed = false;
    if (!control_rejects(changed, ExactInputWriteRefusalOutcome::StreamError)) return false;

    const auto target_rejects = [&](ExactReadCommandResult changed_result,
                                    ExactInputWriteRefusalOutcome expected_outcome) {
        if (classify_write_target(changed_result, expected) != expected_outcome) return false;
        ++mutation_rejections;
        return true;
    };
    changed = target;
    changed.wait_status = 0;
    if (!target_rejects(changed, ExactInputWriteRefusalOutcome::TargetUnexpectedSuccess))
        return false;
    changed = target;
    changed.wait_status = 2 << 8;
    if (!target_rejects(changed, ExactInputWriteRefusalOutcome::TargetWrongExit)) return false;
    changed = target;
    changed.stderr_bytes = "wrong";
    if (!target_rejects(changed, ExactInputWriteRefusalOutcome::TargetStderrMismatch)) return false;
    changed = target;
    changed.stdout_bytes = "x";
    if (!target_rejects(changed, ExactInputWriteRefusalOutcome::TargetStdoutNotEmpty)) return false;

    ExactInputWriteSourceBracket bracket;
    bracket.source_revalidated = bracket.source_bytes_revalidated = true;
    bracket.retained_ofd_revalidated = bracket.container_identity_revalidated = true;
    bracket.mount_revalidated = bracket.proc_credentials_revalidated = true;
    bracket.registered_identity_matched = bracket.registered_mount_matched = true;
    bracket.source_path = "/tmp/private/nginx.conf";
    bracket.source_device = 1u;
    bracket.source_inode = 2u;
    bracket.source_mode = S_IFREG | 0600u;
    bracket.source_uid = bracket.source_gid = 1000u;
    bracket.source_size = 3u;
    bracket.source_links = 1u;
    bracket.source_mtime_seconds = 4;
    bracket.source_mtime_nanoseconds = 5;
    bracket.source_ctime_seconds = 6;
    bracket.source_ctime_nanoseconds = 7;
    const auto bracket_rejects = [&](ExactInputWriteSourceBracket mutated) {
        if (exact_write_source_bracket_equal(bracket, mutated)) return false;
        ++mutation_rejections;
        return true;
    };
    auto mutated = bracket;
    mutated.source_bytes_revalidated = false;
    if (!bracket_rejects(mutated)) return false;
    mutated = bracket;
    mutated.retained_ofd_revalidated = false;
    if (!bracket_rejects(mutated)) return false;
    mutated = bracket;
    mutated.registered_identity_matched = false;
    if (!bracket_rejects(mutated)) return false;
    mutated = bracket;
    mutated.registered_mount_matched = false;
    if (!bracket_rejects(mutated)) return false;
    mutated = bracket;
    ++mutated.source_inode;
    if (!bracket_rejects(mutated)) return false;
    mutated = bracket;
    ++mutated.source_ctime_nanoseconds;
    if (!bracket_rejects(mutated)) return false;
    if (mutation_rejections != 16u) {
        diagnostic = {ExactInputMountPhase::WriteRefusalObservation,
                      0,
                      "write-refusal classifier/mutation rejection count differed"};
        return false;
    }
    return true;
}

static void sync_setup_event_evidence(ExactInputMountOwner& owner) {
    const SetupEventEvidence& evidence = owner.fixture.setup_event_evidence();
    owner.receipt.network_a_create_count = evidence.network_a_create_count;
    owner.receipt.network_a_verify_count = evidence.network_a_verify_count;
    owner.receipt.network_b_create_count = evidence.network_b_create_count;
    owner.receipt.network_b_verify_count = evidence.network_b_verify_count;
    owner.receipt.both_ipam_verify_count = evidence.both_ipam_verify_count;
    owner.receipt.holder_create_count = evidence.holder_create_count;
    owner.receipt.holder_attach_a_verify_count = evidence.holder_attach_a_verify_count;
    owner.receipt.holder_attach_b_count = evidence.holder_attach_b_count;
}

struct ExactMountTopologySettlementContext {
    ExactInputMountOwner* owner = nullptr;
    std::uint32_t* order = nullptr;
};

static bool record_exact_mount_topology_settlement(void* opaque,
                                                   TopologySettlementEvent event,
                                                   bool removed,
                                                   std::string& error) {
    auto& context = *static_cast<ExactMountTopologySettlementContext*>(opaque);
    ExactInputMountOwner& owner = *context.owner;
    const auto settle =
        [&](bool acquired, bool& settled, std::uint32_t& event_order, std::uint32_t& remove_count) {
            if (settled) return;
            settled = true;
            if (acquired) event_order = ++*context.order;
            if (removed) ++remove_count;
        };
    switch (event) {
        case TopologySettlementEvent::Holder:
            settle(owner.receipt.holder_acquired,
                   owner.receipt.holder_settled,
                   owner.receipt.holder_order,
                   owner.receipt.holder_remove_command_count);
            break;
        case TopologySettlementEvent::NetworkB:
            settle(owner.receipt.network_b_acquired,
                   owner.receipt.network_b_settled,
                   owner.receipt.network_b_order,
                   owner.receipt.network_b_remove_command_count);
            if (owner.options.failure_point ==
                    ExactInputMountFailurePoint::RejectNetworkASettlementOnce &&
                !owner.topology_settlement_fault_consumed) {
                owner.topology_settlement_fault_consumed = true;
                error = "injected exact-input mount topology failure before network A settlement";
                return false;
            }
            break;
        case TopologySettlementEvent::NetworkA:
            settle(owner.receipt.network_a_acquired,
                   owner.receipt.network_a_settled,
                   owner.receipt.network_a_order,
                   owner.receipt.network_a_remove_command_count);
            break;
    }
    return true;
}

static void owner_failure(ExactInputMountOwner& owner,
                          ExactInputMountDiagnostic& diagnostic,
                          ExactInputMountPhase phase,
                          const std::string& message,
                          int error_number) {
    diagnostic = {phase, error_number, message};
    if (owner.receipt.diagnostic.phase == ExactInputMountPhase::None)
        owner.receipt.diagnostic = diagnostic;
    if (owner.state != ExactInputMountState::Settled)
        owner.state = ExactInputMountState::Unresolved;
    owner.snapshot.state = owner.state;
    owner.receipt.state = owner.state;
}

static void owner_operation_failure(ExactInputMountOwner& owner,
                                    ExactInputMountPhase phase,
                                    const std::string& message,
                                    int error_number = 0) {
    owner.operation_failed = true;
    if (owner.receipt.diagnostic.phase == ExactInputMountPhase::None)
        owner.receipt.diagnostic = {phase, error_number, message};
}

static bool injected_setup_failure(ExactInputMountOwner& owner,
                                   ExactInputMountDiagnostic& diagnostic,
                                   ExactInputMountFailurePoint actual,
                                   ExactInputMountFailurePoint expected,
                                   ExactInputMountPhase phase,
                                   const char* boundary) {
    if (actual != expected) return false;
    owner_failure(owner,
                  diagnostic,
                  phase,
                  std::string("injected exact-input mount setup failure after ") + boundary);
    return true;
}

static bool setup_exact_input_mount_sidecar_suffix(ExactInputMountOwner& owner,
                                                   std::uint32_t parser_rejections,
                                                   ExactInputMountDiagnostic& diagnostic);

static bool setup_exact_input_mount(ExactInputMountOwner& owner,
                                    ExactInputMountDiagnostic& diagnostic) {
    owner.state = ExactInputMountState::SettingUp;
    owner.snapshot.state = owner.state;
    std::string error;
    std::uint32_t parser_rejections = 0;
    if (!mount_parser_self_checks(parser_rejections, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::MountInspect, error);
        return false;
    }
    if (owner.options.failure_point == ExactInputMountFailurePoint::PreflightBeforeMutation) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Preflight,
                      "injected exact-input mount preflight failure before mutation");
        return false;
    }
    if (!docker_user_namespace_preflight(error) || !preflight(owner.fixture, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Preflight, error);
        return false;
    }
    fixture_private_directory_lease::Diagnostic directory_diagnostic;
    if (!fixture_private_directory_lease::PrivateDirectoryLease::create(owner.directory,
                                                                        directory_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Directory,
                      "exact input private directory creation failed",
                      directory_diagnostic.error_number);
        return false;
    }
    owner.mutated = true;
    owner.receipt.graph_mutated = true;
    owner.receipt.directory_acquired = true;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterDirectory,
                               ExactInputMountPhase::Directory,
                               "directory"))
        return false;

    fixture_exact_input_file_lease::Diagnostic file_diagnostic;
    if (!fixture_exact_input_file_lease::ExactInputFileLease::create(owner.directory,
                                                                     owner.bytes.data(),
                                                                     owner.bytes.size(),
                                                                     owner.input,
                                                                     file_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::InputFile,
                      "exact input file creation failed",
                      file_diagnostic.error_number);
        return false;
    }
    owner.receipt.input_acquired = true;
    char canonical[PATH_MAX]{};
    if (realpath(owner.input.path().c_str(), canonical) == nullptr ||
        owner.input.path() != canonical ||
        owner.input.path().find_first_of(",|#;\n\r\t ") != std::string::npos) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::InputFile,
                      "exact input file path was not canonical and delimiter-safe",
                      errno);
        return false;
    }
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterInputFile,
                               ExactInputMountPhase::InputFile,
                               "input file"))
        return false;

    FailurePoint network_point = FailurePoint::None;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkACreated)
        network_point = FailurePoint::AfterNetworkACreated;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkAVerified)
        network_point = FailurePoint::AfterNetworkAVerified;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkBCreated)
        network_point = FailurePoint::AfterNetworkBCreated;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkBVerified)
        network_point = FailurePoint::AfterNetworkBVerified;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterBothIpamVerified)
        network_point = FailurePoint::AfterBothIpamVerified;
    const bool networks_created = owner.fixture.create_networks(network_point, error);
    sync_setup_event_evidence(owner);
    if (!networks_created) {
        const CleanupEvidence acquired = owner.fixture.cleanup_evidence();
        owner.receipt.network_a_acquired = acquired.network_a_exists;
        owner.receipt.network_b_acquired = acquired.network_b_exists;
        owner_failure(owner, diagnostic, ExactInputMountPhase::Networks, error);
        return false;
    }
    owner.receipt.network_a_acquired = true;
    owner.receipt.network_b_acquired = true;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterNetworks,
                               ExactInputMountPhase::Networks,
                               "networks"))
        return false;
    const FailurePoint holder_point =
        owner.options.failure_point == ExactInputMountFailurePoint::AfterHolderCreated
            ? FailurePoint::AfterHolderCreated
            : FailurePoint::None;
    const bool holder_created = owner.fixture.create_holder(holder_point, error);
    sync_setup_event_evidence(owner);
    if (!holder_created) {
        owner.receipt.holder_acquired = owner.fixture.cleanup_evidence().holder_exists;
        owner_failure(owner, diagnostic, ExactInputMountPhase::Holder, error);
        return false;
    }
    owner.receipt.holder_acquired = true;
    FailurePoint attach_point = FailurePoint::None;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterHolderAttachedA)
        attach_point = FailurePoint::AfterHolderAttachedA;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterHolderAttachedB)
        attach_point = FailurePoint::AfterHolderAttachedB;
    const bool holder_attached = owner.fixture.attach_holder(attach_point, error);
    sync_setup_event_evidence(owner);
    if (!holder_attached) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Holder, error);
        return false;
    }
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterHolder,
                               ExactInputMountPhase::Holder,
                               "holder"))
        return false;
    if (!owner.fixture.verify_topology(FailurePoint::None, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Topology, error);
        return false;
    }
    owner.topology_complete = true;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterTopology,
                               ExactInputMountPhase::Topology,
                               "topology"))
        return false;
    return setup_exact_input_mount_sidecar_suffix(owner, parser_rejections, diagnostic);
}

static bool setup_exact_input_mount_sidecar_suffix(ExactInputMountOwner& owner,
                                                   std::uint32_t parser_rejections,
                                                   ExactInputMountDiagnostic& diagnostic) {
    std::string error;
    fixture_exact_input_file_lease::Diagnostic file_diagnostic;
    if (!owner.input.revalidate(file_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::FileRevalidation,
                      "exact input changed immediately before Docker create",
                      file_diagnostic.error_number);
        return false;
    }
    HeldNamespaceSidecarFailurePoint sidecar_point = HeldNamespaceSidecarFailurePoint::None;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterSidecarCreate)
        sidecar_point = HeldNamespaceSidecarFailurePoint::AfterCreate;
    if (owner.options.failure_point == ExactInputMountFailurePoint::SidecarCreateReportedTimeout)
        sidecar_point = HeldNamespaceSidecarFailurePoint::CreateReportedTimeout;
    if (owner.options.failure_point == ExactInputMountFailurePoint::SidecarCleanupReportedTimeout)
        sidecar_point = HeldNamespaceSidecarFailurePoint::CleanupReportedTimeout;
    if (!owner.fixture.create_exact_input_mount_sidecar(
            owner.input.path(), owner.input.identity(), owner.sidecar_argv, sidecar_point, error)) {
        owner.receipt.sidecar_acquired = owner.fixture.cleanup_evidence().sidecar_exists;
        owner_failure(owner, diagnostic, ExactInputMountPhase::Sidecar, error);
        return false;
    }
    owner.receipt.sidecar_acquired = true;
    if (!exact_input_mount_argv(owner.sidecar_argv, owner.input.path(), owner.input.identity())) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Sidecar,
                      "sidecar creation argv was not the exact argv-only mount dialect");
        return false;
    }
    ParsedMountInspect parsed;
    if (!owner.fixture.revalidate_sidecar_identity(error) ||
        !inspect_exact_mount(
            owner.fixture, owner.input.path(), owner.input.identity(), parsed, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::MountInspect, error);
        return false;
    }
    if (!owner.input.revalidate(file_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::FileRevalidation,
                      "exact input changed after Docker create/inspect",
                      file_diagnostic.error_number);
        return false;
    }
    const HeldNamespaceSidecarSnapshot& sidecar = owner.fixture.sidecar_snapshot();
    const auto& identity = owner.input.identity();
    if (!bracketed_proc_credentials_exact(
            owner.fixture,
            identity.uid,
            identity.gid,
            owner.options.failure_point ==
                ExactInputMountFailurePoint::CredentialBoundarySidecarDeath,
            error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::MountInspect, error);
        return false;
    }
    owner.snapshot.token = owner.fixture.token();
    owner.snapshot.source_path = owner.input.path();
    owner.snapshot.destination = kExactInputMountDestination;
    owner.snapshot.source_device = identity.device;
    owner.snapshot.source_inode = identity.inode;
    owner.snapshot.source_uid = identity.uid;
    owner.snapshot.source_gid = identity.gid;
    owner.snapshot.source_size = identity.size;
    owner.snapshot.holder_id = owner.fixture.holder_id();
    owner.snapshot.sidecar_id = sidecar.id;
    owner.snapshot.config_user = parsed.user;
    owner.snapshot.network_mode = parsed.network_mode;
    owner.snapshot.sidecar_argv = owner.sidecar_argv;
    const ParsedMount& requested = parsed.requested.front();
    owner.snapshot.requested_type = requested.type;
    owner.snapshot.requested_source = requested.source;
    owner.snapshot.requested_destination = requested.destination;
    owner.snapshot.requested_propagation = requested.propagation;
    owner.snapshot.requested_read_only = requested.read_only;
    const auto realized =
        std::find_if(parsed.realized.begin(), parsed.realized.end(), [](const ParsedMount& mount) {
            return mount.destination == kExactInputMountDestination;
        });
    owner.snapshot.realized_type = realized->type;
    owner.snapshot.realized_source = realized->source;
    owner.snapshot.realized_destination = realized->destination;
    owner.snapshot.realized_mode = realized->mode;
    owner.snapshot.realized_propagation = realized->propagation;
    owner.snapshot.realized_read_only = realized->read_only;
    owner.snapshot.exact_container_identity = true;
    owner.snapshot.exact_proc_credentials = true;
    owner.snapshot.parser_mutation_matrix_passed = true;
    owner.snapshot.parser_rejections = parser_rejections;
    owner.registered_sidecar = sidecar;
    owner.registered_mount = parsed;
    owner.state = ExactInputMountState::ReadyForObservation;
    owner.snapshot.state = owner.state;
    owner.receipt.state = owner.state;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterMountInspect,
                               ExactInputMountPhase::MountInspect,
                               "mount inspect"))
        return false;
    diagnostic = {};
    return true;
}

static void invoke_topology_builder(ExactInputTopologyBuilder builder,
                                    const ExactInputTopologyBuildRequest& request,
                                    void* context,
                                    ExactInputTopologyBuildSink& sink,
                                    ExactInputBuilderEvidence& evidence,
                                    std::atomic<bool>& builder_active) {
    ++evidence.invocation_count;
    builder_active.store(true, std::memory_order_release);
    try {
        evidence.callback_reported_success = builder(request, sink, context);
        evidence.returned_normally = true;
    } catch (...) {
        evidence.threw_exception = true;
    }
    builder_active.store(false, std::memory_order_release);
    evidence.sink_size = sink.size();
    evidence.sink_overflow = sink.overflowed();
}

static bool validate_topology_builder_output(const ExactInputBuilderEvidence& evidence,
                                             const ExactInputTopologyBuildSink& sink,
                                             ExactInputMountDiagnostic& diagnostic) {
    if (evidence.reentry_attempted) {
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EDEADLK,
                      "topology input builder attempted controller re-entry"};
        return false;
    }
    if (evidence.threw_exception) {
        diagnostic = {
            ExactInputMountPhase::InputBuilder, 0, "topology input builder threw an exception"};
        return false;
    }
    if (!evidence.callback_reported_success) {
        diagnostic = {
            ExactInputMountPhase::InputBuilder, 0, "topology input builder reported failure"};
        return false;
    }
    if (sink.overflowed()) {
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EOVERFLOW,
                      "topology input builder output exceeded 8192 bytes"};
        return false;
    }
    if (sink.size() == 0u) {
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EINVAL,
                      "topology input builder produced empty output"};
        return false;
    }
    diagnostic = {};
    return true;
}

static bool setup_exact_input_mount_from_topology_builder(ExactInputMountOwner& owner,
                                                          ExactInputTopologyBuilder builder,
                                                          void* context,
                                                          std::atomic<bool>& builder_active,
                                                          std::atomic<bool>& reentry_attempted,
                                                          ExactInputMountDiagnostic& diagnostic) {
    owner.state = ExactInputMountState::SettingUp;
    owner.snapshot.state = owner.state;
    owner.receipt.builder.applicable = true;
    std::string error;
    std::uint32_t parser_rejections = 0;
    if (!mount_parser_self_checks(parser_rejections, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::MountInspect, error);
        return false;
    }
    if (owner.options.failure_point == ExactInputMountFailurePoint::PreflightBeforeMutation) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Preflight,
                      "injected exact-input mount preflight failure before mutation");
        return false;
    }
    if (!docker_user_namespace_preflight(error) || !preflight(owner.fixture, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Preflight, error);
        return false;
    }

    // Docker create/connect operations can report an uncertain result.  Recovery
    // authority is raised before the first command; graph_mutated remains causal.
    owner.recovery_required = true;
    owner.receipt.recovery_required = true;
    owner.receipt.mutation_may_have_occurred = true;
    if (owner.options.failure_point == ExactInputMountFailurePoint::BuilderNetworkMayHaveMutated) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Networks,
                      "injected uncertain first network creation result");
        return false;
    }
    FailurePoint network_point = FailurePoint::None;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkACreated)
        network_point = FailurePoint::AfterNetworkACreated;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkAVerified)
        network_point = FailurePoint::AfterNetworkAVerified;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkBCreated)
        network_point = FailurePoint::AfterNetworkBCreated;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterNetworkBVerified)
        network_point = FailurePoint::AfterNetworkBVerified;
    else if (owner.options.failure_point == ExactInputMountFailurePoint::AfterBothIpamVerified)
        network_point = FailurePoint::AfterBothIpamVerified;
    const bool networks_created = owner.fixture.create_networks(network_point, error);
    sync_setup_event_evidence(owner);
    const CleanupEvidence network_evidence = owner.fixture.cleanup_evidence();
    owner.receipt.network_a_acquired = network_evidence.network_a_exists;
    owner.receipt.network_b_acquired = network_evidence.network_b_exists;
    if (owner.receipt.network_a_acquired || owner.receipt.network_b_acquired) {
        owner.mutated = true;
        owner.receipt.graph_mutated = true;
    }
    if (!networks_created) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Networks, error);
        return false;
    }
    owner.receipt.network_a_acquired = true;
    owner.receipt.network_b_acquired = true;
    owner.mutated = true;
    owner.receipt.graph_mutated = true;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterNetworks,
                               ExactInputMountPhase::Networks,
                               "networks"))
        return false;
    const FailurePoint holder_point =
        owner.options.failure_point == ExactInputMountFailurePoint::AfterHolderCreated
            ? FailurePoint::AfterHolderCreated
            : FailurePoint::None;
    const bool holder_created = owner.fixture.create_holder(holder_point, error);
    sync_setup_event_evidence(owner);
    owner.receipt.holder_acquired = owner.fixture.cleanup_evidence().holder_exists;
    if (!holder_created) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Holder, error);
        return false;
    }
    owner.receipt.holder_acquired = true;
    FailurePoint attach_point = FailurePoint::None;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterHolderAttachedA)
        attach_point = FailurePoint::AfterHolderAttachedA;
    if (owner.options.failure_point == ExactInputMountFailurePoint::AfterHolderAttachedB)
        attach_point = FailurePoint::AfterHolderAttachedB;
    if (!owner.fixture.attach_holder(attach_point, error)) {
        sync_setup_event_evidence(owner);
        owner_failure(owner, diagnostic, ExactInputMountPhase::Holder, error);
        return false;
    }
    sync_setup_event_evidence(owner);
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterHolder,
                               ExactInputMountPhase::Holder,
                               "holder"))
        return false;
    if (!owner.fixture.verify_topology(FailurePoint::None, error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::Topology, error);
        return false;
    }
    owner.topology_complete = true;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterTopology,
                               ExactInputMountPhase::Topology,
                               "topology"))
        return false;

    if (!capture_builder_bracket(owner,
                                 owner.receipt.builder.bracket_a,
                                 ExactInputMountFailurePoint::BuilderRejectBracketA,
                                 diagnostic))
        return false;
    ExactInputTopologyBuildRequest request;
    std::copy(owner.builder_baseline.token.begin(),
              owner.builder_baseline.token.end(),
              request.token.begin());
    std::copy(owner.builder_baseline.positive_ip.begin(),
              owner.builder_baseline.positive_ip.end(),
              request.positive_ipv4.begin());
    std::copy(owner.builder_baseline.guard_ip.begin(),
              owner.builder_baseline.guard_ip.end(),
              request.guard_ipv4.begin());
    request.port = kExactInputTopologyBuilderPort;
    owner.receipt.builder.token = request.token;
    owner.receipt.builder.positive_ipv4 = request.positive_ipv4;
    owner.receipt.builder.guard_ipv4 = request.guard_ipv4;
    owner.receipt.builder.port = request.port;
    owner.receipt.builder.request_validated = true;

    ExactInputTopologyBuildSink sink;
    invoke_topology_builder(builder, request, context, sink, owner.receipt.builder, builder_active);
    owner.receipt.builder.reentry_attempted = reentry_attempted.load(std::memory_order_acquire);

    // B is authoritative and always wins over callback/re-entry/output errors.
    if (!capture_builder_bracket(owner,
                                 owner.receipt.builder.bracket_b,
                                 ExactInputMountFailurePoint::BuilderRejectBracketB,
                                 diagnostic))
        return false;
    ExactInputMountDiagnostic builder_diagnostic;
    if (!validate_topology_builder_output(owner.receipt.builder, sink, builder_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      builder_diagnostic.phase,
                      builder_diagnostic.message,
                      builder_diagnostic.error_number);
        return false;
    }
    owner.bytes.assign(sink.data(), sink.size());
    owner.receipt.builder.output_accepted = true;

    fixture_private_directory_lease::Diagnostic directory_diagnostic;
    if (owner.options.failure_point ==
        ExactInputMountFailurePoint::BuilderDirectoryMayHaveMutated) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Directory,
                      "injected uncertain directory creation result");
        return false;
    }
    if (!fixture_private_directory_lease::PrivateDirectoryLease::create(owner.directory,
                                                                        directory_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Directory,
                      "exact input private directory creation failed",
                      directory_diagnostic.error_number);
        return false;
    }
    owner.receipt.directory_acquired = true;
    owner.receipt.builder.directory_acquired_after_builder = true;
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterDirectory,
                               ExactInputMountPhase::Directory,
                               "directory"))
        return false;
    if (!capture_builder_bracket(owner,
                                 owner.receipt.builder.bracket_c,
                                 ExactInputMountFailurePoint::BuilderRejectBracketC,
                                 diagnostic))
        return false;

    fixture_exact_input_file_lease::Diagnostic file_diagnostic;
    if (owner.options.failure_point == ExactInputMountFailurePoint::BuilderInputMayHaveMutated) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::InputFile,
                      "injected uncertain exact input creation result");
        return false;
    }
    if (!fixture_exact_input_file_lease::ExactInputFileLease::create(owner.directory,
                                                                     owner.bytes.data(),
                                                                     owner.bytes.size(),
                                                                     owner.input,
                                                                     file_diagnostic)) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::InputFile,
                      "exact input file creation failed",
                      file_diagnostic.error_number);
        return false;
    }
    owner.receipt.input_acquired = true;
    owner.receipt.builder.input_acquired_after_builder = true;
    char canonical[PATH_MAX]{};
    if (realpath(owner.input.path().c_str(), canonical) == nullptr ||
        owner.input.path() != canonical ||
        owner.input.path().find_first_of(",|#;\n\r\t ") != std::string::npos) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::InputFile,
                      "exact input file path was not canonical and delimiter-safe",
                      errno);
        return false;
    }
    if (injected_setup_failure(owner,
                               diagnostic,
                               owner.options.failure_point,
                               ExactInputMountFailurePoint::AfterInputFile,
                               ExactInputMountPhase::InputFile,
                               "input file"))
        return false;
    if (!capture_builder_bracket(owner,
                                 owner.receipt.builder.bracket_d,
                                 ExactInputMountFailurePoint::BuilderRejectBracketD,
                                 diagnostic))
        return false;
    return setup_exact_input_mount_sidecar_suffix(owner, parser_rejections, diagnostic);
}

static bool pidfd_dead(int descriptor) {
    if (descriptor < 0) return false;
    pollfd item{descriptor, POLLIN, 0};
    return poll(&item, 1u, 0) == 1 && (item.revents & POLLIN) != 0;
}

static bool wait_nginx_stopped(ExactInputMountOwner& owner,
                               std::int64_t limit_ns,
                               int& exit_code,
                               std::string& error) {
    while (remaining_command_ms(limit_ns) > 0) {
        NginxInspectEvidence inspect;
        if (!inspect_nginx_sibling(owner, inspect, error, limit_ns)) return false;
        if (!inspect.running) {
            exit_code = inspect.exit_code;
            return true;
        }
        (void)poll(nullptr, 0, 25);
    }
    error = "nginx sibling did not stop before phase deadline";
    return false;
}

static bool settle_nginx_sibling(ExactInputMountOwner& owner,
                                 ExactInputNginxLifecycleObservation& observation,
                                 std::int64_t final_deadline_ns,
                                 bool require_quit_only,
                                 std::string& error) {
    NginxSiblingLease& lease = owner.nginx_sibling;
    if (!lease.mutation_may_have_occurred && !lease.exists) {
        close_nginx_pidfds(lease);
        return true;
    }
    const std::int64_t quit_deadline = final_deadline_ns - 8000000000LL;
    const std::int64_t term_deadline = final_deadline_ns - 5000000000LL;
    const std::int64_t kill_deadline = final_deadline_ns - 3000000000LL;
    NginxInspectEvidence inspect;
    std::string inspect_error;
    if (!inspect_nginx_sibling(owner, inspect, inspect_error, final_deadline_ns)) {
        std::string absent_error;
        if (nginx_sibling_absent(owner, final_deadline_ns, absent_error)) {
            lease.exists = false;
            lease.running = false;
            lease.mutation_may_have_occurred = false;
            lease.operation_failed = true;
            observation.operation_failed = true;
            observation.exact_absence = true;
            close_nginx_pidfds(lease);
            error = "nginx sibling disappeared before identity-safe settlement";
            return true;
        }
        error = inspect_error + "; " + absent_error;
        return false;
    }
    lease.id = inspect.id;
    lease.exists = true;
    lease.running = inspect.running;
    bool operation_ok = true;
    int exit_code = inspect.exit_code;
    if (inspect.running) {
        CommandResult signal;
        observation.quit_attempted = true;
        if (!run_command_before(
                {"docker", "kill", "--signal=SIGQUIT", lease.id}, quit_deadline, signal) ||
            !exited_zero(signal) || !wait_nginx_stopped(owner, quit_deadline, exit_code, error)) {
            operation_ok = false;
            observation.uncertain_cleanup = observation.uncertain_cleanup || signal.timed_out;
            CommandResult term;
            observation.term_attempted = true;
            (void)run_command_before(
                {"docker", "kill", "--signal=SIGTERM", lease.id}, term_deadline, term);
            observation.uncertain_cleanup = observation.uncertain_cleanup || term.timed_out;
            if (!wait_nginx_stopped(owner, term_deadline, exit_code, inspect_error)) {
                CommandResult killed;
                observation.kill_attempted = true;
                (void)run_command_before(
                    {"docker", "kill", "--signal=SIGKILL", lease.id}, kill_deadline, killed);
                observation.uncertain_cleanup = observation.uncertain_cleanup || killed.timed_out;
                if (!wait_nginx_stopped(owner, kill_deadline, exit_code, inspect_error)) {
                    error = "nginx sibling remained live after QUIT/TERM/KILL escalation";
                    return false;
                }
            }
        } else {
            observation.quit_only = true;
        }
    }
    observation.stopped_exit_zero = exit_code == 0;
    if (require_quit_only && (!observation.quit_only || !observation.stopped_exit_zero))
        operation_ok = false;

    const auto death_deadline = std::min<std::int64_t>(kill_deadline, final_deadline_ns);
    while (remaining_command_ms(death_deadline) > 0 &&
           ((!pidfd_dead(lease.master_pidfd) && lease.master_pidfd >= 0) ||
            (!pidfd_dead(lease.worker_pidfd) && lease.worker_pidfd >= 0)))
        (void)poll(nullptr, 0, 10);
    observation.cgroup_empty_after_stop = cgroup_empty(lease.cgroup_path);
    if ((!pidfd_dead(lease.master_pidfd) && lease.master_pidfd >= 0) ||
        (!pidfd_dead(lease.worker_pidfd) && lease.worker_pidfd >= 0) ||
        (!lease.cgroup_path.empty() && !observation.cgroup_empty_after_stop))
        operation_ok = false;

    CommandResult logs;
    if (!run_command_before({"docker", "logs", lease.id}, kill_deadline, logs, false, 8192u) ||
        !exited_zero(logs))
        operation_ok = false;

    if (owner.options.failure_point == ExactInputMountFailurePoint::NginxRemoveUnresolved &&
        !owner.nginx_unresolved_fault_consumed) {
        owner.nginx_unresolved_fault_consumed = true;
        observation.operation_failed = true;
        lease.operation_failed = true;
        error = "injected unresolved nginx removal response";
        return false;
    }
    CommandResult removal;
    ++observation.remove_count;
    ++owner.receipt.nginx_remove_count;
    const bool report_timeout =
        owner.options.failure_point == ExactInputMountFailurePoint::NginxRemoveReportedTimeout;
    const bool removal_ok =
        run_command_before({"docker", "rm", lease.id}, final_deadline_ns, removal, report_timeout);
    if (removal.timed_out) {
        operation_ok = false;
        observation.uncertain_cleanup = true;
    }
    if ((!removal_ok || !exited_zero(removal)) && !removal.timed_out) {
        CommandResult forced;
        operation_ok = false;
        observation.force_remove_attempted = true;
        (void)run_command_before({"docker", "rm", "-f", lease.id}, final_deadline_ns, forced);
        observation.uncertain_cleanup = observation.uncertain_cleanup || forced.timed_out;
    } else if (!removal.timed_out) {
        observation.removed_nonforce = true;
    }
    std::string absent_error;
    if (!nginx_sibling_absent(owner, final_deadline_ns, absent_error)) {
        error = "nginx sibling removal/absence proof failed: " + absent_error;
        return false;
    }
    observation.exact_absence = true;
    lease.exists = false;
    lease.running = false;
    lease.mutation_may_have_occurred = false;
    close_nginx_pidfds(lease);
    if (!operation_ok) {
        lease.operation_failed = true;
        observation.operation_failed = true;
        if (error.empty()) error = "nginx sibling required uncertain or escalated settlement";
    }
    return true;
}

static bool revalidate_nginx_baseline(ExactInputMountOwner& owner, std::string& error) {
    fixture_exact_input_file_lease::Diagnostic source_diagnostic;
    if (!owner.input.revalidate(source_diagnostic) ||
        !owner.fixture.revalidate_sidecar_identity(error) ||
        !sidecar_snapshot_equal(owner.fixture.sidecar_snapshot(), owner.registered_sidecar)) {
        if (error.empty()) error = "source or inert sidecar changed after nginx lifecycle";
        return false;
    }
    ParsedMountInspect mount;
    if (!inspect_exact_mount(
            owner.fixture, owner.input.path(), owner.input.identity(), mount, error) ||
        !mount_inspect_equal(mount, owner.registered_mount) ||
        !owner.fixture.verify_topology(FailurePoint::None, error) ||
        !topology_snapshot_equal(owner.builder_baseline,
                                 owner.fixture.current_topology_snapshot()) ||
        !owner.fixture.probe_port_absent(kExactInputTopologyBuilderPort, error) ||
        !owner.fixture.probe_tcp6_port_absent(kExactInputTopologyBuilderPort, error)) {
        if (error.empty()) error = "post-nginx source/mount/topology/listener baseline drifted";
        return false;
    }
    return true;
}

static bool recover_exact_input_mount(ExactInputMountOwner& owner,
                                      ExactInputMountDiagnostic& diagnostic) {
    if (owner.settled) {
        diagnostic = owner.receipt.diagnostic;
        return owner.receipt.terminal_result == ExactInputMountTerminalResult::SettledCleanly;
    }
    if (owner.state == ExactInputMountState::Recovering) {
        owner_failure(owner,
                      diagnostic,
                      ExactInputMountPhase::Lifecycle,
                      "exact input mount recovery re-entry was rejected");
        return false;
    }
    owner.state = ExactInputMountState::Recovering;
    owner.snapshot.state = owner.state;
    owner.receipt.state = owner.state;
    owner.receipt.attempted = true;
    if (!owner.mutated && !owner.recovery_required) {
        owner.receipt.cleanup_not_applicable = true;
        owner.receipt.final_zero_residue = true;
        owner.receipt.settlement_complete = true;
        owner.receipt.terminal_frozen = true;
        owner.receipt.terminal_result = ExactInputMountTerminalResult::SettledCleanly;
        owner.settled = true;
        owner.state = ExactInputMountState::Settled;
        owner.snapshot.state = owner.state;
        owner.receipt.state = owner.state;
        diagnostic = {};
        return true;
    }
    std::string error;
    std::uint32_t order = std::max({owner.receipt.sidecar_order,
                                    owner.receipt.nginx_sibling_order,
                                    owner.receipt.input_order,
                                    owner.receipt.directory_order,
                                    owner.receipt.holder_order,
                                    owner.receipt.network_b_order,
                                    owner.receipt.network_a_order});
    bool just_disconnected = false;

    if (!owner.receipt.nginx_sibling_acquired && !owner.nginx_sibling.mutation_may_have_occurred &&
        !owner.nginx_sibling.exists)
        owner.receipt.nginx_sibling_settled = true;

    if ((owner.receipt.nginx_sibling_acquired || owner.nginx_sibling.mutation_may_have_occurred ||
         owner.nginx_sibling.exists) &&
        !owner.receipt.nginx_sibling_settled) {
        const std::int64_t now = exact_read_monotonic_ns();
        if (now <= 0 || now > std::numeric_limits<std::int64_t>::max() - 30000000000LL) {
            owner_failure(owner,
                          diagnostic,
                          ExactInputMountPhase::Lifecycle,
                          "nginx recovery deadline could not be formed",
                          EOVERFLOW);
            return false;
        }
        error.clear();
        ExactInputNginxLifecycleObservation recovery_observation =
            owner.nginx_lifecycle_observation;
        if (!settle_nginx_sibling(owner, recovery_observation, now + 30000000000LL, false, error)) {
            owner_failure(owner, diagnostic, ExactInputMountPhase::Lifecycle, error);
            return false;
        }
        owner.receipt.nginx_sibling_settled = true;
        if (owner.receipt.nginx_sibling_acquired) owner.receipt.nginx_sibling_order = ++order;
        if (owner.nginx_sibling.operation_failed)
            owner_operation_failure(owner, ExactInputMountPhase::Lifecycle, error);
    }

    if (owner.options.failure_point ==
            ExactInputMountFailurePoint::DisconnectNetworkBeforeInputCleanup &&
        !owner.disconnect_injected && owner.fixture.sidecar_exists()) {
        if (!owner.fixture.disconnect_network_b_for_mount_test(error)) {
            owner_failure(owner, diagnostic, ExactInputMountPhase::TopologyRevalidation, error);
            return false;
        }
        owner.disconnect_injected = true;
        just_disconnected = true;
    }
    if (owner.options.failure_point == ExactInputMountFailurePoint::RejectSidecarRevalidationOnce &&
        !owner.sidecar_fault_consumed) {
        owner.fixture.set_sidecar_revalidation_fault(HeldNamespaceSidecarRevalidationFault::Token);
    }
    if (owner.options.failure_point == ExactInputMountFailurePoint::SidecarDisappearBeforeCleanup &&
        !owner.sidecar_disappearance_consumed && owner.fixture.sidecar_exists()) {
        if (!owner.fixture.disappear_sidecar_before_cleanup(error)) {
            owner_failure(owner, diagnostic, ExactInputMountPhase::SidecarSettlement, error);
            return false;
        }
        owner.sidecar_disappearance_consumed = true;
    }
    const CleanupPhaseResult sidecar = owner.fixture.cleanup_sidecar_phase(error);
    if (owner.options.failure_point == ExactInputMountFailurePoint::RejectSidecarRevalidationOnce &&
        !owner.sidecar_fault_consumed) {
        owner.fixture.set_sidecar_revalidation_fault(HeldNamespaceSidecarRevalidationFault::None);
        owner.sidecar_fault_consumed = true;
    }
    if (!sidecar.settled) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::SidecarSettlement, error);
        return false;
    }
    if (!sidecar.operation_ok)
        owner_operation_failure(
            owner,
            ExactInputMountPhase::SidecarSettlement,
            error.empty() ? "sidecar settlement reported an operation failure" : error);
    if (!owner.receipt.sidecar_settled) {
        owner.receipt.sidecar_settled = true;
        if (owner.receipt.sidecar_acquired) owner.receipt.sidecar_order = ++order;
    }

    const bool topology_cleanup_already_started = owner.receipt.holder_settled ||
                                                  owner.receipt.network_b_settled ||
                                                  owner.receipt.network_a_settled;
    if (owner.topology_complete && !topology_cleanup_already_started) {
        if (just_disconnected) {
            owner_failure(owner,
                          diagnostic,
                          ExactInputMountPhase::TopologyRevalidation,
                          "injected network disconnect retained exact input graph");
            return false;
        }
        if (owner.disconnect_injected && !owner.restore_consumed) {
            if (!owner.options.restore_test_disconnect_on_retry) {
                owner_failure(owner,
                              diagnostic,
                              ExactInputMountPhase::TopologyRevalidation,
                              "injected network disconnect retained exact input graph");
                return false;
            }
            if (!owner.fixture.restore_network_b_for_mount_test(error)) {
                owner_failure(owner, diagnostic, ExactInputMountPhase::TopologyRevalidation, error);
                return false;
            }
            owner.restore_consumed = true;
        }
        if (!owner.fixture.verify_topology(FailurePoint::None, error)) {
            owner_failure(owner, diagnostic, ExactInputMountPhase::TopologyRevalidation, error);
            return false;
        }
        owner.receipt.first_topology_revalidated = true;
    }

    fixture_exact_input_file_lease::Diagnostic file_diagnostic;
    if (owner.input.state() != fixture_exact_input_file_lease::State::Empty &&
        owner.input.state() != fixture_exact_input_file_lease::State::Settled) {
        if (owner.input.active() && !owner.input.revalidate(file_diagnostic)) {
            owner_failure(owner,
                          diagnostic,
                          ExactInputMountPhase::FileRevalidation,
                          "exact input revalidation failed before settlement",
                          file_diagnostic.error_number);
            return false;
        }
        if (!owner.input.cleanup(file_diagnostic)) {
            owner_failure(owner,
                          diagnostic,
                          ExactInputMountPhase::InputSettlement,
                          "exact input settlement failed",
                          file_diagnostic.error_number);
            return false;
        }
    }
    if (!owner.receipt.input_settled) {
        owner.receipt.input_settled = true;
        if (owner.receipt.input_acquired) owner.receipt.input_order = ++order;
    }

    fixture_private_directory_lease::Diagnostic directory_diagnostic;
    if (owner.directory.state() != fixture_private_directory_lease::State::Empty &&
        owner.directory.state() != fixture_private_directory_lease::State::Removed) {
        if (!owner.directory.settle(directory_diagnostic)) {
            owner_failure(owner,
                          diagnostic,
                          ExactInputMountPhase::DirectorySettlement,
                          "exact input directory settlement failed",
                          directory_diagnostic.error_number);
            return false;
        }
    }
    if (!owner.receipt.directory_settled) {
        owner.receipt.directory_settled = true;
        if (owner.receipt.directory_acquired) owner.receipt.directory_order = ++order;
    }

    if (owner.topology_complete && !topology_cleanup_already_started) {
        error.clear();
        if (!owner.fixture.verify_topology(FailurePoint::None, error)) {
            owner_failure(owner, diagnostic, ExactInputMountPhase::TopologyRevalidation, error);
            return false;
        }
        owner.receipt.second_topology_revalidated = true;
    }
    if (owner.options.failure_point == ExactInputMountFailurePoint::HolderDisappearBeforeCleanup &&
        !owner.holder_disappearance_consumed && owner.receipt.holder_acquired) {
        error.clear();
        if (!owner.fixture.disappear_holder_before_cleanup(error)) {
            owner_failure(owner, diagnostic, ExactInputMountPhase::HolderSettlement, error);
            return false;
        }
        owner.holder_disappearance_consumed = true;
        owner.receipt.holder_settled = true;
        owner.receipt.holder_order = ++order;
    }
    error.clear();
    ExactMountTopologySettlementContext settlement_context{&owner, &order};
    const CleanupPhaseResult topology = owner.fixture.cleanup_topology_phase(
        error, record_exact_mount_topology_settlement, &settlement_context);
    if (!topology.settled) {
        const ExactInputMountPhase phase =
            owner.options.failure_point ==
                        ExactInputMountFailurePoint::RejectNetworkASettlementOnce &&
                    owner.topology_settlement_fault_consumed && owner.receipt.network_b_settled &&
                    !owner.receipt.network_a_settled
                ? ExactInputMountPhase::NetworkSettlement
                : ExactInputMountPhase::HolderSettlement;
        owner_failure(owner, diagnostic, phase, error);
        return false;
    }
    if (!topology.operation_ok)
        owner_operation_failure(
            owner,
            ExactInputMountPhase::HolderSettlement,
            error.empty() ? "topology settlement reported an operation failure" : error);
    error.clear();
    if (!audit_zero_residue(owner.fixture.token(),
                            owner.fixture.network_a().name,
                            owner.fixture.network_b().name,
                            owner.fixture.holder_name(),
                            error)) {
        owner_failure(owner, diagnostic, ExactInputMountPhase::FinalAudit, error);
        return false;
    }
    owner.receipt.final_zero_residue = true;
    owner.receipt.settlement_complete = true;
    owner.receipt.terminal_frozen = true;
    owner.receipt.terminal_result = owner.operation_failed
                                        ? ExactInputMountTerminalResult::SettledWithOperationFailure
                                        : ExactInputMountTerminalResult::SettledCleanly;
    owner.settled = true;
    owner.state = ExactInputMountState::Settled;
    owner.snapshot.state = owner.state;
    owner.receipt.state = owner.state;
    diagnostic = owner.operation_failed ? owner.receipt.diagnostic : ExactInputMountDiagnostic{};
    return !owner.operation_failed;
}

}  // namespace

bool ExactInputTopologyBuildSink::append(const void* bytes, std::size_t size) noexcept {
    if (overflowed_) return false;
    if ((bytes == nullptr && size != 0u) || size > bytes_.size() - size_) {
        overflowed_ = true;
        return false;
    }
    if (size != 0u) std::memcpy(bytes_.data() + size_, bytes, size);
    size_ += size;
    return true;
}

std::uint64_t exact_input_mount_test_command_count() {
    return command_invocation_count;
}

std::uint64_t exact_input_mount_test_observation_command_count() {
    return observation_command_invocation_count;
}

bool exact_input_mount_test_write_refusal_self_checks(std::uint32_t& mutation_rejections,
                                                      ExactInputMountDiagnostic& diagnostic) {
    return write_refusal_self_checks_impl(mutation_rejections, diagnostic);
}

bool exact_input_mount_test_nginx_lifecycle_self_checks(std::uint32_t& mutation_rejections,
                                                        ExactInputMountDiagnostic& diagnostic) {
    mutation_rejections = 0u;
    diagnostic = {};
    ExactInputNginxProcessSample first;
    first.complete = first.container_identity_verified = first.source_revalidated = true;
    first.mount_verified = first.topology_verified = first.cgroup_exact = true;
    first.pidfile_exact = first.tcp_exact = first.tcp6_port_absent = true;
    first.end_container_identity_verified = first.end_source_revalidated = true;
    first.end_mount_verified = first.end_topology_verified = first.end_cgroup_exact = true;
    first.end_pidfile_exact = first.end_process_socket_owned = true;
    first.bracket_start_nanoseconds = 1000000000LL;
    first.bracket_end_nanoseconds = 1010000000LL;
    first.monotonic_nanoseconds = first.bracket_end_nanoseconds;
    first.master_pid = 101;
    first.worker_pid = 102;
    first.master_start = 201u;
    first.worker_start = 202u;
    first.listener_inode = 301u;
    first.end_master_pid = first.master_pid;
    first.end_worker_pid = first.worker_pid;
    first.end_master_start = first.master_start;
    first.end_worker_start = first.worker_start;
    ExactInputNginxProcessSample second = first;
    second.bracket_start_nanoseconds = first.bracket_end_nanoseconds + 250000000LL;
    second.bracket_end_nanoseconds = second.bracket_start_nanoseconds + 10000000LL;
    second.monotonic_nanoseconds = second.bracket_end_nanoseconds;
    if (!nginx_samples_stable(first, second)) {
        diagnostic = {ExactInputMountPhase::Lifecycle, 0, "valid nginx sample seed was rejected"};
        return false;
    }
    const auto reject_sample = [&](ExactInputNginxProcessSample mutation) {
        if (nginx_samples_stable(first, mutation)) return false;
        ++mutation_rejections;
        return true;
    };
    ExactInputNginxProcessSample mutation = second;
    mutation.complete = false;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    mutation.bracket_start_nanoseconds = first.bracket_end_nanoseconds + 249999999LL;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    ++mutation.master_pid;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    ++mutation.worker_pid;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    ++mutation.master_start;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    ++mutation.worker_start;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    ++mutation.listener_inode;
    if (!reject_sample(mutation)) return false;
    ExactInputNginxProcessSample zero_listener = first;
    zero_listener.listener_inode = 0u;
    if (nginx_samples_stable(zero_listener, second)) return false;
    ++mutation_rejections;
    mutation = second;
    ++mutation.end_worker_start;
    if (!reject_sample(mutation)) return false;
    mutation = second;
    mutation.end_topology_verified = false;
    if (!reject_sample(mutation)) return false;

    ExactInputNginxLifecycleObservation cleanup;
    cleanup.quit_attempted = true;
    cleanup.quit_only = true;
    cleanup.stopped_exit_zero = true;
    cleanup.cgroup_empty_after_stop = true;
    cleanup.removed_nonforce = true;
    cleanup.exact_absence = true;
    if (!nginx_graceful_cleanup_complete(cleanup)) return false;
    const auto reject_cleanup = [&](ExactInputNginxLifecycleObservation value) {
        if (nginx_graceful_cleanup_complete(value)) return false;
        ++mutation_rejections;
        return true;
    };
#define RUT_REJECT_NGINX_CLEANUP(field, value)                 \
    do {                                                       \
        ExactInputNginxLifecycleObservation changed = cleanup; \
        changed.field = value;                                 \
        if (!reject_cleanup(std::move(changed))) return false; \
    } while (false)
    RUT_REJECT_NGINX_CLEANUP(operation_failed, true);
    RUT_REJECT_NGINX_CLEANUP(quit_attempted, false);
    RUT_REJECT_NGINX_CLEANUP(quit_only, false);
    RUT_REJECT_NGINX_CLEANUP(term_attempted, true);
    RUT_REJECT_NGINX_CLEANUP(kill_attempted, true);
    RUT_REJECT_NGINX_CLEANUP(force_remove_attempted, true);
    RUT_REJECT_NGINX_CLEANUP(uncertain_cleanup, true);
    RUT_REJECT_NGINX_CLEANUP(stopped_exit_zero, false);
    RUT_REJECT_NGINX_CLEANUP(cgroup_empty_after_stop, false);
    RUT_REJECT_NGINX_CLEANUP(removed_nonforce, false);
    RUT_REJECT_NGINX_CLEANUP(exact_absence, false);
#undef RUT_REJECT_NGINX_CLEANUP

    const std::string tcp_header =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
        "timeout inode\n";
    const auto tcp_row = [](const std::string& local,
                            const std::string& state,
                            const std::string& inode,
                            unsigned slot,
                            const std::string& ssthresh = "0") {
        return " " + std::to_string(slot) + ": " + local + " 00000000:0000 " + state +
               " 00000000:00000000 00:00000000 00000000 1000 0 " + inode +
               " 1 0000000000000000 100 0 0 10 " + ssthresh + "\n";
    };
    const auto tcp_time_wait_row = [](const std::string& local, unsigned slot) {
        return " " + std::to_string(slot) + ": " + local +
               " 0100007F:C350 06 00000000:00000000 03:00000001 00000000 1000 0 0 "
               "3 0000000000000000\n";
    };
    const auto exact_listener = [&](const std::string& contents) {
        NginxProcTcpTable table;
        fixture_privileged_listener::Diagnostic parser;
        fixture_privileged_listener::ListenerEvidence listener;
        return parse_nginx_proc_net_tcp(contents, 8u, table) &&
               strict_exact_nginx_listener(
                   table, 0x0a010203u, 0x0a010204u, {301u}, listener, parser) &&
               listener.child_owned_inode == 301u;
    };
    const std::string valid_tcp = tcp_header + tcp_row("0302010A:A381", "0A", "301", 0u) +
                                  tcp_row("00000000:A380", "07", "999", 1u, "-1") +
                                  tcp_time_wait_row("0100007F:C001", 2u);
    if (!exact_listener(valid_tcp)) {
        diagnostic = {ExactInputMountPhase::Lifecycle, 0, "valid strict nginx TCP seed failed"};
        return false;
    }
    for (const std::string& rejected :
         std::array<std::string, 3>{tcp_header + tcp_row("0302010A:A381", "07", "301", 0u),
                                    valid_tcp + tcp_row("00000000:A381", "0A", "302", 2u),
                                    valid_tcp + tcp_row("0402010A:A381", "0A", "303", 2u)}) {
        if (exact_listener(rejected)) return false;
        ++mutation_rejections;
    }
    const auto reject_tcp = [&](std::string contents) {
        NginxProcTcpTable ignored;
        if (parse_nginx_proc_net_tcp(contents, 8u, ignored)) return false;
        ++mutation_rejections;
        return true;
    };
    const std::string selected_ten_tokens = tcp_header +
                                            " 0: 0302010A:A381 00000000:0000 0A 00000000:00000000 "
                                            "00:00000000 00000000 1000 0 301\n";
    if (!reject_tcp(selected_ten_tokens) ||
        !reject_tcp(tcp_header +
                    " 0: 0302010A:A381 00000000:0000 0A 00000000-00000000 "
                    "00:00000000 00000000 1000 0 301 1 0000000000000000 100 0 0 10 0\n") ||
        !reject_tcp(tcp_header +
                    " 0: 0302010A:A381 00000000:0000 0A 00000000:00000000 "
                    "00-00000000 00000000 1000 0 301 1 0000000000000000 100 0 0 10 0\n") ||
        !reject_tcp(tcp_header + tcp_row("0302010A:A381", "0A", "301", 0u) +
                    " 1: 00000000:A380 00000000:0000 07 00000000:00000000 "
                    "00:00000000 00000000 uid 0 999 1 0000000000000000 100 0 0 10 0\n") ||
        !reject_tcp(tcp_header + tcp_row("0302010A:A381", "0A", "301", 0u) +
                    " 1: 00000000:A380 00000000:0000 07 00000000:00000000 "
                    "00:00000000 00000000 1000 0 inode 1 0000000000000000 100 0 0 10 0\n") ||
        !reject_tcp(tcp_header + tcp_row("0302010A:A381", "0A", "301", 0u) +
                    " 1: 00000000:A380 00000000:0000 07 00000000:00000000 "
                    "00:00000000 00000000 1000 0 999 1 0000000000000000 metric 0 0 10 0\n"))
        return false;

    const std::string tcp6_header =
        "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid "
        "timeout inode\n";
    const auto tcp6_row =
        [](const char* port, const char* state, const char* inode, const char* ssthresh = "0") {
            return std::string(" 0: 00000000000000000000000000000000:") + port +
                   " 00000000000000000000000000000000:0000 " + state +
                   " 00000000:00000000 00:00000000 00000000 1000 0 " + inode +
                   " 1 0000000000000000 100 0 0 10 " + ssthresh + "\n";
        };
    const auto tcp6_time_wait_row = [](const char* port) {
        return std::string(" 1: 00000000000000000000000000000000:") + port +
               " 00000000000000000000000000010000:C350 06 00000000:00000000 "
               "03:00000001 00000000 1000 0 0 3 0000000000000000\n";
    };
    const std::string absent =
        tcp6_header + tcp6_row("A380", "0A", "401", "-1") + tcp6_time_wait_row("C001");
    const std::string present_standard = absent + tcp6_row("A381", "07", "402");
    const std::string present_time_wait = absent + tcp6_time_wait_row("A381");
    const std::string malformed_tcp6 = tcp6_header + tcp6_row("A380", "0A", "not-an-inode");
    const std::string malformed_unrelated_tcp6 =
        tcp6_header +
        " 0: 00000000000000000000000000000000:A380 "
        "00000000000000000000000000000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000 1000 0 401 1 0000000000000000 100 0 0 10 -2\n";
    if (!strict_tcp6_port_absent(absent, kExactInputTopologyBuilderPort) ||
        strict_tcp6_port_absent(present_standard, kExactInputTopologyBuilderPort) ||
        strict_tcp6_port_absent(present_time_wait, kExactInputTopologyBuilderPort) ||
        strict_tcp6_port_absent(malformed_tcp6, kExactInputTopologyBuilderPort) ||
        strict_tcp6_port_absent(malformed_unrelated_tcp6, kExactInputTopologyBuilderPort)) {
        diagnostic = {
            ExactInputMountPhase::Lifecycle, 0, "strict nginx TCP6 parser self-check failed"};
        return false;
    }
    mutation_rejections += 4u;
    if (!nginx_auto_remove_disabled("false") || nginx_auto_remove_disabled("true") ||
        nginx_auto_remove_disabled("False") || nginx_auto_remove_disabled("false "))
        return false;
    mutation_rejections += 3u;
    CommandResult generic_timeout;
    generic_timeout.timed_out = true;
    if (!command_outcome_uncertain(generic_timeout) || command_outcome_uncertain(CommandResult{}))
        return false;
    ++mutation_rejections;
    const std::int64_t final = 30000000000LL;
    if (!(final - 15000000000LL < final - 12000000000LL &&
          final - 12000000000LL < final - 8000000000LL &&
          final - 8000000000LL < final - 5000000000LL &&
          final - 5000000000LL < final - 3000000000LL)) {
        diagnostic = {ExactInputMountPhase::Lifecycle, 0, "nginx deadline partition was invalid"};
        return false;
    }
    ++mutation_rejections;
    return mutation_rejections == 39u;
}

bool exact_input_mount_test_builder_self_checks(std::uint32_t& mutation_rejections,
                                                ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    mutation_rejections = 0u;
    HeldTopologySnapshot seed;
    seed.token = std::string(48u, 'a');
    seed.network_a_name = "a-name";
    seed.network_a_id = std::string(64u, 'b');
    seed.network_a_subnet = "10.1.0.0/24";
    seed.network_a_gateway = "10.1.0.1";
    seed.network_b_name = "b-name";
    seed.network_b_id = std::string(64u, 'c');
    seed.network_b_subnet = "10.2.0.0/24";
    seed.network_b_gateway = "10.2.0.1";
    seed.holder_name = "holder";
    seed.holder_id = std::string(64u, 'd');
    seed.positive_ip = "10.1.0.2";
    seed.guard_ip = "10.2.0.2";
    seed.holder_pid = 123;
    seed.holder_start = 456u;
    seed.holder_netns = 789u;
    std::string error;
    if (!valid_builder_topology(seed, error)) {
        diagnostic = {
            ExactInputMountPhase::InputBuilder, 0, "valid builder self-check seed failed"};
        return false;
    }
    const auto reject = [&](HeldTopologySnapshot mutation) {
        if (topology_snapshot_equal(seed, mutation)) return false;
        ++mutation_rejections;
        return true;
    };
#define RUT_REJECT_BUILDER_FIELD(field, value)          \
    do {                                                \
        HeldTopologySnapshot mutation = seed;           \
        mutation.field = value;                         \
        if (!reject(std::move(mutation))) return false; \
    } while (false)
    RUT_REJECT_BUILDER_FIELD(token, std::string(48u, 'e'));
    RUT_REJECT_BUILDER_FIELD(network_a_name, "changed");
    RUT_REJECT_BUILDER_FIELD(network_a_id, std::string(64u, 'e'));
    RUT_REJECT_BUILDER_FIELD(network_a_subnet, "10.3.0.0/24");
    RUT_REJECT_BUILDER_FIELD(network_a_gateway, "10.1.0.9");
    RUT_REJECT_BUILDER_FIELD(network_b_name, "changed-b");
    RUT_REJECT_BUILDER_FIELD(network_b_id, std::string(64u, 'f'));
    RUT_REJECT_BUILDER_FIELD(network_b_subnet, "10.4.0.0/24");
    RUT_REJECT_BUILDER_FIELD(network_b_gateway, "10.2.0.9");
    RUT_REJECT_BUILDER_FIELD(holder_name, "changed-holder");
    RUT_REJECT_BUILDER_FIELD(holder_id, std::string(64u, '0'));
    RUT_REJECT_BUILDER_FIELD(positive_ip, "10.1.0.3");
    RUT_REJECT_BUILDER_FIELD(guard_ip, "10.2.0.3");
    RUT_REJECT_BUILDER_FIELD(holder_pid, 124);
    RUT_REJECT_BUILDER_FIELD(holder_start, 457u);
    RUT_REJECT_BUILDER_FIELD(holder_netns, 790u);
#undef RUT_REJECT_BUILDER_FIELD
    const std::string header =
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout";
    const std::string absent4 = header + "\n 0: 0100007F:A380 00000000:0000 0A\n";
    const std::string present4 = header + "\n 0: 00000000:A381 00000000:0000 0A\n";
    const std::string absent6 = header + "\n 0: 00000000000000000000000000000000:A380 0:0 0A\n";
    const std::string present6 = header + "\n 0: 00000000000000000000000000000000:A381 0:0 0A\n";
    if (!proc_tcp_port_absent(absent4, kExactInputTopologyBuilderPort) ||
        proc_tcp_port_absent(present4, kExactInputTopologyBuilderPort) ||
        !proc_tcp_port_absent(absent6, kExactInputTopologyBuilderPort) ||
        proc_tcp_port_absent(present6, kExactInputTopologyBuilderPort)) {
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      0,
                      "TCP/TCP6 selected-port parser self-check failed"};
        return false;
    }
    mutation_rejections += 4u;

    ExactInputTopologyBuildRequest request;
    std::atomic<bool> active{false};
    const auto evaluate = [&](ExactInputTopologyBuilder builder,
                              bool reentry,
                              const char* expected_message,
                              int expected_errno) {
        ExactInputTopologyBuildSink sink;
        ExactInputBuilderEvidence evidence;
        invoke_topology_builder(builder, request, nullptr, sink, evidence, active);
        evidence.reentry_attempted = reentry;
        ExactInputMountDiagnostic outcome;
        if (validate_topology_builder_output(evidence, sink, outcome) ||
            outcome.phase != ExactInputMountPhase::InputBuilder ||
            outcome.message != expected_message || outcome.error_number != expected_errno ||
            active.load(std::memory_order_acquire) || evidence.invocation_count != 1u)
            return false;
        return true;
    };
    const auto empty =
        +[](const ExactInputTopologyBuildRequest&, ExactInputTopologyBuildSink&, void*) {
            return true;
        };
    const auto rejected =
        +[](const ExactInputTopologyBuildRequest&, ExactInputTopologyBuildSink&, void*) {
            return false;
        };
    const auto overflow =
        +[](const ExactInputTopologyBuildRequest&, ExactInputTopologyBuildSink& sink, void*) {
            std::array<char, kExactInputBuilderCapacity> bytes{};
            const char extra = 'x';
            return sink.append(bytes.data(), bytes.size()) && !sink.append(&extra, 1u);
        };
    const auto standard_throw =
        +[](const ExactInputTopologyBuildRequest&, ExactInputTopologyBuildSink&, void*) -> bool {
        throw std::runtime_error("must not escape");
    };
    const auto nonstandard_throw =
        +[](const ExactInputTopologyBuildRequest&, ExactInputTopologyBuildSink&, void*) -> bool {
        throw 17;
    };
    if (!evaluate(rejected, false, "topology input builder reported failure", 0) ||
        !evaluate(
            overflow, false, "topology input builder output exceeded 8192 bytes", EOVERFLOW) ||
        !evaluate(empty, false, "topology input builder produced empty output", EINVAL) ||
        !evaluate(standard_throw, false, "topology input builder threw an exception", 0) ||
        !evaluate(nonstandard_throw, false, "topology input builder threw an exception", 0) ||
        !evaluate(standard_throw,
                  true,
                  "topology input builder attempted controller re-entry",
                  EDEADLK)) {
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      0,
                      "builder callback outcome/priority self-check failed"};
        return false;
    }
    return true;
}

bool exact_input_mount_test_read_runner_case(ExactInputReadRunnerTestCase test_case,
                                             ExactInputReadObservation& observation,
                                             ExactInputMountDiagnostic& diagnostic) {
    observation = {};
    diagnostic = {};
    std::string name;
    std::string expected;
    int timeout_ms = 3000;
    ExactReadRunnerFault fault = ExactReadRunnerFault::None;
    switch (test_case) {
        case ExactInputReadRunnerTestCase::CommandStartFailure:
            name = "real-exec-failure";
            break;
        case ExactInputReadRunnerTestCase::ImmediateExecSuccess:
            name = "immediate";
            break;
        case ExactInputReadRunnerTestCase::LeaderExitWithDescendant:
            name = "leader-descendant";
            expected = "held";
            timeout_ms = 400;
            break;
        case ExactInputReadRunnerTestCase::ForkHandoffChain:
            name = "handoff";
            expected = "handoff";
            break;
        case ExactInputReadRunnerTestCase::SubtreeConfinement:
            name = "confinement";
            expected = "confined";
            break;
        case ExactInputReadRunnerTestCase::ParentControlEof:
            name = "control-eof-descendant";
            expected = "control-eof-descendant-live";
            fault = ExactReadRunnerFault::ParentControlEof;
            break;
        case ExactInputReadRunnerTestCase::StatusShort:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusShort;
            break;
        case ExactInputReadRunnerTestCase::StatusOversize:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusOversize;
            break;
        case ExactInputReadRunnerTestCase::StatusMultiple:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusMultiple;
            break;
        case ExactInputReadRunnerTestCase::StatusBadMagic:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusBadMagic;
            break;
        case ExactInputReadRunnerTestCase::StatusBadVersion:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusBadVersion;
            break;
        case ExactInputReadRunnerTestCase::StatusReserved:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusReserved;
            break;
        case ExactInputReadRunnerTestCase::StatusNoneStage:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusNoneStage;
            break;
        case ExactInputReadRunnerTestCase::StatusPidfdOpenStage:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusPidfdOpenStage;
            break;
        case ExactInputReadRunnerTestCase::StatusPidfdIdentityStage:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusPidfdIdentityStage;
            break;
        case ExactInputReadRunnerTestCase::StatusExecStatusProtocolStage:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusExecStatusProtocolStage;
            break;
        case ExactInputReadRunnerTestCase::StatusUnknownStage:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusUnknownStage;
            break;
        case ExactInputReadRunnerTestCase::StatusZeroErrno:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusZeroErrno;
            break;
        case ExactInputReadRunnerTestCase::StatusNegativeErrno:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusNegativeErrno;
            break;
        case ExactInputReadRunnerTestCase::StatusZeroBytePreExecDeath:
            name = "immediate";
            fault = ExactReadRunnerFault::StatusZeroBytePreExecDeath;
            break;
        case ExactInputReadRunnerTestCase::ForeignFdExcluded:
            name = "fd-excluded";
            expected = "fd-ok";
            break;
        case ExactInputReadRunnerTestCase::MaxSizeExact:
            name = "max";
            expected.resize(fixture_exact_input_file_lease::kMaximumInputBytes);
            for (size_t index = 0; index < expected.size(); ++index)
                expected[index] = static_cast<char>((index % 251u) + 1u);
            break;
        case ExactInputReadRunnerTestCase::EmbeddedNulExact:
            name = "nul";
            expected = std::string("a\0b", 3);
            break;
        case ExactInputReadRunnerTestCase::HeldOpenAfterExactBytes:
            name = "held";
            expected = "held";
            timeout_ms = 250;
            break;
        case ExactInputReadRunnerTestCase::ExtraByteThenEof:
            name = "extra";
            expected = "abc";
            break;
        case ExactInputReadRunnerTestCase::BeyondSentinel:
            name = "overflow";
            expected = "abc";
            break;
        case ExactInputReadRunnerTestCase::ReadErrorAfterBytes:
            name = "read-error";
            expected = "abc";
            fault = ExactReadRunnerFault::StdoutReadAfterBytes;
            break;
        case ExactInputReadRunnerTestCase::ExitSignaled:
            name = "signaled";
            break;
        case ExactInputReadRunnerTestCase::ExitNonzero:
            name = "nonzero";
            break;
        case ExactInputReadRunnerTestCase::NonemptyStderr:
            name = "stderr";
            expected = "abc";
            break;
    }
    if (expected.size() == std::numeric_limits<size_t>::max()) {
        diagnostic = {ExactInputMountPhase::InputObservation,
                      EOVERFLOW,
                      "runner self-check sentinel overflow"};
        return false;
    }
    observation.attempted = true;
    observation.expected_size = expected.size();
    if (test_case == ExactInputReadRunnerTestCase::CommandStartFailure)
        observation.command_argv = {"/rut-tests/definitely-not-an-executable"};
    else
        observation.command_argv = {"/proc/self/exe", "--exact-input-read-helper", name};
    int foreign_fd = -1;
    if (test_case == ExactInputReadRunnerTestCase::ForeignFdExcluded) {
        foreign_fd = open("/dev/null", O_RDONLY);
        if (foreign_fd < 3) {
            if (foreign_fd >= 0) close(foreign_fd);
            diagnostic = {ExactInputMountPhase::InputObservation,
                          errno == 0 ? EPROTO : errno,
                          "could not allocate a real non-stdio sentinel descriptor"};
            return false;
        }
        observation.command_argv.push_back(std::to_string(foreign_fd));
    }
    pid_t foreign_process = -1;
    if (test_case == ExactInputReadRunnerTestCase::LeaderExitWithDescendant) {
        foreign_process = fork();
        if (foreign_process == 0) {
            if (setpgid(0, 0) != 0) _exit(126);
            (void)poll(nullptr, 0, 5000);
            _exit(0);
        }
        if (foreign_process < 0 ||
            (setpgid(foreign_process, foreign_process) != 0 && errno != EACCES)) {
            if (foreign_process > 0) (void)kill(foreign_process, SIGKILL);
            if (foreign_fd >= 0) close(foreign_fd);
            diagnostic = {ExactInputMountPhase::InputObservation,
                          errno,
                          "could not establish the foreign process-group sentinel"};
            return false;
        }
    }
    ExactReadCommandResult result;
    (void)run_exact_read_command(
        observation.command_argv, expected.size() + 1u, timeout_ms, result, fault);
    copy_exact_read_result(result, observation);
    if (test_case == ExactInputReadRunnerTestCase::ForkHandoffChain) {
        observation.setpgid_denied = result.stdout_bytes == "handoff";
        observation.setsid_denied = result.stdout_bytes == "handoff";
    }
    if (test_case == ExactInputReadRunnerTestCase::SubtreeConfinement) {
        observation.setpgid_denied = result.stdout_bytes == "confined";
        observation.setsid_denied = result.stdout_bytes == "confined";
        observation.clone_parent_observed = result.adopted_reap_count >= 2u;
    }
    if (foreign_fd >= 0) {
        observation.foreign_fd_excluded =
            fcntl(foreign_fd, F_GETFD) >= 0 && result.started && result.stdout_bytes == expected;
        close(foreign_fd);
    }
    if (foreign_process > 0) {
        observation.foreign_process_survived = kill(foreign_process, 0) == 0;
        (void)kill(foreign_process, SIGKILL);
        const auto foreign_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
        int foreign_status = 0;
        for (;;) {
            const pid_t waited = waitpid(foreign_process, &foreign_status, WNOHANG);
            if (waited == foreign_process) break;
            if (waited < 0 && errno != EINTR) {
                diagnostic = {ExactInputMountPhase::InputObservation,
                              errno,
                              "foreign process sentinel custody was lost"};
                return false;
            }
            if (std::chrono::steady_clock::now() >= foreign_deadline) {
                diagnostic = {ExactInputMountPhase::InputObservation,
                              ETIMEDOUT,
                              "foreign process sentinel did not reap"};
                return false;
            }
            (void)poll(nullptr, 0, 10);
        }
    }
    observation.outcome = classify_exact_read(result, expected);
    observation.terminal_frozen = true;
    if (observation.outcome != ExactInputReadOutcome::Complete)
        observation.diagnostic = {ExactInputMountPhase::InputObservation,
                                  result.launch_errno,
                                  "deterministic exact-read runner outcome"};
    return true;
}

static std::int64_t exact_mount_thread_id() {
#ifdef SYS_gettid
    return static_cast<std::int64_t>(syscall(SYS_gettid));
#else
    return static_cast<std::int64_t>(getpid());
#endif
}

static ExactInputMountOwner* exact_mount_owner(std::uintptr_t cookie) {
    return reinterpret_cast<ExactInputMountOwner*>(cookie);
}

static void exact_mount_fatal(const char* reason, const ExactInputMountRecoveryReceipt* receipt) {
    if (receipt == nullptr) {
        dprintf(STDERR_FILENO, "fatal exact-input mount controller: %s; no owner\n", reason);
    } else {
        dprintf(STDERR_FILENO,
                "fatal exact-input mount controller: %s; state=%u attempted=%d sidecar=%d "
                "input=%d directory=%d holder=%d network-b=%d network-a=%d settled=%d "
                "phase=%u error=%s\n",
                reason,
                static_cast<unsigned>(receipt->state),
                receipt->attempted,
                receipt->sidecar_settled,
                receipt->input_settled,
                receipt->directory_settled,
                receipt->holder_settled,
                receipt->network_b_settled,
                receipt->network_a_settled,
                receipt->settlement_complete,
                static_cast<unsigned>(receipt->diagnostic.phase),
                receipt->diagnostic.message.c_str());
    }
    abort();
}

ExactInputMountHandle::~ExactInputMountHandle() {
    if (!borrowed_) return;
    auto* controller = reinterpret_cast<ExactInputMountRecoveryController*>(controller_address_);
    controller->return_handle(*this);
}

ExactInputMountHandle::ExactInputMountHandle(ExactInputMountHandle&& other) noexcept
    : controller_address_(other.controller_address_),
      controller_cookie_(other.controller_cookie_),
      generation_(other.generation_),
      slot_(other.slot_),
      borrowed_(other.borrowed_) {
    other.controller_address_ = 0;
    other.controller_cookie_ = 0;
    other.generation_ = 0;
    other.slot_ = 0;
    other.borrowed_ = false;
}

ExactInputMountHandle& ExactInputMountHandle::operator=(ExactInputMountHandle&& other) noexcept {
    if (this == &other) return *this;
    if (borrowed_) {
        auto* controller =
            reinterpret_cast<ExactInputMountRecoveryController*>(controller_address_);
        controller->return_handle(*this);
    }
    controller_address_ = other.controller_address_;
    controller_cookie_ = other.controller_cookie_;
    generation_ = other.generation_;
    slot_ = other.slot_;
    borrowed_ = other.borrowed_;
    other.controller_address_ = 0;
    other.controller_cookie_ = 0;
    other.generation_ = 0;
    other.slot_ = 0;
    other.borrowed_ = false;
    return *this;
}

ExactInputMountRecoveryController::ExactInputMountRecoveryController()
    : construction_thread_(exact_mount_thread_id()) {
    if (getrandom(&cookie_, sizeof(cookie_), 0) != static_cast<ssize_t>(sizeof(cookie_)) ||
        cookie_ == 0u)
        cookie_ =
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(this)) ^
            static_cast<std::uint64_t>(construction_thread_) ^
            static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    if (cookie_ == 0u) cookie_ = 1u;
}

static bool exact_mount_terminal_settlement(const ExactInputMountRecoveryReceipt& receipt) {
    const auto settled_if_acquired = [](bool acquired, bool settled) {
        return !acquired || settled;
    };
    return receipt.state == ExactInputMountState::Settled && receipt.attempted &&
           receipt.terminal_result != ExactInputMountTerminalResult::None &&
           receipt.final_zero_residue && receipt.settlement_complete && receipt.terminal_frozen &&
           settled_if_acquired(receipt.nginx_sibling_acquired, receipt.nginx_sibling_settled) &&
           settled_if_acquired(receipt.sidecar_acquired, receipt.sidecar_settled) &&
           settled_if_acquired(receipt.input_acquired, receipt.input_settled) &&
           settled_if_acquired(receipt.directory_acquired, receipt.directory_settled) &&
           settled_if_acquired(receipt.holder_acquired, receipt.holder_settled) &&
           settled_if_acquired(receipt.network_b_acquired, receipt.network_b_settled) &&
           settled_if_acquired(receipt.network_a_acquired, receipt.network_a_settled);
}

ExactInputMountRecoveryController::~ExactInputMountRecoveryController() {
    ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
    const ExactInputMountRecoveryReceipt* receipt = owner == nullptr ? nullptr : &owner->receipt;
    if (borrowed_) exact_mount_fatal("destroyed with a live borrowed handle", receipt);
    if (exact_mount_thread_id() != construction_thread_)
        exact_mount_fatal("destroyed on a foreign thread", receipt);
    if (owner != nullptr && !owner->settled) {
        ExactInputMountRecoveryReceipt recovered;
        ExactInputMountDiagnostic diagnostic;
        const bool operation_ok = recover_impl(recovered, diagnostic);
        if (!operation_ok && (recovered.terminal_result !=
                                  ExactInputMountTerminalResult::SettledWithOperationFailure ||
                              !exact_mount_terminal_settlement(recovered)))
            exact_mount_fatal("bounded destructor recovery did not settle the graph",
                              &owner->receipt);
    }
    delete owner;
    owner_cookie_ = 0;
}

bool exact_input_mount_test_terminal_settlement(const ExactInputMountRecoveryReceipt& receipt) {
    return exact_mount_terminal_settlement(receipt);
}

bool ExactInputMountRecoveryController::start(const void* bytes,
                                              std::size_t size,
                                              ExactInputMountHandle& handle,
                                              ExactInputMountDiagnostic& diagnostic,
                                              const ExactInputMountOptions& options) {
    diagnostic = {};
    const std::int64_t thread = exact_mount_thread_id();
    if (thread != construction_thread_) {
        diagnostic = {ExactInputMountPhase::Thread, 0, "start called from a foreign thread"};
        return false;
    }
    if (start_in_progress_.load(std::memory_order_acquire)) {
        if (builder_active_.load(std::memory_order_acquire))
            reentry_attempted_.store(true, std::memory_order_release);
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EDEADLK,
                      "start re-entry during an active setup operation"};
        return false;
    }
    operation_thread_.store(thread, std::memory_order_release);
    start_in_progress_.store(true, std::memory_order_release);
    struct Guard {
        std::atomic<bool>& active;
        std::atomic<std::int64_t>& thread;
        ~Guard() {
            active.store(false, std::memory_order_release);
            thread.store(-1, std::memory_order_release);
        }
    } guard{start_in_progress_, operation_thread_};
    if (bytes == nullptr || size == 0u ||
        size > fixture_exact_input_file_lease::kMaximumInputBytes || handle.borrowed_ ||
        handle.controller_address_ != 0u || handle.controller_cookie_ != 0u ||
        handle.generation_ != 0u) {
        diagnostic = {ExactInputMountPhase::Argument, EINVAL, "invalid exact-input start argument"};
        return false;
    }
    ExactInputMountOwner* prior = exact_mount_owner(owner_cookie_);
    if (borrowed_ || (prior != nullptr && !prior->settled)) {
        diagnostic = {ExactInputMountPhase::Capacity, EBUSY, "the fixed exact-input slot is busy"};
        return false;
    }
    if (prior != nullptr) {
        delete prior;
        owner_cookie_ = 0;
    }
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EOVERFLOW,
                      "exact-input handle generation cannot wrap"};
        return false;
    }
    std::string token;
    if (!high_entropy_token(token)) {
        diagnostic = {ExactInputMountPhase::Preflight,
                      errno,
                      "high-entropy exact-input owner token generation failed"};
        return false;
    }
    std::string exact_bytes(static_cast<const char*>(bytes), size);
    ExactInputMountOwner* owner =
        new (std::nothrow) ExactInputMountOwner(std::move(token), std::move(exact_bytes));
    if (owner == nullptr) {
        diagnostic = {
            ExactInputMountPhase::Capacity, ENOMEM, "exact-input owner allocation failed"};
        return false;
    }
    owner->options = options;
    owner_cookie_ = reinterpret_cast<std::uintptr_t>(owner);
    ++generation_;
    owner->snapshot.generation = generation_;
    if (!setup_exact_input_mount(*owner, diagnostic)) return false;
    handle.controller_address_ = reinterpret_cast<std::uintptr_t>(this);
    handle.controller_cookie_ = cookie_;
    handle.generation_ = generation_;
    handle.slot_ = 0;
    handle.borrowed_ = true;
    borrowed_ = true;
    return true;
}

bool ExactInputMountRecoveryController::start_with_topology_builder(
    ExactInputTopologyBuilder builder,
    void* context,
    ExactInputMountHandle& handle,
    ExactInputMountDiagnostic& diagnostic,
    const ExactInputMountOptions& options) {
    diagnostic = {};
    const std::int64_t thread = exact_mount_thread_id();
    if (thread != construction_thread_) {
        diagnostic = {
            ExactInputMountPhase::Thread, 0, "topology-builder start called from a foreign thread"};
        return false;
    }
    if (start_in_progress_.load(std::memory_order_acquire)) {
        if (builder_active_.load(std::memory_order_acquire))
            reentry_attempted_.store(true, std::memory_order_release);
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EDEADLK,
                      "topology-builder start re-entry during active setup"};
        return false;
    }
    if (builder == nullptr || handle.borrowed_ || handle.controller_address_ != 0u ||
        handle.controller_cookie_ != 0u || handle.generation_ != 0u) {
        diagnostic = {
            ExactInputMountPhase::Argument, EINVAL, "invalid topology-builder start argument"};
        return false;
    }
    ExactInputMountOwner* prior = exact_mount_owner(owner_cookie_);
    if (borrowed_ || (prior != nullptr && !prior->settled)) {
        diagnostic = {ExactInputMountPhase::Capacity, EBUSY, "the fixed exact-input slot is busy"};
        return false;
    }
    if (prior != nullptr) {
        delete prior;
        owner_cookie_ = 0;
    }
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EOVERFLOW,
                      "exact-input handle generation cannot wrap"};
        return false;
    }
    std::string token;
    if (!high_entropy_token(token)) {
        diagnostic = {ExactInputMountPhase::Preflight,
                      errno,
                      "high-entropy topology-builder owner token generation failed"};
        return false;
    }
    ExactInputMountOwner* owner =
        new (std::nothrow) ExactInputMountOwner(std::move(token), std::string{});
    if (owner == nullptr) {
        diagnostic = {
            ExactInputMountPhase::Capacity, ENOMEM, "topology-builder owner allocation failed"};
        return false;
    }
    owner->options = options;
    owner_cookie_ = reinterpret_cast<std::uintptr_t>(owner);
    ++generation_;
    owner->snapshot.generation = generation_;
    reentry_attempted_.store(false, std::memory_order_release);
    operation_thread_.store(thread, std::memory_order_release);
    start_in_progress_.store(true, std::memory_order_release);
    struct Guard {
        std::atomic<bool>& start;
        std::atomic<bool>& builder;
        std::atomic<std::int64_t>& thread;
        ~Guard() {
            builder.store(false, std::memory_order_release);
            start.store(false, std::memory_order_release);
            thread.store(-1, std::memory_order_release);
        }
    } guard{start_in_progress_, builder_active_, operation_thread_};
    if (!setup_exact_input_mount_from_topology_builder(
            *owner, builder, context, builder_active_, reentry_attempted_, diagnostic))
        return false;
    handle.controller_address_ = reinterpret_cast<std::uintptr_t>(this);
    handle.controller_cookie_ = cookie_;
    handle.generation_ = generation_;
    handle.slot_ = 0;
    handle.borrowed_ = true;
    borrowed_ = true;
    return true;
}

bool ExactInputMountRecoveryController::validate_handle(
    const ExactInputMountHandle& handle, ExactInputMountDiagnostic& diagnostic) const {
    if (exact_mount_thread_id() != construction_thread_) {
        diagnostic = {ExactInputMountPhase::Thread, 0, "handle operation called on foreign thread"};
        return false;
    }
    if (start_in_progress_.load(std::memory_order_acquire)) {
        if (builder_active_.load(std::memory_order_acquire))
            reentry_attempted_.store(true, std::memory_order_release);
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EDEADLK,
                      "handle operation re-entry during active topology builder"};
        return false;
    }
    if (!borrowed_ || !handle.borrowed_ ||
        handle.controller_address_ != reinterpret_cast<std::uintptr_t>(this) ||
        handle.controller_cookie_ != cookie_ || handle.slot_ != 0u ||
        handle.generation_ != generation_) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EINVAL,
                      "moved-from, stale, foreign, or already-finished handle"};
        return false;
    }
    return true;
}

bool ExactInputMountRecoveryController::snapshot(const ExactInputMountHandle& handle,
                                                 ExactInputMountSnapshot& snapshot_value,
                                                 ExactInputMountDiagnostic& diagnostic) const {
    diagnostic = {};
    if (!validate_handle(handle, diagnostic)) return false;
    const ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
    if (owner == nullptr || owner->state != ExactInputMountState::ReadyForObservation) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EINVAL,
                      "exact-input mount is not ReadyForObservation"};
        return false;
    }
    snapshot_value = owner->snapshot;
    return true;
}

bool ExactInputMountRecoveryController::observe_input_read(const ExactInputMountHandle& handle,
                                                           ExactInputReadObservation& observation,
                                                           ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    if (!validate_handle(handle, diagnostic)) return false;
    ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
    if (owner == nullptr) {
        diagnostic = {ExactInputMountPhase::Lifecycle, EINVAL, "exact-input owner is absent"};
        return false;
    }
    if (owner->read_attempted) {
        observation = owner->read_observation;
        diagnostic = owner->read_diagnostic;
        return observation.outcome == ExactInputReadOutcome::Complete;
    }

    if (owner->state != ExactInputMountState::ReadyForObservation) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EINVAL,
                      "exact-input mount is not ReadyForObservation"};
        return false;
    }
    owner->read_attempted = true;
    owner->state = ExactInputMountState::ObservingInput;
    owner->snapshot.state = owner->state;
    owner->receipt.state = owner->state;
    ExactInputReadObservation current;
    current.attempted = true;
    current.expected_size = owner->bytes.size();
    const auto freeze_failure =
        [&](ExactInputReadOutcome outcome, const std::string& message, int error_number = 0) {
            current.outcome = outcome;
            current.terminal_frozen = true;
            current.diagnostic = {ExactInputMountPhase::InputObservation, error_number, message};
            owner->operation_failed = true;
            owner_failure(*owner,
                          diagnostic,
                          current.diagnostic.phase,
                          current.diagnostic.message,
                          current.diagnostic.error_number);
            owner->read_observation = current;
            owner->read_diagnostic = current.diagnostic;
            observation = current;
            return false;
        };

    std::string error;
    int error_number = 0;
    ExactInputReadOutcome bracket =
        capture_input_read_bracket(*owner, true, current, error, error_number);
    if (bracket != ExactInputReadOutcome::Complete)
        return freeze_failure(bracket, error, error_number);

    if (owner->bytes.size() == std::numeric_limits<size_t>::max())
        return freeze_failure(ExactInputReadOutcome::OutputLimitExceeded,
                              "expected input size cannot form a one-byte sentinel",
                              EOVERFLOW);
    const size_t stdout_limit = owner->bytes.size() + 1u;
    const std::string user = std::to_string(owner->input.identity().uid) + ":" +
                             std::to_string(owner->input.identity().gid);
    current.command_argv = {"docker",
                            "exec",
                            "--user",
                            user,
                            owner->registered_sidecar.id,
                            "/bin/cat",
                            kExactInputMountDestination};
    if (!full_container_id(owner->registered_sidecar.id) || current.command_argv.size() != 7u)
        return freeze_failure(ExactInputReadOutcome::ContainerIdentityFailed,
                              "registered sidecar ID was not a full immutable Docker ID");
    ExactReadCommandResult command;
    (void)run_exact_read_command(current.command_argv, stdout_limit, 15000, command);
    copy_exact_read_result(command, current);

    if (owner->options.failure_point ==
        ExactInputMountFailurePoint::InputReadPostCommandSidecarDeath) {
        std::string death_error;
        if (!owner->fixture.terminate_sidecar_unexpectedly(death_error))
            return freeze_failure(ExactInputReadOutcome::ContainerIdentityFailed,
                                  "post-command sidecar death injection failed: " + death_error);
    }
    error.clear();
    error_number = 0;
    bracket = capture_input_read_bracket(*owner, false, current, error, error_number);
    if (bracket != ExactInputReadOutcome::Complete)
        return freeze_failure(bracket, error, error_number);

    const ExactInputReadOutcome outcome = classify_exact_read(command, owner->bytes);
    if (outcome != ExactInputReadOutcome::Complete) {
        std::ostringstream message;
        message << "exact container input read failed with outcome "
                << static_cast<unsigned>(outcome);
        return freeze_failure(outcome, message.str());
    }
    current.outcome = ExactInputReadOutcome::Complete;
    current.terminal_frozen = true;
    current.diagnostic = {};
    owner->read_observation = current;
    owner->read_diagnostic = {};
    owner->state = ExactInputMountState::InputReadObserved;
    owner->snapshot.state = owner->state;
    owner->receipt.state = owner->state;
    observation = current;
    diagnostic = {};
    return true;
}

bool ExactInputMountRecoveryController::observe_input_write_refusal(
    const ExactInputMountHandle& handle,
    ExactInputWriteRefusalObservation& observation,
    ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    if (!validate_handle(handle, diagnostic)) return false;
    ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
    if (owner == nullptr) {
        diagnostic = {ExactInputMountPhase::Lifecycle, EINVAL, "exact-input owner is absent"};
        return false;
    }
    if (owner->write_refusal_attempted) {
        observation = owner->write_refusal_observation;
        diagnostic = owner->write_refusal_diagnostic;
        return observation.outcome == ExactInputWriteRefusalOutcome::Complete;
    }
    if (owner->state != ExactInputMountState::InputReadObserved || !owner->read_attempted ||
        owner->read_observation.outcome != ExactInputReadOutcome::Complete) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EINVAL,
                      "write-refusal observation requires a successful exact input read"};
        return false;
    }

    owner->write_refusal_attempted = true;
    owner->state = ExactInputMountState::ObservingWriteRefusal;
    owner->snapshot.state = owner->state;
    owner->receipt.state = owner->state;
    ExactInputWriteRefusalObservation current;
    current.attempted = true;
    current.expected_target_stderr =
        "dd: failed to open '/etc/nginx/nginx.conf': Read-only file system\n";
    const std::int64_t now_ns = exact_read_monotonic_ns();
    if (now_ns > 0 && now_ns <= std::numeric_limits<std::int64_t>::max() - 30000000000LL) {
        current.caller_deadline_recorded = true;
        current.final_deadline_nanoseconds = now_ns + 30000000000LL;
    }
    const auto freeze_failure = [&](ExactInputWriteRefusalOutcome outcome,
                                    const std::string& message,
                                    int error_number = 0) {
        current.outcome = outcome;
        current.terminal_frozen = true;
        current.diagnostic = {ExactInputMountPhase::WriteRefusalObservation, error_number, message};
        owner->operation_failed = true;
        owner_failure(*owner,
                      diagnostic,
                      current.diagnostic.phase,
                      current.diagnostic.message,
                      current.diagnostic.error_number);
        owner->write_refusal_observation = current;
        owner->write_refusal_diagnostic = current.diagnostic;
        observation = current;
        return false;
    };
    if (!current.caller_deadline_recorded)
        return freeze_failure(ExactInputWriteRefusalOutcome::DeadlineExceeded,
                              "caller-owned write-refusal deadline could not be formed",
                              EOVERFLOW);

    std::string error;
    int error_number = 0;
    if (!capture_write_refusal_bracket(
            *owner,
            ExactInputMountFailurePoint::WriteRefusalRejectInitialBracket,
            current.initial_bracket,
            error,
            error_number))
        return freeze_failure(
            ExactInputWriteRefusalOutcome::SourceRevalidationFailed, error, error_number);

    const auto& identity = owner->input.identity();
    current.credentials = std::to_string(identity.uid) + ":" + std::to_string(identity.gid);
    if ((identity.mode & 07777u) != 0600u || current.credentials != owner->registered_mount.user ||
        !full_container_id(owner->registered_sidecar.id))
        return freeze_failure(
            ExactInputWriteRefusalOutcome::ContainerIdentityFailed,
            "source-owner DAC or immutable container credential evidence differed");

    current.control.attempted = true;
    current.control.command_argv = {"docker",
                                    "exec",
                                    "--env",
                                    "LC_ALL=C",
                                    "--user",
                                    current.credentials,
                                    owner->registered_sidecar.id,
                                    "/usr/bin/dd",
                                    "if=/dev/zero",
                                    "of=/dev/null",
                                    "bs=1",
                                    "count=1",
                                    "conv=notrunc",
                                    "status=none"};
    ExactReadCommandResult control;
    (void)run_exact_read_command_until(
        current.control.command_argv, 1u, current.final_deadline_nanoseconds, control);
    copy_exact_read_result(control, current.control);
    current.control.outcome = classify_exact_read(control, {});
    current.control.terminal_frozen = true;
    ExactInputWriteRefusalOutcome outcome = classify_write_control(control);
    if (outcome != ExactInputWriteRefusalOutcome::Complete) {
        std::ostringstream message;
        message << "write-refusal positive control failed with outcome "
                << static_cast<unsigned>(outcome);
        return freeze_failure(outcome, message.str());
    }

    error.clear();
    error_number = 0;
    if (!capture_write_refusal_bracket(*owner,
                                       ExactInputMountFailurePoint::WriteRefusalRejectMiddleBracket,
                                       current.middle_bracket,
                                       error,
                                       error_number) ||
        !exact_write_source_bracket_equal(current.initial_bracket, current.middle_bracket))
        return freeze_failure(
            ExactInputWriteRefusalOutcome::SourceRevalidationFailed,
            error.empty() ? "source/mount identity changed after positive control" : error,
            error_number);

    current.target.attempted = true;
    current.target.command_argv = {"docker",
                                   "exec",
                                   "--env",
                                   "LC_ALL=C",
                                   "--user",
                                   current.credentials,
                                   owner->registered_sidecar.id,
                                   "/usr/bin/dd",
                                   "if=/etc/nginx/nginx.conf",
                                   "of=/etc/nginx/nginx.conf",
                                   "bs=1",
                                   "count=1",
                                   "conv=notrunc",
                                   "status=none"};
    ExactReadCommandResult target;
    (void)run_exact_read_command_until(
        current.target.command_argv, 1u, current.final_deadline_nanoseconds, target);
    copy_exact_read_result(target, current.target);
    current.target.outcome = classify_exact_read(target, {});
    current.target.terminal_frozen = true;
    outcome = classify_write_target(target, current.expected_target_stderr);

    if (owner->options.failure_point ==
        ExactInputMountFailurePoint::WriteRefusalPostTargetSidecarDeath) {
        std::string death_error;
        if (!owner->fixture.terminate_sidecar_unexpectedly(death_error))
            return freeze_failure(ExactInputWriteRefusalOutcome::ContainerIdentityFailed,
                                  "post-target sidecar death injection failed: " + death_error);
    }
    error.clear();
    error_number = 0;
    const bool final_bracket_ok =
        capture_write_refusal_bracket(*owner,
                                      ExactInputMountFailurePoint::WriteRefusalRejectFinalBracket,
                                      current.final_bracket,
                                      error,
                                      error_number);
    if (outcome != ExactInputWriteRefusalOutcome::Complete) {
        std::ostringstream message;
        message << "write-refusal target failed with outcome " << static_cast<unsigned>(outcome);
        return freeze_failure(outcome, message.str());
    }
    if (!final_bracket_ok ||
        !exact_write_source_bracket_equal(current.initial_bracket, current.final_bracket))
        return freeze_failure(
            ExactInputWriteRefusalOutcome::SourceRevalidationFailed,
            error.empty() ? "source/mount identity changed after refusal target" : error,
            error_number);

    current.outcome = ExactInputWriteRefusalOutcome::Complete;
    current.terminal_frozen = true;
    current.diagnostic = {};
    owner->write_refusal_observation = current;
    owner->write_refusal_diagnostic = {};
    owner->state = ExactInputMountState::WriteRefusalObserved;
    owner->snapshot.state = owner->state;
    owner->receipt.state = owner->state;
    observation = current;
    diagnostic = {};
    return true;
}

bool ExactInputMountRecoveryController::observe_nginx_lifecycle(
    const ExactInputMountHandle& handle,
    ExactInputNginxLifecycleObservation& observation,
    ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    if (!validate_handle(handle, diagnostic)) return false;
    ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
    if (owner == nullptr) {
        diagnostic = {ExactInputMountPhase::Lifecycle, EINVAL, "exact-input owner is absent"};
        return false;
    }
    if (owner->nginx_lifecycle_attempted) {
        observation = owner->nginx_lifecycle_observation;
        diagnostic = owner->nginx_lifecycle_diagnostic;
        return observation.outcome == ExactInputNginxLifecycleOutcome::Complete;
    }
    if (owner->state != ExactInputMountState::WriteRefusalObserved ||
        !owner->write_refusal_attempted ||
        owner->write_refusal_observation.outcome != ExactInputWriteRefusalOutcome::Complete ||
        !owner->receipt.builder.applicable || !owner->receipt.builder.output_accepted) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EINVAL,
                      "nginx lifecycle requires topology-built input and successful write refusal"};
        return false;
    }

    owner->nginx_lifecycle_attempted = true;
    owner->state = ExactInputMountState::ObservingNginxLifecycle;
    owner->snapshot.state = owner->state;
    owner->receipt.state = owner->state;
    ExactInputNginxLifecycleObservation current;
    current.attempted = true;
    current.container_name = "rut358-nginx-" + owner->fixture.token();
    owner->nginx_sibling.name = current.container_name;
    const std::int64_t now = exact_read_monotonic_ns();
    if (now > 0 && now <= std::numeric_limits<std::int64_t>::max() - 30000000000LL) {
        current.caller_deadline_recorded = true;
        current.final_deadline_nanoseconds = now + 30000000000LL;
    }
    const auto freeze_failure = [&](ExactInputNginxLifecycleOutcome outcome,
                                    const std::string& message,
                                    int error_number = 0) {
        current.outcome = outcome;
        current.terminal_frozen = true;
        current.operation_failed = true;
        current.diagnostic = {ExactInputMountPhase::Lifecycle, error_number, message};
        owner->operation_failed = true;
        owner->nginx_sibling.operation_failed = true;
        std::string cleanup_error;
        if (current.caller_deadline_recorded && !current.quit_attempted &&
            current.remove_count == 0u &&
            (owner->nginx_sibling.mutation_may_have_occurred || owner->nginx_sibling.exists)) {
            command_deadline_cap_ns = current.final_deadline_nanoseconds;
            if (!settle_nginx_sibling(
                    *owner, current, current.final_deadline_nanoseconds, false, cleanup_error))
                current.diagnostic.message += "; cleanup unresolved: " + cleanup_error;
            else {
                std::string baseline_error;
                if (!revalidate_nginx_baseline(*owner, baseline_error))
                    current.diagnostic.message +=
                        "; baseline revalidation failed: " + baseline_error;
                else
                    current.baseline_restored = true;
            }
        }
        owner_failure(*owner,
                      diagnostic,
                      current.diagnostic.phase,
                      current.diagnostic.message,
                      current.diagnostic.error_number);
        owner->nginx_lifecycle_observation = current;
        owner->nginx_lifecycle_diagnostic = current.diagnostic;
        observation = current;
        return false;
    };
    if (!current.caller_deadline_recorded)
        return freeze_failure(ExactInputNginxLifecycleOutcome::DeadlineExceeded,
                              "nginx lifecycle deadline could not be formed",
                              EOVERFLOW);
    if (!unified_cgroup_preflight())
        return freeze_failure(ExactInputNginxLifecycleOutcome::PreflightUnsupported,
                              "unified cgroup v2 process-membership proof is unsupported",
                              ENOTSUP);

    const std::int64_t sample_a_deadline = current.final_deadline_nanoseconds - 15000000000LL;
    const std::int64_t sample_b_deadline = current.final_deadline_nanoseconds - 12000000000LL;
    CommandDeadlineScope command_deadline(sample_a_deadline);
    fixture_exact_input_file_lease::Diagnostic source_diagnostic;
    std::string error;
    if (!owner->input.revalidate(source_diagnostic) ||
        !owner->fixture.revalidate_sidecar_identity(error) ||
        !owner->fixture.verify_topology(FailurePoint::None, error) ||
        !topology_snapshot_equal(owner->builder_baseline,
                                 owner->fixture.current_topology_snapshot()))
        return freeze_failure(ExactInputNginxLifecycleOutcome::SourceRevalidationFailed,
                              "pre-create source/sidecar/topology bracket failed: " + error,
                              source_diagnostic.error_number);

    const auto& identity = owner->input.identity();
    const std::string credentials =
        std::to_string(identity.uid) + ":" + std::to_string(identity.gid);
    const std::string uid = std::to_string(identity.uid);
    const std::string gid = std::to_string(identity.gid);
    const std::string mount = "type=bind,src=" + owner->input.path() +
                              ",dst=" + kExactInputMountDestination +
                              ",readonly,bind-propagation=rprivate";
    const std::string global = "daemon off; master_process on; worker_processes 1; pid /tmp/rut-" +
                               owner->fixture.token() + "-nginx.pid;";
    current.create_argv = {
        "docker",
        "create",
        "--pull=never",
        "--name",
        current.container_name,
        "--label",
        std::string("rut.stage=") + kNginxStage,
        "--label",
        "rut.token=" + owner->fixture.token(),
        "--label",
        std::string("rut.role=") + kNginxRole,
        "--network",
        "container:" + owner->fixture.holder_id(),
        "--user",
        credentials,
        "--workdir",
        "/",
        "--env",
        "LC_ALL=C",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--restart",
        "no",
        "--stop-signal",
        "SIGQUIT",
        "--mount",
        mount,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=" + uid + ",gid=" + gid,
        "--tmpfs",
        "/var/cache/nginx:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=" + uid + ",gid=" + gid,
        "--tmpfs",
        "/var/log/nginx:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=" + uid + ",gid=" + gid,
        "--entrypoint",
        "/usr/sbin/nginx",
        RUT_PINNED_NGINX_IMAGE,
        "-c",
        kExactInputMountDestination,
        "-e",
        "stderr",
        "-g",
        global};
    if (!exact_nginx_create_argv(current.create_argv,
                                 current.container_name,
                                 owner->fixture.token(),
                                 owner->fixture.holder_id(),
                                 owner->input.path(),
                                 credentials))
        return freeze_failure(ExactInputNginxLifecycleOutcome::IdentityFailed,
                              "nginx create argv was not exact");

    owner->nginx_sibling.mutation_may_have_occurred = true;
    owner->recovery_required = true;
    owner->receipt.recovery_required = true;
    owner->receipt.mutation_may_have_occurred = true;
    current.create_attempted = true;
    ++current.create_count;
    ++owner->receipt.nginx_create_count;
    CommandResult create;
    const bool create_reported_timeout =
        owner->options.failure_point == ExactInputMountFailurePoint::NginxCreateReportedTimeout;
    const bool create_ok =
        run_command_before(current.create_argv, sample_a_deadline, create, create_reported_timeout);
    if ((!create_ok || !exited_zero(create)) && !create.timed_out)
        return freeze_failure(ExactInputNginxLifecycleOutcome::CreateFailed,
                              "nginx sibling create failed: " + trim(create.output));
    if (full_container_id(trim(create.output))) owner->nginx_sibling.id = trim(create.output);
    NginxInspectEvidence created;
    if (!inspect_nginx_sibling(*owner, created, error, sample_a_deadline) || created.running)
        return freeze_failure(ExactInputNginxLifecycleOutcome::IdentityFailed,
                              "post-create nginx identity rejection: " + error);
    owner->nginx_sibling.id = created.id;
    owner->nginx_sibling.exists = true;
    owner->receipt.nginx_sibling_acquired = true;
    owner->mutated = true;
    owner->receipt.graph_mutated = true;
    current.created = true;
    current.container_id = created.id;
    if (command_outcome_uncertain(create))
        return freeze_failure(ExactInputNginxLifecycleOutcome::CreateFailed,
                              "nginx create outcome was uncertain after timeout",
                              ETIMEDOUT);
    if (owner->options.failure_point == ExactInputMountFailurePoint::NginxRejectPostCreateIdentity)
        return freeze_failure(ExactInputNginxLifecycleOutcome::IdentityFailed,
                              "injected post-create nginx identity rejection");

    current.start_attempted = true;
    ++current.start_count;
    ++owner->receipt.nginx_start_count;
    CommandResult start;
    const bool start_reported_timeout =
        owner->options.failure_point == ExactInputMountFailurePoint::NginxStartReportedTimeout;
    const bool start_ok = run_command_before({"docker", "start", owner->nginx_sibling.id},
                                             sample_a_deadline,
                                             start,
                                             start_reported_timeout);
    if ((!start_ok || !exited_zero(start)) && !start.timed_out)
        return freeze_failure(ExactInputNginxLifecycleOutcome::StartFailed,
                              "nginx sibling start failed: " + trim(start.output));
    owner->nginx_sibling.running = true;
    current.started = true;
    if (command_outcome_uncertain(start))
        return freeze_failure(ExactInputNginxLifecycleOutcome::StartFailed,
                              "nginx start outcome was uncertain after timeout",
                              ETIMEDOUT);

    bool sample_a_ok = false;
    std::string first_sample_error;
    while (remaining_command_ms(sample_a_deadline) > 0) {
        error.clear();
        if (capture_nginx_sample(*owner, current.sample_a, sample_a_deadline, true, error)) {
            sample_a_ok = true;
            break;
        }
        if (first_sample_error.empty()) first_sample_error = error;
        close_nginx_pidfds(owner->nginx_sibling);
        owner->nginx_sibling.master_pid = -1;
        owner->nginx_sibling.worker_pid = -1;
        owner->nginx_sibling.cgroup_path.clear();
        (void)poll(nullptr, 0, 25);
    }
    if (!sample_a_ok ||
        owner->options.failure_point == ExactInputMountFailurePoint::NginxRejectSampleA)
        return freeze_failure(
            ExactInputNginxLifecycleOutcome::SampleFailed,
            first_sample_error.empty() ? "injected/rejected nginx sample A" : first_sample_error);
    current.same_source_inode = true;
    current.same_mount_instance = false;
    current.sibling_mount_independently_verified = true;

    command_deadline.set(sample_b_deadline);
    const std::int64_t earliest_b = current.sample_a.bracket_end_nanoseconds + 250000000LL;
    while (exact_read_monotonic_ns() < earliest_b && remaining_command_ms(sample_b_deadline) > 0)
        (void)poll(nullptr, 0, 10);
    if (!capture_nginx_sample(*owner, current.sample_b, sample_b_deadline, false, error) ||
        owner->options.failure_point == ExactInputMountFailurePoint::NginxRejectSampleB)
        return freeze_failure(ExactInputNginxLifecycleOutcome::SampleFailed,
                              error.empty() ? "injected/rejected nginx sample B" : error);
    if (owner->options.failure_point == ExactInputMountFailurePoint::NginxDriftSampleB)
        ++current.sample_b.worker_start;
    current.samples_at_least_250ms_apart =
        current.sample_b.bracket_start_nanoseconds - current.sample_a.bracket_end_nanoseconds >=
        250000000LL;
    const bool stable = current.samples_at_least_250ms_apart &&
                        nginx_samples_stable(current.sample_a, current.sample_b);
    if (!stable)
        return freeze_failure(ExactInputNginxLifecycleOutcome::SampleDrift,
                              "nginx process/listener evidence drifted between stable samples");

    command_deadline.set(current.final_deadline_nanoseconds);
    if (!settle_nginx_sibling(*owner, current, current.final_deadline_nanoseconds, true, error))
        return freeze_failure(ExactInputNginxLifecycleOutcome::RemovalFailed,
                              "nginx sibling cleanup did not settle: " + error);
    if (!nginx_graceful_cleanup_complete(current)) {
        std::ostringstream failure;
        failure << "nginx lifecycle required uncertain/escalated cleanup: quit-only="
                << current.quit_only << " exit-zero=" << current.stopped_exit_zero
                << " cgroup-empty=" << current.cgroup_empty_after_stop
                << " nonforce=" << current.removed_nonforce << " absent=" << current.exact_absence
                << " detail=" << error;
        return freeze_failure(ExactInputNginxLifecycleOutcome::GracefulStopFailed, failure.str());
    }
    if (owner->options.failure_point == ExactInputMountFailurePoint::NginxRejectBaseline ||
        !revalidate_nginx_baseline(*owner, error))
        return freeze_failure(ExactInputNginxLifecycleOutcome::BaselineDrift,
                              error.empty() ? "injected post-nginx baseline drift" : error);
    current.baseline_restored = true;
    current.outcome = ExactInputNginxLifecycleOutcome::Complete;
    current.terminal_frozen = true;
    current.diagnostic = {};
    owner->nginx_lifecycle_observation = current;
    owner->nginx_lifecycle_diagnostic = {};
    owner->state = ExactInputMountState::NginxLifecycleObserved;
    owner->snapshot.state = owner->state;
    owner->receipt.state = owner->state;
    observation = current;
    diagnostic = {};
    return true;
}

void ExactInputMountRecoveryController::return_handle(ExactInputMountHandle& handle) noexcept {
    if (exact_mount_thread_id() != construction_thread_) {
        ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
        exact_mount_fatal("handle custody returned on a foreign thread",
                          owner == nullptr ? nullptr : &owner->receipt);
    }
    if (handle.borrowed_ && handle.controller_address_ == reinterpret_cast<std::uintptr_t>(this) &&
        handle.controller_cookie_ == cookie_ && handle.generation_ == generation_ &&
        handle.slot_ == 0u) {
        borrowed_ = false;
    }
    handle.borrowed_ = false;
}

bool ExactInputMountRecoveryController::recover_impl(ExactInputMountRecoveryReceipt& receipt,
                                                     ExactInputMountDiagnostic& diagnostic) {
    if (recovering_) {
        diagnostic = {ExactInputMountPhase::Lifecycle, EDEADLK, "controller recovery re-entry"};
        return false;
    }
    ExactInputMountOwner* owner = exact_mount_owner(owner_cookie_);
    if (owner == nullptr) {
        receipt = {};
        receipt.state = ExactInputMountState::Settled;
        receipt.terminal_result = ExactInputMountTerminalResult::SettledCleanly;
        receipt.attempted = true;
        receipt.cleanup_not_applicable = true;
        receipt.manifest_not_applicable = true;
        receipt.final_zero_residue = true;
        receipt.settlement_complete = true;
        receipt.terminal_frozen = true;
        diagnostic = {};
        return true;
    }
    recovering_ = true;
    const bool ok = recover_exact_input_mount(*owner, diagnostic);
    recovering_ = false;
    receipt = owner->receipt;
    return ok;
}

bool ExactInputMountRecoveryController::finish(ExactInputMountHandle& handle,
                                               ExactInputMountRecoveryReceipt& receipt,
                                               ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    if (!validate_handle(handle, diagnostic)) return false;
    return_handle(handle);
    return recover_impl(receipt, diagnostic);
}

bool ExactInputMountRecoveryController::recover_all(ExactInputMountRecoveryReceipt& receipt,
                                                    ExactInputMountDiagnostic& diagnostic) {
    diagnostic = {};
    if (exact_mount_thread_id() != construction_thread_) {
        diagnostic = {ExactInputMountPhase::Thread, 0, "recover_all called on a foreign thread"};
        return false;
    }
    if (start_in_progress_.load(std::memory_order_acquire)) {
        if (builder_active_.load(std::memory_order_acquire))
            reentry_attempted_.store(true, std::memory_order_release);
        diagnostic = {ExactInputMountPhase::InputBuilder,
                      EDEADLK,
                      "recover_all re-entry during active topology builder"};
        return false;
    }
    if (borrowed_) {
        diagnostic = {ExactInputMountPhase::Lifecycle,
                      EBUSY,
                      "recover_all refused while a handle retains custody"};
        return false;
    }
    return recover_impl(receipt, diagnostic);
}

bool parse_held_namespace_sidecar_inspect_record(const std::string& record,
                                                 HeldNamespaceSidecarSnapshot& snapshot,
                                                 std::string& error) {
    return parse_sidecar_inspect_record(record, snapshot, error);
}

bool validate_held_namespace_sidecar_snapshot(const HeldTopologySnapshot& topology,
                                              const HeldNamespaceSidecarSnapshot& sidecar,
                                              std::string& error) {
    const auto require = [&](bool condition, const char* field) {
        if (!condition) error = std::string("held-namespace sidecar evidence mismatch: ") + field;
        return condition;
    };
    if (!require(!topology.token.empty(), "topology token") ||
        !require(!topology.holder_id.empty(), "holder ID") ||
        !require(topology.holder_pid > 1, "holder PID") ||
        !require(topology.holder_start != 0, "holder start") ||
        !require(topology.holder_netns != 0, "holder netns") ||
        !require(sidecar.token == topology.token, "token label") ||
        !require(sidecar.stage == kSidecarStage, "stage label") ||
        !require(sidecar.role == kSidecarRole, "role label") ||
        !require(sidecar.name == "rut358-sidecar-" + topology.token, "name") ||
        !require(full_container_id(sidecar.id), "full ID") ||
        !require(sidecar.pinned_image_reference == RUT_PINNED_NGINX_IMAGE,
                 "pinned image reference") ||
        !require(sha256_identity(sidecar.expected_image_id), "expected image ID") ||
        !require(sidecar.image_id == sidecar.expected_image_id, "anchored image ID") ||
        !require(sidecar.network_mode == "container:" + topology.holder_id, "network mode") ||
        !require(sidecar.path == "/bin/sleep", "entrypoint") ||
        !require(sidecar.arguments_json == "[\"infinity\"]", "arguments") ||
        !require(sidecar.running, "running state") || !require(sidecar.pid > 1, "PID") ||
        !require(sidecar.pid != topology.holder_pid, "distinct PID") ||
        !require(sidecar.start != 0, "start time") ||
        !require(sidecar.netns == topology.holder_netns, "holder netns equality") ||
        !require(sidecar.host_netns != 0, "host netns") ||
        !require(sidecar.netns != sidecar.host_netns, "non-host netns") ||
        !require(sidecar.read_only_root, "read-only root") ||
        !require(sidecar.capability_drop_all, "cap-drop ALL") ||
        !require(sidecar.no_new_privileges, "no-new-privileges") ||
        !require(sidecar.no_published_ports, "no published ports"))
        return false;
    return true;
}

static bool rotation_probe_evidence_equal(const HeldTopologyProbeEvidence& left,
                                          const HeldTopologyProbeEvidence& right) {
    return left.policy == right.policy &&
           left.selected_port_absence_checks == right.selected_port_absence_checks &&
           left.host_parent_af_inet_socket_calls == right.host_parent_af_inet_socket_calls &&
           left.successful_refusal_probes == right.successful_refusal_probes;
}

static bool valid_rotation_topology(const HeldTopologySnapshot& topology, std::string& error) {
    const auto require = [&](bool condition, const char* field) {
        if (!condition) error = std::string("held-namespace rotation topology mismatch: ") + field;
        return condition;
    };
    std::string probe_error;
    const SubnetPlan retained_plan{{topology.network_a_subnet, topology.network_a_gateway},
                                   {topology.network_b_subnet, topology.network_b_gateway}};
    std::string expected_positive;
    std::string expected_guard;
    if (!require(lowercase_hex(topology.token, 48u), "token") ||
        !require(topology.network_a_name == "rut358-a-" + topology.token, "network A name") ||
        !require(topology.network_b_name == "rut358-b-" + topology.token, "network B name") ||
        !require(topology.holder_name == "rut358-holder-" + topology.token, "holder name") ||
        !require(full_container_id(topology.network_a_id), "network A ID") ||
        !require(full_container_id(topology.network_b_id), "network B ID") ||
        !require(topology.network_a_id != topology.network_b_id, "distinct network IDs") ||
        !require(valid_subnet_plan(retained_plan), "canonical retained network/IPAM plan") ||
        !require(full_container_id(topology.holder_id), "holder ID") ||
        !require(choose_address(
                     topology.network_a_subnet, topology.network_a_gateway, expected_positive) &&
                     topology.positive_ip == expected_positive,
                 "canonical positive IP") ||
        !require(
            choose_address(topology.network_b_subnet, topology.network_b_gateway, expected_guard) &&
                topology.guard_ip == expected_guard,
            "canonical guard IP") ||
        !require(topology.holder_pid > 1, "holder PID") ||
        !require(topology.holder_start != 0u, "holder start") ||
        !require(topology.holder_netns != 0u, "holder netns") ||
        !require(validate_held_topology_probe_evidence(
                     topology.probe_evidence, topology.probe_evidence.policy, probe_error),
                 probe_error.c_str()))
        return false;
    return true;
}

static bool retained_rotation_topology_equal(const HeldTopologySnapshot& old_topology,
                                             const HeldTopologySnapshot& new_topology) {
    // Keep this explicit: topology_snapshot_equal intentionally omits probe
    // evidence and therefore is not sufficient for a generation receipt.
    return old_topology.token == new_topology.token &&
           old_topology.network_a_name == new_topology.network_a_name &&
           old_topology.network_a_id == new_topology.network_a_id &&
           old_topology.network_a_subnet == new_topology.network_a_subnet &&
           old_topology.network_a_gateway == new_topology.network_a_gateway &&
           old_topology.network_b_name == new_topology.network_b_name &&
           old_topology.network_b_id == new_topology.network_b_id &&
           old_topology.network_b_subnet == new_topology.network_b_subnet &&
           old_topology.network_b_gateway == new_topology.network_b_gateway &&
           old_topology.holder_name == new_topology.holder_name &&
           old_topology.positive_ip == new_topology.positive_ip &&
           old_topology.guard_ip == new_topology.guard_ip &&
           rotation_probe_evidence_equal(old_topology.probe_evidence, new_topology.probe_evidence);
}

static bool stable_rotation_sidecar_equal(const HeldNamespaceSidecarSnapshot& old_sidecar,
                                          const HeldNamespaceSidecarSnapshot& new_sidecar) {
    return old_sidecar.token == new_sidecar.token && old_sidecar.stage == new_sidecar.stage &&
           old_sidecar.role == new_sidecar.role && old_sidecar.name == new_sidecar.name &&
           old_sidecar.pinned_image_reference == new_sidecar.pinned_image_reference &&
           old_sidecar.expected_image_id == new_sidecar.expected_image_id &&
           old_sidecar.image_id == new_sidecar.image_id && old_sidecar.path == new_sidecar.path &&
           old_sidecar.arguments_json == new_sidecar.arguments_json &&
           old_sidecar.host_netns == new_sidecar.host_netns &&
           old_sidecar.running == new_sidecar.running &&
           old_sidecar.read_only_root == new_sidecar.read_only_root &&
           old_sidecar.capability_drop_all == new_sidecar.capability_drop_all &&
           old_sidecar.no_new_privileges == new_sidecar.no_new_privileges &&
           old_sidecar.no_published_ports == new_sidecar.no_published_ports;
}

bool validate_held_namespace_generation_rotation_receipt(
    const HeldNamespaceGenerationRotationReceipt& receipt, std::string& error) {
    error.clear();
    const auto require = [&](bool condition, const char* field) {
        if (!condition)
            error = std::string("held-namespace generation rotation mismatch: ") + field;
        return condition;
    };
    if (!require(receipt.old_generation_phase ==
                         HeldNamespaceGenerationRotationPhase::OldGenerationValidated &&
                     receipt.old_absence.phase ==
                         HeldNamespaceGenerationRotationPhase::OldGenerationAbsent &&
                     receipt.new_generation_created_phase ==
                         HeldNamespaceGenerationRotationPhase::NewGenerationCreated &&
                     receipt.new_generation_validated_phase ==
                         HeldNamespaceGenerationRotationPhase::NewGenerationValidated,
                 "strict fixed phase order"))
        return false;

    const HeldTopologySnapshot& old_topology = receipt.old_generation.topology;
    const HeldNamespaceSidecarSnapshot& old_sidecar = receipt.old_generation.sidecar;
    const HeldTopologySnapshot& new_topology = receipt.new_generation.topology;
    const HeldNamespaceSidecarSnapshot& new_sidecar = receipt.new_generation.sidecar;
    if (!valid_rotation_topology(old_topology, error) ||
        !validate_held_namespace_sidecar_snapshot(old_topology, old_sidecar, error) ||
        !valid_rotation_topology(new_topology, error) ||
        !validate_held_namespace_sidecar_snapshot(new_topology, new_sidecar, error))
        return false;
    const std::array<std::string, 4> container_ids{
        old_topology.holder_id, old_sidecar.id, new_topology.holder_id, new_sidecar.id};
    bool pairwise_distinct_ids = true;
    for (size_t left = 0; left < container_ids.size(); ++left)
        for (size_t right = left + 1; right < container_ids.size(); ++right)
            pairwise_distinct_ids =
                pairwise_distinct_ids && container_ids[left] != container_ids[right];
    if (!require(retained_rotation_topology_equal(old_topology, new_topology),
                 "retained network/IPAM/probe evidence") ||
        !require(stable_rotation_sidecar_equal(old_sidecar, new_sidecar),
                 "stable sidecar name/labels/configuration") ||
        !require(pairwise_distinct_ids, "pairwise distinct generation container IDs") ||
        !require(old_topology.holder_pid != new_topology.holder_pid ||
                     old_topology.holder_start != new_topology.holder_start,
                 "distinct holder process identity") ||
        !require(old_sidecar.pid != new_sidecar.pid || old_sidecar.start != new_sidecar.start,
                 "distinct sidecar process identity"))
        return false;

    const HeldNamespaceGenerationWitnessAbsence& holder = receipt.old_absence.holder;
    const HeldNamespaceGenerationWitnessAbsence& sidecar = receipt.old_absence.sidecar;
    const bool exact_holder_absence = holder.container_id == old_topology.holder_id &&
                                      holder.pid == old_topology.holder_pid &&
                                      holder.start == old_topology.holder_start &&
                                      holder.container_id_absent && holder.process_identity_absent;
    const bool exact_sidecar_absence =
        sidecar.container_id == old_sidecar.id && sidecar.pid == old_sidecar.pid &&
        sidecar.start == old_sidecar.start && sidecar.container_id_absent &&
        sidecar.process_identity_absent;
    const bool exact_name_absence = receipt.old_absence.holder_name == old_topology.holder_name &&
                                    receipt.old_absence.sidecar_name == old_sidecar.name &&
                                    receipt.old_absence.holder_name_absent &&
                                    receipt.old_absence.sidecar_name_absent;
    if (!require(exact_holder_absence, "exact old holder witness absence") ||
        !require(exact_sidecar_absence, "exact old sidecar witness absence") ||
        !require(exact_name_absence, "exact old stable-name absence before reuse"))
        return false;
    // Linux may reuse a namespace inode.  Equality is permitted: this receipt
    // proves only operational absence of exact old container/name/process
    // witnesses, never destruction of a kernel namespace object.
    return true;
}

static bool exact_input_rotation_source_equal(const ExactInputRotationSourceEvidence& left,
                                              const ExactInputRotationSourceEvidence& right) {
    return left.path == right.path && left.bytes == right.bytes && left.device == right.device &&
           left.inode == right.inode && left.mode == right.mode && left.uid == right.uid &&
           left.gid == right.gid && left.size == right.size && left.links == right.links &&
           left.mtime_seconds == right.mtime_seconds &&
           left.mtime_nanoseconds == right.mtime_nanoseconds &&
           left.ctime_seconds == right.ctime_seconds &&
           left.ctime_nanoseconds == right.ctime_nanoseconds &&
           left.regular_0600 == right.regular_0600 &&
           left.exact_bytes_revalidated == right.exact_bytes_revalidated &&
           left.retained_ofd_revalidated == right.retained_ofd_revalidated;
}

static bool exact_input_mounted_equal(const ExactInputMountedSidecarEvidence& left,
                                      const ExactInputMountedSidecarEvidence& right) {
    return left.token == right.token && left.stage == right.stage && left.role == right.role &&
           left.generation == right.generation && left.name == right.name && left.id == right.id &&
           left.image_reference == right.image_reference && left.image_id == right.image_id &&
           left.network_mode == right.network_mode && left.user == right.user &&
           left.path == right.path && left.arguments_json == right.arguments_json &&
           left.source_path == right.source_path && left.pid == right.pid &&
           left.start == right.start && left.network_netns == right.network_netns &&
           left.mount_netns == right.mount_netns && left.running == right.running &&
           left.read_only_root == right.read_only_root &&
           left.capability_drop_all == right.capability_drop_all &&
           left.no_new_privileges == right.no_new_privileges &&
           left.restart_no == right.restart_no &&
           left.no_published_ports == right.no_published_ports &&
           left.requested_mount_exact == right.requested_mount_exact &&
           left.realized_mount_exact == right.realized_mount_exact &&
           left.no_mount_shadowing == right.no_mount_shadowing &&
           left.nonhost_mount_netns == right.nonhost_mount_netns;
}

static bool exact_input_mounted_absence_equal(const ExactInputMountedSidecarAbsence& left,
                                              const ExactInputMountedSidecarAbsence& right) {
    return left.id == right.id && left.name == right.name && left.pid == right.pid &&
           left.start == right.start && left.id_absent == right.id_absent &&
           left.name_absent == right.name_absent &&
           left.token_role_generation_absent == right.token_role_generation_absent &&
           left.process_absent == right.process_absent;
}

static bool exact_input_mounted_absence_matches(const ExactInputMountedSidecarAbsence& absence,
                                                const ExactInputMountedSidecarEvidence& mounted) {
    return absence.id == mounted.id && absence.name == mounted.name && absence.pid == mounted.pid &&
           absence.start == mounted.start && absence.id_absent && absence.name_absent &&
           absence.token_role_generation_absent && absence.process_absent;
}

static bool exact_input_rotation_read_equal(const ExactInputRotationReadEvidence& left,
                                            const ExactInputRotationReadEvidence& right) {
    const auto command_equal = [](const ExactInputReadObservation& a,
                                  const ExactInputReadObservation& b) {
        return a.outcome == b.outcome && a.attempted == b.attempted &&
               a.terminal_frozen == b.terminal_frozen && a.command_started == b.command_started &&
               a.stdout_eof == b.stdout_eof && a.stderr_eof == b.stderr_eof &&
               a.child_reaped == b.child_reaped && a.wait_status_valid == b.wait_status_valid &&
               a.process_group_owned == b.process_group_owned &&
               a.process_group_gone == b.process_group_gone && a.pidfd_opened == b.pidfd_opened &&
               a.pidfd_identity_verified == b.pidfd_identity_verified &&
               a.pidfd_closed_after_group_gone == b.pidfd_closed_after_group_gone &&
               a.final_deadline_recorded == b.final_deadline_recorded &&
               a.cleanup_completed_before_final_deadline ==
                   b.cleanup_completed_before_final_deadline &&
               a.supervisor_session_verified == b.supervisor_session_verified &&
               a.supervisor_subreaper_verified == b.supervisor_subreaper_verified &&
               a.actual_exec_observed == b.actual_exec_observed &&
               a.subtree_confinement_installed == b.subtree_confinement_installed &&
               a.group_echild_observed == b.group_echild_observed &&
               a.control_eof_cleanup == b.control_eof_cleanup &&
               a.leader_exit_observed_before_group_cleanup ==
                   b.leader_exit_observed_before_group_cleanup &&
               a.descendant_group_member_observed == b.descendant_group_member_observed &&
               a.setpgid_denied == b.setpgid_denied && a.setsid_denied == b.setsid_denied &&
               a.clone_parent_observed == b.clone_parent_observed &&
               a.adopted_reap_count == b.adopted_reap_count &&
               a.foreign_process_survived == b.foreign_process_survived &&
               a.foreign_fd_excluded == b.foreign_fd_excluded &&
               a.deadline_exceeded == b.deadline_exceeded &&
               a.output_overflow == b.output_overflow &&
               a.pre_source_revalidated == b.pre_source_revalidated &&
               a.pre_container_identity == b.pre_container_identity &&
               a.pre_mount_inspected == b.pre_mount_inspected &&
               a.pre_proc_credentials == b.pre_proc_credentials &&
               a.post_source_revalidated == b.post_source_revalidated &&
               a.post_container_identity == b.post_container_identity &&
               a.post_mount_inspected == b.post_mount_inspected &&
               a.post_proc_credentials == b.post_proc_credentials &&
               a.registered_identity_matched == b.registered_identity_matched &&
               a.registered_mount_matched == b.registered_mount_matched &&
               a.expected_size == b.expected_size && a.stdout_read_errno == b.stdout_read_errno &&
               a.stderr_read_errno == b.stderr_read_errno &&
               a.launch_failure_stage == b.launch_failure_stage &&
               a.launch_errno == b.launch_errno && a.wait_status == b.wait_status &&
               a.command_argv == b.command_argv && a.resolved_executable == b.resolved_executable &&
               a.stdout_bytes == b.stdout_bytes && a.stderr_bytes == b.stderr_bytes &&
               a.diagnostic.phase == b.diagnostic.phase &&
               a.diagnostic.error_number == b.diagnostic.error_number &&
               a.diagnostic.message == b.diagnostic.message;
    };
    return left.outcome == right.outcome && left.attempted == right.attempted &&
           left.terminal_frozen == right.terminal_frozen &&
           left.caller_deadline_recorded == right.caller_deadline_recorded &&
           left.final_deadline_nanoseconds == right.final_deadline_nanoseconds &&
           exact_input_rotation_source_equal(left.source_before, right.source_before) &&
           exact_input_rotation_source_equal(left.source_after, right.source_after) &&
           exact_input_mounted_equal(left.target_before, right.target_before) &&
           exact_input_mounted_equal(left.target_after, right.target_after) &&
           command_equal(left.command, right.command) &&
           left.source_brackets_equal == right.source_brackets_equal &&
           left.target_brackets_equal == right.target_brackets_equal;
}

static void finalize_rotation_read_command(ExactInputReadObservation& command,
                                           std::size_t expected_size) {
    command.expected_size = expected_size;
    command.terminal_frozen = true;
}

static bool exact_input_rotation_read_complete_contract(
    const ExactInputRotationReadEvidence& read,
    const ExactInputRotationSourceEvidence& source,
    const ExactInputMountedSidecarEvidence& target) {
    const auto& command = read.command;
    const std::vector<std::string> expected_argv = {"docker",
                                                    "exec",
                                                    "--user",
                                                    target.user,
                                                    target.id,
                                                    "/bin/cat",
                                                    kExactInputMountDestination};
    return read.attempted && read.terminal_frozen && read.caller_deadline_recorded &&
           read.final_deadline_nanoseconds > 0 && read.source_brackets_equal &&
           read.target_brackets_equal &&
           exact_input_rotation_source_equal(read.source_before, source) &&
           exact_input_rotation_source_equal(read.source_after, source) &&
           exact_input_mounted_equal(read.target_before, target) &&
           exact_input_mounted_equal(read.target_after, target) &&
           read.outcome == ExactInputReadOutcome::Complete && command.attempted &&
           command.terminal_frozen && command.command_started && command.actual_exec_observed &&
           command.stdout_eof && command.stderr_eof && command.child_reaped &&
           command.wait_status_valid && WIFEXITED(command.wait_status) &&
           WEXITSTATUS(command.wait_status) == 0 && command.process_group_owned &&
           command.process_group_gone && command.group_echild_observed && command.pidfd_opened &&
           command.pidfd_identity_verified && command.pidfd_closed_after_group_gone &&
           command.supervisor_session_verified && command.supervisor_subreaper_verified &&
           command.subtree_confinement_installed && command.final_deadline_recorded &&
           command.cleanup_completed_before_final_deadline && !command.deadline_exceeded &&
           !command.output_overflow && command.stdout_read_errno == 0 &&
           command.stderr_read_errno == 0 &&
           command.launch_failure_stage == ExactInputReadLaunchStage::None &&
           command.launch_errno == 0 && command.expected_size == source.bytes.size() &&
           command.stdout_bytes == source.bytes && command.stderr_bytes.empty() &&
           command.command_argv == expected_argv &&
           command.resolved_executable == resolve_exact_read_executable("docker");
}

static bool rotation_write_bracket_equal_public(const ExactInputRotationWriteBracket& left,
                                                const ExactInputRotationWriteBracket& right) {
    return left.source_revalidated == right.source_revalidated &&
           left.source_bytes_revalidated == right.source_bytes_revalidated &&
           left.retained_ofd_revalidated == right.retained_ofd_revalidated &&
           left.target_revalidated == right.target_revalidated &&
           exact_input_rotation_source_equal(left.source, right.source) &&
           exact_input_mounted_equal(left.target, right.target);
}

static bool rotation_write_bracket_contract(const ExactInputRotationWriteBracket& bracket) {
    const auto& source = bracket.source;
    const auto& target = bracket.target;
    return bracket.source_revalidated && bracket.source_bytes_revalidated &&
           bracket.retained_ofd_revalidated && bracket.target_revalidated && source.regular_0600 &&
           source.exact_bytes_revalidated && source.retained_ofd_revalidated &&
           source.size == source.bytes.size() && full_container_id(target.id) && target.running &&
           target.read_only_root && target.capability_drop_all && target.no_new_privileges &&
           target.restart_no && target.no_published_ports && target.requested_mount_exact &&
           target.realized_mount_exact && target.no_mount_shadowing && target.nonhost_mount_netns &&
           target.user == std::to_string(source.uid) + ":" + std::to_string(source.gid);
}

static bool rotation_write_command_contract_public(const ExactInputReadObservation& command,
                                                   const std::vector<std::string>& argv,
                                                   int expected_status,
                                                   const std::string& expected_stdout,
                                                   const std::string& expected_stderr) {
    return command.attempted && command.terminal_frozen && command.command_started &&
           command.actual_exec_observed && command.stdout_eof && command.stderr_eof &&
           command.child_reaped && command.wait_status_valid && WIFEXITED(command.wait_status) &&
           WEXITSTATUS(command.wait_status) == expected_status && command.process_group_owned &&
           command.process_group_gone && command.group_echild_observed && command.pidfd_opened &&
           command.pidfd_identity_verified && command.pidfd_closed_after_group_gone &&
           command.supervisor_session_verified && command.supervisor_subreaper_verified &&
           command.subtree_confinement_installed && command.final_deadline_recorded &&
           command.cleanup_completed_before_final_deadline && !command.deadline_exceeded &&
           !command.output_overflow && command.stdout_read_errno == 0 &&
           command.stderr_read_errno == 0 &&
           command.launch_failure_stage == ExactInputReadLaunchStage::None &&
           command.launch_errno == 0 && command.command_argv == argv &&
           command.resolved_executable == resolve_exact_read_executable("docker") &&
           command.stdout_bytes == expected_stdout && command.stderr_bytes == expected_stderr;
}

static bool exact_input_rotation_write_complete_contract(
    const ExactInputRotationWriteRefusalEvidence& write,
    const ExactInputRotationSourceEvidence& source,
    const ExactInputMountedSidecarEvidence& target) {
    const std::vector<std::string> control_argv = {"docker",
                                                   "exec",
                                                   "--env",
                                                   "LC_ALL=C",
                                                   "--user",
                                                   write.credentials,
                                                   target.id,
                                                   "/usr/bin/dd",
                                                   "if=/dev/zero",
                                                   "of=/dev/null",
                                                   "bs=1",
                                                   "count=1",
                                                   "conv=notrunc",
                                                   "status=none"};
    const std::vector<std::string> target_argv = {"docker",
                                                  "exec",
                                                  "--env",
                                                  "LC_ALL=C",
                                                  "--user",
                                                  write.credentials,
                                                  target.id,
                                                  "/usr/bin/dd",
                                                  "if=/etc/nginx/nginx.conf",
                                                  "of=/etc/nginx/nginx.conf",
                                                  "bs=1",
                                                  "count=1",
                                                  "conv=notrunc",
                                                  "status=none"};
    return write.attempted && write.terminal_frozen && write.caller_deadline_recorded &&
           write.final_deadline_nanoseconds > 0 &&
           write.credentials == std::to_string(source.uid) + ":" + std::to_string(source.gid) &&
           write.expected_target_stderr ==
               "dd: failed to open '/etc/nginx/nginx.conf': Read-only file system\n" &&
           rotation_write_bracket_equal_public(write.initial_bracket, write.middle_bracket) &&
           rotation_write_bracket_equal_public(write.initial_bracket, write.final_bracket) &&
           rotation_write_bracket_contract(write.initial_bracket) &&
           rotation_write_bracket_contract(write.middle_bracket) &&
           rotation_write_bracket_contract(write.final_bracket) &&
           exact_input_rotation_source_equal(write.initial_bracket.source, source) &&
           exact_input_rotation_source_equal(write.middle_bracket.source, source) &&
           exact_input_rotation_source_equal(write.final_bracket.source, source) &&
           exact_input_mounted_equal(write.initial_bracket.target, target) &&
           exact_input_mounted_equal(write.middle_bracket.target, target) &&
           exact_input_mounted_equal(write.final_bracket.target, target) &&
           rotation_write_command_contract_public(write.control, control_argv, 0, {}, {}) &&
           rotation_write_command_contract_public(
               write.target, target_argv, 1, {}, write.expected_target_stderr) &&
           write.control.outcome == ExactInputReadOutcome::Complete &&
           write.target.outcome == ExactInputReadOutcome::ExitNonzero &&
           write.diagnostic.phase == ExactInputMountPhase::None &&
           write.diagnostic.error_number == 0 && write.diagnostic.message.empty();
}

static bool rotation_write_observation_equal(const ExactInputReadObservation& left,
                                             const ExactInputReadObservation& right) {
    return left.outcome == right.outcome && left.attempted == right.attempted &&
           left.terminal_frozen == right.terminal_frozen &&
           left.command_started == right.command_started && left.stdout_eof == right.stdout_eof &&
           left.stderr_eof == right.stderr_eof && left.child_reaped == right.child_reaped &&
           left.wait_status_valid == right.wait_status_valid &&
           left.process_group_owned == right.process_group_owned &&
           left.process_group_gone == right.process_group_gone &&
           left.pidfd_opened == right.pidfd_opened &&
           left.pidfd_identity_verified == right.pidfd_identity_verified &&
           left.pidfd_closed_after_group_gone == right.pidfd_closed_after_group_gone &&
           left.final_deadline_recorded == right.final_deadline_recorded &&
           left.cleanup_completed_before_final_deadline ==
               right.cleanup_completed_before_final_deadline &&
           left.leader_exit_observed_before_group_cleanup ==
               right.leader_exit_observed_before_group_cleanup &&
           left.descendant_group_member_observed == right.descendant_group_member_observed &&
           left.supervisor_session_verified == right.supervisor_session_verified &&
           left.supervisor_subreaper_verified == right.supervisor_subreaper_verified &&
           left.actual_exec_observed == right.actual_exec_observed &&
           left.subtree_confinement_installed == right.subtree_confinement_installed &&
           left.group_echild_observed == right.group_echild_observed &&
           left.control_eof_cleanup == right.control_eof_cleanup &&
           left.adopted_reap_count == right.adopted_reap_count &&
           left.deadline_exceeded == right.deadline_exceeded &&
           left.output_overflow == right.output_overflow &&
           left.stdout_read_errno == right.stdout_read_errno &&
           left.stderr_read_errno == right.stderr_read_errno &&
           left.launch_failure_stage == right.launch_failure_stage &&
           left.launch_errno == right.launch_errno && left.wait_status == right.wait_status &&
           left.command_argv == right.command_argv &&
           left.resolved_executable == right.resolved_executable &&
           left.stdout_bytes == right.stdout_bytes && left.stderr_bytes == right.stderr_bytes &&
           left.diagnostic.phase == right.diagnostic.phase &&
           left.diagnostic.error_number == right.diagnostic.error_number &&
           left.diagnostic.message == right.diagnostic.message;
}

static bool exact_input_rotation_live_equal(const ExactInputRotationLiveEvidence& left,
                                            const ExactInputRotationLiveEvidence& right) {
    return left.state == right.state &&
           exact_input_rotation_source_equal(left.initial_source, right.initial_source) &&
           exact_input_rotation_source_equal(left.fresh_source, right.fresh_source) &&
           exact_input_mounted_equal(left.old_mounted, right.old_mounted) &&
           exact_input_mounted_absence_equal(left.old_absence, right.old_absence) &&
           generation_receipt_equal(left.generation_receipt, right.generation_receipt) &&
           exact_input_mounted_equal(left.fresh_mounted, right.fresh_mounted) &&
           exact_input_rotation_read_equal(left.fresh_read, right.fresh_read) &&
           left.fresh_write.outcome == right.fresh_write.outcome &&
           left.fresh_write.attempted == right.fresh_write.attempted &&
           left.fresh_write.terminal_frozen == right.fresh_write.terminal_frozen &&
           left.fresh_write.caller_deadline_recorded ==
               right.fresh_write.caller_deadline_recorded &&
           left.fresh_write.final_deadline_nanoseconds ==
               right.fresh_write.final_deadline_nanoseconds &&
           left.fresh_write.credentials == right.fresh_write.credentials &&
           left.fresh_write.expected_target_stderr == right.fresh_write.expected_target_stderr &&
           rotation_write_bracket_equal_public(left.fresh_write.initial_bracket,
                                               right.fresh_write.initial_bracket) &&
           rotation_write_bracket_equal_public(left.fresh_write.middle_bracket,
                                               right.fresh_write.middle_bracket) &&
           rotation_write_bracket_equal_public(left.fresh_write.final_bracket,
                                               right.fresh_write.final_bracket) &&
           exact_input_rotation_source_equal(left.fresh_write.initial_bracket.source,
                                             right.fresh_write.initial_bracket.source) &&
           exact_input_rotation_source_equal(left.fresh_write.middle_bracket.source,
                                             right.fresh_write.middle_bracket.source) &&
           exact_input_rotation_source_equal(left.fresh_write.final_bracket.source,
                                             right.fresh_write.final_bracket.source) &&
           exact_input_mounted_equal(left.fresh_write.initial_bracket.target,
                                     right.fresh_write.initial_bracket.target) &&
           exact_input_mounted_equal(left.fresh_write.middle_bracket.target,
                                     right.fresh_write.middle_bracket.target) &&
           exact_input_mounted_equal(left.fresh_write.final_bracket.target,
                                     right.fresh_write.final_bracket.target) &&
           rotation_write_observation_equal(left.fresh_write.control, right.fresh_write.control) &&
           rotation_write_observation_equal(left.fresh_write.target, right.fresh_write.target) &&
           left.fresh_write.diagnostic.phase == right.fresh_write.diagnostic.phase &&
           left.fresh_write.diagnostic.error_number == right.fresh_write.diagnostic.error_number &&
           left.fresh_write.diagnostic.message == right.fresh_write.diagnostic.message &&
           left.source_continuity == right.source_continuity &&
           left.generation_receipt_validated_twice == right.generation_receipt_validated_twice &&
           left.old_and_fresh_authorities_separate == right.old_and_fresh_authorities_separate &&
           left.operation_ok == right.operation_ok &&
           left.old_create_count == right.old_create_count &&
           left.old_remove_count == right.old_remove_count &&
           left.fresh_create_count == right.fresh_create_count &&
           left.fresh_start_count == right.fresh_start_count &&
           left.fresh_remove_count == right.fresh_remove_count;
}

static bool exact_input_rotation_terminal_equal(const ExactInputRotationTerminalReceipt& left,
                                                const ExactInputRotationTerminalReceipt& right) {
    return left.state == right.state && exact_input_rotation_live_equal(left.live, right.live) &&
           exact_input_mounted_absence_equal(left.fresh_absence, right.fresh_absence) &&
           left.live_published == right.live_published && left.operation_ok == right.operation_ok &&
           left.cleanup_complete == right.cleanup_complete &&
           left.zero_residue == right.zero_residue &&
           left.terminal_frozen == right.terminal_frozen &&
           left.replay_command_free == right.replay_command_free &&
           left.downstream_gates_command_free == right.downstream_gates_command_free &&
           left.fresh_remove_count == right.fresh_remove_count &&
           left.fresh_remove_suppression_count == right.fresh_remove_suppression_count &&
           left.fresh_mounted_order == right.fresh_mounted_order &&
           left.fresh_inert_order == right.fresh_inert_order &&
           left.input_order == right.input_order && left.directory_order == right.directory_order &&
           left.holder_order == right.holder_order &&
           left.network_b_order == right.network_b_order &&
           left.network_a_order == right.network_a_order;
}

bool validate_exact_input_rotation_live_evidence(const ExactInputRotationLiveEvidence& evidence,
                                                 std::string& error) {
    error.clear();
    const auto reject = [&](const char* field) {
        error = std::string("exact-input rotation live evidence mismatch: ") + field;
        return false;
    };
    std::string generation_error;
    if (evidence.state != ExactInputRotationState::LivePublished &&
        evidence.state != ExactInputRotationState::Unresolved)
        return reject("state");
    if (evidence.initial_source.path.empty() || evidence.initial_source.bytes.empty() ||
        evidence.initial_source.size != evidence.initial_source.bytes.size() ||
        !evidence.initial_source.regular_0600 || !evidence.initial_source.exact_bytes_revalidated ||
        !evidence.initial_source.retained_ofd_revalidated ||
        !exact_input_rotation_source_equal(evidence.initial_source, evidence.fresh_source) ||
        !evidence.source_continuity)
        return reject("canonical source continuity");
    if (!validate_held_namespace_generation_rotation_receipt(evidence.generation_receipt,
                                                             generation_error) ||
        !evidence.generation_receipt_validated_twice)
        return reject("complete generation receipt");
    const auto mounted_exact = [](const ExactInputMountedSidecarEvidence& mounted,
                                  const std::string& generation,
                                  const std::string& holder_id,
                                  std::uint64_t holder_netns) {
        return mounted.stage == "358-input-rotation" &&
               mounted.role == "exact-input-mounted-sidecar" && mounted.generation == generation &&
               mounted.name == "rut358-input-" + mounted.token && full_container_id(mounted.id) &&
               mounted.image_reference == RUT_PINNED_NGINX_IMAGE &&
               sha256_identity(mounted.image_id) &&
               mounted.network_mode == "container:" + holder_id && !mounted.user.empty() &&
               mounted.path == "/bin/sleep" && mounted.arguments_json == "[\"infinity\"]" &&
               mounted.pid > 1 && mounted.start != 0u && mounted.running &&
               mounted.network_netns == holder_netns && mounted.mount_netns != 0u &&
               mounted.nonhost_mount_netns && mounted.read_only_root &&
               mounted.capability_drop_all && mounted.no_new_privileges && mounted.restart_no &&
               mounted.no_published_ports && mounted.requested_mount_exact &&
               mounted.realized_mount_exact && mounted.no_mount_shadowing;
    };
    const auto& generation = evidence.generation_receipt;
    if (!mounted_exact(evidence.old_mounted,
                       "0",
                       generation.old_generation.topology.holder_id,
                       generation.old_generation.topology.holder_netns) ||
        !mounted_exact(evidence.fresh_mounted,
                       "1",
                       generation.new_generation.topology.holder_id,
                       generation.new_generation.topology.holder_netns) ||
        evidence.old_mounted.token != generation.old_generation.topology.token ||
        evidence.fresh_mounted.token != generation.new_generation.topology.token ||
        evidence.old_mounted.name != evidence.fresh_mounted.name ||
        evidence.old_mounted.source_path != evidence.initial_source.path ||
        evidence.fresh_mounted.source_path != evidence.fresh_source.path)
        return reject("old/fresh mounted configuration");
    const std::array<std::string, 6> ids{generation.old_generation.topology.holder_id,
                                         generation.old_generation.sidecar.id,
                                         generation.new_generation.topology.holder_id,
                                         generation.new_generation.sidecar.id,
                                         evidence.old_mounted.id,
                                         evidence.fresh_mounted.id};
    for (std::size_t left = 0; left < ids.size(); ++left)
        for (std::size_t right = left + 1; right < ids.size(); ++right)
            if (ids[left] == ids[right]) return reject("pairwise distinct container IDs");
    const auto tuple_distinct =
        [](pid_t left_pid, std::uint64_t left_start, pid_t right_pid, std::uint64_t right_start) {
            return left_pid != right_pid || left_start != right_start;
        };
    if (!tuple_distinct(evidence.old_mounted.pid,
                        evidence.old_mounted.start,
                        generation.old_generation.topology.holder_pid,
                        generation.old_generation.topology.holder_start) ||
        !tuple_distinct(evidence.old_mounted.pid,
                        evidence.old_mounted.start,
                        generation.old_generation.sidecar.pid,
                        generation.old_generation.sidecar.start) ||
        !tuple_distinct(evidence.fresh_mounted.pid,
                        evidence.fresh_mounted.start,
                        generation.new_generation.topology.holder_pid,
                        generation.new_generation.topology.holder_start) ||
        !tuple_distinct(evidence.fresh_mounted.pid,
                        evidence.fresh_mounted.start,
                        generation.new_generation.sidecar.pid,
                        generation.new_generation.sidecar.start) ||
        !tuple_distinct(evidence.old_mounted.pid,
                        evidence.old_mounted.start,
                        evidence.fresh_mounted.pid,
                        evidence.fresh_mounted.start) ||
        !evidence.old_and_fresh_authorities_separate)
        return reject("pairwise distinct process witnesses");
    const auto& absence = evidence.old_absence;
    if (absence.id != evidence.old_mounted.id || absence.name != evidence.old_mounted.name ||
        absence.pid != evidence.old_mounted.pid || absence.start != evidence.old_mounted.start ||
        !absence.id_absent || !absence.name_absent || !absence.token_role_generation_absent ||
        !absence.process_absent)
        return reject("old mounted exact absence");
    if (evidence.old_create_count != 1u || evidence.old_remove_count != 1u ||
        evidence.fresh_create_count != 1u || evidence.fresh_start_count != 1u ||
        evidence.fresh_remove_count != 0u)
        return reject("live command counts");
    if (evidence.state == ExactInputRotationState::LivePublished) {
        if (!exact_input_rotation_read_complete_contract(
                evidence.fresh_read, evidence.initial_source, evidence.fresh_mounted)) {
            return reject("fresh generation exact read evidence");
        }
        if (evidence.fresh_write.outcome != ExactInputWriteRefusalOutcome::Complete ||
            !exact_input_rotation_write_complete_contract(
                evidence.fresh_write, evidence.initial_source, evidence.fresh_mounted)) {
            return reject("fresh generation exact write-refusal evidence");
        }
    } else {
        const auto reject_unresolved = [&](const char* field) {
            error = std::string("exact-input rotation live evidence mismatch: ") + field;
            if (!evidence.fresh_write.diagnostic.message.empty()) {
                error += ": ";
                error += evidence.fresh_write.diagnostic.message;
            }
            return false;
        };
        if (!evidence.fresh_read.attempted) {
            // A pre-read mount observation failure is intentionally command
            // free. It is the only unresolved state with neither operation.
            if (evidence.fresh_read.outcome != ExactInputReadOutcome::None)
                return reject_unresolved("unattempted read carried an outcome");
            if (evidence.fresh_write.attempted)
                return reject_unresolved("write-refusal attempted before read");
            return true;
        }
        if (evidence.fresh_read.outcome != ExactInputReadOutcome::Complete) {
            if (evidence.fresh_read.outcome == ExactInputReadOutcome::None ||
                !evidence.fresh_read.terminal_frozen ||
                !evidence.fresh_read.caller_deadline_recorded)
                return reject_unresolved("unresolved fresh generation read failure");
            if (evidence.fresh_write.attempted)
                return reject_unresolved("write-refusal attempted after failed read");
            return true;
        }
        if (!evidence.fresh_write.attempted)
            return reject_unresolved("successful read was not followed by write refusal");
        if (evidence.fresh_write.outcome == ExactInputWriteRefusalOutcome::None ||
            evidence.fresh_write.outcome == ExactInputWriteRefusalOutcome::Complete ||
            !evidence.fresh_write.terminal_frozen || !evidence.fresh_write.caller_deadline_recorded)
            return reject_unresolved("unresolved fresh generation write-refusal failure");
    }
    return true;
}

bool validate_exact_input_rotation_terminal_receipt(
    const ExactInputRotationTerminalReceipt& receipt, std::string& error) {
    if (receipt.live_published) {
        if (!validate_exact_input_rotation_live_evidence(receipt.live, error)) return false;
    } else {
        ExactInputRotationLiveEvidence retained = receipt.live;
        if (retained.state != ExactInputRotationState::Unresolved) {
            error = "unpublished exact-input rotation did not remain explicitly unresolved";
            return false;
        }
        // Keep every unpublished unresolved state intact.  In particular, a
        // pre-command mount-observation mutation has no read attempt at all;
        // projecting it to LivePublished would falsely require successful
        // fresh-generation read evidence.
        if (!validate_exact_input_rotation_live_evidence(retained, error)) {
            error = "unpublished exact-input rotation lost retained authority: " + error;
            return false;
        }
    }
    const auto& absence = receipt.fresh_absence;
    if (receipt.state != ExactInputRotationState::Settled ||
        absence.id != receipt.live.fresh_mounted.id ||
        absence.name != receipt.live.fresh_mounted.name ||
        absence.pid != receipt.live.fresh_mounted.pid ||
        absence.start != receipt.live.fresh_mounted.start || !absence.id_absent ||
        !absence.name_absent || !absence.token_role_generation_absent || !absence.process_absent ||
        !receipt.cleanup_complete || !receipt.zero_residue || !receipt.terminal_frozen ||
        !receipt.replay_command_free || !receipt.downstream_gates_command_free ||
        receipt.fresh_remove_count != 1u || receipt.fresh_mounted_order != 1u ||
        receipt.fresh_inert_order != 2u || receipt.input_order != 3u ||
        receipt.directory_order != 4u || receipt.holder_order != 5u ||
        receipt.network_b_order != 6u || receipt.network_a_order != 7u) {
        error = "exact-input rotation terminal receipt was not exact and ordered";
        return false;
    }
    return true;
}

static bool held_namespace_generation_rotation_self_checks(std::string& error) {
    HeldNamespaceGenerationRotationReceipt seed;
    HeldTopologySnapshot& old_topology = seed.old_generation.topology;
    old_topology.token = std::string(48, '1');
    old_topology.network_a_name = "rut358-a-" + old_topology.token;
    old_topology.network_a_id = std::string(64, 'a');
    old_topology.network_a_subnet = "10.253.240.0/28";
    old_topology.network_a_gateway = "10.253.240.1";
    old_topology.network_b_name = "rut358-b-" + old_topology.token;
    old_topology.network_b_id = std::string(64, 'b');
    old_topology.network_b_subnet = "10.253.241.0/28";
    old_topology.network_b_gateway = "10.253.241.1";
    old_topology.holder_name = "rut358-holder-" + old_topology.token;
    old_topology.holder_id = std::string(64, 'c');
    old_topology.positive_ip = "10.253.240.2";
    old_topology.guard_ip = "10.253.241.2";
    old_topology.holder_pid = 100;
    old_topology.holder_start = 1000;
    old_topology.holder_netns = 2000;
    old_topology.probe_evidence = {HeldTopologyProbePolicy::SocketlessHostParent, 1u, 0u, 0u};

    HeldNamespaceSidecarSnapshot& old_sidecar = seed.old_generation.sidecar;
    old_sidecar.token = old_topology.token;
    old_sidecar.stage = kSidecarStage;
    old_sidecar.role = kSidecarRole;
    old_sidecar.name = "rut358-sidecar-" + old_topology.token;
    old_sidecar.id = std::string(64, 'd');
    old_sidecar.pinned_image_reference = RUT_PINNED_NGINX_IMAGE;
    old_sidecar.expected_image_id = "sha256:" + std::string(64, 'e');
    old_sidecar.image_id = old_sidecar.expected_image_id;
    old_sidecar.network_mode = "container:" + old_topology.holder_id;
    old_sidecar.path = "/bin/sleep";
    old_sidecar.arguments_json = "[\"infinity\"]";
    old_sidecar.pid = 101;
    old_sidecar.start = 1001;
    old_sidecar.netns = old_topology.holder_netns;
    old_sidecar.host_netns = 3000;
    old_sidecar.running = true;
    old_sidecar.read_only_root = true;
    old_sidecar.capability_drop_all = true;
    old_sidecar.no_new_privileges = true;
    old_sidecar.no_published_ports = true;

    seed.new_generation = seed.old_generation;
    HeldTopologySnapshot& new_topology = seed.new_generation.topology;
    HeldNamespaceSidecarSnapshot& new_sidecar = seed.new_generation.sidecar;
    new_topology.holder_id = std::string(64, 'f');
    // Exercise legal numeric PID and netns-inode reuse: process start and exact
    // container identity distinguish the new generation.
    new_topology.holder_start = 2000;
    new_sidecar.id = std::string(64, '4');
    new_sidecar.network_mode = "container:" + new_topology.holder_id;
    new_sidecar.start = 2001;

    seed.old_absence.holder = {
        old_topology.holder_id, old_topology.holder_pid, old_topology.holder_start, true, true};
    seed.old_absence.sidecar = {old_sidecar.id, old_sidecar.pid, old_sidecar.start, true, true};
    seed.old_absence.holder_name = old_topology.holder_name;
    seed.old_absence.sidecar_name = old_sidecar.name;
    seed.old_absence.holder_name_absent = true;
    seed.old_absence.sidecar_name_absent = true;
    seed.old_generation_phase = HeldNamespaceGenerationRotationPhase::OldGenerationValidated;
    seed.old_absence.phase = HeldNamespaceGenerationRotationPhase::OldGenerationAbsent;
    seed.new_generation_created_phase = HeldNamespaceGenerationRotationPhase::NewGenerationCreated;
    seed.new_generation_validated_phase =
        HeldNamespaceGenerationRotationPhase::NewGenerationValidated;

    std::string first_error = "stale";
    std::string second_error = "different stale value";
    if (!validate_held_namespace_generation_rotation_receipt(seed, first_error) ||
        !validate_held_namespace_generation_rotation_receipt(seed, second_error) ||
        !first_error.empty() || !second_error.empty()) {
        error = "valid deterministic held-namespace generation rotation receipt was rejected";
        return false;
    }

    const auto reject = [&](const HeldNamespaceGenerationRotationReceipt& mutation,
                            const char* field) {
        std::string diagnostic;
        if (validate_held_namespace_generation_rotation_receipt(mutation, diagnostic) ||
            diagnostic.empty()) {
            error =
                std::string("held-namespace generation rotation mutation was accepted: ") + field;
            return false;
        }
        return true;
    };
    const auto mutate =
        [&](const char* field,
            const std::function<void(HeldNamespaceGenerationRotationReceipt&)>& change) {
            HeldNamespaceGenerationRotationReceipt mutation = seed;
            change(mutation);
            return reject(mutation, field);
        };

    // Matching old/new corruption must fail topology validation itself rather
    // than being hidden by the retained-field comparator.
    if (!mutate("matching malformed subnet",
                [](auto& value) {
                    value.old_generation.topology.network_a_subnet = "not-a-cidr";
                    value.new_generation.topology.network_a_subnet = "not-a-cidr";
                }) ||
        !mutate("matching noncanonical subnet",
                [](auto& value) {
                    value.old_generation.topology.network_a_subnet = "10.253.240.1/28";
                    value.new_generation.topology.network_a_subnet = "10.253.240.1/28";
                }) ||
        !mutate("matching malformed gateway",
                [](auto& value) {
                    value.old_generation.topology.network_a_gateway = "not-an-ip";
                    value.new_generation.topology.network_a_gateway = "not-an-ip";
                }) ||
        !mutate("matching noncanonical gateway",
                [](auto& value) {
                    value.old_generation.topology.network_a_gateway = "10.253.240.01";
                    value.new_generation.topology.network_a_gateway = "10.253.240.01";
                }) ||
        !mutate("matching malformed positive IP",
                [](auto& value) {
                    value.old_generation.topology.positive_ip = "not-an-ip";
                    value.new_generation.topology.positive_ip = "not-an-ip";
                }) ||
        !mutate("matching noncanonical positive IP",
                [](auto& value) {
                    value.old_generation.topology.positive_ip = "10.253.240.002";
                    value.new_generation.topology.positive_ip = "10.253.240.002";
                }) ||
        !mutate("matching wrong positive address",
                [](auto& value) {
                    value.old_generation.topology.positive_ip = "10.253.240.3";
                    value.new_generation.topology.positive_ip = "10.253.240.3";
                }) ||
        !mutate("matching malformed guard IP",
                [](auto& value) {
                    value.old_generation.topology.guard_ip = "not-an-ip";
                    value.new_generation.topology.guard_ip = "not-an-ip";
                }) ||
        !mutate("matching noncanonical guard IP",
                [](auto& value) {
                    value.old_generation.topology.guard_ip = "10.253.241.002";
                    value.new_generation.topology.guard_ip = "10.253.241.002";
                }) ||
        !mutate("matching wrong guard address", [](auto& value) {
            value.old_generation.topology.guard_ip = "10.253.241.3";
            value.new_generation.topology.guard_ip = "10.253.241.3";
        }))
        return false;

    // Every retained topology/IPAM/probe field participates in the comparison.
    if (!mutate("token", [](auto& value) { value.new_generation.topology.token[0] = '2'; }) ||
        !mutate("network A name",
                [](auto& value) { value.new_generation.topology.network_a_name += "-changed"; }) ||
        !mutate("network A ID",
                [](auto& value) {
                    value.new_generation.topology.network_a_id = std::string(64, '5');
                }) ||
        !mutate("network A subnet",
                [](auto& value) {
                    value.new_generation.topology.network_a_subnet = "10.253.242.0/28";
                }) ||
        !mutate("network A gateway",
                [](auto& value) {
                    value.new_generation.topology.network_a_gateway = "10.253.240.2";
                }) ||
        !mutate("network B name",
                [](auto& value) { value.new_generation.topology.network_b_name += "-changed"; }) ||
        !mutate("network B ID",
                [](auto& value) {
                    value.new_generation.topology.network_b_id = std::string(64, '6');
                }) ||
        !mutate("network B subnet",
                [](auto& value) {
                    value.new_generation.topology.network_b_subnet = "10.253.243.0/28";
                }) ||
        !mutate("network B gateway",
                [](auto& value) {
                    value.new_generation.topology.network_b_gateway = "10.253.241.2";
                }) ||
        !mutate("holder name",
                [](auto& value) { value.new_generation.topology.holder_name += "-changed"; }) ||
        !mutate("positive IP",
                [](auto& value) { value.new_generation.topology.positive_ip = "10.253.240.3"; }) ||
        !mutate("guard IP",
                [](auto& value) { value.new_generation.topology.guard_ip = "10.253.241.3"; }) ||
        !mutate("probe policy",
                [](auto& value) {
                    value.new_generation.topology.probe_evidence.policy =
                        HeldTopologyProbePolicy::RequireHostRefusalProbes;
                }) ||
        !mutate("probe absence count",
                [](auto& value) {
                    ++value.new_generation.topology.probe_evidence.selected_port_absence_checks;
                }) ||
        !mutate("probe socket count",
                [](auto& value) {
                    ++value.new_generation.topology.probe_evidence.host_parent_af_inet_socket_calls;
                }) ||
        !mutate("probe refusal count", [](auto& value) {
            ++value.new_generation.topology.probe_evidence.successful_refusal_probes;
        }))
        return false;

    // Generation identity changes are required, while PID reuse with a new
    // start time is already exercised by the valid seed above.
    if (!mutate("holder container ID reuse",
                [](auto& value) {
                    value.new_generation.topology.holder_id =
                        value.old_generation.topology.holder_id;
                    value.new_generation.sidecar.network_mode =
                        "container:" + value.new_generation.topology.holder_id;
                }) ||
        !mutate("holder process identity reuse",
                [](auto& value) {
                    value.new_generation.topology.holder_start =
                        value.old_generation.topology.holder_start;
                }) ||
        !mutate("sidecar container ID reuse",
                [](auto& value) {
                    value.new_generation.sidecar.id = value.old_generation.sidecar.id;
                }) ||
        !mutate("new holder/old sidecar cross-role ID collision",
                [](auto& value) {
                    value.new_generation.topology.holder_id = value.old_generation.sidecar.id;
                    value.new_generation.sidecar.network_mode =
                        "container:" + value.new_generation.topology.holder_id;
                }) ||
        !mutate("new sidecar/old holder cross-role ID collision",
                [](auto& value) {
                    value.new_generation.sidecar.id = value.old_generation.topology.holder_id;
                }) ||
        !mutate("sidecar process identity reuse",
                [](auto& value) {
                    value.new_generation.sidecar.start = value.old_generation.sidecar.start;
                }) ||
        !mutate("new holder zero start",
                [](auto& value) { value.new_generation.topology.holder_start = 0; }) ||
        !mutate("new holder zero netns",
                [](auto& value) { value.new_generation.topology.holder_netns = 0; }) ||
        !mutate("sidecar token",
                [](auto& value) { value.new_generation.sidecar.token = "wrong"; }) ||
        !mutate("sidecar stage",
                [](auto& value) { value.new_generation.sidecar.stage = "wrong"; }) ||
        !mutate("sidecar role", [](auto& value) { value.new_generation.sidecar.role = "wrong"; }) ||
        !mutate("sidecar name", [](auto& value) { value.new_generation.sidecar.name = "wrong"; }) ||
        !mutate("sidecar image reference",
                [](auto& value) {
                    value.new_generation.sidecar.pinned_image_reference = "nginx:latest";
                }) ||
        !mutate("sidecar expected image",
                [](auto& value) {
                    value.new_generation.sidecar.expected_image_id =
                        "sha256:" + std::string(64, '7');
                }) ||
        !mutate("sidecar image",
                [](auto& value) {
                    value.new_generation.sidecar.image_id = "sha256:" + std::string(64, '8');
                }) ||
        !mutate("sidecar network mode",
                [](auto& value) { value.new_generation.sidecar.network_mode = "bridge"; }) ||
        !mutate("sidecar path",
                [](auto& value) { value.new_generation.sidecar.path = "/bin/sh"; }) ||
        !mutate("sidecar arguments",
                [](auto& value) { value.new_generation.sidecar.arguments_json = "[\"1\"]"; }) ||
        !mutate("sidecar netns", [](auto& value) { ++value.new_generation.sidecar.netns; }) ||
        !mutate("sidecar host netns",
                [](auto& value) { ++value.new_generation.sidecar.host_netns; }) ||
        !mutate("sidecar running",
                [](auto& value) { value.new_generation.sidecar.running = false; }) ||
        !mutate("sidecar read-only root",
                [](auto& value) { value.new_generation.sidecar.read_only_root = false; }) ||
        !mutate("sidecar cap-drop",
                [](auto& value) { value.new_generation.sidecar.capability_drop_all = false; }) ||
        !mutate("sidecar no-new-privileges",
                [](auto& value) { value.new_generation.sidecar.no_new_privileges = false; }) ||
        !mutate("sidecar published ports",
                [](auto& value) { value.new_generation.sidecar.no_published_ports = false; }))
        return false;

    // Exact old witness fields and stable names are bound to the old generation.
    // The valid seed separately demonstrates that a netns inode may be reused.
    if (!mutate(
            "holder absence ID",
            [](auto& value) { value.old_absence.holder.container_id = std::string(64, '9'); }) ||
        !mutate("holder absence PID", [](auto& value) { ++value.old_absence.holder.pid; }) ||
        !mutate("holder absence start", [](auto& value) { ++value.old_absence.holder.start; }) ||
        !mutate("holder ID absence missing",
                [](auto& value) { value.old_absence.holder.container_id_absent = false; }) ||
        !mutate("holder process absence missing",
                [](auto& value) { value.old_absence.holder.process_identity_absent = false; }) ||
        !mutate(
            "sidecar absence ID",
            [](auto& value) { value.old_absence.sidecar.container_id = std::string(64, '9'); }) ||
        !mutate("sidecar absence PID", [](auto& value) { ++value.old_absence.sidecar.pid; }) ||
        !mutate("sidecar absence start", [](auto& value) { ++value.old_absence.sidecar.start; }) ||
        !mutate("sidecar ID absence missing",
                [](auto& value) { value.old_absence.sidecar.container_id_absent = false; }) ||
        !mutate("sidecar process absence missing",
                [](auto& value) { value.old_absence.sidecar.process_identity_absent = false; }) ||
        !mutate("wrong holder absence name",
                [](auto& value) { value.old_absence.holder_name += "-wrong"; }) ||
        !mutate("missing holder name absence",
                [](auto& value) { value.old_absence.holder_name_absent = false; }) ||
        !mutate("wrong sidecar absence name",
                [](auto& value) { value.old_absence.sidecar_name += "-wrong"; }) ||
        !mutate("missing sidecar name absence",
                [](auto& value) { value.old_absence.sidecar_name_absent = false; }))
        return false;

    if (!mutate("missing old validation phase",
                [](auto& value) {
                    value.old_generation_phase = HeldNamespaceGenerationRotationPhase::None;
                }) ||
        !mutate("duplicate old absence phase",
                [](auto& value) {
                    value.old_absence.phase =
                        HeldNamespaceGenerationRotationPhase::OldGenerationValidated;
                }) ||
        !mutate("absence phase after new generation creation",
                [](auto& value) {
                    value.old_absence.phase =
                        HeldNamespaceGenerationRotationPhase::NewGenerationCreated;
                }) ||
        !mutate("new generation creation phase skipped",
                [](auto& value) {
                    value.new_generation_created_phase =
                        HeldNamespaceGenerationRotationPhase::NewGenerationValidated;
                }) ||
        !mutate("new validation phase regressed", [](auto& value) {
            value.new_generation_validated_phase =
                HeldNamespaceGenerationRotationPhase::OldGenerationAbsent;
        }))
        return false;

    HeldNamespaceGenerationRotationReceipt deterministic_failure = seed;
    deterministic_failure.old_absence.holder.process_identity_absent = false;
    first_error.clear();
    second_error.clear();
    if (validate_held_namespace_generation_rotation_receipt(deterministic_failure, first_error) ||
        validate_held_namespace_generation_rotation_receipt(deterministic_failure, second_error) ||
        first_error.empty() || first_error != second_error) {
        error = "held-namespace generation rotation validation was not deterministic";
        return false;
    }
    return true;
}

bool audit_zero_residue(const std::string& token,
                        const std::string& network_a_name,
                        const std::string& network_b_name,
                        const std::string& holder_name,
                        std::string& error) {
    CommandResult result;
    for (const std::string& name : {network_a_name, network_b_name, holder_name}) {
        if (run_command({"docker", "inspect", name}, result) && exited_zero(result)) {
            error =
                "exact expected resource name remains (including possible ownership collision): " +
                name;
            return false;
        }
    }
    if (!run_command({"docker", "ps", "-aq", "--filter", "label=rut.token=" + token}, result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "labeled container residue remains";
        return false;
    }
    if (!run_command({"docker", "network", "ls", "-q", "--filter", "label=rut.token=" + token},
                     result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "labeled network residue remains";
        return false;
    }
    return true;
}

bool pure_validation_self_checks(std::string& error) {
    if (!pure_holder_retirement_self_checks(error)) return false;
    if (!recreated_sidecar_transition_self_checks(error)) return false;
    if (!generation_receipt_composition_self_checks(error)) return false;
    if (!held_namespace_generation_rotation_self_checks(error)) return false;
    u32 low = 0, high = 0;
    if (parse_cidr("10.0.0.1/24", low, high) || parse_cidr("10.0.0.0/31", low, high) ||
        parse_cidr("10.0.0.0/nope", low, high) || parse_cidr("10.0.0.0/", low, high)) {
        error = "malformed/prefix-edge CIDR validation was accepted";
        return false;
    }
    if (valid_gateway("10.0.0.0/24", "10.0.1.1") || valid_gateway("10.0.0.0/24", "10.0.0.0") ||
        valid_gateway("10.0.0.0/24", "10.0.0.255") || valid_gateway("127.0.0.0/24", "127.0.0.1")) {
        error = "invalid/out-of-subnet/network/broadcast/loopback gateway was accepted";
        return false;
    }
    if (!valid_gateway("10.0.0.0/24", "10.0.0.1")) {
        error = "valid gateway was rejected";
        return false;
    }
    const auto& candidates = subnet_candidates();
    if (candidates.size() != 5 || !valid_subnet_plan(candidates[0]) ||
        !valid_subnet_plan(candidates[1]) || !valid_subnet_plan(candidates[2]) ||
        !valid_subnet_plan(candidates[3]) || !valid_subnet_plan(candidates[4]) ||
        candidates[0].network_a.subnet != "10.253.240.0/28" ||
        candidates[0].network_b.subnet != "10.253.241.0/28" ||
        candidates[4].network_a.subnet != "192.168.250.0/28" ||
        candidates[4].network_b.subnet != "192.168.251.0/28") {
        error = "fixed ordered RFC1918 /28 candidate pairs were not exact";
        return false;
    }
    for (const NetworkPlan& invalid : {NetworkPlan{"10.253.240/28", "10.253.240.1"},
                                       NetworkPlan{"10.253.240.1/28", "10.253.240.1"},
                                       NetworkPlan{"10.253.240.0/031", "10.253.240.1"},
                                       NetworkPlan{"10.253.240.0/31", "10.253.240.1"},
                                       NetworkPlan{"192.0.2.0/28", "192.0.2.1"},
                                       NetworkPlan{"169.254.1.0/28", "169.254.1.1"},
                                       NetworkPlan{"10.253.240.0/28", "10.253.240.0"},
                                       NetworkPlan{"10.253.240.0/28", "10.253.240.15"},
                                       NetworkPlan{"10.253.240.0/28", "10.253.240.2"},
                                       NetworkPlan{"10.253.240.0/28", "10.253.241.1"}}) {
        if (valid_network_plan(invalid)) {
            error = "malformed/noncanonical/reserved/prefix/gateway-edge plan was accepted";
            return false;
        }
    }
    SubnetPlan overlapping_pair = candidates[0];
    overlapping_pair.network_b = overlapping_pair.network_a;
    if (valid_subnet_plan(overlapping_pair)) {
        error = "overlapping topology subnet pair was accepted";
        return false;
    }
    IPv4Range default_route;
    IPv4Range route_conflict;
    IPv4Range docker_conflict;
    if (!parse_cidr_range("0.0.0.0/0", true, default_route) ||
        !parse_cidr_range("10.253.240.8/29", true, route_conflict) ||
        !parse_cidr_range("10.254.241.0/28", true, docker_conflict)) {
        error = "pure selection conflict fixtures were malformed";
        return false;
    }
    SubnetPlan selected_plan;
    if (!select_subnet_plan({default_route}, candidates, selected_plan) ||
        !subnet_plan_equal(selected_plan, candidates[0])) {
        error = "only the default IPv4 route was not ignored for collision selection";
        return false;
    }
    if (!select_subnet_plan({route_conflict}, candidates, selected_plan) ||
        !subnet_plan_equal(selected_plan, candidates[1])) {
        error = "host route overlap did not deterministically reject the first pair";
        return false;
    }
    if (!select_subnet_plan({route_conflict, docker_conflict}, candidates, selected_plan) ||
        !subnet_plan_equal(selected_plan, candidates[2])) {
        error = "route/Docker cross-pair overlap allowed mixed or nondeterministic selection";
        return false;
    }
    SubnetPlan cross_swapped = candidates[2];
    std::swap(cross_swapped.network_a, cross_swapped.network_b);
    if (subnet_plan_equal(cross_swapped, candidates[2])) {
        error = "cross-swapped subnet selection mutation was accepted";
        return false;
    }
    std::vector<IPv4Range> exhaust_candidates;
    for (const SubnetPlan& candidate : candidates) {
        IPv4Range candidate_a;
        if (!valid_network_plan(candidate.network_a, &candidate_a)) {
            error = "candidate exhaustion fixture was invalid";
            return false;
        }
        exhaust_candidates.push_back(candidate_a);
    }
    if (select_subnet_plan(exhaust_candidates, candidates, selected_plan)) {
        error = "exhausted candidate pairs unexpectedly selected a subnet plan";
        return false;
    }
    std::vector<IPv4Range> parsed_observations;
    std::string parse_error;
    if (!parse_host_routes("default via 192.168.1.1 dev eth0\n"
                           "10.253.240.8/29 dev test0 scope link\n",
                           parsed_observations,
                           parse_error) ||
        parsed_observations.size() != 2 || parsed_observations[0].prefix != 0 ||
        parsed_observations[1].low != route_conflict.low ||
        parse_host_routes("10.253.240.1/28 dev test0\n", parsed_observations, parse_error)) {
        error = "host route parsing/default/noncanonical causal checks failed";
        return false;
    }
    parsed_observations.clear();
    parse_error.clear();
    if (!parse_interface_cidrs(
            "2: eth0 inet 10.253.240.9/28 scope global eth0\n", parsed_observations, parse_error) ||
        parsed_observations.size() != 1 || parsed_observations[0].low != 0x0afdf000u ||
        parse_interface_cidrs("2: eth0 inet 10.253.240.009/28 scope global eth0\n",
                              parsed_observations,
                              parse_error)) {
        error = "host interface CIDR/noncanonical causal checks failed";
        return false;
    }
    parsed_observations.clear();
    parse_error.clear();
    if (!parse_interface_cidrs(
            "4: point0 inet 10.100.15.6 peer 10.100.15.5/32 scope global point0\n",
            parsed_observations,
            parse_error) ||
        parsed_observations.size() != 2 || parsed_observations[0].prefix != 32 ||
        parsed_observations[1].prefix != 32) {
        error = "point-to-point host interface/peer CIDRs were not both collected";
        return false;
    }
    const NetworkPlan argv_plan = candidates[0].network_a;
    const std::string argv_token = "0123456789abcdef";
    const std::string argv_name = "rut358-a-test";
    const std::vector<std::string> exact_argv =
        network_create_argv(argv_plan, argv_token, argv_name);
    if (!exact_network_create_argv(exact_argv, argv_plan, argv_token, argv_name)) {
        error = "exact subnet/gateway network-create argv was rejected";
        return false;
    }
    std::vector<std::string> removed_argv = exact_argv;
    removed_argv.erase(removed_argv.begin() + 5, removed_argv.begin() + 7);
    std::vector<std::string> swapped_argv = exact_argv;
    std::swap(swapped_argv[6], swapped_argv[8]);
    std::vector<std::string> changed_argv = exact_argv;
    changed_argv[6] = "10.253.242.0/28";
    std::vector<std::string> duplicated_argv = exact_argv;
    duplicated_argv.insert(duplicated_argv.begin() + 7, {"--subnet", argv_plan.subnet});
    if (exact_network_create_argv(removed_argv, argv_plan, argv_token, argv_name) ||
        exact_network_create_argv(swapped_argv, argv_plan, argv_token, argv_name) ||
        exact_network_create_argv(changed_argv, argv_plan, argv_token, argv_name) ||
        exact_network_create_argv(duplicated_argv, argv_plan, argv_token, argv_name)) {
        error = "network-create subnet/gateway removal/swap/value/count mutation was accepted";
        return false;
    }
    std::string selected;
    if (!choose_address("192.0.2.0/30", "192.0.2.1", selected) || selected != "192.0.2.2" ||
        !choose_address("192.0.2.0/30", "192.0.2.2", selected) || selected != "192.0.2.1") {
        error = "usable /30 address selection did not consider low+1 and the higher usable address";
        return false;
    }
    if (no_published_ports("{\"80/tcp\":[]}", "null") ||
        no_published_ports("{}", "{\"80/tcp\":[{\"HostPort\":\"80\"}]}") ||
        no_published_ports("{}", "{\"80/tcp\":\"malformed:null\"}") ||
        no_published_ports("{}", "{\"80/tcp\":null") ||
        !no_published_ports("{}", "{\"80/tcp\":null}")) {
        error = "published-port mutation validation was not causal";
        return false;
    }
    std::vector<std::string> raw_sidecar_fields{
        std::string(64, 'b'),
        "/rut358-sidecar-0123456789abcdef",
        RUT_PINNED_NGINX_IMAGE,
        "sha256:" + std::string(64, 'c'),
        kSidecarStage,
        "0123456789abcdef",
        kSidecarRole,
        "container:" + std::string(64, 'a'),
        "true",
        "101",
        "/bin/sleep",
        "[\"infinity\"]",
        "true",
        "{}",
        "null",
        "[\"ALL\"]",
        "[\"no-new-privileges\"]",
    };
    const auto raw_record = [](const std::vector<std::string>& fields) {
        std::string record;
        for (size_t index = 0; index < fields.size(); ++index) {
            if (index != 0) record += '|';
            record += fields[index];
        }
        return record;
    };
    HeldNamespaceSidecarSnapshot parsed_raw;
    std::string raw_error;
    if (!parse_sidecar_inspect_record(raw_record(raw_sidecar_fields), parsed_raw, raw_error)) {
        error = "valid exact 17-field sidecar inspect record was rejected: " + raw_error;
        return false;
    }
    const std::array<std::string, 17> raw_mutations{
        std::string(64, 'd'),
        "/wrong",
        "nginx:latest",
        "sha256:" + std::string(64, 'd'),
        "wrong-stage",
        "wrong-token",
        "wrong-role",
        "bridge",
        "false",
        "102",
        "/bin/sh",
        "[\"wrong\"]",
        "false",
        "{\"80/tcp\":[{\"HostPort\":\"80\"}]}",
        "{\"80/tcp\":[{\"HostPort\":\"80\"}]}",
        "[]",
        "[]",
    };
    for (size_t index = 0; index < raw_sidecar_fields.size(); ++index) {
        std::vector<std::string> changed_fields = raw_sidecar_fields;
        changed_fields[index] = raw_mutations[index];
        HeldNamespaceSidecarSnapshot changed;
        raw_error.clear();
        if (!parse_sidecar_inspect_record(raw_record(changed_fields), changed, raw_error) ||
            sidecar_snapshot_equal(parsed_raw, changed)) {
            error =
                "raw sidecar inspect field mutation was hidden at field " + std::to_string(index);
            return false;
        }
    }
    std::vector<std::pair<std::string, std::vector<std::string>>> malformed_records;
    std::vector<std::string> short_record = raw_sidecar_fields;
    short_record.pop_back();
    malformed_records.emplace_back("short record", std::move(short_record));
    const auto add_malformed =
        [&](const std::string& name, size_t index, const std::string& replacement) {
            std::vector<std::string> malformed = raw_sidecar_fields;
            malformed[index] = replacement;
            malformed_records.emplace_back(name, std::move(malformed));
        };
    add_malformed("PID long overflow", 9, std::to_string(std::numeric_limits<long>::max()) + "0");
    add_malformed(
        "PID pid_t max plus one",
        9,
        std::to_string(static_cast<unsigned long long>(std::numeric_limits<pid_t>::max()) + 1ULL));
    add_malformed("negative PID", 9, "-1");
    add_malformed("signed positive PID", 9, "+101");
    add_malformed("leading-space PID", 9, " 101");
    add_malformed("PID trailing bytes", 9, "101x");
    add_malformed("empty PID", 9, "");
    add_malformed("non-numeric PID", 9, "not-a-pid");
    add_malformed("running boolean", 8, "maybe");
    add_malformed("read-only boolean", 12, "maybe");
    add_malformed("unterminated arguments", 11, "[\"unterminated");
    add_malformed("unterminated object", 13, "{");
    add_malformed("unterminated array", 14, "[");
    add_malformed("unterminated capability array", 15, "[\"ALL\"");
    add_malformed("bare token", 16, "not-json");
    add_malformed("crossed delimiters", 14, "[{\"80/tcp\":null]}");
    add_malformed("trailing comma", 11, "[\"infinity\",]");
    add_malformed("trailing junk", 11, "[\"infinity\"]junk");
    add_malformed("invalid escape", 11, "[\"\\q\"]");
    add_malformed("incomplete unicode escape", 11, "[\"\\u12\"]");
    std::string unescaped_control = "[\"bad";
    unescaped_control.push_back('\x01');
    unescaped_control += "\"]";
    add_malformed("unescaped control byte", 11, unescaped_control);
    add_malformed("malformed null", 14, "{\"80/tcp\":nul}");
    std::string excessive_nesting(34, '[');
    excessive_nesting += "null";
    excessive_nesting.append(34, ']');
    add_malformed("excessive nesting", 14, excessive_nesting);
    add_malformed("oversized JSON", 11, "[\"" + std::string(16385, 'x') + "\"]");
    add_malformed("wrong arguments type", 11, "{\"infinity\":true}");
    add_malformed("wrong port map type", 14, "[null]");
    add_malformed("wrong capability type", 15, "\"ALL\"");
    for (const auto& malformed : malformed_records) {
        HeldNamespaceSidecarSnapshot ignored;
        raw_error.clear();
        if (parse_sidecar_inspect_record(raw_record(malformed.second), ignored, raw_error) ||
            raw_error.empty()) {
            error = "malformed sidecar inspect record was accepted: " + malformed.first;
            return false;
        }
    }
    HeldTopologySnapshot topology;
    topology.token = "0123456789abcdef";
    topology.holder_id = std::string(64, 'a');
    topology.holder_pid = 100;
    topology.holder_start = 1000;
    topology.holder_netns = 2000;
    HeldNamespaceSidecarSnapshot sidecar;
    sidecar.token = topology.token;
    sidecar.stage = kSidecarStage;
    sidecar.role = kSidecarRole;
    sidecar.name = "rut358-sidecar-" + topology.token;
    sidecar.id = std::string(64, 'b');
    sidecar.pinned_image_reference = RUT_PINNED_NGINX_IMAGE;
    sidecar.expected_image_id = "sha256:" + std::string(64, 'c');
    sidecar.image_id = "sha256:" + std::string(64, 'c');
    sidecar.network_mode = "container:" + topology.holder_id;
    sidecar.path = "/bin/sleep";
    sidecar.arguments_json = "[\"infinity\"]";
    sidecar.pid = 101;
    sidecar.start = 1001;
    sidecar.netns = topology.holder_netns;
    sidecar.host_netns = 2001;
    sidecar.running = true;
    sidecar.read_only_root = true;
    sidecar.capability_drop_all = true;
    sidecar.no_new_privileges = true;
    sidecar.no_published_ports = true;
    std::string sidecar_error;
    if (!validate_held_namespace_sidecar_snapshot(topology, sidecar, sidecar_error)) {
        error = "valid pure sidecar identity/security evidence was rejected: " + sidecar_error;
        return false;
    }
    std::vector<HeldNamespaceSidecarSnapshot> sidecar_mutations;
    const auto mutate = [&](const std::function<void(HeldNamespaceSidecarSnapshot&)>& change) {
        HeldNamespaceSidecarSnapshot changed = sidecar;
        change(changed);
        sidecar_mutations.push_back(std::move(changed));
    };
    mutate([](auto& value) { value.token = "wrong"; });
    mutate([](auto& value) { value.stage = "wrong"; });
    mutate([](auto& value) { value.role = "wrong"; });
    mutate([](auto& value) { value.name = "wrong"; });
    mutate([](auto& value) { value.id = std::string(63, 'b'); });
    mutate([](auto& value) { value.pinned_image_reference = "nginx:latest"; });
    mutate([](auto& value) { value.expected_image_id = "sha256:" + std::string(64, 'd'); });
    mutate([](auto& value) { value.image_id = "sha256:" + std::string(64, 'g'); });
    mutate([](auto& value) { value.network_mode = "bridge"; });
    mutate([](auto& value) { value.path = "/bin/sh"; });
    mutate([](auto& value) { value.arguments_json = "[\"1\"]"; });
    mutate([&](auto& value) { value.pid = topology.holder_pid; });
    mutate([](auto& value) { value.start = 0; });
    mutate([](auto& value) { value.netns = 2002; });
    mutate([](auto& value) { value.host_netns = 0; });
    mutate([](auto& value) { value.running = false; });
    mutate([](auto& value) { value.read_only_root = false; });
    mutate([](auto& value) { value.capability_drop_all = false; });
    mutate([](auto& value) { value.no_new_privileges = false; });
    mutate([](auto& value) { value.no_published_ports = false; });
    for (const HeldNamespaceSidecarSnapshot& mutation : sidecar_mutations) {
        sidecar_error.clear();
        if (sidecar_snapshot_equal(sidecar, mutation) ||
            validate_held_namespace_sidecar_snapshot(topology, mutation, sidecar_error)) {
            error = "invalid/mutated pure sidecar identity/security evidence was accepted";
            return false;
        }
    }
    for (const auto& change :
         {std::function<void(HeldNamespaceSidecarSnapshot&)>(
              [](auto& value) { value.id = std::string(64, 'd'); }),
          std::function<void(HeldNamespaceSidecarSnapshot&)>([](auto& value) { value.pid += 1; }),
          std::function<void(HeldNamespaceSidecarSnapshot&)>(
              [](auto& value) { value.start += 1; })}) {
        HeldNamespaceSidecarSnapshot changed = sidecar;
        change(changed);
        sidecar_error.clear();
        if (!validate_held_namespace_sidecar_snapshot(topology, changed, sidecar_error) ||
            sidecar_snapshot_equal(sidecar, changed)) {
            error = "exact sidecar identity comparator did not distinguish valid-shaped mutation";
            return false;
        }
    }
    const Endpoint a{"a", "id-a", "10.0.0.2", "10.0.0.2/24", "10.0.0.1"};
    const Endpoint b{"b", "id-b", "10.0.1.2", "10.0.1.2/24", "10.0.1.1"};
    std::vector<Endpoint> expected{a, b};
    std::vector<Endpoint> swapped{b, a};
    std::swap(swapped[0].network_id, swapped[1].network_id);
    if (endpoint_set_equal(expected, swapped)) {
        error = "cross-swapped endpoint validation mutation was accepted";
        return false;
    }
    return true;
}

bool runner_descendant_self_check(std::string& error) {
    CommandResult result;
    DescendantProbe probe;
    if (!run_command({"/bin/true"}, result, 15000, false, true, &probe) ||
        !result.process_group_verified || !probe.marker_received || !probe.same_pgid ||
        !probe.alive_before_cleanup || probe.pid <= 0 || probe.pgid <= 0 ||
        !process_group_gone(probe.pgid) || kill(probe.pid, 0) == 0) {
        error = "runner descendant marker/PID/PGID handshake or cleanup proof failed";
        return false;
    }
    return true;
}

bool validate_held_topology_probe_evidence(const HeldTopologyProbeEvidence& evidence,
                                           HeldTopologyProbePolicy expected_policy,
                                           std::string& error) {
    if (expected_policy != HeldTopologyProbePolicy::RequireHostRefusalProbes &&
        expected_policy != HeldTopologyProbePolicy::SocketlessHostParent) {
        error = "unknown held-topology probe policy";
        return false;
    }
    if (evidence.policy != expected_policy || evidence.selected_port_absence_checks != 1u) {
        error = "held-topology probe policy or read-only absence evidence was not exact";
        return false;
    }
    if (expected_policy == HeldTopologyProbePolicy::RequireHostRefusalProbes) {
        if (evidence.host_parent_af_inet_socket_calls != 2u ||
            evidence.successful_refusal_probes != 2u) {
            error = "held-topology host refusal-probe evidence was not exact";
            return false;
        }
        return true;
    }
    if (evidence.host_parent_af_inet_socket_calls != 0u ||
        evidence.successful_refusal_probes != 0u) {
        error = "socketless held-topology policy reported a host AF_INET probe";
        return false;
    }
    return true;
}

RunResult run(FailurePoint failure_point) {
    RunResult result;
    std::string token;
    if (!high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = "high-entropy token generation unavailable";
        result.success = false;
        return result;
    }
    Fixture fixture(token);
    const auto audit = [&](std::string& error) {
        return audit_zero_residue(token,
                                  fixture.network_a().name,
                                  fixture.network_b().name,
                                  fixture.holder_name(),
                                  error);
    };
    TempDir temp;
    if (!temp.create() || !write_manifest(temp, fixture)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = "parent-owned temporary manifest creation failed";
        return result;
    }
    if (!preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe =
            result.error.find("exact target name already exists") == std::string::npos;
        result.success = false;
        return result;
    }
    if (!fixture.create_networks(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterNetworkACreated &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkAVerified &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkBCreated &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkBVerified &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkACreationReportedTimeout &&
         result.error.find("injected actual-success/reported-timeout") != std::string::npos) ||
        (failure_point == FailurePoint::AfterBothIpamVerified &&
         result.error == "injected boundary failure")) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    if (!fixture.create_holder(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterHolderCreated &&
         result.error == "injected boundary failure")) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    if (!fixture.attach_holder(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterHolderAttachedA &&
         result.error.find("injected") != std::string::npos) ||
        (failure_point == FailurePoint::AfterHolderAttachedB &&
         result.error.find("injected") != std::string::npos)) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    if (!fixture.verify_topology(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterTopologyVerified &&
         result.error.find("injected") != std::string::npos)) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    static constexpr u16 kProbePort = 41857;
    if (!fixture.probe_port_absent(kProbePort, result.error) ||
        !fixture.probe_refused(fixture.positive_ip(), kProbePort, result.error)) {
        fixture.cleanup(result.error);
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = false;
        return result;
    }
    if (failure_point == FailurePoint::AfterFirstProbe) {
        result.error = "injected boundary failure";
        if (!fixture.cleanup(result.error)) {
            result.success = false;
            return result;
        }
        std::string residue_error;
        if (!audit(residue_error)) {
            result.error += "; " + residue_error;
            result.success = false;
            return result;
        }
        result.success = true;
        return result;
    }
    if (!fixture.probe_refused(fixture.guard_ip(), kProbePort, result.error)) {
        fixture.cleanup(result.error);
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = false;
        return result;
    }
    if (!fixture.cleanup(result.error)) {
        result.success = false;
        return result;
    }
    std::string residue_error;
    if (!audit(residue_error)) {
        result.error = residue_error;
        result.success = false;
        return result;
    }
    result.success = true;
    return result;
}

RunResult run_with_held_topology(const HeldTopologyCallback& callback) {
    return run_with_held_topology(HeldTopologyProbePolicy::RequireHostRefusalProbes, callback);
}

RunResult run_with_held_topology(HeldTopologyProbePolicy policy,
                                 const HeldTopologyCallback& callback) {
    RunResult result;
    std::string token;
    if (!callback || !high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = callback ? "high-entropy token generation unavailable"
                                : "held-topology callback was empty";
        return result;
    }
    Fixture fixture(token);
    const auto audit = [&](std::string& error) {
        return audit_zero_residue(token,
                                  fixture.network_a().name,
                                  fixture.network_b().name,
                                  fixture.holder_name(),
                                  error);
    };
    TempDir temp;
    if (!temp.create() || !write_manifest(temp, fixture) || !preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe =
            result.error.find("exact target name already exists") == std::string::npos;
        if (result.error.empty()) result.error = "held-topology preflight failed";
        return result;
    }
    const auto fail_after_cleanup = [&] {
        std::string cleanup_error;
        if (!fixture.cleanup(cleanup_error)) {
            if (!result.error.empty()) result.error += "; ";
            result.error += cleanup_error;
        }
        std::string residue_error;
        if (!audit(residue_error)) {
            if (!result.error.empty()) result.error += "; ";
            result.error += residue_error;
        }
        result.success = false;
        return result;
    };
    if (!fixture.create_networks(FailurePoint::None, result.error) ||
        !fixture.create_holder(FailurePoint::None, result.error) ||
        !fixture.attach_holder(FailurePoint::None, result.error) ||
        !fixture.verify_topology(FailurePoint::None, result.error))
        return fail_after_cleanup();

    static constexpr u16 kProbePort = 41857;
    HeldTopologyProbeEvidence probe_evidence;
    probe_evidence.policy = policy;
    if (!fixture.probe_port_absent(kProbePort, result.error)) return fail_after_cleanup();
    ++probe_evidence.selected_port_absence_checks;
    if (policy == HeldTopologyProbePolicy::RequireHostRefusalProbes) {
        const auto probe_refused = [&](const std::string& address) {
            ++probe_evidence.host_parent_af_inet_socket_calls;
            if (!fixture.probe_refused(address, kProbePort, result.error)) return false;
            ++probe_evidence.successful_refusal_probes;
            return true;
        };
        if (!probe_refused(fixture.positive_ip()) || !probe_refused(fixture.guard_ip()))
            return fail_after_cleanup();
    }
    std::string probe_evidence_error;
    if (!validate_held_topology_probe_evidence(probe_evidence, policy, probe_evidence_error)) {
        result.error = probe_evidence_error;
        return fail_after_cleanup();
    }

    ProcIdentity holder_identity{};
    if (!proc_identity(fixture.holder_pid(), holder_identity, false) ||
        !container_netns_inode(fixture.holder_name(), holder_identity.netns) ||
        holder_identity.start != fixture.holder_start()) {
        result.error = "held topology lost exact holder process identity";
        return fail_after_cleanup();
    }
    HeldTopologySnapshot snapshot;
    snapshot.token = fixture.token();
    snapshot.network_a_name = fixture.network_a().name;
    snapshot.network_a_id = fixture.network_a().id;
    snapshot.network_a_subnet = fixture.network_a().subnet;
    snapshot.network_a_gateway = fixture.network_a().gateway;
    snapshot.network_b_name = fixture.network_b().name;
    snapshot.network_b_id = fixture.network_b().id;
    snapshot.network_b_subnet = fixture.network_b().subnet;
    snapshot.network_b_gateway = fixture.network_b().gateway;
    snapshot.holder_name = fixture.holder_name();
    snapshot.holder_id = fixture.holder_id();
    snapshot.positive_ip = fixture.positive_ip();
    snapshot.guard_ip = fixture.guard_ip();
    snapshot.holder_pid = fixture.holder_pid();
    snapshot.holder_start = fixture.holder_start();
    snapshot.holder_netns = holder_identity.netns;
    snapshot.probe_evidence = probe_evidence;
    if (!callback(snapshot, result.error)) return fail_after_cleanup();
    if (!fixture.cleanup(result.error)) return fail_after_cleanup();
    std::string residue_error;
    if (!audit(residue_error)) {
        result.error = residue_error;
        return result;
    }
    result.success = true;
    return result;
}

RunResult run_with_held_topology_and_sidecar(
    const HeldTopologyAndSidecarCallback& callback,
    HeldNamespaceSidecarFailurePoint failure_point,
    HeldNamespaceSidecarRevalidationFault revalidation_fault,
    HeldNamespaceHolderRemovalFailurePoint holder_removal_failure_point) {
    return run_with_held_topology_and_sidecar(HeldTopologyProbePolicy::RequireHostRefusalProbes,
                                              callback,
                                              failure_point,
                                              revalidation_fault,
                                              holder_removal_failure_point);
}

RunResult run_with_held_topology_and_sidecar(
    HeldTopologyProbePolicy policy,
    const HeldTopologyAndSidecarCallback& callback,
    HeldNamespaceSidecarFailurePoint failure_point,
    HeldNamespaceSidecarRevalidationFault revalidation_fault,
    HeldNamespaceHolderRemovalFailurePoint holder_removal_failure_point) {
    RunResult result;
    if (holder_removal_failure_point != HeldNamespaceHolderRemovalFailurePoint::None &&
        (failure_point != HeldNamespaceSidecarFailurePoint::None ||
         revalidation_fault != HeldNamespaceSidecarRevalidationFault::None)) {
        result.error = "holder-removal seam cannot be combined with sidecar fault injection";
        return result;
    }
    std::string token;
    if (!callback || !high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = callback ? "high-entropy token generation unavailable"
                                : "held-topology sidecar callback was empty";
        return result;
    }
    Fixture fixture(token);
    const auto audit = [&](std::string& error) {
        if (!audit_zero_residue(token,
                                fixture.network_a().name,
                                fixture.network_b().name,
                                fixture.holder_name(),
                                error))
            return false;
        CommandResult inspect;
        if (!run_command({"docker", "inspect", fixture.sidecar_name()}, inspect) ||
            exited_zero(inspect)) {
            error = "exact held-namespace sidecar name remains after cleanup";
            return false;
        }
        return true;
    };
    TempDir temp;
    if (!temp.create() || !write_manifest(temp, fixture) || !preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe =
            result.error.find("exact target name already exists") == std::string::npos;
        if (result.error.empty()) result.error = "held-topology sidecar preflight failed";
        return result;
    }
    const auto finish_after_cleanup = [&](bool semantic_success) {
        std::string cleanup_error;
        const bool cleanup_ok = fixture.cleanup(cleanup_error);
        result.cleanup_complete = cleanup_ok;
        if (failure_point == HeldNamespaceSidecarFailurePoint::CleanupReportedTimeout &&
            semantic_success) {
            if (fixture.cleanup_reported_timeout_observed())
                result.semantic_receipt =
                    "verified sidecar cleanup actual-success/reported-timeout recovery";
            else
                semantic_success = false;
            if (!result.semantic_receipt.empty()) result.error = result.semantic_receipt;
        }
        if (!cleanup_ok && !cleanup_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += cleanup_error;
        }
        std::string residue_error;
        const bool residue_free = audit(residue_error);
        result.residue_free = residue_free;
        if (!residue_free) {
            if (!result.error.empty()) result.error += "; ";
            result.error += residue_error;
        }
        result.success = semantic_success && cleanup_ok && residue_free;
        return result;
    };
    if (!fixture.create_networks(FailurePoint::None, result.error) ||
        !fixture.create_holder(FailurePoint::None, result.error) ||
        !fixture.attach_holder(FailurePoint::None, result.error) ||
        !fixture.verify_topology(FailurePoint::None, result.error))
        return finish_after_cleanup(false);

    static constexpr u16 kProbePort = 41857;
    HeldTopologyProbeEvidence probe_evidence;
    probe_evidence.policy = policy;
    if (!fixture.probe_port_absent(kProbePort, result.error)) return finish_after_cleanup(false);
    ++probe_evidence.selected_port_absence_checks;
    if (policy == HeldTopologyProbePolicy::RequireHostRefusalProbes) {
        const auto probe_refused = [&](const std::string& address) {
            ++probe_evidence.host_parent_af_inet_socket_calls;
            if (!fixture.probe_refused(address, kProbePort, result.error)) return false;
            ++probe_evidence.successful_refusal_probes;
            return true;
        };
        if (!probe_refused(fixture.positive_ip()) || !probe_refused(fixture.guard_ip()))
            return finish_after_cleanup(false);
    }
    std::string probe_error;
    if (!validate_held_topology_probe_evidence(probe_evidence, policy, probe_error)) {
        result.error = probe_error;
        return finish_after_cleanup(false);
    }
    ProcIdentity holder_identity{};
    if (!proc_identity(fixture.holder_pid(), holder_identity, false) ||
        !container_netns_inode(fixture.holder_name(), holder_identity.netns) ||
        holder_identity.start != fixture.holder_start()) {
        result.error = "sidecar topology lost exact holder process identity";
        return finish_after_cleanup(false);
    }
    HeldTopologySnapshot topology;
    topology.token = fixture.token();
    topology.network_a_name = fixture.network_a().name;
    topology.network_a_id = fixture.network_a().id;
    topology.network_a_subnet = fixture.network_a().subnet;
    topology.network_a_gateway = fixture.network_a().gateway;
    topology.network_b_name = fixture.network_b().name;
    topology.network_b_id = fixture.network_b().id;
    topology.network_b_subnet = fixture.network_b().subnet;
    topology.network_b_gateway = fixture.network_b().gateway;
    topology.holder_name = fixture.holder_name();
    topology.holder_id = fixture.holder_id();
    topology.positive_ip = fixture.positive_ip();
    topology.guard_ip = fixture.guard_ip();
    topology.holder_pid = fixture.holder_pid();
    topology.holder_start = fixture.holder_start();
    topology.holder_netns = holder_identity.netns;
    topology.probe_evidence = probe_evidence;

    if (!fixture.create_sidecar(failure_point, result.error)) {
        if (failure_point == HeldNamespaceSidecarFailurePoint::CreateSuppressedNoObject) {
            if (result.error != "injected sidecar create suppression with no Docker object") {
                result.error = "no-object sidecar suppression did not stop at the causal seam";
                return finish_after_cleanup(false);
            }
            std::string cleanup_error;
            if (!fixture.cleanup(cleanup_error) || !cleanup_error.empty()) {
                result.error =
                    "no-object sidecar cleanup did not settle generically: " + cleanup_error;
                return finish_after_cleanup(false);
            }
            const HeldNamespaceOldGenerationAbsence absence = fixture.holder_retirement_absence();
            const CleanupEvidence terminal = fixture.cleanup_evidence();
            if (absence.phase != HeldNamespaceGenerationRotationPhase::None ||
                !absence.sidecar.container_id.empty() || absence.sidecar.pid != -1 ||
                absence.sidecar.start != 0u || absence.sidecar.container_id_absent ||
                absence.sidecar.process_identity_absent || !absence.sidecar_name.empty() ||
                absence.sidecar_name_absent ||
                terminal.progress != CleanupProgress::TopologySettled || terminal.sidecar_exists ||
                terminal.holder_exists || terminal.network_a_exists || terminal.network_b_exists ||
                terminal.sidecar_creation_may_have_mutated) {
                result.error =
                    "no-object generic cleanup fabricated old-sidecar rotation authority";
                return finish_after_cleanup(false);
            }
            const u64 commands_before_replay = command_invocation_count;
            std::string caller_history = "preserve-no-object-history";
            if (!fixture.cleanup(caller_history) ||
                caller_history != "preserve-no-object-history" ||
                command_invocation_count != commands_before_replay ||
                !cleanup_evidence_equal(terminal, fixture.cleanup_evidence())) {
                result.error = "no-object generic cleanup replay was not frozen/command-free";
                return finish_after_cleanup(false);
            }
            result.semantic_receipt =
                "verified no-object sidecar cleanup without rotation authority";
            result.error = result.semantic_receipt;
            return finish_after_cleanup(true);
        }
        if (failure_point ==
            HeldNamespaceSidecarFailurePoint::CreateReportedTimeoutRecoveryUnavailable) {
            if (result.error !=
                "sidecar creation reported timeout and exact recovery failed: injected "
                "sidecar recovery inspection failure") {
                result.error = "uncertain-create injection did not fail at initial recovery";
                return finish_after_cleanup(false);
            }

            const CleanupEvidence before_cleanup = fixture.cleanup_evidence();
            std::string first_cleanup_error;
            const bool first_cleanup_ok = fixture.cleanup(first_cleanup_error);
            const CleanupEvidence after_cleanup = fixture.cleanup_evidence();
            // Keep every test-failure epilogue able to perform authoritative
            // recovery; only the first cleanup is intentionally blinded.
            fixture.clear_uncertain_sidecar_inspection_fault();
            if (first_cleanup_ok ||
                first_cleanup_error.find("sidecar creation state remains unresolved") != 0 ||
                before_cleanup.progress != CleanupProgress::Active ||
                !before_cleanup.sidecar_creation_may_have_mutated ||
                after_cleanup.progress != CleanupProgress::Active || after_cleanup.sidecar_exists ||
                !after_cleanup.sidecar_creation_may_have_mutated || !after_cleanup.holder_exists ||
                !after_cleanup.network_a_exists || !after_cleanup.network_b_exists ||
                after_cleanup.sidecar_operation_ok ||
                before_cleanup.holder_exists != after_cleanup.holder_exists ||
                before_cleanup.network_a_exists != after_cleanup.network_a_exists ||
                before_cleanup.network_b_exists != after_cleanup.network_b_exists) {
                result.error =
                    "uncertain sidecar creation did not fail closed before topology mutation";
                if (!first_cleanup_error.empty()) result.error += ": " + first_cleanup_error;
                return finish_after_cleanup(false);
            }
            std::string topology_error;
            if (!fixture.verify_topology(FailurePoint::None, topology_error)) {
                result.error =
                    "holder/networks changed under uncertain sidecar creation: " + topology_error;
                return finish_after_cleanup(false);
            }

            std::string retry_error;
            if (!fixture.cleanup(retry_error)) {
                result.error =
                    "authoritative sidecar recovery/removal retry failed: " + retry_error;
                return finish_after_cleanup(false);
            }
            const CleanupEvidence terminal = fixture.cleanup_evidence();
            if (terminal.progress != CleanupProgress::TopologySettled || terminal.sidecar_exists ||
                terminal.sidecar_creation_may_have_mutated || terminal.holder_exists ||
                terminal.network_a_exists || terminal.network_b_exists ||
                terminal.sidecar_operation_ok || !terminal.topology_operation_ok) {
                result.error = "uncertain sidecar recovery retry lacked exact terminal evidence";
                return finish_after_cleanup(false);
            }
            result.semantic_receipt =
                "verified uncertain sidecar create fail-closed recovery and zero residue";
            result.error = result.semantic_receipt;
            return finish_after_cleanup(true);
        }
        const bool expected =
            failure_point == HeldNamespaceSidecarFailurePoint::AfterCreate ||
            failure_point == HeldNamespaceSidecarFailurePoint::AfterDiscovery ||
            failure_point == HeldNamespaceSidecarFailurePoint::AfterVerification ||
            failure_point == HeldNamespaceSidecarFailurePoint::CreateReportedTimeout;
        if (expected) result.semantic_receipt = result.error;
        return finish_after_cleanup(expected);
    }
    if (failure_point == HeldNamespaceSidecarFailurePoint::UnexpectedDeath) {
        if (!fixture.terminate_sidecar_unexpectedly(result.error))
            return finish_after_cleanup(false);
        result.semantic_receipt = result.error;
        return finish_after_cleanup(true);
    }
    if (!callback(topology, fixture.sidecar_snapshot(), result.error)) {
        result.semantic_receipt = result.error;
        return finish_after_cleanup(false);
    }
    if (failure_point == HeldNamespaceSidecarFailurePoint::AfterCallbackEntry) {
        result.error = "injected held-namespace sidecar failure after callback entry";
        result.semantic_receipt = result.error;
        return finish_after_cleanup(true);
    }
    if (failure_point == HeldNamespaceSidecarFailurePoint::DisappearBeforeCleanup) {
        if (!fixture.disappear_sidecar_before_cleanup(result.error))
            return finish_after_cleanup(false);
        std::string first_cleanup_error;
        if (fixture.cleanup(first_cleanup_error) ||
            first_cleanup_error != "sidecar disappeared before identity-safe cleanup") {
            result.error =
                "already-disappeared sidecar did not retain truthful cleanup failure evidence";
            return finish_after_cleanup(false);
        }
        const CleanupEvidence terminal = fixture.cleanup_evidence();
        if (terminal.progress != CleanupProgress::TopologySettled || terminal.sidecar_exists ||
            terminal.holder_exists || terminal.network_a_exists || terminal.network_b_exists ||
            terminal.sidecar_operation_ok || !terminal.topology_operation_ok) {
            result.error =
                "already-disappeared sidecar did not permit safe topology residue cleanup";
            return finish_after_cleanup(false);
        }
        const u64 command_count_before_replay = command_invocation_count;
        std::string replay_error;
        if (!fixture.cleanup(replay_error) || !replay_error.empty() ||
            command_invocation_count != command_count_before_replay ||
            !cleanup_evidence_equal(terminal, fixture.cleanup_evidence())) {
            result.error = "already-disappeared terminal cleanup replay was not inert";
            return finish_after_cleanup(false);
        }
        result.semantic_receipt =
            "verified already-disappeared sidecar settlement and safe topology cleanup";
        result.error = result.semantic_receipt;
        return finish_after_cleanup(true);
    }
    if (holder_removal_failure_point ==
        HeldNamespaceHolderRemovalFailurePoint::SuppressFirstCommand) {
        const CleanupPhaseResult sidecar_settlement = fixture.cleanup_sidecar_phase(result.error);
        const CleanupEvidence sidecar_settled = fixture.cleanup_evidence();
        if (!sidecar_settlement.settled || !sidecar_settlement.operation_ok ||
            sidecar_settled.progress != CleanupProgress::SidecarSettled ||
            sidecar_settled.sidecar_exists || !sidecar_settled.holder_exists ||
            !sidecar_settled.network_a_exists || !sidecar_settled.network_b_exists ||
            sidecar_settled.holder_remove_command_count != 0u ||
            sidecar_settled.holder_remove_suppression_count != 0u) {
            if (result.error.empty())
                result.error = "running-holder suppression lacked settled-sidecar custody";
            return finish_after_cleanup(false);
        }
        const HeldTopologySnapshot before_suppression = fixture.current_topology_snapshot();
        const SetupEventEvidence setup_before = fixture.setup_event_evidence();
        std::string live_error;
        if (!fixture.verify_topology(FailurePoint::None, live_error) ||
            !fixture.arm_holder_removal_suppression_once(live_error)) {
            result.error =
                "running-holder suppression could not arm after live validation: " + live_error;
            return finish_after_cleanup(false);
        }

        std::string first_error;
        const CleanupPhaseResult first = fixture.cleanup_holder_phase(first_error);
        const CleanupEvidence after_first = fixture.cleanup_evidence();
        const HeldTopologySnapshot after_suppression = fixture.current_topology_snapshot();
        live_error.clear();
        if (first.settled || first.operation_ok || first.holder_settled || first.holder_removed ||
            first_error !=
                "injected holder removal suppression with exact running holder retained" ||
            after_first.progress != CleanupProgress::SidecarSettled || !after_first.holder_exists ||
            !after_first.network_a_exists || !after_first.network_b_exists ||
            !after_first.holder_removal_may_have_mutated || after_first.holder_operation_ok ||
            after_first.holder_remove_command_count != 0u ||
            after_first.holder_remove_suppression_count != 1u ||
            !topology_snapshot_equal(before_suppression, after_suppression) ||
            !setup_event_evidence_equal(setup_before, fixture.setup_event_evidence()) ||
            !fixture.verify_topology(FailurePoint::None, live_error)) {
            result.error =
                "suppressed holder removal mutated topology or claimed a real removal command";
            if (!first_error.empty()) result.error += ": " + first_error;
            if (!live_error.empty()) result.error += "; " + live_error;
            return finish_after_cleanup(false);
        }

        std::string retry_error;
        const CleanupPhaseResult retry = fixture.cleanup_holder_phase(retry_error);
        const CleanupEvidence holder_settled = fixture.cleanup_evidence();
        const HeldNamespaceOldGenerationAbsence absence = fixture.holder_retirement_absence();
        if (!retry.settled || retry.operation_ok || !retry.holder_settled ||
            !retry.holder_removed || !retry_error.empty() ||
            holder_settled.progress != CleanupProgress::HolderSettled ||
            holder_settled.holder_exists || !holder_settled.network_a_exists ||
            !holder_settled.network_b_exists || holder_settled.holder_removal_may_have_mutated ||
            holder_settled.holder_operation_ok ||
            holder_settled.holder_remove_command_count != 1u ||
            holder_settled.holder_remove_suppression_count != 1u ||
            !setup_event_evidence_equal(setup_before, fixture.setup_event_evidence()) ||
            fixture.network_a().id != before_suppression.network_a_id ||
            fixture.network_a().subnet != before_suppression.network_a_subnet ||
            fixture.network_a().gateway != before_suppression.network_a_gateway ||
            fixture.network_b().id != before_suppression.network_b_id ||
            fixture.network_b().subnet != before_suppression.network_b_subnet ||
            fixture.network_b().gateway != before_suppression.network_b_gateway ||
            absence.holder.container_id != before_suppression.holder_id ||
            absence.holder.pid != before_suppression.holder_pid ||
            absence.holder.start != before_suppression.holder_start ||
            !absence.holder.container_id_absent || !absence.holder.process_identity_absent ||
            absence.holder_name != before_suppression.holder_name || !absence.holder_name_absent) {
            result.error = "running holder exact-ID retry lacked monotonic retained-network proof";
            if (!retry_error.empty()) result.error += ": " + retry_error;
            return finish_after_cleanup(false);
        }

        const u64 commands_before_holder_replay = command_invocation_count;
        const CleanupEvidence before_holder_replay = holder_settled;
        // Phase APIs append diagnostics and never clear caller-owned history.
        // Use a fresh accumulator when proving an inert replay adds none.
        std::string holder_replay_error;
        const CleanupPhaseResult holder_replay = fixture.cleanup_holder_phase(holder_replay_error);
        if (!cleanup_phase_result_equal(retry, holder_replay) || !holder_replay_error.empty() ||
            command_invocation_count != commands_before_holder_replay ||
            !cleanup_evidence_equal(before_holder_replay, fixture.cleanup_evidence())) {
            result.error = "historical holder operation failure replay was not frozen/inert";
            return finish_after_cleanup(false);
        }

        struct SettlementTrace {
            std::vector<TopologySettlementEvent> events;
            std::vector<bool> removed;
        } trace;
        const auto record_settlement =
            [](void* context, TopologySettlementEvent event, bool removed, std::string&) {
                auto& observed = *static_cast<SettlementTrace*>(context);
                observed.events.push_back(event);
                observed.removed.push_back(removed);
                return true;
            };
        std::string topology_cleanup_error;
        const CleanupPhaseResult topology_cleanup =
            fixture.cleanup_topology_phase(topology_cleanup_error, record_settlement, &trace);
        const CleanupEvidence terminal = fixture.cleanup_evidence();
        const std::vector<TopologySettlementEvent> expected_events{
            TopologySettlementEvent::Holder,
            TopologySettlementEvent::NetworkB,
            TopologySettlementEvent::NetworkA};
        if (!topology_cleanup.settled || topology_cleanup.operation_ok ||
            !topology_cleanup.holder_settled || !topology_cleanup.holder_removed ||
            !topology_cleanup.network_b_settled || !topology_cleanup.network_b_removed ||
            !topology_cleanup.network_a_settled || !topology_cleanup.network_a_removed ||
            !topology_cleanup_error.empty() || trace.events != expected_events ||
            trace.removed != std::vector<bool>({true, true, true}) ||
            terminal.progress != CleanupProgress::TopologySettled || terminal.sidecar_exists ||
            terminal.holder_exists || terminal.network_a_exists || terminal.network_b_exists ||
            terminal.holder_operation_ok || terminal.topology_operation_ok ||
            terminal.holder_remove_command_count != 1u ||
            terminal.holder_remove_suppression_count != 1u) {
            result.error = "running-holder recovery did not complete ordered B/A cleanup";
            if (!topology_cleanup_error.empty()) result.error += ": " + topology_cleanup_error;
            return finish_after_cleanup(false);
        }

        const u64 commands_before_terminal_replay = command_invocation_count;
        std::string terminal_replay_error;
        if (fixture.cleanup(terminal_replay_error) || !terminal_replay_error.empty() ||
            command_invocation_count != commands_before_terminal_replay ||
            !cleanup_evidence_equal(terminal, fixture.cleanup_evidence())) {
            result.error = "running-holder terminal recovery replay was not command-free/frozen";
            return finish_after_cleanup(false);
        }
        std::string residue_error;
        result.cleanup_complete = true;
        result.residue_free = audit(residue_error);
        if (!result.residue_free) {
            result.error = residue_error;
            return result;
        }
        result.semantic_receipt =
            "verified running holder suppressed-removal exact-ID recovery and zero residue";
        result.error = result.semantic_receipt;
        result.success = true;
        return result;
    }
    if (failure_point == HeldNamespaceSidecarFailurePoint::PauseAfterSidecarSettlement) {
        const CleanupPhaseResult sidecar_settlement = fixture.cleanup_sidecar_phase(result.error);
        const CleanupEvidence paused = fixture.cleanup_evidence();
        if (!sidecar_settlement.settled || !sidecar_settlement.operation_ok ||
            paused.progress != CleanupProgress::SidecarSettled || paused.sidecar_exists ||
            !paused.holder_exists || !paused.network_a_exists || !paused.network_b_exists ||
            !paused.sidecar_operation_ok) {
            if (result.error.empty())
                result.error = "sidecar settlement pause did not retain exact topology custody";
            return finish_after_cleanup(false);
        }
        std::string topology_error;
        if (!fixture.verify_topology(FailurePoint::None, topology_error)) {
            result.error =
                "holder/networks changed during sidecar settlement pause: " + topology_error;
            return finish_after_cleanup(false);
        }

        std::string retry_error;
        if (!fixture.cleanup(retry_error)) {
            result.error = "topology cleanup retry after sidecar settlement failed: " + retry_error;
            return finish_after_cleanup(false);
        }
        const CleanupEvidence terminal = fixture.cleanup_evidence();
        if (terminal.progress != CleanupProgress::TopologySettled || terminal.sidecar_exists ||
            terminal.holder_exists || terminal.network_a_exists || terminal.network_b_exists ||
            !terminal.sidecar_operation_ok || !terminal.topology_operation_ok) {
            result.error = "topology cleanup retry did not reach exact terminal settlement";
            return finish_after_cleanup(false);
        }

        const u64 command_count_before_replay = command_invocation_count;
        std::string first_replay_error;
        std::string second_replay_error;
        if (!fixture.cleanup(first_replay_error) || !fixture.cleanup(second_replay_error) ||
            !first_replay_error.empty() || !second_replay_error.empty() ||
            command_invocation_count != command_count_before_replay ||
            !cleanup_evidence_equal(terminal, fixture.cleanup_evidence())) {
            result.error = "terminal topology cleanup replay was not inert and idempotent";
            return finish_after_cleanup(false);
        }
        result.semantic_receipt =
            "verified sidecar-settled pause, guarded topology retry, and inert terminal replay";
        result.error = result.semantic_receipt;
        return finish_after_cleanup(true);
    }
    if (revalidation_fault != HeldNamespaceSidecarRevalidationFault::None) {
        fixture.set_sidecar_revalidation_fault(revalidation_fault);
        std::string rejection_error;
        const bool unexpectedly_removed = fixture.cleanup(rejection_error);
        if (unexpectedly_removed || !fixture.sidecar_exists() ||
            rejection_error.find("refusing sidecar deletion") == std::string::npos) {
            fixture.set_sidecar_revalidation_fault(HeldNamespaceSidecarRevalidationFault::None);
            result.error = "injected sidecar revalidation fault was not rejected before removal";
            if (!rejection_error.empty()) result.error += ": " + rejection_error;
            return finish_after_cleanup(false);
        }
        const CleanupEvidence before_guarded_topology = fixture.cleanup_evidence();
        const u64 commands_before_guarded_topology = command_invocation_count;
        std::string guarded_topology_error;
        const CleanupPhaseResult guarded_topology =
            fixture.cleanup_topology_phase(guarded_topology_error);
        if (guarded_topology.settled || guarded_topology.operation_ok ||
            guarded_topology_error !=
                "refusing holder/network cleanup before exact sidecar settlement" ||
            command_invocation_count != commands_before_guarded_topology ||
            !cleanup_evidence_equal(before_guarded_topology, fixture.cleanup_evidence())) {
            fixture.set_sidecar_revalidation_fault(HeldNamespaceSidecarRevalidationFault::None);
            result.error =
                "holder/network phase did not fail closed before exact sidecar settlement";
            return finish_after_cleanup(false);
        }
        fixture.set_sidecar_revalidation_fault(HeldNamespaceSidecarRevalidationFault::None);
        std::string topology_error;
        if (!fixture.verify_topology(FailurePoint::None, topology_error)) {
            result.error =
                "holder/networks changed before rejected sidecar could settle: " + topology_error;
            return finish_after_cleanup(false);
        }
        result.semantic_receipt =
            std::string("verified pre-removal sidecar revalidation rejection ") +
            sidecar_revalidation_fault_name(revalidation_fault) + ": " + rejection_error;
        result.error = result.semantic_receipt;
        return finish_after_cleanup(true);
    }
    return finish_after_cleanup(true);
}

RunResult run_with_holder_only_recreation(const HolderOnlyRecreationCallback& callback,
                                          HolderOnlyRecreationFailurePoint failure_point) {
    RunResult result;
    std::string token;
    if (!callback || !high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = callback ? "high-entropy token generation unavailable"
                                : "holder-only recreation callback was empty";
        return result;
    }
    Fixture fixture(token);
    TempDir temp;
    const auto audit = [&](std::string& error) {
        if (!audit_zero_residue(token,
                                fixture.network_a().name,
                                fixture.network_b().name,
                                fixture.holder_name(),
                                error))
            return false;
        CommandResult sidecar;
        if (!run_command({"docker", "inspect", fixture.sidecar_name()}, sidecar) ||
            exited_zero(sidecar)) {
            error = "old sidecar stable name remains after holder-only recreation";
            return false;
        }
        return true;
    };
    const auto finish = [&](bool semantic_success) {
        std::string cleanup_error;
        const bool cleanup_ok = fixture.cleanup(cleanup_error);
        result.cleanup_complete = cleanup_ok;
        if (!cleanup_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += cleanup_error;
        }
        std::string audit_error;
        result.residue_free = audit(audit_error);
        if (!audit_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += audit_error;
        }
        result.success = semantic_success && cleanup_ok && result.residue_free;
        return result;
    };
    if (!temp.create() || !write_manifest(temp, fixture) || !preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe =
            result.error.find("exact target name already exists") == std::string::npos;
        if (result.error.empty()) result.error = "holder-only recreation preflight failed";
        return result;
    }
    if (!fixture.create_networks(FailurePoint::None, result.error) ||
        !fixture.create_holder(FailurePoint::None, result.error) ||
        !fixture.attach_holder(FailurePoint::None, result.error) ||
        !fixture.verify_topology(FailurePoint::None, result.error) ||
        !fixture.create_sidecar(HeldNamespaceSidecarFailurePoint::None, result.error))
        return finish(false);

    const HeldTopologySnapshot old_topology = fixture.current_topology_snapshot();
    const HeldNamespaceSidecarSnapshot old_sidecar = fixture.sidecar_snapshot();
    std::string sidecar_error;
    const CleanupPhaseResult sidecar = fixture.cleanup_sidecar_phase(sidecar_error);
    if (!sidecar.settled || !sidecar.operation_ok || !sidecar_error.empty()) {
        result.error = "old sidecar did not settle before holder-only recreation: " + sidecar_error;
        return finish(false);
    }
    std::string holder_error;
    const CleanupPhaseResult holder = fixture.cleanup_holder_phase(holder_error);
    if (!holder.settled || !holder.operation_ok || !holder.holder_removed ||
        !holder_error.empty()) {
        result.error = "old holder did not settle before holder-only recreation: " + holder_error;
        return finish(false);
    }
    const CleanupEvidence old_cleanup_frozen = fixture.cleanup_evidence();
    const HeldNamespaceOldGenerationAbsence old_absence = fixture.holder_retirement_absence();
    if (old_absence.phase != HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
        old_absence.holder.container_id != old_topology.holder_id ||
        old_absence.holder.pid != old_topology.holder_pid ||
        old_absence.holder.start != old_topology.holder_start ||
        !old_absence.holder.container_id_absent || !old_absence.holder.process_identity_absent ||
        old_absence.sidecar.container_id != old_sidecar.id ||
        old_absence.sidecar.pid != old_sidecar.pid ||
        old_absence.sidecar.start != old_sidecar.start ||
        !old_absence.sidecar.container_id_absent || !old_absence.sidecar.process_identity_absent ||
        old_absence.holder_name != old_topology.holder_name ||
        old_absence.sidecar_name != old_sidecar.name || !old_absence.holder_name_absent ||
        !old_absence.sidecar_name_absent) {
        result.error = "old holder/sidecar exact absence was incomplete before stable-name reuse";
        return finish(false);
    }

    if (!fixture.recreate_holder_only(failure_point, result.error)) return finish(false);
    const HolderOnlyRecreationEvidence evidence = fixture.holder_only_recreation_evidence();
    const u32 validated_state_mask =
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::Ready)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::CreateMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::CreatedStoppedCleanupOnly)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::StartMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::RunningExactNetworkA)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::NetworkBConnectMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::RunningExactNetworksAB)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::Validated));
    const bool operation_expected_before_cleanup =
        failure_point == HolderOnlyRecreationFailurePoint::None ||
        failure_point == HolderOnlyRecreationFailurePoint::CleanupReportedTimeout;
    if (evidence.complete_generation || evidence.state != HolderOnlyRecreationState::Validated ||
        evidence.old_absence.phase != HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
        evidence.network_a_id != old_topology.network_a_id ||
        evidence.network_b_id != old_topology.network_b_id ||
        evidence.network_a_subnet != old_topology.network_a_subnet ||
        evidence.network_a_gateway != old_topology.network_a_gateway ||
        evidence.network_b_subnet != old_topology.network_b_subnet ||
        evidence.network_b_gateway != old_topology.network_b_gateway ||
        evidence.positive_ip != old_topology.positive_ip ||
        evidence.guard_ip != old_topology.guard_ip ||
        evidence.holder_name != old_topology.holder_name ||
        evidence.holder_id == old_topology.holder_id || evidence.holder_id == old_sidecar.id ||
        !full_container_id(evidence.holder_id) || evidence.holder_pid <= 1 ||
        evidence.holder_start == 0u || !evidence.exact_network_a || !evidence.exact_network_b ||
        !evidence.exact_security || !evidence.network_a_membership_proven_after_start ||
        !evidence.old_authority_frozen || evidence.create_command_count != 1u ||
        evidence.start_command_count != 1u || evidence.connect_b_command_count != 1u ||
        evidence.remove_command_count != 0u ||
        evidence.operation_ok != operation_expected_before_cleanup ||
        evidence.state_visit_mask != validated_state_mask ||
        (evidence.holder_pid == old_topology.holder_pid &&
         evidence.holder_start == old_topology.holder_start) ||
        (evidence.holder_pid == old_sidecar.pid && evidence.holder_start == old_sidecar.start) ||
        !cleanup_evidence_equal(old_cleanup_frozen, fixture.cleanup_evidence())) {
        result.error = "holder-only recreation evidence was not exact/separate/frozen";
        return finish(false);
    }
    if (!callback(evidence, result.error)) return finish(false);

    std::string recreated_cleanup_error;
    if (!fixture.cleanup_recreated_holder(recreated_cleanup_error) ||
        !recreated_cleanup_error.empty()) {
        result.error = "recreated holder exact settlement failed: " + recreated_cleanup_error;
        return finish(false);
    }
    const HolderOnlyRecreationEvidence settled = fixture.holder_only_recreation_evidence();
    const u32 settled_state_mask =
        validated_state_mask |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::RemovalMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::Settled));
    if (settled.state != HolderOnlyRecreationState::Settled || settled.complete_generation ||
        settled.holder_id != evidence.holder_id || settled.remove_command_count != 1u ||
        settled.operation_ok != (failure_point == HolderOnlyRecreationFailurePoint::None) ||
        settled.state_visit_mask != settled_state_mask || settled.create_command_count != 1u ||
        settled.start_command_count != 1u || settled.connect_b_command_count != 1u ||
        !cleanup_evidence_equal(old_cleanup_frozen, fixture.cleanup_evidence())) {
        result.error = "recreated holder settlement mutated old frozen cleanup authority";
        return finish(false);
    }
    const u64 commands_before_recreated_replay = command_invocation_count;
    std::string caller_history = "preserve-caller-history";
    if (!fixture.cleanup_recreated_holder(caller_history) ||
        caller_history != "preserve-caller-history" ||
        command_invocation_count != commands_before_recreated_replay ||
        fixture.holder_only_recreation_evidence().holder_id != evidence.holder_id ||
        fixture.holder_only_recreation_evidence().remove_command_count != 1u) {
        result.error = "recreated holder terminal replay was not command-free/frozen";
        return finish(false);
    }
    if (!fixture.cleanup(result.error)) return finish(false);
    const u64 commands_before_terminal_replay = command_invocation_count;
    const CleanupEvidence terminal = fixture.cleanup_evidence();
    caller_history = "preserve-terminal-history";
    if (!fixture.cleanup(caller_history) || caller_history != "preserve-terminal-history" ||
        command_invocation_count != commands_before_terminal_replay ||
        !cleanup_evidence_equal(terminal, fixture.cleanup_evidence())) {
        result.error = "holder-only recreation owner terminal replay was not inert";
        return finish(false);
    }
    std::string audit_error;
    result.cleanup_complete = true;
    result.residue_free = audit(audit_error);
    if (!result.residue_free) {
        result.error = audit_error;
        return result;
    }
    switch (failure_point) {
        case HolderOnlyRecreationFailurePoint::None:
            result.semantic_receipt =
                "verified holder-only recreation with incomplete-generation evidence and zero "
                "residue";
            break;
        case HolderOnlyRecreationFailurePoint::CreateReportedTimeout:
            result.semantic_receipt =
                "verified holder-only create reported-timeout exact recovery and zero residue";
            break;
        case HolderOnlyRecreationFailurePoint::StartReportedTimeout:
            result.semantic_receipt =
                "verified holder-only start reported-timeout exact recovery and zero residue";
            break;
        case HolderOnlyRecreationFailurePoint::NetworkBConnectReportedTimeout:
            result.semantic_receipt =
                "verified holder-only B-connect reported-timeout exact recovery and zero residue";
            break;
        case HolderOnlyRecreationFailurePoint::CleanupReportedTimeout:
            result.semantic_receipt =
                "verified holder-only cleanup reported-timeout exact absence and zero residue";
            break;
    }
    result.error = result.semantic_receipt;
    result.success = true;
    return result;
}

static bool capture_old_generation_for_receipt(Fixture& fixture,
                                               GenerationReceiptCompositionOwner& composer,
                                               std::string& error) {
    HeldTopologySnapshot old_topology;
    if (!fixture.build_current_generation_topology(old_topology, error) ||
        !fixture.revalidate_sidecar_identity(error)) {
        if (error.empty()) error = "old generation phase-1 revalidation failed";
        generation_receipt_composition_fail(composer);
        return false;
    }
    composer.receipt.old_generation.topology = old_topology;
    composer.receipt.old_generation.sidecar = fixture.sidecar_snapshot();
    if (!validate_held_namespace_sidecar_snapshot(composer.receipt.old_generation.topology,
                                                  composer.receipt.old_generation.sidecar,
                                                  error) ||
        !generation_receipt_composition_transition(
            composer, GenerationReceiptCompositionState::OldGenerationValidated)) {
        if (error.empty()) error = "old generation phase-1 evidence was not exact";
        generation_receipt_composition_fail(composer);
        return false;
    }
    composer.receipt.old_generation_phase =
        HeldNamespaceGenerationRotationPhase::OldGenerationValidated;
    return true;
}

static bool capture_old_absence_for_receipt(Fixture& fixture,
                                            GenerationReceiptCompositionOwner& composer,
                                            std::string& error) {
    composer.receipt.old_absence = fixture.holder_retirement_absence();
    const auto witness_matches = [](const HeldNamespaceGenerationWitnessAbsence& witness,
                                    const std::string& id,
                                    pid_t pid,
                                    u64 start) {
        return witness.container_id == id && witness.pid == pid && witness.start == start &&
               witness.container_id_absent && witness.process_identity_absent;
    };
    if (composer.receipt.old_absence.phase !=
            HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
        !witness_matches(composer.receipt.old_absence.holder,
                         composer.receipt.old_generation.topology.holder_id,
                         composer.receipt.old_generation.topology.holder_pid,
                         composer.receipt.old_generation.topology.holder_start) ||
        !witness_matches(composer.receipt.old_absence.sidecar,
                         composer.receipt.old_generation.sidecar.id,
                         composer.receipt.old_generation.sidecar.pid,
                         composer.receipt.old_generation.sidecar.start) ||
        composer.receipt.old_absence.holder_name !=
            composer.receipt.old_generation.topology.holder_name ||
        composer.receipt.old_absence.sidecar_name != composer.receipt.old_generation.sidecar.name ||
        !composer.receipt.old_absence.holder_name_absent ||
        !composer.receipt.old_absence.sidecar_name_absent ||
        !generation_receipt_composition_transition(
            composer, GenerationReceiptCompositionState::OldGenerationAbsent)) {
        error = "old generation phase-2 exact absence did not match frozen phase-1";
        generation_receipt_composition_fail(composer);
        return false;
    }
    return true;
}

static bool publish_complete_generation_receipt(Fixture& fixture,
                                                const RecreatedSidecarEvidence& sidecar,
                                                bool inject_second_sidecar_observation_mutation,
                                                GenerationReceiptCompositionOwner& composer,
                                                std::string& error) {
    composer.receipt.new_generation.topology = sidecar.fresh_topology;
    composer.receipt.new_generation.sidecar = sidecar.sidecar;
    if (!generation_receipt_composition_transition(
            composer, GenerationReceiptCompositionState::NewGenerationCreated)) {
        error = "new generation phase-3 transition was rejected";
        generation_receipt_composition_fail(composer);
        return false;
    }
    composer.receipt.new_generation_created_phase =
        HeldNamespaceGenerationRotationPhase::NewGenerationCreated;

    HeldNamespaceSidecarSnapshot sidecar_observation_a;
    HeldTopologySnapshot holder_observation;
    HeldNamespaceSidecarSnapshot sidecar_observation_b;
    if (!fixture.revalidate_recreated_sidecar_for_rotation(sidecar_observation_a, false, error) ||
        !fixture.build_recreated_holder_topology(holder_observation, error) ||
        !fixture.revalidate_recreated_sidecar_for_rotation(
            sidecar_observation_b, inject_second_sidecar_observation_mutation, error) ||
        !complete_rotation_topology_equal(holder_observation,
                                          composer.receipt.new_generation.topology) ||
        !sidecar_snapshot_equal(sidecar_observation_a, sidecar_observation_b) ||
        !sidecar_snapshot_equal(sidecar_observation_a, composer.receipt.new_generation.sidecar)) {
        if (error.empty())
            error = "fresh phase-4 sidecar A/holder/sidecar B bracket differed from phase 3";
        generation_receipt_composition_fail(composer);
        return false;
    }

    CommandResult cardinality;
    if (!run_command({"docker",
                      "ps",
                      "-aq",
                      "--no-trunc",
                      "--filter",
                      "label=rut.token=" + fixture.token(),
                      "--filter",
                      std::string("label=rut.role=") + kSidecarRole},
                     cardinality) ||
        !exited_zero(cardinality) || trim(cardinality.output) != sidecar_observation_b.id) {
        error = "fresh sidecar phase-4 cardinality was not exactly one";
        generation_receipt_composition_fail(composer);
        return false;
    }
    if (!generation_receipt_composition_transition(
            composer, GenerationReceiptCompositionState::NewGenerationValidated)) {
        error = "new generation phase-4 transition was rejected";
        generation_receipt_composition_fail(composer);
        return false;
    }
    composer.receipt.new_generation_validated_phase =
        HeldNamespaceGenerationRotationPhase::NewGenerationValidated;
    std::string first_validation_error;
    std::string second_validation_error;
    if (!validate_held_namespace_generation_rotation_receipt(composer.receipt,
                                                             first_validation_error) ||
        !validate_held_namespace_generation_rotation_receipt(composer.receipt,
                                                             second_validation_error) ||
        !first_validation_error.empty() || !second_validation_error.empty()) {
        error = "complete generation receipt failed its two independent validations";
        if (!first_validation_error.empty()) error += ": " + first_validation_error;
        generation_receipt_composition_fail(composer);
        return false;
    }
    if (!generation_receipt_composition_transition(composer,
                                                   GenerationReceiptCompositionState::Published)) {
        error = "complete generation receipt publication transition was rejected";
        generation_receipt_composition_fail(composer);
        return false;
    }
    composer.frozen_receipt = composer.receipt;
    return true;
}

RunResult run_with_recreated_sidecar(
    const RecreatedSidecarCallback& callback,
    HolderOnlyRecreationFailurePoint holder_failure_point,
    RecreatedSidecarFailurePoint sidecar_failure_point,
    const HeldNamespaceGenerationReceiptCallback& receipt_callback) {
    RunResult result;
    std::string token;
    if (!callback || !high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = callback ? "high-entropy token generation unavailable"
                                : "recreated-sidecar callback was empty";
        return result;
    }
    Fixture fixture(token);
    TempDir temp;
    const bool compose_receipt = static_cast<bool>(receipt_callback);
    GenerationReceiptCompositionOwner composer;
    bool receipt_published = false;
    const auto audit = [&](std::string& error) {
        if (!audit_zero_residue(token,
                                fixture.network_a().name,
                                fixture.network_b().name,
                                fixture.holder_name(),
                                error))
            return false;
        CommandResult sidecar;
        if (!run_command({"docker", "inspect", fixture.sidecar_name()}, sidecar) ||
            exited_zero(sidecar)) {
            error = "sidecar stable name remains after fresh-sidecar recreation";
            return false;
        }
        return true;
    };
    const auto finish = [&](bool semantic_success) {
        std::string cleanup_error;
        const bool cleanup_ok = fixture.cleanup(cleanup_error);
        if (receipt_published &&
            !generation_receipt_equal(composer.frozen_receipt, composer.receipt)) {
            if (!cleanup_error.empty()) cleanup_error += "; ";
            cleanup_error += "published generation receipt changed during cleanup";
        }
        result.cleanup_complete = cleanup_ok;
        if (!cleanup_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += cleanup_error;
        }
        std::string audit_error;
        result.residue_free = audit(audit_error);
        if (!audit_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += audit_error;
        }
        result.success = semantic_success && cleanup_ok && result.residue_free;
        return result;
    };
    if (!temp.create() || !write_manifest(temp, fixture) || !preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe =
            result.error.find("exact target name already exists") == std::string::npos;
        if (result.error.empty()) result.error = "recreated-sidecar preflight failed";
        return result;
    }
    if (!fixture.create_networks(FailurePoint::None, result.error) ||
        !fixture.create_holder(FailurePoint::None, result.error) ||
        !fixture.attach_holder(FailurePoint::None, result.error) ||
        !fixture.verify_topology(FailurePoint::None, result.error) ||
        !fixture.create_sidecar(HeldNamespaceSidecarFailurePoint::None, result.error))
        return finish(false);

    HeldTopologySnapshot old_topology;
    HeldNamespaceSidecarSnapshot old_sidecar;
    if (compose_receipt) {
        std::string composition_error;
        if (!capture_old_generation_for_receipt(fixture, composer, composition_error)) {
            result.error = composition_error;
            return finish(false);
        }
        old_topology = composer.receipt.old_generation.topology;
        old_sidecar = composer.receipt.old_generation.sidecar;
    } else {
        old_topology = fixture.current_topology_snapshot();
        old_sidecar = fixture.sidecar_snapshot();
    }
    std::string phase_error;
    const CleanupPhaseResult old_sidecar_settled = fixture.cleanup_sidecar_phase(phase_error);
    if (!old_sidecar_settled.settled || !old_sidecar_settled.operation_ok || !phase_error.empty()) {
        result.error = "old sidecar did not settle before fresh generation: " + phase_error;
        return finish(false);
    }
    phase_error.clear();
    const CleanupPhaseResult old_holder_settled = fixture.cleanup_holder_phase(phase_error);
    if (!old_holder_settled.settled || !old_holder_settled.operation_ok ||
        !old_holder_settled.holder_removed || !phase_error.empty()) {
        result.error = "old holder did not settle before fresh generation: " + phase_error;
        return finish(false);
    }
    const CleanupEvidence old_cleanup = fixture.cleanup_evidence();
    const HeldNamespaceOldGenerationAbsence old_absence = fixture.holder_retirement_absence();
    if (old_absence.phase != HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
        old_absence.holder.container_id != old_topology.holder_id ||
        old_absence.holder.pid != old_topology.holder_pid ||
        old_absence.holder.start != old_topology.holder_start ||
        old_absence.sidecar.container_id != old_sidecar.id ||
        old_absence.sidecar.pid != old_sidecar.pid ||
        old_absence.sidecar.start != old_sidecar.start || !old_absence.holder.container_id_absent ||
        !old_absence.holder.process_identity_absent || !old_absence.sidecar.container_id_absent ||
        !old_absence.sidecar.process_identity_absent || !old_absence.holder_name_absent ||
        !old_absence.sidecar_name_absent) {
        result.error = "old generation exact frozen absence was incomplete";
        return finish(false);
    }
    if (compose_receipt) {
        std::string composition_error;
        if (!capture_old_absence_for_receipt(fixture, composer, composition_error)) {
            result.error = composition_error;
            return finish(false);
        }
    }
    if (!fixture.recreate_holder_only(holder_failure_point, result.error)) return finish(false);
    const HolderOnlyRecreationEvidence holder = fixture.holder_only_recreation_evidence();
    const bool holder_operation_before_cleanup =
        holder_failure_point == HolderOnlyRecreationFailurePoint::None ||
        holder_failure_point == HolderOnlyRecreationFailurePoint::CleanupReportedTimeout;
    const u32 holder_validated_mask =
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::Ready)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::CreateMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::CreatedStoppedCleanupOnly)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::StartMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::RunningExactNetworkA)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::NetworkBConnectMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::RunningExactNetworksAB)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::Validated));
    if (holder.complete_generation || holder.state != HolderOnlyRecreationState::Validated ||
        holder.holder_id == old_topology.holder_id || holder.holder_id == old_sidecar.id ||
        !full_container_id(holder.holder_id) || holder.holder_pid <= 1 ||
        holder.holder_start == 0u || !holder.old_authority_frozen || !holder.exact_network_a ||
        !holder.exact_network_b || !holder.exact_security ||
        !holder.network_a_membership_proven_after_start ||
        holder.operation_ok != holder_operation_before_cleanup ||
        holder.state_visit_mask != holder_validated_mask || holder.create_command_count != 1u ||
        holder.start_command_count != 1u || holder.connect_b_command_count != 1u ||
        holder.remove_command_count != 0u ||
        !cleanup_evidence_equal(old_cleanup, fixture.cleanup_evidence())) {
        result.error = "fresh holder authority changed before fresh-sidecar creation";
        return finish(false);
    }

    std::string foreign_id;
    if (sidecar_failure_point == RecreatedSidecarFailurePoint::PreCreateNameCollision) {
        CommandResult foreign;
        if (!run_command({"docker",
                          "create",
                          "--pull=never",
                          "--name",
                          fixture.sidecar_name(),
                          "--label",
                          "rut.role=foreign-owner",
                          RUT_PINNED_NGINX_IMAGE,
                          "/bin/true"},
                         foreign) ||
            !exited_zero(foreign) || !full_container_id(trim(foreign.output))) {
            result.error = "foreign same-name collision fixture could not be created";
            return finish(false);
        }
        foreign_id = trim(foreign.output);
    }

    std::string sidecar_error;
    const bool created = fixture.recreate_sidecar(sidecar_failure_point, sidecar_error);
    if (sidecar_failure_point == RecreatedSidecarFailurePoint::PreCreateNameCollision) {
        CommandResult still_present;
        if (created ||
            sidecar_error != "fresh sidecar stable-name collision was rejected before create" ||
            !run_command({"docker", "inspect", foreign_id}, still_present) ||
            !exited_zero(still_present) ||
            fixture.recreated_sidecar_evidence().state != RecreatedSidecarState::Ready ||
            fixture.recreated_sidecar_evidence().create_command_count != 0u ||
            fixture.recreated_sidecar_evidence().remove_command_count != 0u) {
            result.error = "fresh-sidecar owner deleted or adopted a foreign same-name occupant";
            return finish(false);
        }
        CommandResult removal;
        if (!run_command({"docker", "rm", "-f", foreign_id}, removal) || !exited_zero(removal)) {
            result.error = "foreign collision fixture exact-ID cleanup failed";
            return finish(false);
        }
        if (compose_receipt && (!generation_receipt_composition_fail(composer) ||
                                !generation_receipt_unpublished(composer, false))) {
            result.error =
                "foreign collision incorrectly advanced or published generation receipt phases";
            return finish(false);
        }
        sidecar_error.clear();
    } else {
        const bool expected_created =
            sidecar_failure_point != RecreatedSidecarFailurePoint::CreateSuppressedNoObject &&
            sidecar_failure_point != RecreatedSidecarFailurePoint::UnexpectedDeath;
        if (created != expected_created) {
            result.error =
                "fresh-sidecar production path returned an unexpected creation result "
                "(holder-case=" +
                std::to_string(static_cast<unsigned>(holder_failure_point)) +
                ", sidecar-case=" + std::to_string(static_cast<unsigned>(sidecar_failure_point)) +
                "): " + sidecar_error;
            return finish(false);
        }
        const RecreatedSidecarEvidence evidence = fixture.recreated_sidecar_evidence();
        const bool no_object =
            sidecar_failure_point == RecreatedSidecarFailurePoint::CreateSuppressedNoObject;
        const bool stopped = sidecar_failure_point == RecreatedSidecarFailurePoint::UnexpectedDeath;
        const bool sidecar_operation_before_cleanup =
            sidecar_failure_point != RecreatedSidecarFailurePoint::CreateReportedTimeout &&
            sidecar_failure_point != RecreatedSidecarFailurePoint::CreateSuppressedNoObject &&
            sidecar_failure_point != RecreatedSidecarFailurePoint::UnexpectedDeath;
        const u32 sidecar_created_mask =
            (1u << static_cast<unsigned>(RecreatedSidecarState::Ready)) |
            (1u << static_cast<unsigned>(RecreatedSidecarState::CreateMayHaveMutated));
        const u32 sidecar_validated_mask =
            sidecar_created_mask |
            (1u << static_cast<unsigned>(RecreatedSidecarState::CreatedExactCleanupOnly)) |
            (1u << static_cast<unsigned>(RecreatedSidecarState::Validated));
        const u32 expected_sidecar_mask =
            no_object ? sidecar_created_mask |
                            (1u << static_cast<unsigned>(RecreatedSidecarState::Settled))
                      : (stopped ? sidecar_validated_mask |
                                       (1u << static_cast<unsigned>(
                                            RecreatedSidecarState::StoppedExactCleanupOnly))
                                 : sidecar_validated_mask);
        if (evidence.complete_generation ||
            evidence.old_absence.phase !=
                HeldNamespaceGenerationRotationPhase::OldGenerationAbsent ||
            evidence.holder.holder_id != holder.holder_id ||
            evidence.fresh_topology.holder_id != holder.holder_id ||
            !evidence.fresh_probe_pid_start_scoped ||
            (!no_object &&
             (evidence.sidecar.id.empty() || evidence.sidecar.id == holder.holder_id ||
              evidence.sidecar.id == old_topology.holder_id ||
              evidence.sidecar.id == old_sidecar.id || !evidence.shared_non_host_netns ||
              evidence.create_command_count != 1u)) ||
            (no_object && (evidence.state != RecreatedSidecarState::Settled ||
                           !evidence.sidecar.id.empty() || evidence.create_command_count != 0u)) ||
            (stopped && evidence.state != RecreatedSidecarState::StoppedExactCleanupOnly) ||
            (!no_object && !stopped && evidence.state != RecreatedSidecarState::Validated) ||
            evidence.operation_ok != sidecar_operation_before_cleanup ||
            evidence.state_visit_mask != expected_sidecar_mask ||
            evidence.remove_command_count != 0u || evidence.remove_suppression_count != 0u ||
            !cleanup_evidence_equal(old_cleanup, fixture.cleanup_evidence())) {
            result.error = "fresh-sidecar evidence was not exact/separate/incomplete-generation";
            return finish(false);
        }
        if (!callback(evidence, result.error)) return finish(false);

        if (compose_receipt) {
            if (no_object || stopped) {
                if (!generation_receipt_composition_fail(composer) ||
                    !generation_receipt_unpublished(composer, false)) {
                    result.error =
                        "failed fresh sidecar incorrectly advanced or published receipt phases";
                    return finish(false);
                }
            } else {
                const bool inject_phase4_mutation =
                    sidecar_failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation;
                std::string composition_error;
                const bool published = publish_complete_generation_receipt(
                    fixture, evidence, inject_phase4_mutation, composer, composition_error);
                if (inject_phase4_mutation) {
                    if (published || composition_error.empty() ||
                        !generation_receipt_unpublished(composer, true)) {
                        result.error =
                            "phase-4 sidecar-B mutation did not fail receipt publication closed";
                        return finish(false);
                    }
                } else {
                    if (!published) {
                        result.error = composition_error;
                        return finish(false);
                    }
                    receipt_published = true;
                    if (!receipt_callback(composer.frozen_receipt, result.error))
                        return finish(false);
                }
            }
        }

        if (sidecar_failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation) {
            const u64 before_rejection = command_invocation_count;
            std::string sidecar_rejection_error;
            if (fixture.cleanup_recreated_sidecar(sidecar_rejection_error) ||
                sidecar_rejection_error !=
                    "fresh sidecar cleanup identity/config/netns mutation was rejected" ||
                command_invocation_count <= before_rejection) {
                result.error = "fresh-sidecar mutation rejection was not causally inspected";
                return finish(false);
            }
            const u64 after_sidecar_rejection = command_invocation_count;
            std::string holder_gate_error;
            if (fixture.cleanup_recreated_holder(holder_gate_error) ||
                holder_gate_error !=
                    "refusing recreated holder cleanup before recreated sidecar settlement" ||
                command_invocation_count != after_sidecar_rejection) {
                result.error = "fresh-sidecar mutation did not independently block holder cleanup";
                return finish(false);
            }
            const u64 before_topology_gate = command_invocation_count;
            std::string topology_gate_error;
            if (fixture.cleanup_topology_phase(topology_gate_error).settled ||
                topology_gate_error !=
                    "refusing retained-network cleanup before recreated sidecar settlement" ||
                command_invocation_count != before_topology_gate) {
                result.error =
                    "fresh-sidecar mutation did not independently block B/A topology cleanup";
                return finish(false);
            }
            fixture.clear_recreated_sidecar_cleanup_fault();
        }
        if (sidecar_failure_point == RecreatedSidecarFailurePoint::SuppressFirstRemoval) {
            std::string suppressed;
            if (fixture.cleanup_recreated_sidecar(suppressed) ||
                fixture.recreated_sidecar_evidence().remove_command_count != 0u ||
                fixture.recreated_sidecar_evidence().remove_suppression_count != 1u) {
                result.error = "fresh-sidecar first-removal suppression was not truthful";
                return finish(false);
            }
        }
        std::string cleanup_error;
        if (!fixture.cleanup_recreated_sidecar(cleanup_error)) {
            result.error = "fresh-sidecar exact settlement failed: " + cleanup_error;
            return finish(false);
        }
        const RecreatedSidecarEvidence settled = fixture.recreated_sidecar_evidence();
        const u32 expected_remove = no_object ? 0u : 1u;
        const bool expected_operation =
            sidecar_failure_point == RecreatedSidecarFailurePoint::None ||
            sidecar_failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation;
        const u32 expected_settled_mask =
            no_object
                ? expected_sidecar_mask
                : expected_sidecar_mask |
                      (1u << static_cast<unsigned>(RecreatedSidecarState::RemovalMayHaveMutated)) |
                      (1u << static_cast<unsigned>(RecreatedSidecarState::Settled));
        const u32 expected_suppression =
            sidecar_failure_point == RecreatedSidecarFailurePoint::SuppressFirstRemoval ? 1u : 0u;
        if (settled.state != RecreatedSidecarState::Settled || settled.complete_generation ||
            settled.sidecar.id != evidence.sidecar.id ||
            settled.remove_command_count != expected_remove ||
            settled.remove_suppression_count != expected_suppression ||
            settled.operation_ok != expected_operation ||
            settled.state_visit_mask != expected_settled_mask ||
            !cleanup_evidence_equal(old_cleanup, fixture.cleanup_evidence())) {
            result.error = "fresh-sidecar settlement evidence was not frozen/exact";
            return finish(false);
        }
        const u64 replay_commands = command_invocation_count;
        std::string caller_history = "preserve-fresh-sidecar-history";
        if (!fixture.cleanup_recreated_sidecar(caller_history) ||
            caller_history != "preserve-fresh-sidecar-history" ||
            command_invocation_count != replay_commands ||
            fixture.recreated_sidecar_evidence().sidecar.id != evidence.sidecar.id) {
            result.error = "fresh-sidecar terminal replay was not command-free/frozen";
            return finish(false);
        }
    }

    std::string holder_cleanup_error;
    if (!fixture.cleanup_recreated_holder(holder_cleanup_error)) {
        result.error = "fresh holder did not settle after fresh sidecar: " + holder_cleanup_error;
        return finish(false);
    }
    const bool holder_operation_after_cleanup =
        holder_failure_point == HolderOnlyRecreationFailurePoint::None;
    const HolderOnlyRecreationEvidence holder_settled = fixture.holder_only_recreation_evidence();
    const u32 holder_settled_mask =
        holder_validated_mask |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::RemovalMayHaveMutated)) |
        (1u << static_cast<unsigned>(HolderOnlyRecreationState::Settled));
    if (holder_settled.state != HolderOnlyRecreationState::Settled ||
        holder_settled.holder_id != holder.holder_id ||
        holder_settled.operation_ok != holder_operation_after_cleanup ||
        holder_settled.state_visit_mask != holder_settled_mask ||
        holder_settled.create_command_count != 1u || holder_settled.start_command_count != 1u ||
        holder_settled.connect_b_command_count != 1u || holder_settled.remove_command_count != 1u) {
        result.error = "fresh holder reported-timeout history was not preserved through cleanup";
        return finish(false);
    }
    struct CleanupOrder {
        std::vector<TopologySettlementEvent> events;
    } order;
    const auto record_order =
        [](void* context, TopologySettlementEvent event, bool removed, std::string& error) {
            auto& observed = *static_cast<CleanupOrder*>(context);
            const std::size_t index = observed.events.size();
            const TopologySettlementEvent expected[] = {TopologySettlementEvent::Holder,
                                                        TopologySettlementEvent::NetworkB,
                                                        TopologySettlementEvent::NetworkA};
            if (index >= 3u || event != expected[index] || !removed) {
                error = "fresh cleanup order/removal evidence was not sidecar->holder->B->A";
                return false;
            }
            observed.events.push_back(event);
            return true;
        };
    const CleanupPhaseResult topology =
        fixture.cleanup_topology_phase(result.error, record_order, &order);
    if (!topology.settled || !topology.operation_ok || order.events.size() != 3u)
        return finish(false);
    const u64 replay_commands = command_invocation_count;
    const CleanupEvidence terminal = fixture.cleanup_evidence();
    std::string caller_history = "preserve-fresh-owner-history";
    if (!fixture.cleanup(caller_history) || caller_history != "preserve-fresh-owner-history" ||
        command_invocation_count != replay_commands ||
        !cleanup_evidence_equal(terminal, fixture.cleanup_evidence()) ||
        (receipt_published &&
         !generation_receipt_equal(composer.frozen_receipt, composer.receipt))) {
        result.error = "fresh sidecar->holder->B->A terminal replay was not inert";
        return finish(false);
    }
    std::string audit_error;
    result.cleanup_complete = true;
    result.residue_free = audit(audit_error);
    if (!result.residue_free) {
        result.error = audit_error;
        return result;
    }
    result.semantic_receipt =
        "verified fresh inert sidecar ownership with complete_generation=false and zero residue";
    result.error = result.semantic_receipt;
    result.success = true;
    return result;
}

RunResult run_with_complete_generation_rotation(
    const HeldNamespaceGenerationReceiptCallback& callback,
    HolderOnlyRecreationFailurePoint holder_failure_point,
    RecreatedSidecarFailurePoint sidecar_failure_point) {
    RunResult result;
    std::string token;
    if (!callback || !high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = callback ? "high-entropy token generation unavailable"
                                : "complete-generation receipt callback was empty";
        return result;
    }
    Fixture fixture(token);
    TempDir temp;
    GenerationReceiptCompositionOwner composer;
    bool receipt_published = false;
    HeldNamespaceGenerationRotationReceipt published_receipt;
    const bool expected_no_publication =
        sidecar_failure_point == RecreatedSidecarFailurePoint::CreateSuppressedNoObject ||
        sidecar_failure_point == RecreatedSidecarFailurePoint::PreCreateNameCollision ||
        sidecar_failure_point == RecreatedSidecarFailurePoint::UnexpectedDeath ||
        sidecar_failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation;
    const auto audit = [&](std::string& error) {
        if (!audit_zero_residue(token,
                                fixture.network_a().name,
                                fixture.network_b().name,
                                fixture.holder_name(),
                                error))
            return false;
        CommandResult sidecar;
        if (!run_command({"docker", "inspect", fixture.sidecar_name()}, sidecar) ||
            exited_zero(sidecar)) {
            error = "complete receipt sidecar stable name remains after cleanup";
            return false;
        }
        return true;
    };
    const auto finish = [&](bool semantic_success) {
        std::string cleanup_error;
        const bool cleanup_ok = fixture.cleanup(cleanup_error);
        if (receipt_published &&
            !generation_receipt_equal(composer.frozen_receipt, published_receipt)) {
            if (!cleanup_error.empty()) cleanup_error += "; ";
            cleanup_error += "published generation receipt changed during cleanup";
        }
        result.cleanup_complete = cleanup_ok;
        if (!cleanup_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += cleanup_error;
        }
        std::string audit_error;
        result.residue_free = audit(audit_error);
        if (!audit_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += audit_error;
        }
        result.success = semantic_success && cleanup_ok && result.residue_free;
        if (result.success && receipt_published) {
            const u64 replay_commands = command_invocation_count;
            std::string replay_error;
            if (!fixture.cleanup(replay_error) || !replay_error.empty() ||
                command_invocation_count != replay_commands ||
                !generation_receipt_equal(composer.frozen_receipt, published_receipt)) {
                result.success = false;
                if (!result.error.empty()) result.error += "; ";
                result.error += "published receipt terminal replay was not command-free/frozen";
            }
        }
        return result;
    };
    if (!temp.create() || !write_manifest(temp, fixture) || !preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        if (result.error.empty()) result.error = "complete-generation receipt preflight failed";
        return result;
    }
    if (!fixture.create_networks(FailurePoint::None, result.error) ||
        !fixture.create_holder(FailurePoint::None, result.error) ||
        !fixture.attach_holder(FailurePoint::None, result.error) ||
        !fixture.verify_topology(FailurePoint::None, result.error) ||
        !fixture.create_sidecar(HeldNamespaceSidecarFailurePoint::None, result.error))
        return finish(false);

    std::string phase_error;
    if (!capture_old_generation_for_receipt(fixture, composer, phase_error)) {
        result.error = phase_error;
        return finish(false);
    }

    phase_error.clear();
    const CleanupPhaseResult old_sidecar = fixture.cleanup_sidecar_phase(phase_error);
    if (!old_sidecar.settled || !old_sidecar.operation_ok || !phase_error.empty()) {
        result.error = "old sidecar did not settle for complete receipt: " + phase_error;
        return finish(false);
    }
    phase_error.clear();
    const CleanupPhaseResult old_holder = fixture.cleanup_holder_phase(phase_error);
    if (!old_holder.settled || !old_holder.operation_ok || !old_holder.holder_removed ||
        !phase_error.empty()) {
        result.error = "old holder did not settle for complete receipt: " + phase_error;
        return finish(false);
    }
    phase_error.clear();
    if (!capture_old_absence_for_receipt(fixture, composer, phase_error)) {
        result.error = phase_error;
        return finish(false);
    }

    if (!fixture.recreate_holder_only(holder_failure_point, result.error)) return finish(false);
    const HolderOnlyRecreationEvidence holder = fixture.holder_only_recreation_evidence();
    const char* holder_evidence_gap =
        holder.complete_generation
            ? "holder-only evidence incorrectly claimed a complete generation"
        : holder.state != HolderOnlyRecreationState::Validated
            ? "holder-only owner was not Validated"
        : !holder.old_authority_frozen ? "old holder/sidecar absence authority was not frozen"
        : !holder.exact_network_a      ? "fresh holder lacked exact network-A authority"
        : !holder.exact_network_b      ? "fresh holder lacked exact network-B authority"
        : !holder.exact_security       ? "fresh holder lacked exact immutable security authority"
        : !holder.network_a_membership_proven_after_start
            ? "fresh holder network-A membership was not proven after start"
            : nullptr;
    if (holder_evidence_gap != nullptr) {
        result.error =
            std::string("complete receipt holder evidence was incomplete: ") + holder_evidence_gap;
        return finish(false);
    }

    std::string foreign_id;
    if (sidecar_failure_point == RecreatedSidecarFailurePoint::PreCreateNameCollision) {
        CommandResult foreign;
        if (!run_command({"docker",
                          "create",
                          "--pull=never",
                          "--name",
                          fixture.sidecar_name(),
                          "--label",
                          "rut.role=foreign-owner",
                          RUT_PINNED_NGINX_IMAGE,
                          "/bin/true"},
                         foreign) ||
            !exited_zero(foreign) || !full_container_id(trim(foreign.output))) {
            result.error = "complete receipt collision fixture could not be created";
            return finish(false);
        }
        foreign_id = trim(foreign.output);
    }
    std::string sidecar_error;
    const bool sidecar_created = fixture.recreate_sidecar(sidecar_failure_point, sidecar_error);
    if (sidecar_failure_point == RecreatedSidecarFailurePoint::PreCreateNameCollision) {
        CommandResult present;
        if (sidecar_created ||
            sidecar_error != "fresh sidecar stable-name collision was rejected before create" ||
            !run_command({"docker", "inspect", foreign_id}, present) || !exited_zero(present)) {
            result.error = "complete receipt collision was not rejected without adoption";
            return finish(false);
        }
        CommandResult remove;
        if (!run_command({"docker", "rm", "-f", foreign_id}, remove) || !exited_zero(remove)) {
            result.error = "complete receipt collision fixture cleanup failed";
            return finish(false);
        }
        if (!generation_receipt_composition_fail(composer) ||
            !generation_receipt_unpublished(composer, false)) {
            result.error =
                "complete receipt collision incorrectly advanced or published receipt phases";
            return finish(false);
        }
        result.semantic_receipt =
            "verified complete-generation receipt was not published after sidecar failure";
        result.error = result.semantic_receipt;
        return finish(true);
    }
    if (!sidecar_created) {
        if (expected_no_publication &&
            (sidecar_failure_point == RecreatedSidecarFailurePoint::CreateSuppressedNoObject ||
             sidecar_failure_point == RecreatedSidecarFailurePoint::UnexpectedDeath)) {
            if (!generation_receipt_composition_fail(composer) ||
                !generation_receipt_unpublished(composer, false)) {
                result.error =
                    "failed sidecar incorrectly advanced or published generation receipt phases";
                return finish(false);
            }
            result.semantic_receipt =
                "verified complete-generation receipt was not published after sidecar failure";
            result.error = result.semantic_receipt;
            return finish(true);
        }
        result.error = "complete receipt sidecar creation failed: " + sidecar_error;
        return finish(false);
    }
    const RecreatedSidecarEvidence sidecar = fixture.recreated_sidecar_evidence();
    if (sidecar.complete_generation || sidecar.state != RecreatedSidecarState::Validated ||
        !sidecar.fresh_probe_pid_start_scoped || !sidecar.shared_non_host_netns ||
        !full_container_id(sidecar.sidecar.id)) {
        result.error = "fresh sidecar phase-3 evidence was incomplete";
        return finish(false);
    }
    const bool inject_second_bracket_mutation =
        sidecar_failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation;
    std::string bracket_error;
    if (!publish_complete_generation_receipt(
            fixture, sidecar, inject_second_bracket_mutation, composer, bracket_error)) {
        if (inject_second_bracket_mutation) fixture.clear_recreated_sidecar_cleanup_fault();
        if (inject_second_bracket_mutation && !generation_receipt_unpublished(composer, true)) {
            result.error = "phase-4 mutation did not leave the complete receipt unpublished";
            return finish(false);
        }
        result.error = bracket_error;
        return finish(expected_no_publication);
    }
    published_receipt = composer.frozen_receipt;
    receipt_published = true;
    if (!callback(composer.frozen_receipt, result.error)) return finish(false);
    if (sidecar_failure_point == RecreatedSidecarFailurePoint::CleanupIdentityMutation)
        fixture.clear_recreated_sidecar_cleanup_fault();
    result.semantic_receipt =
        "verified complete holder-sidecar generation receipt and zero residue";
    result.error = result.semantic_receipt;
    return finish(true);
}

namespace {

constexpr const char* kMountedRotationStage = "358-input-rotation";
constexpr const char* kMountedRotationRole = "exact-input-mounted-sidecar";
// A valid running cleanup observation is exactly: immutable identity inspect,
// mount inspect, and exact-container `/proc/1/ns/net` readlink.
constexpr std::uint64_t kRunningMountedCleanupObservationCommands = 3u;

struct MountedSidecarRotationOwner {
    ExactInputRotationState state = ExactInputRotationState::Ready;
    ExactInputMountedSidecarEvidence old_mounted;
    ExactInputMountedSidecarEvidence fresh_mounted;
    ExactInputMountedSidecarAbsence old_absence;
    ExactInputMountedSidecarAbsence fresh_absence;
    bool fresh_exists = false;
    bool fresh_removal_may_have_mutated = false;
    bool removal_suppression_armed = false;
    bool removal_suppression_consumed = false;
    bool operation_ok = true;
    std::uint32_t old_create_count = 0;
    std::uint32_t old_remove_count = 0;
    std::uint32_t fresh_create_count = 0;
    std::uint32_t fresh_start_count = 0;
    std::uint32_t fresh_remove_count = 0;
    std::uint32_t fresh_remove_suppression_count = 0;
};

struct ExactInputRotationNetworkOrder {
    ExactInputRotationTerminalReceipt* receipt = nullptr;
    std::uint32_t* order = nullptr;
    bool frozen_old_holder_removal_observed = false;
};

static bool record_exact_input_rotation_network_order(void* opaque,
                                                      TopologySettlementEvent event,
                                                      bool removed,
                                                      std::string& error) {
    auto& context = *static_cast<ExactInputRotationNetworkOrder*>(opaque);
    if (context.receipt == nullptr || context.order == nullptr) {
        error = "exact-input rotation network-order context was incomplete";
        return false;
    }
    if (event == TopologySettlementEvent::Holder) {
        // The fresh holder was already removed at order 5.  This is the
        // cleanup phase's frozen confirmation that the distinct old holder was
        // removed; validate it without assigning a second holder order.
        if (!removed || context.frozen_old_holder_removal_observed ||
            context.receipt->network_b_order != 0u || context.receipt->network_a_order != 0u) {
            error = "exact-input rotation did not observe one frozen old-holder removal";
            return false;
        }
        context.frozen_old_holder_removal_observed = true;
        return true;
    }
    if (!context.frozen_old_holder_removal_observed || !removed) {
        error = "exact-input rotation network settlement preceded old-holder removal evidence";
        return false;
    }
    if (event == TopologySettlementEvent::NetworkB) {
        if (context.receipt->network_b_order != 0u || context.receipt->network_a_order != 0u) {
            error = "exact-input rotation network B settlement order was not unique";
            return false;
        }
        context.receipt->network_b_order = ++*context.order;
        return true;
    }
    if (event == TopologySettlementEvent::NetworkA && context.receipt->network_b_order != 0u &&
        context.receipt->network_a_order == 0u) {
        context.receipt->network_a_order = ++*context.order;
        return true;
    }
    error = "exact-input rotation network A settlement order was not exact";
    return false;
}

static bool mounted_rotation_transition(MountedSidecarRotationOwner& owner,
                                        ExactInputRotationState next) {
    bool allowed = false;
    switch (owner.state) {
        case ExactInputRotationState::Ready:
            allowed = next == ExactInputRotationState::OldMountedValidated;
            break;
        case ExactInputRotationState::OldMountedValidated:
            allowed = next == ExactInputRotationState::OldMountedSettled;
            break;
        case ExactInputRotationState::OldMountedSettled:
            allowed = next == ExactInputRotationState::GenerationValidated;
            break;
        case ExactInputRotationState::GenerationValidated:
            allowed = next == ExactInputRotationState::FreshCreateMayHaveMutated;
            break;
        case ExactInputRotationState::FreshCreateMayHaveMutated:
            allowed = next == ExactInputRotationState::FreshMountedValidated ||
                      next == ExactInputRotationState::Unresolved;
            break;
        case ExactInputRotationState::FreshMountedValidated:
            allowed = next == ExactInputRotationState::FreshWriteMayHaveMutated ||
                      next == ExactInputRotationState::Unresolved;
            break;
        case ExactInputRotationState::FreshWriteMayHaveMutated:
            allowed = next == ExactInputRotationState::FreshWriteObserved ||
                      next == ExactInputRotationState::Unresolved;
            break;
        case ExactInputRotationState::FreshWriteObserved:
            allowed = next == ExactInputRotationState::LivePublished ||
                      next == ExactInputRotationState::Unresolved;
            break;
        case ExactInputRotationState::LivePublished:
            allowed = next == ExactInputRotationState::FreshRemovalMayHaveMutated ||
                      next == ExactInputRotationState::Settled;
            break;
        case ExactInputRotationState::Unresolved:
            allowed = next == ExactInputRotationState::FreshRemovalMayHaveMutated ||
                      next == ExactInputRotationState::Settled;
            break;
        case ExactInputRotationState::FreshRemovalMayHaveMutated:
            allowed = next == ExactInputRotationState::Settled;
            break;
        case ExactInputRotationState::Settled:
            break;
    }
    if (!allowed) {
        owner.state = ExactInputRotationState::Unresolved;
        return false;
    }
    owner.state = next;
    return true;
}

static bool capture_rotation_source(ExactInputMountOwner& owner,
                                    ExactInputRotationSourceEvidence& evidence,
                                    std::string& error) {
    fixture_exact_input_file_lease::Diagnostic input_error;
    fixture_private_directory_lease::Diagnostic directory_error;
    struct stat named{};
    struct stat retained{};
    if (!owner.directory.revalidate(directory_error) || !owner.input.revalidate(input_error) ||
        stat(owner.input.path().c_str(), &named) != 0 ||
        fstat(owner.input.descriptor(), &retained) != 0 || named.st_dev != retained.st_dev ||
        named.st_ino != retained.st_ino || named.st_dev != owner.input.identity().device ||
        named.st_ino != owner.input.identity().inode ||
        named.st_uid != owner.input.identity().uid || named.st_gid != owner.input.identity().gid ||
        static_cast<std::uint64_t>(named.st_size) != owner.input.identity().size ||
        static_cast<std::uint64_t>(named.st_nlink) != owner.input.identity().links ||
        !S_ISREG(named.st_mode) || (named.st_mode & 07777) != 0600) {
        error = "canonical exact source lease revalidation failed";
        return false;
    }
    evidence = {};
    evidence.path = owner.input.path();
    evidence.bytes = owner.bytes;
    evidence.device = named.st_dev;
    evidence.inode = named.st_ino;
    evidence.mode = named.st_mode;
    evidence.uid = named.st_uid;
    evidence.gid = named.st_gid;
    evidence.size = named.st_size;
    evidence.links = named.st_nlink;
    evidence.mtime_seconds = named.st_mtim.tv_sec;
    evidence.mtime_nanoseconds = named.st_mtim.tv_nsec;
    evidence.ctime_seconds = named.st_ctim.tv_sec;
    evidence.ctime_nanoseconds = named.st_ctim.tv_nsec;
    evidence.regular_0600 = true;
    evidence.exact_bytes_revalidated = true;
    evidence.retained_ofd_revalidated = true;
    return true;
}

static bool mounted_name_and_labels_absent(const std::string& token,
                                           const std::string& name,
                                           const std::string& generation,
                                           std::string& error) {
    CommandResult result;
    if (!run_command({"docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/" + name + "$"},
                     result) ||
        !exited_zero(result) || !trim(result.output).empty() ||
        !run_command({"docker",
                      "ps",
                      "-aq",
                      "--no-trunc",
                      "--filter",
                      "label=rut.token=" + token,
                      "--filter",
                      std::string("label=rut.role=") + kMountedRotationRole,
                      "--filter",
                      "label=rut.generation=" + generation},
                     result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "mounted sidecar stable name or token/role/generation was not empty";
        return false;
    }
    return true;
}

static bool validate_stopped_mount_record(const std::string& record,
                                          const std::string& id,
                                          const std::string& name,
                                          const std::string& user,
                                          const std::string& network_mode,
                                          const std::string& source,
                                          std::string& error) {
    const size_t first = record.find('#');
    const size_t second = first == std::string::npos ? first : record.find('#', first + 1u);
    std::vector<std::string> prefix;
    std::vector<ParsedMount> requested;
    std::vector<ParsedMount> realized;
    size_t count = 0;
    if (first == std::string::npos || second == std::string::npos ||
        !split_exact(record.substr(0, first), '|', 5u, prefix) || prefix[0] != id ||
        prefix[1] != "/" + name || prefix[2] != user || prefix[3] != network_mode ||
        !decimal_size(prefix[4], count) || count != 1u ||
        !split_mount_list(record.substr(first + 1u, second - first - 1u), true, requested, error) ||
        !split_mount_list(record.substr(second + 1u), false, realized, error) ||
        requested.size() != 1u || realized.size() != 1u) {
        if (error.empty()) error = "stopped mounted-sidecar mount envelope was not exact";
        return false;
    }
    const ParsedMount& requested_mount = requested.front();
    const ParsedMount& realized_mount = realized.front();
    return requested_mount.type == "bind" && requested_mount.source == source &&
           requested_mount.destination == kExactInputMountDestination &&
           requested_mount.read_only && requested_mount.propagation == "rprivate" &&
           realized_mount.type == "bind" && realized_mount.source == source &&
           realized_mount.destination == kExactInputMountDestination && realized_mount.read_only &&
           realized_mount.propagation == "rprivate";
}

static bool inspect_rotation_mounted(const std::string& id,
                                     const std::string& token,
                                     const std::string& name,
                                     const std::string& generation,
                                     const std::string& holder_id,
                                     const ExactInputRotationSourceEvidence& source,
                                     bool running,
                                     bool mutate_mount_observation,
                                     ExactInputMountedSidecarEvidence& evidence,
                                     ParsedMountInspect* parsed_mount,
                                     std::string& error) {
    const std::string format =
        "{{.Id}}|{{.Name}}|{{index .Config.Labels \"rut.stage\"}}|{{index .Config.Labels "
        "\"rut.token\"}}|{{index .Config.Labels \"rut.role\"}}|{{index .Config.Labels "
        "\"rut.generation\"}}|{{.Config.Image}}|{{.Image}}|{{.HostConfig.NetworkMode}}|"
        "{{.Config.User}}|{{.Path}}|{{json .Args}}|{{.State.Running}}|{{.State.Pid}}|"
        "{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|"
        "{{json .HostConfig.SecurityOpt}}|{{.HostConfig.RestartPolicy.Name}}|"
        "{{json .HostConfig.PortBindings}}|{{json .Config.ExposedPorts}}|"
        "{{json .NetworkSettings.Ports}}";
    CommandResult identity_result;
    if (!run_command({"docker", "inspect", "-f", format, id}, identity_result) ||
        !exited_zero(identity_result)) {
        error = "mounted-sidecar exact full-ID identity inspection failed";
        return false;
    }
    std::vector<std::string> fields;
    if (!split_exact(trim(identity_result.output), '|', 21u, fields)) {
        error = "mounted-sidecar identity record was malformed";
        return false;
    }
    size_t pid_value = 0;
    if (!decimal_size(fields[13], pid_value) || fields[0] != id || fields[1] != "/" + name ||
        fields[2] != kMountedRotationStage || fields[3] != token ||
        fields[4] != kMountedRotationRole || fields[5] != generation ||
        fields[6] != RUT_PINNED_NGINX_IMAGE || !sha256_identity(fields[7]) ||
        fields[8] != "container:" + holder_id ||
        fields[9] != std::to_string(source.uid) + ":" + std::to_string(source.gid) ||
        fields[10] != "/bin/sleep" || fields[11] != "[\"infinity\"]" ||
        fields[12] != (running ? "true" : "false") ||
        (running ? pid_value <= 1u : pid_value != 0u) || fields[14] != "true" ||
        fields[15] != "[\"ALL\"]" || fields[16] != "[\"no-new-privileges\"]" ||
        fields[17] != "no" || !no_published_ports(fields[18], fields[20])) {
        error = "mounted-sidecar immutable labels/config/security were not exact";
        return false;
    }
    const std::string mount_format =
        "{{.Id}}|{{.Name}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{len "
        ".HostConfig.Mounts}}#{{range .HostConfig.Mounts}}{{.Type}}|{{.Source}}|{{.Target}}|"
        "{{.ReadOnly}}|{{.BindOptions.Propagation}};{{end}}#{{range .Mounts}}{{.Type}}|"
        "{{.Source}}|{{.Destination}}|{{.Mode}}|{{.RW}}|{{.Propagation}};{{end}}";
    CommandResult mount_result;
    if (!run_command({"docker", "inspect", "-f", mount_format, id}, mount_result) ||
        !exited_zero(mount_result)) {
        error = "mounted-sidecar exact mount inspection failed";
        return false;
    }
    std::string record = trim(mount_result.output);
    if (mutate_mount_observation) {
        const size_t at = record.find(source.path);
        if (at == std::string::npos) {
            error = "mounted-sidecar mutation seam lacked observed source";
            return false;
        }
        record.replace(at, source.path.size(), "/tmp/rut358-mutated-source");
    }
    ParsedMountInspect parsed;
    const std::string user = std::to_string(source.uid) + ":" + std::to_string(source.gid);
    if (running) {
        if (!validate_mount_inspect_record(
                record, id, name, user, "container:" + holder_id, source.path, parsed, error))
            return false;
    } else if (!validate_stopped_mount_record(
                   record, id, name, user, "container:" + holder_id, source.path, error)) {
        return false;
    }
    evidence = {};
    evidence.token = token;
    evidence.stage = kMountedRotationStage;
    evidence.role = kMountedRotationRole;
    evidence.generation = generation;
    evidence.name = name;
    evidence.id = id;
    evidence.image_reference = fields[6];
    evidence.image_id = fields[7];
    evidence.network_mode = fields[8];
    evidence.user = fields[9];
    evidence.path = fields[10];
    evidence.arguments_json = fields[11];
    evidence.source_path = source.path;
    evidence.running = running;
    evidence.read_only_root = true;
    evidence.capability_drop_all = true;
    evidence.no_new_privileges = true;
    evidence.restart_no = true;
    evidence.no_published_ports = true;
    evidence.requested_mount_exact = true;
    // Docker materializes the configured bind in `.Mounts` before start.  This is
    // stopped cleanup authority, not evidence of a live process or namespace.
    evidence.realized_mount_exact = true;
    evidence.no_mount_shadowing = true;
    if (running) {
        evidence.pid = static_cast<pid_t>(pid_value);
        ProcIdentity process{};
        struct stat mount_namespace{};
        struct stat host_mount_namespace{};
        if (!proc_identity(evidence.pid, process, false) || process.start == 0u ||
            !container_netns_inode(id, evidence.network_netns) || evidence.network_netns == 0u ||
            stat(("/proc/" + std::to_string(evidence.pid) + "/ns/mnt").c_str(), &mount_namespace) !=
                0 ||
            mount_namespace.st_ino == 0u ||
            !proc_credentials_exact(evidence.pid, source.uid, source.gid)) {
            error = "mounted-sidecar PID/start/network/mount/credential authority was not exact";
            return false;
        }
        evidence.start = process.start;
        evidence.mount_netns = mount_namespace.st_ino;
        const bool host_visible = stat("/proc/self/ns/mnt", &host_mount_namespace) == 0;
        evidence.nonhost_mount_netns =
            !host_visible || host_mount_namespace.st_ino != mount_namespace.st_ino;
        if (!evidence.nonhost_mount_netns) {
            error = "mounted-sidecar mount namespace was the host namespace";
            return false;
        }
    }
    if (parsed_mount != nullptr) *parsed_mount = parsed;
    return true;
}

static bool create_rotation_mounted(const std::string& token,
                                    const std::string& generation,
                                    const std::string& holder_id,
                                    const ExactInputRotationSourceEvidence& source,
                                    bool reported_timeout,
                                    ExactInputMountedSidecarEvidence& mounted,
                                    ParsedMountInspect& parsed_mount,
                                    std::uint32_t& create_count,
                                    std::uint32_t& start_count,
                                    std::string& error) {
    const std::string name = "rut358-input-" + token;
    if (!mounted_name_and_labels_absent(token, name, generation, error)) return false;
    const std::string credentials = std::to_string(source.uid) + ":" + std::to_string(source.gid);
    const std::string mount = "type=bind,src=" + source.path +
                              ",dst=" + kExactInputMountDestination +
                              ",readonly,bind-propagation=rprivate";
    const std::vector<std::string> create_argv = {"docker",
                                                  "create",
                                                  "--pull=never",
                                                  "--name",
                                                  name,
                                                  "--label",
                                                  std::string("rut.stage=") + kMountedRotationStage,
                                                  "--label",
                                                  "rut.token=" + token,
                                                  "--label",
                                                  std::string("rut.role=") + kMountedRotationRole,
                                                  "--label",
                                                  "rut.generation=" + generation,
                                                  "--network",
                                                  "container:" + holder_id,
                                                  "--user",
                                                  credentials,
                                                  "--read-only",
                                                  "--cap-drop",
                                                  "ALL",
                                                  "--security-opt",
                                                  "no-new-privileges",
                                                  "--restart",
                                                  "no",
                                                  "--mount",
                                                  mount,
                                                  "--entrypoint",
                                                  "/bin/sleep",
                                                  RUT_PINNED_NGINX_IMAGE,
                                                  "infinity"};
    CommandResult created;
    ++create_count;
    const bool create_ok = run_command(create_argv, created, 30000, reported_timeout);
    if ((!create_ok || !exited_zero(created)) && !created.timed_out) {
        error = "mounted-sidecar exact create failed";
        return false;
    }
    const std::string id = trim(created.output);
    if (!full_container_id(id)) {
        error = "mounted-sidecar create did not return one exact full ID";
        return false;
    }
    // Publish exact-ID custody before any fallible inspection.  A create that
    // returned this full ID may have mutated Docker even when stopped validation
    // subsequently fails, so failure cleanup must never fall back to name-only
    // discovery or forget the object.
    mounted = {};
    mounted.token = token;
    mounted.stage = kMountedRotationStage;
    mounted.role = kMountedRotationRole;
    mounted.generation = generation;
    mounted.name = name;
    mounted.id = id;
    mounted.image_reference = RUT_PINNED_NGINX_IMAGE;
    mounted.network_mode = "container:" + holder_id;
    mounted.user = credentials;
    mounted.path = "/bin/sleep";
    mounted.arguments_json = "[\"infinity\"]";
    mounted.source_path = source.path;
    mounted.pid = -1;
    ExactInputMountedSidecarEvidence stopped;
    if (!inspect_rotation_mounted(id,
                                  token,
                                  name,
                                  generation,
                                  holder_id,
                                  source,
                                  false,
                                  false,
                                  stopped,
                                  nullptr,
                                  error)) {
        error = "mounted-sidecar stopped create authority failed: " + error;
        return false;
    }
    CommandResult started;
    ++start_count;
    if (!run_command({"docker", "start", id}, started) || !exited_zero(started) ||
        trim(started.output) != id) {
        error = "mounted-sidecar exact full-ID start failed";
        return false;
    }
    if (!inspect_rotation_mounted(id,
                                  token,
                                  name,
                                  generation,
                                  holder_id,
                                  source,
                                  true,
                                  false,
                                  mounted,
                                  &parsed_mount,
                                  error))
        return false;
    return true;
}

static bool capture_rotation_read(ExactInputMountOwner& root,
                                  const ExactInputMountedSidecarEvidence& mounted,
                                  ExactInputRotationFailurePoint failure_point,
                                  ExactInputRotationReadEvidence& read,
                                  std::string& error) {
    read = {};
    read.attempted = true;
    const std::int64_t now = exact_read_monotonic_ns();
    constexpr std::int64_t kReadBudgetNs = 15000000000LL;
    if (now <= 0 || now > std::numeric_limits<std::int64_t>::max() - kReadBudgetNs) {
        error = "fresh mounted exact read deadline could not be formed";
        read.outcome = ExactInputReadOutcome::DeadlineExceeded;
        read.terminal_frozen = true;
        return false;
    }
    read.caller_deadline_recorded = true;
    read.final_deadline_nanoseconds = now + kReadBudgetNs;
    // This scope caps every run_command issued by both source and target
    // brackets.  It ends before rotation cleanup starts, so an expired read
    // deadline cannot prevent authoritative resource settlement.
    CommandDeadlineScope read_deadline_scope(read.final_deadline_nanoseconds);
    const auto before_deadline = [&]() {
        return exact_read_monotonic_ns() > 0 &&
               exact_read_monotonic_ns() < read.final_deadline_nanoseconds;
    };
    const auto freeze = [&](ExactInputReadOutcome outcome, std::string message) {
        read.outcome = outcome;
        read.terminal_frozen = true;
        error = std::move(message);
        return false;
    };
    if (!before_deadline() || !capture_rotation_source(root, read.source_before, error))
        return freeze(
            ExactInputReadOutcome::SourceRevalidationFailed,
            error.empty() ? std::string("fresh read source-before bracket failed") : error);

    const std::string prefix = "container:";
    if (mounted.network_mode.rfind(prefix, 0) != 0 || !full_container_id(mounted.id))
        return freeze(ExactInputReadOutcome::ContainerIdentityFailed,
                      "fresh read target authority was not an exact full-ID container tuple");
    ParsedMountInspect before_mount;
    if (!before_deadline() || !inspect_rotation_mounted(mounted.id,
                                                        mounted.token,
                                                        mounted.name,
                                                        mounted.generation,
                                                        mounted.network_mode.substr(prefix.size()),
                                                        read.source_before,
                                                        true,
                                                        false,
                                                        read.target_before,
                                                        &before_mount,
                                                        error))
        return freeze(
            ExactInputReadOutcome::ContainerIdentityFailed,
            error.empty() ? std::string("fresh read target-before bracket failed") : error);

    const std::string credentials =
        std::to_string(read.source_before.uid) + ":" + std::to_string(read.source_before.gid);
    if (credentials != mounted.user)
        return freeze(ExactInputReadOutcome::ContainerIdentityFailed,
                      "fresh read target credentials differed from the mounted authority");
    ExactInputReadObservation command;
    if (failure_point == ExactInputRotationFailurePoint::FreshReadTimeout) {
        // This is a test-only uncertain-subtree seam.  The normal path below
        // is always the exact docker exec /bin/cat command required by the
        // observation contract; this command intentionally keeps the exec
        // subtree open so the caller-owned deadline must fail closed.
        command.command_argv = {"docker",
                                "exec",
                                "--user",
                                credentials,
                                mounted.id,
                                "/bin/sh",
                                "-c",
                                "cat /etc/nginx/nginx.conf; sleep 60"};
    } else {
        command.command_argv = {"docker",
                                "exec",
                                "--user",
                                credentials,
                                mounted.id,
                                "/bin/cat",
                                kExactInputMountDestination};
    }
    command.attempted = true;
    const std::size_t stdout_limit = root.bytes.size() + 1u;
    ExactReadCommandResult command_result;
    (void)run_exact_read_command_until(
        command.command_argv, stdout_limit, read.final_deadline_nanoseconds, command_result);
    copy_exact_read_result(command_result, command);
    finalize_rotation_read_command(command, root.bytes.size());
    read.command = command;
    if (before_deadline()) {
        ParsedMountInspect after_mount;
        if (!capture_rotation_source(root, read.source_after, error) ||
            !inspect_rotation_mounted(mounted.id,
                                      mounted.token,
                                      mounted.name,
                                      mounted.generation,
                                      mounted.network_mode.substr(prefix.size()),
                                      read.source_after,
                                      true,
                                      false,
                                      read.target_after,
                                      &after_mount,
                                      error))
            return freeze(ExactInputReadOutcome::ContainerIdentityFailed,
                          error.empty() ? std::string("fresh read after bracket failed") : error);
        read.source_brackets_equal =
            exact_input_rotation_source_equal(read.source_before, read.source_after);
        read.target_brackets_equal =
            exact_input_mounted_equal(read.target_before, read.target_after);
        if (!read.source_brackets_equal || !read.target_brackets_equal)
            return freeze(ExactInputReadOutcome::ContainerIdentityFailed,
                          "fresh read source/target brackets changed across command");
    } else {
        read.outcome = ExactInputReadOutcome::DeadlineExceeded;
        read.terminal_frozen = true;
        error = "fresh mounted exact read exceeded its caller-owned deadline";
        return false;
    }
    read.outcome = classify_exact_read(command_result, root.bytes);
    read.terminal_frozen = true;
    if (read.outcome != ExactInputReadOutcome::Complete) {
        error = "fresh mounted exact read command failed fail-closed";
        return false;
    }
    error.clear();
    return true;
}

static void fill_rotation_write_bracket(const ExactInputRotationSourceEvidence& source,
                                        const ExactInputMountedSidecarEvidence& target,
                                        ExactInputRotationWriteBracket& bracket) {
    bracket = {};
    bracket.source_revalidated = source.regular_0600 && source.exact_bytes_revalidated;
    bracket.source_bytes_revalidated = source.exact_bytes_revalidated;
    bracket.retained_ofd_revalidated = source.retained_ofd_revalidated;
    bracket.target_revalidated =
        full_container_id(target.id) && target.running && target.requested_mount_exact &&
        target.realized_mount_exact && target.no_mount_shadowing &&
        target.user == std::to_string(source.uid) + ":" + std::to_string(source.gid);
    bracket.source = source;
    bracket.target = target;
}

static bool capture_rotation_write_bracket(ExactInputMountOwner& root,
                                           const ExactInputMountedSidecarEvidence& mounted,
                                           ExactInputRotationWriteBracket& bracket,
                                           bool mutate,
                                           std::string& error) {
    ExactInputRotationSourceEvidence source;
    ExactInputMountedSidecarEvidence target;
    if (!capture_rotation_source(root, source, error)) return false;
    ParsedMountInspect parsed;
    const std::string prefix = "container:";
    if (mounted.network_mode.rfind(prefix, 0) != 0 ||
        !inspect_rotation_mounted(mounted.id,
                                  mounted.token,
                                  mounted.name,
                                  mounted.generation,
                                  mounted.network_mode.substr(prefix.size()),
                                  source,
                                  true,
                                  false,
                                  target,
                                  &parsed,
                                  error))
        return false;
    fill_rotation_write_bracket(source, target, bracket);
    if (mutate) {
        // Narrow evidence-only seam: preserve the real Docker object and make
        // one bracket disagree, forcing fail-closed publication.
        ++bracket.source.inode;
    }
    return true;
}

static void copy_rotation_write_command(const ExactReadCommandResult& result,
                                        ExactInputReadObservation& observation) {
    observation = {};
    observation.attempted = true;
    copy_exact_read_result(result, observation);
    observation.terminal_frozen = true;
}

static bool rotation_write_command_contract(const ExactInputReadObservation& command,
                                            const std::vector<std::string>& argv,
                                            int expected_status,
                                            const std::string& expected_stdout,
                                            const std::string& expected_stderr) {
    return command.attempted && command.terminal_frozen && command.command_started &&
           command.actual_exec_observed && command.stdout_eof && command.stderr_eof &&
           command.child_reaped && command.wait_status_valid && WIFEXITED(command.wait_status) &&
           WEXITSTATUS(command.wait_status) == expected_status && command.process_group_owned &&
           command.process_group_gone && command.group_echild_observed && command.pidfd_opened &&
           command.pidfd_identity_verified && command.pidfd_closed_after_group_gone &&
           command.supervisor_session_verified && command.supervisor_subreaper_verified &&
           command.subtree_confinement_installed && command.final_deadline_recorded &&
           command.cleanup_completed_before_final_deadline && !command.deadline_exceeded &&
           !command.output_overflow && command.stdout_read_errno == 0 &&
           command.stderr_read_errno == 0 &&
           command.launch_failure_stage == ExactInputReadLaunchStage::None &&
           command.launch_errno == 0 && command.command_argv == argv &&
           command.resolved_executable == resolve_exact_read_executable("docker") &&
           command.stdout_bytes == expected_stdout && command.stderr_bytes == expected_stderr;
}

static bool capture_rotation_write_refusal(ExactInputMountOwner& root,
                                           const ExactInputMountedSidecarEvidence& mounted,
                                           ExactInputRotationFailurePoint failure_point,
                                           ExactInputRotationWriteRefusalEvidence& write,
                                           std::string& error) {
    write = {};
    write.attempted = true;
    write.expected_target_stderr =
        "dd: failed to open '/etc/nginx/nginx.conf': Read-only file system\n";
    const std::int64_t now = exact_read_monotonic_ns();
    // This focused fault seam uses a bounded eight-second caller budget. The
    // same absolute scope still spans every bracket and the command, while
    // leaving the aggregate CTest target room for the existing rotations.
    constexpr std::int64_t kWriteBudgetNs = 8000000000LL;
    if (now <= 0 || now > std::numeric_limits<std::int64_t>::max() - kWriteBudgetNs) {
        write.outcome = ExactInputWriteRefusalOutcome::DeadlineExceeded;
        write.terminal_frozen = true;
        error = "fresh mounted exact write-refusal deadline could not be formed";
        return false;
    }
    write.caller_deadline_recorded = true;
    write.final_deadline_nanoseconds = now + kWriteBudgetNs;
    CommandDeadlineScope write_deadline_scope(write.final_deadline_nanoseconds);
    const std::string credentials =
        std::to_string(root.input.identity().uid) + ":" + std::to_string(root.input.identity().gid);
    write.credentials = credentials;
    const auto before_deadline = [&]() {
        const std::int64_t current = exact_read_monotonic_ns();
        return current > 0 && current < write.final_deadline_nanoseconds;
    };
    const auto freeze = [&](ExactInputWriteRefusalOutcome outcome, const std::string& message) {
        write.outcome = outcome;
        write.terminal_frozen = true;
        write.diagnostic = {ExactInputMountPhase::WriteRefusalObservation, 0, message};
        error = message;
        return false;
    };
    const bool initial_mutation =
        failure_point == ExactInputRotationFailurePoint::FreshWriteInitialBracketMutation;
    if (!before_deadline() || !capture_rotation_write_bracket(
                                  root, mounted, write.initial_bracket, initial_mutation, error))
        return freeze(ExactInputWriteRefusalOutcome::SourceRevalidationFailed,
                      error.empty() ? "fresh write initial bracket failed" : error);

    std::vector<std::string> control_argv = {"docker",
                                             "exec",
                                             "--env",
                                             "LC_ALL=C",
                                             "--user",
                                             credentials,
                                             mounted.id,
                                             "/usr/bin/dd",
                                             "if=/dev/zero",
                                             "of=/dev/null",
                                             "bs=1",
                                             "count=1",
                                             "conv=notrunc",
                                             "status=none"};
    if (failure_point == ExactInputRotationFailurePoint::FreshWriteTimeout)
        control_argv = {"docker",
                        "exec",
                        "--env",
                        "LC_ALL=C",
                        "--user",
                        credentials,
                        mounted.id,
                        "/bin/sh",
                        "-c",
                        "sleep 60"};
    ExactReadCommandResult control_result;
    (void)run_exact_read_command_until(
        control_argv, 1u, write.final_deadline_nanoseconds, control_result);
    copy_rotation_write_command(control_result, write.control);
    write.control.command_argv = control_argv;
    write.control.outcome = classify_exact_read(control_result, {});
    if (!rotation_write_command_contract(write.control, control_argv, 0, {}, {}))
        return freeze(failure_point == ExactInputRotationFailurePoint::FreshWriteTimeout
                          ? ExactInputWriteRefusalOutcome::DeadlineExceeded
                          : ExactInputWriteRefusalOutcome::ControlExitNonzero,
                      "fresh write positive control failed its exact supervisor contract");
    const bool middle_mutation =
        failure_point == ExactInputRotationFailurePoint::FreshWriteMiddleBracketMutation;
    if (!before_deadline() ||
        !capture_rotation_write_bracket(
            root, mounted, write.middle_bracket, middle_mutation, error) ||
        !rotation_write_bracket_equal_public(write.initial_bracket, write.middle_bracket))
        return freeze(ExactInputWriteRefusalOutcome::SourceRevalidationFailed,
                      error.empty() ? "fresh write middle bracket changed" : error);

    std::vector<std::string> target_argv = {"docker",
                                            "exec",
                                            "--env",
                                            "LC_ALL=C",
                                            "--user",
                                            credentials,
                                            mounted.id,
                                            "/usr/bin/dd",
                                            "if=/etc/nginx/nginx.conf",
                                            "of=/etc/nginx/nginx.conf",
                                            "bs=1",
                                            "count=1",
                                            "conv=notrunc",
                                            "status=none"};
    if (failure_point == ExactInputRotationFailurePoint::FreshWriteTargetUnexpectedSuccess)
        target_argv = {
            "docker", "exec", "--env", "LC_ALL=C", "--user", credentials, mounted.id, "/bin/true"};
    else if (failure_point == ExactInputRotationFailurePoint::FreshWriteTargetWrongStderr)
        target_argv = {"docker",
                       "exec",
                       "--env",
                       "LC_ALL=C",
                       "--user",
                       credentials,
                       mounted.id,
                       "/bin/sh",
                       "-c",
                       "printf wrong >&2; exit 1"};
    ExactReadCommandResult target_result;
    (void)run_exact_read_command_until(
        target_argv, 1u, write.final_deadline_nanoseconds, target_result);
    copy_rotation_write_command(target_result, write.target);
    write.target.command_argv = target_argv;
    write.target.outcome = classify_exact_read(target_result, {});
    const bool final_mutation =
        failure_point == ExactInputRotationFailurePoint::FreshWriteFinalBracketMutation;
    std::string final_error;
    const bool final_ok =
        before_deadline() && capture_rotation_write_bracket(
                                 root, mounted, write.final_bracket, final_mutation, final_error);
    if (!final_ok && (write.target.outcome == ExactInputReadOutcome::ExitNonzero ||
                      write.target.outcome == ExactInputReadOutcome::Complete))
        return freeze(ExactInputWriteRefusalOutcome::SourceRevalidationFailed,
                      final_error.empty() ? "fresh write final bracket failed" : final_error);
    const bool target_refused = rotation_write_command_contract(
        write.target, target_argv, 1, {}, write.expected_target_stderr);
    if (!target_refused)
        return freeze(
            failure_point == ExactInputRotationFailurePoint::FreshWriteTargetUnexpectedSuccess
                ? ExactInputWriteRefusalOutcome::TargetUnexpectedSuccess
            : failure_point == ExactInputRotationFailurePoint::FreshWriteTargetWrongStderr
                ? ExactInputWriteRefusalOutcome::TargetStderrMismatch
                : ExactInputWriteRefusalOutcome::TargetWrongExit,
            "fresh write target did not prove exact read-only refusal");
    if (!final_ok ||
        !rotation_write_bracket_equal_public(write.initial_bracket, write.final_bracket))
        return freeze(ExactInputWriteRefusalOutcome::SourceRevalidationFailed,
                      final_error.empty() ? "fresh write final bracket changed" : final_error);
    write.outcome = ExactInputWriteRefusalOutcome::Complete;
    write.terminal_frozen = true;
    error.clear();
    return true;
}

static bool mounted_cleanup_identity_matches(const ExactInputMountedSidecarEvidence& current,
                                             const ExactInputMountedSidecarEvidence& recorded) {
    const bool immutable_exact =
        current.token == recorded.token && current.stage == recorded.stage &&
        current.role == recorded.role && current.generation == recorded.generation &&
        current.name == recorded.name && current.id == recorded.id &&
        current.image_reference == recorded.image_reference &&
        current.network_mode == recorded.network_mode && current.user == recorded.user &&
        current.path == recorded.path && current.arguments_json == recorded.arguments_json &&
        current.source_path == recorded.source_path && current.read_only_root &&
        current.capability_drop_all && current.no_new_privileges && current.restart_no &&
        current.no_published_ports && current.requested_mount_exact &&
        current.realized_mount_exact && current.no_mount_shadowing;
    if (!immutable_exact || (!recorded.image_id.empty() && current.image_id != recorded.image_id))
        return false;
    return !recorded.running || exact_input_mounted_equal(current, recorded);
}

static bool prove_rotation_mounted_absent(const ExactInputMountedSidecarEvidence& mounted,
                                          ExactInputMountedSidecarAbsence& absence,
                                          std::string& error) {
    CommandResult result;
    if (!run_command({"docker", "inspect", mounted.id}, result) || exited_zero(result) ||
        !mounted_name_and_labels_absent(mounted.token, mounted.name, mounted.generation, error)) {
        if (error.empty()) error = "mounted-sidecar ID/name/labels remained after removal";
        return false;
    }
    ProcIdentity process{};
    if (proc_identity(mounted.pid, process, false) && process.start == mounted.start) {
        error = "mounted-sidecar PID/start remained after removal";
        return false;
    }
    absence = {mounted.id, mounted.name, mounted.pid, mounted.start, true, true, true, true};
    return true;
}

static bool remove_rotation_mounted(MountedSidecarRotationOwner& owner,
                                    bool old_generation,
                                    bool allow_suppression,
                                    std::string& error) {
    ExactInputMountedSidecarEvidence& mounted =
        old_generation ? owner.old_mounted : owner.fresh_mounted;
    ExactInputMountedSidecarAbsence& absence =
        old_generation ? owner.old_absence : owner.fresh_absence;
    if (!old_generation && owner.state == ExactInputRotationState::Settled) return true;
    ExactInputMountedSidecarEvidence current;
    ParsedMountInspect parsed;
    ExactInputRotationSourceEvidence cleanup_source;
    cleanup_source.path = mounted.source_path;
    const size_t credential_separator = mounted.user.find(':');
    if (credential_separator == std::string::npos) {
        error = "mounted-sidecar cleanup credentials were malformed";
        return false;
    }
    cleanup_source.uid =
        strtoull(mounted.user.substr(0, credential_separator).c_str(), nullptr, 10);
    cleanup_source.gid =
        strtoull(mounted.user.substr(credential_separator + 1u).c_str(), nullptr, 10);
    const std::string holder_id = mounted.network_mode.substr(std::string("container:").size());
    std::string running_error;
    bool inspected = inspect_rotation_mounted(mounted.id,
                                              mounted.token,
                                              mounted.name,
                                              mounted.generation,
                                              holder_id,
                                              cleanup_source,
                                              true,
                                              false,
                                              current,
                                              &parsed,
                                              running_error);
    if (!inspected) {
        std::string stopped_error;
        inspected = inspect_rotation_mounted(mounted.id,
                                             mounted.token,
                                             mounted.name,
                                             mounted.generation,
                                             holder_id,
                                             cleanup_source,
                                             false,
                                             false,
                                             current,
                                             &parsed,
                                             stopped_error);
        if (!inspected)
            error =
                "mounted-sidecar cleanup exact-ID inspection failed (running: " + running_error +
                "; stopped: " + stopped_error + ")";
    }
    if (!inspected || !mounted_cleanup_identity_matches(current, mounted)) {
        if (error.empty()) error = "mounted-sidecar cleanup authority changed";
        owner.state = ExactInputRotationState::Unresolved;
        return false;
    }
    if (!old_generation && allow_suppression && owner.removal_suppression_armed &&
        !owner.removal_suppression_consumed) {
        owner.removal_suppression_armed = false;
        owner.removal_suppression_consumed = true;
        owner.fresh_removal_may_have_mutated = true;
        owner.operation_ok = false;
        ++owner.fresh_remove_suppression_count;
        (void)mounted_rotation_transition(owner,
                                          ExactInputRotationState::FreshRemovalMayHaveMutated);
        error = "injected fresh mounted-sidecar removal suppression";
        return false;
    }
    CommandResult removed;
    if (!run_command({"docker", "rm", "-f", mounted.id}, removed) || !exited_zero(removed)) {
        error = "mounted-sidecar exact full-ID removal failed";
        return false;
    }
    if (old_generation)
        ++owner.old_remove_count;
    else
        ++owner.fresh_remove_count;
    if (!prove_rotation_mounted_absent(mounted, absence, error)) return false;
    if (old_generation)
        (void)mounted_rotation_transition(owner, ExactInputRotationState::OldMountedSettled);
    else {
        owner.fresh_exists = false;
        owner.fresh_removal_may_have_mutated = false;
        (void)mounted_rotation_transition(owner, ExactInputRotationState::Settled);
    }
    return true;
}

}  // namespace

RunResult run_with_exact_input_rotation(const std::string& bytes,
                                        ExactInputRotationFailurePoint failure_point,
                                        const ExactInputRotationCallback& callback,
                                        ExactInputRotationTerminalReceipt& terminal_receipt) {
    RunResult result;
    terminal_receipt = {};
    std::string token;
    if (bytes.empty() || bytes.size() > fixture_exact_input_file_lease::kMaximumInputBytes ||
        !callback || !high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = "exact-input rotation arguments or entropy were unavailable";
        return result;
    }
    ExactInputMountOwner root(token, bytes);
    const HeldNamespaceSidecarSnapshot preserved_registered_sidecar = root.registered_sidecar;
    const ParsedMountInspect preserved_registered_mount = root.registered_mount;
    MountedSidecarRotationOwner mounted;
    GenerationReceiptCompositionOwner composer;
    ExactInputRotationLiveEvidence live;
    bool directory_acquired = false;
    bool input_acquired = false;
    bool callback_ran = false;
    std::uint32_t order = 0;
    const auto require_mounted_settled = [&](const char* consumer, std::string& gate_error) {
        if (mounted.state == ExactInputRotationState::Settled && mounted.fresh_absence.id_absent &&
            mounted.fresh_absence.name_absent &&
            mounted.fresh_absence.token_role_generation_absent &&
            mounted.fresh_absence.process_absent)
            return true;
        gate_error = std::string("fresh mounted-sidecar unsettled; blocked ") + consumer;
        return false;
    };
    const auto settle_source = [&]() {
        bool ok = true;
        fixture_exact_input_file_lease::Diagnostic input_error;
        fixture_private_directory_lease::Diagnostic directory_error;
        if (input_acquired && root.input.active()) ok = root.input.cleanup(input_error) && ok;
        if (directory_acquired &&
            root.directory.state() != fixture_private_directory_lease::State::Removed)
            ok = root.directory.settle(directory_error) && ok;
        return ok;
    };
    const auto finish_failure = [&](bool semantic_success) {
        std::string cleanup_error;
        bool cleanup_ok = true;
        if (!mounted.fresh_mounted.id.empty() && !mounted.fresh_absence.id_absent) {
            mounted.removal_suppression_armed = false;
            cleanup_ok =
                remove_rotation_mounted(mounted, false, false, cleanup_error) && cleanup_ok;
        }
        if (!mounted.old_mounted.id.empty() && !mounted.old_absence.id_absent)
            cleanup_ok = remove_rotation_mounted(mounted, true, false, cleanup_error) && cleanup_ok;
        if (!cleanup_ok) {
            result.error += result.error.empty() ? cleanup_error : "; " + cleanup_error;
            result.cleanup_complete = false;
            result.residue_free = false;
            return result;
        }
        std::string sidecar_error;
        cleanup_ok = root.fixture.cleanup_recreated_sidecar(sidecar_error) && cleanup_ok;
        const CleanupPhaseResult old_sidecar = root.fixture.cleanup_sidecar_phase(sidecar_error);
        cleanup_ok = old_sidecar.settled && cleanup_ok;
        cleanup_ok = settle_source() && cleanup_ok;
        cleanup_ok = root.fixture.cleanup(cleanup_error) && cleanup_ok;
        std::string audit_error;
        const bool residue_free = audit_zero_residue(token,
                                                     root.fixture.network_a().name,
                                                     root.fixture.network_b().name,
                                                     root.fixture.holder_name(),
                                                     audit_error);
        root.settled = cleanup_ok && residue_free;
        result.cleanup_complete = cleanup_ok;
        result.residue_free = residue_free;
        if (!cleanup_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += cleanup_error;
        }
        if (!audit_error.empty()) {
            if (!result.error.empty()) result.error += "; ";
            result.error += audit_error;
        }
        result.success = semantic_success && cleanup_ok && residue_free;
        return result;
    };

    std::string error;
    if (!docker_user_namespace_preflight(error) || !preflight(root.fixture, error) ||
        !mounted_name_and_labels_absent(token, "rut358-input-" + token, "0", error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = error;
        root.settled = true;
        return result;
    }
    fixture_private_directory_lease::Diagnostic directory_error;
    if (!fixture_private_directory_lease::PrivateDirectoryLease::create(root.directory,
                                                                        directory_error)) {
        result.error = "exact-input rotation directory creation failed";
        root.settled = true;
        return result;
    }
    directory_acquired = true;
    root.mutated = true;
    fixture_exact_input_file_lease::Diagnostic input_error;
    if (!fixture_exact_input_file_lease::ExactInputFileLease::create(
            root.directory, bytes.data(), bytes.size(), root.input, input_error)) {
        result.error = "exact-input rotation source creation failed";
        return finish_failure(false);
    }
    input_acquired = true;
    if (!capture_rotation_source(root, live.initial_source, error) ||
        !root.fixture.create_networks(FailurePoint::None, error) ||
        !root.fixture.create_holder(FailurePoint::None, error) ||
        !root.fixture.attach_holder(FailurePoint::None, error) ||
        !root.fixture.verify_topology(FailurePoint::None, error) ||
        !root.fixture.create_sidecar(HeldNamespaceSidecarFailurePoint::None, error)) {
        result.error = error;
        return finish_failure(false);
    }

    ParsedMountInspect old_mount;
    std::uint32_t old_start_count = 0;
    if (!create_rotation_mounted(token,
                                 "0",
                                 root.fixture.holder_id(),
                                 live.initial_source,
                                 false,
                                 mounted.old_mounted,
                                 old_mount,
                                 mounted.old_create_count,
                                 old_start_count,
                                 error)) {
        result.error = error;
        return finish_failure(false);
    }
    if (!mounted_rotation_transition(mounted, ExactInputRotationState::OldMountedValidated)) {
        result.error = "old mounted owner transition was rejected";
        return finish_failure(false);
    }
    const ExactInputMountedSidecarAbsence expected_old_absence{mounted.old_mounted.id,
                                                               mounted.old_mounted.name,
                                                               mounted.old_mounted.pid,
                                                               mounted.old_mounted.start,
                                                               true,
                                                               true,
                                                               true,
                                                               true};

    if (!capture_old_generation_for_receipt(root.fixture, composer, error) ||
        mounted.old_mounted.id == composer.receipt.old_generation.sidecar.id ||
        (mounted.old_mounted.pid == composer.receipt.old_generation.sidecar.pid &&
         mounted.old_mounted.start == composer.receipt.old_generation.sidecar.start) ||
        mounted.old_mounted.network_netns !=
            composer.receipt.old_generation.topology.holder_netns ||
        !remove_rotation_mounted(mounted, true, false, error) ||
        !exact_input_mounted_absence_matches(mounted.old_absence, mounted.old_mounted) ||
        !exact_input_mounted_absence_equal(mounted.old_absence, expected_old_absence) ||
        !sidecar_snapshot_equal(root.registered_sidecar, preserved_registered_sidecar) ||
        !mount_inspect_equal(root.registered_mount, preserved_registered_mount)) {
        if (error.empty()) error = "old mounted-sibling authority/history was not exact";
        result.error = error;
        return finish_failure(false);
    }
    std::string phase_error;
    const CleanupPhaseResult old_inert = root.fixture.cleanup_sidecar_phase(phase_error);
    const CleanupPhaseResult old_holder = root.fixture.cleanup_holder_phase(phase_error);
    if (!old_inert.settled || !old_inert.operation_ok || !old_holder.settled ||
        !old_holder.operation_ok || !old_holder.holder_removed ||
        !capture_old_absence_for_receipt(root.fixture, composer, phase_error) ||
        !root.fixture.recreate_holder_only(HolderOnlyRecreationFailurePoint::None, phase_error) ||
        !root.fixture.recreate_sidecar(RecreatedSidecarFailurePoint::None, phase_error)) {
        result.error = phase_error;
        return finish_failure(false);
    }
    const RecreatedSidecarEvidence fresh_inert = root.fixture.recreated_sidecar_evidence();
    if (!publish_complete_generation_receipt(
            root.fixture, fresh_inert, false, composer, phase_error)) {
        result.error = phase_error;
        return finish_failure(false);
    }
    if (!mounted_rotation_transition(mounted, ExactInputRotationState::GenerationValidated)) {
        result.error = "generation-validated owner transition was rejected";
        return finish_failure(false);
    }
    std::string receipt_error_a;
    std::string receipt_error_b;
    if (!validate_held_namespace_generation_rotation_receipt(composer.frozen_receipt,
                                                             receipt_error_a) ||
        !validate_held_namespace_generation_rotation_receipt(composer.frozen_receipt,
                                                             receipt_error_b) ||
        !receipt_error_a.empty() || !receipt_error_b.empty() ||
        !capture_rotation_source(root, live.fresh_source, error) ||
        !exact_input_rotation_source_equal(live.initial_source, live.fresh_source) ||
        !mounted_name_and_labels_absent(token, "rut358-input-" + token, "1", error)) {
        result.error = error.empty() ? "source/phase4 revalidation failed" : error;
        return finish_failure(false);
    }

    ParsedMountInspect fresh_mount;
    const bool reported_timeout =
        failure_point == ExactInputRotationFailurePoint::FreshCreateReportedTimeout;
    if (!mounted_rotation_transition(mounted, ExactInputRotationState::FreshCreateMayHaveMutated) ||
        !create_rotation_mounted(token,
                                 "1",
                                 composer.frozen_receipt.new_generation.topology.holder_id,
                                 live.fresh_source,
                                 reported_timeout,
                                 mounted.fresh_mounted,
                                 fresh_mount,
                                 mounted.fresh_create_count,
                                 mounted.fresh_start_count,
                                 error)) {
        result.error = error;
        return finish_failure(false);
    }
    mounted.fresh_exists = true;
    if (reported_timeout) mounted.operation_ok = false;
    if (!mounted_rotation_transition(mounted, ExactInputRotationState::FreshMountedValidated)) {
        result.error = "fresh mounted owner transition was rejected";
        return finish_failure(false);
    }
    live.old_mounted = mounted.old_mounted;
    live.old_absence = mounted.old_absence;
    live.generation_receipt = composer.frozen_receipt;
    live.fresh_mounted = mounted.fresh_mounted;
    live.source_continuity = true;
    live.generation_receipt_validated_twice = true;
    live.old_and_fresh_authorities_separate = true;
    live.operation_ok = mounted.operation_ok;
    live.old_create_count = mounted.old_create_count;
    live.old_remove_count = mounted.old_remove_count;
    live.fresh_create_count = mounted.fresh_create_count;
    live.fresh_start_count = mounted.fresh_start_count;
    live.fresh_remove_count = 0;
    if (failure_point == ExactInputRotationFailurePoint::FreshMountObservationMutation) {
        ExactInputMountedSidecarEvidence rejected;
        ParsedMountInspect rejected_mount;
        std::string mutation_error;
        if (inspect_rotation_mounted(mounted.fresh_mounted.id,
                                     token,
                                     mounted.fresh_mounted.name,
                                     "1",
                                     composer.frozen_receipt.new_generation.topology.holder_id,
                                     live.fresh_source,
                                     true,
                                     true,
                                     rejected,
                                     &rejected_mount,
                                     mutation_error) ||
            mutation_error.empty()) {
            result.error = "fresh mount observation mutation was accepted";
            return finish_failure(false);
        }
        (void)mounted_rotation_transition(mounted, ExactInputRotationState::Unresolved);
        live.state = ExactInputRotationState::Unresolved;
    } else {
        std::string read_error;
        const bool read_ok = capture_rotation_read(
            root, mounted.fresh_mounted, failure_point, live.fresh_read, read_error);
        if (!read_ok) {
            mounted.operation_ok = false;
            (void)mounted_rotation_transition(mounted, ExactInputRotationState::Unresolved);
            live.state = ExactInputRotationState::Unresolved;
            live.operation_ok = false;
            error = read_error;
        } else {
            if (!mounted_rotation_transition(mounted,
                                             ExactInputRotationState::FreshWriteMayHaveMutated)) {
                result.error = "fresh write observation transition was rejected";
                return finish_failure(false);
            }
            std::string write_error;
            if (!capture_rotation_write_refusal(
                    root, mounted.fresh_mounted, failure_point, live.fresh_write, write_error)) {
                mounted.operation_ok = false;
                (void)mounted_rotation_transition(mounted, ExactInputRotationState::Unresolved);
                live.state = ExactInputRotationState::Unresolved;
                live.operation_ok = false;
                error = write_error;
            } else if (!mounted_rotation_transition(mounted,
                                                    ExactInputRotationState::FreshWriteObserved)) {
                result.error = "fresh write observation completion transition was rejected";
                return finish_failure(false);
            } else {
                live.state = ExactInputRotationState::LivePublished;
                if (!validate_exact_input_rotation_live_evidence(live, error) ||
                    !callback(live, error)) {
                    result.error = error;
                    return finish_failure(false);
                }
                callback_ran = true;
                if (!mounted_rotation_transition(mounted, ExactInputRotationState::LivePublished)) {
                    result.error = "live publication owner transition was rejected";
                    return finish_failure(false);
                }
            }
        }
    }

    const auto cleanup_inert_after_mounted = [&](std::string& guarded_error) {
        if (!require_mounted_settled("fresh inert cleanup", guarded_error)) return false;
        return root.fixture.cleanup_recreated_sidecar(guarded_error);
    };
    const auto cleanup_source_after_mounted = [&](std::string& guarded_error) {
        if (!require_mounted_settled("source cleanup", guarded_error)) return false;
        fixture_exact_input_file_lease::Diagnostic guarded_input_error;
        if (root.input.cleanup(guarded_input_error)) return true;
        guarded_error = "exact source cleanup failed";
        return false;
    };
    const auto cleanup_holder_after_mounted = [&](std::string& guarded_error) {
        if (!require_mounted_settled("fresh holder cleanup", guarded_error)) return false;
        return root.fixture.cleanup_recreated_holder(guarded_error);
    };
    const auto cleanup_topology_after_mounted = [&](std::string& guarded_error) {
        if (!require_mounted_settled("retained topology cleanup", guarded_error))
            return CleanupPhaseResult{};
        return root.fixture.cleanup_topology_phase(guarded_error);
    };

    mounted.removal_suppression_armed =
        failure_point == ExactInputRotationFailurePoint::SuppressFirstFreshRemoval;
    if (mounted.removal_suppression_armed) {
        const std::uint64_t before_observation = command_invocation_count;
        std::string suppressed;
        if (remove_rotation_mounted(mounted, false, true, suppressed) || suppressed.empty() ||
            mounted.fresh_remove_count != 0u || mounted.fresh_remove_suppression_count != 1u ||
            command_invocation_count !=
                before_observation + kRunningMountedCleanupObservationCommands ||
            mounted.state != ExactInputRotationState::FreshRemovalMayHaveMutated ||
            !mounted.fresh_exists || mounted.fresh_absence.id_absent ||
            mounted.fresh_absence.name_absent) {
            result.error =
                "fresh mounted removal suppression did not retain exact observed custody";
            return finish_failure(false);
        }
        std::string inert_gate;
        std::string source_gate;
        std::string holder_gate;
        std::string topology_gate;
        const std::uint64_t before_inert_gate = command_invocation_count;
        const bool inert_blocked = !cleanup_inert_after_mounted(inert_gate);
        const bool inert_command_free = command_invocation_count == before_inert_gate;
        const std::uint64_t before_source_gate = command_invocation_count;
        const bool source_blocked = !cleanup_source_after_mounted(source_gate);
        const bool source_command_free = command_invocation_count == before_source_gate;
        const std::uint64_t before_holder_gate = command_invocation_count;
        const bool holder_blocked = !cleanup_holder_after_mounted(holder_gate);
        const bool holder_command_free = command_invocation_count == before_holder_gate;
        const std::uint64_t before_topology_gate = command_invocation_count;
        const bool topology_blocked = !cleanup_topology_after_mounted(topology_gate).settled;
        const bool topology_command_free = command_invocation_count == before_topology_gate;
        terminal_receipt.downstream_gates_command_free =
            inert_blocked && source_blocked && holder_blocked && topology_blocked &&
            inert_command_free && source_command_free && holder_command_free &&
            topology_command_free && root.input.active() &&
            inert_gate == "fresh mounted-sidecar unsettled; blocked fresh inert cleanup" &&
            source_gate == "fresh mounted-sidecar unsettled; blocked source cleanup" &&
            holder_gate == "fresh mounted-sidecar unsettled; blocked fresh holder cleanup" &&
            topology_gate == "fresh mounted-sidecar unsettled; blocked retained topology cleanup";
    } else {
        terminal_receipt.downstream_gates_command_free = true;
    }
    error.clear();
    const std::uint32_t expected_suppression_count =
        failure_point == ExactInputRotationFailurePoint::SuppressFirstFreshRemoval ? 1u : 0u;
    if (!remove_rotation_mounted(mounted, false, false, error) ||
        mounted.fresh_remove_count != 1u ||
        mounted.fresh_remove_suppression_count != expected_suppression_count ||
        mounted.state != ExactInputRotationState::Settled || mounted.fresh_exists ||
        !exact_input_mounted_absence_matches(mounted.fresh_absence, mounted.fresh_mounted)) {
        if (error.empty()) error = "fresh mounted exact-ID retry did not settle exact custody";
        result.error = error;
        return finish_failure(false);
    }
    terminal_receipt.fresh_mounted_order = ++order;
    std::string cleanup_error;
    if (!cleanup_inert_after_mounted(cleanup_error)) {
        result.error = cleanup_error;
        return finish_failure(false);
    }
    terminal_receipt.fresh_inert_order = ++order;
    if (!cleanup_source_after_mounted(cleanup_error)) {
        result.error = "exact source cleanup failed";
        return finish_failure(false);
    }
    terminal_receipt.input_order = ++order;
    if (!root.directory.settle(directory_error)) {
        result.error = "exact source directory cleanup failed";
        return finish_failure(false);
    }
    terminal_receipt.directory_order = ++order;
    input_acquired = false;
    directory_acquired = false;
    if (!cleanup_holder_after_mounted(cleanup_error)) {
        result.error = cleanup_error;
        return finish_failure(false);
    }
    terminal_receipt.holder_order = ++order;
    ExactInputRotationNetworkOrder network_order{&terminal_receipt, &order, false};
    CleanupPhaseResult topology;
    if (require_mounted_settled("retained topology cleanup", cleanup_error))
        topology = root.fixture.cleanup_topology_phase(
            cleanup_error, record_exact_input_rotation_network_order, &network_order);
    if (!topology.settled || !topology.operation_ok || terminal_receipt.network_b_order != 6u ||
        terminal_receipt.network_a_order != 7u ||
        !network_order.frozen_old_holder_removal_observed) {
        result.error = cleanup_error;
        return finish_failure(false);
    }
    std::string audit_error;
    if (!audit_zero_residue(token,
                            root.fixture.network_a().name,
                            root.fixture.network_b().name,
                            root.fixture.holder_name(),
                            audit_error)) {
        result.error = audit_error;
        return finish_failure(false);
    }
    terminal_receipt.state = ExactInputRotationState::Settled;
    terminal_receipt.live = live;
    terminal_receipt.live_published = callback_ran;
    terminal_receipt.fresh_absence = mounted.fresh_absence;
    terminal_receipt.operation_ok = mounted.operation_ok;
    terminal_receipt.cleanup_complete = true;
    terminal_receipt.zero_residue = true;
    terminal_receipt.terminal_frozen = true;
    terminal_receipt.fresh_remove_count = mounted.fresh_remove_count;
    terminal_receipt.fresh_remove_suppression_count = mounted.fresh_remove_suppression_count;
    const auto replay_rotation_cleanup = [&](std::string& history) {
        if (!remove_rotation_mounted(mounted, false, false, history) ||
            !cleanup_inert_after_mounted(history))
            return false;
        if (root.input.active()) {
            history = "terminal replay found a live exact source lease";
            return false;
        }
        if (root.directory.state() != fixture_private_directory_lease::State::Removed) {
            history = "terminal replay found a live exact source directory";
            return false;
        }
        if (!cleanup_holder_after_mounted(history)) return false;
        const CleanupPhaseResult replay_topology = cleanup_topology_after_mounted(history);
        return replay_topology.settled && root.fixture.cleanup(history);
    };
    const std::uint64_t replay_commands = command_invocation_count;
    std::string caller_history = "preserve-input-rotation-history";
    const bool replay_ok = replay_rotation_cleanup(caller_history) &&
                           caller_history == "preserve-input-rotation-history" &&
                           command_invocation_count == replay_commands;
    terminal_receipt.replay_command_free = replay_ok;
    const ExactInputRotationTerminalReceipt frozen = terminal_receipt;
    caller_history = "preserve-input-rotation-history-again";
    const bool frozen_replay = replay_rotation_cleanup(caller_history) &&
                               caller_history == "preserve-input-rotation-history-again" &&
                               command_invocation_count == replay_commands &&
                               exact_input_rotation_terminal_equal(terminal_receipt, frozen);
    root.settled = true;
    std::string terminal_error;
    if (!validate_exact_input_rotation_terminal_receipt(terminal_receipt, terminal_error)) {
        result.error = terminal_error;
        return result;
    }
    if (!frozen_replay) {
        result.error = "terminal exact-input rotation receipt changed during replay";
        return result;
    }
    if (!sidecar_snapshot_equal(root.registered_sidecar, preserved_registered_sidecar) ||
        !mount_inspect_equal(root.registered_mount, preserved_registered_mount)) {
        result.error = "legacy exact-input mount history changed during mounted rotation";
        return result;
    }
    result.cleanup_complete = true;
    result.residue_free = true;
    result.success = true;
    result.semantic_receipt = callback_ran
                                  ? "verified exact input mount authority across one rotation"
                                  : "verified mutated fresh mount observation stayed unpublished";
    result.error = result.semantic_receipt;
    return result;
}

bool exact_input_rotation_pure_self_checks(std::uint32_t& mutation_rejections, std::string& error) {
    mutation_rejections = 0;
    ExactInputRotationLiveEvidence seed;
    seed.state = ExactInputRotationState::LivePublished;
    seed.initial_source.path = "/tmp/rut358-source/nginx.conf";
    seed.initial_source.bytes = "events {}\n";
    seed.initial_source.device = 10;
    seed.initial_source.inode = 20;
    seed.initial_source.mode = S_IFREG | 0600;
    seed.initial_source.uid = 1000;
    seed.initial_source.gid = 1000;
    seed.initial_source.size = seed.initial_source.bytes.size();
    seed.initial_source.links = 1;
    seed.initial_source.mtime_seconds = 30;
    seed.initial_source.mtime_nanoseconds = 40;
    seed.initial_source.ctime_seconds = 50;
    seed.initial_source.ctime_nanoseconds = 60;
    seed.initial_source.regular_0600 = true;
    seed.initial_source.exact_bytes_revalidated = true;
    seed.initial_source.retained_ofd_revalidated = true;
    seed.fresh_source = seed.initial_source;
    const std::string token(48, '1');
    auto& old_topology = seed.generation_receipt.old_generation.topology;
    old_topology.token = token;
    old_topology.network_a_name = "rut358-a-" + token;
    old_topology.network_a_id = std::string(64, 'a');
    old_topology.network_a_subnet = "10.253.240.0/28";
    old_topology.network_a_gateway = "10.253.240.1";
    old_topology.network_b_name = "rut358-b-" + token;
    old_topology.network_b_id = std::string(64, 'b');
    old_topology.network_b_subnet = "10.253.241.0/28";
    old_topology.network_b_gateway = "10.253.241.1";
    old_topology.holder_name = "rut358-holder-" + token;
    old_topology.holder_id = std::string(64, 'c');
    old_topology.positive_ip = "10.253.240.2";
    old_topology.guard_ip = "10.253.241.2";
    old_topology.holder_pid = 100;
    old_topology.holder_start = 1000;
    old_topology.holder_netns = 2000;
    old_topology.probe_evidence = {HeldTopologyProbePolicy::SocketlessHostParent, 1, 0, 0};
    auto& old_inert = seed.generation_receipt.old_generation.sidecar;
    old_inert.token = token;
    old_inert.stage = kSidecarStage;
    old_inert.role = kSidecarRole;
    old_inert.name = "rut358-sidecar-" + token;
    old_inert.id = std::string(64, 'd');
    old_inert.pinned_image_reference = RUT_PINNED_NGINX_IMAGE;
    old_inert.expected_image_id = "sha256:" + std::string(64, 'e');
    old_inert.image_id = old_inert.expected_image_id;
    old_inert.network_mode = "container:" + old_topology.holder_id;
    old_inert.path = "/bin/sleep";
    old_inert.arguments_json = "[\"infinity\"]";
    old_inert.pid = 101;
    old_inert.start = 1001;
    old_inert.netns = 2000;
    old_inert.host_netns = 3000;
    old_inert.running = old_inert.read_only_root = old_inert.capability_drop_all = true;
    old_inert.no_new_privileges = old_inert.no_published_ports = true;
    seed.generation_receipt.new_generation = seed.generation_receipt.old_generation;
    auto& fresh_topology = seed.generation_receipt.new_generation.topology;
    auto& fresh_inert = seed.generation_receipt.new_generation.sidecar;
    fresh_topology.holder_id = std::string(64, 'f');
    fresh_topology.holder_start = 2000;
    fresh_inert.id = std::string(64, '4');
    fresh_inert.network_mode = "container:" + fresh_topology.holder_id;
    fresh_inert.start = 2001;
    auto& old_absence = seed.generation_receipt.old_absence;
    old_absence.holder = {old_topology.holder_id, 100, 1000, true, true};
    old_absence.sidecar = {old_inert.id, 101, 1001, true, true};
    old_absence.holder_name = old_topology.holder_name;
    old_absence.sidecar_name = old_inert.name;
    old_absence.holder_name_absent = old_absence.sidecar_name_absent = true;
    seed.generation_receipt.old_generation_phase =
        HeldNamespaceGenerationRotationPhase::OldGenerationValidated;
    old_absence.phase = HeldNamespaceGenerationRotationPhase::OldGenerationAbsent;
    seed.generation_receipt.new_generation_created_phase =
        HeldNamespaceGenerationRotationPhase::NewGenerationCreated;
    seed.generation_receipt.new_generation_validated_phase =
        HeldNamespaceGenerationRotationPhase::NewGenerationValidated;
    const auto fill_mounted = [&](ExactInputMountedSidecarEvidence& mounted,
                                  const char generation,
                                  const char id,
                                  pid_t pid,
                                  std::uint64_t start,
                                  const std::string& holder_id,
                                  std::uint64_t netns,
                                  std::uint64_t mount_netns) {
        mounted.token = token;
        mounted.stage = kMountedRotationStage;
        mounted.role = kMountedRotationRole;
        mounted.generation = std::string(1, generation);
        mounted.name = "rut358-input-" + token;
        mounted.id = std::string(64, id);
        mounted.image_reference = RUT_PINNED_NGINX_IMAGE;
        mounted.image_id = "sha256:" + std::string(64, 'e');
        mounted.network_mode = "container:" + holder_id;
        mounted.user = "1000:1000";
        mounted.path = "/bin/sleep";
        mounted.arguments_json = "[\"infinity\"]";
        mounted.source_path = seed.initial_source.path;
        mounted.pid = pid;
        mounted.start = start;
        mounted.network_netns = netns;
        mounted.mount_netns = mount_netns;
        mounted.running = mounted.read_only_root = mounted.capability_drop_all = true;
        mounted.no_new_privileges = mounted.restart_no = mounted.no_published_ports = true;
        mounted.requested_mount_exact = mounted.realized_mount_exact = true;
        mounted.no_mount_shadowing = mounted.nonhost_mount_netns = true;
    };
    fill_mounted(seed.old_mounted, '0', '5', 102, 1002, old_topology.holder_id, 2000, 4000);
    fill_mounted(seed.fresh_mounted, '1', '6', 102, 2002, fresh_topology.holder_id, 2000, 5000);
    seed.fresh_read.attempted = seed.fresh_read.terminal_frozen =
        seed.fresh_read.caller_deadline_recorded = true;
    seed.fresh_read.final_deadline_nanoseconds = 9000000000LL;
    seed.fresh_read.source_before = seed.initial_source;
    seed.fresh_read.source_after = seed.initial_source;
    seed.fresh_read.target_before = seed.fresh_mounted;
    seed.fresh_read.target_after = seed.fresh_mounted;
    seed.fresh_read.source_brackets_equal = seed.fresh_read.target_brackets_equal = true;
    seed.fresh_read.outcome = ExactInputReadOutcome::Complete;
    auto& read_command = seed.fresh_read.command;
    read_command.attempted = read_command.terminal_frozen = read_command.command_started = true;
    read_command.stdout_eof = read_command.stderr_eof = read_command.child_reaped = true;
    read_command.wait_status_valid = read_command.process_group_owned = true;
    read_command.process_group_gone = read_command.pidfd_opened = true;
    read_command.pidfd_identity_verified = read_command.pidfd_closed_after_group_gone = true;
    read_command.final_deadline_recorded = read_command.cleanup_completed_before_final_deadline =
        true;
    read_command.supervisor_session_verified = read_command.supervisor_subreaper_verified = true;
    read_command.actual_exec_observed = read_command.subtree_confinement_installed = true;
    read_command.group_echild_observed = true;
    read_command.adopted_reap_count = 1u;
    read_command.resolved_executable = "/usr/bin/docker";
    read_command.command_argv = {"docker",
                                 "exec",
                                 "--user",
                                 seed.fresh_mounted.user,
                                 seed.fresh_mounted.id,
                                 "/bin/cat",
                                 kExactInputMountDestination};
    read_command.stdout_bytes = seed.initial_source.bytes;
    finalize_rotation_read_command(read_command, seed.initial_source.bytes.size());
    seed.fresh_write.attempted = seed.fresh_write.terminal_frozen =
        seed.fresh_write.caller_deadline_recorded = true;
    seed.fresh_write.final_deadline_nanoseconds = 12000000000LL;
    seed.fresh_write.credentials = "1000:1000";
    seed.fresh_write.expected_target_stderr =
        "dd: failed to open '/etc/nginx/nginx.conf': Read-only file system\n";
    fill_rotation_write_bracket(
        seed.initial_source, seed.fresh_mounted, seed.fresh_write.initial_bracket);
    seed.fresh_write.middle_bracket = seed.fresh_write.initial_bracket;
    seed.fresh_write.final_bracket = seed.fresh_write.initial_bracket;
    seed.fresh_write.outcome = ExactInputWriteRefusalOutcome::Complete;
    auto& control_command = seed.fresh_write.control;
    control_command.attempted = control_command.terminal_frozen = control_command.command_started =
        true;
    control_command.stdout_eof = control_command.stderr_eof = control_command.child_reaped = true;
    control_command.wait_status_valid = control_command.process_group_owned = true;
    control_command.process_group_gone = control_command.pidfd_opened = true;
    control_command.pidfd_identity_verified = control_command.pidfd_closed_after_group_gone = true;
    control_command.final_deadline_recorded =
        control_command.cleanup_completed_before_final_deadline = true;
    control_command.supervisor_session_verified = control_command.supervisor_subreaper_verified =
        true;
    control_command.actual_exec_observed = control_command.subtree_confinement_installed = true;
    control_command.group_echild_observed = true;
    control_command.wait_status = 0;
    control_command.resolved_executable = "/usr/bin/docker";
    control_command.command_argv = {"docker",
                                    "exec",
                                    "--env",
                                    "LC_ALL=C",
                                    "--user",
                                    "1000:1000",
                                    seed.fresh_mounted.id,
                                    "/usr/bin/dd",
                                    "if=/dev/zero",
                                    "of=/dev/null",
                                    "bs=1",
                                    "count=1",
                                    "conv=notrunc",
                                    "status=none"};
    control_command.stdout_bytes.clear();
    auto& target_command = seed.fresh_write.target;
    target_command = control_command;
    target_command.wait_status = 256;
    target_command.command_argv = {"docker",
                                   "exec",
                                   "--env",
                                   "LC_ALL=C",
                                   "--user",
                                   "1000:1000",
                                   seed.fresh_mounted.id,
                                   "/usr/bin/dd",
                                   "if=/etc/nginx/nginx.conf",
                                   "of=/etc/nginx/nginx.conf",
                                   "bs=1",
                                   "count=1",
                                   "conv=notrunc",
                                   "status=none"};
    target_command.stderr_bytes = seed.fresh_write.expected_target_stderr;
    target_command.outcome = ExactInputReadOutcome::ExitNonzero;
    control_command.outcome = ExactInputReadOutcome::Complete;
    seed.old_absence = {seed.old_mounted.id,
                        seed.old_mounted.name,
                        seed.old_mounted.pid,
                        seed.old_mounted.start,
                        true,
                        true,
                        true,
                        true};
    seed.source_continuity = seed.generation_receipt_validated_twice = true;
    seed.old_and_fresh_authorities_separate = seed.operation_ok = true;
    seed.old_create_count = seed.old_remove_count = seed.fresh_create_count =
        seed.fresh_start_count = 1;
    std::string diagnostic;
    if (!validate_exact_input_rotation_live_evidence(seed, diagnostic)) {
        error = "valid exact-input rotation seed was rejected: " + diagnostic;
        return false;
    }
    const auto reject = [&](const std::function<void(ExactInputRotationLiveEvidence&)>& mutate) {
        ExactInputRotationLiveEvidence changed = seed;
        mutate(changed);
        std::string rejected;
        if (validate_exact_input_rotation_live_evidence(changed, rejected) || rejected.empty())
            return false;
        ++mutation_rejections;
        return true;
    };
    if (!reject([](auto& value) { ++value.fresh_source.inode; }) ||
        !reject([](auto& value) { value.fresh_mounted.generation = "0"; }) ||
        !reject([](auto& value) { value.old_absence.process_absent = false; }) ||
        !reject([](auto& value) { value.fresh_mounted.id = value.old_mounted.id; }) ||
        !reject([](auto& value) { value.fresh_mounted.network_netns = 0; }) ||
        !reject([](auto& value) { value.generation_receipt_validated_twice = false; }) ||
        !reject([](auto& value) { value.fresh_read.command.command_started = false; }) ||
        !reject([](auto& value) { value.fresh_read.command.actual_exec_observed = false; }) ||
        !reject([](auto& value) { value.fresh_read.command.stdout_eof = false; }) ||
        !reject([](auto& value) { value.fresh_read.command.child_reaped = false; }) ||
        !reject([](auto& value) { value.fresh_read.command.process_group_gone = false; }) ||
        !reject([](auto& value) { value.fresh_read.command.pidfd_identity_verified = false; }) ||
        !reject(
            [](auto& value) { value.fresh_read.command.supervisor_session_verified = false; }) ||
        !reject(
            [](auto& value) { value.fresh_read.command.subtree_confinement_installed = false; }) ||
        !reject([](auto& value) {
            value.fresh_read.command.cleanup_completed_before_final_deadline = false;
        }) ||
        !reject([](auto& value) { value.fresh_read.command.launch_errno = EPERM; }) ||
        !reject([](auto& value) { ++value.fresh_read.command.expected_size; }) ||
        !reject([](auto& value) { value.fresh_read.command.stdout_bytes.push_back('x'); }) ||
        !reject([](auto& value) { value.fresh_read.command.stderr_bytes = "unexpected"; }) ||
        !reject([](auto& value) { value.fresh_read.command.command_argv.back() = "/tmp/other"; }) ||
        !reject(
            [](auto& value) { value.fresh_read.command.resolved_executable = "/tmp/docker"; }) ||
        // Unresolved outcome/attempt combinations must fail closed.
        !reject([](auto& value) {
            value.fresh_read.attempted = false;
            value.fresh_read.outcome = ExactInputReadOutcome::DeadlineExceeded;
        }) ||
        !reject([](auto& value) { value.fresh_read.outcome = ExactInputReadOutcome::None; }) ||
        !reject(
            [](auto& value) { value.fresh_write.outcome = ExactInputWriteRefusalOutcome::None; })) {
        error = "exact-input rotation live mutation was accepted";
        return false;
    }
    const auto reject_write =
        [&](const std::function<void(ExactInputRotationLiveEvidence&)>& mutate) {
            ExactInputRotationLiveEvidence changed = seed;
            mutate(changed);
            std::string rejected;
            if (validate_exact_input_rotation_live_evidence(changed, rejected) || rejected.empty())
                return false;
            ++mutation_rejections;
            return true;
        };
    if (!reject_write([](auto& value) { value.fresh_write.control.command_argv.back() = "bad"; }) ||
        !reject_write([](auto& value) { value.fresh_write.target.wait_status = 0; }) ||
        !reject_write([](auto& value) { value.fresh_write.target.stderr_bytes = "bad\n"; }) ||
        !reject_write([](auto& value) { ++value.fresh_write.middle_bracket.source.inode; }) ||
        !reject_write([](auto& value) { value.fresh_write.final_bracket.target.pid = 0; }) ||
        !reject_write([](auto& value) { value.fresh_write.caller_deadline_recorded = false; })) {
        error = "exact-input rotation write-refusal mutation was accepted";
        return false;
    }
    const auto expect_unresolved = [&](ExactInputRotationLiveEvidence candidate,
                                       bool expected,
                                       const char* description) {
        candidate.state = ExactInputRotationState::Unresolved;
        std::string unresolved_error;
        const bool actual =
            validate_exact_input_rotation_live_evidence(candidate, unresolved_error);
        if (actual != expected) {
            error = std::string("exact-input rotation unresolved case mismatch: ") + description;
            if (!unresolved_error.empty()) {
                error += ": ";
                error += unresolved_error;
            }
            return false;
        }
        return true;
    };
    ExactInputRotationLiveEvidence failed_read = seed;
    failed_read.fresh_read.outcome = ExactInputReadOutcome::DeadlineExceeded;
    failed_read.fresh_write = {};
    if (!expect_unresolved(failed_read, true, "failed read without write")) {
        return false;
    }
    ExactInputRotationLiveEvidence failed_read_with_write = failed_read;
    failed_read_with_write.fresh_write.attempted = true;
    failed_read_with_write.fresh_write.terminal_frozen = true;
    failed_read_with_write.fresh_write.caller_deadline_recorded = true;
    failed_read_with_write.fresh_write.outcome = ExactInputWriteRefusalOutcome::ControlExitNonzero;
    failed_read_with_write.fresh_write.diagnostic.message =
        "write was not permitted after read failure";
    if (!expect_unresolved(failed_read_with_write, false, "failed read with write")) {
        return false;
    }
    ExactInputRotationLiveEvidence failed_write = seed;
    failed_write.state = ExactInputRotationState::Unresolved;
    failed_write.fresh_write.outcome = ExactInputWriteRefusalOutcome::TargetWrongExit;
    failed_write.fresh_write.diagnostic.message = "target refusal was unresolved";
    if (!expect_unresolved(failed_write, true, "successful read with failed write")) {
        return false;
    }
    if (!expect_unresolved(seed, false, "successful read with successful write")) {
        return false;
    }
    ExactInputRotationTerminalReceipt terminal;
    terminal.state = ExactInputRotationState::Settled;
    terminal.live = seed;
    terminal.live_published = true;
    terminal.fresh_absence = {seed.fresh_mounted.id,
                              seed.fresh_mounted.name,
                              seed.fresh_mounted.pid,
                              seed.fresh_mounted.start,
                              true,
                              true,
                              true,
                              true};
    terminal.cleanup_complete = terminal.zero_residue = terminal.terminal_frozen = true;
    terminal.replay_command_free = terminal.downstream_gates_command_free = true;
    terminal.fresh_remove_count = 1;
    terminal.fresh_mounted_order = 1;
    terminal.fresh_inert_order = 2;
    terminal.input_order = 3;
    terminal.directory_order = 4;
    terminal.holder_order = 5;
    terminal.network_b_order = 6;
    terminal.network_a_order = 7;
    if (!validate_exact_input_rotation_terminal_receipt(terminal, diagnostic)) {
        error = "valid exact-input terminal seed was rejected: " + diagnostic;
        return false;
    }
    MountedSidecarRotationOwner transitions;
    for (ExactInputRotationState next : {ExactInputRotationState::OldMountedValidated,
                                         ExactInputRotationState::OldMountedSettled,
                                         ExactInputRotationState::GenerationValidated,
                                         ExactInputRotationState::FreshCreateMayHaveMutated,
                                         ExactInputRotationState::FreshMountedValidated,
                                         ExactInputRotationState::FreshWriteMayHaveMutated,
                                         ExactInputRotationState::FreshWriteObserved,
                                         ExactInputRotationState::LivePublished,
                                         ExactInputRotationState::Settled})
        if (!mounted_rotation_transition(transitions, next)) {
            error = "valid mounted-sidecar transition path was rejected";
            return false;
        }
    if (mounted_rotation_transition(transitions, ExactInputRotationState::Ready)) {
        error = "terminal mounted-sidecar transition replay was accepted";
        return false;
    }
    ExactInputRotationTerminalReceipt order_receipt;
    std::uint32_t cleanup_order = 5u;
    ExactInputRotationNetworkOrder order_context{&order_receipt, &cleanup_order, false};
    std::string order_error;
    if (!record_exact_input_rotation_network_order(
            &order_context, TopologySettlementEvent::Holder, true, order_error) ||
        !record_exact_input_rotation_network_order(
            &order_context, TopologySettlementEvent::NetworkB, true, order_error) ||
        !record_exact_input_rotation_network_order(
            &order_context, TopologySettlementEvent::NetworkA, true, order_error) ||
        !order_error.empty() || !order_context.frozen_old_holder_removal_observed ||
        order_receipt.network_b_order != 6u || order_receipt.network_a_order != 7u) {
        error = "frozen old-holder removal and B/A network order was rejected";
        return false;
    }
    ExactInputRotationTerminalReceipt missing_removal_receipt;
    cleanup_order = 5u;
    ExactInputRotationNetworkOrder missing_removal_context{
        &missing_removal_receipt, &cleanup_order, false};
    order_error.clear();
    if (record_exact_input_rotation_network_order(
            &missing_removal_context, TopologySettlementEvent::Holder, false, order_error) ||
        order_error.empty() || cleanup_order != 5u ||
        missing_removal_context.frozen_old_holder_removal_observed) {
        error = "holder event without frozen old-holder removal was accepted";
        return false;
    }
    ExactInputRotationTerminalReceipt rejected_order_receipt;
    cleanup_order = 5u;
    ExactInputRotationNetworkOrder rejected_order_context{
        &rejected_order_receipt, &cleanup_order, false};
    order_error.clear();
    if (record_exact_input_rotation_network_order(
            &rejected_order_context, TopologySettlementEvent::NetworkB, true, order_error) ||
        order_error.empty() || cleanup_order != 5u ||
        rejected_order_receipt.network_b_order != 0u) {
        error = "network settlement before frozen old-holder removal was accepted";
        return false;
    }
    return true;
}

}  // namespace rut::test::ipv4_topology
