#include "fixture_wildcard_paused_child_lease.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <linux/limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace rut::test::fixture_wildcard_paused_child_lease {
namespace {

using fixture_worker_protocol::read_file;
using fixture_worker_protocol::read_proc;
using fixture_worker_protocol::same_process_identity;

constexpr unsigned char kReady = 0x7e;
constexpr unsigned char kRelease = 0x52;

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number = 0) {
    diagnostic = {phase, error_number};
}

bool before_deadline(std::chrono::steady_clock::time_point deadline) {
    return std::chrono::steady_clock::now() < deadline;
}

int remaining_ms(std::chrono::steady_clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) return 0;
    const auto max_int = std::chrono::milliseconds(std::numeric_limits<int>::max());
    return static_cast<int>(left > max_int ? max_int.count() : left.count());
}

bool wait_fd_until(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const int timeout = remaining_ms(deadline);
        if (timeout <= 0) return false;
        pollfd descriptor{fd, events, 0};
        const int result = poll(&descriptor, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        return result > 0 && (descriptor.revents & (events | POLLERR | POLLHUP)) != 0;
    }
}

bool write_byte_until(int fd, unsigned char byte, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        if (!wait_fd_until(fd, POLLOUT, deadline)) return false;
        const ssize_t result = write(fd, &byte, 1);
        if (result == 1) return true;
        if (result < 0 && errno == EINTR) continue;
        return false;
    }
}

bool read_byte_until(int fd, unsigned char& byte, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        if (!wait_fd_until(fd, POLLIN, deadline)) return false;
        const ssize_t result = read(fd, &byte, 1);
        if (result == 1) return true;
        if (result < 0 && errno == EINTR) continue;
        return false;
    }
}

bool read_eof_until(int fd, std::chrono::steady_clock::time_point deadline, int& error_number) {
    unsigned char byte = 0;
    for (;;) {
        const int timeout = remaining_ms(deadline);
        if (timeout <= 0) {
            error_number = ETIMEDOUT;
            return false;
        }
        pollfd descriptor{fd, POLLIN, 0};
        const int poll_result = poll(&descriptor, 1, timeout);
        if (poll_result < 0 && errno == EINTR) continue;
        if (poll_result == 0) {
            error_number = ETIMEDOUT;
            return false;
        }
        if (poll_result < 0 || (descriptor.revents & (POLLIN | POLLERR | POLLHUP)) == 0) {
            error_number = poll_result < 0 && errno != 0 ? errno : EIO;
            return false;
        }
        const ssize_t result = read(fd, &byte, 1);
        if (result == 0) return true;
        if (result < 0 && errno == EINTR) continue;
        error_number = result > 0 ? EPROTO : (errno == 0 ? EIO : errno);
        return false;
    }
}

bool close_once(int& fd, Diagnostic& diagnostic) {
    if (fd < 0) return true;
    const int old = fd;
    fd = -1;  // Never retry an uncertain close.
    if (close(old) == 0) return true;
    fail(diagnostic, FailurePhase::Close, errno == 0 ? EIO : errno);
    return false;
}

void close_ignoring(int& fd) {
    Diagnostic diagnostic;
    (void)close_once(fd, diagnostic);
}

bool direct_children(std::chrono::steady_clock::time_point deadline,
                     std::vector<pid_t>& children,
                     Diagnostic& diagnostic) {
    children.clear();
    if (!before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Children, ETIMEDOUT);
        return false;
    }
    std::string text;
    if (!read_file("/proc/self/task/" + std::to_string(getpid()) + "/children", text, 65536)) {
        fail(diagnostic, FailurePhase::Children, errno == 0 ? EIO : errno);
        return false;
    }
    std::istringstream fields(text);
    std::string token;
    while (fields >> token) {
        if (token.empty()) {
            fail(diagnostic, FailurePhase::Children, EPROTO);
            return false;
        }
        for (const unsigned char byte : token) {
            if (byte < '0' || byte > '9') {
                fail(diagnostic, FailurePhase::Children, EPROTO);
                return false;
            }
        }
        unsigned long long value = 0;
        const auto [end, parse_error] =
            std::from_chars(token.data(), token.data() + token.size(), value, 10);
        if (parse_error != std::errc{} || end != token.data() + token.size()) {
            fail(diagnostic, FailurePhase::Children, EPROTO);
            return false;
        }
        if (value <= 1 ||
            value > static_cast<unsigned long long>(std::numeric_limits<pid_t>::max())) {
            fail(diagnostic, FailurePhase::Children, EPROTO);
            return false;
        }
        children.push_back(static_cast<pid_t>(value));
    }
    if (!before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Children, ETIMEDOUT);
        return false;
    }
    return true;
}

bool open_fd_snapshot(std::vector<int>& descriptors, Diagnostic& diagnostic) {
    descriptors.clear();
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) {
        fail(diagnostic, FailurePhase::Descriptors, errno == 0 ? EIO : errno);
        return false;
    }
    const int directory_fd = dirfd(directory);
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        unsigned long long value = 0;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::char_traits<char>::length(begin);
        const auto [parsed_end, parse_error] = std::from_chars(begin, end, value, 10);
        if (parse_error == std::errc{} && parsed_end == end &&
            value <= static_cast<unsigned long long>(std::numeric_limits<int>::max()) &&
            static_cast<int>(value) != directory_fd)
            descriptors.push_back(static_cast<int>(value));
        errno = 0;
    }
    const int read_error = errno;
    if (closedir(directory) != 0 || read_error != 0) {
        fail(diagnostic,
             FailurePhase::Descriptors,
             read_error != 0 ? read_error : (errno == 0 ? EIO : errno));
        descriptors.clear();
        return false;
    }
    std::sort(descriptors.begin(), descriptors.end());
    if (std::adjacent_find(descriptors.begin(), descriptors.end()) != descriptors.end()) {
        fail(diagnostic, FailurePhase::Descriptors, EPROTO);
        descriptors.clear();
        return false;
    }
    return true;
}

bool process_fd_snapshot(pid_t pid, std::vector<int>& descriptors) {
    descriptors.clear();
    const std::string path = "/proc/" + std::to_string(pid) + "/fd";
    DIR* directory = opendir(path.c_str());
    if (directory == nullptr) return false;
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        unsigned long long value = 0;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::char_traits<char>::length(begin);
        const auto [parsed_end, parse_error] = std::from_chars(begin, end, value, 10);
        if (parse_error == std::errc{} && parsed_end == end &&
            value <= static_cast<unsigned long long>(std::numeric_limits<int>::max()))
            descriptors.push_back(static_cast<int>(value));
        errno = 0;
    }
    const int read_error = errno;
    const bool close_ok = closedir(directory) == 0;
    if (read_error != 0 || !close_ok) {
        descriptors.clear();
        return false;
    }
    std::sort(descriptors.begin(), descriptors.end());
    return std::adjacent_find(descriptors.begin(), descriptors.end()) == descriptors.end();
}

bool process_fd_cloexec(pid_t pid, int fd, bool& cloexec) {
    std::string text;
    if (!read_file("/proc/" + std::to_string(pid) + "/fdinfo/" + std::to_string(fd), text, 4096))
        return false;
    std::istringstream lines(text);
    std::string key;
    bool found = false;
    while (lines >> key) {
        if (key == "flags:") {
            std::string token;
            if (found || !(lines >> token) || token.empty()) return false;
            unsigned long long flags = 0;
            const auto [end, parse_error] =
                std::from_chars(token.data(), token.data() + token.size(), flags, 8);
            if (parse_error != std::errc{} || end != token.data() + token.size()) return false;
            cloexec = (flags & static_cast<unsigned long long>(O_CLOEXEC)) != 0u;
            found = true;
        }
        std::string ignored;
        std::getline(lines, ignored);
    }
    return found;
}

bool pidfd_binding(int fd, pid_t expected, bool allow_dead) {
    std::string text;
    if (fd < 0 || !read_file("/proc/self/fdinfo/" + std::to_string(fd), text, 4096)) return false;
    std::istringstream lines(text);
    std::string key;
    bool found = false;
    while (lines >> key) {
        if (key == "Pid:") {
            long value = 0;
            if (found || !(lines >> value) || (value != expected && !(allow_dead && value == -1)))
                return false;
            found = true;
        }
        std::string ignored;
        std::getline(lines, ignored);
    }
    return found;
}

bool same_fd_object(int fd, dev_t device, ino_t inode) {
    struct stat status{};
    return fd >= 0 && device != 0 && inode != 0 && fstat(fd, &status) == 0 &&
           status.st_dev == device && status.st_ino == inode;
}

bool same_open_file_description(int first, int second) {
#ifdef SYS_kcmp
    errno = 0;
    return syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, first, second) == 0;
#else
    (void)first;
    (void)second;
    errno = ENOSYS;
    return false;
#endif
}

bool valid_pidfd_unbounded(int fd, pid_t expected, bool require_live, dev_t device, ino_t inode) {
    const int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0 || !same_fd_object(fd, device, inode) ||
        !pidfd_binding(fd, expected, !require_live))
        return false;
    if (!require_live) return true;
    for (;;) {
        pollfd descriptor{fd, POLLIN | POLLERR | POLLHUP, 0};
        const int result = poll(&descriptor, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        return result == 0 && descriptor.revents == 0;
    }
}

bool pidfd_live_until(int fd, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        if (!before_deadline(deadline)) return false;
        pollfd descriptor{fd, POLLIN | POLLERR | POLLHUP, 0};
        const int result = poll(&descriptor, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        return result == 0 && descriptor.revents == 0;
    }
}

bool pidfd_signal(int fd, int signal_number) {
#ifdef SYS_pidfd_send_signal
    return syscall(SYS_pidfd_send_signal, fd, signal_number, nullptr, 0u) == 0;
#else
    (void)fd;
    (void)signal_number;
    errno = ENOSYS;
    return false;
#endif
}

bool reap_child_until(pid_t child, int& status, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return true;
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return false;
        const int timeout = remaining_ms(deadline);
        if (timeout <= 0) return false;
        poll(nullptr, 0, timeout > 5 ? 5 : timeout);
    }
}

int open_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
    return static_cast<int>(syscall(SYS_pidfd_open, pid, 0u));
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

void child_main(int ready_fd,
                int release_fd,
                pid_t expected_parent,
                unsigned int delay_ms,
                unsigned int post_ready_delay_ms,
                unsigned int post_release_delay_ms,
                bool prepared,
                int output_fd,
                int null_input_fd,
                int executable_fd,
                int exec_status_fd,
                ChildContinuation continuation,
                const int* inherited_fds,
                std::size_t inherited_fd_count,
                int injected_close_failure_fd,
                int retained_fd_for_testing,
                volatile int* close_attempt_evidence) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent) _exit(120);
    if (prepared) {
        if ((null_input_fd >= 0 && dup2(null_input_fd, STDIN_FILENO) != STDIN_FILENO) ||
            dup2(output_fd, STDOUT_FILENO) != STDOUT_FILENO ||
            dup2(output_fd, STDERR_FILENO) != STDERR_FILENO)
            _exit(125);
        for (std::size_t index = 0; index < inherited_fd_count; ++index) {
            const int fd = inherited_fds[index];
            if (fd < 3 || fd == ready_fd || fd == release_fd || fd == executable_fd ||
                fd == exec_status_fd || fd == retained_fd_for_testing)
                continue;
            if (fd == injected_close_failure_fd) {
                const int close_result = close(fd);  // Exactly one real attempt.
                if (prepared && close_attempt_evidence != nullptr)
                    *close_attempt_evidence =
                        close_result == 0 ? static_cast<int>(*close_attempt_evidence + 1) : -1;
                errno = EINTR;
                _exit(126);
            }
            if (close(fd) != 0) _exit(126);  // Never retry an uncertain close.
        }
        const int input_flags = fcntl(STDIN_FILENO, F_GETFD);
        const int output_flags = fcntl(STDOUT_FILENO, F_GETFD);
        const int error_flags = fcntl(STDERR_FILENO, F_GETFD);
        const int release_flags = fcntl(release_fd, F_GETFD);
        const int executable_flags = executable_fd < 0 ? FD_CLOEXEC : fcntl(executable_fd, F_GETFD);
        const int status_writer_flags =
            exec_status_fd < 0 ? FD_CLOEXEC : fcntl(exec_status_fd, F_GETFD);
        if (input_flags < 0 || output_flags < 0 || error_flags < 0 || release_flags < 0 ||
            executable_flags < 0 || status_writer_flags < 0 || (output_flags & FD_CLOEXEC) != 0 ||
            (error_flags & FD_CLOEXEC) != 0 ||
            (continuation.kind == ChildContinuationKind::Execveat &&
             (input_flags & FD_CLOEXEC) != 0) ||
            (release_flags & FD_CLOEXEC) == 0 || (executable_flags & FD_CLOEXEC) == 0 ||
            (status_writer_flags & FD_CLOEXEC) == 0)
            _exit(127);
        if (continuation.executable_mutation != 0) {
            if (continuation.executable_mutation == 3) {
                if (fcntl(executable_fd, F_SETFD, 0) != 0) _exit(133);
            } else {
                const char* replacement_path =
                    continuation.executable_mutation == 1 ? continuation.argv0.data() : "/dev/null";
                const int replacement = open(replacement_path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
                if (replacement < 0 ||
                    dup3(replacement, executable_fd, O_CLOEXEC) != executable_fd ||
                    close(replacement) != 0)
                    _exit(133);
            }
        }
    }
    if (delay_ms != 0) {
        timespec delay{static_cast<time_t>(delay_ms / 1000u),
                       static_cast<long>((delay_ms % 1000u) * 1000000u)};
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
    }
    unsigned char ready = kReady;
    if (prepared && close_attempt_evidence != nullptr) *close_attempt_evidence = 100;
    for (;;) {
        const ssize_t result = write(ready_fd, &ready, 1);
        if (result == 1) break;
        if (result < 0 && errno == EINTR) continue;
        _exit(121);
    }
    if (post_ready_delay_ms != 0) {
        timespec delay{static_cast<time_t>(post_ready_delay_ms / 1000u),
                       static_cast<long>((post_ready_delay_ms % 1000u) * 1000000u)};
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
    }
    if (close(ready_fd) != 0 && prepared) _exit(128);
    unsigned char release = 0;
    for (;;) {
        const ssize_t result = read(release_fd, &release, 1);
        if (result == 1) break;
        if (result < 0 && errno == EINTR) continue;
        _exit(result == 0 ? 123 : 122);
    }
    if (close(release_fd) != 0 && prepared) _exit(129);
    if (release == kRelease && post_release_delay_ms != 0) {
        timespec delay{static_cast<time_t>(post_release_delay_ms / 1000u),
                       static_cast<long>((post_release_delay_ms % 1000u) * 1000000u)};
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
    }
    if (release != kRelease) _exit(124);
    if (continuation.kind == ChildContinuationKind::Execveat) {
        const auto report = [&](unsigned char phase, int error_number) {
            unsigned char frame[16] = {'R', 'E', 'X', '1', 1, phase, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            const unsigned int value =
                static_cast<unsigned int>(error_number == 0 ? EIO : error_number);
            frame[8] = static_cast<unsigned char>(value & 0xffu);
            frame[9] = static_cast<unsigned char>((value >> 8u) & 0xffu);
            frame[10] = static_cast<unsigned char>((value >> 16u) & 0xffu);
            frame[11] = static_cast<unsigned char>((value >> 24u) & 0xffu);
            for (;;) {
                const ssize_t written = write(exec_status_fd, frame, sizeof(frame));
                if (written < 0 && errno == EINTR) continue;
                return written == static_cast<ssize_t>(sizeof(frame));
            }
        };
        if (continuation.status_injection != 0) {
            unsigned char frame[32] = {
                'R', 'E', 'X', '1', 1, 2, 0, 0, ENOEXEC, 0, 0, 0, 0, 0, 0, 0};
            if (continuation.status_injection == 2) frame[0] = 'X';
            const std::size_t count =
                continuation.status_injection == 1                                         ? 8u
                : continuation.status_injection >= 3 && continuation.status_injection <= 4 ? 32u
                                                                                           : 16u;
            if (continuation.status_injection == 3)
                std::memcpy(frame + 16, "trailing-garbage!", 16);
            if (continuation.status_injection == 4) std::memcpy(frame + 16, frame, 16);
            if (continuation.status_injection == 6) frame[4] = 2;
            if (continuation.status_injection == 7) frame[5] = 3;
            if (continuation.status_injection == 8) frame[6] = 1;
            if (continuation.status_injection == 9) frame[8] = 0;
            (void)write(exec_status_fd, frame, count);
            if (continuation.status_injection == 5) {
                for (;;) pause();
            }
            _exit(132);
        }
        if (continuation.inject_pre_exec_failure) {
            if (!report(1u, EIO)) _exit(135);
            _exit(130);
        }
        char* argv[] = {continuation.argv0.data(), nullptr};
        char* environment[] = {nullptr};
#ifdef SYS_execveat
        syscall(SYS_execveat, executable_fd, "", argv, environment, AT_EMPTY_PATH);
        const int exec_error = errno;
#else
        const int exec_error = ENOSYS;
#endif
        if (!report(2u, exec_error)) _exit(135);
        _exit(131);
    }
    _exit(0);
}

}  // namespace

PausedChildLease::PausedChildLease() : cleanup_state_(std::make_shared<CleanupState>()) {}

PausedChildLease::~PausedChildLease() {
    if (!active_) return;
    Diagnostic diagnostic;
    bool observation_valid = false;
    ProcIdentity current;
    if (observation_pidfd_ >= 0)
        observation_valid = valid_pidfd_unbounded(
            observation_pidfd_, child_pid_, false, observation_dev_, observation_ino_);
    if (observation_valid && !same_open_file_description(observation_pidfd_, authority_pidfd_))
        observation_valid = false;
    bool reaped = child_reaped_;
    if (!reaped) {
        pid_t result = -1;
        do {
            result = waitpid(child_pid_, &child_status_, WNOHANG);
        } while (result < 0 && errno == EINTR);
        if (result == child_pid_) {
            child_reaped_ = true;
            reaped = true;
            if (settlement_) {
                settlement_->terminal = true;
                settlement_->reaped = true;
                settlement_->wait_status = child_status_;
            }
        } else if (result < 0 && errno == ECHILD) {
            // Another bounded owner may already have reaped this direct
            // child. There is no child left to signal or wait for.
            child_reaped_ = true;
            reaped = true;
            if (settlement_) {
                settlement_->terminal = true;
                settlement_->reaped = false;
                settlement_->error_number = ECHILD;
            }
        } else if (result < 0) {
            (void)close_once(release_fd_, diagnostic);
            do {
                result = waitpid(child_pid_, &child_status_, 0);
            } while (result < 0 && errno == EINTR);
            child_reaped_ = result == child_pid_;
            reaped = child_reaped_;
            if (settlement_) {
                settlement_->terminal = result == child_pid_ || (result < 0 && errno == ECHILD);
                settlement_->reaped = result == child_pid_;
                settlement_->wait_status = child_status_;
                settlement_->error_number = result < 0 ? errno : 0;
            }
        } else if (result == 0) {
            const bool authority_valid =
                valid_pidfd_unbounded(
                    authority_pidfd_, child_pid_, true, authority_dev_, authority_ino_) &&
                read_proc(child_pid_, current) && same_process_identity(identity_, current);
            if (authority_valid && pidfd_signal(authority_pidfd_, SIGKILL)) {
                do {
                    result = waitpid(child_pid_, &child_status_, 0);
                } while (result < 0 && errno == EINTR);
                reaped = result == child_pid_;
                child_reaped_ = reaped;
                if (settlement_) {
                    settlement_->terminal = reaped;
                    settlement_->reaped = reaped;
                    settlement_->wait_status = child_status_;
                }
            } else {
                (void)close_once(release_fd_, diagnostic);  // EOF is the safe fallback.
                do {
                    result = waitpid(child_pid_, &child_status_, 0);
                } while (result < 0 && errno == EINTR);
                reaped = result == child_pid_;
                child_reaped_ = reaped;
                if (settlement_) {
                    settlement_->terminal = reaped;
                    settlement_->reaped = reaped;
                    settlement_->wait_status = child_status_;
                }
            }
        }
    }
    bool success = reaped;
    if (reaped) {
        Diagnostic close_diagnostic;
        if (observation_valid)
            success = close_once(observation_pidfd_, close_diagnostic) && success;
        if (close_once(authority_pidfd_, close_diagnostic) == false) success = false;
        if (close_once(ready_fd_, close_diagnostic) == false) success = false;
        if (close_once(release_fd_, close_diagnostic) == false) success = false;
        if (close_diagnostic.phase != FailurePhase::None) diagnostic = close_diagnostic;
        active_ = false;
    }
    // Destruction is unbounded and cannot report success to its caller. Keep
    // the evidence as attempted-but-not-successful even when it left no
    // process residue.
    record_cleanup(false,
                   diagnostic.phase == FailurePhase::None
                       ? Diagnostic{FailurePhase::Cleanup, success ? 0 : ECHILD}
                       : diagnostic);
}

bool PausedChildLease::create(std::chrono::steady_clock::time_point deadline,
                              PausedChildLease& lease,
                              Diagnostic& diagnostic) {
    return create_impl(deadline, nullptr, nullptr, lease, diagnostic);
}

bool PausedChildLease::create_with_hooks_for_testing(std::chrono::steady_clock::time_point deadline,
                                                     const HooksForTesting& hooks,
                                                     PausedChildLease& lease,
                                                     Diagnostic& diagnostic) {
    return create_impl(deadline, nullptr, &hooks, lease, diagnostic);
}

bool PausedChildLease::create_prepared(std::chrono::steady_clock::time_point deadline,
                                       const ChildDescriptorPlan& plan,
                                       PausedChildLease& lease,
                                       Diagnostic& diagnostic) {
    return create_impl(deadline, &plan, nullptr, lease, diagnostic);
}

bool PausedChildLease::create_prepared_with_hooks_for_testing(
    std::chrono::steady_clock::time_point deadline,
    const ChildDescriptorPlan& plan,
    const HooksForTesting& hooks,
    PausedChildLease& lease,
    Diagnostic& diagnostic) {
    return create_impl(deadline, &plan, &hooks, lease, diagnostic);
}

bool PausedChildLease::create_impl(std::chrono::steady_clock::time_point deadline,
                                   const ChildDescriptorPlan* plan,
                                   const HooksForTesting* hooks,
                                   PausedChildLease& lease,
                                   Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.active_ || lease.released_ || !before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    const bool prepared = plan != nullptr;
    if (prepared) {
        if (plan->child_use_receipt_ &&
            plan->child_use_receipt_->state_ != PreparedChildUseState::OwnerLive) {
            fail(diagnostic,
                 FailurePhase::Argument,
                 plan->child_use_receipt_->state_ == PreparedChildUseState::Abandoned ? ESTALE
                                                                                      : EALREADY);
            return false;
        }
        const int output_fd = plan->combined_output_fd;
        if (output_fd <= 2 ||
            (hooks != nullptr && hooks->child_close_failure_fd >= 0 &&
             hooks->child_close_failure_fd == hooks->child_retain_fd_for_testing)) {
            fail(diagnostic, FailurePhase::Argument, EINVAL);
            return false;
        }
        errno = 0;
        const int output_flags = fcntl(output_fd, F_GETFD);
        if (output_flags < 0) {
            fail(diagnostic, FailurePhase::Argument, errno == 0 ? EBADF : errno);
            return false;
        }
        errno = 0;
        const int status_flags = fcntl(output_fd, F_GETFL);
        if (status_flags < 0) {
            fail(diagnostic, FailurePhase::Argument, errno == 0 ? EBADF : errno);
            return false;
        }
        if ((output_flags & FD_CLOEXEC) == 0 || (status_flags & O_ACCMODE) == O_RDONLY) {
            fail(diagnostic, FailurePhase::Argument, EINVAL);
            return false;
        }
        const bool exec_mode = plan->continuation.kind == ChildContinuationKind::Execveat;
        if (exec_mode) {
            if (plan->null_input_fd <= 2 || plan->executable_fd <= 2 || plan->exec_status_fd <= 2 ||
                plan->exec_status_authority_fd <= 2 || plan->continuation.argv0.front() != '/' ||
                plan->continuation.argv0.back() != '\0' ||
                std::find(plan->continuation.argv0.begin(), plan->continuation.argv0.end(), '\0') ==
                    plan->continuation.argv0.end()) {
                fail(diagnostic, FailurePhase::Argument, EINVAL);
                return false;
            }
            const int input_fd_flags = fcntl(plan->null_input_fd, F_GETFD);
            const int input_status = fcntl(plan->null_input_fd, F_GETFL);
            const int executable_flags = fcntl(plan->executable_fd, F_GETFD);
            const int executable_status = fcntl(plan->executable_fd, F_GETFL);
            const int writer_flags = fcntl(plan->exec_status_fd, F_GETFD);
            const int writer_status = fcntl(plan->exec_status_fd, F_GETFL);
            const int writer_authority_flags = fcntl(plan->exec_status_authority_fd, F_GETFD);
            struct stat input_stat{};
            struct stat null_stat{};
            if (input_fd_flags < 0 || input_status < 0 || executable_flags < 0 ||
                executable_status < 0 || writer_flags < 0 || writer_status < 0 ||
                fstat(plan->null_input_fd, &input_stat) != 0 ||
                stat("/dev/null", &null_stat) != 0 || !S_ISCHR(input_stat.st_mode) ||
                input_stat.st_dev != null_stat.st_dev || input_stat.st_ino != null_stat.st_ino ||
                input_stat.st_rdev != null_stat.st_rdev || (input_fd_flags & FD_CLOEXEC) == 0 ||
                (input_status & O_ACCMODE) != O_RDONLY || (executable_flags & FD_CLOEXEC) == 0 ||
                writer_authority_flags < 0 || (writer_authority_flags & FD_CLOEXEC) == 0 ||
                (executable_status & O_PATH) != O_PATH || (writer_flags & FD_CLOEXEC) == 0 ||
                (writer_status & O_ACCMODE) == O_RDONLY) {
                fail(diagnostic, FailurePhase::Argument, errno == 0 ? EINVAL : errno);
                return false;
            }
        } else if (plan->null_input_fd >= 0 || plan->executable_fd >= 0 ||
                   plan->exec_status_fd >= 0 || plan->exec_status_authority_fd >= 0) {
            fail(diagnostic, FailurePhase::Argument, EINVAL);
            return false;
        }
        for (const int standard_fd : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
            errno = 0;
            if (fcntl(standard_fd, F_GETFD) < 0) {
                fail(diagnostic, FailurePhase::Argument, errno == 0 ? EBADF : errno);
                return false;
            }
        }
    }
    std::vector<pid_t> children;
    if (!direct_children(deadline, children, diagnostic)) return false;
    if (!children.empty()) {
        fail(diagnostic, FailurePhase::Children, EBUSY);
        return false;
    }
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    if (pipe2(ready, O_CLOEXEC) != 0 || pipe2(release, O_CLOEXEC) != 0) {
        fail(diagnostic, FailurePhase::Pipe, errno);
        close_ignoring(ready[0]);
        close_ignoring(ready[1]);
        close_ignoring(release[0]);
        close_ignoring(release[1]);
        return false;
    }
    std::vector<int> inherited_fds;
    if (prepared) {
        if (plan->combined_output_fd == ready[0] || plan->combined_output_fd == ready[1] ||
            plan->combined_output_fd == release[0] || plan->combined_output_fd == release[1] ||
            ready[0] <= 2 || ready[1] <= 2 || release[0] <= 2 || release[1] <= 2 ||
            ready[0] == ready[1] || ready[0] == release[0] || ready[0] == release[1] ||
            ready[1] == release[0] || ready[1] == release[1] || release[0] == release[1]) {
            fail(diagnostic, FailurePhase::Descriptors, EINVAL);
            close_ignoring(ready[0]);
            close_ignoring(ready[1]);
            close_ignoring(release[0]);
            close_ignoring(release[1]);
            return false;
        }
        errno = 0;
        const int current_output_flags = fcntl(plan->combined_output_fd, F_GETFD);
        if (current_output_flags < 0) {
            fail(diagnostic, FailurePhase::Descriptors, errno == 0 ? EBADF : errno);
            close_ignoring(ready[0]);
            close_ignoring(ready[1]);
            close_ignoring(release[0]);
            close_ignoring(release[1]);
            return false;
        }
        if ((current_output_flags & FD_CLOEXEC) == 0) {
            fail(diagnostic, FailurePhase::Descriptors, EINVAL);
            close_ignoring(ready[0]);
            close_ignoring(ready[1]);
            close_ignoring(release[0]);
            close_ignoring(release[1]);
            return false;
        }
        if (!open_fd_snapshot(inherited_fds, diagnostic)) {
            close_ignoring(ready[0]);
            close_ignoring(ready[1]);
            close_ignoring(release[0]);
            close_ignoring(release[1]);
            return false;
        }
        const auto valid_inherited_test_fd = [&](int fd) {
            return fd < 0 || (fd > 2 && fd != ready[0] && fd != ready[1] && fd != release[0] &&
                              fd != release[1] &&
                              std::binary_search(inherited_fds.begin(), inherited_fds.end(), fd));
        };
        if (hooks != nullptr && (!valid_inherited_test_fd(hooks->child_close_failure_fd) ||
                                 !valid_inherited_test_fd(hooks->child_retain_fd_for_testing) ||
                                 (hooks->child_close_attempt_evidence != nullptr &&
                                  hooks->child_close_failure_fd < 0))) {
            fail(diagnostic, FailurePhase::Descriptors, EINVAL);
            close_ignoring(ready[0]);
            close_ignoring(ready[1]);
            close_ignoring(release[0]);
            close_ignoring(release[1]);
            return false;
        }
    }
    const pid_t parent = getpid();
    const int child_output_fd = prepared ? plan->combined_output_fd : -1;
    const int child_input_fd = prepared ? plan->null_input_fd : -1;
    const int child_executable_fd = prepared ? plan->executable_fd : -1;
    const int child_exec_status_fd = prepared ? plan->exec_status_fd : -1;
    const ChildContinuation continuation = prepared ? plan->continuation : ChildContinuation{};
    const int* const inherited_fd_data = inherited_fds.data();
    const std::size_t inherited_fd_count = inherited_fds.size();
    const unsigned int child_delay = hooks == nullptr ? 0u : hooks->child_delay_ms;
    const unsigned int post_ready_delay = hooks == nullptr ? 0u : hooks->child_post_ready_delay_ms;
    const unsigned int post_release_delay = hooks == nullptr ? 0u : hooks->post_release_delay_ms;
    const int child_close_failure_fd = hooks == nullptr ? -1 : hooks->child_close_failure_fd;
    const int child_retain_fd = hooks == nullptr ? -1 : hooks->child_retain_fd_for_testing;
    volatile int* const close_attempt_evidence =
        hooks == nullptr ? nullptr : hooks->child_close_attempt_evidence;
    if (hooks != nullptr && hooks->fail_fork) {
        fail(diagnostic, FailurePhase::Fork, EAGAIN);
        close_ignoring(ready[0]);
        close_ignoring(ready[1]);
        close_ignoring(release[0]);
        close_ignoring(release[1]);
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        fail(diagnostic, FailurePhase::Fork, errno);
        close_ignoring(ready[0]);
        close_ignoring(ready[1]);
        close_ignoring(release[0]);
        close_ignoring(release[1]);
        return false;
    }
    if (child == 0) {
        if (!prepared) {
            close(ready[0]);
            close(release[1]);
        }
        child_main(ready[1],
                   release[0],
                   parent,
                   child_delay,
                   post_ready_delay,
                   post_release_delay,
                   prepared,
                   child_output_fd,
                   child_input_fd,
                   child_executable_fd,
                   child_exec_status_fd,
                   continuation,
                   inherited_fd_data,
                   inherited_fd_count,
                   child_close_failure_fd,
                   child_retain_fd,
                   close_attempt_evidence);
    }
    close(ready[1]);
    close(release[0]);
    const auto reap_failed_child = [&]() {
        int status = 0;
        if (!reap_child_until(child, status, deadline)) {
            // The normal child exits on release EOF. If an injected failure
            // prevents that bounded reap, retain an active local owner whose
            // unbounded destructor wait is the emergency containment path.
            PausedChildLease emergency;
            emergency.child_pid_ = child;
            emergency.active_ = true;
        }
    };
    int observation = hooks != nullptr && hooks->pidfd_open != nullptr
                          ? hooks->pidfd_open(child, 0u)
                          : open_pidfd(child);
    if (observation < 0) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? ENOSYS : errno);
        close_ignoring(ready[0]);
        close_ignoring(release[1]);  // Child observes EOF and exits nonzero.
        reap_failed_child();
        return false;
    }
    const int authority = fcntl(observation, F_DUPFD_CLOEXEC, 0);
    if (authority < 0) {
        fail(diagnostic, FailurePhase::Pidfd, errno);
        close_ignoring(observation);
        close_ignoring(ready[0]);
        close_ignoring(release[1]);
        reap_failed_child();
        return false;
    }
    PausedChildLease candidate;
    candidate.ready_fd_ = ready[0];
    candidate.release_fd_ = release[1];
    candidate.observation_pidfd_ = observation;
    candidate.authority_pidfd_ = authority;
    candidate.parent_pid_ = parent;
    candidate.child_pid_ = child;
    candidate.close_hook_ = hooks == nullptr ? nullptr : hooks->close_fd;
    candidate.close_context_ = hooks == nullptr ? nullptr : hooks->close_context;
    candidate.mode_ = prepared ? Mode::Prepared : Mode::Plain;
    candidate.combined_output_fd_ = prepared ? plan->combined_output_fd : -1;
    candidate.child_release_fd_ = prepared ? release[0] : -1;
    candidate.null_input_fd_ = prepared ? plan->null_input_fd : -1;
    candidate.child_executable_fd_ = prepared ? plan->executable_fd : -1;
    candidate.child_exec_status_fd_ = prepared ? plan->exec_status_fd : -1;
    candidate.exec_status_authority_fd_ = prepared ? plan->exec_status_authority_fd : -1;
    candidate.continuation_ = continuation;
    candidate.kcmp_file_hook_ = hooks == nullptr ? nullptr : hooks->kcmp_file;
    candidate.prepared_procfs_allowed_hook_ =
        hooks == nullptr ? nullptr : hooks->prepared_procfs_allowed;
    candidate.prepared_validation_context_ =
        hooks == nullptr ? nullptr : hooks->prepared_validation_context;
    candidate.active_ = true;
    candidate.settlement_ = std::make_shared<SettlementReceipt>();
    candidate.settlement_->child_pid = child;
    if (!candidate.validate_pidfd(observation, true, deadline, diagnostic) ||
        !candidate.validate_pidfd(authority, true, deadline, diagnostic)) {
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.ready_fd_);
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    struct stat observation_status{};
    struct stat authority_status{};
    if (fstat(observation, &observation_status) != 0 || fstat(authority, &authority_status) != 0) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? EIO : errno);
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    candidate.observation_dev_ = observation_status.st_dev;
    candidate.observation_ino_ = observation_status.st_ino;
    candidate.authority_dev_ = authority_status.st_dev;
    candidate.authority_ino_ = authority_status.st_ino;
    if (!wait_fd_until(candidate.ready_fd_, POLLIN, deadline)) {
        fail(diagnostic, FailurePhase::Readiness, ETIMEDOUT);
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.ready_fd_);
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    unsigned char byte = 0;
    if (!read_byte_until(candidate.ready_fd_, byte, deadline) || byte != kReady) {
        fail(diagnostic, FailurePhase::Readiness, EPROTO);
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.ready_fd_);
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    int readiness_eof_error = 0;
    if (prepared && !read_eof_until(candidate.ready_fd_, deadline, readiness_eof_error)) {
        fail(diagnostic,
             FailurePhase::Readiness,
             readiness_eof_error == 0 ? EPROTO : readiness_eof_error);
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.ready_fd_);
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    Diagnostic ready_close_diagnostic;
    if (!candidate.close_fd(candidate.ready_fd_, ready_close_diagnostic)) {
        diagnostic = ready_close_diagnostic;
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    if (!read_proc(child, candidate.identity_) || candidate.identity_.ppid != parent) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    if (!candidate.validate_identity(deadline, diagnostic) ||
        !candidate.validate_bound_child(deadline, diagnostic) ||
        (prepared && !candidate.validate_prepared_descriptors(deadline, diagnostic))) {
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    // Expose no partially initialized object: copy the fully validated state.
    lease.ready_fd_ = candidate.ready_fd_;
    lease.release_fd_ = candidate.release_fd_;
    lease.observation_pidfd_ = candidate.observation_pidfd_;
    lease.authority_pidfd_ = candidate.authority_pidfd_;
    lease.parent_pid_ = candidate.parent_pid_;
    lease.child_pid_ = candidate.child_pid_;
    lease.identity_ = candidate.identity_;
    lease.observation_dev_ = candidate.observation_dev_;
    lease.observation_ino_ = candidate.observation_ino_;
    lease.authority_dev_ = candidate.authority_dev_;
    lease.authority_ino_ = candidate.authority_ino_;
    lease.close_hook_ = candidate.close_hook_;
    lease.close_context_ = candidate.close_context_;
    lease.mode_ = candidate.mode_;
    lease.combined_output_fd_ = candidate.combined_output_fd_;
    lease.child_release_fd_ = candidate.child_release_fd_;
    lease.null_input_fd_ = candidate.null_input_fd_;
    lease.child_executable_fd_ = candidate.child_executable_fd_;
    lease.child_exec_status_fd_ = candidate.child_exec_status_fd_;
    lease.exec_status_authority_fd_ = candidate.exec_status_authority_fd_;
    lease.continuation_ = candidate.continuation_;
    lease.kcmp_file_hook_ = candidate.kcmp_file_hook_;
    lease.prepared_procfs_allowed_hook_ = candidate.prepared_procfs_allowed_hook_;
    lease.prepared_validation_context_ = candidate.prepared_validation_context_;
    lease.active_ = true;
    lease.settlement_ = candidate.settlement_;
    lease.settlement_->identity = lease.identity_;
    if (prepared && plan->child_use_receipt_) {
        plan->child_use_receipt_->state_ = PreparedChildUseState::Claimed;
        plan->child_use_receipt_->child_pid_ = child;
        plan->child_use_receipt_->settlement_ = lease.settlement_;
    }
    candidate.ready_fd_ = -1;
    candidate.release_fd_ = -1;
    candidate.observation_pidfd_ = -1;
    candidate.authority_pidfd_ = -1;
    candidate.active_ = false;
    return true;
}

bool PausedChildLease::validate_pidfd(int fd,
                                      bool require_live,
                                      std::chrono::steady_clock::time_point deadline,
                                      Diagnostic& diagnostic) const {
    if (fd < 0) {
        fail(diagnostic, FailurePhase::Pidfd, EBADF);
        return false;
    }
    if (!before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Pidfd, ETIMEDOUT);
        return false;
    }
    const int flags = fcntl(fd, F_GETFD);
    const bool object_ok =
        fd == observation_pidfd_
            ? (observation_dev_ == 0 || same_fd_object(fd, observation_dev_, observation_ino_))
            : (authority_dev_ == 0 || same_fd_object(fd, authority_dev_, authority_ino_));
    if (flags < 0) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? EBADF : errno);
        return false;
    }
    if ((flags & FD_CLOEXEC) == 0 || !object_ok || !pidfd_binding(fd, child_pid_, !require_live)) {
        fail(diagnostic, FailurePhase::Pidfd, EINVAL);
        return false;
    }
    if (require_live && !pidfd_live_until(fd, deadline)) {
        fail(diagnostic, FailurePhase::Pidfd, before_deadline(deadline) ? EIO : ETIMEDOUT);
        return false;
    }
    return true;
}

bool PausedChildLease::validate_identity(std::chrono::steady_clock::time_point deadline,
                                         Diagnostic& diagnostic) const {
    if (!before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Identity, ETIMEDOUT);
        return false;
    }
    ProcIdentity current;
    if (!read_proc(child_pid_, current) || !same_process_identity(identity_, current) ||
        current.ppid != parent_pid_) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        return false;
    }
    return true;
}

bool PausedChildLease::validate_bound_child(std::chrono::steady_clock::time_point deadline,
                                            Diagnostic& diagnostic) const {
    if (!validate_pidfd(observation_pidfd_, true, deadline, diagnostic) ||
        !validate_pidfd(authority_pidfd_, true, deadline, diagnostic))
        return false;
    if (!same_open_file_description(observation_pidfd_, authority_pidfd_)) {
        fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? EINVAL : errno);
        return false;
    }
    if (!validate_identity(deadline, diagnostic)) return false;
    std::vector<pid_t> children;
    if (!direct_children(deadline, children, diagnostic)) return false;
    if (children.size() != 1 || children.front() != child_pid_) {
        fail(diagnostic, FailurePhase::Children, ECHILD);
        return false;
    }
    return true;
}

bool PausedChildLease::validate_prepared_descriptors(std::chrono::steady_clock::time_point deadline,
                                                     Diagnostic& diagnostic) const {
    if (mode_ != Mode::Prepared || combined_output_fd_ <= 2 || child_release_fd_ <= 2) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    if (!before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Descriptors, ETIMEDOUT);
        return false;
    }
    const int output_flags = fcntl(combined_output_fd_, F_GETFD);
    const int status_flags = fcntl(combined_output_fd_, F_GETFL);
    if (output_flags < 0 || status_flags < 0 || (output_flags & FD_CLOEXEC) == 0 ||
        (status_flags & O_ACCMODE) == O_RDONLY) {
        fail(diagnostic,
             FailurePhase::Descriptors,
             (output_flags < 0 || status_flags < 0) && errno != 0 ? errno : EINVAL);
        return false;
    }
    if (prepared_procfs_allowed_hook_ != nullptr &&
        !prepared_procfs_allowed_hook_(prepared_validation_context_)) {
        fail(diagnostic, FailurePhase::Descriptors, EACCES);
        return false;
    }
    std::vector<int> descriptors;
    if (!process_fd_snapshot(child_pid_, descriptors)) {
        fail(diagnostic, FailurePhase::Descriptors, errno == 0 ? EIO : errno);
        return false;
    }
    const bool exec_mode = continuation_.kind == ChildContinuationKind::Execveat;
    std::vector<int> expected{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, child_release_fd_};
    if (exec_mode) {
        expected.push_back(child_executable_fd_);
        expected.push_back(child_exec_status_fd_);
    }
    std::sort(expected.begin(), expected.end());
    if (descriptors != expected) {
        fail(diagnostic, FailurePhase::Descriptors, EPROTO);
        return false;
    }
    bool stdout_cloexec = true;
    bool stderr_cloexec = true;
    bool release_cloexec = false;
    bool input_cloexec = true;
    bool executable_cloexec = false;
    bool status_writer_cloexec = false;
    if (!process_fd_cloexec(child_pid_, STDOUT_FILENO, stdout_cloexec) ||
        !process_fd_cloexec(child_pid_, STDERR_FILENO, stderr_cloexec) ||
        !process_fd_cloexec(child_pid_, child_release_fd_, release_cloexec) ||
        (exec_mode && !process_fd_cloexec(child_pid_, STDIN_FILENO, input_cloexec)) ||
        (exec_mode &&
         (!process_fd_cloexec(child_pid_, child_executable_fd_, executable_cloexec) ||
          !process_fd_cloexec(child_pid_, child_exec_status_fd_, status_writer_cloexec)))) {
        fail(diagnostic, FailurePhase::Descriptors, errno == 0 ? EIO : errno);
        return false;
    }
    if ((exec_mode && input_cloexec) || stdout_cloexec || stderr_cloexec || !release_cloexec ||
        (exec_mode && (!executable_cloexec || !status_writer_cloexec))) {
        fail(diagnostic, FailurePhase::Descriptors, EINVAL);
        return false;
    }
    const auto compare = [&](int parent_fd, int child_fd) {
        errno = 0;
        if (kcmp_file_hook_ != nullptr)
            return kcmp_file_hook_(parent_pid_,
                                   child_pid_,
                                   parent_fd,
                                   child_fd,
                                   prepared_validation_context_) == 0;
#ifdef SYS_kcmp
        return syscall(SYS_kcmp, parent_pid_, child_pid_, KCMP_FILE, parent_fd, child_fd) == 0;
#else
        errno = ENOSYS;
        return false;
#endif
    };
    if (!compare(combined_output_fd_, STDOUT_FILENO) ||
        !compare(combined_output_fd_, STDERR_FILENO) ||
        (exec_mode && (!compare(null_input_fd_, STDIN_FILENO) ||
                       !compare(child_executable_fd_, child_executable_fd_) ||
                       !compare(exec_status_authority_fd_, child_exec_status_fd_)))) {
        fail(diagnostic, FailurePhase::Descriptors, errno == 0 ? EINVAL : errno);
        return false;
    }
    if (!before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Descriptors, ETIMEDOUT);
        return false;
    }
    return true;
}

bool PausedChildLease::validate_paused(std::chrono::steady_clock::time_point deadline,
                                       Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || released_ || release_sent_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        return false;
    }
    if (!validate_bound_child(deadline, diagnostic)) return false;
    return mode_ == Mode::Plain || validate_prepared_descriptors(deadline, diagnostic);
}

bool PausedChildLease::validate_prepared(std::chrono::steady_clock::time_point deadline,
                                         Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || released_ || release_sent_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        return false;
    }
    if (mode_ != Mode::Prepared) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    return validate_bound_child(deadline, diagnostic) &&
           validate_prepared_descriptors(deadline, diagnostic);
}

bool PausedChildLease::wait_reap(std::chrono::steady_clock::time_point deadline,
                                 Diagnostic& diagnostic) {
    while (!child_reaped_) {
        const pid_t result = waitpid(child_pid_, &child_status_, WNOHANG);
        if (result == child_pid_) {
            child_reaped_ = true;
            if (settlement_) {
                settlement_->terminal = true;
                settlement_->reaped = true;
                settlement_->wait_status = child_status_;
                settlement_->error_number = 0;
            }
            break;
        }
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) {
            if (settlement_) {
                settlement_->terminal = true;
                settlement_->reaped = false;
                settlement_->error_number = errno;
            }
            fail(diagnostic, FailurePhase::Wait, errno);
            return false;
        }
        const int timeout = remaining_ms(deadline);
        if (timeout <= 0) {
            fail(diagnostic, FailurePhase::Wait, ETIMEDOUT);
            return false;
        }
        poll(nullptr, 0, timeout > 5 ? 5 : timeout);
    }
    return true;
}

bool PausedChildLease::close_fd(int& fd, Diagnostic& diagnostic) {
    if (fd < 0) return true;
    const int old = fd;
    fd = -1;
    const int result = close_hook_ == nullptr ? close(old) : close_hook_(old, close_context_);
    if (result == 0) return true;
    fail(diagnostic, FailurePhase::Close, errno == 0 ? EIO : errno);
    return false;
}

bool PausedChildLease::close_after_reap(Diagnostic& diagnostic, bool observation_valid) {
    bool success = true;
    Diagnostic close_diagnostic;
    if (observation_valid && !same_open_file_description(observation_pidfd_, authority_pidfd_)) {
        fail(diagnostic, FailurePhase::Close, errno == 0 ? EINVAL : errno);
        return false;
    }
    if (observation_valid) success = close_fd(observation_pidfd_, close_diagnostic) && success;
    success = close_fd(authority_pidfd_, close_diagnostic) && success;
    success = close_fd(release_fd_, close_diagnostic) && success;
    if (close_diagnostic.phase != FailurePhase::None) diagnostic = close_diagnostic;
    if (success) {
        active_ = false;
        released_ = true;
    }
    return success;
}

bool PausedChildLease::release(std::chrono::steady_clock::time_point deadline,
                               Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || released_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        return false;
    }
    const bool observation_valid_before = !release_sent_;
    Diagnostic release_close_diagnostic;
    if (!release_sent_) {
        const ReleaseSendState send_state = send_release(deadline, diagnostic);
        if (send_state == ReleaseSendState::NotSent) return false;
        if (send_state == ReleaseSendState::SentCloseUncertain)
            release_close_diagnostic = diagnostic;
    }
    if (mode_ == Mode::Prepared && !prepared_release_authorized_) {
        fail(diagnostic, FailurePhase::Release, EPERM);
        return false;
    }
    if (!wait_reap(deadline, diagnostic)) return false;
    if (!WIFEXITED(child_status_) || WEXITSTATUS(child_status_) != 0) {
        fail(diagnostic, FailurePhase::Release, EPROTO);
        return false;
    }
    bool observation_valid = observation_valid_before;
    if (!observation_valid) {
        observation_valid = validate_pidfd(observation_pidfd_, false, deadline, diagnostic);
        if (!observation_valid) return false;
    }
    const bool closed = close_after_reap(diagnostic, observation_valid);
    if (release_close_uncertain_) {
        active_ = false;
        released_ = true;
        diagnostic = release_close_diagnostic.phase == FailurePhase::None
                         ? Diagnostic{FailurePhase::Close, EIO}
                         : release_close_diagnostic;
        record_cleanup(false, diagnostic);
        return false;
    }
    return closed;
}

ReleaseSendState PausedChildLease::send_release(std::chrono::steady_clock::time_point deadline,
                                                Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || released_ || release_sent_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        return ReleaseSendState::NotSent;
    }
    const bool exec_mode =
        mode_ == Mode::Prepared && continuation_.kind == ChildContinuationKind::Execveat;
    if (exec_mode && !prepared_release_authorized_) {
        fail(diagnostic, FailurePhase::Release, EPERM);
        return ReleaseSendState::NotSent;
    }
    if (!validate_bound_child(deadline, diagnostic) ||
        (mode_ == Mode::Prepared && !prepared_release_authorized_ &&
         !validate_prepared_descriptors(deadline, diagnostic)))
        return ReleaseSendState::NotSent;
    if (!write_byte_until(release_fd_, kRelease, deadline)) {
        fail(diagnostic, FailurePhase::Release, ETIMEDOUT);
        return ReleaseSendState::NotSent;
    }
    release_sent_ = true;
    if (mode_ == Mode::Prepared) prepared_release_authorized_ = true;
    Diagnostic close_diagnostic;
    if (!close_fd(release_fd_, close_diagnostic)) {
        diagnostic = close_diagnostic;
        release_close_uncertain_ = true;
        return ReleaseSendState::SentCloseUncertain;
    }
    return ReleaseSendState::Sent;
}

bool PausedChildLease::authorize_exec_release(std::chrono::steady_clock::time_point deadline,
                                              Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || released_ || release_sent_ || mode_ != Mode::Prepared ||
        continuation_.kind != ChildContinuationKind::Execveat || prepared_release_authorized_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        return false;
    }
    if (!validate_bound_child(deadline, diagnostic) ||
        !validate_prepared_descriptors(deadline, diagnostic))
        return false;
    prepared_release_authorized_ = true;
    return true;
}

bool PausedChildLease::cleanup(std::chrono::steady_clock::time_point deadline,
                               Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_) {
        fail(diagnostic, FailurePhase::Argument, EALREADY);
        record_cleanup(false, diagnostic);
        return false;
    }
    pid_t result = child_pid_;
    if (!child_reaped_) {
        for (;;) {
            result = waitpid(child_pid_, &child_status_, WNOHANG);
            if (result >= 0 || errno != EINTR) break;
            if (!before_deadline(deadline)) {
                fail(diagnostic, FailurePhase::Cleanup, ETIMEDOUT);
                record_cleanup(false, diagnostic);
                return false;
            }
        }
    }
    if (result == child_pid_) {
        child_reaped_ = true;
        if (settlement_) {
            settlement_->terminal = true;
            settlement_->reaped = true;
            settlement_->wait_status = child_status_;
            settlement_->error_number = 0;
        }
    } else if (result < 0 && errno == ECHILD && settlement_) {
        settlement_->terminal = true;
        settlement_->reaped = false;
        settlement_->error_number = ECHILD;
    }
    bool observation_valid = false;
    if (!child_reaped_ && result == 0) {
        ProcIdentity current;
        if (!validate_pidfd(observation_pidfd_, true, deadline, diagnostic) ||
            !validate_pidfd(authority_pidfd_, true, deadline, diagnostic)) {
            record_cleanup(false, diagnostic);
            return false;
        }
        if (!same_open_file_description(observation_pidfd_, authority_pidfd_)) {
            fail(diagnostic, FailurePhase::Pidfd, errno == 0 ? EINVAL : errno);
            record_cleanup(false, diagnostic);
            return false;
        }
        if (!read_proc(child_pid_, current) || !same_process_identity(identity_, current) ||
            current.ppid != parent_pid_) {
            fail(diagnostic, FailurePhase::Cleanup, ESTALE);
            record_cleanup(false, diagnostic);
            return false;
        }
        observation_valid = true;
        if (!pidfd_signal(authority_pidfd_, SIGKILL)) {
            fail(diagnostic, FailurePhase::Cleanup, errno == 0 ? EIO : errno);
            record_cleanup(false, diagnostic);
            return false;
        }
        if (!wait_reap(deadline, diagnostic)) {
            record_cleanup(false, diagnostic);
            return false;
        }
    }
    if (!child_reaped_) {
        fail(diagnostic, FailurePhase::Cleanup, ECHILD);
        record_cleanup(false, diagnostic);
        return false;
    }
    if (!observation_valid)
        observation_valid = validate_pidfd(observation_pidfd_, false, deadline, diagnostic);
    if (!observation_valid) {
        record_cleanup(false, diagnostic);  // Never close a wrong observation slot.
        return false;
    }
    const bool result_ok = true;  // Cleanup intentionally accepts signal termination.
    const bool closed = close_after_reap(diagnostic, true);
    if (!closed) {
        record_cleanup(false, diagnostic);
        return false;
    }
    if (!result_ok) {
        fail(diagnostic, FailurePhase::Cleanup, ECHILD);
        record_cleanup(false, diagnostic);
        return false;
    }
    record_cleanup(true, Diagnostic{});
    return true;
}

void PausedChildLease::record_cleanup(bool succeeded, const Diagnostic& diagnostic) {
    if (!cleanup_state_) cleanup_state_ = std::make_shared<CleanupState>();
    cleanup_state_->attempted = true;
    cleanup_state_->succeeded = succeeded;
    cleanup_state_->diagnostic = diagnostic;
}

}  // namespace rut::test::fixture_wildcard_paused_child_lease
