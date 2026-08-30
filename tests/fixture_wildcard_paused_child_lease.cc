#include "fixture_wildcard_paused_child_lease.h"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
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
        std::size_t consumed = 0;
        unsigned long long value = 0;
        try {
            value = std::stoull(token, &consumed, 10);
        } catch (...) {
            fail(diagnostic, FailurePhase::Children, EPROTO);
            return false;
        }
        if (consumed != token.size() || value <= 1 ||
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

void child_main(int ready_fd, int release_fd, pid_t expected_parent) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent) _exit(120);
    unsigned char ready = kReady;
    for (;;) {
        const ssize_t result = write(ready_fd, &ready, 1);
        if (result == 1) break;
        if (result < 0 && errno == EINTR) continue;
        _exit(121);
    }
    close(ready_fd);
    unsigned char release = 0;
    for (;;) {
        const ssize_t result = read(release_fd, &release, 1);
        if (result == 1) break;
        if (result < 0 && errno == EINTR) continue;
        _exit(result == 0 ? 123 : 122);
    }
    close(release_fd);
    _exit(release == kRelease ? 0 : 124);
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
    bool reaped = child_reaped_;
    if (!reaped) {
        pid_t result = -1;
        do {
            result = waitpid(child_pid_, &child_status_, WNOHANG);
        } while (result < 0 && errno == EINTR);
        if (result == child_pid_) {
            child_reaped_ = true;
            reaped = true;
        } else if (result < 0 && errno == ECHILD) {
            // Another bounded owner may already have reaped this direct
            // child. There is no child left to signal or wait for.
            child_reaped_ = true;
            reaped = true;
        } else if (result < 0) {
            (void)close_once(release_fd_, diagnostic);
            do {
                result = waitpid(child_pid_, &child_status_, 0);
            } while (result < 0 && errno == EINTR);
            child_reaped_ = result == child_pid_;
            reaped = child_reaped_;
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
            } else {
                (void)close_once(release_fd_, diagnostic);  // EOF is the safe fallback.
                do {
                    result = waitpid(child_pid_, &child_status_, 0);
                } while (result < 0 && errno == EINTR);
                reaped = result == child_pid_;
                child_reaped_ = reaped;
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
    return create_impl(deadline, nullptr, lease, diagnostic);
}

bool PausedChildLease::create_with_hooks_for_testing(std::chrono::steady_clock::time_point deadline,
                                                     const HooksForTesting& hooks,
                                                     PausedChildLease& lease,
                                                     Diagnostic& diagnostic) {
    return create_impl(deadline, &hooks, lease, diagnostic);
}

bool PausedChildLease::create_impl(std::chrono::steady_clock::time_point deadline,
                                   const HooksForTesting* hooks,
                                   PausedChildLease& lease,
                                   Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.active_ || lease.released_ || !before_deadline(deadline)) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
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
    const pid_t parent = getpid();
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
        close(ready[0]);
        close(release[1]);
        child_main(ready[1], release[0], parent);
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
    candidate.active_ = true;
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
    close_ignoring(candidate.ready_fd_);
    if (!read_proc(child, candidate.identity_) || candidate.identity_.ppid != parent) {
        fail(diagnostic, FailurePhase::Identity, ESTALE);
        close_ignoring(candidate.release_fd_);
        reap_failed_child();
        close_ignoring(candidate.observation_pidfd_);
        close_ignoring(candidate.authority_pidfd_);
        return false;
    }
    if (!candidate.validate_identity(deadline, diagnostic) ||
        !candidate.validate_bound_child(deadline, diagnostic)) {
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
    lease.active_ = true;
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
    if (!validate_identity(deadline, diagnostic)) return false;
    std::vector<pid_t> children;
    if (!direct_children(deadline, children, diagnostic)) return false;
    if (children.size() != 1 || children.front() != child_pid_) {
        fail(diagnostic, FailurePhase::Children, ECHILD);
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
    return validate_bound_child(deadline, diagnostic);
}

bool PausedChildLease::wait_reap(std::chrono::steady_clock::time_point deadline,
                                 Diagnostic& diagnostic) {
    while (!child_reaped_) {
        const pid_t result = waitpid(child_pid_, &child_status_, WNOHANG);
        if (result == child_pid_) {
            child_reaped_ = true;
            break;
        }
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) {
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
    return close_once(fd, diagnostic);
}

bool PausedChildLease::close_after_reap(Diagnostic& diagnostic, bool observation_valid) {
    bool success = true;
    Diagnostic close_diagnostic;
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
    bool observation_valid = false;
    if (!release_sent_) {
        if (!validate_bound_child(deadline, diagnostic)) return false;
        observation_valid = true;
        if (!write_byte_until(release_fd_, kRelease, deadline)) {
            fail(diagnostic, FailurePhase::Release, ETIMEDOUT);
            return false;
        }
        release_sent_ = true;
        Diagnostic close_diagnostic;
        if (!close_fd(release_fd_, close_diagnostic)) diagnostic = close_diagnostic;
    }
    if (!wait_reap(deadline, diagnostic)) return false;
    if (!WIFEXITED(child_status_) || WEXITSTATUS(child_status_) != 0) {
        fail(diagnostic, FailurePhase::Release, EPROTO);
        return false;
    }
    if (!observation_valid)
        observation_valid = validate_pidfd(observation_pidfd_, false, deadline, diagnostic);
    return close_after_reap(diagnostic, observation_valid);
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
    if (result == child_pid_) child_reaped_ = true;
    bool observation_valid = false;
    if (!child_reaped_ && result == 0) {
        ProcIdentity current;
        if (!validate_pidfd(observation_pidfd_, true, deadline, diagnostic) ||
            !validate_pidfd(authority_pidfd_, true, deadline, diagnostic) ||
            !read_proc(child_pid_, current) || !same_process_identity(identity_, current) ||
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
