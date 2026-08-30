#include "fixture_executable_exec_handoff.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <string>

#include <fcntl.h>
#include <linux/kcmp.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut::test::fixture_executable_exec_handoff {
namespace {

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number) {
    diagnostic = {phase, error_number == 0 ? EIO : error_number};
}

int remaining_ms(std::chrono::steady_clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) return 0;
    return static_cast<int>(std::min<std::int64_t>(left.count(), std::numeric_limits<int>::max()));
}

bool pidfd_live(int fd) {
    pollfd descriptor{fd, POLLIN | POLLERR | POLLHUP, 0};
    for (;;) {
        const int result = poll(&descriptor, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        return result == 0 && descriptor.revents == 0;
    }
}

bool exact_live_identity(pid_t pid,
                         int pidfd,
                         const std::string& path,
                         const executable::ExecutableIdentity& expected_executable,
                         child_fixture::ProcIdentity& identity) {
    if (!pidfd_live(pidfd) || !fixture_worker_protocol::read_proc(pid, identity)) return false;
    std::string environment;
    if (!fixture_worker_protocol::read_file(
            "/proc/" + std::to_string(pid) + "/environ", environment, 1) ||
        !environment.empty())
        return false;
    const std::string expected_argv = path + std::string(1, '\0');
    return identity.pid == pid && identity.ppid == getpid() && identity.exe == path &&
           static_cast<std::uint64_t>(identity.exe_dev) == expected_executable.device &&
           static_cast<std::uint64_t>(identity.exe_ino) == expected_executable.inode &&
           identity.cmdline == expected_argv;
}

}  // namespace

ExecutableExecHandoffLease::ExecutableExecHandoffLease()
    : cleanup_(std::make_shared<CleanupState>()) {}

ExecutableExecHandoffLease::~ExecutableExecHandoffLease() {
    if (active_) destructor_cleanup();
}

bool ExecutableExecHandoffLease::create(executable::ExecutableLease& source,
                                        ExecutableExecHandoffLease& lease,
                                        Diagnostic& diagnostic) {
    return create_impl(source, nullptr, lease, diagnostic);
}

bool ExecutableExecHandoffLease::create_with_hooks_for_testing(executable::ExecutableLease& source,
                                                               const HooksForTesting& hooks,
                                                               ExecutableExecHandoffLease& lease,
                                                               Diagnostic& diagnostic) {
    return create_impl(source, &hooks, lease, diagnostic);
}

bool ExecutableExecHandoffLease::create_impl(executable::ExecutableLease& source,
                                             const HooksForTesting* hooks,
                                             ExecutableExecHandoffLease& lease,
                                             Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.active_ || lease.plan_made_ || !source.active()) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    executable::Diagnostic source_diagnostic;
    if (!source.revalidate(source_diagnostic)) {
        fail(diagnostic, FailurePhase::Source, source_diagnostic.error_number);
        return false;
    }
    const int executable_fd = fcntl(source.observation_fd(), F_DUPFD_CLOEXEC, 3);
    const int authority_one =
        executable_fd < 0 ? -1 : fcntl(source.observation_fd(), F_DUPFD_CLOEXEC, 3);
    const int authority_two =
        authority_one < 0 ? -1 : fcntl(source.observation_fd(), F_DUPFD_CLOEXEC, 3);
    if (executable_fd < 0 || authority_one < 0 || authority_two < 0) {
        const int error_number = errno == 0 ? EMFILE : errno;
        if (executable_fd >= 0) ::close(executable_fd);
        if (authority_one >= 0) ::close(authority_one);
        if (authority_two >= 0) ::close(authority_two);
        fail(diagnostic, FailurePhase::Duplicate, error_number);
        return false;
    }
    ExecutableExecHandoffLease candidate;
    candidate.executable_fd_ = executable_fd;
    candidate.authority_one_fd_ = authority_one;
    candidate.authority_two_fd_ = authority_two;
    candidate.canonical_path_ = source.canonical_path();
    candidate.identity_ = source.identity();
    if (hooks != nullptr) candidate.hooks_ = *hooks;
    candidate.active_ = true;
    if (!candidate.validate_custody(diagnostic) || !source.revalidate(source_diagnostic)) {
        if (diagnostic.phase == FailurePhase::None)
            fail(diagnostic, FailurePhase::Source, source_diagnostic.error_number);
        ::close(candidate.executable_fd_);
        ::close(candidate.authority_one_fd_);
        ::close(candidate.authority_two_fd_);
        candidate.active_ = false;
        return false;
    }
    lease.executable_fd_ = candidate.executable_fd_;
    lease.authority_one_fd_ = candidate.authority_one_fd_;
    lease.authority_two_fd_ = candidate.authority_two_fd_;
    lease.canonical_path_ = candidate.canonical_path_;
    lease.identity_ = candidate.identity_;
    lease.hooks_ = candidate.hooks_;
    lease.active_ = true;
    candidate.active_ = false;
    candidate.executable_fd_ = candidate.authority_one_fd_ = candidate.authority_two_fd_ = -1;
    return true;
}

bool ExecutableExecHandoffLease::same_ofd(pid_t first_pid,
                                          pid_t second_pid,
                                          int first,
                                          int second) const {
    errno = 0;
    if (hooks_.kcmp_file != nullptr)
        return hooks_.kcmp_file(first_pid, second_pid, first, second, hooks_.context) == 0;
#ifdef SYS_kcmp
    return syscall(SYS_kcmp, first_pid, second_pid, KCMP_FILE, first, second) == 0;
#else
    errno = ENOSYS;
    return false;
#endif
}

bool ExecutableExecHandoffLease::validate_custody(Diagnostic& diagnostic) const {
    for (const int fd : {executable_fd_, authority_one_fd_, authority_two_fd_}) {
        errno = 0;
        const int descriptor_flags = fcntl(fd, F_GETFD);
        const int status_flags = fcntl(fd, F_GETFL);
        struct stat status{};
        if (descriptor_flags < 0 || status_flags < 0 || fstat(fd, &status) != 0 ||
            (descriptor_flags & FD_CLOEXEC) == 0 || (status_flags & O_PATH) != O_PATH ||
            static_cast<std::uint64_t>(status.st_dev) != identity_.device ||
            static_cast<std::uint64_t>(status.st_ino) != identity_.inode) {
            fail(diagnostic, FailurePhase::Custody, errno == 0 ? ESTALE : errno);
            return false;
        }
    }
    if (!same_ofd(getpid(), getpid(), executable_fd_, authority_one_fd_) ||
        !same_ofd(getpid(), getpid(), executable_fd_, authority_two_fd_) ||
        !same_ofd(getpid(), getpid(), authority_one_fd_, authority_two_fd_)) {
        fail(diagnostic, FailurePhase::Custody, errno == 0 ? ESTALE : errno);
        return false;
    }
    return true;
}

bool ExecutableExecHandoffLease::make_child_plan(int borrowed_null_input_fd,
                                                 int borrowed_combined_output_fd,
                                                 bool inject_pre_exec_failure,
                                                 child_fixture::ChildDescriptorPlan& plan,
                                                 Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || plan_made_ || borrowed_null_input_fd <= 2 || borrowed_combined_output_fd <= 2 ||
        borrowed_null_input_fd == borrowed_combined_output_fd ||
        borrowed_null_input_fd == executable_fd_ || borrowed_combined_output_fd == executable_fd_ ||
        borrowed_null_input_fd == authority_one_fd_ ||
        borrowed_null_input_fd == authority_two_fd_ ||
        borrowed_combined_output_fd == authority_one_fd_ ||
        borrowed_combined_output_fd == authority_two_fd_ || !validate_custody(diagnostic)) {
        if (diagnostic.phase == FailurePhase::None)
            fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    int status[2] = {-1, -1};
    if (pipe2(status, O_CLOEXEC) != 0) {
        fail(diagnostic, FailurePhase::Pipe, errno);
        return false;
    }
    const int authority = fcntl(status[1], F_DUPFD_CLOEXEC, 3);
    if (authority < 0) {
        const int error_number = errno;
        ::close(status[0]);
        ::close(status[1]);
        fail(diagnostic, FailurePhase::Pipe, error_number);
        return false;
    }
    child_fixture::ChildContinuation continuation;
    continuation.kind = child_fixture::ChildContinuationKind::Execveat;
    continuation.inject_pre_exec_failure = inject_pre_exec_failure;
    continuation.status_injection = hooks_.child_status_injection;
    continuation.executable_mutation = hooks_.child_executable_mutation;
    if (canonical_path_.size() + 1 > continuation.argv0.size()) {
        ::close(status[0]);
        ::close(status[1]);
        ::close(authority);
        fail(diagnostic, FailurePhase::Argument, ENAMETOOLONG);
        return false;
    }
    std::copy(canonical_path_.begin(), canonical_path_.end(), continuation.argv0.begin());
    continuation.argv0[canonical_path_.size()] = '\0';
    plan = {};
    plan.combined_output_fd = borrowed_combined_output_fd;
    plan.null_input_fd = borrowed_null_input_fd;
    plan.executable_fd = executable_fd_;
    plan.exec_status_fd = status[1];
    plan.exec_status_authority_fd = authority;
    plan.continuation = continuation;
    status_reader_fd_ = status[0];
    status_writer_fd_ = status[1];
    status_writer_authority_fd_ = authority;
    plan_made_ = true;
    return true;
}

bool ExecutableExecHandoffLease::release_and_observe(executable::ExecutableLease& source,
                                                     child_fixture::PausedChildLease& child,
                                                     std::chrono::steady_clock::time_point deadline,
                                                     ExecObservation& observation,
                                                     Diagnostic& diagnostic) {
    diagnostic = {};
    observation = {};
    if (!active_ || !plan_made_ || writer_retired_ || !child.active() ||
        child.child_executable_fd() != executable_fd_) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    executable::Diagnostic source_diagnostic;
    child_fixture::Diagnostic child_diagnostic;
    ++cleanup_->semantic_attempts;
    cleanup_->semantic_validated = false;
    cleanup_->semantic_diagnostic = {};
    if (!source.revalidate(source_diagnostic)) {
        fail(diagnostic, FailurePhase::Source, source_diagnostic.error_number);
        cleanup_->semantic_diagnostic = diagnostic;
        return false;
    }
    child_pid_ = child.child_pid();
    settlement_ = child.settlement_receipt();
    if (!validate_custody(diagnostic) ||
        !same_ofd(getpid(), child.child_pid(), executable_fd_, child.child_executable_fd())) {
        if (diagnostic.phase == FailurePhase::None)
            fail(diagnostic, FailurePhase::Child, errno == 0 ? ESTALE : errno);
        cleanup_->semantic_diagnostic = diagnostic;
        return false;
    }
    cleanup_->semantic_validated = true;
    cleanup_->semantic_diagnostic = {};

    if (!child.authorize_exec_release(deadline, child_diagnostic)) {
        fail(diagnostic, FailurePhase::Child, child_diagnostic.error_number);
        cleanup_->semantic_validated = false;
        cleanup_->semantic_diagnostic = diagnostic;
        return false;
    }
    ++cleanup_->release_close_attempts;
    cleanup_->release_close_attempted = true;
    Diagnostic close_diagnostic;
    if (!close_one(status_writer_fd_, close_diagnostic)) {
        writer_retired_ = true;  // Detached before the one uncertain close.
        cleanup_->release_close_succeeded = false;
        cleanup_->release_close_diagnostic = close_diagnostic;
        fail(diagnostic, FailurePhase::Close, close_diagnostic.error_number);
        return false;
    }
    if (!close_one(status_writer_authority_fd_, close_diagnostic)) {
        writer_retired_ = true;
        cleanup_->release_close_succeeded = false;
        cleanup_->release_close_diagnostic = close_diagnostic;
        fail(diagnostic, FailurePhase::Close, close_diagnostic.error_number);
        return false;
    }
    writer_retired_ = true;
    cleanup_->release_close_succeeded = true;
    if (!child.send_release(deadline, child_diagnostic)) {
        fail(diagnostic, FailurePhase::Release, child_diagnostic.error_number);
        return false;
    }

    ++cleanup_->status_attempts;
    const auto publish_status = [&](ExecOutcome outcome, const Diagnostic& status_diagnostic) {
        cleanup_->status_observed = true;
        cleanup_->status_outcome = outcome;
        cleanup_->status_diagnostic = status_diagnostic;
    };

    unsigned char bytes[33]{};
    std::size_t used = 0;
    bool eof = false;
    while (!eof && used < sizeof(bytes)) {
        const int timeout = remaining_ms(deadline);
        if (timeout <= 0) {
            observation.outcome = ExecOutcome::Timeout;
            fail(diagnostic, FailurePhase::Status, ETIMEDOUT);
            publish_status(observation.outcome, diagnostic);
            return true;
        }
        pollfd descriptor{status_reader_fd_, POLLIN | POLLHUP | POLLERR, 0};
        int polled;
        do {
            polled = poll(&descriptor, 1, timeout);
        } while (polled < 0 && errno == EINTR);
        if (polled == 0) {
            observation.outcome = ExecOutcome::Timeout;
            fail(diagnostic, FailurePhase::Status, ETIMEDOUT);
            publish_status(observation.outcome, diagnostic);
            return true;
        }
        if (polled < 0) {
            fail(diagnostic, FailurePhase::Status, errno);
            publish_status(ExecOutcome::None, diagnostic);
            return false;
        }
        ssize_t count;
        do {
            count = read(status_reader_fd_, bytes + used, sizeof(bytes) - used);
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            fail(diagnostic, FailurePhase::Status, errno);
            publish_status(ExecOutcome::None, diagnostic);
            return false;
        }
        if (count == 0) {
            eof = true;
        } else {
            used += static_cast<std::size_t>(count);
        }
    }
    if (!eof || (used != 0 && used != 16)) {
        observation.outcome = ExecOutcome::ProtocolFailure;
        fail(diagnostic, FailurePhase::Status, EPROTO);
        publish_status(observation.outcome, diagnostic);
        return true;
    }
    if (used == 16) {
        const bool reserved_clear =
            bytes[6] == 0 && bytes[7] == 0 &&
            std::all_of(bytes + 12, bytes + 16, [](unsigned char b) { return b == 0; });
        const unsigned int error_number = static_cast<unsigned int>(bytes[8]) |
                                          (static_cast<unsigned int>(bytes[9]) << 8u) |
                                          (static_cast<unsigned int>(bytes[10]) << 16u) |
                                          (static_cast<unsigned int>(bytes[11]) << 24u);
        if (std::memcmp(bytes, "REX1", 4) != 0 || bytes[4] != 1 ||
            (bytes[5] != 1 && bytes[5] != 2) || !reserved_clear || error_number == 0) {
            observation.outcome = ExecOutcome::ProtocolFailure;
            fail(diagnostic, FailurePhase::Status, EPROTO);
            publish_status(observation.outcome, diagnostic);
            return true;
        }
        if (error_number > static_cast<unsigned int>(std::numeric_limits<int>::max())) {
            observation.outcome = ExecOutcome::ProtocolFailure;
            fail(diagnostic, FailurePhase::Status, EPROTO);
            publish_status(observation.outcome, diagnostic);
            return true;
        }
        observation.outcome =
            bytes[5] == 1 ? ExecOutcome::PreExecFailure : ExecOutcome::ExecFailure;
        observation.error_number = static_cast<int>(error_number);
        publish_status(observation.outcome, {});
        return true;
    }

    if (hooks_.post_eof_delay_ms != 0) {
        const int delay = static_cast<int>(std::min<unsigned int>(
            hooks_.post_eof_delay_ms, static_cast<unsigned int>(std::numeric_limits<int>::max())));
        poll(nullptr, 0, delay);
    }

    if (!pidfd_live(child.observation_pidfd())) {
        observation.outcome = ExecOutcome::EarlyDeath;
        publish_status(observation.outcome, {});
        return true;
    }
    const auto proc_allowed = [&]() {
        return hooks_.proc_snapshot_allowed == nullptr ||
               hooks_.proc_snapshot_allowed(hooks_.context);
    };
    if (!proc_allowed() ||
        !exact_live_identity(
            child_pid_, child.observation_pidfd(), canonical_path_, identity_, observation.first)) {
        observation.outcome = pidfd_live(child.observation_pidfd()) ? ExecOutcome::ProtocolFailure
                                                                    : ExecOutcome::EarlyDeath;
        Diagnostic proc_diagnostic;
        if (observation.outcome == ExecOutcome::ProtocolFailure)
            fail(proc_diagnostic, FailurePhase::Proc, ESTALE);
        diagnostic = proc_diagnostic;
        publish_status(observation.outcome, proc_diagnostic);
        return true;
    }
    if (!pidfd_live(child.observation_pidfd())) {
        observation.outcome = ExecOutcome::EarlyDeath;
        publish_status(observation.outcome, {});
        return true;
    }
    if (!proc_allowed() || !exact_live_identity(child_pid_,
                                                child.observation_pidfd(),
                                                canonical_path_,
                                                identity_,
                                                observation.second)) {
        observation.outcome = pidfd_live(child.observation_pidfd()) ? ExecOutcome::ProtocolFailure
                                                                    : ExecOutcome::EarlyDeath;
        Diagnostic proc_diagnostic;
        if (observation.outcome == ExecOutcome::ProtocolFailure)
            fail(proc_diagnostic, FailurePhase::Proc, ESTALE);
        diagnostic = proc_diagnostic;
        publish_status(observation.outcome, proc_diagnostic);
        return true;
    }
    if (!pidfd_live(child.observation_pidfd())) {
        observation.outcome = ExecOutcome::EarlyDeath;
        publish_status(observation.outcome, {});
        return true;
    }
    if (!fixture_worker_protocol::same_process_identity(observation.first, observation.second) ||
        observation.first.ppid != observation.second.ppid ||
        observation.first.exe != observation.second.exe ||
        observation.first.cmdline != observation.second.cmdline) {
        observation.outcome = ExecOutcome::ProtocolFailure;
        Diagnostic proc_diagnostic;
        fail(proc_diagnostic, FailurePhase::Proc, ESTALE);
        diagnostic = proc_diagnostic;
        publish_status(observation.outcome, proc_diagnostic);
        return true;
    }
    observation.outcome = ExecOutcome::ExecObservedLive;
    publish_status(observation.outcome, {});
    return true;
}

bool ExecutableExecHandoffLease::close_one(int& fd, Diagnostic& diagnostic) {
    if (fd < 0) return true;
    const int detached = fd;
    fd = -1;
    const int result =
        hooks_.close_fd == nullptr ? ::close(detached) : hooks_.close_fd(detached, hooks_.context);
    if (result == 0) return true;
    fail(diagnostic, FailurePhase::Close, errno);
    return false;
}

bool ExecutableExecHandoffLease::close(Diagnostic& diagnostic) {
    diagnostic = {};
    ++cleanup_->cleanup_attempts;
    cleanup_->cleanup_attempted = true;
    if (!active_ || !settlement_ || settlement_->child_pid != child_pid_ ||
        !settlement_->terminal || !settlement_->reaped) {
        fail(diagnostic, FailurePhase::Settlement, EPERM);
        cleanup_->cleanup_diagnostic = diagnostic;
        return false;
    }
    if (!validate_custody(diagnostic)) {
        cleanup_->cleanup_diagnostic = diagnostic;
        return false;
    }
    bool success = true;
    success = close_one(executable_fd_, diagnostic) && success;
    success = close_one(authority_one_fd_, diagnostic) && success;
    success = close_one(authority_two_fd_, diagnostic) && success;
    success = close_one(status_reader_fd_, diagnostic) && success;
    success = close_one(status_writer_fd_, diagnostic) && success;
    success = close_one(status_writer_authority_fd_, diagnostic) && success;
    cleanup_->cleanup_succeeded = success;
    cleanup_->cleanup_diagnostic = diagnostic;
    if (success) active_ = false;
    return success;
}

void ExecutableExecHandoffLease::destructor_cleanup() {
    ++cleanup_->cleanup_attempts;
    cleanup_->cleanup_attempted = true;
    cleanup_->cleanup_succeeded = false;
    cleanup_->cleanup_diagnostic = {FailurePhase::Settlement, EPERM};
    if (!settlement_ || settlement_->child_pid != child_pid_ || !settlement_->terminal ||
        !settlement_->reaped)
        return;
    const bool xa = same_ofd(getpid(), getpid(), executable_fd_, authority_one_fd_);
    const bool xb = same_ofd(getpid(), getpid(), executable_fd_, authority_two_fd_);
    const bool ab = same_ofd(getpid(), getpid(), authority_one_fd_, authority_two_fd_);
    const unsigned agreements =
        static_cast<unsigned>(xa) + static_cast<unsigned>(xb) + static_cast<unsigned>(ab);
    if (agreements != 1u && agreements != 3u) return;
    Diagnostic ignored;
    if (agreements == 3u) {
        (void)close_one(executable_fd_, ignored);
        (void)close_one(authority_one_fd_, ignored);
        (void)close_one(authority_two_fd_, ignored);
    } else if (xa) {
        (void)close_one(executable_fd_, ignored);
        (void)close_one(authority_one_fd_, ignored);
    } else if (xb) {
        (void)close_one(executable_fd_, ignored);
        (void)close_one(authority_two_fd_, ignored);
    } else {
        (void)close_one(authority_one_fd_, ignored);
        (void)close_one(authority_two_fd_, ignored);
    }
    (void)close_one(status_reader_fd_, ignored);
    (void)close_one(status_writer_fd_, ignored);
    (void)close_one(status_writer_authority_fd_, ignored);
    active_ = false;
}

}  // namespace rut::test::fixture_executable_exec_handoff
