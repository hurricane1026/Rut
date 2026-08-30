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
    if (!candidate.validate_custody(diagnostic) || !source.revalidate(source_diagnostic) ||
        !candidate.same_ofd(
            getpid(), getpid(), source.observation_fd(), candidate.executable_fd_) ||
        !candidate.validate_custody(diagnostic)) {
        if (diagnostic.phase == FailurePhase::None)
            fail(diagnostic,
                 FailurePhase::Source,
                 source_diagnostic.error_number != 0 ? source_diagnostic.error_number
                                                     : (errno == 0 ? ESTALE : errno));
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

bool ExecutableExecHandoffLease::validate_status_triad(int first,
                                                       int second,
                                                       int third,
                                                       int access_mode,
                                                       bool allow_one_detached,
                                                       Diagnostic& diagnostic) const {
    const std::array<int, 3> descriptors = {first, second, third};
    unsigned int present = 0;
    for (const int fd : descriptors) {
        if (fd < 0) continue;
        ++present;
        errno = 0;
        const int descriptor_flags = fcntl(fd, F_GETFD);
        const int status_flags = fcntl(fd, F_GETFL);
        struct stat status{};
        if (descriptor_flags < 0 || status_flags < 0 || fstat(fd, &status) != 0 ||
            (descriptor_flags & FD_CLOEXEC) == 0 || (status_flags & O_ACCMODE) != access_mode ||
            static_cast<std::uint64_t>(status.st_dev) != status_device_ ||
            static_cast<std::uint64_t>(status.st_ino) != status_inode_) {
            fail(diagnostic, FailurePhase::Custody, errno == 0 ? ESTALE : errno);
            return false;
        }
    }
    if ((!allow_one_detached && present != 3) || (allow_one_detached && present < 2)) {
        fail(diagnostic, FailurePhase::Custody, EBADF);
        return false;
    }
    for (std::size_t first_index = 0; first_index < descriptors.size(); ++first_index) {
        if (descriptors[first_index] < 0) continue;
        for (std::size_t second_index = first_index + 1; second_index < descriptors.size();
             ++second_index) {
            if (descriptors[second_index] < 0) continue;
            if (!same_ofd(
                    getpid(), getpid(), descriptors[first_index], descriptors[second_index])) {
                fail(diagnostic, FailurePhase::Custody, errno == 0 ? ESTALE : errno);
                return false;
            }
        }
    }
    return true;
}

bool ExecutableExecHandoffLease::validate_status_custody(bool allow_retired_writer,
                                                         Diagnostic& diagnostic) const {
    if (!validate_status_triad(status_reader_fd_,
                               status_reader_authority_one_fd_,
                               status_reader_authority_two_fd_,
                               O_RDONLY,
                               false,
                               diagnostic))
        return false;
    const unsigned int writers_present =
        static_cast<unsigned int>(status_writer_fd_ >= 0) +
        static_cast<unsigned int>(status_writer_authority_one_fd_ >= 0) +
        static_cast<unsigned int>(status_writer_authority_two_fd_ >= 0);
    if (writers_present == 0 && allow_retired_writer) return true;
    return validate_status_triad(status_writer_fd_,
                                 status_writer_authority_one_fd_,
                                 status_writer_authority_two_fd_,
                                 O_WRONLY,
                                 allow_retired_writer,
                                 diagnostic);
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
    const int reader_authority_one = fcntl(status[0], F_DUPFD_CLOEXEC, 3);
    const int reader_authority_two =
        reader_authority_one < 0 ? -1 : fcntl(status[0], F_DUPFD_CLOEXEC, 3);
    const int writer_authority_one =
        reader_authority_two < 0 ? -1 : fcntl(status[1], F_DUPFD_CLOEXEC, 3);
    const int writer_authority_two =
        writer_authority_one < 0 ? -1 : fcntl(status[1], F_DUPFD_CLOEXEC, 3);
    if (reader_authority_one < 0 || reader_authority_two < 0 || writer_authority_one < 0 ||
        writer_authority_two < 0) {
        const int error_number = errno;
        ::close(status[0]);
        ::close(status[1]);
        if (reader_authority_one >= 0) ::close(reader_authority_one);
        if (reader_authority_two >= 0) ::close(reader_authority_two);
        if (writer_authority_one >= 0) ::close(writer_authority_one);
        if (writer_authority_two >= 0) ::close(writer_authority_two);
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
        ::close(reader_authority_one);
        ::close(reader_authority_two);
        ::close(writer_authority_one);
        ::close(writer_authority_two);
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
    plan.exec_status_authority_fd = writer_authority_one;
    plan.continuation = continuation;
    status_reader_fd_ = status[0];
    status_reader_authority_one_fd_ = reader_authority_one;
    status_reader_authority_two_fd_ = reader_authority_two;
    status_writer_fd_ = status[1];
    status_writer_authority_one_fd_ = writer_authority_one;
    status_writer_authority_two_fd_ = writer_authority_two;
    struct stat status_identity{};
    if (fstat(status_reader_fd_, &status_identity) != 0) {
        fail(diagnostic, FailurePhase::Pipe, errno);
        Diagnostic ignored;
        (void)close_one(status_reader_fd_, ignored);
        (void)close_one(status_reader_authority_one_fd_, ignored);
        (void)close_one(status_reader_authority_two_fd_, ignored);
        (void)close_one(status_writer_fd_, ignored);
        (void)close_one(status_writer_authority_one_fd_, ignored);
        (void)close_one(status_writer_authority_two_fd_, ignored);
        return false;
    }
    status_device_ = static_cast<std::uint64_t>(status_identity.st_dev);
    status_inode_ = static_cast<std::uint64_t>(status_identity.st_ino);
    if (!validate_status_custody(false, diagnostic)) {
        ::close(status_reader_fd_);
        ::close(status_reader_authority_one_fd_);
        ::close(status_reader_authority_two_fd_);
        ::close(status_writer_fd_);
        ::close(status_writer_authority_one_fd_);
        ::close(status_writer_authority_two_fd_);
        status_reader_fd_ = status_reader_authority_one_fd_ = status_reader_authority_two_fd_ = -1;
        status_writer_fd_ = status_writer_authority_one_fd_ = status_writer_authority_two_fd_ = -1;
        plan = {};
        return false;
    }
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
    if (!same_ofd(getpid(), getpid(), source.observation_fd(), executable_fd_)) {
        fail(diagnostic, FailurePhase::Source, errno == 0 ? ESTALE : errno);
        cleanup_->semantic_diagnostic = diagnostic;
        return false;
    }
    child_pid_ = child.child_pid();
    settlement_ = child.settlement_receipt();
    if (!validate_custody(diagnostic) || !validate_status_custody(false, diagnostic) ||
        !same_ofd(getpid(), child.child_pid(), executable_fd_, child.child_executable_fd()) ||
        !same_ofd(getpid(),
                  child.child_pid(),
                  status_writer_authority_two_fd_,
                  child.child_exec_status_fd())) {
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
    bool writer_close_success = true;
    writer_close_success =
        close_status_one(status_writer_fd_, cleanup_->status_writer_close[0], close_diagnostic) &&
        writer_close_success;
    writer_close_success =
        close_status_one(
            status_writer_authority_one_fd_, cleanup_->status_writer_close[1], close_diagnostic) &&
        writer_close_success;
    writer_close_success =
        close_status_one(
            status_writer_authority_two_fd_, cleanup_->status_writer_close[2], close_diagnostic) &&
        writer_close_success;
    writer_retired_ = true;
    cleanup_->release_close_succeeded = writer_close_success;
    cleanup_->release_close_diagnostic = close_diagnostic;
    if (!writer_close_success) {
        diagnostic = close_diagnostic;
        return false;
    }
    const child_fixture::ReleaseSendState send_state =
        child.send_release(deadline, child_diagnostic);
    cleanup_->child_release_send_state = send_state;
    if (send_state == child_fixture::ReleaseSendState::NotSent) {
        fail(diagnostic, FailurePhase::Release, child_diagnostic.error_number);
        return false;
    }
    const bool reportable_success = send_state == child_fixture::ReleaseSendState::Sent;

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
            return reportable_success;
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
            return reportable_success;
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
        return reportable_success;
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
            return reportable_success;
        }
        if (error_number > static_cast<unsigned int>(std::numeric_limits<int>::max())) {
            observation.outcome = ExecOutcome::ProtocolFailure;
            fail(diagnostic, FailurePhase::Status, EPROTO);
            publish_status(observation.outcome, diagnostic);
            return reportable_success;
        }
        observation.outcome =
            bytes[5] == 1 ? ExecOutcome::PreExecFailure : ExecOutcome::ExecFailure;
        observation.error_number = static_cast<int>(error_number);
        publish_status(observation.outcome, {});
        return reportable_success;
    }

    if (hooks_.post_eof_delay_ms != 0) {
        const int delay = static_cast<int>(std::min<unsigned int>(
            hooks_.post_eof_delay_ms, static_cast<unsigned int>(std::numeric_limits<int>::max())));
        poll(nullptr, 0, delay);
    }

    if (!pidfd_live(child.observation_pidfd())) {
        observation.outcome = ExecOutcome::EarlyDeath;
        publish_status(observation.outcome, {});
        return reportable_success;
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
        return reportable_success;
    }
    if (!pidfd_live(child.observation_pidfd())) {
        observation.outcome = ExecOutcome::EarlyDeath;
        publish_status(observation.outcome, {});
        return reportable_success;
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
        return reportable_success;
    }
    if (!pidfd_live(child.observation_pidfd())) {
        observation.outcome = ExecOutcome::EarlyDeath;
        publish_status(observation.outcome, {});
        return reportable_success;
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
        return reportable_success;
    }
    observation.outcome = ExecOutcome::ExecObservedLive;
    publish_status(observation.outcome, {});
    return reportable_success;
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

bool ExecutableExecHandoffLease::close_status_one(int& fd,
                                                  CloseOutcome& outcome,
                                                  Diagnostic& diagnostic) {
    if (fd < 0) return true;
    ++outcome.attempts;
    outcome.attempted = true;
    const int detached = fd;
    fd = -1;
    const int result =
        hooks_.close_fd == nullptr ? ::close(detached) : hooks_.close_fd(detached, hooks_.context);
    if (result == 0) {
        outcome.succeeded = true;
        outcome.error_number = 0;
        return true;
    }
    outcome.succeeded = false;
    outcome.error_number = errno == 0 ? EIO : errno;
    fail(diagnostic, FailurePhase::Close, outcome.error_number);
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
    if (!validate_custody(diagnostic) || !validate_status_custody(true, diagnostic)) {
        cleanup_->cleanup_diagnostic = diagnostic;
        return false;
    }
    bool success = true;
    success = close_one(executable_fd_, diagnostic) && success;
    success = close_one(authority_one_fd_, diagnostic) && success;
    success = close_one(authority_two_fd_, diagnostic) && success;
    success = close_status_one(status_reader_fd_, cleanup_->status_reader_close[0], diagnostic) &&
              success;
    success = close_status_one(
                  status_reader_authority_one_fd_, cleanup_->status_reader_close[1], diagnostic) &&
              success;
    success = close_status_one(
                  status_reader_authority_two_fd_, cleanup_->status_reader_close[2], diagnostic) &&
              success;
    success = close_status_one(status_writer_fd_, cleanup_->status_writer_close[0], diagnostic) &&
              success;
    success = close_status_one(
                  status_writer_authority_one_fd_, cleanup_->status_writer_close[1], diagnostic) &&
              success;
    success = close_status_one(
                  status_writer_authority_two_fd_, cleanup_->status_writer_close[2], diagnostic) &&
              success;
    cleanup_->cleanup_succeeded = success;
    cleanup_->cleanup_diagnostic = diagnostic;
    if (success) active_ = false;
    return success;
}

void ExecutableExecHandoffLease::destructor_close_status_triad(
    int& first, int& second, int& third, int access_mode, std::array<CloseOutcome, 3>& outcomes) {
    const std::array<int, 3> descriptors = {first, second, third};
    std::array<bool, 3> candidates{};
    for (std::size_t index = 0; index < descriptors.size(); ++index) {
        const int fd = descriptors[index];
        if (fd < 0) continue;
        const int descriptor_flags = fcntl(fd, F_GETFD);
        const int status_flags = fcntl(fd, F_GETFL);
        struct stat status{};
        candidates[index] = descriptor_flags >= 0 && status_flags >= 0 && fstat(fd, &status) == 0 &&
                            (descriptor_flags & FD_CLOEXEC) != 0 &&
                            (status_flags & O_ACCMODE) == access_mode &&
                            static_cast<std::uint64_t>(status.st_dev) == status_device_ &&
                            static_cast<std::uint64_t>(status.st_ino) == status_inode_;
    }
    std::array<std::array<bool, 3>, 3> same{};
    unsigned int same_edges = 0;
    for (std::size_t left = 0; left < descriptors.size(); ++left) {
        for (std::size_t right = left + 1; right < descriptors.size(); ++right) {
            if (candidates[left] && candidates[right] &&
                same_ofd(getpid(), getpid(), descriptors[left], descriptors[right])) {
                same[left][right] = true;
                ++same_edges;
            }
        }
    }
    if (same_edges != 1 && same_edges != 3) return;
    std::array<bool, 3> originals{};
    if (same_edges == 3) {
        originals = {true, true, true};
    } else {
        for (std::size_t left = 0; left < descriptors.size(); ++left)
            for (std::size_t right = left + 1; right < descriptors.size(); ++right)
                if (same[left][right]) {
                    originals[left] = true;
                    originals[right] = true;
                }
    }
    std::array<int*, 3> slots = {&first, &second, &third};
    Diagnostic ignored;
    for (std::size_t index = 0; index < slots.size(); ++index)
        if (originals[index]) (void)close_status_one(*slots[index], outcomes[index], ignored);
}

void ExecutableExecHandoffLease::destructor_cleanup() {
    ++cleanup_->cleanup_attempts;
    cleanup_->cleanup_attempted = true;
    cleanup_->cleanup_succeeded = false;
    cleanup_->cleanup_diagnostic = {FailurePhase::Settlement, EPERM};
    if (!settlement_ || settlement_->child_pid != child_pid_ || !settlement_->terminal ||
        !settlement_->reaped)
        return;
    destructor_close_status_triad(status_reader_fd_,
                                  status_reader_authority_one_fd_,
                                  status_reader_authority_two_fd_,
                                  O_RDONLY,
                                  cleanup_->status_reader_close);
    destructor_close_status_triad(status_writer_fd_,
                                  status_writer_authority_one_fd_,
                                  status_writer_authority_two_fd_,
                                  O_WRONLY,
                                  cleanup_->status_writer_close);
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
    active_ = false;
}

}  // namespace rut::test::fixture_executable_exec_handoff
