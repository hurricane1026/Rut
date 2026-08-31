#include "fixture_public_rut_session_attempt.h"

#include "fixture_worker_protocol.h"
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rut::test::fixture_public_rut_session_attempt {
namespace {

using Clock = std::chrono::steady_clock;
int remaining_ms(Clock::time_point deadline) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (remaining <= 0) return 0;
    return remaining > 2147483647 ? 2147483647 : static_cast<int>(remaining);
}

int nonzero(int error_number, int fallback) {
    return error_number == 0 ? fallback : error_number;
}

bool same_source_identity(const source::SourceIdentity& first,
                          const source::SourceIdentity& second) {
    return first.device == second.device && first.inode == second.inode &&
           first.mode == second.mode && first.uid == second.uid && first.gid == second.gid &&
           first.size == second.size;
}

bool same_executable_identity(const executable::ExecutableIdentity& first,
                              const executable::ExecutableIdentity& second) {
    return first.device == second.device && first.inode == second.inode &&
           first.mode == second.mode && first.uid == second.uid && first.gid == second.gid &&
           first.size == second.size && first.mtime_seconds == second.mtime_seconds &&
           first.mtime_nanoseconds == second.mtime_nanoseconds &&
           first.ctime_seconds == second.ctime_seconds &&
           first.ctime_nanoseconds == second.ctime_nanoseconds;
}

}  // namespace

bool PublicRutAttemptLease::OwnedFd::close_owned() {
    if (value < 0) return true;
    const int detached = value;
    value = -1;
    errno = 0;
    return close_hook == nullptr ? close(detached) == 0 : close_hook(detached, context) == 0;
}

PublicRutAttemptLease::OwnedFd::~OwnedFd() {
    if (value >= 0) (void)close_owned();
}

PublicRutAttemptLease::PublicRutAttemptLease() : cleanup_(std::make_shared<CleanupState>()) {}

PublicRutAttemptLease::~PublicRutAttemptLease() {
    destructor_cleanup();
}

bool PublicRutAttemptLease::reject(Diagnostic& diagnostic, FailurePhase phase, int error_number) {
    diagnostic = {phase, nonzero(error_number, EIO)};
    cleanup_->diagnostic = diagnostic;
    return false;
}

bool PublicRutAttemptLease::owner_evidence_matches(source::WildcardAttemptSourceLease& source_owner,
                                                   executable::ExecutableLease& executable_owner,
                                                   Diagnostic& diagnostic) const {
    source::Diagnostic source_diagnostic;
    if (!source_owner.revalidate(source_diagnostic) || source_owner.path() != source_path_ ||
        !same_source_identity(source_owner.source_identity(), source_identity_)) {
        diagnostic = {FailurePhase::Source, nonzero(source_diagnostic.error_number, ESTALE)};
        return false;
    }
    executable::Diagnostic executable_diagnostic;
    if (!executable_owner.revalidate(executable_diagnostic) ||
        executable_owner.canonical_path() != executable_path_ ||
        !same_executable_identity(executable_owner.identity(), executable_identity_)) {
        diagnostic = {FailurePhase::Executable,
                      nonzero(executable_diagnostic.error_number, ESTALE)};
        return false;
    }
    return true;
}

bool PublicRutAttemptLease::prepare(source::WildcardAttemptSourceLease& source_owner,
                                    executable::ExecutableLease& executable_owner,
                                    std::span<const std::string_view> arguments,
                                    Clock::time_point deadline,
                                    const HooksForTesting& hooks,
                                    Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Empty || arguments.empty() ||
        arguments.size() > child::kMaxExecArgumentCount ||
        arguments.front() != executable_owner.canonical_path() || arguments.size() < 2u ||
        arguments[1] != source_owner.path() || Clock::now() >= deadline)
        return reject(diagnostic, FailurePhase::Argument, EINVAL);

    source_path_ = source_owner.path();
    source_identity_ = source_owner.source_identity();
    executable_path_ = executable_owner.canonical_path();
    executable_identity_ = executable_owner.identity();
    if (!owner_evidence_matches(source_owner, executable_owner, diagnostic)) {
        cleanup_->diagnostic = diagnostic;
        return false;
    }
    argument_count_ = arguments.size();
    expected_cmdline_.clear();
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        arguments_[index].assign(arguments[index]);
        expected_cmdline_.append(arguments[index]);
        expected_cmdline_.push_back('\0');
    }

    capture::Diagnostic capture_diagnostic;
    if (!capture::AnonymousLogCapture::create_with_hooks_for_testing(
            capture::kMaxCaptureBytes, hooks.capture, capture_, capture_diagnostic)) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Capture, capture_diagnostic.error_number);
    }
    if (hooks.prepare_failure == PrepareFailurePoint::AfterCapture) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Injected, EIO);
    }

    null_input_.close_hook = hooks.close_null_input;
    null_input_.context = hooks.null_context;
    null_input_.value = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_input_.value < 0) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::NullInput, errno);
    }
    if (hooks.prepare_failure == PrepareFailurePoint::AfterNullInput) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Injected, EIO);
    }

    handoff::Diagnostic handoff_diagnostic;
    if (!handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            executable_owner, hooks.handoff, handoff_, handoff_diagnostic)) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Handoff, handoff_diagnostic.error_number);
    }
    if (hooks.prepare_failure == PrepareFailurePoint::AfterHandoff) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Injected, EIO);
    }

    std::array<std::string_view, child::kMaxExecArgumentCount> owned_views{};
    for (std::size_t index = 0; index < argument_count_; ++index)
        owned_views[index] = arguments_[index];
    child::ChildDescriptorPlan plan;
    if (!handoff_.make_child_plan_with_arguments(
            null_input_.value,
            capture_.descriptor(),
            false,
            std::span<const std::string_view>(owned_views.data(), argument_count_),
            plan,
            handoff_diagnostic)) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Handoff, handoff_diagnostic.error_number);
    }
    if (hooks.prepare_failure == PrepareFailurePoint::AfterPlan) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Injected, EIO);
    }

    child::Diagnostic child_diagnostic;
    if (!child::PausedChildLease::create_prepared_with_hooks_for_testing(
            deadline, plan, hooks.child, child_, child_diagnostic)) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Child, child_diagnostic.error_number);
    }
    settlement_ = child_.settlement_receipt();
    state_ = State::Prepared;
    if (hooks.prepare_failure == PrepareFailurePoint::AfterChild) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Injected, EIO);
    }
    return true;
}

bool PublicRutAttemptLease::exec_and_observe(source::WildcardAttemptSourceLease& source_owner,
                                             executable::ExecutableLease& executable_owner,
                                             Clock::time_point deadline,
                                             Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Prepared) return reject(diagnostic, FailurePhase::Argument, EALREADY);
    if (!owner_evidence_matches(source_owner, executable_owner, diagnostic)) {
        cleanup_->diagnostic = diagnostic;
        return false;
    }
    handoff::Diagnostic handoff_diagnostic;
    const bool observed = handoff_.release_and_observe(
        executable_owner, child_, deadline, observation_, handoff_diagnostic);
    if (!observed) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Exec, handoff_diagnostic.error_number);
    }
    state_ = State::ExecReleased;
    if (observation_.outcome == handoff::ExecOutcome::ExecObservedLive) {
        state_ = State::ExecObservedLive;
        return true;
    }
    if (observation_.outcome == handoff::ExecOutcome::EarlyDeath) {
        state_ = State::EarlyDeath;
        return true;
    }
    state_ = State::Failed;
    return reject(diagnostic, FailurePhase::Exec, nonzero(observation_.error_number, EPROTO));
}

bool PublicRutAttemptLease::snapshot_capture(std::string& bytes, Diagnostic& diagnostic) const {
    diagnostic = {};
    if (state_ == State::Empty || state_ == State::EvidenceClosed || !capture_.active()) {
        diagnostic = {FailurePhase::Argument, EALREADY};
        return false;
    }
    capture::Diagnostic capture_diagnostic;
    if (!capture_.snapshot(bytes, capture_diagnostic)) {
        diagnostic = {FailurePhase::Snapshot, nonzero(capture_diagnostic.error_number, EIO)};
        return false;
    }
    return true;
}

bool PublicRutAttemptLease::settle_after_reap(State success_state, Diagnostic& diagnostic) {
    bool success = true;
    handoff::Diagnostic handoff_diagnostic;
    if (handoff_.active()) {
        cleanup_->handoff_closed = handoff_.close(handoff_diagnostic);
        success = cleanup_->handoff_closed && success;
        if (!cleanup_->handoff_closed)
            diagnostic = {FailurePhase::Handoff, nonzero(handoff_diagnostic.error_number, EIO)};
    }
    if (null_input_.value >= 0) {
        cleanup_->null_closed = null_input_.close_owned();
        success = cleanup_->null_closed && success;
        if (!cleanup_->null_closed && diagnostic.phase == FailurePhase::None)
            diagnostic = {FailurePhase::NullInput, nonzero(errno, EIO)};
    }
    capture::Diagnostic capture_diagnostic;
    if (capture_.active() && !capture_.settled()) {
        cleanup_->capture_settled = capture_.settle(capture_diagnostic);
        success = cleanup_->capture_settled && success;
        if (!cleanup_->capture_settled && diagnostic.phase == FailurePhase::None)
            diagnostic = {FailurePhase::Capture, nonzero(capture_diagnostic.error_number, EIO)};
    }
    if (capture_.settled()) {
        cleanup_->capture_settled = true;
        capture::Diagnostic snapshot_diagnostic;
        const bool snapshotted = capture_.snapshot(sealed_capture_bytes_, snapshot_diagnostic);
        success = snapshotted && success;
        if (!snapshotted && diagnostic.phase == FailurePhase::None)
            diagnostic = {FailurePhase::Snapshot, nonzero(snapshot_diagnostic.error_number, EIO)};
    }
    state_ = success ? success_state : State::Failed;
    cleanup_->diagnostic = success ? Diagnostic{} : diagnostic;
    return success;
}

bool PublicRutAttemptLease::settle_natural(int expected_exit,
                                           Clock::time_point deadline,
                                           Diagnostic& diagnostic) {
    diagnostic = {};
    if ((state_ != State::ExecObservedLive && state_ != State::EarlyDeath) || expected_exit < 0 ||
        expected_exit > 255)
        return reject(diagnostic, FailurePhase::Argument, EINVAL);
    for (;;) {
        const int timeout = remaining_ms(deadline);
        if (timeout <= 0) return reject(diagnostic, FailurePhase::Wait, ETIMEDOUT);
        pollfd descriptor{child_.observation_pidfd(), POLLIN | POLLERR | POLLHUP, 0};
        int result;
        do {
            result = poll(&descriptor, 1, timeout);
        } while (result < 0 && errno == EINTR);
        if (result == 0) return reject(diagnostic, FailurePhase::Wait, ETIMEDOUT);
        if (result < 0) return reject(diagnostic, FailurePhase::Wait, nonzero(errno, EIO));
        if ((descriptor.revents & (POLLIN | POLLERR | POLLHUP)) != 0) break;
    }
    state_ = State::NaturalTerminalObserved;
    child::Diagnostic child_diagnostic;
    cleanup_->child_settled = child_.cleanup(deadline, child_diagnostic);
    const bool exact = cleanup_->child_settled && settlement_ && settlement_->terminal &&
                       settlement_->reaped && settlement_->error_number == 0 &&
                       WIFEXITED(settlement_->wait_status) &&
                       WEXITSTATUS(settlement_->wait_status) == expected_exit;
    const bool owners_settled =
        settlement_ && settlement_->reaped
            ? settle_after_reap(State::NaturalReapedEvidenceOpen, diagnostic)
            : false;
    if (!exact || !owners_settled) {
        state_ = State::Failed;
        if (diagnostic.phase == FailurePhase::None)
            diagnostic = {FailurePhase::Settlement, nonzero(child_diagnostic.error_number, EPROTO)};
        cleanup_->diagnostic = diagnostic;
        return false;
    }
    return true;
}

bool PublicRutAttemptLease::settle_killed(int expected_signal,
                                          Clock::time_point deadline,
                                          Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::ExecObservedLive || expected_signal <= 0 || expected_signal >= NSIG)
        return reject(diagnostic, FailurePhase::Argument, EINVAL);
    fixture_worker_protocol::ProcIdentity current;
    pollfd descriptor{child_.observation_pidfd(), POLLIN | POLLERR | POLLHUP, 0};
    int live_result;
    do {
        live_result = poll(&descriptor, 1, 0);
    } while (live_result < 0 && errno == EINTR);
    if (live_result != 0 || descriptor.revents != 0 ||
        !fixture_worker_protocol::read_proc(child_.child_pid(), current) ||
        !fixture_worker_protocol::same_process_identity(observation_.second, current))
        return reject(diagnostic, FailurePhase::Child, ESTALE);

    child::Diagnostic child_diagnostic;
    cleanup_->child_settled = child_.cleanup(deadline, child_diagnostic);
    const bool exact = cleanup_->child_settled && settlement_ && settlement_->terminal &&
                       settlement_->reaped && settlement_->error_number == 0 &&
                       WIFSIGNALED(settlement_->wait_status) &&
                       WTERMSIG(settlement_->wait_status) == expected_signal;
    const bool owners_settled = settlement_ && settlement_->reaped
                                    ? settle_after_reap(State::KilledReapedEvidenceOpen, diagnostic)
                                    : false;
    if (!exact || !owners_settled) {
        state_ = State::Failed;
        if (diagnostic.phase == FailurePhase::None)
            diagnostic = {FailurePhase::Settlement, nonzero(child_diagnostic.error_number, EPROTO)};
        cleanup_->diagnostic = diagnostic;
        return false;
    }
    return true;
}

bool PublicRutAttemptLease::close_evidence(Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::NaturalReapedEvidenceOpen && state_ != State::KilledReapedEvidenceOpen)
        return reject(diagnostic, FailurePhase::Argument, EALREADY);
    capture::Diagnostic capture_diagnostic;
    cleanup_->capture_closed = capture_.close(capture_diagnostic);
    if (!cleanup_->capture_closed) {
        state_ = State::Failed;
        return reject(diagnostic, FailurePhase::Close, capture_diagnostic.error_number);
    }
    state_ = State::EvidenceClosed;
    cleanup_->diagnostic = {};
    return true;
}

void PublicRutAttemptLease::destructor_cleanup() {
    cleanup_->destructor_attempted = true;
    Diagnostic diagnostic;
    const auto until = Clock::now() + std::chrono::seconds(7);
    if (child_.active()) {
        child::Diagnostic child_diagnostic;
        cleanup_->child_settled = child_.cleanup(until, child_diagnostic);
        if (!cleanup_->child_settled)
            diagnostic = {FailurePhase::Child, nonzero(child_diagnostic.error_number, EIO)};
    }
    const bool safe = !settlement_ || (settlement_->terminal && settlement_->reaped);
    if (safe) {
        if (handoff_.active()) {
            handoff::Diagnostic handoff_diagnostic;
            cleanup_->handoff_closed = handoff_.close(handoff_diagnostic);
            if (!cleanup_->handoff_closed && diagnostic.phase == FailurePhase::None)
                diagnostic = {FailurePhase::Handoff, nonzero(handoff_diagnostic.error_number, EIO)};
        }
        if (null_input_.value >= 0) {
            cleanup_->null_closed = null_input_.close_owned();
            if (!cleanup_->null_closed && diagnostic.phase == FailurePhase::None)
                diagnostic = {FailurePhase::NullInput, nonzero(errno, EIO)};
        }
        capture::Diagnostic capture_diagnostic;
        if (capture_.active() && !capture_.settled()) {
            cleanup_->capture_settled = capture_.settle(capture_diagnostic);
            if (!cleanup_->capture_settled && diagnostic.phase == FailurePhase::None)
                diagnostic = {FailurePhase::Capture, nonzero(capture_diagnostic.error_number, EIO)};
        }
        if (capture_.active()) {
            cleanup_->capture_closed = capture_.close(capture_diagnostic);
            if (!cleanup_->capture_closed && diagnostic.phase == FailurePhase::None)
                diagnostic = {FailurePhase::Close, nonzero(capture_diagnostic.error_number, EIO)};
        }
    }
    cleanup_->destructor_reportable_success = false;
    cleanup_->diagnostic = diagnostic;
}

}  // namespace rut::test::fixture_public_rut_session_attempt
