#pragma once

#include "fixture_executable_lease.h"
#include "fixture_wildcard_paused_child_lease.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace rut::test::fixture_executable_exec_handoff {

namespace executable = fixture_executable_lease;
namespace child_fixture = fixture_wildcard_paused_child_lease;

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Source,
    Duplicate,
    Custody,
    Pipe,
    Child,
    Release,
    Status,
    Proc,
    Settlement,
    Close,
};

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

enum class ExecOutcome : std::uint8_t {
    None,
    PreExecFailure,
    ExecFailure,
    ExecObservedLive,
    EarlyDeath,
    Timeout,
    ProtocolFailure,
};

struct ExecObservation {
    ExecOutcome outcome = ExecOutcome::None;
    int error_number = 0;
    child_fixture::ProcIdentity first;
    child_fixture::ProcIdentity second;
};

struct CloseOutcome {
    unsigned int attempts = 0;
    bool attempted = false;
    bool succeeded = false;
    int error_number = 0;
};

struct CleanupState {
    unsigned int semantic_attempts = 0;
    bool semantic_validated = false;
    Diagnostic semantic_diagnostic;
    unsigned int status_attempts = 0;
    bool status_observed = false;
    ExecOutcome status_outcome = ExecOutcome::None;
    Diagnostic status_diagnostic;
    unsigned int release_close_attempts = 0;
    bool release_close_attempted = false;
    bool release_close_succeeded = false;
    Diagnostic release_close_diagnostic;
    child_fixture::ReleaseSendState child_release_send_state =
        child_fixture::ReleaseSendState::NotSent;
    unsigned int cleanup_attempts = 0;
    bool cleanup_attempted = false;
    bool cleanup_succeeded = false;
    Diagnostic cleanup_diagnostic;
    std::array<CloseOutcome, 3> status_reader_close;
    std::array<CloseOutcome, 3> status_writer_close;
};

struct HooksForTesting {
    int (*kcmp_file)(pid_t, pid_t, int, int, void*) = nullptr;
    int (*close_fd)(int, void*) = nullptr;
    void* context = nullptr;
    // 1 partial; 2 bad magic; 3 extra; 4 duplicate; 5 legal-without-EOF;
    // 6 bad version; 7 bad phase; 8 nonzero reserved; 9 zero errno.
    std::uint8_t child_status_injection = 0;
    unsigned int post_eof_delay_ms = 0;
    // 1 same-inode/new-OFD, 2 different object, 3 clear CLOEXEC.
    std::uint8_t child_executable_mutation = 0;
    bool (*proc_snapshot_allowed)(void*) = nullptr;
    void (*post_exec_observation_mutation)(child_fixture::ProcIdentity&,
                                           child_fixture::ProcIdentity&,
                                           void*) = nullptr;
    bool fail_status_identity_fstat = false;
};

// Tests-only, single-use custody bridge.  The source ExecutableLease remains
// independently active.  This lease owns only X/A1/A2 and its status-pipe
// descriptors.  Its destructor never signals, waits, reaps, or dereferences a
// source lease.  Defensive destructor closure is bounded to at most one H-slot
// replacement; ambiguity preserves every unproven numeric slot.
// This increment transports at most nine bounded, owned argument byte strings;
// it does not parse their application-level meaning or compose a session.
// Numeric accessors are observation-only causal-test seams; the exclusive
// parent owner does not read them or mutate its FD table during an operation.
// Deliberate test mutations are detected fail-closed before release or close.
// Destroying an H with a claimed active/unreaped child is nonreportable misuse:
// it deliberately preserves every owned slot and never signals or reaps.
class ExecutableExecHandoffLease {
public:
    ExecutableExecHandoffLease();
    ~ExecutableExecHandoffLease();
    ExecutableExecHandoffLease(const ExecutableExecHandoffLease&) = delete;
    ExecutableExecHandoffLease& operator=(const ExecutableExecHandoffLease&) = delete;
    ExecutableExecHandoffLease(ExecutableExecHandoffLease&&) = delete;
    ExecutableExecHandoffLease& operator=(ExecutableExecHandoffLease&&) = delete;

    static bool create(executable::ExecutableLease& source,
                       ExecutableExecHandoffLease& lease,
                       Diagnostic& diagnostic);
    static bool create_with_hooks_for_testing(executable::ExecutableLease& source,
                                              const HooksForTesting& hooks,
                                              ExecutableExecHandoffLease& lease,
                                              Diagnostic& diagnostic);

    bool make_child_plan(int borrowed_null_input_fd,
                         int borrowed_combined_output_fd,
                         bool inject_pre_exec_failure,
                         child_fixture::ChildDescriptorPlan& plan,
                         Diagnostic& diagnostic);
    bool make_child_plan_with_arguments(int borrowed_null_input_fd,
                                        int borrowed_combined_output_fd,
                                        bool inject_pre_exec_failure,
                                        std::span<const std::string_view> arguments,
                                        child_fixture::ChildDescriptorPlan& plan,
                                        Diagnostic& diagnostic);
    bool release_and_observe(executable::ExecutableLease& source,
                             child_fixture::PausedChildLease& child,
                             std::chrono::steady_clock::time_point deadline,
                             ExecObservation& observation,
                             Diagnostic& diagnostic);
    bool close(Diagnostic& diagnostic);

    bool active() const { return active_; }
    int observation_fd() const { return executable_fd_; }
    int status_reader_fd_for_testing() const { return status_reader_fd_; }
    int status_reader_authority_one_fd_for_testing() const {
        return status_reader_authority_one_fd_;
    }
    int status_reader_authority_two_fd_for_testing() const {
        return status_reader_authority_two_fd_;
    }
    int status_writer_fd_for_testing() const { return status_writer_fd_; }
    int status_writer_authority_one_fd_for_testing() const {
        return status_writer_authority_one_fd_;
    }
    int status_writer_authority_two_fd_for_testing() const {
        return status_writer_authority_two_fd_;
    }
    int authority_one_fd_for_testing() const { return authority_one_fd_; }
    int authority_two_fd_for_testing() const { return authority_two_fd_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_; }

private:
    static bool create_impl(executable::ExecutableLease& source,
                            const HooksForTesting* hooks,
                            ExecutableExecHandoffLease& lease,
                            Diagnostic& diagnostic);
    bool validate_custody(Diagnostic& diagnostic) const;
    bool validate_status_custody(bool allow_retired_writer, Diagnostic& diagnostic) const;
    bool validate_status_triad(int first,
                               int second,
                               int third,
                               int access_mode,
                               bool allow_one_detached,
                               Diagnostic& diagnostic) const;
    bool same_ofd(pid_t first_pid, pid_t second_pid, int first, int second) const;
    bool close_one(int& fd, Diagnostic& diagnostic);
    bool close_status_one(int& fd, CloseOutcome& outcome, Diagnostic& diagnostic);
    void destructor_close_status_triad(int& first,
                                       int& second,
                                       int& third,
                                       int access_mode,
                                       std::array<CloseOutcome, 3>& outcomes);
    void destructor_cleanup();

    int executable_fd_ = -1;
    int authority_one_fd_ = -1;
    int authority_two_fd_ = -1;
    int status_reader_fd_ = -1;
    int status_reader_authority_one_fd_ = -1;
    int status_reader_authority_two_fd_ = -1;
    int status_writer_fd_ = -1;
    int status_writer_authority_one_fd_ = -1;
    int status_writer_authority_two_fd_ = -1;
    std::uint64_t status_device_ = 0;
    std::uint64_t status_inode_ = 0;
    bool active_ = false;
    bool plan_made_ = false;
    bool writer_retired_ = false;
    pid_t child_pid_ = -1;
    std::string canonical_path_;
    executable::ExecutableIdentity identity_;
    std::shared_ptr<const child_fixture::SettlementReceipt> settlement_;
    std::shared_ptr<child_fixture::PreparedChildUseReceipt> child_use_receipt_;
    std::shared_ptr<CleanupState> cleanup_;
    HooksForTesting hooks_{};
};

}  // namespace rut::test::fixture_executable_exec_handoff
