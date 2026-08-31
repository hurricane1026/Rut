#pragma once

#include "fixture_anonymous_log_capture.h"
#include "fixture_executable_exec_handoff.h"
#include "fixture_executable_lease.h"
#include "fixture_wildcard_paused_child_lease.h"
#include "fixture_wildcard_source_lease.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace rut::test::fixture_public_rut_session_attempt {

namespace capture = fixture_anonymous_log_capture;
namespace child = fixture_wildcard_paused_child_lease;
namespace executable = fixture_executable_lease;
namespace handoff = fixture_executable_exec_handoff;
namespace source = fixture_wildcard_source_lease;

enum class State : std::uint8_t {
    Empty,
    Prepared,
    ExecReleased,
    ExecObservedLive,
    EarlyDeath,
    NaturalTerminalObserved,
    NaturalReapedEvidenceOpen,
    KilledReapedEvidenceOpen,
    EvidenceClosed,
    Failed,
};

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Source,
    Executable,
    Capture,
    NullInput,
    Handoff,
    Child,
    Exec,
    Snapshot,
    Wait,
    Settlement,
    Close,
    Injected,
};

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

enum class PrepareFailurePoint : std::uint8_t {
    None,
    AfterCapture,
    AfterNullInput,
    AfterHandoff,
    AfterPlan,
    AfterChild,
};

struct HooksForTesting {
    capture::HooksForTesting capture;
    handoff::HooksForTesting handoff;
    child::HooksForTesting child;
    int (*close_null_input)(int descriptor, void* context) = nullptr;
    void* null_context = nullptr;
    PrepareFailurePoint prepare_failure = PrepareFailurePoint::None;
};

struct CleanupState {
    bool destructor_attempted = false, destructor_reportable_success = false;
    bool child_settled = false, handoff_closed = false, null_closed = false;
    bool capture_settled = false, capture_closed = false;
    Diagnostic diagnostic;
};
// Owners are borrowed synchronously; destruction runs child, handoff, null, then capture.
class PublicRutAttemptLease {
public:
    PublicRutAttemptLease();
    ~PublicRutAttemptLease();
    PublicRutAttemptLease(const PublicRutAttemptLease&) = delete;
    PublicRutAttemptLease& operator=(const PublicRutAttemptLease&) = delete;
    PublicRutAttemptLease(PublicRutAttemptLease&&) = delete;
    PublicRutAttemptLease& operator=(PublicRutAttemptLease&&) = delete;

    bool prepare(source::WildcardAttemptSourceLease& source_owner,
                 executable::ExecutableLease& executable_owner,
                 std::span<const std::string_view> arguments,
                 std::chrono::steady_clock::time_point deadline,
                 const HooksForTesting& hooks,
                 Diagnostic& diagnostic);
    bool exec_and_observe(source::WildcardAttemptSourceLease& source_owner,
                          executable::ExecutableLease& executable_owner,
                          std::chrono::steady_clock::time_point deadline,
                          Diagnostic& diagnostic);
    bool snapshot_capture(std::string& bytes, Diagnostic& diagnostic) const;
    bool settle_natural(int expected_exit,
                        std::chrono::steady_clock::time_point deadline,
                        Diagnostic& diagnostic);
    bool settle_killed(int expected_signal,
                       std::chrono::steady_clock::time_point deadline,
                       Diagnostic& diagnostic);
    bool close_evidence(Diagnostic& diagnostic);

    State state() const { return state_; }
    pid_t child_pid() const { return child_.child_pid(); }
    int observation_pidfd() const { return child_.observation_pidfd(); }
    const handoff::ExecObservation& exec_observation() const { return observation_; }
    const std::string& expected_cmdline() const { return expected_cmdline_; }
    const std::string& sealed_capture_bytes() const { return sealed_capture_bytes_; }
    std::shared_ptr<const child::SettlementReceipt> settlement_receipt() const {
        return settlement_;
    }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_; }

private:
    struct OwnedFd {
        int value = -1;
        int (*close_hook)(int, void*) = nullptr;
        void* context = nullptr;
        bool close_owned();
        ~OwnedFd();
    };

    bool owner_evidence_matches(source::WildcardAttemptSourceLease& source_owner,
                                executable::ExecutableLease& executable_owner,
                                Diagnostic& diagnostic) const;
    bool settle_after_reap(State success_state, Diagnostic& diagnostic);
    bool reject(Diagnostic& diagnostic, FailurePhase phase, int error_number);
    void destructor_cleanup();

    capture::AnonymousLogCapture capture_;
    OwnedFd null_input_;
    handoff::ExecutableExecHandoffLease handoff_;
    child::PausedChildLease child_;
    State state_ = State::Empty;
    std::string source_path_;
    source::SourceIdentity source_identity_;
    std::string executable_path_;
    executable::ExecutableIdentity executable_identity_;
    std::array<std::string, child::kMaxExecArgumentCount> arguments_{};
    std::size_t argument_count_ = 0u;
    std::string expected_cmdline_;
    std::string sealed_capture_bytes_;
    handoff::ExecObservation observation_;
    std::shared_ptr<const child::SettlementReceipt> settlement_;
    std::shared_ptr<CleanupState> cleanup_;
};

}  // namespace rut::test::fixture_public_rut_session_attempt
