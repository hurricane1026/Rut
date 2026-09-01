#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rut::test::ipv4_topology {

inline constexpr const char* kExactInputMountDestination = "/etc/nginx/nginx.conf";
inline constexpr std::uint16_t kExactInputTopologyBuilderPort = 41857u;
inline constexpr std::size_t kExactInputBuilderCapacity = 8192u;

struct ExactInputTopologyBuildRequest {
    std::array<char, 49> token{};
    std::array<char, 16> positive_ipv4{};
    std::array<char, 16> guard_ipv4{};
    std::uint16_t port = 0;
};

class ExactInputTopologyBuildSink {
public:
    ExactInputTopologyBuildSink() = default;
    ExactInputTopologyBuildSink(const ExactInputTopologyBuildSink&) = delete;
    ExactInputTopologyBuildSink& operator=(const ExactInputTopologyBuildSink&) = delete;
    ExactInputTopologyBuildSink(ExactInputTopologyBuildSink&&) = delete;
    ExactInputTopologyBuildSink& operator=(ExactInputTopologyBuildSink&&) = delete;

    bool append(const void* bytes, std::size_t size) noexcept;
    const char* data() const noexcept { return bytes_.data(); }
    std::size_t size() const noexcept { return size_; }
    bool overflowed() const noexcept { return overflowed_; }

private:
    std::array<char, kExactInputBuilderCapacity> bytes_{};
    std::size_t size_ = 0;
    bool overflowed_ = false;
};

using ExactInputTopologyBuilder = bool (*)(const ExactInputTopologyBuildRequest& request,
                                           ExactInputTopologyBuildSink& sink,
                                           void* context);

enum class ExactInputMountState : std::uint8_t {
    Empty,
    SettingUp,
    ReadyForObservation,
    ObservingInput,
    InputReadObserved,
    ObservingWriteRefusal,
    WriteRefusalObserved,
    Recovering,
    Settled,
    Unresolved,
};

enum class ExactInputReadOutcome : std::uint8_t {
    None,
    Complete,
    SourceRevalidationFailed,
    ContainerIdentityFailed,
    CommandStartFailed,
    DeadlineExceeded,
    OutputLimitExceeded,
    StreamError,
    ExitSignaled,
    ExitNonzero,
    StderrNotEmpty,
    ByteMismatch,
};

enum class ExactInputReadLaunchStage : std::uint8_t {
    None,
    ProcessGroup,
    ParentDeathGuard,
    StdoutDuplication,
    StderrDuplication,
    DescriptorCustody,
    SubtreeConfinement,
    Execute,
    PidfdOpen,
    PidfdIdentity,
    ExecStatusProtocol,
};

enum class ExactInputWriteRefusalOutcome : std::uint8_t {
    None,
    Complete,
    SourceRevalidationFailed,
    ContainerIdentityFailed,
    CommandStartFailed,
    DeadlineExceeded,
    OutputLimitExceeded,
    StreamError,
    ExitSignaled,
    ControlExitNonzero,
    ControlOutputMismatch,
    TargetUnexpectedSuccess,
    TargetWrongExit,
    TargetStdoutNotEmpty,
    TargetStderrMismatch,
};

enum class ExactInputMountTerminalResult : std::uint8_t {
    None,
    SettledCleanly,
    SettledWithOperationFailure,
};

enum class ExactInputMountPhase : std::uint8_t {
    None,
    Argument,
    Thread,
    Capacity,
    Preflight,
    Manifest,
    Directory,
    InputFile,
    Networks,
    Holder,
    Topology,
    InputBuilder,
    Sidecar,
    MountInspect,
    FileRevalidation,
    InputObservation,
    WriteRefusalObservation,
    SidecarSettlement,
    TopologyRevalidation,
    InputSettlement,
    DirectorySettlement,
    HolderSettlement,
    NetworkSettlement,
    FinalAudit,
    Lifecycle,
};

// Every fault is a tests-only boundary. Production callers use None.
enum class ExactInputMountFailurePoint : std::uint8_t {
    None,
    PreflightBeforeMutation,
    AfterDirectory,
    AfterInputFile,
    AfterNetworkACreated,
    AfterNetworkAVerified,
    AfterNetworkBCreated,
    AfterNetworkBVerified,
    AfterBothIpamVerified,
    AfterNetworks,
    AfterHolderCreated,
    AfterHolderAttachedA,
    AfterHolderAttachedB,
    AfterHolder,
    AfterTopology,
    BuilderRejectBracketA,
    BuilderRejectBracketB,
    BuilderRejectBracketC,
    BuilderRejectBracketD,
    BuilderRejectTcpBracket,
    BuilderRejectTcp6Bracket,
    BuilderRejectPositiveProbeBracket,
    BuilderRejectGuardProbeBracket,
    BuilderNetworkMayHaveMutated,
    BuilderDirectoryMayHaveMutated,
    BuilderInputMayHaveMutated,
    AfterSidecarCreate,
    AfterMountInspect,
    SidecarCreateReportedTimeout,
    SidecarCleanupReportedTimeout,
    SidecarDisappearBeforeCleanup,
    HolderDisappearBeforeCleanup,
    CredentialBoundarySidecarDeath,
    RejectSidecarRevalidationOnce,
    DisconnectNetworkBeforeInputCleanup,
    RejectNetworkASettlementOnce,
    InputReadRejectSourceRevalidation,
    InputReadPostCommandSidecarDeath,
    WriteRefusalRejectInitialBracket,
    WriteRefusalRejectMiddleBracket,
    WriteRefusalRejectFinalBracket,
    WriteRefusalPostTargetSidecarDeath,
};

struct ExactInputMountOptions {
    ExactInputMountFailurePoint failure_point = ExactInputMountFailurePoint::None;
    bool restore_test_disconnect_on_retry = false;
};

struct ExactInputMountDiagnostic {
    ExactInputMountPhase phase = ExactInputMountPhase::None;
    int error_number = 0;
    std::string message;
};

struct ExactInputMountSnapshot {
    ExactInputMountState state = ExactInputMountState::Empty;
    std::uint64_t generation = 0;
    std::string token;
    std::string source_path;
    std::string destination;
    std::uint64_t source_device = 0;
    std::uint64_t source_inode = 0;
    std::uint64_t source_uid = 0;
    std::uint64_t source_gid = 0;
    std::uint64_t source_size = 0;
    std::string holder_id;
    std::string sidecar_id;
    std::string config_user;
    std::string network_mode;
    std::vector<std::string> sidecar_argv;
    std::string requested_type;
    std::string requested_source;
    std::string requested_destination;
    std::string requested_propagation;
    std::string realized_type;
    std::string realized_source;
    std::string realized_destination;
    std::string realized_mode;
    std::string realized_propagation;
    bool requested_read_only = false;
    bool realized_read_only = false;
    bool exact_container_identity = false;
    bool exact_proc_credentials = false;
    bool parser_mutation_matrix_passed = false;
    std::uint32_t parser_rejections = 0;
};

struct ExactInputBuilderBracketEvidence {
    bool topology_verified = false;
    bool snapshot_equal_to_a = false;
    bool tcp_absence_verified = false;
    bool tcp_absence_pre_equal = false;
    bool tcp_absence_post_equal = false;
    bool tcp6_absence_verified = false;
    bool tcp6_absence_pre_equal = false;
    bool tcp6_absence_post_equal = false;
    bool positive_refusal_verified = false;
    bool positive_refusal_pre_equal = false;
    bool positive_refusal_post_equal = false;
    bool guard_refusal_verified = false;
    bool guard_refusal_pre_equal = false;
    bool guard_refusal_post_equal = false;
};

struct ExactInputBuilderEvidence {
    bool applicable = false;
    bool request_validated = false;
    std::array<char, 49> token{};
    std::array<char, 16> positive_ipv4{};
    std::array<char, 16> guard_ipv4{};
    std::uint16_t port = 0;
    ExactInputBuilderBracketEvidence bracket_a;
    ExactInputBuilderBracketEvidence bracket_b;
    ExactInputBuilderBracketEvidence bracket_c;
    ExactInputBuilderBracketEvidence bracket_d;
    std::uint32_t invocation_count = 0;
    bool returned_normally = false;
    bool threw_exception = false;
    bool callback_reported_success = false;
    bool reentry_attempted = false;
    std::size_t sink_size = 0;
    bool sink_overflow = false;
    bool output_accepted = false;
    bool directory_acquired_after_builder = false;
    bool input_acquired_after_builder = false;
};

struct ExactInputReadObservation {
    ExactInputReadOutcome outcome = ExactInputReadOutcome::None;
    bool attempted = false;
    bool terminal_frozen = false;
    bool command_started = false;
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
    bool setpgid_denied = false;
    bool setsid_denied = false;
    bool clone_parent_observed = false;
    std::uint32_t adopted_reap_count = 0;
    bool foreign_process_survived = false;
    bool foreign_fd_excluded = false;
    bool deadline_exceeded = false;
    bool output_overflow = false;
    bool pre_source_revalidated = false;
    bool pre_container_identity = false;
    bool pre_mount_inspected = false;
    // These fields prove the inert sidecar's actual /proc UID/GID within fresh
    // immutable-identity brackets. They are not credential proof for the
    // transient docker-exec /bin/cat process.
    bool pre_proc_credentials = false;
    bool post_source_revalidated = false;
    bool post_container_identity = false;
    bool post_mount_inspected = false;
    bool post_proc_credentials = false;
    bool registered_identity_matched = false;
    bool registered_mount_matched = false;
    std::size_t expected_size = 0;
    int stdout_read_errno = 0;
    int stderr_read_errno = 0;
    ExactInputReadLaunchStage launch_failure_stage = ExactInputReadLaunchStage::None;
    int launch_errno = 0;
    int wait_status = 0;
    std::vector<std::string> command_argv;
    std::string resolved_executable;
    std::string stdout_bytes;
    std::string stderr_bytes;
    ExactInputMountDiagnostic diagnostic;
};

struct ExactInputWriteSourceBracket {
    bool source_revalidated = false;
    bool source_bytes_revalidated = false;
    bool retained_ofd_revalidated = false;
    bool container_identity_revalidated = false;
    bool mount_revalidated = false;
    bool proc_credentials_revalidated = false;
    bool registered_identity_matched = false;
    bool registered_mount_matched = false;
    std::string source_path;
    std::uint64_t source_device = 0;
    std::uint64_t source_inode = 0;
    std::uint64_t source_mode = 0;
    std::uint64_t source_uid = 0;
    std::uint64_t source_gid = 0;
    std::uint64_t source_size = 0;
    std::uint64_t source_links = 0;
    std::int64_t source_mtime_seconds = 0;
    std::int64_t source_mtime_nanoseconds = 0;
    std::int64_t source_ctime_seconds = 0;
    std::int64_t source_ctime_nanoseconds = 0;
};

struct ExactInputWriteRefusalObservation {
    ExactInputWriteRefusalOutcome outcome = ExactInputWriteRefusalOutcome::None;
    bool attempted = false;
    bool terminal_frozen = false;
    bool caller_deadline_recorded = false;
    std::int64_t final_deadline_nanoseconds = 0;
    std::string credentials;
    std::string expected_target_stderr;
    ExactInputWriteSourceBracket initial_bracket;
    ExactInputWriteSourceBracket middle_bracket;
    ExactInputWriteSourceBracket final_bracket;
    ExactInputReadObservation control;
    ExactInputReadObservation target;
    ExactInputMountDiagnostic diagnostic;
};

enum class ExactInputReadRunnerTestCase : std::uint8_t {
    CommandStartFailure,
    ImmediateExecSuccess,
    LeaderExitWithDescendant,
    ForkHandoffChain,
    SubtreeConfinement,
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
    ForeignFdExcluded,
    MaxSizeExact,
    EmbeddedNulExact,
    HeldOpenAfterExactBytes,
    ExtraByteThenEof,
    BeyondSentinel,
    ReadErrorAfterBytes,
    ExitSignaled,
    ExitNonzero,
    NonemptyStderr,
};

struct ExactInputMountRecoveryReceipt {
    ExactInputMountState state = ExactInputMountState::Empty;
    ExactInputMountTerminalResult terminal_result = ExactInputMountTerminalResult::None;
    bool attempted = false;
    bool mutation_may_have_occurred = false;
    bool recovery_required = false;
    bool graph_mutated = false;
    bool cleanup_not_applicable = false;
    bool sidecar_acquired = false;
    bool input_acquired = false;
    bool directory_acquired = false;
    bool holder_acquired = false;
    bool network_b_acquired = false;
    bool network_a_acquired = false;
    bool sidecar_settled = false;
    bool first_topology_revalidated = false;
    bool input_settled = false;
    bool directory_settled = false;
    bool second_topology_revalidated = false;
    bool holder_settled = false;
    bool network_b_settled = false;
    bool network_a_settled = false;
    bool manifest_not_applicable = false;
    bool final_zero_residue = false;
    bool settlement_complete = false;
    bool terminal_frozen = false;
    std::uint32_t network_a_create_count = 0;
    std::uint32_t network_a_verify_count = 0;
    std::uint32_t network_b_create_count = 0;
    std::uint32_t network_b_verify_count = 0;
    std::uint32_t both_ipam_verify_count = 0;
    std::uint32_t holder_create_count = 0;
    std::uint32_t holder_attach_a_verify_count = 0;
    std::uint32_t holder_attach_b_count = 0;
    std::uint32_t holder_remove_command_count = 0;
    std::uint32_t network_b_remove_command_count = 0;
    std::uint32_t network_a_remove_command_count = 0;
    std::uint32_t sidecar_order = 0;
    std::uint32_t input_order = 0;
    std::uint32_t directory_order = 0;
    std::uint32_t holder_order = 0;
    std::uint32_t network_b_order = 0;
    std::uint32_t network_a_order = 0;
    ExactInputBuilderEvidence builder;
    ExactInputMountDiagnostic diagnostic;
};

// Tests-only observation of the shared argv-only command runner.  It does not
// mutate fixture state and exists to prove that a never-started controller and
// a frozen terminal replay issue no external commands.
std::uint64_t exact_input_mount_test_command_count();
std::uint64_t exact_input_mount_test_observation_command_count();
bool exact_input_mount_test_terminal_settlement(const ExactInputMountRecoveryReceipt& receipt);
bool exact_input_mount_test_read_runner_case(ExactInputReadRunnerTestCase test_case,
                                             ExactInputReadObservation& observation,
                                             ExactInputMountDiagnostic& diagnostic);
bool exact_input_mount_test_write_refusal_self_checks(std::uint32_t& mutation_rejections,
                                                      ExactInputMountDiagnostic& diagnostic);
bool exact_input_mount_test_builder_self_checks(std::uint32_t& mutation_rejections,
                                                ExactInputMountDiagnostic& diagnostic);

class ExactInputMountRecoveryController;

class ExactInputMountHandle {
public:
    ExactInputMountHandle() = default;
    ~ExactInputMountHandle();
    ExactInputMountHandle(const ExactInputMountHandle&) = delete;
    ExactInputMountHandle& operator=(const ExactInputMountHandle&) = delete;
    ExactInputMountHandle(ExactInputMountHandle&& other) noexcept;
    ExactInputMountHandle& operator=(ExactInputMountHandle&& other) noexcept;

private:
    friend class ExactInputMountRecoveryController;
    std::uintptr_t controller_address_ = 0;
    std::uint64_t controller_cookie_ = 0;
    std::uint64_t generation_ = 0;
    std::uint8_t slot_ = 0;
    bool borrowed_ = false;
};

class ExactInputMountRecoveryController {
public:
    ExactInputMountRecoveryController();
    ~ExactInputMountRecoveryController();
    ExactInputMountRecoveryController(const ExactInputMountRecoveryController&) = delete;
    ExactInputMountRecoveryController& operator=(const ExactInputMountRecoveryController&) = delete;
    ExactInputMountRecoveryController(ExactInputMountRecoveryController&&) = delete;
    ExactInputMountRecoveryController& operator=(ExactInputMountRecoveryController&&) = delete;

    bool start(const void* bytes,
               std::size_t size,
               ExactInputMountHandle& handle,
               ExactInputMountDiagnostic& diagnostic,
               const ExactInputMountOptions& options = {});
    bool start_with_topology_builder(ExactInputTopologyBuilder builder,
                                     void* context,
                                     ExactInputMountHandle& handle,
                                     ExactInputMountDiagnostic& diagnostic,
                                     const ExactInputMountOptions& options = {});
    bool snapshot(const ExactInputMountHandle& handle,
                  ExactInputMountSnapshot& snapshot,
                  ExactInputMountDiagnostic& diagnostic) const;
    bool observe_input_read(const ExactInputMountHandle& handle,
                            ExactInputReadObservation& observation,
                            ExactInputMountDiagnostic& diagnostic);
    bool observe_input_write_refusal(const ExactInputMountHandle& handle,
                                     ExactInputWriteRefusalObservation& observation,
                                     ExactInputMountDiagnostic& diagnostic);
    bool finish(ExactInputMountHandle& handle,
                ExactInputMountRecoveryReceipt& receipt,
                ExactInputMountDiagnostic& diagnostic);
    bool recover_all(ExactInputMountRecoveryReceipt& receipt,
                     ExactInputMountDiagnostic& diagnostic);

private:
    friend class ExactInputMountHandle;
    void return_handle(ExactInputMountHandle& handle) noexcept;
    bool validate_handle(const ExactInputMountHandle& handle,
                         ExactInputMountDiagnostic& diagnostic) const;
    bool recover_impl(ExactInputMountRecoveryReceipt& receipt,
                      ExactInputMountDiagnostic& diagnostic);

    std::uintptr_t owner_cookie_ = 0;
    std::uint64_t cookie_ = 0;
    std::uint64_t generation_ = 0;
    std::int64_t construction_thread_ = -1;
    bool borrowed_ = false;
    bool recovering_ = false;
    std::atomic<bool> start_in_progress_{false};
    std::atomic<bool> builder_active_{false};
    mutable std::atomic<bool> reentry_attempted_{false};
    std::atomic<std::int64_t> operation_thread_{-1};
};

}  // namespace rut::test::ipv4_topology
