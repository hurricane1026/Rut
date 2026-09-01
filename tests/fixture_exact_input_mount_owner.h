#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rut::test::ipv4_topology {

inline constexpr const char* kExactInputMountDestination = "/etc/nginx/nginx.conf";

enum class ExactInputMountState : std::uint8_t {
    Empty,
    SettingUp,
    ReadyForObservation,
    ObservingInput,
    InputReadObserved,
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
    StdoutDuplication,
    StderrDuplication,
    DescriptorCustody,
    Execute,
    PidfdOpen,
    PidfdIdentity,
    ExecStatusProtocol,
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
    Sidecar,
    MountInspect,
    FileRevalidation,
    InputObservation,
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
    std::uint32_t group_absence_confirmations = 0;
    bool pidfd_opened = false;
    bool pidfd_identity_verified = false;
    bool pidfd_closed_after_group_gone = false;
    bool final_deadline_recorded = false;
    bool cleanup_completed_before_final_deadline = false;
    bool leader_exit_observed_before_group_cleanup = false;
    bool descendant_group_member_observed = false;
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
    std::string stdout_bytes;
    std::string stderr_bytes;
    ExactInputMountDiagnostic diagnostic;
};

enum class ExactInputReadRunnerTestCase : std::uint8_t {
    CommandStartFailure,
    LeaderExitWithDescendant,
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
    ExactInputMountDiagnostic diagnostic;
};

// Tests-only observation of the shared argv-only command runner.  It does not
// mutate fixture state and exists to prove that a never-started controller and
// a frozen terminal replay issue no external commands.
std::uint64_t exact_input_mount_test_command_count();
bool exact_input_mount_test_read_runner_case(ExactInputReadRunnerTestCase test_case,
                                             ExactInputReadObservation& observation,
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
    bool snapshot(const ExactInputMountHandle& handle,
                  ExactInputMountSnapshot& snapshot,
                  ExactInputMountDiagnostic& diagnostic) const;
    bool observe_input_read(const ExactInputMountHandle& handle,
                            ExactInputReadObservation& observation,
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
};

}  // namespace rut::test::ipv4_topology
