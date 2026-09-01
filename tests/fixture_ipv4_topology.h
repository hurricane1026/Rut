#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include <sys/types.h>

namespace rut::test::ipv4_topology {

// This fixture intentionally stops before any worker/process namespace entry.
// It is the Docker/IPAM substrate for the later listener experiment.
enum class FailurePoint {
    None,
    AfterNetworkACreated,
    AfterNetworkAVerified,
    AfterNetworkBCreated,
    AfterNetworkBVerified,
    AfterNetworkACreationReportedTimeout,
    AfterBothIpamVerified,
    AfterHolderCreated,
    AfterHolderAttachedA,
    AfterHolderAttachedB,
    AfterTopologyVerified,
    AfterFirstProbe,
};

struct RunResult {
    bool success = false;
    bool prerequisite_failure = false;
    bool optional_skip_safe = false;
    bool cleanup_complete = false;
    bool residue_free = false;
    std::string error;
    std::string semantic_receipt;
};

// Controls only the host-parent verification performed after Docker topology
// setup. Docker/IPAM setup and read-only holder /proc validation are unchanged.
enum class HeldTopologyProbePolicy {
    RequireHostRefusalProbes,
    SocketlessHostParent,
};

struct HeldTopologyProbeEvidence {
    HeldTopologyProbePolicy policy = HeldTopologyProbePolicy::RequireHostRefusalProbes;
    std::uint32_t selected_port_absence_checks = 0;
    std::uint32_t host_parent_af_inet_socket_calls = 0;
    std::uint32_t successful_refusal_probes = 0;
};

// Immutable evidence exposed only while the topology fixture remains alive.
// The fixture retains exclusive ownership of every Docker resource.
struct HeldTopologySnapshot {
    std::string token;
    std::string network_a_name;
    std::string network_a_id;
    std::string network_a_subnet;
    std::string network_a_gateway;
    std::string network_b_name;
    std::string network_b_id;
    std::string network_b_subnet;
    std::string network_b_gateway;
    std::string holder_name;
    std::string holder_id;
    std::string positive_ip;
    std::string guard_ip;
    pid_t holder_pid = -1;
    std::uint64_t holder_start = 0;
    ino_t holder_netns = 0;
    HeldTopologyProbeEvidence probe_evidence;
};

// Immutable evidence for one inert sibling container that shares the held
// holder's network namespace.  The topology Fixture remains the sole owner of
// the container and removes it before releasing the holder.
struct HeldNamespaceSidecarSnapshot {
    std::string token;
    std::string stage;
    std::string role;
    std::string name;
    std::string id;
    std::string pinned_image_reference;
    std::string expected_image_id;
    std::string image_id;
    std::string network_mode;
    std::string path;
    std::string arguments_json;
    pid_t pid = -1;
    std::uint64_t start = 0;
    ino_t netns = 0;
    ino_t host_netns = 0;
    bool running = false;
    bool read_only_root = false;
    bool capability_drop_all = false;
    bool no_new_privileges = false;
    bool no_published_ports = false;
};

// Pure value evidence for replacing only the holder/sidecar generation while
// retaining the exact Docker networks and addressing plan.  It deliberately
// records process identity as (pid,start): a numeric PID may be reused by a
// later generation when its start time differs.
struct HeldNamespaceGenerationSnapshot {
    HeldTopologySnapshot topology;
    HeldNamespaceSidecarSnapshot sidecar;
};

struct HeldNamespaceGenerationWitnessAbsence {
    std::string container_id;
    pid_t pid = -1;
    std::uint64_t start = 0;
    bool container_id_absent = false;
    bool process_identity_absent = false;
};

enum class HeldNamespaceGenerationRotationPhase : std::uint8_t {
    None = 0,
    OldGenerationValidated = 1,
    OldGenerationAbsent = 2,
    NewGenerationCreated = 3,
    NewGenerationValidated = 4,
};

struct HeldNamespaceOldGenerationAbsence {
    HeldNamespaceGenerationWitnessAbsence holder;
    HeldNamespaceGenerationWitnessAbsence sidecar;
    std::string holder_name;
    std::string sidecar_name;
    bool holder_name_absent = false;
    bool sidecar_name_absent = false;
    // This aggregate phase is complete only after all exact ID, process and
    // name witnesses above are absent, before either stable name is reused.
    HeldNamespaceGenerationRotationPhase phase = HeldNamespaceGenerationRotationPhase::None;
};

struct HeldNamespaceGenerationRotationReceipt {
    HeldNamespaceGenerationSnapshot old_generation;
    HeldNamespaceGenerationRotationPhase old_generation_phase =
        HeldNamespaceGenerationRotationPhase::None;
    HeldNamespaceOldGenerationAbsence old_absence;
    HeldNamespaceGenerationSnapshot new_generation;
    HeldNamespaceGenerationRotationPhase new_generation_created_phase =
        HeldNamespaceGenerationRotationPhase::None;
    HeldNamespaceGenerationRotationPhase new_generation_validated_phase =
        HeldNamespaceGenerationRotationPhase::None;
};

enum class HeldNamespaceSidecarFailurePoint {
    None,
    AfterCreate,
    AfterDiscovery,
    AfterVerification,
    AfterCallbackEntry,
    CreateReportedTimeout,
    CreateReportedTimeoutRecoveryUnavailable,
    CleanupReportedTimeout,
    UnexpectedDeath,
    DisappearBeforeCleanup,
    PauseAfterSidecarSettlement,
};

// A bounded test-only seam.  Each value corrupts one field of the raw Docker
// inspect record during the first cleanup revalidation.  Production callers
// leave this disabled.
enum class HeldNamespaceSidecarRevalidationFault {
    None,
    Token,
    Role,
    Id,
    ImageReference,
    ImageId,
    NetworkMode,
    Pid,
    StartIdentity,
    NetworkNamespace,
    Arguments,
    ReadOnlyRoot,
    CapabilityDrop,
    NoNewPrivileges,
    PublishedPorts,
};

using HeldTopologyCallback =
    std::function<bool(const HeldTopologySnapshot& snapshot, std::string& error)>;
using HeldTopologyAndSidecarCallback =
    std::function<bool(const HeldTopologySnapshot& topology,
                       const HeldNamespaceSidecarSnapshot& sidecar,
                       std::string& error)>;

RunResult run(FailurePoint failure_point);
RunResult run_with_held_topology(const HeldTopologyCallback& callback);
RunResult run_with_held_topology(HeldTopologyProbePolicy policy,
                                 const HeldTopologyCallback& callback);
RunResult run_with_held_topology_and_sidecar(
    const HeldTopologyAndSidecarCallback& callback,
    HeldNamespaceSidecarFailurePoint failure_point = HeldNamespaceSidecarFailurePoint::None,
    HeldNamespaceSidecarRevalidationFault revalidation_fault =
        HeldNamespaceSidecarRevalidationFault::None);
RunResult run_with_held_topology_and_sidecar(
    HeldTopologyProbePolicy policy,
    const HeldTopologyAndSidecarCallback& callback,
    HeldNamespaceSidecarFailurePoint failure_point = HeldNamespaceSidecarFailurePoint::None,
    HeldNamespaceSidecarRevalidationFault revalidation_fault =
        HeldNamespaceSidecarRevalidationFault::None);
bool parse_held_namespace_sidecar_inspect_record(const std::string& record,
                                                 HeldNamespaceSidecarSnapshot& snapshot,
                                                 std::string& error);
bool validate_held_namespace_sidecar_snapshot(const HeldTopologySnapshot& topology,
                                              const HeldNamespaceSidecarSnapshot& sidecar,
                                              std::string& error);
bool validate_held_namespace_generation_rotation_receipt(
    const HeldNamespaceGenerationRotationReceipt& receipt, std::string& error);
bool validate_held_topology_probe_evidence(const HeldTopologyProbeEvidence& evidence,
                                           HeldTopologyProbePolicy expected_policy,
                                           std::string& error);
bool audit_zero_residue(const std::string& token,
                        const std::string& network_a_name,
                        const std::string& network_b_name,
                        const std::string& holder_name,
                        std::string& error);
bool pure_validation_self_checks(std::string& error);
bool runner_descendant_self_check(std::string& error);

}  // namespace rut::test::ipv4_topology
