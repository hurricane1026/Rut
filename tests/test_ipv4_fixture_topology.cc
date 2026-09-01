#include "fixture_ipv4_topology.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>

using rut::test::ipv4_topology::FailurePoint;
using rut::test::ipv4_topology::HeldNamespaceSidecarFailurePoint;
using rut::test::ipv4_topology::HeldNamespaceSidecarRevalidationFault;
using rut::test::ipv4_topology::HeldTopologyProbeEvidence;
using rut::test::ipv4_topology::HeldTopologyProbePolicy;
using rut::test::ipv4_topology::RunResult;

int main() {
    const char* required = std::getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED");
    const bool must_run = required != nullptr && std::string(required) == "1";
    std::string validation_error;
    if (!rut::test::ipv4_topology::pure_validation_self_checks(validation_error)) {
        std::cerr << "FAIL [#358 Stage 2a2 pure validation]: " << validation_error << "\n";
        return 1;
    }
    if (!rut::test::ipv4_topology::runner_descendant_self_check(validation_error)) {
        std::cerr << "FAIL [#358 Stage 2a2 runner PGID validation]: " << validation_error << "\n";
        return 1;
    }
    HeldTopologyProbeEvidence default_probe_evidence{
        HeldTopologyProbePolicy::RequireHostRefusalProbes, 1u, 2u, 2u};
    if (!rut::test::ipv4_topology::validate_held_topology_probe_evidence(
            default_probe_evidence,
            HeldTopologyProbePolicy::RequireHostRefusalProbes,
            validation_error)) {
        std::cerr << "FAIL [#358 Stage 2a3b held topology probe policy]: " << validation_error
                  << "\n";
        return 1;
    }
    HeldTopologyProbeEvidence mutated_probe_evidence = default_probe_evidence;
    mutated_probe_evidence.host_parent_af_inet_socket_calls = 0u;
    validation_error.clear();
    if (rut::test::ipv4_topology::validate_held_topology_probe_evidence(
            mutated_probe_evidence,
            HeldTopologyProbePolicy::RequireHostRefusalProbes,
            validation_error)) {
        std::cerr << "FAIL [#358 Stage 2a3b held topology probe policy]: mutated default probe "
                     "evidence was accepted\n";
        return 1;
    }
    HeldTopologyProbeEvidence socketless_probe_evidence{
        HeldTopologyProbePolicy::SocketlessHostParent, 1u, 0u, 0u};
    validation_error.clear();
    if (!rut::test::ipv4_topology::validate_held_topology_probe_evidence(
            socketless_probe_evidence,
            HeldTopologyProbePolicy::SocketlessHostParent,
            validation_error)) {
        std::cerr << "FAIL [#358 Stage 2a3b socketless topology probe policy]: " << validation_error
                  << "\n";
        return 1;
    }
    mutated_probe_evidence = socketless_probe_evidence;
    mutated_probe_evidence.host_parent_af_inet_socket_calls = 1u;
    validation_error.clear();
    if (rut::test::ipv4_topology::validate_held_topology_probe_evidence(
            mutated_probe_evidence,
            HeldTopologyProbePolicy::SocketlessHostParent,
            validation_error) ||
        rut::test::ipv4_topology::validate_held_topology_probe_evidence(
            socketless_probe_evidence,
            HeldTopologyProbePolicy::RequireHostRefusalProbes,
            validation_error) ||
        rut::test::ipv4_topology::validate_held_topology_probe_evidence(
            default_probe_evidence,
            HeldTopologyProbePolicy::SocketlessHostParent,
            validation_error)) {
        std::cerr << "FAIL [#358 Stage 2a3b socketless topology probe policy]: mutated/swapped "
                     "socket policy evidence was accepted\n";
        return 1;
    }
    const RunResult preflight = rut::test::ipv4_topology::run(FailurePoint::AfterNetworkACreated);
    if (preflight.prerequisite_failure) {
        if (!preflight.optional_skip_safe) {
            std::cerr << "FAIL [#358 Stage 2a2 preflight]: " << preflight.error << "\n";
            return 1;
        }
        std::cerr << (must_run ? "FAIL" : "SKIP")
                  << " [#358 Stage 2a2 preflight]: " << preflight.error << "\n";
        return must_run ? 1 : 77;
    }
    if (!preflight.success) {
        std::cerr << "FAIL [#358 Stage 2a2 failure injection]: " << preflight.error << "\n";
        return 1;
    }
    for (FailurePoint point : {FailurePoint::AfterNetworkAVerified,
                               FailurePoint::AfterNetworkBCreated,
                               FailurePoint::AfterNetworkBVerified,
                               FailurePoint::AfterNetworkACreationReportedTimeout,
                               FailurePoint::AfterBothIpamVerified,
                               FailurePoint::AfterHolderCreated,
                               FailurePoint::AfterHolderAttachedA,
                               FailurePoint::AfterHolderAttachedB,
                               FailurePoint::AfterTopologyVerified,
                               FailurePoint::AfterFirstProbe}) {
        const RunResult injected = rut::test::ipv4_topology::run(point);
        if (injected.prerequisite_failure) {
            std::cerr << "FAIL [#358 Stage 2a2 matrix preflight changed after mutation]: "
                      << injected.error << "\n";
            return 1;
        }
        if (!injected.success) {
            std::cerr << "FAIL [#358 Stage 2a2 failure-atomic matrix]: " << injected.error << "\n";
            return 1;
        }
    }
    const RunResult full = rut::test::ipv4_topology::run(FailurePoint::None);
    if (full.prerequisite_failure) {
        std::cerr << "FAIL [#358 Stage 2a2 preflight changed before full run]: " << full.error
                  << "\n";
        return 1;
    }
    if (!full.success) {
        std::cerr << "FAIL [#358 Stage 2a2 topology]: " << full.error << "\n";
        return 1;
    }
    bool held_callback_ran = false;
    const RunResult held = rut::test::ipv4_topology::run_with_held_topology(
        [&](const rut::test::ipv4_topology::HeldTopologySnapshot& snapshot, std::string& error) {
            held_callback_ran = true;
            const auto require = [&](bool condition, const char* field) {
                if (!condition && error.empty())
                    error = std::string("held topology snapshot invalid field: ") + field;
                return condition;
            };
            std::string probe_error;
            return require(rut::test::ipv4_topology::validate_held_topology_probe_evidence(
                               snapshot.probe_evidence,
                               HeldTopologyProbePolicy::RequireHostRefusalProbes,
                               probe_error),
                           probe_error.c_str()) &&
                   require(!snapshot.token.empty(), "token") &&
                   require(!snapshot.network_a_name.empty(), "network_a_name") &&
                   require(!snapshot.network_a_id.empty(), "network_a_id") &&
                   require(!snapshot.network_a_subnet.empty(), "network_a_subnet") &&
                   require(!snapshot.network_a_gateway.empty(), "network_a_gateway") &&
                   require(!snapshot.network_b_name.empty(), "network_b_name") &&
                   require(!snapshot.network_b_id.empty(), "network_b_id") &&
                   require(!snapshot.network_b_subnet.empty(), "network_b_subnet") &&
                   require(!snapshot.network_b_gateway.empty(), "network_b_gateway") &&
                   require(snapshot.network_a_name != snapshot.network_b_name, "network_names") &&
                   require(snapshot.network_a_id != snapshot.network_b_id, "network_ids") &&
                   require(!snapshot.holder_name.empty(), "holder_name") &&
                   require(!snapshot.holder_id.empty(), "holder_id") &&
                   require(!snapshot.positive_ip.empty(), "positive_ip") &&
                   require(!snapshot.guard_ip.empty(), "guard_ip") &&
                   require(snapshot.positive_ip != snapshot.guard_ip, "fixture_ips") &&
                   require(snapshot.holder_pid > 1, "holder_pid") &&
                   require(snapshot.holder_start != 0, "holder_start") &&
                   require(snapshot.holder_netns != 0, "holder_netns");
        });
    if (held.prerequisite_failure || !held.success || !held_callback_ran) {
        std::cerr << "FAIL [#358 Stage 2a3b held topology callback]: " << held.error << "\n";
        return 1;
    }
    const auto sidecar_callback =
        [&](const rut::test::ipv4_topology::HeldTopologySnapshot& topology,
            const rut::test::ipv4_topology::HeldNamespaceSidecarSnapshot& sidecar,
            std::string& error) {
            return rut::test::ipv4_topology::validate_held_namespace_sidecar_snapshot(
                topology, sidecar, error);
        };
    const RunResult sidecar_normal =
        rut::test::ipv4_topology::run_with_held_topology_and_sidecar(sidecar_callback);
    if (sidecar_normal.prerequisite_failure || !sidecar_normal.success ||
        !sidecar_normal.cleanup_complete || !sidecar_normal.residue_free ||
        !sidecar_normal.semantic_receipt.empty() || !sidecar_normal.error.empty()) {
        std::cerr << "FAIL [#358 held-namespace sidecar normal lifecycle]: " << sidecar_normal.error
                  << "\n";
        return 1;
    }
    for (const auto& injection :
         {std::pair{HeldNamespaceSidecarFailurePoint::AfterCreate,
                    std::string("injected held-namespace sidecar failure after create")},
          std::pair{HeldNamespaceSidecarFailurePoint::AfterDiscovery,
                    std::string("injected held-namespace sidecar failure after discovery")},
          std::pair{HeldNamespaceSidecarFailurePoint::AfterVerification,
                    std::string("injected held-namespace sidecar failure after verification")},
          std::pair{HeldNamespaceSidecarFailurePoint::AfterCallbackEntry,
                    std::string("injected held-namespace sidecar failure after callback entry")},
          std::pair{HeldNamespaceSidecarFailurePoint::CreateReportedTimeout,
                    std::string("injected sidecar actual-success/reported-timeout; recovered exact "
                                "identity")},
          std::pair{HeldNamespaceSidecarFailurePoint::CreateReportedTimeoutRecoveryUnavailable,
                    std::string("verified uncertain sidecar create fail-closed recovery and zero "
                                "residue")},
          std::pair{HeldNamespaceSidecarFailurePoint::CleanupReportedTimeout,
                    std::string("verified sidecar cleanup actual-success/reported-timeout "
                                "recovery")},
          std::pair{HeldNamespaceSidecarFailurePoint::UnexpectedDeath,
                    std::string("verified unexpected sidecar death: exact stopped identity and no "
                                "live /proc witness")},
          std::pair{HeldNamespaceSidecarFailurePoint::DisappearBeforeCleanup,
                    std::string("verified already-disappeared sidecar settlement and safe topology "
                                "cleanup")},
          std::pair{HeldNamespaceSidecarFailurePoint::PauseAfterSidecarSettlement,
                    std::string("verified sidecar-settled pause, guarded topology retry, and inert "
                                "terminal replay")}}) {
        const RunResult injected = rut::test::ipv4_topology::run_with_held_topology_and_sidecar(
            sidecar_callback, injection.first);
        if (injected.prerequisite_failure || !injected.success || !injected.cleanup_complete ||
            !injected.residue_free || injected.semantic_receipt != injection.second ||
            injected.error != injection.second) {
            std::cerr << "FAIL [#358 held-namespace sidecar failure-atomic matrix]: "
                      << injected.error << "\n";
            return 1;
        }
    }
    bool failing_callback_ran = false;
    const RunResult callback_failure = rut::test::ipv4_topology::run_with_held_topology_and_sidecar(
        [&](const rut::test::ipv4_topology::HeldTopologySnapshot&,
            const rut::test::ipv4_topology::HeldNamespaceSidecarSnapshot&,
            std::string& error) {
            failing_callback_ran = true;
            error = "injected sidecar callback failure";
            return false;
        });
    if (callback_failure.prerequisite_failure || callback_failure.success ||
        !callback_failure.cleanup_complete || !callback_failure.residue_free ||
        !failing_callback_ran || callback_failure.error != "injected sidecar callback failure" ||
        callback_failure.semantic_receipt != "injected sidecar callback failure") {
        std::cerr << "FAIL [#358 held-namespace sidecar callback cleanup]: "
                  << callback_failure.error << "\n";
        return 1;
    }
    for (const auto& fault :
         {std::pair{HeldNamespaceSidecarRevalidationFault::Token, "token"},
          std::pair{HeldNamespaceSidecarRevalidationFault::Role, "role"},
          std::pair{HeldNamespaceSidecarRevalidationFault::Id, "id"},
          std::pair{HeldNamespaceSidecarRevalidationFault::ImageReference, "image-reference"},
          std::pair{HeldNamespaceSidecarRevalidationFault::ImageId, "image-id"},
          std::pair{HeldNamespaceSidecarRevalidationFault::NetworkMode, "network-mode"},
          std::pair{HeldNamespaceSidecarRevalidationFault::Pid, "pid"},
          std::pair{HeldNamespaceSidecarRevalidationFault::StartIdentity, "start-identity"},
          std::pair{HeldNamespaceSidecarRevalidationFault::NetworkNamespace, "network-namespace"},
          std::pair{HeldNamespaceSidecarRevalidationFault::Arguments, "arguments"},
          std::pair{HeldNamespaceSidecarRevalidationFault::ReadOnlyRoot, "read-only-root"},
          std::pair{HeldNamespaceSidecarRevalidationFault::CapabilityDrop, "capability-drop"},
          std::pair{HeldNamespaceSidecarRevalidationFault::NoNewPrivileges, "no-new-privileges"},
          std::pair{HeldNamespaceSidecarRevalidationFault::PublishedPorts, "published-ports"}}) {
        const RunResult rejected = rut::test::ipv4_topology::run_with_held_topology_and_sidecar(
            sidecar_callback, HeldNamespaceSidecarFailurePoint::None, fault.first);
        const std::string expected_receipt_prefix =
            std::string("verified pre-removal sidecar revalidation rejection ") + fault.second +
            ": refusing sidecar deletion";
        if (rejected.prerequisite_failure || !rejected.success || !rejected.cleanup_complete ||
            !rejected.residue_free || rejected.semantic_receipt.empty() ||
            rejected.error != rejected.semantic_receipt ||
            rejected.semantic_receipt.find(expected_receipt_prefix) != 0) {
            std::cerr << "FAIL [#358 held-namespace sidecar revalidation mutation]: "
                      << rejected.error << "\n";
            return 1;
        }
    }
    std::cerr << "PASS: #358 Stage 2a2 Docker topology/IPAM and failure-atomic cleanup\n";
    std::cerr << "PASS: #358 held-namespace sibling-container lease and zero-residue cleanup\n";
    return 0;
}
