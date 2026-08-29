#pragma once

#include <string>

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
    std::string error;
};

RunResult run(FailurePoint failure_point);
bool audit_zero_residue(const std::string& token,
                        const std::string& network_a_name,
                        const std::string& network_b_name,
                        const std::string& holder_name,
                        std::string& error);
bool pure_validation_self_checks(std::string& error);
bool runner_descendant_self_check(std::string& error);

}  // namespace rut::test::ipv4_topology
