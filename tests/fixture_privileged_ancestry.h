#pragma once

#include "fixture_ancestry_bundle.h"
#include "fixture_direct_launch.h"
#include "fixture_identity_bundle.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <sys/types.h>

namespace rut::test::fixture_privileged_ancestry {

namespace ancestry = fixture_ancestry_bundle;
namespace identity = fixture_identity_bundle;
using fixture_direct_launch::DirectLaunch;
using fixture_direct_launch::ProcIdentity;

struct RetainedAnchorEvidence {
    pid_t pid = -1;
    pid_t ppid = -1;
    pid_t pgid = -1;
    pid_t sid = -1;
    std::uint64_t start = 0;
    char state = 0;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    std::array<uid_t, 4> uid_values{};
    std::array<gid_t, 4> gid_values{};
    std::string cmdline;
    bool pidfd_live = false;
};

// A snapshot of the caller-owned group lease. The helper does not own or close
// the pidfd; callers retain ownership for their lifecycle and cleanup policy.
struct RetainedAnchorLease {
    pid_t pid = -1;
    pid_t pgid = -1;
    pid_t sid = -1;
    std::uint64_t start = 0;
    int pidfd = -1;
};

bool collect_ancestry(pid_t first_parent,
                      pid_t ordinary_parent,
                      ancestry::AncestryBundle& output,
                      std::chrono::steady_clock::time_point deadline,
                      std::string& safe_diagnostic);

bool parse_retained_anchor_stat(const std::string& text, RetainedAnchorEvidence& evidence);
bool parse_retained_anchor_status(const std::string& text, RetainedAnchorEvidence& evidence);
bool retained_pidfd_live(int pidfd);
bool capture_retained_anchor_evidence(const DirectLaunch& launch,
                                      const RetainedAnchorLease& lease,
                                      RetainedAnchorEvidence& evidence,
                                      std::string& reason);

// Bind the sole ancestry record to the retained-anchor semantic evidence.
// Zero or more than one record is deliberately rejected.
bool bind_retained_anchor_evidence(const std::vector<identity::ProcessIdentityEvidence>& records,
                                   RetainedAnchorEvidence& evidence,
                                   std::string& error);

bool prove_retained_sudo_wrapper(DirectLaunch& launch,
                                 const ProcIdentity& launcher,
                                 const RetainedAnchorEvidence& evidence,
                                 std::string& reason);

}  // namespace rut::test::fixture_privileged_ancestry
