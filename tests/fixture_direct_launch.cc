#include "fixture_direct_launch.h"

#include <algorithm>
#include <sstream>
#include <utility>

namespace rut::test::fixture_direct_launch {
namespace {

int stage_rank(LaunchStage stage) {
    switch (stage) {
        case LaunchStage::Sudo:
            return 0;
        case LaunchStage::Nsenter:
            return 1;
        case LaunchStage::Launcher:
            return 2;
    }
    return -1;
}

const StageDescriptor& descriptor(const DirectLaunch& launch, LaunchStage stage) {
    switch (stage) {
        case LaunchStage::Sudo:
            return launch.allowed.sudo_stage;
        case LaunchStage::Nsenter:
            return launch.allowed.nsenter_stage;
        case LaunchStage::Launcher:
            return launch.allowed.launcher_stage;
    }
    return launch.allowed.sudo_stage;
}

bool identify_stage(const DirectLaunch& launch,
                    const ProcIdentity& identity,
                    LaunchStage& stage,
                    std::string& reason) {
    for (const LaunchStage candidate :
         {LaunchStage::Sudo, LaunchStage::Nsenter, LaunchStage::Launcher}) {
        const StageDescriptor& expected = descriptor(launch, candidate);
        if (identity.exe_dev == expected.exe_dev && identity.exe_ino == expected.exe_ino &&
            identity.cmdline == expected.argv) {
            stage = candidate;
            return true;
        }
    }
    reason = "executable/argv is not an exact allowed launch stage";
    return false;
}

bool stage_context_valid(const DirectLaunch& launch,
                         LaunchStage stage,
                         const ProcIdentity& identity,
                         std::string& reason) {
    if (stage == LaunchStage::Sudo) {
        const bool caller =
            identity.uid == launch.anchor.caller_uid && identity.gid == launch.anchor.caller_gid;
        const bool elevated = identity.uid == 0 && identity.gid == 0;
        if ((caller || elevated) && identity.netns == launch.anchor.host_netns) return true;
        reason = "sudo stage had neither exact caller nor exact root credentials in host netns";
        return false;
    }
    if (identity.uid != 0 || identity.gid != 0) {
        reason = "nsenter/launcher stage did not have exact root credentials";
        return false;
    }
    if (stage == LaunchStage::Nsenter && (identity.netns == launch.anchor.host_netns ||
                                          identity.netns == launch.allowed.holder_netns))
        return true;
    if (stage == LaunchStage::Launcher && identity.netns == launch.allowed.holder_netns)
        return true;
    reason = "launch stage had an invalid host/holder netns transition";
    return false;
}

bool common_identity_valid(const DirectLaunch& launch,
                           const ProcIdentity& identity,
                           bool direct,
                           std::string& reason) {
    if (launch.anchor.pid <= 1 || launch.anchor.start == 0 ||
        launch.anchor.pgid != launch.anchor.pid ||
        launch.anchor.caller_uid == static_cast<uid_t>(-1) ||
        launch.anchor.caller_gid == static_cast<gid_t>(-1) || launch.anchor.host_netns == 0 ||
        launch.allowed.holder_netns == 0 ||
        launch.anchor.host_netns == launch.allowed.holder_netns) {
        reason = "immutable direct launch anchor was stale or unsafe";
        return false;
    }
    if (identity.pid <= 1 || identity.start == 0 || identity.pgid <= 1 ||
        identity.pgid != launch.anchor.pgid) {
        reason = "launch identity had a stale PID/start or unsafe PGID";
        return false;
    }
    if (direct && (identity.pid != launch.anchor.pid || identity.start != launch.anchor.start)) {
        reason = "direct identity did not match the immutable PID/start anchor";
        return false;
    }
    return true;
}

void append_observed(DirectLaunch& launch, LaunchStage stage) {
    if (launch.observed_stages.empty() || launch.observed_stages.back() != stage)
        launch.observed_stages.push_back(stage);
}

bool exact_stage_identity(const DirectLaunch& launch,
                          const ProcIdentity& identity,
                          bool direct,
                          LaunchStage& stage,
                          std::string& reason) {
    return common_identity_valid(launch, identity, direct, reason) &&
           identify_stage(launch, identity, stage, reason) &&
           stage_context_valid(launch, stage, identity, reason);
}

}  // namespace

DirectLaunch::DirectLaunch(DirectLaunchAnchor anchor_value,
                           AllowedStages allowed_value,
                           bool marker_was_valid)
    : anchor(std::move(anchor_value)),
      allowed(std::move(allowed_value)),
      marker_valid(marker_was_valid) {}

bool launch_marker_matches(const unsigned char* marker, size_t size) {
    return marker != nullptr && size == kLaunchMarker.size() &&
           std::equal(kLaunchMarker.begin(), kLaunchMarker.end(), marker);
}

bool observe_direct(DirectLaunch& launch, const ProcIdentity& identity, std::string& reason) {
    if (!launch.marker_valid) {
        reason = "launch marker was missing or invalid";
        launch.reason = reason;
        return false;
    }
    LaunchStage stage = LaunchStage::Sudo;
    if (!exact_stage_identity(launch, identity, true, stage, reason)) {
        launch.reason = reason;
        return false;
    }
    if (launch.current_valid && stage_rank(stage) < stage_rank(launch.current_stage)) {
        reason = "direct launch stages were reordered";
        launch.reason = reason;
        return false;
    }
    if (launch.current_valid && launch.current_stage == LaunchStage::Nsenter &&
        launch.current_identity.netns == launch.allowed.holder_netns &&
        identity.netns == launch.anchor.host_netns) {
        reason = "nsenter netns transition regressed to the host";
        launch.reason = reason;
        return false;
    }
    if (launch.current_valid && launch.current_stage == LaunchStage::Sudo &&
        launch.current_identity.uid == 0 && identity.uid == launch.anchor.caller_uid) {
        reason = "sudo credential transition regressed from root to caller";
        launch.reason = reason;
        return false;
    }
    if (launch.mode == LaunchMode::SudoWrapper && stage != LaunchStage::Sudo) {
        reason = "sudo-wrapper direct process changed away from exact sudo";
        launch.reason = reason;
        return false;
    }
    if (stage != LaunchStage::Sudo) launch.mode = LaunchMode::ExecChain;
    append_observed(launch, stage);
    launch.current_identity = identity;
    launch.current_stage = stage;
    launch.current_valid = true;
    if (stage == LaunchStage::Launcher) {
        launch.launcher_identity = identity;
        launch.launcher_valid = true;
    }
    launch.reason.clear();
    reason.clear();
    return true;
}

bool validate_launcher_ancestry(DirectLaunch& launch,
                                const ProcIdentity& launcher,
                                const std::vector<ProcIdentity>& ancestry,
                                std::string& reason) {
    LaunchStage launcher_stage = LaunchStage::Sudo;
    if (!exact_stage_identity(
            launch, launcher, launcher.pid == launch.anchor.pid, launcher_stage, reason) ||
        launcher_stage != LaunchStage::Launcher) {
        if (reason.empty()) reason = "reported wrapper was not the exact launcher stage";
        launch.reason = reason;
        return false;
    }
    if (launcher.pid == launch.anchor.pid) {
        if (!ancestry.empty() || !observe_direct(launch, launcher, reason) ||
            launch.mode != LaunchMode::ExecChain) {
            if (reason.empty()) reason = "direct launcher was not a valid exec chain";
            launch.reason = reason;
            return false;
        }
        launch.launcher_identity = launcher;
        launch.launcher_valid = true;
        return true;
    }
    if (launch.mode == LaunchMode::ExecChain || ancestry.empty() ||
        ancestry.size() > kMaxLaunchAncestry || launcher.ppid != ancestry.front().pid) {
        reason = "sudo-wrapper launcher ancestry was missing, oversized, or inconsistent";
        launch.reason = reason;
        return false;
    }
    pid_t expected_pid = launcher.ppid;
    int previous_rank = stage_rank(LaunchStage::Launcher);
    ino_t later_nsenter_netns = launch.allowed.holder_netns;
    bool later_sudo_is_caller = false;
    std::vector<LaunchStage> reverse_stages;
    for (size_t index = 0; index != ancestry.size(); ++index) {
        const ProcIdentity& identity = ancestry[index];
        if (identity.pid != expected_pid) {
            reason = "sudo-wrapper ancestry parent link changed";
            launch.reason = reason;
            return false;
        }
        const bool direct = index + 1 == ancestry.size();
        LaunchStage stage = LaunchStage::Sudo;
        if (!exact_stage_identity(launch, identity, direct, stage, reason) ||
            stage == LaunchStage::Launcher || stage_rank(stage) > previous_rank ||
            (stage == LaunchStage::Nsenter && later_nsenter_netns == launch.anchor.host_netns &&
             identity.netns == launch.allowed.holder_netns) ||
            (stage == LaunchStage::Sudo && later_sudo_is_caller && identity.uid == 0)) {
            if (reason.empty()) reason = "sudo-wrapper intermediary stage was reordered";
            launch.reason = reason;
            return false;
        }
        if (stage == LaunchStage::Nsenter) later_nsenter_netns = identity.netns;
        if (stage == LaunchStage::Sudo)
            later_sudo_is_caller = identity.uid == launch.anchor.caller_uid;
        reverse_stages.push_back(stage);
        previous_rank = stage_rank(stage);
        expected_pid = identity.ppid;
    }
    const ProcIdentity& direct = ancestry.back();
    if (direct.pid != launch.anchor.pid || reverse_stages.back() != LaunchStage::Sudo) {
        reason = "sudo-wrapper ancestry did not terminate at exact direct sudo";
        launch.reason = reason;
        return false;
    }
    if (launch.current_valid && launch.current_stage != LaunchStage::Sudo) {
        reason = "sudo-wrapper conflicted with observed direct exec-chain stage";
        launch.reason = reason;
        return false;
    }
    launch.mode = LaunchMode::SudoWrapper;
    launch.current_identity = direct;
    launch.current_stage = LaunchStage::Sudo;
    launch.current_valid = true;
    for (auto stage = reverse_stages.rbegin(); stage != reverse_stages.rend(); ++stage)
        append_observed(launch, *stage);
    append_observed(launch, LaunchStage::Launcher);
    launch.launcher_identity = launcher;
    launch.launcher_valid = true;
    launch.reason.clear();
    reason.clear();
    return true;
}

bool current_allows_group_signal(const DirectLaunch& launch,
                                 const ProcIdentity& current,
                                 std::string& reason) {
    LaunchStage retained_stage = LaunchStage::Sudo;
    if (!launch.current_valid || !launch.marker_valid ||
        !exact_stage_identity(launch, launch.current_identity, true, retained_stage, reason) ||
        retained_stage != launch.current_stage ||
        (launch.mode == LaunchMode::SudoWrapper && retained_stage != LaunchStage::Sudo)) {
        if (reason.empty()) reason = "retained current launch identity was not exact";
        return false;
    }
    DirectLaunch checked(launch.anchor, launch.allowed, launch.marker_valid);
    checked.observed_stages = launch.observed_stages;
    checked.mode = launch.mode;
    checked.current_identity = launch.current_identity;
    checked.current_stage = launch.current_stage;
    checked.current_valid = launch.current_valid;
    checked.launcher_identity = launch.launcher_identity;
    checked.launcher_valid = launch.launcher_valid;
    return observe_direct(checked, current, reason);
}

const char* launch_stage_name(LaunchStage stage) {
    switch (stage) {
        case LaunchStage::Sudo:
            return "sudo";
        case LaunchStage::Nsenter:
            return "nsenter";
        case LaunchStage::Launcher:
            return "launcher";
    }
    return "unknown";
}

const char* launch_mode_name(LaunchMode mode) {
    switch (mode) {
        case LaunchMode::Pending:
            return "Pending";
        case LaunchMode::ExecChain:
            return "ExecChain";
        case LaunchMode::SudoWrapper:
            return "SudoWrapper";
    }
    return "Unknown";
}

std::string direct_launch_diagnostic(const DirectLaunch& launch) {
    std::ostringstream out;
    out << "anchor{pid=" << launch.anchor.pid << ",start=" << launch.anchor.start
        << ",pgid=" << launch.anchor.pgid << ",uid=" << launch.anchor.caller_uid
        << ",gid=" << launch.anchor.caller_gid << ",host_netns=" << launch.anchor.host_netns
        << ",marker=" << (launch.marker_valid ? "exact" : "invalid")
        << "} mode=" << launch_mode_name(launch.mode) << " observed=[";
    for (size_t i = 0; i != launch.observed_stages.size(); ++i) {
        if (i != 0) out << ',';
        out << launch_stage_name(launch.observed_stages[i]);
    }
    out << ']';
    if (launch.current_valid)
        out << " current{stage=" << launch_stage_name(launch.current_stage)
            << ",pid=" << launch.current_identity.pid << ",start=" << launch.current_identity.start
            << ",ppid=" << launch.current_identity.ppid << ",pgid=" << launch.current_identity.pgid
            << ",uid=" << launch.current_identity.uid << ",gid=" << launch.current_identity.gid
            << ",netns=" << launch.current_identity.netns
            << ",exe=" << launch.current_identity.exe_dev << ':' << launch.current_identity.exe_ino
            << ",argv_bytes=" << launch.current_identity.cmdline.size() << '}';
    if (launch.launcher_valid)
        out << " launcher{pid=" << launch.launcher_identity.pid
            << ",start=" << launch.launcher_identity.start
            << ",ppid=" << launch.launcher_identity.ppid
            << ",pgid=" << launch.launcher_identity.pgid << '}';
    if (!launch.reason.empty()) out << " reason=" << launch.reason;
    return out.str();
}

}  // namespace rut::test::fixture_direct_launch
