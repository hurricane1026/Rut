#pragma once

#include "fixture_worker_protocol.h"
#include <array>
#include <string>
#include <vector>

namespace rut::test::fixture_direct_launch {

using fixture_worker_protocol::ProcIdentity;

enum class LaunchStage { Sudo, Nsenter, Launcher };
enum class LaunchMode { Pending, ExecChain, SudoWrapper };

struct StageDescriptor {
    dev_t exe_dev = 0;
    ino_t exe_ino = 0;
    std::string argv;
};

struct AllowedStages {
    StageDescriptor sudo_stage;
    StageDescriptor nsenter_stage;
    StageDescriptor launcher_stage;
    ino_t holder_netns = 0;
};

struct DirectLaunchAnchor {
    pid_t pid = -1;
    std::uint64_t start = 0;
    pid_t pgid = -1;
    uid_t caller_uid = static_cast<uid_t>(-1);
    gid_t caller_gid = static_cast<gid_t>(-1);
    ino_t host_netns = 0;
    pid_t sid = -1;
    dev_t exe_dev = 0;
    ino_t exe_ino = 0;
    std::string exe;
    std::string cmdline;
};

inline constexpr std::array<unsigned char, 8> kLaunchMarker{
    0x52, 0x55, 0x54, 0x33, 0x35, 0x38, 0xa3, 0xb1};
inline constexpr size_t kMaxLaunchAncestry = 8;

struct DirectLaunch {
    const DirectLaunchAnchor anchor;
    const AllowedStages allowed;
    const bool marker_valid;
    std::vector<LaunchStage> observed_stages;
    LaunchMode mode = LaunchMode::Pending;
    ProcIdentity current_identity;
    LaunchStage current_stage = LaunchStage::Sudo;
    bool current_valid = false;
    ProcIdentity launcher_identity;
    bool launcher_valid = false;
    std::string reason;
    int status = 0;
    bool reaped = false;

    DirectLaunch(DirectLaunchAnchor anchor_value,
                 AllowedStages allowed_value,
                 bool marker_was_valid = true);
};

bool launch_marker_matches(const unsigned char* marker, size_t size);
bool observe_direct(DirectLaunch& launch, const ProcIdentity& identity, std::string& reason);
bool validate_launcher_ancestry(DirectLaunch& launch,
                                const ProcIdentity& launcher,
                                const std::vector<ProcIdentity>& ancestry,
                                std::string& reason);
bool current_allows_group_signal(const DirectLaunch& launch,
                                 const ProcIdentity& current,
                                 std::string& reason);
const char* launch_stage_name(LaunchStage stage);
const char* launch_mode_name(LaunchMode mode);
std::string direct_launch_diagnostic(const DirectLaunch& launch);

}  // namespace rut::test::fixture_direct_launch
