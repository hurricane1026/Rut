#include "fixture_direct_launch.h"
#include <iostream>
#include <string>
#include <type_traits>
#include <vector>

namespace {
using namespace rut::test::fixture_direct_launch;
using namespace std::string_literals;

constexpr pid_t kDirectPid = 4100;
constexpr pid_t kLaunchPgid = kDirectPid;
constexpr uid_t kCallerUid = 1000;
constexpr gid_t kCallerGid = 1001;
constexpr ino_t kHostNetns = 7001;
constexpr ino_t kHolderNetns = 7002;
static_assert(std::is_const_v<decltype(DirectLaunch::anchor)>);
static_assert(std::is_const_v<decltype(DirectLaunch::allowed)>);

DirectLaunch make_launch(bool marker = true) {
    DirectLaunchAnchor anchor{};
    anchor.pid = kDirectPid;
    anchor.start = 9001;
    anchor.pgid = kLaunchPgid;
    anchor.caller_uid = kCallerUid;
    anchor.caller_gid = kCallerGid;
    anchor.host_netns = kHostNetns;
    AllowedStages allowed{{11, 12, "sudo\0-n\0--\0"s},
                          {21, 22, "nsenter\0--net=/proc/99/ns/net\0--\0launcher\0"s},
                          {31, 32, "launcher\0--fixture-broker-launcher\0"s},
                          kHolderNetns};
    return DirectLaunch(anchor, allowed, marker);
}

ProcIdentity identity(LaunchStage stage, pid_t pid = kDirectPid) {
    const DirectLaunch launch = make_launch();
    const StageDescriptor* descriptor = &launch.allowed.sudo_stage;
    uid_t uid = kCallerUid;
    gid_t gid = kCallerGid;
    ino_t netns = kHostNetns;
    if (stage == LaunchStage::Nsenter) {
        descriptor = &launch.allowed.nsenter_stage;
        uid = 0;
        gid = 0;
    } else if (stage == LaunchStage::Launcher) {
        descriptor = &launch.allowed.launcher_stage;
        uid = 0;
        gid = 0;
        netns = kHolderNetns;
    }
    ProcIdentity result;
    result.pid = pid;
    result.ppid = pid == kDirectPid ? 4000 : kDirectPid;
    result.start = pid == kDirectPid ? 9001 : static_cast<std::uint64_t>(9001 + pid);
    result.pgid = kLaunchPgid;
    result.uid = uid;
    result.gid = gid;
    result.netns = netns;
    result.exe_dev = descriptor->exe_dev;
    result.exe_ino = descriptor->exe_ino;
    result.cmdline = descriptor->argv;
    return result;
}

bool expect(bool condition, const char* name, std::string& error) {
    if (condition) return true;
    error = name;
    return false;
}

bool run_checks(std::string& error) {
    std::string reason;
    DirectLaunch full = make_launch();
    ProcIdentity sudo = identity(LaunchStage::Sudo);
    ProcIdentity nsenter_host = identity(LaunchStage::Nsenter);
    ProcIdentity nsenter_holder = nsenter_host;
    nsenter_holder.netns = kHolderNetns;
    ProcIdentity launcher_direct = identity(LaunchStage::Launcher);
    if (!expect(observe_direct(full, sudo, reason) && observe_direct(full, nsenter_host, reason) &&
                    observe_direct(full, nsenter_holder, reason) &&
                    validate_launcher_ancestry(full, launcher_direct, {}, reason) &&
                    full.mode == LaunchMode::ExecChain && full.observed_stages.size() == 3,
                "full exact exec-chain sequence",
                error))
        return false;

    DirectLaunch launcher_only = make_launch();
    if (!expect(validate_launcher_ancestry(launcher_only, launcher_direct, {}, reason),
                "marker-anchored launcher-only skip",
                error))
        return false;
    DirectLaunch missing_marker = make_launch(false);
    if (!expect(!validate_launcher_ancestry(missing_marker, launcher_direct, {}, reason),
                "missing marker rejection",
                error))
        return false;
    auto changed_marker = kLaunchMarker;
    changed_marker[3] ^= 1;
    if (!expect(launch_marker_matches(kLaunchMarker.data(), kLaunchMarker.size()) &&
                    !launch_marker_matches(changed_marker.data(), changed_marker.size()) &&
                    !launch_marker_matches(kLaunchMarker.data(), kLaunchMarker.size() - 1),
                "exact marker matcher",
                error))
        return false;

    DirectLaunch skipped = make_launch();
    if (!expect(observe_direct(skipped, nsenter_host, reason) &&
                    observe_direct(skipped, launcher_direct, reason),
                "exact skipped sudo stage",
                error))
        return false;
    DirectLaunch sudo_to_launcher = make_launch();
    if (!expect(observe_direct(sudo_to_launcher, sudo, reason) &&
                    observe_direct(sudo_to_launcher, launcher_direct, reason),
                "exact skipped nsenter stage",
                error))
        return false;

    DirectLaunch wrapper = make_launch();
    ProcIdentity wrapper_sudo = sudo;
    wrapper_sudo.uid = 0;
    wrapper_sudo.gid = 0;
    ProcIdentity intermediary = identity(LaunchStage::Nsenter, 4200);
    intermediary.ppid = kDirectPid;
    ProcIdentity wrapper_launcher = identity(LaunchStage::Launcher, 4300);
    wrapper_launcher.ppid = intermediary.pid;
    if (!expect(observe_direct(wrapper, wrapper_sudo, reason) &&
                    validate_launcher_ancestry(
                        wrapper, wrapper_launcher, {intermediary, wrapper_sudo}, reason) &&
                    wrapper.mode == LaunchMode::SudoWrapper && wrapper.launcher_valid,
                "exact sudo-wrapper ancestry",
                error))
        return false;
    DirectLaunch wrapper_skip = make_launch();
    ProcIdentity adjacent_launcher = wrapper_launcher;
    adjacent_launcher.ppid = kDirectPid;
    if (!expect(validate_launcher_ancestry(wrapper_skip, adjacent_launcher, {wrapper_sudo}, reason),
                "exact sudo-wrapper skipped nsenter",
                error))
        return false;

    DirectLaunch sudo_elevation = make_launch();
    ProcIdentity root_sudo = sudo;
    root_sudo.uid = 0;
    root_sudo.gid = 0;
    ProcIdentity mixed_sudo = root_sudo;
    mixed_sudo.gid = kCallerGid;
    DirectLaunch mixed_credentials = make_launch();
    if (!expect(observe_direct(sudo_elevation, sudo, reason) &&
                    observe_direct(sudo_elevation, root_sudo, reason) &&
                    !observe_direct(sudo_elevation, sudo, reason),
                "monotonic sudo caller-to-root transition",
                error) ||
        !expect(!observe_direct(mixed_credentials, mixed_sudo, reason),
                "mixed sudo credential rejection",
                error))
        return false;

    for (const char* mutation : {"pid", "start", "pgid", "argv", "exe", "uid", "netns"}) {
        DirectLaunch changed = make_launch();
        ProcIdentity value = sudo;
        if (std::string(mutation) == "pid") ++value.pid;
        if (std::string(mutation) == "start") ++value.start;
        if (std::string(mutation) == "pgid") value.pgid = 1;
        if (std::string(mutation) == "argv") value.cmdline += "altered";
        if (std::string(mutation) == "exe") ++value.exe_ino;
        if (std::string(mutation) == "uid") ++value.uid;
        if (std::string(mutation) == "netns") value.netns = kHolderNetns;
        if (!expect(!observe_direct(changed, value, reason), mutation, error)) return false;
    }

    DirectLaunch reordered = make_launch();
    if (!expect(observe_direct(reordered, launcher_direct, reason) &&
                    !observe_direct(reordered, nsenter_host, reason),
                "direct stage reordering",
                error))
        return false;
    DirectLaunch netns_regression = make_launch();
    if (!expect(observe_direct(netns_regression, nsenter_holder, reason) &&
                    !observe_direct(netns_regression, nsenter_host, reason),
                "nsenter netns regression",
                error))
        return false;
    DirectLaunch unknown_direct = make_launch();
    ProcIdentity unknown_stage = sudo;
    unknown_stage.exe_dev = 99;
    unknown_stage.exe_ino = 100;
    unknown_stage.cmdline = "unknown\0stage\0"s;
    if (!expect(
            !observe_direct(unknown_direct, unknown_stage, reason), "unknown direct stage", error))
        return false;
    DirectLaunch transient_unknown = make_launch();
    if (!expect(!observe_direct(transient_unknown, unknown_stage, reason) &&
                    observe_direct(transient_unknown, sudo, reason),
                "transient unknown stage followed by exact stage",
                error))
        return false;
    DirectLaunch bad_nsenter_credentials = make_launch();
    ProcIdentity caller_nsenter = nsenter_host;
    caller_nsenter.uid = kCallerUid;
    caller_nsenter.gid = kCallerGid;
    DirectLaunch bad_launcher_netns = make_launch();
    ProcIdentity host_launcher = launcher_direct;
    host_launcher.netns = kHostNetns;
    if (!expect(!observe_direct(bad_nsenter_credentials, caller_nsenter, reason) &&
                    !observe_direct(bad_launcher_netns, host_launcher, reason),
                "root/holder stage transition restrictions",
                error))
        return false;

    for (const char* stage_name :
         {"nsenter-argv", "nsenter-exe", "launcher-argv", "launcher-exe"}) {
        DirectLaunch changed = make_launch();
        const bool launcher_mutation = std::string(stage_name).rfind("launcher", 0) == 0;
        ProcIdentity value = launcher_mutation ? launcher_direct : nsenter_host;
        if (std::string(stage_name).find("argv") != std::string::npos)
            value.cmdline += "altered";
        else
            ++value.exe_ino;
        if (!expect(!observe_direct(changed, value, reason), stage_name, error)) return false;
    }

    DirectLaunch bad_ancestry = make_launch();
    ProcIdentity unknown = intermediary;
    ++unknown.exe_dev;
    if (!expect(!validate_launcher_ancestry(
                    bad_ancestry, wrapper_launcher, {unknown, wrapper_sudo}, reason),
                "unknown intermediary",
                error))
        return false;
    DirectLaunch altered_ancestry_argv = make_launch();
    ProcIdentity altered_intermediary_argv = intermediary;
    altered_intermediary_argv.cmdline += "altered";
    if (!expect(!validate_launcher_ancestry(altered_ancestry_argv,
                                            wrapper_launcher,
                                            {altered_intermediary_argv, wrapper_sudo},
                                            reason),
                "altered intermediary argv",
                error))
        return false;
    DirectLaunch broken_link = make_launch();
    wrapper_launcher.ppid++;
    if (!expect(!validate_launcher_ancestry(
                    broken_link, wrapper_launcher, {intermediary, wrapper_sudo}, reason),
                "broken ancestry link",
                error))
        return false;
    DirectLaunch missing_ancestry = make_launch();
    if (!expect(!validate_launcher_ancestry(missing_ancestry, wrapper_launcher, {}, reason),
                "missing wrapper ancestry",
                error))
        return false;
    DirectLaunch bad_intermediary_pgid = make_launch();
    ProcIdentity unsafe_intermediary = intermediary;
    unsafe_intermediary.pgid = 1;
    ProcIdentity launcher_over_unsafe = identity(LaunchStage::Launcher, 4300);
    launcher_over_unsafe.ppid = unsafe_intermediary.pid;
    if (!expect(!validate_launcher_ancestry(bad_intermediary_pgid,
                                            launcher_over_unsafe,
                                            {unsafe_intermediary, wrapper_sudo},
                                            reason),
                "unsafe intermediary PGID",
                error))
        return false;
    DirectLaunch bad_launcher_pgid = make_launch();
    ProcIdentity unsafe_launcher = identity(LaunchStage::Launcher, 4300);
    unsafe_launcher.pgid = 1;
    if (!expect(
            !validate_launcher_ancestry(bad_launcher_pgid, unsafe_launcher, {wrapper_sudo}, reason),
            "unsafe launcher PGID",
            error))
        return false;
    DirectLaunch stale_ancestry = make_launch();
    ProcIdentity stale_direct = wrapper_sudo;
    ++stale_direct.start;
    if (!expect(
            !validate_launcher_ancestry(stale_ancestry, adjacent_launcher, {stale_direct}, reason),
            "stale direct ancestry anchor",
            error))
        return false;
    DirectLaunch reordered_ancestry = make_launch();
    ProcIdentity later_sudo = identity(LaunchStage::Sudo, 4250);
    later_sudo.ppid = intermediary.pid;
    ProcIdentity reordered_launcher = identity(LaunchStage::Launcher, 4300);
    reordered_launcher.ppid = later_sudo.pid;
    if (!expect(!validate_launcher_ancestry(reordered_ancestry,
                                            reordered_launcher,
                                            {later_sudo, intermediary, wrapper_sudo},
                                            reason),
                "reordered wrapper stages",
                error))
        return false;
    DirectLaunch credential_regression = make_launch();
    ProcIdentity caller_sudo_child = identity(LaunchStage::Sudo, 4250);
    caller_sudo_child.ppid = kDirectPid;
    ProcIdentity launcher_over_caller_sudo = identity(LaunchStage::Launcher, 4300);
    launcher_over_caller_sudo.ppid = caller_sudo_child.pid;
    if (!expect(!validate_launcher_ancestry(credential_regression,
                                            launcher_over_caller_sudo,
                                            {caller_sudo_child, wrapper_sudo},
                                            reason),
                "wrapper sudo root-to-caller regression",
                error))
        return false;
    DirectLaunch ancestry_netns_regression = make_launch();
    ProcIdentity holder_nsenter = intermediary;
    holder_nsenter.netns = kHolderNetns;
    ProcIdentity host_nsenter_child = identity(LaunchStage::Nsenter, 4250);
    host_nsenter_child.ppid = holder_nsenter.pid;
    ProcIdentity launcher_over_regression = identity(LaunchStage::Launcher, 4300);
    launcher_over_regression.ppid = host_nsenter_child.pid;
    if (!expect(!validate_launcher_ancestry(ancestry_netns_regression,
                                            launcher_over_regression,
                                            {host_nsenter_child, holder_nsenter, wrapper_sudo},
                                            reason),
                "wrapper nsenter holder-to-host regression",
                error))
        return false;
    DirectLaunch oversized = make_launch();
    std::vector<ProcIdentity> long_ancestry(kMaxLaunchAncestry + 1, wrapper_sudo);
    if (!expect(!validate_launcher_ancestry(oversized, adjacent_launcher, long_ancestry, reason),
                "bounded wrapper ancestry",
                error))
        return false;

    DirectLaunch fixed_exec_chain = make_launch();
    if (!expect(observe_direct(fixed_exec_chain, nsenter_host, reason) &&
                    !validate_launcher_ancestry(
                        fixed_exec_chain, adjacent_launcher, {wrapper_sudo}, reason),
                "exec-chain cannot become sudo-wrapper",
                error))
        return false;
    DirectLaunch fixed_wrapper = make_launch();
    if (!expect(
            validate_launcher_ancestry(fixed_wrapper, adjacent_launcher, {wrapper_sudo}, reason) &&
                !observe_direct(fixed_wrapper, nsenter_host, reason),
            "sudo-wrapper direct must remain exact sudo",
            error))
        return false;

    DirectLaunch signal = make_launch();
    if (!expect(observe_direct(signal, sudo, reason) &&
                    current_allows_group_signal(signal, sudo, reason),
                "exact signal revalidation",
                error))
        return false;
    ProcIdentity stale = sudo;
    ++stale.start;
    ProcIdentity unsafe = sudo;
    unsafe.pgid = 1;
    ProcIdentity altered = sudo;
    altered.cmdline += "x";
    if (!expect(!current_allows_group_signal(signal, stale, reason) &&
                    !current_allows_group_signal(signal, unsafe, reason) &&
                    !current_allows_group_signal(signal, altered, reason),
                "stale/unsafe/unknown signal rejection",
                error))
        return false;
    DirectLaunchAnchor unsafe_anchor = signal.anchor;
    unsafe_anchor.pgid = unsafe_anchor.pid + 1;
    DirectLaunch unsafe_anchor_launch(unsafe_anchor, signal.allowed);
    if (!expect(!observe_direct(unsafe_anchor_launch, sudo, reason),
                "unsafe immutable anchor rejection",
                error))
        return false;
    signal.reason = "synthetic final reason";
    const std::string diagnostic = direct_launch_diagnostic(signal);
    if (!expect(diagnostic.find("anchor{pid=4100,start=9001,pgid=4100") != std::string::npos &&
                    diagnostic.find("mode=Pending observed=[sudo]") != std::string::npos &&
                    diagnostic.find("current{stage=sudo") != std::string::npos &&
                    diagnostic.find("reason=synthetic final reason") != std::string::npos,
                "detailed launch diagnostic",
                error))
        return false;
    return true;
}

}  // namespace

int main() {
    std::string error;
    if (!run_checks(error)) {
        std::cerr << "FAIL [#358 direct-launch state]: " << error << "\n";
        return 1;
    }
    std::cerr << "PASS: #358 exact privileged direct-launch state machine\n";
    return 0;
}
