// #358 Stage 2a3b: authenticated sudo/nsenter broker lifecycle only.
// The listener-guard-reservation scenario lets only the secured ordinary Target
// own the non-listening AF_INET guard, exact public-RUT child, and bounded HTTP/
// refusal clients. The host parent retains read-only identity evidence only.

#include "fixture_ancestry_bundle.h"
#include "fixture_collision_release_evidence_protocol.h"
#include "fixture_collision_release_evidence_transport.h"
#include "fixture_collision_release_protocol.h"
#include "fixture_direct_launch.h"
#include "fixture_exact_tcp_reservation_lease.h"
#include "fixture_executable_lease.h"
#include "fixture_identity_bundle.h"
#include "fixture_ipv4_topology.h"
#include "fixture_private_directory_lease.h"
#include "fixture_privileged_ancestry.h"
#include "fixture_privileged_listener.h"
#include "fixture_public_rut_session_attempt.h"
#include "fixture_wildcard_source_lease.h"
#include "fixture_worker_protocol.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace rut::test::fixture_worker_protocol;
namespace identity_bundle = rut::test::fixture_identity_bundle;
namespace ancestry_bundle = rut::test::fixture_ancestry_bundle;
namespace privileged_ancestry = rut::test::fixture_privileged_ancestry;
namespace privileged_listener = rut::test::fixture_privileged_listener;
namespace collision_control = rut::test::fixture_collision_release_protocol;
namespace collision_evidence = rut::test::fixture_collision_release_evidence_protocol;
namespace evidence_transport = rut::test::fixture_collision_release_evidence_transport;
namespace exact_reservation = rut::test::fixture_exact_tcp_reservation_lease;
namespace executable_lease = rut::test::fixture_executable_lease;
namespace private_directory = rut::test::fixture_private_directory_lease;
namespace public_attempt = rut::test::fixture_public_rut_session_attempt;
namespace source_lease = rut::test::fixture_wildcard_source_lease;
using privileged_ancestry::parse_retained_anchor_stat;
using privileged_ancestry::parse_retained_anchor_status;
using privileged_ancestry::prove_retained_sudo_wrapper;
using privileged_ancestry::retained_pidfd_live;
using privileged_ancestry::RetainedAnchorEvidence;
using rut::test::fixture_direct_launch::AllowedStages;
using rut::test::fixture_direct_launch::current_allows_group_signal;
using rut::test::fixture_direct_launch::direct_launch_diagnostic;
using rut::test::fixture_direct_launch::DirectLaunch;
using rut::test::fixture_direct_launch::DirectLaunchAnchor;
using rut::test::fixture_direct_launch::kLaunchMarker;
using rut::test::fixture_direct_launch::kMaxLaunchAncestry;
using rut::test::fixture_direct_launch::launch_marker_matches;
using rut::test::fixture_direct_launch::LaunchStage;
using rut::test::fixture_direct_launch::observe_direct;
using rut::test::fixture_direct_launch::StageDescriptor;
using rut::test::fixture_direct_launch::validate_launcher_ancestry;
using rut::test::ipv4_topology::HeldTopologyProbePolicy;
using rut::test::ipv4_topology::HeldTopologySnapshot;

constexpr u16 kBrokerRootHello = 20;
constexpr u16 kCallerCredentials = 21;
constexpr u16 kBrokerDropped = 22;
constexpr u16 kLaunchTarget = 23;
constexpr u16 kTargetExited = 24;
constexpr u16 kBrokerExitEarly = 25;
constexpr u16 kSecurityTrace = 26;
constexpr u16 kIdentityBundleRequest = 27;
constexpr u16 kIdentityBundleAck = 28;
constexpr u16 kDroppedIdentityRequest = 29;
constexpr u16 kAncestryProbeHello = 30;
constexpr u16 kAncestryProbeRequest = 31;
constexpr u16 kAncestryProbeRelease = 32;
constexpr u16 kInitialAncestryRequest = 33;
constexpr u16 kFinalAncestryRequest = 34;
constexpr u16 kGuardReserve = 35;
constexpr u16 kGuardHeld = 36;
constexpr u16 kGuardRelease = 37;
constexpr u16 kGuardReleased = 38;
constexpr u16 kGuardFinish = 39;
constexpr u16 kGuardFinished = 40;
constexpr u16 kExactRutRun = 41;
constexpr u16 kExactRutWitness = 42;
constexpr u16 kExactRutCleanup = 43;
constexpr u16 kExactRutCleaned = 44;
constexpr u16 kExactRutFailure = 45;
constexpr u16 kExactEscrowSettled = 46;
// Values 47--50 belong to the already reviewed listener protocol namespace and
// remain reserved.  Wildcard-attempt Stage 1 deliberately starts after it.
constexpr u16 kWildcardAttemptCommand = 51;
constexpr u16 kWildcardAttemptPhase = 52;
constexpr u16 kWildcardAttemptDecision = 53;
constexpr u16 kWildcardAttemptSettlement = 54;
constexpr int kBrokerDeadlineMs = 5000;
constexpr int kListenerDeadlineMs = 15000;
constexpr int kCredentialFd = 198;
constexpr int kExactCustodyFd = 199;
constexpr int kLauncherBundleFdBase = 220;
static_assert(kLauncherBundleFdBase > kExactCustodyFd && kExactCustodyFd != kCredentialFd);

struct EndpointIdentity {
    dev_t directory_dev = 0;
    ino_t directory_ino = 0;
    dev_t socket_dev = 0;
    ino_t socket_ino = 0;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
};

struct ParentEndpoint {
    std::string directory;
    std::string socket;
    int listener = -1;
    EndpointIdentity identity;

    bool cleanup(std::string& error);
    ~ParentEndpoint();
};

struct MutationDiagnostic {
    bool success = true;
    std::string failed_label;
    std::string detail;
};

static bool endpoint_matches(const ParentEndpoint& endpoint, const EndpointIdentity& expected);
static bool endpoint_unchanged(const ParentEndpoint& endpoint);
static bool endpoint_replacement_self_check(std::string& error);
static bool bounded_wait_and_signal_self_check(std::string& error);
static bool group_lease_self_check(std::string& error);
static bool lease_loss_owner_cascade_self_check(std::string& error);
static bool launcher_error_order_self_check(std::string& error);
static bool prelaunch_close_first_self_check(std::string& error);
static bool identity_bundle_integration_self_check(std::string& error);
static bool retained_anchor_self_check(std::string& error);
static bool safe_signal_target(const Report& report,
                               const Peer& peer,
                               const ProcIdentity& expected,
                               int signal_number);
static bool target_socket_inode(pid_t target, int fd, u64 expected_inode);
static bool read_process_tcp_table(pid_t pid, privileged_listener::ProcTcpTable& table);
static bool process_socket_inodes(pid_t pid, std::vector<u64>& inodes);
static bool pidfd_link_matches(pid_t owner, int fd);
static bool exact_pidfd_binding(int fd, pid_t expected_pid);
static bool exact_log_ready(const std::string& log,
                            const std::string& source_path,
                            u16 port,
                            u64& backend);
static bool parse_canonical_ipv4(const std::string& text, u32& ipv4);
static bool exact_listener_absent(const privileged_listener::ProcTcpTable& table,
                                  const privileged_listener::ListenerPlan& plan,
                                  u64 listener_inode);
static bool write_pipe_exact(int fd, const unsigned char* data, size_t size, int timeout_ms);
static bool stable_proc_identity(pid_t pid, ProcIdentity& identity);
static bool child_exited_wnowait(pid_t pid);
enum class GroupScanResult { Exact, Unreadable };
static GroupScanResult scan_group_stat(pid_t pgid,
                                       int& member_count,
                                       bool& live_member,
                                       pid_t permitted_zombie,
                                       pid_t& sole_member,
                                       std::uint64_t& sole_start);
static GroupScanResult group_member_count(pid_t pgid, int& count);
struct GroupLease;
static bool cleanup_group_lease(GroupLease& lease,
                                DirectLaunch& launch,
                                bool authority,
                                std::string& error);
static bool has_group_authority(const DirectLaunch& launch, const GroupLease& lease);
static bool arm_parent_death(pid_t expected_parent);
enum class ExactLiveness { Live, ExitedOrReused, Unknown };
static ExactLiveness observe_exact_liveness(const ProcIdentity& expected);
static bool exact_liveness_self_check(std::string& error);
static int remaining_deadline_ms(std::chrono::steady_clock::time_point deadline);
static std::chrono::steady_clock::time_point new_exact_cleanup_deadline();

static bool listener_scenario_name(const char* scenario) {
    return strcmp(scenario, "listener-guard-reservation") == 0 ||
           strcmp(scenario, "listener-cleanup-observation-failure") == 0 ||
           strcmp(scenario, "listener-canonical-collision-release") == 0;
}

static bool canonical_collision_scenario(const char* scenario) {
    return strcmp(scenario, "listener-canonical-collision-release") == 0;
}

static bool listener_failure_integration(const char* scenario) {
    return strcmp(scenario, "listener-cleanup-observation-failure") == 0;
}

static_assert(kListenerDeadlineMs <= std::numeric_limits<int>::max() / 4);
constexpr int kListenerFailureLauncherWaitMs = kListenerDeadlineMs * 4;
constexpr int kListenerFailureFrame45WaitMs = kListenerDeadlineMs * 2;
constexpr int kWildcardAttemptAggregateWaitMs = kListenerDeadlineMs * 6;

static int launcher_broker_wait_ms(const char* scenario) {
    if (canonical_collision_scenario(scenario)) return kWildcardAttemptAggregateWaitMs;
    return listener_failure_integration(scenario) ? kListenerFailureLauncherWaitMs
                                                  : kBrokerDeadlineMs;
}

static int cleanup_response_wait_ms(const char* scenario) {
    return listener_failure_integration(scenario) ? kListenerFailureFrame45WaitMs
                                                  : kListenerDeadlineMs;
}

static int scenario_aggregate_wait_ms(const char* scenario) {
    if (strcmp(scenario, "listener-wildcard-attempt") == 0 ||
        canonical_collision_scenario(scenario))
        return kWildcardAttemptAggregateWaitMs;
    if (listener_failure_integration(scenario)) return kListenerFailureLauncherWaitMs;
    if (listener_scenario_name(scenario)) return kListenerDeadlineMs;
    return kBrokerDeadlineMs;
}

static bool listener_failure_bound_self_check(std::string& error) {
    if (launcher_broker_wait_ms("listener-cleanup-observation-failure") !=
            kListenerDeadlineMs * 4 ||
        cleanup_response_wait_ms("listener-cleanup-observation-failure") !=
            kListenerDeadlineMs * 2 ||
        launcher_broker_wait_ms("listener-guard-reservation") != kBrokerDeadlineMs ||
        cleanup_response_wait_ms("listener-guard-reservation") != kListenerDeadlineMs ||
        launcher_broker_wait_ms("normal") != kBrokerDeadlineMs ||
        cleanup_response_wait_ms("normal") != kListenerDeadlineMs ||
        scenario_aggregate_wait_ms("normal") != kBrokerDeadlineMs ||
        scenario_aggregate_wait_ms("listener-guard-reservation") != kListenerDeadlineMs ||
        scenario_aggregate_wait_ms("listener-cleanup-observation-failure") !=
            kListenerFailureLauncherWaitMs ||
        scenario_aggregate_wait_ms("listener-wildcard-attempt") !=
            kWildcardAttemptAggregateWaitMs ||
        scenario_aggregate_wait_ms("listener-canonical-collision-release") !=
            kWildcardAttemptAggregateWaitMs ||
        kBrokerDeadlineMs != 5000 || kListenerDeadlineMs != 15000 ||
        kListenerFailureFrame45WaitMs != 30000 || kListenerFailureLauncherWaitMs != 60000 ||
        kWildcardAttemptAggregateWaitMs != 90000) {
        error = "listener failure extended deadline selection failed";
        return false;
    }
    return true;
}

static bool exact_request(const Frame& request, u16 expected_type, const Token& token) {
    return request.type == expected_type && token_equal(request.token, token) &&
           request.payload.empty();
}

static bool receive_exact_request_until(int fd,
                                        u16 expected_type,
                                        const Token& token,
                                        std::chrono::steady_clock::time_point deadline) {
    Frame request;
    return receive_frame_until(fd, request, deadline) &&
           exact_request(request, expected_type, token);
}

static bool validate_dropped_identity_binding(
    const identity_bundle::DroppedIdentityEvidence& evidence,
    const Report& report,
    const Peer& peer,
    const Peer& root_peer,
    const ProcIdentity& root_proc,
    const HeldTopologySnapshot& topology,
    const std::string& executable,
    const std::string& dropped_argv,
    uid_t caller_uid,
    gid_t caller_gid,
    bool root_control_ok,
    bool endpoint_ok,
    std::string& error);
static MutationDiagnostic dropped_identity_mutation_checks(
    const identity_bundle::DroppedIdentityEvidence& evidence,
    const Report& report,
    const Peer& peer,
    const Peer& root_peer,
    const ProcIdentity& root_proc,
    const HeldTopologySnapshot& topology,
    const std::string& executable,
    const std::string& dropped_argv,
    uid_t caller_uid,
    gid_t caller_gid);

static void close_launcher_bundle_handoff() {
    for (size_t i = 0; i != identity_bundle::kFdsPerRole; ++i)
        close(kLauncherBundleFdBase + static_cast<int>(i));
}

static bool install_launcher_bundle_handoff(const identity_bundle::RoleBundle& launcher_role) {
    for (size_t i = 0; i != identity_bundle::kFdsPerRole; ++i) {
        const int destination = kLauncherBundleFdBase + static_cast<int>(i);
        errno = 0;
        const int flags = fcntl(destination, F_GETFD);
        if (flags >= 0) {
            if (std::find(launcher_role.fds.begin(), launcher_role.fds.end(), destination) ==
                launcher_role.fds.end())
                return false;
        } else if (errno != EBADF) {
            return false;
        }
    }
    std::array<int, identity_bundle::kFdsPerRole> temporary{};
    temporary.fill(-1);
    for (size_t i = 0; i != temporary.size(); ++i) {
        temporary[i] =
            fcntl(launcher_role.fds[i],
                  F_DUPFD_CLOEXEC,
                  kLauncherBundleFdBase + static_cast<int>(identity_bundle::kFdsPerRole));
        if (temporary[i] < 0) {
            for (int fd : temporary)
                if (fd >= 0) close(fd);
            return false;
        }
    }
    bool installed = true;
    for (size_t i = 0; i != temporary.size(); ++i) {
        const int destination = kLauncherBundleFdBase + static_cast<int>(i);
        if (dup3(temporary[i], destination, 0) != destination) installed = false;
    }
    for (int fd : temporary) close(fd);
    if (!installed) close_launcher_bundle_handoff();
    return installed;
}

static bool take_launcher_bundle_handoff(identity_bundle::RoleBundle& launcher_role,
                                         std::string& error) {
    std::array<int, identity_bundle::kFdsPerRole> inherited{};
    inherited.fill(-1);
    for (size_t i = 0; i != inherited.size(); ++i) {
        const int fd = kLauncherBundleFdBase + static_cast<int>(i);
        const int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
            for (int owned : inherited)
                if (owned >= 0) close(owned);
            for (size_t rest = i; rest != inherited.size(); ++rest)
                close(kLauncherBundleFdBase + static_cast<int>(rest));
            error = "launcher identity handoff slot was missing or not restorable CLOEXEC";
            return false;
        }
        inherited[i] = fd;
    }
    return identity_bundle::adopt_role(
        identity_bundle::Role::Launcher, inherited, launcher_role, error);
}

static bool control_lease_lost(int fd) {
    if (fd < 0) return false;
    pollfd descriptor{fd, static_cast<short>(POLLIN | POLLHUP | POLLERR), 0};
    const int polled = poll(&descriptor, 1, 0);
    if (polled < 0) return errno != EINTR;
    if (polled == 0) return false;
    unsigned char byte = 0;
    const ssize_t received = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    if (received > 0) return false;
    if (received == 0) return true;
    return errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR;
}

static bool wait_control_eof(int fd, std::chrono::steady_clock::time_point deadline) {
    while (fd >= 0 && std::chrono::steady_clock::now() < deadline) {
        pollfd descriptor{fd, static_cast<short>(POLLIN | POLLHUP | POLLERR), 0};
        const int timeout = remaining_deadline_ms(deadline);
        int polled;
        do {
            polled = poll(&descriptor, 1, timeout);
        } while (polled < 0 && errno == EINTR);
        if (polled <= 0 || (descriptor.revents & POLLNVAL) != 0) return false;
        unsigned char byte = 0u;
        const ssize_t received = recv(fd, &byte, 1u, MSG_PEEK | MSG_DONTWAIT);
        if (received == 0) return true;
        if (received > 0) return false;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
    }
    return false;
}

static bool arm_parent_death(pid_t expected_parent) {
    if (expected_parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) return false;
    int configured_signal = 0;
    return prctl(PR_GET_PDEATHSIG, &configured_signal) == 0 && configured_signal == SIGKILL &&
           getppid() == expected_parent;
}

struct ExactProcStat {
    pid_t pid = -1;
    char state = '\0';
    std::uint64_t start = 0;
};

static bool parse_exact_proc_stat(const std::string& text, ExactProcStat& result) {
    result = ExactProcStat{};
    const size_t first_space = text.find(' ');
    const size_t close_comm = text.rfind(')');
    if (first_space == std::string::npos || close_comm == std::string::npos ||
        close_comm + 2 >= text.size() || first_space >= close_comm)
        return false;
    std::istringstream pid_text(text.substr(0, first_space));
    long long pid_value = 0;
    if (!(pid_text >> pid_value) || pid_value <= 0 ||
        pid_value > std::numeric_limits<pid_t>::max() ||
        pid_text.peek() != std::char_traits<char>::eof())
        return false;
    std::istringstream fields(text.substr(close_comm + 2));
    char state = '\0';
    long long ignored = 0;
    if (!(fields >> state >> ignored >> ignored >> ignored)) return false;
    for (int field = 7; field <= 21; ++field)
        if (!(fields >> ignored)) return false;
    unsigned long long start = 0;
    if (!(fields >> start) || start == 0) return false;
    result.pid = static_cast<pid_t>(pid_value);
    result.state = state;
    result.start = static_cast<std::uint64_t>(start);
    return true;
}

static bool exact_proc_stat(const ProcIdentity& expected, ExactProcStat& result) {
    if (expected.pid <= 1 || expected.start == 0) return false;
    std::string text;
    errno = 0;
    if (!read_file("/proc/" + std::to_string(expected.pid) + "/stat", text, 8192)) return false;
    if (!parse_exact_proc_stat(text, result)) return false;
    return result.pid == expected.pid;
}

static ExactLiveness observe_exact_liveness(const ProcIdentity& expected) {
    if (expected.pid <= 1 || expected.start == 0) return ExactLiveness::Unknown;
    ExactProcStat first;
    ExactProcStat second;
    errno = 0;
    if (!exact_proc_stat(expected, first)) {
        return errno == ENOENT || errno == ESRCH ? ExactLiveness::ExitedOrReused
                                                 : ExactLiveness::Unknown;
    }
    if (first.start != expected.start) return ExactLiveness::ExitedOrReused;
    errno = 0;
    if (!exact_proc_stat(expected, second)) {
        return errno == ENOENT || errno == ESRCH ? ExactLiveness::ExitedOrReused
                                                 : ExactLiveness::Unknown;
    }
    if (second.start != expected.start) return ExactLiveness::ExitedOrReused;
    if (second.start != first.start) return ExactLiveness::Unknown;
    switch (second.state) {
        case 'R':
        case 'S':
        case 'D':
        case 'T':
        case 't':
        case 'W':
        case 'K':
        case 'P':
        case 'I':
            return ExactLiveness::Live;
        case 'Z':
        case 'X':
        case 'x':
            return ExactLiveness::ExitedOrReused;
        default:
            return ExactLiveness::Unknown;
    }
}

static bool exact_pre_root_loss_causal_state(ExactLiveness root_liveness, short broker_events) {
    return root_liveness == ExactLiveness::Live && broker_events == 0;
}

static bool observe_quiet_broker_while_root_live(int broker_fd,
                                                 const ProcIdentity& root,
                                                 std::chrono::steady_clock::time_point deadline) {
    if (broker_fd < 0 || !exact_pre_root_loss_causal_state(observe_exact_liveness(root), 0))
        return false;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        pollfd descriptor{broker_fd, static_cast<short>(POLLIN | POLLHUP | POLLERR), 0};
        int polled;
        do {
            polled = poll(
                &descriptor, 1, static_cast<int>(std::min<std::int64_t>(10, remaining.count())));
        } while (polled < 0 && errno == EINTR);
        if (polled < 0 ||
            !exact_pre_root_loss_causal_state(observe_exact_liveness(root), descriptor.revents))
            return false;
    }
    return exact_pre_root_loss_causal_state(observe_exact_liveness(root), 0);
}

static bool exact_liveness_self_check(std::string& error) {
    if (!exact_pre_root_loss_causal_state(ExactLiveness::Live, 0) ||
        exact_pre_root_loss_causal_state(ExactLiveness::Unknown, 0) ||
        exact_pre_root_loss_causal_state(ExactLiveness::ExitedOrReused, 0) ||
        exact_pre_root_loss_causal_state(ExactLiveness::Live, POLLIN) ||
        exact_pre_root_loss_causal_state(ExactLiveness::Live, POLLHUP) ||
        exact_pre_root_loss_causal_state(ExactLiveness::Live, POLLERR) ||
        exact_pre_root_loss_causal_state(ExactLiveness::Live, POLLNVAL)) {
        error = "pre-Root-loss broker quiet/live causal decision failed";
        return false;
    }
    int arm_pipe[2] = {-1, -1};
    if (pipe2(arm_pipe, O_CLOEXEC) != 0) {
        error = "PDEATHSIG self-check pipe failed";
        return false;
    }
    const pid_t arm_child = fork();
    if (arm_child < 0) {
        close(arm_pipe[0]);
        close(arm_pipe[1]);
        error = "PDEATHSIG self-check fork failed";
        return false;
    }
    if (arm_child == 0) {
        close(arm_pipe[0]);
        const unsigned char result = arm_parent_death(getppid()) ? 1 : 0;
        (void)write(arm_pipe[1], &result, 1);
        close(arm_pipe[1]);
        _exit(result == 1 ? 0 : 1);
    }
    close(arm_pipe[1]);
    unsigned char arm_result = 0;
    const bool arm_ok = read_exact(arm_pipe[0], &arm_result, 1, kCleanupMs) && arm_result == 1;
    close(arm_pipe[0]);
    int arm_status = 0;
    bool arm_reaped = false;
    const auto arm_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < arm_deadline) {
        const pid_t waited = waitpid(arm_child, &arm_status, WNOHANG);
        if (waited == arm_child) {
            arm_reaped = true;
            break;
        }
        if (waited == 0) {
            (void)poll(nullptr, 0, 10);
            continue;
        }
        if (waited < 0 && errno == EINTR) continue;
        break;
    }

    const pid_t child = fork();
    if (child < 0) {
        error = "exact liveness self-check fork failed";
        return false;
    }
    if (child == 0) {
        for (;;) pause();
    }
    ProcIdentity expected;
    const bool identity_ok =
        read_proc(child, expected, false) && expected.pid == child && expected.start != 0;
    const bool live = identity_ok && observe_exact_liveness(expected) == ExactLiveness::Live;
    ProcIdentity wrong_start = expected;
    ++wrong_start.start;
    const bool wrong_start_gone =
        identity_ok && observe_exact_liveness(wrong_start) == ExactLiveness::ExitedOrReused;
    const bool killed = kill(child, SIGKILL) == 0;
    siginfo_t info{};
    bool wnowait_zombie = false;
    if (killed) {
        const auto zombie_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
        while (std::chrono::steady_clock::now() < zombie_deadline) {
            memset(&info, 0, sizeof(info));
            const int waited =
                waitid(P_PID, static_cast<id_t>(child), &info, WEXITED | WNOHANG | WNOWAIT);
            if (waited == 0 && info.si_pid == child) {
                wnowait_zombie = info.si_pid == child;
                break;
            }
            if (waited == 0) {
                (void)poll(nullptr, 0, 10);
                continue;
            }
            if (errno == EINTR) continue;
            break;
        }
    }
    const bool zombie_not_live = identity_ok && wnowait_zombie &&
                                 observe_exact_liveness(expected) == ExactLiveness::ExitedOrReused;
    int status = 0;
    bool reaped = false;
    const auto reap_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < reap_deadline) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            reaped = true;
            break;
        }
        if (waited == 0) {
            (void)poll(nullptr, 0, 10);
            continue;
        }
        if (waited < 0 && errno == EINTR) continue;
        break;
    }
    const bool gone =
        identity_ok && reaped && observe_exact_liveness(expected) == ExactLiveness::ExitedOrReused;
    ExactProcStat malformed;
    const bool malformed_rejected = !parse_exact_proc_stat("not-a-stat", malformed);
    ProcIdentity invalid;
    const bool invalid_unknown = observe_exact_liveness(invalid) == ExactLiveness::Unknown;
    if (!arm_ok || !arm_reaped || !WIFEXITED(arm_status) || WEXITSTATUS(arm_status) != 0 || !live ||
        !wrong_start_gone || !zombie_not_live || !gone || !malformed_rejected || !invalid_unknown) {
        error = "PDEATHSIG/exact PID-start-state liveness self-check failed";
        return false;
    }
    return true;
}

struct ProcFailureProbe {
    bool stat_read = false;
    bool stat_parse = false;
    bool stat_start_stable = false;
    std::uint64_t stat_start_before = 0;
    std::uint64_t stat_start_after = 0;
    pid_t stat_sid = -1;
    int stat_errno = 0;
    bool status_read = false;
    bool status_parse = false;
    int status_errno = 0;
    bool netns_stat = false;
    int netns_errno = 0;
    bool exe_stat = false;
    int exe_stat_errno = 0;
    bool exe_read = false;
    int exe_errno = 0;
    bool cmdline_read = false;
    int cmdline_errno = 0;
    size_t cmdline_length = 0;
    std::uint64_t cmdline_hash = 0;
};

static std::uint64_t probe_hash(const std::string& value) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool parse_probe_stat(const std::string& text, pid_t& sid, std::uint64_t& start) {
    const size_t comm_end = text.rfind(") ");
    if (comm_end == std::string::npos) return false;
    std::istringstream fields(text.substr(comm_end + 2));
    char state = 0;
    long ppid = 0;
    long pgid = 0;
    long session = 0;
    if (!(fields >> state >> ppid >> pgid >> session)) return false;
    for (int field = 7; field <= 22; ++field) {
        if (field == 22) {
            unsigned long long value = 0;
            if (!(fields >> value)) return false;
            start = static_cast<std::uint64_t>(value);
        } else {
            long long value = 0;
            if (!(fields >> value)) return false;
        }
    }
    sid = static_cast<pid_t>(session);
    return sid > 0 && start != 0;
}

static bool probe_file(const std::string& path, std::string& output, int& error_number) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        error_number = errno;
        return false;
    }
    output.clear();
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            if (output.size() > 128 * 1024 - static_cast<size_t>(count)) {
                error_number = EOVERFLOW;
                close(fd);
                return false;
            }
            output.append(buffer.data(), static_cast<size_t>(count));
            continue;
        }
        if (count == 0) {
            close(fd);
            error_number = 0;
            return true;
        }
        if (errno == EINTR) continue;
        error_number = errno;
        close(fd);
        return false;
    }
}

static ProcFailureProbe probe_proc(pid_t pid) {
    ProcFailureProbe probe;
    const std::string prefix = "/proc/" + std::to_string(pid);
    std::string stat_text;
    probe.stat_read = probe_file(prefix + "/stat", stat_text, probe.stat_errno);
    if (probe.stat_read) {
        probe.stat_parse = parse_probe_stat(stat_text, probe.stat_sid, probe.stat_start_before);
        if (probe.stat_parse) {
            std::string after_text;
            int after_errno = 0;
            pid_t after_sid = -1;
            probe.stat_start_stable =
                probe_file(prefix + "/stat", after_text, after_errno) &&
                parse_probe_stat(after_text, after_sid, probe.stat_start_after) &&
                after_sid == probe.stat_sid && probe.stat_start_after == probe.stat_start_before;
            if (!probe.stat_start_stable && probe.stat_errno == 0) probe.stat_errno = after_errno;
        }
    }
    std::string status;
    probe.status_read = probe_file(prefix + "/status", status, probe.status_errno);
    if (probe.status_read) {
        bool uid = false, gid = false, groups = false, nnp = false;
        std::istringstream lines(status);
        std::string line;
        while (std::getline(lines, line)) {
            const size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::istringstream value(line.substr(colon + 1));
            if (line.rfind("Uid:", 0) == 0) {
                unsigned long ignored = 0;
                uid = static_cast<bool>(value >> ignored);
            } else if (line.rfind("Gid:", 0) == 0) {
                unsigned long ignored = 0;
                gid = static_cast<bool>(value >> ignored);
            } else if (line.rfind("Groups:", 0) == 0) {
                std::string ignored;
                groups = static_cast<bool>(value >> ignored) || value.eof();
            } else if (line.rfind("NoNewPrivs:", 0) == 0) {
                int ignored = 0;
                nnp = static_cast<bool>(value >> ignored);
            }
        }
        probe.status_parse = uid && gid && groups && nnp;
    }
    struct stat netns{};
    probe.netns_stat = stat((prefix + "/ns/net").c_str(), &netns) == 0;
    if (!probe.netns_stat) probe.netns_errno = errno;
    struct stat executable{};
    probe.exe_stat = stat((prefix + "/exe").c_str(), &executable) == 0;
    if (!probe.exe_stat) probe.exe_stat_errno = errno;
    std::array<char, PATH_MAX> exe{};
    const ssize_t exe_length = readlink((prefix + "/exe").c_str(), exe.data(), exe.size() - 1);
    probe.exe_read = exe_length >= 0;
    if (!probe.exe_read) probe.exe_errno = errno;
    std::string cmdline;
    probe.cmdline_read = probe_file(prefix + "/cmdline", cmdline, probe.cmdline_errno);
    if (probe.cmdline_read) {
        probe.cmdline_length = cmdline.size();
        probe.cmdline_hash = probe_hash(cmdline);
    }
    return probe;
}

static std::string probe_diagnostic(pid_t pid) {
    const ProcFailureProbe probe = probe_proc(pid);
    std::ostringstream out;
    out << "proc-probe pid=" << pid << " stat{read=" << probe.stat_read
        << ",parse=" << probe.stat_parse << ",errno=" << probe.stat_errno
        << ",start=" << probe.stat_start_before << ",after=" << probe.stat_start_after
        << ",stable=" << probe.stat_start_stable << "} status{read=" << probe.status_read
        << ",parse=" << probe.status_parse << ",errno=" << probe.status_errno
        << "} netns{stat=" << probe.netns_stat << ",errno=" << probe.netns_errno
        << "} exe{stat=" << probe.exe_stat << ",stat_errno=" << probe.exe_stat_errno
        << ",read=" << probe.exe_read << ",errno=" << probe.exe_errno
        << "} cmdline{read=" << probe.cmdline_read << ",errno=" << probe.cmdline_errno
        << ",length=" << probe.cmdline_length << ",hash=0x" << std::hex << probe.cmdline_hash
        << std::dec << "}";
    return out.str();
}

enum class DirectWaitDisposition { Reaped, Retry, Error };
enum class OwnedReapResult { Reaped, TimedOut, Error };

static OwnedReapResult reap_owned_child_bounded(pid_t child);

static DirectWaitDisposition classify_direct_wait(pid_t waited, pid_t expected, int wait_errno) {
    if (waited == expected) return DirectWaitDisposition::Reaped;
    if (waited == 0 || (waited < 0 && wait_errno == EINTR)) return DirectWaitDisposition::Retry;
    return DirectWaitDisposition::Error;
}

struct GroupLease {
    pid_t pid = -1;
    pid_t pgid = -1;
    pid_t sid = -1;
    std::uint64_t start = 0;
    int pidfd = -1;

    ~GroupLease() {
        if (pidfd >= 0) close(pidfd);
    }

    bool establish(const ProcIdentity& identity) {
        pid = identity.pid;
        pgid = identity.pgid;
        sid = identity.sid;
        start = identity.start;
        int member_count = 0;
        if (pid <= 1 || pgid != pid || sid <= 1 || start == 0 ||
            group_member_count(pgid, member_count) != GroupScanResult::Exact || member_count != 1)
            return false;
#ifdef SYS_pidfd_open
        pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
        if (pidfd < 0 && errno != ENOSYS) return false;
#endif
        return true;
    }

    bool revalidate() const {
        ProcIdentity current;
        return pid > 1 && pgid == pid && sid > 1 && start != 0 &&
               stable_proc_identity(pid, current) && current.pid == pid && current.start == start &&
               current.pgid == pgid && current.sid == sid && kill(-pgid, 0) == 0;
    }

    bool gone() const {
        if (pgid <= 1) return false;
        errno = 0;
        if (kill(-pgid, 0) < 0 && errno == ESRCH) return true;
        // A direct child remains a zombie until its owning parent waitpid()s it;
        // Linux keeps that zombie's process group addressable.  WNOWAIT plus a
        // /proc group scan is the safe pre-reap equivalent of ESRCH here.
        int count = 0;
        bool live = true;
        pid_t sole_member = -1;
        std::uint64_t sole_start = 0;
        return child_exited_wnowait(pid) &&
               scan_group_stat(pgid, count, live, pid, sole_member, sole_start) ==
                   GroupScanResult::Exact &&
               count == 1 && sole_member == pid && sole_start == start && !live;
    }

    bool empty_group_exact() const {
        int count = 0;
        bool live = false;
        pid_t sole_member = -1;
        std::uint64_t sole_start = 0;
        errno = 0;
        const bool esrch = kill(-pgid, 0) < 0 && errno == ESRCH;
        return pgid > 1 && esrch &&
               scan_group_stat(pgid, count, live, -1, sole_member, sole_start) ==
                   GroupScanResult::Exact &&
               count == 0 && !live;
    }

    bool signal_single(int signal_number) const {
        ProcIdentity current;
        if (geteuid() == 0 || pid <= 1 || pidfd < 0 || !revalidate() ||
            !read_proc(pid, current, false) || current.uid != getuid() || current.gid != getgid())
            return false;
#ifdef SYS_pidfd_send_signal
        return syscall(SYS_pidfd_send_signal, pidfd, signal_number, nullptr, 0) == 0;
#else
        (void)signal_number;
        return false;
#endif
    }
};

static const privileged_ancestry::RetainedAnchorLease retained_lease(const GroupLease& lease) {
    return {lease.pid, lease.pgid, lease.sid, lease.start, lease.pidfd};
}

static std::string retained_wrapper_diagnostic(const DirectLaunch& launch,
                                               const GroupLease& lease,
                                               const RetainedAnchorEvidence& evidence,
                                               const identity_bundle::RoleManifest& launcher) {
    std::ostringstream out;
    out << "retained-wrapper{mode="
        << rut::test::fixture_direct_launch::launch_mode_name(launch.mode)
        << ",current_valid=" << launch.current_valid << ",observed_stage="
        << (launch.current_valid
                ? rut::test::fixture_direct_launch::launch_stage_name(launch.current_stage)
                : "none")
        << ",expected_stage=sudo"
        << ",anchor=" << launch.anchor.pid << ':' << launch.anchor.start << ':'
        << launch.anchor.pgid << ':' << launch.anchor.sid << ",lease=" << lease.pid << ':'
        << lease.start << ':' << lease.pgid << ':' << lease.sid
        << ",lease_pidfd_live=" << retained_pidfd_live(lease.pidfd) << ",evidence=" << evidence.pid
        << ':' << evidence.start << ':' << evidence.ppid << ':' << evidence.pgid << ':'
        << evidence.sid << ':' << evidence.state << ':' << evidence.uid << ':' << evidence.gid
        << ",evidence_pidfd_live=" << evidence.pidfd_live << ",launcher=" << launcher.pid << ':'
        << launcher.start << ':' << launcher.ppid << ':' << launcher.pgid << ':' << launcher.sid
        << ':' << launcher.uid << ':' << launcher.gid
        << ",launcher_stage=launcher,launcher_exe=" << launcher.exe_dev << ':' << launcher.exe_ino
        << ",launcher_argv_bytes=" << launcher.argv_length << ",launcher_argv_hash=0x" << std::hex
        << launcher.argv_hash << std::dec << ",sudo_exe=" << launch.allowed.sudo_stage.exe_dev
        << ':' << launch.allowed.sudo_stage.exe_ino << ",sudo_uid_tuple=" << evidence.uid_values[0]
        << ':' << evidence.uid_values[1] << ':' << evidence.uid_values[2] << ':'
        << evidence.uid_values[3] << ",sudo_gid_tuple=" << evidence.gid_values[0] << ':'
        << evidence.gid_values[1] << ':' << evidence.gid_values[2] << ':' << evidence.gid_values[3]
        << ",sudo_argv_observed_bytes=" << evidence.cmdline.size() << ",sudo_argv_observed_hash=0x"
        << std::hex << probe_hash(evidence.cmdline) << std::dec
        << ",sudo_argv_expected_bytes=" << launch.allowed.sudo_stage.argv.size()
        << ",sudo_argv_expected_hash=0x" << std::hex << probe_hash(launch.allowed.sudo_stage.argv)
        << std::dec << '}';
    return out.str();
}

static bool parse_u64(const char* text, u64& value) {
    if (text == nullptr || *text == '\0') return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return false;
    value = static_cast<u64>(parsed);
    return true;
}

static std::string token_text(const Token& token) {
    std::array<char, 2 * kTokenBytes + 1> text{};
    for (size_t i = 0; i != kTokenBytes; ++i)
        snprintf(text.data() + 2 * i, 3, "%02x", token.bytes[i]);
    return text.data();
}

static bool new_token(Token& token) {
    size_t offset = 0;
    while (offset != token.bytes.size()) {
        const ssize_t count =
            getrandom(token.bytes.data() + offset, token.bytes.size() - offset, 0);
        if (count > 0)
            offset += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else
            return false;
    }
    return true;
}

static std::string exact_argv(const std::vector<std::string>& values) {
    std::string result;
    for (const std::string& value : values) result.append(value.data(), value.size() + 1);
    return result;
}

struct LaunchArgv {
    std::vector<std::string> launcher;
    std::vector<std::string> nsenter;
    std::vector<std::string> sudo_command;
};

static LaunchArgv make_launch_argv(const std::string& sudo_path,
                                   const std::string& nsenter_path,
                                   const std::string& netns_arg,
                                   const std::string& executable,
                                   const std::string& endpoint,
                                   const std::string& token,
                                   const std::string& expected_netns,
                                   const std::string& scenario) {
    LaunchArgv argv;
    argv.launcher = {
        executable, "--fixture-broker-launcher", endpoint, token, expected_netns, scenario};
    argv.nsenter = {nsenter_path};
    argv.nsenter.push_back(netns_arg);
    argv.nsenter.emplace_back("--");
    argv.nsenter.insert(argv.nsenter.end(), argv.launcher.begin(), argv.launcher.end());
    argv.sudo_command = {sudo_path, "-n", "--"};
    argv.sudo_command.insert(argv.sudo_command.end(), argv.nsenter.begin(), argv.nsenter.end());
    return argv;
}

static bool launch_argv_refactor_self_check(std::string& error) {
    const LaunchArgv formal = make_launch_argv("/sudo",
                                               "/nsenter",
                                               "--net=/proc/7/ns/net",
                                               "/fixture",
                                               "/endpoint",
                                               "token",
                                               "88",
                                               "normal");
    const bool exact =
        exact_argv(formal.launcher) ==
            exact_argv(
                {"/fixture", "--fixture-broker-launcher", "/endpoint", "token", "88", "normal"}) &&
        exact_argv(formal.nsenter) == exact_argv({"/nsenter",
                                                  "--net=/proc/7/ns/net",
                                                  "--",
                                                  "/fixture",
                                                  "--fixture-broker-launcher",
                                                  "/endpoint",
                                                  "token",
                                                  "88",
                                                  "normal"}) &&
        exact_argv(formal.sudo_command) == exact_argv({"/sudo",
                                                       "-n",
                                                       "--",
                                                       "/nsenter",
                                                       "--net=/proc/7/ns/net",
                                                       "--",
                                                       "/fixture",
                                                       "--fixture-broker-launcher",
                                                       "/endpoint",
                                                       "token",
                                                       "88",
                                                       "normal"});
    if (!exact) {
        error = "shared formal/probe launch argv construction self-check failed";
        return false;
    }
    return true;
}

static bool clear_caps() {
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    __user_cap_data_struct data[2]{};
    return syscall(SYS_capset, &header, data) == 0;
}

static bool fill_report(const char* mode, u64 wrapper_pid, Report& report, bool groups_clear) {
    ProcIdentity proc;
    if (!read_proc(getpid(), proc, false)) return false;
    report.target_pid = static_cast<u64>(proc.pid);
    report.wrapper_pid = wrapper_pid;
    report.start = proc.start;
    report.pgid = static_cast<u64>(proc.pgid);
    report.uid = proc.uid;
    report.gid = proc.gid;
    report.netns = proc.netns;
    report.exe_dev = proc.exe_dev;
    report.exe_ino = proc.exe_ino;
    report.no_new_privs = proc.no_new_privs ? 1 : 0;
    report.capabilities_clear = proc.capabilities_clear ? 1 : 0;
    report.groups_clear = groups_clear ? 1 : 0;
    report.groups_unchanged = groups_clear ? 0 : 1;
    report.exe = proc.exe;
    report.argv = proc.cmdline;
    report.mode = mode;
    return true;
}

static std::vector<unsigned char> credentials_payload(uid_t uid, gid_t gid) {
    std::vector<unsigned char> result(16, 0);
    const u64 values[] = {static_cast<u64>(uid), static_cast<u64>(gid)};
    for (size_t field = 0; field != 2; ++field)
        for (unsigned shift = 0; shift != 64; shift += 8)
            result[field * 8 + shift / 8] = static_cast<unsigned char>(values[field] >> shift);
    return result;
}

static bool parse_credentials(const std::vector<unsigned char>& payload, uid_t& uid, gid_t& gid) {
    if (payload.size() != 16) return false;
    u64 values[2]{};
    for (size_t field = 0; field != 2; ++field)
        for (unsigned shift = 0; shift != 64; shift += 8)
            values[field] |= static_cast<u64>(payload[field * 8 + shift / 8]) << shift;
    if (values[0] == 0 || values[0] > std::numeric_limits<uid_t>::max() ||
        values[1] > std::numeric_limits<gid_t>::max())
        return false;
    uid = static_cast<uid_t>(values[0]);
    gid = static_cast<gid_t>(values[1]);
    return true;
}

static bool credentials_match_peer(const std::vector<unsigned char>& payload,
                                   uid_t expected_uid,
                                   gid_t expected_gid) {
    uid_t uid = 0;
    gid_t gid = 0;
    return parse_credentials(payload, uid, gid) && uid == expected_uid && gid == expected_gid;
}

constexpr std::size_t kGuardReportFields = 19u;

struct GuardReport {
    privileged_listener::ListenerPlan plan;
    u64 guard_fd = 0u;
    u64 socket_inode = 0u;
    u64 owner_pid = 0u;
    u64 owner_start = 0u;
    u64 netns = 0u;
    u64 baseline_fd_count = 0u;
    u64 current_fd_count = 0u;
    u64 family = 0u;
    u64 socket_type = 0u;
    u64 fd_cloexec = 0u;
    u64 accept_connection = 0u;
    u64 reuse_port = 0u;
    u64 reuse_address = 0u;
    u64 connect_error = 0u;
    u64 fd_invalidated = 0u;
};

struct ExecutableLease {
    std::string path;
    int fd = -1;
    struct stat status{};

    ~ExecutableLease() {
        if (fd >= 0) close(fd);
    }
};

constexpr u64 kExactProtocolVersion = 1u;
constexpr std::size_t kExactReportFields = 25u;
struct ExactRutReport {
    u64 version = kExactProtocolVersion;
    u64 child_pid = 0u;
    u64 child_start = 0u;
    u64 child_ppid = 0u;
    u64 child_pgid = 0u;
    u64 child_sid = 0u;
    u64 child_uid = 0u;
    u64 child_gid = 0u;
    u64 child_netns = 0u;
    u64 child_exe_dev = 0u;
    u64 child_exe_ino = 0u;
    u64 pidfd = 0u;
    u64 pidfd_cloexec = 0u;
    u64 listener_inode = 0u;
    u64 source_dev = 0u;
    u64 source_ino = 0u;
    u64 log_dev = 0u;
    u64 log_ino = 0u;
    u64 target_fd_count = 0u;
    u64 response_bytes = 0u;
    u64 response_exact = 0u;
    u64 prompt_eof = 0u;
    u64 guard_connect_error = 0u;
    u64 stable = 0u;
    u64 backend = 0u;
};

constexpr std::size_t kExactCleanedFields = 11u;
struct ExactRutCleanedReport {
    u64 version = kExactProtocolVersion;
    u64 child_pid = 0u;
    u64 child_start = 0u;
    u64 listener_inode = 0u;
    u64 clean_exit = 0u;
    u64 pidfd_invalidated = 0u;
    u64 child_absent = 0u;
    u64 listener_absent = 0u;
    u64 temps_absent = 0u;
    u64 target_fd_count = 0u;
    u64 guard_connect_error = 0u;
};

enum class ExactFailurePhase : u64 {
    LeaseReopen = 1u,
    Temp = 2u,
    ForkPreExec = 3u,
    Exec = 4u,
    PidfdIdentity = 5u,
    ListenerLog = 6u,
    HttpEof = 7u,
    GuardRefusal = 8u,
    StabilityFd = 9u,
    Cleanup = 10u,
};

struct ExactFailureReport {
    u64 version = 2u;
    ExactFailurePhase phase = ExactFailurePhase::LeaseReopen;
    u64 error_number = 0u;
    u64 count = 0u;
    u64 escrow_required = 0u;
    u64 child_pid = 0u;
    u64 child_start = 0u;
};

constexpr u64 kExactCustodyVersion = 1u;
constexpr u64 kExactSettledVersion = 2u;
constexpr std::size_t kExactCustodyFields = 21u;
struct ExactCustodyRecord {
    u64 version = kExactCustodyVersion;
    u64 child_pid = 0u;
    u64 child_start = 0u;
    u64 child_exe_dev = 0u;
    u64 child_exe_ino = 0u;
    u64 listener_inode = 0u;
    u64 positive_ipv4 = 0u;
    u64 guard_ipv4 = 0u;
    u64 port = 0u;
    u64 guard_inode = 0u;
    u64 netns = 0u;
    u64 directory_dev = 0u;
    u64 directory_ino = 0u;
    u64 source_dev = 0u;
    u64 source_ino = 0u;
    u64 log_dev = 0u;
    u64 log_ino = 0u;
    u64 target_pid = 0u;
    u64 target_start = 0u;
    u64 has_pidfd = 0u;
    u64 child_reaped = 0u;
};

struct ExactEscrowRights {
    int guard = -1;
    int pidfd = -1;
    int directory = -1;

    void close_all() {
        for (int* fd : {&guard, &pidfd, &directory}) {
            if (*fd >= 0) close(*fd);
            *fd = -1;
        }
    }
};

constexpr std::size_t kExactSettledFields = 11u;
struct ExactSettledRecord {
    u64 version = kExactSettledVersion;
    u64 target_pid = 0u;
    u64 child_pid = 0u;
    u64 child_start = 0u;
    u64 guard_inode = 0u;
    u64 adopted = 0u;
    u64 reaped = 0u;
    u64 listener_absent = 0u;
    u64 temps_absent = 0u;
    u64 competing_bind_error = 0u;
    u64 guard_closed = 0u;
};

static bool executable_lease_unchanged(const ExecutableLease& lease);

static void append_u64(std::vector<unsigned char>& payload, u64 value) {
    for (unsigned shift = 0u; shift != 64u; shift += 8u)
        payload.push_back(static_cast<unsigned char>(value >> shift));
}

static u64 read_u64(const unsigned char* value) {
    u64 result = 0u;
    for (unsigned shift = 0u; shift != 64u; shift += 8u)
        result |= static_cast<u64>(value[shift / 8u]) << shift;
    return result;
}

constexpr u64 kWildcardAttemptVersion = 1u;

enum class WildcardAttemptMode : u64 {
    Canonical = 1u,
    MissingCollision = 2u,
    PrematureGuardRelease = 3u,
    WrongListenerKind = 4u,
    WrongListenerAddress = 5u,
    WrongListenerInode = 6u,
    FalsePostReleaseSuccess = 7u,
};

enum class WildcardAttemptPhase : u64 {
    GuardHeld = 1u,
    ExactRutWitness = 2u,
    CollisionPrepared = 3u,
    CollisionRejected = 4u,
    ExactCleanedGuardHeld = 5u,
    GuardReleased = 6u,
    WildcardLive = 7u,
};

enum class WildcardAttemptDecisionKind : u64 {
    AuthorizeCollisionExec = 1u,
    AuthorizeExactCleanup = 2u,
    AuthorizeGuardRelease = 3u,
    AuthorizeWildcardExec = 4u,
    AuthorizeWildcardCleanup = 5u,
    RejectAndCleanup = 6u,
    Finish = 7u,
};

enum class WildcardAttemptSettlementKind : u64 {
    AttemptSettled = 1u,
    MutationSettled = 2u,
};

struct WildcardAttemptCommandV1 {
    u64 version = kWildcardAttemptVersion;
    u64 transaction_id = 0u;
    WildcardAttemptMode mode = WildcardAttemptMode::Canonical;
    u64 sequence = 0u;
};

struct WildcardAttemptPhaseV1 {
    u64 version = kWildcardAttemptVersion;
    u64 transaction_id = 0u;
    WildcardAttemptMode mode = WildcardAttemptMode::Canonical;
    WildcardAttemptPhase phase = WildcardAttemptPhase::GuardHeld;
    u64 sequence = 0u;
};

struct WildcardAttemptDecisionV1 {
    u64 version = kWildcardAttemptVersion;
    u64 transaction_id = 0u;
    WildcardAttemptMode mode = WildcardAttemptMode::Canonical;
    WildcardAttemptDecisionKind decision = WildcardAttemptDecisionKind::AuthorizeCollisionExec;
    WildcardAttemptPhase for_phase = WildcardAttemptPhase::CollisionPrepared;
    u64 sequence = 0u;
};

struct WildcardAttemptSettlementV1 {
    u64 version = kWildcardAttemptVersion;
    u64 transaction_id = 0u;
    WildcardAttemptMode mode = WildcardAttemptMode::Canonical;
    WildcardAttemptSettlementKind settlement = WildcardAttemptSettlementKind::AttemptSettled;
    WildcardAttemptPhase terminal_phase = WildcardAttemptPhase::WildcardLive;
    u64 sequence = 0u;
};

static bool valid_wildcard_attempt_mode(WildcardAttemptMode mode) {
    switch (mode) {
        case WildcardAttemptMode::Canonical:
        case WildcardAttemptMode::MissingCollision:
        case WildcardAttemptMode::PrematureGuardRelease:
        case WildcardAttemptMode::WrongListenerKind:
        case WildcardAttemptMode::WrongListenerAddress:
        case WildcardAttemptMode::WrongListenerInode:
        case WildcardAttemptMode::FalsePostReleaseSuccess:
            return true;
    }
    return false;
}

static bool valid_wildcard_attempt_phase(WildcardAttemptPhase phase) {
    switch (phase) {
        case WildcardAttemptPhase::GuardHeld:
        case WildcardAttemptPhase::ExactRutWitness:
        case WildcardAttemptPhase::CollisionPrepared:
        case WildcardAttemptPhase::CollisionRejected:
        case WildcardAttemptPhase::ExactCleanedGuardHeld:
        case WildcardAttemptPhase::GuardReleased:
        case WildcardAttemptPhase::WildcardLive:
            return true;
    }
    return false;
}

static bool valid_wildcard_attempt_mode_value(u64 value) {
    return value >= static_cast<u64>(WildcardAttemptMode::Canonical) &&
           value <= static_cast<u64>(WildcardAttemptMode::FalsePostReleaseSuccess);
}

static bool valid_wildcard_attempt_phase_value(u64 value) {
    return value >= static_cast<u64>(WildcardAttemptPhase::GuardHeld) &&
           value <= static_cast<u64>(WildcardAttemptPhase::WildcardLive);
}

static bool valid_wildcard_attempt_decision_value(u64 value) {
    return value >= static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeCollisionExec) &&
           value <= static_cast<u64>(WildcardAttemptDecisionKind::Finish);
}

static bool valid_wildcard_attempt_settlement_value(u64 value) {
    return value >= static_cast<u64>(WildcardAttemptSettlementKind::AttemptSettled) &&
           value <= static_cast<u64>(WildcardAttemptSettlementKind::MutationSettled);
}

static u64 wildcard_phase_sequence(WildcardAttemptPhase phase) {
    switch (phase) {
        case WildcardAttemptPhase::GuardHeld:
            return 1u;
        case WildcardAttemptPhase::ExactRutWitness:
            return 2u;
        case WildcardAttemptPhase::CollisionPrepared:
            return 3u;
        case WildcardAttemptPhase::CollisionRejected:
            return 5u;
        case WildcardAttemptPhase::ExactCleanedGuardHeld:
            return 7u;
        case WildcardAttemptPhase::GuardReleased:
            return 9u;
        case WildcardAttemptPhase::WildcardLive:
            return 11u;
    }
    return 0u;
}

static u64 wildcard_phase_sequence_value(u64 phase) {
    switch (phase) {
        case static_cast<u64>(WildcardAttemptPhase::GuardHeld):
            return 1u;
        case static_cast<u64>(WildcardAttemptPhase::ExactRutWitness):
            return 2u;
        case static_cast<u64>(WildcardAttemptPhase::CollisionPrepared):
            return 3u;
        case static_cast<u64>(WildcardAttemptPhase::CollisionRejected):
            return 5u;
        case static_cast<u64>(WildcardAttemptPhase::ExactCleanedGuardHeld):
            return 7u;
        case static_cast<u64>(WildcardAttemptPhase::GuardReleased):
            return 9u;
        case static_cast<u64>(WildcardAttemptPhase::WildcardLive):
            return 11u;
    }
    return 0u;
}

static u64 wildcard_rejection_checkpoint_value(u64 mode) {
    switch (mode) {
        case static_cast<u64>(WildcardAttemptMode::MissingCollision):
        case static_cast<u64>(WildcardAttemptMode::PrematureGuardRelease):
            return static_cast<u64>(WildcardAttemptPhase::CollisionRejected);
        case static_cast<u64>(WildcardAttemptMode::WrongListenerKind):
        case static_cast<u64>(WildcardAttemptMode::WrongListenerAddress):
        case static_cast<u64>(WildcardAttemptMode::WrongListenerInode):
        case static_cast<u64>(WildcardAttemptMode::FalsePostReleaseSuccess):
            return static_cast<u64>(WildcardAttemptPhase::WildcardLive);
        case static_cast<u64>(WildcardAttemptMode::Canonical):
            return 0u;
    }
    return 0u;
}

static WildcardAttemptPhase wildcard_rejection_checkpoint(WildcardAttemptMode mode) {
    switch (mode) {
        case WildcardAttemptMode::MissingCollision:
        case WildcardAttemptMode::PrematureGuardRelease:
            return WildcardAttemptPhase::CollisionRejected;
        case WildcardAttemptMode::WrongListenerKind:
        case WildcardAttemptMode::WrongListenerAddress:
        case WildcardAttemptMode::WrongListenerInode:
        case WildcardAttemptMode::FalsePostReleaseSuccess:
            return WildcardAttemptPhase::WildcardLive;
        case WildcardAttemptMode::Canonical:
            break;
    }
    return static_cast<WildcardAttemptPhase>(0u);
}

template <std::size_t Size>
static bool decode_wildcard_fields(const std::vector<unsigned char>& payload,
                                   std::array<u64, Size>& fields) {
    if (payload.size() != Size * sizeof(u64)) return false;
    for (std::size_t i = 0u; i != fields.size(); ++i)
        fields[i] = read_u64(payload.data() + i * sizeof(u64));
    return true;
}

template <std::size_t Size>
static std::vector<unsigned char> encode_wildcard_fields(const std::array<u64, Size>& fields) {
    std::vector<unsigned char> payload;
    payload.reserve(fields.size() * sizeof(u64));
    for (u64 field : fields) append_u64(payload, field);
    return payload;
}

static bool valid_wildcard_command(const WildcardAttemptCommandV1& command) {
    return command.version == kWildcardAttemptVersion && command.transaction_id != 0u &&
           valid_wildcard_attempt_mode(command.mode) && command.sequence == 0u;
}

static std::vector<unsigned char> encode_wildcard_command(const WildcardAttemptCommandV1& command) {
    return encode_wildcard_fields(std::array<u64, 4u>{
        command.version, command.transaction_id, static_cast<u64>(command.mode), command.sequence});
}

static bool decode_wildcard_command(const std::vector<unsigned char>& payload,
                                    WildcardAttemptCommandV1& command) {
    std::array<u64, 4u> fields{};
    if (!decode_wildcard_fields(payload, fields) || fields[0] != kWildcardAttemptVersion ||
        fields[1] == 0u || !valid_wildcard_attempt_mode_value(fields[2]) || fields[3] != 0u)
        return false;
    const WildcardAttemptCommandV1 decoded{
        fields[0], fields[1], static_cast<WildcardAttemptMode>(fields[2]), fields[3]};
    command = decoded;
    return true;
}

static bool valid_wildcard_phase(const WildcardAttemptPhaseV1& witness) {
    return witness.version == kWildcardAttemptVersion && witness.transaction_id != 0u &&
           valid_wildcard_attempt_mode(witness.mode) &&
           valid_wildcard_attempt_phase(witness.phase) &&
           witness.sequence == wildcard_phase_sequence(witness.phase);
}

static std::vector<unsigned char> encode_wildcard_phase(const WildcardAttemptPhaseV1& witness) {
    return encode_wildcard_fields(std::array<u64, 5u>{witness.version,
                                                      witness.transaction_id,
                                                      static_cast<u64>(witness.mode),
                                                      static_cast<u64>(witness.phase),
                                                      witness.sequence});
}

static bool decode_wildcard_phase(const std::vector<unsigned char>& payload,
                                  WildcardAttemptPhaseV1& witness) {
    std::array<u64, 5u> fields{};
    if (!decode_wildcard_fields(payload, fields) || fields[0] != kWildcardAttemptVersion ||
        fields[1] == 0u || !valid_wildcard_attempt_mode_value(fields[2]) ||
        !valid_wildcard_attempt_phase_value(fields[3]) ||
        fields[4] != wildcard_phase_sequence_value(fields[3]))
        return false;
    const WildcardAttemptPhaseV1 decoded{fields[0],
                                         fields[1],
                                         static_cast<WildcardAttemptMode>(fields[2]),
                                         static_cast<WildcardAttemptPhase>(fields[3]),
                                         fields[4]};
    witness = decoded;
    return true;
}

static bool valid_wildcard_decision(const WildcardAttemptDecisionV1& decision) {
    if (decision.version != kWildcardAttemptVersion || decision.transaction_id == 0u ||
        !valid_wildcard_attempt_mode(decision.mode) ||
        !valid_wildcard_attempt_phase(decision.for_phase))
        return false;
    switch (decision.decision) {
        case WildcardAttemptDecisionKind::AuthorizeCollisionExec:
            return decision.for_phase == WildcardAttemptPhase::CollisionPrepared &&
                   decision.sequence == 4u;
        case WildcardAttemptDecisionKind::AuthorizeExactCleanup:
            return decision.for_phase == WildcardAttemptPhase::CollisionRejected &&
                   decision.sequence == 6u;
        case WildcardAttemptDecisionKind::AuthorizeGuardRelease:
            return decision.for_phase == WildcardAttemptPhase::ExactCleanedGuardHeld &&
                   decision.sequence == 8u;
        case WildcardAttemptDecisionKind::AuthorizeWildcardExec:
            return decision.for_phase == WildcardAttemptPhase::GuardReleased &&
                   decision.sequence == 10u;
        case WildcardAttemptDecisionKind::AuthorizeWildcardCleanup:
            return decision.for_phase == WildcardAttemptPhase::WildcardLive &&
                   decision.sequence == 12u;
        case WildcardAttemptDecisionKind::RejectAndCleanup:
            return decision.mode != WildcardAttemptMode::Canonical &&
                   decision.for_phase == wildcard_rejection_checkpoint(decision.mode) &&
                   decision.sequence == wildcard_phase_sequence(decision.for_phase);
        case WildcardAttemptDecisionKind::Finish:
            return decision.mode == WildcardAttemptMode::Canonical &&
                   decision.for_phase == WildcardAttemptPhase::WildcardLive &&
                   decision.sequence == 14u;
    }
    return false;
}

static std::vector<unsigned char> encode_wildcard_decision(
    const WildcardAttemptDecisionV1& decision) {
    return encode_wildcard_fields(std::array<u64, 6u>{decision.version,
                                                      decision.transaction_id,
                                                      static_cast<u64>(decision.mode),
                                                      static_cast<u64>(decision.decision),
                                                      static_cast<u64>(decision.for_phase),
                                                      decision.sequence});
}

static bool decode_wildcard_decision(const std::vector<unsigned char>& payload,
                                     WildcardAttemptDecisionV1& decision) {
    std::array<u64, 6u> fields{};
    if (!decode_wildcard_fields(payload, fields) || fields[0] != kWildcardAttemptVersion ||
        fields[1] == 0u || !valid_wildcard_attempt_mode_value(fields[2]) ||
        !valid_wildcard_attempt_decision_value(fields[3]) ||
        !valid_wildcard_attempt_phase_value(fields[4]))
        return false;
    const u64 checkpoint = wildcard_rejection_checkpoint_value(fields[2]);
    bool valid = false;
    switch (fields[3]) {
        case static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeCollisionExec):
            valid = fields[4] == static_cast<u64>(WildcardAttemptPhase::CollisionPrepared) &&
                    fields[5] == 4u;
            break;
        case static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeExactCleanup):
            valid = fields[4] == static_cast<u64>(WildcardAttemptPhase::CollisionRejected) &&
                    fields[5] == 6u;
            break;
        case static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeGuardRelease):
            valid = fields[4] == static_cast<u64>(WildcardAttemptPhase::ExactCleanedGuardHeld) &&
                    fields[5] == 8u;
            break;
        case static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeWildcardExec):
            valid = fields[4] == static_cast<u64>(WildcardAttemptPhase::GuardReleased) &&
                    fields[5] == 10u;
            break;
        case static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeWildcardCleanup):
            valid = fields[4] == static_cast<u64>(WildcardAttemptPhase::WildcardLive) &&
                    fields[5] == 12u;
            break;
        case static_cast<u64>(WildcardAttemptDecisionKind::RejectAndCleanup):
            valid = fields[2] != static_cast<u64>(WildcardAttemptMode::Canonical) &&
                    fields[4] == checkpoint &&
                    fields[5] == wildcard_phase_sequence_value(fields[4]);
            break;
        case static_cast<u64>(WildcardAttemptDecisionKind::Finish):
            valid = fields[2] == static_cast<u64>(WildcardAttemptMode::Canonical) &&
                    fields[4] == static_cast<u64>(WildcardAttemptPhase::WildcardLive) &&
                    fields[5] == 14u;
            break;
    }
    if (!valid) return false;
    const WildcardAttemptDecisionV1 decoded{fields[0],
                                            fields[1],
                                            static_cast<WildcardAttemptMode>(fields[2]),
                                            static_cast<WildcardAttemptDecisionKind>(fields[3]),
                                            static_cast<WildcardAttemptPhase>(fields[4]),
                                            fields[5]};
    decision = decoded;
    return true;
}

static bool valid_wildcard_settlement(const WildcardAttemptSettlementV1& settlement) {
    if (settlement.version != kWildcardAttemptVersion || settlement.transaction_id == 0u ||
        !valid_wildcard_attempt_mode(settlement.mode) ||
        !valid_wildcard_attempt_phase(settlement.terminal_phase))
        return false;
    switch (settlement.settlement) {
        case WildcardAttemptSettlementKind::AttemptSettled:
            return settlement.mode == WildcardAttemptMode::Canonical &&
                   settlement.terminal_phase == WildcardAttemptPhase::WildcardLive &&
                   settlement.sequence == 13u;
        case WildcardAttemptSettlementKind::MutationSettled:
            return settlement.mode != WildcardAttemptMode::Canonical &&
                   settlement.terminal_phase == wildcard_rejection_checkpoint(settlement.mode) &&
                   settlement.sequence == wildcard_phase_sequence(settlement.terminal_phase) + 1u;
    }
    return false;
}

static std::vector<unsigned char> encode_wildcard_settlement(
    const WildcardAttemptSettlementV1& settlement) {
    return encode_wildcard_fields(std::array<u64, 6u>{settlement.version,
                                                      settlement.transaction_id,
                                                      static_cast<u64>(settlement.mode),
                                                      static_cast<u64>(settlement.settlement),
                                                      static_cast<u64>(settlement.terminal_phase),
                                                      settlement.sequence});
}

static bool decode_wildcard_settlement(const std::vector<unsigned char>& payload,
                                       WildcardAttemptSettlementV1& settlement) {
    std::array<u64, 6u> fields{};
    if (!decode_wildcard_fields(payload, fields) || fields[0] != kWildcardAttemptVersion ||
        fields[1] == 0u || !valid_wildcard_attempt_mode_value(fields[2]) ||
        !valid_wildcard_attempt_settlement_value(fields[3]) ||
        !valid_wildcard_attempt_phase_value(fields[4]))
        return false;
    bool valid = false;
    switch (fields[3]) {
        case static_cast<u64>(WildcardAttemptSettlementKind::AttemptSettled):
            valid = fields[2] == static_cast<u64>(WildcardAttemptMode::Canonical) &&
                    fields[4] == static_cast<u64>(WildcardAttemptPhase::WildcardLive) &&
                    fields[5] == 13u;
            break;
        case static_cast<u64>(WildcardAttemptSettlementKind::MutationSettled):
            valid = fields[2] != static_cast<u64>(WildcardAttemptMode::Canonical) &&
                    fields[4] == wildcard_rejection_checkpoint_value(fields[2]) &&
                    fields[5] == wildcard_phase_sequence_value(fields[4]) + 1u;
            break;
    }
    if (!valid) return false;
    const WildcardAttemptSettlementV1 decoded{fields[0],
                                              fields[1],
                                              static_cast<WildcardAttemptMode>(fields[2]),
                                              static_cast<WildcardAttemptSettlementKind>(fields[3]),
                                              static_cast<WildcardAttemptPhase>(fields[4]),
                                              fields[5]};
    settlement = decoded;
    return true;
}

class WildcardAttemptStateMachine {
public:
    bool begin(const WildcardAttemptCommandV1& command) {
        if (state_ != State::Empty || !valid_wildcard_command(command)) return fail();
        version_ = command.version;
        transaction_id_ = command.transaction_id;
        mode_ = command.mode;
        state_ = State::AwaitGuardHeld;
        return true;
    }

    bool observe(const WildcardAttemptPhaseV1& witness) {
        if (!bound(witness.version, witness.transaction_id, witness.mode) ||
            !valid_wildcard_phase(witness))
            return fail();
        switch (state_) {
            case State::AwaitGuardHeld:
                return accept_phase(
                    witness, WildcardAttemptPhase::GuardHeld, State::AwaitExactRutWitness);
            case State::AwaitExactRutWitness:
                return accept_phase(
                    witness, WildcardAttemptPhase::ExactRutWitness, State::AwaitCollisionPrepared);
            case State::AwaitCollisionPrepared:
                return accept_phase(witness,
                                    WildcardAttemptPhase::CollisionPrepared,
                                    State::AwaitCollisionAuthorization);
            case State::AwaitCollisionRejected:
                if (wildcard_rejection_checkpoint(mode_) == WildcardAttemptPhase::CollisionRejected)
                    return fail();
                return accept_phase(witness,
                                    WildcardAttemptPhase::CollisionRejected,
                                    State::AwaitExactCleanupAuthorization);
            case State::AwaitExactCleanedGuardHeld:
                return accept_phase(witness,
                                    WildcardAttemptPhase::ExactCleanedGuardHeld,
                                    State::AwaitGuardReleaseAuthorization);
            case State::AwaitGuardReleased:
                return accept_phase(witness,
                                    WildcardAttemptPhase::GuardReleased,
                                    State::AwaitWildcardAuthorization);
            case State::AwaitWildcardLive:
                if (mode_ != WildcardAttemptMode::Canonical) return fail();
                return accept_phase(witness,
                                    WildcardAttemptPhase::WildcardLive,
                                    State::AwaitWildcardCleanupAuthorization);
            case State::Empty:
            case State::AwaitCollisionAuthorization:
            case State::AwaitExactCleanupAuthorization:
            case State::AwaitGuardReleaseAuthorization:
            case State::AwaitWildcardAuthorization:
            case State::AwaitWildcardCleanupAuthorization:
            case State::AwaitAttemptSettlement:
            case State::AwaitFinish:
            case State::AwaitMutationSettlement:
            case State::Complete:
            case State::MutationRejected:
            case State::Failed:
                return fail();
        }
        return fail();
    }

    bool decide(const WildcardAttemptDecisionV1& decision) {
        if (!bound(decision.version, decision.transaction_id, decision.mode) ||
            !valid_wildcard_decision(decision))
            return fail();
        switch (state_) {
            case State::AwaitCollisionAuthorization:
                return accept_decision(decision,
                                       WildcardAttemptDecisionKind::AuthorizeCollisionExec,
                                       State::AwaitCollisionRejected);
            case State::AwaitCollisionRejected:
            case State::AwaitWildcardLive:
                if (decision.decision != WildcardAttemptDecisionKind::RejectAndCleanup ||
                    mode_ == WildcardAttemptMode::Canonical ||
                    decision.for_phase != wildcard_rejection_checkpoint(mode_))
                    return fail();
                state_ = State::AwaitMutationSettlement;
                return true;
            case State::AwaitExactCleanupAuthorization:
                return accept_decision(decision,
                                       WildcardAttemptDecisionKind::AuthorizeExactCleanup,
                                       State::AwaitExactCleanedGuardHeld);
            case State::AwaitGuardReleaseAuthorization:
                return accept_decision(decision,
                                       WildcardAttemptDecisionKind::AuthorizeGuardRelease,
                                       State::AwaitGuardReleased);
            case State::AwaitWildcardAuthorization:
                return accept_decision(decision,
                                       WildcardAttemptDecisionKind::AuthorizeWildcardExec,
                                       State::AwaitWildcardLive);
            case State::AwaitWildcardCleanupAuthorization:
                return accept_decision(decision,
                                       WildcardAttemptDecisionKind::AuthorizeWildcardCleanup,
                                       State::AwaitAttemptSettlement);
            case State::AwaitFinish:
                return accept_decision(
                    decision, WildcardAttemptDecisionKind::Finish, State::Complete);
            case State::Empty:
            case State::AwaitGuardHeld:
            case State::AwaitExactRutWitness:
            case State::AwaitCollisionPrepared:
            case State::AwaitExactCleanedGuardHeld:
            case State::AwaitGuardReleased:
            case State::AwaitAttemptSettlement:
            case State::AwaitMutationSettlement:
            case State::Complete:
            case State::MutationRejected:
            case State::Failed:
                return fail();
        }
        return fail();
    }

    bool settle(const WildcardAttemptSettlementV1& settlement) {
        if (!bound(settlement.version, settlement.transaction_id, settlement.mode) ||
            !valid_wildcard_settlement(settlement))
            return fail();
        if (state_ == State::AwaitAttemptSettlement &&
            settlement.settlement == WildcardAttemptSettlementKind::AttemptSettled) {
            state_ = State::AwaitFinish;
            return true;
        }
        if (state_ == State::AwaitMutationSettlement &&
            settlement.settlement == WildcardAttemptSettlementKind::MutationSettled) {
            state_ = State::MutationRejected;
            return true;
        }
        return fail();
    }

    bool complete() const { return state_ == State::Complete; }
    bool mutation_rejected() const { return state_ == State::MutationRejected; }
    bool failed() const { return state_ == State::Failed; }

private:
    enum class State {
        Empty,
        AwaitGuardHeld,
        AwaitExactRutWitness,
        AwaitCollisionPrepared,
        AwaitCollisionAuthorization,
        AwaitCollisionRejected,
        AwaitExactCleanupAuthorization,
        AwaitExactCleanedGuardHeld,
        AwaitGuardReleaseAuthorization,
        AwaitGuardReleased,
        AwaitWildcardAuthorization,
        AwaitWildcardLive,
        AwaitWildcardCleanupAuthorization,
        AwaitAttemptSettlement,
        AwaitFinish,
        AwaitMutationSettlement,
        Complete,
        MutationRejected,
        Failed,
    };

    bool bound(u64 version, u64 transaction_id, WildcardAttemptMode mode) const {
        return state_ != State::Empty && state_ != State::Complete &&
               state_ != State::MutationRejected && state_ != State::Failed &&
               version == version_ && transaction_id == transaction_id_ && mode == mode_;
    }

    bool accept_phase(const WildcardAttemptPhaseV1& witness,
                      WildcardAttemptPhase expected,
                      State next) {
        if (witness.phase != expected) return fail();
        state_ = next;
        return true;
    }

    bool accept_decision(const WildcardAttemptDecisionV1& decision,
                         WildcardAttemptDecisionKind expected,
                         State next) {
        if (decision.decision != expected) return fail();
        state_ = next;
        return true;
    }

    bool fail() {
        state_ = State::Failed;
        return false;
    }

    State state_ = State::Empty;
    u64 version_ = 0u;
    u64 transaction_id_ = 0u;
    WildcardAttemptMode mode_ = WildcardAttemptMode::Canonical;
};

static std::vector<unsigned char> executable_lease_payload(const ExecutableLease& lease) {
    std::vector<unsigned char> payload;
    payload.reserve(7u * sizeof(u64) + lease.path.size());
    append_u64(payload, 1u);
    append_u64(payload, static_cast<u64>(lease.status.st_dev));
    append_u64(payload, static_cast<u64>(lease.status.st_ino));
    append_u64(payload, static_cast<u64>(lease.status.st_mode));
    append_u64(payload, static_cast<u64>(lease.status.st_uid));
    append_u64(payload, static_cast<u64>(lease.status.st_gid));
    append_u64(payload, lease.path.size());
    payload.insert(payload.end(), lease.path.begin(), lease.path.end());
    return payload;
}

static bool parse_executable_lease(const std::vector<unsigned char>& payload,
                                   std::string& path,
                                   struct stat& expected) {
    path.clear();
    expected = {};
    if (payload.size() < 7u * sizeof(u64)) return false;
    const u64 version = read_u64(payload.data());
    const u64 dev = read_u64(payload.data() + sizeof(u64));
    const u64 ino = read_u64(payload.data() + 2u * sizeof(u64));
    const u64 mode = read_u64(payload.data() + 3u * sizeof(u64));
    const u64 uid = read_u64(payload.data() + 4u * sizeof(u64));
    const u64 gid = read_u64(payload.data() + 5u * sizeof(u64));
    const u64 length = read_u64(payload.data() + 6u * sizeof(u64));
    if (version != 1u || length == 0u || length > PATH_MAX ||
        length != payload.size() - 7u * sizeof(u64) || dev > std::numeric_limits<dev_t>::max() ||
        ino > std::numeric_limits<ino_t>::max() || mode > std::numeric_limits<mode_t>::max() ||
        uid > std::numeric_limits<uid_t>::max() || gid > std::numeric_limits<gid_t>::max())
        return false;
    path.assign(reinterpret_cast<const char*>(payload.data() + 7u * sizeof(u64)),
                static_cast<std::size_t>(length));
    if (path.front() != '/' || path.find('\0') != std::string::npos) return false;
    expected.st_dev = static_cast<dev_t>(dev);
    expected.st_ino = static_cast<ino_t>(ino);
    expected.st_mode = static_cast<mode_t>(mode);
    expected.st_uid = static_cast<uid_t>(uid);
    expected.st_gid = static_cast<gid_t>(gid);
    return S_ISREG(expected.st_mode) && (expected.st_mode & 0111) != 0 &&
           (expected.st_mode & 0022) == 0;
}

static std::vector<unsigned char> encode_exact_report(const ExactRutReport& report) {
    const std::array<u64, kExactReportFields> fields{
        report.version,
        report.child_pid,
        report.child_start,
        report.child_ppid,
        report.child_pgid,
        report.child_sid,
        report.child_uid,
        report.child_gid,
        report.child_netns,
        report.child_exe_dev,
        report.child_exe_ino,
        report.pidfd,
        report.pidfd_cloexec,
        report.listener_inode,
        report.source_dev,
        report.source_ino,
        report.log_dev,
        report.log_ino,
        report.target_fd_count,
        report.response_bytes,
        report.response_exact,
        report.prompt_eof,
        report.guard_connect_error,
        report.stable,
        report.backend,
    };
    std::vector<unsigned char> payload;
    payload.reserve(fields.size() * sizeof(u64));
    for (u64 field : fields) append_u64(payload, field);
    return payload;
}

static bool decode_exact_report(const std::vector<unsigned char>& payload, ExactRutReport& report) {
    report = {};
    if (payload.size() != kExactReportFields * sizeof(u64)) return false;
    std::array<u64, kExactReportFields> fields{};
    for (std::size_t i = 0u; i < kExactReportFields; ++i)
        fields[i] = read_u64(payload.data() + i * sizeof(u64));
    if (fields[0] != kExactProtocolVersion) return false;
    report = {fields[0],  fields[1],  fields[2],  fields[3],  fields[4],  fields[5],  fields[6],
              fields[7],  fields[8],  fields[9],  fields[10], fields[11], fields[12], fields[13],
              fields[14], fields[15], fields[16], fields[17], fields[18], fields[19], fields[20],
              fields[21], fields[22], fields[23], fields[24]};
    return report.version == kExactProtocolVersion;
}

static std::vector<unsigned char> encode_exact_cleaned(const ExactRutCleanedReport& report) {
    const std::array<u64, kExactCleanedFields> fields{
        report.version,
        report.child_pid,
        report.child_start,
        report.listener_inode,
        report.clean_exit,
        report.pidfd_invalidated,
        report.child_absent,
        report.listener_absent,
        report.temps_absent,
        report.target_fd_count,
        report.guard_connect_error,
    };
    std::vector<unsigned char> payload;
    payload.reserve(fields.size() * sizeof(u64));
    for (u64 field : fields) append_u64(payload, field);
    return payload;
}

static bool decode_exact_cleaned(const std::vector<unsigned char>& payload,
                                 ExactRutCleanedReport& report) {
    report = {};
    if (payload.size() != kExactCleanedFields * sizeof(u64)) return false;
    std::array<u64, kExactCleanedFields> fields{};
    for (std::size_t i = 0u; i < kExactCleanedFields; ++i)
        fields[i] = read_u64(payload.data() + i * sizeof(u64));
    if (fields[0] != kExactProtocolVersion) return false;
    report = {fields[0],
              fields[1],
              fields[2],
              fields[3],
              fields[4],
              fields[5],
              fields[6],
              fields[7],
              fields[8],
              fields[9],
              fields[10]};
    return report.version == kExactProtocolVersion;
}

static std::vector<unsigned char> exact_cleanup_payload() {
    std::vector<unsigned char> payload;
    append_u64(payload, kExactProtocolVersion);
    return payload;
}

static bool exact_cleanup_request(const Frame& request, const Token& token) {
    return request.type == kExactRutCleanup && token_equal(request.token, token) &&
           request.payload.size() == sizeof(u64) &&
           read_u64(request.payload.data()) == kExactProtocolVersion;
}

static bool valid_exact_failure_phase(ExactFailurePhase phase) {
    const u64 value = static_cast<u64>(phase);
    return value >= static_cast<u64>(ExactFailurePhase::LeaseReopen) &&
           value <= static_cast<u64>(ExactFailurePhase::Cleanup);
}

static const char* exact_failure_phase_name(ExactFailurePhase phase) {
    switch (phase) {
        case ExactFailurePhase::LeaseReopen:
            return "lease/reopen";
        case ExactFailurePhase::Temp:
            return "temp";
        case ExactFailurePhase::ForkPreExec:
            return "fork/pre-exec";
        case ExactFailurePhase::Exec:
            return "exec";
        case ExactFailurePhase::PidfdIdentity:
            return "pidfd/identity";
        case ExactFailurePhase::ListenerLog:
            return "listener/log";
        case ExactFailurePhase::HttpEof:
            return "HTTP/EOF";
        case ExactFailurePhase::GuardRefusal:
            return "guard-refusal";
        case ExactFailurePhase::StabilityFd:
            return "stability/FD";
        case ExactFailurePhase::Cleanup:
            return "cleanup";
    }
    return "invalid";
}

static std::vector<unsigned char> encode_exact_failure(const ExactFailureReport& report) {
    std::vector<unsigned char> payload;
    payload.reserve(7u * sizeof(u64));
    append_u64(payload, report.version);
    append_u64(payload, static_cast<u64>(report.phase));
    append_u64(payload, report.error_number);
    append_u64(payload, report.count);
    append_u64(payload, report.escrow_required);
    append_u64(payload, report.child_pid);
    append_u64(payload, report.child_start);
    return payload;
}

static bool decode_exact_failure(const std::vector<unsigned char>& payload,
                                 ExactFailureReport& report) {
    report = {};
    if (payload.size() != 7u * sizeof(u64)) return false;
    const u64 version = read_u64(payload.data());
    const auto phase = static_cast<ExactFailurePhase>(read_u64(payload.data() + sizeof(u64)));
    const u64 error_number = read_u64(payload.data() + 2u * sizeof(u64));
    const u64 count = read_u64(payload.data() + 3u * sizeof(u64));
    const u64 escrow_required = read_u64(payload.data() + 4u * sizeof(u64));
    const u64 child_pid = read_u64(payload.data() + 5u * sizeof(u64));
    const u64 child_start = read_u64(payload.data() + 6u * sizeof(u64));
    if (version != 2u || !valid_exact_failure_phase(phase) ||
        error_number > static_cast<u64>(std::numeric_limits<int>::max()) || count > 1024u ||
        escrow_required > 1u || (escrow_required != 0u && (child_pid <= 1u || child_start == 0u)) ||
        (escrow_required == 0u && (child_pid != 0u || child_start != 0u)))
        return false;
    report = {version, phase, error_number, count, escrow_required, child_pid, child_start};
    return true;
}

static std::vector<unsigned char> encode_exact_custody(const ExactCustodyRecord& record,
                                                       const Token& token) {
    std::vector<unsigned char> wire;
    wire.reserve(kTokenBytes + kExactCustodyFields * sizeof(u64));
    wire.insert(wire.end(), token.bytes.begin(), token.bytes.end());
    for (u64 field :
         {record.version,       record.child_pid,      record.child_start,   record.child_exe_dev,
          record.child_exe_ino, record.listener_inode, record.positive_ipv4, record.guard_ipv4,
          record.port,          record.guard_inode,    record.netns,         record.directory_dev,
          record.directory_ino, record.source_dev,     record.source_ino,    record.log_dev,
          record.log_ino,       record.target_pid,     record.target_start,  record.has_pidfd,
          record.child_reaped})
        append_u64(wire, field);
    return wire;
}

static bool decode_exact_custody(const std::vector<unsigned char>& wire,
                                 const Token& token,
                                 ExactCustodyRecord& record) {
    record = {};
    if (wire.size() != kTokenBytes + kExactCustodyFields * sizeof(u64) ||
        !std::equal(token.bytes.begin(), token.bytes.end(), wire.begin()))
        return false;
    std::array<u64, kExactCustodyFields> fields{};
    for (std::size_t i = 0; i != fields.size(); ++i)
        fields[i] = read_u64(wire.data() + kTokenBytes + i * sizeof(u64));
    if (fields[0] != kExactCustodyVersion || fields[1] <= 1u || fields[2] == 0u ||
        fields[6] > std::numeric_limits<u32>::max() ||
        fields[7] > std::numeric_limits<u32>::max() || fields[8] == 0u ||
        fields[8] > std::numeric_limits<u16>::max() || fields[9] == 0u || fields[10] == 0u ||
        fields[11] == 0u || fields[12] == 0u || fields[14] == 0u || fields[16] == 0u ||
        fields[17] <= 1u || fields[18] == 0u || fields[19] > 1u || fields[20] > 1u ||
        (fields[20] != 0u && fields[19] != 0u))
        return false;
    record = {fields[0],  fields[1],  fields[2],  fields[3],  fields[4],  fields[5],  fields[6],
              fields[7],  fields[8],  fields[9],  fields[10], fields[11], fields[12], fields[13],
              fields[14], fields[15], fields[16], fields[17], fields[18], fields[19], fields[20]};
    return true;
}

static std::vector<unsigned char> encode_exact_settled(const ExactSettledRecord& settled) {
    std::vector<unsigned char> payload;
    payload.reserve(kExactSettledFields * sizeof(u64));
    for (u64 field : {settled.version,
                      settled.target_pid,
                      settled.child_pid,
                      settled.child_start,
                      settled.guard_inode,
                      settled.adopted,
                      settled.reaped,
                      settled.listener_absent,
                      settled.temps_absent,
                      settled.competing_bind_error,
                      settled.guard_closed})
        append_u64(payload, field);
    return payload;
}

static bool decode_exact_settled(const std::vector<unsigned char>& payload,
                                 ExactSettledRecord& settled) {
    settled = {};
    if (payload.size() != kExactSettledFields * sizeof(u64)) return false;
    std::array<u64, kExactSettledFields> fields{};
    for (std::size_t i = 0; i != fields.size(); ++i)
        fields[i] = read_u64(payload.data() + i * sizeof(u64));
    if (fields[0] != kExactSettledVersion || fields[1] <= 1u || fields[2] <= 1u ||
        fields[3] == 0u || fields[4] == 0u || fields[5] > 1u || fields[6] > 1u || fields[7] > 1u ||
        fields[8] > 1u || fields[9] > static_cast<u64>(std::numeric_limits<int>::max()) ||
        fields[10] > 1u)
        return false;
    settled = {fields[0],
               fields[1],
               fields[2],
               fields[3],
               fields[4],
               fields[5],
               fields[6],
               fields[7],
               fields[8],
               fields[9],
               fields[10]};
    return true;
}

static bool exact_settlement_complete(const ExactSettledRecord& settled,
                                      pid_t expected_target,
                                      u64 expected_guard_inode,
                                      bool require_adopted = true) {
    return settled.target_pid == static_cast<u64>(expected_target) &&
           settled.guard_inode == expected_guard_inode &&
           (!require_adopted || settled.adopted == 1u) && settled.reaped == 1u &&
           settled.listener_absent == 1u && settled.temps_absent == 1u &&
           settled.competing_bind_error == EADDRINUSE && settled.guard_closed == 1u;
}

static bool exact_settlement_matches_failure(const ExactSettledRecord& settled,
                                             const ExactFailureReport& failure) {
    return failure.escrow_required == 1u && settled.child_pid == failure.child_pid &&
           settled.child_start == failure.child_start;
}

static bool exact_injected_cleanup_failure(const ExactFailureReport& failure,
                                           const ExactRutReport& witness) {
    return failure.phase == ExactFailurePhase::Cleanup && failure.error_number == ETIMEDOUT &&
           failure.count > 0u && failure.escrow_required == 1u &&
           failure.child_pid == witness.child_pid && failure.child_start == witness.child_start;
}

enum class ExactFailureIntegrationStage { Failure, Settlement, TargetExit, Complete };

static bool advance_exact_failure_integration(ExactFailureIntegrationStage& stage, u16 frame_type) {
    if (stage == ExactFailureIntegrationStage::Failure && frame_type == kExactRutFailure)
        stage = ExactFailureIntegrationStage::Settlement;
    else if (stage == ExactFailureIntegrationStage::Settlement && frame_type == kExactEscrowSettled)
        stage = ExactFailureIntegrationStage::TargetExit;
    else if (stage == ExactFailureIntegrationStage::TargetExit && frame_type == kTargetExited)
        stage = ExactFailureIntegrationStage::Complete;
    else
        return false;
    return true;
}

static bool receive_failed_target_lifecycle(
    int broker_fd,
    const Token& token,
    pid_t expected_target,
    const ExactFailureReport& failure,
    u64 expected_guard_inode,
    std::string& error,
    ExactFailureIntegrationStage* integration_stage = nullptr) {
    Frame record;
    bool settlement_received = false;
    if (!receive_frame(broker_fd, record, kListenerDeadlineMs)) {
        error += "; dropped failure lifecycle timed out";
        return false;
    }
    if (record.type == kExactEscrowSettled) {
        ExactSettledRecord settled;
        if ((integration_stage != nullptr &&
             !advance_exact_failure_integration(*integration_stage, record.type)) ||
            !token_equal(record.token, token) || !decode_exact_settled(record.payload, settled) ||
            !exact_settlement_matches_failure(settled, failure) ||
            !exact_settlement_complete(
                settled, expected_target, expected_guard_inode, integration_stage != nullptr) ||
            !receive_frame(broker_fd, record, kHandshakeMs)) {
            error += "; malformed or incomplete failure-settled evidence";
            return false;
        }
        settlement_received = true;
    }
    if ((failure.escrow_required != 0u) != settlement_received) {
        error += "; required failure-settled evidence was missing or out of order";
        return false;
    }
    if ((integration_stage != nullptr &&
         !advance_exact_failure_integration(*integration_stage, record.type)) ||
        record.type != kTargetExited || !token_equal(record.token, token) ||
        record.payload.size() != 4u) {
        error += "; missing failed Target exit evidence";
        return false;
    }
    const int status =
        static_cast<int>(record.payload[0]) | (static_cast<int>(record.payload[1]) << 8) |
        (static_cast<int>(record.payload[2]) << 16) | (static_cast<int>(record.payload[3]) << 24);
    Frame released;
    if ((!WIFEXITED(status) || WEXITSTATUS(status) == 0) && !WIFSIGNALED(status)) {
        error += "; failed Target reported success";
        return false;
    }
    if (!send_frame(broker_fd, Frame{kRelease, token, {}}, kHandshakeMs) ||
        !receive_frame(broker_fd, released, kHandshakeMs) || released.type != kReleased ||
        !token_equal(released.token, token) || !released.payload.empty()) {
        error += "; dropped failure release handshake failed";
        return false;
    }
    return true;
}

static void close_rights_in_message(msghdr& message) {
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0) || header->cmsg_len > message.msg_controllen)
            continue;
        const std::size_t bytes = header->cmsg_len - CMSG_LEN(0);
        const int* fds = reinterpret_cast<const int*>(CMSG_DATA(header));
        for (std::size_t i = 0; i != bytes / sizeof(int); ++i)
            if (fds[i] >= 0) close(fds[i]);
    }
}

enum class ExactCustodyPeek { Record, Eof, Retry, Error };
enum class ExactPostReapCustodyAction { Receive, ReturnExited, Retry, Hold };

static ExactPostReapCustodyAction exact_post_reap_custody_action(ExactCustodyPeek peek) {
    if (peek == ExactCustodyPeek::Record) return ExactPostReapCustodyAction::Receive;
    if (peek == ExactCustodyPeek::Eof) return ExactPostReapCustodyAction::ReturnExited;
    if (peek == ExactCustodyPeek::Retry) return ExactPostReapCustodyAction::Retry;
    return ExactPostReapCustodyAction::Hold;
}

static ExactCustodyPeek peek_exact_custody(int fd, bool peer_hup) {
    unsigned char byte = 0u;
    alignas(cmsghdr)
        std::array<unsigned char, CMSG_SPACE(3 * sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))>
            control{};
    iovec vector{&byte, 1u};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1u;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do {
        received = recvmsg(fd, &message, MSG_PEEK | MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK ? ExactCustodyPeek::Retry
                                                       : ExactCustodyPeek::Error;
    const bool ancillary_present = CMSG_FIRSTHDR(&message) != nullptr;
    close_rights_in_message(message);
    if (received > 0 || ancillary_present || (message.msg_flags & MSG_CTRUNC) != 0)
        return ExactCustodyPeek::Record;
    return peer_hup ? ExactCustodyPeek::Eof : ExactCustodyPeek::Record;
}

static bool send_exact_custody(int fd,
                               const Token& token,
                               const ExactCustodyRecord& record,
                               const ExactEscrowRights& rights,
                               std::chrono::steady_clock::time_point deadline) {
    const std::vector<unsigned char> wire = encode_exact_custody(record, token);
    std::array<int, 3> fds{rights.guard, rights.pidfd, rights.directory};
    const std::size_t count = record.has_pidfd != 0u ? 3u : 2u;
    if (record.has_pidfd == 0u) fds[1] = rights.directory;
    if (fd < 0 || rights.guard < 0 || rights.directory < 0 ||
        (record.has_pidfd != 0u && rights.pidfd < 0) || !wait_fd(fd, POLLOUT, deadline))
        return false;
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(3 * sizeof(int))> control{};
    iovec vector{const_cast<unsigned char*>(wire.data()), wire.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), fds.data(), count * sizeof(int));
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == static_cast<ssize_t>(wire.size());
}

static bool receive_exact_custody(int fd,
                                  const Token& token,
                                  pid_t expected_target,
                                  uid_t expected_uid,
                                  gid_t expected_gid,
                                  std::chrono::steady_clock::time_point deadline,
                                  ExactCustodyRecord& record,
                                  ExactEscrowRights& rights) {
    rights.close_all();
    if (fd < 0 || !wait_fd(fd, POLLIN, deadline)) return false;
    std::vector<unsigned char> wire(kTokenBytes + kExactCustodyFields * sizeof(u64));
    alignas(cmsghdr)
        std::array<unsigned char, CMSG_SPACE(3 * sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))>
            control{};
    iovec vector{wire.data(), wire.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t received;
    do {
        received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<ssize_t>(wire.size()) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
        !decode_exact_custody(wire, token, record)) {
        close_rights_in_message(message);
        return false;
    }
    const cmsghdr* rights_header = nullptr;
    const cmsghdr* credentials_header = nullptr;
    std::size_t header_count = 0u;
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        ++header_count;
        if (header->cmsg_level != SOL_SOCKET) continue;
        if (header->cmsg_type == SCM_RIGHTS && rights_header == nullptr)
            rights_header = header;
        else if (header->cmsg_type == SCM_CREDENTIALS && credentials_header == nullptr)
            credentials_header = header;
    }
    const std::size_t expected_count = record.has_pidfd != 0u ? 3u : 2u;
    if (header_count != 2u || rights_header == nullptr || credentials_header == nullptr ||
        rights_header->cmsg_len != CMSG_LEN(expected_count * sizeof(int)) ||
        credentials_header->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
        close_rights_in_message(message);
        return false;
    }
    struct ucred credentials{};
    memcpy(&credentials, CMSG_DATA(credentials_header), sizeof(credentials));
    if (credentials.pid != expected_target || credentials.uid != expected_uid ||
        credentials.gid != expected_gid || record.target_pid != static_cast<u64>(expected_target)) {
        close_rights_in_message(message);
        return false;
    }
    std::array<int, 3> fds{-1, -1, -1};
    memcpy(fds.data(), CMSG_DATA(rights_header), expected_count * sizeof(int));
    rights.guard = fds[0];
    rights.pidfd = record.has_pidfd != 0u ? fds[1] : -1;
    rights.directory = record.has_pidfd != 0u ? fds[2] : fds[1];
    return rights.guard >= 0 && rights.directory >= 0 &&
           (record.has_pidfd == 0u || rights.pidfd >= 0);
}

static std::vector<unsigned char> exact_custody_ack(const Token& token) {
    std::vector<unsigned char> wire;
    wire.reserve(kTokenBytes + sizeof(u64));
    wire.insert(wire.end(), token.bytes.begin(), token.bytes.end());
    append_u64(wire, kExactCustodyVersion);
    return wire;
}

static bool send_exact_custody_ack(int fd,
                                   const Token& token,
                                   std::chrono::steady_clock::time_point deadline) {
    const std::vector<unsigned char> wire = exact_custody_ack(token);
    if (!wait_fd(fd, POLLOUT, deadline)) return false;
    ssize_t sent;
    do {
        sent = send(fd, wire.data(), wire.size(), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == static_cast<ssize_t>(wire.size());
}

static bool receive_exact_custody_ack(int fd,
                                      const Token& token,
                                      pid_t expected_dropped,
                                      uid_t expected_uid,
                                      gid_t expected_gid,
                                      std::chrono::steady_clock::time_point deadline) {
    const std::vector<unsigned char> expected = exact_custody_ack(token);
    std::vector<unsigned char> wire(expected.size());
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(struct ucred))> control{};
    iovec vector{wire.data(), wire.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    if (!wait_fd(fd, POLLIN, deadline)) return false;
    ssize_t received;
    do {
        received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    cmsghdr* only = CMSG_FIRSTHDR(&message);
    if (received != static_cast<ssize_t>(wire.size()) || wire != expected ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || only == nullptr ||
        CMSG_NXTHDR(&message, only) != nullptr || only->cmsg_level != SOL_SOCKET ||
        only->cmsg_type != SCM_CREDENTIALS || only->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
        close_rights_in_message(message);
        return false;
    }
    struct ucred credentials{};
    memcpy(&credentials, CMSG_DATA(only), sizeof(credentials));
    return credentials.pid == expected_dropped && credentials.uid == expected_uid &&
           credentials.gid == expected_gid;
}

static std::vector<unsigned char> guard_request_payload(u32 positive_ipv4, u32 guard_ipv4) {
    std::vector<unsigned char> payload;
    payload.reserve(2u * sizeof(u64));
    append_u64(payload, positive_ipv4);
    append_u64(payload, guard_ipv4);
    return payload;
}

static bool parse_guard_request(const std::vector<unsigned char>& payload,
                                u32& positive_ipv4,
                                u32& guard_ipv4) {
    if (payload.size() != 2u * sizeof(u64)) return false;
    const u64 positive = read_u64(payload.data());
    const u64 guard = read_u64(payload.data() + sizeof(u64));
    if (positive > std::numeric_limits<u32>::max() || guard > std::numeric_limits<u32>::max())
        return false;
    positive_ipv4 = static_cast<u32>(positive);
    guard_ipv4 = static_cast<u32>(guard);
    privileged_listener::ListenerPlan plan{positive_ipv4, guard_ipv4, 1u};
    privileged_listener::ListenerPlanText text;
    privileged_listener::Diagnostic diagnostic;
    return privileged_listener::validate_listener_plan(plan, text, diagnostic);
}

// Canonical collision/release keeps the existing two-address guard request but
// carries the already pinned RUT pathname in a bounded, length-delimited tail.
// The Target reopens and pins this name itself; the parent never passes an FD.
static std::vector<unsigned char> canonical_request_payload(u32 positive_ipv4,
                                                            u32 guard_ipv4,
                                                            const std::string& executable) {
    std::vector<unsigned char> payload = guard_request_payload(positive_ipv4, guard_ipv4);
    append_u64(payload, executable.size());
    payload.insert(payload.end(), executable.begin(), executable.end());
    return payload;
}

static bool parse_canonical_request(const std::vector<unsigned char>& payload,
                                    u32& positive_ipv4,
                                    u32& guard_ipv4,
                                    std::string& executable) {
    executable.clear();
    if (payload.size() < 3u * sizeof(u64)) return false;
    std::vector<unsigned char> guard_payload(payload.begin(), payload.begin() + 2u * sizeof(u64));
    if (!parse_guard_request(guard_payload, positive_ipv4, guard_ipv4)) return false;
    const u64 length = read_u64(payload.data() + 2u * sizeof(u64));
    if (length == 0u || length > PATH_MAX || length != payload.size() - 3u * sizeof(u64) ||
        length > collision_evidence::kMaxSourcePath)
        return false;
    executable.assign(reinterpret_cast<const char*>(payload.data() + 3u * sizeof(u64)),
                      static_cast<std::size_t>(length));
    return executable.front() == '/' && executable.find('\0') == std::string::npos;
}

static ssize_t canonical_source_pread(int fd, void* buffer, std::size_t size, off_t offset) {
    return pread(fd, buffer, size, offset);
}

static collision_evidence::Proc13 canonical_proc13(const ProcIdentity& value) {
    return {static_cast<u64>(value.pid),
            static_cast<u64>(value.ppid),
            static_cast<u64>(value.sid),
            value.start,
            static_cast<u64>(value.pgid),
            static_cast<u64>(value.uid),
            static_cast<u64>(value.gid),
            static_cast<u64>(value.netns),
            static_cast<u64>(value.exe_dev),
            static_cast<u64>(value.exe_ino),
            value.no_new_privs ? 1u : 0u,
            value.capabilities_clear ? 1u : 0u,
            static_cast<u64>(value.supplementary_groups)};
}

static collision_evidence::ProcPair canonical_proc_pair(
    const public_attempt::PublicRutAttemptLease& attempt_lease, bool live) {
    collision_evidence::ProcPair value;
    if (!live) return value;
    value.first_tag = 1u;
    value.second_tag = 1u;
    value.first = canonical_proc13(attempt_lease.exec_observation().first);
    value.second = canonical_proc13(attempt_lease.exec_observation().second);
    return value;
}

static collision_evidence::Settlement9 canonical_settlement(
    const std::shared_ptr<const public_attempt::child::SettlementReceipt>& receipt) {
    if (!receipt) return {};
    return {static_cast<u64>(receipt->child_pid),
            static_cast<u64>(receipt->identity.pid),
            static_cast<u64>(receipt->identity.ppid),
            receipt->identity.start,
            static_cast<u64>(receipt->identity.netns),
            receipt->terminal ? 1u : 0u,
            receipt->reaped ? 1u : 0u,
            static_cast<u64>(receipt->wait_status),
            static_cast<u64>(receipt->error_number)};
}

static collision_evidence::Cleanup14 canonical_cleanup(
    const std::shared_ptr<const public_attempt::CleanupState>& value) {
    if (!value) return {};
    return {value->destructor_attempted ? 1u : 0u,
            value->destructor_reportable_success ? 1u : 0u,
            value->child_attempted ? 1u : 0u,
            value->child_settled ? 1u : 0u,
            value->handoff_attempted ? 1u : 0u,
            value->handoff_closed ? 1u : 0u,
            value->null_attempted ? 1u : 0u,
            value->null_closed ? 1u : 0u,
            value->capture_settle_attempted ? 1u : 0u,
            value->capture_settled ? 1u : 0u,
            value->capture_close_attempted ? 1u : 0u,
            value->capture_closed ? 1u : 0u,
            static_cast<u64>(value->diagnostic.phase),
            static_cast<u64>(value->diagnostic.error_number)};
}

static bool canonical_proc_link(int fd, std::string& link) {
    link.clear();
    if (fd < 0) return false;
    std::array<char, collision_evidence::kMaxProcLink + 1u> buffer{};
    const ssize_t length = readlink((std::string("/proc/self/fd/") + std::to_string(fd)).c_str(),
                                    buffer.data(),
                                    buffer.size() - 1u);
    if (length <= 0 || static_cast<std::size_t>(length) >= buffer.size()) return false;
    link.assign(buffer.data(), static_cast<std::size_t>(length));
    return link.starts_with("socket:[") && link.back() == ']';
}

static bool canonical_socket_fields(int fd,
                                    u64& g_fgetfd,
                                    u64& g_fgetfl,
                                    u64& mode,
                                    u64& device,
                                    u64& rdevice,
                                    u64& domain,
                                    u64& type,
                                    u64& protocol,
                                    u64& reuseaddr,
                                    u64& reuseport,
                                    u64& acceptconn,
                                    u64& inode,
                                    std::string& proc_link) {
    struct stat status{};
    const int fgetfd = fcntl(fd, F_GETFD);
    const int fgetfl = fcntl(fd, F_GETFL);
    int socket_domain = 0, socket_type = 0, socket_protocol = 0;
    int socket_reuseaddr = 0, socket_reuseport = 0, socket_acceptconn = 0;
    socklen_t size = sizeof(int);
    if (fd < 0 || fgetfd < 0 || fgetfl < 0 || fstat(fd, &status) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &socket_domain, &size) != 0)
        return false;
    size = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &size) != 0) return false;
    size = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &socket_protocol, &size) != 0) return false;
    size = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &socket_reuseaddr, &size) != 0) return false;
    size = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &socket_reuseport, &size) != 0) return false;
    size = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &socket_acceptconn, &size) != 0) return false;
    if (!canonical_proc_link(fd, proc_link)) return false;
    g_fgetfd = static_cast<u64>(fgetfd);
    g_fgetfl = static_cast<u64>(fgetfl);
    mode = static_cast<u64>(status.st_mode);
    device = static_cast<u64>(status.st_dev);
    rdevice = static_cast<u64>(status.st_rdev);
    domain = static_cast<u64>(socket_domain);
    type = static_cast<u64>(socket_type);
    protocol = static_cast<u64>(socket_protocol);
    reuseaddr = static_cast<u64>(socket_reuseaddr);
    reuseport = static_cast<u64>(socket_reuseport);
    acceptconn = static_cast<u64>(socket_acceptconn);
    inode = static_cast<u64>(status.st_ino);
    return S_ISSOCK(status.st_mode) && inode != 0u &&
           proc_link == "socket:[" + std::to_string(inode) + "]";
}

static bool canonical_reservation_source(
    const exact_reservation::ExactTcpReservationLease& reservation,
    const source_lease::WildcardAttemptSourceLease& source,
    const private_directory::PrivateDirectoryLease& directory,
    const std::string& source_bytes,
    const ProcIdentity& target,
    collision_evidence::ReservationSource& report) {
    report = {};
    struct stat source_status{};
    if (!source.active() || source.state() != source_lease::State::Active ||
        reservation.state() != exact_reservation::State::Held ||
        fstat(source.descriptor(), &source_status) != 0 || !S_ISREG(source_status.st_mode) ||
        source_status.st_nlink != 1 || source_status.st_size < 0 ||
        static_cast<u64>(source_status.st_size) != source_bytes.size())
        return false;
    u64 g_fgetfd = 0u, g_fgetfl = 0u, mode = 0u, device = 0u, rdevice = 0u, domain = 0u, type = 0u;
    u64 protocol = 0u, reuseaddr = 0u, reuseport = 0u, acceptconn = 0u, inode = 0u;
    std::string proc_link;
    source_lease::Diagnostic source_diagnostic;
    if (!canonical_socket_fields(reservation.descriptor(),
                                 g_fgetfd,
                                 g_fgetfl,
                                 mode,
                                 device,
                                 rdevice,
                                 domain,
                                 type,
                                 protocol,
                                 reuseaddr,
                                 reuseport,
                                 acceptconn,
                                 inode,
                                 proc_link))
        return false;
    if (!source_lease::read_exact_bytes_for_testing(
            source.descriptor(), source_bytes, canonical_source_pread, source_diagnostic))
        return false;
    report.reservation_state = static_cast<u64>(collision_evidence::ReservationState::Held);
    report.g_fd = static_cast<u64>(reservation.descriptor());
    report.g_f_getfd = g_fgetfd;
    report.g_f_getfl = g_fgetfl;
    report.ipv4 = reservation.ipv4();
    report.port = reservation.port();
    report.dev = device;
    report.ino = inode;
    report.mode = mode;
    report.rdev = rdevice;
    report.socket_domain = domain;
    report.socket_type = type;
    report.socket_protocol = protocol;
    report.reuseaddr = reuseaddr;
    report.reuseport = reuseport;
    report.acceptconn = acceptconn;
    report.proc_link_len = proc_link.size();
    report.proc_link = proc_link;
    report.directory_dev = directory.identity().device;
    report.directory_ino = directory.identity().inode;
    report.directory_mode = directory.identity().mode;
    report.directory_uid = directory.identity().uid;
    report.directory_gid = directory.identity().gid;
    report.source_state = static_cast<u64>(collision_evidence::SourceState::Active);
    report.source_dev = static_cast<u64>(source_status.st_dev);
    report.source_ino = static_cast<u64>(source_status.st_ino);
    report.source_mode = static_cast<u64>(source_status.st_mode);
    report.source_uid = static_cast<u64>(source_status.st_uid);
    report.source_gid = static_cast<u64>(source_status.st_gid);
    report.source_size = static_cast<u64>(source_status.st_size);
    report.source_nlink = static_cast<u64>(source_status.st_nlink);
    report.path_len = source.path().size();
    report.bytes_len = source_bytes.size();
    report.source_path = source.path();
    report.source_bytes = source_bytes;
    return report.g_fd != 0u && report.ino == inode && target.pid > 1 &&
           report.path_len <= collision_evidence::kMaxSourcePath &&
           report.bytes_len <= collision_evidence::kMaxSourceBytes &&
           report.source_path.front() == '/';
}

static collision_evidence::Envelope canonical_envelope_from_frame(
    const Frame& frame, collision_evidence::ReportKind expected_kind) {
    collision_evidence::Envelope value;
    if (frame.type != collision_evidence::kEvidenceFrameType ||
        frame.payload.size() < collision_evidence::kEnvelopeBytes)
        return value;
    std::array<u64, 11u> fields{};
    for (std::size_t index = 0u; index != fields.size(); ++index)
        fields[index] = read_u64(frame.payload.data() + index * sizeof(u64));
    value.version = fields[0];
    value.transaction = fields[1];
    value.domain = fields[2];
    value.kind = static_cast<collision_evidence::ReportKind>(fields[3]);
    value.binding = static_cast<collision_evidence::Binding>(fields[4]);
    value.phase = static_cast<collision_evidence::Phase>(fields[5]);
    value.sequence = fields[6];
    value.target = {fields[7], fields[8], fields[9]};
    if (value.kind != expected_kind ||
        fields[10] != frame.payload.size() - collision_evidence::kEnvelopeBytes)
        return {};
    return value;
}

static collision_evidence::Envelope canonical_expected_envelope(
    u64 transaction,
    const collision_evidence::Target& target,
    collision_evidence::ReportKind kind,
    collision_evidence::Binding binding,
    collision_evidence::Phase phase,
    u64 sequence) {
    collision_evidence::Envelope value;
    value.transaction = transaction;
    value.kind = kind;
    value.binding = binding;
    value.phase = phase;
    value.sequence = sequence;
    value.target = target;
    return value;
}

static bool canonical_send_evidence(int fd,
                                    const Token& token,
                                    const Frame& frame,
                                    std::size_t maximum,
                                    std::chrono::steady_clock::time_point deadline) {
    evidence_transport::Diagnostic diagnostic;
    return evidence_transport::send_frame(fd, token, maximum, deadline, frame, diagnostic);
}

static bool canonical_receive_evidence(int fd,
                                       const Token& token,
                                       std::size_t maximum,
                                       std::chrono::steady_clock::time_point deadline,
                                       Frame& frame) {
    evidence_transport::Diagnostic diagnostic;
    return evidence_transport::receive_frame(fd, token, maximum, deadline, frame, diagnostic);
}

static bool canonical_random_transaction(u64& transaction) {
    transaction = 0u;
    for (;;) {
        const ssize_t count = getrandom(&transaction, sizeof(transaction), GRND_NONBLOCK);
        if (count == static_cast<ssize_t>(sizeof(transaction))) return transaction != 0u;
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
}

static bool canonical_empty_environment(pid_t pid) {
    std::string environment;
    return pid > 1 && read_file("/proc/" + std::to_string(pid) + "/environ", environment, 8192u) &&
           environment.empty();
}

static bool canonical_pidfd_live(int pidfd) {
    if (pidfd < 0) return false;
    pollfd descriptor{pidfd, POLLIN | POLLERR | POLLHUP, 0};
    int result;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0 && descriptor.revents == 0;
}

static bool canonical_target_socket_evidence(
    pid_t child, u32 positive_ipv4, u32 guard_ipv4, u16 port, u64& socket_inode) {
    socket_inode = 0u;
    privileged_listener::ProcTcpTable table;
    std::vector<u64> inodes;
    privileged_listener::Diagnostic diagnostic;
    if (!read_process_tcp_table(child, table) || !process_socket_inodes(child, inodes))
        return false;
    const privileged_listener::ListenerPlan classified{positive_ipv4, guard_ipv4, port};
    privileged_listener::ListenerEvidence evidence;
    if (!privileged_listener::classify_listener_evidence(
            table,
            classified,
            inodes,
            privileged_listener::ListenerEvidenceKind::ExactPositive,
            evidence,
            diagnostic))
        return false;
    socket_inode = evidence.child_owned_inode;
    return socket_inode != 0u;
}

static bool canonical_attempt_projection(
    const public_attempt::PublicRutAttemptLease& attempt_lease,
    const source_lease::WildcardAttemptSourceLease& source,
    const exact_reservation::ExactTcpReservationLease& reservation,
    const ProcIdentity& target,
    const std::string& expected_cmdline,
    const privileged_listener::CollisionLogEvidence& classifier,
    bool live,
    collision_evidence::CollisionAttempt& report) {
    report = {};
    const auto settlement = attempt_lease.settlement_receipt();
    const auto cleanup = attempt_lease.cleanup_state();
    if (!settlement || !cleanup || settlement->child_pid <= 1 || settlement->identity.start == 0u)
        return false;
    report.cross = {static_cast<u64>(reservation.descriptor()),
                    reservation.socket_inode(),
                    source.source_identity().device,
                    source.source_identity().inode};
    report.header = {live ? static_cast<u64>(collision_evidence::AttemptState::ExecObservedLive)
                          : static_cast<u64>(collision_evidence::AttemptState::EarlyDeath),
                     static_cast<u64>(collision_evidence::CollisionOutcome::NaturallyRejected),
                     static_cast<u64>(EADDRINUSE),
                     static_cast<u64>(settlement->child_pid),
                     settlement->identity.start,
                     live ? static_cast<u64>(collision_evidence::CmdlineProvenance::BracketedProc)
                          : static_cast<u64>(collision_evidence::CmdlineProvenance::OwnedExpected),
                     expected_cmdline.size()};
    report.procs = canonical_proc_pair(attempt_lease, live);
    report.settlement = canonical_settlement(settlement);
    report.cleanup = canonical_cleanup(cleanup);
    report.classifier = {classifier.backend == privileged_listener::CollisionBackend::Epoll
                             ? static_cast<u64>(collision_evidence::ClassifierBackend::Epoll)
                             : static_cast<u64>(collision_evidence::ClassifierBackend::IoUring),
                         2u,
                         static_cast<u64>(EADDRINUSE),
                         4u,
                         attempt_lease.sealed_capture_bytes().size()};
    report.cmdline = expected_cmdline;
    return target.pid > 1 && report.cross.g_inode == reservation.socket_inode() &&
           report.header.child_pid == report.settlement.child_pid &&
           report.classifier.capture_len <= collision_evidence::kMaxCapture;
}

static bool canonical_evidence_closed_projection(
    const public_attempt::PublicRutAttemptLease& attempt_lease,
    const source_lease::WildcardAttemptSourceLease& source,
    const exact_reservation::ExactTcpReservationLease& reservation,
    bool collision_live,
    collision_evidence::EvidenceClosed& report) {
    const auto settlement = attempt_lease.settlement_receipt();
    if (!settlement || !attempt_lease.sealed_capture_bytes().size()) return false;
    report = {static_cast<u64>(reservation.descriptor()),
              reservation.socket_inode(),
              source.source_identity().device,
              source.source_identity().inode,
              static_cast<u64>(settlement->child_pid),
              settlement->identity.start,
              collision_live ? static_cast<u64>(collision_evidence::AttemptState::ExecObservedLive)
                             : static_cast<u64>(collision_evidence::AttemptState::EarlyDeath),
              static_cast<u64>(collision_evidence::ReservationState::Held),
              static_cast<u64>(collision_evidence::SourceState::Active),
              attempt_lease.sealed_capture_bytes().size(),
              canonical_cleanup(attempt_lease.cleanup_state())};
    return report.g_fd != 0u && report.g_inode == reservation.socket_inode() &&
           report.source_dev == source.source_identity().device &&
           report.source_inode == source.source_identity().inode && report.attempt_state != 0u;
}

static bool canonical_release_projection(
    const exact_reservation::ExactTcpReservationLease& reservation,
    collision_evidence::Release& report) {
    const auto receipt = reservation.release_receipt();
    if (!receipt) return false;
    const u64 invalid_fgetfd = std::numeric_limits<u64>::max();
    report.g_fd = static_cast<u64>(reservation.descriptor());
    report.ipv4 = reservation.ipv4();
    report.port = reservation.port();
    report.g_inode = reservation.socket_inode();
    report.receipt = {receipt->attempted ? 1u : 0u,
                      receipt->destructor ? 1u : 0u,
                      receipt->real_close_attempts,
                      static_cast<u64>(receipt->real_close_result),
                      static_cast<u64>(receipt->real_close_error),
                      static_cast<u64>(receipt->reported_close_error),
                      receipt->immediate_ebadf ? invalid_fgetfd : 0u,
                      static_cast<u64>(receipt->immediate_fgetfd_error),
                      receipt->immediate_ebadf ? 1u : 0u,
                      receipt->post_inventory_checked ? 1u : 0u,
                      receipt->baseline_restored ? 1u : 0u,
                      receipt->socket_inode_absent ? 1u : 0u,
                      receipt->reportable_success ? 1u : 0u,
                      static_cast<u64>(collision_evidence::ReleaseState::Released),
                      static_cast<u64>(receipt->diagnostic.phase),
                      static_cast<u64>(receipt->diagnostic.error_number)};
    return report.receipt.attempted == 1u && report.receipt.destructor == 0u &&
           report.receipt.real_close_attempts == 1u && report.receipt.real_close_result == 0u &&
           report.receipt.immediate_ebadf == 1u && report.receipt.reportable_success == 1u;
}

static bool canonical_retry_live_projection(
    const public_attempt::PublicRutAttemptLease& attempt_lease,
    const source_lease::WildcardAttemptSourceLease& source,
    const exact_reservation::ExactTcpReservationLease& reservation,
    const std::string& expected_cmdline,
    u64 backend,
    const std::string& startup,
    collision_evidence::RetryLive& report) {
    const auto observation = attempt_lease.exec_observation();
    report = {};
    report.source_dev = source.source_identity().device;
    report.source_inode = source.source_identity().inode;
    report.source_size = source.source_identity().size;
    report.source_path_len = source.path().size();
    report.g_inode = reservation.socket_inode();
    report.port = reservation.port();
    report.header = {static_cast<u64>(collision_evidence::AttemptState::ExecObservedLive),
                     static_cast<u64>(collision_evidence::CollisionOutcome::NaturallyRejected),
                     static_cast<u64>(EADDRINUSE),
                     static_cast<u64>(attempt_lease.child_pid()),
                     observation.second.start,
                     static_cast<u64>(collision_evidence::CmdlineProvenance::BracketedProc),
                     expected_cmdline.size()};
    report.procs = canonical_proc_pair(attempt_lease, true);
    report.pidfd.pidfd_fd = static_cast<u64>(attempt_lease.observation_pidfd());
    report.pidfd.poll_result = 0u;
    report.pidfd.revents = 0u;
    report.pidfd.fdinfo_pid = static_cast<u64>(attempt_lease.child_pid());
    report.startup = {backend, 2u, reservation.port(), startup.size()};
    report.source_path = source.path();
    report.cmdline = expected_cmdline;
    return report.source_path_len <= collision_evidence::kMaxSourcePath &&
           report.startup.capture_len <= collision_evidence::kMaxCapture &&
           canonical_pidfd_live(attempt_lease.observation_pidfd()) &&
           exact_pidfd_binding(attempt_lease.observation_pidfd(), attempt_lease.child_pid());
}

static bool canonical_retry_settlement_projection(
    const public_attempt::PublicRutAttemptLease& attempt_lease,
    const source_lease::WildcardAttemptSourceLease& source,
    collision_evidence::RetrySettlement& report) {
    const auto receipt = attempt_lease.settlement_receipt();
    if (!receipt) return false;
    report = {source.source_identity().device,
              source.source_identity().inode,
              static_cast<u64>(attempt_lease.child_pid()),
              receipt->identity.start,
              static_cast<u64>(collision_evidence::AttemptState::ExecObservedLive),
              canonical_settlement(receipt),
              canonical_cleanup(attempt_lease.cleanup_state()),
              attempt_lease.sealed_capture_bytes().size()};
    return report.settlement.wait_status == 9u && report.settlement.terminal == 1u &&
           report.settlement.reaped == 1u && report.final_capture_len != 0u;
}

static bool canonical_target_phase(int control,
                                   const Token& token,
                                   collision_control::StateMachine& machine,
                                   u64 transaction,
                                   collision_control::Phase phase,
                                   std::chrono::steady_clock::time_point deadline) {
    u64 sequence = 0u;
    switch (phase) {
        case collision_control::Phase::ReservationHeld:
            sequence = 1u;
            break;
        case collision_control::Phase::CollisionNaturallyRejectedEvidenceOpen:
            sequence = 3u;
            break;
        case collision_control::Phase::EvidenceClosedReservationHeld:
            sequence = 5u;
            break;
        case collision_control::Phase::ReservationReleased:
            sequence = 7u;
            break;
        case collision_control::Phase::RetryLive:
            sequence = 9u;
            break;
    }
    if (sequence == 0u) return false;
    const collision_control::PhaseV2 value{collision_control::kProfileVersion,
                                           transaction,
                                           collision_control::Profile::Canonical,
                                           phase,
                                           sequence};
    const Frame frame = collision_control::encode_phase(token, value);
    return machine.observe(frame, token) &&
           send_frame(control, frame, remaining_deadline_ms(deadline));
}

static bool canonical_target_decision(int control,
                                      const Token& token,
                                      collision_control::StateMachine& machine,
                                      std::chrono::steady_clock::time_point deadline,
                                      collision_control::DecisionKind expected) {
    Frame frame;
    collision_control::DecisionV2 decision;
    return receive_frame_until(control, frame, deadline) &&
           collision_control::decode_decision(frame, token, decision) &&
           decision.decision == expected && machine.decide(frame, token);
}

static bool canonical_target_settlement(int control,
                                        const Token& token,
                                        collision_control::StateMachine& machine,
                                        std::chrono::steady_clock::time_point deadline) {
    Frame frame;
    collision_control::SettlementV2 settlement;
    return receive_frame_until(control, frame, deadline) &&
           collision_control::decode_settlement(frame, token, settlement) &&
           machine.settle(frame, token);
}

static int canonical_target_flow(int control,
                                 const Token& token,
                                 const std::vector<unsigned char>& request,
                                 const std::string& control_path) {
    u32 positive_ipv4 = 0u, guard_ipv4 = 0u;
    std::string executable_path;
    if (!parse_canonical_request(request, positive_ipv4, guard_ipv4, executable_path)) return 60;
    const auto transaction_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    u64 transaction = 0u;
    ProcIdentity target_identity;
    if (!canonical_random_transaction(transaction) || !read_proc(getpid(), target_identity) ||
        target_identity.uid != geteuid() || target_identity.gid != getegid() ||
        target_identity.supplementary_groups != 0 || !target_identity.no_new_privs ||
        !target_identity.capabilities_clear || target_identity.netns == 0)
        return 61;

    private_directory::PrivateDirectoryLease directory;
    source_lease::WildcardAttemptSourceLease source;
    executable_lease::ExecutableLease executable;
    exact_reservation::ExactTcpReservationLease reservation;
    public_attempt::PublicRutAttemptLease collision_attempt;
    public_attempt::PublicRutAttemptLease retry_attempt;
    private_directory::Diagnostic directory_diagnostic;
    source_lease::Diagnostic source_diagnostic;
    executable_lease::Diagnostic executable_diagnostic;
    exact_reservation::Diagnostic reservation_diagnostic;
    public_attempt::Diagnostic attempt_diagnostic;
    if (!private_directory::PrivateDirectoryLease::create(directory, directory_diagnostic) ||
        !source_lease::WildcardAttemptSourceLease::stage(directory.descriptor(),
                                                         directory.path(),
                                                         "canonical-listener.rut",
                                                         source,
                                                         source_diagnostic) ||
        !executable_lease::ExecutableLease::create(
            executable_path, executable, executable_diagnostic) ||
        !exact_reservation::ExactTcpReservationLease::reserve(
            guard_ipv4, reservation, reservation_diagnostic))
        return 62;

    const std::string dotted_guard = [&]() {
        std::array<char, INET_ADDRSTRLEN> text{};
        in_addr address{htonl(guard_ipv4)};
        return inet_ntop(AF_INET, &address, text.data(), text.size()) == nullptr
                   ? std::string{}
                   : std::string(text.data());
    }();
    if (dotted_guard.empty() || reservation.port() == 0u ||
        reservation.port() > std::numeric_limits<u16>::max())
        return 63;
    const std::string source_bytes = "listen " + dotted_guard + ":" +
                                     std::to_string(reservation.port()) +
                                     "\nroute GET \"/\" { return 204 }\n";
    if (source_bytes.size() > collision_evidence::kMaxSourceBytes ||
        !source.finalize_exact_bytes(source_bytes, source_diagnostic) ||
        !reservation.revalidate(reservation_diagnostic))
        return 64;

    collision_evidence::ReservationSource source_report;
    if (!canonical_reservation_source(
            reservation, source, directory, source_bytes, target_identity, source_report))
        return 65;
    const collision_evidence::Target evidence_target{static_cast<u64>(target_identity.pid),
                                                     target_identity.start,
                                                     static_cast<u64>(target_identity.netns)};
    const collision_evidence::Envelope source_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::ReservationSource,
                                    collision_evidence::Binding::Phase,
                                    collision_evidence::Phase::ReservationHeld,
                                    1u);
    const Frame source_frame =
        collision_evidence::encode_reservation_source(token, source_envelope, source_report);
    if (!canonical_send_evidence(
            control,
            token,
            source_frame,
            collision_evidence::max_payload(collision_evidence::ReportKind::ReservationSource),
            transaction_deadline))
        return 66;

    Frame command_frame;
    collision_control::CommandV2 command;
    collision_control::StateMachine machine;
    if (!receive_frame_until(control, command_frame, transaction_deadline) ||
        !collision_control::decode_command(command_frame, token, command) ||
        command.transaction_id != transaction || !machine.begin(command_frame, token) ||
        !canonical_target_phase(control,
                                token,
                                machine,
                                transaction,
                                collision_control::Phase::ReservationHeld,
                                transaction_deadline) ||
        !canonical_target_decision(control,
                                   token,
                                   machine,
                                   transaction_deadline,
                                   collision_control::DecisionKind::AuthorizeCollisionExec))
        return 67;

    const std::array<std::string_view, 9u> arguments = {executable.canonical_path(),
                                                        source.path(),
                                                        "--shards",
                                                        "1",
                                                        "--no-pin",
                                                        "--drain",
                                                        "0",
                                                        "--opt",
                                                        "2"};
    const std::string expected_cmdline = [&]() {
        std::string value;
        for (const std::string_view argument : arguments) {
            value.append(argument);
            value.push_back('\0');
        }
        return value;
    }();
    if (expected_cmdline.size() > collision_evidence::kMaxCmdline ||
        !collision_attempt.prepare(
            source, executable, arguments, transaction_deadline, {}, attempt_diagnostic) ||
        !collision_attempt.exec_and_observe(
            source, executable, transaction_deadline, attempt_diagnostic) ||
        (collision_attempt.state() != public_attempt::State::EarlyDeath &&
         collision_attempt.state() != public_attempt::State::ExecObservedLive) ||
        !collision_attempt.settle_natural(1, transaction_deadline, attempt_diagnostic))
        return 68;
    const bool collision_live = collision_attempt.exec_observation().outcome ==
                                public_attempt::handoff::ExecOutcome::ExecObservedLive;
    std::string collision_capture = collision_attempt.sealed_capture_bytes();
    privileged_listener::CollisionLogEvidence collision_classifier;
    privileged_listener::Diagnostic collision_diagnostic;
    if (collision_capture.empty() ||
        !privileged_listener::classify_collision_log(
            collision_capture, source.path(), 2u, collision_classifier, collision_diagnostic) ||
        collision_attempt.state() != public_attempt::State::NaturalReapedEvidenceOpen)
        return 69;
    collision_evidence::CollisionAttempt collision_report;
    if (!canonical_attempt_projection(collision_attempt,
                                      source,
                                      reservation,
                                      target_identity,
                                      expected_cmdline,
                                      collision_classifier,
                                      collision_live,
                                      collision_report))
        return 70;
    const collision_evidence::Envelope collision_envelope = canonical_expected_envelope(
        transaction,
        evidence_target,
        collision_evidence::ReportKind::CollisionAttempt,
        collision_evidence::Binding::Phase,
        collision_evidence::Phase::CollisionNaturallyRejectedEvidenceOpen,
        3u);
    const Frame collision_frame =
        collision_evidence::encode_collision_attempt(token, collision_envelope, collision_report);
    const collision_evidence::CollisionCapture capture_report{
        static_cast<u64>(collision_capture.size()), collision_capture};
    const collision_evidence::Envelope collision_capture_envelope = canonical_expected_envelope(
        transaction,
        evidence_target,
        collision_evidence::ReportKind::CollisionCapture,
        collision_evidence::Binding::Phase,
        collision_evidence::Phase::CollisionNaturallyRejectedEvidenceOpen,
        3u);
    const Frame capture_frame = collision_evidence::encode_collision_capture(
        token, collision_capture_envelope, capture_report);
    if (!canonical_target_phase(control,
                                token,
                                machine,
                                transaction,
                                collision_control::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                transaction_deadline) ||
        !canonical_send_evidence(
            control,
            token,
            collision_frame,
            collision_evidence::max_payload(collision_evidence::ReportKind::CollisionAttempt),
            transaction_deadline) ||
        !canonical_send_evidence(
            control,
            token,
            capture_frame,
            collision_evidence::max_payload(collision_evidence::ReportKind::CollisionCapture),
            transaction_deadline) ||
        !canonical_target_decision(control,
                                   token,
                                   machine,
                                   transaction_deadline,
                                   collision_control::DecisionKind::AuthorizeEvidenceClose) ||
        !collision_attempt.close_evidence(attempt_diagnostic) ||
        !reservation.revalidate(reservation_diagnostic) || !source.revalidate(source_diagnostic))
        return 71;

    collision_evidence::EvidenceClosed closed_report;
    closed_report.attempt_state = collision_report.header.attempt_state;
    // Build the closed projection only after the capture FD is closed. The
    // report helper reads only immutable source/G identities and cleanup state.
    if (!canonical_evidence_closed_projection(
            collision_attempt, source, reservation, collision_live, closed_report))
        return 72;
    const collision_evidence::Envelope closed_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::EvidenceClosed,
                                    collision_evidence::Binding::Phase,
                                    collision_evidence::Phase::EvidenceClosedReservationHeld,
                                    5u);
    if (!canonical_target_phase(control,
                                token,
                                machine,
                                transaction,
                                collision_control::Phase::EvidenceClosedReservationHeld,
                                transaction_deadline) ||
        !canonical_send_evidence(
            control,
            token,
            collision_evidence::encode_evidence_closed(token, closed_envelope, closed_report),
            collision_evidence::max_payload(collision_evidence::ReportKind::EvidenceClosed),
            transaction_deadline) ||
        !canonical_target_decision(control,
                                   token,
                                   machine,
                                   transaction_deadline,
                                   collision_control::DecisionKind::AuthorizeReservationRelease))
        return 73;

    const int released_fd = reservation.descriptor();
    const u64 released_inode = reservation.socket_inode();
    if (released_fd < 0 || released_inode == 0u || !reservation.release(reservation_diagnostic))
        return 74;
    collision_evidence::Release release_report;
    if (!canonical_release_projection(reservation, release_report)) return 75;
    release_report.g_fd = static_cast<u64>(released_fd);
    release_report.g_inode = released_inode;
    const collision_evidence::Envelope release_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::Release,
                                    collision_evidence::Binding::Phase,
                                    collision_evidence::Phase::ReservationReleased,
                                    7u);
    if (!canonical_target_phase(control,
                                token,
                                machine,
                                transaction,
                                collision_control::Phase::ReservationReleased,
                                transaction_deadline) ||
        !canonical_send_evidence(
            control,
            token,
            collision_evidence::encode_release(token, release_envelope, release_report),
            collision_evidence::max_payload(collision_evidence::ReportKind::Release),
            transaction_deadline) ||
        !canonical_target_decision(control,
                                   token,
                                   machine,
                                   transaction_deadline,
                                   collision_control::DecisionKind::AuthorizeRetryExec))
        return 76;

    if (!retry_attempt.prepare(
            source, executable, arguments, transaction_deadline, {}, attempt_diagnostic) ||
        !retry_attempt.exec_and_observe(
            source, executable, transaction_deadline, attempt_diagnostic) ||
        retry_attempt.state() != public_attempt::State::ExecObservedLive)
        return 77;
    std::string startup_capture;
    u64 startup_backend = 0u;
    bool retry_ready = false;
    const privileged_listener::ListenerPlan retry_plan{
        guard_ipv4, positive_ipv4, reservation.port()};
    while (std::chrono::steady_clock::now() < transaction_deadline) {
        std::string candidate;
        ProcIdentity first, second;
        privileged_listener::ProcTcpTable table;
        std::vector<u64> sockets;
        privileged_listener::ListenerEvidence listener;
        privileged_listener::Diagnostic listener_diagnostic;
        if (retry_attempt.snapshot_capture(candidate, attempt_diagnostic) &&
            exact_log_ready(candidate, source.path(), reservation.port(), startup_backend) &&
            read_proc(retry_attempt.child_pid(), first) &&
            read_proc(retry_attempt.child_pid(), second) && same_process_identity(first, second) &&
            first.pid == retry_attempt.child_pid() && first.ppid == getpid() &&
            first.netns == target_identity.netns && canonical_empty_environment(first.pid) &&
            source.revalidate(source_diagnostic) && executable.revalidate(executable_diagnostic) &&
            canonical_pidfd_live(retry_attempt.observation_pidfd()) &&
            exact_pidfd_binding(retry_attempt.observation_pidfd(), retry_attempt.child_pid()) &&
            read_process_tcp_table(retry_attempt.child_pid(), table) &&
            process_socket_inodes(retry_attempt.child_pid(), sockets) &&
            privileged_listener::classify_listener_evidence(
                table,
                retry_plan,
                sockets,
                privileged_listener::ListenerEvidenceKind::ExactPositive,
                listener,
                listener_diagnostic) &&
            listener.child_owned_inode != 0u) {
            startup_capture = candidate;
            retry_ready = true;
            break;
        }
        (void)poll(nullptr, 0, 5);
    }
    if (!retry_ready) return 78;
    collision_evidence::RetryLive retry_report;
    if (!canonical_retry_live_projection(retry_attempt,
                                         source,
                                         reservation,
                                         expected_cmdline,
                                         startup_backend,
                                         startup_capture,
                                         retry_report))
        return 79;
    const collision_evidence::Envelope retry_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::RetryLive,
                                    collision_evidence::Binding::Phase,
                                    collision_evidence::Phase::RetryLive,
                                    9u);
    const collision_evidence::RetryLiveCapture retry_capture_report{
        static_cast<u64>(startup_capture.size()), startup_capture};
    const collision_evidence::Envelope retry_capture_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::RetryLiveCapture,
                                    collision_evidence::Binding::Phase,
                                    collision_evidence::Phase::RetryLive,
                                    9u);
    if (!canonical_target_phase(control,
                                token,
                                machine,
                                transaction,
                                collision_control::Phase::RetryLive,
                                transaction_deadline) ||
        !canonical_send_evidence(
            control,
            token,
            collision_evidence::encode_retry_live(token, retry_envelope, retry_report),
            collision_evidence::max_payload(collision_evidence::ReportKind::RetryLive),
            transaction_deadline) ||
        !canonical_send_evidence(
            control,
            token,
            collision_evidence::encode_retry_live_capture(
                token, retry_capture_envelope, retry_capture_report),
            collision_evidence::max_payload(collision_evidence::ReportKind::RetryLiveCapture),
            transaction_deadline) ||
        !canonical_target_decision(control,
                                   token,
                                   machine,
                                   transaction_deadline,
                                   collision_control::DecisionKind::AuthorizeRetrySettlement) ||
        !retry_attempt.settle_killed(SIGKILL, transaction_deadline, attempt_diagnostic))
        return 80;

    std::string final_capture;
    if (!retry_attempt.snapshot_capture(final_capture, attempt_diagnostic) ||
        final_capture.size() < startup_capture.size() ||
        std::memcmp(final_capture.data(), startup_capture.data(), startup_capture.size()) != 0)
        return 81;
    collision_evidence::RetrySettlement settlement_report;
    if (!canonical_retry_settlement_projection(retry_attempt, source, settlement_report)) return 82;
    const collision_evidence::Envelope settlement_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::RetrySettlement,
                                    collision_evidence::Binding::Settlement,
                                    collision_evidence::Phase::RetryLive,
                                    11u);
    if (!canonical_send_evidence(
            control,
            token,
            collision_evidence::encode_retry_settlement(
                token, settlement_envelope, settlement_report),
            collision_evidence::max_payload(collision_evidence::ReportKind::RetrySettlement),
            transaction_deadline) ||
        !retry_attempt.close_evidence(attempt_diagnostic) || !source.remove(source_diagnostic) ||
        !directory.settle(directory_diagnostic) || !executable.close(executable_diagnostic))
        return 83;
    const collision_evidence::RetryFinalCapture final_report{static_cast<u64>(final_capture.size()),
                                                             final_capture};
    const collision_evidence::Envelope final_envelope =
        canonical_expected_envelope(transaction,
                                    evidence_target,
                                    collision_evidence::ReportKind::RetryFinalCapture,
                                    collision_evidence::Binding::Settlement,
                                    collision_evidence::Phase::RetryLive,
                                    11u);
    if (!canonical_send_evidence(
            control,
            token,
            collision_evidence::encode_retry_final_capture(token, final_envelope, final_report),
            collision_evidence::max_payload(collision_evidence::ReportKind::RetryFinalCapture),
            transaction_deadline) ||
        !canonical_target_settlement(control, token, machine, transaction_deadline))
        return 84;
    if (!canonical_target_decision(control,
                                   token,
                                   machine,
                                   transaction_deadline,
                                   collision_control::DecisionKind::Finish) ||
        machine.state() != collision_control::State::Complete)
        return 85;
    close(control);
    (void)control_path;
    return 0;
}

static bool canonical_parent_phase(int target_fd,
                                   const Token& token,
                                   collision_control::StateMachine& machine,
                                   std::chrono::steady_clock::time_point deadline,
                                   collision_control::Phase expected_phase) {
    Frame frame;
    collision_control::PhaseV2 phase;
    return receive_frame_until(target_fd, frame, deadline) &&
           collision_control::decode_phase(frame, token, phase) && phase.phase == expected_phase &&
           machine.observe(frame, token);
}

static bool canonical_parent_g_evidence(const collision_evidence::ReservationSource& source,
                                        const ProcIdentity& target) {
    if (target.pid <= 1 || source.g_fd > static_cast<u64>(std::numeric_limits<int>::max()))
        return false;
    const int descriptor = static_cast<int>(source.g_fd);
    std::array<char, collision_evidence::kMaxProcLink + 1u> link_buffer{};
    const std::string link_path =
        "/proc/" + std::to_string(target.pid) + "/fd/" + std::to_string(descriptor);
    const ssize_t link_size = readlink(link_path.c_str(), link_buffer.data(), link_buffer.size());
    if (link_size <= 0 || static_cast<std::size_t>(link_size) >= link_buffer.size()) return false;
    const std::string link(link_buffer.data(), static_cast<std::size_t>(link_size));
    if (link != source.proc_link) return false;

    std::string fdinfo;
    if (!read_file("/proc/" + std::to_string(target.pid) + "/fdinfo/" + std::to_string(descriptor),
                   fdinfo,
                   4096u))
        return false;
    std::istringstream lines(fdinfo);
    std::string key, value;
    u64 flags = 0u;
    bool found_flags = false;
    while (lines >> key) {
        if (key == "flags:") {
            if (found_flags || !(lines >> value) || value.empty()) return false;
            u64 parsed = 0u;
            const auto result =
                std::from_chars(value.data(), value.data() + value.size(), parsed, 8);
            if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) return false;
            flags = parsed;
            found_flags = true;
        }
        std::string rest;
        std::getline(lines, rest);
    }
    return found_flags && (flags & static_cast<u64>(O_CLOEXEC)) != 0u &&
           (flags & ~static_cast<u64>(O_CLOEXEC)) == source.g_f_getfl;
}

static bool canonical_parent_decision(int target_fd,
                                      const Token& token,
                                      collision_control::StateMachine& machine,
                                      std::chrono::steady_clock::time_point deadline,
                                      collision_control::DecisionKind decision) {
    collision_control::Phase phase = collision_control::Phase::ReservationHeld;
    u64 sequence = 2u;
    switch (decision) {
        case collision_control::DecisionKind::AuthorizeCollisionExec:
            phase = collision_control::Phase::ReservationHeld;
            sequence = 2u;
            break;
        case collision_control::DecisionKind::AuthorizeEvidenceClose:
            phase = collision_control::Phase::CollisionNaturallyRejectedEvidenceOpen;
            sequence = 4u;
            break;
        case collision_control::DecisionKind::AuthorizeReservationRelease:
            phase = collision_control::Phase::EvidenceClosedReservationHeld;
            sequence = 6u;
            break;
        case collision_control::DecisionKind::AuthorizeRetryExec:
            phase = collision_control::Phase::ReservationReleased;
            sequence = 8u;
            break;
        case collision_control::DecisionKind::AuthorizeRetrySettlement:
        case collision_control::DecisionKind::Finish:
            phase = collision_control::Phase::RetryLive;
            sequence = decision == collision_control::DecisionKind::Finish ? 12u : 10u;
            break;
    }
    const collision_control::DecisionV2 value{collision_control::kProfileVersion,
                                              machine.transaction_id(),
                                              collision_control::Profile::Canonical,
                                              decision,
                                              phase,
                                              sequence};
    const Frame frame = collision_control::encode_decision(token, value);
    collision_control::DecisionV2 checked;
    return collision_control::decode_decision(frame, token, checked) &&
           checked.decision == decision && machine.decide(frame, token) &&
           send_frame(target_fd, frame, remaining_deadline_ms(deadline));
}

static bool canonical_parent_validate_source(const collision_evidence::Envelope& envelope,
                                             const collision_evidence::ReservationSource& source,
                                             const ProcIdentity& target,
                                             u32 positive_ipv4,
                                             u32 guard_ipv4,
                                             const std::string& executable,
                                             std::string& error) {
    std::array<char, INET_ADDRSTRLEN> dotted{};
    in_addr address{htonl(guard_ipv4)};
    if (inet_ntop(AF_INET, &address, dotted.data(), dotted.size()) == nullptr) {
        error = "guard address formatting failed";
        return false;
    }
    const std::string expected_bytes = "listen " + std::string(dotted.data()) + ":" +
                                       std::to_string(source.port) +
                                       "\nroute GET \"/\" { return 204 }\n";
    const std::string prefix = "/tmp/rut377-private-";
    const std::string suffix = "/canonical-listener.rut";
    if (!collision_evidence::valid_envelope(envelope,
                                            collision_evidence::ReportKind::ReservationSource) ||
        envelope.binding != collision_evidence::Binding::Phase ||
        envelope.phase != collision_evidence::Phase::ReservationHeld || envelope.sequence != 1u ||
        envelope.target.pid != static_cast<u64>(target.pid) ||
        envelope.target.start != target.start ||
        envelope.target.netns != static_cast<u64>(target.netns) || positive_ipv4 == 0u ||
        positive_ipv4 == guard_ipv4 ||
        source.reservation_state != static_cast<u64>(collision_evidence::ReservationState::Held) ||
        source.ipv4 != guard_ipv4 || source.port == 0u || source.port > 65535u ||
        source.g_fd <= 2u || source.g_f_getfd != static_cast<u64>(FD_CLOEXEC) ||
        (source.g_f_getfl & static_cast<u64>(O_ACCMODE)) != static_cast<u64>(O_RDWR) ||
        (source.g_f_getfl & static_cast<u64>(O_NONBLOCK | O_APPEND | O_ASYNC)) != 0u ||
        source.dev == 0u || source.ino == 0u || source.mode == 0u ||
        (source.mode & static_cast<u64>(S_IFMT)) != static_cast<u64>(S_IFSOCK) ||
        source.rdev != 0u || source.socket_domain != static_cast<u64>(AF_INET) ||
        source.socket_type != static_cast<u64>(SOCK_STREAM) || source.socket_protocol != 0u ||
        source.reuseaddr != 0u || source.reuseport != 0u || source.acceptconn != 0u ||
        source.proc_link != "socket:[" + std::to_string(source.ino) + "]" ||
        source.proc_link_len != source.proc_link.size() || source.proc_link.size() > 29u ||
        source.directory_dev == 0u || source.directory_ino == 0u ||
        (source.directory_mode & 0777u) != 0700u || source.directory_uid != getuid() ||
        source.directory_gid != getgid() ||
        source.source_state != static_cast<u64>(collision_evidence::SourceState::Active) ||
        source.source_dev == 0u || source.source_ino == 0u ||
        (source.source_mode & static_cast<u64>(S_IFMT)) != static_cast<u64>(S_IFREG) ||
        (source.source_mode & 0777u) != 0600u || source.source_uid != getuid() ||
        source.source_gid != getgid() || source.source_size != source.bytes_len ||
        source.source_nlink != 1u || source.path_len != source.source_path.size() ||
        source.bytes_len != source.source_bytes.size() ||
        source.bytes_len != expected_bytes.size() || source.source_bytes != expected_bytes ||
        source.path_len > collision_evidence::kMaxSourcePath ||
        source.bytes_len > collision_evidence::kMaxSourceBytes ||
        source.source_path.rfind(prefix, 0u) != 0u ||
        source.source_path.size() <= prefix.size() + suffix.size() ||
        source.source_path.compare(
            source.source_path.size() - suffix.size(), suffix.size(), suffix) != 0 ||
        source.source_path.find('\0') != std::string::npos || executable.empty() ||
        !canonical_parent_g_evidence(source, target)) {
        error = "reservation/source bootstrap projection was not exact";
        return false;
    }
    const std::string directory_path = source.source_path.substr(
        0u, source.source_path.size() - std::string("/canonical-listener.rut").size());
    struct stat directory_status{}, source_status{};
    if (lstat(directory_path.c_str(), &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) ||
        static_cast<u64>(directory_status.st_dev) != source.directory_dev ||
        static_cast<u64>(directory_status.st_ino) != source.directory_ino ||
        lstat(source.source_path.c_str(), &source_status) != 0 ||
        static_cast<u64>(source_status.st_dev) != source.source_dev ||
        static_cast<u64>(source_status.st_ino) != source.source_ino ||
        static_cast<u64>(source_status.st_size) != source.source_size ||
        static_cast<u64>(source_status.st_mode) != source.source_mode ||
        source_status.st_nlink != 1u || source_status.st_uid != getuid() ||
        source_status.st_gid != getgid() ||
        static_cast<u64>(directory_status.st_mode) != source.directory_mode ||
        directory_status.st_uid != getuid() || directory_status.st_gid != getgid()) {
        error = "random source path/stat identity was not independently observed";
        return false;
    }
    std::string observed_bytes;
    if (!read_file(source.source_path, observed_bytes, collision_evidence::kMaxSourceBytes) ||
        observed_bytes != expected_bytes) {
        error = "source bytes were not independently read at report1 bootstrap";
        return false;
    }
    (void)positive_ipv4;
    return true;
}

static bool canonical_parent_pidfd_info(pid_t target, int fd, pid_t child) {
    if (target <= 1 || fd < 0 || child <= 1) return false;
    std::string text;
    if (!read_file(
            "/proc/" + std::to_string(target) + "/fdinfo/" + std::to_string(fd), text, 4096u))
        return false;
    std::istringstream lines(text);
    std::string key;
    bool found = false;
    while (lines >> key) {
        if (key == "Pid:") {
            long value = 0;
            if (found || !(lines >> value) || value != child) return false;
            found = true;
        }
        std::string rest;
        std::getline(lines, rest);
    }
    return found;
}

static bool canonical_parent_retry_identity(const collision_evidence::RetryLive& report,
                                            const ProcIdentity& target,
                                            const std::string& executable,
                                            const collision_evidence::Target& evidence_target,
                                            u32 positive_ipv4,
                                            u32 guard_ipv4,
                                            std::string& error) {
    if (report.header.child_pid <= 1u ||
        report.header.child_pid > static_cast<u64>(std::numeric_limits<pid_t>::max()) ||
        report.header.child_pid == 0u || report.header.child_start == 0u ||
        report.pidfd.pidfd_fd > static_cast<u64>(std::numeric_limits<int>::max()) ||
        report.procs.first_tag != 1u || report.procs.second_tag != 1u ||
        report.procs.first != report.procs.second ||
        report.procs.first.pid != report.header.child_pid ||
        report.procs.first.start != report.header.child_start ||
        report.procs.first.ppid != evidence_target.pid ||
        report.procs.first.netns != evidence_target.netns)
        return false;
    const pid_t child = static_cast<pid_t>(report.header.child_pid);
    ProcIdentity first, second;
    const std::string expected_cmdline = report.cmdline;
    if (!read_proc(child, first) || !read_proc(child, second) ||
        !same_process_identity(first, second) || first.start != report.header.child_start ||
        canonical_proc13(first) != report.procs.first ||
        canonical_proc13(second) != report.procs.second || first.ppid != target.pid ||
        first.uid != getuid() || first.gid != getgid() || first.netns != target.netns ||
        first.exe != executable || first.cmdline != expected_cmdline ||
        !canonical_empty_environment(child) ||
        !pidfd_link_matches(target.pid, static_cast<int>(report.pidfd.pidfd_fd)) ||
        !canonical_parent_pidfd_info(target.pid, static_cast<int>(report.pidfd.pidfd_fd), child) ||
        [&]() {
            u64 socket_inode = 0u;
            return canonical_target_socket_evidence(child,
                                                    positive_ipv4,
                                                    guard_ipv4,
                                                    static_cast<u16>(report.port),
                                                    socket_inode) &&
                   socket_inode != 0u;
        }()) {
        error = "retry child/pidfd/socket identity was not independently observed";
        return false;
    }
    return report.pidfd.poll_result == 0u && report.pidfd.revents == 0u;
}

static bool run_canonical_collision_release_parent(int target_fd,
                                                   const Token& token,
                                                   const HeldTopologySnapshot& topology,
                                                   const std::string& executable,
                                                   const ProcIdentity& target_proc,
                                                   std::string& error) {
    u32 positive_ipv4 = 0u, guard_ipv4 = 0u;
    if (!parse_canonical_ipv4(topology.positive_ip, positive_ipv4) ||
        !parse_canonical_ipv4(topology.guard_ip, guard_ipv4)) {
        error = "held topology addresses were not canonical IPv4";
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    const std::vector<unsigned char> request =
        canonical_request_payload(positive_ipv4, guard_ipv4, executable);
    if (!send_frame(
            target_fd, Frame{kGuardReserve, token, request}, remaining_deadline_ms(deadline))) {
        error = "canonical reservation request transport failed";
        return false;
    }
    Frame source_frame;
    if (!canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::ReservationSource),
            deadline,
            source_frame)) {
        error = "canonical report1 transport failed";
        return false;
    }
    const collision_evidence::Envelope source_envelope = canonical_envelope_from_frame(
        source_frame, collision_evidence::ReportKind::ReservationSource);
    collision_evidence::ReservationSource source;
    if (!collision_evidence::decode_reservation_source(
            source_frame, token, source_envelope, source) ||
        !canonical_parent_validate_source(
            source_envelope, source, target_proc, positive_ipv4, guard_ipv4, executable, error))
        return false;
    const collision_evidence::Target evidence_target{
        source_envelope.target.pid, source_envelope.target.start, source_envelope.target.netns};
    const std::array<std::string_view, 9u> arguments = {
        executable, source.source_path, "--shards", "1", "--no-pin", "--drain", "0", "--opt", "2"};
    std::string expected_cmdline;
    for (const std::string_view argument : arguments) {
        expected_cmdline.append(argument);
        expected_cmdline.push_back('\0');
    }
    collision_evidence::ReceiverContext receiver_context{token,
                                                         source_envelope.transaction,
                                                         source_envelope.domain,
                                                         evidence_target,
                                                         source,
                                                         expected_cmdline};
    collision_evidence::Receiver receiver(receiver_context);
    if (!receiver.observe(source_frame)) {
        error = "report1 strict receiver replay failed";
        return false;
    }
    collision_control::StateMachine machine;
    const collision_control::CommandV2 command{collision_control::kProfileVersion,
                                               source_envelope.transaction,
                                               collision_control::Profile::Canonical,
                                               0u};
    const Frame command_frame = collision_control::encode_command(token, command);
    if (!machine.begin(command_frame, token) ||
        !send_frame(target_fd, command_frame, remaining_deadline_ms(deadline)) ||
        !canonical_parent_phase(
            target_fd, token, machine, deadline, collision_control::Phase::ReservationHeld) ||
        !canonical_parent_decision(target_fd,
                                   token,
                                   machine,
                                   deadline,
                                   collision_control::DecisionKind::AuthorizeCollisionExec) ||
        !canonical_parent_phase(target_fd,
                                token,
                                machine,
                                deadline,
                                collision_control::Phase::CollisionNaturallyRejectedEvidenceOpen)) {
        error = "collision control reservation/exec barrier failed";
        return false;
    }
    Frame collision_frame, capture_frame;
    const auto collision_max =
        collision_evidence::max_payload(collision_evidence::ReportKind::CollisionAttempt);
    const auto capture_max =
        collision_evidence::max_payload(collision_evidence::ReportKind::CollisionCapture);
    if (!canonical_receive_evidence(target_fd, token, collision_max, deadline, collision_frame) ||
        !canonical_receive_evidence(target_fd, token, capture_max, deadline, capture_frame) ||
        !receiver.observe(collision_frame) || !receiver.observe(capture_frame)) {
        error = "collision reports 2/3 were malformed or out of order";
        return false;
    }
    if (!canonical_parent_decision(target_fd,
                                   token,
                                   machine,
                                   deadline,
                                   collision_control::DecisionKind::AuthorizeEvidenceClose) ||
        !canonical_parent_phase(target_fd,
                                token,
                                machine,
                                deadline,
                                collision_control::Phase::EvidenceClosedReservationHeld)) {
        error = "collision evidence-close barrier failed";
        return false;
    }
    Frame closed_frame;
    if (!canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::EvidenceClosed),
            deadline,
            closed_frame) ||
        !receiver.observe(closed_frame)) {
        error = "report4 evidence-closed transport/replay failed";
        return false;
    }
    if (!canonical_parent_decision(target_fd,
                                   token,
                                   machine,
                                   deadline,
                                   collision_control::DecisionKind::AuthorizeReservationRelease) ||
        !canonical_parent_phase(
            target_fd, token, machine, deadline, collision_control::Phase::ReservationReleased)) {
        error = "one-shot reservation release barrier failed";
        return false;
    }
    Frame release_frame;
    if (!canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::Release),
            deadline,
            release_frame) ||
        !receiver.observe(release_frame)) {
        error = "report5 release receipt transport/replay failed";
        return false;
    }
    if (!canonical_parent_decision(target_fd,
                                   token,
                                   machine,
                                   deadline,
                                   collision_control::DecisionKind::AuthorizeRetryExec) ||
        !canonical_parent_phase(
            target_fd, token, machine, deadline, collision_control::Phase::RetryLive)) {
        error = "retry execution barrier failed";
        return false;
    }
    Frame retry_frame, retry_capture_frame;
    if (!canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::RetryLive),
            deadline,
            retry_frame)) {
        error = "report6 retry-live transport failed";
        return false;
    }
    const collision_evidence::Envelope retry_envelope =
        canonical_envelope_from_frame(retry_frame, collision_evidence::ReportKind::RetryLive);
    collision_evidence::RetryLive retry_live;
    if (!collision_evidence::decode_retry_live(retry_frame, token, retry_envelope, retry_live) ||
        !canonical_parent_retry_identity(
            retry_live, target_proc, executable, evidence_target, guard_ipv4, positive_ipv4, error))
        return false;
    if (!canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::RetryLiveCapture),
            deadline,
            retry_capture_frame) ||
        !receiver.observe(retry_frame) || !receiver.observe(retry_capture_frame)) {
        error = "report7 live capture transport/replay failed";
        return false;
    }
    collision_evidence::RetryLiveCapture retry_capture;
    const collision_evidence::Envelope retry_capture_envelope = canonical_envelope_from_frame(
        retry_capture_frame, collision_evidence::ReportKind::RetryLiveCapture);
    if (!collision_evidence::decode_retry_live_capture(
            retry_capture_frame, token, retry_capture_envelope, retry_capture) ||
        !exact_log_ready(
            retry_capture.capture, source.source_path, source.port, retry_live.startup.backend)) {
        error = "retry startup capture was not exact";
        return false;
    }
    if (!canonical_parent_decision(target_fd,
                                   token,
                                   machine,
                                   deadline,
                                   collision_control::DecisionKind::AuthorizeRetrySettlement)) {
        error = "retry settlement barrier failed";
        return false;
    }
    Frame settlement_frame, final_frame;
    if (!canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::RetrySettlement),
            deadline,
            settlement_frame) ||
        !receiver.observe(settlement_frame) ||
        !canonical_receive_evidence(
            target_fd,
            token,
            collision_evidence::max_payload(collision_evidence::ReportKind::RetryFinalCapture),
            deadline,
            final_frame) ||
        !receiver.observe(final_frame)) {
        error = "reports 8/9 transport/replay failed";
        return false;
    }
    collision_evidence::RetryFinalCapture final_capture;
    const collision_evidence::Envelope final_envelope = canonical_envelope_from_frame(
        final_frame, collision_evidence::ReportKind::RetryFinalCapture);
    if (!collision_evidence::decode_retry_final_capture(
            final_frame, token, final_envelope, final_capture) ||
        final_capture.capture.size() < retry_capture.capture.size() ||
        std::memcmp(final_capture.capture.data(),
                    retry_capture.capture.data(),
                    retry_capture.capture.size()) != 0 ||
        receiver.state() != collision_evidence::State::AwaitFinish) {
        error = "final capture prefix/evidence receiver completion failed";
        return false;
    }
    const collision_control::SettlementV2 settlement{
        collision_control::kProfileVersion,
        machine.transaction_id(),
        collision_control::Profile::Canonical,
        collision_control::SettlementKind::AttemptSettled,
        collision_control::Phase::RetryLive,
        11u};
    const Frame settlement_control = collision_control::encode_settlement(token, settlement);
    if (!machine.settle(settlement_control, token) ||
        !send_frame(target_fd, settlement_control, remaining_deadline_ms(deadline)) ||
        !canonical_parent_decision(
            target_fd, token, machine, deadline, collision_control::DecisionKind::Finish) ||
        machine.state() != collision_control::State::Complete || !receiver.finish()) {
        error = "control settlement/finish ordering failed";
        return false;
    }
    return true;
}

static std::vector<unsigned char> encode_guard_report(const GuardReport& report) {
    const std::array<u64, kGuardReportFields> fields{
        report.plan.positive_ipv4,
        report.plan.guard_ipv4,
        report.plan.port,
        report.guard_fd,
        report.socket_inode,
        report.owner_pid,
        report.owner_start,
        report.netns,
        report.baseline_fd_count,
        report.current_fd_count,
        report.family,
        report.socket_type,
        report.fd_cloexec,
        report.accept_connection,
        report.reuse_port,
        report.reuse_address,
        report.connect_error,
        report.fd_invalidated,
        1u,
    };
    std::vector<unsigned char> payload;
    payload.reserve(fields.size() * sizeof(u64));
    for (u64 field : fields) append_u64(payload, field);
    return payload;
}

static bool decode_guard_report(const std::vector<unsigned char>& payload, GuardReport& report) {
    report = {};
    if (payload.size() != kGuardReportFields * sizeof(u64)) return false;
    std::array<u64, kGuardReportFields> fields{};
    for (std::size_t i = 0u; i < fields.size(); ++i)
        fields[i] = read_u64(payload.data() + i * sizeof(u64));
    if (fields[18] != 1u) return false;
    report.plan = {static_cast<u32>(fields[0]), static_cast<u32>(fields[1]), fields[2]};
    if (fields[0] != report.plan.positive_ipv4 || fields[1] != report.plan.guard_ipv4) return false;
    report.guard_fd = fields[3];
    report.socket_inode = fields[4];
    report.owner_pid = fields[5];
    report.owner_start = fields[6];
    report.netns = fields[7];
    report.baseline_fd_count = fields[8];
    report.current_fd_count = fields[9];
    report.family = fields[10];
    report.socket_type = fields[11];
    report.fd_cloexec = fields[12];
    report.accept_connection = fields[13];
    report.reuse_port = fields[14];
    report.reuse_address = fields[15];
    report.connect_error = fields[16];
    report.fd_invalidated = fields[17];
    return true;
}

static bool count_open_fds(u64& count) {
    count = 0u;
    const int directory_fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) return false;
    DIR* directory = fdopendir(directory_fd);
    if (directory == nullptr) {
        close(directory_fd);
        return false;
    }
    bool ok = true;
    while (dirent* entry = readdir(directory)) {
        char* end = nullptr;
        errno = 0;
        const long value = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0') continue;
        if (errno != 0 || value < 0 || value > std::numeric_limits<int>::max()) {
            ok = false;
            break;
        }
        if (value != directory_fd) count++;
        if (count > 1024u) {
            ok = false;
            break;
        }
    }
    if (closedir(directory) != 0) ok = false;
    return ok;
}

static bool bounded_connect_refused(u32 ipv4, u16 port, int& connect_error) {
    connect_error = 0;
    const int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (client < 0) return false;
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    endpoint.sin_addr.s_addr = htonl(ipv4);
    int result = connect(client, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint));
    if (result == 0) {
        close(client);
        return false;
    }
    connect_error = errno;
    if (connect_error == EINPROGRESS) {
        pollfd descriptor{client, POLLOUT, 0};
        do {
            result = poll(&descriptor, 1, kHandshakeMs);
        } while (result < 0 && errno == EINTR);
        if (result <= 0) {
            close(client);
            return false;
        }
        socklen_t size = sizeof(connect_error);
        if (getsockopt(client, SOL_SOCKET, SO_ERROR, &connect_error, &size) != 0 ||
            size != sizeof(connect_error)) {
            close(client);
            return false;
        }
    }
    const bool refused = connect_error == ECONNREFUSED;
    close(client);
    return refused;
}

static bool fill_guard_socket_report(int guard_fd,
                                     const privileged_listener::ListenerPlan& plan,
                                     u64 baseline_fd_count,
                                     GuardReport& report) {
    report = {};
    if (guard_fd < 0) return false;
    ProcIdentity self;
    struct stat socket_status{};
    sockaddr_in endpoint{};
    socklen_t endpoint_size = sizeof(endpoint);
    int socket_type = 0, accept_connection = 0, reuse_port = 0, reuse_address = 0;
    socklen_t option_size = sizeof(int);
    const int fd_flags = fcntl(guard_fd, F_GETFD);
    u64 current_fd_count = 0u;
    int connect_error = 0;
    if (!read_proc(getpid(), self) || !self.no_new_privs || !self.capabilities_clear ||
        self.supplementary_groups != 0 || fstat(guard_fd, &socket_status) != 0 ||
        !S_ISSOCK(socket_status.st_mode) ||
        getsockname(guard_fd, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_size) != 0 ||
        endpoint_size != sizeof(endpoint) || endpoint.sin_family != AF_INET ||
        getsockopt(guard_fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_size) != 0 ||
        option_size != sizeof(int) ||
        getsockopt(guard_fd, SOL_SOCKET, SO_ACCEPTCONN, &accept_connection, &option_size) != 0 ||
        option_size != sizeof(int) ||
        getsockopt(guard_fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, &option_size) != 0 ||
        option_size != sizeof(int) ||
        getsockopt(guard_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, &option_size) != 0 ||
        option_size != sizeof(int) || fd_flags < 0 || !count_open_fds(current_fd_count) ||
        !bounded_connect_refused(plan.guard_ipv4, static_cast<u16>(plan.port), connect_error))
        return false;
    report.plan = plan;
    report.guard_fd = static_cast<u64>(guard_fd);
    report.socket_inode = socket_status.st_ino;
    report.owner_pid = static_cast<u64>(self.pid);
    report.owner_start = self.start;
    report.netns = self.netns;
    report.baseline_fd_count = baseline_fd_count;
    report.current_fd_count = current_fd_count;
    report.family = endpoint.sin_family;
    report.socket_type = static_cast<u64>(socket_type);
    report.fd_cloexec = (fd_flags & FD_CLOEXEC) != 0 ? 1u : 0u;
    report.accept_connection = static_cast<u64>(accept_connection);
    report.reuse_port = static_cast<u64>(reuse_port);
    report.reuse_address = static_cast<u64>(reuse_address);
    report.connect_error = static_cast<u64>(connect_error);
    return ntohl(endpoint.sin_addr.s_addr) == plan.guard_ipv4 &&
           ntohs(endpoint.sin_port) == plan.port;
}

static bool validate_guard_report(const GuardReport& report,
                                  const privileged_listener::ListenerPlan& expected_plan,
                                  const ProcIdentity& target,
                                  bool released) {
    privileged_listener::ListenerPlanText text;
    privileged_listener::Diagnostic diagnostic;
    const bool common =
        privileged_listener::validate_listener_plan(report.plan, text, diagnostic) &&
        report.plan.positive_ipv4 == expected_plan.positive_ipv4 &&
        report.plan.guard_ipv4 == expected_plan.guard_ipv4 &&
        report.plan.port == expected_plan.port &&
        report.guard_fd <= static_cast<u64>(std::numeric_limits<int>::max()) &&
        report.socket_inode != 0u && report.owner_pid == static_cast<u64>(target.pid) &&
        report.owner_start == target.start && report.netns == target.netns &&
        report.baseline_fd_count > 0u && report.baseline_fd_count < 1024u &&
        report.family == AF_INET && report.socket_type == SOCK_STREAM && report.fd_cloexec == 1u &&
        report.accept_connection == 0u && report.reuse_port == 0u && report.reuse_address == 0u &&
        report.connect_error == static_cast<u64>(ECONNREFUSED);
    return common && (released ? report.fd_invalidated == 1u &&
                                     report.current_fd_count == report.baseline_fd_count
                               : report.fd_invalidated == 0u &&
                                     report.current_fd_count == report.baseline_fd_count + 1u);
}

static bool secure_as(uid_t uid, gid_t gid) {
    if (setgroups(0, nullptr) != 0 || setgid(gid) != 0 || setuid(uid) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || !clear_caps() || setpgid(0, 0) != 0)
        return false;
    ProcIdentity self;
    return read_proc(getpid(), self) && self.uid == uid && self.gid == gid &&
           self.supplementary_groups == 0 && self.no_new_privs && self.capabilities_clear &&
           self.pgid == getpid();
}

static bool write_trace_step(int fd, char step) {
    ssize_t count;
    do {
        count = write(fd, &step, 1);
    } while (count < 0 && errno == EINTR);
    return count == 1;
}

static bool secure_target(uid_t uid, gid_t gid, int trace_fd) {
    if (setgroups(0, nullptr) != 0 || !write_trace_step(trace_fd, 'G') || setgid(gid) != 0 ||
        !write_trace_step(trace_fd, 'D') || setuid(uid) != 0 || !write_trace_step(trace_fd, 'U') ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || !write_trace_step(trace_fd, 'N') ||
        !clear_caps() || !write_trace_step(trace_fd, 'C') || setpgid(0, 0) != 0 ||
        !write_trace_step(trace_fd, 'P') || !write_trace_step(trace_fd, 'X'))
        return false;
    ProcIdentity self;
    return read_proc(getpid(), self) && self.uid == uid && self.gid == gid &&
           self.supplementary_groups == 0 && self.no_new_privs && self.capabilities_clear &&
           self.pgid == getpid();
}

static bool valid_security_trace(const std::vector<unsigned char>& payload) {
    static constexpr char kExpected[] = "GDUNCPX";
    return payload.size() == sizeof(kExpected) - 1 &&
           memcmp(payload.data(), kExpected, sizeof(kExpected) - 1) == 0;
}

static bool pure_protocol_self_checks(std::string& error) {
    const uid_t uid = getuid() == 0 ? 1000 : getuid();
    const gid_t gid = getgid();
    uid_t parsed_uid = 0;
    gid_t parsed_gid = 0;
    const std::vector<unsigned char> credentials = credentials_payload(uid, gid);
    std::vector<unsigned char> changed_credentials = credentials;
    changed_credentials[8] ^= 1;
    uid_t changed_uid = 0;
    gid_t changed_gid = 0;
    std::vector<unsigned char> short_credentials = credentials;
    short_credentials.pop_back();
    std::vector<unsigned char> root_credentials = credentials_payload(0, gid);
    const std::vector<unsigned char> trace{'G', 'D', 'U', 'N', 'C', 'P', 'X'};
    std::vector<unsigned char> reordered_trace = trace;
    std::swap(reordered_trace[1], reordered_trace[2]);
    std::vector<unsigned char> duplicate_trace = trace;
    duplicate_trace.push_back('X');
    std::vector<unsigned char> short_trace = trace;
    short_trace.pop_back();
    int release_pipe[2] = {-1, -1};
    if (pipe2(release_pipe, O_CLOEXEC) != 0) {
        error = "release-pipe self-check setup failed";
        return false;
    }
    const unsigned char release = 0x4c;
    const bool socket_helper_rejected = !write_exact(release_pipe[1], &release, 1, 50);
    const bool pipe_helper_accepted = write_pipe_exact(release_pipe[1], &release, 1, 50);
    unsigned char received = 0;
    const bool release_exact = read(release_pipe[0], &received, 1) == 1 && received == release;
    close(release_pipe[0]);
    close(release_pipe[1]);
    const bool wait_decisions =
        classify_direct_wait(42, 42, 0) == DirectWaitDisposition::Reaped &&
        classify_direct_wait(0, 42, 0) == DirectWaitDisposition::Retry &&
        classify_direct_wait(-1, 42, EINTR) == DirectWaitDisposition::Retry &&
        classify_direct_wait(-1, 42, ECHILD) == DirectWaitDisposition::Error &&
        classify_direct_wait(-1, 42, ESRCH) == DirectWaitDisposition::Error;
    const ProcFailureProbe self_probe = probe_proc(getpid());
    const std::string self_probe_text = probe_diagnostic(getpid());
    const bool probe_success_is_diagnostic_only =
        self_probe.stat_read && self_probe.stat_parse && self_probe.stat_start_stable &&
        self_probe.status_read && self_probe.status_parse && self_probe.netns_stat &&
        self_probe.exe_stat && self_probe.exe_read && self_probe.cmdline_read &&
        self_probe_text.find("stat{read=1,parse=1") != std::string::npos &&
        self_probe_text.find("status{read=1,parse=1") != std::string::npos &&
        self_probe_text.find("exe{stat=1") != std::string::npos &&
        self_probe_text.find("cmdline{read=1") != std::string::npos;
    pid_t malformed_sid = -1;
    std::uint64_t malformed_start = 0;
    const bool probe_parse_mutations =
        !parse_probe_stat("", malformed_sid, malformed_start) &&
        !parse_probe_stat("(partial) R 1 2", malformed_sid, malformed_start) &&
        !probe_proc(0).stat_read && !probe_proc(0).status_read &&
        probe_diagnostic(0).find("stat{read=0,parse=0") != std::string::npos;
    const bool no_signal_on_echild = reap_owned_child_bounded(getpid()) == OwnedReapResult::Error;
    if (!parse_credentials(credentials, parsed_uid, parsed_gid) || parsed_uid != uid ||
        parsed_gid != gid || !parse_credentials(changed_credentials, changed_uid, changed_gid) ||
        (changed_uid == uid && changed_gid == gid) ||
        credentials_match_peer(changed_credentials, uid, gid) ||
        parse_credentials(short_credentials, changed_uid, changed_gid) ||
        parse_credentials(root_credentials, changed_uid, changed_gid) ||
        !valid_security_trace(trace) || valid_security_trace(reordered_trace) ||
        valid_security_trace(duplicate_trace) || valid_security_trace(short_trace) ||
        !socket_helper_rejected || !pipe_helper_accepted || !release_exact || !wait_decisions ||
        !probe_success_is_diagnostic_only || !probe_parse_mutations || !no_signal_on_echild) {
        error = "credential/security-trace mutation self-check failed";
        return false;
    }
    return true;
}

enum class OwnedWaitResult { Exited, LeaseLost, Error };

static OwnedReapResult reap_owned_child_bounded(pid_t child) {
    if (child <= 1) return OwnedReapResult::Error;
    int status = 0;
    const auto wait_for_child = [&](std::chrono::steady_clock::time_point deadline) {
        while (std::chrono::steady_clock::now() < deadline) {
            const pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) return OwnedReapResult::Reaped;
            if (waited < 0 && errno != EINTR) return OwnedReapResult::Error;
            (void)poll(nullptr, 0, 10);
        }
        return OwnedReapResult::TimedOut;
    };
    const OwnedReapResult initial =
        wait_for_child(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
    if (initial == OwnedReapResult::Reaped || initial == OwnedReapResult::Error) return initial;
    if (kill(child, SIGTERM) != 0 && errno != ESRCH) return OwnedReapResult::Error;
    const OwnedReapResult after_term =
        wait_for_child(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
    if (after_term == OwnedReapResult::Reaped || after_term == OwnedReapResult::Error)
        return after_term;
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) return OwnedReapResult::Error;
    return wait_for_child(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
}

// This is the same gate used by launcher_main: adopted children are only
// drained after the direct broker has been positively reaped.
static bool broker_reap_allows_adopted_drain(OwnedReapResult result) {
    return result == OwnedReapResult::Reaped;
}

class OwnedChildCleanup {
public:
    explicit OwnedChildCleanup(pid_t child,
                               int* downstream_fd = nullptr,
                               bool* cleanup_error = nullptr)
        : child_(child), cleanup_error_(cleanup_error) {
        if (downstream_fd != nullptr) downstream_fds_.push_back(downstream_fd);
    }
    OwnedChildCleanup(const OwnedChildCleanup&) = delete;
    OwnedChildCleanup& operator=(const OwnedChildCleanup&) = delete;
    ~OwnedChildCleanup() {
        if (!armed_) return;
        for (int* downstream_fd : downstream_fds_) {
            if (downstream_fd != nullptr && *downstream_fd >= 0) {
                close(*downstream_fd);
                *downstream_fd = -1;
            }
        }
        if (reap_owned_child_bounded(child_) != OwnedReapResult::Reaped &&
            cleanup_error_ != nullptr)
            *cleanup_error_ = true;
    }
    void add_downstream_fd(int* downstream_fd) {
        if (downstream_fd != nullptr) downstream_fds_.push_back(downstream_fd);
    }
    void disarm() { armed_ = false; }

private:
    pid_t child_;
    std::vector<int*> downstream_fds_;
    bool* cleanup_error_ = nullptr;
    bool armed_ = true;
};

static bool lease_loss_owner_cascade_self_check(std::string& error) {
    int lease_pipe[2] = {-1, -1};
    int event_pipe[2] = {-1, -1};
    if (pipe2(lease_pipe, O_CLOEXEC) != 0 || pipe2(event_pipe, O_CLOEXEC) != 0) {
        if (lease_pipe[0] >= 0) close(lease_pipe[0]);
        if (lease_pipe[1] >= 0) close(lease_pipe[1]);
        if (event_pipe[0] >= 0) close(event_pipe[0]);
        if (event_pipe[1] >= 0) close(event_pipe[1]);
        error = "lease-loss cascade harness pipe setup failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(lease_pipe[0]);
        close(lease_pipe[1]);
        close(event_pipe[0]);
        close(event_pipe[1]);
        error = "lease-loss cascade harness fork failed";
        return false;
    }
    if (child == 0) {
        close(lease_pipe[1]);
        close(event_pipe[0]);
        char byte = 0;
        const ssize_t received = read(lease_pipe[0], &byte, 1);
        close(lease_pipe[0]);
        const unsigned char eof_seen = received == 0 ? 0xe1 : 0xee;
        (void)write(event_pipe[1], &eof_seen, 1);
        close(event_pipe[1]);
        _exit(received == 0 ? 0 : 1);
    }
    close(lease_pipe[0]);
    close(event_pipe[1]);
    close(lease_pipe[1]);
    unsigned char event = 0;
    const bool downstream_eof = read_exact(event_pipe[0], &event, 1, kCleanupMs) && event == 0xe1;
    close(event_pipe[0]);
    const bool reaped = reap_owned_child_bounded(child) == OwnedReapResult::Reaped;
    if (!downstream_eof || !reaped) {
        error = "lease-loss cascade did not close downstream before owner reap";
        return false;
    }
    return true;
}

static bool launcher_error_order_self_check(std::string& error) {
    for (const OwnedReapResult result :
         {OwnedReapResult::Reaped, OwnedReapResult::TimedOut, OwnedReapResult::Error}) {
        std::vector<int> events;
        bool disarmed = false;
        events.push_back(1);  // broker bounded reap completed/failed
        if (broker_reap_allows_adopted_drain(result)) {
            disarmed = true;
            events.push_back(2);  // owner guard disarmed only after Reaped
            events.push_back(3);  // adopted drain
        }
        const bool expected = result == OwnedReapResult::Reaped;
        if (disarmed != expected || (expected && events != std::vector<int>{1, 2, 3}) ||
            (!expected && events != std::vector<int>{1})) {
            error = "launcher error cleanup order/disarm decision was unsafe";
            return false;
        }
    }
    return true;
}

static bool prelaunch_close_first_self_check(std::string& error) {
    int release_pipe[2] = {-1, -1};
    int event_pipe[2] = {-1, -1};
    if (pipe2(release_pipe, O_CLOEXEC) != 0 || pipe2(event_pipe, O_CLOEXEC) != 0) {
        if (release_pipe[0] >= 0) close(release_pipe[0]);
        if (release_pipe[1] >= 0) close(release_pipe[1]);
        if (event_pipe[0] >= 0) close(event_pipe[0]);
        if (event_pipe[1] >= 0) close(event_pipe[1]);
        error = "pre-launch close-first harness pipe setup failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(release_pipe[0]);
        close(release_pipe[1]);
        close(event_pipe[0]);
        close(event_pipe[1]);
        error = "pre-launch close-first harness fork failed";
        return false;
    }
    if (child == 0) {
        close(release_pipe[1]);
        close(event_pipe[0]);
        char byte = 0;
        const ssize_t received = read(release_pipe[0], &byte, 1);
        close(release_pipe[0]);
        const unsigned char eof_seen = received == 0 ? 0xc1 : 0xcf;
        (void)write(event_pipe[1], &eof_seen, 1);
        close(event_pipe[1]);
        _exit(received == 0 ? 0 : 1);
    }
    close(release_pipe[0]);
    close(event_pipe[1]);
    // This models a pre-launch return: close the writer first, then reap the
    // blocked target.  The target's successful exit is the no-signal proof.
    close(release_pipe[1]);
    unsigned char event = 0;
    const bool downstream_eof = read_exact(event_pipe[0], &event, 1, kCleanupMs) && event == 0xc1;
    close(event_pipe[0]);
    const bool reaped = reap_owned_child_bounded(child) == OwnedReapResult::Reaped;
    if (!downstream_eof || !reaped) {
        error = "pre-launch writer close did not let blocked target exit naturally";
        return false;
    }
    return true;
}

static OwnedWaitResult wait_owned_child_bounded(pid_t child,
                                                const std::string& expected_exe,
                                                const std::string& expected_argv,
                                                uid_t expected_uid,
                                                gid_t expected_gid,
                                                ino_t expected_netns,
                                                pid_t expected_pgid,
                                                bool require_capabilities_clear,
                                                int timeout_ms,
                                                int& status,
                                                int lease_fd = -1,
                                                int* downstream_lease_fd = nullptr,
                                                bool return_immediately_on_lease_loss = false) {
    bool lease_revoked = false;
    const auto wait_until = [&](std::chrono::steady_clock::time_point deadline,
                                bool monitor_lease) {
        while (std::chrono::steady_clock::now() < deadline) {
            if (monitor_lease && control_lease_lost(lease_fd)) {
                if (downstream_lease_fd != nullptr && *downstream_lease_fd >= 0) {
                    close(*downstream_lease_fd);
                    *downstream_lease_fd = -1;
                }
                lease_revoked = true;
                return OwnedWaitResult::LeaseLost;
            }
            const pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) return OwnedWaitResult::Exited;
            if (waited < 0 && errno != EINTR) return OwnedWaitResult::Error;
            (void)poll(nullptr, 0, 10);
        }
        return OwnedWaitResult::Error;
    };
    OwnedWaitResult result =
        wait_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms), true);
    if (result == OwnedWaitResult::Exited) return result;
    lease_revoked = result == OwnedWaitResult::LeaseLost;
    if (lease_revoked && return_immediately_on_lease_loss) return OwnedWaitResult::LeaseLost;
    if (lease_revoked) {
        // The downstream lease was closed by wait_until.  Give this owner a
        // full bounded natural-reap window before any identity-safe signal.
        result = wait_until(
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs), false);
        if (result == OwnedWaitResult::Exited) return OwnedWaitResult::LeaseLost;
    }
    ProcIdentity before;
    if (child <= 1 || expected_pgid <= 1 || !read_proc(child, before, require_capabilities_clear) ||
        before.pid != child || before.ppid != getpid() || before.pgid != expected_pgid ||
        before.uid != expected_uid || before.gid != expected_gid ||
        before.netns != expected_netns || before.exe != expected_exe ||
        before.cmdline != expected_argv || kill(child, SIGTERM) != 0)
        return OwnedWaitResult::Error;
    // Once EOF has revoked the lease, cleanup must not short-circuit on that
    // same EOF: this owner still has to reap its child.
    result =
        wait_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs), false);
    if (result == OwnedWaitResult::Exited)
        return lease_revoked ? OwnedWaitResult::LeaseLost : OwnedWaitResult::Exited;
    ProcIdentity after_term;
    if (!read_proc(child, after_term, require_capabilities_clear) ||
        !same_process_identity(before, after_term) || after_term.ppid != getpid() ||
        after_term.pgid != expected_pgid || kill(child, SIGKILL) != 0)
        return OwnedWaitResult::Error;
    result =
        wait_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs), false);
    if (result != OwnedWaitResult::Exited) return OwnedWaitResult::Error;
    return lease_revoked ? OwnedWaitResult::LeaseLost : OwnedWaitResult::Exited;
}

struct ExactChildState {
    pid_t pid = -1;
    int pidfd = -1;
    bool pidfd_acquired = false;
    bool forked = false;
    bool reaped = false;
    bool post_exec_identity = false;
    int wait_status = 0;
    ProcIdentity identity;
    struct stat executable_status{};
    std::string executable;
    std::string argv;
    std::string source_path;
    std::string log_path;
    std::string directory_path;
    struct stat directory_status{};
    struct stat source_status{};
    struct stat log_status{};
    u64 listener_inode = 0u;
    bool guard_release_safe = false;
    bool cleanup_complete = false;
};

static bool validate_exact_custody_endpoint(int fd, pid_t expected_dropped) {
    int type = 0;
    socklen_t type_size = sizeof(type);
    Peer peer;
    const int enabled = 1;
    const int flags = fcntl(fd, F_GETFD);
    return fd == kExactCustodyFd && expected_dropped > 1 && flags >= 0 &&
           getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0 &&
           type_size == sizeof(type) && type == SOCK_SEQPACKET && get_peer(fd, peer) &&
           peer.pid == expected_dropped && peer.uid == 0u && peer.gid == 0u &&
           setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0 &&
           fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool write_all_fd(int fd, const std::string& contents) {
    std::size_t offset = 0u;
    while (offset < contents.size()) {
        const ssize_t count = write(fd, contents.data() + offset, contents.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

static bool read_process_tcp_table(pid_t pid, privileged_listener::ProcTcpTable& table) {
    std::string contents;
    privileged_listener::Diagnostic diagnostic;
    return pid > 1 &&
           read_file("/proc/" + std::to_string(pid) + "/net/tcp",
                     contents,
                     privileged_listener::kMaxProcBytes) &&
           privileged_listener::parse_proc_net_tcp(contents, table, diagnostic);
}

static bool process_socket_inodes(pid_t pid, std::vector<u64>& inodes) {
    inodes.clear();
    if (pid <= 1) return false;
    const std::string directory_path = "/proc/" + std::to_string(pid) + "/fd";
    const int directory_fd = open(directory_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) return false;
    DIR* directory = fdopendir(directory_fd);
    if (directory == nullptr) {
        close(directory_fd);
        return false;
    }
    bool ok = true;
    while (dirent* entry = readdir(directory)) {
        char* end = nullptr;
        errno = 0;
        const long fd = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0') continue;
        if (errno != 0 || fd < 0 || fd > std::numeric_limits<int>::max()) {
            ok = false;
            break;
        }
        std::array<char, 64> link{};
        const ssize_t length =
            readlinkat(directory_fd, entry->d_name, link.data(), link.size() - 1u);
        if (length <= 9 || static_cast<std::size_t>(length) >= link.size()) continue;
        link[static_cast<std::size_t>(length)] = '\0';
        const std::string value(link.data(), static_cast<std::size_t>(length));
        if (value.rfind("socket:[", 0u) != 0u || value.back() != ']') continue;
        u64 inode = 0u;
        const std::string inode_text = value.substr(8u, value.size() - 9u);
        if (!parse_u64(inode_text.c_str(), inode) || inode == 0u ||
            inodes.size() >= privileged_listener::kMaxOwnedSocketInodes) {
            ok = false;
            break;
        }
        inodes.push_back(inode);
    }
    if (closedir(directory) != 0) ok = false;
    std::sort(inodes.begin(), inodes.end());
    if (std::adjacent_find(inodes.begin(), inodes.end()) != inodes.end()) ok = false;
    return ok;
}

static bool pidfd_link_matches(pid_t owner, int fd) {
    if (owner <= 1 || fd < 0) return false;
    const std::string path = "/proc/" + std::to_string(owner) + "/fd/" + std::to_string(fd);
    std::array<char, 64> link{};
    const ssize_t length = readlink(path.c_str(), link.data(), link.size() - 1u);
    if (length <= 0 || static_cast<std::size_t>(length) >= link.size()) return false;
    return std::string(link.data(), static_cast<std::size_t>(length)) == "anon_inode:[pidfd]";
}

static bool exact_pidfd_binding(int fd, pid_t expected_pid) {
    if (fd < 0 || expected_pid <= 1) return false;
    std::string text;
    if (!read_file("/proc/self/fdinfo/" + std::to_string(fd), text, 4096)) return false;
    std::istringstream lines(text);
    std::string key;
    bool found = false;
    while (lines >> key) {
        if (key == "Pid:") {
            long pid = 0;
            if (found || !(lines >> pid) || pid != expected_pid) return false;
            found = true;
        }
        std::string rest;
        std::getline(lines, rest);
    }
    return found;
}

static bool exact_log_ready(const std::string& log,
                            const std::string& source_path,
                            u16 port,
                            u64& backend) {
    backend = 0u;
    if (log.empty() || log.size() > privileged_listener::kMaxCollisionLogBytes ||
        log.find('\0') != std::string::npos)
        return false;
    const std::string loaded = "Loaded program: " + source_path + " (opt O2)\n";
    const std::string listening =
        "Listening on port " + std::to_string(port) + " with 1 shard(s)\n";
    const auto occurrences = [&](const std::string& needle) {
        std::size_t count = 0u, offset = 0u;
        while ((offset = log.find(needle, offset)) != std::string::npos) {
            count++;
            offset += needle.size();
        }
        return count;
    };
    const std::size_t epoll = occurrences("Backend: epoll\n");
    const std::size_t io_uring = occurrences("Backend: io_uring\n");
    if (epoll + io_uring != 1u || occurrences(loaded) != 1u || occurrences(listening) != 1u ||
        log.find("Backend: io_uring TLS") != std::string::npos ||
        log.find("Failed") != std::string::npos)
        return false;
    const std::size_t loaded_at = log.find(loaded);
    const std::size_t backend_at =
        log.find(epoll == 1u ? "Backend: epoll\n" : "Backend: io_uring\n");
    const std::size_t listening_at = log.find(listening);
    if (!(loaded_at < backend_at && backend_at < listening_at)) return false;
    backend = epoll == 1u ? 1u : 2u;
    return true;
}

static bool exact_http_exchange(u32 ipv4,
                                u16 port,
                                std::chrono::steady_clock::time_point deadline,
                                ExactRutReport& report) {
    static constexpr char request[] =
        "GET / HTTP/1.1\r\nHost: exact-listener.invalid\r\nConnection: close\r\n\r\n";
    static constexpr char expected[] =
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static_assert(sizeof(expected) - 1u == 65u);
    const int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (client < 0) return false;
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    endpoint.sin_addr.s_addr = htonl(ipv4);
    int rc = connect(client, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint));
    if (rc < 0 && errno == EINPROGRESS) {
        if (!wait_fd(client, POLLOUT, deadline)) {
            close(client);
            return false;
        }
        int socket_error = 0;
        socklen_t size = sizeof(socket_error);
        if (getsockopt(client, SOL_SOCKET, SO_ERROR, &socket_error, &size) != 0 ||
            socket_error != 0) {
            close(client);
            return false;
        }
    } else if (rc < 0) {
        close(client);
        return false;
    }
    std::size_t sent = 0u;
    while (sent < sizeof(request) - 1u) {
        if (!wait_fd(client, POLLOUT, deadline)) {
            close(client);
            return false;
        }
        const ssize_t count =
            send(client, request + sent, sizeof(request) - 1u - sent, MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) {
            close(client);
            return false;
        }
        sent += static_cast<std::size_t>(count);
    }
    std::string response;
    response.reserve(sizeof(expected));
    bool eof = false;
    while (response.size() <= sizeof(expected) - 1u) {
        if (!wait_fd(client, POLLIN | POLLHUP, deadline)) break;
        std::array<char, 128> bytes{};
        const ssize_t count = recv(client, bytes.data(), bytes.size(), 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) break;
        if (count == 0) {
            eof = true;
            break;
        }
        response.append(bytes.data(), static_cast<std::size_t>(count));
    }
    linger reset_after_eof{1, 0};
    const bool reset_configured =
        eof &&
        setsockopt(client, SOL_SOCKET, SO_LINGER, &reset_after_eof, sizeof(reset_after_eof)) == 0;
    close(client);
    report.response_bytes = response.size();
    report.response_exact = response == std::string(expected, sizeof(expected) - 1u) ? 1u : 0u;
    report.prompt_eof = eof ? 1u : 0u;
    return report.response_exact == 1u && report.prompt_eof == 1u && reset_configured;
}

static bool connect_refused_until(u32 ipv4,
                                  u16 port,
                                  std::chrono::steady_clock::time_point deadline,
                                  int& connect_error) {
    connect_error = 0;
    const int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (client < 0) return false;
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    endpoint.sin_addr.s_addr = htonl(ipv4);
    int result = connect(client, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint));
    if (result == 0) {
        close(client);
        return false;
    }
    connect_error = errno;
    if (connect_error == EINPROGRESS) {
        if (!wait_fd(client, POLLOUT, deadline)) {
            close(client);
            return false;
        }
        socklen_t size = sizeof(connect_error);
        if (getsockopt(client, SOL_SOCKET, SO_ERROR, &connect_error, &size) != 0 ||
            size != sizeof(connect_error)) {
            close(client);
            return false;
        }
    }
    close(client);
    return connect_error == ECONNREFUSED;
}

static bool exact_child_identity(const ExactChildState& child,
                                 const struct stat& executable,
                                 ino_t netns,
                                 ProcIdentity& current) {
    return child.pid > 1 && read_proc(child.pid, current) && current.pid == child.pid &&
           current.ppid == getpid() && current.pgid == child.pid && current.sid == getsid(0) &&
           current.uid == getuid() && current.gid == getgid() &&
           current.supplementary_groups == 0 && current.no_new_privs &&
           current.capabilities_clear && current.netns == netns &&
           current.exe_dev == executable.st_dev && current.exe_ino == executable.st_ino &&
           current.exe == child.executable && current.cmdline == child.argv;
}

static bool unlink_regular_at_if_identity(int directory_fd,
                                          const char* name,
                                          const struct stat& expected) {
    struct stat current{};
    return directory_fd >= 0 && expected.st_ino != 0u &&
           fstatat(directory_fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
           current.st_dev == expected.st_dev && current.st_ino == expected.st_ino &&
           S_ISREG(current.st_mode) && unlinkat(directory_fd, name, 0) == 0;
}

static bool exact_direct_wait(ExactChildState& child) {
    if (!child.forked || child.pid <= 1 || child.reaped) return !child.forked || child.reaped;
    for (;;) {
        const pid_t waited = waitpid(child.pid, &child.wait_status, WNOHANG);
        if (waited == child.pid) {
            child.reaped = true;
            return true;
        }
        if (waited == 0) return false;
        if (waited < 0 && errno == EINTR) continue;
        return false;
    }
}

static bool signal_exact_owned_child(ExactChildState& child, int signal_number) {
    if (exact_direct_wait(child)) return true;
#ifdef SYS_pidfd_send_signal
    if (child.pidfd >= 0 &&
        syscall(SYS_pidfd_send_signal, child.pidfd, signal_number, nullptr, 0) == 0)
        return true;
#endif
    // An unreaped direct child still owns its PID, so the fork ownership itself
    // is safe authority even before the public executable identity is visible.
    return kill(child.pid, signal_number) == 0 || errno == ESRCH;
}

static bool reap_exact_owned_child(ExactChildState& child,
                                   std::chrono::steady_clock::time_point deadline) {
    if (!child.forked) return true;
    if (exact_direct_wait(child)) return true;
    if (std::chrono::steady_clock::now() >= deadline) {
        errno = ETIMEDOUT;
        return false;
    }
    if (!signal_exact_owned_child(child, SIGTERM)) return false;
    const auto kill_deadline =
        std::chrono::steady_clock::now() + (deadline - std::chrono::steady_clock::now()) / 2;
    bool killed = false;
    while (std::chrono::steady_clock::now() < deadline) {
        if (exact_direct_wait(child)) return true;
        if (!killed && std::chrono::steady_clock::now() >= kill_deadline) {
            if (!signal_exact_owned_child(child, SIGKILL)) return false;
            killed = true;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() > 0)
            (void)poll(nullptr, 0, static_cast<int>(std::min<std::int64_t>(10, remaining.count())));
    }
    if (exact_direct_wait(child)) return true;
    errno = ETIMEDOUT;
    return false;
}

static int reopen_exact_directory(const ExactChildState& child) {
    if (child.directory_path.empty() || child.directory_status.st_ino == 0u) return -1;
    const int fd =
        open(child.directory_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat current{};
    if (fd < 0 || fstat(fd, &current) != 0 || current.st_dev != child.directory_status.st_dev ||
        current.st_ino != child.directory_status.st_ino || !S_ISDIR(current.st_mode) ||
        current.st_uid != getuid() || current.st_gid != getgid() ||
        (current.st_mode & 0777) != 0700) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

enum class ExactHandoffResult { NotSent, AwaitingAck, Acked };

static ExactHandoffResult handoff_failed_exact_cleanup(const Token& token,
                                                       const GuardReport& held,
                                                       int guard_fd,
                                                       const ExactChildState& child) {
    if (!child.forked || child.pid <= 1 || guard_fd < 0) return ExactHandoffResult::NotSent;
    ProcIdentity target_identity;
    ProcIdentity child_identity = child.identity;
    if (!read_proc(getpid(), target_identity) || target_identity.pid != getpid() ||
        target_identity.ppid <= 1)
        return ExactHandoffResult::NotSent;
    if ((!child.reaped && (!read_proc(child.pid, child_identity, false) ||
                           child_identity.pid != child.pid || child_identity.ppid != getpid())) ||
        child_identity.start == 0u || child_identity.netns != held.netns)
        return ExactHandoffResult::NotSent;
    const int directory_fd = reopen_exact_directory(child);
    if (directory_fd < 0) return ExactHandoffResult::NotSent;
    ExactCustodyRecord record;
    record.child_pid = static_cast<u64>(child.pid);
    record.child_start = child_identity.start;
    record.child_exe_dev = child_identity.exe_dev;
    record.child_exe_ino = child_identity.exe_ino;
    record.listener_inode = child.listener_inode;
    record.positive_ipv4 = held.plan.positive_ipv4;
    record.guard_ipv4 = held.plan.guard_ipv4;
    record.port = held.plan.port;
    record.guard_inode = held.socket_inode;
    record.netns = held.netns;
    record.directory_dev = child.directory_status.st_dev;
    record.directory_ino = child.directory_status.st_ino;
    record.source_dev = child.source_status.st_dev;
    record.source_ino = child.source_status.st_ino;
    record.log_dev = child.log_status.st_dev;
    record.log_ino = child.log_status.st_ino;
    record.target_pid = static_cast<u64>(getpid());
    record.target_start = target_identity.start;
    record.has_pidfd = !child.reaped && child.pidfd >= 0 ? 1u : 0u;
    record.child_reaped = child.reaped ? 1u : 0u;
    ExactEscrowRights rights;
    rights.guard = guard_fd;
    rights.pidfd = child.pidfd;
    rights.directory = directory_fd;
    const auto deadline = new_exact_cleanup_deadline();
    const bool sent = send_exact_custody(kExactCustodyFd, token, record, rights, deadline);
    close(directory_fd);
    if (!sent) return ExactHandoffResult::NotSent;
    return receive_exact_custody_ack(kExactCustodyFd,
                                     token,
                                     target_identity.ppid,
                                     target_identity.uid,
                                     target_identity.gid,
                                     deadline)
               ? ExactHandoffResult::Acked
               : ExactHandoffResult::AwaitingAck;
}

static bool remove_exact_temp(int directory_fd, const char* name, const struct stat& expected) {
    struct stat current{};
    errno = 0;
    if (directory_fd < 0) return false;
    if (fstatat(directory_fd, name, &current, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT;
    return expected.st_ino != 0u && current.st_dev == expected.st_dev &&
           current.st_ino == expected.st_ino && S_ISREG(current.st_mode) &&
           unlinkat(directory_fd, name, 0) == 0;
}

static bool exact_guard_release_gate(const ExactChildState& child,
                                     bool proc_observed,
                                     bool listener_absent) {
    return (!child.forked || child.reaped) && proc_observed && listener_absent;
}

static bool exact_live_fd_count(u64 observed, const GuardReport& held) {
    return observed == held.current_fd_count + 1u;
}

static std::chrono::steady_clock::time_point new_exact_cleanup_deadline() {
    return std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs * 2);
}

enum class ExactCleanupFault { None, ProcFailure, ListenerPresent };

struct ExactCleanupObservation {
    bool proc_observed = false;
    bool listener_absent = false;
    int error_number = 0;
    u64 attempts = 0u;
};

static bool observe_exact_listener_absence(const ExactChildState& child,
                                           const GuardReport& held,
                                           std::chrono::steady_clock::time_point deadline,
                                           ExactCleanupFault fault,
                                           ExactCleanupObservation& observation) {
    observation = {};
    while (held.plan.port != 0u && std::chrono::steady_clock::now() < deadline) {
        if (observation.attempts < 1024u) ++observation.attempts;
        privileged_listener::ProcTcpTable table;
        const bool observed =
            fault == ExactCleanupFault::ListenerPresent ||
            (fault != ExactCleanupFault::ProcFailure && read_process_tcp_table(getpid(), table));
        if (observed) {
            observation.proc_observed = true;
            observation.listener_absent =
                fault != ExactCleanupFault::ListenerPresent &&
                exact_listener_absent(table, held.plan, child.listener_inode);
            if (observation.listener_absent) return true;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() > 0)
            (void)poll(nullptr, 0, static_cast<int>(std::min<std::int64_t>(10, remaining.count())));
    }
    observation.error_number = ETIMEDOUT;
    return false;
}

static bool exact_transaction_self_check(std::string& error) {
    ExactChildState early;
    early.pid = fork();
    if (early.pid < 0) {
        error = "exact ownership early-exit fork self-check failed";
        return false;
    }
    if (early.pid == 0) _exit(7);
    early.forked = true;
    siginfo_t early_info{};
    bool early_waitable = false;
    const auto early_deadline = new_exact_cleanup_deadline();
    while (std::chrono::steady_clock::now() < early_deadline) {
        memset(&early_info, 0, sizeof(early_info));
        const int waited =
            waitid(P_PID, static_cast<id_t>(early.pid), &early_info, WEXITED | WNOHANG | WNOWAIT);
        if (waited == 0 && early_info.si_pid == early.pid) {
            early_waitable = true;
            break;
        }
        if (waited == 0) {
            (void)poll(nullptr, 0, 10);
            continue;
        }
        if (errno != EINTR) break;
    }
    if (!early_waitable) {
        (void)reap_exact_owned_child(early, new_exact_cleanup_deadline());
        error = "exact ownership early-exit WNOWAIT self-check failed";
        return false;
    }
    if (!reap_exact_owned_child(early, new_exact_cleanup_deadline()) || !early.reaped ||
        early.pid <= 1 || !WIFEXITED(early.wait_status) || WEXITSTATUS(early.wait_status) != 7) {
        error = "early-reaped exact child ownership was lost";
        return false;
    }
    ExactChildState no_pidfd;
    no_pidfd.pid = fork();
    if (no_pidfd.pid < 0) {
        error = "exact ownership pidfd-failure model fork failed";
        return false;
    }
    if (no_pidfd.pid == 0) {
        for (;;) pause();
    }
    no_pidfd.forked = true;
    if (!reap_exact_owned_child(no_pidfd, new_exact_cleanup_deadline()) || !no_pidfd.reaped ||
        no_pidfd.pidfd != -1) {
        error = "pidfd-open failure model did not retain direct child reap authority";
        return false;
    }
    ExactChildState deadline_child;
    deadline_child.pid = fork();
    if (deadline_child.pid < 0) {
        error = "exact bounded-reap fault model fork failed";
        return false;
    }
    if (deadline_child.pid == 0) {
        for (;;) pause();
    }
    deadline_child.forked = true;
    const auto expired = std::chrono::steady_clock::now();
    const bool expired_reaped = reap_exact_owned_child(deadline_child, expired);
    const bool expired_bounded =
        std::chrono::steady_clock::now() - expired <= std::chrono::milliseconds(100);
    if (expired_reaped || deadline_child.reaped || !expired_bounded) {
        (void)reap_exact_owned_child(deadline_child, new_exact_cleanup_deadline());
        error = "expired exact child reap did not return boundedly fail-closed";
        return false;
    }
    if (!reap_exact_owned_child(deadline_child, new_exact_cleanup_deadline()) ||
        !deadline_child.reaped) {
        error = "bounded-reap fault model child was not subsequently reclaimed";
        return false;
    }
    ExactChildState live;
    live.forked = true;
    GuardReport held;
    held.current_fd_count = 5u;
    if (exact_guard_release_gate(live, true, true) ||
        exact_guard_release_gate(early, false, true) ||
        exact_guard_release_gate(early, true, false) ||
        !exact_guard_release_gate(early, true, true) || exact_live_fd_count(7u, held) ||
        !exact_live_fd_count(6u, held)) {
        error = "cleanup-before-witness/proc-failure/transient-FD gate self-check failed";
        return false;
    }
    held.plan.port = 1u;
    ExactCleanupObservation observation;
    const auto proc_start = std::chrono::steady_clock::now();
    if (observe_exact_listener_absence(early,
                                       held,
                                       proc_start + std::chrono::milliseconds(30),
                                       ExactCleanupFault::ProcFailure,
                                       observation) ||
        observation.proc_observed || observation.listener_absent ||
        exact_guard_release_gate(early, observation.proc_observed, observation.listener_absent) ||
        observation.error_number != ETIMEDOUT || observation.attempts == 0u ||
        std::chrono::steady_clock::now() - proc_start > std::chrono::milliseconds(200)) {
        error = "persistent proc-observation failure did not return boundedly fail-closed";
        return false;
    }
    const auto listener_start = std::chrono::steady_clock::now();
    if (observe_exact_listener_absence(early,
                                       held,
                                       listener_start + std::chrono::milliseconds(30),
                                       ExactCleanupFault::ListenerPresent,
                                       observation) ||
        !observation.proc_observed || observation.listener_absent ||
        exact_guard_release_gate(early, observation.proc_observed, observation.listener_absent) ||
        observation.error_number != ETIMEDOUT || observation.attempts == 0u ||
        std::chrono::steady_clock::now() - listener_start > std::chrono::milliseconds(200)) {
        error = "persistent listener evidence did not return boundedly fail-closed";
        return false;
    }
    return true;
}

enum class ExactCustodyMutation { Canonical, MissingRights, ExtraRights, Truncated, WrongCreds };

static bool exact_custody_peek_self_check(std::string& error) {
    if (exact_post_reap_custody_action(ExactCustodyPeek::Record) !=
            ExactPostReapCustodyAction::Receive ||
        exact_post_reap_custody_action(ExactCustodyPeek::Eof) !=
            ExactPostReapCustodyAction::ReturnExited ||
        exact_post_reap_custody_action(ExactCustodyPeek::Retry) !=
            ExactPostReapCustodyAction::Retry ||
        exact_post_reap_custody_action(ExactCustodyPeek::Error) !=
            ExactPostReapCustodyAction::Hold) {
        error = "exact post-reap custody record/EOF decision failed";
        return false;
    }
    for (bool queued_record : {true, false}) {
        u64 baseline = 0u;
        int sockets[2] = {-1, -1};
        const int pass_credentials = 1;
        if (!count_open_fds(baseline) ||
            socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
            error = "exact custody EOF peek self-check setup failed";
            return false;
        }
        if (setsockopt(
                sockets[0], SOL_SOCKET, SO_PASSCRED, &pass_credentials, sizeof(pass_credentials)) !=
            0) {
            close(sockets[0]);
            close(sockets[1]);
            error = "exact custody EOF peek self-check credential setup failed";
            return false;
        }
        if (queued_record) {
            const int transferred = open("/dev/null", O_RDONLY | O_CLOEXEC);
            unsigned char byte = 0xa5u;
            alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> control{};
            iovec vector{&byte, 1u};
            msghdr message{};
            message.msg_iov = &vector;
            message.msg_iovlen = 1u;
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            cmsghdr* header = CMSG_FIRSTHDR(&message);
            if (transferred < 0 || header == nullptr) {
                if (transferred >= 0) close(transferred);
                close(sockets[0]);
                close(sockets[1]);
                error = "exact custody EOF peek self-check right setup failed";
                return false;
            }
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(header), &transferred, sizeof(transferred));
            const bool sent = sendmsg(sockets[1], &message, MSG_NOSIGNAL) == 1;
            close(transferred);
            if (!sent) {
                close(sockets[0]);
                close(sockets[1]);
                error = "exact custody EOF peek self-check send failed";
                return false;
            }
        }
        close(sockets[1]);
        sockets[1] = -1;
        pollfd descriptor{sockets[0], POLLIN | POLLHUP, 0};
        if (poll(&descriptor, 1, kCleanupMs) <= 0 || (descriptor.revents & POLLHUP) == 0 ||
            peek_exact_custody(sockets[0], true) !=
                (queued_record ? ExactCustodyPeek::Record : ExactCustodyPeek::Eof)) {
            close(sockets[0]);
            error = "exact custody record/EOF peek classification failed";
            return false;
        }
        if (queued_record) {
            unsigned char byte = 0u;
            alignas(cmsghdr) std::array<unsigned char,
                                        CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))>
                control{};
            iovec vector{&byte, 1u};
            msghdr message{};
            message.msg_iov = &vector;
            message.msg_iovlen = 1u;
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            const ssize_t received = recvmsg(sockets[0], &message, MSG_CMSG_CLOEXEC);
            bool right_preserved = false;
            for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
                 header = CMSG_NXTHDR(&message, header))
                if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
                    header->cmsg_len == CMSG_LEN(sizeof(int)))
                    right_preserved = true;
            close_rights_in_message(message);
            if (received != 1 || byte != 0xa5u || !right_preserved ||
                peek_exact_custody(sockets[0], true) != ExactCustodyPeek::Eof) {
                close(sockets[0]);
                error = "exact custody peek consumed or lost queued rights";
                return false;
            }
        }
        close(sockets[0]);
        u64 after = 0u;
        if (!count_open_fds(after) || after != baseline) {
            error = "exact custody EOF peek self-check leaked a descriptor";
            return false;
        }
    }
    return true;
}

static bool exact_custody_ancillary_self_check(std::string& error) {
    if (!exact_custody_peek_self_check(error)) return false;
    for (ExactCustodyMutation mutation : {ExactCustodyMutation::Canonical,
                                          ExactCustodyMutation::MissingRights,
                                          ExactCustodyMutation::ExtraRights,
                                          ExactCustodyMutation::Truncated,
                                          ExactCustodyMutation::WrongCreds}) {
        int sockets[2] = {-1, -1};
        const int enabled = 1;
        u64 baseline = 0u;
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0 ||
            setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0 ||
            !count_open_fds(baseline)) {
            error = "exact custody ancillary self-check setup failed";
            return false;
        }
        const pid_t sender = fork();
        if (sender < 0) {
            close(sockets[0]);
            close(sockets[1]);
            error = "exact custody ancillary self-check fork failed";
            return false;
        }
        if (sender == 0) {
            close(sockets[0]);
            Token token{};
            token.bytes[0] = 0xa5u;
            ExactCustodyRecord record;
            record.child_pid = 101u;
            record.child_start = 102u;
            record.child_exe_dev = 103u;
            record.child_exe_ino = 104u;
            record.listener_inode = 105u;
            record.positive_ipv4 = 0x7f000002u;
            record.guard_ipv4 = 0x7f000003u;
            record.port = 8080u;
            record.guard_inode = 106u;
            record.netns = 107u;
            record.directory_dev = 108u;
            record.directory_ino = 109u;
            record.source_dev = 110u;
            record.source_ino = 111u;
            record.log_dev = 112u;
            record.log_ino = 113u;
            record.target_pid = static_cast<u64>(getpid());
            record.target_start = 115u;
            record.has_pidfd = mutation == ExactCustodyMutation::ExtraRights ? 0u : 1u;
            ExactEscrowRights rights;
            rights.guard = open("/dev/null", O_RDONLY | O_CLOEXEC);
            rights.pidfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            rights.directory = open("/dev/null", O_RDONLY | O_CLOEXEC);
            const std::vector<unsigned char> canonical = encode_exact_custody(record, token);
            std::vector<unsigned char> wire = canonical;
            if (mutation == ExactCustodyMutation::Truncated) wire.push_back(0u);
            bool sent = false;
            if (mutation == ExactCustodyMutation::Canonical ||
                mutation == ExactCustodyMutation::WrongCreds) {
                sent = send_exact_custody(
                    sockets[1],
                    token,
                    record,
                    rights,
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
            } else if (mutation == ExactCustodyMutation::MissingRights ||
                       mutation == ExactCustodyMutation::Truncated) {
                sent = send(sockets[1], wire.data(), wire.size(), MSG_NOSIGNAL) ==
                       static_cast<ssize_t>(wire.size());
            } else {
                alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(3 * sizeof(int))> control{};
                const std::array<int, 3> fds{rights.guard, rights.pidfd, rights.directory};
                iovec vector{wire.data(), wire.size()};
                msghdr message{};
                message.msg_iov = &vector;
                message.msg_iovlen = 1;
                message.msg_control = control.data();
                message.msg_controllen = control.size();
                cmsghdr* header = CMSG_FIRSTHDR(&message);
                header->cmsg_level = SOL_SOCKET;
                header->cmsg_type = SCM_RIGHTS;
                header->cmsg_len = CMSG_LEN(fds.size() * sizeof(int));
                memcpy(CMSG_DATA(header), fds.data(), fds.size() * sizeof(int));
                sent = sendmsg(sockets[1], &message, MSG_NOSIGNAL) ==
                       static_cast<ssize_t>(wire.size());
            }
            if (sent && mutation == ExactCustodyMutation::Canonical) {
                const int pass_credentials = 1;
                sent = setsockopt(sockets[1],
                                  SOL_SOCKET,
                                  SO_PASSCRED,
                                  &pass_credentials,
                                  sizeof(pass_credentials)) == 0 &&
                       receive_exact_custody_ack(sockets[1],
                                                 token,
                                                 getppid(),
                                                 getuid(),
                                                 getgid(),
                                                 std::chrono::steady_clock::now() +
                                                     std::chrono::milliseconds(kCleanupMs));
            }
            rights.close_all();
            close(sockets[1]);
            _exit(sent ? 0 : 1);
        }
        close(sockets[1]);
        Token token{};
        token.bytes[0] = 0xa5u;
        ExactCustodyRecord record;
        ExactEscrowRights rights;
        const pid_t expected = mutation == ExactCustodyMutation::WrongCreds ? sender + 1 : sender;
        const bool received = receive_exact_custody(sockets[0],
                                                    token,
                                                    expected,
                                                    getuid(),
                                                    getgid(),
                                                    new_exact_cleanup_deadline(),
                                                    record,
                                                    rights);
        const bool canonical = mutation == ExactCustodyMutation::Canonical;
        const bool acked =
            !canonical || send_exact_custody_ack(sockets[0], token, new_exact_cleanup_deadline());
        const bool wrong_types =
            received && (fcntl(rights.guard, F_GETFD) < 0 || fcntl(rights.directory, F_GETFD) < 0);
        rights.close_all();
        close(sockets[0]);
        int status = 0;
        bool reaped = false;
        const auto deadline = new_exact_cleanup_deadline();
        while (std::chrono::steady_clock::now() < deadline) {
            const pid_t waited = waitpid(sender, &status, WNOHANG);
            if (waited == sender) {
                reaped = true;
                break;
            }
            if (waited < 0 && errno != EINTR) break;
            (void)poll(nullptr, 0, 10);
        }
        u64 after = 0u;
        if (received != canonical || !acked || wrong_types || !reaped || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 || !count_open_fds(after) || after + 2u != baseline) {
            error = "exact custody ancillary inventory/credential mutation self-check failed";
            return false;
        }
    }
    return true;
}

static bool cleanup_exact_child(ExactChildState& child,
                                const GuardReport& held,
                                int guard_fd,
                                ExactRutCleanedReport* cleaned,
                                bool require_clean_exit,
                                std::chrono::steady_clock::time_point deadline,
                                ExactFailureReport* failure = nullptr,
                                ExactCleanupFault fault = ExactCleanupFault::None) {
    const bool reaped = reap_exact_owned_child(child, deadline);
    const int reap_error = reaped ? 0 : (errno != 0 ? errno : ETIMEDOUT);
    const bool clean_exit = reaped && child.forked && WIFEXITED(child.wait_status) &&
                            WEXITSTATUS(child.wait_status) == 0;
    bool pidfd_invalidated = false;
    if (reaped && child.pidfd >= 0) {
        const int old = child.pidfd;
        close(child.pidfd);
        child.pidfd = -1;
        errno = 0;
        pidfd_invalidated = fcntl(old, F_GETFD) < 0 && errno == EBADF;
    }
    const int directory_fd = reaped ? reopen_exact_directory(child) : -1;
    const bool no_temp_custody = child.directory_path.empty() && child.source_status.st_ino == 0u &&
                                 child.log_status.st_ino == 0u;
    const bool source_removed =
        reaped && (no_temp_custody ||
                   remove_exact_temp(directory_fd, "exact-listener.rut", child.source_status));
    const bool log_removed =
        reaped && (no_temp_custody ||
                   remove_exact_temp(directory_fd, "exact-listener.log", child.log_status));
    if (directory_fd >= 0) close(directory_fd);
    u64 fd_count = 0u;
    int guard_error = 0;
    ExactCleanupObservation observation;
    const bool absence_observed =
        reaped && observe_exact_listener_absence(child, held, deadline, fault, observation);
    const bool proc_observed = absence_observed && observation.proc_observed;
    const bool listener_absent = absence_observed && observation.listener_absent;
    const bool child_absent = !child.forked || (reaped && !process_alive(child.pid));
    const bool guard_deadline_live = std::chrono::steady_clock::now() < deadline;
    if (!guard_deadline_live) guard_error = ETIMEDOUT;
    const bool guard_ok =
        target_socket_inode(getpid(), guard_fd, held.socket_inode) && guard_deadline_live &&
        connect_refused_until(
            held.plan.guard_ipv4, static_cast<u16>(held.plan.port), deadline, guard_error);
    const bool fd_ok = count_open_fds(fd_count) && fd_count == held.current_fd_count;
    child.guard_release_safe = exact_guard_release_gate(child, proc_observed, listener_absent);
    if (!child.guard_release_safe && failure != nullptr) {
        failure->phase = ExactFailurePhase::Cleanup;
        failure->error_number = static_cast<u64>(reaped ? observation.error_number : reap_error);
        failure->count = std::min<u64>(observation.attempts, 1024u);
    }
    if (cleaned != nullptr) {
        cleaned->version = kExactProtocolVersion;
        cleaned->child_pid = child.pid;
        cleaned->child_start = child.identity.start;
        cleaned->listener_inode = child.listener_inode;
        cleaned->clean_exit = clean_exit ? 1u : 0u;
        cleaned->pidfd_invalidated = pidfd_invalidated ? 1u : 0u;
        cleaned->child_absent = child_absent ? 1u : 0u;
        cleaned->listener_absent = listener_absent ? 1u : 0u;
        cleaned->temps_absent = source_removed && log_removed ? 1u : 0u;
        cleaned->target_fd_count = fd_count;
        cleaned->guard_connect_error = guard_error;
    }
    child.cleanup_complete = child.guard_release_safe && (!require_clean_exit || clean_exit) &&
                             child.pidfd < 0 && (!child.pidfd_acquired || pidfd_invalidated) &&
                             child_absent && source_removed && log_removed && guard_ok && fd_ok;
    return child.cleanup_complete;
}

static bool start_exact_child(const Frame& command,
                              const char* control_path,
                              int guard_fd,
                              const GuardReport& held,
                              ExactChildState& child,
                              ExactRutReport& report,
                              ExactFailureReport& failure) {
    report = {};
    failure = {};
    failure.phase = ExactFailurePhase::LeaseReopen;
    std::string executable;
    struct stat expected_executable{};
    if (!parse_executable_lease(command.payload, executable, expected_executable) ||
        expected_executable.st_uid != getuid() || expected_executable.st_gid != getgid())
        return false;
    std::array<char, PATH_MAX> canonical_executable{};
    if (realpath(executable.c_str(), canonical_executable.data()) == nullptr ||
        executable != canonical_executable.data())
        return false;
#ifdef O_PATH
    const int executable_fd = open(executable.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
#else
    const int executable_fd = -1;
#endif
    struct stat pinned{}, path_status{};
    if (executable_fd < 0 || fstat(executable_fd, &pinned) != 0 ||
        lstat(executable.c_str(), &path_status) != 0 ||
        pinned.st_dev != expected_executable.st_dev ||
        pinned.st_ino != expected_executable.st_ino ||
        pinned.st_mode != expected_executable.st_mode ||
        pinned.st_uid != expected_executable.st_uid ||
        pinned.st_gid != expected_executable.st_gid || path_status.st_dev != pinned.st_dev ||
        path_status.st_ino != pinned.st_ino) {
        if (executable_fd >= 0) close(executable_fd);
        return false;
    }
    const std::string control(control_path);
    const std::size_t slash = control.rfind('/');
    if (slash == std::string::npos || slash == 0u) {
        close(executable_fd);
        return false;
    }
    const std::string directory_path = control.substr(0u, slash);
    const int directory_fd =
        open(directory_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat directory_status{};
    if (directory_fd < 0 || fstat(directory_fd, &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) || directory_status.st_uid != getuid() ||
        directory_status.st_gid != getgid() || (directory_status.st_mode & 0777) != 0700) {
        if (directory_fd >= 0) close(directory_fd);
        close(executable_fd);
        return false;
    }
    child.directory_path = directory_path;
    child.directory_status = directory_status;
    child.source_path = directory_path + "/exact-listener.rut";
    child.log_path = directory_path + "/exact-listener.log";
    failure.phase = ExactFailurePhase::Temp;
    std::string source;
    privileged_listener::Diagnostic source_diagnostic;
    if (!privileged_listener::build_listener_source(
            held.plan, privileged_listener::ListenerSourceKind::Exact, source, source_diagnostic)) {
        close(directory_fd);
        close(executable_fd);
        return false;
    }
    const int source_fd = openat(directory_fd,
                                 "exact-listener.rut",
                                 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                                 0600);
    const int log_fd = openat(directory_fd,
                              "exact-listener.log",
                              O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              0600);
    const bool source_identity = source_fd >= 0 && fstat(source_fd, &child.source_status) == 0;
    const bool log_identity = log_fd >= 0 && fstat(log_fd, &child.log_status) == 0;
    if (!source_identity || !log_identity || !write_all_fd(source_fd, source) ||
        fsync(source_fd) != 0 || !S_ISREG(child.source_status.st_mode) ||
        !S_ISREG(child.log_status.st_mode) || (child.source_status.st_mode & 0777) != 0600 ||
        (child.log_status.st_mode & 0777) != 0600) {
        if (source_fd >= 0) close(source_fd);
        if (log_fd >= 0) close(log_fd);
        (void)unlink_regular_at_if_identity(
            directory_fd, "exact-listener.rut", child.source_status);
        (void)unlink_regular_at_if_identity(directory_fd, "exact-listener.log", child.log_status);
        close(directory_fd);
        close(executable_fd);
        return false;
    }
    close(source_fd);
    failure.phase = ExactFailurePhase::ForkPreExec;
    const pid_t parent = getpid();
    const pid_t pid = fork();
    if (pid == 0) {
        if (setpgid(0, 0) != 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent ||
            dup2(log_fd, STDOUT_FILENO) < 0 || dup2(log_fd, STDERR_FILENO) < 0)
            _exit(125);
        const int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0) _exit(125);
#ifdef SYS_close_range
        if ((executable_fd > 3 &&
             syscall(SYS_close_range, 3u, static_cast<unsigned>(executable_fd - 1), 0u) != 0) ||
            syscall(SYS_close_range,
                    static_cast<unsigned>(executable_fd + 1),
                    std::numeric_limits<unsigned>::max(),
                    0u) != 0)
            _exit(125);
#else
        const long limit = sysconf(_SC_OPEN_MAX);
        if (limit <= 0 || limit > std::numeric_limits<int>::max()) _exit(125);
        for (int fd = 3; fd < limit; ++fd)
            if (fd != executable_fd) close(fd);
#endif
        std::array<char*, 10> argv{
            const_cast<char*>(executable.c_str()),
            const_cast<char*>(child.source_path.c_str()),
            const_cast<char*>("--shards"),
            const_cast<char*>("1"),
            const_cast<char*>("--no-pin"),
            const_cast<char*>("--drain"),
            const_cast<char*>("0"),
            const_cast<char*>("--opt"),
            const_cast<char*>("2"),
            nullptr,
        };
#ifdef SYS_execveat
        syscall(SYS_execveat, executable_fd, "", argv.data(), environ, AT_EMPTY_PATH);
#endif
        _exit(126);
    }
    close(log_fd);
    if (pid <= 1) {
        (void)unlink_regular_at_if_identity(
            directory_fd, "exact-listener.rut", child.source_status);
        (void)unlink_regular_at_if_identity(directory_fd, "exact-listener.log", child.log_status);
        close(directory_fd);
        close(executable_fd);
        return false;
    }
    child.forked = true;
    (void)setpgid(pid, pid);
    child.pid = pid;
    child.executable = executable;
    child.executable_status = pinned;
    child.argv = exact_argv(
        {executable, child.source_path, "--shards", "1", "--no-pin", "--drain", "0", "--opt", "2"});
#ifdef SYS_pidfd_open
    child.pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
#endif
    child.pidfd_acquired = child.pidfd >= 0;
    close(directory_fd);
    failure.phase = ExactFailurePhase::PidfdIdentity;
    bool ready = child.pidfd >= 0 && (fcntl(child.pidfd, F_GETFD) & FD_CLOEXEC) != 0;
    u64 backend = 0u;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kListenerDeadlineMs);
    while (ready && std::chrono::steady_clock::now() < deadline) {
        ProcIdentity identity;
        privileged_listener::ProcTcpTable table;
        std::vector<u64> inodes;
        privileged_listener::ListenerEvidence evidence;
        privileged_listener::Diagnostic diagnostic;
        std::string log;
        const bool identity_ready = exact_child_identity(child, pinned, held.netns, identity);
        if (identity_ready) {
            child.identity = identity;
            child.post_exec_identity = true;
        }
        if (identity_ready && read_process_tcp_table(pid, table) &&
            process_socket_inodes(pid, inodes) &&
            privileged_listener::classify_listener_evidence(
                table,
                held.plan,
                inodes,
                privileged_listener::ListenerEvidenceKind::ExactPositive,
                evidence,
                diagnostic) &&
            read_file(child.log_path, log, privileged_listener::kMaxCollisionLogBytes) &&
            exact_log_ready(log, child.source_path, static_cast<u16>(held.plan.port), backend)) {
            child.listener_inode = evidence.child_owned_inode;
            break;
        }
        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) {
            child.reaped = true;
            child.wait_status = status;
            ready = false;
            break;
        }
        (void)poll(nullptr, 0, 10);
    }
    close(executable_fd);
    const auto cleanup_after_failure = [&]() {
        return cleanup_exact_child(
            child, held, guard_fd, nullptr, false, new_exact_cleanup_deadline(), &failure);
    };
    if (!ready || child.identity.pid != pid) {
        failure.phase = child.reaped && !child.post_exec_identity
                            ? ExactFailurePhase::Exec
                            : ExactFailurePhase::PidfdIdentity;
        failure.error_number = errno > 0 ? static_cast<u64>(errno) : 0u;
        if (!cleanup_after_failure()) failure.phase = ExactFailurePhase::Cleanup;
        return false;
    }
    if (child.listener_inode == 0u) {
        failure.phase = ExactFailurePhase::ListenerLog;
        if (!cleanup_after_failure()) failure.phase = ExactFailurePhase::Cleanup;
        return false;
    }
    failure.phase = ExactFailurePhase::HttpEof;
    if (!exact_http_exchange(
            held.plan.positive_ipv4, static_cast<u16>(held.plan.port), deadline, report)) {
        failure.count = report.response_bytes;
        if (!cleanup_after_failure()) failure.phase = ExactFailurePhase::Cleanup;
        return false;
    }
    failure.phase = ExactFailurePhase::GuardRefusal;
    int guard_error = 0;
    if (!connect_refused_until(
            held.plan.guard_ipv4, static_cast<u16>(held.plan.port), deadline, guard_error)) {
        failure.error_number = guard_error > 0 ? static_cast<u64>(guard_error) : 0u;
        if (!cleanup_after_failure()) failure.phase = ExactFailurePhase::Cleanup;
        return false;
    }
    failure.phase = ExactFailurePhase::StabilityFd;
    if (std::chrono::steady_clock::now() + std::chrono::milliseconds(500) > deadline) {
        if (!cleanup_after_failure()) failure.phase = ExactFailurePhase::Cleanup;
        return false;
    }
    (void)poll(nullptr, 0, 500);
    ProcIdentity stable;
    privileged_listener::ProcTcpTable table;
    std::vector<u64> inodes;
    privileged_listener::ListenerEvidence evidence;
    privileged_listener::Diagnostic diagnostic;
    u64 fd_count = 0u;
    if (!exact_child_identity(child, pinned, held.netns, stable) ||
        !same_process_identity(stable, child.identity) || !read_process_tcp_table(pid, table) ||
        !process_socket_inodes(pid, inodes) ||
        !privileged_listener::classify_listener_evidence(
            table,
            held.plan,
            inodes,
            privileged_listener::ListenerEvidenceKind::ExactPositive,
            evidence,
            diagnostic) ||
        evidence.child_owned_inode != child.listener_inode ||
        !target_socket_inode(getpid(), guard_fd, held.socket_inode) || !count_open_fds(fd_count) ||
        !exact_live_fd_count(fd_count, held) || !pidfd_link_matches(getpid(), child.pidfd)) {
        failure.count = fd_count;
        if (!cleanup_after_failure()) failure.phase = ExactFailurePhase::Cleanup;
        return false;
    }
    report.child_pid = pid;
    report.child_start = child.identity.start;
    report.child_ppid = child.identity.ppid;
    report.child_pgid = child.identity.pgid;
    report.child_sid = child.identity.sid;
    report.child_uid = child.identity.uid;
    report.child_gid = child.identity.gid;
    report.child_netns = child.identity.netns;
    report.child_exe_dev = child.identity.exe_dev;
    report.child_exe_ino = child.identity.exe_ino;
    report.pidfd = child.pidfd;
    report.pidfd_cloexec = 1u;
    report.listener_inode = child.listener_inode;
    report.source_dev = child.source_status.st_dev;
    report.source_ino = child.source_status.st_ino;
    report.log_dev = child.log_status.st_dev;
    report.log_ino = child.log_status.st_ino;
    report.target_fd_count = fd_count;
    report.guard_connect_error = guard_error;
    report.stable = 1u;
    report.backend = backend;
    return true;
}

static int finish_exact_failure(int control,
                                const Token& token,
                                const GuardReport& held,
                                int guard_fd,
                                ExactChildState& child,
                                ExactFailureReport failure,
                                int exit_code,
                                bool require_live_escrow = false) {
    while (!child.cleanup_complete) {
        if (!child.forked || child.identity.start == 0u) {
            if (cleanup_exact_child(
                    child, held, guard_fd, nullptr, false, new_exact_cleanup_deadline(), &failure))
                break;
            (void)poll(nullptr, 0, 10);
            continue;
        }
        const ExactHandoffResult handoff =
            handoff_failed_exact_cleanup(token, held, guard_fd, child);
        if (handoff == ExactHandoffResult::NotSent) {
            if (require_live_escrow) {
                (void)poll(nullptr, 0, 10);
                continue;
            }
            if (cleanup_exact_child(
                    child, held, guard_fd, nullptr, false, new_exact_cleanup_deadline(), &failure))
                break;
            (void)poll(nullptr, 0, 10);
            continue;
        }
        if (handoff == ExactHandoffResult::AwaitingAck) {
            ProcIdentity target;
            if (!read_proc(getpid(), target)) {
                (void)poll(nullptr, 0, 10);
                continue;
            }
            while (!receive_exact_custody_ack(kExactCustodyFd,
                                              token,
                                              target.ppid,
                                              target.uid,
                                              target.gid,
                                              new_exact_cleanup_deadline()))
                (void)poll(nullptr, 0, 10);
        }
        failure.escrow_required = 1u;
        failure.child_pid = static_cast<u64>(child.pid);
        failure.child_start = child.identity.start;
        break;
    }
    (void)send_frame(
        control, Frame{kExactRutFailure, token, encode_exact_failure(failure)}, kHandshakeMs);
    close(control);
    // The guard is deliberately not closed here.  When the owned child has
    // been definitively reaped, nonzero Target exit is a safe terminal action:
    // kernel process teardown closes the still-owned guard without publishing
    // frame 44 or frame 37 success.  An unreaped deadline failure is likewise
    // reported without further PID signalling or a false cleanup claim.
    (void)child;
    return exit_code;
}

static int secured_target_main(const char* control_path,
                               const char* token_string,
                               const char* broker_text,
                               const char* scenario) {
    Token token;
    u64 broker = 0;
    if (!token_from_hex(token_string, token) || !parse_u64(broker_text, broker) || broker <= 1)
        return 40;
    if (listener_scenario_name(scenario) &&
        !validate_exact_custody_endpoint(kExactCustodyFd, static_cast<pid_t>(broker)))
        return 39;
    const int control = connect_control(control_path);
    if (control < 0) return 41;
    if (strcmp(scenario, "no-ready") == 0) {
        Frame ignored;
        (void)receive_frame(control, ignored, kBrokerDeadlineMs);
        close(control);
        return 0;
    }
    Report report;
    if (!fill_report("privileged-target", broker, report, true) ||
        !send_frame(control, Frame{kReady, token, encode_report(report)}, kHandshakeMs)) {
        close(control);
        return 42;
    }
    for (;;) {
        Frame command;
        if (!receive_frame(control, command, kBrokerDeadlineMs) ||
            !token_equal(command.token, token)) {
            close(control);
            return 0;
        }
        if (canonical_collision_scenario(scenario) && command.type == kGuardReserve)
            return canonical_target_flow(control, token, command.payload, control_path);
        if (command.type == kGuardReserve && listener_scenario_name(scenario)) {
            u32 positive_ipv4 = 0u, guard_ipv4 = 0u;
            ProcIdentity secured_identity;
            u64 baseline_fd_count = 0u;
            if (!parse_guard_request(command.payload, positive_ipv4, guard_ipv4) ||
                !read_proc(getpid(), secured_identity) || secured_identity.uid != geteuid() ||
                secured_identity.gid != getegid() || secured_identity.supplementary_groups != 0 ||
                !secured_identity.no_new_privs || !secured_identity.capabilities_clear ||
                !count_open_fds(baseline_fd_count)) {
                close(control);
                return 45;
            }
            const int guard_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (guard_fd < 0) {
                close(control);
                return 46;
            }
            sockaddr_in endpoint{};
            endpoint.sin_family = AF_INET;
            endpoint.sin_port = 0;
            endpoint.sin_addr.s_addr = htonl(guard_ipv4);
            socklen_t endpoint_size = sizeof(endpoint);
            if (bind(guard_fd, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) != 0 ||
                getsockname(guard_fd, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_size) !=
                    0 ||
                endpoint_size != sizeof(endpoint) || endpoint.sin_family != AF_INET) {
                close(guard_fd);
                close(control);
                return 47;
            }
            const privileged_listener::ListenerPlan plan{
                positive_ipv4, guard_ipv4, ntohs(endpoint.sin_port)};
            GuardReport held;
            if (plan.port == 0u || ntohl(endpoint.sin_addr.s_addr) != guard_ipv4 ||
                !fill_guard_socket_report(guard_fd, plan, baseline_fd_count, held) ||
                !validate_guard_report(held, plan, secured_identity, false) ||
                !send_frame(
                    control, Frame{kGuardHeld, token, encode_guard_report(held)}, kHandshakeMs)) {
                close(guard_fd);
                close(control);
                return 48;
            }
            Frame exact_run;
            ExactChildState exact_child;
            ExactRutReport exact_report;
            ExactFailureReport exact_failure;
            const bool run_request = receive_frame(control, exact_run, kListenerDeadlineMs) &&
                                     exact_run.type == kExactRutRun &&
                                     token_equal(exact_run.token, token);
            const bool started = run_request && start_exact_child(exact_run,
                                                                  control_path,
                                                                  guard_fd,
                                                                  held,
                                                                  exact_child,
                                                                  exact_report,
                                                                  exact_failure);
            if (!started) {
                if (!run_request) exact_failure.phase = ExactFailurePhase::LeaseReopen;
                if (!exact_child.guard_release_safe &&
                    !cleanup_exact_child(exact_child,
                                         held,
                                         guard_fd,
                                         nullptr,
                                         false,
                                         new_exact_cleanup_deadline(),
                                         &exact_failure))
                    exact_failure.phase = ExactFailurePhase::Cleanup;
                return finish_exact_failure(
                    control, token, held, guard_fd, exact_child, exact_failure, 53);
            }
            if (!send_frame(control,
                            Frame{kExactRutWitness, token, encode_exact_report(exact_report)},
                            kHandshakeMs)) {
                exact_failure.phase = ExactFailurePhase::HttpEof;
                exact_failure.error_number = errno > 0 ? static_cast<u64>(errno) : 0u;
                const bool cleanup_ok = cleanup_exact_child(exact_child,
                                                            held,
                                                            guard_fd,
                                                            nullptr,
                                                            false,
                                                            new_exact_cleanup_deadline(),
                                                            &exact_failure);
                (void)cleanup_ok;
                return finish_exact_failure(
                    control, token, held, guard_fd, exact_child, exact_failure, 53);
            }
            Frame exact_cleanup;
            ExactRutCleanedReport exact_cleaned;
            const bool cleanup_command =
                receive_frame(control, exact_cleanup, kListenerDeadlineMs) &&
                exact_cleanup_request(exact_cleanup, token);
            if (cleanup_command && listener_failure_integration(scenario)) {
                ExactCleanupObservation injected;
                const bool unexpectedly_absent =
                    observe_exact_listener_absence(exact_child,
                                                   held,
                                                   new_exact_cleanup_deadline(),
                                                   ExactCleanupFault::ProcFailure,
                                                   injected);
                exact_failure.phase = ExactFailurePhase::Cleanup;
                exact_failure.error_number = static_cast<u64>(injected.error_number);
                exact_failure.count = std::min<u64>(injected.attempts, 1024u);
                if (unexpectedly_absent || exact_child.reaped || injected.proc_observed ||
                    injected.listener_absent || injected.error_number != ETIMEDOUT ||
                    injected.attempts == 0u) {
                    exact_failure.error_number = EPROTO;
                }
                return finish_exact_failure(
                    control, token, held, guard_fd, exact_child, exact_failure, 55, true);
            }
            const bool cleanup_ok = cleanup_exact_child(exact_child,
                                                        held,
                                                        guard_fd,
                                                        &exact_cleaned,
                                                        cleanup_command,
                                                        new_exact_cleanup_deadline(),
                                                        &exact_failure);
            if (!cleanup_command || !cleanup_ok ||
                !send_frame(control,
                            Frame{kExactRutCleaned, token, encode_exact_cleaned(exact_cleaned)},
                            kHandshakeMs)) {
                exact_failure.phase = ExactFailurePhase::Cleanup;
                return finish_exact_failure(
                    control, token, held, guard_fd, exact_child, exact_failure, 54);
            }
            Frame release;
            if (!receive_frame(control, release, kBrokerDeadlineMs) ||
                !exact_request(release, kGuardRelease, token)) {
                if (!exact_child.guard_release_safe)
                    return finish_exact_failure(
                        control, token, held, guard_fd, exact_child, exact_failure, 49);
                close(guard_fd);
                close(control);
                return 49;
            }
            if (!exact_child.guard_release_safe) {
                exact_failure.phase = ExactFailurePhase::Cleanup;
                (void)cleanup_exact_child(exact_child,
                                          held,
                                          guard_fd,
                                          nullptr,
                                          false,
                                          new_exact_cleanup_deadline(),
                                          &exact_failure);
                if (!exact_child.guard_release_safe)
                    return finish_exact_failure(
                        control, token, held, guard_fd, exact_child, exact_failure, 49);
            }
            close(guard_fd);
            errno = 0;
            const bool invalidated = fcntl(guard_fd, F_GETFD) < 0 && errno == EBADF;
            GuardReport released = held;
            int connect_error = 0;
            released.fd_invalidated = invalidated ? 1u : 0u;
            if (!count_open_fds(released.current_fd_count) ||
                !bounded_connect_refused(
                    plan.guard_ipv4, static_cast<u16>(plan.port), connect_error)) {
                close(control);
                return 50;
            }
            released.connect_error = static_cast<u64>(connect_error);
            if (!validate_guard_report(released, plan, secured_identity, true) ||
                !send_frame(control,
                            Frame{kGuardReleased, token, encode_guard_report(released)},
                            kHandshakeMs)) {
                close(control);
                return 51;
            }
            Frame finish;
            if (!receive_frame(control, finish, kBrokerDeadlineMs) ||
                !exact_request(finish, kGuardFinish, token) ||
                !send_frame(control, Frame{kGuardFinished, token, {}}, kHandshakeMs)) {
                close(control);
                return 52;
            }
            close(control);
            return 0;
        }
        if (!command.payload.empty()) {
            close(control);
            return 44;
        }
        if (command.type == kPing) {
            if (!send_frame(control, Frame{kPong, token, {}}, kHandshakeMs)) return 43;
        } else if (command.type == kRelease) {
            (void)send_frame(control, Frame{kReleased, token, {}}, kHandshakeMs);
            close(control);
            return 0;
        } else {
            close(control);
            return 44;
        }
    }
}

static bool validate_escrow_temp(int directory,
                                 const char* name,
                                 u64 device,
                                 u64 inode,
                                 uid_t uid,
                                 gid_t gid,
                                 bool allow_absent) {
    struct stat status{};
    errno = 0;
    if (fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) < 0)
        return allow_absent && errno == ENOENT;
    return S_ISREG(status.st_mode) && status.st_dev == static_cast<dev_t>(device) &&
           status.st_ino == static_cast<ino_t>(inode) && status.st_uid == uid &&
           status.st_gid == gid && (status.st_mode & 0777) == 0600;
}

static bool exact_custody_child_identity_matches(const ProcIdentity& child,
                                                 const ExactCustodyRecord& record,
                                                 pid_t expected_parent,
                                                 ino_t expected_netns,
                                                 uid_t expected_uid,
                                                 gid_t expected_gid) {
    return child.pid == static_cast<pid_t>(record.child_pid) && child.ppid == expected_parent &&
           child.start == record.child_start && child.exe_dev == record.child_exe_dev &&
           child.exe_ino == record.child_exe_ino && child.netns == expected_netns &&
           child.uid == expected_uid && child.gid == expected_gid;
}

enum class ExactEscrowValidation { Invalid, ObservationTransient, Valid };

static ExactEscrowValidation classify_exact_child_observation(bool read_succeeded,
                                                              const ProcIdentity& child,
                                                              const ExactCustodyRecord& record,
                                                              pid_t expected_parent,
                                                              pid_t transition_parent,
                                                              ino_t expected_netns,
                                                              uid_t expected_uid,
                                                              gid_t expected_gid) {
    if (!read_succeeded) return ExactEscrowValidation::ObservationTransient;
    if (child.pid != static_cast<pid_t>(record.child_pid) || child.start != record.child_start ||
        child.exe_dev != record.child_exe_dev || child.exe_ino != record.child_exe_ino ||
        child.netns != expected_netns || child.uid != expected_uid || child.gid != expected_gid)
        return ExactEscrowValidation::Invalid;
    if (child.ppid == expected_parent) return ExactEscrowValidation::Valid;
    return child.ppid == transition_parent ? ExactEscrowValidation::ObservationTransient
                                           : ExactEscrowValidation::Invalid;
}

static ExactEscrowValidation classify_exact_listener_observation(
    bool table_read,
    bool inodes_read,
    bool positive_exact_evidence,
    bool inode_matches,
    ExactEscrowValidation identity_revalidation) {
    if (!table_read || !inodes_read) return ExactEscrowValidation::ObservationTransient;
    if (!positive_exact_evidence) return ExactEscrowValidation::ObservationTransient;
    if (identity_revalidation != ExactEscrowValidation::Valid) return identity_revalidation;
    return inode_matches ? ExactEscrowValidation::Valid : ExactEscrowValidation::Invalid;
}

static ExactEscrowValidation validate_exact_escrow(const ExactCustodyRecord& record,
                                                   const ExactEscrowRights& rights,
                                                   pid_t expected_target,
                                                   u64 expected_target_start,
                                                   pid_t expected_child_parent,
                                                   ino_t expected_netns,
                                                   uid_t expected_uid,
                                                   gid_t expected_gid) {
    if (record.target_pid != static_cast<u64>(expected_target) ||
        record.target_start != expected_target_start ||
        record.netns != static_cast<u64>(expected_netns) || rights.guard < 0 ||
        rights.directory < 0)
        return ExactEscrowValidation::Invalid;
    struct stat guard_status{}, directory_status{};
    sockaddr_in endpoint{};
    socklen_t endpoint_size = sizeof(endpoint);
    int socket_type = 0;
    int accept_connection = 0;
    socklen_t option_size = sizeof(int);
    if (fstat(rights.guard, &guard_status) != 0 || !S_ISSOCK(guard_status.st_mode) ||
        guard_status.st_ino != record.guard_inode ||
        getsockname(rights.guard, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_size) != 0 ||
        endpoint_size != sizeof(endpoint) || endpoint.sin_family != AF_INET ||
        ntohl(endpoint.sin_addr.s_addr) != record.guard_ipv4 ||
        ntohs(endpoint.sin_port) != record.port ||
        getsockopt(rights.guard, SOL_SOCKET, SO_TYPE, &socket_type, &option_size) != 0 ||
        socket_type != SOCK_STREAM ||
        getsockopt(rights.guard, SOL_SOCKET, SO_ACCEPTCONN, &accept_connection, &option_size) !=
            0 ||
        accept_connection != 0 || fstat(rights.directory, &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) || directory_status.st_dev != record.directory_dev ||
        directory_status.st_ino != record.directory_ino ||
        directory_status.st_uid != expected_uid || directory_status.st_gid != expected_gid ||
        (directory_status.st_mode & 0777) != 0700 ||
        !validate_escrow_temp(rights.directory,
                              "exact-listener.rut",
                              record.source_dev,
                              record.source_ino,
                              expected_uid,
                              expected_gid,
                              record.child_reaped != 0u) ||
        !validate_escrow_temp(rights.directory,
                              "exact-listener.log",
                              record.log_dev,
                              record.log_ino,
                              expected_uid,
                              expected_gid,
                              record.child_reaped != 0u))
        return ExactEscrowValidation::Invalid;
    ProcIdentity child;
    if (record.child_reaped != 0u) {
        child.pid = static_cast<pid_t>(record.child_pid);
        child.start = record.child_start;
        if (record.has_pidfd != 0u ||
            observe_exact_liveness(child) != ExactLiveness::ExitedOrReused)
            return ExactEscrowValidation::Invalid;
    } else {
        const bool child_read = read_proc(static_cast<pid_t>(record.child_pid), child, false);
        const pid_t transition_parent =
            expected_child_parent == expected_target ? getpid() : expected_target;
        const ExactEscrowValidation child_validation =
            classify_exact_child_observation(child_read,
                                             child,
                                             record,
                                             expected_child_parent,
                                             transition_parent,
                                             expected_netns,
                                             expected_uid,
                                             expected_gid);
        if (child_validation != ExactEscrowValidation::Valid) return child_validation;
    }
    if (record.has_pidfd != 0u &&
        (rights.pidfd < 0 || !pidfd_link_matches(getpid(), rights.pidfd) ||
         !exact_pidfd_binding(rights.pidfd, static_cast<pid_t>(record.child_pid))))
        return ExactEscrowValidation::Invalid;
    if (record.child_reaped == 0u && record.listener_inode != 0u) {
        privileged_listener::ProcTcpTable table;
        std::vector<u64> inodes;
        privileged_listener::ListenerEvidence evidence;
        privileged_listener::Diagnostic diagnostic;
        const privileged_listener::ListenerPlan plan{static_cast<u32>(record.positive_ipv4),
                                                     static_cast<u32>(record.guard_ipv4),
                                                     record.port};
        const bool table_read = read_process_tcp_table(child.pid, table);
        const bool inodes_read = process_socket_inodes(child.pid, inodes);
        const bool positive_exact_evidence =
            table_read && inodes_read &&
            privileged_listener::classify_listener_evidence(
                table,
                plan,
                inodes,
                privileged_listener::ListenerEvidenceKind::ExactPositive,
                evidence,
                diagnostic);
        ExactEscrowValidation identity_revalidation = ExactEscrowValidation::ObservationTransient;
        if (positive_exact_evidence) {
            ProcIdentity child_after;
            const bool child_after_read = read_proc(child.pid, child_after, false);
            const pid_t transition_parent =
                expected_child_parent == expected_target ? getpid() : expected_target;
            identity_revalidation = classify_exact_child_observation(child_after_read,
                                                                     child_after,
                                                                     record,
                                                                     expected_child_parent,
                                                                     transition_parent,
                                                                     expected_netns,
                                                                     expected_uid,
                                                                     expected_gid);
        }
        const ExactEscrowValidation listener_validation = classify_exact_listener_observation(
            table_read,
            inodes_read,
            positive_exact_evidence,
            positive_exact_evidence && evidence.child_owned_inode == record.listener_inode,
            identity_revalidation);
        if (listener_validation != ExactEscrowValidation::Valid) return listener_validation;
    }
    return ExactEscrowValidation::Valid;
}

enum class ExactCustodyTargetState { Invalid, Transient, Live, ExitedAndAdopted };

static ExactCustodyTargetState validate_received_exact_custody(const ExactCustodyRecord& custody,
                                                               const ExactEscrowRights& rights,
                                                               pid_t target,
                                                               u64 expected_target_start,
                                                               const std::string& target_executable,
                                                               const std::string& target_argv,
                                                               ino_t expected_netns,
                                                               uid_t expected_uid,
                                                               gid_t expected_gid,
                                                               bool& target_reaped,
                                                               int& target_status) {
    if (custody.target_pid != static_cast<u64>(target) ||
        custody.target_start != expected_target_start)
        return ExactCustodyTargetState::Invalid;
    ProcIdentity target_identity;
    const bool target_live =
        !target_reaped && read_proc(target, target_identity, false) &&
        target_identity.pid == target && target_identity.ppid == getpid() &&
        target_identity.start == expected_target_start &&
        target_identity.exe == target_executable && target_identity.cmdline == target_argv &&
        target_identity.netns == expected_netns && target_identity.uid == expected_uid &&
        target_identity.gid == expected_gid;
    if (target_live) {
        const ExactEscrowValidation live_validation = validate_exact_escrow(custody,
                                                                            rights,
                                                                            target,
                                                                            expected_target_start,
                                                                            target,
                                                                            expected_netns,
                                                                            expected_uid,
                                                                            expected_gid);
        if (live_validation == ExactEscrowValidation::Valid) return ExactCustodyTargetState::Live;
        if (live_validation == ExactEscrowValidation::Invalid)
            return ExactCustodyTargetState::Invalid;
    }
    if (!target_reaped) {
        errno = 0;
        const pid_t waited = waitpid(target, &target_status, WNOHANG);
        if (waited != target) return ExactCustodyTargetState::Transient;
        target_reaped = true;
    }
    const ExactEscrowValidation adopted_validation = validate_exact_escrow(custody,
                                                                           rights,
                                                                           target,
                                                                           expected_target_start,
                                                                           getpid(),
                                                                           expected_netns,
                                                                           expected_uid,
                                                                           expected_gid);
    if (adopted_validation == ExactEscrowValidation::Invalid)
        return ExactCustodyTargetState::Invalid;
    if (adopted_validation == ExactEscrowValidation::ObservationTransient)
        return ExactCustodyTargetState::Transient;
    return ExactCustodyTargetState::ExitedAndAdopted;
}

static bool wait_reap_adopted_exact(const ExactCustodyRecord& record,
                                    ExactEscrowRights& rights,
                                    std::chrono::steady_clock::time_point deadline,
                                    bool& adopted) {
    adopted = false;
    bool term_sent = false;
    bool kill_sent = false;
    const auto kill_deadline =
        std::chrono::steady_clock::now() + (deadline - std::chrono::steady_clock::now()) / 2;
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = waitpid(static_cast<pid_t>(record.child_pid), &status, WNOHANG);
        if (waited == static_cast<pid_t>(record.child_pid)) {
            adopted = true;
            return true;
        }
        if (waited < 0 && errno != EINTR && errno != ECHILD) return false;
        ProcIdentity child;
        const bool identity = read_proc(static_cast<pid_t>(record.child_pid), child, false) &&
                              child.pid == static_cast<pid_t>(record.child_pid) &&
                              child.ppid == getpid() && child.start == record.child_start &&
                              child.exe_dev == record.child_exe_dev &&
                              child.exe_ino == record.child_exe_ino;
        if (identity) {
            adopted = true;
            if (!term_sent) {
#ifdef SYS_pidfd_send_signal
                const bool signalled =
                    rights.pidfd >= 0
                        ? syscall(SYS_pidfd_send_signal, rights.pidfd, SIGTERM, nullptr, 0) == 0
                        : kill(child.pid, SIGTERM) == 0;
#else
                const bool signalled = kill(child.pid, SIGTERM) == 0;
#endif
                if (!signalled && errno != ESRCH) return false;
                term_sent = true;
            } else if (!kill_sent && std::chrono::steady_clock::now() >= kill_deadline) {
#ifdef SYS_pidfd_send_signal
                const bool signalled =
                    rights.pidfd >= 0
                        ? syscall(SYS_pidfd_send_signal, rights.pidfd, SIGKILL, nullptr, 0) == 0
                        : kill(child.pid, SIGKILL) == 0;
#else
                const bool signalled = kill(child.pid, SIGKILL) == 0;
#endif
                if (!signalled && errno != ESRCH) return false;
                kill_sent = true;
            }
        }
        (void)poll(nullptr, 0, 10);
    }
    return false;
}

struct ExactSettlementProgress {
    bool adopted = false;
    bool reaped = false;
    bool listener_absent = false;
    bool source_absent = false;
    bool log_absent = false;
};

static int exact_competing_guard_bind_error(const ExactCustodyRecord& record,
                                            const ExactEscrowRights& rights,
                                            u64& observed_guard_inode) {
    observed_guard_inode = 0u;
    struct stat guard_status{};
    if (rights.guard < 0 || fstat(rights.guard, &guard_status) != 0 ||
        !S_ISSOCK(guard_status.st_mode))
        return 0;
    observed_guard_inode = static_cast<u64>(guard_status.st_ino);
    if (observed_guard_inode != record.guard_inode) return 0;
    const int competing = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (competing < 0) return errno;
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(static_cast<u16>(record.port));
    endpoint.sin_addr.s_addr = htonl(static_cast<u32>(record.guard_ipv4));
    errno = 0;
    const int result =
        bind(competing, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));
    const int bind_error = result == 0 ? 0 : errno;
    close(competing);
    return bind_error;
}

static bool exact_escrow_temp_absent(int directory, const char* name) {
    struct stat status{};
    errno = 0;
    return directory >= 0 && fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) < 0 &&
           errno == ENOENT;
}

static bool settle_exact_escrow(int control,
                                const Token& token,
                                const ExactCustodyRecord& record,
                                ExactEscrowRights& rights,
                                ExactSettlementProgress& progress,
                                ExactSettledRecord& settled,
                                bool publish_settlement) {
    settled.version = kExactSettledVersion;
    settled.target_pid = record.target_pid;
    settled.child_pid = record.child_pid;
    settled.child_start = record.child_start;
    settled.guard_inode = 0u;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kListenerDeadlineMs);
    if (record.child_reaped != 0u) {
        progress.reaped = true;
    } else if (!progress.reaped) {
        bool adopted = false;
        progress.reaped = wait_reap_adopted_exact(record, rights, deadline, adopted);
        progress.adopted = progress.adopted || adopted;
    }
    privileged_listener::ProcTcpTable table;
    while (progress.reaped && !progress.listener_absent &&
           std::chrono::steady_clock::now() < deadline) {
        if (read_process_tcp_table(getpid(), table) &&
            exact_listener_absent(table,
                                  {static_cast<u32>(record.positive_ipv4),
                                   static_cast<u32>(record.guard_ipv4),
                                   record.port},
                                  record.listener_inode)) {
            progress.listener_absent = true;
            break;
        }
        (void)poll(nullptr, 0, 10);
    }
    struct stat source{}, log{};
    source.st_dev = record.source_dev;
    source.st_ino = record.source_ino;
    log.st_dev = record.log_dev;
    log.st_ino = record.log_ino;
    if (progress.reaped && !progress.source_absent)
        progress.source_absent = remove_exact_temp(rights.directory, "exact-listener.rut", source);
    if (progress.reaped && !progress.log_absent)
        progress.log_absent = remove_exact_temp(rights.directory, "exact-listener.log", log);
    const bool temps_absent = progress.source_absent && progress.log_absent &&
                              exact_escrow_temp_absent(rights.directory, "exact-listener.rut") &&
                              exact_escrow_temp_absent(rights.directory, "exact-listener.log");
    settled.adopted = progress.adopted ? 1u : 0u;
    settled.reaped = progress.reaped ? 1u : 0u;
    settled.listener_absent = progress.listener_absent ? 1u : 0u;
    settled.temps_absent = temps_absent ? 1u : 0u;
    if (progress.reaped && progress.listener_absent && temps_absent) {
        settled.competing_bind_error =
            static_cast<u64>(exact_competing_guard_bind_error(record, rights, settled.guard_inode));
        if (settled.competing_bind_error == EADDRINUSE) {
            if (rights.pidfd >= 0) close(rights.pidfd);
            rights.pidfd = -1;
            close(rights.directory);
            rights.directory = -1;
            const int old_guard = rights.guard;
            close(rights.guard);
            rights.guard = -1;
            errno = 0;
            settled.guard_closed = fcntl(old_guard, F_GETFD) < 0 && errno == EBADF ? 1u : 0u;
        }
    }
    if (rights.guard >= 0) return false;
    return !publish_settlement ||
           send_frame(control,
                      Frame{kExactEscrowSettled, token, encode_exact_settled(settled)},
                      kHandshakeMs);
}

static bool exact_target_numeric_signal_allowed(pid_t wait_result,
                                                int wait_error,
                                                bool identity_matches) {
    return wait_result == 0 && wait_error == 0 && identity_matches;
}

static OwnedWaitResult finish_post_ack_escrow(pid_t target,
                                              int control,
                                              const Token& token,
                                              const ExactCustodyRecord& custody,
                                              ExactEscrowRights& rights,
                                              bool target_reaped,
                                              bool publish_settlement,
                                              int& target_status) {
    bool kill_sent = false;
    bool direct_wait_authority = true;
    auto target_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kListenerDeadlineMs);
    while (!target_reaped) {
        errno = 0;
        const pid_t waited = waitpid(target, &target_status, WNOHANG);
        const int wait_error = waited < 0 ? errno : 0;
        if (waited == target) {
            target_reaped = true;
            break;
        }
        if (waited < 0 && wait_error != EINTR) {
            direct_wait_authority = false;
            (void)poll(nullptr, 0, 10);
            continue;
        }
        if (!kill_sent && direct_wait_authority &&
            std::chrono::steady_clock::now() >= target_deadline) {
            ProcIdentity identity;
            const bool matches = read_proc(target, identity, false) && identity.pid == target &&
                                 identity.ppid == getpid() &&
                                 identity.start == custody.target_start;
            if (exact_target_numeric_signal_allowed(waited, wait_error, matches) &&
                (kill(target, SIGKILL) == 0 || errno == ESRCH))
                kill_sent = true;
            target_deadline = new_exact_cleanup_deadline();
        }
        (void)poll(nullptr, 0, 10);
    }
    ExactSettlementProgress progress;
    for (;;) {
        ExactSettledRecord settled;
        const bool sent = settle_exact_escrow(
            control, token, custody, rights, progress, settled, publish_settlement);
        if (rights.guard < 0) {
            rights.close_all();
            return sent ? OwnedWaitResult::Exited : OwnedWaitResult::Error;
        }
        // A genuinely unkillable adopted child or unreadable listener state
        // intentionally retains this process and guard.  It is failure-only
        // custody and can never publish TargetExited or settlement success.
        (void)poll(nullptr, 0, 10);
    }
}

enum class ExactListenerWaitEvent { Progress, RootLoss, WaitError, PollError, Deadline };
enum class ExactPeerClosedAction { WaitDirect, ReturnExited, Hold };

static bool exact_listener_failure_requires_hold(bool custody_received,
                                                 ExactListenerWaitEvent event) {
    return !custody_received && event != ExactListenerWaitEvent::Progress;
}

static bool exact_failure_losses_complete(bool custody_received,
                                          bool root_loss_observed,
                                          bool custody_hup_observed) {
    return custody_received && root_loss_observed && custody_hup_observed;
}

static bool exact_listener_target_reaped(pid_t target, u64 expected_start, int& status) {
    if (target <= 1 || expected_start == 0u) return false;
    errno = 0;
    return waitpid(target, &status, WNOHANG) == target;
}

static ExactPeerClosedAction exact_peer_closed_action(bool target_waitable, bool deadline_expired) {
    if (target_waitable) return ExactPeerClosedAction::ReturnExited;
    return deadline_expired ? ExactPeerClosedAction::Hold : ExactPeerClosedAction::WaitDirect;
}

[[noreturn]] static void hold_listener_failure(int root_lease, int custody_fd) {
    // A listener Target may own the only guard while its exact-child safety is
    // unknown.  Keep Dropped alive across lease, transport, and pre-ACK
    // failures so Target PDEATHSIG cannot turn uncertainty into guard release.
    const std::array<pollfd, 2> descriptors{
        {{root_lease, POLLIN | POLLHUP | POLLERR, 0}, {custody_fd, POLLIN | POLLHUP | POLLERR, 0}}};
    for (;;) {
        auto observed = descriptors;
        int result;
        do {
            result = poll(observed.data(), observed.size(), kCleanupMs);
        } while (result < 0 && errno == EINTR);
        (void)result;
    }
}

static OwnedWaitResult wait_listener_target_bounded(pid_t target,
                                                    u64 expected_target_start,
                                                    const std::string& target_executable,
                                                    const std::string& target_argv,
                                                    pid_t root_broker,
                                                    u64 expected_root_start,
                                                    int root_lease,
                                                    int custody_fd,
                                                    bool require_failure_losses,
                                                    int control,
                                                    const Token& token,
                                                    ino_t expected_netns,
                                                    uid_t expected_uid,
                                                    gid_t expected_gid,
                                                    int target_wait_ms,
                                                    int& target_status) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(target_wait_ms);
    bool custody_received = false;
    bool custody_peer_closed = false;
    bool root_loss_observed = false;
    bool custody_hup_observed = false;
    ExactCustodyRecord custody;
    ExactEscrowRights rights;
    const auto accept_custody = [&](bool target_reaped) -> std::optional<OwnedWaitResult> {
        if (!receive_exact_custody(
                custody_fd, token, target, expected_uid, expected_gid, deadline, custody, rights))
            hold_listener_failure(root_lease, custody_fd);
        ExactCustodyTargetState state = ExactCustodyTargetState::Transient;
        while (state == ExactCustodyTargetState::Transient &&
               std::chrono::steady_clock::now() < deadline) {
            state = validate_received_exact_custody(custody,
                                                    rights,
                                                    target,
                                                    expected_target_start,
                                                    target_executable,
                                                    target_argv,
                                                    expected_netns,
                                                    expected_uid,
                                                    expected_gid,
                                                    target_reaped,
                                                    target_status);
            if (state == ExactCustodyTargetState::Transient) (void)poll(nullptr, 0, 10);
        }
        if (state == ExactCustodyTargetState::Transient)
            hold_listener_failure(root_lease, custody_fd);
        if (state == ExactCustodyTargetState::Invalid) {
            rights.close_all();
            hold_listener_failure(root_lease, custody_fd);
        }
        if (state == ExactCustodyTargetState::ExitedAndAdopted && require_failure_losses)
            hold_listener_failure(root_lease, custody_fd);
        if (state == ExactCustodyTargetState::ExitedAndAdopted)
            return finish_post_ack_escrow(
                target, control, token, custody, rights, true, false, target_status);
        if (control_lease_lost(root_lease) || getppid() != root_broker)
            hold_listener_failure(root_lease, custody_fd);
        while (!send_exact_custody_ack(custody_fd, token, new_exact_cleanup_deadline()))
            (void)poll(nullptr, 0, 10);
        custody_received = true;
        return std::nullopt;
    };
    while (std::chrono::steady_clock::now() < deadline) {
        const bool root_lost = control_lease_lost(root_lease) || getppid() != root_broker;
        ProcIdentity expected_root;
        expected_root.pid = root_broker;
        expected_root.start = expected_root_start;
        if (custody_received && root_lost &&
            observe_exact_liveness(expected_root) == ExactLiveness::ExitedOrReused)
            root_loss_observed = true;
        if (root_lost && exact_listener_failure_requires_hold(custody_received,
                                                              ExactListenerWaitEvent::RootLoss)) {
            if (require_failure_losses) hold_listener_failure(root_lease, custody_fd);
            if (exact_listener_target_reaped(target, expected_target_start, target_status))
                return OwnedWaitResult::Exited;
            hold_listener_failure(root_lease, custody_fd);
        }
        pollfd descriptor{custody_fd, POLLIN, 0};
        int polled = 0;
        if (!custody_peer_closed) {
            do {
                polled = poll(&descriptor, 1, 10);
            } while (polled < 0 && errno == EINTR);
        }
        if (polled < 0) {
            if (custody_received && require_failure_losses &&
                !exact_failure_losses_complete(
                    custody_received, root_loss_observed, custody_hup_observed))
                hold_listener_failure(root_lease, custody_fd);
            if (custody_received)
                return finish_post_ack_escrow(
                    target, control, token, custody, rights, false, true, target_status);
            if (exact_listener_target_reaped(target, expected_target_start, target_status))
                return OwnedWaitResult::Exited;
            hold_listener_failure(root_lease, custody_fd);
        }
        if ((descriptor.revents & POLLIN) != 0) {
            const ExactCustodyPeek peek =
                peek_exact_custody(custody_fd, (descriptor.revents & POLLHUP) != 0);
            if (custody_received) {
                if ((descriptor.revents & POLLHUP) != 0 && peek == ExactCustodyPeek::Eof)
                    custody_hup_observed = true;
                if (!require_failure_losses ||
                    exact_failure_losses_complete(
                        custody_received, root_loss_observed, custody_hup_observed))
                    return finish_post_ack_escrow(
                        target, control, token, custody, rights, false, true, target_status);
                continue;
            }
            if (peek == ExactCustodyPeek::Record) {
                if (const auto result = accept_custody(false)) return *result;
            } else if (peek == ExactCustodyPeek::Eof) {
                custody_peer_closed = true;
            } else if (peek == ExactCustodyPeek::Error) {
                if (exact_listener_target_reaped(target, expected_target_start, target_status))
                    return OwnedWaitResult::Exited;
                hold_listener_failure(root_lease, custody_fd);
            }
        }
        if ((descriptor.revents & POLLHUP) != 0) {
            if (!custody_received)
                custody_peer_closed = true;
            else if (peek_exact_custody(custody_fd, true) == ExactCustodyPeek::Eof)
                custody_hup_observed = true;
        }
        if ((descriptor.revents & POLLNVAL) != 0 ||
            ((descriptor.revents & POLLERR) != 0 && !custody_peer_closed)) {
            if (custody_received && require_failure_losses &&
                !exact_failure_losses_complete(
                    custody_received, root_loss_observed, custody_hup_observed))
                hold_listener_failure(root_lease, custody_fd);
            if (custody_received)
                return finish_post_ack_escrow(
                    target, control, token, custody, rights, false, true, target_status);
            if (exact_listener_target_reaped(target, expected_target_start, target_status))
                return OwnedWaitResult::Exited;
            hold_listener_failure(root_lease, custody_fd);
        }
        if (custody_received && require_failure_losses) {
            if (exact_failure_losses_complete(
                    custody_received, root_loss_observed, custody_hup_observed))
                return finish_post_ack_escrow(
                    target, control, token, custody, rights, false, true, target_status);
            (void)poll(nullptr, 0, 10);
            continue;
        }
        int status = 0;
        errno = 0;
        const pid_t waited = waitpid(target, &status, WNOHANG);
        if (waited == target) {
            target_status = status;
            if (custody_received)
                return finish_post_ack_escrow(
                    target, control, token, custody, rights, true, true, target_status);
            bool first_pending_check = true;
            const auto pending_deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
            while (first_pending_check || std::chrono::steady_clock::now() < pending_deadline) {
                pollfd pending{custody_fd, POLLIN | POLLHUP, 0};
                int pending_result;
                const int timeout = first_pending_check ? 0 : 10;
                first_pending_check = false;
                do {
                    pending_result = poll(&pending, 1, timeout);
                } while (pending_result < 0 && errno == EINTR);
                if (pending_result < 0 || (pending.revents & POLLNVAL) != 0 ||
                    ((pending.revents & POLLERR) != 0 && (pending.revents & POLLHUP) == 0))
                    hold_listener_failure(root_lease, custody_fd);
                if (pending_result == 0) {
                    if (timeout == 0) return OwnedWaitResult::Exited;
                    continue;
                }
                const ExactPostReapCustodyAction action = exact_post_reap_custody_action(
                    peek_exact_custody(custody_fd, (pending.revents & POLLHUP) != 0));
                if (action == ExactPostReapCustodyAction::Receive) {
                    if (const auto result = accept_custody(true)) return *result;
                } else if (action == ExactPostReapCustodyAction::ReturnExited) {
                    return OwnedWaitResult::Exited;
                } else if (action == ExactPostReapCustodyAction::Hold) {
                    hold_listener_failure(root_lease, custody_fd);
                }
            }
            hold_listener_failure(root_lease, custody_fd);
        }
        if (waited < 0 && errno != EINTR) {
            if (custody_received)
                return finish_post_ack_escrow(
                    target, control, token, custody, rights, false, true, target_status);
            hold_listener_failure(root_lease, custody_fd);
        }
        if (custody_peer_closed &&
            exact_peer_closed_action(false, false) == ExactPeerClosedAction::WaitDirect)
            (void)poll(nullptr, 0, 10);
    }
    if (custody_received && require_failure_losses &&
        !exact_failure_losses_complete(custody_received, root_loss_observed, custody_hup_observed))
        hold_listener_failure(root_lease, custody_fd);
    if (exact_listener_failure_requires_hold(custody_received, ExactListenerWaitEvent::Deadline)) {
        if (exact_listener_target_reaped(target, expected_target_start, target_status))
            return OwnedWaitResult::Exited;
        if (exact_peer_closed_action(false, true) == ExactPeerClosedAction::Hold)
            hold_listener_failure(root_lease, custody_fd);
    }
    return finish_post_ack_escrow(
        target, control, token, custody, rights, false, true, target_status);
}

static bool exact_adoption_fault_self_check(std::string& error) {
    if (classify_exact_listener_observation(
            false, true, false, false, ExactEscrowValidation::Valid) !=
            ExactEscrowValidation::ObservationTransient ||
        classify_exact_listener_observation(
            true, false, false, false, ExactEscrowValidation::Valid) !=
            ExactEscrowValidation::ObservationTransient ||
        classify_exact_listener_observation(
            true, true, false, false, ExactEscrowValidation::Valid) !=
            ExactEscrowValidation::ObservationTransient ||
        classify_exact_listener_observation(
            true, true, true, false, ExactEscrowValidation::ObservationTransient) !=
            ExactEscrowValidation::ObservationTransient ||
        classify_exact_listener_observation(
            true, true, true, false, ExactEscrowValidation::Valid) !=
            ExactEscrowValidation::Invalid ||
        classify_exact_listener_observation(true, true, true, true, ExactEscrowValidation::Valid) !=
            ExactEscrowValidation::Valid) {
        error = "exact listener absence/conflict identity classification failed";
        return false;
    }
    if (exact_peer_closed_action(false, false) != ExactPeerClosedAction::WaitDirect ||
        exact_peer_closed_action(true, false) != ExactPeerClosedAction::ReturnExited ||
        exact_peer_closed_action(false, true) != ExactPeerClosedAction::Hold) {
        error = "exact custody HUP-before-waitable state decision failed";
        return false;
    }
    if (!exact_listener_failure_requires_hold(false, ExactListenerWaitEvent::RootLoss) ||
        !exact_listener_failure_requires_hold(false, ExactListenerWaitEvent::Deadline) ||
        exact_listener_failure_requires_hold(true, ExactListenerWaitEvent::RootLoss)) {
        error = "exact pre-custody root-loss/deadline hold decision failed";
        return false;
    }
    if (exact_failure_losses_complete(false, true, true) ||
        exact_failure_losses_complete(true, false, true) ||
        exact_failure_losses_complete(true, true, false) ||
        !exact_failure_losses_complete(true, true, true)) {
        error = "exact custody/root-loss/HUP settlement gate failed";
        return false;
    }
    if (exact_target_numeric_signal_allowed(-1, ECHILD, true) ||
        exact_target_numeric_signal_allowed(0, 0, false) ||
        !exact_target_numeric_signal_allowed(0, 0, true)) {
        error = "exact Target waitpid-error signalling decision failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        error = "exact adoption PID-start self-check fork failed";
        return false;
    }
    if (child == 0) {
        for (;;) pause();
    }
    ProcIdentity identity;
    if (!read_proc(child, identity, false)) {
        (void)kill(child, SIGKILL);
        error = "exact adoption PID-start self-check identity failed";
        return false;
    }
    ExactCustodyRecord wrong;
    wrong.child_pid = static_cast<u64>(child);
    wrong.child_start = identity.start + 1u;
    wrong.child_exe_dev = identity.exe_dev;
    wrong.child_exe_ino = identity.exe_ino;
    ExactEscrowRights rights;
    bool adopted = false;
    const auto start = std::chrono::steady_clock::now();
    if (wait_reap_adopted_exact(wrong, rights, start + std::chrono::milliseconds(30), adopted) ||
        adopted || std::chrono::steady_clock::now() - start > std::chrono::milliseconds(250)) {
        (void)kill(child, SIGKILL);
        error = "wrong exact adopted PID-start was not rejected boundedly";
        return false;
    }
    ExactCustodyRecord correct = wrong;
    correct.child_start = identity.start;
    ProcIdentity transitioned = identity;
    transitioned.ppid = getpid() + 1;
    ProcIdentity wrong_identity = identity;
    ++wrong_identity.start;
    if (classify_exact_child_observation(false,
                                         identity,
                                         correct,
                                         getpid(),
                                         transitioned.ppid,
                                         identity.netns,
                                         identity.uid,
                                         identity.gid) !=
            ExactEscrowValidation::ObservationTransient ||
        classify_exact_child_observation(true,
                                         transitioned,
                                         correct,
                                         getpid(),
                                         transitioned.ppid,
                                         identity.netns,
                                         identity.uid,
                                         identity.gid) !=
            ExactEscrowValidation::ObservationTransient ||
        classify_exact_child_observation(true,
                                         wrong_identity,
                                         correct,
                                         getpid(),
                                         transitioned.ppid,
                                         identity.netns,
                                         identity.uid,
                                         identity.gid) != ExactEscrowValidation::Invalid) {
        (void)kill(child, SIGKILL);
        error = "exact child read/transition/stable mismatch classification failed";
        return false;
    }
    if (!exact_custody_child_identity_matches(
            identity, correct, getpid(), identity.netns, identity.uid, identity.gid) ||
        exact_custody_child_identity_matches(
            identity, correct, getpid() + 1, identity.netns, identity.uid, identity.gid)) {
        (void)kill(child, SIGKILL);
        error = "exact Target-exit/adopted-child identity branch failed";
        return false;
    }
    if (!wait_reap_adopted_exact(correct, rights, new_exact_cleanup_deadline(), adopted) ||
        !adopted) {
        (void)kill(child, SIGKILL);
        error = "exact adopted child direct authority did not reap";
        return false;
    }
    return true;
}

static int dropped_broker_main(const char* executable,
                               const char* control_path,
                               const char* token_string,
                               const char* expected_netns_text,
                               const char* scenario,
                               const char* credential_fd_text) {
    Token token;
    u64 expected_netns = 0;
    u64 credential_fd_value = 0;
    if (!token_from_hex(token_string, token) || !parse_u64(expected_netns_text, expected_netns) ||
        !parse_u64(credential_fd_text, credential_fd_value) || expected_netns == 0 ||
        credential_fd_value != kCredentialFd || geteuid() != 0)
        return 20;
    const pid_t root_broker = getppid();
    if (!arm_parent_death(root_broker)) return 21;
    const std::string expected_root_argv = exact_argv({executable,
                                                       "--fixture-privileged-broker",
                                                       control_path,
                                                       token_string,
                                                       expected_netns_text,
                                                       scenario});
    ProcIdentity root_identity;
    Peer root_peer;
    if (!read_proc(root_broker, root_identity, false) || root_identity.uid != 0 ||
        root_identity.gid != 0 || root_identity.netns != expected_netns ||
        root_identity.exe != executable || root_identity.cmdline != expected_root_argv ||
        !get_peer(kCredentialFd, root_peer) || root_peer.pid != root_broker || root_peer.uid != 0 ||
        root_peer.gid != 0 || getppid() != root_broker)
        return 22;
    Frame credentials;
    uid_t caller_uid = 0;
    gid_t caller_gid = 0;
    if (!receive_frame(kCredentialFd, credentials, kHandshakeMs) ||
        credentials.type != kCallerCredentials || !token_equal(credentials.token, token) ||
        !parse_credentials(credentials.payload, caller_uid, caller_gid) || caller_uid == 0)
        return 25;
    const gid_t sentinel = caller_gid == static_cast<gid_t>(65534) ? 65533 : 65534;
    if (setgroups(1, &sentinel) != 0) return 26;
    int launch_pipe[2] = {-1, -1};
    int trace_pipe[2] = {-1, -1};
    if (pipe2(launch_pipe, O_CLOEXEC) != 0 || pipe2(trace_pipe, O_CLOEXEC) != 0) return 27;
    const bool listener_scenario = listener_scenario_name(scenario);
    int custody_pair[2] = {-1, -1};
    const int pass_credentials = 1;
    if (listener_scenario &&
        (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0 ||
         socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, custody_pair) != 0 ||
         setsockopt(custody_pair[0],
                    SOL_SOCKET,
                    SO_PASSCRED,
                    &pass_credentials,
                    sizeof(pass_credentials)) != 0))
        return 27;
    const pid_t target = fork();
    if (target < 0) return 28;
    if (target == 0) {
        const pid_t broker_parent = getppid();
        close(launch_pipe[1]);
        close(trace_pipe[0]);
        if (listener_scenario) {
            close(custody_pair[0]);
            if (custody_pair[1] == kExactCustodyFd) {
                const int flags = fcntl(kExactCustodyFd, F_GETFD);
                if (flags < 0 || fcntl(kExactCustodyFd, F_SETFD, flags & ~FD_CLOEXEC) != 0)
                    _exit(49);
            } else {
                if (dup3(custody_pair[1], kExactCustodyFd, 0) != kExactCustodyFd) _exit(49);
                close(custody_pair[1]);
            }
        }
        if (!arm_parent_death(broker_parent)) _exit(50);
        char authorization = 0;
        ssize_t count;
        do {
            count = read(launch_pipe[0], &authorization, 1);
        } while (count < 0 && errno == EINTR);
        close(launch_pipe[0]);
        if (count != 1 || authorization != 'L') _exit(51);
        if (strcmp(scenario, "term-ignore") == 0 ||
            strcmp(scenario, "owned-wait-term-ignore") == 0) {
            struct sigaction action{};
            action.sa_handler = SIG_IGN;
            sigemptyset(&action.sa_mask);
            if (sigaction(SIGTERM, &action, nullptr) != 0) _exit(52);
        }
        if (!secure_target(caller_uid, caller_gid, trace_pipe[1]) ||
            !arm_parent_death(broker_parent))
            _exit(53);
        close(trace_pipe[1]);
        const std::string broker_pid = std::to_string(getppid());
        execl(executable,
              executable,
              "--fixture-privileged-target",
              control_path,
              token_string,
              broker_pid.c_str(),
              scenario,
              static_cast<char*>(nullptr));
        _exit(54);
    }
    close(launch_pipe[0]);
    close(trace_pipe[1]);
    if (listener_scenario) {
        close(custody_pair[1]);
        custody_pair[1] = -1;
    }
    int control = -1;
    OwnedChildCleanup target_cleanup(target, &control);
    u64 listener_target_start = 0u;
    // These are all downstream leases owned by this dropped broker.  Close
    // them before reaping on every pre-launch return so a blocked target gets
    // EOF/PDEATHSIG and can exit without an unsafe signal from its parent.
    target_cleanup.add_downstream_fd(&launch_pipe[1]);
    target_cleanup.add_downstream_fd(&trace_pipe[0]);
    if (listener_scenario) target_cleanup.add_downstream_fd(&custody_pair[0]);
    if (listener_scenario) {
        ProcIdentity spawned_target;
        if (!read_proc(target, spawned_target, false) || spawned_target.pid != target ||
            spawned_target.ppid != getpid() || spawned_target.start == 0u)
            return 28;
        listener_target_start = spawned_target.start;
    }
    if (!secure_as(caller_uid, caller_gid) || !arm_parent_death(root_broker) ||
        (listener_scenario && (prctl(PR_SET_PDEATHSIG, 0) != 0 || getppid() != root_broker)))
        return 29;
    control = connect_control(control_path);
    if (control < 0) return 30;
    Report dropped_report;
    if (!fill_report("broker-dropped", static_cast<u64>(root_broker), dropped_report, true) ||
        !send_frame(
            control, Frame{kBrokerDropped, token, encode_report(dropped_report)}, kHandshakeMs))
        return 31;
    Frame identity_request;
    if (!receive_frame(control, identity_request, kHandshakeMs) ||
        identity_request.type != kDroppedIdentityRequest ||
        !token_equal(identity_request.token, token) || !identity_request.payload.empty())
        return 32;
    identity_bundle::RoleBundle dropped_role;
    std::string dropped_identity_error;
    if (!identity_bundle::open_role(
            getpid(), identity_bundle::Role::Dropped, dropped_role, dropped_identity_error) ||
        !identity_bundle::send_dropped_role(
            control,
            dropped_role,
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs)))
        return 32;
    // The sender retains no received/source descriptors after the SCM_RIGHTS
    // record is accepted; the parent owns the copies used for extraction.
    dropped_role.close();
    Frame launch;
    if (!receive_frame(control, launch, kHandshakeMs) || launch.type != kLaunchTarget ||
        !token_equal(launch.token, token) || !launch.payload.empty() ||
        write(launch_pipe[1], "L", 1) != 1)
        return 32;
    close(launch_pipe[1]);
    launch_pipe[1] = -1;
    std::array<unsigned char, 7> trace{};
    if (!read_exact(trace_pipe[0], trace.data(), trace.size(), kHandshakeMs)) return 36;
    char extra = 0;
    ssize_t extra_count;
    do {
        extra_count = read(trace_pipe[0], &extra, 1);
    } while (extra_count < 0 && errno == EINTR);
    close(trace_pipe[0]);
    trace_pipe[0] = -1;
    if (extra_count != 0 ||
        !send_frame(
            control,
            Frame{kSecurityTrace, token, std::vector<unsigned char>(trace.begin(), trace.end())},
            kHandshakeMs))
        return 36;
    Frame command;
    if (strcmp(scenario, "broker-early") == 0) {
        if (!receive_frame(control, command, kBrokerDeadlineMs) ||
            command.type != kBrokerExitEarly || !token_equal(command.token, token))
            return 33;
        _exit(86);
    }
    int target_status = 0;
    const std::string target_argv = exact_argv({executable,
                                                "--fixture-privileged-target",
                                                control_path,
                                                token_string,
                                                std::to_string(getpid()),
                                                scenario});
    const int target_wait_ms =
        strcmp(scenario, "owned-wait-term-ignore") == 0 ? kCleanupMs : kBrokerDeadlineMs;
    const OwnedWaitResult target_wait_result =
        listener_scenario ? wait_listener_target_bounded(target,
                                                         listener_target_start,
                                                         executable,
                                                         target_argv,
                                                         root_broker,
                                                         root_identity.start,
                                                         kCredentialFd,
                                                         custody_pair[0],
                                                         listener_failure_integration(scenario),
                                                         control,
                                                         token,
                                                         static_cast<ino_t>(expected_netns),
                                                         caller_uid,
                                                         caller_gid,
                                                         canonical_collision_scenario(scenario)
                                                             ? kWildcardAttemptAggregateWaitMs
                                                             : kListenerDeadlineMs * 2,
                                                         target_status)
                          : wait_owned_child_bounded(target,
                                                     executable,
                                                     target_argv,
                                                     caller_uid,
                                                     caller_gid,
                                                     static_cast<ino_t>(expected_netns),
                                                     target,
                                                     true,
                                                     target_wait_ms,
                                                     target_status,
                                                     kCredentialFd,
                                                     &control);
    if (target_wait_result != OwnedWaitResult::Exited) {
        if (target_wait_result == OwnedWaitResult::LeaseLost) target_cleanup.disarm();
        close(kCredentialFd);
        return 34;
    }
    target_cleanup.disarm();
    if (custody_pair[0] >= 0) {
        close(custody_pair[0]);
        custody_pair[0] = -1;
    }
    const std::vector<unsigned char> status_payload{
        static_cast<unsigned char>(target_status),
        static_cast<unsigned char>(target_status >> 8),
        static_cast<unsigned char>(target_status >> 16),
        static_cast<unsigned char>(target_status >> 24)};
    if (!send_frame(control, Frame{kTargetExited, token, status_payload}, kHandshakeMs) ||
        !receive_frame(control, command, kHandshakeMs) || command.type != kRelease ||
        !token_equal(command.token, token) || !command.payload.empty())
        return 35;
    (void)send_frame(control, Frame{kReleased, token, {}}, kHandshakeMs);
    close(control);
    close(kCredentialFd);
    return 0;
}

static bool collect_probe_ancestry(pid_t first_parent,
                                   pid_t ordinary_parent,
                                   ancestry_bundle::AncestryBundle& ancestry,
                                   std::chrono::steady_clock::time_point deadline,
                                   std::string& safe_diagnostic) {
    return privileged_ancestry::collect_ancestry(
        first_parent, ordinary_parent, ancestry, deadline, safe_diagnostic);
}

static int root_broker_main(const char* executable,
                            const char* control_path,
                            const char* token_string,
                            const char* expected_netns_text,
                            const char* scenario) {
    Token token;
    u64 expected_netns = 0;
    if (!token_from_hex(token_string, token) || !parse_u64(expected_netns_text, expected_netns) ||
        expected_netns == 0 || geteuid() != 0)
        return 20;
    const pid_t launcher = getppid();
    if (launcher <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != launcher) return 21;
    identity_bundle::IdentityBundle bundle;
    std::string identity_error;
    if (!take_launcher_bundle_handoff(bundle.roles[0], identity_error) ||
        bundle.roles[0].manifest.pid != launcher ||
        !identity_bundle::open_role(
            getpid(), identity_bundle::Role::Root, bundle.roles[1], identity_error) ||
        !identity_bundle::validate_bundle(bundle, identity_error) ||
        bundle.roles[1].manifest.ppid != bundle.roles[0].manifest.pid)
        return 22;
    ProcIdentity identity;
    if (!read_proc(getpid(), identity, false) || identity.netns != expected_netns) return 22;
    const int root_control = connect_control(control_path);
    if (root_control < 0) return 23;
    const bool ancestry_probe = strcmp(scenario, "ancestry-probe-direct") == 0;
    if (ancestry_probe) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kBrokerDeadlineMs);
        Peer ordinary_parent;
        Frame request;
        if (!get_peer(root_control, ordinary_parent) || ordinary_parent.pid <= 1 ||
            ordinary_parent.uid == 0 || ordinary_parent.gid == 0 ||
            ordinary_parent.pid == launcher ||
            !send_frame(root_control,
                        Frame{kAncestryProbeHello, token, {}},
                        remaining_deadline_ms(deadline)) ||
            !receive_frame_until(root_control, request, deadline) ||
            request.type != kIdentityBundleRequest || !token_equal(request.token, token) ||
            !request.payload.empty() ||
            !identity_bundle::send_bundle(root_control, bundle, deadline) ||
            !receive_frame_until(root_control, request, deadline) ||
            request.type != kAncestryProbeRequest || !token_equal(request.token, token) ||
            !request.payload.empty()) {
            close(root_control);
            return 90;
        }
        ancestry_bundle::AncestryBundle ancestry;
        std::string diagnostic;
        if (!collect_probe_ancestry(bundle.roles[0].manifest.ppid,
                                    ordinary_parent.pid,
                                    ancestry,
                                    deadline,
                                    diagnostic)) {
            std::cerr << "FAIL [#358 ancestry access]: " << diagnostic << "\n";
            close(root_control);
            return 91;
        }
        if (!ancestry_bundle::send_bundle(root_control, ancestry, deadline)) {
            ancestry.close();
            close(root_control);
            return 92;
        }
        ancestry.close();
        bundle.close();
        if (!receive_frame_until(root_control, request, deadline) ||
            request.type != kAncestryProbeRelease || !token_equal(request.token, token) ||
            !request.payload.empty()) {
            close(root_control);
            return 93;
        }
        close(root_control);
        return 0;
    }
    const auto authorization_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kBrokerDeadlineMs);
    Report root_report;
    if (!fill_report("broker-root", static_cast<u64>(launcher), root_report, false) ||
        !send_frame(root_control,
                    Frame{kBrokerRootHello, token, encode_report(root_report)},
                    remaining_deadline_ms(authorization_deadline)))
        return 24;
    Frame bundle_request;
    if (!receive_frame_until(root_control, bundle_request, authorization_deadline) ||
        bundle_request.type != kIdentityBundleRequest ||
        !token_equal(bundle_request.token, token) || !bundle_request.payload.empty() ||
        !identity_bundle::send_bundle(root_control, bundle, authorization_deadline))
        return 24;
    Peer ordinary_parent;
    if (!get_peer(root_control, ordinary_parent) || ordinary_parent.pid <= 1 ||
        ordinary_parent.uid == 0 || ordinary_parent.gid == 0 || ordinary_parent.pid == launcher ||
        !receive_exact_request_until(
            root_control, kInitialAncestryRequest, token, authorization_deadline))
        return 24;
    ancestry_bundle::AncestryBundle initial_ancestry;
    std::string ancestry_diagnostic;
    if (!collect_probe_ancestry(bundle.roles[0].manifest.ppid,
                                ordinary_parent.pid,
                                initial_ancestry,
                                authorization_deadline,
                                ancestry_diagnostic) ||
        !ancestry_bundle::send_bundle(root_control, initial_ancestry, authorization_deadline)) {
        initial_ancestry.close();
        return 24;
    }
    initial_ancestry.close();
    if (!receive_exact_request_until(
            root_control, kFinalAncestryRequest, token, authorization_deadline))
        return 24;
    identity_bundle::ProcessIdentityEvidence launcher_evidence;
    identity_bundle::ProcessIdentityEvidence root_evidence;
    Peer final_parent;
    if (!identity_bundle::extract_process_identity_evidence(
            bundle.roles[0], identity_bundle::Role::Launcher, launcher_evidence, identity_error) ||
        !identity_bundle::extract_process_identity_evidence(
            bundle.roles[1], identity_bundle::Role::Root, root_evidence, identity_error) ||
        launcher_evidence.identity.pid != launcher || root_evidence.identity.pid != getpid() ||
        root_evidence.identity.ppid != launcher_evidence.identity.pid ||
        launcher_evidence.identity.ppid != bundle.roles[0].manifest.ppid ||
        !get_peer(root_control, final_parent) || final_parent.pid != ordinary_parent.pid ||
        final_parent.uid != ordinary_parent.uid || final_parent.gid != ordinary_parent.gid)
        return 24;
    ancestry_bundle::AncestryBundle final_ancestry;
    if (!collect_probe_ancestry(bundle.roles[0].manifest.ppid,
                                ordinary_parent.pid,
                                final_ancestry,
                                authorization_deadline,
                                ancestry_diagnostic) ||
        !ancestry_bundle::send_bundle(root_control, final_ancestry, authorization_deadline)) {
        final_ancestry.close();
        return 24;
    }
    final_ancestry.close();
    Frame bundle_ack;
    if (!receive_frame_until(root_control, bundle_ack, authorization_deadline) ||
        bundle_ack.type != kIdentityBundleAck || !token_equal(bundle_ack.token, token) ||
        !bundle_ack.payload.empty())
        return 24;
    bundle.close();
    for (size_t i = 0; i != identity_bundle::kFdsPerRole; ++i) {
        errno = 0;
        if (fcntl(kLauncherBundleFdBase + static_cast<int>(i), F_GETFD) >= 0 || errno != EBADF)
            return 24;
    }
    Peer parent_peer;
    Frame credentials;
    uid_t caller_uid = 0;
    gid_t caller_gid = 0;
    if (!get_peer(root_control, parent_peer) ||
        !receive_frame_until(root_control, credentials, authorization_deadline) ||
        credentials.type != kCallerCredentials || !token_equal(credentials.token, token) ||
        !parse_credentials(credentials.payload, caller_uid, caller_gid) ||
        !credentials_match_peer(credentials.payload, parent_peer.uid, parent_peer.gid) ||
        caller_uid != parent_peer.uid || caller_gid != parent_peer.gid || caller_uid == 0)
        return 25;
    const std::string dropped_argv = exact_argv({executable,
                                                 "--fixture-privileged-dropped-broker",
                                                 control_path,
                                                 token_string,
                                                 expected_netns_text,
                                                 scenario,
                                                 std::to_string(kCredentialFd)});
    int credential_pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, credential_pair) != 0) return 26;
    const pid_t dropped = fork();
    if (dropped < 0) return 27;
    if (dropped == 0) {
        close(credential_pair[0]);
        if (credential_pair[1] == kCredentialFd) {
            const int flags = fcntl(kCredentialFd, F_GETFD);
            if (flags < 0 || fcntl(kCredentialFd, F_SETFD, flags & ~FD_CLOEXEC) != 0) _exit(55);
        } else {
            if (dup3(credential_pair[1], kCredentialFd, 0) != kCredentialFd) _exit(55);
            close(credential_pair[1]);
        }
        const std::string credential_fd = std::to_string(kCredentialFd);
        execl(executable,
              executable,
              "--fixture-privileged-dropped-broker",
              control_path,
              token_string,
              expected_netns_text,
              scenario,
              credential_fd.c_str(),
              static_cast<char*>(nullptr));
        _exit(56);
    }
    close(credential_pair[1]);
    OwnedChildCleanup dropped_cleanup(dropped, &credential_pair[0]);
    if (!send_frame(credential_pair[0],
                    Frame{kCallerCredentials, token, credentials.payload},
                    kHandshakeMs)) {
        close(credential_pair[0]);
        credential_pair[0] = -1;
        int abandoned_status = 0;
        const OwnedWaitResult abandoned =
            wait_owned_child_bounded(dropped,
                                     executable,
                                     dropped_argv,
                                     caller_uid,
                                     caller_gid,
                                     static_cast<ino_t>(expected_netns),
                                     dropped,
                                     true,
                                     kCleanupMs,
                                     abandoned_status,
                                     root_control);
        close(root_control);
        if (credential_pair[0] >= 0) close(credential_pair[0]);
        if (abandoned != OwnedWaitResult::Error) dropped_cleanup.disarm();
        return abandoned == OwnedWaitResult::Exited ? 28 : 29;
    }
    int status = 0;
    const int dropped_wait_ms = canonical_collision_scenario(scenario)
                                    ? kWildcardAttemptAggregateWaitMs
                                : listener_scenario_name(scenario) ? kListenerDeadlineMs * 3
                                                                   : kBrokerDeadlineMs;
    const OwnedWaitResult dropped_wait_result =
        wait_owned_child_bounded(dropped,
                                 executable,
                                 dropped_argv,
                                 caller_uid,
                                 caller_gid,
                                 static_cast<ino_t>(expected_netns),
                                 dropped,
                                 true,
                                 dropped_wait_ms,
                                 status,
                                 root_control,
                                 &credential_pair[0],
                                 listener_failure_integration(scenario));
    if (dropped_wait_result != OwnedWaitResult::Exited) {
        if (dropped_wait_result == OwnedWaitResult::LeaseLost &&
            listener_failure_integration(scenario)) {
            dropped_cleanup.disarm();
            close(root_control);
            if (credential_pair[0] >= 0) close(credential_pair[0]);
            return 0;
        }
        if (dropped_wait_result == OwnedWaitResult::LeaseLost) dropped_cleanup.disarm();
        close(root_control);
        if (credential_pair[0] >= 0) close(credential_pair[0]);
        return 29;
    }
    dropped_cleanup.disarm();
    close(root_control);
    if (credential_pair[0] >= 0) close(credential_pair[0]);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 30;
}

static bool drain_adopted_children_until(std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        int status = 0;
        const pid_t adopted = waitpid(-1, &status, WNOHANG);
        if (adopted > 0) continue;
        if (adopted < 0 && errno == EINTR) continue;
        if (adopted < 0 && errno == ECHILD) return true;
        if (adopted < 0) return false;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        (void)poll(nullptr, 0, 10);
    }
}

static int launcher_main(const char* executable,
                         const char* control_path,
                         const char* token,
                         const char* expected_netns,
                         const char* scenario) {
    const pid_t parent = getppid();
    if (parent <= 1 || geteuid() != 0 || prctl(PR_SET_CHILD_SUBREAPER, 1) != 0 ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
        return 10;
    u64 expected_netns_value = 0;
    if (!parse_u64(expected_netns, expected_netns_value)) return 11;
    identity_bundle::RoleBundle launcher_role;
    std::string identity_error;
    if (!identity_bundle::open_role(
            getpid(), identity_bundle::Role::Launcher, launcher_role, identity_error) ||
        launcher_role.manifest.pid != getpid() || launcher_role.manifest.ppid != parent ||
        launcher_role.manifest.pgid != getpgrp() || launcher_role.manifest.uid != 0 ||
        launcher_role.manifest.gid != 0 || launcher_role.manifest.netns != expected_netns_value)
        return 11;
    const std::string broker_argv = exact_argv(
        {executable, "--fixture-privileged-broker", control_path, token, expected_netns, scenario});
    const pid_t broker = fork();
    if (broker < 0) return 12;
    if (broker == 0) {
        if (!install_launcher_bundle_handoff(launcher_role)) _exit(126);
        execl(executable,
              executable,
              "--fixture-privileged-broker",
              control_path,
              token,
              expected_netns,
              scenario,
              static_cast<char*>(nullptr));
        _exit(127);
    }
    OwnedChildCleanup broker_cleanup(broker);
    if (getppid() != parent) {
        int abandoned_status = 0;
        const OwnedWaitResult abandoned =
            wait_owned_child_bounded(broker,
                                     executable,
                                     broker_argv,
                                     0,
                                     0,
                                     static_cast<ino_t>(expected_netns_value),
                                     getpgrp(),
                                     false,
                                     kCleanupMs,
                                     abandoned_status);
        if (abandoned != OwnedWaitResult::Error) broker_cleanup.disarm();
        return abandoned == OwnedWaitResult::Exited ? 13 : 14;
    }
    int status = 0;
    const OwnedWaitResult broker_wait_result =
        wait_owned_child_bounded(broker,
                                 executable,
                                 broker_argv,
                                 0,
                                 0,
                                 static_cast<ino_t>(expected_netns_value),
                                 getpgrp(),
                                 false,
                                 launcher_broker_wait_ms(scenario),
                                 status);
    if (broker_wait_result != OwnedWaitResult::Exited) {
        const OwnedReapResult broker_reap = reap_owned_child_bounded(broker);
        // Adopted children may only be drained after the direct broker has
        // been positively reaped.  Keep the owner guard armed on timeout or
        // wait error; its bounded destructor remains responsible for the
        // broker and no adopted drain can race a live broker.
        if (!broker_reap_allows_adopted_drain(broker_reap)) return 15;
        broker_cleanup.disarm();
        const bool drained = drain_adopted_children_until(
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs * 2));
        return drained ? 13 : 15;
    }
    broker_cleanup.disarm();
    // Reap any target adopted after an intentionally early broker death.
    const bool broker_abnormal =
        WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0);
    const bool adopted_drained =
        !broker_abnormal || drain_adopted_children_until(std::chrono::steady_clock::now() +
                                                         std::chrono::milliseconds(kCleanupMs * 2));
    if (!adopted_drained) return 15;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 14;
}

static bool create_parent_endpoint(ParentEndpoint& endpoint, std::string& error) {
    std::array<char, 64> pattern{};
    snprintf(pattern.data(), pattern.size(), "/tmp/rut358-broker-XXXXXX");
    if (mkdtemp(pattern.data()) == nullptr) {
        error = "parent temporary directory creation failed";
        return false;
    }
    endpoint.directory = pattern.data();
    struct stat directory{};
    if (chmod(endpoint.directory.c_str(), 0700) != 0 ||
        stat(endpoint.directory.c_str(), &directory) != 0 || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != getuid() || directory.st_gid != getgid() ||
        (directory.st_mode & 0777) != 0700) {
        error = "parent temporary directory identity was not exact";
        return false;
    }
    endpoint.identity.directory_dev = directory.st_dev;
    endpoint.identity.directory_ino = directory.st_ino;
    endpoint.identity.uid = directory.st_uid;
    endpoint.identity.gid = directory.st_gid;
    const std::string socket_path = endpoint.directory + "/control.sock";
    if (!create_listener(socket_path, endpoint.listener)) {
        error = "parent AF_UNIX endpoint creation failed";
        return false;
    }
    endpoint.socket = socket_path;
    struct stat socket{};
    if (lstat(socket_path.c_str(), &socket) != 0 || !S_ISSOCK(socket.st_mode) ||
        (socket.st_mode & 0777) != 0600 || socket.st_uid != getuid() || socket.st_gid != getgid()) {
        error = "parent endpoint ownership/mode was not exact";
        return false;
    }
    endpoint.identity.socket_dev = socket.st_dev;
    endpoint.identity.socket_ino = socket.st_ino;
    return true;
}

static bool endpoint_matches(const ParentEndpoint& endpoint, const EndpointIdentity& expected) {
    struct stat directory{}, socket{};
    return stat(endpoint.directory.c_str(), &directory) == 0 &&
           lstat(endpoint.socket.c_str(), &socket) == 0 && S_ISDIR(directory.st_mode) &&
           S_ISSOCK(socket.st_mode) && directory.st_dev == expected.directory_dev &&
           directory.st_ino == expected.directory_ino && socket.st_dev == expected.socket_dev &&
           socket.st_ino == expected.socket_ino && directory.st_uid == expected.uid &&
           socket.st_uid == expected.uid && directory.st_gid == expected.gid &&
           socket.st_gid == expected.gid && (directory.st_mode & 0777) == 0700 &&
           (socket.st_mode & 0777) == 0600;
}

static bool endpoint_unchanged(const ParentEndpoint& endpoint) {
    return endpoint_matches(endpoint, endpoint.identity);
}

bool ParentEndpoint::cleanup(std::string& error) {
    if (listener >= 0) {
        close(listener);
        listener = -1;
    }
    if (socket.empty() && directory.empty()) return true;
    struct stat directory_status{};
    if (directory.empty() || stat(directory.c_str(), &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) || directory_status.st_dev != identity.directory_dev ||
        directory_status.st_ino != identity.directory_ino ||
        directory_status.st_uid != identity.uid || directory_status.st_gid != identity.gid ||
        (directory_status.st_mode & 0777) != 0700) {
        error = "refusing parent endpoint cleanup after identity/type/mode replacement";
        return false;
    }
    if (!socket.empty()) {
        struct stat socket_status{};
        if (lstat(socket.c_str(), &socket_status) != 0 || !S_ISSOCK(socket_status.st_mode) ||
            socket_status.st_dev != identity.socket_dev ||
            socket_status.st_ino != identity.socket_ino || socket_status.st_uid != identity.uid ||
            socket_status.st_gid != identity.gid || (socket_status.st_mode & 0777) != 0600) {
            error = "refusing parent endpoint cleanup after identity/type/mode replacement";
            return false;
        }
        if (unlink(socket.c_str()) != 0) {
            error = "exact parent control socket unlink failed";
            return false;
        }
        socket.clear();
    }
    if (rmdir(directory.c_str()) != 0) {
        error = "exact parent temporary directory removal failed";
        return false;
    }
    directory.clear();
    return true;
}

ParentEndpoint::~ParentEndpoint() {
    std::string error;
    if (!cleanup(error) && !error.empty())
        std::cerr << "FAIL [#358 Stage 2a3b endpoint destructor]: " << error << "\n";
}

static bool endpoint_replacement_self_check(std::string& error) {
    ParentEndpoint endpoint;
    if (!create_parent_endpoint(endpoint, error)) return false;
    close(endpoint.listener);
    endpoint.listener = -1;
    if (unlink(endpoint.socket.c_str()) != 0) {
        error = "endpoint replacement self-check could not remove its original socket";
        return false;
    }
    const int replacement =
        open(endpoint.socket.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (replacement < 0) {
        error = "endpoint replacement self-check could not create its owned mutation";
        return false;
    }
    close(replacement);
    struct stat replaced{};
    if (lstat(endpoint.socket.c_str(), &replaced) != 0 || !S_ISREG(replaced.st_mode) ||
        replaced.st_uid != getuid() || replaced.st_gid != getgid() ||
        (replaced.st_mode & 0777) != 0600) {
        error = "endpoint replacement mutation was not exact";
        return false;
    }
    std::string cleanup_error;
    if (endpoint.cleanup(cleanup_error) || cleanup_error.empty()) {
        error = "endpoint cleanup accepted a replaced socket";
        return false;
    }
    struct stat still_replaced{};
    if (lstat(endpoint.socket.c_str(), &still_replaced) != 0 ||
        still_replaced.st_dev != replaced.st_dev || still_replaced.st_ino != replaced.st_ino ||
        !S_ISREG(still_replaced.st_mode)) {
        error = "refused endpoint cleanup deleted or changed the replacement";
        return false;
    }
    if (unlink(endpoint.socket.c_str()) != 0) {
        error = "self-check-owned replacement unlink failed";
        return false;
    }
    endpoint.socket.clear();
    struct stat directory{};
    if (stat(endpoint.directory.c_str(), &directory) != 0 || !S_ISDIR(directory.st_mode) ||
        directory.st_dev != endpoint.identity.directory_dev ||
        directory.st_ino != endpoint.identity.directory_ino || directory.st_uid != getuid() ||
        directory.st_gid != getgid() || (directory.st_mode & 0777) != 0700 ||
        rmdir(endpoint.directory.c_str()) != 0) {
        error = "self-check-owned directory cleanup was not identity safe";
        return false;
    }
    endpoint.directory.clear();
    return true;
}

static bool no_process_with_token(const std::string& token) {
    const int directory = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return false;
    DIR* entries = fdopendir(directory);
    if (entries == nullptr) {
        close(directory);
        return false;
    }
    bool clean = true;
    while (dirent* entry = readdir(entries)) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
        char* end = nullptr;
        const long pid = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || pid <= 1 || pid == getpid()) continue;
        std::string cmdline;
        if (read_file("/proc/" + std::to_string(pid) + "/cmdline", cmdline, 8192) &&
            cmdline.find(token) != std::string::npos) {
            clean = false;
            break;
        }
    }
    closedir(entries);
    return clean;
}

static bool wait_direct(DirectLaunch& child, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t waited = waitpid(child.anchor.pid, &child.status, WNOHANG);
        const DirectWaitDisposition disposition =
            classify_direct_wait(waited, child.anchor.pid, waited < 0 ? errno : 0);
        if (disposition == DirectWaitDisposition::Reaped) {
            child.reaped = true;
            return true;
        }
        if (disposition == DirectWaitDisposition::Error) {
            child.reason = "waitpid(direct launch) failed: " + std::string(strerror(errno));
            return false;
        }
        (void)poll(nullptr, 0, 10);
    }
    return false;
}

static bool safe_signal_direct_child(DirectLaunch& child, int signal_number) {
    ProcIdentity current;
    std::string reason;
    if (child.anchor.pid <= 1 || child.anchor.pgid <= 1 ||
        !read_proc(child.anchor.pid, current, false) ||
        !current_allows_group_signal(child, current, reason)) {
        child.reason =
            reason.empty() ? "direct launch could not be revalidated for group signal" : reason;
        return false;
    }
    if (!observe_direct(child, current, reason)) return false;
    if (geteuid() == 0) return kill(-child.anchor.pgid, signal_number) == 0;
    if (current.uid != getuid() || current.gid != getgid()) {
        child.reason = "ordinary parent lacked exact direct-child credentials";
        return false;
    }
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, current.pid, 0));
    if (pidfd < 0) return false;
    ProcIdentity confirmed;
    const bool exact = read_proc(current.pid, confirmed, false) &&
                       same_process_identity(current, confirmed) && confirmed.uid == getuid() &&
                       confirmed.gid == getgid();
    const bool signaled =
        exact && syscall(SYS_pidfd_send_signal, pidfd, signal_number, nullptr, 0) == 0;
    close(pidfd);
    return signaled;
#else
    (void)signal_number;
    return false;
#endif
}

static bool bounded_wait_and_signal_self_check(std::string& error) {
    int ready[2] = {-1, -1};
    if (pipe2(ready, O_CLOEXEC) != 0) {
        error = "bounded-wait self-check pipe failed";
        return false;
    }
    ProcIdentity parent;
    if (!read_proc(getpid(), parent, false)) {
        close(ready[0]);
        close(ready[1]);
        error = "bounded-wait self-check parent identity failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        error = "bounded-wait self-check fork failed";
        return false;
    }
    if (child == 0) {
        close(ready[0]);
        struct sigaction action{};
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        const unsigned char marker = 0xa3;
        if (setpgid(0, 0) != 0 || sigaction(SIGTERM, &action, nullptr) != 0 ||
            write(ready[1], &marker, 1) != 1)
            _exit(70);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    unsigned char marker = 0;
    const bool ready_exact = read_exact(ready[0], &marker, 1, kHandshakeMs) && marker == 0xa3;
    close(ready[0]);
    ProcIdentity observed;
    const bool identity_exact = ready_exact && read_proc(child, observed, false) &&
                                observed.ppid == getpid() && observed.pgid == child &&
                                observed.uid == parent.uid && observed.gid == parent.gid &&
                                observed.netns == parent.netns && observed.exe == parent.exe &&
                                observed.cmdline == parent.cmdline;
    const StageDescriptor self_stage{observed.exe_dev, observed.exe_ino, observed.cmdline};
    DirectLaunchAnchor self_anchor{};
    self_anchor.pid = child;
    self_anchor.start = observed.start;
    self_anchor.pgid = child;
    self_anchor.caller_uid = parent.uid;
    self_anchor.caller_gid = parent.gid;
    self_anchor.host_netns = parent.netns;
    self_anchor.sid = observed.sid;
    self_anchor.exe_dev = observed.exe_dev;
    self_anchor.exe_ino = observed.exe_ino;
    self_anchor.exe = observed.exe;
    self_anchor.cmdline = observed.cmdline;
    DirectLaunch direct(self_anchor, {self_stage, self_stage, self_stage, parent.netns + 1});
    std::string launch_reason;
    const bool observed_exact = identity_exact && observe_direct(direct, observed, launch_reason);
    DirectLaunch stale = direct;
    stale.current_identity.start++;
    DirectLaunch unsafe = direct;
    unsafe.current_identity.pgid = 1;
    const bool mutations = observed_exact && safe_signal_direct_child(direct, 0) &&
                           !safe_signal_direct_child(stale, 0) &&
                           !safe_signal_direct_child(unsafe, 0);
    int status = 0;
    const bool reaped = wait_owned_child_bounded(child,
                                                 parent.exe,
                                                 parent.cmdline,
                                                 parent.uid,
                                                 parent.gid,
                                                 parent.netns,
                                                 child,
                                                 false,
                                                 50,
                                                 status) == OwnedWaitResult::Exited;
    if (!identity_exact || !mutations || !reaped || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGKILL) {
        error = "bounded child wait/stale identity/TERM-ignore self-check failed";
        return false;
    }
    return true;
}

static bool stable_proc_identity(pid_t pid, ProcIdentity& identity) {
    ProcIdentity first, second;
    return read_proc(pid, first, false) && read_proc(pid, second, false) &&
           same_process_identity(first, second) && (identity = std::move(second), true);
}

static bool retained_anchor_self_check(std::string& error) {
    const std::string valid_status("Uid: 0 0 0 0\nGid: 0 0 0 0\n");
    RetainedAnchorEvidence parsed_status;
    RetainedAnchorEvidence missing_status;
    RetainedAnchorEvidence extra_status;
    RetainedAnchorEvidence out_of_range_status;
    const bool status_parser_ok =
        parse_retained_anchor_status(valid_status, parsed_status) &&
        parsed_status.uid_values == std::array<uid_t, 4>{0, 0, 0, 0} &&
        parsed_status.gid_values == std::array<gid_t, 4>{0, 0, 0, 0} &&
        !parse_retained_anchor_status("Uid: 0 0 0\nGid: 0 0 0 0\n", missing_status) &&
        !parse_retained_anchor_status("Uid: 0 0 0 0 0\nGid: 0 0 0 0\n", extra_status) &&
        !parse_retained_anchor_status("Uid: 18446744073709551616 0 0 0\nGid: 0 0 0 0\n",
                                      out_of_range_status);
    if (!status_parser_ok) {
        error = "retained sudo credential tuple parser mutation self-check failed";
        return false;
    }
    int ready[2] = {-1, -1};
    if (pipe2(ready, O_CLOEXEC) != 0) {
        error = "retained-anchor ready pipe failed";
        return false;
    }
    const pid_t expected_parent = getpid();
    const pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        error = "retained-anchor child fork failed";
        return false;
    }
    if (child == 0) {
        close(ready[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent ||
            setpgid(0, 0) != 0)
            _exit(125);
        const unsigned char marker = 0xa7;
        if (!write_pipe_exact(ready[1], &marker, 1, kCleanupMs)) _exit(125);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    unsigned char marker = 0;
    bool ok = read_exact(ready[0], &marker, 1, kCleanupMs) && marker == 0xa7;
    close(ready[0]);

    ProcIdentity direct_identity;
    GroupLease lease;
    ok = ok && stable_proc_identity(child, direct_identity) && lease.establish(direct_identity);
    const ino_t holder_netns = direct_identity.netns + 1;
    const std::string launcher_argv("retained-launcher\0", 18);
    AllowedStages allowed{
        {direct_identity.exe_dev, direct_identity.exe_ino, direct_identity.cmdline},
        {direct_identity.exe_dev, direct_identity.exe_ino, "nsenter\0"},
        {direct_identity.exe_dev, direct_identity.exe_ino, launcher_argv},
        holder_netns};
    const DirectLaunchAnchor anchor{child,
                                    direct_identity.start,
                                    child,
                                    direct_identity.uid,
                                    direct_identity.gid,
                                    direct_identity.netns,
                                    direct_identity.sid,
                                    direct_identity.exe_dev,
                                    direct_identity.exe_ino,
                                    direct_identity.exe,
                                    direct_identity.cmdline};
    RetainedAnchorEvidence retained;
    std::string reason;
    ok = ok && privileged_ancestry::capture_retained_anchor_evidence(
                   DirectLaunch(anchor, allowed, true), retained_lease(lease), retained, reason);
    ProcIdentity launcher;
    launcher.pid = child + 100000;
    launcher.ppid = child;
    launcher.start = direct_identity.start + 1;
    launcher.pgid = child;
    launcher.sid = direct_identity.sid;
    launcher.uid = 0;
    launcher.gid = 0;
    launcher.netns = holder_netns;
    launcher.exe_dev = direct_identity.exe_dev;
    launcher.exe_ino = direct_identity.exe_ino;
    launcher.cmdline = launcher_argv;
    const auto accepted = [&](const RetainedAnchorEvidence& candidate_retained,
                              const ProcIdentity& candidate_launcher) {
        DirectLaunch candidate(anchor, allowed, true);
        std::string candidate_reason;
        return prove_retained_sudo_wrapper(
                   candidate, candidate_launcher, candidate_retained, candidate_reason) &&
               candidate.mode == rut::test::fixture_direct_launch::LaunchMode::SudoWrapper &&
               candidate.current_valid && candidate.current_stage == LaunchStage::Sudo &&
               candidate.launcher_valid;
    };
    ok = ok && accepted(retained, launcher);
    RetainedAnchorEvidence retained_sudo = retained;
    retained_sudo.uid_values = {anchor.caller_uid, 0, 0, 0};
    retained_sudo.gid_values = {0, 0, 0, 0};
    retained_sudo.uid = retained_sudo.uid_values[0];
    retained_sudo.gid = retained_sudo.gid_values[0];
    RetainedAnchorEvidence root_credentials = retained_sudo;
    root_credentials.uid_values.fill(0);
    root_credentials.uid = 0;
    const auto uid_sentinel = [&](uid_t caller) {
        if (caller == 0) return static_cast<uid_t>(1);
        if (caller == 1) return static_cast<uid_t>(2);
        if (caller == std::numeric_limits<uid_t>::max())
            return static_cast<uid_t>(caller - static_cast<uid_t>(1));
        return static_cast<uid_t>(caller + static_cast<uid_t>(1));
    };
    const auto rejects_uid_slot = [&](size_t slot) {
        RetainedAnchorEvidence changed = retained_sudo;
        const uid_t before = changed.uid_values[slot];
        if (slot == 0) {
            changed.uid_values[slot] = uid_sentinel(anchor.caller_uid);
        } else {
            changed.uid_values[slot] =
                anchor.caller_uid == 0 ? static_cast<uid_t>(1) : anchor.caller_uid;
        }
        changed.uid = changed.uid_values[0];
        return changed.uid_values[slot] != before && !accepted(changed, launcher);
    };
    const auto rejects_gid_slot = [&](size_t slot) {
        RetainedAnchorEvidence changed = retained_sudo;
        const gid_t before = changed.gid_values[slot];
        changed.gid_values[slot] =
            anchor.caller_gid == 0 ? static_cast<gid_t>(1) : anchor.caller_gid;
        changed.gid = changed.gid_values[0];
        return changed.gid_values[slot] != before && !accepted(changed, launcher);
    };
    ok = ok && accepted(retained_sudo, launcher) && accepted(root_credentials, launcher) &&
         rejects_uid_slot(0) && rejects_uid_slot(1) && rejects_uid_slot(2) && rejects_uid_slot(3) &&
         rejects_gid_slot(0) && rejects_gid_slot(1) && rejects_gid_slot(2) && rejects_gid_slot(3);
    const auto rejects_retained = [&](auto mutation) {
        RetainedAnchorEvidence changed = retained;
        mutation(changed);
        return !accepted(changed, launcher);
    };
    const auto rejects_launcher = [&](auto mutation) {
        ProcIdentity changed = launcher;
        mutation(changed);
        return !accepted(retained, changed);
    };
    ok = ok && rejects_retained([](auto& value) { ++value.start; }) &&
         rejects_retained([](auto& value) { ++value.pid; }) &&
         rejects_retained([](auto& value) { ++value.ppid; }) &&
         rejects_retained([](auto& value) { ++value.pgid; }) &&
         rejects_retained([](auto& value) { ++value.sid; }) &&
         rejects_retained([](auto& value) { value.pidfd_live = false; }) &&
         rejects_retained([](auto& value) { value.state = 'Z'; }) &&
         rejects_launcher([](auto& value) { value.ppid = 1; }) &&
         rejects_launcher([](auto& value) { ++value.pgid; }) &&
         rejects_launcher([](auto& value) { ++value.sid; }) &&
         rejects_launcher([](auto& value) { ++value.exe_ino; }) &&
         rejects_launcher([](auto& value) { value.cmdline.push_back('x'); });

    if (kill(child, SIGKILL) != 0 && errno != ESRCH) ok = false;
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    RetainedAnchorEvidence dead;
    DirectLaunch dead_launch(anchor, allowed, true);
    ok = ok && waited == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
         !privileged_ancestry::capture_retained_anchor_evidence(
             dead_launch, retained_lease(lease), dead, reason);
    if (!ok) {
        error = "retained sudo anchor/pidfd/launcher mutation self-check failed: " + reason;
        return false;
    }
    return true;
}

static bool write_pipe_exact(int fd, const unsigned char* data, size_t size, int timeout_ms) {
    struct sigaction ignore{};
    struct sigaction old_action{};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, &old_action) != 0) return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t offset = 0;
    bool complete = true;
    while (offset != size) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        if (remaining <= 0) {
            complete = false;
            break;
        }
        pollfd descriptor{fd, POLLOUT, 0};
        const int polled = poll(&descriptor, 1, static_cast<int>(remaining));
        if (polled < 0 && errno == EINTR) continue;
        if (polled <= 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            complete = false;
            break;
        }
        const ssize_t written = write(fd, data + offset, size - offset);
        if (written > 0)
            offset += static_cast<size_t>(written);
        else if (written < 0 && errno == EINTR)
            continue;
        else {
            complete = false;
            break;
        }
    }
    (void)sigaction(SIGPIPE, &old_action, nullptr);
    return complete;
}

static bool reap_failed_direct(pid_t child, std::optional<DirectLaunch>& launch) {
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        const DirectWaitDisposition disposition =
            classify_direct_wait(waited, child, waited < 0 ? errno : 0);
        if (disposition == DirectWaitDisposition::Reaped) {
            if (launch) launch->reaped = true;
            return true;
        }
        if (disposition == DirectWaitDisposition::Error) {
            if (launch)
                launch->reason =
                    "waitpid(direct launch cleanup) failed: " + std::string(strerror(errno));
            return false;
        }
        (void)poll(nullptr, 0, 10);
    }
    if (launch && launch->current_valid && safe_signal_direct_child(*launch, SIGKILL) &&
        wait_direct(*launch, kCleanupMs))
        return true;
    if (launch) {
        if (launch->reason.empty())
            launch->reason = "direct launch cleanup timed out without an exact signalable stage";
    }
    return false;
}

static bool is_pre_exec_anchor(const DirectLaunch& launch, const ProcIdentity& identity) {
    return identity.pid == launch.anchor.pid && identity.start == launch.anchor.start &&
           identity.pgid == launch.anchor.pgid && identity.sid == launch.anchor.sid &&
           identity.uid == launch.anchor.caller_uid && identity.gid == launch.anchor.caller_gid &&
           identity.netns == launch.anchor.host_netns &&
           identity.exe_dev == launch.anchor.exe_dev && identity.exe_ino == launch.anchor.exe_ino &&
           identity.exe == launch.anchor.exe && identity.cmdline == launch.anchor.cmdline;
}

static bool wait_group_gone(const GroupLease& lease, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (lease.gone()) return true;
        (void)poll(nullptr, 0, 5);
    }
    return lease.gone();
}

static bool child_exited_wnowait(pid_t pid) {
    siginfo_t info{};
    if (pid <= 1 || waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT) != 0)
        return false;
    return info.si_pid == pid &&
           (info.si_code == CLD_EXITED || info.si_code == CLD_KILLED || info.si_code == CLD_DUMPED);
}

static GroupScanResult scan_group_stat(pid_t pgid,
                                       int& count,
                                       bool& live,
                                       pid_t permitted_zombie,
                                       pid_t& sole_member,
                                       std::uint64_t& sole_start) {
    const int directory = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return GroupScanResult::Unreadable;
    DIR* entries = fdopendir(directory);
    if (entries == nullptr) {
        close(directory);
        return GroupScanResult::Unreadable;
    }
    count = 0;
    live = false;
    sole_member = -1;
    sole_start = 0;
    GroupScanResult result = GroupScanResult::Exact;
    while (dirent* entry = readdir(entries)) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
        char* end = nullptr;
        const long parsed = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || parsed <= 1) continue;
        const pid_t pid = static_cast<pid_t>(parsed);
        std::string stat_text;
        const std::string path = "/proc/" + std::to_string(pid) + "/stat";
        if (!read_file(path, stat_text, 8192)) {
            errno = 0;
            if (kill(pid, 0) == 0 || errno == EPERM) result = GroupScanResult::Unreadable;
            continue;
        }
        const size_t comm_end = stat_text.rfind(") ");
        if (comm_end == std::string::npos) {
            result = GroupScanResult::Unreadable;
            break;
        }
        std::istringstream fields(stat_text.substr(comm_end + 2));
        char state = 0;
        long ppid = 0;
        long process_group = 0;
        if (!(fields >> state >> ppid >> process_group)) {
            result = GroupScanResult::Unreadable;
            break;
        }
        std::uint64_t start = 0;
        for (int field = 6; field <= 22; ++field) {
            if (field == 22) {
                unsigned long long value = 0;
                if (!(fields >> value)) {
                    result = GroupScanResult::Unreadable;
                    break;
                }
                start = static_cast<std::uint64_t>(value);
            } else {
                long long value = 0;
                if (!(fields >> value)) {
                    result = GroupScanResult::Unreadable;
                    break;
                }
            }
        }
        if (result == GroupScanResult::Unreadable) break;
        if (process_group == pgid) {
            ++count;
            sole_member = pid;
            sole_start = start;
        }
        if (process_group == pgid && pid != permitted_zombie && state != 'Z' && state != 'X')
            live = true;
    }
    closedir(entries);
    return result;
}

static GroupScanResult group_member_count(pid_t pgid, int& count) {
    bool live = false;
    pid_t sole_member = -1;
    std::uint64_t sole_start = 0;
    return scan_group_stat(pgid, count, live, -1, sole_member, sole_start);
}

static bool cleanup_group_lease(GroupLease& lease,
                                DirectLaunch& launch,
                                bool authority,
                                std::string& error) {
    if (lease.gone()) return true;
    if (!authority) {
        error = "direct launch group cleanup lacked caller authority";
        return false;
    }
    const auto signal_group = [&](int signal_number) {
        // An unprivileged parent may only signal its exact direct child.  A
        // privileged parent may signal the revalidated launch group.
        if (geteuid() == 0 && launch.current_valid)
            return safe_signal_direct_child(launch, signal_number);
        return lease.signal_single(signal_number);
    };
    if (!signal_group(SIGTERM)) {
        error = "direct launch group TERM failed identity/authority revalidation";
        return false;
    }
    if (wait_group_gone(lease, kCleanupMs)) return true;
    if (!signal_group(SIGKILL)) {
        error = "direct launch group KILL failed identity/authority revalidation";
        return false;
    }
    if (!wait_group_gone(lease, kCleanupMs)) {
        error = "direct launch group did not reach ESRCH after bounded KILL";
        return false;
    }
    return true;
}

static bool launcher_gone_or_wnowait(const DirectLaunch& launch) {
    if (!launch.launcher_valid || launch.launcher_identity.pid <= 1) return false;
    if (launch.launcher_identity.pid == launch.anchor.pid)
        return child_exited_wnowait(launch.anchor.pid);
    ProcIdentity current;
    if (read_proc(launch.launcher_identity.pid, current, false))
        return current.start != launch.launcher_identity.start;
    errno = 0;
    return kill(launch.launcher_identity.pid, 0) < 0 && errno == ESRCH;
}

static bool has_group_authority(const DirectLaunch& launch, const GroupLease& lease) {
    if (geteuid() == 0) return true;
    if (!launch.marker_valid || lease.pidfd < 0 || lease.pid != launch.anchor.pid ||
        lease.start != launch.anchor.start || lease.pgid != launch.anchor.pgid ||
        lease.sid != launch.anchor.sid)
        return false;
    ProcIdentity current;
    return read_proc(lease.pid, current, false) && current.pid == launch.anchor.pid &&
           current.start == launch.anchor.start && current.pgid == launch.anchor.pgid &&
           current.sid == launch.anchor.sid && current.uid == getuid() && current.gid == getgid() &&
           current.uid == launch.anchor.caller_uid && current.gid == launch.anchor.caller_gid &&
           current.exe_dev == launch.anchor.exe_dev && current.exe_ino == launch.anchor.exe_ino &&
           current.exe == launch.anchor.exe && current.cmdline == launch.anchor.cmdline;
}

static bool group_lease_self_check(std::string& error) {
    int ready[2] = {-1, -1};
    if (pipe2(ready, O_CLOEXEC) != 0) {
        error = "GroupLease WNOWAIT harness pipe failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        error = "GroupLease WNOWAIT harness fork failed";
        return false;
    }
    if (child == 0) {
        close(ready[0]);
        const unsigned char marker = 0x57;
        if (setpgid(0, 0) != 0 || write(ready[1], &marker, 1) != 1) _exit(71);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    unsigned char marker = 0;
    ProcIdentity identity;
    const bool ready_exact = read_exact(ready[0], &marker, 1, kHandshakeMs) && marker == 0x57 &&
                             stable_proc_identity(child, identity);
    close(ready[0]);
    GroupLease lease;
    const bool lease_exact = ready_exact && lease.establish(identity) && lease.revalidate();
    const auto saved_start = lease.start;
    lease.start++;
    const bool stale_pidfd_rejected = !lease.revalidate();
    lease.start = saved_start;
    const pid_t saved_pgid = lease.pgid;
    lease.pgid = 1;
    const bool unsafe_pgid_rejected = !lease.revalidate();
    lease.pgid = saved_pgid;
    siginfo_t live{};
    const bool live_wnowait =
        lease_exact &&
        waitid(P_PID, static_cast<id_t>(child), &live, WEXITED | WNOHANG | WNOWAIT) == 0 &&
        live.si_pid == 0;
    const bool signaled = lease_exact && lease.signal_single(SIGKILL);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    bool exited_wnowait = false;
    while (std::chrono::steady_clock::now() < deadline && !exited_wnowait) {
        exited_wnowait = child_exited_wnowait(child);
        if (!exited_wnowait) (void)poll(nullptr, 0, 5);
    }
    int status = 0;
    bool reaped = false;
    const auto reap_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < reap_deadline) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) break;
        (void)poll(nullptr, 0, 5);
    }
    const bool group_disappeared = reaped && wait_group_gone(lease, kCleanupMs);
    if (!ready_exact || !lease_exact || !stale_pidfd_rejected || !unsafe_pgid_rejected ||
        !live_wnowait || !signaled || !exited_wnowait || !group_disappeared || !reaped ||
        !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
        error = "GroupLease WNOWAIT/PGID disappearance harness failed";
        if (!reaped && lease_exact && lease.signal_single(SIGKILL)) {
            // The exact-PID fallback above is the only signal available to an
            // ordinary parent; never turn a failed self-check into a PGID kill.
        }
        if (!reaped) {
            const auto reap_deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
            while (std::chrono::steady_clock::now() < reap_deadline) {
                const pid_t waited = waitpid(child, &status, WNOHANG);
                if (waited == child || (waited < 0 && errno == ECHILD)) break;
                if (waited < 0 && errno != EINTR) break;
                (void)poll(nullptr, 0, 5);
            }
        }
        return false;
    }
    return true;
}

static bool begin_launch(const std::string& sudo_path,
                         const std::string& nsenter_path,
                         const std::string& executable,
                         const HeldTopologySnapshot& topology,
                         const ParentEndpoint& endpoint,
                         const Token& token,
                         const char* scenario,
                         int post_release_timeout_ms,
                         std::optional<DirectLaunch>& launch,
                         std::optional<GroupLease>& lease,
                         std::chrono::steady_clock::time_point& hello_deadline,
                         std::string& error) {
    const std::string netns = "/proc/" + std::to_string(topology.holder_pid) + "/ns/net";
    const std::string netns_arg = "--net=" + netns;
    const std::string expected_netns = std::to_string(topology.holder_netns);
    const std::string token_value = token_text(token);
    struct stat sudo_status{}, nsenter_status{}, launcher_status{};
    ProcIdentity parent;
    if (stat(sudo_path.c_str(), &sudo_status) != 0 ||
        stat(nsenter_path.c_str(), &nsenter_status) != 0 ||
        stat(executable.c_str(), &launcher_status) != 0 || !read_proc(getpid(), parent, false) ||
        parent.uid == 0 || parent.netns == topology.holder_netns) {
        error = "launch descriptor or caller identity setup failed";
        return false;
    }
    LaunchArgv launch_argv = make_launch_argv(sudo_path,
                                              nsenter_path,
                                              netns_arg,
                                              executable,
                                              endpoint.socket,
                                              token_value,
                                              expected_netns,
                                              scenario);
    const std::string launcher_argv = exact_argv(launch_argv.launcher);
    const std::string nsenter_argv = exact_argv(launch_argv.nsenter);
    const std::string sudo_argv = exact_argv(launch_argv.sudo_command);
    const AllowedStages allowed{{sudo_status.st_dev, sudo_status.st_ino, sudo_argv},
                                {nsenter_status.st_dev, nsenter_status.st_ino, nsenter_argv},
                                {launcher_status.st_dev, launcher_status.st_ino, launcher_argv},
                                topology.holder_netns};
    int marker_pipe[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    if (pipe2(marker_pipe, O_CLOEXEC) != 0 || pipe2(release_pipe, O_CLOEXEC) != 0) {
        if (marker_pipe[0] >= 0) close(marker_pipe[0]);
        if (marker_pipe[1] >= 0) close(marker_pipe[1]);
        error = "CLOEXEC launch marker pipe setup failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(marker_pipe[0]);
        close(marker_pipe[1]);
        close(release_pipe[0]);
        close(release_pipe[1]);
        error = "sudo launch fork failed";
        return false;
    }
    if (child == 0) {
        close(marker_pipe[0]);
        close(release_pipe[1]);
        size_t offset = 0;
        const pid_t expected_parent = getppid();
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent ||
            setpgid(0, 0) != 0)
            _exit(125);
        while (offset != kLaunchMarker.size()) {
            const ssize_t count =
                write(marker_pipe[1], kLaunchMarker.data() + offset, kLaunchMarker.size() - offset);
            if (count > 0)
                offset += static_cast<size_t>(count);
            else if (count < 0 && errno == EINTR)
                continue;
            else
                _exit(125);
        }
        close(marker_pipe[1]);
        unsigned char release = 0;
        ssize_t count;
        do {
            count = read(release_pipe[0], &release, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1 || release != 0x4c) _exit(125);
        std::vector<char*> argv;
        for (std::string& value : launch_argv.sudo_command) argv.push_back(value.data());
        argv.push_back(nullptr);
        execv(sudo_path.c_str(), argv.data());
        _exit(127);
    }
    close(marker_pipe[1]);
    close(release_pipe[0]);
    std::array<unsigned char, kLaunchMarker.size()> marker{};
    ProcIdentity anchor_identity;
    const bool marker_exact =
        read_exact(marker_pipe[0], marker.data(), marker.size(), kHandshakeMs) &&
        launch_marker_matches(marker.data(), marker.size());
    const bool anchor_exact =
        marker_exact && stable_proc_identity(child, anchor_identity) &&
        anchor_identity.pid == child && anchor_identity.ppid == getpid() &&
        anchor_identity.start != 0 && anchor_identity.pgid == child &&
        anchor_identity.uid == parent.uid && anchor_identity.gid == parent.gid &&
        anchor_identity.netns == parent.netns && anchor_identity.exe_dev == parent.exe_dev &&
        anchor_identity.exe_ino == parent.exe_ino && anchor_identity.cmdline == parent.cmdline;
    if (anchor_exact)
        launch.emplace(DirectLaunchAnchor{child,
                                          anchor_identity.start,
                                          child,
                                          parent.uid,
                                          parent.gid,
                                          parent.netns,
                                          anchor_identity.sid,
                                          anchor_identity.exe_dev,
                                          anchor_identity.exe_ino,
                                          anchor_identity.exe,
                                          anchor_identity.cmdline},
                       allowed,
                       true);
    if (launch && anchor_exact) {
        lease.emplace();
        if (!lease->establish(anchor_identity)) {
            lease.reset();
            launch->reason = "direct launch group lease could not be established";
        }
    }
    const unsigned char release = 0x4c;
    hello_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(post_release_timeout_ms);
    const bool released = anchor_exact && lease && lease->revalidate() &&
                          write_pipe_exact(release_pipe[1], &release, 1, kHandshakeMs);
    close(release_pipe[1]);
    close(marker_pipe[0]);
    if (!anchor_exact || !released) {
        error = !marker_exact   ? "missing or invalid child launch marker"
                : !anchor_exact ? "fork/marker immutable /proc anchor was not exact"
                                : "release pipe write failed before the exact launch gate";
        bool cleaned = false;
        if (launch && lease) {
            std::string lease_error;
            cleaned = cleanup_group_lease(
                *lease, *launch, has_group_authority(*launch, *lease), lease_error);
            if (cleaned && !launch->reaped && lease->gone())
                cleaned = wait_direct(*launch, kCleanupMs);
            if (!cleaned && !lease_error.empty()) error += "; " + lease_error;
        } else {
            cleaned = reap_failed_direct(child, launch);
        }
        if (!cleaned && launch)
            error += "; direct launch cleanup failed: " + direct_launch_diagnostic(*launch);
        return false;
    }
    return true;
}

static bool decode_ready(
    int fd, u16 expected_type, const Token& token, Peer& peer, Report& report) {
    Frame frame;
    return get_peer(fd, peer) && receive_frame(fd, frame, kHandshakeMs) &&
           frame.type == expected_type && token_equal(frame.token, token) &&
           decode_report(frame.payload, report);
}

static int remaining_deadline_ms(std::chrono::steady_clock::time_point deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                               deadline - std::chrono::steady_clock::now())
                               .count();
    if (remaining <= 0) return 0;
    return static_cast<int>(std::min<std::int64_t>(remaining, std::numeric_limits<int>::max()));
}

static bool await_root_hello(const ParentEndpoint& endpoint,
                             DirectLaunch& launch,
                             const Token& token,
                             std::chrono::steady_clock::time_point deadline,
                             int& root_fd,
                             Peer& peer,
                             Report& report,
                             Token& frame_token,
                             identity_bundle::ReceivedBundle& received_bundle,
                             ancestry_bundle::AncestryBundle& initial_ancestry,
                             std::string& error) {
    root_fd = -1;
    received_bundle.reset();
    initial_ancestry.close();
    std::string last_observation = "no direct /proc observation";
    for (;;) {
        const int remaining = remaining_deadline_ms(deadline);
        if (remaining == 0) break;
        ProcIdentity identity;
        if (stable_proc_identity(launch.anchor.pid, identity)) {
            std::string reason;
            if (!observe_direct(launch, identity, reason)) {
                if (is_pre_exec_anchor(launch, identity)) {
                    last_observation = "blocked pre-exec anchor";
                } else if (reason == "executable/argv is not an exact allowed launch stage") {
                    error = "stable direct launch identity was not an allowed stage";
                    launch.reason = error;
                    return false;
                } else {
                    last_observation = reason;
                }
            } else {
                last_observation =
                    std::string("exact stage ") +
                    rut::test::fixture_direct_launch::launch_stage_name(launch.current_stage);
            }
        } else {
            last_observation = "transient /proc identity was unavailable";
        }

        pollfd descriptor{endpoint.listener, POLLIN, 0};
        const int polled = poll(&descriptor, 1, std::min(remaining, 10));
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) {
            error = "root HELLO listener poll failed";
            return false;
        }
        if (polled == 0 || (descriptor.revents & POLLIN) == 0) continue;
        root_fd = accept4(endpoint.listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (root_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            error = "root HELLO accept failed";
            return false;
        }
        if (!get_peer(root_fd, peer)) {
            error = "root HELLO SO_PEERCRED failed";
            return false;
        }
        Frame frame;
        if (!receive_frame_until(root_fd, frame, deadline) || frame.type != kBrokerRootHello ||
            !token_equal(frame.token, token) || !decode_report(frame.payload, report)) {
            error = "root HELLO frame was invalid before the absolute deadline";
            return false;
        }
        frame_token = frame.token;
        if (!send_frame(root_fd,
                        Frame{kIdentityBundleRequest, token, {}},
                        remaining_deadline_ms(deadline)) ||
            !identity_bundle::receive_bundle(root_fd, received_bundle, deadline, error) ||
            !send_frame(root_fd,
                        Frame{kInitialAncestryRequest, token, {}},
                        remaining_deadline_ms(deadline)) ||
            !ancestry_bundle::receive_bundle(root_fd, initial_ancestry, deadline, error)) {
            if (error.empty()) error = "root IDB1/initial ANC1 request/receive failed";
            return false;
        }
        return true;
    }
    error = "root HELLO missed the absolute post-release deadline (last observation: " +
            last_observation + ")";
    launch.reason = error;
    return false;
}

static bool validate_root_broker(const Report& report,
                                 const Peer& peer,
                                 const ProcIdentity& proc,
                                 const ProcIdentity& launcher,
                                 const HeldTopologySnapshot& topology,
                                 const std::string& executable,
                                 const std::string& expected_argv,
                                 const std::string& expected_launcher_argv,
                                 const RetainedAnchorEvidence* retained_anchor,
                                 DirectLaunch& sudo_launch) {
    if (peer.pid <= 1 || peer.uid != 0 || peer.gid != 0 ||
        report.target_pid != static_cast<u64>(peer.pid) ||
        report.target_pid != static_cast<u64>(proc.pid) || report.wrapper_pid <= 1 ||
        report.target_pid == report.wrapper_pid || report.start != proc.start ||
        report.pgid != static_cast<u64>(proc.pgid) || proc.pgid != sudo_launch.anchor.pgid ||
        proc.sid != sudo_launch.anchor.sid || report.netns != topology.holder_netns ||
        proc.netns != topology.holder_netns || report.uid != 0 || report.gid != 0 ||
        proc.uid != 0 || proc.gid != 0 || report.exe != executable || proc.exe != executable ||
        report.exe_dev != proc.exe_dev || report.exe_ino != proc.exe_ino ||
        proc.exe_dev != sudo_launch.allowed.launcher_stage.exe_dev ||
        proc.exe_ino != sudo_launch.allowed.launcher_stage.exe_ino ||
        report.argv != expected_argv || proc.cmdline != expected_argv ||
        report.mode != "broker-root" || proc.ppid != static_cast<pid_t>(report.wrapper_pid) ||
        launcher.pid != proc.ppid || launcher.start == 0 ||
        launcher.pgid != sudo_launch.anchor.pgid || launcher.sid != sudo_launch.anchor.sid ||
        launcher.uid != 0 || launcher.gid != 0 || launcher.netns != topology.holder_netns ||
        launcher.exe != executable ||
        launcher.exe_dev != sudo_launch.allowed.launcher_stage.exe_dev ||
        launcher.exe_ino != sudo_launch.allowed.launcher_stage.exe_ino ||
        launcher.cmdline != expected_launcher_argv ||
        report.no_new_privs != static_cast<u64>(proc.no_new_privs) ||
        report.capabilities_clear != static_cast<u64>(proc.capabilities_clear) ||
        report.groups_clear > 1 || report.groups_unchanged > 1 ||
        report.groups_clear + report.groups_unchanged != 1 ||
        (report.groups_clear == 1 && proc.supplementary_groups != 0)) {
        sudo_launch.reason = "root broker report/peer/current /proc fields were not exact";
        return false;
    }
    std::vector<ProcIdentity> ancestry;
    std::string reason;
    if (launcher.pid != sudo_launch.anchor.pid) {
        if (retained_anchor == nullptr ||
            !prove_retained_sudo_wrapper(sudo_launch, launcher, *retained_anchor, reason)) {
            sudo_launch.reason =
                reason.empty() ? "live sudo-wrapper direct lineage was not exact" : reason;
            return false;
        }
        return true;
    }
    if (retained_anchor != nullptr || launcher.start != sudo_launch.anchor.start ||
        !validate_launcher_ancestry(sudo_launch, launcher, ancestry, reason)) {
        sudo_launch.reason =
            reason.empty() ? "root broker launcher provenance was not exact" : reason;
        return false;
    }
    return true;
}

static ProcIdentity proc_from_bundle_role(const identity_bundle::RoleManifest& manifest,
                                          const std::string& executable,
                                          const std::string& argv) {
    ProcIdentity proc;
    proc.pid = manifest.pid;
    proc.ppid = manifest.ppid;
    proc.sid = manifest.sid;
    proc.start = manifest.start;
    proc.pgid = manifest.pgid;
    proc.uid = manifest.uid;
    proc.gid = manifest.gid;
    proc.netns = static_cast<ino_t>(manifest.netns);
    proc.exe_dev = static_cast<dev_t>(manifest.exe_dev);
    proc.exe_ino = static_cast<ino_t>(manifest.exe_ino);
    proc.exe = executable;
    proc.cmdline = argv;
    return proc;
}

struct BundleStatusEvidence {
    bool no_new_privs = false;
    bool capabilities_clear = false;
    std::vector<gid_t> supplementary_groups;
};

static bool read_bundle_status_evidence(const identity_bundle::RoleBundle& role,
                                        BundleStatusEvidence& evidence) {
    const int fd = role.fds[static_cast<size_t>(identity_bundle::FdSlot::Status)];
    if (fd < 0 || lseek(fd, 0, SEEK_SET) < 0) return false;
    std::string status;
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            if (status.size() > 16384 - static_cast<size_t>(count)) return false;
            status.append(buffer.data(), static_cast<size_t>(count));
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        return false;
    }
    bool have_nnp = false;
    bool have_groups = false;
    bool seen_inh = false;
    bool seen_prm = false;
    bool seen_eff = false;
    bool clear_inh = false;
    bool clear_prm = false;
    bool clear_eff = false;
    std::istringstream lines(status);
    std::string line;
    while (std::getline(lines, line)) {
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::istringstream value(line.substr(colon + 1));
        if (line.rfind("NoNewPrivs:", 0) == 0) {
            int parsed = -1;
            if (!(value >> parsed) || (parsed != 0 && parsed != 1)) return false;
            evidence.no_new_privs = parsed == 1;
            have_nnp = true;
        } else if (line.rfind("Groups:", 0) == 0) {
            std::string group;
            evidence.supplementary_groups.clear();
            while (value >> group) {
                char* end = nullptr;
                errno = 0;
                const unsigned long long parsed = strtoull(group.c_str(), &end, 10);
                if (errno != 0 || end == group.c_str() || *end != '\0' ||
                    parsed > std::numeric_limits<gid_t>::max())
                    return false;
                evidence.supplementary_groups.push_back(static_cast<gid_t>(parsed));
            }
            have_groups = true;
        } else if (line.rfind("CapInh:", 0) == 0 || line.rfind("CapPrm:", 0) == 0 ||
                   line.rfind("CapEff:", 0) == 0) {
            std::string hex;
            if (!(value >> hex) || hex.empty()) return false;
            const bool clear = hex.find_first_not_of('0') == std::string::npos;
            if (line.rfind("CapInh:", 0) == 0) {
                seen_inh = true;
                clear_inh = clear;
            }
            if (line.rfind("CapPrm:", 0) == 0) {
                seen_prm = true;
                clear_prm = clear;
            }
            if (line.rfind("CapEff:", 0) == 0) {
                seen_eff = true;
                clear_eff = clear;
            }
        }
    }
    evidence.capabilities_clear = clear_inh && clear_prm && clear_eff;
    return have_nnp && have_groups && seen_inh && seen_prm && seen_eff;
}

static bool groups_evidence_matches(const Report& report,
                                    const BundleStatusEvidence& launcher,
                                    const BundleStatusEvidence& root) {
    if (report.groups_clear > 1 || report.groups_unchanged > 1 ||
        report.groups_clear + report.groups_unchanged != 1)
        return false;
    if (report.groups_clear == 1) return root.supplementary_groups.empty();
    return root.supplementary_groups == launcher.supplementary_groups;
}

static MutationDiagnostic first_failed_mutation(
    const std::vector<std::pair<const char*, bool>>& checks) {
    for (const auto& check : checks)
        if (!check.second) return {false, check.first, "mutation accepted unexpectedly"};
    return {};
}

static std::string group_mutation_detail(const Report& report,
                                         const BundleStatusEvidence& launcher,
                                         const BundleStatusEvidence& root) {
    std::ostringstream detail;
    detail << "groups{clear=" << report.groups_clear << ",unchanged=" << report.groups_unchanged
           << ",launcher_count=" << launcher.supplementary_groups.size()
           << ",root_count=" << root.supplementary_groups.size() << '}';
    return detail.str();
}

static ProcIdentity proc_from_dropped_evidence(
    const identity_bundle::DroppedIdentityEvidence& evidence, const std::string& executable) {
    ProcIdentity proc;
    const identity_bundle::RoleManifest& identity = evidence.identity;
    proc.pid = identity.pid;
    proc.ppid = identity.ppid;
    proc.sid = identity.sid;
    proc.start = identity.start;
    proc.pgid = identity.pgid;
    proc.uid = identity.uid;
    proc.gid = identity.gid;
    proc.netns = static_cast<ino_t>(identity.netns);
    proc.exe_dev = static_cast<dev_t>(identity.exe_dev);
    proc.exe_ino = static_cast<ino_t>(identity.exe_ino);
    proc.exe = executable;
    proc.cmdline = evidence.cmdline;
    proc.no_new_privs = evidence.status.no_new_privs;
    proc.capabilities_clear = evidence.status.cap_inh_clear && evidence.status.cap_prm_clear &&
                              evidence.status.cap_eff_clear;
    proc.supplementary_groups = evidence.status.supplementary_groups.size();
    return proc;
}

static bool validate_dropped_identity_binding(
    const identity_bundle::DroppedIdentityEvidence& evidence,
    const Report& report,
    const Peer& peer,
    const Peer& root_peer,
    const ProcIdentity& root_proc,
    const HeldTopologySnapshot& topology,
    const std::string& executable,
    const std::string& dropped_argv,
    uid_t caller_uid,
    gid_t caller_gid,
    bool root_control_ok,
    bool endpoint_ok,
    std::string& error) {
    const identity_bundle::RoleManifest& identity = evidence.identity;
    const bool uid_slots = std::all_of(evidence.status.uid_values.begin(),
                                       evidence.status.uid_values.end(),
                                       [caller_uid](uid_t value) { return value == caller_uid; });
    const bool gid_slots = std::all_of(evidence.status.gid_values.begin(),
                                       evidence.status.gid_values.end(),
                                       [caller_gid](gid_t value) { return value == caller_gid; });
    const bool caps_clear = evidence.status.cap_inh_clear && evidence.status.cap_prm_clear &&
                            evidence.status.cap_eff_clear;
    const bool live_state = evidence.state == 'R' || evidence.state == 'S' ||
                            evidence.state == 'D' || evidence.state == 'T' ||
                            evidence.state == 't' || evidence.state == 'W' ||
                            evidence.state == 'K' || evidence.state == 'P' || evidence.state == 'I';
    struct stat expected_executable{};
    const bool expected_executable_ok =
        stat(executable.c_str(), &expected_executable) == 0 && S_ISREG(expected_executable.st_mode);
    const bool exact =
        peer.pid > 1 && peer.pid == identity.pid &&
        report.target_pid == static_cast<u64>(peer.pid) && peer.uid == caller_uid &&
        peer.gid == caller_gid && root_peer.pid > 1 && root_peer.uid == 0 && root_peer.gid == 0 &&
        identity.ppid == root_peer.pid && root_peer.pid == root_proc.pid && root_proc.start != 0 &&
        root_proc.sid > 1 && root_proc.exe == executable && identity.pgid == identity.pid &&
        identity.sid == root_proc.sid && identity.uid == caller_uid && identity.gid == caller_gid &&
        identity.netns == topology.holder_netns && expected_executable_ok &&
        root_proc.exe_dev == static_cast<dev_t>(expected_executable.st_dev) &&
        root_proc.exe_ino == static_cast<ino_t>(expected_executable.st_ino) &&
        identity.exe_dev == static_cast<u64>(root_proc.exe_dev) &&
        identity.exe_ino == static_cast<u64>(root_proc.exe_ino) &&
        identity.exe_dev == static_cast<u64>(expected_executable.st_dev) &&
        identity.exe_ino == static_cast<u64>(expected_executable.st_ino) &&
        identity.argv_length == dropped_argv.size() &&
        identity.argv_hash == probe_hash(dropped_argv) && evidence.cmdline == dropped_argv &&
        live_state && uid_slots && gid_slots && evidence.status.supplementary_groups.empty() &&
        evidence.status.no_new_privs && caps_clear && evidence.pidfd_live &&
        report.target_pid == static_cast<u64>(identity.pid) &&
        report.wrapper_pid == static_cast<u64>(root_peer.pid) && report.start == identity.start &&
        report.pgid == static_cast<u64>(identity.pgid) && report.uid == caller_uid &&
        report.gid == caller_gid && report.netns == topology.holder_netns &&
        report.exe_dev == identity.exe_dev && report.exe_ino == identity.exe_ino &&
        report.exe == executable && report.argv == dropped_argv &&
        report.mode == "broker-dropped" && report.no_new_privs == 1 &&
        report.capabilities_clear == 1 && report.groups_clear == 1 &&
        report.groups_unchanged == 0 && root_control_ok && endpoint_ok;
    if (!exact) error = "dropped kernel evidence/report binding was not exact";
    return exact;
}

static MutationDiagnostic dropped_identity_mutation_checks(
    const identity_bundle::DroppedIdentityEvidence& evidence,
    const Report& report,
    const Peer& peer,
    const Peer& root_peer,
    const ProcIdentity& root_proc,
    const HeldTopologySnapshot& topology,
    const std::string& executable,
    const std::string& dropped_argv,
    uid_t caller_uid,
    gid_t caller_gid) {
    const auto accepted = [&](const identity_bundle::DroppedIdentityEvidence& candidate_evidence,
                              const Report& candidate_report,
                              const Peer& candidate_peer,
                              const Peer& candidate_root_peer,
                              bool root_control_ok = true,
                              bool endpoint_ok = true) {
        std::string ignored;
        return validate_dropped_identity_binding(candidate_evidence,
                                                 candidate_report,
                                                 candidate_peer,
                                                 candidate_root_peer,
                                                 root_proc,
                                                 topology,
                                                 executable,
                                                 dropped_argv,
                                                 caller_uid,
                                                 caller_gid,
                                                 root_control_ok,
                                                 endpoint_ok,
                                                 ignored);
    };
    const auto check = [](const char* label, bool rejected) -> MutationDiagnostic {
        return rejected ? MutationDiagnostic{}
                        : MutationDiagnostic{false, label, "mutation accepted unexpectedly"};
    };
    const auto distinct_uid = [caller_uid]() {
        return caller_uid == std::numeric_limits<uid_t>::max() ? static_cast<uid_t>(caller_uid - 1)
                                                               : static_cast<uid_t>(caller_uid + 1);
    };
    const auto distinct_gid = [caller_gid]() {
        return caller_gid == std::numeric_limits<gid_t>::max() ? static_cast<gid_t>(caller_gid - 1)
                                                               : static_cast<gid_t>(caller_gid + 1);
    };
    std::string baseline_error;
    if (!validate_dropped_identity_binding(evidence,
                                           report,
                                           peer,
                                           root_peer,
                                           root_proc,
                                           topology,
                                           executable,
                                           dropped_argv,
                                           caller_uid,
                                           caller_gid,
                                           true,
                                           true,
                                           baseline_error))
        return {false, "baseline.extracted", baseline_error};
    auto candidate = evidence;
    Peer changed_peer = peer;
    changed_peer.pid = peer.pid == std::numeric_limits<pid_t>::max() ? peer.pid - 1 : peer.pid + 1;
    MutationDiagnostic result =
        check("peer.pid", !accepted(candidate, report, changed_peer, root_peer));
    if (!result.success) return result;
    changed_peer = peer;
    changed_peer.uid = distinct_uid();
    result = check("peer.uid", !accepted(candidate, report, changed_peer, root_peer));
    if (!result.success) return result;
    changed_peer = peer;
    changed_peer.gid = distinct_gid();
    result = check("peer.gid", !accepted(candidate, report, changed_peer, root_peer));
    if (!result.success) return result;

    const auto report_mutation = [&](const char* label, auto mutate) {
        Report changed = report;
        mutate(changed);
        return check(label, !accepted(candidate, changed, peer, root_peer));
    };
    result = report_mutation("report.target_pid", [](Report& value) { ++value.target_pid; });
    if (!result.success) return result;
    result = report_mutation("report.wrapper_pid", [](Report& value) { ++value.wrapper_pid; });
    if (!result.success) return result;
    result = report_mutation("report.start", [](Report& value) { ++value.start; });
    if (!result.success) return result;
    result = report_mutation("report.pgid", [](Report& value) { ++value.pgid; });
    if (!result.success) return result;
    result = report_mutation("report.uid", [&](Report& value) { value.uid = distinct_uid(); });
    if (!result.success) return result;
    result = report_mutation("report.gid", [&](Report& value) { value.gid = distinct_gid(); });
    if (!result.success) return result;
    result = report_mutation("report.netns", [](Report& value) { ++value.netns; });
    if (!result.success) return result;
    result = report_mutation("report.exe", [](Report& value) { value.exe.push_back('x'); });
    if (!result.success) return result;
    result = report_mutation("report.exe_dev", [](Report& value) { ++value.exe_dev; });
    if (!result.success) return result;
    result = report_mutation("report.exe_ino", [](Report& value) { ++value.exe_ino; });
    if (!result.success) return result;
    result = report_mutation("report.argv", [](Report& value) { value.argv.push_back('\0'); });
    if (!result.success) return result;
    result = report_mutation("report.no_new_privs", [](Report& value) { value.no_new_privs = 0; });
    if (!result.success) return result;
    result = report_mutation("report.capabilities_clear",
                             [](Report& value) { value.capabilities_clear = 0; });
    if (!result.success) return result;
    result = report_mutation("report.groups_clear", [](Report& value) { value.groups_clear = 0; });
    if (!result.success) return result;
    result = report_mutation("report.groups_unchanged",
                             [](Report& value) { value.groups_unchanged = 1; });
    if (!result.success) return result;
    result = report_mutation("report.mode", [](Report& value) { value.mode = "other"; });
    if (!result.success) return result;

    const auto identity_mutation = [&](const char* label, auto mutate) {
        auto changed = evidence;
        mutate(changed.identity);
        return check(label, !accepted(changed, report, peer, root_peer));
    };
    result = identity_mutation("identity.pid", [&](auto& value) { value.pid = peer.pid + 1; });
    if (!result.success) return result;
    result = identity_mutation("identity.start", [](auto& value) { value.start = 0; });
    if (!result.success) return result;
    result = identity_mutation("identity.ppid", [](auto& value) { ++value.ppid; });
    if (!result.success) return result;
    result = identity_mutation("identity.pgid", [](auto& value) { ++value.pgid; });
    if (!result.success) return result;
    result = identity_mutation("identity.sid", [](auto& value) { ++value.sid; });
    if (!result.success) return result;
    result = identity_mutation("identity.uid", [&](auto& value) { value.uid = distinct_uid(); });
    if (!result.success) return result;
    result = identity_mutation("identity.gid", [&](auto& value) { value.gid = distinct_gid(); });
    if (!result.success) return result;
    result = identity_mutation("identity.netns", [](auto& value) { ++value.netns; });
    if (!result.success) return result;
    result = identity_mutation("identity.exe_dev", [](auto& value) { ++value.exe_dev; });
    if (!result.success) return result;
    result = identity_mutation("identity.exe_ino", [](auto& value) { ++value.exe_ino; });
    if (!result.success) return result;
    result = identity_mutation("identity.argv_length", [](auto& value) { ++value.argv_length; });
    if (!result.success) return result;
    result = identity_mutation("identity.argv_hash", [](auto& value) { ++value.argv_hash; });
    if (!result.success) return result;
    auto changed = evidence;
    auto changed_cmdline = evidence;
    changed_cmdline.cmdline.push_back('\0');
    result = check("identity.cmdline", !accepted(changed_cmdline, report, peer, root_peer));
    if (!result.success) return result;
    auto changed_pidfd = evidence;
    changed_pidfd.pidfd_live = false;
    result = check("identity.pidfd_live", !accepted(changed_pidfd, report, peer, root_peer));
    if (!result.success) return result;
    changed = evidence;
    changed.state = '\0';
    result = check("identity.state.unknown", !accepted(changed, report, peer, root_peer));
    if (!result.success) return result;
    changed = evidence;

    for (size_t slot = 0; slot != evidence.status.uid_values.size(); ++slot) {
        auto changed = evidence;
        changed.status.uid_values[slot] = distinct_uid();
        result = check("status.uid.slot", !accepted(changed, report, peer, root_peer));
        if (!result.success) return result;
    }
    for (size_t slot = 0; slot != evidence.status.gid_values.size(); ++slot) {
        auto changed = evidence;
        changed.status.gid_values[slot] = distinct_gid();
        result = check("status.gid.slot", !accepted(changed, report, peer, root_peer));
        if (!result.success) return result;
    }
    changed.status.supplementary_groups.push_back(distinct_gid());
    result = check("status.groups.nonempty", !accepted(changed, report, peer, root_peer));
    if (!result.success) return result;
    changed = evidence;
    changed.status.no_new_privs = false;
    result = check("status.nnp", !accepted(changed, report, peer, root_peer));
    if (!result.success) return result;
    for (const auto field : {0, 1, 2}) {
        changed = evidence;
        if (field == 0) changed.status.cap_inh_clear = false;
        if (field == 1) changed.status.cap_prm_clear = false;
        if (field == 2) changed.status.cap_eff_clear = false;
        result = check(field == 0   ? "status.cap_inh"
                       : field == 1 ? "status.cap_prm"
                                    : "status.cap_eff",
                       !accepted(changed, report, peer, root_peer));
        if (!result.success) return result;
    }
    Peer changed_root = root_peer;
    changed_root.pid++;
    result = check("root.peer.pid", !accepted(candidate, report, peer, changed_root));
    if (!result.success) return result;
    changed_root = root_peer;
    changed_root.uid = 1;
    result = check("root.peer.uid", !accepted(candidate, report, peer, changed_root));
    if (!result.success) return result;
    changed_root = root_peer;
    changed_root.gid = 1;
    result = check("root.peer.gid", !accepted(candidate, report, peer, changed_root));
    if (!result.success) return result;
    result = check("root.control.lease", !accepted(candidate, report, peer, root_peer, false));
    if (!result.success) return result;
    result =
        check("endpoint.stability", !accepted(candidate, report, peer, root_peer, true, false));
    return result;
}

static bool validate_identity_manifest_binding(
    const std::array<identity_bundle::RoleManifest, identity_bundle::kRoleCount>& manifests,
    const Report& report,
    const Peer& peer,
    const HeldTopologySnapshot& topology,
    const std::string& executable,
    const std::string& expected_root_argv,
    const std::string& expected_launcher_argv,
    const BundleStatusEvidence& launcher_status_evidence,
    const BundleStatusEvidence& root_status_evidence,
    const RetainedAnchorEvidence* retained_anchor,
    DirectLaunch& sudo_launch,
    ProcIdentity& root_proc,
    ProcIdentity& launcher_proc,
    std::string& error) {
    const identity_bundle::RoleManifest& launcher = manifests[0];
    const identity_bundle::RoleManifest& root = manifests[1];
    const auto argv_exact = [](const identity_bundle::RoleManifest& manifest,
                               const std::string& expected) {
        return manifest.argv_length == expected.size() &&
               manifest.argv_hash == probe_hash(expected);
    };
    const dev_t expected_dev = sudo_launch.allowed.launcher_stage.exe_dev;
    const ino_t expected_ino = sudo_launch.allowed.launcher_stage.exe_ino;
    if (launcher.role != identity_bundle::Role::Launcher ||
        root.role != identity_bundle::Role::Root || peer.pid <= 1 || peer.uid != 0 ||
        peer.gid != 0 || root.pid != peer.pid ||
        root.pid != static_cast<pid_t>(report.target_pid) || root.start != report.start ||
        root.ppid != launcher.pid || root.ppid != static_cast<pid_t>(report.wrapper_pid) ||
        root.pgid != sudo_launch.anchor.pgid || root.sid != sudo_launch.anchor.sid ||
        root.uid != 0 || root.gid != 0 || root.netns != topology.holder_netns ||
        root.exe_dev != static_cast<u64>(expected_dev) ||
        root.exe_ino != static_cast<u64>(expected_ino) || !argv_exact(root, expected_root_argv) ||
        launcher.pid != static_cast<pid_t>(report.wrapper_pid) || launcher.start == 0 ||
        (launcher.pid == sudo_launch.anchor.pid ? launcher.ppid != getpid()
                                                : launcher.ppid != sudo_launch.anchor.pid) ||
        launcher.pgid != sudo_launch.anchor.pgid || launcher.sid != sudo_launch.anchor.sid ||
        launcher.uid != 0 || launcher.gid != 0 || launcher.netns != topology.holder_netns ||
        launcher.exe_dev != static_cast<u64>(expected_dev) ||
        launcher.exe_ino != static_cast<u64>(expected_ino) ||
        !argv_exact(launcher, expected_launcher_argv) || report.exe != executable ||
        report.exe_dev != root.exe_dev || report.exe_ino != root.exe_ino ||
        report.argv != expected_root_argv || report.uid != 0 || report.gid != 0 ||
        report.netns != topology.holder_netns || report.pgid != static_cast<u64>(root.pgid) ||
        report.mode != "broker-root" ||
        !groups_evidence_matches(report, launcher_status_evidence, root_status_evidence)) {
        error = "identity bundle manifest/peer/report binding was not exact";
        return false;
    }
    root_proc = proc_from_bundle_role(root, executable, expected_root_argv);
    root_proc.no_new_privs = root_status_evidence.no_new_privs;
    root_proc.capabilities_clear = root_status_evidence.capabilities_clear;
    root_proc.supplementary_groups = root_status_evidence.supplementary_groups.size();
    launcher_proc = proc_from_bundle_role(launcher, executable, expected_launcher_argv);
    if (!validate_root_broker(report,
                              peer,
                              root_proc,
                              launcher_proc,
                              topology,
                              executable,
                              expected_root_argv,
                              expected_launcher_argv,
                              retained_anchor,
                              sudo_launch)) {
        error = sudo_launch.reason;
        return false;
    }
    return true;
}

static bool validate_received_identity_bundle(const identity_bundle::IdentityBundle& bundle,
                                              const Report& report,
                                              const Peer& peer,
                                              const HeldTopologySnapshot& topology,
                                              const std::string& executable,
                                              const std::string& expected_root_argv,
                                              const std::string& expected_launcher_argv,
                                              const RetainedAnchorEvidence* retained_anchor,
                                              DirectLaunch& sudo_launch,
                                              ProcIdentity& root_proc,
                                              ProcIdentity& launcher_proc,
                                              std::string& error) {
    std::string transport_error;
    if (!identity_bundle::validate_bundle(bundle, transport_error)) {
        error = "received identity bundle failed transport validation: " + transport_error;
        return false;
    }
    const std::array<identity_bundle::RoleManifest, identity_bundle::kRoleCount> manifests{
        bundle.roles[0].manifest, bundle.roles[1].manifest};
    BundleStatusEvidence launcher_status_evidence;
    BundleStatusEvidence root_status_evidence;
    if (!read_bundle_status_evidence(bundle.roles[0], launcher_status_evidence) ||
        !read_bundle_status_evidence(bundle.roles[1], root_status_evidence)) {
        error = "received Launcher/Root status FD security evidence was invalid";
        return false;
    }
    return validate_identity_manifest_binding(manifests,
                                              report,
                                              peer,
                                              topology,
                                              executable,
                                              expected_root_argv,
                                              expected_launcher_argv,
                                              launcher_status_evidence,
                                              root_status_evidence,
                                              retained_anchor,
                                              sudo_launch,
                                              root_proc,
                                              launcher_proc,
                                              error);
}

static bool identity_bundle_integration_self_check(std::string& error) {
    const pid_t expected_parent = getpid();
    int child_ready[2] = {-1, -1};
    if (pipe2(child_ready, O_CLOEXEC) != 0) {
        error = "identity integration child-ready pipe failed";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(child_ready[0]);
        close(child_ready[1]);
        error = "identity integration child fork failed";
        return false;
    }
    if (child == 0) {
        close(child_ready[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent) _exit(125);
        const unsigned char ready = 0x91;
        if (!write_pipe_exact(child_ready[1], &ready, 1, kCleanupMs)) _exit(125);
        close(child_ready[1]);
        for (;;) pause();
    }
    close(child_ready[1]);
    unsigned char ready = 0;
    bool ok = read_exact(child_ready[0], &ready, 1, kCleanupMs) && ready == 0x91;
    close(child_ready[0]);

    Report unchanged_groups;
    unchanged_groups.groups_clear = 0;
    unchanged_groups.groups_unchanged = 1;
    Report clear_groups = unchanged_groups;
    clear_groups.groups_clear = 1;
    clear_groups.groups_unchanged = 0;
    BundleStatusEvidence empty_launcher_groups;
    BundleStatusEvidence empty_root_groups;
    BundleStatusEvidence nonempty_launcher_groups;
    nonempty_launcher_groups.supplementary_groups = {1};
    BundleStatusEvidence nonempty_root_groups = nonempty_launcher_groups;
    ok =
        ok && groups_evidence_matches(unchanged_groups, empty_launcher_groups, empty_root_groups) &&
        groups_evidence_matches(unchanged_groups, nonempty_launcher_groups, nonempty_root_groups) &&
        groups_evidence_matches(clear_groups, nonempty_launcher_groups, empty_root_groups) &&
        !groups_evidence_matches(unchanged_groups, nonempty_launcher_groups, empty_root_groups) &&
        !groups_evidence_matches(clear_groups, empty_launcher_groups, nonempty_root_groups);
    const MutationDiagnostic first_failed = first_failed_mutation(
        {{"mutation.first", true}, {"mutation.second", false}, {"mutation.third", false}});
    const MutationDiagnostic all_passed =
        first_failed_mutation({{"mutation.first", true}, {"mutation.second", true}});
    const std::array<const char*, 3> first_labels{
        "mutation.first", "mutation.second", "mutation.third"};
    bool every_first_label = true;
    for (size_t first = 0; first != first_labels.size(); ++first) {
        std::vector<std::pair<const char*, bool>> checks;
        for (size_t index = 0; index != first_labels.size(); ++index)
            checks.emplace_back(first_labels[index], index != first);
        const MutationDiagnostic selected = first_failed_mutation(checks);
        every_first_label =
            every_first_label && !selected.success && selected.failed_label == first_labels[first];
    }
    const Peer equal_start_peer{321, 0, 0};
    const Peer equal_start_root{320, 0, 0};
    ProcIdentity equal_start_proc;
    ProcIdentity equal_start_root_proc;
    equal_start_proc.pid = equal_start_peer.pid;
    equal_start_root_proc.pid = equal_start_root.pid;
    equal_start_proc.start = 77;
    equal_start_root_proc.start = 77;
    const MutationDiagnostic equal_start_diagnostic = first_failed_mutation(
        {{"peer.distinct_root", equal_start_peer.pid != equal_start_root.pid},
         {"proc.start_distinct", equal_start_proc.start != equal_start_root_proc.start}});
    ok = ok && !first_failed.success && first_failed.failed_label == "mutation.second" &&
         all_passed.success && all_passed.failed_label.empty() && every_first_label &&
         !equal_start_diagnostic.success &&
         equal_start_diagnostic.failed_label == "proc.start_distinct";

    identity_bundle::IdentityBundle source;
    std::string bundle_error;
    ok = ok &&
         identity_bundle::open_role(
             getpid(), identity_bundle::Role::Launcher, source.roles[0], bundle_error) &&
         identity_bundle::open_role(
             child, identity_bundle::Role::Root, source.roles[1], bundle_error) &&
         identity_bundle::validate_bundle(source, bundle_error);
    int sockets[2] = {-1, -1};
    ok = ok && socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0;
    Token token;
    ok = ok && new_token(token);
    Frame frame;
    if (ok) {
        ok = send_frame(sockets[0], Frame{kBrokerRootHello, token, {}}, kHandshakeMs) &&
             receive_frame(sockets[1], frame, kHandshakeMs) && frame.type == kBrokerRootHello &&
             token_equal(frame.token, token) &&
             send_frame(sockets[1], Frame{kIdentityBundleRequest, token, {}}, kHandshakeMs) &&
             receive_frame(sockets[0], frame, kHandshakeMs) &&
             frame.type == kIdentityBundleRequest && token_equal(frame.token, token);
    }
    identity_bundle::ReceivedBundle received;
    if (ok) {
        ok = identity_bundle::send_bundle(
                 sockets[0],
                 source,
                 std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(identity_bundle::kTransportTimeoutMs)) &&
             identity_bundle::receive_bundle(
                 sockets[1],
                 received,
                 std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(identity_bundle::kTransportTimeoutMs),
                 bundle_error) &&
             send_frame(sockets[1], Frame{kIdentityBundleAck, token, {}}, kHandshakeMs) &&
             receive_frame(sockets[0], frame, kHandshakeMs) && frame.type == kIdentityBundleAck &&
             token_equal(frame.token, token);
    }

    identity_bundle::RoleBundle adopted_handoff;
    std::string handoff_error;
    if (ok) {
        ok = install_launcher_bundle_handoff(source.roles[0]) &&
             take_launcher_bundle_handoff(adopted_handoff, handoff_error) &&
             adopted_handoff.manifest.pid == source.roles[0].manifest.pid &&
             adopted_handoff.manifest.start == source.roles[0].manifest.start &&
             adopted_handoff.manifest.exe_dev == source.roles[0].manifest.exe_dev &&
             adopted_handoff.manifest.exe_ino == source.roles[0].manifest.exe_ino &&
             adopted_handoff.manifest.argv_length == source.roles[0].manifest.argv_length &&
             adopted_handoff.manifest.argv_hash == source.roles[0].manifest.argv_hash;
        adopted_handoff.close();
        for (size_t i = 0; i != identity_bundle::kFdsPerRole; ++i) {
            errno = 0;
            ok = ok && fcntl(kLauncherBundleFdBase + static_cast<int>(i), F_GETFD) < 0 &&
                 errno == EBADF;
        }
    }

    received.reset();
    source.close();
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) ok = false;
    pid_t waited;
    do {
        waited = waitpid(child, nullptr, 0);
    } while (waited < 0 && errno == EINTR);
    ok = ok && waited == child;
    if (!ok) {
        error = "identity bundle handshake/binding mutation self-check failed: " + bundle_error;
        return false;
    }
    return true;
}

static MutationDiagnostic live_identity_bundle_mutation_checks(
    const identity_bundle::IdentityBundle& bundle,
    const Report& report,
    const Peer& peer,
    const HeldTopologySnapshot& topology,
    const std::string& executable,
    const std::string& root_argv,
    const std::string& launcher_argv,
    const RetainedAnchorEvidence* retained_anchor,
    const DirectLaunch& live_launch) {
    ProcIdentity ignored_root;
    ProcIdentity ignored_launcher;
    std::string ignored_error;
    DirectLaunch full_baseline = live_launch;
    if (!validate_received_identity_bundle(bundle,
                                           report,
                                           peer,
                                           topology,
                                           executable,
                                           root_argv,
                                           launcher_argv,
                                           retained_anchor,
                                           full_baseline,
                                           ignored_root,
                                           ignored_launcher,
                                           ignored_error))
        return {false, "baseline.repeated_semantic", "repeated full identity validation failed"};
    const std::array<identity_bundle::RoleManifest, identity_bundle::kRoleCount> manifests{
        bundle.roles[0].manifest, bundle.roles[1].manifest};
    BundleStatusEvidence launcher_status;
    BundleStatusEvidence root_status;
    if (!read_bundle_status_evidence(bundle.roles[0], launcher_status) ||
        !read_bundle_status_evidence(bundle.roles[1], root_status))
        return {false, "status_fd.reread", "Launcher/Root status reread failed"};
    const auto accepted_with_evidence = [&](const auto& candidate_manifests,
                                            const Report& candidate_report,
                                            const Peer& candidate_peer,
                                            const BundleStatusEvidence& candidate_launcher_status,
                                            const BundleStatusEvidence& candidate_root_status) {
        DirectLaunch launch = live_launch;
        ProcIdentity root_proc;
        ProcIdentity launcher_proc;
        std::string error;
        return validate_identity_manifest_binding(candidate_manifests,
                                                  candidate_report,
                                                  candidate_peer,
                                                  topology,
                                                  executable,
                                                  root_argv,
                                                  launcher_argv,
                                                  candidate_launcher_status,
                                                  candidate_root_status,
                                                  retained_anchor,
                                                  launch,
                                                  root_proc,
                                                  launcher_proc,
                                                  error);
    };
    const auto accepted = [&](const auto& candidate_manifests,
                              const Report& candidate_report,
                              const Peer& candidate_peer) {
        return accepted_with_evidence(
            candidate_manifests, candidate_report, candidate_peer, launcher_status, root_status);
    };
    if (!accepted(manifests, report, peer))
        return {false, "baseline.repeated_semantic", "repeated full identity validation failed"};
    const auto rejects = [&](auto mutation) {
        auto changed = manifests;
        mutation(changed);
        return !accepted(changed, report, peer);
    };
    Peer changed_peer = peer;
    ++changed_peer.pid;
    Report changed_report = report;
    ++changed_report.target_pid;
    Report changed_nnp_report = report;
    changed_nnp_report.no_new_privs ^= 1;
    Report changed_caps_report = report;
    changed_caps_report.capabilities_clear ^= 1;
    Report changed_groups_report = report;
    changed_groups_report.groups_clear = 1;
    changed_groups_report.groups_unchanged = 0;
    BundleStatusEvidence changed_nnp_evidence = root_status;
    changed_nnp_evidence.no_new_privs = !changed_nnp_evidence.no_new_privs;
    BundleStatusEvidence changed_caps_evidence = root_status;
    changed_caps_evidence.capabilities_clear = !changed_caps_evidence.capabilities_clear;
    BundleStatusEvidence changed_root_groups = root_status;
    changed_root_groups.supplementary_groups.push_back(
        changed_root_groups.supplementary_groups.empty()
            ? 1
            : static_cast<gid_t>(changed_root_groups.supplementary_groups.back() + 1));
    BundleStatusEvidence changed_launcher_groups = launcher_status;
    changed_launcher_groups.supplementary_groups.push_back(
        changed_launcher_groups.supplementary_groups.empty()
            ? 1
            : static_cast<gid_t>(changed_launcher_groups.supplementary_groups.back() + 1));
    auto detached = manifests;
    detached[0].pid += 100000;
    detached[0].ppid = 1;
    detached[1].ppid = detached[0].pid;
    Report detached_report = report;
    detached_report.wrapper_pid = static_cast<u64>(detached[0].pid);
    const auto check =
        [&](const char* label, bool rejected, std::string detail = {}) -> MutationDiagnostic {
        if (rejected) return {};
        if (detail.empty()) detail = "mutation accepted unexpectedly";
        return {false, label, std::move(detail)};
    };
    MutationDiagnostic diagnostic;
    diagnostic = check("peer.pid", !accepted(manifests, report, changed_peer));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("report.target_pid", !accepted(manifests, changed_report, peer));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("report.no_new_privs", !accepted(manifests, changed_nnp_report, peer));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("report.capabilities_clear", !accepted(manifests, changed_caps_report, peer));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("report.groups_flags",
                       !accepted(manifests, changed_groups_report, peer),
                       group_mutation_detail(changed_groups_report, launcher_status, root_status));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check(
        "status.root.no_new_privs",
        !accepted_with_evidence(manifests, report, peer, launcher_status, changed_nnp_evidence));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check(
        "status.root.capabilities",
        !accepted_with_evidence(manifests, report, peer, launcher_status, changed_caps_evidence));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check(
        "status.root.groups",
        !accepted_with_evidence(manifests, report, peer, launcher_status, changed_root_groups),
        group_mutation_detail(report, launcher_status, changed_root_groups));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check(
        "status.launcher.groups",
        !accepted_with_evidence(manifests, report, peer, changed_launcher_groups, root_status),
        group_mutation_detail(report, changed_launcher_groups, root_status));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.pid", rejects([](auto& value) { ++value[1].pid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.launcher.pid", rejects([](auto& value) { ++value[0].pid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.ppid", rejects([](auto& value) { ++value[1].ppid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.launcher.ppid", rejects([](auto& value) { ++value[0].ppid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.start", rejects([](auto& value) { ++value[1].start; }));
    if (!diagnostic.success) return diagnostic;
    // Semantic validation has no independent Launcher start source after the
    // bundle has been received; exercise its explicit nonzero guard here.
    diagnostic = check("manifest.launcher.start", rejects([](auto& value) { value[0].start = 0; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.netns", rejects([](auto& value) { ++value[1].netns; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.launcher.netns", rejects([](auto& value) { ++value[0].netns; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.exe_dev", rejects([](auto& value) { ++value[1].exe_dev; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.exe_ino", rejects([](auto& value) { ++value[1].exe_ino; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("manifest.launcher.exe_dev", rejects([](auto& value) { ++value[0].exe_dev; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("manifest.launcher.exe_ino", rejects([](auto& value) { ++value[0].exe_ino; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("manifest.root.argv_length", rejects([](auto& value) { ++value[1].argv_length; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("manifest.root.argv_hash", rejects([](auto& value) { ++value[1].argv_hash; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.launcher.argv_length",
                       rejects([](auto& value) { ++value[0].argv_length; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("manifest.launcher.argv_hash", rejects([](auto& value) { ++value[0].argv_hash; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.uid", rejects([](auto& value) { ++value[1].uid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.root.gid", rejects([](auto& value) { ++value[1].gid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.launcher.uid", rejects([](auto& value) { ++value[0].uid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("manifest.launcher.gid", rejects([](auto& value) { ++value[0].gid; }));
    if (!diagnostic.success) return diagnostic;
    diagnostic =
        check("manifest.role_swap", rejects([](auto& value) { std::swap(value[0], value[1]); }));
    if (!diagnostic.success) return diagnostic;
    diagnostic = check("detached.lineage", !accepted(detached, detached_report, peer));
    if (!diagnostic.success) return diagnostic;
    return diagnostic;
}

struct DestructiveAuth {
    bool valid = false;
};

// This authorization is deliberately narrower than semantic success.  It is
// only a close-only proof; the full launcher/ancestry validation remains a
// separate gate before credentials or target launch are allowed.
static DestructiveAuth authorize_destructive_close(const ParentEndpoint& endpoint,
                                                   const Report& report,
                                                   const Peer& peer,
                                                   const Token& expected_token,
                                                   const Token& frame_token,
                                                   const HeldTopologySnapshot& topology,
                                                   const std::string& executable,
                                                   const std::string& expected_argv,
                                                   const std::string& expected_launcher_argv,
                                                   DirectLaunch& launch) {
    (void)expected_launcher_argv;
    (void)launch;
    const bool basic_report = peer.pid > 1 && peer.uid == 0 && peer.gid == 0 &&
                              report.target_pid == static_cast<u64>(peer.pid) &&
                              report.wrapper_pid > 1 && report.pgid > 1 && report.start != 0 &&
                              report.uid == 0 && report.gid == 0 &&
                              report.netns == topology.holder_netns && report.exe == executable &&
                              report.argv == expected_argv && report.mode == "broker-root";
    return {endpoint_unchanged(endpoint) && token_equal(expected_token, frame_token) &&
            basic_report};
}

static DirectLaunch copy_launch_with_anchor(const DirectLaunch& source, DirectLaunchAnchor anchor) {
    DirectLaunch result(std::move(anchor), source.allowed, source.marker_valid);
    result.observed_stages = source.observed_stages;
    result.mode = source.mode;
    result.current_identity = source.current_identity;
    result.current_stage = source.current_stage;
    result.current_valid = source.current_valid;
    result.launcher_identity = source.launcher_identity;
    result.launcher_valid = source.launcher_valid;
    result.reason = source.reason;
    result.status = source.status;
    result.reaped = source.reaped;
    return result;
}

static MutationDiagnostic causal_mutation_self_checks(const Report& root_report,
                                                      const Peer& root_peer,
                                                      const ProcIdentity& root_proc,
                                                      const ProcIdentity& launcher_proc,
                                                      const Report& broker_report,
                                                      const Peer& broker_peer,
                                                      const ProcIdentity& broker_proc,
                                                      const Report& target_report,
                                                      const Peer& target_peer,
                                                      const ProcIdentity& target_proc,
                                                      const HeldTopologySnapshot& topology,
                                                      const std::string& executable,
                                                      const std::string& root_argv,
                                                      const std::string& launcher_argv,
                                                      const std::string& dropped_argv,
                                                      const std::string& target_argv,
                                                      const Token& token,
                                                      DirectLaunch& sudo_child,
                                                      const RetainedAnchorEvidence* retained_anchor,
                                                      const ParentEndpoint& endpoint) {
    DirectLaunch baseline_launch = sudo_child;
    const bool root_baseline = validate_root_broker(root_report,
                                                    root_peer,
                                                    root_proc,
                                                    launcher_proc,
                                                    topology,
                                                    executable,
                                                    root_argv,
                                                    launcher_argv,
                                                    retained_anchor,
                                                    baseline_launch);
    Report changed_root = root_report;
    changed_root.netns++;
    Peer changed_root_peer = root_peer;
    changed_root_peer.pid++;
    ProcIdentity changed_root_proc = root_proc;
    changed_root_proc.start++;
    DirectLaunchAnchor stale_anchor = sudo_child.anchor;
    stale_anchor.start++;
    DirectLaunch changed_sudo = copy_launch_with_anchor(sudo_child, stale_anchor);
    DirectLaunch changed_report_launch = sudo_child;
    DirectLaunch changed_peer_launch = sudo_child;
    DirectLaunch changed_proc_launch = sudo_child;
    const bool root_mutations = !validate_root_broker(changed_root,
                                                      root_peer,
                                                      root_proc,
                                                      launcher_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      retained_anchor,
                                                      changed_report_launch) &&
                                !validate_root_broker(root_report,
                                                      changed_root_peer,
                                                      root_proc,
                                                      launcher_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      retained_anchor,
                                                      changed_peer_launch) &&
                                !validate_root_broker(root_report,
                                                      root_peer,
                                                      changed_root_proc,
                                                      launcher_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      retained_anchor,
                                                      changed_proc_launch) &&
                                !validate_root_broker(root_report,
                                                      root_peer,
                                                      root_proc,
                                                      launcher_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      retained_anchor,
                                                      changed_sudo);
    const bool broker_baseline = identity_matches_report(broker_report,
                                                         broker_peer,
                                                         broker_proc,
                                                         executable,
                                                         dropped_argv,
                                                         "broker-dropped",
                                                         token,
                                                         token,
                                                         true,
                                                         false,
                                                         true) &&
                                 broker_report.wrapper_pid == static_cast<u64>(root_peer.pid) &&
                                 broker_proc.ppid == root_peer.pid &&
                                 broker_peer.pid != root_peer.pid;
    Report changed_broker = broker_report;
    changed_broker.wrapper_pid++;
    Peer changed_broker_peer = broker_peer;
    changed_broker_peer.pid++;
    ProcIdentity changed_broker_proc = broker_proc;
    changed_broker_proc.start++;
    const bool broker_mutations =
        changed_broker.wrapper_pid != broker_report.wrapper_pid &&
        changed_broker_peer.pid != broker_peer.pid &&
        changed_broker_proc.start != broker_proc.start &&
        !(identity_matches_report(changed_broker,
                                  broker_peer,
                                  broker_proc,
                                  executable,
                                  dropped_argv,
                                  "broker-dropped",
                                  token,
                                  token,
                                  true,
                                  false,
                                  true) &&
          changed_broker.wrapper_pid == static_cast<u64>(root_peer.pid)) &&
        !identity_matches_report(broker_report,
                                 changed_broker_peer,
                                 broker_proc,
                                 executable,
                                 dropped_argv,
                                 "broker-dropped",
                                 token,
                                 token,
                                 true,
                                 false,
                                 true) &&
        !identity_matches_report(broker_report,
                                 broker_peer,
                                 changed_broker_proc,
                                 executable,
                                 dropped_argv,
                                 "broker-dropped",
                                 token,
                                 token,
                                 true,
                                 false,
                                 true);
    const bool target_baseline = identity_matches_report(target_report,
                                                         target_peer,
                                                         target_proc,
                                                         executable,
                                                         target_argv,
                                                         "privileged-target",
                                                         token,
                                                         token,
                                                         true,
                                                         false,
                                                         true);
    Report changed_target = target_report;
    changed_target.pgid = 1;
    Peer changed_target_peer = target_peer;
    changed_target_peer.uid++;
    ProcIdentity changed_target_proc = target_proc;
    changed_target_proc.start++;
    const bool target_mutations = !identity_matches_report(changed_target,
                                                           target_peer,
                                                           target_proc,
                                                           executable,
                                                           target_argv,
                                                           "privileged-target",
                                                           token,
                                                           token,
                                                           true,
                                                           false,
                                                           true) &&
                                  !identity_matches_report(target_report,
                                                           changed_target_peer,
                                                           target_proc,
                                                           executable,
                                                           target_argv,
                                                           "privileged-target",
                                                           token,
                                                           token,
                                                           true,
                                                           false,
                                                           true) &&
                                  !identity_matches_report(target_report,
                                                           target_peer,
                                                           changed_target_proc,
                                                           executable,
                                                           target_argv,
                                                           "privileged-target",
                                                           token,
                                                           token,
                                                           true,
                                                           false,
                                                           true);
    Report unsafe_signal_report = target_report;
    unsafe_signal_report.pgid = 1;
    const bool signal_mutations =
        safe_signal_target(target_report, target_peer, target_proc, 0) &&
        !safe_signal_target(target_report, target_peer, changed_target_proc, 0) &&
        !safe_signal_target(unsafe_signal_report, target_peer, target_proc, 0) &&
        process_alive(target_peer.pid);
    DirectLaunch baseline_sudo = sudo_child;
    DirectLaunch stale_sudo = sudo_child;
    stale_sudo.current_identity.start++;
    DirectLaunch unsafe_sudo = sudo_child;
    unsafe_sudo.current_identity.pgid = 1;
    // The retained sudo wrapper has transitioned away from the ordinary
    // parent's exact UID/GID authority.  Its live identity must remain
    // unsignalable here; caller-owned direct launches retain the positive
    // single-PID signal coverage exercised by bounded_wait_and_signal_self_check().
    const bool sudo_signal_baseline = retained_anchor != nullptr
                                          ? !safe_signal_direct_child(baseline_sudo, 0)
                                          : safe_signal_direct_child(baseline_sudo, 0);
    const bool sudo_signal_mutations =
        sudo_child.current_valid &&
        stale_sudo.current_identity.start != sudo_child.current_identity.start &&
        unsafe_sudo.current_identity.pgid != sudo_child.current_identity.pgid &&
        sudo_signal_baseline && !safe_signal_direct_child(stale_sudo, 0) &&
        !safe_signal_direct_child(unsafe_sudo, 0) && process_alive(sudo_child.anchor.pid);
    EndpointIdentity changed_endpoint = endpoint.identity;
    changed_endpoint.socket_ino++;
    const std::vector<unsigned char> trace{'G', 'D', 'U', 'N', 'C', 'P', 'X'};
    std::vector<unsigned char> swapped_trace = trace;
    std::swap(swapped_trace[1], swapped_trace[2]);
    std::vector<unsigned char> short_trace = trace;
    short_trace.pop_back();
    MutationDiagnostic diagnostic =
        first_failed_mutation({{"root.baseline", root_baseline},
                               {"root.mutations", root_mutations},
                               {"broker.baseline", broker_baseline},
                               {"broker.mutations", broker_mutations},
                               {"target.baseline", target_baseline},
                               {"target.mutations", target_mutations},
                               {"target.signal", signal_mutations},
                               {"sudo.signal", sudo_signal_mutations},
                               {"endpoint.current", endpoint_unchanged(endpoint)},
                               {"endpoint.mutation", !endpoint_matches(endpoint, changed_endpoint)},
                               {"trace.exact", valid_security_trace(trace)},
                               {"trace.swap", !valid_security_trace(swapped_trace)},
                               {"trace.short", !valid_security_trace(short_trace)}});
    if (!diagnostic.success) diagnostic.detail = "causal predicate failed";
    return diagnostic;
}

static bool safe_signal_target(const Report& report,
                               const Peer& peer,
                               const ProcIdentity& expected,
                               int signal_number) {
    ProcIdentity current;
    if (report.target_pid <= 1 || report.pgid != report.target_pid ||
        report.target_pid != static_cast<u64>(peer.pid) || expected.pid != peer.pid ||
        !read_proc(peer.pid, current) || !same_process_identity(expected, current) ||
        current.pgid != current.pid)
        return false;
    // The ordinary test parent never signals a process group: target identity
    // is revalidated, then only that exact PID is signaled.
    return kill(current.pid, signal_number) == 0;
}

static bool wait_identity_gone_or_reused_until(const ProcIdentity& expected,
                                               std::chrono::steady_clock::time_point deadline) {
    if (expected.pid <= 1 || expected.start == 0) return true;
    for (;;) {
        ProcIdentity current;
        if (read_proc(expected.pid, current, false)) {
            if (current.start != expected.start) return true;
        } else {
            errno = 0;
            if (kill(expected.pid, 0) < 0 && errno == ESRCH) return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) return false;
        (void)poll(nullptr, 0, 10);
    }
}

enum class ProbeNodeStage { Sudo, Nsenter, Invalid };

struct ProbeNodeFact {
    pid_t pid = -1;
    pid_t ppid = -1;
    pid_t pgid = -1;
    pid_t sid = -1;
    std::uint64_t start = 0;
    ProbeNodeStage stage = ProbeNodeStage::Invalid;
    bool live = false;
    bool access = false;
};

struct ProbeChainFacts {
    pid_t peer_pid = -1;
    pid_t root_pid = -1;
    pid_t root_ppid = -1;
    pid_t launcher_pid = -1;
    pid_t launcher_ppid = -1;
    pid_t ordinary_parent = -1;
    pid_t anchor_pid = -1;
    pid_t anchor_ppid = -1;
    pid_t anchor_pgid = -1;
    pid_t anchor_sid = -1;
    std::uint64_t anchor_start = 0;
    pid_t lease_pid = -1;
    pid_t lease_pgid = -1;
    pid_t lease_sid = -1;
    std::uint64_t lease_start = 0;
    bool lease_pidfd_live = false;
    std::vector<ProbeNodeFact> nodes;
};

static bool validate_probe_chain_facts(const ProbeChainFacts& facts, std::string& error) {
    if (facts.peer_pid <= 1 || facts.root_pid != facts.peer_pid || facts.root_ppid <= 1 ||
        facts.launcher_pid <= 1 || facts.root_ppid != facts.launcher_pid ||
        facts.launcher_ppid <= 1 || facts.ordinary_parent <= 1 || facts.nodes.empty() ||
        facts.nodes.size() > kMaxLaunchAncestry || facts.launcher_ppid != facts.nodes.front().pid) {
        error = "probe root/peer/launcher binding or ancestry entry was invalid";
        return false;
    }
    pid_t expected = facts.launcher_ppid;
    std::vector<pid_t> seen;
    for (const ProbeNodeFact& node : facts.nodes) {
        if (!node.access || !node.live || node.pid <= 1 || node.start == 0 ||
            node.pid != expected || node.pgid != facts.anchor_pgid ||
            node.sid != facts.anchor_sid || node.stage == ProbeNodeStage::Invalid ||
            std::find(seen.begin(), seen.end(), node.pid) != seen.end()) {
            error = "probe ancestry node access/liveness/order was invalid";
            return false;
        }
        seen.push_back(node.pid);
        expected = node.ppid;
    }
    const ProbeNodeFact& anchor = facts.nodes.back();
    if (anchor.stage != ProbeNodeStage::Sudo || anchor.pid != facts.anchor_pid ||
        anchor.start != facts.anchor_start || anchor.ppid != facts.anchor_ppid ||
        anchor.pgid != facts.anchor_pgid || anchor.sid != facts.anchor_sid ||
        anchor.ppid != facts.ordinary_parent || facts.lease_pid != facts.anchor_pid ||
        facts.lease_start != facts.anchor_start || facts.lease_pgid != facts.anchor_pgid ||
        facts.lease_sid != facts.anchor_sid || !facts.lease_pidfd_live) {
        error = "probe final sudo anchor or GroupLease binding was invalid";
        return false;
    }
    // Network-only nsenter execs Launcher and is therefore not a retained
    // ancestor.  This access spike proves the one ancestor that exists on the
    // required runner: the immutable retained sudo anchor.  Any future launch
    // shape with extra intermediaries remains fail-closed until separately
    // proven on a real runner.
    if (facts.nodes.size() != 1 || facts.nodes.front().stage != ProbeNodeStage::Sudo) {
        error = "probe retained sudo anchor launch shape was not exact";
        return false;
    }
    error.clear();
    return true;
}

static bool ancestry_probe_validation_self_check(std::string& error) {
    const ProbeNodeFact sudo{101, 10, 101, 10, 1001, ProbeNodeStage::Sudo, true, true};
    ProbeChainFacts direct;
    direct.peer_pid = 103;
    direct.root_pid = 103;
    direct.root_ppid = 104;
    direct.launcher_pid = 104;
    direct.launcher_ppid = 101;
    direct.ordinary_parent = 10;
    direct.anchor_pid = 101;
    direct.anchor_ppid = 10;
    direct.anchor_pgid = 101;
    direct.anchor_sid = 10;
    direct.anchor_start = 1001;
    direct.lease_pid = 101;
    direct.lease_pgid = 101;
    direct.lease_sid = 10;
    direct.lease_start = 1001;
    direct.lease_pidfd_live = true;
    direct.nodes = {sudo};
    const auto accepts = [](const ProbeChainFacts& candidate) {
        std::string ignored;
        return validate_probe_chain_facts(candidate, ignored);
    };
    if (!accepts(direct)) {
        error = "ancestry probe retained sudo anchor baseline self-check failed";
        return false;
    }
    std::vector<ProbeChainFacts> rejected;
    ProbeChainFacts changed = direct;
    changed.nodes.clear();
    rejected.push_back(changed);
    changed = direct;
    changed.nodes.push_back(changed.nodes.front());
    rejected.push_back(changed);
    changed = direct;
    changed.anchor_start++;
    rejected.push_back(changed);
    changed.nodes[0].stage = ProbeNodeStage::Nsenter;
    rejected.push_back(changed);
    changed = direct;
    changed.peer_pid++;
    rejected.push_back(changed);
    changed = direct;
    changed.root_ppid++;
    rejected.push_back(changed);
    changed = direct;
    changed.anchor_pid++;
    rejected.push_back(changed);
    changed = direct;
    changed.lease_start++;
    rejected.push_back(changed);
    changed = direct;
    changed.lease_pidfd_live = false;
    rejected.push_back(changed);
    changed = direct;
    changed.ordinary_parent++;
    rejected.push_back(changed);
    changed = direct;
    changed.nodes[0].live = false;
    rejected.push_back(changed);
    changed = direct;
    changed.nodes[0].access = false;
    rejected.push_back(changed);
    for (const ProbeChainFacts& mutation : rejected)
        if (accepts(mutation)) {
            error = "ancestry probe causal mutation was accepted";
            return false;
        }
    return true;
}

static ProcIdentity proc_from_process_evidence(
    const identity_bundle::ProcessIdentityEvidence& evidence) {
    ProcIdentity proc;
    proc.pid = evidence.identity.pid;
    proc.ppid = evidence.identity.ppid;
    proc.pgid = evidence.identity.pgid;
    proc.sid = evidence.identity.sid;
    proc.start = evidence.identity.start;
    proc.uid = evidence.identity.uid;
    proc.gid = evidence.identity.gid;
    proc.netns = static_cast<ino_t>(evidence.identity.netns);
    proc.exe_dev = static_cast<dev_t>(evidence.identity.exe_dev);
    proc.exe_ino = static_cast<ino_t>(evidence.identity.exe_ino);
    proc.cmdline = evidence.cmdline;
    return proc;
}

static bool all_root_ids(const identity_bundle::DroppedStatusEvidence& status) {
    return std::all_of(status.uid_values.begin(),
                       status.uid_values.end(),
                       [](uid_t id) { return id == 0; }) &&
           std::all_of(status.gid_values.begin(), status.gid_values.end(), [](gid_t id) {
               return id == 0;
           });
}

static bool same_security_status(const identity_bundle::DroppedStatusEvidence& first,
                                 const identity_bundle::DroppedStatusEvidence& second) {
    return first.uid_values == second.uid_values && first.gid_values == second.gid_values &&
           first.supplementary_groups == second.supplementary_groups &&
           first.no_new_privs == second.no_new_privs && first.cap_inh == second.cap_inh &&
           first.cap_prm == second.cap_prm && first.cap_eff == second.cap_eff &&
           first.cap_bnd == second.cap_bnd && first.cap_amb == second.cap_amb;
}

static bool exact_sudo_ids(const identity_bundle::DroppedStatusEvidence& status,
                           uid_t caller_uid,
                           gid_t caller_gid) {
    const bool caller = std::all_of(status.uid_values.begin(),
                                    status.uid_values.end(),
                                    [&](uid_t id) { return id == caller_uid; }) &&
                        std::all_of(status.gid_values.begin(),
                                    status.gid_values.end(),
                                    [&](gid_t id) { return id == caller_gid; });
    const bool retained =
        status.uid_values[0] == caller_uid && status.uid_values[1] == 0 &&
        status.uid_values[2] == 0 && status.uid_values[3] == 0 &&
        std::all_of(
            status.gid_values.begin(), status.gid_values.end(), [](gid_t id) { return id == 0; });
    return caller || retained || all_root_ids(status);
}

static bool validate_ancestry_probe_evidence(const identity_bundle::IdentityBundle& identity,
                                             const ancestry_bundle::AncestryBundle& ancestry,
                                             const Peer& root_peer,
                                             const std::string& executable,
                                             const HeldTopologySnapshot& topology,
                                             const std::string& root_argv,
                                             const std::string& launcher_argv,
                                             DirectLaunch& launch,
                                             const GroupLease& lease,
                                             std::string& error) {
    identity_bundle::ProcessIdentityEvidence launcher_evidence;
    identity_bundle::ProcessIdentityEvidence root_evidence;
    std::vector<identity_bundle::ProcessIdentityEvidence> ancestry_evidence;
    if (!identity_bundle::extract_process_identity_evidence(
            identity.roles[0], identity_bundle::Role::Launcher, launcher_evidence, error) ||
        !identity_bundle::extract_process_identity_evidence(
            identity.roles[1], identity_bundle::Role::Root, root_evidence, error) ||
        !ancestry_bundle::extract_evidence(ancestry, ancestry_evidence, error)) {
        if (error.empty()) error = "probe receiver evidence extraction failed";
        return false;
    }
    const ProcIdentity launcher = proc_from_process_evidence(launcher_evidence);
    const ProcIdentity root = proc_from_process_evidence(root_evidence);
    struct stat executable_status{};
    if (stat(executable.c_str(), &executable_status) != 0 || root_peer.pid <= 1 ||
        root_peer.uid != 0 || root_peer.gid != 0 || root.pid != root_peer.pid ||
        root.ppid != launcher.pid || root.uid != 0 || root.gid != 0 || launcher.uid != 0 ||
        launcher.gid != 0 || root.netns != topology.holder_netns ||
        launcher.netns != topology.holder_netns || root.cmdline != root_argv ||
        launcher.cmdline != launcher_argv || root.exe_dev != executable_status.st_dev ||
        root.exe_ino != executable_status.st_ino || launcher.exe_dev != executable_status.st_dev ||
        launcher.exe_ino != executable_status.st_ino || root.pgid != launch.anchor.pgid ||
        launcher.pgid != launch.anchor.pgid || root.sid != launch.anchor.sid ||
        launcher.sid != launch.anchor.sid || !all_root_ids(root_evidence.status) ||
        !all_root_ids(launcher_evidence.status) ||
        !same_security_status(root_evidence.status, launcher_evidence.status)) {
        error = "probe Root/Launcher IDB1 peer, process, argv, credential, or netns binding failed";
        return false;
    }
    ProbeChainFacts facts;
    facts.peer_pid = root_peer.pid;
    facts.root_pid = root.pid;
    facts.root_ppid = root.ppid;
    facts.launcher_pid = launcher.pid;
    facts.launcher_ppid = launcher.ppid;
    facts.ordinary_parent = getpid();
    facts.anchor_pid = launch.anchor.pid;
    facts.anchor_ppid = getpid();
    facts.anchor_pgid = launch.anchor.pgid;
    facts.anchor_sid = launch.anchor.sid;
    facts.anchor_start = launch.anchor.start;
    facts.lease_pid = lease.pid;
    facts.lease_pgid = lease.pgid;
    facts.lease_sid = lease.sid;
    facts.lease_start = lease.start;
    facts.lease_pidfd_live = retained_pidfd_live(lease.pidfd);
    bool root_was_recorded = false;
    for (const auto& evidence : ancestry_evidence) {
        ProcIdentity process = proc_from_process_evidence(evidence);
        const bool sudo_stage =
            process.exe_dev == launch.allowed.sudo_stage.exe_dev &&
            process.exe_ino == launch.allowed.sudo_stage.exe_ino &&
            process.cmdline == launch.allowed.sudo_stage.argv &&
            process.netns == launch.anchor.host_netns &&
            exact_sudo_ids(evidence.status, launch.anchor.caller_uid, launch.anchor.caller_gid);
        const bool nsenter_stage = process.exe_dev == launch.allowed.nsenter_stage.exe_dev &&
                                   process.exe_ino == launch.allowed.nsenter_stage.exe_ino &&
                                   process.cmdline == launch.allowed.nsenter_stage.argv &&
                                   (process.netns == launch.anchor.host_netns ||
                                    process.netns == launch.allowed.holder_netns) &&
                                   all_root_ids(evidence.status);
        ProbeNodeStage stage = ProbeNodeStage::Invalid;
        if (sudo_stage != nsenter_stage)
            stage = sudo_stage ? ProbeNodeStage::Sudo : ProbeNodeStage::Nsenter;
        facts.nodes.push_back(
            ProbeNodeFact{process.pid,
                          process.ppid,
                          process.pgid,
                          process.sid,
                          process.start,
                          stage,
                          evidence.pidfd_live && evidence.state != 'Z' && evidence.state != 'X',
                          true});
        root_was_recorded =
            root_was_recorded || process.pid == root.pid || process.pid == launcher.pid;
    }
    if (root_was_recorded) {
        error = "probe ancestry unexpectedly included Root or Launcher";
        return false;
    }
    if (!validate_probe_chain_facts(facts, error)) return false;
    RetainedAnchorEvidence retained_anchor;
    if (!privileged_ancestry::bind_retained_anchor_evidence(
            ancestry_evidence, retained_anchor, error))
        return false;
    std::string ancestry_error;
    if (!prove_retained_sudo_wrapper(launch, launcher, retained_anchor, ancestry_error) ||
        launch.mode != rut::test::fixture_direct_launch::LaunchMode::SudoWrapper) {
        error = "probe ancestry failed shared launch validation: " + ancestry_error;
        return false;
    }
    return true;
}

struct AuthorizationSnapshot {
    identity_bundle::ProcessIdentityEvidence launcher;
    identity_bundle::ProcessIdentityEvidence root;
    identity_bundle::ProcessIdentityEvidence anchor;
    RetainedAnchorEvidence retained_anchor;
};

static bool live_evidence_state(char state) {
    return state != '\0' && state != 'Z' && state != 'X';
}

static bool same_manifest(const identity_bundle::RoleManifest& first,
                          const identity_bundle::RoleManifest& second) {
    return first.role == second.role && first.pid == second.pid && first.start == second.start &&
           first.ppid == second.ppid && first.pgid == second.pgid && first.sid == second.sid &&
           first.uid == second.uid && first.gid == second.gid && first.netns == second.netns &&
           first.exe_dev == second.exe_dev && first.exe_ino == second.exe_ino &&
           first.argv_length == second.argv_length && first.argv_hash == second.argv_hash;
}

static bool same_immutable_security_evidence(
    const identity_bundle::ProcessIdentityEvidence& first,
    const identity_bundle::ProcessIdentityEvidence& second) {
    return live_evidence_state(first.state) && live_evidence_state(second.state) &&
           first.pidfd_live && second.pidfd_live &&
           same_manifest(first.identity, second.identity) &&
           same_security_status(first.status, second.status) && first.cmdline == second.cmdline;
}

static bool extract_authorization_snapshot(const identity_bundle::IdentityBundle& identity,
                                           const ancestry_bundle::AncestryBundle& ancestry,
                                           AuthorizationSnapshot& snapshot,
                                           std::string& error) {
    std::vector<identity_bundle::ProcessIdentityEvidence> anchors;
    if (!identity_bundle::extract_process_identity_evidence(
            identity.roles[0], identity_bundle::Role::Launcher, snapshot.launcher, error) ||
        !identity_bundle::extract_process_identity_evidence(
            identity.roles[1], identity_bundle::Role::Root, snapshot.root, error) ||
        !ancestry_bundle::extract_evidence(ancestry, anchors, error) || anchors.size() != 1 ||
        !privileged_ancestry::bind_retained_anchor_evidence(
            anchors, snapshot.retained_anchor, error)) {
        if (error.empty()) error = "authorization snapshot extraction failed";
        return false;
    }
    snapshot.anchor = std::move(anchors.front());
    return true;
}

static bool same_authorization_snapshot(const AuthorizationSnapshot& initial,
                                        const AuthorizationSnapshot& final) {
    return same_immutable_security_evidence(initial.launcher, final.launcher) &&
           same_immutable_security_evidence(initial.root, final.root) &&
           same_immutable_security_evidence(initial.anchor, final.anchor);
}

static bool retained_lease_matches_snapshot(const GroupLease& lease,
                                            const DirectLaunch& launch,
                                            const AuthorizationSnapshot& snapshot) {
    const RetainedAnchorEvidence& anchor = snapshot.retained_anchor;
    return lease.pidfd >= 0 && retained_pidfd_live(lease.pidfd) && anchor.pidfd_live &&
           lease.pid == launch.anchor.pid && lease.start == launch.anchor.start &&
           lease.pgid == launch.anchor.pgid && lease.sid == launch.anchor.sid &&
           anchor.pid == lease.pid && anchor.start == lease.start && anchor.pgid == lease.pgid &&
           anchor.sid == lease.sid && anchor.ppid == getpid();
}

static bool validate_formal_ancestry_snapshot(const identity_bundle::IdentityBundle& identity,
                                              const ancestry_bundle::AncestryBundle& ancestry,
                                              const Peer& root_peer,
                                              const std::string& executable,
                                              const HeldTopologySnapshot& topology,
                                              const std::string& root_argv,
                                              const std::string& launcher_argv,
                                              DirectLaunch& launch,
                                              const GroupLease& lease,
                                              AuthorizationSnapshot& snapshot,
                                              std::string& error) {
    return validate_ancestry_probe_evidence(identity,
                                            ancestry,
                                            root_peer,
                                            executable,
                                            topology,
                                            root_argv,
                                            launcher_argv,
                                            launch,
                                            lease,
                                            error) &&
           extract_authorization_snapshot(identity, ancestry, snapshot, error) &&
           retained_lease_matches_snapshot(lease, launch, snapshot);
}

enum class AuthorizationEmission { Rejected, AckFailed, CredentialsFailed, Sent };

static AuthorizationEmission emit_authorization_frames(
    int fd, bool authorized, const Token& token, std::chrono::steady_clock::time_point deadline) {
    if (!authorized) return AuthorizationEmission::Rejected;
    if (!send_frame(fd, Frame{kIdentityBundleAck, token, {}}, remaining_deadline_ms(deadline)))
        return AuthorizationEmission::AckFailed;
    if (!send_frame(fd,
                    Frame{kCallerCredentials, token, credentials_payload(getuid(), getgid())},
                    remaining_deadline_ms(deadline)))
        return AuthorizationEmission::CredentialsFailed;
    return AuthorizationEmission::Sent;
}

static bool formal_authorization_policy_self_check(std::string& error) {
    Token token;
    if (!new_token(token)) {
        error = "formal authorization token setup failed";
        return false;
    }
    Token changed_token = token;
    changed_token.bytes[0] ^= 1;
    const Frame initial{kInitialAncestryRequest, token, {}};
    const Frame final{kFinalAncestryRequest, token, {}};
    if (kInitialAncestryRequest != 33 || kFinalAncestryRequest != 34 ||
        !exact_request(initial, kInitialAncestryRequest, token) ||
        !exact_request(final, kFinalAncestryRequest, token) ||
        exact_request(initial, kFinalAncestryRequest, token) ||
        exact_request(
            Frame{kInitialAncestryRequest, changed_token, {}}, kInitialAncestryRequest, token) ||
        exact_request(Frame{kInitialAncestryRequest, token, {1}}, kInitialAncestryRequest, token)) {
        error = "formal ancestry request type/token/payload policy failed";
        return false;
    }

    AuthorizationSnapshot baseline;
    const auto fill = [](identity_bundle::ProcessIdentityEvidence& evidence,
                         identity_bundle::Role role,
                         pid_t pid) {
        evidence.identity.role = role;
        evidence.identity.pid = pid;
        evidence.identity.start = static_cast<u64>(pid + 1000);
        evidence.identity.ppid = pid - 1;
        evidence.identity.pgid = 101;
        evidence.identity.sid = 10;
        evidence.identity.uid = 0;
        evidence.identity.gid = 0;
        evidence.identity.netns = 200;
        evidence.identity.exe_dev = 300;
        evidence.identity.exe_ino = 400;
        evidence.identity.argv_length = 5;
        evidence.identity.argv_hash = 500;
        evidence.state = 'S';
        evidence.status.uid_values = {0, 0, 0, 0};
        evidence.status.gid_values = {0, 0, 0, 0};
        evidence.status.supplementary_groups = {0};
        evidence.status.cap_bnd = 1;
        evidence.cmdline = "safe";
        evidence.pidfd_live = true;
    };
    fill(baseline.launcher, identity_bundle::Role::Launcher, 103);
    fill(baseline.root, identity_bundle::Role::Root, 104);
    fill(baseline.anchor, identity_bundle::Role::Ancestry, 101);
    AuthorizationSnapshot changed = baseline;
    changed.root.state = 'R';
    if (!same_authorization_snapshot(baseline, changed)) {
        error = "formal authorization compared scheduler state for equality";
        return false;
    }
    const auto rejected = [&](const auto& mutate) {
        AuthorizationSnapshot candidate = baseline;
        mutate(candidate);
        return !same_authorization_snapshot(baseline, candidate);
    };
    if (!rejected([](auto& value) { ++value.anchor.identity.pid; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.start; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.ppid; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.pgid; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.sid; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.netns; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.exe_dev; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.exe_ino; }) ||
        !rejected([](auto& value) { ++value.anchor.identity.argv_hash; }) ||
        !rejected([](auto& value) { value.anchor.status.uid_values[1] = 1; }) ||
        !rejected([](auto& value) { value.anchor.status.gid_values[1] = 1; }) ||
        !rejected([](auto& value) { value.anchor.status.supplementary_groups.push_back(1); }) ||
        !rejected([](auto& value) { value.anchor.status.no_new_privs = true; }) ||
        !rejected([](auto& value) { value.anchor.status.cap_eff = 1; }) ||
        !rejected([](auto& value) { value.anchor.cmdline.push_back('x'); }) ||
        !rejected([](auto& value) { value.anchor.state = 'Z'; }) ||
        !rejected([](auto& value) { value.anchor.pidfd_live = false; }) ||
        !rejected([](auto& value) { ++value.root.identity.pid; }) ||
        !rejected([](auto& value) { ++value.launcher.status.cap_bnd; })) {
        error = "formal authorization identity/security drift mutation was accepted";
        return false;
    }

    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        error = "formal authorization no-emission socketpair failed";
        return false;
    }
    AuthorizationSnapshot rejected_snapshot = baseline;
    ++rejected_snapshot.anchor.identity.pid;
    const bool rejected_authorization = same_authorization_snapshot(baseline, rejected_snapshot);
    const AuthorizationEmission emission =
        emit_authorization_frames(sockets[0],
                                  rejected_authorization,
                                  token,
                                  std::chrono::steady_clock::now() + std::chrono::seconds(1));
    pollfd readable{sockets[1], POLLIN, 0};
    const int polled = poll(&readable, 1, 0);
    if (emission != AuthorizationEmission::Rejected || polled != 0) {
        close(sockets[0]);
        close(sockets[1]);
        error = "formal authorization rejection emitted ACK or credentials";
        return false;
    }
    const bool accepted_authorization = same_authorization_snapshot(baseline, changed);
    const AuthorizationEmission sent =
        emit_authorization_frames(sockets[0],
                                  accepted_authorization,
                                  token,
                                  std::chrono::steady_clock::now() + std::chrono::seconds(1));
    Frame ack;
    Frame credentials;
    const bool exact_order =
        sent == AuthorizationEmission::Sent && receive_frame(sockets[1], ack, kHandshakeMs) &&
        ack.type == kIdentityBundleAck && token_equal(ack.token, token) && ack.payload.empty() &&
        receive_frame(sockets[1], credentials, kHandshakeMs) &&
        credentials.type == kCallerCredentials && token_equal(credentials.token, token);
    close(sockets[0]);
    close(sockets[1]);
    if (!exact_order) {
        error = "formal authorization ACK/credentials emission order failed";
        return false;
    }
    return true;
}

static bool run_ancestry_probe_session(const std::string& sudo_path,
                                       const std::string& nsenter_path,
                                       const std::string& executable,
                                       const HeldTopologySnapshot& topology,
                                       std::string& error) {
    ParentEndpoint endpoint;
    Token token;
    if (!new_token(token) || !create_parent_endpoint(endpoint, error)) return false;
    constexpr const char* scenario = "ancestry-probe-direct";
    std::optional<DirectLaunch> direct_launch;
    std::optional<GroupLease> group_lease;
    std::chrono::steady_clock::time_point deadline;
    std::string launch_error;
    if (!begin_launch(sudo_path,
                      nsenter_path,
                      executable,
                      topology,
                      endpoint,
                      token,
                      scenario,
                      kBrokerDeadlineMs,
                      direct_launch,
                      group_lease,
                      deadline,
                      launch_error)) {
        error = "ancestry probe launch failed: " + launch_error;
        return false;
    }
    DirectLaunch& launch = *direct_launch;
    GroupLease& lease = *group_lease;
    int root_fd = -1;
    bool success = false;
    do {
        const int remaining = remaining_deadline_ms(deadline);
        if (remaining <= 0) {
            error = "ancestry probe expired before Root HELLO";
            break;
        }
        pollfd listener{endpoint.listener, POLLIN, 0};
        int polled;
        do {
            polled = poll(&listener, 1, remaining);
        } while (polled < 0 && errno == EINTR);
        if (polled <= 0 || (listener.revents & POLLIN) == 0) {
            error = "ancestry probe Root connection missed absolute deadline";
            break;
        }
        root_fd = accept4(endpoint.listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        Peer root_peer;
        Frame hello;
        if (root_fd < 0 || !get_peer(root_fd, root_peer) ||
            !receive_frame_until(root_fd, hello, deadline) || hello.type != kAncestryProbeHello ||
            !token_equal(hello.token, token) || !hello.payload.empty() ||
            !send_frame(root_fd,
                        Frame{kIdentityBundleRequest, token, {}},
                        remaining_deadline_ms(deadline))) {
            error = "ancestry probe HELLO/Root peer/IDB request failed";
            break;
        }
        identity_bundle::ReceivedBundle received_identity;
        if (!identity_bundle::receive_bundle(root_fd, received_identity, deadline, error) ||
            !send_frame(root_fd,
                        Frame{kAncestryProbeRequest, token, {}},
                        remaining_deadline_ms(deadline))) {
            if (error.empty()) error = "ancestry probe IDB1 receive/ANC request failed";
            break;
        }
        ancestry_bundle::AncestryBundle ancestry;
        if (!ancestry_bundle::receive_bundle(root_fd, ancestry, deadline, error)) {
            if (error.empty()) error = "ancestry probe ANC1 receive failed";
            break;
        }
        const std::string root_argv = exact_argv({executable,
                                                  "--fixture-privileged-broker",
                                                  endpoint.socket,
                                                  token_text(token),
                                                  std::to_string(topology.holder_netns),
                                                  scenario});
        const std::string launcher_argv = exact_argv({executable,
                                                      "--fixture-broker-launcher",
                                                      endpoint.socket,
                                                      token_text(token),
                                                      std::to_string(topology.holder_netns),
                                                      scenario});
        if (!validate_ancestry_probe_evidence(received_identity.bundle(),
                                              ancestry,
                                              root_peer,
                                              executable,
                                              topology,
                                              root_argv,
                                              launcher_argv,
                                              launch,
                                              lease,
                                              error)) {
            if (error.empty()) error = "ancestry probe semantic validation failed";
            break;
        }
        if (!endpoint_unchanged(endpoint)) {
            error = "ancestry probe endpoint identity changed";
            break;
        }
        Peer final_root_peer;
        if (control_lease_lost(root_fd) || !get_peer(root_fd, final_root_peer) ||
            final_root_peer.pid != root_peer.pid || final_root_peer.uid != root_peer.uid ||
            final_root_peer.gid != root_peer.gid) {
            error = "ancestry probe Root control lease/peer changed before release";
            break;
        }
        ancestry.close();
        received_identity.reset();
        if (!send_frame(root_fd,
                        Frame{kAncestryProbeRelease, token, {}},
                        remaining_deadline_ms(deadline))) {
            error = "ancestry probe release failed";
            break;
        }
        close(root_fd);
        root_fd = -1;
        if (!wait_group_gone(lease, kCleanupMs) || !wait_direct(launch, kCleanupMs) ||
            !launch.reaped || !WIFEXITED(launch.status) || WEXITSTATUS(launch.status) != 0 ||
            !lease.empty_group_exact() || !endpoint_unchanged(endpoint) ||
            !no_process_with_token(token_text(token))) {
            error = "ancestry probe exact Root/Launcher/group/token cleanup failed";
            break;
        }
        success = true;
    } while (false);
    if (root_fd >= 0) close(root_fd);
    if (!success) {
        if (!wait_group_gone(lease, kCleanupMs)) {
            std::string cleanup_error;
            if (!cleanup_group_lease(
                    lease, launch, has_group_authority(launch, lease), cleanup_error)) {
                if (!error.empty()) error += "; ";
                error += cleanup_error;
            }
        }
        if (!launch.reaped && lease.gone() && !wait_direct(launch, kCleanupMs)) {
            if (!error.empty()) error += "; ";
            error += "ancestry probe original child reap failed";
        }
    }
    if (launch.reaped && !lease.empty_group_exact()) {
        if (!error.empty()) error += "; ";
        error += "ancestry probe reaped before exact empty group";
        success = false;
    }
    std::string endpoint_error;
    if (!endpoint.cleanup(endpoint_error)) {
        if (!error.empty()) error += "; ";
        error += endpoint_error;
        success = false;
    }
    if (!no_process_with_token(token_text(token))) {
        if (!error.empty()) error += "; ";
        error += "ancestry probe token residue remained";
        success = false;
    }
    return success;
}

static bool parse_canonical_ipv4(const std::string& text, u32& ipv4) {
    in_addr address{};
    if (text.empty() || text.size() > INET_ADDRSTRLEN ||
        inet_pton(AF_INET, text.c_str(), &address) != 1)
        return false;
    std::array<char, INET_ADDRSTRLEN> canonical{};
    if (inet_ntop(AF_INET, &address, canonical.data(), canonical.size()) == nullptr ||
        text != canonical.data())
        return false;
    ipv4 = ntohl(address.s_addr);
    return true;
}

static bool target_socket_inode(pid_t target, int fd, u64 expected_inode) {
    if (target <= 1 || fd < 0 || expected_inode == 0u) return false;
    std::array<char, 64> link{};
    const std::string path = "/proc/" + std::to_string(target) + "/fd/" + std::to_string(fd);
    const ssize_t length = readlink(path.c_str(), link.data(), link.size() - 1u);
    if (length <= 9 || static_cast<std::size_t>(length) >= link.size()) return false;
    link[static_cast<std::size_t>(length)] = '\0';
    const std::string value(link.data(), static_cast<std::size_t>(length));
    if (value.rfind("socket:[", 0u) != 0u || value.back() != ']') return false;
    const std::string inode_text = value.substr(8u, value.size() - 9u);
    u64 inode = 0u;
    return parse_u64(inode_text.c_str(), inode) && inode == expected_inode;
}

static bool target_fd_absent(pid_t target, int fd) {
    if (target <= 1 || fd < 0) return false;
    const std::string path = "/proc/" + std::to_string(target) + "/fd/" + std::to_string(fd);
    std::array<char, 8> link{};
    errno = 0;
    return readlink(path.c_str(), link.data(), link.size()) < 0 && errno == ENOENT;
}

static bool count_target_fds(pid_t target, u64& count) {
    count = 0u;
    if (target <= 1) return false;
    const std::string path = "/proc/" + std::to_string(target) + "/fd";
    const int directory_fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) return false;
    DIR* directory = fdopendir(directory_fd);
    if (directory == nullptr) {
        close(directory_fd);
        return false;
    }
    bool ok = true;
    while (dirent* entry = readdir(directory)) {
        char* end = nullptr;
        errno = 0;
        const long value = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0') continue;
        if (errno != 0 || value < 0 || value > std::numeric_limits<int>::max() || ++count > 1024u) {
            ok = false;
            break;
        }
    }
    if (closedir(directory) != 0) ok = false;
    return ok;
}

static bool read_target_tcp_table(pid_t target,
                                  privileged_listener::ProcTcpTable& table,
                                  std::string& error) {
    std::string contents;
    privileged_listener::Diagnostic diagnostic;
    if (target <= 1 ||
        !read_file("/proc/" + std::to_string(target) + "/net/tcp",
                   contents,
                   privileged_listener::kMaxProcBytes) ||
        !privileged_listener::parse_proc_net_tcp(contents, table, diagnostic)) {
        error = "bounded target /proc/net/tcp read or parse failed";
        return false;
    }
    return true;
}

static bool observe_guard_held(const ProcIdentity& target,
                               const privileged_listener::ListenerPlan& plan,
                               const GuardReport& report,
                               std::string& error) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs);
    for (;;) {
        ProcIdentity current;
        privileged_listener::ProcTcpTable table;
        u64 fd_count = 0u;
        if (!read_proc(target.pid, current) || !same_process_identity(target, current) ||
            !target_socket_inode(
                target.pid, static_cast<int>(report.guard_fd), report.socket_inode) ||
            !count_target_fds(target.pid, fd_count) || fd_count != report.current_fd_count ||
            !read_target_tcp_table(target.pid, table, error)) {
            if (error.empty()) error = "target guard owner identity or FD inode changed";
            return false;
        }
        privileged_listener::GuardReservationEvidence evidence;
        privileged_listener::Diagnostic diagnostic;
        if (privileged_listener::classify_guard_reservation(
                table, plan, report.socket_inode, evidence, diagnostic))
            return evidence.target_owned_inode == report.socket_inode;
        if (std::chrono::steady_clock::now() >= deadline) {
            error = "target-owned guard reservation never reached exact proc evidence";
            return false;
        }
        (void)poll(nullptr, 0, 5);
    }
}

static bool observe_guard_released(const ProcIdentity& target,
                                   const privileged_listener::ListenerPlan& plan,
                                   const GuardReport& report,
                                   std::string& error) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs);
    for (;;) {
        ProcIdentity current;
        privileged_listener::ProcTcpTable table;
        u64 fd_count = 0u;
        if (!read_proc(target.pid, current) || !same_process_identity(target, current) ||
            !target_fd_absent(target.pid, static_cast<int>(report.guard_fd)) ||
            !count_target_fds(target.pid, fd_count) || fd_count != report.baseline_fd_count ||
            !read_target_tcp_table(target.pid, table, error)) {
            if (error.empty()) error = "released target guard FD or identity changed";
            return false;
        }
        privileged_listener::ListenerEvidence evidence;
        privileged_listener::Diagnostic diagnostic;
        if (privileged_listener::classify_listener_evidence(
                table,
                plan,
                {},
                privileged_listener::ListenerEvidenceKind::PortAbsent,
                evidence,
                diagnostic))
            return evidence.child_owned_inode == 0u && !evidence.guard_covered_by_listener;
        if (std::chrono::steady_clock::now() >= deadline) {
            error = "released guard selected port never reached complete proc absence";
            return false;
        }
        (void)poll(nullptr, 0, 5);
    }
}

static bool exact_listener_absent(const privileged_listener::ProcTcpTable& table,
                                  const privileged_listener::ListenerPlan& plan,
                                  u64 listener_inode) {
    for (std::size_t i = 0u; i < table.count; ++i) {
        const auto& row = table.rows[i];
        if (row.state == 0x0au && row.local_ipv4 == plan.positive_ipv4 &&
            row.local_port == plan.port)
            return false;
        if (listener_inode != 0u && row.inode == listener_inode) return false;
    }
    return true;
}

static bool regular_temp_identity(const std::string& path, u64 dev, u64 ino) {
    struct stat status{};
    return dev != 0u && ino != 0u && lstat(path.c_str(), &status) == 0 && S_ISREG(status.st_mode) &&
           (status.st_mode & 0777) == 0600 && status.st_uid == getuid() &&
           status.st_gid == getgid() && static_cast<u64>(status.st_dev) == dev &&
           static_cast<u64>(status.st_ino) == ino;
}

static bool validate_exact_witness(const ExactRutReport& report,
                                   const ExecutableLease& lease,
                                   const ParentEndpoint& endpoint,
                                   const ProcIdentity& target,
                                   const GuardReport& held,
                                   ProcIdentity& child_identity,
                                   std::string& error) {
    const std::string source_path = endpoint.directory + "/exact-listener.rut";
    const std::string log_path = endpoint.directory + "/exact-listener.log";
    const std::string expected_argv = exact_argv(
        {lease.path, source_path, "--shards", "1", "--no-pin", "--drain", "0", "--opt", "2"});
    if (report.version != kExactProtocolVersion || report.child_pid <= 1u ||
        report.child_pid > static_cast<u64>(std::numeric_limits<pid_t>::max()) ||
        report.child_ppid != static_cast<u64>(target.pid) ||
        report.child_pgid != report.child_pid || report.child_sid != static_cast<u64>(target.sid) ||
        report.child_uid != getuid() || report.child_gid != getgid() ||
        report.child_netns != target.netns || report.child_exe_dev != lease.status.st_dev ||
        report.child_exe_ino != lease.status.st_ino ||
        report.pidfd > static_cast<u64>(std::numeric_limits<int>::max()) ||
        report.pidfd_cloexec != 1u || report.listener_inode == 0u ||
        report.target_fd_count != held.current_fd_count + 1u || report.response_bytes != 65u ||
        report.response_exact != 1u || report.prompt_eof != 1u ||
        report.guard_connect_error != ECONNREFUSED || report.stable != 1u ||
        (report.backend != 1u && report.backend != 2u) || !executable_lease_unchanged(lease)) {
        error = "exact RUT witness scalar/executable evidence was invalid";
        return false;
    }
    const pid_t child = static_cast<pid_t>(report.child_pid);
    if (!read_proc(child, child_identity) || child_identity.start != report.child_start ||
        child_identity.ppid != target.pid || child_identity.pgid != child ||
        child_identity.sid != target.sid || child_identity.uid != getuid() ||
        child_identity.gid != getgid() || child_identity.supplementary_groups != 0 ||
        !child_identity.no_new_privs || !child_identity.capabilities_clear ||
        child_identity.netns != target.netns || child_identity.exe_dev != lease.status.st_dev ||
        child_identity.exe_ino != lease.status.st_ino || child_identity.exe != lease.path ||
        child_identity.cmdline != expected_argv ||
        !pidfd_link_matches(target.pid, static_cast<int>(report.pidfd)) ||
        !target_socket_inode(target.pid, static_cast<int>(held.guard_fd), held.socket_inode)) {
        error = "parent exact RUT child/pidfd/guard identity proof failed";
        return false;
    }
    privileged_listener::ProcTcpTable table;
    std::vector<u64> inodes;
    privileged_listener::ListenerEvidence evidence;
    privileged_listener::Diagnostic diagnostic;
    if (!read_process_tcp_table(child, table) || !process_socket_inodes(child, inodes) ||
        !privileged_listener::classify_listener_evidence(
            table,
            held.plan,
            inodes,
            privileged_listener::ListenerEvidenceKind::ExactPositive,
            evidence,
            diagnostic) ||
        evidence.child_owned_inode != report.listener_inode) {
        error = "parent exact positive listener inode/table ownership proof failed";
        return false;
    }
    std::string source, log;
    u64 backend = 0u;
    privileged_listener::Diagnostic source_diagnostic;
    std::string expected_source;
    u64 target_fds = 0u;
    if (!regular_temp_identity(source_path, report.source_dev, report.source_ino) ||
        !regular_temp_identity(log_path, report.log_dev, report.log_ino) ||
        !read_file(source_path, source, 4096u) ||
        !privileged_listener::build_listener_source(held.plan,
                                                    privileged_listener::ListenerSourceKind::Exact,
                                                    expected_source,
                                                    source_diagnostic) ||
        source != expected_source ||
        !read_file(log_path, log, privileged_listener::kMaxCollisionLogBytes) ||
        !exact_log_ready(log, source_path, static_cast<u16>(held.plan.port), backend) ||
        backend != report.backend || !count_target_fds(target.pid, target_fds) ||
        target_fds != report.target_fd_count) {
        error = "parent exact source/log/backend/temp/FD evidence failed";
        return false;
    }
    return true;
}

static bool validate_exact_cleaned_report(const ExactRutCleanedReport& report,
                                          const ExactRutReport& live,
                                          const ProcIdentity& child,
                                          const ParentEndpoint& endpoint,
                                          const ProcIdentity& target,
                                          const GuardReport& held,
                                          std::string& error) {
    if (report.version != kExactProtocolVersion || report.child_pid != live.child_pid ||
        report.child_start != live.child_start || report.listener_inode != live.listener_inode ||
        report.clean_exit != 1u || report.pidfd_invalidated != 1u || report.child_absent != 1u ||
        report.listener_absent != 1u || report.temps_absent != 1u ||
        report.target_fd_count != held.current_fd_count ||
        report.guard_connect_error != ECONNREFUSED || !target_gone_or_reused(child) ||
        !target_fd_absent(target.pid, static_cast<int>(live.pidfd)) ||
        !target_socket_inode(target.pid, static_cast<int>(held.guard_fd), held.socket_inode)) {
        error = "parent exact cleanup scalar/process/pidfd/guard evidence failed";
        return false;
    }
    struct stat ignored{};
    errno = 0;
    const bool source_absent =
        lstat((endpoint.directory + "/exact-listener.rut").c_str(), &ignored) < 0 &&
        errno == ENOENT;
    errno = 0;
    const bool log_absent =
        lstat((endpoint.directory + "/exact-listener.log").c_str(), &ignored) < 0 &&
        errno == ENOENT;
    privileged_listener::ProcTcpTable table;
    u64 target_fds = 0u;
    if (!source_absent || !log_absent || !read_process_tcp_table(target.pid, table) ||
        !exact_listener_absent(table, held.plan, live.listener_inode) ||
        !count_target_fds(target.pid, target_fds) || target_fds != held.current_fd_count) {
        error = "parent exact listener/temp/FD cleanup evidence failed";
        return false;
    }
    return true;
}

static bool exact_witness_mutation_self_check(const ExactRutReport& canonical,
                                              const ExecutableLease& lease,
                                              const ParentEndpoint& endpoint,
                                              const ProcIdentity& target,
                                              const GuardReport& held) {
    const auto rejects = [&](ExactRutReport mutation) {
        ProcIdentity ignored_identity;
        std::string ignored_error;
        return !validate_exact_witness(
            mutation, lease, endpoint, target, held, ignored_identity, ignored_error);
    };
    ExactRutReport mutation = canonical;
    mutation.version++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.child_start++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.child_ppid++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.child_pgid++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.child_exe_ino++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.pidfd++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.listener_inode++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.source_ino++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.log_ino++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.response_bytes--;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.response_exact = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.prompt_eof = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.guard_connect_error = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.stable = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.backend = 0u;
    return rejects(mutation);
}

static bool exact_cleaned_mutation_self_check(const ExactRutCleanedReport& canonical,
                                              const ExactRutReport& live,
                                              const ProcIdentity& child,
                                              const ParentEndpoint& endpoint,
                                              const ProcIdentity& target,
                                              const GuardReport& held) {
    const auto rejects = [&](ExactRutCleanedReport mutation) {
        std::string ignored_error;
        return !validate_exact_cleaned_report(
            mutation, live, child, endpoint, target, held, ignored_error);
    };
    ExactRutCleanedReport mutation = canonical;
    mutation.version++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.clean_exit = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.pidfd_invalidated = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.child_absent = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.listener_absent = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.temps_absent = 0u;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.target_fd_count++;
    if (!rejects(mutation)) return false;
    mutation = canonical;
    mutation.guard_connect_error = 0u;
    return rejects(mutation);
}

static WildcardAttemptPhaseV1 wildcard_phase(WildcardAttemptMode mode,
                                             WildcardAttemptPhase phase,
                                             u64 transaction_id = 0x377u) {
    return {kWildcardAttemptVersion, transaction_id, mode, phase, wildcard_phase_sequence(phase)};
}

static WildcardAttemptDecisionV1 wildcard_decision(WildcardAttemptMode mode,
                                                   WildcardAttemptDecisionKind decision,
                                                   WildcardAttemptPhase phase,
                                                   u64 sequence,
                                                   u64 transaction_id = 0x377u) {
    return {kWildcardAttemptVersion, transaction_id, mode, decision, phase, sequence};
}

static WildcardAttemptSettlementV1 wildcard_settlement(WildcardAttemptMode mode,
                                                       WildcardAttemptSettlementKind settlement,
                                                       WildcardAttemptPhase phase,
                                                       u64 sequence,
                                                       u64 transaction_id = 0x377u) {
    return {kWildcardAttemptVersion, transaction_id, mode, settlement, phase, sequence};
}

static bool wildcard_existing_frame_golden_self_check() {
    if (kGuardReserve != 35u || kGuardHeld != 36u || kGuardRelease != 37u ||
        kGuardReleased != 38u || kGuardFinish != 39u || kGuardFinished != 40u ||
        kExactRutRun != 41u || kExactRutWitness != 42u || kExactRutCleanup != 43u ||
        kExactRutCleaned != 44u || kExactRutFailure != 45u || kExactEscrowSettled != 46u ||
        kWildcardAttemptCommand != 51u || kWildcardAttemptPhase != 52u ||
        kWildcardAttemptDecision != 53u || kWildcardAttemptSettlement != 54u)
        return false;
    constexpr std::array<u16, 16u> existing_types{
        35u,
        36u,
        37u,
        38u,
        39u,
        40u,
        41u,
        42u,
        43u,
        44u,
        45u,
        46u,
        47u,
        48u,
        49u,
        50u,
    };
    Token token{};
    for (u16 type : existing_types) {
        const std::vector<unsigned char> wire = frame_bytes(Frame{type, token, {}});
        std::array<unsigned char, kHeaderBytes> golden{};
        golden[0] = 0x35u;
        golden[1] = 0x33u;
        golden[2] = 0x52u;
        golden[3] = 0x31u;
        golden[4] = 0x01u;
        golden[6] = static_cast<unsigned char>(type);
        golden[7] = static_cast<unsigned char>(type >> 8u);
        if (wire.size() != golden.size() || !std::equal(wire.begin(), wire.end(), golden.begin()))
            return false;
    }
    return true;
}

static bool same_wildcard_command(const WildcardAttemptCommandV1& left,
                                  const WildcardAttemptCommandV1& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.mode == right.mode && left.sequence == right.sequence;
}

static bool same_wildcard_phase(const WildcardAttemptPhaseV1& left,
                                const WildcardAttemptPhaseV1& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.mode == right.mode && left.phase == right.phase && left.sequence == right.sequence;
}

static bool same_wildcard_decision(const WildcardAttemptDecisionV1& left,
                                   const WildcardAttemptDecisionV1& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.mode == right.mode && left.decision == right.decision &&
           left.for_phase == right.for_phase && left.sequence == right.sequence;
}

static bool same_wildcard_settlement(const WildcardAttemptSettlementV1& left,
                                     const WildcardAttemptSettlementV1& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.mode == right.mode && left.settlement == right.settlement &&
           left.terminal_phase == right.terminal_phase && left.sequence == right.sequence;
}

template <typename Value, typename Decoder, typename Equal>
static bool rejects_without_mutating(const std::vector<unsigned char>& payload,
                                     const Value& sentinel,
                                     Decoder decoder,
                                     Equal equal) {
    Value output = sentinel;
    return !decoder(payload, output) && equal(output, sentinel);
}

constexpr WildcardAttemptCommandV1 kWildcardCommandDecodeSentinel{
    kWildcardAttemptVersion, 0x3771u, WildcardAttemptMode::WrongListenerInode, 0u};
constexpr WildcardAttemptPhaseV1 kWildcardPhaseDecodeSentinel{
    kWildcardAttemptVersion,
    0x3772u,
    WildcardAttemptMode::WrongListenerAddress,
    WildcardAttemptPhase::GuardReleased,
    9u};
constexpr WildcardAttemptDecisionV1 kWildcardDecisionDecodeSentinel{
    kWildcardAttemptVersion,
    0x3773u,
    WildcardAttemptMode::WrongListenerInode,
    WildcardAttemptDecisionKind::RejectAndCleanup,
    WildcardAttemptPhase::WildcardLive,
    11u};
constexpr WildcardAttemptSettlementV1 kWildcardSettlementDecodeSentinel{
    kWildcardAttemptVersion,
    0x3774u,
    WildcardAttemptMode::FalsePostReleaseSuccess,
    WildcardAttemptSettlementKind::MutationSettled,
    WildcardAttemptPhase::WildcardLive,
    12u};

static bool wildcard_decoder_atomic_failure_self_check(std::string& error) {
    if (!valid_wildcard_command(kWildcardCommandDecodeSentinel) ||
        !valid_wildcard_phase(kWildcardPhaseDecodeSentinel) ||
        !valid_wildcard_decision(kWildcardDecisionDecodeSentinel) ||
        !valid_wildcard_settlement(kWildcardSettlementDecodeSentinel)) {
        error = "wildcard decoder atomic-failure sentinel is not valid";
        return false;
    }

    const std::array<u64, 4u> command_fields{
        kWildcardAttemptVersion, 0x377u, static_cast<u64>(WildcardAttemptMode::Canonical), 0u};
    for (std::size_t field = 0u; field != command_fields.size(); ++field) {
        std::array<u64, 4u> invalid = command_fields;
        invalid[field] = field == 0u ? 2u : (field == 1u ? 0u : (field == 2u ? 8u : 1u));
        if (!rejects_without_mutating(encode_wildcard_fields(invalid),
                                      kWildcardCommandDecodeSentinel,
                                      decode_wildcard_command,
                                      same_wildcard_command)) {
            error = "invalid raw wildcard command mutated decoder output";
            return false;
        }
    }

    const std::array<u64, 5u> phase_fields{kWildcardAttemptVersion,
                                           0x377u,
                                           static_cast<u64>(WildcardAttemptMode::Canonical),
                                           static_cast<u64>(WildcardAttemptPhase::GuardHeld),
                                           1u};
    for (std::size_t field = 0u; field != phase_fields.size(); ++field) {
        std::array<u64, 5u> invalid = phase_fields;
        invalid[field] =
            field == 0u ? 2u : (field == 1u ? 0u : (field == 2u ? 8u : (field == 3u ? 8u : 0u)));
        if (!rejects_without_mutating(encode_wildcard_fields(invalid),
                                      kWildcardPhaseDecodeSentinel,
                                      decode_wildcard_phase,
                                      same_wildcard_phase)) {
            error = "invalid raw wildcard phase mutated decoder output";
            return false;
        }
    }

    const std::array<u64, 6u> decision_fields{
        kWildcardAttemptVersion,
        0x377u,
        static_cast<u64>(WildcardAttemptMode::Canonical),
        static_cast<u64>(WildcardAttemptDecisionKind::AuthorizeCollisionExec),
        static_cast<u64>(WildcardAttemptPhase::CollisionPrepared),
        4u};
    for (std::size_t field = 0u; field != decision_fields.size(); ++field) {
        std::array<u64, 6u> invalid = decision_fields;
        invalid[field] =
            field == 0u
                ? 2u
                : (field == 1u ? 0u
                               : (field == 2u ? 8u : (field == 3u ? 8u : (field == 4u ? 8u : 0u))));
        if (!rejects_without_mutating(encode_wildcard_fields(invalid),
                                      kWildcardDecisionDecodeSentinel,
                                      decode_wildcard_decision,
                                      same_wildcard_decision)) {
            error = "invalid raw wildcard decision mutated decoder output";
            return false;
        }
    }

    const std::array<u64, 6u> settlement_fields{
        kWildcardAttemptVersion,
        0x377u,
        static_cast<u64>(WildcardAttemptMode::Canonical),
        static_cast<u64>(WildcardAttemptSettlementKind::AttemptSettled),
        static_cast<u64>(WildcardAttemptPhase::WildcardLive),
        13u};
    for (std::size_t field = 0u; field != settlement_fields.size(); ++field) {
        std::array<u64, 6u> invalid = settlement_fields;
        invalid[field] =
            field == 0u
                ? 2u
                : (field == 1u ? 0u
                               : (field == 2u ? 8u : (field == 3u ? 3u : (field == 4u ? 8u : 0u))));
        if (!rejects_without_mutating(encode_wildcard_fields(invalid),
                                      kWildcardSettlementDecodeSentinel,
                                      decode_wildcard_settlement,
                                      same_wildcard_settlement)) {
            error = "invalid raw wildcard settlement mutated decoder output";
            return false;
        }
    }
    return true;
}

static bool wildcard_attempt_codec_self_check(std::string& error) {
    constexpr std::array<WildcardAttemptMode, 7u> modes{
        WildcardAttemptMode::Canonical,
        WildcardAttemptMode::MissingCollision,
        WildcardAttemptMode::PrematureGuardRelease,
        WildcardAttemptMode::WrongListenerKind,
        WildcardAttemptMode::WrongListenerAddress,
        WildcardAttemptMode::WrongListenerInode,
        WildcardAttemptMode::FalsePostReleaseSuccess,
    };
    constexpr std::array<WildcardAttemptPhase, 7u> phases{
        WildcardAttemptPhase::GuardHeld,
        WildcardAttemptPhase::ExactRutWitness,
        WildcardAttemptPhase::CollisionPrepared,
        WildcardAttemptPhase::CollisionRejected,
        WildcardAttemptPhase::ExactCleanedGuardHeld,
        WildcardAttemptPhase::GuardReleased,
        WildcardAttemptPhase::WildcardLive,
    };
    if (!wildcard_existing_frame_golden_self_check()) {
        error = "wildcard frame allocation changed an existing 35--50 wire header";
        return false;
    }
    if (!wildcard_decoder_atomic_failure_self_check(error)) return false;
    for (WildcardAttemptMode mode : modes) {
        WildcardAttemptCommandV1 command{kWildcardAttemptVersion, 0x377u, mode, 0u};
        WildcardAttemptCommandV1 decoded;
        if (!decode_wildcard_command(encode_wildcard_command(command), decoded) ||
            decoded.mode != mode || decoded.transaction_id != command.transaction_id) {
            error = "wildcard command closed-mode round trip failed";
            return false;
        }
    }
    for (WildcardAttemptPhase phase : phases) {
        const WildcardAttemptPhaseV1 witness =
            wildcard_phase(WildcardAttemptMode::Canonical, phase);
        WildcardAttemptPhaseV1 decoded;
        if (!decode_wildcard_phase(encode_wildcard_phase(witness), decoded) ||
            decoded.phase != phase || decoded.sequence != wildcard_phase_sequence(phase)) {
            error = "wildcard phase round trip failed";
            return false;
        }
    }
    const std::array<WildcardAttemptDecisionV1, 6u> canonical_decisions{
        wildcard_decision(WildcardAttemptMode::Canonical,
                          WildcardAttemptDecisionKind::AuthorizeCollisionExec,
                          WildcardAttemptPhase::CollisionPrepared,
                          4u),
        wildcard_decision(WildcardAttemptMode::Canonical,
                          WildcardAttemptDecisionKind::AuthorizeExactCleanup,
                          WildcardAttemptPhase::CollisionRejected,
                          6u),
        wildcard_decision(WildcardAttemptMode::Canonical,
                          WildcardAttemptDecisionKind::AuthorizeGuardRelease,
                          WildcardAttemptPhase::ExactCleanedGuardHeld,
                          8u),
        wildcard_decision(WildcardAttemptMode::Canonical,
                          WildcardAttemptDecisionKind::AuthorizeWildcardExec,
                          WildcardAttemptPhase::GuardReleased,
                          10u),
        wildcard_decision(WildcardAttemptMode::Canonical,
                          WildcardAttemptDecisionKind::AuthorizeWildcardCleanup,
                          WildcardAttemptPhase::WildcardLive,
                          12u),
        wildcard_decision(WildcardAttemptMode::Canonical,
                          WildcardAttemptDecisionKind::Finish,
                          WildcardAttemptPhase::WildcardLive,
                          14u),
    };
    for (const auto& decision : canonical_decisions) {
        WildcardAttemptDecisionV1 decoded;
        if (!decode_wildcard_decision(encode_wildcard_decision(decision), decoded) ||
            decoded.decision != decision.decision || decoded.for_phase != decision.for_phase) {
            error = "wildcard authorization round trip failed";
            return false;
        }
    }
    for (WildcardAttemptMode mode : modes) {
        if (mode == WildcardAttemptMode::Canonical) continue;
        const WildcardAttemptPhase checkpoint = wildcard_rejection_checkpoint(mode);
        const WildcardAttemptDecisionV1 rejection =
            wildcard_decision(mode,
                              WildcardAttemptDecisionKind::RejectAndCleanup,
                              checkpoint,
                              wildcard_phase_sequence(checkpoint));
        WildcardAttemptDecisionV1 decoded_decision;
        const WildcardAttemptSettlementV1 settlement =
            wildcard_settlement(mode,
                                WildcardAttemptSettlementKind::MutationSettled,
                                checkpoint,
                                wildcard_phase_sequence(checkpoint) + 1u);
        WildcardAttemptSettlementV1 decoded_settlement;
        if (!decode_wildcard_decision(encode_wildcard_decision(rejection), decoded_decision) ||
            !decode_wildcard_settlement(encode_wildcard_settlement(settlement),
                                        decoded_settlement) ||
            decoded_decision.mode != mode || decoded_settlement.mode != mode) {
            error = "wildcard mutation terminal round trip failed";
            return false;
        }
    }
    WildcardAttemptSettlementV1 canonical_settlement =
        wildcard_settlement(WildcardAttemptMode::Canonical,
                            WildcardAttemptSettlementKind::AttemptSettled,
                            WildcardAttemptPhase::WildcardLive,
                            13u);
    WildcardAttemptSettlementV1 decoded_settlement;
    if (!decode_wildcard_settlement(encode_wildcard_settlement(canonical_settlement),
                                    decoded_settlement)) {
        error = "wildcard canonical settlement round trip failed";
        return false;
    }

    WildcardAttemptCommandV1 command{
        kWildcardAttemptVersion, 0x377u, WildcardAttemptMode::Canonical, 0u};
    std::vector<unsigned char> payload = encode_wildcard_command(command);
    payload.pop_back();
    if (!rejects_without_mutating(payload,
                                  kWildcardCommandDecodeSentinel,
                                  decode_wildcard_command,
                                  same_wildcard_command)) {
        error = "truncated wildcard command was accepted or mutated decoder output";
        return false;
    }
    payload = encode_wildcard_command(command);
    payload.push_back(0u);
    if (!rejects_without_mutating(payload,
                                  kWildcardCommandDecodeSentinel,
                                  decode_wildcard_command,
                                  same_wildcard_command)) {
        error = "trailing wildcard command bytes were accepted or mutated decoder output";
        return false;
    }
    for (unsigned mutation = 0u; mutation != 4u; ++mutation) {
        WildcardAttemptCommandV1 invalid = command;
        if (mutation == 0u)
            invalid.version++;
        else if (mutation == 1u)
            invalid.transaction_id = 0u;
        else if (mutation == 2u)
            invalid.mode = static_cast<WildcardAttemptMode>(8u);
        else
            invalid.sequence = 1u;
        if (!rejects_without_mutating(encode_wildcard_command(invalid),
                                      kWildcardCommandDecodeSentinel,
                                      decode_wildcard_command,
                                      same_wildcard_command)) {
            error = "invalid wildcard command was accepted or mutated decoder output";
            return false;
        }
    }

    WildcardAttemptPhaseV1 witness =
        wildcard_phase(WildcardAttemptMode::Canonical, WildcardAttemptPhase::GuardHeld);
    payload = encode_wildcard_phase(witness);
    payload.pop_back();
    if (!rejects_without_mutating(
            payload, kWildcardPhaseDecodeSentinel, decode_wildcard_phase, same_wildcard_phase)) {
        error = "truncated wildcard phase was accepted or mutated decoder output";
        return false;
    }
    payload = encode_wildcard_phase(witness);
    payload.push_back(0u);
    if (!rejects_without_mutating(
            payload, kWildcardPhaseDecodeSentinel, decode_wildcard_phase, same_wildcard_phase)) {
        error = "trailing wildcard phase bytes were accepted or mutated decoder output";
        return false;
    }
    for (unsigned mutation = 0u; mutation != 5u; ++mutation) {
        WildcardAttemptPhaseV1 invalid = witness;
        if (mutation == 0u)
            invalid.version++;
        else if (mutation == 1u)
            invalid.transaction_id = 0u;
        else if (mutation == 2u)
            invalid.mode = static_cast<WildcardAttemptMode>(8u);
        else if (mutation == 3u)
            invalid.phase = static_cast<WildcardAttemptPhase>(8u);
        else
            invalid.sequence++;
        if (!rejects_without_mutating(encode_wildcard_phase(invalid),
                                      kWildcardPhaseDecodeSentinel,
                                      decode_wildcard_phase,
                                      same_wildcard_phase)) {
            error = "invalid wildcard phase was accepted or mutated decoder output";
            return false;
        }
    }

    WildcardAttemptDecisionV1 decision = canonical_decisions.front();
    payload = encode_wildcard_decision(decision);
    payload.pop_back();
    if (!rejects_without_mutating(payload,
                                  kWildcardDecisionDecodeSentinel,
                                  decode_wildcard_decision,
                                  same_wildcard_decision)) {
        error = "truncated wildcard decision was accepted or mutated decoder output";
        return false;
    }
    payload = encode_wildcard_decision(decision);
    payload.push_back(0u);
    if (!rejects_without_mutating(payload,
                                  kWildcardDecisionDecodeSentinel,
                                  decode_wildcard_decision,
                                  same_wildcard_decision)) {
        error = "trailing wildcard decision bytes were accepted or mutated decoder output";
        return false;
    }
    for (unsigned mutation = 0u; mutation != 7u; ++mutation) {
        WildcardAttemptDecisionV1 invalid = decision;
        if (mutation == 0u)
            invalid.version++;
        else if (mutation == 1u)
            invalid.transaction_id = 0u;
        else if (mutation == 2u)
            invalid.mode = static_cast<WildcardAttemptMode>(8u);
        else if (mutation == 3u)
            invalid.decision = static_cast<WildcardAttemptDecisionKind>(8u);
        else if (mutation == 4u)
            invalid.for_phase = static_cast<WildcardAttemptPhase>(8u);
        else if (mutation == 5u)
            invalid.for_phase = WildcardAttemptPhase::GuardHeld;
        else
            invalid.sequence++;
        if (!rejects_without_mutating(encode_wildcard_decision(invalid),
                                      kWildcardDecisionDecodeSentinel,
                                      decode_wildcard_decision,
                                      same_wildcard_decision)) {
            error = "invalid wildcard decision was accepted or mutated decoder output";
            return false;
        }
    }

    payload = encode_wildcard_settlement(canonical_settlement);
    payload.pop_back();
    if (!rejects_without_mutating(payload,
                                  kWildcardSettlementDecodeSentinel,
                                  decode_wildcard_settlement,
                                  same_wildcard_settlement)) {
        error = "truncated wildcard settlement was accepted or mutated decoder output";
        return false;
    }
    payload = encode_wildcard_settlement(canonical_settlement);
    payload.push_back(0u);
    if (!rejects_without_mutating(payload,
                                  kWildcardSettlementDecodeSentinel,
                                  decode_wildcard_settlement,
                                  same_wildcard_settlement)) {
        error = "trailing wildcard settlement bytes were accepted or mutated decoder output";
        return false;
    }
    for (unsigned mutation = 0u; mutation != 7u; ++mutation) {
        WildcardAttemptSettlementV1 invalid = canonical_settlement;
        if (mutation == 0u)
            invalid.version++;
        else if (mutation == 1u)
            invalid.transaction_id = 0u;
        else if (mutation == 2u)
            invalid.mode = static_cast<WildcardAttemptMode>(8u);
        else if (mutation == 3u)
            invalid.settlement = static_cast<WildcardAttemptSettlementKind>(3u);
        else if (mutation == 4u)
            invalid.terminal_phase = static_cast<WildcardAttemptPhase>(8u);
        else if (mutation == 5u)
            invalid.terminal_phase = WildcardAttemptPhase::GuardReleased;
        else
            invalid.sequence++;
        if (!rejects_without_mutating(encode_wildcard_settlement(invalid),
                                      kWildcardSettlementDecodeSentinel,
                                      decode_wildcard_settlement,
                                      same_wildcard_settlement)) {
            error = "invalid wildcard settlement was accepted or mutated decoder output";
            return false;
        }
    }
    return true;
}

static bool drive_wildcard_canonical(WildcardAttemptStateMachine& machine,
                                     u64 transaction_id = 0x377u) {
    const WildcardAttemptMode mode = WildcardAttemptMode::Canonical;
    return machine.begin({kWildcardAttemptVersion, transaction_id, mode, 0u}) &&
           machine.observe(wildcard_phase(mode, WildcardAttemptPhase::GuardHeld, transaction_id)) &&
           machine.observe(
               wildcard_phase(mode, WildcardAttemptPhase::ExactRutWitness, transaction_id)) &&
           machine.observe(
               wildcard_phase(mode, WildcardAttemptPhase::CollisionPrepared, transaction_id)) &&
           machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::AuthorizeCollisionExec,
                                            WildcardAttemptPhase::CollisionPrepared,
                                            4u,
                                            transaction_id)) &&
           machine.observe(
               wildcard_phase(mode, WildcardAttemptPhase::CollisionRejected, transaction_id)) &&
           machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::AuthorizeExactCleanup,
                                            WildcardAttemptPhase::CollisionRejected,
                                            6u,
                                            transaction_id)) &&
           machine.observe(
               wildcard_phase(mode, WildcardAttemptPhase::ExactCleanedGuardHeld, transaction_id)) &&
           machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::AuthorizeGuardRelease,
                                            WildcardAttemptPhase::ExactCleanedGuardHeld,
                                            8u,
                                            transaction_id)) &&
           machine.observe(
               wildcard_phase(mode, WildcardAttemptPhase::GuardReleased, transaction_id)) &&
           machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::AuthorizeWildcardExec,
                                            WildcardAttemptPhase::GuardReleased,
                                            10u,
                                            transaction_id)) &&
           machine.observe(
               wildcard_phase(mode, WildcardAttemptPhase::WildcardLive, transaction_id)) &&
           machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::AuthorizeWildcardCleanup,
                                            WildcardAttemptPhase::WildcardLive,
                                            12u,
                                            transaction_id)) &&
           machine.settle(wildcard_settlement(mode,
                                              WildcardAttemptSettlementKind::AttemptSettled,
                                              WildcardAttemptPhase::WildcardLive,
                                              13u,
                                              transaction_id)) &&
           machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::Finish,
                                            WildcardAttemptPhase::WildcardLive,
                                            14u,
                                            transaction_id)) &&
           machine.complete();
}

static bool drive_wildcard_mutation(WildcardAttemptStateMachine& machine,
                                    WildcardAttemptMode mode,
                                    u64 transaction_id = 0x377u) {
    if (mode == WildcardAttemptMode::Canonical ||
        !machine.begin({kWildcardAttemptVersion, transaction_id, mode, 0u}) ||
        !machine.observe(wildcard_phase(mode, WildcardAttemptPhase::GuardHeld, transaction_id)) ||
        !machine.observe(
            wildcard_phase(mode, WildcardAttemptPhase::ExactRutWitness, transaction_id)) ||
        !machine.observe(
            wildcard_phase(mode, WildcardAttemptPhase::CollisionPrepared, transaction_id)) ||
        !machine.decide(wildcard_decision(mode,
                                          WildcardAttemptDecisionKind::AuthorizeCollisionExec,
                                          WildcardAttemptPhase::CollisionPrepared,
                                          4u,
                                          transaction_id)))
        return false;
    const WildcardAttemptPhase checkpoint = wildcard_rejection_checkpoint(mode);
    if (checkpoint == WildcardAttemptPhase::WildcardLive &&
        (!machine.observe(
             wildcard_phase(mode, WildcardAttemptPhase::CollisionRejected, transaction_id)) ||
         !machine.decide(wildcard_decision(mode,
                                           WildcardAttemptDecisionKind::AuthorizeExactCleanup,
                                           WildcardAttemptPhase::CollisionRejected,
                                           6u,
                                           transaction_id)) ||
         !machine.observe(
             wildcard_phase(mode, WildcardAttemptPhase::ExactCleanedGuardHeld, transaction_id)) ||
         !machine.decide(wildcard_decision(mode,
                                           WildcardAttemptDecisionKind::AuthorizeGuardRelease,
                                           WildcardAttemptPhase::ExactCleanedGuardHeld,
                                           8u,
                                           transaction_id)) ||
         !machine.observe(
             wildcard_phase(mode, WildcardAttemptPhase::GuardReleased, transaction_id)) ||
         !machine.decide(wildcard_decision(mode,
                                           WildcardAttemptDecisionKind::AuthorizeWildcardExec,
                                           WildcardAttemptPhase::GuardReleased,
                                           10u,
                                           transaction_id))))
        return false;
    return machine.decide(wildcard_decision(mode,
                                            WildcardAttemptDecisionKind::RejectAndCleanup,
                                            checkpoint,
                                            wildcard_phase_sequence(checkpoint),
                                            transaction_id)) &&
           machine.settle(wildcard_settlement(mode,
                                              WildcardAttemptSettlementKind::MutationSettled,
                                              checkpoint,
                                              wildcard_phase_sequence(checkpoint) + 1u,
                                              transaction_id)) &&
           machine.mutation_rejected();
}

static bool wildcard_attempt_state_self_check(std::string& error) {
    WildcardAttemptStateMachine canonical_replay;
    if (!drive_wildcard_canonical(canonical_replay)) {
        error = "canonical wildcard state sequence was rejected";
        return false;
    }
    if (canonical_replay.observe(
            wildcard_phase(WildcardAttemptMode::Canonical, WildcardAttemptPhase::GuardHeld)) ||
        !canonical_replay.failed() || canonical_replay.complete() ||
        canonical_replay.mutation_rejected()) {
        error = "valid replay after canonical completion did not poison terminal state";
        return false;
    }
    WildcardAttemptStateMachine canonical_wrong_binding;
    if (!drive_wildcard_canonical(canonical_wrong_binding) ||
        canonical_wrong_binding.observe(wildcard_phase(
            WildcardAttemptMode::Canonical, WildcardAttemptPhase::GuardHeld, 0x378u)) ||
        !canonical_wrong_binding.failed() || canonical_wrong_binding.complete() ||
        canonical_wrong_binding.mutation_rejected()) {
        error = "wrong-bound input after canonical completion did not poison terminal state";
        return false;
    }
    for (WildcardAttemptMode mode : {WildcardAttemptMode::MissingCollision,
                                     WildcardAttemptMode::PrematureGuardRelease,
                                     WildcardAttemptMode::WrongListenerKind,
                                     WildcardAttemptMode::WrongListenerAddress,
                                     WildcardAttemptMode::WrongListenerInode,
                                     WildcardAttemptMode::FalsePostReleaseSuccess}) {
        WildcardAttemptStateMachine mutation;
        if (!drive_wildcard_mutation(mutation, mode)) {
            error = "intended wildcard mutation rejection sequence failed";
            return false;
        }
        if (!mutation.mutation_rejected() || mutation.complete() || mutation.failed()) {
            error = "wildcard mutation did not retain its initial rejection terminal state";
            return false;
        }
    }
    constexpr WildcardAttemptMode terminal_mutation_mode = WildcardAttemptMode::MissingCollision;
    constexpr WildcardAttemptPhase terminal_mutation_phase =
        WildcardAttemptPhase::CollisionRejected;
    WildcardAttemptStateMachine mutation_replay;
    if (!drive_wildcard_mutation(mutation_replay, terminal_mutation_mode) ||
        mutation_replay.settle(
            wildcard_settlement(terminal_mutation_mode,
                                WildcardAttemptSettlementKind::MutationSettled,
                                terminal_mutation_phase,
                                wildcard_phase_sequence(terminal_mutation_phase) + 1u)) ||
        !mutation_replay.failed() || mutation_replay.complete() ||
        mutation_replay.mutation_rejected()) {
        error = "valid replay after mutation rejection did not poison terminal state";
        return false;
    }
    WildcardAttemptStateMachine mutation_wrong_binding;
    if (!drive_wildcard_mutation(mutation_wrong_binding, terminal_mutation_mode) ||
        mutation_wrong_binding.settle(
            wildcard_settlement(terminal_mutation_mode,
                                WildcardAttemptSettlementKind::MutationSettled,
                                terminal_mutation_phase,
                                wildcard_phase_sequence(terminal_mutation_phase) + 1u,
                                0x378u)) ||
        !mutation_wrong_binding.failed() || mutation_wrong_binding.complete() ||
        mutation_wrong_binding.mutation_rejected()) {
        error = "wrong-bound input after mutation rejection did not poison terminal state";
        return false;
    }

    const auto new_machine_at_collision = [] {
        WildcardAttemptStateMachine machine;
        const WildcardAttemptMode mode = WildcardAttemptMode::MissingCollision;
        (void)machine.begin({kWildcardAttemptVersion, 0x377u, mode, 0u});
        (void)machine.observe(wildcard_phase(mode, WildcardAttemptPhase::GuardHeld));
        (void)machine.observe(wildcard_phase(mode, WildcardAttemptPhase::ExactRutWitness));
        (void)machine.observe(wildcard_phase(mode, WildcardAttemptPhase::CollisionPrepared));
        (void)machine.decide(wildcard_decision(mode,
                                               WildcardAttemptDecisionKind::AuthorizeCollisionExec,
                                               WildcardAttemptPhase::CollisionPrepared,
                                               4u));
        return machine;
    };
    WildcardAttemptStateMachine duplicate;
    if (!duplicate.begin({kWildcardAttemptVersion, 0x377u, WildcardAttemptMode::Canonical, 0u}) ||
        !duplicate.observe(
            wildcard_phase(WildcardAttemptMode::Canonical, WildcardAttemptPhase::GuardHeld)) ||
        duplicate.observe(
            wildcard_phase(WildcardAttemptMode::Canonical, WildcardAttemptPhase::GuardHeld)) ||
        !duplicate.failed()) {
        error = "duplicate wildcard phase did not fail closed";
        return false;
    }
    WildcardAttemptStateMachine skipped;
    if (!skipped.begin({kWildcardAttemptVersion, 0x377u, WildcardAttemptMode::Canonical, 0u}) ||
        skipped.observe(wildcard_phase(WildcardAttemptMode::Canonical,
                                       WildcardAttemptPhase::ExactRutWitness)) ||
        !skipped.failed()) {
        error = "skipped/out-of-order wildcard phase did not fail closed";
        return false;
    }
    for (unsigned mutation = 0u; mutation != 4u; ++mutation) {
        WildcardAttemptStateMachine bound;
        const WildcardAttemptMode mode = WildcardAttemptMode::Canonical;
        if (!bound.begin({kWildcardAttemptVersion, 0x377u, mode, 0u})) return false;
        WildcardAttemptPhaseV1 witness = wildcard_phase(mode, WildcardAttemptPhase::GuardHeld);
        if (mutation == 0u)
            witness.version++;
        else if (mutation == 1u)
            witness.transaction_id++;
        else if (mutation == 2u)
            witness.mode = WildcardAttemptMode::WrongListenerInode;
        else
            witness.sequence++;
        if (bound.observe(witness) || !bound.failed()) {
            error = "unbound wildcard version/transaction/mode/sequence was accepted";
            return false;
        }
    }
    WildcardAttemptStateMachine replay = new_machine_at_collision();
    if (replay.decide(wildcard_decision(WildcardAttemptMode::MissingCollision,
                                        WildcardAttemptDecisionKind::AuthorizeCollisionExec,
                                        WildcardAttemptPhase::CollisionPrepared,
                                        4u)) ||
        !replay.failed()) {
        error = "replayed wildcard authorization did not fail closed";
        return false;
    }
    WildcardAttemptStateMachine settle_before_reject = new_machine_at_collision();
    if (settle_before_reject.settle(
            wildcard_settlement(WildcardAttemptMode::MissingCollision,
                                WildcardAttemptSettlementKind::MutationSettled,
                                WildcardAttemptPhase::CollisionRejected,
                                6u)) ||
        !settle_before_reject.failed()) {
        error = "wildcard mutation settlement before rejection was accepted";
        return false;
    }
    WildcardAttemptStateMachine authorize_after_reject = new_machine_at_collision();
    if (!authorize_after_reject.decide(
            wildcard_decision(WildcardAttemptMode::MissingCollision,
                              WildcardAttemptDecisionKind::RejectAndCleanup,
                              WildcardAttemptPhase::CollisionRejected,
                              5u)) ||
        authorize_after_reject.decide(
            wildcard_decision(WildcardAttemptMode::MissingCollision,
                              WildcardAttemptDecisionKind::AuthorizeExactCleanup,
                              WildcardAttemptPhase::CollisionRejected,
                              6u)) ||
        !authorize_after_reject.failed()) {
        error = "authorization after wildcard rejection did not fail closed";
        return false;
    }
    WildcardAttemptStateMachine duplicate_command;
    WildcardAttemptCommandV1 command{
        kWildcardAttemptVersion, 0x377u, WildcardAttemptMode::Canonical, 0u};
    if (!duplicate_command.begin(command) || duplicate_command.begin(command) ||
        !duplicate_command.failed()) {
        error = "duplicate wildcard command did not fail closed";
        return false;
    }
    return true;
}

static bool wildcard_attempt_protocol_self_check(std::string& error) {
    return wildcard_attempt_codec_self_check(error) && wildcard_attempt_state_self_check(error) &&
           listener_failure_bound_self_check(error);
}

static bool guard_protocol_self_check(std::string& error) {
    constexpr u32 positive = 0x0a010203u;
    constexpr u32 guard = 0x0a010204u;
    u32 decoded_positive = 0u, decoded_guard = 0u;
    std::vector<unsigned char> request = guard_request_payload(positive, guard);
    if (kGuardReserve != 35u || kGuardHeld != 36u || kGuardRelease != 37u ||
        kGuardReleased != 38u || kGuardFinish != 39u || kGuardFinished != 40u ||
        kExactRutRun != 41u || kExactRutWitness != 42u || kExactRutCleanup != 43u ||
        kExactRutCleaned != 44u || kExactRutFailure != 45u || kExactEscrowSettled != 46u ||
        !parse_guard_request(request, decoded_positive, decoded_guard) ||
        decoded_positive != positive || decoded_guard != guard) {
        error = "private guard frame/request codec self-check failed";
        return false;
    }
    request.pop_back();
    if (parse_guard_request(request, decoded_positive, decoded_guard) ||
        parse_guard_request(
            guard_request_payload(positive, positive), decoded_positive, decoded_guard)) {
        error = "malformed guard request was accepted";
        return false;
    }
    ProcIdentity target;
    target.pid = 101;
    target.start = 202u;
    target.netns = 303u;
    GuardReport held;
    held.plan = {positive, guard, 8080u};
    held.guard_fd = 9u;
    held.socket_inode = 404u;
    held.owner_pid = 101u;
    held.owner_start = 202u;
    held.netns = 303u;
    held.baseline_fd_count = 4u;
    held.current_fd_count = 5u;
    held.family = AF_INET;
    held.socket_type = SOCK_STREAM;
    held.fd_cloexec = 1u;
    held.connect_error = ECONNREFUSED;
    GuardReport decoded;
    const std::vector<unsigned char> encoded = encode_guard_report(held);
    if (!decode_guard_report(encoded, decoded) ||
        !validate_guard_report(decoded, held.plan, target, false)) {
        error = "canonical held guard report codec/validation failed";
        return false;
    }
    const auto rejects = [&](GuardReport mutation) {
        return !validate_guard_report(mutation, held.plan, target, false);
    };
    GuardReport mutation = held;
    mutation.reuse_port = 1u;
    if (!rejects(mutation)) {
        error = "SO_REUSEPORT guard mutation was accepted";
        return false;
    }
    mutation = held;
    mutation.accept_connection = 1u;
    if (!rejects(mutation)) {
        error = "listening guard mutation was accepted";
        return false;
    }
    mutation = held;
    mutation.owner_pid++;
    if (!rejects(mutation)) {
        error = "guard owner mutation was accepted";
        return false;
    }
    mutation = held;
    mutation.current_fd_count = mutation.baseline_fd_count;
    if (!rejects(mutation)) {
        error = "held guard FD baseline mutation was accepted";
        return false;
    }
    GuardReport released = held;
    released.current_fd_count = released.baseline_fd_count;
    released.fd_invalidated = 1u;
    if (!validate_guard_report(released, held.plan, target, true)) {
        error = "canonical released guard report was rejected";
        return false;
    }
    std::vector<unsigned char> bad_version = encoded;
    bad_version.back() = 2u;
    if (decode_guard_report(bad_version, decoded)) {
        error = "unknown guard report version was accepted";
        return false;
    }
    ExecutableLease lease;
    lease.path = "/tmp/build/rut";
    lease.status.st_dev = 11;
    lease.status.st_ino = 12;
    lease.status.st_mode = S_IFREG | 0755;
    lease.status.st_uid = 1000;
    lease.status.st_gid = 1000;
    std::string decoded_path;
    struct stat decoded_status{};
    std::vector<unsigned char> lease_payload = executable_lease_payload(lease);
    if (!parse_executable_lease(lease_payload, decoded_path, decoded_status) ||
        decoded_path != lease.path || decoded_status.st_dev != lease.status.st_dev ||
        decoded_status.st_ino != lease.status.st_ino ||
        decoded_status.st_mode != lease.status.st_mode || decoded_status.st_uid != 1000u ||
        decoded_status.st_gid != 1000u) {
        error = "canonical exact executable lease codec failed";
        return false;
    }
    lease_payload.pop_back();
    if (parse_executable_lease(lease_payload, decoded_path, decoded_status)) {
        error = "truncated exact executable lease was accepted";
        return false;
    }
    lease.status.st_mode = S_IFREG | 0775;
    if (parse_executable_lease(executable_lease_payload(lease), decoded_path, decoded_status)) {
        error = "group-writable exact executable lease was accepted";
        return false;
    }
    ExactRutReport live;
    live.child_pid = 101u;
    live.child_start = 202u;
    live.listener_inode = 303u;
    live.response_bytes = 65u;
    live.response_exact = 1u;
    live.prompt_eof = 1u;
    live.guard_connect_error = ECONNREFUSED;
    live.stable = 1u;
    live.backend = 2u;
    ExactRutReport live_decoded;
    std::vector<unsigned char> live_payload = encode_exact_report(live);
    if (!decode_exact_report(live_payload, live_decoded) ||
        live_decoded.child_pid != live.child_pid ||
        live_decoded.listener_inode != live.listener_inode || live_decoded.response_bytes != 65u ||
        live_decoded.backend != 2u) {
        error = "canonical exact witness codec failed";
        return false;
    }
    live_payload.push_back(0u);
    if (decode_exact_report(live_payload, live_decoded)) {
        error = "oversized exact witness was accepted";
        return false;
    }
    live_payload = encode_exact_report(live);
    live_payload[0] = 2u;
    if (decode_exact_report(live_payload, live_decoded)) {
        error = "unknown exact witness version was accepted";
        return false;
    }
    ExactRutCleanedReport cleaned;
    cleaned.child_pid = 101u;
    cleaned.child_start = 202u;
    cleaned.listener_inode = 303u;
    cleaned.clean_exit = cleaned.pidfd_invalidated = cleaned.child_absent = 1u;
    cleaned.listener_absent = cleaned.temps_absent = 1u;
    cleaned.target_fd_count = 5u;
    cleaned.guard_connect_error = ECONNREFUSED;
    ExactRutCleanedReport cleaned_decoded;
    std::vector<unsigned char> cleaned_payload = encode_exact_cleaned(cleaned);
    if (!decode_exact_cleaned(cleaned_payload, cleaned_decoded) ||
        cleaned_decoded.child_pid != cleaned.child_pid || cleaned_decoded.clean_exit != 1u ||
        cleaned_decoded.temps_absent != 1u) {
        error = "canonical exact cleanup codec failed";
        return false;
    }
    cleaned_payload.pop_back();
    if (decode_exact_cleaned(cleaned_payload, cleaned_decoded)) {
        error = "truncated exact cleanup was accepted";
        return false;
    }
    cleaned_payload = encode_exact_cleaned(cleaned);
    cleaned_payload[0] = 2u;
    if (decode_exact_cleaned(cleaned_payload, cleaned_decoded)) {
        error = "unknown exact cleaned version was accepted";
        return false;
    }
    Token exact_token{};
    Frame cleanup{kExactRutCleanup, exact_token, exact_cleanup_payload()};
    if (!exact_cleanup_request(cleanup, exact_token)) {
        error = "canonical exact cleanup request was rejected";
        return false;
    }
    cleanup.payload.clear();
    if (exact_cleanup_request(cleanup, exact_token)) {
        error = "empty exact cleanup request was accepted";
        return false;
    }
    cleanup.payload = exact_cleanup_payload();
    cleanup.payload[0] = 2u;
    if (exact_cleanup_request(cleanup, exact_token)) {
        error = "unknown exact cleanup version was accepted";
        return false;
    }
    cleanup.payload = exact_cleanup_payload();
    cleanup.payload.push_back(0u);
    if (exact_cleanup_request(cleanup, exact_token)) {
        error = "oversized exact cleanup request was accepted";
        return false;
    }
    ExactFailureReport canonical_failure;
    canonical_failure.phase = ExactFailurePhase::ListenerLog;
    canonical_failure.error_number = EPROTO;
    canonical_failure.count = 3u;
    ExactFailureReport decoded_failure;
    std::vector<unsigned char> failure_payload = encode_exact_failure(canonical_failure);
    if (!decode_exact_failure(failure_payload, decoded_failure) ||
        decoded_failure.phase != ExactFailurePhase::ListenerLog ||
        decoded_failure.error_number != EPROTO || decoded_failure.count != 3u) {
        error = "canonical bounded exact failure codec failed";
        return false;
    }
    failure_payload[0] = 3u;
    if (decode_exact_failure(failure_payload, decoded_failure)) {
        error = "unknown exact failure version was accepted";
        return false;
    }
    failure_payload = encode_exact_failure(canonical_failure);
    std::fill(
        failure_payload.begin() + sizeof(u64), failure_payload.begin() + 2u * sizeof(u64), 0xffu);
    if (decode_exact_failure(failure_payload, decoded_failure)) {
        error = "unknown exact failure phase was accepted";
        return false;
    }
    failure_payload = encode_exact_failure(canonical_failure);
    failure_payload.pop_back();
    if (decode_exact_failure(failure_payload, decoded_failure)) {
        error = "truncated exact failure was accepted";
        return false;
    }
    failure_payload = encode_exact_failure(canonical_failure);
    failure_payload.push_back(0u);
    if (decode_exact_failure(failure_payload, decoded_failure)) {
        error = "oversized exact failure was accepted";
        return false;
    }
    canonical_failure.count = 1025u;
    if (decode_exact_failure(encode_exact_failure(canonical_failure), decoded_failure)) {
        error = "overflow exact failure count was accepted";
        return false;
    }
    canonical_failure.count = 3u;
    canonical_failure.escrow_required = 1u;
    canonical_failure.child_pid = 101u;
    canonical_failure.child_start = 102u;
    if (!decode_exact_failure(encode_exact_failure(canonical_failure), decoded_failure) ||
        decoded_failure.escrow_required != 1u || decoded_failure.child_pid != 101u ||
        decoded_failure.child_start != 102u) {
        error = "canonical escrow-marked exact failure codec failed";
        return false;
    }
    ExactFailureReport injected_failure = canonical_failure;
    injected_failure.phase = ExactFailurePhase::Cleanup;
    injected_failure.error_number = ETIMEDOUT;
    injected_failure.count = 1u;
    ExactRutReport injected_witness;
    injected_witness.child_pid = injected_failure.child_pid;
    injected_witness.child_start = injected_failure.child_start;
    if (!exact_injected_cleanup_failure(injected_failure, injected_witness)) {
        error = "canonical injected cleanup failure binding was rejected";
        return false;
    }
    for (unsigned mutation_index = 0u; mutation_index != 5u; ++mutation_index) {
        ExactFailureReport mutation = injected_failure;
        if (mutation_index == 0u)
            mutation.phase = ExactFailurePhase::ListenerLog;
        else if (mutation_index == 1u)
            mutation.error_number = EIO;
        else if (mutation_index == 2u)
            mutation.count = 0u;
        else if (mutation_index == 3u)
            mutation.child_pid++;
        else
            mutation.child_start++;
        if (exact_injected_cleanup_failure(mutation, injected_witness)) {
            error = "mutated injected cleanup failure binding was accepted";
            return false;
        }
    }
    canonical_failure.child_start = 0u;
    if (decode_exact_failure(encode_exact_failure(canonical_failure), decoded_failure)) {
        error = "incomplete escrow-marked exact failure was accepted";
        return false;
    }
    canonical_failure.child_start = 102u;
    canonical_failure.escrow_required = 2u;
    if (decode_exact_failure(encode_exact_failure(canonical_failure), decoded_failure)) {
        error = "unknown exact failure escrow state was accepted";
        return false;
    }
    ExactCustodyRecord custody;
    custody.child_pid = 101u;
    custody.child_start = 102u;
    custody.child_exe_dev = 103u;
    custody.child_exe_ino = 104u;
    custody.listener_inode = 105u;
    custody.positive_ipv4 = 0x7f000002u;
    custody.guard_ipv4 = 0x7f000003u;
    custody.port = 8080u;
    custody.guard_inode = 106u;
    custody.netns = 107u;
    custody.directory_dev = 108u;
    custody.directory_ino = 109u;
    custody.source_dev = 110u;
    custody.source_ino = 111u;
    custody.log_dev = 112u;
    custody.log_ino = 113u;
    custody.target_pid = 114u;
    custody.target_start = 115u;
    custody.has_pidfd = 1u;
    ExactCustodyRecord decoded_custody;
    std::vector<unsigned char> custody_wire = encode_exact_custody(custody, exact_token);
    if (!decode_exact_custody(custody_wire, exact_token, decoded_custody) ||
        decoded_custody.child_pid != custody.child_pid ||
        decoded_custody.guard_inode != custody.guard_inode || decoded_custody.has_pidfd != 1u) {
        error = "canonical exact custody codec failed";
        return false;
    }
    custody_wire.pop_back();
    if (decode_exact_custody(custody_wire, exact_token, decoded_custody)) {
        error = "truncated exact custody was accepted";
        return false;
    }
    custody_wire = encode_exact_custody(custody, exact_token);
    custody_wire[kTokenBytes] = 2u;
    if (decode_exact_custody(custody_wire, exact_token, decoded_custody)) {
        error = "unknown exact custody version was accepted";
        return false;
    }
    Token wrong_custody_token = exact_token;
    wrong_custody_token.bytes[0] ^= 1u;
    if (decode_exact_custody(
            encode_exact_custody(custody, wrong_custody_token), exact_token, decoded_custody)) {
        error = "wrong exact custody token was accepted";
        return false;
    }
    custody.has_pidfd = 2u;
    if (decode_exact_custody(
            encode_exact_custody(custody, exact_token), exact_token, decoded_custody)) {
        error = "overflow exact custody rights inventory was accepted";
        return false;
    }
    custody.has_pidfd = 0u;
    custody.child_reaped = 1u;
    if (!decode_exact_custody(
            encode_exact_custody(custody, exact_token), exact_token, decoded_custody) ||
        decoded_custody.child_reaped != 1u || decoded_custody.has_pidfd != 0u) {
        error = "reaped exact custody without pidfd was rejected";
        return false;
    }
    custody.has_pidfd = 1u;
    if (decode_exact_custody(
            encode_exact_custody(custody, exact_token), exact_token, decoded_custody)) {
        error = "reaped exact custody with pidfd was accepted";
        return false;
    }
    ExactSettledRecord settled;
    settled.target_pid = 114u;
    settled.child_pid = 101u;
    settled.child_start = 102u;
    settled.guard_inode = 106u;
    settled.adopted = settled.reaped = settled.listener_absent = settled.temps_absent =
        settled.guard_closed = 1u;
    settled.competing_bind_error = EADDRINUSE;
    ExactSettledRecord decoded_settled;
    std::vector<unsigned char> settled_payload = encode_exact_settled(settled);
    if (!decode_exact_settled(settled_payload, decoded_settled) ||
        decoded_settled.target_pid != settled.target_pid || decoded_settled.adopted != 1u ||
        decoded_settled.child_start != settled.child_start ||
        decoded_settled.competing_bind_error != EADDRINUSE || decoded_settled.guard_closed != 1u) {
        error = "canonical exact failure-settled codec failed";
        return false;
    }
    settled_payload.pop_back();
    if (decode_exact_settled(settled_payload, decoded_settled)) {
        error = "truncated exact failure-settled record was accepted";
        return false;
    }
    settled_payload = encode_exact_settled(settled);
    settled_payload[0] = 3u;
    if (decode_exact_settled(settled_payload, decoded_settled)) {
        error = "unknown exact failure-settled version was accepted";
        return false;
    }
    settled.guard_closed = 2u;
    if (decode_exact_settled(encode_exact_settled(settled), decoded_settled)) {
        error = "overflow exact failure-settled state was accepted";
        return false;
    }
    settled.guard_closed = 1u;
    ExactFailureReport settled_failure;
    settled_failure.escrow_required = 1u;
    settled_failure.child_pid = settled.child_pid;
    settled_failure.child_start = settled.child_start;
    if (!exact_settlement_matches_failure(settled, settled_failure)) {
        error = "matching exact failure settlement was rejected";
        return false;
    }
    ++settled.child_start;
    if (exact_settlement_matches_failure(settled, settled_failure)) {
        error = "mismatched exact failure settlement PID-start was accepted";
        return false;
    }
    --settled.child_start;
    if (!exact_settlement_complete(settled, 114, 106u)) {
        error = "complete exact failure settlement was rejected";
        return false;
    }
    for (unsigned mutation_index = 0u; mutation_index != 7u; ++mutation_index) {
        ExactSettledRecord mutation = settled;
        switch (mutation_index) {
            case 0u:
                mutation.target_pid++;
                break;
            case 1u:
                mutation.guard_inode++;
                break;
            case 2u:
                mutation.adopted = 0u;
                break;
            case 3u:
                mutation.reaped = 0u;
                break;
            case 4u:
                mutation.listener_absent = 0u;
                break;
            case 5u:
                mutation.temps_absent = 0u;
                break;
            default:
                mutation.competing_bind_error = 0u;
                break;
        }
        if (exact_settlement_complete(mutation, 114, 106u)) {
            error = "incomplete exact failure settlement mutation was accepted";
            return false;
        }
    }
    ExactSettledRecord open_guard = settled;
    open_guard.guard_closed = 0u;
    if (exact_settlement_complete(open_guard, 114, 106u)) {
        error = "open exact failure guard mutation was accepted";
        return false;
    }
    ExactFailureIntegrationStage integration_stage = ExactFailureIntegrationStage::Failure;
    if (!advance_exact_failure_integration(integration_stage, kExactRutFailure) ||
        advance_exact_failure_integration(integration_stage, kExactRutCleaned) ||
        advance_exact_failure_integration(integration_stage, kGuardRelease) ||
        advance_exact_failure_integration(integration_stage, kGuardReleased) ||
        !advance_exact_failure_integration(integration_stage, kExactEscrowSettled) ||
        !advance_exact_failure_integration(integration_stage, kTargetExited) ||
        integration_stage != ExactFailureIntegrationStage::Complete) {
        error = "exact failure frame45/46/TargetExited ordering policy failed";
        return false;
    }
    const int current_directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const std::string absent_temp = ".rut-exact-absent-" + std::to_string(getpid());
    if (current_directory < 0 ||
        validate_escrow_temp(
            current_directory, absent_temp.c_str(), 1u, 1u, getuid(), getgid(), false) ||
        !validate_escrow_temp(
            current_directory, absent_temp.c_str(), 1u, 1u, getuid(), getgid(), true)) {
        if (current_directory >= 0) close(current_directory);
        error = "exact live/reaped temporary absence policy failed";
        return false;
    }
    close(current_directory);
    return true;
}

static bool run_session(const std::string& sudo_path,
                        const std::string& nsenter_path,
                        const std::string& executable,
                        const ExecutableLease& rut_executable,
                        const HeldTopologySnapshot& topology,
                        const char* scenario,
                        std::string& error) {
    ParentEndpoint endpoint;
    Token token;
    if (!new_token(token) || !create_parent_endpoint(endpoint, error)) return false;
    std::optional<DirectLaunch> direct_launch;
    std::optional<GroupLease> group_lease;
    std::chrono::steady_clock::time_point hello_deadline;
    std::string launch_error;
    if (!begin_launch(sudo_path,
                      nsenter_path,
                      executable,
                      topology,
                      endpoint,
                      token,
                      scenario,
                      kBrokerDeadlineMs,
                      direct_launch,
                      group_lease,
                      hello_deadline,
                      launch_error)) {
        error = "sudo/nsenter launch failed: " + launch_error;
        if (direct_launch) error += "; " + direct_launch_diagnostic(*direct_launch);
        if (direct_launch && group_lease) {
            std::string cleanup_error;
            if (!cleanup_group_lease(*group_lease,
                                     *direct_launch,
                                     has_group_authority(*direct_launch, *group_lease),
                                     cleanup_error) ||
                !group_lease->gone()) {
                if (!error.empty()) error += "; ";
                error +=
                    cleanup_error.empty() ? "direct launch group cleanup failed" : cleanup_error;
            }
        }
        return false;
    }
    DirectLaunch& sudo_child = *direct_launch;
    GroupLease& launch_lease = *group_lease;
    int root_fd = -1, broker_fd = -1, target_fd = -1;
    Report root_report, broker_report, target_report;
    Peer root_peer, broker_peer, target_peer;
    ProcIdentity root_proc, launcher_proc, broker_proc, target_proc;
    Token root_frame_token;
    identity_bundle::ReceivedBundle received_identity;
    ancestry_bundle::AncestryBundle initial_ancestry;
    ancestry_bundle::AncestryBundle final_ancestry;
    bool success = false;
    bool broker_lifecycle_complete = false;
    do {
        const bool root_hello_ok = await_root_hello(endpoint,
                                                    sudo_child,
                                                    token,
                                                    hello_deadline,
                                                    root_fd,
                                                    root_peer,
                                                    root_report,
                                                    root_frame_token,
                                                    received_identity,
                                                    initial_ancestry,
                                                    error);
        const std::string root_argv = exact_argv({executable,
                                                  "--fixture-privileged-broker",
                                                  endpoint.socket,
                                                  token_text(token),
                                                  std::to_string(topology.holder_netns),
                                                  scenario});
        const std::string launcher_argv = exact_argv({executable,
                                                      "--fixture-broker-launcher",
                                                      endpoint.socket,
                                                      token_text(token),
                                                      std::to_string(topology.holder_netns),
                                                      scenario});
        const DestructiveAuth destructive_auth = authorize_destructive_close(endpoint,
                                                                             root_report,
                                                                             root_peer,
                                                                             token,
                                                                             root_frame_token,
                                                                             topology,
                                                                             executable,
                                                                             root_argv,
                                                                             launcher_argv,
                                                                             sudo_child);
        if (!root_hello_ok || !destructive_auth.valid) {
            if (error.empty()) error = "root broker HELLO/peer identity failed";
            received_identity.reset();
            break;
        }
        const std::string dropped_argv = exact_argv({executable,
                                                     "--fixture-privileged-dropped-broker",
                                                     endpoint.socket,
                                                     token_text(token),
                                                     std::to_string(topology.holder_netns),
                                                     scenario,
                                                     std::to_string(kCredentialFd)});
        std::string identity_error;
        AuthorizationSnapshot initial_snapshot;
        if (!validate_formal_ancestry_snapshot(received_identity.bundle(),
                                               initial_ancestry,
                                               root_peer,
                                               executable,
                                               topology,
                                               root_argv,
                                               launcher_argv,
                                               sudo_child,
                                               launch_lease,
                                               initial_snapshot,
                                               identity_error)) {
            error = "root broker initial ancestry validation failed: " + identity_error;
            break;
        }
        const RetainedAnchorEvidence* retained_anchor_ptr = &initial_snapshot.retained_anchor;
        const bool semantic_baseline_ok =
            validate_received_identity_bundle(received_identity.bundle(),
                                              root_report,
                                              root_peer,
                                              topology,
                                              executable,
                                              root_argv,
                                              launcher_argv,
                                              retained_anchor_ptr,
                                              sudo_child,
                                              root_proc,
                                              launcher_proc,
                                              identity_error);
        const bool endpoint_ok = semantic_baseline_ok && endpoint_unchanged(endpoint);
        MutationDiagnostic mutation_diagnostic;
        if (semantic_baseline_ok && endpoint_ok && strcmp(scenario, "normal") == 0)
            mutation_diagnostic = live_identity_bundle_mutation_checks(received_identity.bundle(),
                                                                       root_report,
                                                                       root_peer,
                                                                       topology,
                                                                       executable,
                                                                       root_argv,
                                                                       launcher_argv,
                                                                       retained_anchor_ptr,
                                                                       sudo_child);
        if (!semantic_baseline_ok || !endpoint_ok ||
            (strcmp(scenario, "normal") == 0 && !mutation_diagnostic.success)) {
            if (!semantic_baseline_ok)
                identity_error =
                    "baseline.semantic: " +
                    (identity_error.empty() ? "full identity validation failed" : identity_error);
            else if (!endpoint_ok)
                identity_error = "endpoint.stability: endpoint identity changed";
            else if (semantic_baseline_ok && !mutation_diagnostic.failed_label.empty())
                identity_error = mutation_diagnostic.failed_label + std::string(": ") +
                                 mutation_diagnostic.detail;
            error = "root broker bundle provenance validation failed: " + identity_error + "; " +
                    direct_launch_diagnostic(sudo_child);
            error +=
                "; " + retained_wrapper_diagnostic(sudo_child,
                                                   launch_lease,
                                                   initial_snapshot.retained_anchor,
                                                   received_identity.bundle().roles[0].manifest);
            received_identity.reset();
            break;
        }
        if (!send_frame(root_fd,
                        Frame{kFinalAncestryRequest, token, {}},
                        remaining_deadline_ms(hello_deadline)) ||
            !ancestry_bundle::receive_bundle(
                root_fd, final_ancestry, hello_deadline, identity_error)) {
            error = "root broker final ancestry request/receive failed: " + identity_error;
            break;
        }
        AuthorizationSnapshot final_snapshot;
        Peer final_root_peer;
        DirectLaunch final_launch = sudo_child;
        const bool final_authorized =
            validate_formal_ancestry_snapshot(received_identity.bundle(),
                                              final_ancestry,
                                              root_peer,
                                              executable,
                                              topology,
                                              root_argv,
                                              launcher_argv,
                                              final_launch,
                                              launch_lease,
                                              final_snapshot,
                                              identity_error) &&
            validate_received_identity_bundle(received_identity.bundle(),
                                              root_report,
                                              root_peer,
                                              topology,
                                              executable,
                                              root_argv,
                                              launcher_argv,
                                              &final_snapshot.retained_anchor,
                                              final_launch,
                                              root_proc,
                                              launcher_proc,
                                              identity_error) &&
            same_authorization_snapshot(initial_snapshot, final_snapshot) &&
            retained_lease_matches_snapshot(launch_lease, final_launch, final_snapshot) &&
            !control_lease_lost(root_fd) && get_peer(root_fd, final_root_peer) &&
            final_root_peer.pid == root_peer.pid && final_root_peer.uid == root_peer.uid &&
            final_root_peer.gid == root_peer.gid && endpoint_unchanged(endpoint);
        if (!final_authorized && identity_error.empty())
            identity_error = "final authorization evidence changed";
        const AuthorizationEmission emission =
            emit_authorization_frames(root_fd, final_authorized, token, hello_deadline);
        if (emission != AuthorizationEmission::Sent) {
            if (emission == AuthorizationEmission::Rejected)
                error = "root broker final pre-ACK authorization failed: " + identity_error;
            else if (emission == AuthorizationEmission::AckFailed)
                error = "identity bundle ACK frame failed";
            else
                error = "caller credential frame failed after identity bundle ACK";
            break;
        }
        received_identity.reset();
        initial_ancestry.close();
        final_ancestry.close();
        const auto dropped_failure = [&](const char* label) {
            error = std::string("dropped broker identity transition failed: ") + label;
        };
        if (!accept_bounded(endpoint.listener, broker_fd)) {
            dropped_failure("accept");
            break;
        }
        if (!get_peer(broker_fd, broker_peer)) {
            dropped_failure("peercred");
            break;
        }
        Frame dropped_frame;
        if (!receive_frame(broker_fd, dropped_frame, kHandshakeMs)) {
            dropped_failure("frame.receive");
            break;
        }
        if (dropped_frame.type != kBrokerDropped) {
            dropped_failure("frame.type");
            break;
        }
        if (!token_equal(dropped_frame.token, token)) {
            dropped_failure("frame.token");
            break;
        }
        if (!decode_report(dropped_frame.payload, broker_report)) {
            dropped_failure("report.decode");
            break;
        }
        if (broker_peer.pid <= 1 || broker_peer.pid == root_peer.pid ||
            broker_peer.uid != getuid() || broker_peer.gid != getgid() ||
            broker_report.target_pid != static_cast<u64>(broker_peer.pid)) {
            dropped_failure("peer.distinct_root");
            break;
        }
        if (!send_frame(broker_fd, Frame{kDroppedIdentityRequest, token, {}}, kHandshakeMs)) {
            dropped_failure("proof.request.send");
            break;
        }
        identity_bundle::RoleBundle received_dropped;
        std::string dropped_identity_error;
        if (!identity_bundle::receive_dropped_role(
                broker_fd,
                received_dropped,
                std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs),
                dropped_identity_error)) {
            dropped_failure("proof.receive");
            error += ": " + dropped_identity_error;
            break;
        }
        identity_bundle::DroppedIdentityEvidence dropped_evidence;
        if (!identity_bundle::extract_dropped_identity_evidence(
                received_dropped, dropped_evidence, dropped_identity_error)) {
            dropped_failure("proof.extract");
            error += ": " + dropped_identity_error;
            break;
        }
        Peer root_control_peer;
        const bool root_control_ok =
            !control_lease_lost(root_fd) && get_peer(root_fd, root_control_peer) &&
            root_control_peer.pid == root_peer.pid && root_control_peer.uid == root_peer.uid &&
            root_control_peer.gid == root_peer.gid;
        const bool dropped_endpoint_ok = endpoint_unchanged(endpoint);
        std::string dropped_binding_error;
        if (!validate_dropped_identity_binding(dropped_evidence,
                                               broker_report,
                                               broker_peer,
                                               root_peer,
                                               root_proc,
                                               topology,
                                               executable,
                                               dropped_argv,
                                               getuid(),
                                               getgid(),
                                               root_control_ok,
                                               dropped_endpoint_ok,
                                               dropped_binding_error)) {
            dropped_failure(root_control_ok
                                ? (dropped_endpoint_ok ? "proof.cross_bind" : "endpoint.stability")
                                : "root.lease");
            error += ": " + dropped_binding_error;
            break;
        }
        if (strcmp(scenario, "normal") == 0) {
            const MutationDiagnostic dropped_mutations =
                dropped_identity_mutation_checks(dropped_evidence,
                                                 broker_report,
                                                 broker_peer,
                                                 root_peer,
                                                 root_proc,
                                                 topology,
                                                 executable,
                                                 dropped_argv,
                                                 getuid(),
                                                 getgid());
            if (!dropped_mutations.success) {
                dropped_failure("proof.mutation");
                error += ": " + dropped_mutations.failed_label + ": " + dropped_mutations.detail;
                break;
            }
        }
        // Re-extract from the same received descriptors immediately before the
        // sole target authorization.  This is the final FD-backed proof; no
        // report or parent /proc read is substituted for it.
        identity_bundle::DroppedIdentityEvidence final_dropped_evidence;
        if (!identity_bundle::extract_dropped_identity_evidence(
                received_dropped, final_dropped_evidence, dropped_identity_error)) {
            dropped_failure("proof.final_extract");
            error += ": " + dropped_identity_error;
            break;
        }
        Peer final_broker_peer;
        if (!get_peer(broker_fd, final_broker_peer) || final_broker_peer.pid != broker_peer.pid ||
            final_broker_peer.uid != broker_peer.uid || final_broker_peer.gid != broker_peer.gid) {
            dropped_failure("proof.final_peer");
            break;
        }
        const bool final_root_control_ok =
            !control_lease_lost(root_fd) && get_peer(root_fd, root_control_peer) &&
            root_control_peer.pid == root_peer.pid && root_control_peer.uid == root_peer.uid &&
            root_control_peer.gid == root_peer.gid;
        if (!validate_dropped_identity_binding(final_dropped_evidence,
                                               broker_report,
                                               final_broker_peer,
                                               root_peer,
                                               root_proc,
                                               topology,
                                               executable,
                                               dropped_argv,
                                               getuid(),
                                               getgid(),
                                               final_root_control_ok,
                                               endpoint_unchanged(endpoint),
                                               dropped_binding_error)) {
            dropped_failure(final_root_control_ok ? "proof.final_cross_bind" : "root.lease");
            error += ": " + dropped_binding_error;
            break;
        }
        broker_proc = proc_from_dropped_evidence(final_dropped_evidence, executable);
        received_dropped.close();
        if (!send_frame(broker_fd, Frame{kLaunchTarget, token, {}}, kHandshakeMs) ||
            !accept_bounded(endpoint.listener, target_fd)) {
            error = "target launch/connection failed";
            break;
        }
        const std::string target_argv = exact_argv({executable,
                                                    "--fixture-privileged-target",
                                                    endpoint.socket,
                                                    token_text(token),
                                                    std::to_string(broker_peer.pid),
                                                    scenario});
        if (strcmp(scenario, "no-ready") == 0) {
            if (!get_peer(target_fd, target_peer) || !read_proc(target_peer.pid, target_proc) ||
                target_peer.uid != getuid() || target_peer.gid != getgid() ||
                target_proc.ppid != broker_peer.pid || target_proc.pgid != target_proc.pid ||
                target_proc.netns != topology.holder_netns || target_proc.cmdline != target_argv ||
                target_proc.supplementary_groups != 0 || !target_proc.no_new_privs ||
                !target_proc.capabilities_clear) {
                error = "no-ready target exact secured identity failed";
                break;
            }
        } else if (!decode_ready(target_fd, kReady, token, target_peer, target_report) ||
                   !read_proc(target_peer.pid, target_proc)) {
            error = "target READY/peer identity failed";
            break;
        } else {
            if (!identity_matches_report(target_report,
                                         target_peer,
                                         target_proc,
                                         executable,
                                         target_argv,
                                         "privileged-target",
                                         token,
                                         token,
                                         true,
                                         false,
                                         true) ||
                target_proc.ppid != broker_peer.pid || target_peer.pid == root_peer.pid ||
                target_peer.pid == broker_peer.pid || target_peer.pid == sudo_child.anchor.pid ||
                target_peer.pid == static_cast<pid_t>(root_report.wrapper_pid) ||
                target_proc.netns != topology.holder_netns) {
                error = "target exact secured identity failed";
                break;
            }
            if (strcmp(scenario, "normal") == 0) {
                const MutationDiagnostic causal = causal_mutation_self_checks(root_report,
                                                                              root_peer,
                                                                              root_proc,
                                                                              launcher_proc,
                                                                              broker_report,
                                                                              broker_peer,
                                                                              broker_proc,
                                                                              target_report,
                                                                              target_peer,
                                                                              target_proc,
                                                                              topology,
                                                                              executable,
                                                                              root_argv,
                                                                              launcher_argv,
                                                                              dropped_argv,
                                                                              target_argv,
                                                                              token,
                                                                              sudo_child,
                                                                              retained_anchor_ptr,
                                                                              endpoint);
                if (!causal.success) {
                    error =
                        "broker/target causal mutation self-check failed: " + causal.failed_label +
                        ": " + causal.detail;
                    break;
                }
            }
        }
        Frame security_trace;
        if (!receive_frame(broker_fd, security_trace, kHandshakeMs) ||
            security_trace.type != kSecurityTrace || !token_equal(security_trace.token, token) ||
            !valid_security_trace(security_trace.payload)) {
            error = "target security transition trace was not exact";
            break;
        }
        if (strcmp(scenario, "no-ready") == 0 || strcmp(scenario, "ready-loss") == 0) {
            close(target_fd);
            target_fd = -1;
        } else if (strcmp(scenario, "normal") == 0) {
            Frame pong, released;
            if (!send_frame(target_fd, Frame{kPing, token, {}}, kHandshakeMs) ||
                !receive_frame(target_fd, pong, kHandshakeMs) || pong.type != kPong ||
                !send_frame(target_fd, Frame{kRelease, token, {}}, kHandshakeMs) ||
                !receive_frame(target_fd, released, kHandshakeMs) || released.type != kReleased) {
                error = "target PING/PONG/release failed";
                break;
            }
        } else if (canonical_collision_scenario(scenario)) {
            if (!run_canonical_collision_release_parent(
                    target_fd, token, topology, rut_executable.path, target_proc, error))
                break;
        } else if (listener_scenario_name(scenario)) {
            u32 positive_ipv4 = 0u, guard_ipv4 = 0u;
            if (!parse_canonical_ipv4(topology.positive_ip, positive_ipv4) ||
                !parse_canonical_ipv4(topology.guard_ip, guard_ipv4)) {
                error = "held topology listener addresses were not canonical IPv4";
                break;
            }
            Frame held_frame;
            GuardReport held;
            if (!send_frame(
                    target_fd,
                    Frame{kGuardReserve, token, guard_request_payload(positive_ipv4, guard_ipv4)},
                    kHandshakeMs) ||
                !receive_frame(target_fd, held_frame, kBrokerDeadlineMs) ||
                held_frame.type != kGuardHeld || !token_equal(held_frame.token, token) ||
                !decode_guard_report(held_frame.payload, held)) {
                error = "secured target guard reservation/report failed";
                break;
            }
            const privileged_listener::ListenerPlan plan{positive_ipv4, guard_ipv4, held.plan.port};
            if (!validate_guard_report(held, plan, target_proc, false) ||
                !observe_guard_held(target_proc, plan, held, error)) {
                if (error.empty()) error = "held guard report/proc evidence was invalid";
                break;
            }
            Frame exact_frame;
            ExactRutReport exact_report;
            ProcIdentity exact_child;
            if (!executable_lease_unchanged(rut_executable) ||
                !send_frame(target_fd,
                            Frame{kExactRutRun, token, executable_lease_payload(rut_executable)},
                            kHandshakeMs) ||
                !receive_frame(target_fd, exact_frame, kListenerDeadlineMs)) {
                error = "exact public-RUT run/witness transport failed";
                break;
            }
            if (exact_frame.type == kExactRutFailure && token_equal(exact_frame.token, token)) {
                ExactFailureReport failure;
                if (!decode_exact_failure(exact_frame.payload, failure)) {
                    error = "exact public-RUT returned malformed bounded failure evidence";
                } else {
                    error = "exact public-RUT failed at phase " +
                            std::string(exact_failure_phase_name(failure.phase)) +
                            " errno=" + std::to_string(failure.error_number) +
                            " count=" + std::to_string(failure.count);
                }
                (void)receive_failed_target_lifecycle(
                    broker_fd, token, target_proc.pid, failure, held.socket_inode, error);
                break;
            }
            if (exact_frame.type != kExactRutWitness || !token_equal(exact_frame.token, token) ||
                !decode_exact_report(exact_frame.payload, exact_report) ||
                !validate_exact_witness(exact_report,
                                        rut_executable,
                                        endpoint,
                                        target_proc,
                                        held,
                                        exact_child,
                                        error) ||
                !exact_witness_mutation_self_check(
                    exact_report, rut_executable, endpoint, target_proc, held)) {
                if (error.empty()) error = "exact public-RUT run/witness evidence failed";
                break;
            }
            Frame exact_cleaned_frame;
            ExactRutCleanedReport exact_cleaned;
            if (!send_frame(target_fd,
                            Frame{kExactRutCleanup, token, exact_cleanup_payload()},
                            kHandshakeMs) ||
                !receive_frame(
                    target_fd, exact_cleaned_frame, cleanup_response_wait_ms(scenario))) {
                error = "exact public-RUT cleanup transport failed";
                break;
            }
            if (listener_failure_integration(scenario)) {
                ExactFailureReport failure;
                ExactFailureIntegrationStage integration_stage =
                    ExactFailureIntegrationStage::Failure;
                if (!advance_exact_failure_integration(integration_stage,
                                                       exact_cleaned_frame.type) ||
                    !token_equal(exact_cleaned_frame.token, token) ||
                    !decode_exact_failure(exact_cleaned_frame.payload, failure) ||
                    !exact_injected_cleanup_failure(failure, exact_report)) {
                    error = "injected cleanup failure evidence was malformed or misbound";
                    break;
                }
                const auto target_eof_deadline = std::chrono::steady_clock::now() +
                                                 std::chrono::milliseconds(kListenerDeadlineMs);
                if (!wait_control_eof(target_fd, target_eof_deadline)) {
                    error = "injected failure Target EOF was missing or out of order";
                    break;
                }
                close(target_fd);
                target_fd = -1;
                if (observe_exact_liveness(root_proc) != ExactLiveness::Live) {
                    error = "exact Root PID/start was not live before deliberate loss";
                    break;
                }
                const auto pre_root_loss_deadline =
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
                if (!observe_quiet_broker_while_root_live(
                        broker_fd, root_proc, pre_root_loss_deadline)) {
                    error = "frame46/broker event preceded deliberate exact Root loss";
                    break;
                }
                close(root_fd);
                root_fd = -1;
                const auto root_loss_deadline = std::chrono::steady_clock::now() +
                                                std::chrono::milliseconds(kListenerDeadlineMs);
                if (!wait_identity_gone_or_reused_until(root_proc, root_loss_deadline)) {
                    error = "exact Root PID/start survived deliberate lease loss";
                    break;
                }
                if (!receive_failed_target_lifecycle(broker_fd,
                                                     token,
                                                     target_proc.pid,
                                                     failure,
                                                     held.socket_inode,
                                                     error,
                                                     &integration_stage) ||
                    integration_stage != ExactFailureIntegrationStage::Complete) {
                    if (error.empty())
                        error = "injected failure settlement/exit lifecycle was incomplete";
                    break;
                }
                broker_lifecycle_complete = true;
            } else {
                if (exact_cleaned_frame.type == kExactRutFailure &&
                    token_equal(exact_cleaned_frame.token, token)) {
                    ExactFailureReport failure;
                    if (decode_exact_failure(exact_cleaned_frame.payload, failure))
                        error = "exact public-RUT failed at phase " +
                                std::string(exact_failure_phase_name(failure.phase)) +
                                " errno=" + std::to_string(failure.error_number) +
                                " count=" + std::to_string(failure.count);
                    else
                        error = "exact public-RUT returned malformed cleanup failure evidence";
                    (void)receive_failed_target_lifecycle(
                        broker_fd, token, target_proc.pid, failure, held.socket_inode, error);
                    break;
                }
                if (exact_cleaned_frame.type != kExactRutCleaned ||
                    !token_equal(exact_cleaned_frame.token, token) ||
                    !decode_exact_cleaned(exact_cleaned_frame.payload, exact_cleaned) ||
                    !validate_exact_cleaned_report(exact_cleaned,
                                                   exact_report,
                                                   exact_child,
                                                   endpoint,
                                                   target_proc,
                                                   held,
                                                   error) ||
                    !exact_cleaned_mutation_self_check(
                        exact_cleaned, exact_report, exact_child, endpoint, target_proc, held) ||
                    !observe_guard_held(target_proc, plan, held, error)) {
                    if (error.empty())
                        error = "exact public-RUT cleanup/guard-held evidence failed";
                    break;
                }
                Frame released_frame;
                GuardReport released;
                if (!send_frame(target_fd, Frame{kGuardRelease, token, {}}, kHandshakeMs) ||
                    !receive_frame(target_fd, released_frame, kBrokerDeadlineMs) ||
                    released_frame.type != kGuardReleased ||
                    !token_equal(released_frame.token, token) ||
                    !decode_guard_report(released_frame.payload, released) ||
                    !validate_guard_report(released, plan, target_proc, true) ||
                    released.guard_fd != held.guard_fd ||
                    released.socket_inode != held.socket_inode ||
                    released.baseline_fd_count != held.baseline_fd_count ||
                    released.owner_pid != held.owner_pid ||
                    released.owner_start != held.owner_start || released.netns != held.netns ||
                    !observe_guard_released(target_proc, plan, released, error)) {
                    if (error.empty()) error = "released guard report/proc/FD evidence was invalid";
                    break;
                }
                Frame finished;
                if (!send_frame(target_fd, Frame{kGuardFinish, token, {}}, kHandshakeMs) ||
                    !receive_frame(target_fd, finished, kHandshakeMs) ||
                    !exact_request(finished, kGuardFinished, token)) {
                    error = "guard lifecycle final release handshake failed";
                    break;
                }
            }
        } else if (strcmp(scenario, "term-ignore") == 0) {
            if (!safe_signal_target(target_report, target_peer, target_proc, SIGTERM)) {
                error = "TERM-ignore identity-safe TERM failed";
                break;
            }
            (void)poll(nullptr, 0, kCleanupMs);
            if (!process_alive(target_peer.pid) ||
                !safe_signal_target(target_report, target_peer, target_proc, SIGKILL)) {
                error = "TERM-ignore did not require revalidated KILL";
                break;
            }
        } else if (strcmp(scenario, "broker-early") == 0) {
            if (!send_frame(broker_fd, Frame{kBrokerExitEarly, token, {}}, kHandshakeMs)) {
                error = "broker early-death trigger failed";
                break;
            }
            close(broker_fd);
            broker_fd = -1;
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
            ExactLiveness target_liveness = observe_exact_liveness(target_proc);
            while (target_liveness == ExactLiveness::Live &&
                   std::chrono::steady_clock::now() < deadline) {
                (void)poll(nullptr, 0, 10);
                target_liveness = observe_exact_liveness(target_proc);
            }
            if (target_liveness != ExactLiveness::ExitedOrReused) {
                error = "broker death left live target";
                break;
            }
        } else if (strcmp(scenario, "broker-lease-loss") == 0) {
            close(target_fd);
            target_fd = -1;
            close(broker_fd);
            broker_fd = -1;
        }
        if (broker_fd >= 0 && !broker_lifecycle_complete && strcmp(scenario, "broker-early") != 0 &&
            strcmp(scenario, "broker-lease-loss") != 0) {
            Frame exited, released;
            if (!receive_frame(broker_fd, exited, kHandshakeMs) || exited.type != kTargetExited ||
                exited.payload.size() != 4 ||
                !send_frame(broker_fd, Frame{kRelease, token, {}}, kHandshakeMs) ||
                !receive_frame(broker_fd, released, kHandshakeMs) || released.type != kReleased) {
                error = "broker target-exit/release lifecycle failed";
                break;
            }
            const int target_status = static_cast<int>(exited.payload[0]) |
                                      (static_cast<int>(exited.payload[1]) << 8) |
                                      (static_cast<int>(exited.payload[2]) << 16) |
                                      (static_cast<int>(exited.payload[3]) << 24);
            const bool expected_status =
                (strcmp(scenario, "term-ignore") == 0 ||
                 strcmp(scenario, "owned-wait-term-ignore") == 0)
                    ? WIFSIGNALED(target_status) && WTERMSIG(target_status) == SIGKILL
                    : WIFEXITED(target_status) && WEXITSTATUS(target_status) == 0;
            if (!expected_status) {
                error = "broker reported an unexpected exact target status";
                break;
            }
        }
        const int group_gone_timeout =
            listener_failure_integration(scenario) ? kListenerDeadlineMs : kCleanupMs;
        if (!wait_group_gone(launch_lease, group_gone_timeout) ||
            !launcher_gone_or_wnowait(sudo_child) || !endpoint_unchanged(endpoint) ||
            process_alive(root_peer.pid) || !no_process_with_token(token_text(token))) {
            error = "sudo/broker/target disappearance or endpoint ownership failed";
            break;
        }
        ExactLiveness target_liveness = observe_exact_liveness(target_proc);
        const auto target_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
        while (target_liveness != ExactLiveness::ExitedOrReused &&
               std::chrono::steady_clock::now() < target_deadline) {
            (void)poll(nullptr, 0, 10);
            target_liveness = observe_exact_liveness(target_proc);
        }
        if (target_liveness != ExactLiveness::ExitedOrReused) {
            error = "target exact PID/start did not reach a bounded non-live state";
            break;
        }
        if (!wait_direct(sudo_child, kBrokerDeadlineMs) || !sudo_child.reaped ||
            !WIFEXITED(sudo_child.status) ||
            (strcmp(scenario, "broker-early") == 0        ? WEXITSTATUS(sudo_child.status) != 86
             : strcmp(scenario, "broker-lease-loss") == 0 ? WEXITSTATUS(sudo_child.status) != 35
                                                          : WEXITSTATUS(sudo_child.status) != 0)) {
            error = "sudo child did not reap with the expected bounded status";
            break;
        }
        if (!launch_lease.empty_group_exact()) {
            error = "launch group was not proven empty after direct reap";
            break;
        }
        success = true;
    } while (false);
    received_identity.reset();
    initial_ancestry.close();
    final_ancestry.close();
    if (root_fd >= 0) close(root_fd);
    if (broker_fd >= 0) close(broker_fd);
    if (target_fd >= 0) close(target_fd);
    if (!success) {
        // Closing leases is the first failure action.  The root/dropped/target
        // PDEATHSIG/EOF chain owns its descendants; allow that chain to settle
        // before considering any identity-safe fallback.
        const auto cleanup_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs * 3);
        (void)wait_identity_gone_or_reused_until(target_proc, cleanup_deadline);
        (void)wait_identity_gone_or_reused_until(broker_proc, cleanup_deadline);
        (void)wait_identity_gone_or_reused_until(root_proc, cleanup_deadline);
    }
    if (!success) {
        std::string lease_error;
        if (!cleanup_group_lease(launch_lease,
                                 sudo_child,
                                 has_group_authority(sudo_child, launch_lease),
                                 lease_error)) {
            if (!error.empty()) error += "; ";
            error += lease_error;
            success = false;
        }
    }
    if (!sudo_child.reaped && sudo_child.anchor.pid > 1) {
        if (!launch_lease.gone()) {
            if (!error.empty()) error += "; ";
            error += "refused direct wait before launch group reached ESRCH";
            success = false;
        } else if (!wait_direct(sudo_child, kCleanupMs)) {
            if (!safe_signal_direct_child(sudo_child, SIGTERM)) {
                if (!error.empty()) error += "; ";
                error += "refused unsafe direct-launch cleanup signal: " +
                         direct_launch_diagnostic(sudo_child);
            } else if (!wait_direct(sudo_child, kCleanupMs) &&
                       (!safe_signal_direct_child(sudo_child, SIGKILL) ||
                        !wait_direct(sudo_child, kCleanupMs))) {
                if (!error.empty()) error += "; ";
                error += "identity-safe sudo-child cleanup did not reap";
            }
        }
    }
    if (sudo_child.reaped && !launch_lease.empty_group_exact()) {
        if (!error.empty()) error += "; ";
        error += "direct child reaped without an exact empty launch group";
        success = false;
    }
    if (!endpoint_unchanged(endpoint) && error.empty()) error = "endpoint changed during cleanup";
    std::string endpoint_cleanup_error;
    if (!endpoint.cleanup(endpoint_cleanup_error)) {
        success = false;
        if (!error.empty()) error += "; ";
        error += endpoint_cleanup_error;
    }
    return success;
}

static bool regular_root_owned_executable(const char* path) {
    struct stat status{};
    return path != nullptr && path[0] == '/' && stat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && status.st_uid == 0 && (status.st_mode & 0022) == 0 &&
           access(path, X_OK) == 0;
}

static bool open_canonical_caller_executable(const char* path,
                                             ExecutableLease& lease,
                                             std::string& error) {
    lease.path.clear();
    lease.status = {};
    if (lease.fd >= 0) {
        close(lease.fd);
        lease.fd = -1;
    }
    std::array<char, PATH_MAX> canonical{};
    if (path == nullptr || path[0] != '/' || realpath(path, canonical.data()) == nullptr ||
        path != std::string(canonical.data())) {
        error = "RUT executable path was not canonical absolute";
        return false;
    }
#ifdef O_PATH
    lease.fd = open(path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
#else
    lease.fd = -1;
    errno = ENOTSUP;
#endif
    struct stat path_status{};
    if (lease.fd < 0 || fstat(lease.fd, &lease.status) != 0 || lstat(path, &path_status) != 0 ||
        !S_ISREG(lease.status.st_mode) || lease.status.st_uid != getuid() ||
        lease.status.st_gid != getgid() || (lease.status.st_mode & 0111) == 0 ||
        (lease.status.st_mode & 0022) != 0 || access(path, X_OK) != 0 ||
        lease.status.st_dev != path_status.st_dev || lease.status.st_ino != path_status.st_ino) {
        error = "RUT executable custody or caller-owned mode validation failed";
        if (lease.fd >= 0) close(lease.fd);
        lease.fd = -1;
        return false;
    }
    lease.path = canonical.data();
    return true;
}

static bool executable_lease_unchanged(const ExecutableLease& lease) {
    struct stat pinned{}, path{};
    return lease.fd >= 0 && !lease.path.empty() && fstat(lease.fd, &pinned) == 0 &&
           lstat(lease.path.c_str(), &path) == 0 && pinned.st_dev == lease.status.st_dev &&
           pinned.st_ino == lease.status.st_ino && pinned.st_mode == lease.status.st_mode &&
           pinned.st_uid == lease.status.st_uid && pinned.st_gid == lease.status.st_gid &&
           path.st_dev == pinned.st_dev && path.st_ino == pinned.st_ino;
}

static bool run_preflight_command(const std::vector<std::string>& argv) {
    const pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        (void)setpgid(0, 0);
        const int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDOUT_FILENO);
            (void)dup2(null_fd, STDERR_FILENO);
        }
        std::vector<char*> args;
        for (const std::string& value : argv) args.push_back(const_cast<char*>(value.c_str()));
        args.push_back(nullptr);
        execv(args[0], args.data());
        _exit(127);
    }
    (void)setpgid(child, child);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2500);
    int status = 0;
    for (;;) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (waited < 0 && errno != EINTR) return false;
        if (std::chrono::steady_clock::now() >= deadline) break;
        (void)poll(nullptr, 0, 10);
    }
    (void)kill(child, SIGKILL);
    const auto kill_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < kill_deadline) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno != EINTR) break;
        (void)poll(nullptr, 0, 10);
    }
    return false;
}

static bool preflight(std::string& sudo_path, std::string& nsenter_path, std::string& error) {
#ifndef __linux__
    error = "Linux is required";
    return false;
#else
    uid_t ruid = 0, euid = 0, suid = 0;
    gid_t rgid = 0, egid = 0, sgid = 0;
    if (getresuid(&ruid, &euid, &suid) != 0 || getresgid(&rgid, &egid, &sgid) != 0 || ruid == 0 ||
        ruid != euid || ruid != suid || rgid != egid || rgid != sgid) {
        error = "ordinary nonroot real/effective/saved credentials are required";
        return false;
    }
    for (const char* candidate : {"/usr/bin/sudo", "/bin/sudo"})
        if (regular_root_owned_executable(candidate)) {
            sudo_path = candidate;
            break;
        }
    for (const char* candidate : {"/usr/bin/nsenter", "/bin/nsenter"})
        if (regular_root_owned_executable(candidate)) {
            nsenter_path = candidate;
            break;
        }
    if (sudo_path.empty() || nsenter_path.empty()) {
        error = "root-owned sudo or nsenter executable unavailable";
        return false;
    }
    if (!run_preflight_command({sudo_path, "-n", "--", "/bin/true"})) {
        error = "passwordless sudo preflight failed";
        return false;
    }
    if (!run_preflight_command(
            {sudo_path, "-n", "--", nsenter_path, "--net=/proc/self/ns/net", "--", "/bin/true"})) {
        error = "sudo nsenter network-namespace preflight failed";
        return false;
    }
    return true;
#endif
}

static bool run_positive(const std::string& sudo_path,
                         const std::string& nsenter_path,
                         const std::string& executable,
                         const ExecutableLease& rut_executable,
                         const HeldTopologySnapshot& topology,
                         bool required,
                         std::string& error) {
    ProcIdentity host;
    if (!read_proc(getpid(), host) || topology.holder_pid <= 1 || topology.holder_start == 0 ||
        topology.holder_netns == 0 || !process_alive(topology.holder_pid) ||
        host.netns == topology.holder_netns) {
        error = "held topology holder identity changed before broker launch";
        return false;
    }
    if (required &&
        !run_ancestry_probe_session(sudo_path, nsenter_path, executable, topology, error)) {
        error = "required ancestry access probe: " + error;
        return false;
    }
    for (const char* scenario : {"normal",
                                 "ready-loss",
                                 "no-ready",
                                 "term-ignore",
                                 "owned-wait-term-ignore",
                                 "broker-early",
                                 "broker-lease-loss"})
        if (!run_session(
                sudo_path, nsenter_path, executable, rut_executable, topology, scenario, error)) {
            error = std::string(scenario) + ": " + error;
            return false;
        }
    if (!run_session(sudo_path,
                     nsenter_path,
                     executable,
                     rut_executable,
                     topology,
                     "listener-guard-reservation",
                     error)) {
        error = "listener-guard-reservation: " + error;
        return false;
    }
    if (!run_session(sudo_path,
                     nsenter_path,
                     executable,
                     rut_executable,
                     topology,
                     "listener-cleanup-observation-failure",
                     error)) {
        error = "listener-cleanup-observation-failure: " + error;
        return false;
    }
    if (!run_session(sudo_path,
                     nsenter_path,
                     executable,
                     rut_executable,
                     topology,
                     "listener-canonical-collision-release",
                     error)) {
        error = "listener-canonical-collision-release: " + error;
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--wildcard-attempt-protocol-self-check") == 0) {
        std::string error;
        if (!wildcard_attempt_protocol_self_check(error)) {
            std::cerr << "FAIL [#377 wildcard-attempt protocol self-check]: " << error << "\n";
            return 1;
        }
        std::cerr << "PASS: #377 wildcard-attempt protocol self-check\n";
        return 0;
    }
    if (argc == 6 && strcmp(argv[1], "--fixture-broker-launcher") == 0)
        return launcher_main(argv[0], argv[2], argv[3], argv[4], argv[5]);
    if (argc == 6 && strcmp(argv[1], "--fixture-privileged-broker") == 0)
        return root_broker_main(argv[0], argv[2], argv[3], argv[4], argv[5]);
    if (argc == 7 && strcmp(argv[1], "--fixture-privileged-dropped-broker") == 0)
        return dropped_broker_main(argv[0], argv[2], argv[3], argv[4], argv[5], argv[6]);
    if (argc == 6 && strcmp(argv[1], "--fixture-privileged-target") == 0)
        return secured_target_main(argv[2], argv[3], argv[4], argv[5]);
    if (argc != 2) {
        std::cerr << "usage: test_fixture_privileged_broker /canonical/path/to/rut\n";
        return 2;
    }
    std::array<char, PATH_MAX> self{};
    const ssize_t length = readlink("/proc/self/exe", self.data(), self.size() - 1);
    if (length <= 0) return 1;
    self[static_cast<size_t>(length)] = '\0';
    std::string sudo_path, nsenter_path, error;
    ExecutableLease rut_executable;
    const bool required = getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED") != nullptr &&
                          strcmp(getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED"), "1") == 0;
    if (!open_canonical_caller_executable(argv[1], rut_executable, error) ||
        !pure_protocol_self_checks(error) || !launch_argv_refactor_self_check(error) ||
        !listener_failure_bound_self_check(error) || !exact_liveness_self_check(error) ||
        !endpoint_replacement_self_check(error) || !bounded_wait_and_signal_self_check(error) ||
        !group_lease_self_check(error) || !lease_loss_owner_cascade_self_check(error) ||
        !launcher_error_order_self_check(error) || !prelaunch_close_first_self_check(error) ||
        !identity_bundle_integration_self_check(error) || !retained_anchor_self_check(error) ||
        !ancestry_probe_validation_self_check(error) ||
        !formal_authorization_policy_self_check(error) || !guard_protocol_self_check(error) ||
        !exact_transaction_self_check(error) || !exact_custody_ancillary_self_check(error) ||
        !exact_adoption_fault_self_check(error)) {
        std::cerr << "FAIL [#358 Stage 2a3b protocol self-check]: " << error << "\n";
        return 1;
    }
    if (!preflight(sudo_path, nsenter_path, error)) {
        std::cerr << (required ? "FAIL" : "SKIP") << " [#358 Stage 2a3b preflight]: " << error
                  << "\n";
        return required ? 1 : 77;
    }
    const auto result = rut::test::ipv4_topology::run_with_held_topology(
        HeldTopologyProbePolicy::SocketlessHostParent,
        [&](const HeldTopologySnapshot& topology, std::string& callback_error) {
            if (!rut::test::ipv4_topology::validate_held_topology_probe_evidence(
                    topology.probe_evidence,
                    HeldTopologyProbePolicy::SocketlessHostParent,
                    callback_error))
                return false;
            return run_positive(sudo_path,
                                nsenter_path,
                                self.data(),
                                rut_executable,
                                topology,
                                required,
                                callback_error);
        });
    if (result.prerequisite_failure) {
        std::cerr << (required ? "FAIL" : "SKIP") << " [#358 Stage 2a3b topology]: " << result.error
                  << "\n";
        return required ? 1 : 77;
    }
    if (!result.success) {
        std::cerr << "FAIL [#358 Stage 2a3b broker]: " << result.error << "\n";
        return 1;
    }
    std::cerr << "PASS: #358 Stage 2a3b authenticated sudo/nsenter broker lifecycle\n";
    return 0;
}
