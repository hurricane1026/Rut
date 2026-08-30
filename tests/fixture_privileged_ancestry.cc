#include "fixture_privileged_ancestry.h"

#include "fixture_worker_protocol.h"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace rut::test::fixture_privileged_ancestry {
namespace {

const char* fd_slot_name(identity::FdSlot slot) {
    switch (slot) {
        case identity::FdSlot::Stat:
            return "stat";
        case identity::FdSlot::Status:
            return "status";
        case identity::FdSlot::Cmdline:
            return "cmdline";
        case identity::FdSlot::Executable:
            return "exe";
        case identity::FdSlot::Netns:
            return "netns";
        case identity::FdSlot::Pidfd:
            return "pidfd";
        case identity::FdSlot::Unknown:
            return "unknown";
    }
    return "unknown";
}

std::string diagnostic(size_t node,
                       pid_t pid,
                       const char* slot,
                       const char* phase,
                       const char* operation,
                       int error_number) {
    return "node=" + std::to_string(node) + ",pid=" + std::to_string(pid) + ",slot=" + slot +
           ",phase=" + phase + ",syscall=" + operation + ",errno=" + std::to_string(error_number);
}

bool deadline_ok(std::chrono::steady_clock::time_point deadline) {
    return std::chrono::steady_clock::now() < deadline;
}

}  // namespace

bool collect_ancestry(pid_t first_parent,
                      pid_t ordinary_parent,
                      ancestry::AncestryBundle& output,
                      std::chrono::steady_clock::time_point deadline,
                      std::string& safe_diagnostic) {
    output.close();
    safe_diagnostic.clear();
    if (first_parent <= 1 || ordinary_parent <= 1 || first_parent == ordinary_parent) {
        safe_diagnostic = diagnostic(0, first_parent, "unknown", "boundary", "none", 0);
        return false;
    }
    pid_t current = first_parent;
    for (size_t index = 0; index != fixture_direct_launch::kMaxLaunchAncestry; ++index) {
        if (!deadline_ok(deadline)) {
            safe_diagnostic = diagnostic(index, current, "unknown", "deadline", "none", ETIMEDOUT);
            output.close();
            return false;
        }
        for (const identity::RoleBundle& previous : output.nodes) {
            if (previous.manifest.pid == current) {
                safe_diagnostic = diagnostic(index, current, "unknown", "cycle", "none", 0);
                output.close();
                return false;
            }
        }
        identity::RoleBundle node;
        identity::OpenRoleFailure failure;
        std::string open_error;
        if (!identity::open_role(current, identity::Role::Ancestry, node, failure, open_error)) {
            safe_diagnostic = diagnostic(index,
                                         current,
                                         fd_slot_name(failure.slot),
                                         failure.phase.c_str(),
                                         failure.operation.c_str(),
                                         failure.error_number);
            output.close();
            return false;
        }
        if (!deadline_ok(deadline)) {
            safe_diagnostic = diagnostic(index, current, "unknown", "deadline", "none", ETIMEDOUT);
            node.close();
            output.close();
            return false;
        }
        const pid_t next = node.manifest.ppid;
        output.nodes.push_back(std::move(node));
        if (next == ordinary_parent) return true;
        if (next <= 1 || next == current) {
            safe_diagnostic = diagnostic(index, current, "unknown", "parent_edge", "none", 0);
            output.close();
            return false;
        }
        current = next;
    }
    safe_diagnostic = diagnostic(
        fixture_direct_launch::kMaxLaunchAncestry, current, "unknown", "overflow", "none", 0);
    output.close();
    return false;
}

bool parse_retained_anchor_stat(const std::string& text, RetainedAnchorEvidence& evidence) {
    const size_t pid_end = text.find(' ');
    if (pid_end == std::string::npos || pid_end == 0) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long parsed_pid = strtoul(text.substr(0, pid_end).c_str(), &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0' || parsed_pid <= 1 ||
        parsed_pid > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()))
        return false;
    const size_t comm_end = text.rfind(") ");
    if (comm_end == std::string::npos) return false;
    std::istringstream fields(text.substr(comm_end + 2));
    long ppid = 0, pgid = 0, sid = 0;
    if (!(fields >> evidence.state >> ppid >> pgid >> sid)) return false;
    for (int field = 7; field <= 22; ++field) {
        if (field == 22) {
            unsigned long long start = 0;
            if (!(fields >> start)) return false;
            evidence.start = static_cast<std::uint64_t>(start);
        } else {
            long long ignored = 0;
            if (!(fields >> ignored)) return false;
        }
    }
    evidence.pid = static_cast<pid_t>(parsed_pid);
    evidence.ppid = static_cast<pid_t>(ppid);
    evidence.pgid = static_cast<pid_t>(pgid);
    evidence.sid = static_cast<pid_t>(sid);
    return evidence.ppid > 1 && evidence.pgid > 1 && evidence.sid > 1 && evidence.start != 0;
}

bool parse_retained_anchor_status(const std::string& text, RetainedAnchorEvidence& evidence) {
    bool have_uid = false, have_gid = false;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        const bool is_uid = line.rfind("Uid:", 0) == 0;
        const bool is_gid = line.rfind("Gid:", 0) == 0;
        if (!is_uid && !is_gid) continue;
        bool& present = is_uid ? have_uid : have_gid;
        if (present) return false;
        std::istringstream values(line.substr(colon + 1));
        std::array<unsigned long long, 4> ids{};
        for (auto& id : ids)
            if (!(values >> id)) return false;
        std::string extra;
        if (values >> extra) return false;
        if (is_uid) {
            for (size_t i = 0; i != ids.size(); ++i) {
                if (ids[i] > std::numeric_limits<uid_t>::max()) return false;
                evidence.uid_values[i] = static_cast<uid_t>(ids[i]);
            }
            evidence.uid = evidence.uid_values[0];
        } else {
            for (size_t i = 0; i != ids.size(); ++i) {
                if (ids[i] > std::numeric_limits<gid_t>::max()) return false;
                evidence.gid_values[i] = static_cast<gid_t>(ids[i]);
            }
            evidence.gid = evidence.gid_values[0];
        }
        present = true;
    }
    return have_uid && have_gid;
}

bool retained_pidfd_live(int pidfd) {
    if (pidfd < 0 || fcntl(pidfd, F_GETFD) < 0) return false;
    pollfd descriptor{pidfd, POLLIN, 0};
    int result;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0;
}

bool capture_retained_anchor_evidence(const DirectLaunch& launch,
                                      const RetainedAnchorLease& lease,
                                      RetainedAnchorEvidence& evidence,
                                      std::string& reason) {
    if (!launch.marker_valid || lease.pid != launch.anchor.pid ||
        lease.start != launch.anchor.start || lease.pgid != launch.anchor.pgid ||
        lease.sid != launch.anchor.sid || !retained_pidfd_live(lease.pidfd)) {
        reason = "retained sudo anchor lease/pidfd binding was stale";
        return false;
    }
    const std::string prefix = "/proc/" + std::to_string(launch.anchor.pid);
    std::string first_text, second_text, status;
    RetainedAnchorEvidence first, second;
    if (!fixture_worker_protocol::read_file(prefix + "/stat", first_text, 8192) ||
        !parse_retained_anchor_stat(first_text, first) ||
        !fixture_worker_protocol::read_file(prefix + "/stat", second_text, 8192) ||
        !parse_retained_anchor_stat(second_text, second) || first.pid != second.pid ||
        first.ppid != second.ppid || first.pgid != second.pgid || first.sid != second.sid ||
        first.start != second.start || first.state != second.state ||
        !fixture_worker_protocol::read_file(prefix + "/status", status) ||
        !parse_retained_anchor_status(status, second) ||
        !fixture_worker_protocol::read_file(prefix + "/cmdline", second.cmdline, 8192)) {
        reason = "retained sudo anchor stat/status/cmdline evidence was unavailable or unstable";
        return false;
    }
    second.pidfd_live = retained_pidfd_live(lease.pidfd);
    if (!second.pidfd_live || second.pid != launch.anchor.pid ||
        second.start != launch.anchor.start || second.ppid != getpid() ||
        second.pgid != launch.anchor.pgid || second.sid != launch.anchor.sid ||
        second.state == 'Z' || second.state == 'X') {
        reason = "retained sudo anchor kernel identity was stale, detached, or dead";
        return false;
    }
    evidence = std::move(second);
    return true;
}

bool bind_retained_anchor_evidence(const std::vector<identity::ProcessIdentityEvidence>& records,
                                   RetainedAnchorEvidence& evidence,
                                   std::string& error) {
    if (records.size() != 1) {
        error = "retained sudo ancestry required exactly one record";
        return false;
    }
    const identity::ProcessIdentityEvidence& source = records.front();
    if (source.identity.pid <= 1 || source.identity.start == 0 || source.identity.ppid <= 1 ||
        source.identity.pgid <= 1 || source.identity.sid <= 1 || source.identity.netns == 0 ||
        source.identity.exe_dev == 0 || source.identity.exe_ino == 0 ||
        source.identity.argv_length == 0 || source.cmdline.empty() || !source.pidfd_live) {
        error = "retained sudo ancestry record was incomplete";
        return false;
    }
    evidence.pid = source.identity.pid;
    evidence.ppid = source.identity.ppid;
    evidence.pgid = source.identity.pgid;
    evidence.sid = source.identity.sid;
    evidence.start = source.identity.start;
    evidence.state = source.state;
    evidence.uid = source.identity.uid;
    evidence.gid = source.identity.gid;
    evidence.uid_values = source.status.uid_values;
    evidence.gid_values = source.status.gid_values;
    evidence.cmdline = source.cmdline;
    evidence.pidfd_live = source.pidfd_live;
    error.clear();
    return true;
}

bool prove_retained_sudo_wrapper(DirectLaunch& launch,
                                 const ProcIdentity& launcher,
                                 const RetainedAnchorEvidence& evidence,
                                 std::string& reason) {
    if (!launch.marker_valid || launch.mode == fixture_direct_launch::LaunchMode::ExecChain ||
        !evidence.pidfd_live || evidence.pid != launch.anchor.pid ||
        evidence.start != launch.anchor.start || evidence.ppid != getpid() ||
        evidence.pgid != launch.anchor.pgid || evidence.sid != launch.anchor.sid ||
        evidence.state == 'Z' || evidence.state == 'X' || launcher.pid == launch.anchor.pid ||
        launcher.ppid != launch.anchor.pid || launcher.pgid != launch.anchor.pgid ||
        launcher.sid != launch.anchor.sid) {
        reason = "retained sudo anchor/launcher kernel chain was not exact";
        launch.reason = reason;
        return false;
    }
    const auto all_uid = [&](uid_t expected) {
        return std::all_of(evidence.uid_values.begin(),
                           evidence.uid_values.end(),
                           [expected](uid_t value) { return value == expected; });
    };
    const auto all_gid = [&](gid_t expected) {
        return std::all_of(evidence.gid_values.begin(),
                           evidence.gid_values.end(),
                           [expected](gid_t value) { return value == expected; });
    };
    const bool caller = all_uid(launch.anchor.caller_uid) && all_gid(launch.anchor.caller_gid);
    const bool retained = evidence.uid_values[0] == launch.anchor.caller_uid &&
                          evidence.uid_values[1] == 0 && evidence.uid_values[2] == 0 &&
                          evidence.uid_values[3] == 0 && all_gid(0);
    const bool root = all_uid(0) && all_gid(0);
    if ((!caller && !retained && !root) || evidence.cmdline != launch.allowed.sudo_stage.argv) {
        reason = "retained sudo status/cmdline was not the exact allowed sudo stage";
        launch.reason = reason;
        return false;
    }
    ProcIdentity direct;
    direct.pid = evidence.pid;
    direct.ppid = evidence.ppid;
    direct.pgid = evidence.pgid;
    direct.sid = evidence.sid;
    direct.start = evidence.start;
    direct.uid = evidence.uid_values[1];
    direct.gid = evidence.gid_values[1];
    direct.cmdline = evidence.cmdline;
    direct.exe_dev = launch.allowed.sudo_stage.exe_dev;
    direct.exe_ino = launch.allowed.sudo_stage.exe_ino;
    direct.netns = launch.anchor.host_netns;
    return fixture_direct_launch::validate_launcher_ancestry(launch, launcher, {direct}, reason);
}

}  // namespace rut::test::fixture_privileged_ancestry
