// #358 Stage 2a3b: authenticated sudo/nsenter broker lifecycle only.
// No HTTP listener, nginx process, RUT process, or AF_INET socket is created here.

#include "fixture_direct_launch.h"
#include "fixture_ipv4_topology.h"
#include "fixture_worker_protocol.h"
#include <algorithm>
#include <array>
#include <cerrno>
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
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/limits.h>
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
using rut::test::ipv4_topology::HeldTopologySnapshot;

constexpr u16 kBrokerRootHello = 20;
constexpr u16 kCallerCredentials = 21;
constexpr u16 kBrokerDropped = 22;
constexpr u16 kLaunchTarget = 23;
constexpr u16 kTargetExited = 24;
constexpr u16 kBrokerExitEarly = 25;
constexpr u16 kSecurityTrace = 26;
constexpr int kBrokerDeadlineMs = 5000;
constexpr int kCredentialFd = 198;

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

static bool endpoint_matches(const ParentEndpoint& endpoint, const EndpointIdentity& expected);
static bool endpoint_unchanged(const ParentEndpoint& endpoint);
static bool endpoint_replacement_self_check(std::string& error);
static bool bounded_wait_and_signal_self_check(std::string& error);
static bool group_lease_self_check(std::string& error);
static bool safe_signal_target(const Report& report,
                               const Peer& peer,
                               const ProcIdentity& expected,
                               int signal_number);
static bool write_pipe_exact(int fd, const unsigned char* data, size_t size, int timeout_ms);
static bool stable_proc_identity(pid_t pid, ProcIdentity& identity);
static bool child_exited_wnowait(pid_t pid);
enum class GroupScanResult { Exact, Unreadable };
static GroupScanResult scan_group_stat(pid_t pgid,
                                       int& member_count,
                                       bool& live_member,
                                       pid_t permitted_zombie);
static GroupScanResult group_member_count(pid_t pgid, int& count);
struct GroupLease;
static bool cleanup_group_lease(GroupLease& lease,
                                DirectLaunch& launch,
                                bool authority,
                                std::string& error);
static bool has_group_authority(const DirectLaunch& launch, const GroupLease& lease);

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
        return child_exited_wnowait(pid) &&
               scan_group_stat(pgid, count, live, pid) == GroupScanResult::Exact && !live;
    }

    bool empty_group_exact() const {
        int count = 0;
        bool live = false;
        errno = 0;
        const bool esrch = kill(-pgid, 0) < 0 && errno == ESRCH;
        return pgid > 1 && esrch &&
               scan_group_stat(pgid, count, live, -1) == GroupScanResult::Exact && count == 0 &&
               !live;
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
    if (!parse_credentials(credentials, parsed_uid, parsed_gid) || parsed_uid != uid ||
        parsed_gid != gid || !parse_credentials(changed_credentials, changed_uid, changed_gid) ||
        (changed_uid == uid && changed_gid == gid) ||
        credentials_match_peer(changed_credentials, uid, gid) ||
        parse_credentials(short_credentials, changed_uid, changed_gid) ||
        parse_credentials(root_credentials, changed_uid, changed_gid) ||
        !valid_security_trace(trace) || valid_security_trace(reordered_trace) ||
        valid_security_trace(duplicate_trace) || valid_security_trace(short_trace) ||
        !socket_helper_rejected || !pipe_helper_accepted || !release_exact || !wait_decisions ||
        !probe_success_is_diagnostic_only || !probe_parse_mutations) {
        error = "credential/security-trace mutation self-check failed";
        return false;
    }
    return true;
}

enum class OwnedWaitResult { Exited, LeaseLost, Error };

static bool reap_owned_child_bounded(pid_t child) {
    if (child <= 1) return false;
    int status = 0;
    const auto wait_for_child = [&](std::chrono::steady_clock::time_point deadline) {
        while (std::chrono::steady_clock::now() < deadline) {
            const pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) return true;
            if (waited < 0 && errno != EINTR) return false;
            (void)poll(nullptr, 0, 10);
        }
        return false;
    };
    if (wait_for_child(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs)))
        return true;
    if (kill(child, SIGTERM) != 0 && errno != ESRCH) return false;
    if (wait_for_child(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs)))
        return true;
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) return false;
    return wait_for_child(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
}

class OwnedChildCleanup {
public:
    explicit OwnedChildCleanup(pid_t child) : child_(child) {}
    OwnedChildCleanup(const OwnedChildCleanup&) = delete;
    OwnedChildCleanup& operator=(const OwnedChildCleanup&) = delete;
    ~OwnedChildCleanup() {
        if (armed_) (void)reap_owned_child_bounded(child_);
    }
    void disarm() { armed_ = false; }

private:
    pid_t child_;
    bool armed_ = true;
};

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
                                                int lease_fd = -1) {
    const auto wait_until = [&](std::chrono::steady_clock::time_point deadline) {
        while (std::chrono::steady_clock::now() < deadline) {
            if (control_lease_lost(lease_fd)) return OwnedWaitResult::LeaseLost;
            const pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) return OwnedWaitResult::Exited;
            if (waited < 0 && errno != EINTR) return OwnedWaitResult::Error;
            (void)poll(nullptr, 0, 10);
        }
        return OwnedWaitResult::Error;
    };
    OwnedWaitResult result =
        wait_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms));
    if (result == OwnedWaitResult::Exited) return result;
    const bool lease_lost = result == OwnedWaitResult::LeaseLost;
    ProcIdentity before;
    if (child <= 1 || expected_pgid <= 1 || !read_proc(child, before, require_capabilities_clear) ||
        before.pid != child || before.ppid != getpid() || before.pgid != expected_pgid ||
        before.uid != expected_uid || before.gid != expected_gid ||
        before.netns != expected_netns || before.exe != expected_exe ||
        before.cmdline != expected_argv || kill(child, SIGTERM) != 0)
        return OwnedWaitResult::Error;
    result = wait_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
    if (result == OwnedWaitResult::Exited)
        return lease_lost ? OwnedWaitResult::LeaseLost : OwnedWaitResult::Exited;
    if (result == OwnedWaitResult::Error && control_lease_lost(lease_fd))
        return OwnedWaitResult::Error;
    ProcIdentity after_term;
    if (!read_proc(child, after_term, require_capabilities_clear) ||
        !same_process_identity(before, after_term) || after_term.ppid != getpid() ||
        after_term.pgid != expected_pgid || kill(child, SIGKILL) != 0)
        return OwnedWaitResult::Error;
    result = wait_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs));
    if (result != OwnedWaitResult::Exited) return OwnedWaitResult::Error;
    return lease_lost ? OwnedWaitResult::LeaseLost : OwnedWaitResult::Exited;
}

static int secured_target_main(const char* control_path,
                               const char* token_string,
                               const char* broker_text,
                               const char* scenario) {
    Token token;
    u64 broker = 0;
    if (!token_from_hex(token_string, token) || !parse_u64(broker_text, broker) || broker <= 1)
        return 40;
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
            !token_equal(command.token, token) || !command.payload.empty()) {
            close(control);
            return 0;
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
    if (root_broker <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != root_broker)
        return 21;
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
    const pid_t target = fork();
    if (target < 0) return 28;
    if (target == 0) {
        const pid_t broker_parent = getppid();
        close(launch_pipe[1]);
        close(trace_pipe[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != broker_parent) _exit(50);
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
        if (!secure_target(caller_uid, caller_gid, trace_pipe[1])) _exit(53);
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
    OwnedChildCleanup target_cleanup(target);
    if (!secure_as(caller_uid, caller_gid)) return 29;
    int control = connect_control(control_path);
    if (control < 0) return 30;
    Report dropped_report;
    if (!fill_report("broker-dropped", static_cast<u64>(root_broker), dropped_report, true) ||
        !send_frame(
            control, Frame{kBrokerDropped, token, encode_report(dropped_report)}, kHandshakeMs))
        return 31;
    Frame launch;
    if (!receive_frame(control, launch, kHandshakeMs) || launch.type != kLaunchTarget ||
        !token_equal(launch.token, token) || !launch.payload.empty() ||
        write(launch_pipe[1], "L", 1) != 1)
        return 32;
    close(launch_pipe[1]);
    std::array<unsigned char, 7> trace{};
    if (!read_exact(trace_pipe[0], trace.data(), trace.size(), kHandshakeMs)) return 36;
    char extra = 0;
    ssize_t extra_count;
    do {
        extra_count = read(trace_pipe[0], &extra, 1);
    } while (extra_count < 0 && errno == EINTR);
    close(trace_pipe[0]);
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
        wait_owned_child_bounded(target,
                                 executable,
                                 target_argv,
                                 caller_uid,
                                 caller_gid,
                                 static_cast<ino_t>(expected_netns),
                                 target,
                                 true,
                                 target_wait_ms,
                                 target_status,
                                 kCredentialFd);
    if (target_wait_result != OwnedWaitResult::Exited) {
        if (target_wait_result == OwnedWaitResult::LeaseLost) target_cleanup.disarm();
        close(kCredentialFd);
        return 34;
    }
    target_cleanup.disarm();
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
    ProcIdentity identity;
    if (!read_proc(getpid(), identity, false) || identity.netns != expected_netns) return 22;
    const int root_control = connect_control(control_path);
    if (root_control < 0) return 23;
    Report root_report;
    if (!fill_report("broker-root", static_cast<u64>(launcher), root_report, false) ||
        !send_frame(
            root_control, Frame{kBrokerRootHello, token, encode_report(root_report)}, kHandshakeMs))
        return 24;
    Peer parent_peer;
    Frame credentials;
    uid_t caller_uid = 0;
    gid_t caller_gid = 0;
    if (!get_peer(root_control, parent_peer) ||
        !receive_frame(root_control, credentials, kHandshakeMs) ||
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
    OwnedChildCleanup dropped_cleanup(dropped);
    if (!send_frame(credential_pair[0],
                    Frame{kCallerCredentials, token, credentials.payload},
                    kHandshakeMs)) {
        close(credential_pair[0]);
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
        close(credential_pair[0]);
        if (abandoned != OwnedWaitResult::Error) dropped_cleanup.disarm();
        return abandoned == OwnedWaitResult::Exited ? 28 : 29;
    }
    int status = 0;
    const OwnedWaitResult dropped_wait_result =
        wait_owned_child_bounded(dropped,
                                 executable,
                                 dropped_argv,
                                 caller_uid,
                                 caller_gid,
                                 static_cast<ino_t>(expected_netns),
                                 dropped,
                                 true,
                                 kBrokerDeadlineMs,
                                 status,
                                 root_control);
    if (dropped_wait_result != OwnedWaitResult::Exited) {
        if (dropped_wait_result == OwnedWaitResult::LeaseLost) dropped_cleanup.disarm();
        close(root_control);
        close(credential_pair[0]);
        return 29;
    }
    dropped_cleanup.disarm();
    close(root_control);
    close(credential_pair[0]);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 30;
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
    const std::string broker_argv = exact_argv(
        {executable, "--fixture-privileged-broker", control_path, token, expected_netns, scenario});
    const pid_t broker = fork();
    if (broker < 0) return 12;
    if (broker == 0) {
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
                                 kBrokerDeadlineMs,
                                 status);
    if (broker_wait_result != OwnedWaitResult::Exited) {
        if (broker_wait_result == OwnedWaitResult::LeaseLost) broker_cleanup.disarm();
        return 13;
    }
    broker_cleanup.disarm();
    // Reap any target adopted after an intentionally early broker death.
    const bool broker_abnormal =
        WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0);
    bool adopted_drained = !broker_abnormal;
    const auto adopted_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs * 2);
    while (broker_abnormal && !adopted_drained) {
        int adopted_status = 0;
        const pid_t adopted = waitpid(-1, &adopted_status, WNOHANG);
        if (adopted > 0) continue;
        if (adopted < 0 && errno == EINTR) continue;
        if (adopted < 0 && errno == ECHILD) {
            adopted_drained = true;
            break;
        }
        if (adopted == 0 && std::chrono::steady_clock::now() < adopted_deadline) {
            (void)poll(nullptr, 0, 10);
            continue;
        }
        break;
    }
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

static bool record_direct_launch_identity(DirectLaunch& child) {
    ProcIdentity current;
    std::string reason;
    if (child.anchor.pid > 1 && read_proc(child.anchor.pid, current, false) &&
        observe_direct(child, current, reason))
        return true;
    child.reason =
        reason.empty() ? "direct launch current /proc identity could not be read" : reason;
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

static GroupScanResult scan_group_stat(pid_t pgid, int& count, bool& live, pid_t permitted_zombie) {
    const int directory = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return GroupScanResult::Unreadable;
    DIR* entries = fdopendir(directory);
    if (entries == nullptr) {
        close(directory);
        return GroupScanResult::Unreadable;
    }
    count = 0;
    live = false;
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
        if (process_group == pgid) ++count;
        if (process_group == pgid && pid != permitted_zombie && state != 'Z' && state != 'X')
            live = true;
    }
    closedir(entries);
    return result;
}

static GroupScanResult group_member_count(pid_t pgid, int& count) {
    bool live = false;
    return scan_group_stat(pgid, count, live, -1);
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
    const std::string launcher_argv = exact_argv({executable,
                                                  "--fixture-broker-launcher",
                                                  endpoint.socket,
                                                  token_value,
                                                  expected_netns,
                                                  scenario});
    const std::string nsenter_argv = exact_argv({nsenter_path,
                                                 netns_arg,
                                                 "--",
                                                 executable,
                                                 "--fixture-broker-launcher",
                                                 endpoint.socket,
                                                 token_value,
                                                 expected_netns,
                                                 scenario});
    const std::string sudo_argv = exact_argv({sudo_path,
                                              "-n",
                                              "--",
                                              nsenter_path,
                                              netns_arg,
                                              "--",
                                              executable,
                                              "--fixture-broker-launcher",
                                              endpoint.socket,
                                              token_value,
                                              expected_netns,
                                              scenario});
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
        if (setpgid(0, 0) != 0) _exit(125);
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
        execl(sudo_path.c_str(),
              sudo_path.c_str(),
              "-n",
              "--",
              nsenter_path.c_str(),
              netns_arg.c_str(),
              "--",
              executable.c_str(),
              "--fixture-broker-launcher",
              endpoint.socket.c_str(),
              token_value.c_str(),
              expected_netns.c_str(),
              scenario,
              static_cast<char*>(nullptr));
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
    hello_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs);
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
                             std::string& error) {
    root_fd = -1;
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
        return true;
    }
    error = "root HELLO missed the absolute post-release deadline (last observation: " +
            last_observation + ")";
    launch.reason = error;
    return false;
}

static bool read_launcher_ancestry(const ProcIdentity& launcher,
                                   const DirectLaunch& launch,
                                   std::vector<ProcIdentity>& ancestry,
                                   std::string& reason) {
    pid_t current = launcher.ppid;
    for (size_t depth = 0; depth != kMaxLaunchAncestry && current > 1; ++depth) {
        ProcIdentity identity;
        if (!stable_proc_identity(current, identity) || identity.ppid == identity.pid) {
            reason = "launcher ancestry could not be read as a stable /proc chain";
            return false;
        }
        ancestry.push_back(identity);
        if (identity.pid == launch.anchor.pid) return true;
        current = identity.ppid;
    }
    reason = "launcher ancestry did not reach immutable direct PID within bound";
    return false;
}

static bool validate_root_broker(const Report& report,
                                 const Peer& peer,
                                 const ProcIdentity& proc,
                                 const HeldTopologySnapshot& topology,
                                 const std::string& executable,
                                 const std::string& expected_argv,
                                 const std::string& expected_launcher_argv,
                                 DirectLaunch& sudo_launch) {
    if (peer.pid <= 1 || peer.uid != 0 || peer.gid != 0 ||
        report.target_pid != static_cast<u64>(peer.pid) ||
        report.target_pid != static_cast<u64>(proc.pid) || report.wrapper_pid <= 1 ||
        report.target_pid == report.wrapper_pid || report.start != proc.start ||
        report.pgid != static_cast<u64>(proc.pgid) || proc.pgid != sudo_launch.anchor.pgid ||
        report.netns != topology.holder_netns || proc.netns != topology.holder_netns ||
        report.uid != 0 || report.gid != 0 || proc.uid != 0 || proc.gid != 0 ||
        report.exe != executable || proc.exe != executable || report.exe_dev != proc.exe_dev ||
        report.exe_ino != proc.exe_ino ||
        proc.exe_dev != sudo_launch.allowed.launcher_stage.exe_dev ||
        proc.exe_ino != sudo_launch.allowed.launcher_stage.exe_ino ||
        report.argv != expected_argv || proc.cmdline != expected_argv ||
        report.mode != "broker-root" || proc.ppid != static_cast<pid_t>(report.wrapper_pid) ||
        report.no_new_privs != static_cast<u64>(proc.no_new_privs) ||
        report.capabilities_clear != static_cast<u64>(proc.capabilities_clear) ||
        report.groups_clear != 0 || report.groups_unchanged != 1) {
        sudo_launch.reason = "root broker report/peer/current /proc fields were not exact";
        return false;
    }
    ProcIdentity launcher;
    std::vector<ProcIdentity> ancestry;
    std::string reason;
    if (!stable_proc_identity(proc.ppid, launcher) || launcher.pid != proc.ppid ||
        launcher.cmdline != expected_launcher_argv ||
        (launcher.pid != sudo_launch.anchor.pid &&
         !read_launcher_ancestry(launcher, sudo_launch, ancestry, reason)) ||
        !validate_launcher_ancestry(sudo_launch, launcher, ancestry, reason)) {
        sudo_launch.reason =
            reason.empty() ? "root broker launcher provenance was not exact" : reason;
        return false;
    }
    return true;
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
                                                   const ProcIdentity& proc,
                                                   const Token& expected_token,
                                                   const Token& frame_token,
                                                   const HeldTopologySnapshot& topology,
                                                   const std::string& executable,
                                                   const std::string& expected_argv,
                                                   const std::string& expected_launcher_argv,
                                                   DirectLaunch& launch) {
    (void)expected_launcher_argv;
    (void)launch;
    const bool basic_report =
        peer.pid > 1 && peer.uid == 0 && peer.gid == 0 &&
        report.target_pid == static_cast<u64>(peer.pid) &&
        report.target_pid == static_cast<u64>(proc.pid) && report.wrapper_pid > 1 &&
        report.start == proc.start && report.pgid == static_cast<u64>(proc.pgid) &&
        report.uid == 0 && report.gid == 0 && report.netns == topology.holder_netns &&
        proc.netns == topology.holder_netns && report.exe == executable && proc.exe == executable &&
        report.argv == expected_argv && proc.cmdline == expected_argv &&
        report.mode == "broker-root" && proc.ppid == static_cast<pid_t>(report.wrapper_pid);
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

static bool causal_mutation_self_checks(const Report& root_report,
                                        const Peer& root_peer,
                                        const ProcIdentity& root_proc,
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
                                        const ParentEndpoint& endpoint) {
    DirectLaunch baseline_launch = sudo_child;
    const bool root_baseline = validate_root_broker(root_report,
                                                    root_peer,
                                                    root_proc,
                                                    topology,
                                                    executable,
                                                    root_argv,
                                                    launcher_argv,
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
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      changed_report_launch) &&
                                !validate_root_broker(root_report,
                                                      changed_root_peer,
                                                      root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      changed_peer_launch) &&
                                !validate_root_broker(root_report,
                                                      root_peer,
                                                      changed_root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      changed_proc_launch) &&
                                !validate_root_broker(root_report,
                                                      root_peer,
                                                      root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
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
    DirectLaunch stale_sudo = sudo_child;
    stale_sudo.current_identity.start++;
    DirectLaunch unsafe_sudo = sudo_child;
    unsafe_sudo.current_identity.pgid = 1;
    const bool sudo_signal_mutations =
        sudo_child.current_valid &&
        stale_sudo.current_identity.start != sudo_child.current_identity.start &&
        unsafe_sudo.current_identity.pgid != sudo_child.current_identity.pgid &&
        safe_signal_direct_child(sudo_child, 0) && !safe_signal_direct_child(stale_sudo, 0) &&
        !safe_signal_direct_child(unsafe_sudo, 0) && process_alive(sudo_child.anchor.pid);
    EndpointIdentity changed_endpoint = endpoint.identity;
    changed_endpoint.socket_ino++;
    const std::vector<unsigned char> trace{'G', 'D', 'U', 'N', 'C', 'P', 'X'};
    std::vector<unsigned char> swapped_trace = trace;
    std::swap(swapped_trace[1], swapped_trace[2]);
    std::vector<unsigned char> short_trace = trace;
    short_trace.pop_back();
    return root_baseline && root_mutations && broker_baseline && broker_mutations &&
           target_baseline && target_mutations && signal_mutations && sudo_signal_mutations &&
           endpoint_unchanged(endpoint) && !endpoint_matches(endpoint, changed_endpoint) &&
           valid_security_trace(trace) && !valid_security_trace(swapped_trace) &&
           !valid_security_trace(short_trace);
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

static bool wait_identity_gone_or_reused(const ProcIdentity& expected, int timeout_ms) {
    if (expected.pid <= 1 || expected.start == 0) return true;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
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

static bool terminate_verified(const Report& report,
                               const Peer& peer,
                               const ProcIdentity& expected) {
    if (target_gone_or_reused(expected)) return true;
    if (!safe_signal_target(report, peer, expected, SIGTERM)) return false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (target_gone_or_reused(expected)) return true;
        (void)poll(nullptr, 0, 10);
    }
    if (!safe_signal_target(report, peer, expected, SIGKILL)) return false;
    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (target_gone_or_reused(expected)) return true;
        (void)poll(nullptr, 0, 10);
    }
    return target_gone_or_reused(expected);
}

static bool run_session(const std::string& sudo_path,
                        const std::string& nsenter_path,
                        const std::string& executable,
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
    ProcIdentity root_proc, broker_proc, target_proc;
    Token root_frame_token;
    bool success = false;
    do {
        const bool root_hello_ok = await_root_hello(endpoint,
                                                    sudo_child,
                                                    token,
                                                    hello_deadline,
                                                    root_fd,
                                                    root_peer,
                                                    root_report,
                                                    root_frame_token,
                                                    error);
        const bool root_proc_ok =
            root_hello_ok && root_peer.pid > 1 && read_proc(root_peer.pid, root_proc, false);
        if (!root_hello_ok || !root_proc_ok) {
            if (error.empty()) error = "root broker HELLO/peer identity failed";
            if (!root_proc_ok) error += "; " + probe_diagnostic(root_peer.pid);
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
        const std::string dropped_argv = exact_argv({executable,
                                                     "--fixture-privileged-dropped-broker",
                                                     endpoint.socket,
                                                     token_text(token),
                                                     std::to_string(topology.holder_netns),
                                                     scenario,
                                                     std::to_string(kCredentialFd)});
        const DestructiveAuth destructive_auth = authorize_destructive_close(endpoint,
                                                                             root_report,
                                                                             root_peer,
                                                                             root_proc,
                                                                             token,
                                                                             root_frame_token,
                                                                             topology,
                                                                             executable,
                                                                             root_argv,
                                                                             launcher_argv,
                                                                             sudo_child);
        if (!destructive_auth.valid ||
            !validate_root_broker(root_report,
                                  root_peer,
                                  root_proc,
                                  topology,
                                  executable,
                                  root_argv,
                                  launcher_argv,
                                  sudo_child) ||
            !record_direct_launch_identity(sudo_child)) {
            error = "root broker provenance/endpoint validation failed: " +
                    direct_launch_diagnostic(sudo_child);
            break;
        }
        if (!send_frame(root_fd,
                        Frame{kCallerCredentials, token, credentials_payload(getuid(), getgid())},
                        kHandshakeMs)) {
            error = "caller credential frame failed";
            break;
        }
        if (!accept_bounded(endpoint.listener, broker_fd) ||
            !decode_ready(broker_fd, kBrokerDropped, token, broker_peer, broker_report) ||
            broker_peer.pid == root_peer.pid || !read_proc(broker_peer.pid, broker_proc) ||
            broker_proc.start == root_proc.start || broker_peer.uid != getuid() ||
            broker_peer.gid != getgid() || broker_proc.uid != getuid() ||
            broker_proc.gid != getgid() || broker_proc.ppid != root_peer.pid ||
            broker_peer.pid == static_cast<pid_t>(root_report.wrapper_pid) ||
            broker_proc.supplementary_groups != 0 || broker_proc.netns != topology.holder_netns ||
            broker_report.mode != "broker-dropped" ||
            broker_report.wrapper_pid != static_cast<u64>(root_peer.pid) ||
            !identity_matches_report(broker_report,
                                     broker_peer,
                                     broker_proc,
                                     executable,
                                     dropped_argv,
                                     "broker-dropped",
                                     token,
                                     token,
                                     true,
                                     false,
                                     true) ||
            !endpoint_unchanged(endpoint)) {
            error = "dropped broker identity transition failed";
            break;
        }
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
            if (strcmp(scenario, "normal") == 0 && !causal_mutation_self_checks(root_report,
                                                                                root_peer,
                                                                                root_proc,
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
                                                                                endpoint)) {
                error = "broker/target causal mutation self-check failed";
                break;
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
            while (process_alive(target_peer.pid) && std::chrono::steady_clock::now() < deadline)
                (void)poll(nullptr, 0, 10);
            if (process_alive(target_peer.pid)) {
                error = "broker death left live target";
                break;
            }
        } else if (strcmp(scenario, "broker-lease-loss") == 0) {
            close(target_fd);
            target_fd = -1;
            close(broker_fd);
            broker_fd = -1;
        }
        if (broker_fd >= 0 && strcmp(scenario, "broker-early") != 0 &&
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
        if (!wait_group_gone(launch_lease, kCleanupMs) || !launcher_gone_or_wnowait(sudo_child) ||
            !endpoint_unchanged(endpoint) || process_alive(root_peer.pid) ||
            (target_peer.pid > 1 && process_alive(target_peer.pid)) ||
            !no_process_with_token(token_text(token))) {
            error = "sudo/broker/target disappearance or endpoint ownership failed";
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
    if (root_fd >= 0) close(root_fd);
    if (broker_fd >= 0) close(broker_fd);
    if (target_fd >= 0) close(target_fd);
    if (!success) {
        // Closing leases is the first failure action.  The root/dropped/target
        // PDEATHSIG/EOF chain owns its descendants; allow that chain to settle
        // before considering any identity-safe fallback.
        (void)wait_identity_gone_or_reused(target_proc, kCleanupMs);
        (void)wait_identity_gone_or_reused(broker_proc, kCleanupMs);
        (void)wait_identity_gone_or_reused(root_proc, kCleanupMs);
        if (target_peer.pid > 1 && target_proc.pid == target_peer.pid &&
            process_alive(target_peer.pid))
            (void)terminate_verified(target_report, target_peer, target_proc);
        if (broker_peer.pid > 1 && broker_proc.pid == broker_peer.pid &&
            process_alive(broker_peer.pid))
            (void)terminate_verified(broker_report, broker_peer, broker_proc);
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
    if (sudo_path.empty() || nsenter_path.empty() ||
        !run_preflight_command({sudo_path, "-n", "--", "/bin/true"}) ||
        !run_preflight_command(
            {sudo_path, "-n", "--", nsenter_path, "--net=/proc/self/ns/net", "--", "/bin/true"})) {
        error = "passwordless sudo/nsenter network-namespace prerequisite unavailable";
        return false;
    }
    return true;
#endif
}

static bool run_positive(const std::string& sudo_path,
                         const std::string& nsenter_path,
                         const std::string& executable,
                         const HeldTopologySnapshot& topology,
                         std::string& error) {
    ProcIdentity host;
    if (!read_proc(getpid(), host) || topology.holder_pid <= 1 || topology.holder_start == 0 ||
        topology.holder_netns == 0 || !process_alive(topology.holder_pid) ||
        host.netns == topology.holder_netns) {
        error = "held topology holder identity changed before broker launch";
        return false;
    }
    for (const char* scenario : {"normal",
                                 "ready-loss",
                                 "no-ready",
                                 "term-ignore",
                                 "owned-wait-term-ignore",
                                 "broker-early",
                                 "broker-lease-loss"})
        if (!run_session(sudo_path, nsenter_path, executable, topology, scenario, error)) {
            error = std::string(scenario) + ": " + error;
            return false;
        }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 6 && strcmp(argv[1], "--fixture-broker-launcher") == 0)
        return launcher_main(argv[0], argv[2], argv[3], argv[4], argv[5]);
    if (argc == 6 && strcmp(argv[1], "--fixture-privileged-broker") == 0)
        return root_broker_main(argv[0], argv[2], argv[3], argv[4], argv[5]);
    if (argc == 7 && strcmp(argv[1], "--fixture-privileged-dropped-broker") == 0)
        return dropped_broker_main(argv[0], argv[2], argv[3], argv[4], argv[5], argv[6]);
    if (argc == 6 && strcmp(argv[1], "--fixture-privileged-target") == 0)
        return secured_target_main(argv[2], argv[3], argv[4], argv[5]);
    if (argc != 1) {
        std::cerr << "usage: test_fixture_privileged_broker\n";
        return 2;
    }
    std::array<char, PATH_MAX> self{};
    const ssize_t length = readlink("/proc/self/exe", self.data(), self.size() - 1);
    if (length <= 0) return 1;
    self[static_cast<size_t>(length)] = '\0';
    std::string sudo_path, nsenter_path, error;
    const bool required = getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED") != nullptr &&
                          strcmp(getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED"), "1") == 0;
    if (!pure_protocol_self_checks(error) || !endpoint_replacement_self_check(error) ||
        !bounded_wait_and_signal_self_check(error) || !group_lease_self_check(error)) {
        std::cerr << "FAIL [#358 Stage 2a3b protocol self-check]: " << error << "\n";
        return 1;
    }
    if (!preflight(sudo_path, nsenter_path, error)) {
        std::cerr << (required ? "FAIL" : "SKIP") << " [#358 Stage 2a3b preflight]: " << error
                  << "\n";
        return required ? 1 : 77;
    }
    const auto result = rut::test::ipv4_topology::run_with_held_topology(
        [&](const HeldTopologySnapshot& topology, std::string& callback_error) {
            return run_positive(sudo_path, nsenter_path, self.data(), topology, callback_error);
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
