// #358 Stage 2a3b: authenticated sudo/nsenter broker lifecycle only.
// No HTTP listener, nginx process, RUT process, or AF_INET socket is created here.

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

    ~ParentEndpoint() {
        if (listener >= 0) close(listener);
        if (!socket.empty()) (void)unlink(socket.c_str());
        if (!directory.empty()) (void)rmdir(directory.c_str());
    }
};

struct DirectChild {
    pid_t pid = -1;
    u64 start = 0;
    dev_t expected_exe_dev = 0;
    ino_t expected_exe_ino = 0;
    std::string expected_argv;
    int status = 0;
    bool reaped = false;
};

static bool endpoint_matches(const ParentEndpoint& endpoint, const EndpointIdentity& expected);
static bool endpoint_unchanged(const ParentEndpoint& endpoint);
static bool safe_signal_target(const Report& report,
                               const Peer& peer,
                               const ProcIdentity& expected,
                               int signal_number);

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
    if (!parse_credentials(credentials, parsed_uid, parsed_gid) || parsed_uid != uid ||
        parsed_gid != gid || !parse_credentials(changed_credentials, changed_uid, changed_gid) ||
        (changed_uid == uid && changed_gid == gid) ||
        credentials_match_peer(changed_credentials, uid, gid) ||
        parse_credentials(short_credentials, changed_uid, changed_gid) ||
        parse_credentials(root_credentials, changed_uid, changed_gid) ||
        !valid_security_trace(trace) || valid_security_trace(reordered_trace) ||
        valid_security_trace(duplicate_trace) || valid_security_trace(short_trace)) {
        error = "credential/security-trace mutation self-check failed";
        return false;
    }
    return true;
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
        (void)receive_frame(control, ignored, 60'000);
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
        if (!receive_frame(control, command, 60'000) || !token_equal(command.token, token) ||
            !command.payload.empty()) {
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
    alarm(15);
    Frame credentials;
    uid_t caller_uid = 0;
    gid_t caller_gid = 0;
    if (!receive_frame(kCredentialFd, credentials, kHandshakeMs) ||
        credentials.type != kCallerCredentials || !token_equal(credentials.token, token) ||
        !parse_credentials(credentials.payload, caller_uid, caller_gid) || caller_uid == 0)
        return 25;
    close(kCredentialFd);

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
        if (strcmp(scenario, "term-ignore") == 0) {
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
    alarm(0);
    Frame command;
    if (strcmp(scenario, "broker-early") == 0) {
        if (!receive_frame(control, command, 60'000) || command.type != kBrokerExitEarly ||
            !token_equal(command.token, token))
            return 33;
        _exit(86);
    }
    int target_status = 0;
    pid_t waited;
    do {
        waited = waitpid(target, &target_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != target) return 34;
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
    alarm(15);
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
    close(root_control);

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
    if (!send_frame(credential_pair[0],
                    Frame{kCallerCredentials, token, credentials.payload},
                    kHandshakeMs)) {
        close(credential_pair[0]);
        (void)kill(dropped, SIGKILL);
        return 28;
    }
    close(credential_pair[0]);
    alarm(0);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(dropped, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != dropped) return 29;
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
    const pid_t broker = fork();
    if (broker < 0) return 11;
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
    if (getppid() != parent) {
        (void)kill(broker, SIGKILL);
        return 12;
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(broker, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != broker) return 13;
    // Reap any target adopted after an intentionally early broker death.
    const bool broker_died_early = WIFEXITED(status) && WEXITSTATUS(status) == 86;
    const auto adopted_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs * 2);
    for (;;) {
        int adopted_status = 0;
        const pid_t adopted = waitpid(-1, &adopted_status, WNOHANG);
        if (adopted > 0) continue;
        if (adopted < 0 && errno == EINTR) continue;
        if (broker_died_early && adopted == 0 &&
            std::chrono::steady_clock::now() < adopted_deadline) {
            (void)poll(nullptr, 0, 10);
            continue;
        }
        break;
    }
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
    endpoint.socket = endpoint.directory + "/control.sock";
    if (chmod(endpoint.directory.c_str(), 0700) != 0 ||
        !create_listener(endpoint.socket, endpoint.listener) ||
        chmod(endpoint.socket.c_str(), 0600) != 0) {
        error = "parent AF_UNIX endpoint creation failed";
        return false;
    }
    struct stat directory{}, socket{};
    if (stat(endpoint.directory.c_str(), &directory) != 0 ||
        lstat(endpoint.socket.c_str(), &socket) != 0 || !S_ISDIR(directory.st_mode) ||
        !S_ISSOCK(socket.st_mode) || (directory.st_mode & 0777) != 0700 ||
        (socket.st_mode & 0777) != 0600 || directory.st_uid != getuid() ||
        socket.st_uid != getuid() || directory.st_gid != getgid() || socket.st_gid != getgid()) {
        error = "parent endpoint ownership/mode was not exact";
        return false;
    }
    endpoint.identity = {directory.st_dev,
                         directory.st_ino,
                         socket.st_dev,
                         socket.st_ino,
                         directory.st_uid,
                         directory.st_gid};
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

static bool wait_direct(DirectChild& child, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t waited = waitpid(child.pid, &child.status, WNOHANG);
        if (waited == child.pid) {
            child.reaped = true;
            return true;
        }
        if (waited < 0 && errno != EINTR) return false;
        (void)poll(nullptr, 0, 10);
    }
    return false;
}

static bool launch_sudo(const std::string& sudo_path,
                        const std::string& nsenter_path,
                        const std::string& executable,
                        const HeldTopologySnapshot& topology,
                        const ParentEndpoint& endpoint,
                        const Token& token,
                        const char* scenario,
                        DirectChild& child) {
    const std::string netns = "/proc/" + std::to_string(topology.holder_pid) + "/ns/net";
    const std::string netns_arg = "--net=" + netns;
    const std::string expected_netns = std::to_string(topology.holder_netns);
    const std::string token_value = token_text(token);
    struct stat sudo_status{};
    if (stat(sudo_path.c_str(), &sudo_status) != 0) return false;
    child.expected_exe_dev = sudo_status.st_dev;
    child.expected_exe_ino = sudo_status.st_ino;
    child.expected_argv = exact_argv({sudo_path,
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
    child.pid = fork();
    if (child.pid < 0) return false;
    if (child.pid == 0) {
        (void)setpgid(0, 0);
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
    (void)setpgid(child.pid, child.pid);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    do {
        ProcIdentity identity;
        if (read_proc(child.pid, identity, false)) {
            child.start = identity.start;
            return true;
        }
        (void)poll(nullptr, 0, 5);
    } while (std::chrono::steady_clock::now() < deadline);
    (void)kill(-child.pid, SIGKILL);
    while (waitpid(child.pid, &child.status, 0) < 0 && errno == EINTR) {
    }
    child.reaped = true;
    return false;
}

static bool decode_ready(
    int fd, u16 expected_type, const Token& token, Peer& peer, Report& report) {
    Frame frame;
    return get_peer(fd, peer) && receive_frame(fd, frame, kHandshakeMs) &&
           frame.type == expected_type && token_equal(frame.token, token) &&
           decode_report(frame.payload, report);
}

static bool ancestor_contains(pid_t start, pid_t expected, size_t limit) {
    pid_t current = start;
    for (size_t depth = 0; depth != limit && current > 1; ++depth) {
        if (current == expected) return true;
        ProcIdentity identity;
        if (!read_proc(current, identity, false) || identity.ppid == current) return false;
        current = identity.ppid;
    }
    return current == expected;
}

static bool validate_root_broker(const Report& report,
                                 const Peer& peer,
                                 const ProcIdentity& proc,
                                 const HeldTopologySnapshot& topology,
                                 const std::string& executable,
                                 const std::string& expected_argv,
                                 const std::string& expected_launcher_argv,
                                 const DirectChild& sudo_child) {
    if (peer.pid <= 1 || peer.uid != 0 || peer.gid != 0 ||
        report.target_pid != static_cast<u64>(peer.pid) ||
        report.target_pid != static_cast<u64>(proc.pid) || report.wrapper_pid <= 1 ||
        report.target_pid == report.wrapper_pid || report.start != proc.start ||
        report.netns != topology.holder_netns || proc.netns != topology.holder_netns ||
        report.uid != 0 || report.gid != 0 || report.exe != executable || proc.exe != executable ||
        report.exe_dev != proc.exe_dev || report.exe_ino != proc.exe_ino ||
        report.argv != expected_argv || proc.cmdline != expected_argv ||
        report.mode != "broker-root" || proc.ppid != static_cast<pid_t>(report.wrapper_pid) ||
        peer.pid == sudo_child.pid)
        return false;
    ProcIdentity launcher;
    ProcIdentity sudo_identity;
    return proc.ppid != sudo_child.pid && read_proc(proc.ppid, launcher, false) &&
           launcher.netns == topology.holder_netns && launcher.exe == executable &&
           launcher.cmdline == expected_launcher_argv &&
           read_proc(sudo_child.pid, sudo_identity, false) &&
           sudo_identity.start == sudo_child.start &&
           sudo_identity.exe_dev == sudo_child.expected_exe_dev &&
           sudo_identity.exe_ino == sudo_child.expected_exe_ino &&
           sudo_identity.cmdline == sudo_child.expected_argv &&
           ancestor_contains(proc.ppid, sudo_child.pid, 8);
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
                                        const DirectChild& sudo_child,
                                        const ParentEndpoint& endpoint) {
    const bool root_baseline = validate_root_broker(root_report,
                                                    root_peer,
                                                    root_proc,
                                                    topology,
                                                    executable,
                                                    root_argv,
                                                    launcher_argv,
                                                    sudo_child);
    Report changed_root = root_report;
    changed_root.netns++;
    Peer changed_root_peer = root_peer;
    changed_root_peer.pid++;
    ProcIdentity changed_root_proc = root_proc;
    changed_root_proc.start++;
    const bool root_mutations = !validate_root_broker(changed_root,
                                                      root_peer,
                                                      root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      sudo_child) &&
                                !validate_root_broker(root_report,
                                                      changed_root_peer,
                                                      root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      sudo_child) &&
                                !validate_root_broker(root_report,
                                                      root_peer,
                                                      changed_root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      sudo_child) &&
                                !validate_root_broker(root_report,
                                                      root_peer,
                                                      root_proc,
                                                      topology,
                                                      executable,
                                                      root_argv,
                                                      launcher_argv,
                                                      DirectChild{sudo_child.pid,
                                                                  sudo_child.start + 1,
                                                                  sudo_child.expected_exe_dev,
                                                                  sudo_child.expected_exe_ino,
                                                                  sudo_child.expected_argv,
                                                                  0,
                                                                  false});
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
    EndpointIdentity changed_endpoint = endpoint.identity;
    changed_endpoint.socket_ino++;
    const std::vector<unsigned char> trace{'G', 'D', 'U', 'N', 'C', 'P', 'X'};
    std::vector<unsigned char> swapped_trace = trace;
    std::swap(swapped_trace[1], swapped_trace[2]);
    std::vector<unsigned char> short_trace = trace;
    short_trace.pop_back();
    return root_baseline && root_mutations && broker_baseline && broker_mutations &&
           target_baseline && target_mutations && signal_mutations &&
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
    return kill(-current.pgid, signal_number) == 0;
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
    DirectChild sudo_child;
    if (!launch_sudo(
            sudo_path, nsenter_path, executable, topology, endpoint, token, scenario, sudo_child)) {
        error = "sudo/nsenter launch failed";
        return false;
    }
    int root_fd = -1, broker_fd = -1, target_fd = -1;
    Report root_report, broker_report, target_report;
    Peer root_peer, broker_peer, target_peer;
    ProcIdentity root_proc, broker_proc, target_proc;
    bool success = false;
    do {
        if (!accept_bounded(endpoint.listener, root_fd) ||
            !decode_ready(root_fd, kBrokerRootHello, token, root_peer, root_report) ||
            !read_proc(root_peer.pid, root_proc, false)) {
            error = "root broker HELLO/peer identity failed";
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
        if (!validate_root_broker(root_report,
                                  root_peer,
                                  root_proc,
                                  topology,
                                  executable,
                                  root_argv,
                                  launcher_argv,
                                  sudo_child) ||
            !endpoint_unchanged(endpoint)) {
            error = "root broker provenance/endpoint validation failed";
            break;
        }
        if (!send_frame(root_fd,
                        Frame{kCallerCredentials, token, credentials_payload(getuid(), getgid())},
                        kHandshakeMs)) {
            error = "caller credential frame failed";
            break;
        }
        close(root_fd);
        root_fd = -1;
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
                target_peer.pid == broker_peer.pid || target_peer.pid == sudo_child.pid ||
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
                strcmp(scenario, "term-ignore") == 0
                    ? WIFSIGNALED(target_status) && WTERMSIG(target_status) == SIGKILL
                    : WIFEXITED(target_status) && WEXITSTATUS(target_status) == 0;
            if (!expected_status) {
                error = "broker reported an unexpected exact target status";
                break;
            }
        }
        if (!wait_direct(sudo_child, kBrokerDeadlineMs) || !sudo_child.reaped ||
            !endpoint_unchanged(endpoint) || process_alive(root_peer.pid) ||
            (target_peer.pid > 1 && process_alive(target_peer.pid)) ||
            !no_process_with_token(token_text(token)) || !WIFEXITED(sudo_child.status) ||
            (strcmp(scenario, "broker-early") == 0        ? WEXITSTATUS(sudo_child.status) != 86
             : strcmp(scenario, "broker-lease-loss") == 0 ? WEXITSTATUS(sudo_child.status) != 35
                                                          : WEXITSTATUS(sudo_child.status) != 0)) {
            error = "sudo/broker/target disappearance or endpoint ownership failed";
            break;
        }
        success = true;
    } while (false);
    if (root_fd >= 0) close(root_fd);
    if (broker_fd >= 0) close(broker_fd);
    if (target_fd >= 0) close(target_fd);
    if (!success && target_peer.pid > 1 && target_proc.pid == target_peer.pid &&
        process_alive(target_peer.pid))
        (void)terminate_verified(target_report, target_peer, target_proc);
    if (!success && broker_peer.pid > 1 && broker_proc.pid == broker_peer.pid &&
        process_alive(broker_peer.pid))
        (void)terminate_verified(broker_report, broker_peer, broker_proc);
    if (!sudo_child.reaped && sudo_child.pid > 1) {
        (void)kill(-sudo_child.pid, SIGTERM);
        if (!wait_direct(sudo_child, kCleanupMs)) {
            (void)kill(-sudo_child.pid, SIGKILL);
            (void)wait_direct(sudo_child, kCleanupMs);
        }
    }
    if (!endpoint_unchanged(endpoint) && error.empty()) error = "endpoint changed during cleanup";
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
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
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
    ProcIdentity host, holder;
    if (!read_proc(getpid(), host) || !read_proc(topology.holder_pid, holder, false) ||
        holder.start != topology.holder_start || holder.netns != topology.holder_netns ||
        host.netns == topology.holder_netns) {
        error = "held topology holder identity changed before broker launch";
        return false;
    }
    for (const char* scenario :
         {"normal", "ready-loss", "no-ready", "term-ignore", "broker-early", "broker-lease-loss"})
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
    if (!pure_protocol_self_checks(error)) {
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
