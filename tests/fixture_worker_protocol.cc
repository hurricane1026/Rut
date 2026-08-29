#include "fixture_worker_protocol.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace rut::test::fixture_worker_protocol {

bool read_file(const std::string& path, std::string& out, size_t limit) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    std::array<char, 4096> buffer{};
    bool ok = true;
    for (;;) {
        const ssize_t n = read(fd, buffer.data(), buffer.size());
        if (n > 0) {
            if (out.size() > limit - static_cast<size_t>(n)) {
                ok = false;
                break;
            }
            out.append(buffer.data(), static_cast<size_t>(n));
        } else if (n == 0) {
            break;
        } else if (errno != EINTR) {
            ok = false;
            break;
        }
    }
    close(fd);
    return ok;
}

bool wait_fd(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        if (left <= 0) return false;
        pollfd p{fd, events, 0};
        const int rc = poll(&p, 1, static_cast<int>(left));
        if (rc < 0 && errno == EINTR) continue;
        return rc > 0 && (p.revents & (events | POLLERR | POLLHUP)) != 0;
    }
}

bool write_exact(int fd, const unsigned char* data, size_t size, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t done = 0;
    while (done != size) {
        if (!wait_fd(fd, POLLOUT, deadline)) return false;
        const ssize_t n = write(fd, data + done, size - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

bool read_exact(int fd, unsigned char* data, size_t size, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t done = 0;
    while (done != size) {
        if (!wait_fd(fd, POLLIN, deadline)) return false;
        const ssize_t n = read(fd, data + done, size - done);
        if (n > 0) {
            done += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static void put16(std::vector<unsigned char>& out, u16 value) {
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

static void put32(std::vector<unsigned char>& out, u32 value) {
    for (unsigned shift = 0; shift != 32; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

static void put64(std::vector<unsigned char>& out, u64 value) {
    for (unsigned shift = 0; shift != 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

static bool get16(const std::vector<unsigned char>& in, size_t& at, u16& value) {
    if (at > in.size() || in.size() - at < 2) return false;
    value = static_cast<u16>(in[at]) | static_cast<u16>(in[at + 1] << 8);
    at += 2;
    return true;
}

static bool get64(const std::vector<unsigned char>& in, size_t& at, u64& value) {
    if (at > in.size() || in.size() - at < 8) return false;
    value = 0;
    for (unsigned shift = 0; shift != 64; shift += 8) value |= static_cast<u64>(in[at++]) << shift;
    return true;
}

std::vector<unsigned char> frame_bytes(const Frame& frame) {
    std::vector<unsigned char> out;
    out.reserve(kHeaderBytes + frame.payload.size());
    put32(out, kMagic);
    put16(out, kVersion);
    put16(out, frame.type);
    put32(out, static_cast<u32>(frame.payload.size()));
    out.insert(out.end(), frame.token.bytes.begin(), frame.token.bytes.end());
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return out;
}

bool send_frame(int fd, const Frame& frame, int timeout_ms) {
    const std::vector<unsigned char> bytes = frame_bytes(frame);
    return bytes.size() <= kHeaderBytes + kMaxPayload &&
           write_exact(fd, bytes.data(), bytes.size(), timeout_ms);
}

bool valid_frame_header(const unsigned char* header, const Token& expected) {
    const u32 magic = static_cast<u32>(header[0]) | (static_cast<u32>(header[1]) << 8) |
                      (static_cast<u32>(header[2]) << 16) | (static_cast<u32>(header[3]) << 24);
    const u16 version = static_cast<u16>(header[4]) | static_cast<u16>(header[5] << 8);
    const u32 length = static_cast<u32>(header[8]) | (static_cast<u32>(header[9]) << 8) |
                       (static_cast<u32>(header[10]) << 16) | (static_cast<u32>(header[11]) << 24);
    return magic == kMagic && version == kVersion && length <= kMaxPayload &&
           std::equal(header + 12, header + kHeaderBytes, expected.bytes.begin());
}

bool receive_frame(int fd, Frame& frame, int timeout_ms) {
    std::array<unsigned char, kHeaderBytes> header{};
    if (!read_exact(fd, header.data(), header.size(), timeout_ms)) return false;
    frame.type = static_cast<u16>(header[6]) | static_cast<u16>(header[7] << 8);
    const u32 length = static_cast<u32>(header[8]) | (static_cast<u32>(header[9]) << 8) |
                       (static_cast<u32>(header[10]) << 16) | (static_cast<u32>(header[11]) << 24);
    std::copy(header.begin() + 12, header.end(), frame.token.bytes.begin());
    if (length > kMaxPayload || !valid_frame_header(header.data(), frame.token)) return false;
    frame.payload.assign(length, 0);
    return length == 0 || read_exact(fd, frame.payload.data(), length, timeout_ms);
}

bool token_equal(const Token& a, const Token& b) {
    return a.bytes == b.bytes;
}

bool read_proc(pid_t pid, ProcIdentity& result) {
    if (pid <= 0) return false;
    std::string stat_text;
    if (!read_file("/proc/" + std::to_string(pid) + "/stat", stat_text, 8192)) return false;
    const size_t comm_end = stat_text.rfind(") ");
    if (comm_end == std::string::npos) return false;
    std::istringstream fields(stat_text.substr(comm_end + 2));
    char state = 0;
    long ppid = 0;
    long pgrp = 0;
    if (!(fields >> state >> ppid >> pgrp)) return false;
    long ignored = 0;
    u64 start = 0;
    for (int field = 6; field <= 22; ++field) {
        if (field == 22) {
            unsigned long long value = 0;
            if (!(fields >> value)) return false;
            start = static_cast<u64>(value);
        } else if (!(fields >> ignored)) {
            return false;
        }
    }
    result.pid = pid;
    result.ppid = static_cast<pid_t>(ppid);
    result.start = start;
    result.pgid = static_cast<pid_t>(pgrp);

    std::string status;
    if (!read_file("/proc/" + std::to_string(pid) + "/status", status)) return false;
    bool have_uid = false;
    bool have_gid = false;
    bool have_nnp = false;
    bool have_inh = false;
    bool have_prm = false;
    bool have_eff = false;
    bool have_groups = false;
    std::istringstream lines(status);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream value(line.substr(line.find(':') + 1));
        if (line.rfind("Uid:", 0) == 0) {
            unsigned long v = 0;
            if (!(value >> v)) return false;
            result.uid = static_cast<uid_t>(v);
            have_uid = true;
        } else if (line.rfind("Gid:", 0) == 0) {
            unsigned long v = 0;
            if (!(value >> v)) return false;
            result.gid = static_cast<gid_t>(v);
            have_gid = true;
        } else if (line.rfind("NoNewPrivs:", 0) == 0) {
            int v = 0;
            if (!(value >> v)) return false;
            result.no_new_privs = v == 1;
            have_nnp = true;
        } else if (line.rfind("Groups:", 0) == 0) {
            std::istringstream group_values(line.substr(line.find(':') + 1));
            std::string group;
            size_t count = 0;
            while (group_values >> group) ++count;
            result.supplementary_groups = count;
            have_groups = true;
        } else if (line.rfind("CapInh:", 0) == 0 || line.rfind("CapPrm:", 0) == 0 ||
                   line.rfind("CapEff:", 0) == 0) {
            std::string hex;
            if (!(value >> hex)) return false;
            const bool clear = hex.find_first_not_of('0') == std::string::npos;
            if (line.rfind("CapInh:", 0) == 0) have_inh = clear;
            if (line.rfind("CapPrm:", 0) == 0) have_prm = clear;
            if (line.rfind("CapEff:", 0) == 0) have_eff = clear;
        }
    }
    result.capabilities_clear = have_inh && have_prm && have_eff;
    if (!have_uid || !have_gid || !have_nnp || !have_groups) return false;
    struct stat netns{};
    struct stat executable{};
    if (stat(("/proc/" + std::to_string(pid) + "/ns/net").c_str(), &netns) != 0 ||
        stat(("/proc/" + std::to_string(pid) + "/exe").c_str(), &executable) != 0)
        return false;
    result.netns = netns.st_ino;
    result.exe_dev = executable.st_dev;
    result.exe_ino = executable.st_ino;
    std::array<char, PATH_MAX> exe{};
    const ssize_t length =
        readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), exe.data(), exe.size() - 1);
    if (length <= 0) return false;
    result.exe.assign(exe.data(), static_cast<size_t>(length));
    if (!read_file("/proc/" + std::to_string(pid) + "/cmdline", result.cmdline, 8192)) return false;
    return result.netns != 0 && result.start != 0 && result.pgid > 0 && result.capabilities_clear;
}

bool get_peer(int fd, Peer& peer) {
#ifdef SO_PEERCRED
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials))
        return false;
    peer.pid = credentials.pid;
    peer.uid = credentials.uid;
    peer.gid = credentials.gid;
    return peer.pid > 0;
#else
    (void)fd;
    (void)peer;
    return false;
#endif
}

int connect_control(const char* path) {
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    memcpy(address.sun_path, path, strlen(path) + 1);
    const int rc = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc != 0 &&
        !wait_fd(fd,
                 POLLOUT,
                 std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs))) {
        close(fd);
        return -1;
    }
    int error = 0;
    socklen_t error_length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 || error != 0) {
        close(fd);
        return -1;
    }
    (void)fcntl(fd, F_SETFL, flags);
    return fd;
}

static bool clear_capabilities() {
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    __user_cap_data_struct data[2]{};
    return syscall(SYS_capset, &header, data) == 0;
}

bool child_security_setup(u64& groups_clear) {
    groups_clear = 0;
    const int group_count = getgroups(0, nullptr);
    if (group_count < 0) return false;
    if (setgroups(0, nullptr) == 0) {
        groups_clear = 1;
    } else if (errno != EPERM) {
        return false;
    } else {
        // An unprivileged process may not clear groups.  EPERM is the only
        // permitted outcome; the parent still independently reads Uid/Gid.
        groups_clear = group_count == 0 ? 1 : 0;
    }
    const uid_t invoking_uid = getuid();
    const gid_t invoking_gid = getgid();
    if (setgid(invoking_gid) != 0 || setuid(invoking_uid) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || !clear_capabilities() || setpgid(0, 0) != 0)
        return false;
    ProcIdentity self;
    return read_proc(getpid(), self) && self.uid == invoking_uid && self.gid == invoking_gid &&
           self.pgid == getpid() && self.no_new_privs && self.capabilities_clear;
}

bool token_from_hex(const char* text, Token& token) {
    if (text == nullptr || strlen(text) != 2 * kTokenBytes) return false;
    for (size_t i = 0; i != kTokenBytes; ++i) {
        const auto nibble = [](unsigned char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int high = nibble(static_cast<unsigned char>(text[2 * i]));
        const int low = nibble(static_cast<unsigned char>(text[2 * i + 1]));
        if (high < 0 || low < 0) return false;
        token.bytes[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

std::string make_expected_argv(const char* executable,
                               const char* path,
                               const char* token,
                               const char* mode,
                               const char* role) {
    std::string result;
    result.append(executable, strlen(executable) + 1);
    result.append(role, strlen(role) + 1);
    result.append(path, strlen(path) + 1);
    result.append(token, strlen(token) + 1);
    result.append(mode, strlen(mode) + 1);
    return result;
}

std::vector<unsigned char> encode_report(const Report& report) {
    if (report.exe.size() > std::numeric_limits<u16>::max() ||
        report.argv.size() > std::numeric_limits<u16>::max() ||
        report.mode.size() > std::numeric_limits<u16>::max())
        return {};
    std::vector<unsigned char> out;
    out.reserve(kReportFixedBytes + report.exe.size() + report.argv.size() + report.mode.size());
    put64(out, report.target_pid);
    put64(out, report.wrapper_pid);
    put64(out, report.start);
    put64(out, report.pgid);
    put64(out, report.uid);
    put64(out, report.gid);
    put64(out, report.netns);
    put64(out, report.exe_dev);
    put64(out, report.exe_ino);
    put64(out, report.no_new_privs);
    put64(out, report.capabilities_clear);
    put64(out, report.groups_clear);
    put64(out, report.groups_unchanged);
    put16(out, static_cast<u16>(report.exe.size()));
    put16(out, static_cast<u16>(report.argv.size()));
    put16(out, static_cast<u16>(report.mode.size()));
    put16(out, 0);
    out.insert(out.end(), report.exe.begin(), report.exe.end());
    out.insert(out.end(), report.argv.begin(), report.argv.end());
    out.insert(out.end(), report.mode.begin(), report.mode.end());
    return out;
}

bool decode_report(const std::vector<unsigned char>& payload, Report& report) {
    if (payload.size() < kReportFixedBytes) return false;
    size_t at = 0;
    if (!get64(payload, at, report.target_pid) || !get64(payload, at, report.wrapper_pid) ||
        !get64(payload, at, report.start) || !get64(payload, at, report.pgid) ||
        !get64(payload, at, report.uid) || !get64(payload, at, report.gid) ||
        !get64(payload, at, report.netns) || !get64(payload, at, report.exe_dev) ||
        !get64(payload, at, report.exe_ino) || !get64(payload, at, report.no_new_privs) ||
        !get64(payload, at, report.capabilities_clear) ||
        !get64(payload, at, report.groups_clear) || !get64(payload, at, report.groups_unchanged))
        return false;
    u16 exe_length = 0;
    u16 argv_length = 0;
    u16 mode_length = 0;
    u16 reserved = 0;
    if (!get16(payload, at, exe_length) || !get16(payload, at, argv_length) ||
        !get16(payload, at, mode_length) || !get16(payload, at, reserved) || reserved != 0)
        return false;
    const size_t total = static_cast<size_t>(exe_length) + argv_length + mode_length;
    if (total != payload.size() - at) return false;
    report.exe.assign(reinterpret_cast<const char*>(payload.data() + at), exe_length);
    at += exe_length;
    report.argv.assign(reinterpret_cast<const char*>(payload.data() + at), argv_length);
    at += argv_length;
    report.mode.assign(reinterpret_cast<const char*>(payload.data() + at), mode_length);
    // Every string field has an exact wire length and no embedded NUL.  argv
    // is the sole exception: it is deliberately a NUL-separated vector.
    if (report.exe.empty() || report.exe.back() == '\0' || report.mode.empty() ||
        report.mode.back() == '\0' || report.mode.find('\0') != std::string::npos ||
        report.argv.empty() || report.argv.back() != '\0')
        return false;
    return true;
}

bool identity_matches_report(const Report& report,
                             const Peer& peer,
                             const ProcIdentity& proc,
                             const std::string& expected_exe,
                             const std::string& expected_argv,
                             const std::string& expected_mode,
                             const Token& token,
                             const Token& frame_token,
                             bool authority,
                             bool require_wrapper_equal,
                             bool require_groups_clear) {
    if (!authority || !token_equal(token, frame_token) || report.target_pid <= 1 ||
        report.wrapper_pid == 0 || report.pgid <= 1 || report.pgid != report.target_pid ||
        report.target_pid != static_cast<u64>(peer.pid) || report.uid != peer.uid ||
        report.gid != peer.gid || report.target_pid != static_cast<u64>(proc.pid) ||
        report.start != proc.start || report.pgid != static_cast<u64>(proc.pgid) ||
        report.uid != proc.uid || report.gid != proc.gid || report.netns != proc.netns ||
        report.exe != expected_exe || report.exe != proc.exe || report.exe_dev != proc.exe_dev ||
        report.exe_ino != proc.exe_ino || report.argv != expected_argv ||
        report.argv != proc.cmdline || report.mode != expected_mode || report.no_new_privs != 1 ||
        report.capabilities_clear != 1 || report.groups_clear > 1 || report.groups_unchanged > 1 ||
        report.groups_clear + report.groups_unchanged != 1 ||
        ((proc.supplementary_groups == 0) != (report.groups_clear == 1)) ||
        ((proc.supplementary_groups != 0) != (report.groups_unchanged == 1)) ||
        (require_groups_clear && report.groups_clear != 1) || !proc.no_new_privs ||
        !proc.capabilities_clear)
        return false;
    // A synthetic wrapper may differ, but it can never replace the exact
    // peercred/proc target identity above.
    return !require_wrapper_equal || report.wrapper_pid == report.target_pid;
}

bool process_alive(pid_t pid) {
    if (pid <= 0) return false;
    if (kill(pid, 0) == 0) return true;
    return errno == EPERM;
}

bool same_process_identity(const ProcIdentity& a, const ProcIdentity& b) {
    return a.pid == b.pid && a.ppid == b.ppid && a.start == b.start && a.pgid == b.pgid &&
           a.uid == b.uid && a.uid != static_cast<uid_t>(-1) && a.gid == b.gid &&
           a.netns == b.netns && a.exe_dev == b.exe_dev && a.exe_ino == b.exe_ino &&
           a.exe == b.exe && a.cmdline == b.cmdline && a.no_new_privs == b.no_new_privs &&
           a.capabilities_clear == b.capabilities_clear &&
           a.supplementary_groups == b.supplementary_groups;
}

bool reap_bounded(Child& child, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        const pid_t rc = waitpid(child.pid, &child.status, WNOHANG);
        if (rc == child.pid) {
            child.reaped = true;
            return true;
        }
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0 || std::chrono::steady_clock::now() >= deadline) return false;
        poll(nullptr, 0, 5);
    }
}

bool target_gone_or_reused(const ProcIdentity& before) {
    ProcIdentity after;
    if (!read_proc(before.pid, after)) return true;
    return after.start != before.start || after.exe_dev != before.exe_dev ||
           after.exe_ino != before.exe_ino || after.exe != before.exe;
}

bool safe_cleanup(Child& child,
                  const Report& report,
                  const Peer& peer,
                  const ProcIdentity& before,
                  const Token& token,
                  const Token& frame_token,
                  bool authority) {
    ProcIdentity current;
    if (child.pid <= 1 || child.target_pid <= 1 || !authority ||
        report.target_pid != static_cast<u64>(child.target_pid) ||
        report.wrapper_pid != static_cast<u64>(child.pid) || report.pgid != report.target_pid ||
        before.pid != child.target_pid || !read_proc(child.target_pid, current) ||
        current.ppid != child.pid || !same_process_identity(before, current) ||
        !identity_matches_report(report,
                                 peer,
                                 current,
                                 current.exe,
                                 current.cmdline,
                                 report.mode,
                                 token,
                                 frame_token,
                                 true,
                                 false))
        return false;
    if (kill(-static_cast<pid_t>(report.pgid), 0) != 0) return false;
    if (kill(-static_cast<pid_t>(report.pgid), SIGTERM) != 0) return false;
    if (reap_bounded(child, kCleanupMs)) return target_gone_or_reused(before);
    // Never escalate to KILL after identity has gone stale or disappeared.
    ProcIdentity after;
    if (!read_proc(child.target_pid, after) || !same_process_identity(before, after)) return false;
    if (kill(-static_cast<pid_t>(report.pgid), SIGKILL) != 0) return false;
    return reap_bounded(child, kCleanupMs) && target_gone_or_reused(before);
}

bool safe_cleanup_unready(Child& child,
                          const ProcIdentity& expected,
                          const std::string& expected_argv,
                          bool authority) {
    if (!authority || child.pid <= 1 || child.target_pid <= 1 || expected.pid != child.target_pid ||
        expected.pgid != child.target_pid || expected.pgid <= 1 || !expected.no_new_privs ||
        !expected.capabilities_clear)
        return false;
    ProcIdentity current;
    if (!read_proc(child.target_pid, current) || current.start != expected.start ||
        current.ppid != expected.ppid || current.pgid != expected.pgid ||
        current.uid != expected.uid || current.gid != expected.gid ||
        current.netns != expected.netns || current.exe != expected.exe ||
        current.exe_dev != expected.exe_dev || current.exe_ino != expected.exe_ino ||
        current.cmdline != expected_argv || !current.no_new_privs || !current.capabilities_clear)
        return false;
    if (kill(-expected.pgid, 0) != 0) return false;
    if (kill(-expected.pgid, SIGTERM) != 0) return false;
    if (reap_bounded(child, kCleanupMs)) return true;
    if (!read_proc(child.target_pid, current) || !same_process_identity(expected, current) ||
        current.cmdline != expected_argv)
        return false;
    if (kill(-expected.pgid, SIGKILL) != 0) return false;
    return reap_bounded(child, kCleanupMs);
}

bool safe_cleanup_orphan_target(pid_t target_pid, const ProcIdentity& expected, bool authority) {
    if (!authority || target_pid <= 1 || expected.pid != target_pid ||
        expected.pgid != target_pid || expected.pgid <= 1)
        return false;
    ProcIdentity current;
    if (!read_proc(target_pid, current) || !same_process_identity(expected, current)) return false;
    if (kill(-expected.pgid, 0) != 0 || kill(-expected.pgid, SIGTERM) != 0) return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (target_gone_or_reused(expected)) return true;
        poll(nullptr, 0, 5);
    }
    if (!read_proc(target_pid, current) || !same_process_identity(expected, current) ||
        kill(-expected.pgid, 0) != 0 || kill(-expected.pgid, SIGKILL) != 0)
        return false;
    const auto kill_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kCleanupMs);
    while (std::chrono::steady_clock::now() < kill_deadline) {
        if (target_gone_or_reused(expected)) return true;
        poll(nullptr, 0, 5);
    }
    return target_gone_or_reused(expected);
}

bool create_listener(const std::string& path, int& fd) {
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return false;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) {
        close(fd);
        fd = -1;
        return false;
    }
    memcpy(address.sun_path, path.data(), path.size() + 1);
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        chmod(path.c_str(), 0600) != 0 || listen(fd, 1) != 0) {
        close(fd);
        fd = -1;
        return false;
    }
    return true;
}

bool accept_bounded(int listener, int& fd) {
    fd = -1;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kHandshakeMs);
    for (;;) {
        if (!wait_fd(listener, POLLIN, deadline)) return false;
        fd = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd >= 0) return true;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return false;
    }
}

}  // namespace rut::test::fixture_worker_protocol
