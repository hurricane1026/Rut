// Standalone #358 Stage 2a1 protocol self-check.
//
// This test intentionally has no Docker, sudo, namespace, IP socket, or shell
// dependency.  The parent creates and owns the control socket; the child only
// connects to the already-listening endpoint and reports its identity.

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
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr u32 kMagic = 0x31523335u;  // "53R1", deliberately not a string protocol.
constexpr u16 kVersion = 1;
constexpr u16 kReady = 1;
constexpr u16 kPing = 2;
constexpr u16 kPong = 3;
constexpr u16 kRelease = 4;
constexpr u16 kReleased = 5;
constexpr size_t kTokenBytes = 32;
static_assert(kTokenBytes == 32);
constexpr size_t kHeaderBytes = 4 + 2 + 2 + 4 + kTokenBytes;
constexpr size_t kReportFixedBytes = 13 * sizeof(u64) + 4 * sizeof(u16);
constexpr size_t kMaxPayload = 8192;
constexpr int kHandshakeMs = 2500;
constexpr int kCleanupMs = 350;

struct Token {
    std::array<unsigned char, kTokenBytes> bytes{};
};

struct Frame {
    u16 type = 0;
    Token token;
    std::vector<unsigned char> payload;
};

struct ProcIdentity {
    pid_t pid = -1;
    pid_t ppid = -1;
    u64 start = 0;
    pid_t pgid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    ino_t netns = 0;
    dev_t exe_dev = 0;
    ino_t exe_ino = 0;
    std::string exe;
    std::string cmdline;
    bool no_new_privs = false;
    bool capabilities_clear = false;
    size_t supplementary_groups = 0;
};

struct Report {
    u64 target_pid = 0;
    u64 wrapper_pid = 0;
    u64 start = 0;
    u64 pgid = 0;
    u64 uid = 0;
    u64 gid = 0;
    u64 netns = 0;
    u64 exe_dev = 0;
    u64 exe_ino = 0;
    u64 no_new_privs = 0;
    u64 capabilities_clear = 0;
    u64 groups_clear = 0;
    u64 groups_unchanged = 0;
    std::string exe;
    std::string argv;
    std::string mode;
};

struct Peer {
    pid_t pid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
};

struct Child {
    pid_t pid = -1;
    pid_t target_pid = -1;
    int status = 0;
    bool reaped = false;
};

bool read_file(const std::string& path, std::string& out, size_t limit = 128 * 1024) {
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

void put16(std::vector<unsigned char>& out, u16 value) {
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void put32(std::vector<unsigned char>& out, u32 value) {
    for (unsigned shift = 0; shift != 32; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

void put64(std::vector<unsigned char>& out, u64 value) {
    for (unsigned shift = 0; shift != 64; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

bool get16(const std::vector<unsigned char>& in, size_t& at, u16& value) {
    if (at > in.size() || in.size() - at < 2) return false;
    value = static_cast<u16>(in[at]) | static_cast<u16>(in[at + 1] << 8);
    at += 2;
    return true;
}

bool get64(const std::vector<unsigned char>& in, size_t& at, u64& value) {
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

bool token_from_hex(const char* text, Token& token);
std::vector<unsigned char> encode_report(const Report& report);
bool decode_report(const std::vector<unsigned char>& payload, Report& report);
bool token_equal(const Token& a, const Token& b);

bool run_transport_tests(const Token& token, std::string& error) {
    auto one_case = [&](const std::vector<unsigned char>& bytes,
                        size_t bytes_to_write,
                        bool expect_success,
                        bool fragment) {
        int sockets[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
        bool wrote = true;
        if (fragment) {
            for (size_t i = 0; i != bytes_to_write && wrote; ++i)
                wrote = write(sockets[0], bytes.data() + i, 1) == 1;
        } else if (bytes_to_write != 0) {
            wrote = write(sockets[0], bytes.data(), bytes_to_write) ==
                    static_cast<ssize_t>(bytes_to_write);
        }
        if (shutdown(sockets[0], SHUT_WR) != 0) wrote = false;
        Frame received;
        const bool result = receive_frame(sockets[1], received, kHandshakeMs);
        close(sockets[0]);
        close(sockets[1]);
        return wrote && result == expect_success;
    };

    const Frame fragmented_frame{kPing, token, {9, 8, 7, 6, 5}};
    const std::vector<unsigned char> fragmented_bytes = frame_bytes(fragmented_frame);
    int fragmented_sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fragmented_sockets) != 0) {
        error = "fragmented frame socketpair failed";
        return false;
    }
    bool fragmented_write = true;
    for (size_t i = 0; i != fragmented_bytes.size() && fragmented_write; ++i)
        fragmented_write = write(fragmented_sockets[0], fragmented_bytes.data() + i, 1) == 1;
    (void)shutdown(fragmented_sockets[0], SHUT_WR);
    Frame fragmented_received;
    const bool fragmented_read =
        receive_frame(fragmented_sockets[1], fragmented_received, kHandshakeMs);
    const bool fragmented_exact = fragmented_received.type == fragmented_frame.type &&
                                  token_equal(fragmented_received.token, fragmented_frame.token) &&
                                  fragmented_received.payload == fragmented_frame.payload;
    close(fragmented_sockets[0]);
    close(fragmented_sockets[1]);
    if (!fragmented_write || !fragmented_read || !fragmented_exact) {
        error = "fragmented frame transport test failed";
        return false;
    }
    const Frame ping{kPing, token, {}};
    const std::vector<unsigned char> ping_bytes = frame_bytes(ping);
    if (!one_case(ping_bytes, kHeaderBytes - 1, false, false)) {
        error = "truncated header transport test failed";
        return false;
    }
    Frame payload_frame{kPing, token, {1, 2, 3, 4}};
    const std::vector<unsigned char> payload_bytes = frame_bytes(payload_frame);
    if (!one_case(payload_bytes, kHeaderBytes + 2, false, false)) {
        error = "truncated payload transport test failed";
        return false;
    }
    std::vector<unsigned char> oversized = ping_bytes;
    oversized[8] = static_cast<unsigned char>((kMaxPayload + 1) & 0xff);
    oversized[9] = static_cast<unsigned char>(((kMaxPayload + 1) >> 8) & 0xff);
    if (!one_case(oversized, kHeaderBytes, false, false)) {
        error = "oversized receive transport test failed";
        return false;
    }
    if (!one_case({}, 0, false, false)) {
        error = "early EOF transport test failed";
        return false;
    }
    return true;
}

bool run_malformed_input_tests(std::string& error) {
    Token token;
    const std::string valid_token(2 * kTokenBytes, 'a');
    if (!token_from_hex(valid_token.c_str(), token)) {
        error = "valid token was rejected";
        return false;
    }
    const std::array<std::string, 5> malformed_tokens{"",
                                                      std::string(63, 'a'),
                                                      std::string(65, 'a'),
                                                      std::string(63, 'a') + "x",
                                                      std::string(64, 'a') + "0"};
    for (const std::string& malformed : malformed_tokens) {
        if (token_from_hex(malformed.c_str(), token)) {
            error = "malformed token was accepted";
            return false;
        }
    }
    Report malformed_report;
    malformed_report.exe = "/fixture";
    const char malformed_argv[] = "/fixture\0--fixture-worker\0bad";
    malformed_report.argv.assign(malformed_argv, sizeof(malformed_argv) - 1);
    malformed_report.mode = "ready";
    if (malformed_report.argv.empty() || malformed_report.argv.back() == '\0') {
        error = "malformed argv mutation was not non-vacuous";
        return false;
    }
    const std::vector<unsigned char> malformed_payload = encode_report(malformed_report);
    Report decoded;
    if (malformed_payload.empty() || decode_report(malformed_payload, decoded)) {
        error = "malformed NUL-separated argv was accepted";
        return false;
    }
    return true;
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

bool clear_capabilities() {
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
                               const char* role = "--fixture-worker") {
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
                             bool require_groups_clear = false) {
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

int worker_main(const char* executable,
                const char* path,
                const char* token_text,
                const char* mode) {
    if (strcmp(mode, "ready") != 0 && strcmp(mode, "no-ready") != 0 &&
        strcmp(mode, "term-ignore") != 0 && strcmp(mode, "wrapper-early-death") != 0)
        return 2;
    Token token;
    if (!token_from_hex(token_text, token)) return 2;
    if (strcmp(mode, "term-ignore") == 0 || strcmp(mode, "wrapper-early-death") == 0) {
        struct sigaction action{};
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, nullptr) != 0) return 3;
    }
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) return 3;
    const pid_t lease_parent = getppid();
    u64 groups_clear = 0;
    if (!child_security_setup(groups_clear) ||
        (getppid() != lease_parent && strcmp(mode, "wrapper-early-death") != 0))
        return 3;
    const int fd = connect_control(path);
    if (fd < 0) return 4;
    if (strcmp(mode, "no-ready") == 0) {
        // A lease is held by the control connection.  Closing it must release
        // an unready worker without relying on an unbounded pause.
        for (;;) {
            pollfd descriptor{fd, POLLIN, 0};
            const int ready = poll(&descriptor, 1, 100);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || (ready > 0 && (descriptor.revents & (POLLIN | POLLERR | POLLHUP)))) {
                char byte = 0;
                if (read(fd, &byte, 1) <= 0) break;
            }
        }
        close(fd);
        return 0;
    }
    ProcIdentity proc;
    if (!read_proc(getpid(), proc)) {
        close(fd);
        return 5;
    }
    Report report;
    report.target_pid = static_cast<u64>(getpid());
    report.wrapper_pid = static_cast<u64>(getppid());
    report.start = proc.start;
    report.pgid = static_cast<u64>(proc.pgid);
    report.uid = proc.uid;
    report.gid = proc.gid;
    report.netns = proc.netns;
    report.exe_dev = proc.exe_dev;
    report.exe_ino = proc.exe_ino;
    report.no_new_privs = proc.no_new_privs ? 1 : 0;
    report.capabilities_clear = proc.capabilities_clear ? 1 : 0;
    report.groups_clear = groups_clear;
    report.groups_unchanged = groups_clear == 0 ? 1 : 0;
    report.exe = proc.exe;
    report.argv = make_expected_argv(executable, path, token_text, mode);
    report.mode = mode;
    Frame ready{kReady, token, encode_report(report)};
    if (ready.payload.empty() || !send_frame(fd, ready, kHandshakeMs)) {
        close(fd);
        return 6;
    }
    for (;;) {
        Frame command;
        if (!receive_frame(fd, command, 60'000) || !token_equal(command.token, token) ||
            !command.payload.empty()) {
            close(fd);
            return 7;
        }
        if (command.type == kPing) {
            if (!send_frame(fd, Frame{kPong, token, {}}, kHandshakeMs)) break;
        } else if (command.type == kRelease) {
            (void)send_frame(fd, Frame{kReleased, token, {}}, kHandshakeMs);
            close(fd);
            return 0;
        } else {
            close(fd);
            return 8;
        }
    }
    return 9;
}

int wrapper_main(const char* executable, const char* path, const char* token, const char* mode) {
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) return 20;
    const pid_t parent = getppid();
    const pid_t target = fork();
    if (target < 0) return 21;
    if (target == 0) {
        execl(executable,
              executable,
              "--fixture-worker",
              path,
              token,
              mode,
              static_cast<char*>(nullptr));
        _exit(127);
    }
    if (strcmp(mode, "wrapper-early-death") == 0) _exit(0);
    if (getppid() != parent) {
        (void)kill(target, SIGTERM);
        (void)waitpid(target, nullptr, 0);
        return 22;
    }
    int status = 0;
    pid_t result;
    do {
        result = waitpid(target, &status, 0);
    } while (result < 0 && errno == EINTR);
    if (result != target) return 23;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 24;
}

struct TempDir {
    std::string path;
    std::string socket;
    ~TempDir() {
        if (!socket.empty()) (void)unlink(socket.c_str());
        if (!path.empty()) (void)rmdir(path.c_str());
    }
};

bool make_temp(TempDir& temp) {
    std::array<char, 64> pattern{};
    const int written = snprintf(pattern.data(), pattern.size(), "/tmp/rut358-proto-XXXXXX");
    if (written <= 0 || static_cast<size_t>(written) >= pattern.size() ||
        mkdtemp(pattern.data()) == nullptr)
        return false;
    temp.path = pattern.data();
    temp.socket = temp.path + "/control.sock";
    return true;
}

bool launch_worker(const std::string& executable,
                   const TempDir& temp,
                   const Token& token,
                   const char* mode,
                   Child& child) {
    std::array<char, 2 * kTokenBytes + 1> token_text{};
    for (size_t i = 0; i != kTokenBytes; ++i)
        snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
    child.pid = fork();
    if (child.pid < 0) return false;
    if (child.pid == 0) {
        execl(executable.c_str(),
              executable.c_str(),
              "--fixture-wrapper",
              temp.socket.c_str(),
              token_text.data(),
              mode,
              static_cast<char*>(nullptr));
        _exit(127);
    }
    return true;
}

bool reject_changed(
    bool field_changed, bool baseline, bool mutated, const char* label, std::string& error) {
    if (!field_changed) {
        error = std::string("mutation did not change field: ") + label;
        return false;
    }
    if (baseline == mutated) {
        error = std::string("mutation did not change validation result: ") + label;
        return false;
    }
    if (!baseline || mutated) {
        error = std::string("mutation was accepted: ") + label;
        return false;
    }
    return true;
}

bool run_ready_case(const std::string& executable, std::string& error, const char* mode = "ready") {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "secure temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "parent-owned AF_UNIX listener creation failed";
        return false;
    }
    Token token;
    const u64 seed = static_cast<u64>(getpid()) ^
                     static_cast<u64>(std::chrono::steady_clock::now().time_since_epoch().count());
    for (size_t i = 0; i != token.bytes.size(); ++i)
        token.bytes[i] = static_cast<unsigned char>((seed >> ((i % 8) * 8)) + i * 17 + 3);
    Child child;
    if (!launch_worker(executable, temp, token, mode, child)) {
        close(listener);
        error = "direct worker launch failed";
        return false;
    }
    int control = -1;
    Peer peer;
    Frame ready;
    Report report;
    bool cleaned = false;
    if (!accept_bounded(listener, control) || !get_peer(control, peer) ||
        !receive_frame(control, ready, kHandshakeMs) || ready.type != kReady ||
        !decode_report(ready.payload, report)) {
        error = "missing or malformed READY frame";
    } else {
        child.target_pid = peer.pid;
        ProcIdentity proc;
        ProcIdentity wrapper;
        const std::string expected_exe = executable;
        const std::string expected_argv = [&] {
            std::array<char, 2 * kTokenBytes + 1> text{};
            for (size_t i = 0; i != kTokenBytes; ++i)
                snprintf(text.data() + i * 2, 3, "%02x", token.bytes[i]);
            return make_expected_argv(executable.c_str(), temp.socket.c_str(), text.data(), mode);
        }();
        const std::string expected_wrapper_argv = [&] {
            std::array<char, 2 * kTokenBytes + 1> text{};
            for (size_t i = 0; i != kTokenBytes; ++i)
                snprintf(text.data() + i * 2, 3, "%02x", token.bytes[i]);
            return make_expected_argv(
                executable.c_str(), temp.socket.c_str(), text.data(), mode, "--fixture-wrapper");
        }();
        const bool baseline_fields =
            read_proc(child.target_pid, proc) && read_proc(child.pid, wrapper) &&
            report.wrapper_pid == static_cast<u64>(child.pid) && proc.ppid == child.pid &&
            wrapper.uid == proc.uid && wrapper.gid == proc.gid && wrapper.exe == expected_exe &&
            wrapper.cmdline == expected_wrapper_argv &&
            identity_matches_report(report,
                                    peer,
                                    proc,
                                    expected_exe,
                                    expected_argv,
                                    mode,
                                    token,
                                    ready.token,
                                    true,
                                    false);
        if (!baseline_fields) {
            error = "READY identity did not match SO_PEERCRED and /proc";
        } else if (identity_matches_report(report,
                                           peer,
                                           proc,
                                           expected_exe,
                                           expected_argv,
                                           mode,
                                           token,
                                           ready.token,
                                           true,
                                           false,
                                           true) != (proc.supplementary_groups == 0)) {
            error = "strict supplementary-group semantics were not enforced";
        } else if (!send_frame(control, Frame{kPing, token, {}}, kHandshakeMs)) {
            error = "bounded PING write failed";
        } else {
            Frame pong;
            if (!receive_frame(control, pong, kHandshakeMs) || pong.type != kPong ||
                !token_equal(pong.token, token) || !pong.payload.empty())
                error = "bounded PONG read failed";
            else {
                const bool baseline = identity_matches_report(report,
                                                              peer,
                                                              proc,
                                                              expected_exe,
                                                              expected_argv,
                                                              mode,
                                                              token,
                                                              ready.token,
                                                              true,
                                                              false);
                Report changed = report;
                changed.target_pid++;
                (void)reject_changed(changed.target_pid != report.target_pid,
                                     baseline,
                                     identity_matches_report(changed,
                                                             peer,
                                                             proc,
                                                             expected_exe,
                                                             expected_argv,
                                                             mode,
                                                             token,
                                                             ready.token,
                                                             true,
                                                             false),
                                     "report PID",
                                     error);
                changed = report;
                changed.wrapper_pid = report.target_pid + 1;
                const bool synthetic = identity_matches_report(changed,
                                                               peer,
                                                               proc,
                                                               expected_exe,
                                                               expected_argv,
                                                               mode,
                                                               token,
                                                               ready.token,
                                                               true,
                                                               false);
                if (error.empty() && !synthetic)
                    error = "synthetic wrapper!=target model was rejected";
                changed.target_pid = changed.wrapper_pid;
                const bool wrapper_only = identity_matches_report(changed,
                                                                  peer,
                                                                  proc,
                                                                  expected_exe,
                                                                  expected_argv,
                                                                  mode,
                                                                  token,
                                                                  ready.token,
                                                                  true,
                                                                  false);
                if (error.empty() && wrapper_only) error = "wrapper-only identity was accepted";

                for (const char* label : {"peer PID", "peer uid", "peer gid"}) {
                    Peer peer_mutation = peer;
                    if (strcmp(label, "peer PID") == 0)
                        ++peer_mutation.pid;
                    else if (strcmp(label, "peer uid") == 0)
                        ++peer_mutation.uid;
                    else
                        ++peer_mutation.gid;
                    const bool mutated_accepts = identity_matches_report(report,
                                                                         peer_mutation,
                                                                         proc,
                                                                         expected_exe,
                                                                         expected_argv,
                                                                         mode,
                                                                         token,
                                                                         ready.token,
                                                                         true,
                                                                         false);
                    if (error.empty())
                        (void)reject_changed(
                            (strcmp(label, "peer PID") == 0 && peer_mutation.pid != peer.pid) ||
                                (strcmp(label, "peer uid") == 0 && peer_mutation.uid != peer.uid) ||
                                (strcmp(label, "peer gid") == 0 && peer_mutation.gid != peer.gid),
                            baseline,
                            mutated_accepts,
                            label,
                            error);
                }

                const std::array<const char*, 11> labels{"report uid",
                                                         "report gid",
                                                         "start time",
                                                         "PGID",
                                                         "uid",
                                                         "gid",
                                                         "netns inode",
                                                         "executable",
                                                         "argv",
                                                         "mode",
                                                         "groups state"};
                for (const char* label : labels) {
                    Report mutation = report;
                    ProcIdentity proc_mutation = proc;
                    if (strcmp(label, "report uid") == 0) mutation.uid++;
                    if (strcmp(label, "report gid") == 0) mutation.gid++;
                    if (strcmp(label, "uid") == 0) proc_mutation.uid++;
                    if (strcmp(label, "gid") == 0) proc_mutation.gid++;
                    if (strcmp(label, "start time") == 0) mutation.start++;
                    if (strcmp(label, "PGID") == 0) mutation.pgid++;
                    if (strcmp(label, "netns inode") == 0) mutation.netns++;
                    if (strcmp(label, "executable") == 0) mutation.exe = "/bad/executable";
                    if (strcmp(label, "argv") == 0) mutation.argv.push_back('x');
                    if (strcmp(label, "mode") == 0) mutation.mode = "no-ready";
                    if (strcmp(label, "groups state") == 0) mutation.groups_clear ^= 1;
                    const bool mutated_accepts = identity_matches_report(mutation,
                                                                         peer,
                                                                         proc_mutation,
                                                                         expected_exe,
                                                                         expected_argv,
                                                                         mode,
                                                                         token,
                                                                         ready.token,
                                                                         true,
                                                                         false);
                    if (error.empty()) {
                        bool field_changed = false;
                        if (strcmp(label, "report uid") == 0)
                            field_changed = mutation.uid != report.uid;
                        else if (strcmp(label, "report gid") == 0)
                            field_changed = mutation.gid != report.gid;
                        else if (strcmp(label, "uid") == 0)
                            field_changed = proc_mutation.uid != proc.uid;
                        else if (strcmp(label, "gid") == 0)
                            field_changed = proc_mutation.gid != proc.gid;
                        else if (strcmp(label, "start time") == 0)
                            field_changed = mutation.start != report.start;
                        else if (strcmp(label, "PGID") == 0)
                            field_changed = mutation.pgid != report.pgid;
                        else if (strcmp(label, "netns inode") == 0)
                            field_changed = mutation.netns != report.netns;
                        else if (strcmp(label, "executable") == 0)
                            field_changed = mutation.exe != report.exe;
                        else if (strcmp(label, "argv") == 0)
                            field_changed = mutation.argv != report.argv;
                        else if (strcmp(label, "mode") == 0)
                            field_changed = mutation.mode != report.mode;
                        else if (strcmp(label, "groups state") == 0)
                            field_changed = mutation.groups_clear != report.groups_clear;
                        (void)reject_changed(
                            field_changed, baseline, mutated_accepts, label, error);
                    }
                }

                std::vector<unsigned char> raw = frame_bytes(ready);
                const bool raw_baseline = valid_frame_header(raw.data(), token);
                raw[12] ^= 1;
                const bool token_changed =
                    !std::equal(raw.data() + 12, raw.data() + kHeaderBytes, token.bytes.begin());
                const bool token_rejected = token_changed && !valid_frame_header(raw.data(), token);
                raw = frame_bytes(ready);
                raw[4] = static_cast<unsigned char>(kVersion + 1);
                const bool version_changed = raw[4] != static_cast<unsigned char>(kVersion);
                const bool version_rejected =
                    version_changed && !valid_frame_header(raw.data(), token);
                raw = frame_bytes(ready);
                raw[8] = static_cast<unsigned char>(kMaxPayload + 1);
                raw[9] = static_cast<unsigned char>((kMaxPayload + 1) >> 8);
                const bool length_changed =
                    raw[8] != frame_bytes(ready)[8] || raw[9] != frame_bytes(ready)[9];
                const bool length_rejected =
                    length_changed && !valid_frame_header(raw.data(), token);
                if (error.empty() &&
                    (!raw_baseline || !token_rejected || !version_rejected || !length_rejected))
                    error = "token/version/length mutation was not causally rejected";

                ProcIdentity stale = proc;
                stale.start++;
                const bool stale_rejected = !identity_matches_report(report,
                                                                     peer,
                                                                     stale,
                                                                     expected_exe,
                                                                     expected_argv,
                                                                     mode,
                                                                     token,
                                                                     ready.token,
                                                                     true,
                                                                     false);
                if (error.empty() && !stale_rejected) error = "stale identity was accepted";
                const bool unsafe_pgid_rejected = [&] {
                    Report unsafe = report;
                    unsafe.pgid = 1;
                    return !identity_matches_report(unsafe,
                                                    peer,
                                                    proc,
                                                    expected_exe,
                                                    expected_argv,
                                                    mode,
                                                    token,
                                                    ready.token,
                                                    true,
                                                    false);
                }();
                if (error.empty() && !unsafe_pgid_rejected) error = "unsafe PGID was accepted";
                ProcIdentity stale_cleanup = proc;
                ++stale_cleanup.start;
                if (error.empty() &&
                    safe_cleanup(child, report, peer, stale_cleanup, token, ready.token, true))
                    error = "stale cleanup identity was accepted";
                if (error.empty() && !process_alive(child.target_pid))
                    error = "stale cleanup changed process state";
                if (error.empty()) {
                    const auto cleanup_started = std::chrono::steady_clock::now();
                    cleaned = safe_cleanup(child, report, peer, proc, token, ready.token, true);
                    if (!cleaned) error = "verified TERM/KILL cleanup failed";
                    if (error.empty() && strcmp(mode, "term-ignore") == 0 &&
                        std::chrono::steady_clock::now() - cleanup_started <
                            std::chrono::milliseconds(kCleanupMs - 50))
                        error = "TERM-ignore target did not exercise bounded KILL fallback";
                }
            }
        }
    }
    if (control >= 0) close(control);
    close(listener);
    if (!cleaned && child.pid > 1 && !child.reaped) {
        ProcIdentity proc;
        if (child.target_pid > 1 && read_proc(child.target_pid, proc))
            (void)safe_cleanup_unready(child, proc, proc.cmdline, true);
        if (!child.reaped) (void)reap_bounded(child, kCleanupMs);
    }
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (access(temp.socket.c_str(), F_OK) == 0 && error.empty())
        error = "control socket artifact survived cleanup";
    return error.empty() && cleaned && access(temp.socket.c_str(), F_OK) != 0 &&
           access(temp.path.c_str(), F_OK) != 0;
}

bool run_no_ready_case(const std::string& executable, std::string& error) {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "induced-failure temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "induced-failure listener creation failed";
        return false;
    }
    Token token;
    for (size_t i = 0; i != token.bytes.size(); ++i)
        token.bytes[i] = static_cast<unsigned char>(0xa0 + i);
    Child child;
    if (!launch_worker(executable, temp, token, "no-ready", child)) {
        close(listener);
        error = "induced-failure worker launch failed";
        return false;
    }
    int control = -1;
    std::array<char, 2 * kTokenBytes + 1> token_text{};
    for (size_t i = 0; i != kTokenBytes; ++i)
        snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
    const std::string expected_worker_argv =
        make_expected_argv(executable.c_str(), temp.socket.c_str(), token_text.data(), "no-ready");
    Peer peer;
    bool ok = accept_bounded(listener, control) && get_peer(control, peer);
    if (ok) child.target_pid = peer.pid;
    ProcIdentity identity;
    if (!ok || !read_proc(child.target_pid, identity))
        error = "missing-READY path did not reach bounded state";
    if (ok && error.empty()) {
        if (safe_cleanup_unready(child, identity, expected_worker_argv, false))
            error = "cleanup without authority was accepted";
        if (error.empty() && !process_alive(child.target_pid))
            error = "unauthorized cleanup changed process state";
    }
    if (control >= 0) close(control);
    close(listener);
    if (error.empty() && !child.reaped && !reap_bounded(child, kCleanupMs))
        error = "control disappearance did not terminate wrapper/target lease";
    if (error.empty() && process_alive(child.target_pid))
        error = "control disappearance left target process alive";
    if (!child.reaped && child.pid > 1 && child.target_pid > 1) {
        (void)safe_cleanup_unready(child, identity, expected_worker_argv, true);
        if (!child.reaped) (void)reap_bounded(child, kCleanupMs);
    }
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (error.empty() && access(temp.socket.c_str(), F_OK) == 0)
        error = "failure socket artifact survived";
    return error.empty() && child.reaped && access(temp.socket.c_str(), F_OK) != 0 &&
           access(temp.path.c_str(), F_OK) != 0;
}

bool run_ready_lease_loss_case(const std::string& executable,
                               const char* mode,
                               std::string& error) {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "ready lease-loss temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "ready lease-loss listener creation failed";
        return false;
    }
    Token token;
    for (size_t i = 0; i != kTokenBytes; ++i) token.bytes[i] = static_cast<unsigned char>(0x60 + i);
    Child child;
    if (!launch_worker(executable, temp, token, mode, child)) {
        close(listener);
        error = "ready lease-loss worker launch failed";
        return false;
    }
    int control = -1;
    Peer peer;
    Frame ready;
    Report report;
    ProcIdentity target;
    if (!accept_bounded(listener, control) || !get_peer(control, peer) ||
        !receive_frame(control, ready, kHandshakeMs) || ready.type != kReady ||
        !decode_report(ready.payload, report)) {
        error = "ready lease-loss READY was missing or malformed";
    } else {
        child.target_pid = peer.pid;
        std::array<char, 2 * kTokenBytes + 1> token_text{};
        for (size_t i = 0; i != kTokenBytes; ++i)
            snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
        const std::string expected_argv =
            make_expected_argv(executable.c_str(), temp.socket.c_str(), token_text.data(), mode);
        if (!read_proc(child.target_pid, target) ||
            report.target_pid != static_cast<u64>(peer.pid) ||
            report.wrapper_pid != static_cast<u64>(child.pid) || target.ppid != child.pid ||
            report.argv != expected_argv) {
            error = "ready lease-loss identity was not established";
        } else {
            close(control);
            control = -1;
            close(listener);
            listener = -1;
            if (!reap_bounded(child, kHandshakeMs)) {
                (void)safe_cleanup_unready(child, target, expected_argv, true);
                if (!child.reaped) (void)reap_bounded(child, kCleanupMs);
            }
            if (!child.reaped || process_alive(child.target_pid))
                error = "ready lease loss left wrapper or target alive";
        }
    }
    if (control >= 0) close(control);
    if (listener >= 0) close(listener);
    if (!child.reaped && child.pid > 1) (void)reap_bounded(child, kCleanupMs);
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (error.empty() && access(temp.socket.c_str(), F_OK) == 0)
        error = "ready lease-loss socket artifact survived";
    return error.empty() && child.reaped && access(temp.socket.c_str(), F_OK) != 0 &&
           access(temp.path.c_str(), F_OK) != 0;
}

bool run_wrapper_early_death_case(const std::string& executable, std::string& error) {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "early-wrapper-death temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "early-wrapper-death listener creation failed";
        return false;
    }
    Token token;
    for (size_t i = 0; i != kTokenBytes; ++i) token.bytes[i] = static_cast<unsigned char>(0x40 + i);
    Child child;
    if (!launch_worker(executable, temp, token, "wrapper-early-death", child)) {
        close(listener);
        error = "early-wrapper-death worker launch failed";
        return false;
    }
    int control = -1;
    Peer peer;
    Frame ready;
    Report report;
    bool target_cleaned = false;
    if (!accept_bounded(listener, control) || !get_peer(control, peer) ||
        !receive_frame(control, ready, kHandshakeMs) || ready.type != kReady ||
        !decode_report(ready.payload, report)) {
        error = "early-wrapper-death READY was missing or malformed";
    } else {
        child.target_pid = peer.pid;
        std::array<char, 2 * kTokenBytes + 1> token_text{};
        for (size_t i = 0; i != kTokenBytes; ++i)
            snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
        const std::string expected_argv = make_expected_argv(
            executable.c_str(), temp.socket.c_str(), token_text.data(), "wrapper-early-death");
        ProcIdentity target;
        if (!read_proc(child.target_pid, target) || !reap_bounded(child, kHandshakeMs)) {
            error = "early wrapper was not reaped as the direct child";
        } else if (report.wrapper_pid == static_cast<u64>(child.pid) || target.ppid == child.pid ||
                   !target.no_new_privs || !target.capabilities_clear ||
                   !identity_matches_report(report,
                                            peer,
                                            target,
                                            executable,
                                            expected_argv,
                                            "wrapper-early-death",
                                            token,
                                            ready.token,
                                            true,
                                            false)) {
            error = "wrapper-early-death target was incorrectly authenticated";
        } else if (safe_cleanup(child, report, peer, target, token, ready.token, true)) {
            error = "live target was reported cleaned after wrapper death";
        } else if (!process_alive(child.target_pid)) {
            error = "wrapper-death mutation unexpectedly lost the live target";
        } else {
            target_cleaned = safe_cleanup_orphan_target(child.target_pid, target, true);
            if (!target_cleaned) error = "orphan target identity-safe cleanup failed";
        }
    }
    if (control >= 0) close(control);
    close(listener);
    if (!child.reaped && child.pid > 1) (void)reap_bounded(child, kCleanupMs);
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (error.empty() && access(temp.socket.c_str(), F_OK) == 0)
        error = "early-wrapper-death socket artifact survived";
    return error.empty() && target_cleaned && child.reaped &&
           access(temp.socket.c_str(), F_OK) != 0 && access(temp.path.c_str(), F_OK) != 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 5 && strcmp(argv[1], "--fixture-worker") == 0)
        return worker_main(argv[0], argv[2], argv[3], argv[4]);
    if (argc == 5 && strcmp(argv[1], "--fixture-wrapper") == 0)
        return wrapper_main(argv[0], argv[2], argv[3], argv[4]);
    if (argc != 1) {
        std::cerr << "usage: test_fixture_worker_protocol\n";
        return 2;
    }
    std::array<char, PATH_MAX> self{};
    const ssize_t length = readlink("/proc/self/exe", self.data(), self.size() - 1);
    if (length <= 0) {
        std::cerr << "FAIL [#358 Stage 2a1]: cannot resolve test executable\n";
        return 1;
    }
    self[static_cast<size_t>(length)] = '\0';
    std::string error;
    Token transport_token;
    for (size_t i = 0; i != transport_token.bytes.size(); ++i)
        transport_token.bytes[i] = static_cast<unsigned char>(i + 1);
    if (!run_transport_tests(transport_token, error) || !run_malformed_input_tests(error) ||
        !run_ready_case(self.data(), error) || !run_ready_case(self.data(), error, "term-ignore") ||
        !run_no_ready_case(self.data(), error) ||
        !run_ready_lease_loss_case(self.data(), "ready", error) ||
        !run_ready_lease_loss_case(self.data(), "term-ignore", error) ||
        !run_wrapper_early_death_case(self.data(), error)) {
        std::cerr << "FAIL [#358 Stage 2a1 protocol self-check]: " << error << "\n";
        return 1;
    }
    std::cerr << "PASS: #358 Stage 2a1 parent-owned authenticated fixture-worker protocol, "
                 "causal identity mutations, bounded cleanup, and failure artifact cleanup\n";
    return 0;
}
