#include "fixture_identity_bundle.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <linux/limits.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut::test::fixture_identity_bundle {
namespace {

constexpr unsigned long kProcMagic = 0x9fa0;
constexpr unsigned long kNsfsMagic = 0x6e736673;
constexpr unsigned long kPidfdMagic = 0x50494446;

static_assert(sizeof(pid_t) <= sizeof(u64));

static u64 hash_bytes(const std::string& bytes) {
    u64 hash = 1469598103934665603ULL;
    for (const char byte : bytes) {
        hash ^= static_cast<u64>(static_cast<unsigned char>(byte));
        hash *= 1099511628211ULL;
    }
    return hash;
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

static bool get16(const unsigned char* data, size_t size, size_t& at, u16& value) {
    if (at > size || size - at < 2) return false;
    value = static_cast<u16>(data[at]) | static_cast<u16>(data[at + 1] << 8);
    at += 2;
    return true;
}

static bool get32(const unsigned char* data, size_t size, size_t& at, u32& value) {
    if (at > size || size - at < 4) return false;
    value = static_cast<u32>(data[at]) | (static_cast<u32>(data[at + 1]) << 8) |
            (static_cast<u32>(data[at + 2]) << 16) | (static_cast<u32>(data[at + 3]) << 24);
    at += 4;
    return true;
}

static bool get64(const unsigned char* data, size_t size, size_t& at, u64& value) {
    if (at > size || size - at < 8) return false;
    value = 0;
    for (unsigned shift = 0; shift != 64; shift += 8)
        value |= static_cast<u64>(data[at++]) << shift;
    return true;
}

static bool wait_fd(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        if (left <= 0) return false;
        pollfd descriptor{fd, events, 0};
        const int result = poll(&descriptor, 1, static_cast<int>(left));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return false;
        return (descriptor.revents & (events | POLLERR | POLLHUP | POLLNVAL)) != 0;
    }
}

static bool read_fd(int fd, std::string& output, size_t limit) {
    output.clear();
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            if (output.size() > limit - static_cast<size_t>(count)) return false;
            output.append(buffer.data(), static_cast<size_t>(count));
            continue;
        }
        if (count == 0) return true;
        if (errno == EINTR) continue;
        return false;
    }
}

static bool parse_proc_stat(const std::string& text,
                            RoleManifest& manifest,
                            char* process_state = nullptr) {
    const size_t pid_end = text.find(' ');
    if (pid_end == std::string::npos || pid_end == 0) return false;
    const std::string pid_text = text.substr(0, pid_end);
    char* pid_parse_end = nullptr;
    errno = 0;
    const unsigned long parsed_pid = std::strtoul(pid_text.c_str(), &pid_parse_end, 10);
    if (errno != 0 || pid_parse_end == nullptr || *pid_parse_end != '\0' || parsed_pid <= 1 ||
        parsed_pid > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()))
        return false;
    manifest.pid = static_cast<pid_t>(parsed_pid);
    const size_t comm_end = text.rfind(") ");
    if (comm_end == std::string::npos) return false;
    std::istringstream fields(text.substr(comm_end + 2));
    char state = 0;
    long ppid = 0;
    long pgid = 0;
    if (!(fields >> state >> ppid >> pgid)) return false;
    if (process_state != nullptr) *process_state = state;
    manifest.ppid = static_cast<pid_t>(ppid);
    manifest.pgid = static_cast<pid_t>(pgid);
    for (int field = 6; field <= 22; ++field) {
        if (field == 6) {
            long sid = 0;
            if (!(fields >> sid)) return false;
            manifest.sid = static_cast<pid_t>(sid);
        } else if (field == 22) {
            unsigned long long start = 0;
            if (!(fields >> start)) return false;
            manifest.start = static_cast<u64>(start);
        } else {
            long long ignored = 0;
            if (!(fields >> ignored)) return false;
        }
    }
    return manifest.start != 0 && manifest.ppid > 0 && manifest.pgid > 0 && manifest.sid > 0;
}

static bool live_process_state(char state) {
    switch (state) {
        case 'R':
        case 'S':
        case 'D':
        case 'T':
        case 't':
        case 'W':
        case 'K':
        case 'P':
        case 'I':
            return true;
        case 'Z':
        case 'X':
        case 'x':
            return false;
        default:
            return false;
    }
}

static bool parse_decimal(const std::string& text, u64 maximum, u64& value) {
    if (text.empty()) return false;
    u64 parsed = 0;
    for (const unsigned char byte : text) {
        if (!std::isdigit(byte)) return false;
        const u64 digit = static_cast<u64>(byte - static_cast<unsigned char>('0'));
        if (digit > maximum) return false;
        if (parsed > (maximum - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    value = parsed;
    return true;
}

static bool exact_tokens(const std::string& text, std::vector<std::string>& tokens) {
    tokens.clear();
    std::istringstream input(text);
    std::string token;
    while (input >> token) tokens.push_back(token);
    return input.eof();
}

static bool parse_capability(const std::vector<std::string>& tokens, u64& value, bool& clear) {
    if (tokens.size() != 1 || tokens[0].size() != 16) return false;
    u64 parsed = 0;
    for (const unsigned char byte : tokens[0]) {
        unsigned digit = 0;
        if (byte >= '0' && byte <= '9')
            digit = static_cast<unsigned>(byte - '0');
        else if (byte >= 'a' && byte <= 'f')
            digit = static_cast<unsigned>(byte - 'a') + 10;
        else if (byte >= 'A' && byte <= 'F')
            digit = static_cast<unsigned>(byte - 'A') + 10;
        else
            return false;
        parsed = (parsed << 4) | digit;
    }
    value = parsed;
    clear = parsed == 0;
    return true;
}

static bool parse_dropped_status(const std::string& text,
                                 DroppedStatusEvidence& evidence,
                                 std::string& error) {
    DroppedStatusEvidence parsed;
    bool have_uid = false;
    bool have_gid = false;
    bool have_groups = false;
    bool have_nnp = false;
    bool have_inh = false;
    bool have_prm = false;
    bool have_eff = false;
    bool have_bnd = false;
    bool have_amb = false;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        const std::string key = line.substr(0, colon);
        if (key != "Uid" && key != "Gid" && key != "Groups" && key != "NoNewPrivs" &&
            key != "CapInh" && key != "CapPrm" && key != "CapEff" && key != "CapBnd" &&
            key != "CapAmb")
            continue;
        std::vector<std::string> tokens;
        if (!exact_tokens(line.substr(colon + 1), tokens)) {
            error = "dropped status field tokenization failed";
            return false;
        }
        if (key == "Uid" || key == "Gid") {
            bool& present = key == "Uid" ? have_uid : have_gid;
            if (present || tokens.size() != 4) {
                error = "dropped status ID field count was not exact";
                return false;
            }
            for (size_t index = 0; index != tokens.size(); ++index) {
                u64 value = 0;
                const u64 maximum = key == "Uid" ? std::numeric_limits<uid_t>::max()
                                                 : std::numeric_limits<gid_t>::max();
                if (!parse_decimal(tokens[index], maximum, value)) {
                    error = "dropped status ID field was malformed or out of range";
                    return false;
                }
                if (key == "Uid")
                    parsed.uid_values[index] = static_cast<uid_t>(value);
                else
                    parsed.gid_values[index] = static_cast<gid_t>(value);
            }
            present = true;
            continue;
        }
        if (key == "Groups") {
            if (have_groups) {
                error = "dropped status Groups field was duplicated";
                return false;
            }
            for (const std::string& token : tokens) {
                u64 value = 0;
                if (!parse_decimal(token, std::numeric_limits<gid_t>::max(), value)) {
                    error = "dropped status Groups field was malformed or out of range";
                    return false;
                }
                parsed.supplementary_groups.push_back(static_cast<gid_t>(value));
            }
            have_groups = true;
            continue;
        }
        if (key == "NoNewPrivs") {
            u64 value = 0;
            if (have_nnp || tokens.size() != 1 || !parse_decimal(tokens[0], 1, value)) {
                error = "dropped status NoNewPrivs field was not exact";
                return false;
            }
            parsed.no_new_privs = value == 1;
            have_nnp = true;
            continue;
        }
        bool* clear = nullptr;
        u64* raw = nullptr;
        bool* present = nullptr;
        if (key == "CapInh") {
            clear = &parsed.cap_inh_clear;
            raw = &parsed.cap_inh;
            present = &have_inh;
        } else if (key == "CapPrm") {
            clear = &parsed.cap_prm_clear;
            raw = &parsed.cap_prm;
            present = &have_prm;
        } else if (key == "CapEff") {
            clear = &parsed.cap_eff_clear;
            raw = &parsed.cap_eff;
            present = &have_eff;
        } else if (key == "CapBnd") {
            clear = &parsed.cap_inh_clear;
            raw = &parsed.cap_bnd;
            present = &have_bnd;
        } else {
            clear = &parsed.cap_inh_clear;
            raw = &parsed.cap_amb;
            present = &have_amb;
        }
        bool ignored_clear = false;
        bool& parsed_clear = (key == "CapBnd" || key == "CapAmb") ? ignored_clear : *clear;
        if (*present || !parse_capability(tokens, *raw, parsed_clear)) {
            error = "dropped status capability field was not exact hexadecimal evidence";
            return false;
        }
        *present = true;
    }
    if (!have_uid || !have_gid || !have_groups || !have_nnp || !have_inh || !have_prm ||
        !have_eff || !have_bnd || !have_amb) {
        error = "dropped status required security field was missing";
        return false;
    }
    evidence = std::move(parsed);
    return true;
}

static bool parse_status_ids(const std::string& text, uid_t& uid, gid_t& gid) {
    bool got_uid = false;
    bool got_gid = false;
    std::istringstream lines(text);
    std::string key;
    while (lines >> key) {
        unsigned long long effective = 0;
        if (key == "Uid:") {
            if (!(lines >> effective) || effective > std::numeric_limits<uid_t>::max())
                return false;
            uid = static_cast<uid_t>(effective);
            got_uid = true;
        } else if (key == "Gid:") {
            if (!(lines >> effective) || effective > std::numeric_limits<gid_t>::max())
                return false;
            gid = static_cast<gid_t>(effective);
            got_gid = true;
        }
        std::string rest;
        std::getline(lines, rest);
    }
    return got_uid && got_gid;
}

static bool open_cloexec(const std::string& path, int flags, int& fd) {
    fd = open(path.c_str(), flags | O_CLOEXEC);
    return fd >= 0;
}

static bool fd_cloexec(int fd) {
    const int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && (flags & FD_CLOEXEC) != 0;
}

static bool fd_fs_magic(int fd, unsigned long expected) {
    struct statfs filesystem{};
    return fstatfs(fd, &filesystem) == 0 &&
           static_cast<unsigned long>(filesystem.f_type) == expected;
}

static bool fd_fs_readable(int fd) {
    struct statfs filesystem{};
    return fstatfs(fd, &filesystem) == 0 && filesystem.f_type != 0;
}

static bool fd_link(int fd, std::string& path) {
    std::array<char, PATH_MAX> buffer{};
    const ssize_t length =
        readlink(("/proc/self/fd/" + std::to_string(fd)).c_str(), buffer.data(), buffer.size() - 1);
    if (length < 0) return false;
    path.assign(buffer.data(), static_cast<size_t>(length));
    return true;
}

static bool read_pidfd_binding(int fd, pid_t expected_pid) {
    const int info =
        open(("/proc/self/fdinfo/" + std::to_string(fd)).c_str(), O_RDONLY | O_CLOEXEC);
    if (info < 0) return false;
    std::string text;
    const bool read = read_fd(info, text, 4096);
    close(info);
    if (!read) return false;
    std::istringstream lines(text);
    std::string key;
    pid_t pid = -1;
    bool found = false;
    while (lines >> key) {
        if (key == "Pid:") {
            long parsed = 0;
            if (found || !(lines >> parsed) || parsed <= 1 || parsed != expected_pid) return false;
            pid = static_cast<pid_t>(parsed);
            found = true;
        }
        std::string rest;
        std::getline(lines, rest);
    }
    return found && pid == expected_pid;
}

static bool pidfd_is_live(int fd) {
    pollfd descriptor{fd, static_cast<short>(POLLIN | POLLERR | POLLHUP), 0};
    int result;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0 && descriptor.revents == 0;
}

static bool decode_manifest(const unsigned char* data,
                            size_t size,
                            size_t& at,
                            RoleManifest& manifest) {
    u64 values[14]{};
    for (u64& value : values)
        if (!get64(data, size, at, value)) return false;
    if (values[0] != static_cast<u16>(Role::Launcher) && values[0] != static_cast<u16>(Role::Root))
        return false;
    manifest.role = static_cast<Role>(values[0]);
    manifest.pid = static_cast<pid_t>(values[1]);
    manifest.start = values[2];
    manifest.ppid = static_cast<pid_t>(values[3]);
    manifest.pgid = static_cast<pid_t>(values[4]);
    manifest.sid = static_cast<pid_t>(values[5]);
    manifest.uid = static_cast<uid_t>(values[6]);
    manifest.gid = static_cast<gid_t>(values[7]);
    manifest.netns = values[8];
    manifest.exe_dev = values[9];
    manifest.exe_ino = values[10];
    manifest.argv_length = values[11];
    manifest.argv_hash = values[12];
    return values[13] == 0;
}

static void encode_manifest(std::vector<unsigned char>& output, const RoleManifest& manifest) {
    put64(output, static_cast<u64>(manifest.role));
    put64(output, static_cast<u64>(manifest.pid));
    put64(output, manifest.start);
    put64(output, static_cast<u64>(manifest.ppid));
    put64(output, static_cast<u64>(manifest.pgid));
    put64(output, static_cast<u64>(manifest.sid));
    put64(output, static_cast<u64>(manifest.uid));
    put64(output, static_cast<u64>(manifest.gid));
    put64(output, manifest.netns);
    put64(output, manifest.exe_dev);
    put64(output, manifest.exe_ino);
    put64(output, manifest.argv_length);
    put64(output, manifest.argv_hash);
    put64(output, 0);
}

static bool parse_wire(const unsigned char* data, size_t size, IdentityBundle& bundle) {
    if (size != kWireBytes) return false;
    size_t at = 0;
    u32 magic = 0;
    u16 version = 0;
    u16 roles = 0;
    u16 fds = 0;
    u16 reserved = 0;
    u32 payload = 0;
    if (!get32(data, size, at, magic) || !get16(data, size, at, version) ||
        !get16(data, size, at, roles) || !get16(data, size, at, fds) ||
        !get16(data, size, at, reserved) || !get32(data, size, at, payload) || magic != kMagic ||
        version != kVersion || roles != kRoleCount || fds != kBundleFdCount || reserved != 0 ||
        payload != kPayloadBytes)
        return false;
    for (RoleBundle& role : bundle.roles)
        if (!decode_manifest(data, size, at, role.manifest)) return false;
    return at == size;
}

static bool validate_role(const RoleBundle& role, std::string& error) {
    const RoleManifest& m = role.manifest;
    const auto invalid = [&](const char* reason) {
        error = reason;
        return false;
    };
    if (m.pid <= 1 || m.start == 0 || m.ppid <= 0 || m.pgid <= 0 || m.sid <= 0 || m.netns == 0 ||
        m.exe_dev == 0 || m.exe_ino == 0 || m.argv_length == 0)
        return invalid("manifest scalar invalid");
    for (int fd : role.fds)
        if (fd < 0 || !fd_cloexec(fd)) return invalid("fd cloexec invalid");
    for (size_t i = 0; i != role.fds.size(); ++i)
        for (size_t j = i + 1; j != role.fds.size(); ++j)
            if (role.fds[i] == role.fds[j]) return invalid("duplicate fd");

    const std::string prefix = "/proc/" + std::to_string(m.pid) + "/";
    const char* names[] = {"stat", "status", "cmdline"};
    for (size_t i = 0; i != 3; ++i) {
        std::string link;
        if (!fd_link(role.fds[i], link) || link != prefix + names[i] ||
            !fd_fs_magic(role.fds[i], kProcMagic))
            return invalid("proc fd type/path invalid");
    }
    if (!fd_fs_readable(role.fds[static_cast<size_t>(FdSlot::Executable)]) ||
        !fd_fs_magic(role.fds[static_cast<size_t>(FdSlot::Netns)], kNsfsMagic) ||
        !fd_fs_magic(role.fds[static_cast<size_t>(FdSlot::Pidfd)], kPidfdMagic) ||
        !read_pidfd_binding(role.fds[static_cast<size_t>(FdSlot::Pidfd)], m.pid))
        return invalid("fd filesystem type invalid");

    // The transport boundary proves regular type plus dev/inode and opened
    // proc content under the trusted fixture root.  A later integration layer
    // must cross-check the expected binary; malicious-root and same-inode /
    // hardlink attestation are deliberately outside this transport core.
    struct stat executable{};
    if (fstat(role.fds[static_cast<size_t>(FdSlot::Executable)], &executable) != 0 ||
        static_cast<u64>(executable.st_dev) != m.exe_dev ||
        static_cast<u64>(executable.st_ino) != m.exe_ino || !S_ISREG(executable.st_mode))
        return invalid("executable stat invalid");
    std::string netns_link;
    if (!fd_link(role.fds[static_cast<size_t>(FdSlot::Netns)], netns_link) ||
        netns_link != "net:[" + std::to_string(m.netns) + "]")
        return invalid("netns link invalid");
    std::string stat_text;
    RoleManifest observed = m;
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Stat)], stat_text, 8192) ||
        !parse_proc_stat(stat_text, observed))
        return invalid("stat content invalid");
    if (observed.pid != m.pid || observed.start != m.start || observed.ppid != m.ppid ||
        observed.pgid != m.pgid || observed.sid != m.sid)
        return invalid("stat manifest mismatch");
    std::string status_text;
    uid_t uid = 0;
    gid_t gid = 0;
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Status)], status_text, 16384) ||
        !parse_status_ids(status_text, uid, gid) || uid != m.uid || gid != m.gid)
        return invalid("status content invalid");
    std::string cmdline;
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Cmdline)], cmdline, 8192) ||
        cmdline.size() != m.argv_length || hash_bytes(cmdline) != m.argv_hash)
        return invalid("cmdline content invalid");
    RoleManifest stable = m;
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Stat)], stat_text, 8192) ||
        !parse_proc_stat(stat_text, stable) || stable.pid != observed.pid ||
        stable.start != observed.start || stable.ppid != observed.ppid ||
        stable.pgid != observed.pgid || stable.sid != observed.sid)
        return invalid("stat identity was not stable");
    (void)error;
    return true;
}

static bool send_bytes(int fd,
                       const unsigned char* data,
                       size_t size,
                       std::chrono::steady_clock::time_point deadline) {
    size_t offset = 0;
    while (offset != size) {
        if (!wait_fd(fd, POLLOUT, deadline)) return false;
        const ssize_t count = send(fd, data + offset, size - offset, MSG_NOSIGNAL);
        if (count > 0)
            offset += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else
            return false;
    }
    return true;
}

static bool parse_rights(struct msghdr& message, std::array<int, kBundleFdCount>& fds) {
    size_t count = 0;
    bool found = false;
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || found ||
            header->cmsg_len > message.msg_controllen ||
            header->cmsg_len != CMSG_LEN(kBundleFdCount * sizeof(int)))
            return false;
        found = true;
        const size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes != kBundleFdCount * sizeof(int)) return false;
        const int* values = reinterpret_cast<const int*>(CMSG_DATA(header));
        for (size_t i = 0; i != kBundleFdCount; ++i) {
            if (values[i] < 0) return false;
            fds[count++] = values[i];
        }
    }
    if (!found || count != kBundleFdCount) return false;
    for (size_t i = 0; i != count; ++i)
        for (size_t j = i + 1; j != count; ++j)
            if (fds[i] == fds[j]) return false;
    return true;
}

static bool parse_dropped_rights(struct msghdr& message, std::array<int, kDroppedFdCount>& fds) {
    size_t count = 0;
    bool found = false;
    std::array<int, kDroppedFdCount> parsed{};
    parsed.fill(-1);
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || found ||
            header->cmsg_len > message.msg_controllen ||
            header->cmsg_len != CMSG_LEN(kDroppedFdCount * sizeof(int)))
            return false;
        found = true;
        const size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes != kDroppedFdCount * sizeof(int)) return false;
        const int* values = reinterpret_cast<const int*>(CMSG_DATA(header));
        for (size_t i = 0; i != kDroppedFdCount; ++i) {
            if (values[i] < 0) return false;
            parsed[count++] = values[i];
        }
    }
    if (!found || count != kDroppedFdCount) return false;
    fds = parsed;
    return true;
}

static void close_rights_in_message(const struct msghdr& message) {
    for (cmsghdr* header = CMSG_FIRSTHDR(const_cast<struct msghdr*>(&message)); header != nullptr;
         header = CMSG_NXTHDR(const_cast<struct msghdr*>(&message), header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0) || header->cmsg_len > message.msg_controllen)
            continue;
        const size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes > (kBundleFdCount + 1) * sizeof(int)) continue;
        const int* values = reinterpret_cast<const int*>(CMSG_DATA(header));
        for (size_t i = 0; i != bytes / sizeof(int); ++i)
            if (values[i] >= 0) close(values[i]);
    }
}

static void close_fds(std::array<int, kBundleFdCount>& fds) {
    for (int& fd : fds) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
}

static void close_dropped_fds(std::array<int, kDroppedFdCount>& fds) {
    for (int& fd : fds) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
}

}  // namespace

RoleBundle::RoleBundle() {
    fds.fill(-1);
}

RoleBundle::~RoleBundle() {
    close();
}

RoleBundle::RoleBundle(RoleBundle&& other) noexcept : manifest(other.manifest), fds(other.fds) {
    other.fds.fill(-1);
}

RoleBundle& RoleBundle::operator=(RoleBundle&& other) noexcept {
    if (this == &other) return *this;
    close();
    manifest = other.manifest;
    fds = other.fds;
    other.fds.fill(-1);
    return *this;
}

void RoleBundle::close() {
    for (int& fd : fds) {
        if (fd >= 0) ::close(fd);
        fd = -1;
    }
}

void IdentityBundle::close() {
    for (RoleBundle& role : roles) role.close();
}

bool open_role(pid_t pid, Role role, RoleBundle& role_bundle, std::string& error) {
    role_bundle.close();
    role_bundle.manifest = RoleManifest{};
    role_bundle.manifest.role = role;
    role_bundle.manifest.pid = pid;
    if (pid <= 1) {
        error = "identity bundle pid was unsafe";
        return false;
    }
    const std::string prefix = "/proc/" + std::to_string(pid);
    if (!open_cloexec(prefix + "/stat", O_RDONLY, role_bundle.fds[0]) ||
        !open_cloexec(prefix + "/status", O_RDONLY, role_bundle.fds[1]) ||
        !open_cloexec(prefix + "/cmdline", O_RDONLY, role_bundle.fds[2]) ||
        !open_cloexec(prefix + "/exe", O_PATH, role_bundle.fds[3]) ||
        !open_cloexec(prefix + "/ns/net", O_PATH, role_bundle.fds[4])) {
        role_bundle.close();
        error = "identity bundle proc fd open failed";
        return false;
    }
#ifdef SYS_pidfd_open
    const long raw_pidfd = syscall(SYS_pidfd_open, pid, 0);
    if (raw_pidfd < 0 || raw_pidfd > std::numeric_limits<int>::max()) {
        role_bundle.close();
        error = "identity bundle pidfd open failed";
        return false;
    }
    role_bundle.fds[5] = static_cast<int>(raw_pidfd);
#else
    role_bundle.close();
    error = "identity bundle pidfd is unavailable";
    return false;
#endif
    std::string stat_text;
    std::string status_text;
    std::string cmdline;
    if (!read_fd(role_bundle.fds[0], stat_text, 8192) ||
        !parse_proc_stat(stat_text, role_bundle.manifest) ||
        !read_fd(role_bundle.fds[1], status_text, 16384) ||
        !parse_status_ids(status_text, role_bundle.manifest.uid, role_bundle.manifest.gid) ||
        !read_fd(role_bundle.fds[2], cmdline, 8192)) {
        role_bundle.close();
        error = "identity bundle proc manifest parse failed";
        return false;
    }
    struct stat executable{};
    struct stat netns{};
    if (fstat(role_bundle.fds[3], &executable) != 0 || fstat(role_bundle.fds[4], &netns) != 0) {
        role_bundle.close();
        error = "identity bundle executable/netns stat failed";
        return false;
    }
    role_bundle.manifest.netns = static_cast<u64>(netns.st_ino);
    role_bundle.manifest.exe_dev = static_cast<u64>(executable.st_dev);
    role_bundle.manifest.exe_ino = static_cast<u64>(executable.st_ino);
    role_bundle.manifest.argv_length = cmdline.size();
    role_bundle.manifest.argv_hash = hash_bytes(cmdline);
    if (!validate_role(role_bundle, error)) {
        role_bundle.close();
        return false;
    }
    return true;
}

bool adopt_role(Role role,
                std::array<int, kFdsPerRole>& inherited_fds,
                RoleBundle& role_bundle,
                std::string& error) {
    role_bundle.close();
    role_bundle.manifest = RoleManifest{};
    role_bundle.manifest.role = role;
    role_bundle.fds = inherited_fds;
    inherited_fds.fill(-1);
    std::string stat_text;
    std::string status_text;
    std::string cmdline;
    if (!read_fd(role_bundle.fds[static_cast<size_t>(FdSlot::Stat)], stat_text, 8192) ||
        !parse_proc_stat(stat_text, role_bundle.manifest) ||
        !read_fd(role_bundle.fds[static_cast<size_t>(FdSlot::Status)], status_text, 16384) ||
        !parse_status_ids(status_text, role_bundle.manifest.uid, role_bundle.manifest.gid) ||
        !read_fd(role_bundle.fds[static_cast<size_t>(FdSlot::Cmdline)], cmdline, 8192)) {
        role_bundle.close();
        error = "inherited identity bundle proc manifest parse failed";
        return false;
    }
    struct stat executable{};
    struct stat netns{};
    if (fstat(role_bundle.fds[static_cast<size_t>(FdSlot::Executable)], &executable) != 0 ||
        fstat(role_bundle.fds[static_cast<size_t>(FdSlot::Netns)], &netns) != 0) {
        role_bundle.close();
        error = "inherited identity bundle executable/netns stat failed";
        return false;
    }
    role_bundle.manifest.netns = static_cast<u64>(netns.st_ino);
    role_bundle.manifest.exe_dev = static_cast<u64>(executable.st_dev);
    role_bundle.manifest.exe_ino = static_cast<u64>(executable.st_ino);
    role_bundle.manifest.argv_length = cmdline.size();
    role_bundle.manifest.argv_hash = hash_bytes(cmdline);
    if (!validate_role(role_bundle, error)) {
        role_bundle.close();
        return false;
    }
    return true;
}

std::vector<unsigned char> encode_bundle(const IdentityBundle& bundle) {
    std::vector<unsigned char> output;
    output.reserve(kWireBytes);
    put32(output, kMagic);
    put16(output, kVersion);
    put16(output, kRoleCount);
    put16(output, kBundleFdCount);
    put16(output, 0);
    put32(output, kPayloadBytes);
    for (const RoleBundle& role : bundle.roles) encode_manifest(output, role.manifest);
    return output;
}

bool validate_bundle(const IdentityBundle& bundle, std::string& error) {
    if (bundle.roles[0].manifest.role != Role::Launcher ||
        bundle.roles[1].manifest.role != Role::Root ||
        bundle.roles[0].manifest.pid == bundle.roles[1].manifest.pid) {
        error = "identity bundle role or pid relation was invalid";
        return false;
    }
    return validate_role(bundle.roles[0], error) && validate_role(bundle.roles[1], error);
}

bool parse_dropped_status_evidence(const std::string& status,
                                   DroppedStatusEvidence& evidence,
                                   std::string& error) {
    evidence = DroppedStatusEvidence{};
    error.clear();
    return parse_dropped_status(status, evidence, error);
}

bool extract_dropped_identity_evidence(const RoleBundle& role,
                                       DroppedIdentityEvidence& evidence,
                                       std::string& error) {
    evidence = DroppedIdentityEvidence{};
    ProcessIdentityEvidence process;
    if (!extract_process_identity_evidence(role, Role::Dropped, process, error)) return false;
    evidence.identity = process.identity;
    evidence.state = process.state;
    evidence.status = std::move(process.status);
    evidence.cmdline = std::move(process.cmdline);
    evidence.pidfd_live = process.pidfd_live;
    return true;
}

bool extract_process_identity_evidence(const RoleBundle& role,
                                       Role expected_role,
                                       ProcessIdentityEvidence& evidence,
                                       std::string& error) {
    evidence = ProcessIdentityEvidence{};
    error.clear();
    if (role.manifest.role != expected_role) {
        error = "process evidence role was not exact";
        return false;
    }
    if (!validate_role(role, error)) {
        error = "process evidence role FD validation failed: " + error;
        return false;
    }

    const auto identity_matches_manifest = [&](const RoleManifest& observed) {
        return observed.pid == role.manifest.pid && observed.start == role.manifest.start &&
               observed.ppid == role.manifest.ppid && observed.pgid == role.manifest.pgid &&
               observed.sid == role.manifest.sid;
    };
    const auto same_stat_identity = [](const RoleManifest& first, const RoleManifest& second) {
        return first.pid == second.pid && first.start == second.start &&
               first.ppid == second.ppid && first.pgid == second.pgid && first.sid == second.sid;
    };
    std::string stat_text;
    RoleManifest first = role.manifest;
    RoleManifest second = role.manifest;
    char first_state = '\0';
    char second_state = '\0';
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Stat)], stat_text, 8192) ||
        !parse_proc_stat(stat_text, first, &first_state) || !live_process_state(first_state) ||
        !identity_matches_manifest(first) ||
        !read_fd(role.fds[static_cast<size_t>(FdSlot::Stat)], stat_text, 8192) ||
        !parse_proc_stat(stat_text, second, &second_state) || !live_process_state(second_state) ||
        !identity_matches_manifest(second) || !same_stat_identity(first, second)) {
        error = "process evidence stat identity/state was invalid, dead, or unstable";
        return false;
    }

    DroppedStatusEvidence first_status;
    DroppedStatusEvidence second_status;
    std::string first_status_text;
    std::string second_status_text;
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Status)], first_status_text, 16384) ||
        !parse_dropped_status(first_status_text, first_status, error) ||
        !read_fd(role.fds[static_cast<size_t>(FdSlot::Status)], second_status_text, 16384) ||
        !parse_dropped_status(second_status_text, second_status, error) ||
        first_status.uid_values != second_status.uid_values ||
        first_status.gid_values != second_status.gid_values ||
        first_status.supplementary_groups != second_status.supplementary_groups ||
        first_status.no_new_privs != second_status.no_new_privs ||
        first_status.cap_inh != second_status.cap_inh ||
        first_status.cap_prm != second_status.cap_prm ||
        first_status.cap_eff != second_status.cap_eff ||
        first_status.cap_bnd != second_status.cap_bnd ||
        first_status.cap_amb != second_status.cap_amb ||
        first_status.cap_inh_clear != second_status.cap_inh_clear ||
        first_status.cap_prm_clear != second_status.cap_prm_clear ||
        first_status.cap_eff_clear != second_status.cap_eff_clear ||
        second_status.uid_values[0] != role.manifest.uid ||
        second_status.gid_values[0] != role.manifest.gid) {
        if (error.empty()) error = "process evidence status was unstable or mismatched";
        return false;
    }

    std::string first_cmdline;
    std::string second_cmdline;
    if (!read_fd(role.fds[static_cast<size_t>(FdSlot::Cmdline)], first_cmdline, 8192) ||
        !read_fd(role.fds[static_cast<size_t>(FdSlot::Cmdline)], second_cmdline, 8192) ||
        first_cmdline != second_cmdline || second_cmdline.size() != role.manifest.argv_length ||
        hash_bytes(second_cmdline) != role.manifest.argv_hash) {
        error = "process evidence cmdline was unstable or mismatched";
        return false;
    }
    const int pidfd = role.fds[static_cast<size_t>(FdSlot::Pidfd)];
    if (!read_pidfd_binding(pidfd, role.manifest.pid) || !pidfd_is_live(pidfd)) {
        error = "process evidence pidfd was not bound and live";
        return false;
    }

    second.netns = role.manifest.netns;
    second.exe_dev = role.manifest.exe_dev;
    second.exe_ino = role.manifest.exe_ino;
    second.uid = role.manifest.uid;
    second.gid = role.manifest.gid;
    second.argv_length = role.manifest.argv_length;
    second.argv_hash = role.manifest.argv_hash;
    evidence.identity = second;
    evidence.state = second_state;
    evidence.status = std::move(second_status);
    evidence.cmdline = std::move(second_cmdline);
    evidence.pidfd_live = true;
    error.clear();
    return true;
}

static std::vector<unsigned char> encode_dropped_header() {
    std::vector<unsigned char> output;
    output.reserve(kDroppedHeaderBytes);
    put32(output, kDroppedMagic);
    put16(output, kDroppedVersion);
    put16(output, static_cast<u16>(Role::Dropped));
    put16(output, static_cast<u16>(kDroppedFdCount));
    put16(output, 0);
    put32(output, 0);
    return output;
}

static bool parse_dropped_header(const std::array<unsigned char, kDroppedHeaderBytes>& wire) {
    size_t at = 0;
    u32 magic = 0;
    u16 version = 0;
    u16 role = 0;
    u16 fds = 0;
    u16 reserved = 0;
    u32 payload = 0;
    return get32(wire.data(), wire.size(), at, magic) &&
           get16(wire.data(), wire.size(), at, version) &&
           get16(wire.data(), wire.size(), at, role) && get16(wire.data(), wire.size(), at, fds) &&
           get16(wire.data(), wire.size(), at, reserved) &&
           get32(wire.data(), wire.size(), at, payload) && magic == kDroppedMagic &&
           version == kDroppedVersion && role == static_cast<u16>(Role::Dropped) &&
           fds == kDroppedFdCount && reserved == 0 && payload == 0 && at == wire.size();
}

static bool valid_dropped_sender(const RoleBundle& role) {
    if (role.manifest.role != Role::Dropped) return false;
    std::string error;
    return validate_role(role, error);
}

bool send_bundle(int fd,
                 const IdentityBundle& bundle,
                 std::chrono::steady_clock::time_point deadline) {
    std::string error;
    if (fd < 0 || !validate_bundle(bundle, error)) return false;
    const std::vector<unsigned char> wire = encode_bundle(bundle);
    std::array<int, kBundleFdCount> fds{};
    size_t at = 0;
    for (const RoleBundle& role : bundle.roles)
        for (int value : role.fds) fds[at++] = value;
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(kBundleFdCount * sizeof(int))> control{};
    iovec vector{const_cast<unsigned char*>(wire.data()), wire.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(kBundleFdCount * sizeof(int));
    memcpy(CMSG_DATA(header), fds.data(), kBundleFdCount * sizeof(int));
    if (!wait_fd(fd, POLLOUT, deadline)) return false;
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent <= 0) return false;
    return static_cast<size_t>(sent) == wire.size() ||
           send_bytes(fd, wire.data() + sent, wire.size() - static_cast<size_t>(sent), deadline);
}

bool receive_bundle(int fd,
                    ReceivedBundle& received,
                    std::chrono::steady_clock::time_point deadline,
                    std::string& error) {
    received.reset();
    if (fd < 0 || !wait_fd(fd, POLLIN, deadline)) {
        error = "identity bundle receive deadline/descriptor failure";
        return false;
    }
    std::array<unsigned char, kWireBytes> wire{};
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(kBundleFdCount * sizeof(int))> control{};
    iovec vector{wire.data(), wire.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count <= 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        close_rights_in_message(message);
        error = "identity bundle initial frame was truncated or EOF";
        return false;
    }
    std::array<int, kBundleFdCount> fds{};
    fds.fill(-1);
    if (!parse_rights(message, fds)) {
        close_rights_in_message(message);
        close_fds(fds);
        error = "identity bundle ancillary rights were not exactly 12 SCM_RIGHTS";
        return false;
    }
    size_t done = static_cast<size_t>(count);
    while (done != wire.size()) {
        if (!wait_fd(fd, POLLIN, deadline)) {
            close_fds(fds);
            error = "identity bundle frame was truncated before payload completion";
            return false;
        }
        alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> extra_control{};
        iovec rest{wire.data() + done, wire.size() - done};
        msghdr rest_message{};
        rest_message.msg_iov = &rest;
        rest_message.msg_iovlen = 1;
        rest_message.msg_control = extra_control.data();
        rest_message.msg_controllen = extra_control.size();
        do {
            count = recvmsg(fd, &rest_message, MSG_CMSG_CLOEXEC);
        } while (count < 0 && errno == EINTR);
        if (count <= 0 || (rest_message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 ||
            CMSG_FIRSTHDR(&rest_message) != nullptr) {
            close_rights_in_message(rest_message);
            close_fds(fds);
            error = "identity bundle payload read had EOF/truncation/ancillary data";
            return false;
        }
        done += static_cast<size_t>(count);
    }
    // A bundle is one complete transport record.  A queued byte or ancillary
    // record after it is never silently ignored (the caller may still use the
    // socket in the opposite direction for its ACK).
    pollfd trailing{fd, POLLIN, 0};
    int trailing_poll;
    do {
        trailing_poll = poll(&trailing, 1, 0);
    } while (trailing_poll < 0 && errno == EINTR);
    if (trailing_poll < 0) {
        close_fds(fds);
        error = "identity bundle trailing-data poll failed";
        return false;
    }
    if ((trailing.revents & POLLIN) != 0) {
        unsigned char byte = 0;
        alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> trailing_control{};
        iovec trailing_vector{&byte, sizeof(byte)};
        msghdr trailing_message{};
        trailing_message.msg_iov = &trailing_vector;
        trailing_message.msg_iovlen = 1;
        trailing_message.msg_control = trailing_control.data();
        trailing_message.msg_controllen = trailing_control.size();
        ssize_t trailing_count;
        do {
            trailing_count = recvmsg(fd, &trailing_message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        } while (trailing_count < 0 && errno == EINTR);
        if (trailing_count > 0 || CMSG_FIRSTHDR(&trailing_message) != nullptr) {
            close_rights_in_message(trailing_message);
            close_fds(fds);
            error = "identity bundle had trailing data or ancillary records";
            return false;
        }
        if (trailing_count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close_fds(fds);
            error = "identity bundle trailing-data receive failed";
            return false;
        }
    }
    IdentityBundle decoded;
    if (!parse_wire(wire.data(), wire.size(), decoded)) {
        close_fds(fds);
        error = "identity bundle manifest header/payload was invalid";
        return false;
    }
    size_t at = 0;
    for (RoleBundle& role : decoded.roles)
        for (int& value : role.fds) value = fds[at++];
    if (!validate_bundle(decoded, error)) {
        decoded.close();
        return false;
    }
    received.bundle() = std::move(decoded);
    return true;
}

bool send_dropped_role(int fd,
                       const RoleBundle& role,
                       std::chrono::steady_clock::time_point deadline) {
    if (fd < 0 || !valid_dropped_sender(role)) return false;
    const std::vector<unsigned char> wire = encode_dropped_header();
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(kDroppedFdCount * sizeof(int))> control{};
    iovec vector{const_cast<unsigned char*>(wire.data()), wire.size()};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(kDroppedFdCount * sizeof(int));
    memcpy(CMSG_DATA(header), role.fds.data(), kDroppedFdCount * sizeof(int));
    if (!wait_fd(fd, POLLOUT, deadline)) return false;
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent <= 0) return false;
    return static_cast<size_t>(sent) == wire.size() ||
           send_bytes(fd, wire.data() + sent, wire.size() - static_cast<size_t>(sent), deadline);
}

bool receive_dropped_role(int fd,
                          RoleBundle& role,
                          std::chrono::steady_clock::time_point deadline,
                          std::string& error) {
    role.close();
    if (fd < 0 || !wait_fd(fd, POLLIN, deadline)) {
        error = "dropped identity receive deadline/descriptor failure";
        return false;
    }
    std::array<unsigned char, kDroppedHeaderBytes> wire{};
    std::array<int, kDroppedFdCount> fds{};
    fds.fill(-1);
    size_t done = 0;
    bool first = true;
    while (done != wire.size()) {
        if (!wait_fd(fd, POLLIN, deadline)) {
            close_dropped_fds(fds);
            error = "dropped identity header fragment deadline/descriptor failure";
            return false;
        }
        alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(kDroppedFdCount * sizeof(int))>
            control{};
        iovec vector{wire.data() + done, wire.size() - done};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        ssize_t count;
        do {
            count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
        } while (count < 0 && errno == EINTR);
        if (count <= 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
            close_rights_in_message(message);
            close_dropped_fds(fds);
            error = "dropped identity header was truncated or EOF";
            return false;
        }
        if (first) {
            if (!parse_dropped_rights(message, fds)) {
                close_rights_in_message(message);
                error = "dropped identity ancillary rights were not exactly six SCM_RIGHTS";
                return false;
            }
            first = false;
        } else if (CMSG_FIRSTHDR(&message) != nullptr) {
            close_rights_in_message(message);
            close_dropped_fds(fds);
            error = "dropped identity header had ancillary data after its first fragment";
            return false;
        }
        done += static_cast<size_t>(count);
    }
    if (!parse_dropped_header(wire)) {
        close_dropped_fds(fds);
        error = "dropped identity fixed header was invalid";
        return false;
    }
    // This zero-time probe rejects only data already queued behind the fixed
    // record under the caller's request/wait barrier; it is not a race-free
    // generic stream boundary and does not consume a legitimate next frame.
    pollfd trailing{fd, POLLIN, 0};
    int trailing_poll;
    do {
        trailing_poll = poll(&trailing, 1, 0);
    } while (trailing_poll < 0 && errno == EINTR);
    if (trailing_poll < 0) {
        close_dropped_fds(fds);
        error = "dropped identity trailing-data poll failed";
        return false;
    }
    if ((trailing.revents & POLLIN) != 0) {
        unsigned char byte = 0;
        alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> control{};
        iovec vector{&byte, sizeof(byte)};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        ssize_t count;
        do {
            count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        } while (count < 0 && errno == EINTR);
        if (count > 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 ||
            CMSG_FIRSTHDR(&message) != nullptr) {
            close_rights_in_message(message);
            close_dropped_fds(fds);
            error = "dropped identity record had trailing data or ancillary records";
            return false;
        }
        if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close_rights_in_message(message);
            close_dropped_fds(fds);
            error = "dropped identity trailing-data receive failed";
            return false;
        }
    }
    if (!adopt_role(Role::Dropped, fds, role, error)) {
        close_dropped_fds(fds);
        return false;
    }
    return true;
}

}  // namespace rut::test::fixture_identity_bundle
