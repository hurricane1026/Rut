#include "fixture_identity_bundle.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace rut::test::fixture_identity_bundle;

enum class CmsgShape { Exact, Missing, Short, Long, ExtraCredentials };

static bool send_plain(int fd,
                       const unsigned char* data,
                       size_t size,
                       std::chrono::steady_clock::time_point deadline) {
    size_t offset = 0;
    while (offset != size) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        if (left <= 0) return false;
        pollfd descriptor{fd, POLLOUT, 0};
        if (poll(&descriptor, 1, static_cast<int>(left)) <= 0) return false;
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

static std::array<int, kBundleFdCount> flatten(const IdentityBundle& bundle) {
    std::array<int, kBundleFdCount> result{};
    size_t at = 0;
    for (const RoleBundle& role : bundle.roles)
        for (int fd : role.fds) result[at++] = fd;
    return result;
}

static std::array<int, kDroppedFdCount> flatten_role(const RoleBundle& role) {
    std::array<int, kDroppedFdCount> result{};
    result = role.fds;
    return result;
}

static u64 read_wire_u64(const std::vector<unsigned char>& wire, size_t offset) {
    u64 value = 0;
    for (unsigned shift = 0; shift != 64; shift += 8)
        value |= static_cast<u64>(wire[offset + shift / 8]) << shift;
    return value;
}

static bool xor_nonzero_wire_u64(std::vector<unsigned char>& wire, size_t offset) {
    const u64 before = read_wire_u64(wire, offset);
    for (size_t byte = 0; byte != sizeof(u64); ++byte) {
        wire[offset + byte] ^= 0x01;
        if (read_wire_u64(wire, offset) != 0 && read_wire_u64(wire, offset) != before) return true;
        wire[offset + byte] ^= 0x01;
    }
    return false;
}

static bool send_dropped_raw(int fd,
                             const std::vector<unsigned char>& wire,
                             const std::array<int, kDroppedFdCount>& fds,
                             CmsgShape shape,
                             size_t first_bytes,
                             bool trailing = false,
                             bool complete = true) {
    if (first_bytes > wire.size()) return false;
    const size_t count = shape == CmsgShape::Short  ? kDroppedFdCount - 1
                         : shape == CmsgShape::Long ? kDroppedFdCount + 1
                                                    : kDroppedFdCount;
    std::array<int, kDroppedFdCount + 1> rights{};
    std::copy(fds.begin(), fds.end(), rights.begin());
    alignas(cmsghdr) std::array<unsigned char,
                                CMSG_SPACE((kDroppedFdCount + 1) * sizeof(int)) +
                                    CMSG_SPACE(sizeof(struct ucred))>
        control{};
    iovec vector{const_cast<unsigned char*>(wire.data()), first_bytes};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (shape != CmsgShape::Missing) {
        message.msg_control = control.data();
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        if (shape == CmsgShape::ExtraCredentials)
            message.msg_controllen += CMSG_SPACE(sizeof(struct ucred));
        cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), rights.data(), count * sizeof(int));
        if (shape == CmsgShape::ExtraCredentials) {
            cmsghdr* credentials_header = CMSG_NXTHDR(&message, header);
            if (credentials_header == nullptr) return false;
            const struct ucred credentials{getpid(), getuid(), getgid()};
            credentials_header->cmsg_level = SOL_SOCKET;
            credentials_header->cmsg_type = SCM_CREDENTIALS;
            credentials_header->cmsg_len = CMSG_LEN(sizeof(credentials));
            memcpy(CMSG_DATA(credentials_header), &credentials, sizeof(credentials));
        }
    }
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) return false;
    if (static_cast<size_t>(sent) != first_bytes &&
        !send_plain(fd,
                    wire.data() + sent,
                    first_bytes - static_cast<size_t>(sent),
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(500)))
        return false;
    if (complete && first_bytes != wire.size() &&
        !send_plain(fd,
                    wire.data() + first_bytes,
                    wire.size() - first_bytes,
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(500)))
        return false;
    if (trailing) {
        alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> trailing_control{};
        unsigned char byte = 0;
        iovec trailing_vector{&byte, sizeof(byte)};
        msghdr trailing_message{};
        trailing_message.msg_iov = &trailing_vector;
        trailing_message.msg_iovlen = 1;
        trailing_message.msg_control = trailing_control.data();
        trailing_message.msg_controllen = trailing_control.size();
        cmsghdr* header = CMSG_FIRSTHDR(&trailing_message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fds[0], sizeof(int));
        do {
            sent = sendmsg(fd, &trailing_message, MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent != 1) return false;
    }
    return true;
}

static bool send_raw(int fd,
                     const std::vector<unsigned char>& wire,
                     const std::array<int, kBundleFdCount>& fds,
                     CmsgShape shape,
                     size_t first_bytes,
                     bool trailing_rights = false,
                     bool complete = true,
                     bool rest_rights = false) {
    const size_t count = shape == CmsgShape::Short  ? kBundleFdCount - 1
                         : shape == CmsgShape::Long ? kBundleFdCount + 1
                                                    : kBundleFdCount;
    std::array<int, kBundleFdCount + 1> rights{};
    std::copy(fds.begin(), fds.end(), rights.begin());
    rights[kBundleFdCount] = fds[0];
    alignas(cmsghdr) std::array<unsigned char,
                                CMSG_SPACE((kBundleFdCount + 1) * sizeof(int)) +
                                    CMSG_SPACE(sizeof(struct ucred))>
        control{};
    iovec vector{const_cast<unsigned char*>(wire.data()), first_bytes};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (shape != CmsgShape::Missing) {
        message.msg_control = control.data();
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        if (shape == CmsgShape::ExtraCredentials)
            message.msg_controllen += CMSG_SPACE(sizeof(struct ucred));
        cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), rights.data(), count * sizeof(int));
        if (shape == CmsgShape::ExtraCredentials) {
            cmsghdr* credentials_header = CMSG_NXTHDR(&message, header);
            if (credentials_header == nullptr) return false;
            const struct ucred credentials{getpid(), getuid(), getgid()};
            credentials_header->cmsg_level = SOL_SOCKET;
            credentials_header->cmsg_type = SCM_CREDENTIALS;
            credentials_header->cmsg_len = CMSG_LEN(sizeof(credentials));
            memcpy(CMSG_DATA(credentials_header), &credentials, sizeof(credentials));
        }
    }
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) return false;
    if (static_cast<size_t>(sent) != first_bytes &&
        !send_plain(fd,
                    wire.data() + sent,
                    first_bytes - static_cast<size_t>(sent),
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(500))) {
        return false;
    }
    if (complete && first_bytes != wire.size()) {
        const size_t remaining = wire.size() - first_bytes;
        if (rest_rights) {
            alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> rest_control{};
            iovec rest_vector{const_cast<unsigned char*>(wire.data() + first_bytes), remaining};
            msghdr rest_message{};
            rest_message.msg_iov = &rest_vector;
            rest_message.msg_iovlen = 1;
            rest_message.msg_control = rest_control.data();
            rest_message.msg_controllen = rest_control.size();
            cmsghdr* rest_header = CMSG_FIRSTHDR(&rest_message);
            rest_header->cmsg_level = SOL_SOCKET;
            rest_header->cmsg_type = SCM_RIGHTS;
            rest_header->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(rest_header), &fds[0], sizeof(int));
            do {
                sent = sendmsg(fd, &rest_message, MSG_NOSIGNAL);
            } while (sent < 0 && errno == EINTR);
            if (sent < 0) return false;
            if (static_cast<size_t>(sent) != remaining &&
                !send_plain(fd,
                            wire.data() + first_bytes + sent,
                            remaining - static_cast<size_t>(sent),
                            std::chrono::steady_clock::now() + std::chrono::milliseconds(500)))
                return false;
        } else if (!send_plain(fd,
                               wire.data() + first_bytes,
                               remaining,
                               std::chrono::steady_clock::now() + std::chrono::milliseconds(500))) {
            return false;
        }
    }
    if (trailing_rights) {
        alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> trailing_control{};
        unsigned char byte = 0;
        iovec trailing_vector{&byte, sizeof(byte)};
        msghdr trailing{};
        trailing.msg_iov = &trailing_vector;
        trailing.msg_iovlen = 1;
        trailing.msg_control = trailing_control.data();
        trailing.msg_controllen = trailing_control.size();
        cmsghdr* header = CMSG_FIRSTHDR(&trailing);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fds[0], sizeof(int));
        do {
            sent = sendmsg(fd, &trailing, MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent != 1) return false;
    }
    return true;
}

static size_t fd_count() {
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return 0;
    size_t count = 0;
    while (readdir(directory) != nullptr) ++count;
    closedir(directory);
    return count;
}

static bool receive_dropped_fails(const std::vector<unsigned char>& wire,
                                  const std::array<int, kDroppedFdCount>& fds,
                                  CmsgShape shape,
                                  size_t first_bytes,
                                  bool trailing = false,
                                  bool complete = true) {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    const size_t before = fd_count();
    if (shape == CmsgShape::ExtraCredentials) {
        int enabled = 1;
        if (setsockopt(sockets[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) {
            close(sockets[0]);
            close(sockets[1]);
            return false;
        }
    }
    const bool sent =
        send_dropped_raw(sockets[0], wire, fds, shape, first_bytes, trailing, complete);
    const int send_errno = sent ? 0 : errno;
    shutdown(sockets[0], SHUT_WR);
    RoleBundle received;
    std::string error;
    const bool accepted =
        receive_dropped_role(sockets[1],
                             received,
                             std::chrono::steady_clock::now() + std::chrono::milliseconds(250),
                             error);
    received.close();
    const bool no_leak = fd_count() == before;
    close(sockets[0]);
    close(sockets[1]);
    if (!sent) {
        if (shape == CmsgShape::ExtraCredentials && send_errno == EINVAL) {
            std::fprintf(stderr, "kernel rejected dropped SCM_CREDENTIALS ancillary\n");
            return true;
        }
        return false;
    }
    return !accepted && no_leak;
}

static std::vector<unsigned char> dropped_header() {
    std::vector<unsigned char> wire;
    const auto put16 = [&](u16 value) {
        wire.push_back(static_cast<unsigned char>(value));
        wire.push_back(static_cast<unsigned char>(value >> 8));
    };
    const auto put32 = [&](u32 value) {
        for (unsigned shift = 0; shift != 32; shift += 8)
            wire.push_back(static_cast<unsigned char>(value >> shift));
    };
    put32(kDroppedMagic);
    put16(kDroppedVersion);
    put16(static_cast<u16>(Role::Dropped));
    put16(static_cast<u16>(kDroppedFdCount));
    put16(0);
    put32(0);
    return wire;
}

static bool receive_fails(const std::vector<unsigned char>& wire,
                          const std::array<int, kBundleFdCount>& fds,
                          CmsgShape shape,
                          size_t first_bytes,
                          bool trailing = false,
                          bool complete = true,
                          bool rest_rights = false) {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    const size_t before = fd_count();
    if (shape == CmsgShape::ExtraCredentials) {
        int enabled = 1;
        if (setsockopt(sockets[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) {
            close(sockets[0]);
            close(sockets[1]);
            return false;
        }
    }
    const bool sent =
        send_raw(sockets[0], wire, fds, shape, first_bytes, trailing, complete, rest_rights);
    const int send_errno = sent ? 0 : errno;
    shutdown(sockets[0], SHUT_WR);
    ReceivedBundle received;
    std::string error;
    const bool accepted =
        receive_bundle(sockets[1],
                       received,
                       std::chrono::steady_clock::now() + std::chrono::milliseconds(250),
                       error);
    received.reset();
    const bool no_leak = fd_count() == before;
    close(sockets[0]);
    close(sockets[1]);
    if (shape == CmsgShape::ExtraCredentials && !sent) {
        // Some kernels reject explicitly supplied credentials on stream
        // sockets.  Treat that as a kernel-level rejection, never as proof
        // that our receiver rejected the ancillary record.
        if (send_errno == EINVAL) {
            std::fprintf(stderr, "kernel rejected SCM_CREDENTIALS ancillary\n");
            return true;
        }
        return false;
    }
    // Non-empty negative cases must first prove that the malformed record was
    // delivered.  Otherwise a sender-side failure could masquerade as a
    // receiver rejection (the empty call below is the intentional EOF case).
    if (!wire.empty() && !sent) return false;
    return !accepted && no_leak;
}

static bool compare_manifests(const IdentityBundle& expected, const IdentityBundle& actual) {
    for (size_t i = 0; i != kRoleCount; ++i) {
        const RoleManifest& a = expected.roles[i].manifest;
        const RoleManifest& b = actual.roles[i].manifest;
        if (a.role != b.role || a.pid != b.pid || a.start != b.start || a.ppid != b.ppid ||
            a.pgid != b.pgid || a.sid != b.sid || a.uid != b.uid || a.gid != b.gid ||
            a.netns != b.netns || a.exe_dev != b.exe_dev || a.exe_ino != b.exe_ino ||
            a.argv_length != b.argv_length || a.argv_hash != b.argv_hash)
            return false;
    }
    return true;
}

static bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

static bool read_path(const std::string& path, std::string& output) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    output.clear();
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            if (output.size() > 16384 - static_cast<size_t>(count)) {
                close(fd);
                return false;
            }
            output.append(buffer.data(), static_cast<size_t>(count));
            continue;
        }
        if (count == 0) {
            close(fd);
            return true;
        }
        if (errno == EINTR) continue;
        close(fd);
        return false;
    }
}

static std::string replace_once(std::string value,
                                const std::string& before,
                                const std::string& after) {
    const size_t at = value.find(before);
    if (at == std::string::npos) return {};
    value.replace(at, before.size(), after);
    return value;
}

static std::string remove_line(std::string value, const std::string& prefix) {
    const size_t at = value.find(prefix);
    if (at == std::string::npos) return {};
    const size_t end = value.find('\n', at);
    value.erase(at, end == std::string::npos ? value.size() - at : end + 1 - at);
    return value;
}

}  // namespace

int main() {
    const std::string strict_status =
        "Name:\tevidence\n"
        "Uid:\t11\t12\t13\t14\n"
        "Gid:\t21\t22\t23\t24\n"
        "Groups:\t31 32 31\n"
        "NoNewPrivs:\t1\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000001\n"
        "CapEff:\tABCDEF0123456789\n"
        "CapBnd:\t000001ffffffffff\n"
        "CapAmb:\t0000000000000002\n";
    DroppedStatusEvidence strict_evidence;
    std::string strict_error;
    bool ok =
        check(parse_dropped_status_evidence(strict_status, strict_evidence, strict_error) &&
                  strict_evidence.uid_values == std::array<uid_t, 4>{11, 12, 13, 14} &&
                  strict_evidence.gid_values == std::array<gid_t, 4>{21, 22, 23, 24} &&
                  strict_evidence.supplementary_groups == std::vector<gid_t>{31, 32, 31} &&
                  strict_evidence.no_new_privs && strict_evidence.cap_inh_clear &&
                  !strict_evidence.cap_prm_clear && !strict_evidence.cap_eff_clear &&
                  strict_evidence.cap_inh == 0 && strict_evidence.cap_prm == 1 &&
                  strict_evidence.cap_eff == 0xabcdef0123456789ULL &&
                  strict_evidence.cap_bnd == 0x000001ffffffffffULL && strict_evidence.cap_amb == 2,
              "strict dropped status evidence retains every field");
    const auto owns_no_fds = [](const RoleBundle& role) {
        return std::all_of(role.fds.begin(), role.fds.end(), [](int fd) { return fd < 0; });
    };
    RoleBundle failed_role;
    OpenRoleFailure open_failure;
    std::string open_failure_error;
    ok &= check(!open_role(1, Role::Ancestry, failed_role, open_failure, open_failure_error) &&
                    open_failure.slot == FdSlot::Unknown && open_failure.phase == "pid_validate" &&
                    open_failure.operation == "none" && open_failure.error_number == 0 &&
                    owns_no_fds(failed_role),
                "unsafe PID open diagnostic is aggregate and owns no FDs");
    const pid_t vanished = fork();
    if (!check(vanished >= 0, "vanished child fork")) return 1;
    if (vanished == 0) _exit(0);
    int vanished_status = 0;
    pid_t vanished_waited;
    do {
        vanished_waited = waitpid(vanished, &vanished_status, 0);
    } while (vanished_waited < 0 && errno == EINTR);
    open_failure = OpenRoleFailure{};
    open_failure_error.clear();
    ok &= check(
        vanished_waited == vanished &&
            !open_role(vanished, Role::Ancestry, failed_role, open_failure, open_failure_error) &&
            open_failure.slot == FdSlot::Stat && open_failure.phase == "open" &&
            open_failure.operation == "open" && open_failure.error_number != 0 &&
            owns_no_fds(failed_role),
        "reaped PID reports first stat open failure and owns no FDs");
    const std::string empty_groups_status =
        replace_once(strict_status, "Groups:\t31 32 31", "Groups:\t");
    const std::string nnp_zero_status =
        replace_once(strict_status, "NoNewPrivs:\t1", "NoNewPrivs:\t0");
    DroppedStatusEvidence empty_groups_evidence;
    DroppedStatusEvidence nnp_zero_evidence;
    DroppedStatusEvidence changed_nonzero_cap_evidence;
    const std::string changed_nonzero_cap_status =
        replace_once(strict_status, "CapPrm:\t0000000000000001", "CapPrm:\t0000000000000002");
    ok &= check(
        parse_dropped_status_evidence(empty_groups_status, empty_groups_evidence, strict_error) &&
            empty_groups_evidence.supplementary_groups.empty() &&
            parse_dropped_status_evidence(nnp_zero_status, nnp_zero_evidence, strict_error) &&
            !nnp_zero_evidence.no_new_privs &&
            parse_dropped_status_evidence(
                changed_nonzero_cap_status, changed_nonzero_cap_evidence, strict_error) &&
            !strict_evidence.cap_prm_clear && !changed_nonzero_cap_evidence.cap_prm_clear &&
            strict_evidence.cap_prm != changed_nonzero_cap_evidence.cap_prm,
        "strict status extraction does not impose later group/NNP expectations");
    const auto status_rejected = [&](const std::string& status) {
        DroppedStatusEvidence ignored;
        std::string error;
        return !status.empty() && !parse_dropped_status_evidence(status, ignored, error) &&
               !error.empty();
    };
    const std::string uid_overflow = std::to_string(std::numeric_limits<uid_t>::max()) + "0";
    const std::string gid_overflow = std::to_string(std::numeric_limits<gid_t>::max()) + "0";
    ok &= check(status_rejected(remove_line(strict_status, "Uid:")) &&
                    status_rejected(strict_status + "Uid:\t1 2 3 4\n") &&
                    status_rejected(replace_once(
                        strict_status, "Uid:\t11\t12\t13\t14", "Uid:\t11 12 13 14 15")) &&
                    status_rejected(replace_once(
                        strict_status, "Uid:\t11\t12\t13\t14", "Uid:\t11 bad 13 14")) &&
                    status_rejected(replace_once(
                        strict_status, "Uid:\t11\t12\t13\t14", "Uid:\t11 12 13 " + uid_overflow)),
                "strict Uid missing/duplicate/extra/malformed/range mutations rejected");
    ok &= check(status_rejected(remove_line(strict_status, "Gid:")) &&
                    status_rejected(strict_status + "Gid:\t1 2 3 4\n") &&
                    status_rejected(replace_once(
                        strict_status, "Gid:\t21\t22\t23\t24", "Gid:\t21 22 23 24 25")) &&
                    status_rejected(replace_once(
                        strict_status, "Gid:\t21\t22\t23\t24", "Gid:\t21 22 bad 24")) &&
                    status_rejected(replace_once(
                        strict_status, "Gid:\t21\t22\t23\t24", "Gid:\t21 22 23 " + gid_overflow)),
                "strict Gid missing/duplicate/extra/malformed/range mutations rejected");
    ok &= check(status_rejected(remove_line(strict_status, "Groups:")) &&
                    status_rejected(strict_status + "Groups:\t1\n") &&
                    status_rejected(
                        replace_once(strict_status, "Groups:\t31 32 31", "Groups:\t31 bad 31")) &&
                    status_rejected(replace_once(
                        strict_status, "Groups:\t31 32 31", "Groups:\t31 " + gid_overflow)),
                "strict Groups missing/duplicate/malformed/range mutations rejected");
    ok &= check(
        status_rejected(remove_line(strict_status, "NoNewPrivs:")) &&
            status_rejected(strict_status + "NoNewPrivs:\t1\n") &&
            status_rejected(replace_once(strict_status, "NoNewPrivs:\t1", "NoNewPrivs:\t1 0")) &&
            status_rejected(replace_once(strict_status, "NoNewPrivs:\t1", "NoNewPrivs:\tbad")) &&
            status_rejected(replace_once(strict_status, "NoNewPrivs:\t1", "NoNewPrivs:\t2")),
        "strict NoNewPrivs missing/duplicate/extra/malformed/range mutations rejected");
    for (const char* capability : {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}) {
        const std::string prefix = std::string(capability) + ":";
        const size_t start = strict_status.find(prefix);
        const size_t end = strict_status.find('\n', start);
        const std::string line = strict_status.substr(start, end + 1 - start);
        ok &= check(start != std::string::npos &&
                        status_rejected(remove_line(strict_status, prefix)) &&
                        status_rejected(strict_status + line) &&
                        status_rejected(replace_once(strict_status, line, prefix + "\t0 0\n")) &&
                        status_rejected(replace_once(strict_status, line, prefix + "\txyz\n")) &&
                        status_rejected(
                            replace_once(strict_status, line, prefix + "\t00000000000000000\n")),
                    "strict capability missing/duplicate/extra/nonhex/width mutations rejected");
    }

    int ready[2] = {-1, -1};
    if (!check(pipe2(ready, O_CLOEXEC) == 0, "ready pipe setup")) return 1;
    const pid_t child = fork();
    if (!check(child >= 0, "child fork")) return 1;
    if (child == 0) {
        close(ready[0]);
        setpgid(0, 0);
        const unsigned char marker = 0x42;
        (void)write(ready[1], &marker, 1);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    unsigned char marker = 0;
    if (!check(read(ready[0], &marker, 1) == 1 && marker == 0x42, "child ready")) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return 1;
    }
    close(ready[0]);

    IdentityBundle bundle;
    std::string error;
    if (!check(open_role(getpid(), Role::Launcher, bundle.roles[0], error), "open launcher role") ||
        !check(open_role(child, Role::Root, bundle.roles[1], error), "open root role") ||
        !check(validate_bundle(bundle, error), "validate real bundle")) {
        std::fprintf(stderr, "detail: %s\n", error.c_str());
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return 1;
    }
    bool shared_objects = bundle.roles[0].manifest.exe_dev == bundle.roles[1].manifest.exe_dev &&
                          bundle.roles[0].manifest.exe_ino == bundle.roles[1].manifest.exe_ino &&
                          bundle.roles[0].manifest.netns == bundle.roles[1].manifest.netns;
    if (!check(shared_objects, "shared executable/netns objects accepted across roles")) {
        bundle.close();
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return 1;
    }
    const std::vector<unsigned char> wire = encode_bundle(bundle);
    const std::array<int, kBundleFdCount> fds = flatten(bundle);
    ok &= check(wire.size() == kWireBytes && kPayloadBytes != 0, "fixed nonempty payload");

    int sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0,
                "success socketpair");
    ReceivedBundle received;
    ok &= check(send_bundle(sockets[0],
                            bundle,
                            std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(kTransportTimeoutMs)),
                "send bundle");
    ok &= check(receive_bundle(sockets[1],
                               received,
                               std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(kTransportTimeoutMs),
                               error),
                "receive bundle");
    ok &= check(compare_manifests(bundle, received.bundle()), "exact decoded manifest");
    for (const RoleBundle& role : received.bundle().roles)
        for (int fd : role.fds)
            ok &= check((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "received CLOEXEC");
    const unsigned char ack = 0xa5;
    ok &= check(send(sockets[1], &ack, 1, MSG_NOSIGNAL) == 1, "ACK simulation");
    unsigned char got_ack = 0;
    ok &= check(recv(sockets[0], &got_ack, 1, 0) == 1 && got_ack == ack, "ACK received");
    close(sockets[0]);
    close(sockets[1]);

    ok &=
        check(receive_fails(wire, fds, CmsgShape::Missing, wire.size()), "missing rights rejected");
    ok &= check(receive_fails(wire, fds, CmsgShape::Short, wire.size()), "short rights rejected");
    ok &= check(receive_fails(wire, fds, CmsgShape::Long, wire.size()), "long rights rejected");
    ok &= check(receive_fails(wire, fds, CmsgShape::ExtraCredentials, wire.size()),
                "extra credentials ancillary rejected");
    ok &= check(receive_fails(wire, fds, CmsgShape::Exact, 5, false, false),
                "truncated header rejected");
    ok &= check(receive_fails(wire, fds, CmsgShape::Exact, kHeaderBytes + 2, false, false),
                "truncated payload rejected");
    ok &= check(receive_fails(wire, fds, CmsgShape::Exact, kHeaderBytes, false, true, true),
                "payload ancillary rejected and closed");
    ok &= check(receive_fails(wire, fds, CmsgShape::Exact, wire.size(), true),
                "trailing ancillary rejected");
    std::vector<unsigned char> oversized = wire;
    oversized[12] = static_cast<unsigned char>((kPayloadBytes + 1) & 0xff);
    oversized[13] = static_cast<unsigned char>((kPayloadBytes + 1) >> 8);
    ok &= check(oversized != wire, "oversized mutation differs");
    ok &= check(receive_fails(oversized, fds, CmsgShape::Exact, oversized.size()),
                "oversized payload rejected");
    std::vector<unsigned char> bad_manifest = wire;
    bad_manifest[kHeaderBytes + kRoleManifestBytes - 1] = 1;
    ok &= check(bad_manifest != wire, "manifest mutation differs");
    ok &= check(receive_fails(bad_manifest, fds, CmsgShape::Exact, bad_manifest.size()),
                "manifest reserved mutation rejected");
    // Semantic mutation checks separately require a nonzero start.  These
    // transport mutations keep that invariant while changing the exact
    // little-endian start field checked against the retained Stat FD.
    constexpr size_t kManifestStartOffset = 2 * sizeof(u64);  // role, pid, start
    const size_t launcher_start_offset = kHeaderBytes + kManifestStartOffset;
    const size_t root_start_offset = kHeaderBytes + kRoleManifestBytes + kManifestStartOffset;
    std::vector<unsigned char> bad_launcher_start = wire;
    const u64 launcher_start = read_wire_u64(bad_launcher_start, launcher_start_offset);
    ok &= check(xor_nonzero_wire_u64(bad_launcher_start, launcher_start_offset) &&
                    bad_launcher_start != wire &&
                    read_wire_u64(bad_launcher_start, launcher_start_offset) != 0 &&
                    read_wire_u64(bad_launcher_start, launcher_start_offset) != launcher_start,
                "launcher start wire mutation differs and remains nonzero");
    ok &= check(receive_fails(bad_launcher_start, fds, CmsgShape::Exact, bad_launcher_start.size()),
                "launcher start/stat FD mismatch rejected");
    std::vector<unsigned char> bad_root_start = wire;
    const u64 root_start = read_wire_u64(bad_root_start, root_start_offset);
    ok &= check(xor_nonzero_wire_u64(bad_root_start, root_start_offset) && bad_root_start != wire &&
                    read_wire_u64(bad_root_start, root_start_offset) != 0 &&
                    read_wire_u64(bad_root_start, root_start_offset) != root_start,
                "root start wire mutation differs and remains nonzero");
    ok &= check(receive_fails(bad_root_start, fds, CmsgShape::Exact, bad_root_start.size()),
                "root start/stat FD mismatch rejected");
    std::vector<int> reordered(fds.begin(), fds.end());
    std::swap(reordered[0], reordered[1]);
    std::array<int, kBundleFdCount> reordered_array{};
    std::copy(reordered.begin(), reordered.end(), reordered_array.begin());
    ok &= check(reordered_array != fds, "reordered fd mutation differs");
    ok &= check(receive_fails(wire, reordered_array, CmsgShape::Exact, wire.size()),
                "reordered fd rejected");
    std::array<int, kBundleFdCount> duplicate = fds;
    duplicate[1] = duplicate[0];
    ok &= check(fds[1] != fds[0] && duplicate != fds, "duplicate fd mutation differs");
    ok &= check(receive_fails(wire, duplicate, CmsgShape::Exact, wire.size()),
                "duplicate fd rejected");
    const int foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ok &= check(foreign >= 0, "foreign fd setup");
    std::array<int, kBundleFdCount> foreign_array = fds;
    foreign_array[0] = foreign;
    ok &= check(receive_fails(wire, foreign_array, CmsgShape::Exact, wire.size()),
                "foreign fd rejected");
    close(foreign);
    const pid_t foreign_child = fork();
    if (foreign_child == 0)
        for (;;) pause();
    ok &= check(foreign_child > 1, "foreign child setup");
    int foreign_child_pidfd = -1;
#ifdef SYS_pidfd_open
    if (foreign_child > 1) {
        const long raw_foreign_pidfd = syscall(SYS_pidfd_open, foreign_child, 0);
        if (raw_foreign_pidfd >= 0 && raw_foreign_pidfd <= std::numeric_limits<int>::max())
            foreign_child_pidfd = static_cast<int>(raw_foreign_pidfd);
    }
#endif
    std::array<int, kBundleFdCount> foreign_pidfd = fds;
    foreign_pidfd[11] = foreign_child_pidfd;
    ok &= check(foreign_child_pidfd >= 0 && fds[11] != foreign_child_pidfd && foreign_pidfd != fds,
                "foreign child pidfd mutation differs");
    ok &= check(receive_fails(wire, foreign_pidfd, CmsgShape::Exact, wire.size()),
                "foreign child pidfd rejected");
    if (foreign_child_pidfd >= 0) close(foreign_child_pidfd);
    if (foreign_child > 1) {
        kill(foreign_child, SIGKILL);
        waitpid(foreign_child, nullptr, 0);
    }
    std::vector<unsigned char> bad_pid = wire;
    ++bad_pid[kHeaderBytes + 8];
    ok &= check(bad_pid != wire, "manifest pid mutation differs");
    ok &= check(receive_fails(bad_pid, fds, CmsgShape::Exact, bad_pid.size()),
                "manifest pid mutation rejected");
    ok &= check(receive_fails({}, fds, CmsgShape::Missing, 0), "early EOF rejected");

    sockets[0] = sockets[1] = -1;
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0,
                "fragment socketpair");
    ReceivedBundle fragmented;
    ok &= check(send_raw(sockets[0], wire, fds, CmsgShape::Exact, 3), "fragmented send");
    ok &= check(receive_bundle(sockets[1],
                               fragmented,
                               std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(kTransportTimeoutMs),
                               error),
                "fragmented receive");
    ok &= check(compare_manifests(bundle, fragmented.bundle()), "fragmented exact decoded payload");
    close(sockets[0]);
    close(sockets[1]);

    RoleBundle dropped_source;
    std::string self_status;
    std::string self_cmdline;
    DroppedStatusEvidence expected_self_status;
    ok &= check(read_path("/proc/self/status", self_status) &&
                    read_path("/proc/self/cmdline", self_cmdline) &&
                    parse_dropped_status_evidence(self_status, expected_self_status, error),
                "read strict self dropped evidence");
    ok &= check(open_role(getpid(), Role::Dropped, dropped_source, error), "open dropped role");
    int dropped_sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, dropped_sockets) == 0,
                "dropped success socketpair");
    RoleBundle dropped_received;
    ok &= check(send_dropped_role(dropped_sockets[0],
                                  dropped_source,
                                  std::chrono::steady_clock::now() +
                                      std::chrono::milliseconds(kTransportTimeoutMs)),
                "send dropped role");
    const std::array<int, kDroppedFdCount> dropped_source_fds = dropped_source.fds;
    bool dropped_source_fds_valid = true;
    for (size_t i = 0; i != dropped_source_fds.size(); ++i) {
        dropped_source_fds_valid = dropped_source_fds_valid && dropped_source_fds[i] >= 0;
        for (size_t j = i + 1; j != dropped_source_fds.size(); ++j)
            dropped_source_fds_valid =
                dropped_source_fds_valid && dropped_source_fds[i] != dropped_source_fds[j];
    }
    ok &= check(dropped_source_fds_valid, "dropped source FD snapshot valid and unique");
    dropped_source.close();
    for (int fd : dropped_source_fds) {
        errno = 0;
        ok &= check(fcntl(fd, F_GETFD) < 0 && errno == EBADF,
                    "dropped exact source FD closed causally");
    }
    ok &= check(receive_dropped_role(dropped_sockets[1],
                                     dropped_received,
                                     std::chrono::steady_clock::now() +
                                         std::chrono::milliseconds(kTransportTimeoutMs),
                                     error),
                "receive dropped role");
    const auto same_role_manifest = [&](const RoleManifest& a, const RoleManifest& b) {
        return a.role == b.role && a.pid == b.pid && a.start == b.start && a.ppid == b.ppid &&
               a.pgid == b.pgid && a.sid == b.sid && a.uid == b.uid && a.gid == b.gid &&
               a.netns == b.netns && a.exe_dev == b.exe_dev && a.exe_ino == b.exe_ino &&
               a.argv_length == b.argv_length && a.argv_hash == b.argv_hash;
    };
    ok &= check(same_role_manifest(dropped_source.manifest, dropped_received.manifest),
                "dropped receiver-derived manifest exact");
    ok &= check(dropped_received.manifest.role == Role::Dropped &&
                    dropped_received.manifest.pid == getpid() &&
                    dropped_received.manifest.start != 0 && dropped_received.manifest.ppid > 0 &&
                    dropped_received.manifest.pgid > 0 && dropped_received.manifest.sid > 0,
                "dropped receiver-derived manifest");
    for (int fd : dropped_received.fds)
        ok &= check((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "dropped received CLOEXEC");
    DroppedIdentityEvidence dropped_evidence;
    const bool dropped_extracted =
        extract_dropped_identity_evidence(dropped_received, dropped_evidence, error);
    const Role saved_role = dropped_received.manifest.role;
    dropped_received.manifest.role = Role::Launcher;
    DroppedIdentityEvidence wrong_role_evidence;
    ok &= check(!extract_dropped_identity_evidence(dropped_received, wrong_role_evidence, error),
                "extractor rejects wrong role");
    dropped_received.manifest.role = saved_role;
    dropped_received.close();
    ok &= check(dropped_extracted && dropped_evidence.identity.pid == getpid() &&
                    dropped_evidence.state != '\0' &&
                    dropped_evidence.status.uid_values == expected_self_status.uid_values &&
                    dropped_evidence.status.gid_values == expected_self_status.gid_values &&
                    dropped_evidence.status.supplementary_groups ==
                        expected_self_status.supplementary_groups &&
                    dropped_evidence.status.no_new_privs == expected_self_status.no_new_privs &&
                    dropped_evidence.status.cap_inh_clear == expected_self_status.cap_inh_clear &&
                    dropped_evidence.status.cap_prm_clear == expected_self_status.cap_prm_clear &&
                    dropped_evidence.status.cap_eff_clear == expected_self_status.cap_eff_clear &&
                    dropped_evidence.cmdline == self_cmdline && dropped_evidence.pidfd_live,
                "extracted self evidence remains owned after source/received FD close");
    close(dropped_sockets[0]);
    close(dropped_sockets[1]);

    RoleBundle dropped_negative;
    ok &= check(open_role(child, Role::Dropped, dropped_negative, error),
                "reopen dropped role for mutations");
    const std::array<int, kDroppedFdCount> dropped_fds = flatten_role(dropped_negative);
    const std::vector<unsigned char> dropped_wire = dropped_header();
    auto dropped_header_mutation = [&](size_t offset, u32 value, size_t bytes) {
        std::vector<unsigned char> changed = dropped_wire;
        for (size_t index = 0; index != bytes; ++index)
            changed[offset + index] = static_cast<unsigned char>(value >> (index * 8));
        return changed;
    };
    std::vector<unsigned char> bad_dropped_magic = dropped_wire;
    bad_dropped_magic[0] ^= 0x01;
    ok &= check(receive_dropped_fails(
                    bad_dropped_magic, dropped_fds, CmsgShape::Exact, bad_dropped_magic.size()),
                "dropped wrong magic rejected");
    ok &= check(
        receive_dropped_fails(
            dropped_header_mutation(4, 2, 2), dropped_fds, CmsgShape::Exact, dropped_wire.size()),
        "dropped wrong version rejected");
    ok &=
        check(receive_dropped_fails(dropped_header_mutation(6, static_cast<u16>(Role::Launcher), 2),
                                    dropped_fds,
                                    CmsgShape::Exact,
                                    dropped_wire.size()),
              "dropped wrong role rejected");
    ok &=
        check(receive_dropped_fails(dropped_header_mutation(6, static_cast<u16>(Role::Ancestry), 2),
                                    dropped_fds,
                                    CmsgShape::Exact,
                                    dropped_wire.size()),
              "dropped wire rejects Ancestry role numeric");
    ok &= check(receive_dropped_fails(dropped_header_mutation(8, kDroppedFdCount - 1, 2),
                                      dropped_fds,
                                      CmsgShape::Exact,
                                      dropped_wire.size()),
                "dropped wrong FD count rejected");
    ok &= check(
        receive_dropped_fails(
            dropped_header_mutation(10, 1, 2), dropped_fds, CmsgShape::Exact, dropped_wire.size()),
        "dropped reserved field rejected");
    ok &= check(
        receive_dropped_fails(
            dropped_header_mutation(12, 1, 4), dropped_fds, CmsgShape::Exact, dropped_wire.size()),
        "dropped payload field rejected");
    ok &= check(
        receive_dropped_fails(dropped_wire, dropped_fds, CmsgShape::Missing, dropped_wire.size()),
        "dropped missing rights rejected");
    ok &= check(
        receive_dropped_fails(dropped_wire, dropped_fds, CmsgShape::Short, dropped_wire.size()),
        "dropped short rights rejected");
    ok &= check(
        receive_dropped_fails(dropped_wire, dropped_fds, CmsgShape::Long, dropped_wire.size()),
        "dropped long rights rejected");
    ok &= check(receive_dropped_fails(
                    dropped_wire, dropped_fds, CmsgShape::ExtraCredentials, dropped_wire.size()),
                "dropped extra credentials rejected");
    ok &= check(receive_dropped_fails(dropped_wire, dropped_fds, CmsgShape::Exact, 3, false, false),
                "dropped truncated header rejected");
    ok &= check(receive_dropped_fails(dropped_wire, dropped_fds, CmsgShape::Exact, 3, true),
                "dropped trailing/coalesced bytes rejected");
    std::vector<int> dropped_reordered_vector(dropped_fds.begin(), dropped_fds.end());
    std::swap(dropped_reordered_vector[0], dropped_reordered_vector[1]);
    std::array<int, kDroppedFdCount> dropped_reordered{};
    std::copy(dropped_reordered_vector.begin(),
              dropped_reordered_vector.end(),
              dropped_reordered.begin());
    ok &= check(receive_dropped_fails(
                    dropped_wire, dropped_reordered, CmsgShape::Exact, dropped_wire.size()),
                "dropped reordered FD rejected");
    std::array<int, kDroppedFdCount> dropped_duplicate = dropped_fds;
    dropped_duplicate[1] = dropped_duplicate[0];
    ok &= check(receive_dropped_fails(
                    dropped_wire, dropped_duplicate, CmsgShape::Exact, dropped_wire.size()),
                "dropped duplicate FD rejected");
    const int dropped_foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ok &= check(dropped_foreign >= 0, "dropped foreign FD setup");
    std::array<int, kDroppedFdCount> dropped_foreign_array = dropped_fds;
    dropped_foreign_array[0] = dropped_foreign;
    ok &= check(receive_dropped_fails(
                    dropped_wire, dropped_foreign_array, CmsgShape::Exact, dropped_wire.size()),
                "dropped foreign FD rejected");
    close(dropped_foreign);
    int fragment_sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fragment_sockets) == 0,
                "dropped fragment socketpair");
    RoleBundle dropped_fragment;
    ok &=
        check(send_dropped_raw(fragment_sockets[0], dropped_wire, dropped_fds, CmsgShape::Exact, 3),
              "dropped fragmented send");
    ok &= check(receive_dropped_role(fragment_sockets[1],
                                     dropped_fragment,
                                     std::chrono::steady_clock::now() +
                                         std::chrono::milliseconds(kTransportTimeoutMs),
                                     error),
                "dropped fragmented receive");
    ok &= check(same_role_manifest(dropped_negative.manifest, dropped_fragment.manifest),
                "dropped fragmented manifest exact");
    dropped_fragment.close();
    close(fragment_sockets[0]);
    close(fragment_sockets[1]);
    int partial_deadline_sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, partial_deadline_sockets) == 0,
                "dropped partial deadline socketpair");
    const size_t partial_before = fd_count();
    ok &= check(send_dropped_raw(partial_deadline_sockets[0],
                                 dropped_wire,
                                 dropped_fds,
                                 CmsgShape::Exact,
                                 3,
                                 false,
                                 false),
                "dropped incomplete header send");
    RoleBundle dropped_partial;
    ok &= check(
        !receive_dropped_role(partial_deadline_sockets[1],
                              dropped_partial,
                              std::chrono::steady_clock::now() + std::chrono::milliseconds(20),
                              error) &&
            fd_count() == partial_before,
        "dropped incomplete header deadline and FD cleanup");
    dropped_partial.close();
    close(partial_deadline_sockets[0]);
    close(partial_deadline_sockets[1]);
    int deadline_sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, deadline_sockets) == 0,
                "dropped deadline socketpair");
    RoleBundle dropped_timed_out;
    ok &= check(
        !receive_dropped_role(deadline_sockets[1],
                              dropped_timed_out,
                              std::chrono::steady_clock::now() + std::chrono::milliseconds(20),
                              error),
        "dropped receive deadline rejected");
    close(deadline_sockets[0]);
    close(deadline_sockets[1]);
    dropped_negative.close();

    std::vector<unsigned char> old_launcher_dropped = wire;
    old_launcher_dropped[kHeaderBytes + 0] = static_cast<unsigned char>(Role::Dropped);
    ok &= check(
        receive_fails(old_launcher_dropped, fds, CmsgShape::Exact, old_launcher_dropped.size()),
        "old bundle Dropped Launcher slot rejected");
    std::vector<unsigned char> old_root_dropped = wire;
    old_root_dropped[kHeaderBytes + kRoleManifestBytes] = static_cast<unsigned char>(Role::Dropped);
    ok &= check(receive_fails(old_root_dropped, fds, CmsgShape::Exact, old_root_dropped.size()),
                "old bundle Dropped Root slot rejected");
    std::vector<unsigned char> old_launcher_ancestry = wire;
    old_launcher_ancestry[kHeaderBytes + 0] = static_cast<unsigned char>(Role::Ancestry);
    ok &= check(
        receive_fails(old_launcher_ancestry, fds, CmsgShape::Exact, old_launcher_ancestry.size()),
        "old bundle Ancestry Launcher slot rejected");
    std::vector<unsigned char> old_root_ancestry = wire;
    old_root_ancestry[kHeaderBytes + kRoleManifestBytes] =
        static_cast<unsigned char>(Role::Ancestry);
    ok &= check(receive_fails(old_root_ancestry, fds, CmsgShape::Exact, old_root_ancestry.size()),
                "old bundle Ancestry Root slot rejected");

    RoleBundle dead_dropped;
    ok &= check(open_role(child, Role::Dropped, dead_dropped, error),
                "open owned child dropped evidence before death");
    ok &= check(kill(child, SIGKILL) == 0, "kill owned child for dead evidence");
    siginfo_t dead_info{};
    int waitid_result;
    do {
        waitid_result = waitid(P_PID, child, &dead_info, WEXITED | WNOWAIT);
    } while (waitid_result < 0 && errno == EINTR);
    DroppedIdentityEvidence dead_evidence;
    ok &= check(waitid_result == 0 && dead_info.si_pid == child &&
                    !extract_dropped_identity_evidence(dead_dropped, dead_evidence, error),
                "zombie dropped stat/pidfd evidence rejected");
    int dead_status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &dead_status, 0);
    } while (waited < 0 && errno == EINTR);
    ok &= check(
        waited == child && !extract_dropped_identity_evidence(dead_dropped, dead_evidence, error),
        "reaped dropped stat/pidfd evidence rejected");
    dead_dropped.close();

    bundle.close();
    return ok ? 0 : 1;
}
