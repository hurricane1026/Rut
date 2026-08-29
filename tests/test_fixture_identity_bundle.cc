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

}  // namespace

int main() {
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
    bool ok = check(wire.size() == kWireBytes && kPayloadBytes != 0, "fixed nonempty payload");

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

    bundle.close();
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    return ok ? 0 : 1;
}
