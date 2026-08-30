#include "fixture_ancestry_bundle.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ancestry = rut::test::fixture_ancestry_bundle;
namespace identity = rut::test::fixture_identity_bundle;

namespace {

enum class CmsgShape { Exact, Missing, Short, Long, Credentials };

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

size_t fd_count() {
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return 0;
    size_t count = 0;
    while (readdir(directory) != nullptr) ++count;
    closedir(directory);
    return count;
}

struct Children {
    std::vector<pid_t> pids;

    ~Children() {
        for (pid_t pid : pids)
            if (pid > 1) (void)kill(pid, SIGKILL);
        for (pid_t pid : pids) {
            int status = 0;
            pid_t waited;
            do {
                waited = waitpid(pid, &status, 0);
            } while (waited < 0 && errno == EINTR);
        }
    }
};

bool spawn_children(size_t count, Children& children) {
    const pid_t parent = getpid();
    for (size_t index = 0; index != count; ++index) {
        const pid_t child = fork();
        if (child < 0) return false;
        if (child == 0) {
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(125);
            for (;;) pause();
        }
        children.pids.push_back(child);
    }
    return true;
}

bool open_bundle(const std::vector<pid_t>& pids, ancestry::AncestryBundle& bundle) {
    bundle.close();
    std::string error;
    for (pid_t pid : pids) {
        identity::RoleBundle node;
        if (!identity::open_role(pid, identity::Role::Ancestry, node, error)) return false;
        bundle.nodes.push_back(std::move(node));
    }
    return ancestry::validate_bundle(bundle, error);
}

std::vector<int> flatten(const ancestry::AncestryBundle& bundle) {
    std::vector<int> result;
    for (const auto& node : bundle.nodes)
        result.insert(result.end(), node.fds.begin(), node.fds.end());
    return result;
}

bool send_plain(int fd, const unsigned char* data, size_t size) {
    size_t offset = 0;
    while (offset != size) {
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

bool send_raw(int fd,
              const std::vector<unsigned char>& wire,
              const std::vector<int>& source,
              CmsgShape shape,
              size_t first_bytes,
              bool complete = true,
              bool trailing = false,
              bool rights_on_rest = false) {
    if (first_bytes > wire.size() || source.empty()) return false;
    size_t rights_count = source.size();
    if (shape == CmsgShape::Short) --rights_count;
    if (shape == CmsgShape::Long) ++rights_count;
    std::vector<int> rights = source;
    rights.push_back(source.front());
    alignas(cmsghdr) std::array<unsigned char,
                                CMSG_SPACE((ancestry::kMaxFdCount + 1) * sizeof(int)) +
                                    CMSG_SPACE(sizeof(ucred))>
        control{};
    iovec vector{const_cast<unsigned char*>(wire.data()), first_bytes};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (shape != CmsgShape::Missing) {
        message.msg_control = control.data();
        message.msg_controllen = CMSG_SPACE(rights_count * sizeof(int));
        if (shape == CmsgShape::Credentials) message.msg_controllen += CMSG_SPACE(sizeof(ucred));
        cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(rights_count * sizeof(int));
        memcpy(CMSG_DATA(header), rights.data(), rights_count * sizeof(int));
        if (shape == CmsgShape::Credentials) {
            cmsghdr* credentials = CMSG_NXTHDR(&message, header);
            if (credentials == nullptr) return false;
            const ucred value{getpid(), getuid(), getgid()};
            credentials->cmsg_level = SOL_SOCKET;
            credentials->cmsg_type = SCM_CREDENTIALS;
            credentials->cmsg_len = CMSG_LEN(sizeof(value));
            memcpy(CMSG_DATA(credentials), &value, sizeof(value));
        }
    }
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0 || static_cast<size_t>(sent) > first_bytes) return false;
    if (static_cast<size_t>(sent) != first_bytes &&
        !send_plain(fd, wire.data() + sent, first_bytes - static_cast<size_t>(sent)))
        return false;
    if (complete && first_bytes != wire.size()) {
        const size_t rest = wire.size() - first_bytes;
        if (rights_on_rest) {
            alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> rest_control{};
            iovec rest_vector{const_cast<unsigned char*>(wire.data() + first_bytes), rest};
            msghdr rest_message{};
            rest_message.msg_iov = &rest_vector;
            rest_message.msg_iovlen = 1;
            rest_message.msg_control = rest_control.data();
            rest_message.msg_controllen = rest_control.size();
            cmsghdr* header = CMSG_FIRSTHDR(&rest_message);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(header), &source.front(), sizeof(int));
            do {
                sent = sendmsg(fd, &rest_message, MSG_NOSIGNAL);
            } while (sent < 0 && errno == EINTR);
            if (sent < 0 || static_cast<size_t>(sent) > rest) return false;
            if (static_cast<size_t>(sent) != rest &&
                !send_plain(fd, wire.data() + first_bytes + sent, rest - static_cast<size_t>(sent)))
                return false;
        } else if (!send_plain(fd, wire.data() + first_bytes, rest)) {
            return false;
        }
    }
    if (trailing) {
        const unsigned char byte = 0xee;
        if (!send_plain(fd, &byte, 1)) return false;
    }
    return true;
}

bool receive_fails(const std::vector<unsigned char>& wire,
                   const std::vector<int>& fds,
                   CmsgShape shape,
                   size_t first_bytes,
                   bool complete = true,
                   bool trailing = false,
                   bool rights_on_rest = false) {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    if (shape == CmsgShape::Credentials) {
        int enabled = 1;
        if (setsockopt(sockets[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) {
            close(sockets[0]);
            close(sockets[1]);
            return false;
        }
    }
    const size_t before = fd_count();
    const bool sent =
        send_raw(sockets[0], wire, fds, shape, first_bytes, complete, trailing, rights_on_rest);
    const int send_error = errno;
    shutdown(sockets[0], SHUT_WR);
    ancestry::AncestryBundle received;
    std::string error;
    const bool accepted =
        ancestry::receive_bundle(sockets[1],
                                 received,
                                 std::chrono::steady_clock::now() + std::chrono::milliseconds(100),
                                 error);
    received.close();
    const bool no_leak = fd_count() == before;
    close(sockets[0]);
    close(sockets[1]);
    if (!sent && shape == CmsgShape::Credentials && send_error == EINVAL) return true;
    return sent && !accepted && no_leak;
}

bool round_trip(ancestry::AncestryBundle& source,
                ancestry::AncestryBundle& received,
                std::string& error) {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ancestry::kTransportTimeoutMs);
    const bool result = ancestry::send_bundle(sockets[0], source, deadline) &&
                        ancestry::receive_bundle(sockets[1], received, deadline, error);
    close(sockets[0]);
    close(sockets[1]);
    return result;
}

void mutate16(std::vector<unsigned char>& wire, size_t at, std::uint16_t value) {
    wire[at] = static_cast<unsigned char>(value);
    wire[at + 1] = static_cast<unsigned char>(value >> 8);
}

}  // namespace

int main() {
    const size_t baseline_fds = fd_count();
    bool ok = true;
    Children children;
    ok &= check(spawn_children(8, children), "spawn eight owned live nodes");

    ancestry::AncestryBundle one;
    ok &= check(open_bundle({getpid()}, one), "open N=1 live self ancestry source");
    ancestry::AncestryBundle received_one;
    std::string error;
    ok &= check(round_trip(one, received_one, error), "N=1 ancestry round trip");
    std::vector<identity::ProcessIdentityEvidence> one_evidence;
    ok &= check(ancestry::extract_evidence(received_one, one_evidence, error) &&
                    one_evidence.size() == 1 && one_evidence[0].identity.pid == getpid() &&
                    one_evidence[0].pidfd_live && !one_evidence[0].cmdline.empty() &&
                    one_evidence[0].status.cap_inh_clear == (one_evidence[0].status.cap_inh == 0) &&
                    one_evidence[0].status.cap_prm_clear == (one_evidence[0].status.cap_prm == 0) &&
                    one_evidence[0].status.cap_eff_clear == (one_evidence[0].status.cap_eff == 0),
                "strict stable self evidence and raw capability values");
    for (const auto& node : received_one.nodes)
        for (int fd : node.fds)
            ok &= check((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "receiver FD is CLOEXEC");

    ancestry::AncestryBundle two;
    ok &= check(open_bundle({children.pids[0], children.pids[1]}, two),
                "open N=2 distinct ordered nodes");
    ancestry::AncestryBundle received_two;
    ok &= check(round_trip(two, received_two, error) && received_two.nodes.size() == 2 &&
                    received_two.nodes[0].manifest.pid == children.pids[0] &&
                    received_two.nodes[1].manifest.pid == children.pids[1],
                "N=2 nearest-first order preserved");

    ancestry::AncestryBundle maximum;
    ok &= check(open_bundle(children.pids, maximum), "open N=8 max ancestry source");
    ancestry::AncestryBundle received_maximum;
    ok &= check(round_trip(maximum, received_maximum, error) &&
                    received_maximum.nodes.size() == ancestry::kMaxNodes,
                "N=8 maximum boundary round trip");

    const std::vector<int> one_fds = flatten(one);
    const std::vector<unsigned char> valid = ancestry::encode_header(1);
    const auto malformed = [&](size_t at, std::uint16_t value) {
        std::vector<unsigned char> wire = valid;
        mutate16(wire, at, value);
        return receive_fails(wire, one_fds, CmsgShape::Exact, wire.size());
    };
    std::vector<unsigned char> bad_magic = valid;
    bad_magic[0] ^= 1;
    ok &= check(receive_fails(bad_magic, one_fds, CmsgShape::Exact, bad_magic.size()),
                "wrong ANC1 magic rejected");
    ok &= check(malformed(4, ancestry::kVersion + 1), "wrong ANC1 version rejected");
    ok &= check(malformed(6, ancestry::kType + 1), "wrong ANC1 type rejected");
    ok &= check(malformed(8, 0), "zero node count rejected");
    ok &= check(malformed(8, ancestry::kMaxNodes + 1), "oversize node count rejected");
    ok &= check(malformed(10, 5), "wrong ancestry FD count rejected");
    ok &= check(malformed(12, 0), "missing anchor-last flag rejected");
    ok &= check(malformed(12, ancestry::kAnchorLast + 1), "unknown ancestry flag rejected");
    ok &= check(malformed(14, 1), "nonzero ancestry reserved field rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Missing, valid.size()),
                "missing ancillary rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Short, valid.size()),
                "short ancillary rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Long, valid.size()),
                "long ancillary rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Credentials, valid.size()),
                "extra credentials ancillary rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Exact, 3, false),
                "truncated header deadline/EOF rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Exact, valid.size(), true, true),
                "queued trailing byte rejected");
    ok &= check(receive_fails(valid, one_fds, CmsgShape::Exact, 3, true, false, true),
                "ancillary on later fragment rejected");

    int fragment_sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fragment_sockets) == 0,
                "fragment socketpair");
    ok &= check(send_raw(fragment_sockets[0], valid, one_fds, CmsgShape::Exact, 3),
                "fragmented ANC1 raw send");
    ancestry::AncestryBundle fragmented;
    ok &= check(
        ancestry::receive_bundle(fragment_sockets[1],
                                 fragmented,
                                 std::chrono::steady_clock::now() + std::chrono::milliseconds(250),
                                 error),
        "fragmented ANC1 receive");
    fragmented.close();
    close(fragment_sockets[0]);
    close(fragment_sockets[1]);

    std::vector<int> reordered = one_fds;
    std::swap(reordered[0], reordered[1]);
    ok &= check(receive_fails(valid, reordered, CmsgShape::Exact, valid.size()),
                "reordered stat/status slots rejected");
    const int foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
    std::vector<int> foreign_fds = one_fds;
    foreign_fds[0] = foreign;
    ok &= check(foreign >= 0 && receive_fails(valid, foreign_fds, CmsgShape::Exact, valid.size()),
                "foreign proc FD rejected");
    close(foreign);

    const int saved = one.nodes[0].fds[1];
    one.nodes[0].fds[1] = one.nodes[0].fds[0];
    ok &= check(!ancestry::validate_bundle(one, error), "duplicate source raw FD rejected");
    one.nodes[0].fds[1] = saved;

    ancestry::AncestryBundle duplicate_pid;
    ok &= check(open_bundle({children.pids[2], children.pids[2]}, duplicate_pid) == false,
                "duplicate PID source rejected");
    identity::RoleBundle duplicate_first;
    identity::RoleBundle duplicate_second;
    ok &= check(
        identity::open_role(children.pids[2], identity::Role::Ancestry, duplicate_first, error) &&
            identity::open_role(
                children.pids[2], identity::Role::Ancestry, duplicate_second, error),
        "duplicate PID raw receiver setup");
    ancestry::AncestryBundle duplicate_raw_bundle;
    duplicate_raw_bundle.nodes.push_back(std::move(duplicate_first));
    duplicate_raw_bundle.nodes.push_back(std::move(duplicate_second));
    const std::vector<int> duplicate_pid_fds = flatten(duplicate_raw_bundle);
    const std::vector<unsigned char> duplicate_header = ancestry::encode_header(2);
    ok &= check(receive_fails(
                    duplicate_header, duplicate_pid_fds, CmsgShape::Exact, duplicate_header.size()),
                "receiver duplicate PID records rejected");

    identity::RoleBundle dead_node;
    ok &= check(identity::open_role(children.pids[3], identity::Role::Ancestry, dead_node, error),
                "open node before zombie transition");
    ok &= check(kill(children.pids[3], SIGKILL) == 0, "kill owned ancestry node");
    siginfo_t dead_info{};
    int waited_result;
    do {
        waited_result = waitid(P_PID, children.pids[3], &dead_info, WEXITED | WNOWAIT);
    } while (waited_result < 0 && errno == EINTR);
    ancestry::AncestryBundle dead_bundle;
    dead_bundle.nodes.push_back(std::move(dead_node));
    const std::vector<int> dead_fds = flatten(dead_bundle);
    ok &= check(waited_result == 0 && dead_info.si_pid == children.pids[3] &&
                    receive_fails(valid, dead_fds, CmsgShape::Exact, valid.size()),
                "dead/zombie ancestry evidence rejected");
    int dead_status = 0;
    pid_t reaped;
    do {
        reaped = waitpid(children.pids[3], &dead_status, 0);
    } while (reaped < 0 && errno == EINTR);
    ok &= check(reaped == children.pids[3], "owned dead ancestry node reaped");
    children.pids[3] = -1;

    int empty_sockets[2] = {-1, -1};
    ok &= check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, empty_sockets) == 0,
                "deadline/EOF socketpair");
    ancestry::AncestryBundle empty_received;
    ok &= check(
        !ancestry::receive_bundle(empty_sockets[1],
                                  empty_received,
                                  std::chrono::steady_clock::now() + std::chrono::milliseconds(20),
                                  error),
        "empty receive deadline rejected");
    shutdown(empty_sockets[0], SHUT_WR);
    ok &= check(
        !ancestry::receive_bundle(empty_sockets[1],
                                  empty_received,
                                  std::chrono::steady_clock::now() + std::chrono::milliseconds(20),
                                  error),
        "empty receive EOF rejected");
    close(empty_sockets[0]);
    close(empty_sockets[1]);

    std::array<int, identity::kFdsPerRole> source_snapshot = one.nodes[0].fds;
    one.close();
    bool source_closed = true;
    for (int fd : source_snapshot) {
        errno = 0;
        source_closed = source_closed && fcntl(fd, F_GETFD) < 0 && errno == EBADF;
    }
    std::vector<identity::ProcessIdentityEvidence> retained_evidence;
    ok &=
        check(source_closed && ancestry::extract_evidence(received_one, retained_evidence, error) &&
                  retained_evidence.size() == 1,
              "source close is immediate and receiver evidence remains owned");

    received_one.close();
    two.close();
    received_two.close();
    maximum.close();
    received_maximum.close();
    duplicate_pid.close();
    duplicate_raw_bundle.close();
    dead_bundle.close();
    empty_received.close();
    ok &= check(fd_count() == baseline_fds, "ancestry test returned to exact FD baseline");
    return ok ? 0 : 1;
}
