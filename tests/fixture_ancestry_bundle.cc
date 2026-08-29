#include "fixture_ancestry_bundle.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut::test::fixture_ancestry_bundle {
namespace {

void put16(std::vector<unsigned char>& out, u16 value) {
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void put32(std::vector<unsigned char>& out, u32 value) {
    for (unsigned shift = 0; shift != 32; shift += 8)
        out.push_back(static_cast<unsigned char>(value >> shift));
}

bool get16(const unsigned char* data, size_t size, size_t& at, u16& value) {
    if (at > size || size - at < 2) return false;
    value = static_cast<u16>(data[at]) | static_cast<u16>(data[at + 1] << 8);
    at += 2;
    return true;
}

bool get32(const unsigned char* data, size_t size, size_t& at, u32& value) {
    if (at > size || size - at < 4) return false;
    value = static_cast<u32>(data[at]) | (static_cast<u32>(data[at + 1]) << 8) |
            (static_cast<u32>(data[at + 2]) << 16) | (static_cast<u32>(data[at + 3]) << 24);
    at += 4;
    return true;
}

bool wait_fd(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        if (left <= 0 || left > std::numeric_limits<int>::max()) return false;
        pollfd descriptor{fd, events, 0};
        const int result = poll(&descriptor, 1, static_cast<int>(left));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return false;
        return (descriptor.revents & events) != 0;
    }
}

bool send_plain(int fd,
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

bool parse_header(const std::array<unsigned char, kHeaderBytes>& wire,
                  size_t& node_count,
                  size_t& fd_count) {
    size_t at = 0;
    u32 magic = 0;
    u16 version = 0;
    u16 type = 0;
    u16 nodes = 0;
    u16 fds = 0;
    u16 flags = 0;
    u16 reserved = 0;
    if (!get32(wire.data(), wire.size(), at, magic) ||
        !get16(wire.data(), wire.size(), at, version) ||
        !get16(wire.data(), wire.size(), at, type) || !get16(wire.data(), wire.size(), at, nodes) ||
        !get16(wire.data(), wire.size(), at, fds) || !get16(wire.data(), wire.size(), at, flags) ||
        !get16(wire.data(), wire.size(), at, reserved) || at != wire.size() || magic != kMagic ||
        version != kVersion || type != kType || flags != kAnchorLast || reserved != 0 ||
        nodes == 0 || nodes > kMaxNodes || fds != static_cast<u16>(nodes * kFdsPerNode) ||
        fds > kMaxFdCount)
        return false;
    node_count = nodes;
    fd_count = fds;
    return true;
}

void close_raw(std::array<int, kMaxFdCount>& fds) {
    for (int& fd : fds) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
}

void close_rights(const msghdr& message) {
    msghdr copy = message;
    for (cmsghdr* header = CMSG_FIRSTHDR(&copy); header != nullptr;
         header = CMSG_NXTHDR(&copy, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0) || header->cmsg_len > message.msg_controllen)
            continue;
        const size_t bytes = header->cmsg_len - CMSG_LEN(0);
        const int* values = reinterpret_cast<const int*>(CMSG_DATA(header));
        for (size_t index = 0; index != bytes / sizeof(int); ++index)
            if (values[index] >= 0) close(values[index]);
    }
}

bool receive_fragment(int fd,
                      unsigned char* data,
                      size_t size,
                      std::chrono::steady_clock::time_point deadline,
                      std::array<int, kMaxFdCount>& rights,
                      size_t& rights_count,
                      bool expect_rights,
                      ssize_t& count) {
    if (!wait_fd(fd, POLLIN, deadline)) return false;
    alignas(cmsghdr)
        std::array<unsigned char,
                   CMSG_SPACE((kMaxFdCount + 1) * sizeof(int)) + CMSG_SPACE(sizeof(ucred))>
            control{};
    iovec vector{data, size};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    do {
        count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count <= 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        close_rights(message);
        return false;
    }
    cmsghdr* only = CMSG_FIRSTHDR(&message);
    if (!expect_rights) {
        if (only != nullptr) {
            close_rights(message);
            return false;
        }
        return true;
    }
    if (only == nullptr || CMSG_NXTHDR(&message, only) != nullptr ||
        only->cmsg_level != SOL_SOCKET || only->cmsg_type != SCM_RIGHTS ||
        only->cmsg_len < CMSG_LEN(0) || only->cmsg_len > message.msg_controllen) {
        close_rights(message);
        return false;
    }
    const size_t bytes = only->cmsg_len - CMSG_LEN(0);
    if (bytes == 0 || bytes % sizeof(int) != 0 || bytes / sizeof(int) > kMaxFdCount) {
        close_rights(message);
        return false;
    }
    rights_count = bytes / sizeof(int);
    const int* values = reinterpret_cast<const int*>(CMSG_DATA(only));
    for (size_t index = 0; index != rights_count; ++index) {
        if (values[index] < 0) {
            close_rights(message);
            return false;
        }
        rights[index] = values[index];
    }
    return true;
}

bool no_trailing_data(int fd, std::string& error) {
    pollfd descriptor{fd, POLLIN, 0};
    int result;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        error = "ancestry trailing-data poll failed";
        return false;
    }
    if (result == 0 || (descriptor.revents & POLLIN) == 0) return true;
    unsigned char byte = 0;
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(sizeof(int))> control{};
    iovec vector{&byte, 1};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count;
    do {
        count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    } while (count < 0 && errno == EINTR);
    if (count > 0 || CMSG_FIRSTHDR(&message) != nullptr) {
        close_rights(message);
        error = "ancestry record had trailing data or ancillary";
        return false;
    }
    if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        error = "ancestry trailing-data receive failed";
        return false;
    }
    return true;
}

}  // namespace

void AncestryBundle::close() {
    for (identity::RoleBundle& node : nodes) node.close();
    nodes.clear();
}

std::vector<unsigned char> encode_header(size_t node_count) {
    std::vector<unsigned char> output;
    output.reserve(kHeaderBytes);
    put32(output, kMagic);
    put16(output, kVersion);
    put16(output, kType);
    put16(output, static_cast<u16>(node_count));
    put16(output, static_cast<u16>(node_count * kFdsPerNode));
    put16(output, kAnchorLast);
    put16(output, 0);
    return output;
}

bool extract_evidence(const AncestryBundle& bundle,
                      std::vector<identity::ProcessIdentityEvidence>& evidence,
                      std::string& error) {
    evidence.clear();
    if (bundle.nodes.empty() || bundle.nodes.size() > kMaxNodes) {
        error = "ancestry node count was out of bounds";
        return false;
    }
    evidence.reserve(bundle.nodes.size());
    for (const identity::RoleBundle& node : bundle.nodes) {
        identity::ProcessIdentityEvidence item;
        if (!identity::extract_process_identity_evidence(
                node, identity::Role::Ancestry, item, error)) {
            evidence.clear();
            return false;
        }
        for (const auto& previous : evidence)
            if (previous.identity.pid == item.identity.pid) {
                error = "ancestry record duplicated a process PID";
                evidence.clear();
                return false;
            }
        evidence.push_back(std::move(item));
    }
    error.clear();
    return true;
}

bool validate_bundle(const AncestryBundle& bundle, std::string& error) {
    std::vector<identity::ProcessIdentityEvidence> ignored;
    if (!extract_evidence(bundle, ignored, error)) return false;
    std::array<int, kMaxFdCount> raw{};
    raw.fill(-1);
    size_t count = 0;
    for (const identity::RoleBundle& node : bundle.nodes)
        for (const int fd : node.fds) {
            for (size_t previous = 0; previous != count; ++previous)
                if (raw[previous] == fd) {
                    error = "ancestry source reused a raw FD";
                    return false;
                }
            raw[count++] = fd;
        }
    return true;
}

bool send_bundle(int fd,
                 const AncestryBundle& bundle,
                 std::chrono::steady_clock::time_point deadline) {
    std::string error;
    if (fd < 0 || !validate_bundle(bundle, error)) return false;
    const std::vector<unsigned char> wire = encode_header(bundle.nodes.size());
    std::array<int, kMaxFdCount> rights{};
    rights.fill(-1);
    size_t count = 0;
    for (const identity::RoleBundle& node : bundle.nodes)
        for (const int node_fd : node.fds) rights[count++] = node_fd;
    alignas(cmsghdr) std::array<unsigned char, CMSG_SPACE(kMaxFdCount * sizeof(int))> control{};
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
    memcpy(CMSG_DATA(header), rights.data(), count * sizeof(int));
    if (!wait_fd(fd, POLLOUT, deadline)) return false;
    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent <= 0 || static_cast<size_t>(sent) > wire.size()) return false;
    return send_plain(fd, wire.data() + sent, wire.size() - static_cast<size_t>(sent), deadline);
}

bool receive_bundle(int fd,
                    AncestryBundle& bundle,
                    std::chrono::steady_clock::time_point deadline,
                    std::string& error) {
    bundle.close();
    error.clear();
    std::array<unsigned char, kHeaderBytes> wire{};
    std::array<int, kMaxFdCount> raw{};
    raw.fill(-1);
    size_t rights_count = 0;
    ssize_t received = 0;
    if (fd < 0 || !receive_fragment(
                      fd, wire.data(), wire.size(), deadline, raw, rights_count, true, received)) {
        close_raw(raw);
        error = "ancestry header/rights receive failed";
        return false;
    }
    size_t offset = static_cast<size_t>(received);
    while (offset != wire.size()) {
        if (!receive_fragment(fd,
                              wire.data() + offset,
                              wire.size() - offset,
                              deadline,
                              raw,
                              rights_count,
                              false,
                              received)) {
            close_raw(raw);
            error = "ancestry fragmented header receive failed";
            return false;
        }
        offset += static_cast<size_t>(received);
    }
    size_t node_count = 0;
    size_t fd_count = 0;
    if (!parse_header(wire, node_count, fd_count) || rights_count != fd_count) {
        close_raw(raw);
        error = "ancestry header or exact FD count was invalid";
        return false;
    }
    for (size_t left = 0; left != rights_count; ++left)
        for (size_t right = left + 1; right != rights_count; ++right)
            if (raw[left] == raw[right]) {
                close_raw(raw);
                error = "ancestry receiver observed a duplicate raw FD";
                return false;
            }
    if (!no_trailing_data(fd, error)) {
        close_raw(raw);
        return false;
    }
    bundle.nodes.reserve(node_count);
    for (size_t node = 0; node != node_count; ++node) {
        std::array<int, identity::kFdsPerRole> node_fds{};
        node_fds.fill(-1);
        for (size_t slot = 0; slot != node_fds.size(); ++slot) {
            node_fds[slot] = raw[node * node_fds.size() + slot];
            raw[node * node_fds.size() + slot] = -1;
        }
        identity::RoleBundle adopted;
        if (!identity::adopt_role(identity::Role::Ancestry, node_fds, adopted, error)) {
            close_raw(raw);
            bundle.close();
            return false;
        }
        bundle.nodes.push_back(std::move(adopted));
    }
    close_raw(raw);
    if (!validate_bundle(bundle, error)) {
        bundle.close();
        return false;
    }
    return true;
}

}  // namespace rut::test::fixture_ancestry_bundle
