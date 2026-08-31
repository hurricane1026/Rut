#include "fixture_exact_tcp_reservation_lease.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <limits>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut::test::fixture_exact_tcp_reservation_lease {
namespace {

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number = 0) {
    diagnostic = {phase, error_number == 0 ? EINVAL : error_number};
}

FdIdentity identity_from(int descriptor, const char* name, int proc_fd, int& error_number) {
    FdIdentity identity;
    struct stat status{};
    errno = 0;
    if (fstat(descriptor, &status) != 0) {
        error_number = errno == 0 ? EIO : errno;
        return {};
    }
    std::array<char, 512> link{};
    errno = 0;
    const ssize_t size = readlinkat(proc_fd, name, link.data(), link.size());
    if (size < 0 || static_cast<std::size_t>(size) == link.size()) {
        error_number = size < 0 && errno != 0 ? errno : ENAMETOOLONG;
        return {};
    }
    identity.device = static_cast<std::uint64_t>(status.st_dev);
    identity.inode = static_cast<std::uint64_t>(status.st_ino);
    identity.mode = static_cast<std::uint64_t>(status.st_mode);
    identity.rdevice = static_cast<std::uint64_t>(status.st_rdev);
    identity.proc_link.assign(link.data(), static_cast<std::size_t>(size));
    error_number = 0;
    return identity;
}

bool take_snapshot(FdSnapshot& snapshot, int& error_number) {
    snapshot.clear();
    errno = 0;
    DIR* stream = opendir("/proc/self/fd");
    if (stream == nullptr) {
        error_number = errno == 0 ? EIO : errno;
        return false;
    }
    const int proc_fd = dirfd(stream);
    bool valid = proc_fd >= 0;
    int failure = valid ? 0 : (errno == 0 ? EIO : errno);
    errno = 0;
    while (valid) {
        dirent* const entry = readdir(stream);
        if (entry == nullptr) {
            if (errno != 0) {
                valid = false;
                failure = errno;
            }
            break;
        }
        int descriptor = -1;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::strlen(begin);
        const auto parsed = std::from_chars(begin, end, descriptor);
        if (parsed.ec != std::errc{} || parsed.ptr != end || descriptor < 0 ||
            descriptor == proc_fd)
            continue;
        int identity_error = 0;
        FdIdentity identity = identity_from(descriptor, entry->d_name, proc_fd, identity_error);
        if (identity_error != 0 || !snapshot.emplace(descriptor, std::move(identity)).second) {
            valid = false;
            failure = identity_error == 0 ? EINVAL : identity_error;
        }
        errno = 0;
    }
    errno = 0;
    if (closedir(stream) != 0 && valid) {
        valid = false;
        failure = errno == 0 ? EIO : errno;
    }
    if (!valid) snapshot.clear();
    error_number = failure;
    return valid;
}

bool is_socket_identity(const FdIdentity& identity) {
    return (identity.mode & S_IFMT) == S_IFSOCK && identity.inode != 0u &&
           identity.proc_link == "socket:[" + std::to_string(identity.inode) + "]";
}

bool get_integer_option(int descriptor, int level, int option, int expected, int& error_number) {
    int value = -1;
    socklen_t size = sizeof(value);
    errno = 0;
    if (getsockopt(descriptor, level, option, &value, &size) != 0) {
        error_number = errno == 0 ? EIO : errno;
        return false;
    }
    if (size != sizeof(value) || value != expected) {
        error_number = EINVAL;
        return false;
    }
    error_number = 0;
    return true;
}

bool set_zero_option(int descriptor, int option, int& error_number) {
    constexpr int zero = 0;
    errno = 0;
    if (setsockopt(descriptor, SOL_SOCKET, option, &zero, sizeof(zero)) != 0) {
        error_number = errno == 0 ? EIO : errno;
        return false;
    }
    return get_integer_option(descriptor, SOL_SOCKET, option, zero, error_number);
}

}  // namespace

bool eligible_ipv4(std::uint32_t address, unsigned interface_flags) {
    const std::uint32_t first_octet = address >> 24u;
    return (interface_flags & IFF_UP) != 0u && (interface_flags & IFF_LOOPBACK) == 0u &&
           address != INADDR_ANY && address != INADDR_BROADCAST && first_octet != 127u &&
           !(first_octet >= 224u && first_octet <= 239u);
}

bool discover_eligible_ipv4(std::vector<std::uint32_t>& addresses, Diagnostic& diagnostic) {
    addresses.clear();
    diagnostic = {};
    ifaddrs* list = nullptr;
    errno = 0;
    if (getifaddrs(&list) != 0) {
        fail(diagnostic, FailurePhase::Discovery, errno == 0 ? EIO : errno);
        return false;
    }
    bool valid = true;
    for (const ifaddrs* item = list; item != nullptr; item = item->ifa_next) {
        if (item->ifa_addr == nullptr || item->ifa_addr->sa_family != AF_INET) continue;
        const auto* const address = reinterpret_cast<const sockaddr_in*>(item->ifa_addr);
        const std::uint32_t host = ntohl(address->sin_addr.s_addr);
        if (eligible_ipv4(host, item->ifa_flags)) addresses.push_back(host);
    }
    freeifaddrs(list);
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
    if (addresses.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        addresses.clear();
        fail(diagnostic, FailurePhase::Discovery, EOVERFLOW);
        valid = false;
    }
    return valid;
}

ExactTcpReservationLease::ExactTcpReservationLease()
    : receipt_(std::make_shared<ReleaseReceipt>()) {}

ExactTcpReservationLease::~ExactTcpReservationLease() {
    if (state_ == State::Held) {
        Diagnostic diagnostic;
        if (!release_impl(true, diagnostic) && state_ == State::BindingLost)
            record_unresolved_destructor(binding_loss_diagnostic_);
    } else if (state_ == State::BindingLost) {
        record_unresolved_destructor(binding_loss_diagnostic_);
    }
}

bool ExactTcpReservationLease::reserve(std::uint32_t host_order_ipv4,
                                       ExactTcpReservationLease& lease,
                                       Diagnostic& diagnostic) {
    return reserve_impl(host_order_ipv4, nullptr, lease, diagnostic);
}

bool ExactTcpReservationLease::reserve_with_hooks_for_testing(std::uint32_t host_order_ipv4,
                                                              const HooksForTesting& hooks,
                                                              ExactTcpReservationLease& lease,
                                                              Diagnostic& diagnostic) {
    return reserve_impl(host_order_ipv4, &hooks, lease, diagnostic);
}

bool ExactTcpReservationLease::reserve_impl(std::uint32_t host_order_ipv4,
                                            const HooksForTesting* hooks,
                                            ExactTcpReservationLease& lease,
                                            Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.state_ != State::Fresh || lease.descriptor_ >= 0 ||
        !eligible_ipv4(host_order_ipv4, IFF_UP)) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    int snapshot_error = 0;
    if (!take_snapshot(lease.baseline_, snapshot_error)) {
        fail(diagnostic, FailurePhase::Snapshot, snapshot_error);
        return false;
    }
    lease.hooks_ = hooks == nullptr ? HooksForTesting{} : *hooks;
    lease.ipv4_ = host_order_ipv4;
    lease.receipt_ = std::make_shared<ReleaseReceipt>();

    errno = 0;
    lease.descriptor_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (lease.descriptor_ < 0) {
        fail(diagnostic, FailurePhase::Socket, errno == 0 ? EIO : errno);
        lease.baseline_.clear();
        lease.ipv4_ = 0u;
        return false;
    }
    lease.state_ = State::Held;
    auto abort_owned = [&](FailurePhase phase, int error_number) {
        const int owned = lease.descriptor_;
        lease.descriptor_ = -1;
        errno = 0;
        const int result = ::close(owned);
        lease.state_ = result == 0 ? State::Released : State::ReleaseUncertain;
        fail(diagnostic, phase, error_number);
        return false;
    };

    int option_error = 0;
    if (!set_zero_option(lease.descriptor_, SO_REUSEADDR, option_error) ||
        !set_zero_option(lease.descriptor_, SO_REUSEPORT, option_error))
        return abort_owned(FailurePhase::Option, option_error);

    sockaddr_in requested{};
    requested.sin_family = AF_INET;
    requested.sin_port = 0;
    requested.sin_addr.s_addr = htonl(host_order_ipv4);
    errno = 0;
    if (bind(lease.descriptor_, reinterpret_cast<const sockaddr*>(&requested), sizeof(requested)) !=
        0)
        return abort_owned(FailurePhase::Bind, errno == 0 ? EIO : errno);

    sockaddr_in observed{};
    socklen_t observed_size = sizeof(observed);
    errno = 0;
    if (getsockname(lease.descriptor_, reinterpret_cast<sockaddr*>(&observed), &observed_size) != 0)
        return abort_owned(FailurePhase::Address, errno == 0 ? EIO : errno);
    if (observed_size != sizeof(observed) || observed.sin_family != AF_INET ||
        ntohl(observed.sin_addr.s_addr) != host_order_ipv4 || observed.sin_port == 0)
        return abort_owned(FailurePhase::Address, EINVAL);
    lease.port_ = ntohs(observed.sin_port);

    struct stat status{};
    errno = 0;
    if (fstat(lease.descriptor_, &status) != 0)
        return abort_owned(FailurePhase::Identity, errno == 0 ? EIO : errno);
    lease.socket_identity_ = {static_cast<std::uint64_t>(status.st_dev),
                              static_cast<std::uint64_t>(status.st_ino),
                              static_cast<std::uint64_t>(status.st_mode),
                              static_cast<std::uint64_t>(status.st_rdev),
                              "socket:[" + std::to_string(status.st_ino) + "]"};
    if (!lease.validate_socket(diagnostic) || !lease.validate_held_inventory(diagnostic)) {
        const Diagnostic original = diagnostic;
        return abort_owned(original.phase, original.error_number);
    }
    diagnostic = {};
    return true;
}

bool ExactTcpReservationLease::validate_socket(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (descriptor_ < 0 || port_ == 0u || ipv4_ == 0u || !is_socket_identity(socket_identity_)) {
        fail(diagnostic, FailurePhase::Identity, EBADF);
        return false;
    }
    int error_number = 0;
    if (!get_integer_option(descriptor_, SOL_SOCKET, SO_REUSEADDR, 0, error_number) ||
        !get_integer_option(descriptor_, SOL_SOCKET, SO_REUSEPORT, 0, error_number) ||
        !get_integer_option(descriptor_, SOL_SOCKET, SO_ACCEPTCONN, 0, error_number) ||
        !get_integer_option(descriptor_, SOL_SOCKET, SO_TYPE, SOCK_STREAM, error_number) ||
        !get_integer_option(descriptor_, SOL_SOCKET, SO_DOMAIN, AF_INET, error_number) ||
        !get_integer_option(descriptor_, SOL_SOCKET, SO_PROTOCOL, IPPROTO_TCP, error_number)) {
        fail(diagnostic, FailurePhase::Option, error_number);
        return false;
    }
    errno = 0;
    const int descriptor_flags = fcntl(descriptor_, F_GETFD);
    if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) == 0) {
        fail(diagnostic,
             FailurePhase::Identity,
             descriptor_flags < 0 && errno != 0 ? errno : EINVAL);
        return false;
    }
    errno = 0;
    const int status_flags = fcntl(descriptor_, F_GETFL);
    if (status_flags < 0 || (status_flags & O_ACCMODE) != O_RDWR ||
        (status_flags & (O_NONBLOCK | O_APPEND | O_ASYNC)) != 0) {
        fail(diagnostic, FailurePhase::Identity, status_flags < 0 && errno != 0 ? errno : EINVAL);
        return false;
    }
    sockaddr_in observed{};
    socklen_t size = sizeof(observed);
    errno = 0;
    if (getsockname(descriptor_, reinterpret_cast<sockaddr*>(&observed), &size) != 0 ||
        size != sizeof(observed) || observed.sin_family != AF_INET ||
        ntohl(observed.sin_addr.s_addr) != ipv4_ || ntohs(observed.sin_port) != port_) {
        fail(diagnostic, FailurePhase::Address, errno == 0 ? EINVAL : errno);
        return false;
    }
    struct stat status{};
    errno = 0;
    if (fstat(descriptor_, &status) != 0 || !S_ISSOCK(status.st_mode) || status.st_ino == 0u ||
        static_cast<std::uint64_t>(status.st_dev) != socket_identity_.device ||
        static_cast<std::uint64_t>(status.st_ino) != socket_identity_.inode ||
        static_cast<std::uint64_t>(status.st_mode) != socket_identity_.mode ||
        static_cast<std::uint64_t>(status.st_rdev) != socket_identity_.rdevice) {
        fail(diagnostic, FailurePhase::Identity, errno == 0 ? ESTALE : errno);
        return false;
    }
    std::array<char, 512> path{};
    const int count = std::snprintf(path.data(), path.size(), "/proc/self/fd/%d", descriptor_);
    std::array<char, 512> link{};
    errno = 0;
    const ssize_t link_size = count > 0 && static_cast<std::size_t>(count) < path.size()
                                  ? readlink(path.data(), link.data(), link.size())
                                  : -1;
    if (link_size < 0 || static_cast<std::size_t>(link_size) == link.size() ||
        std::string(link.data(), static_cast<std::size_t>(link_size)) !=
            socket_identity_.proc_link) {
        fail(diagnostic, FailurePhase::Identity, errno == 0 ? ESTALE : errno);
        return false;
    }
    return true;
}

bool ExactTcpReservationLease::validate_held_inventory(Diagnostic& diagnostic) const {
    FdSnapshot observed;
    int error_number = 0;
    if (!take_snapshot(observed, error_number)) {
        fail(diagnostic, FailurePhase::Snapshot, error_number);
        return false;
    }
    FdSnapshot expected = baseline_;
    if (!expected.emplace(descriptor_, socket_identity_).second || observed != expected) {
        fail(diagnostic, FailurePhase::Inventory, ESTALE);
        return false;
    }
    const auto references = static_cast<unsigned>(
        std::count_if(observed.begin(), observed.end(), [&](const auto& item) {
            return is_socket_identity(item.second) && item.second.inode == socket_identity_.inode;
        }));
    if (references != 1u) {
        fail(diagnostic, FailurePhase::Inventory, EMLINK);
        return false;
    }
    return true;
}

bool ExactTcpReservationLease::revalidate(Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Held && state_ != State::BindingLost) {
        fail(diagnostic, FailurePhase::State, EALREADY);
        return false;
    }
    const State prior_state = state_;
    if (!validate_socket(diagnostic) || !validate_held_inventory(diagnostic)) {
        if (prior_state == State::Held) binding_loss_diagnostic_ = diagnostic;
        state_ = State::BindingLost;
        return false;
    }
    state_ = State::Held;
    binding_loss_diagnostic_ = {};
    return true;
}

bool ExactTcpReservationLease::release(Diagnostic& diagnostic) {
    if (state_ == State::Released || state_ == State::ReleaseUncertain) {
        fail(diagnostic, FailurePhase::State, EALREADY);
        return false;
    }
    return release_impl(false, diagnostic);
}

bool ExactTcpReservationLease::release_impl(bool destructor, Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Held && state_ != State::BindingLost) {
        fail(diagnostic, FailurePhase::State, state_ == State::Fresh ? EINVAL : EALREADY);
        return false;
    }
    if (!revalidate(diagnostic)) return false;

    const int owned = descriptor_;
    descriptor_ = -1;
    ReleaseReceipt next;
    next.attempted = true;
    next.destructor = destructor;
    next.real_close_attempts = 1u;

    errno = 0;
    next.real_close_result = ::close(owned);
    next.real_close_error = next.real_close_result == 0 ? 0 : (errno == 0 ? EIO : errno);
    if (next.real_close_result == 0) {
        if (hooks_.close_fault == CloseFaultForTesting::SynthesizeEintr)
            next.reported_close_error = EINTR;
        else if (hooks_.close_fault == CloseFaultForTesting::SynthesizeEio)
            next.reported_close_error = EIO;
    } else {
        next.reported_close_error = next.real_close_error;
    }

    errno = 0;
    next.immediate_fgetfd_result = fcntl(owned, F_GETFD);
    next.immediate_fgetfd_error = next.immediate_fgetfd_result < 0 ? errno : 0;
    next.immediate_ebadf =
        next.immediate_fgetfd_result == -1 && next.immediate_fgetfd_error == EBADF;

    if (next.immediate_ebadf && hooks_.after_immediate_ebadf != nullptr)
        hooks_.after_immediate_ebadf(hooks_.context);

    FdSnapshot observed;
    int snapshot_error = 0;
    next.post_inventory_checked = take_snapshot(observed, snapshot_error);
    if (next.post_inventory_checked) {
        next.baseline_restored = observed == baseline_;
        next.socket_inode_absent =
            std::none_of(observed.begin(), observed.end(), [&](const auto& item) {
                return is_socket_identity(item.second) &&
                       item.second.inode == socket_identity_.inode;
            });
    }

    const bool success = next.real_close_result == 0 && next.reported_close_error == 0 &&
                         next.immediate_ebadf && next.post_inventory_checked &&
                         next.baseline_restored && next.socket_inode_absent;
    state_ = success ? State::Released : State::ReleaseUncertain;
    next.state = state_;
    next.reportable_success = success && !destructor;
    if (!success) {
        if (next.reported_close_error != 0)
            fail(next.diagnostic, FailurePhase::Close, next.reported_close_error);
        else if (!next.immediate_ebadf)
            fail(next.diagnostic,
                 FailurePhase::PostClose,
                 next.immediate_fgetfd_error == 0 ? EBUSY : next.immediate_fgetfd_error);
        else if (!next.post_inventory_checked)
            fail(next.diagnostic, FailurePhase::Snapshot, snapshot_error);
        else
            fail(next.diagnostic, FailurePhase::PostClose, ESTALE);
        diagnostic = next.diagnostic;
    }
    *receipt_ = next;
    return success && !destructor;
}

void ExactTcpReservationLease::record_unresolved_destructor(const Diagnostic& diagnostic) {
    if (!receipt_) receipt_ = std::make_shared<ReleaseReceipt>();
    if (receipt_->attempted) return;
    receipt_->attempted = true;
    receipt_->destructor = true;
    receipt_->reportable_success = false;
    receipt_->state = state_;
    receipt_->diagnostic = diagnostic;
}

}  // namespace rut::test::fixture_exact_tcp_reservation_lease
