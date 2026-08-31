#include "fixture_exact_tcp_reservation_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace reservation = rut::test::fixture_exact_tcp_reservation_lease;
namespace {

using Snapshot = std::map<int, std::string>;

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

bool snapshot(Snapshot& result) {
    result.clear();
    DIR* stream = opendir("/proc/self/fd");
    if (stream == nullptr) return false;
    const int own = dirfd(stream);
    bool valid = own >= 0;
    errno = 0;
    while (valid) {
        dirent* entry = readdir(stream);
        if (entry == nullptr) {
            if (errno != 0) valid = false;
            break;
        }
        int fd = -1;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::strlen(begin);
        const auto parsed = std::from_chars(begin, end, fd);
        if (parsed.ec != std::errc{} || parsed.ptr != end || fd < 0 || fd == own) continue;
        struct stat status{};
        std::array<char, 512> link{};
        const ssize_t size = readlinkat(own, entry->d_name, link.data(), link.size());
        if (fstat(fd, &status) != 0 || size < 0 || static_cast<std::size_t>(size) == link.size()) {
            valid = false;
            break;
        }
        std::string identity = std::to_string(status.st_dev) + ":" + std::to_string(status.st_ino) +
                               ":" + std::to_string(status.st_mode) + ":" +
                               std::string(link.data(), static_cast<std::size_t>(size));
        if (!result.emplace(fd, std::move(identity)).second) valid = false;
        errno = 0;
    }
    const int read_error = errno;
    const bool closed = closedir(stream) == 0;
    if (!valid || read_error != 0 || !closed) result.clear();
    return valid && read_error == 0 && closed;
}

bool failed(const reservation::Diagnostic& diagnostic,
            reservation::FailurePhase phase,
            int error_number) {
    return diagnostic.phase == phase && diagnostic.error_number == error_number;
}

bool complete_release(const std::shared_ptr<const reservation::ReleaseReceipt>& receipt,
                      bool reportable,
                      bool destructor) {
    return receipt && receipt->attempted && receipt->destructor == destructor &&
           receipt->real_close_attempts == 1u && receipt->real_close_result == 0 &&
           receipt->real_close_error == 0 && receipt->reported_close_error == 0 &&
           receipt->immediate_fgetfd_result == -1 && receipt->immediate_fgetfd_error == EBADF &&
           receipt->immediate_ebadf && receipt->post_inventory_checked &&
           receipt->baseline_restored && receipt->socket_inode_absent &&
           receipt->reportable_success == reportable &&
           receipt->state == reservation::State::Released &&
           receipt->diagnostic.phase == reservation::FailurePhase::None;
}

bool same_receipt(const reservation::ReleaseReceipt& left,
                  const reservation::ReleaseReceipt& right) {
    return left.attempted == right.attempted && left.destructor == right.destructor &&
           left.real_close_attempts == right.real_close_attempts &&
           left.real_close_result == right.real_close_result &&
           left.real_close_error == right.real_close_error &&
           left.reported_close_error == right.reported_close_error &&
           left.immediate_fgetfd_result == right.immediate_fgetfd_result &&
           left.immediate_fgetfd_error == right.immediate_fgetfd_error &&
           left.immediate_ebadf == right.immediate_ebadf &&
           left.post_inventory_checked == right.post_inventory_checked &&
           left.baseline_restored == right.baseline_restored &&
           left.socket_inode_absent == right.socket_inode_absent &&
           left.reportable_success == right.reportable_success && left.state == right.state &&
           left.diagnostic.phase == right.diagnostic.phase &&
           left.diagnostic.error_number == right.diagnostic.error_number;
}

bool run_case(const char* name, const std::function<bool()>& body) {
    Snapshot before;
    Snapshot after;
    bool ok = check(snapshot(before), "case baseline snapshot");
    if (ok) ok = body();
    ok = check(snapshot(after) && before == after, "case exact FD identity residue") && ok;
    if (!ok) std::fprintf(stderr, "CASE FAILED: %s\n", name);
    return ok;
}

bool reserve(std::uint32_t address,
             reservation::ExactTcpReservationLease& lease,
             reservation::Diagnostic& diagnostic) {
    return reservation::ExactTcpReservationLease::reserve(address, lease, diagnostic);
}

bool wildcard_probe(std::uint16_t port, bool expect_collision) {
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0) return false;
    constexpr int one = 1;
    bool ok = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0 &&
              setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) == 0;
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    endpoint.sin_addr.s_addr = htonl(INADDR_ANY);
    errno = 0;
    const int result =
        ok ? bind(fd, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) : -1;
    const int bind_error = errno;
    ok = ok && (expect_collision ? result == -1 && bind_error == EADDRINUSE : result == 0);
    return close(fd) == 0 && ok;
}

bool filter_and_discovery_tests(const std::vector<std::uint32_t>& addresses) {
    const unsigned up = IFF_UP;
    const bool filters = reservation::eligible_ipv4(0x0a000001u, up) &&
                         !reservation::eligible_ipv4(0x0a000001u, 0u) &&
                         !reservation::eligible_ipv4(0x0a000001u, up | IFF_LOOPBACK) &&
                         !reservation::eligible_ipv4(INADDR_ANY, up) &&
                         !reservation::eligible_ipv4(0x7f000001u, up) &&
                         !reservation::eligible_ipv4(0x7fffffffu, up) &&
                         !reservation::eligible_ipv4(0xe0000001u, up) &&
                         !reservation::eligible_ipv4(0xefffffffu, up) &&
                         !reservation::eligible_ipv4(INADDR_BROADCAST, up) &&
                         reservation::eligible_ipv4(0xf0000001u, up);
    const bool deterministic =
        std::is_sorted(addresses.begin(), addresses.end()) &&
        std::adjacent_find(addresses.begin(), addresses.end()) == addresses.end() &&
        std::all_of(addresses.begin(), addresses.end(), [&](auto address) {
            return reservation::eligible_ipv4(address, up);
        });
    return check(filters && deterministic, "address filters and deterministic discovery");
}

bool invalid_address_zero_change() {
    Snapshot before;
    Snapshot after;
    reservation::ExactTcpReservationLease lease;
    reservation::Diagnostic diagnostic;
    return check(snapshot(before) && !reserve(INADDR_ANY, lease, diagnostic) &&
                     failed(diagnostic, reservation::FailurePhase::Argument, EINVAL) &&
                     lease.state() == reservation::State::Fresh && lease.descriptor() == -1 &&
                     snapshot(after) && before == after,
                 "invalid address has zero FD change");
}

bool normal_and_probe(std::uint32_t address) {
    reservation::ExactTcpReservationLease lease;
    reservation::Diagnostic diagnostic;
    if (!check(reserve(address, lease, diagnostic), "normal reserve")) return false;
    const int fd = lease.descriptor();
    const std::uint16_t port = lease.port();
    const std::uint64_t inode = lease.socket_inode();
    int reuse_address = -1;
    int reuse_port = -1;
    int accept_connection = -1;
    socklen_t size = sizeof(int);
    const bool held =
        fd >= 0 && port != 0u && inode != 0u && lease.ipv4() == address &&
        getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, &size) == 0 &&
        reuse_address == 0 && getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, &size) == 0 &&
        reuse_port == 0 &&
        getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accept_connection, &size) == 0 &&
        accept_connection == 0 && wildcard_probe(port, true) && lease.revalidate(diagnostic);
    const auto receipt = lease.release_receipt();
    const bool released = held && lease.release(diagnostic) &&
                          lease.state() == reservation::State::Released &&
                          complete_release(receipt, true, false) && wildcard_probe(port, false);
    const reservation::ReleaseReceipt retained = *receipt;
    const bool doubled = !lease.release(diagnostic) &&
                         failed(diagnostic, reservation::FailurePhase::State, EALREADY) &&
                         same_receipt(*receipt, retained);
    return check(released && doubled, "normal explicit release, raw probes, and double release");
}

bool unrelated_and_option_recovery(std::uint32_t address) {
    reservation::ExactTcpReservationLease lease;
    reservation::Diagnostic diagnostic;
    if (!reserve(address, lease, diagnostic)) return false;
    const int unrelated = open("/dev/null", O_RDONLY | O_CLOEXEC);
    bool ok = unrelated >= 0 && !lease.release(diagnostic) &&
              lease.state() == reservation::State::BindingLost &&
              failed(diagnostic, reservation::FailurePhase::Inventory, ESTALE) &&
              close(unrelated) == 0 && lease.revalidate(diagnostic);
    constexpr int one = 1;
    constexpr int zero = 0;
    ok = ok && setsockopt(lease.descriptor(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0 &&
         !lease.release(diagnostic) && lease.state() == reservation::State::BindingLost &&
         failed(diagnostic, reservation::FailurePhase::Option, EINVAL) &&
         setsockopt(lease.descriptor(), SOL_SOCKET, SO_REUSEADDR, &zero, sizeof(zero)) == 0 &&
         lease.revalidate(diagnostic) && lease.release(diagnostic);
    return check(ok, "unrelated FD and option exact restoration");
}

bool duplicate_recovery(std::uint32_t address) {
    reservation::ExactTcpReservationLease lease;
    reservation::Diagnostic diagnostic;
    if (!reserve(address, lease, diagnostic)) return false;
    const int duplicate = fcntl(lease.descriptor(), F_DUPFD_CLOEXEC, 3);
    const bool ok = duplicate >= 0 && !lease.release(diagnostic) &&
                    lease.state() == reservation::State::BindingLost &&
                    failed(diagnostic, reservation::FailurePhase::Inventory, ESTALE) &&
                    close(duplicate) == 0 && lease.revalidate(diagnostic) &&
                    lease.release(diagnostic);
    return check(ok, "duplicate G rejection and exact recovery");
}

bool replacement_recovery(std::uint32_t address) {
    reservation::ExactTcpReservationLease lease;
    reservation::Diagnostic diagnostic;
    if (!reserve(address, lease, diagnostic)) return false;
    const int owned_slot = lease.descriptor();
    const int saved = fcntl(owned_slot, F_DUPFD_CLOEXEC, 3);
    const int foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
    bool ok = saved >= 0 && foreign >= 0 && dup3(foreign, owned_slot, O_CLOEXEC) == owned_slot &&
              close(foreign) == 0 && !lease.release(diagnostic) &&
              lease.state() == reservation::State::BindingLost && fcntl(owned_slot, F_GETFD) >= 0 &&
              dup3(saved, owned_slot, O_CLOEXEC) == owned_slot && close(saved) == 0 &&
              lease.revalidate(diagnostic) && lease.release(diagnostic);
    return check(ok, "numeric-slot replacement preserves foreign FD and restores");
}

bool destructor_foreign_preservation(std::uint32_t address) {
    std::shared_ptr<const reservation::ReleaseReceipt> receipt;
    reservation::Diagnostic binding_loss;
    int owned_slot = -1;
    int saved = -1;
    {
        reservation::ExactTcpReservationLease lease;
        reservation::Diagnostic diagnostic;
        if (!reserve(address, lease, diagnostic)) return false;
        owned_slot = lease.descriptor();
        saved = fcntl(owned_slot, F_DUPFD_CLOEXEC, 3);
        const int foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (saved < 0 || foreign < 0 || dup3(foreign, owned_slot, O_CLOEXEC) != owned_slot ||
            close(foreign) != 0 || lease.revalidate(diagnostic))
            return false;
        binding_loss = diagnostic;
        receipt = lease.release_receipt();
    }
    const bool preserved = fcntl(owned_slot, F_GETFD) >= 0 && receipt && receipt->attempted &&
                           receipt->destructor && receipt->real_close_attempts == 0u &&
                           !receipt->reportable_success &&
                           receipt->state == reservation::State::BindingLost &&
                           receipt->diagnostic.phase == binding_loss.phase &&
                           receipt->diagnostic.error_number == binding_loss.error_number;
    const bool cleaned = close(owned_slot) == 0 && close(saved) == 0;
    return check(preserved && cleaned, "BindingLost destructor preserves foreign replacement");
}

bool destructor_option_diagnostic(std::uint32_t address) {
    std::shared_ptr<const reservation::ReleaseReceipt> receipt;
    reservation::Diagnostic binding_loss;
    int descriptor = -1;
    {
        reservation::ExactTcpReservationLease lease;
        reservation::Diagnostic diagnostic;
        if (!reserve(address, lease, diagnostic)) return false;
        descriptor = lease.descriptor();
        constexpr int one = 1;
        if (setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
            lease.revalidate(diagnostic) ||
            !failed(diagnostic, reservation::FailurePhase::Option, EINVAL))
            return false;
        binding_loss = diagnostic;
        receipt = lease.release_receipt();
    }
    const bool retained = descriptor >= 0 && fcntl(descriptor, F_GETFD) >= 0 && receipt &&
                          receipt->attempted && receipt->destructor &&
                          receipt->real_close_attempts == 0u &&
                          receipt->state == reservation::State::BindingLost &&
                          receipt->diagnostic.phase == binding_loss.phase &&
                          receipt->diagnostic.error_number == binding_loss.error_number;
    const bool cleaned = descriptor >= 0 && close(descriptor) == 0;
    return check(retained && cleaned, "BindingLost destructor retains exact option diagnostic");
}

bool destructor_release(std::uint32_t address) {
    std::shared_ptr<const reservation::ReleaseReceipt> receipt;
    {
        reservation::ExactTcpReservationLease lease;
        reservation::Diagnostic diagnostic;
        if (!reserve(address, lease, diagnostic)) return false;
        receipt = lease.release_receipt();
    }
    return check(complete_release(receipt, false, true), "valid Held destructor one-shot release");
}

bool synthesized_close_error(std::uint32_t address,
                             reservation::CloseFaultForTesting fault,
                             int expected_error) {
    reservation::HooksForTesting hooks;
    hooks.close_fault = fault;
    std::shared_ptr<const reservation::ReleaseReceipt> receipt;
    {
        reservation::ExactTcpReservationLease lease;
        reservation::Diagnostic diagnostic;
        if (!reservation::ExactTcpReservationLease::reserve_with_hooks_for_testing(
                address, hooks, lease, diagnostic))
            return false;
        receipt = lease.release_receipt();
        if (lease.release(diagnostic) || lease.state() != reservation::State::ReleaseUncertain ||
            !failed(diagnostic, reservation::FailurePhase::Close, expected_error))
            return false;
    }
    return check(receipt && receipt->real_close_attempts == 1u && receipt->real_close_result == 0 &&
                     receipt->real_close_error == 0 &&
                     receipt->reported_close_error == expected_error && receipt->immediate_ebadf &&
                     receipt->baseline_restored && receipt->socket_inode_absent &&
                     !receipt->reportable_success,
                 "real-close-then-synthesized error is terminal without retry");
}

struct PostCloseMutation {
    int descriptor = -1;
};

void open_after_ebadf(void* opaque) {
    auto& mutation = *static_cast<PostCloseMutation*>(opaque);
    mutation.descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
}

bool post_close_uncertainty(std::uint32_t address) {
    PostCloseMutation mutation;
    reservation::HooksForTesting hooks;
    hooks.after_immediate_ebadf = open_after_ebadf;
    hooks.context = &mutation;
    reservation::ExactTcpReservationLease lease;
    reservation::Diagnostic diagnostic;
    if (!reservation::ExactTcpReservationLease::reserve_with_hooks_for_testing(
            address, hooks, lease, diagnostic))
        return false;
    const auto receipt = lease.release_receipt();
    const bool uncertain = !lease.release(diagnostic) && mutation.descriptor >= 0 &&
                           lease.state() == reservation::State::ReleaseUncertain &&
                           failed(diagnostic, reservation::FailurePhase::PostClose, ESTALE) &&
                           receipt->real_close_attempts == 1u && receipt->immediate_ebadf &&
                           receipt->post_inventory_checked && !receipt->baseline_restored &&
                           receipt->socket_inode_absent && !receipt->reportable_success;
    const bool cleaned = mutation.descriptor >= 0 && close(mutation.descriptor) == 0;
    return check(uncertain && cleaned,
                 "post-close exact inventory failure is terminal uncertainty");
}

}  // namespace

int main() {
    std::vector<std::uint32_t> addresses;
    reservation::Diagnostic diagnostic;
    if (!reservation::discover_eligible_ipv4(addresses, diagnostic)) {
        std::fprintf(stderr,
                     "FAIL: IPv4 discovery (phase=%u errno=%d)\n",
                     static_cast<unsigned>(diagnostic.phase),
                     diagnostic.error_number);
        return 1;
    }
    if (addresses.empty()) {
        std::fprintf(stderr, "SKIP: no eligible UP non-loopback AF_INET address\n");
        return 77;
    }
    const std::uint32_t address = addresses.front();
    bool ok = filter_and_discovery_tests(addresses);
    ok = run_case("invalid-address", invalid_address_zero_change) && ok;
    ok = run_case("normal-and-probes", [&] { return normal_and_probe(address); }) && ok;
    ok = run_case("unrelated-option-recovery",
                  [&] { return unrelated_and_option_recovery(address); }) &&
         ok;
    ok = run_case("duplicate-recovery", [&] { return duplicate_recovery(address); }) && ok;
    ok = run_case("replacement-recovery", [&] { return replacement_recovery(address); }) && ok;
    ok = run_case("destructor-foreign", [&] { return destructor_foreign_preservation(address); }) &&
         ok;
    ok = run_case("destructor-option-diagnostic",
                  [&] { return destructor_option_diagnostic(address); }) &&
         ok;
    ok = run_case("destructor-release", [&] { return destructor_release(address); }) && ok;
    ok = run_case("synthesized-eintr",
                  [&] {
                      return synthesized_close_error(
                          address, reservation::CloseFaultForTesting::SynthesizeEintr, EINTR);
                  }) &&
         ok;
    ok = run_case("synthesized-eio",
                  [&] {
                      return synthesized_close_error(
                          address, reservation::CloseFaultForTesting::SynthesizeEio, EIO);
                  }) &&
         ok;
    ok = run_case("post-close-uncertainty", [&] { return post_close_uncertainty(address); }) && ok;
    return ok ? 0 : 1;
}
