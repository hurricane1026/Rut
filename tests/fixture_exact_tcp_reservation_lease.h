#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace rut::test::fixture_exact_tcp_reservation_lease {

enum class State : std::uint8_t {
    Fresh,
    Held,
    BindingLost,
    Released,
    ReleaseUncertain,
};

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Discovery,
    Snapshot,
    Socket,
    Option,
    Bind,
    Address,
    Identity,
    Inventory,
    Close,
    PostClose,
    State,
};

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

struct FdIdentity {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t mode = 0u;
    std::uint64_t rdevice = 0u;
    std::string proc_link;

    bool operator==(const FdIdentity&) const = default;
};

using FdSnapshot = std::map<int, FdIdentity>;

enum class CloseFaultForTesting : std::uint8_t {
    None,
    SynthesizeEintr,
    SynthesizeEio,
};

struct HooksForTesting {
    CloseFaultForTesting close_fault = CloseFaultForTesting::None;
    void (*after_immediate_ebadf)(void* context) = nullptr;
    void* context = nullptr;
};

struct ReleaseReceipt {
    bool attempted = false;
    bool destructor = false;
    unsigned real_close_attempts = 0u;
    int real_close_result = 0;
    int real_close_error = 0;
    int reported_close_error = 0;
    int immediate_fgetfd_result = 0;
    int immediate_fgetfd_error = 0;
    bool immediate_ebadf = false;
    bool post_inventory_checked = false;
    bool baseline_restored = false;
    bool socket_inode_absent = false;
    bool reportable_success = false;
    State state = State::Fresh;
    Diagnostic diagnostic;
};

// Host-order IPv4 values. Discovery is deterministic, sorted and deduplicated.
bool eligible_ipv4(std::uint32_t address, unsigned interface_flags);
bool discover_eligible_ipv4(std::vector<std::uint32_t>& addresses, Diagnostic& diagnostic);

// Tests-only exclusive custody of one exact, bound, non-listening TCP socket.
// The process must provide exclusive ownership of its FD table while this lease
// is active: no concurrent open/close/dup/close_range or descriptor reuse.
// The lease is noncopyable, nonmovable, single-use and non-thread-safe.
class ExactTcpReservationLease {
public:
    ExactTcpReservationLease();
    ~ExactTcpReservationLease();

    ExactTcpReservationLease(const ExactTcpReservationLease&) = delete;
    ExactTcpReservationLease& operator=(const ExactTcpReservationLease&) = delete;
    ExactTcpReservationLease(ExactTcpReservationLease&&) = delete;
    ExactTcpReservationLease& operator=(ExactTcpReservationLease&&) = delete;

    static bool reserve(std::uint32_t host_order_ipv4,
                        ExactTcpReservationLease& lease,
                        Diagnostic& diagnostic);
    static bool reserve_with_hooks_for_testing(std::uint32_t host_order_ipv4,
                                               const HooksForTesting& hooks,
                                               ExactTcpReservationLease& lease,
                                               Diagnostic& diagnostic);

    bool revalidate(Diagnostic& diagnostic);
    bool release(Diagnostic& diagnostic);

    State state() const { return state_; }
    int descriptor() const { return descriptor_; }
    std::uint32_t ipv4() const { return ipv4_; }
    std::uint16_t port() const { return port_; }
    std::uint64_t socket_inode() const { return socket_identity_.inode; }
    const FdSnapshot& baseline() const { return baseline_; }
    std::shared_ptr<const ReleaseReceipt> release_receipt() const { return receipt_; }

private:
    static bool reserve_impl(std::uint32_t host_order_ipv4,
                             const HooksForTesting* hooks,
                             ExactTcpReservationLease& lease,
                             Diagnostic& diagnostic);
    bool validate_socket(Diagnostic& diagnostic) const;
    bool validate_held_inventory(Diagnostic& diagnostic) const;
    bool release_impl(bool destructor, Diagnostic& diagnostic);
    void record_unresolved_destructor(const Diagnostic& diagnostic);

    int descriptor_ = -1;
    std::uint32_t ipv4_ = 0u;
    std::uint16_t port_ = 0u;
    FdIdentity socket_identity_;
    FdSnapshot baseline_;
    State state_ = State::Fresh;
    HooksForTesting hooks_;
    std::shared_ptr<ReleaseReceipt> receipt_;
};

}  // namespace rut::test::fixture_exact_tcp_reservation_lease
