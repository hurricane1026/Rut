#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
namespace rut::test::fixture_private_directory_lease {
enum class State : std::uint8_t {
    Empty,
    PendingIdentity,
    Owned,
    BindingLost,
    RenamePendingValidation,
    Quarantined,
    Removed,
    Unresolved,
};
enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Parent,
    Random,
    Create,
    Identity,
    Permission,
    Revalidate,
    Quarantine,
    Remove,
    Close,
    Hook,
};
enum class Residue : std::uint8_t { Unknown, Present, Absent };
enum class AbortPoint : std::uint8_t { None, AfterMkdir, AfterFirstOwnedMatch };
struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};
struct Identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t mode = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
};
struct SettlementReceipt {
    bool attempted = false;
    bool object_removed = false;
    bool descriptor_closed = false;
    Residue residue = Residue::Unknown;
    State state = State::Empty;
    Diagnostic diagnostic;
    std::string path;
    std::string original_basename;
    std::string last_candidate;
};
using RenameHookForTesting = void (*)(int parent_fd, const char* candidate, void* context);
struct HooksForTesting {
    const char* creation_seed = nullptr;
    std::array<const char*, 2> quarantine_seeds{};
    std::size_t quarantine_seed_count = 0;
    AbortPoint abort = AbortPoint::None;
    RenameHookForTesting after_quarantine_rename = nullptr;
    void* context = nullptr;
};
// Tests-only, fixed-parent (/tmp) identity lease. Concurrency protection is
// limited to the explicit validation boundaries; it does not claim safety
// against arbitrary same-UID namespace races between syscalls.
class PrivateDirectoryLease {
public:
    PrivateDirectoryLease();
    ~PrivateDirectoryLease();
    PrivateDirectoryLease(const PrivateDirectoryLease&) = delete;
    PrivateDirectoryLease& operator=(const PrivateDirectoryLease&) = delete;
    PrivateDirectoryLease(PrivateDirectoryLease&&) = delete;
    PrivateDirectoryLease& operator=(PrivateDirectoryLease&&) = delete;
    static bool create(PrivateDirectoryLease& lease, Diagnostic& diagnostic);
    static bool create_with_hooks_for_testing(const HooksForTesting& hooks,
                                              PrivateDirectoryLease& lease,
                                              Diagnostic& diagnostic);
    bool revalidate(Diagnostic& diagnostic);
    bool settle(Diagnostic& diagnostic);
    int descriptor() const { return directory_fd_; }
    const std::string& path() const { return path_; }
    const std::string& basename() const { return current_basename_; }
    State state() const { return state_; }
    const Identity& identity() const { return identity_; }
    std::shared_ptr<const SettlementReceipt> settlement_receipt() const { return receipt_; }

private:
    bool create_impl(const HooksForTesting* hooks, Diagnostic& diagnostic);
    bool reject(Diagnostic& diagnostic, FailurePhase phase, int error_number);
    void transition(State state);
    bool validate_binding(Diagnostic& diagnostic);
    bool next_name(bool creation, std::string& name, Diagnostic& diagnostic);
    void observe_residue();
    void close_descriptors(Diagnostic& diagnostic);

    int parent_fd_ = -1;
    int directory_fd_ = -1;
    State state_ = State::Empty;
    State binding_prior_ = State::Empty;
    Identity identity_;
    std::string path_;
    std::string original_basename_;
    std::string current_basename_;
    HooksForTesting hooks_;
    std::size_t quarantine_index_ = 0;
    std::shared_ptr<SettlementReceipt> receipt_;
};
}  // namespace rut::test::fixture_private_directory_lease
