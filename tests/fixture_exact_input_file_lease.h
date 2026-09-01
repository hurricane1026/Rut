#pragma once

#include "fixture_private_directory_lease.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <sys/types.h>

namespace rut::test::fixture_exact_input_file_lease {

inline constexpr std::size_t kMaximumInputBytes = 8192u;

enum class State : std::uint8_t {
    Empty,
    Creating,
    Active,
    BindingLost,
    Quarantined,
    Detached,
    Settled,
    Unresolved,
};

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Directory,
    Name,
    Open,
    Identity,
    Write,
    Sync,
    Reopen,
    Verification,
    WriterClose,
    Revalidate,
    Bytes,
    Quarantine,
    Unlink,
    Detached,
    DescriptorClose,
    DirectorySettlement,
    Hook,
};

enum class Residue : std::uint8_t { Unknown, Present, Absent };

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

struct Identity {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t mode = 0u;
    std::uint64_t uid = 0u;
    std::uint64_t gid = 0u;
    std::uint64_t size = 0u;
    std::uint64_t links = 0u;
};

struct CloseOutcome {
    unsigned attempts = 0u;
    bool attempted = false;
    bool succeeded = false;
    bool uncertain = false;
    int error_number = 0;
};

struct CleanupReceipt {
    bool attempted = false;
    bool semantic_validated = false;
    bool path_quarantined = false;
    bool exact_unlinked = false;
    bool detached_inode_proven = false;
    bool descriptor_closed = false;
    bool directory_settled = false;
    bool settlement_complete = false;
    bool foreign_reader_preserved = false;
    Residue original_residue = Residue::Unknown;
    Residue quarantine_residue = Residue::Unknown;
    State state = State::Empty;
    Diagnostic diagnostic;
    std::string original_basename;
    std::string quarantine_basename;
    std::string path;
    CloseOutcome writer_close;
    CloseOutcome reader_close;
    CloseOutcome authority_one_close;
    CloseOutcome authority_two_close;
    CloseOutcome directory_close;
};

enum class CreationFaultForTesting : std::uint8_t {
    None,
    PreOpen,
    Open,
    Identity,
    WritePartial,
    WriteError,
    Sync,
    Reopen,
    Verification,
    WriterCloseUncertain,
};

enum class CleanupFaultForTesting : std::uint8_t {
    None,
    QuarantineRename,
    Unlink,
    DirectorySync,
    ReaderCloseUncertain,
};

using QuarantineHookForTesting = void (*)(int directory_fd,
                                          const char* original,
                                          const char* quarantine,
                                          void* context);
using KcmpForTesting = int (*)(int first, int second, void* context);

enum class DescriptorRole : std::uint8_t {
    Writer,
    Reader,
    AuthorityOne,
    AuthorityTwo,
    Directory,
};
using CloseForTesting = int (*)(int descriptor, DescriptorRole role, void* context);

struct HooksForTesting {
    std::string creation_seed;
    std::string quarantine_seed;
    CreationFaultForTesting creation_fault = CreationFaultForTesting::None;
    CleanupFaultForTesting cleanup_fault = CleanupFaultForTesting::None;
    QuarantineHookForTesting after_quarantine_rename = nullptr;
    QuarantineHookForTesting before_final_remove = nullptr;
    KcmpForTesting kcmp = nullptr;
    CloseForTesting close = nullptr;
    void* context = nullptr;
};

// Tests-only owner for one nonempty bounded uninterpreted byte string. The
// caller's PrivateDirectoryLease must remain active until cleanup completes.
// The owner is non-thread-safe.  The caller excludes concurrent mutation of
// the process FD table and the private directory namespace; deterministic
// boundary hooks model mutations at every accepted check/use boundary. The
// defensive reader cleanup tolerates at most one numeric slot replacement;
// two coordinated foreign slots sharing one new OFD are outside the contract.
class ExactInputFileLease {
public:
    ExactInputFileLease();
    ~ExactInputFileLease();

    ExactInputFileLease(const ExactInputFileLease&) = delete;
    ExactInputFileLease& operator=(const ExactInputFileLease&) = delete;
    ExactInputFileLease(ExactInputFileLease&&) = delete;
    ExactInputFileLease& operator=(ExactInputFileLease&&) = delete;

    static bool create(fixture_private_directory_lease::PrivateDirectoryLease& directory,
                       const void* bytes,
                       std::size_t size,
                       ExactInputFileLease& lease,
                       Diagnostic& diagnostic);
    static bool create_with_hooks_for_testing(
        fixture_private_directory_lease::PrivateDirectoryLease& directory,
        const void* bytes,
        std::size_t size,
        const HooksForTesting& hooks,
        ExactInputFileLease& lease,
        Diagnostic& diagnostic);

    bool revalidate(Diagnostic& diagnostic);
    bool cleanup(Diagnostic& diagnostic);

    State state() const { return state_; }
    bool active() const { return state_ == State::Active; }
    int descriptor() const { return reader_fd_; }
    const std::string& path() const { return receipt_->path; }
    const std::string& basename() const { return receipt_->original_basename; }
    const Identity& identity() const { return identity_; }
    std::shared_ptr<const CleanupReceipt> cleanup_receipt() const { return receipt_; }

private:
    bool create_impl(fixture_private_directory_lease::PrivateDirectoryLease& directory,
                     const void* bytes,
                     std::size_t size,
                     const HooksForTesting* hooks,
                     Diagnostic& diagnostic);
    bool validate_directory(Diagnostic& diagnostic) const;
    bool validate_reader(bool linked, Diagnostic& diagnostic) const;
    bool validate_private_authorities(bool linked, Diagnostic& diagnostic) const;
    bool same_open_file_description(int first, int second, Diagnostic& diagnostic) const;
    bool validate_named(const std::string& name,
                        bool exact_semantics,
                        Diagnostic& diagnostic) const;
    bool validate_bytes(Diagnostic& diagnostic) const;
    bool quarantine(Diagnostic& diagnostic);
    bool finish_detached(Diagnostic& diagnostic);
    bool close_reader(Diagnostic& diagnostic);
    bool close_directory(Diagnostic& diagnostic);
    bool close_one(int& descriptor,
                   DescriptorRole role,
                   CloseOutcome& outcome,
                   Diagnostic& diagnostic);
    bool creation_failed(const Diagnostic& cause, Diagnostic& diagnostic);
    bool reject(Diagnostic& diagnostic, FailurePhase phase, int error_number);
    void remember(const Diagnostic& diagnostic);
    void transition(State state);
    void observe_residues();

    int directory_fd_ = -1;
    int writer_fd_ = -1;
    int reader_fd_ = -1;
    int authority_one_fd_ = -1;
    int authority_two_fd_ = -1;
    std::string directory_path_;
    std::string current_basename_;
    std::string expected_bytes_;
    fixture_private_directory_lease::Identity directory_identity_;
    Identity identity_;
    HooksForTesting hooks_;
    State state_ = State::Empty;
    bool identity_known_ = false;
    bool cleanup_fault_consumed_ = false;
    std::shared_ptr<CleanupReceipt> receipt_;
};

}  // namespace rut::test::fixture_exact_input_file_lease
