#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace rut::test::fixture_executable_lease {

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Canonical,
    Open,
    Duplicate,
    Identity,
    Policy,
    Path,
    Kcmp,
    Close,
    Cleanup,
};

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

struct ExecutableIdentity {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t mode = 0u;
    std::uint64_t uid = 0u;
    std::uint64_t gid = 0u;
    std::uint64_t size = 0u;
    std::int64_t mtime_seconds = 0;
    std::int64_t mtime_nanoseconds = 0;
    std::int64_t ctime_seconds = 0;
    std::int64_t ctime_nanoseconds = 0;
};

struct CloseOutcome {
    unsigned attempts = 0u;
    bool attempted = false;
    bool succeeded = false;
    int error_number = 0;
};

struct ValidationOutcome {
    unsigned attempts = 0u;
    bool succeeded = false;
    Diagnostic diagnostic;
};

// Retaining this state makes explicit and destructor cleanup independently
// auditable. Validation is separate from each descriptor's one-shot close
// result. Destruction deliberately never sets reportable_success.
struct CleanupState {
    ValidationOutcome semantic_validation;
    ValidationOutcome custody_validation;
    bool creation_cleanup = false;
    Diagnostic creation_diagnostic;
    CloseOutcome observation;
    CloseOutcome authority_one;
    CloseOutcome authority_two;
    bool destructor = false;
    bool reportable_success = false;
    Diagnostic diagnostic;
};

using KcmpForTesting = int (*)(int first, int second, void* context);
using CloseForTesting = int (*)(int descriptor, void* context);
using AccessForTesting = int (*)(int descriptor, void* context);

enum class CreationFailurePoint : std::uint8_t {
    None,
    AfterOpen,
    AfterFirstDuplicate,
    AfterDuplicate,
    IdentityValidation,
};

struct HooksForTesting {
    KcmpForTesting kcmp = nullptr;
    CloseForTesting close = nullptr;
    AccessForTesting access = nullptr;
    void* context = nullptr;
    CreationFailurePoint creation_failure = CreationFailurePoint::None;
};

// Tests-only custody of one caller-owned executable name and open file
// description. The caller supplies an already-canonical absolute path and
// contractually excludes pathname, content and metadata mutation, external
// writers, and concurrent parent-FD-table mutation while the lease is active.
// The realpath comparison is a non-atomic canonical-input check; it is not
// dentry-lineage proof, namespace attestation, or content immutability.
//
// Lifecycle is single-use Fresh -> Active -> Terminal. The object is
// noncopyable, nonmovable and non-thread-safe. observation_fd() is borrowed;
// two exact duplicate authorities are private. If an excluded caller mutation
// replaces the observation slot, revalidation and close fail closed without
// closing the foreign descriptor; restoring an exact duplicate permits retry.
// Under the explicit at-most-one-numeric-slot-replacement defensive boundary,
// destructor cleanup can settle the original two-member exact-OFD majority.
// Without a unique majority, or when kcmp cannot provide exact evidence, every
// unproven slot is preserved. Two coordinated replacements that share one new
// OFD can form a false majority and are explicitly outside this guarantee.
// Initial ctime is retained as diagnostic evidence. Because nlink is not an
// invariant, revalidation checks only current ctime agreement among the path
// and all pinned members; it cannot attest against excluded restored metadata,
// ACL, or same-size/mtime-restored content mutations.
class ExecutableLease {
public:
    ExecutableLease();
    ~ExecutableLease();

    ExecutableLease(const ExecutableLease&) = delete;
    ExecutableLease& operator=(const ExecutableLease&) = delete;
    ExecutableLease(ExecutableLease&&) = delete;
    ExecutableLease& operator=(ExecutableLease&&) = delete;

    static bool create(const std::string& canonical_absolute_path,
                       ExecutableLease& lease,
                       Diagnostic& diagnostic);
    static bool create_with_hooks_for_testing(const std::string& canonical_absolute_path,
                                              const HooksForTesting& hooks,
                                              ExecutableLease& lease,
                                              Diagnostic& diagnostic);

    bool revalidate(Diagnostic& diagnostic) const;
    bool close(Diagnostic& diagnostic);

    bool active() const { return active_; }
    int observation_fd() const { return observation_fd_; }
    const std::string& canonical_path() const { return path_; }
    const ExecutableIdentity& identity() const { return identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

private:
    static bool create_impl(const std::string& canonical_absolute_path,
                            const HooksForTesting* hooks,
                            ExecutableLease& lease,
                            Diagnostic& diagnostic);
    bool validate_custody(Diagnostic& diagnostic) const;
    bool authorize_cleanup(bool require_cloexec,
                           std::array<bool, 3>& original_members,
                           Diagnostic& diagnostic) const;
    bool validate_descriptor(int descriptor, bool require_metadata, Diagnostic& diagnostic) const;
    bool validate_policy(int descriptor, Diagnostic& diagnostic) const;
    bool same_open_file_description(int first, int second, Diagnostic& diagnostic) const;
    bool fail_after_acquire(const Diagnostic& original, Diagnostic& diagnostic);
    bool close_active(bool destructor, Diagnostic& diagnostic);
    bool close_one(int& descriptor, CloseOutcome& outcome, Diagnostic& diagnostic);
    void record_semantic_validation(bool succeeded, const Diagnostic& diagnostic) const;
    void record_custody_validation(bool succeeded, const Diagnostic& diagnostic) const;

    int observation_fd_ = -1;
    int authority_one_fd_ = -1;
    int authority_two_fd_ = -1;
    bool active_ = false;
    bool terminal_ = false;
    std::string path_;
    ExecutableIdentity identity_;
    std::shared_ptr<CleanupState> cleanup_state_;
    KcmpForTesting kcmp_for_testing_ = nullptr;
    CloseForTesting close_for_testing_ = nullptr;
    AccessForTesting access_for_testing_ = nullptr;
    void* hook_context_ = nullptr;
};

}  // namespace rut::test::fixture_executable_lease
