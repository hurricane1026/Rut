#pragma once

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

// Retaining this state makes explicit and destructor cleanup independently
// auditable. Validation is separate from each descriptor's one-shot close
// result. Destruction deliberately never sets reportable_success.
struct CleanupState {
    unsigned validation_attempts = 0u;
    bool validation_succeeded = false;
    Diagnostic validation_diagnostic;
    CloseOutcome observation;
    CloseOutcome authority;
    bool destructor = false;
    bool reportable_success = false;
    Diagnostic diagnostic;
};

using KcmpForTesting = int (*)(int first, int second, void* context);
using CloseForTesting = int (*)(int descriptor, void* context);

enum class CreationFailurePoint : std::uint8_t {
    None,
    AfterOpen,
    AfterDuplicate,
    IdentityValidation,
};

struct HooksForTesting {
    KcmpForTesting kcmp = nullptr;
    CloseForTesting close = nullptr;
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
// the exact duplicate authority is private. If an excluded caller mutation
// replaces the observation slot, revalidation and close fail closed without
// closing the foreign descriptor; restoring an exact duplicate permits retry.
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
    const ExecutableIdentity& identity() const { return identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

private:
    static bool create_impl(const std::string& canonical_absolute_path,
                            const HooksForTesting* hooks,
                            ExecutableLease& lease,
                            Diagnostic& diagnostic);
    bool validate_custody(Diagnostic& diagnostic) const;
    bool validate_descriptor(int descriptor, bool require_metadata, Diagnostic& diagnostic) const;
    bool validate_policy(int descriptor, Diagnostic& diagnostic) const;
    bool same_open_file_description(int first, int second, Diagnostic& diagnostic) const;
    bool fail_after_acquire(const Diagnostic& original, Diagnostic& diagnostic);
    bool close_active(bool destructor, Diagnostic& diagnostic);
    bool close_one(int& descriptor, CloseOutcome& outcome, Diagnostic& diagnostic);
    void record_validation(bool succeeded, const Diagnostic& diagnostic) const;

    int observation_fd_ = -1;
    int authority_fd_ = -1;
    bool active_ = false;
    bool terminal_ = false;
    std::string path_;
    ExecutableIdentity identity_;
    // The initial full identity remains immutable evidence. Linux ctime can
    // advance for accepted nlink/name-binding transitions, so the current
    // common ctime baseline is tracked separately.
    mutable std::int64_t accepted_ctime_seconds_ = 0;
    mutable std::int64_t accepted_ctime_nanoseconds_ = 0;
    std::shared_ptr<CleanupState> cleanup_state_;
    KcmpForTesting kcmp_for_testing_ = nullptr;
    CloseForTesting close_for_testing_ = nullptr;
    void* hook_context_ = nullptr;
};

}  // namespace rut::test::fixture_executable_lease
