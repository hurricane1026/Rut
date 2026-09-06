#pragma once

#include "fixture_privileged_listener.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <sys/types.h>

namespace rut::test::fixture_wildcard_source_lease {

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Directory,
    Create,
    Write,
    Lease,
    Path,
    Bytes,
    Quarantine,
    Restore,
    Remove,
    Close,
    Finalize,
    State,
};

enum class State : std::uint8_t { Fresh, Staged, Active, FinalizeFailed, Removed };

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

struct DirectoryIdentity {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t mode = 0u;
    std::uint64_t uid = 0u;
    std::uint64_t gid = 0u;
};

struct SourceIdentity {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t mode = 0u;
    std::uint64_t uid = 0u;
    std::uint64_t gid = 0u;
    std::uint64_t size = 0u;
};

// This state outlives the lease when retained by a test. It makes a destructor
// cleanup refusal observable without allowing the destructor to unlink a
// replacement directory entry.
struct CleanupState {
    bool attempted = false;
    bool succeeded = false;
    Diagnostic diagnostic;
};

using BoundaryHookForTesting = void (*)(int directory_fd, const char* basename, void* context);
using PreadForTesting = ssize_t (*)(int fd, void* buffer, std::size_t count, off_t offset);
using FinalizeBoundaryHookForTesting =
    void (*)(int directory_fd, const char* basename, int writer_fd, int reader_fd, void* context);
using FtruncateForTesting = int (*)(int fd, off_t length, void* context);
using PwriteForTesting =
    ssize_t (*)(int fd, const void* buffer, std::size_t count, off_t offset, void* context);
using FsyncForTesting = int (*)(int fd, void* context);
using CloseForTesting = int (*)(int fd, void* context);
enum class StageFaultForTesting : std::uint8_t { None, InitialIdentity, InitialFlags };

struct SourceLeaseHooksForTesting {
    BoundaryHookForTesting before_reopen = nullptr;
    void* context = nullptr;
};

struct StagedSourceHooksForTesting {
    FinalizeBoundaryHookForTesting before_finalize_identity = nullptr;
    FinalizeBoundaryHookForTesting after_finalize_sync = nullptr;
    FtruncateForTesting ftruncate_operation = nullptr;
    PwriteForTesting pwrite_operation = nullptr;
    FsyncForTesting fsync_operation = nullptr;
    FsyncForTesting cleanup_fsync_operation = nullptr;
    CloseForTesting close_operation = nullptr;
    StageFaultForTesting stage_fault = StageFaultForTesting::None;
    void* context = nullptr;
};

// Shared by the lease and its deterministic EINTR test. This is fixture-only;
// no runtime or converter target links this library.
bool read_exact_bytes_for_testing(int fd,
                                  const std::string& expected,
                                  PreadForTesting operation,
                                  Diagnostic& diagnostic);

// Owns a read-only lease for exactly one ordinary-RUT wildcard source. The
// supplied directory must already be an identity-bound, current-user 0700
// private directory. All source operations are relative to the retained
// directory descriptor.
class WildcardAttemptSourceLease {
public:
    WildcardAttemptSourceLease();
    ~WildcardAttemptSourceLease();

    WildcardAttemptSourceLease(const WildcardAttemptSourceLease&) = delete;
    WildcardAttemptSourceLease& operator=(const WildcardAttemptSourceLease&) = delete;
    WildcardAttemptSourceLease(WildcardAttemptSourceLease&&) = delete;
    WildcardAttemptSourceLease& operator=(WildcardAttemptSourceLease&&) = delete;

    static bool create(int identity_bound_directory_fd,
                       const std::string& directory_path,
                       const std::string& basename,
                       const fixture_privileged_listener::ListenerPlan& plan,
                       WildcardAttemptSourceLease& lease,
                       Diagnostic& diagnostic);

    // Creates the same identity-bound source lease from caller-supplied
    // ordinary-RUT bytes.  This narrow tests-only seam is bounded to the
    // fixture's exact-read capacity and does not interpret the source.
    static bool create_exact_bytes(int identity_bound_directory_fd,
                                   const std::string& directory_path,
                                   const std::string& basename,
                                   const std::string& exact_bytes,
                                   WildcardAttemptSourceLease& lease,
                                   Diagnostic& diagnostic);

    static bool create_with_hooks_for_testing(int identity_bound_directory_fd,
                                              const std::string& directory_path,
                                              const std::string& basename,
                                              const fixture_privileged_listener::ListenerPlan& plan,
                                              const SourceLeaseHooksForTesting& hooks,
                                              WildcardAttemptSourceLease& lease,
                                              Diagnostic& diagnostic);

    // Stages an empty, identity-bound inode and all of its descriptors. This
    // must happen before an ExactTcpReservationLease establishes its Held FD
    // baseline. finalize_exact_bytes() changes no descriptor identity.
    static bool stage(int identity_bound_directory_fd,
                      const std::string& directory_path,
                      const std::string& basename,
                      WildcardAttemptSourceLease& lease,
                      Diagnostic& diagnostic);
    static bool stage_with_hooks_for_testing(int identity_bound_directory_fd,
                                             const std::string& directory_path,
                                             const std::string& basename,
                                             const StagedSourceHooksForTesting& hooks,
                                             WildcardAttemptSourceLease& lease,
                                             Diagnostic& diagnostic);
    bool finalize_exact_bytes(const std::string& exact_bytes, Diagnostic& diagnostic);

    bool revalidate(Diagnostic& diagnostic) const;
    bool validate_detached_after_unlink(Diagnostic& diagnostic) const;
    bool remove(Diagnostic& diagnostic);
    bool remove_with_hook_for_testing(BoundaryHookForTesting hook,
                                      void* context,
                                      Diagnostic& diagnostic);

    bool active() const { return active_; }
    State state() const { return state_; }
    int descriptor() const { return source_fd_; }
    const std::string& path() const { return path_; }
    const std::string& basename() const { return basename_; }
    const DirectoryIdentity& directory_identity() const { return directory_identity_; }
    const SourceIdentity& source_identity() const { return source_identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

    bool same_source_identity(const WildcardAttemptSourceLease& other) const;

private:
    static bool create_impl(int identity_bound_directory_fd,
                            const std::string& directory_path,
                            const std::string& basename,
                            const fixture_privileged_listener::ListenerPlan& plan,
                            const SourceLeaseHooksForTesting* hooks,
                            WildcardAttemptSourceLease& lease,
                            Diagnostic& diagnostic);
    static bool create_exact_bytes_impl(int identity_bound_directory_fd,
                                        const std::string& directory_path,
                                        const std::string& basename,
                                        const std::string& exact_bytes,
                                        const SourceLeaseHooksForTesting* hooks,
                                        WildcardAttemptSourceLease& lease,
                                        Diagnostic& diagnostic);
    static bool stage_impl(int identity_bound_directory_fd,
                           const std::string& directory_path,
                           const std::string& basename,
                           const StagedSourceHooksForTesting* hooks,
                           WildcardAttemptSourceLease& lease,
                           Diagnostic& diagnostic);
    bool validate_directory(Diagnostic& diagnostic) const;
    bool validate_open_source(bool require_link, Diagnostic& diagnostic) const;
    bool validate_staged_sources(bool require_link,
                                 bool require_empty,
                                 const SourceIdentity& expected,
                                 Diagnostic& diagnostic) const;
    bool validate_staged_detached(Diagnostic& diagnostic) const;
    bool read_exact_bytes(Diagnostic& diagnostic) const;
    bool quarantine_and_remove(BoundaryHookForTesting hook, void* context, Diagnostic& diagnostic);
    bool fail_created(const Diagnostic& original, Diagnostic& diagnostic);
    void record_cleanup(bool succeeded, const Diagnostic& diagnostic);
    void close_descriptors(Diagnostic& diagnostic);

    int directory_fd_ = -1;
    int source_fd_ = -1;
    int writer_fd_ = -1;
    bool active_ = false;
    bool cleanup_required_ = false;
    bool owned_entry_known_ = false;
    bool source_identity_known_ = false;
    bool source_fd_is_created_ = false;
    bool unlink_evidence_complete_ = false;
    std::string directory_path_;
    std::string basename_;
    std::string path_;
    std::string expected_bytes_;
    std::array<char, 255> staged_expected_bytes_{};
    std::size_t staged_expected_size_ = 0u;
    std::string owned_basename_;
    DirectoryIdentity directory_identity_;
    SourceIdentity source_identity_;
    State state_ = State::Fresh;
    StagedSourceHooksForTesting staged_hooks_;
    std::shared_ptr<CleanupState> cleanup_state_;
};

}  // namespace rut::test::fixture_wildcard_source_lease
