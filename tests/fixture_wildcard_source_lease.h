#pragma once

#include "fixture_privileged_listener.h"
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
};

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

struct SourceLeaseHooksForTesting {
    BoundaryHookForTesting before_reopen = nullptr;
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

    bool revalidate(Diagnostic& diagnostic) const;
    bool validate_detached_after_unlink(Diagnostic& diagnostic) const;
    bool remove(Diagnostic& diagnostic);
    bool remove_with_hook_for_testing(BoundaryHookForTesting hook,
                                      void* context,
                                      Diagnostic& diagnostic);

    bool active() const { return active_; }
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
    bool validate_directory(Diagnostic& diagnostic) const;
    bool validate_open_source(bool require_link, Diagnostic& diagnostic) const;
    bool read_exact_bytes(Diagnostic& diagnostic) const;
    bool quarantine_and_remove(BoundaryHookForTesting hook, void* context, Diagnostic& diagnostic);
    bool fail_created(const Diagnostic& original, Diagnostic& diagnostic);
    void record_cleanup(bool succeeded, const Diagnostic& diagnostic);
    void close_descriptors(Diagnostic& diagnostic);

    int directory_fd_ = -1;
    int source_fd_ = -1;
    bool active_ = false;
    bool cleanup_required_ = false;
    bool owned_entry_known_ = false;
    bool source_identity_known_ = false;
    bool source_fd_is_created_ = false;
    std::string directory_path_;
    std::string basename_;
    std::string path_;
    std::string expected_bytes_;
    std::string owned_basename_;
    DirectoryIdentity directory_identity_;
    SourceIdentity source_identity_;
    std::shared_ptr<CleanupState> cleanup_state_;
};

}  // namespace rut::test::fixture_wildcard_source_lease
