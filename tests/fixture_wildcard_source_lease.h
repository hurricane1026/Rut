#pragma once

#include "fixture_privileged_listener.h"
#include <cstdint>
#include <memory>
#include <string>

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

    bool revalidate(Diagnostic& diagnostic) const;
    bool validate_detached_after_unlink(Diagnostic& diagnostic) const;
    bool remove(Diagnostic& diagnostic);

    bool active() const { return active_; }
    int descriptor() const { return source_fd_; }
    const std::string& path() const { return path_; }
    const std::string& basename() const { return basename_; }
    const DirectoryIdentity& directory_identity() const { return directory_identity_; }
    const SourceIdentity& source_identity() const { return source_identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

    bool same_source_identity(const WildcardAttemptSourceLease& other) const;

private:
    bool validate_directory(Diagnostic& diagnostic) const;
    bool validate_open_source(bool require_link, Diagnostic& diagnostic) const;
    bool read_exact_bytes(Diagnostic& diagnostic) const;
    void record_cleanup(bool succeeded, const Diagnostic& diagnostic);
    void close_descriptors(Diagnostic& diagnostic);

    int directory_fd_ = -1;
    int source_fd_ = -1;
    bool active_ = false;
    std::string directory_path_;
    std::string basename_;
    std::string path_;
    std::string expected_bytes_;
    DirectoryIdentity directory_identity_;
    SourceIdentity source_identity_;
    std::shared_ptr<CleanupState> cleanup_state_;
};

}  // namespace rut::test::fixture_wildcard_source_lease
