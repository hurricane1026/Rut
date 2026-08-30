#pragma once

#include "fixture_wildcard_source_lease.h"
#include "fixture_worker_protocol.h"
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include <sys/types.h>

namespace rut::test::fixture_wildcard_attempt_child {

namespace source_lease = fixture_wildcard_source_lease;
using ProcIdentity = fixture_worker_protocol::ProcIdentity;

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Source,
    Directory,
    Log,
    Fork,
    Readiness,
    Identity,
    Pidfd,
    Proc,
    Release,
    Cleanup,
    Close,
};

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

struct CleanupState {
    bool attempted = false;
    bool succeeded = false;
    Diagnostic diagnostic;
};

// A move-only paused direct-child lease. The source lease is borrowed: this
// object never unlinks the source pathname and never closes its descriptor.
class WildcardAttemptChildLease {
public:
    WildcardAttemptChildLease();
    ~WildcardAttemptChildLease();

    WildcardAttemptChildLease(const WildcardAttemptChildLease&) = delete;
    WildcardAttemptChildLease& operator=(const WildcardAttemptChildLease&) = delete;
    WildcardAttemptChildLease(WildcardAttemptChildLease&& other) noexcept;
    WildcardAttemptChildLease& operator=(WildcardAttemptChildLease&& other) noexcept;

    static bool create(const source_lease::WildcardAttemptSourceLease& source,
                       const std::string& log_basename,
                       std::chrono::steady_clock::time_point deadline,
                       WildcardAttemptChildLease& lease,
                       Diagnostic& diagnostic);

    // Validate the direct-child set and the complete immutable child identity.
    bool validate_paused(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);

    // One-shot release only writes the release byte and waits for this child;
    // it does not remove either the source or log pathname.
    bool release(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);

    // Identity/pidfd-guarded TERM -> KILL -> waitpid cleanup, followed by
    // replacement-preserving log cleanup.
    bool cleanup(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);

    bool active() const { return active_; }
    bool released() const { return released_; }
    pid_t child_pid() const { return child_.pid; }
    int pidfd() const { return pidfd_; }
    int log_descriptor() const { return log_fd_; }
    const std::string& log_path() const { return log_path_; }
    const ProcIdentity& identity() const { return identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

    // Public so focused tests can prove that an unrelated direct child is not
    // touched. It only reads /proc and never signals or reaps a process.
    bool scan_direct_children(std::chrono::steady_clock::time_point deadline,
                              Diagnostic& diagnostic) const;

private:
    static bool create_impl(const source_lease::WildcardAttemptSourceLease& source,
                            const std::string& log_basename,
                            std::chrono::steady_clock::time_point deadline,
                            WildcardAttemptChildLease& lease,
                            Diagnostic& diagnostic);
    bool validate_source(Diagnostic& diagnostic) const;
    bool validate_pidfd(bool require_live, Diagnostic& diagnostic) const;
    bool validate_identity(ProcIdentity& current, Diagnostic& diagnostic) const;
    bool reap_until(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool cleanup_log(Diagnostic& diagnostic);
    bool quarantine_log(Diagnostic& diagnostic);
    bool close_descriptors(Diagnostic& diagnostic);
    void record_cleanup(bool succeeded, const Diagnostic& diagnostic);
    void move_from(WildcardAttemptChildLease&& other) noexcept;

    const source_lease::WildcardAttemptSourceLease* source_ = nullptr;
    int directory_fd_ = -1;
    int log_fd_ = -1;
    int ready_fd_ = -1;
    int release_fd_ = -1;
    int pidfd_ = -1;
    pid_t parent_pid_ = -1;
    fixture_worker_protocol::Child child_;
    ProcIdentity identity_;
    std::string log_basename_;
    std::string log_path_;
    source_lease::SourceIdentity log_identity_;
    bool log_identity_known_ = false;
    bool log_entry_known_ = false;
    bool log_cleanup_required_ = false;
    bool active_ = false;
    bool released_ = false;
    std::shared_ptr<CleanupState> cleanup_state_;
};

}  // namespace rut::test::fixture_wildcard_attempt_child
