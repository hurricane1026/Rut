#pragma once

#include "fixture_worker_protocol.h"
#include <chrono>
#include <cstdint>
#include <memory>

#include <sys/types.h>

namespace rut::test::fixture_wildcard_paused_child_lease {

using ProcIdentity = fixture_worker_protocol::ProcIdentity;

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Children,
    Pipe,
    Fork,
    Pidfd,
    Identity,
    Readiness,
    Release,
    Wait,
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

struct HooksForTesting {
    int (*pidfd_open)(pid_t, unsigned int) = nullptr;
    bool fail_fork = false;
};

// A single-use, non-movable paused direct-child lease. The caller owns the
// parent descriptor table exclusively while the lease is active. In
// particular, no same-process thread may close or replace a returned FD.
class PausedChildLease {
public:
    PausedChildLease();
    ~PausedChildLease();

    PausedChildLease(const PausedChildLease&) = delete;
    PausedChildLease& operator=(const PausedChildLease&) = delete;
    PausedChildLease(PausedChildLease&&) = delete;
    PausedChildLease& operator=(PausedChildLease&&) = delete;

    static bool create(std::chrono::steady_clock::time_point deadline,
                       PausedChildLease& lease,
                       Diagnostic& diagnostic);
    static bool create_with_hooks_for_testing(std::chrono::steady_clock::time_point deadline,
                                              const HooksForTesting& hooks,
                                              PausedChildLease& lease,
                                              Diagnostic& diagnostic);

    bool validate_paused(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool release(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool cleanup(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);

    bool active() const { return active_; }
    bool released() const { return released_; }
    pid_t child_pid() const { return child_pid_; }
    int observation_pidfd() const { return observation_pidfd_; }
    const ProcIdentity& identity() const { return identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

private:
    static bool create_impl(std::chrono::steady_clock::time_point deadline,
                            const HooksForTesting* hooks,
                            PausedChildLease& lease,
                            Diagnostic& diagnostic);

    bool validate_pidfd(int fd,
                        bool require_live,
                        std::chrono::steady_clock::time_point deadline,
                        Diagnostic& diagnostic) const;
    bool validate_identity(std::chrono::steady_clock::time_point deadline,
                           Diagnostic& diagnostic) const;
    bool validate_bound_child(std::chrono::steady_clock::time_point deadline,
                              Diagnostic& diagnostic) const;
    bool wait_reap(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool close_fd(int& fd, Diagnostic& diagnostic);
    bool close_after_reap(Diagnostic& diagnostic, bool observation_valid);
    void record_cleanup(bool succeeded, const Diagnostic& diagnostic);

    int ready_fd_ = -1;
    int release_fd_ = -1;
    int observation_pidfd_ = -1;
    int authority_pidfd_ = -1;
    pid_t parent_pid_ = -1;
    pid_t child_pid_ = -1;
    ProcIdentity identity_;
    bool active_ = false;
    bool released_ = false;
    bool release_sent_ = false;
    bool child_reaped_ = false;
    int child_status_ = 0;
    dev_t observation_dev_ = 0;
    ino_t observation_ino_ = 0;
    dev_t authority_dev_ = 0;
    ino_t authority_ino_ = 0;
    std::shared_ptr<CleanupState> cleanup_state_;
};

}  // namespace rut::test::fixture_wildcard_paused_child_lease
