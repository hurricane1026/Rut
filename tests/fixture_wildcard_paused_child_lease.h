#pragma once

#include "fixture_worker_protocol.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <type_traits>

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
    Descriptors,
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

struct SettlementReceipt {
    pid_t child_pid = -1;
    ProcIdentity identity;
    bool terminal = false;
    bool reaped = false;
    int wait_status = 0;
    int error_number = 0;
};

enum class ChildContinuationKind : std::uint8_t { Inert, Execveat };

// Fully materialized before fork.  The child only reads this POD and performs
// async-signal-safe syscalls after fork.
struct ChildContinuation {
    ChildContinuationKind kind = ChildContinuationKind::Inert;
    std::array<char, 4096> argv0{};
    bool inject_pre_exec_failure = false;
    std::uint8_t status_injection = 0;
    std::uint8_t executable_mutation = 0;
};
static_assert(std::is_trivially_copyable_v<ChildContinuation>);
static_assert(std::is_standard_layout_v<ChildContinuation>);

struct HooksForTesting {
    int (*pidfd_open)(pid_t, unsigned int) = nullptr;
    bool fail_fork = false;
    int (*close_fd)(int, void*) = nullptr;
    void* close_context = nullptr;
    unsigned int child_delay_ms = 0;
    unsigned int child_post_ready_delay_ms = 0;
    unsigned int post_release_delay_ms = 0;
    int child_close_failure_fd = -1;
    int child_retain_fd_for_testing = -1;
    volatile int* child_close_attempt_evidence = nullptr;
    int (*kcmp_file)(pid_t, pid_t, int, int, void*) = nullptr;
    bool (*prepared_procfs_allowed)(void*) = nullptr;
    void* prepared_validation_context = nullptr;
};

// A declaration-only descriptor plan. The output descriptor remains borrowed
// from the caller; the lease deliberately retains no duplicate authority for
// it and therefore requires exclusive ownership of the parent descriptor
// table until settlement.
struct ChildDescriptorPlan {
    int combined_output_fd = -1;
    int null_input_fd = -1;
    int executable_fd = -1;
    int exec_status_fd = -1;
    int exec_status_authority_fd = -1;
    ChildContinuation continuation{};
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
    static bool create_prepared(std::chrono::steady_clock::time_point deadline,
                                const ChildDescriptorPlan& plan,
                                PausedChildLease& lease,
                                Diagnostic& diagnostic);
    static bool create_prepared_with_hooks_for_testing(
        std::chrono::steady_clock::time_point deadline,
        const ChildDescriptorPlan& plan,
        const HooksForTesting& hooks,
        PausedChildLease& lease,
        Diagnostic& diagnostic);

    bool validate_paused(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool validate_prepared(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool release(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    // Sends and certainly retires the release writer but deliberately neither
    // waits nor reaps.  release() is the strict legacy wrapper around this seam.
    bool send_release(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);
    bool authorize_exec_release(std::chrono::steady_clock::time_point deadline,
                                Diagnostic& diagnostic);
    bool cleanup(std::chrono::steady_clock::time_point deadline, Diagnostic& diagnostic);

    bool active() const { return active_; }
    bool released() const { return released_; }
    pid_t child_pid() const { return child_pid_; }
    int observation_pidfd() const { return observation_pidfd_; }
    const ProcIdentity& identity() const { return identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }
    std::shared_ptr<const SettlementReceipt> settlement_receipt() const { return settlement_; }
    int child_executable_fd() const { return child_executable_fd_; }

private:
    static bool create_impl(std::chrono::steady_clock::time_point deadline,
                            const ChildDescriptorPlan* plan,
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
    bool validate_prepared_descriptors(std::chrono::steady_clock::time_point deadline,
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
    bool release_close_uncertain_ = false;
    int child_status_ = 0;
    enum class Mode : std::uint8_t { Plain, Prepared };
    Mode mode_ = Mode::Plain;
    int combined_output_fd_ = -1;
    int child_release_fd_ = -1;
    int null_input_fd_ = -1;
    int child_executable_fd_ = -1;
    int child_exec_status_fd_ = -1;
    int exec_status_authority_fd_ = -1;
    ChildContinuation continuation_{};
    int (*kcmp_file_hook_)(pid_t, pid_t, int, int, void*) = nullptr;
    bool (*prepared_procfs_allowed_hook_)(void*) = nullptr;
    void* prepared_validation_context_ = nullptr;
    bool prepared_release_authorized_ = false;
    dev_t observation_dev_ = 0;
    ino_t observation_ino_ = 0;
    dev_t authority_dev_ = 0;
    ino_t authority_ino_ = 0;
    int (*close_hook_)(int, void*) = nullptr;
    void* close_context_ = nullptr;
    std::shared_ptr<CleanupState> cleanup_state_;
    std::shared_ptr<SettlementReceipt> settlement_;
};

}  // namespace rut::test::fixture_wildcard_paused_child_lease
