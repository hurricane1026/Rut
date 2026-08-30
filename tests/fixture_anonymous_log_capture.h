#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <sys/types.h>

namespace rut::test::fixture_anonymous_log_capture {

// Keep this local to the generic capture fixture. It is deliberately equal to
// the existing collision-log bound (4096), but has no listener dependency.
inline constexpr std::size_t kMaxCaptureBytes = 4096u;

enum class FailurePhase : std::uint8_t {
    None,
    Argument,
    Syscall,
    Identity,
    Capacity,
    Offset,
    Read,
    Seal,
    Close,
};

struct Diagnostic {
    FailurePhase phase = FailurePhase::None;
    int error_number = 0;
};

// This state intentionally outlives the lease when retained by a test. close()
// takes ownership of the descriptor out of the object before invoking close(2),
// so an EINTR/other error is recorded but never retried against an uncertain FD.
struct CleanupState {
    bool attempted = false;
    bool succeeded = false;
    Diagnostic diagnostic;
};

struct Identity {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t mode = 0u;
    std::uint64_t uid = 0u;
    std::uint64_t gid = 0u;
};

using PreadForTesting = ssize_t (*)(int fd, void* buffer, std::size_t count, off_t offset);
using CloseForTesting = int (*)(int fd);

struct HooksForTesting {
    PreadForTesting pread = nullptr;
    CloseForTesting close = nullptr;
};

// A move-only, anonymous bounded stdout/stderr sink. The descriptor returned
// by descriptor() is one shared open-file-description: dup2() in a child can
// attach both stdout and stderr, and sequential writes advance one offset.
class AnonymousLogCapture {
public:
    AnonymousLogCapture();
    ~AnonymousLogCapture();

    AnonymousLogCapture(const AnonymousLogCapture&) = delete;
    AnonymousLogCapture& operator=(const AnonymousLogCapture&) = delete;
    AnonymousLogCapture(AnonymousLogCapture&& other) noexcept;
    // Assignment is deliberately prohibited: callers must explicitly close
    // the destination before moving another lease into a fresh object.
    AnonymousLogCapture& operator=(AnonymousLogCapture&&) = delete;

    static bool create(std::size_t max_bytes, AnonymousLogCapture& capture, Diagnostic& diagnostic);
    static bool create_with_hooks_for_testing(std::size_t max_bytes,
                                              const HooksForTesting& hooks,
                                              AnonymousLogCapture& capture,
                                              Diagnostic& diagnostic);

    bool active() const { return fd_ >= 0; }
    bool settled() const { return settled_; }
    int descriptor() const { return fd_; }
    std::size_t max_bytes() const { return max_bytes_; }
    const Identity& identity() const { return identity_; }
    std::shared_ptr<const CleanupState> cleanup_state() const { return cleanup_state_; }

    // Reads [0,current-offset) without changing the shared writer offset.
    // A snapshot is bounded by the offset observed at its start.
    bool snapshot(std::string& bytes, Diagnostic& diagnostic) const;
    bool snapshot_at_offset_for_testing(off_t offset,
                                        std::string& bytes,
                                        PreadForTesting operation,
                                        Diagnostic& diagnostic) const;

    // Revalidates immutable identity, fixed capacity and current offset, then
    // seals writes permanently. Call only after all writers have settled.
    bool settle(Diagnostic& diagnostic);

    // Explicit close is observable through cleanup_state(). Ownership is
    // removed before close(2), and close errors are not retried.
    bool close(Diagnostic& diagnostic);

private:
    static bool create_impl(std::size_t max_bytes,
                            const HooksForTesting* hooks,
                            AnonymousLogCapture& capture,
                            Diagnostic& diagnostic);

    bool validate_identity_and_capacity(Diagnostic& diagnostic) const;
    bool validate_offset(off_t offset, Diagnostic& diagnostic) const;
    bool snapshot_at_offset(off_t offset,
                            std::string& bytes,
                            PreadForTesting operation,
                            Diagnostic& diagnostic) const;
    void record_cleanup(bool succeeded, const Diagnostic& diagnostic);
    bool close_owned(CloseForTesting operation, Diagnostic& diagnostic);

    int fd_ = -1;
    std::size_t max_bytes_ = 0u;
    Identity identity_;
    std::shared_ptr<CleanupState> cleanup_state_;
    PreadForTesting pread_for_testing_ = nullptr;
    CloseForTesting close_for_testing_ = nullptr;
    bool settled_ = false;
};

}  // namespace rut::test::fixture_anonymous_log_capture
