#include "fixture_executable_exec_handoff.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace handoff = rut::test::fixture_executable_exec_handoff;
namespace executable = rut::test::fixture_executable_lease;
namespace child_fixture = rut::test::fixture_wildcard_paused_child_lease;

namespace {

[[noreturn]] void live_exec_helper() {
    for (;;) pause();
}

bool canonical_self(std::string& path) {
    char resolved[PATH_MAX]{};
    if (realpath("/proc/self/exe", resolved) == nullptr) return false;
    path = resolved;
    return !path.empty();
}

int create_capture() {
#ifdef MFD_CLOEXEC
    return memfd_create("rut-exec-handoff-output", MFD_CLOEXEC);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int open_fd_count() {
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return -1;
    const int own_fd = dirfd(directory);
    int count = 0;
    while (const dirent* entry = readdir(directory)) {
        char* end = nullptr;
        const long value = std::strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && value >= 0 && value != own_fd) ++count;
    }
    if (closedir(directory) != 0) return -1;
    return count;
}

std::vector<int> fd_snapshot() {
    std::vector<int> snapshot;
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return snapshot;
    const int own_fd = dirfd(directory);
    while (const dirent* entry = readdir(directory)) {
        char* end = nullptr;
        const long value = std::strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && value >= 0 && value != own_fd)
            snapshot.push_back(static_cast<int>(value));
    }
    if (closedir(directory) != 0) return {};
    std::sort(snapshot.begin(), snapshot.end());
    return snapshot;
}

std::array<int, 6> status_slots(const handoff::ExecutableExecHandoffLease& lease);

std::string encoded_arguments(std::span<const std::string_view> arguments) {
    std::string encoded;
    for (const std::string_view argument : arguments) {
        if (!argument.empty()) encoded.append(argument.data(), argument.size());
        encoded.push_back('\0');
    }
    return encoded;
}

bool plan_arguments_equal(const child_fixture::ChildDescriptorPlan& plan,
                          std::span<const std::string_view> arguments) {
    const auto& packed = plan.continuation.arguments;
    const std::string expected = encoded_arguments(arguments);
    if (packed.argc != arguments.size() || packed.encoded_bytes != expected.size() ||
        (expected.size() != 0 &&
         std::memcmp(packed.arena.data(), expected.data(), expected.size()) != 0))
        return false;
    std::size_t offset = 0;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        if (packed.offsets[index] != offset) return false;
        offset += arguments[index].size() + 1;
    }
    return packed.offsets[arguments.size()] == offset;
}

bool legacy_inert_prepared_stdin_cloexec_case() {
    const int original_flags = fcntl(STDIN_FILENO, F_GETFD);
    const int output = create_capture();
    if (original_flags < 0 || output < 0 ||
        fcntl(STDIN_FILENO, F_SETFD, original_flags | FD_CLOEXEC) != 0)
        return false;
    child_fixture::ChildDescriptorPlan plan;
    plan.combined_output_fd = output;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    const bool created =
        child_fixture::PausedChildLease::create_prepared(deadline, plan, child, diagnostic);
    const bool validated = created && child.validate_prepared(deadline, diagnostic);
    const bool released = validated && child.release(deadline, diagnostic);
    const bool restored = fcntl(STDIN_FILENO, F_SETFD, original_flags) == 0;
    const bool output_closed = close(output) == 0;
    return created && validated && released && restored && output_closed;
}

bool run_live_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;

    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    if (input < 0 || output < 0) return false;
    child_fixture::ChildDescriptorPlan plan;
    if (!handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic))
        return false;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    if (!child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ExecObservedLive)
        return false;
    if (handoff_lease.close(handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Settlement)
        return false;
    if (!child.cleanup(deadline, child_diagnostic)) return false;
    if (!handoff_lease.close(handoff_diagnostic)) return false;
    const auto evidence = handoff_lease.cleanup_state();
    if (!evidence || evidence->semantic_attempts != 1 || !evidence->semantic_validated ||
        evidence->status_attempts != 1 || !evidence->status_observed ||
        evidence->status_outcome != handoff::ExecOutcome::ExecObservedLive ||
        evidence->release_close_attempts != 1 || !evidence->release_close_succeeded ||
        evidence->cleanup_attempts != 2 || !evidence->cleanup_succeeded)
        return false;
    if (!source.close(source_diagnostic)) return false;
    const bool closed = close(input) == 0 && close(output) == 0;
    return closed;
}

bool run_pre_exec_failure_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, true, plan, handoff_diagnostic))
        return false;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    if (!child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::PreExecFailure ||
        observation.error_number != EIO)
        return false;
    // release() remains the sole wait/reap owner after the send seam.  The
    // injected nonzero child status is expected and independently auditable.
    if (child.release(deadline, child_diagnostic)) return false;
    if (!child.cleanup(deadline, child_diagnostic)) return false;
    if (!handoff_lease.close(handoff_diagnostic)) {
        std::fprintf(stderr,
                     "external handoff close phase=%u errno=%d\n",
                     static_cast<unsigned>(handoff_diagnostic.phase),
                     handoff_diagnostic.error_number);
        return false;
    }
    if (!source.close(source_diagnostic)) {
        std::fprintf(stderr,
                     "external source close phase=%u errno=%d\n",
                     static_cast<unsigned>(source_diagnostic.phase),
                     source_diagnostic.error_number);
        return false;
    }
    const int input_close = close(input);
    const int input_error = errno;
    const int output_close = close(output);
    if (input_close != 0 || output_close != 0)
        std::fprintf(stderr,
                     "external borrowed close input=%d/%d output=%d/%d\n",
                     input_close,
                     input_error,
                     output_close,
                     errno);
    return input_close == 0 && output_close == 0;
}

bool direct_exec_release_requires_authorization_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    if (child.send_release(deadline, child_diagnostic) !=
            child_fixture::ReleaseSendState::NotSent ||
        child_diagnostic.phase != child_fixture::FailurePhase::Release ||
        child_diagnostic.error_number != EPERM ||
        !child.validate_prepared(deadline, child_diagnostic) ||
        child.release(deadline, child_diagnostic) ||
        child_diagnostic.phase != child_fixture::FailurePhase::Release ||
        child_diagnostic.error_number != EPERM ||
        !child.validate_prepared(deadline, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ExecObservedLive ||
        !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool run_status_injection(std::uint8_t injection, handoff::ExecOutcome expected) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    handoff::HooksForTesting hooks;
    hooks.child_status_injection = injection;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic))
        return false;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
    if (!child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != expected) {
        std::fprintf(stderr,
                     "observe got=%u expected=%u phase=%u errno=%d\n",
                     static_cast<unsigned>(observation.outcome),
                     static_cast<unsigned>(expected),
                     static_cast<unsigned>(handoff_diagnostic.phase),
                     handoff_diagnostic.error_number);
        return false;
    }
    const auto cleanup_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    if (expected != handoff::ExecOutcome::Timeout &&
        child.release(cleanup_deadline, child_diagnostic))
        return false;
    if (!child.cleanup(cleanup_deadline, child_diagnostic)) {
        std::fprintf(stderr,
                     "cleanup phase=%u errno=%d\n",
                     static_cast<unsigned>(child_diagnostic.phase),
                     child_diagnostic.error_number);
        return false;
    }
    if (!handoff_lease.close(handoff_diagnostic)) {
        std::fprintf(stderr,
                     "handoff close phase=%u errno=%d\n",
                     static_cast<unsigned>(handoff_diagnostic.phase),
                     handoff_diagnostic.error_number);
        return false;
    }
    if (!source.close(source_diagnostic)) return false;
    return close(input) == 0 && close(output) == 0;
}

int deny_cross_process(pid_t first, pid_t second, int, int, void*) {
    if (first != second) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

bool run_cross_kcmp_denial_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    handoff::HooksForTesting hooks;
    hooks.kcmp_file = deny_cross_process;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Child)
        return false;
    if (!child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

struct CloseOnceContext {
    bool failed = false;
};

struct TargetCloseContext {
    int target = -1;
    bool failed = false;
};

int target_close_uncertain(int fd, void* opaque) {
    auto& context = *static_cast<TargetCloseContext*>(opaque);
    const int result = close(fd);
    if (fd == context.target && !context.failed) {
        context.failed = true;
        errno = EINTR;
        return -1;
    }
    return result;
}

struct FailSecondCloseContext {
    unsigned int calls = 0;
};

int close_second_uncertain(int fd, void* opaque) {
    auto& context = *static_cast<FailSecondCloseContext*>(opaque);
    ++context.calls;
    const int result = close(fd);
    if (context.calls == 2) {
        errno = EINTR;
        return -1;
    }
    return result;
}

int close_once_uncertain(int fd, void* opaque) {
    auto& context = *static_cast<CloseOnceContext*>(opaque);
    const int result = close(fd);
    if (!context.failed) {
        context.failed = true;
        errno = EINTR;
        return -1;
    }
    return result;
}

bool run_writer_close_uncertainty_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    CloseOnceContext close_context;
    handoff::HooksForTesting hooks;
    hooks.close_fd = close_once_uncertain;
    hooks.context = &close_context;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Close)
        return false;
    if (!child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool run_release_close_uncertainty_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, true, plan, handoff_diagnostic))
        return false;
    FailSecondCloseContext close_context;
    child_fixture::HooksForTesting child_hooks;
    child_hooks.close_fd = close_second_uncertain;
    child_hooks.close_context = &close_context;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (!child_fixture::PausedChildLease::create_prepared_with_hooks_for_testing(
            deadline, plan, child_hooks, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::PreExecFailure ||
        observation.error_number != EIO) {
        std::fprintf(stderr,
                     "release uncertainty observe phase=%u errno=%d calls=%u\n",
                     static_cast<unsigned>(handoff_diagnostic.phase),
                     handoff_diagnostic.error_number,
                     close_context.calls);
        return false;
    }
    // The byte was sent, but reportable success is permanently forbidden by
    // the detached uncertain release-writer close.  The legacy wrapper still
    // performs the actual waitpid settlement.
    if (child.release(deadline, child_diagnostic) || !child.active() || child.released()) {
        std::fprintf(
            stderr,
            "release uncertainty settle phase=%u errno=%d active=%d released=%d calls=%u\n",
            static_cast<unsigned>(child_diagnostic.phase),
            child_diagnostic.error_number,
            child.active(),
            child.released(),
            close_context.calls);
        return false;
    }
    const auto receipt = child.settlement_receipt();
    if (!receipt || !receipt->terminal || !receipt->reaped) return false;
    if (!child.cleanup(deadline, child_diagnostic)) return false;
    const auto evidence = handoff_lease.cleanup_state();
    if (!evidence ||
        evidence->child_release_send_state != child_fixture::ReleaseSendState::SentCloseUncertain ||
        !evidence->status_observed ||
        evidence->status_outcome != handoff::ExecOutcome::PreExecFailure)
        return false;
    if (!handoff_lease.close(handoff_diagnostic) || !source.close(source_diagnostic)) return false;
    return close(input) == 0 && close(output) == 0;
}

bool status_slot_close_uncertainty_case(unsigned int slot_index) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    TargetCloseContext close_context;
    handoff::HooksForTesting hooks;
    hooks.close_fd = target_close_uncertain;
    hooks.context = &close_context;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    const auto slots = status_slots(handoff_lease);
    close_context.target = slots[slot_index];
    handoff::ExecObservation observation;
    if (slot_index >= 3) {
        if (handoff_lease.release_and_observe(
                source, child, deadline, observation, handoff_diagnostic) ||
            handoff_diagnostic.phase != handoff::FailurePhase::Close ||
            !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic))
            return false;
    } else {
        if (!handoff_lease.release_and_observe(
                source, child, deadline, observation, handoff_diagnostic) ||
            observation.outcome != handoff::ExecOutcome::ExecObservedLive ||
            !child.cleanup(deadline, child_diagnostic) || handoff_lease.close(handoff_diagnostic) ||
            handoff_diagnostic.phase != handoff::FailurePhase::Close)
            return false;
    }
    const auto evidence = handoff_lease.cleanup_state();
    const auto& outcome = slot_index < 3 ? evidence->status_reader_close[slot_index]
                                         : evidence->status_writer_close[slot_index - 3];
    if (!close_context.failed || !outcome.attempted || outcome.succeeded ||
        outcome.error_number != EINTR)
        return false;
    if (slot_index < 3 && (!evidence->status_observed ||
                           evidence->status_outcome != handoff::ExecOutcome::ExecObservedLive))
        return false;
    if (!source.close(source_diagnostic)) return false;
    return close(input) == 0 && close(output) == 0;
}

bool run_external_exec_case(const std::string& path,
                            handoff::ExecOutcome expected,
                            int expected_errno,
                            unsigned int post_eof_delay_ms = 0) {
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(path, source, source_diagnostic)) {
        std::fprintf(stderr,
                     "external source create phase=%u errno=%d path=%s\n",
                     static_cast<unsigned>(source_diagnostic.phase),
                     source_diagnostic.error_number,
                     path.c_str());
        return false;
    }
    handoff::HooksForTesting hooks;
    hooks.post_eof_delay_ms = post_eof_delay_ms;
    if (!handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic)) {
        std::fprintf(stderr,
                     "external handoff create phase=%u errno=%d\n",
                     static_cast<unsigned>(handoff_diagnostic.phase),
                     handoff_diagnostic.error_number);
        return false;
    }
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != expected ||
        (expected_errno != 0 && observation.error_number != expected_errno)) {
        std::fprintf(stderr,
                     "external observe got=%u expected=%u errno=%d phase=%u\n",
                     static_cast<unsigned>(observation.outcome),
                     static_cast<unsigned>(expected),
                     observation.error_number,
                     static_cast<unsigned>(handoff_diagnostic.phase));
        return false;
    }
    const bool ordinary_success = child.release(deadline, child_diagnostic);
    if (expected == handoff::ExecOutcome::EarlyDeath) {
        if (!ordinary_success) {
            std::fprintf(stderr,
                         "external release phase=%u errno=%d\n",
                         static_cast<unsigned>(child_diagnostic.phase),
                         child_diagnostic.error_number);
            return false;
        }
    } else {
        if (ordinary_success || !child.cleanup(deadline, child_diagnostic)) return false;
    }
    if (!handoff_lease.close(handoff_diagnostic)) {
        std::fprintf(stderr,
                     "external handoff close phase=%u errno=%d\n",
                     static_cast<unsigned>(handoff_diagnostic.phase),
                     handoff_diagnostic.error_number);
        return false;
    }
    if (!source.close(source_diagnostic)) return false;
    const int input_close = close(input);
    const int input_error = errno;
    const int output_close = close(output);
    if (input_close != 0 || output_close != 0)
        std::fprintf(stderr,
                     "external borrowed close input=%d/%d output=%d/%d\n",
                     input_close,
                     input_error,
                     output_close,
                     errno);
    return input_close == 0 && output_close == 0;
}

bool run_real_shebang_enoent_case() {
    char path[] = "/tmp/rut-exec-handoff-script-XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) return false;
    constexpr char contents[] = "#!/definitely/missing/rut-interpreter\n";
    const bool prepared =
        write(fd, contents, sizeof(contents) - 1) == static_cast<ssize_t>(sizeof(contents) - 1) &&
        fchmod(fd, 0700) == 0 && close(fd) == 0;
    const bool result =
        prepared && run_external_exec_case(path, handoff::ExecOutcome::ExecFailure, ENOENT);
    const bool removed = unlink(path) == 0;
    return result && removed;
}

bool run_fast_death_case() {
    const char* source_path = access("/usr/bin/true", R_OK) == 0 ? "/usr/bin/true" : "/bin/true";
    const int source = open(source_path, O_RDONLY | O_CLOEXEC);
    char path[] = "/tmp/rut-exec-handoff-true-XXXXXX";
    const int destination = mkstemp(path);
    bool copied = source >= 0 && destination >= 0;
    char buffer[16384];
    while (copied) {
        const ssize_t count = read(source, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            copied = false;
            break;
        }
        std::size_t offset = 0;
        while (offset < static_cast<std::size_t>(count)) {
            const ssize_t written =
                write(destination, buffer + offset, static_cast<std::size_t>(count) - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) {
                copied = false;
                break;
            }
            offset += static_cast<std::size_t>(written);
        }
    }
    copied = copied && fchmod(destination, 0700) == 0;
    if (source >= 0) copied = close(source) == 0 && copied;
    if (destination >= 0) copied = close(destination) == 0 && copied;
    const bool result =
        copied && run_external_exec_case(path, handoff::ExecOutcome::EarlyDeath, 0, 50);
    const bool removed = unlink(path) == 0;
    return result && removed;
}

enum class SlotMutation : std::uint8_t { SameInodeNewOfd, DifferentObject, ClearCloexec };

bool run_handoff_slot_restore_case(unsigned int slot_index, SlotMutation mutation) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    const int slot = slot_index == 0   ? handoff_lease.observation_fd()
                     : slot_index == 1 ? handoff_lease.authority_one_fd_for_testing()
                                       : handoff_lease.authority_two_fd_for_testing();
    const int backup = fcntl(slot, F_DUPFD_CLOEXEC, 3);
    if (backup < 0) return false;
    int replacement = -1;
    if (mutation == SlotMutation::SameInodeNewOfd)
        replacement = open(self.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
    else if (mutation == SlotMutation::DifferentObject)
        replacement = open("/dev/null", O_PATH | O_CLOEXEC);
    if ((replacement >= 0 && dup3(replacement, slot, O_CLOEXEC) != slot) ||
        (mutation == SlotMutation::ClearCloexec && fcntl(slot, F_SETFD, 0) != 0))
        return false;
    handoff::ExecObservation observation;
    const auto expected_phase = slot_index == 0 && mutation != SlotMutation::ClearCloexec
                                    ? handoff::FailurePhase::Source
                                    : handoff::FailurePhase::Custody;
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != expected_phase)
        return false;
    if (dup3(backup, slot, O_CLOEXEC) != slot) return false;
    if (replacement >= 0 && close(replacement) != 0) return false;
    if (close(backup) != 0) return false;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ExecObservedLive)
        return false;
    if (!child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

std::array<int, 6> status_slots(const handoff::ExecutableExecHandoffLease& lease) {
    return {lease.status_reader_fd_for_testing(),
            lease.status_reader_authority_one_fd_for_testing(),
            lease.status_reader_authority_two_fd_for_testing(),
            lease.status_writer_fd_for_testing(),
            lease.status_writer_authority_one_fd_for_testing(),
            lease.status_writer_authority_two_fd_for_testing()};
}

bool explicit_status_foreign_slot_restore_case(unsigned int slot_index) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    const auto slots = status_slots(handoff_lease);
    const int selected = slots[slot_index];
    const int backup = fcntl(selected, F_DUPFD_CLOEXEC, 3);
    const int replacement = open("/dev/null", (slot_index < 3 ? O_RDONLY : O_WRONLY) | O_CLOEXEC);
    if (backup < 0 || replacement < 0 || dup3(replacement, selected, O_CLOEXEC) != selected)
        return false;
    handoff::ExecObservation observation;
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Custody ||
        !child.cleanup(deadline, child_diagnostic))
        return false;
    if (handoff_lease.close(handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Custody)
        return false;
    for (const int slot : slots)
        if (fcntl(slot, F_GETFD) < 0) return false;
    if (dup3(backup, selected, O_CLOEXEC) != selected || close(backup) != 0 ||
        close(replacement) != 0 || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool destructor_status_foreign_slot_case(unsigned int slot_index) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    int input = -1;
    int output = -1;
    std::array<int, 6> slots{};
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic handoff_diagnostic;
        handoff::HooksForTesting hooks;
        hooks.kcmp_file = deny_cross_process;
        if (!handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
                source, hooks, handoff_lease, handoff_diagnostic))
            return false;
        input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        output = create_capture();
        child_fixture::ChildDescriptorPlan plan;
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
        if (input < 0 || output < 0 ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
            !child_fixture::PausedChildLease::create_prepared(
                deadline, plan, child, child_diagnostic))
            return false;
        handoff::ExecObservation observation;
        if (handoff_lease.release_and_observe(
                source, child, deadline, observation, handoff_diagnostic) ||
            handoff_diagnostic.phase != handoff::FailurePhase::Child ||
            !child.cleanup(deadline, child_diagnostic))
            return false;
        slots = status_slots(handoff_lease);
        const int replacement =
            open("/dev/null", (slot_index < 3 ? O_RDONLY : O_WRONLY) | O_CLOEXEC);
        if (replacement < 0 ||
            dup3(replacement, slots[slot_index], O_CLOEXEC) != slots[slot_index] ||
            close(replacement) != 0)
            return false;
    }
    bool result = fcntl(slots[slot_index], F_GETFD) >= 0;
    for (unsigned int index = 0; index < slots.size(); ++index) {
        if (index == slot_index) continue;
        errno = 0;
        result = result && fcntl(slots[index], F_GETFD) < 0 && errno == EBADF;
    }
    result = close(slots[slot_index]) == 0 && close(input) == 0 && close(output) == 0 &&
             source.close(source_diagnostic) && result;
    return result;
}

bool destructor_status_no_majority_case(bool writer_triad) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    int input = -1;
    int output = -1;
    std::array<int, 6> slots{};
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic handoff_diagnostic;
        handoff::HooksForTesting hooks;
        hooks.kcmp_file = deny_cross_process;
        if (!handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
                source, hooks, handoff_lease, handoff_diagnostic))
            return false;
        input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        output = create_capture();
        child_fixture::ChildDescriptorPlan plan;
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
        if (input < 0 || output < 0 ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
            !child_fixture::PausedChildLease::create_prepared(
                deadline, plan, child, child_diagnostic))
            return false;
        handoff::ExecObservation observation;
        if (handoff_lease.release_and_observe(
                source, child, deadline, observation, handoff_diagnostic) ||
            !child.cleanup(deadline, child_diagnostic))
            return false;
        slots = status_slots(handoff_lease);
        const unsigned int begin = writer_triad ? 3u : 0u;
        for (unsigned int index = begin; index < begin + 3; ++index) {
            const int replacement =
                open("/dev/null", (writer_triad ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
            if (replacement < 0 || dup3(replacement, slots[index], O_CLOEXEC) != slots[index] ||
                close(replacement) != 0)
                return false;
        }
    }
    const unsigned int begin = writer_triad ? 3u : 0u;
    bool result = true;
    for (unsigned int index = 0; index < slots.size(); ++index) {
        errno = 0;
        if (index >= begin && index < begin + 3)
            result = result && fcntl(slots[index], F_GETFD) >= 0;
        else
            result = result && fcntl(slots[index], F_GETFD) < 0 && errno == EBADF;
    }
    for (unsigned int index = begin; index < begin + 3; ++index)
        result = close(slots[index]) == 0 && result;
    result = close(input) == 0 && close(output) == 0 && source.close(source_diagnostic) && result;
    return result;
}

bool child_executable_mutation_rejected(std::uint8_t mutation) {
    const pid_t subprocess = fork();
    if (subprocess < 0) return false;
    if (subprocess == 0) {
        std::string self;
        executable::ExecutableLease source;
        executable::Diagnostic source_diagnostic;
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic handoff_diagnostic;
        handoff::HooksForTesting hooks;
        hooks.child_executable_mutation = mutation;
        if (!canonical_self(self) ||
            !executable::ExecutableLease::create(self, source, source_diagnostic) ||
            !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
                source, hooks, handoff_lease, handoff_diagnostic))
            _exit(2);
        const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        const int output = create_capture();
        child_fixture::ChildDescriptorPlan plan;
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        if (input < 0 || output < 0 ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic))
            _exit(3);
        const bool created = child_fixture::PausedChildLease::create_prepared(
            deadline, plan, child, child_diagnostic);
        _exit(!created && child_diagnostic.phase == child_fixture::FailurePhase::Descriptors ? 0
                                                                                             : 4);
    }
    int status = 0;
    while (waitpid(subprocess, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool altered_status_plan_rejected(bool alter_child_writer) {
    const pid_t subprocess = fork();
    if (subprocess < 0) return false;
    if (subprocess == 0) {
        std::string self;
        executable::ExecutableLease source;
        executable::Diagnostic source_diagnostic;
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic handoff_diagnostic;
        if (!canonical_self(self) ||
            !executable::ExecutableLease::create(self, source, source_diagnostic) ||
            !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
            _exit(2);
        const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        const int output = create_capture();
        child_fixture::ChildDescriptorPlan plan;
        if (input < 0 || output < 0 ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic))
            _exit(3);
        int foreign[2] = {-1, -1};
        if (pipe2(foreign, O_CLOEXEC) != 0) _exit(4);
        if (alter_child_writer)
            plan.exec_status_fd = foreign[1];
        else
            plan.exec_status_authority_fd = foreign[1];
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        const bool created = child_fixture::PausedChildLease::create_prepared(
            deadline, plan, child, child_diagnostic);
        _exit(!created && child_diagnostic.phase == child_fixture::FailurePhase::Descriptors ? 0
                                                                                             : 5);
    }
    int status = 0;
    while (waitpid(subprocess, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool source_pre_release_revalidation_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    const int source_slot = source.observation_fd();
    const int backup = fcntl(source_slot, F_DUPFD_CLOEXEC, 3);
    const int replacement = open(self.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (backup < 0 || replacement < 0 || dup3(replacement, source_slot, O_CLOEXEC) != source_slot)
        return false;
    handoff::ExecObservation observation;
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Source)
        return false;
    if (dup3(backup, source_slot, O_CLOEXEC) != source_slot || close(backup) != 0 ||
        close(replacement) != 0)
        return false;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ExecObservedLive)
        return false;
    if (!child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool wrong_source_exact_ofd_rejected_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::ExecutableLease wrong_source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !executable::ExecutableLease::create(self, wrong_source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (handoff_lease.release_and_observe(
            wrong_source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Source ||
        !child.validate_prepared(deadline, child_diagnostic))
        return false;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ExecObservedLive ||
        !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !wrong_source.close(source_diagnostic) || !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool deny_proc_snapshot(void*) {
    return false;
}

bool unstable_proc_never_live_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    handoff::HooksForTesting hooks;
    hooks.proc_snapshot_allowed = deny_proc_snapshot;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ProtocolFailure)
        return false;
    if (!child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool destructor_majority_case(bool unique_majority) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    int slots[3] = {-1, -1, -1};
    int status_reader = -1;
    int input = -1;
    int output = -1;
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic handoff_diagnostic;
        if (!handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
            return false;
        input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        output = create_capture();
        child_fixture::ChildDescriptorPlan plan;
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
        if (input < 0 || output < 0 ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
            !child_fixture::PausedChildLease::create_prepared(
                deadline, plan, child, child_diagnostic))
            return false;
        handoff::ExecObservation observation;
        if (!handoff_lease.release_and_observe(
                source, child, deadline, observation, handoff_diagnostic) ||
            observation.outcome != handoff::ExecOutcome::ExecObservedLive ||
            !child.cleanup(deadline, child_diagnostic))
            return false;
        slots[0] = handoff_lease.observation_fd();
        slots[1] = handoff_lease.authority_one_fd_for_testing();
        slots[2] = handoff_lease.authority_two_fd_for_testing();
        status_reader = handoff_lease.status_reader_fd_for_testing();
        const char* replacements[3] = {"/dev/null", "/dev/zero", "/dev/full"};
        const unsigned int replace_count = unique_majority ? 1u : 3u;
        for (unsigned int index = 0; index < replace_count; ++index) {
            const int replacement = open(replacements[index], O_PATH | O_CLOEXEC);
            if (replacement < 0 || dup3(replacement, slots[index], O_CLOEXEC) != slots[index] ||
                close(replacement) != 0)
                return false;
        }
    }
    bool result = fcntl(slots[0], F_GETFD) >= 0;
    if (unique_majority) {
        errno = 0;
        result = result && fcntl(slots[1], F_GETFD) < 0 && errno == EBADF;
        errno = 0;
        result = result && fcntl(slots[2], F_GETFD) < 0 && errno == EBADF;
        errno = 0;
        result = result && fcntl(status_reader, F_GETFD) < 0 && errno == EBADF;
        result = close(slots[0]) == 0 && result;
    } else {
        result = result && fcntl(slots[1], F_GETFD) >= 0 && fcntl(slots[2], F_GETFD) >= 0 &&
                 fcntl(status_reader, F_GETFD) < 0 && errno == EBADF;
        result = close(slots[0]) == 0 && close(slots[1]) == 0 && close(slots[2]) == 0 && result;
    }
    result = close(input) == 0 && close(output) == 0 && source.close(source_diagnostic) && result;
    return result;
}

bool pack_acceptance_case(const std::vector<std::string_view>& arguments) {
    std::string self;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!canonical_self(self) || arguments.empty() || arguments.front() != self ||
        !executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    const bool packed =
        input >= 0 && output >= 0 &&
        handoff_lease.make_child_plan_with_arguments(
            input, output, false, arguments, plan, handoff_diagnostic) &&
        plan_arguments_equal(plan, arguments) &&
        child_fixture::validate_bounded_exec_arguments(plan.continuation.arguments, self);
    const bool closed = packed && handoff_lease.close(handoff_diagnostic) &&
                        source.close(source_diagnostic) && close(input) == 0 && close(output) == 0;
    return closed;
}

bool argument_pack_limits_case() {
    std::string self;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic diagnostic;
    if (!canonical_self(self) ||
        !executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    if (input < 0 || output < 0) return false;
    const auto baseline = fd_snapshot();
    child_fixture::ChildDescriptorPlan plan;
    const std::array<std::string_view, 0> none{};
    if (handoff_lease.make_child_plan_with_arguments(
            input, output, false, none, plan, diagnostic) ||
        diagnostic.phase != handoff::FailurePhase::Argument || fd_snapshot() != baseline)
        return false;
    std::array<std::string_view, 10> ten{};
    ten.fill("x");
    ten[0] = self;
    if (handoff_lease.make_child_plan_with_arguments(input, output, false, ten, plan, diagnostic) ||
        diagnostic.error_number != E2BIG || fd_snapshot() != baseline)
        return false;
    for (const std::string_view bad_argv0 :
         {std::string_view{}, std::string_view{"relative"}, std::string_view{"/different"}}) {
        const std::array arguments = {bad_argv0};
        if (handoff_lease.make_child_plan_with_arguments(
                input, output, false, arguments, plan, diagnostic) ||
            diagnostic.error_number != EINVAL || fd_snapshot() != baseline)
            return false;
    }
    const std::string embedded("a\0b", 3);
    const std::array embedded_arguments = {std::string_view{self}, std::string_view{embedded}};
    if (handoff_lease.make_child_plan_with_arguments(
            input, output, false, embedded_arguments, plan, diagnostic) ||
        diagnostic.error_number != EINVAL || fd_snapshot() != baseline)
        return false;
    const std::string embedded_argv0 = self + std::string("\0tail", 5);
    const std::array bad_argv0_nul = {std::string_view{embedded_argv0}};
    if (handoff_lease.make_child_plan_with_arguments(
            input, output, false, bad_argv0_nul, plan, diagnostic) ||
        diagnostic.error_number != EINVAL || fd_snapshot() != baseline)
        return false;
    const std::string too_long(4096, 'x');
    const std::array too_long_arguments = {std::string_view{self}, std::string_view{too_long}};
    if (handoff_lease.make_child_plan_with_arguments(
            input, output, false, too_long_arguments, plan, diagnostic) ||
        diagnostic.error_number != E2BIG || fd_snapshot() != baseline)
        return false;

    const std::size_t argv0_encoded = self.size() + 1;
    if (argv0_encoded >= 4096) return false;
    const std::string first(4095, 'a');
    const std::size_t exact_tail_encoded = 8192 - argv0_encoded - 4096;
    if (exact_tail_encoded == 0 || exact_tail_encoded > 4096) return false;
    const std::string exact_tail(exact_tail_encoded - 1, 'b');
    const std::string over_tail(exact_tail_encoded, 'b');
    const std::array over_total = {
        std::string_view{self}, std::string_view{first}, std::string_view{over_tail}};
    if (handoff_lease.make_child_plan_with_arguments(
            input, output, false, over_total, plan, diagnostic) ||
        diagnostic.error_number != E2BIG || fd_snapshot() != baseline)
        return false;

    const std::array exact_total = {
        std::string_view{self}, std::string_view{first}, std::string_view{exact_tail}};
    const bool packed = handoff_lease.make_child_plan_with_arguments(
                            input, output, false, exact_total, plan, diagnostic) &&
                        plan.continuation.arguments.encoded_bytes == 8192 &&
                        plan_arguments_equal(plan, exact_total);
    return packed && handoff_lease.close(diagnostic) && source.close(source_diagnostic) &&
           close(input) == 0 && close(output) == 0;
}

bool owned_argument_bytes_case() {
    std::string self;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic diagnostic;
    if (!canonical_self(self) ||
        !executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    std::string expected;
    {
        std::string poisonable = "owned-value";
        std::string_view null_empty;
        const std::array arguments = {
            std::string_view{self}, std::string_view{poisonable}, null_empty, std::string_view{""}};
        expected = encoded_arguments(arguments);
        if (input < 0 || output < 0 ||
            !handoff_lease.make_child_plan_with_arguments(
                input, output, false, arguments, plan, diagnostic))
            return false;
        poisonable.assign(poisonable.size(), 'z');
    }
    const auto& packed = plan.continuation.arguments;
    const bool owned = packed.encoded_bytes == expected.size() &&
                       std::memcmp(packed.arena.data(), expected.data(), expected.size()) == 0;
    return owned && handoff_lease.close(diagnostic) && source.close(source_diagnostic) &&
           close(input) == 0 && close(output) == 0;
}

using ArgumentMutation = void (*)(child_fixture::ChildContinuation&);

void mutate_argc(child_fixture::ChildContinuation& continuation) {
    continuation.arguments.argc = 0;
}
void mutate_encoded(child_fixture::ChildContinuation& continuation) {
    --continuation.arguments.encoded_bytes;
}
void mutate_offset_zero(child_fixture::ChildContinuation& continuation) {
    continuation.arguments.offsets[0] = 1;
}
void mutate_boundary(child_fixture::ChildContinuation& continuation) {
    continuation.arguments.offsets[1] = 0;
}
void mutate_terminal_offset(child_fixture::ChildContinuation& continuation) {
    --continuation.arguments.offsets[continuation.arguments.argc];
}
void mutate_terminal_nul(child_fixture::ChildContinuation& continuation) {
    continuation.arguments.arena[continuation.arguments.encoded_bytes - 1] = 'x';
}
void mutate_early_nul(child_fixture::ChildContinuation& continuation) {
    continuation.arguments.arena[continuation.arguments.offsets[1]] = '\0';
}
void mutate_active_arena(child_fixture::ChildContinuation& continuation) {
    continuation.arguments.arena[continuation.arguments.offsets[1]] ^= 1;
}

bool argument_mutation_rejected_and_retry_case(ArgumentMutation mutation, bool through_hook) {
    std::string self;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!canonical_self(self) ||
        !executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    const std::array arguments = {
        std::string_view{self}, std::string_view{"argument"}, std::string_view{"tail"}};
    child_fixture::ChildDescriptorPlan original;
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan_with_arguments(
            input, output, false, arguments, original, handoff_diagnostic))
        return false;
    child_fixture::ChildDescriptorPlan changed = original;
    child_fixture::HooksForTesting hooks;
    if (through_hook) {
        hooks.pre_fork_continuation_mutation = [](child_fixture::ChildContinuation& continuation,
                                                  void* opaque) {
            (*static_cast<ArgumentMutation*>(opaque))(continuation);
        };
        hooks.pre_fork_continuation_context = &mutation;
    } else {
        mutation(changed.continuation);
    }
    const auto baseline = fd_snapshot();
    child_fixture::PausedChildLease rejected;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    const bool created =
        through_hook ? child_fixture::PausedChildLease::create_prepared_with_hooks_for_testing(
                           deadline, changed, hooks, rejected, child_diagnostic)
                     : child_fixture::PausedChildLease::create_prepared(
                           deadline, changed, rejected, child_diagnostic);
    int wait_status = 0;
    errno = 0;
    if (created || rejected.active() ||
        child_diagnostic.phase != child_fixture::FailurePhase::Argument ||
        child_diagnostic.error_number != EINVAL || fd_snapshot() != baseline ||
        waitpid(-1, &wait_status, WNOHANG) != -1 || errno != ECHILD ||
        original.child_use_receipt_for_testing()->state() !=
            child_fixture::PreparedChildUseState::OwnerLive)
        return false;
    child_fixture::PausedChildLease child;
    if (!child_fixture::PausedChildLease::create_prepared(
            deadline, original, child, child_diagnostic) ||
        !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(input) == 0 && close(output) == 0;
}

bool run_live_arguments_case(const std::vector<std::string_view>& arguments) {
    std::string self;
    const auto baseline = fd_snapshot();
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!canonical_self(self) || arguments.empty() || arguments.front() != self ||
        !executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan_with_arguments(
            input, output, false, arguments, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    const std::string expected = encoded_arguments(arguments);
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ExecObservedLive ||
        observation.first.cmdline != expected || observation.second.cmdline != expected ||
        !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    if (close(input) != 0 || close(output) != 0 || fd_snapshot() != baseline) return false;
    int status = 0;
    errno = 0;
    return waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD;
}

void forge_first_post_exec_cmdline(child_fixture::ProcIdentity& first,
                                   child_fixture::ProcIdentity&,
                                   void*) {
    first.cmdline.push_back('x');
}

bool forged_post_exec_identity_rejected_case() {
    std::string self;
    const auto baseline = fd_snapshot();
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    handoff::HooksForTesting hooks;
    hooks.post_exec_observation_mutation = forge_first_post_exec_cmdline;
    if (!canonical_self(self) ||
        !executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
            source, hooks, handoff_lease, handoff_diagnostic))
        return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    const std::array arguments = {
        std::string_view{self}, std::string_view{""}, std::string_view{"after-empty"}};
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    if (input < 0 || output < 0 ||
        !handoff_lease.make_child_plan_with_arguments(
            input, output, false, arguments, plan, handoff_diagnostic) ||
        !child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic))
        return false;
    handoff::ExecObservation observation;
    if (!handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        observation.outcome != handoff::ExecOutcome::ProtocolFailure ||
        handoff_diagnostic.phase != handoff::FailurePhase::Child ||
        handoff_diagnostic.error_number != ESTALE ||
        observation.first.cmdline == observation.second.cmdline ||
        !child.attest_post_exec_identity(
            observation.second, observation.second, deadline, child_diagnostic) ||
        !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic) || close(input) != 0 || close(output) != 0 ||
        fd_snapshot() != baseline)
        return false;
    int status = 0;
    errno = 0;
    return waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD;
}

bool post_exec_destructor_containment_case() {
    const pid_t subprocess = fork();
    if (subprocess < 0) return false;
    if (subprocess == 0) {
        const auto baseline = fd_snapshot();
        std::string self;
        executable::ExecutableLease source;
        executable::Diagnostic source_diagnostic;
        if (!canonical_self(self) ||
            !executable::ExecutableLease::create(self, source, source_diagnostic))
            _exit(2);
        const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        const int output = create_capture();
        const auto owned_baseline = fd_snapshot();
        {
            handoff::ExecutableExecHandoffLease handoff_lease;
            handoff::Diagnostic handoff_diagnostic;
            child_fixture::ChildDescriptorPlan plan;
            child_fixture::PausedChildLease child;
            child_fixture::Diagnostic child_diagnostic;
            const std::array arguments = {
                std::string_view{self}, std::string_view{""}, std::string_view{"after-empty"}};
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            if (input < 0 || output < 0 ||
                !handoff::ExecutableExecHandoffLease::create(
                    source, handoff_lease, handoff_diagnostic) ||
                !handoff_lease.make_child_plan_with_arguments(
                    input, output, false, arguments, plan, handoff_diagnostic) ||
                !child_fixture::PausedChildLease::create_prepared(
                    deadline, plan, child, child_diagnostic))
                _exit(3);
            handoff::ExecObservation observation;
            if (!handoff_lease.release_and_observe(
                    source, child, deadline, observation, handoff_diagnostic) ||
                observation.outcome != handoff::ExecOutcome::ExecObservedLive)
                _exit(4);
            // Reverse destruction is deliberate: child contains and reaps the
            // attested exec process before H settles its claimed descriptors.
        }
        if (fd_snapshot() != owned_baseline || !source.close(source_diagnostic) ||
            close(input) != 0 || close(output) != 0 || fd_snapshot() != baseline)
            _exit(5);
        int status = 0;
        errno = 0;
        if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) _exit(6);
        _exit(0);
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    int status = 0;
    for (;;) {
        const pid_t result = waitpid(subprocess, &status, WNOHANG);
        if (result == subprocess) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return false;
        if (std::chrono::steady_clock::now() >= deadline) {
            (void)kill(subprocess, SIGKILL);
            while (waitpid(subprocess, &status, 0) < 0 && errno == EINTR) {
            }
            return false;
        }
        poll(nullptr, 0, 5);
    }
}

bool bounded_argument_transport_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    const std::string per_argument_max(4095, 'x');
    if (!pack_acceptance_case({self, per_argument_max}) || !argument_pack_limits_case() ||
        !owned_argument_bytes_case())
        return false;
    const std::array<ArgumentMutation, 8> mutations = {mutate_argc,
                                                       mutate_encoded,
                                                       mutate_offset_zero,
                                                       mutate_boundary,
                                                       mutate_terminal_offset,
                                                       mutate_terminal_nul,
                                                       mutate_early_nul,
                                                       mutate_active_arena};
    for (ArgumentMutation mutation : mutations)
        if (!argument_mutation_rejected_and_retry_case(mutation, false)) return false;
    if (!argument_mutation_rejected_and_retry_case(mutate_active_arena, true)) return false;
    if (!run_live_arguments_case({self}) ||
        !run_live_arguments_case({self, std::string_view{}, "after-empty"}) ||
        !run_live_arguments_case({self,
                                  "/tmp/future-source.rut",
                                  "--shards",
                                  "1",
                                  "--no-pin",
                                  "--drain",
                                  "0",
                                  "--opt",
                                  "2"}))
        return false;
    return forged_post_exec_identity_rejected_case() && post_exec_destructor_containment_case();
}

bool plan_is_reset(const child_fixture::ChildDescriptorPlan& plan) {
    return plan.combined_output_fd == -1 && plan.null_input_fd == -1 && plan.executable_fd == -1 &&
           plan.exec_status_fd == -1 && plan.exec_status_authority_fd == -1 &&
           plan.continuation.kind == child_fixture::ChildContinuationKind::Inert &&
           !plan.child_use_receipt_for_testing();
}

bool create_only_destructor_residue_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    const auto baseline = fd_snapshot();
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic diagnostic;
        if (!handoff::ExecutableExecHandoffLease::create(source, handoff_lease, diagnostic))
            return false;
    }
    return fd_snapshot() == baseline && source.close(source_diagnostic);
}

bool post_assignment_plan_failure_resets_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    if (input < 0 || output < 0) return false;
    const auto baseline = fd_snapshot();
    child_fixture::ChildDescriptorPlan plan;
    plan.combined_output_fd = 77;
    plan.null_input_fd = 78;
    plan.executable_fd = 79;
    plan.exec_status_fd = 80;
    plan.exec_status_authority_fd = 81;
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic diagnostic;
        handoff::HooksForTesting hooks;
        hooks.fail_status_identity_fstat = true;
        if (!handoff::ExecutableExecHandoffLease::create_with_hooks_for_testing(
                source, hooks, handoff_lease, diagnostic) ||
            handoff_lease.make_child_plan(input, output, false, plan, diagnostic) ||
            diagnostic.phase != handoff::FailurePhase::Pipe || diagnostic.error_number != EIO ||
            !plan_is_reset(plan))
            return false;
    }
    const bool clean = fd_snapshot() == baseline;
    return close(input) == 0 && close(output) == 0 && source.close(source_diagnostic) && clean;
}

bool rejected_prepared_child_destructor_residue_case(bool invalid_input) {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    const int input = open(invalid_input ? "/dev/zero" : "/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = invalid_input ? create_capture() : open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (input < 0 || output < 0) return false;
    const auto baseline = fd_snapshot();
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        handoff::Diagnostic handoff_diagnostic;
        child_fixture::ChildDescriptorPlan plan;
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        if (!handoff::ExecutableExecHandoffLease::create(
                source, handoff_lease, handoff_diagnostic) ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
            child_fixture::PausedChildLease::create_prepared(
                deadline, plan, child, child_diagnostic) ||
            child_diagnostic.phase != child_fixture::FailurePhase::Argument ||
            !plan.child_use_receipt_for_testing() ||
            plan.child_use_receipt_for_testing()->state() !=
                child_fixture::PreparedChildUseState::OwnerLive ||
            plan.child_use_receipt_for_testing()->child_pid() != -1 ||
            plan.child_use_receipt_for_testing()->settlement())
            return false;
    }
    const bool clean = fd_snapshot() == baseline;
    return close(input) == 0 && close(output) == 0 && source.close(source_diagnostic) && clean;
}

bool failed_prepared_create_can_retry_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    handoff::ExecutableExecHandoffLease handoff_lease;
    handoff::Diagnostic handoff_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic) ||
        !handoff::ExecutableExecHandoffLease::create(source, handoff_lease, handoff_diagnostic))
        return false;
    const int invalid_input = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    const int valid_input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    child_fixture::ChildDescriptorPlan plan;
    child_fixture::PausedChildLease child;
    child_fixture::Diagnostic child_diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    if (invalid_input < 0 || valid_input < 0 || output < 0 ||
        !handoff_lease.make_child_plan(invalid_input, output, false, plan, handoff_diagnostic) ||
        child_fixture::PausedChildLease::create_prepared(deadline, plan, child, child_diagnostic) ||
        child_diagnostic.phase != child_fixture::FailurePhase::Argument ||
        !plan.child_use_receipt_for_testing() ||
        plan.child_use_receipt_for_testing()->state() !=
            child_fixture::PreparedChildUseState::OwnerLive)
        return false;
    plan.null_input_fd = valid_input;
    if (!child_fixture::PausedChildLease::create_prepared(
            deadline, plan, child, child_diagnostic) ||
        plan.child_use_receipt_for_testing()->state() !=
            child_fixture::PreparedChildUseState::Claimed)
        return false;
    child_fixture::PausedChildLease duplicate_child;
    if (child_fixture::PausedChildLease::create_prepared(
            deadline, plan, duplicate_child, child_diagnostic) ||
        child_diagnostic.phase != child_fixture::FailurePhase::Argument ||
        child_diagnostic.error_number != EALREADY || duplicate_child.active() ||
        !child.validate_prepared(deadline, child_diagnostic) ||
        !child.cleanup(deadline, child_diagnostic) || !handoff_lease.close(handoff_diagnostic) ||
        !source.close(source_diagnostic))
        return false;
    return close(invalid_input) == 0 && close(valid_input) == 0 && close(output) == 0;
}

bool copied_plan_rejected_after_owner_end_case(bool explicit_close) {
    const pid_t subprocess = fork();
    if (subprocess < 0) return false;
    if (subprocess == 0) {
        std::string self;
        executable::ExecutableLease source;
        executable::Diagnostic source_diagnostic;
        if (!canonical_self(self) ||
            !executable::ExecutableLease::create(self, source, source_diagnostic))
            _exit(2);
        const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        const int output = create_capture();
        child_fixture::ChildDescriptorPlan copied_plan;
        std::array<int, 3> stale_slots{};
        {
            handoff::ExecutableExecHandoffLease handoff_lease;
            handoff::Diagnostic handoff_diagnostic;
            child_fixture::ChildDescriptorPlan plan;
            if (input < 0 || output < 0 ||
                !handoff::ExecutableExecHandoffLease::create(
                    source, handoff_lease, handoff_diagnostic) ||
                !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic))
                _exit(3);
            copied_plan = plan;
            stale_slots = {plan.executable_fd, plan.exec_status_fd, plan.exec_status_authority_fd};
            if (explicit_close && !handoff_lease.close(handoff_diagnostic)) _exit(4);
        }
        const auto receipt = copied_plan.child_use_receipt_for_testing();
        if (!receipt || receipt->state() != child_fixture::PreparedChildUseState::Abandoned)
            _exit(5);
        for (const int slot : stale_slots) {
            const int replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (replacement < 0) _exit(6);
            if (replacement != slot) {
                if (dup3(replacement, slot, O_CLOEXEC) != slot || close(replacement) != 0) _exit(7);
            }
        }
        const auto repopulated = fd_snapshot();
        int status = 0;
        errno = 0;
        if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) _exit(8);
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        if (child_fixture::PausedChildLease::create_prepared(
                deadline, copied_plan, child, child_diagnostic) ||
            child_diagnostic.phase != child_fixture::FailurePhase::Argument ||
            child_diagnostic.error_number != ESTALE || child.active() ||
            fd_snapshot() != repopulated)
            _exit(9);
        errno = 0;
        if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) _exit(10);
        for (const int slot : stale_slots)
            if (close(slot) != 0) _exit(11);
        if (close(input) != 0 || close(output) != 0 || !source.close(source_diagnostic)) _exit(12);
        _exit(0);
    }
    int status = 0;
    while (waitpid(subprocess, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool active_child_handoff_destructor_preserves_case() {
    const pid_t subprocess = fork();
    if (subprocess < 0) return false;
    if (subprocess == 0) {
        std::string self;
        executable::ExecutableLease source;
        executable::Diagnostic source_diagnostic;
        child_fixture::PausedChildLease child;
        child_fixture::Diagnostic child_diagnostic;
        child_fixture::ChildDescriptorPlan plan;
        if (!canonical_self(self) ||
            !executable::ExecutableLease::create(self, source, source_diagnostic))
            _exit(2);
        const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        const int output = create_capture();
        std::array<int, 9> owned{};
        {
            handoff::ExecutableExecHandoffLease handoff_lease;
            handoff::Diagnostic handoff_diagnostic;
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            if (input < 0 || output < 0 ||
                !handoff::ExecutableExecHandoffLease::create(
                    source, handoff_lease, handoff_diagnostic) ||
                !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
                !child_fixture::PausedChildLease::create_prepared(
                    deadline, plan, child, child_diagnostic))
                _exit(3);
            if (!plan.child_use_receipt_for_testing() ||
                plan.child_use_receipt_for_testing()->state() !=
                    child_fixture::PreparedChildUseState::Claimed)
                _exit(8);
            const auto status = status_slots(handoff_lease);
            owned = {handoff_lease.observation_fd(),
                     handoff_lease.authority_one_fd_for_testing(),
                     handoff_lease.authority_two_fd_for_testing(),
                     status[0],
                     status[1],
                     status[2],
                     status[3],
                     status[4],
                     status[5]};
            if (handoff_lease.close(handoff_diagnostic) ||
                handoff_diagnostic.phase != handoff::FailurePhase::Settlement ||
                handoff_diagnostic.error_number != EPERM ||
                plan.child_use_receipt_for_testing()->state() !=
                    child_fixture::PreparedChildUseState::Claimed)
                _exit(10);
            for (const int fd : owned)
                if (fcntl(fd, F_GETFD) < 0) _exit(11);
        }
        if (plan.child_use_receipt_for_testing()->state() !=
            child_fixture::PreparedChildUseState::Claimed)
            _exit(9);
        for (const int fd : owned)
            if (fcntl(fd, F_GETFD) < 0) _exit(4);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        if (!child.validate_prepared(deadline, child_diagnostic) ||
            !child.cleanup(deadline, child_diagnostic))
            _exit(5);
        for (const int fd : owned)
            if (close(fd) != 0) _exit(6);
        if (!source.close(source_diagnostic) || close(input) != 0 || close(output) != 0) _exit(7);
        _exit(0);
    }
    int status = 0;
    while (waitpid(subprocess, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool reverse_destruction_settlement_residue_case() {
    std::string self;
    if (!canonical_self(self)) return false;
    executable::ExecutableLease source;
    executable::Diagnostic source_diagnostic;
    if (!executable::ExecutableLease::create(self, source, source_diagnostic)) return false;
    const int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int output = create_capture();
    if (input < 0 || output < 0) return false;
    const auto baseline = fd_snapshot();
    {
        handoff::ExecutableExecHandoffLease handoff_lease;
        child_fixture::ChildDescriptorPlan plan;
        child_fixture::PausedChildLease child;
        handoff::Diagnostic handoff_diagnostic;
        child_fixture::Diagnostic child_diagnostic;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        if (!handoff::ExecutableExecHandoffLease::create(
                source, handoff_lease, handoff_diagnostic) ||
            !handoff_lease.make_child_plan(input, output, false, plan, handoff_diagnostic) ||
            !child_fixture::PausedChildLease::create_prepared(
                deadline, plan, child, child_diagnostic))
            return false;
    }
    const bool clean = fd_snapshot() == baseline;
    return close(input) == 0 && close(output) == 0 && source.close(source_diagnostic) && clean;
}

}  // namespace

int main() {
    if (getenv("PATH") == nullptr) live_exec_helper();
    const int fd_baseline = open_fd_count();
    if (fd_baseline < 0) return 1;
    if (!legacy_inert_prepared_stdin_cloexec_case()) {
        std::fprintf(stderr, "legacy prepared stdin CLOEXEC regression failed\n");
        return 1;
    }
    if (!create_only_destructor_residue_case()) {
        std::fprintf(stderr, "create-only destructor residue case failed\n");
        return 1;
    }
    if (!post_assignment_plan_failure_resets_case()) {
        std::fprintf(stderr, "post-assignment plan failure reset case failed\n");
        return 1;
    }
    if (!rejected_prepared_child_destructor_residue_case(true) ||
        !rejected_prepared_child_destructor_residue_case(false)) {
        std::fprintf(stderr, "rejected prepared-child destructor residue case failed\n");
        return 1;
    }
    if (!failed_prepared_create_can_retry_case()) {
        std::fprintf(stderr, "failed prepared-child create retry case failed\n");
        return 1;
    }
    if (!copied_plan_rejected_after_owner_end_case(false) ||
        !copied_plan_rejected_after_owner_end_case(true)) {
        std::fprintf(stderr, "copied stale plan owner-lifecycle case failed\n");
        return 1;
    }
    if (!active_child_handoff_destructor_preserves_case()) {
        std::fprintf(stderr, "active-child handoff destructor preservation case failed\n");
        return 1;
    }
    if (!reverse_destruction_settlement_residue_case()) {
        std::fprintf(stderr, "reverse destruction settlement residue case failed\n");
        return 1;
    }
    if (!bounded_argument_transport_case()) {
        std::fprintf(stderr, "bounded executable argument transport case failed\n");
        return 1;
    }
    if (!run_live_case()) {
        std::fprintf(stderr, "live executable handoff case failed\n");
        return 1;
    }
    if (!run_pre_exec_failure_case()) {
        std::fprintf(stderr, "pre-exec failure handoff case failed\n");
        return 1;
    }
    if (!direct_exec_release_requires_authorization_case()) {
        std::fprintf(stderr, "direct exec-plan release authorization case failed\n");
        return 1;
    }
    for (const auto& [injection, outcome] :
         {std::pair{std::uint8_t{1}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{2}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{3}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{4}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{5}, handoff::ExecOutcome::Timeout},
          std::pair{std::uint8_t{6}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{7}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{8}, handoff::ExecOutcome::ProtocolFailure},
          std::pair{std::uint8_t{9}, handoff::ExecOutcome::ProtocolFailure}}) {
        if (!run_status_injection(injection, outcome)) {
            std::fprintf(stderr, "status injection %u failed\n", injection);
            return 1;
        }
    }
    if (!run_cross_kcmp_denial_case()) {
        std::fprintf(stderr, "cross-process kcmp denial case failed\n");
        return 1;
    }
    if (!run_writer_close_uncertainty_case()) {
        std::fprintf(stderr, "status-writer close uncertainty case failed\n");
        return 1;
    }
    if (!run_release_close_uncertainty_case()) {
        std::fprintf(stderr, "release-writer close uncertainty case failed\n");
        return 1;
    }
    for (unsigned int slot = 0; slot < 6; ++slot) {
        if (!status_slot_close_uncertainty_case(slot)) {
            std::fprintf(stderr, "status close uncertainty case failed: slot=%u\n", slot);
            return 1;
        }
    }
    if (!destructor_status_no_majority_case(false) || !destructor_status_no_majority_case(true)) {
        std::fprintf(stderr, "status destructor no-majority case failed\n");
        return 1;
    }
    if (!run_real_shebang_enoent_case()) {
        std::fprintf(stderr, "real shebang ENOENT case failed\n");
        return 1;
    }
    if (!run_fast_death_case()) {
        std::fprintf(stderr, "fast-death case failed\n");
        return 1;
    }
    for (unsigned int slot = 0; slot < 3; ++slot) {
        for (const SlotMutation mutation : {SlotMutation::SameInodeNewOfd,
                                            SlotMutation::DifferentObject,
                                            SlotMutation::ClearCloexec}) {
            if (!run_handoff_slot_restore_case(slot, mutation)) {
                std::fprintf(stderr,
                             "handoff slot restore case failed: slot=%u mutation=%u\n",
                             slot,
                             static_cast<unsigned>(mutation));
                return 1;
            }
        }
    }
    for (std::uint8_t mutation = 1; mutation <= 3; ++mutation) {
        if (!child_executable_mutation_rejected(mutation)) {
            std::fprintf(stderr, "child executable mutation %u was not rejected\n", mutation);
            return 1;
        }
    }
    if (!altered_status_plan_rejected(true) || !altered_status_plan_rejected(false)) {
        std::fprintf(stderr, "altered child status plan was not rejected\n");
        return 1;
    }
    for (unsigned int slot = 0; slot < 6; ++slot) {
        if (!explicit_status_foreign_slot_restore_case(slot) ||
            !destructor_status_foreign_slot_case(slot)) {
            std::fprintf(stderr, "status custody mutation case failed: slot=%u\n", slot);
            return 1;
        }
    }
    if (!source_pre_release_revalidation_case()) {
        std::fprintf(stderr, "immediate source pre-release revalidation case failed\n");
        return 1;
    }
    if (!wrong_source_exact_ofd_rejected_case()) {
        std::fprintf(stderr, "wrong source exact-OFD binding case failed\n");
        return 1;
    }
    if (!unstable_proc_never_live_case()) {
        std::fprintf(stderr, "unstable proc snapshot was reported live\n");
        return 1;
    }
    if (!destructor_majority_case(true) || !destructor_majority_case(false)) {
        std::fprintf(stderr, "destructor majority/no-majority case failed\n");
        return 1;
    }
    if (open_fd_count() != fd_baseline) {
        std::fprintf(stderr, "descriptor residue after handoff suite\n");
        return 1;
    }
    return 0;
}
