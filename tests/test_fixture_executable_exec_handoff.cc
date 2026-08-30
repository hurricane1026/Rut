#include "fixture_executable_exec_handoff.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
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
        handoff_diagnostic.phase != handoff::FailurePhase::Release) {
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
    if (!handoff_lease.close(handoff_diagnostic) || !source.close(source_diagnostic)) return false;
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
    if (handoff_lease.release_and_observe(
            source, child, deadline, observation, handoff_diagnostic) ||
        handoff_diagnostic.phase != handoff::FailurePhase::Custody)
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
    const int replacement = open("/dev/null", O_PATH | O_CLOEXEC);
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
        status_reader = handoff_lease.status_reader_fd();
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
                 fcntl(status_reader, F_GETFD) >= 0;
        result = close(slots[0]) == 0 && close(slots[1]) == 0 && close(slots[2]) == 0 &&
                 close(status_reader) == 0 && result;
    }
    result = close(input) == 0 && close(output) == 0 && source.close(source_diagnostic) && result;
    return result;
}

}  // namespace

int main() {
    if (getenv("PATH") == nullptr) live_exec_helper();
    const int fd_baseline = open_fd_count();
    if (fd_baseline < 0) return 1;
    if (!run_live_case()) {
        std::fprintf(stderr, "live executable handoff case failed\n");
        return 1;
    }
    if (!run_pre_exec_failure_case()) {
        std::fprintf(stderr, "pre-exec failure handoff case failed\n");
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
    if (!source_pre_release_revalidation_case()) {
        std::fprintf(stderr, "immediate source pre-release revalidation case failed\n");
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
