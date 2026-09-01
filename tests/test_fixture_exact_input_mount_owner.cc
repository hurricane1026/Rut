#include "fixture_exact_input_mount_owner.h"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <thread>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace rut::test::ipv4_topology;

const std::string kConfig =
    "events {}\nhttp { server { listen 8080; location / { proxy_pass "
    "http://127.0.0.1:9000; } } }\n";

bool exact_terminal(const ExactInputMountRecoveryReceipt& receipt) {
    return receipt.state == ExactInputMountState::Settled && receipt.settlement_complete &&
           receipt.terminal_result == ExactInputMountTerminalResult::SettledCleanly &&
           receipt.graph_mutated && !receipt.cleanup_not_applicable && receipt.sidecar_acquired &&
           receipt.input_acquired && receipt.directory_acquired && receipt.holder_acquired &&
           receipt.network_b_acquired && receipt.network_a_acquired && receipt.terminal_frozen &&
           receipt.sidecar_settled && receipt.input_settled && receipt.directory_settled &&
           receipt.holder_settled && receipt.network_b_settled && receipt.network_a_settled &&
           receipt.manifest_not_applicable && receipt.final_zero_residue &&
           receipt.sidecar_order < receipt.input_order &&
           receipt.input_order < receipt.directory_order &&
           receipt.directory_order < receipt.holder_order &&
           receipt.holder_order < receipt.network_b_order &&
           receipt.network_b_order < receipt.network_a_order;
}

bool truthful_partial_terminal(const ExactInputMountRecoveryReceipt& receipt) {
    const auto exact_event = [](bool acquired, bool settled, std::uint32_t order) {
        return settled && (acquired ? order != 0u : order == 0u);
    };
    std::vector<std::uint32_t> events;
    for (const std::uint32_t order : {receipt.sidecar_order,
                                      receipt.input_order,
                                      receipt.directory_order,
                                      receipt.holder_order,
                                      receipt.network_b_order,
                                      receipt.network_a_order})
        if (order != 0u) events.push_back(order);
    const bool strict_event_order =
        std::adjacent_find(events.begin(), events.end(), std::greater_equal<>()) == events.end();
    return receipt.state == ExactInputMountState::Settled && receipt.settlement_complete &&
           receipt.terminal_frozen &&
           receipt.terminal_result == ExactInputMountTerminalResult::SettledCleanly &&
           receipt.graph_mutated && receipt.manifest_not_applicable && receipt.final_zero_residue &&
           exact_event(receipt.sidecar_acquired, receipt.sidecar_settled, receipt.sidecar_order) &&
           exact_event(receipt.input_acquired, receipt.input_settled, receipt.input_order) &&
           exact_event(
               receipt.directory_acquired, receipt.directory_settled, receipt.directory_order) &&
           exact_event(receipt.holder_acquired, receipt.holder_settled, receipt.holder_order) &&
           exact_event(
               receipt.network_b_acquired, receipt.network_b_settled, receipt.network_b_order) &&
           exact_event(
               receipt.network_a_acquired, receipt.network_a_settled, receipt.network_a_order) &&
           strict_event_order;
}

bool receipt_equal(const ExactInputMountRecoveryReceipt& left,
                   const ExactInputMountRecoveryReceipt& right) {
    return left.state == right.state && left.terminal_result == right.terminal_result &&
           left.attempted == right.attempted && left.graph_mutated == right.graph_mutated &&
           left.cleanup_not_applicable == right.cleanup_not_applicable &&
           left.sidecar_acquired == right.sidecar_acquired &&
           left.input_acquired == right.input_acquired &&
           left.directory_acquired == right.directory_acquired &&
           left.holder_acquired == right.holder_acquired &&
           left.network_b_acquired == right.network_b_acquired &&
           left.network_a_acquired == right.network_a_acquired &&
           left.sidecar_settled == right.sidecar_settled &&
           left.first_topology_revalidated == right.first_topology_revalidated &&
           left.input_settled == right.input_settled &&
           left.directory_settled == right.directory_settled &&
           left.second_topology_revalidated == right.second_topology_revalidated &&
           left.holder_settled == right.holder_settled &&
           left.network_b_settled == right.network_b_settled &&
           left.network_a_settled == right.network_a_settled &&
           left.manifest_not_applicable == right.manifest_not_applicable &&
           left.final_zero_residue == right.final_zero_residue &&
           left.settlement_complete == right.settlement_complete &&
           left.terminal_frozen == right.terminal_frozen &&
           left.network_a_create_count == right.network_a_create_count &&
           left.network_a_verify_count == right.network_a_verify_count &&
           left.network_b_create_count == right.network_b_create_count &&
           left.network_b_verify_count == right.network_b_verify_count &&
           left.both_ipam_verify_count == right.both_ipam_verify_count &&
           left.holder_create_count == right.holder_create_count &&
           left.holder_attach_a_verify_count == right.holder_attach_a_verify_count &&
           left.holder_attach_b_count == right.holder_attach_b_count &&
           left.holder_remove_command_count == right.holder_remove_command_count &&
           left.network_b_remove_command_count == right.network_b_remove_command_count &&
           left.network_a_remove_command_count == right.network_a_remove_command_count &&
           left.sidecar_order == right.sidecar_order && left.input_order == right.input_order &&
           left.directory_order == right.directory_order &&
           left.holder_order == right.holder_order &&
           left.network_b_order == right.network_b_order &&
           left.network_a_order == right.network_a_order &&
           left.diagnostic.phase == right.diagnostic.phase &&
           left.diagnostic.error_number == right.diagnostic.error_number &&
           left.diagnostic.message == right.diagnostic.message;
}

bool operation_failure_terminal(const ExactInputMountRecoveryReceipt& receipt,
                                ExactInputMountPhase phase) {
    return receipt.state == ExactInputMountState::Settled && receipt.settlement_complete &&
           receipt.terminal_frozen && receipt.final_zero_residue &&
           receipt.terminal_result == ExactInputMountTerminalResult::SettledWithOperationFailure &&
           receipt.diagnostic.phase == phase;
}

bool write_all(int fd, const std::string& bytes) {
    size_t written = 0;
    while (written < bytes.size()) {
        const ssize_t count = write(fd, bytes.data() + written, bytes.size() - written);
        if (count > 0)
            written += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else
            return false;
    }
    return true;
}

int run_exact_read_helper(const std::string& name, const char* argument = nullptr) {
    if (name == "max") {
        std::string bytes(8192, '\0');
        for (size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<char>((index % 251u) + 1u);
        return write_all(STDOUT_FILENO, bytes) ? 0 : 126;
    }
    if (name == "nul") return write_all(STDOUT_FILENO, std::string("a\0b", 3)) ? 0 : 126;
    if (name == "held") {
        if (!write_all(STDOUT_FILENO, "held")) return 126;
        (void)usleep(3000000);
        return 0;
    }
    if (name == "leader-descendant") {
        const pid_t descendant = fork();
        if (descendant < 0) return 126;
        if (descendant == 0) {
            if (!write_all(STDOUT_FILENO, "held")) _exit(126);
            (void)poll(nullptr, 0, 3000);
            _exit(0);
        }
        return 0;
    }
    if (name == "fd-excluded") {
        if (argument == nullptr) return 126;
        char* end = nullptr;
        errno = 0;
        const long raw_fd = strtol(argument, &end, 10);
        if (errno != 0 || end == argument || *end != '\0' || raw_fd < 3 ||
            raw_fd > std::numeric_limits<int>::max())
            return 126;
        errno = 0;
        if (fcntl(static_cast<int>(raw_fd), F_GETFD) >= 0 || errno != EBADF) return 125;
        return write_all(STDOUT_FILENO, "fd-ok") ? 0 : 126;
    }
    if (name == "extra") return write_all(STDOUT_FILENO, "abcX") ? 0 : 126;
    if (name == "overflow") return write_all(STDOUT_FILENO, "abcXY") ? 0 : 126;
    if (name == "read-error") return write_all(STDOUT_FILENO, "abc") ? 0 : 126;
    if (name == "signaled") {
        (void)raise(SIGUSR1);
        return 126;
    }
    if (name == "nonzero") return 23;
    if (name == "stderr") {
        if (!write_all(STDOUT_FILENO, "abc") || !write_all(STDERR_FILENO, "bad")) return 126;
        return 0;
    }
    return 125;
}

bool read_observation_equal(const ExactInputReadObservation& left,
                            const ExactInputReadObservation& right) {
    return left.outcome == right.outcome && left.attempted == right.attempted &&
           left.terminal_frozen == right.terminal_frozen &&
           left.command_started == right.command_started && left.stdout_eof == right.stdout_eof &&
           left.stderr_eof == right.stderr_eof && left.child_reaped == right.child_reaped &&
           left.wait_status_valid == right.wait_status_valid &&
           left.process_group_owned == right.process_group_owned &&
           left.process_group_gone == right.process_group_gone &&
           left.group_absence_confirmations == right.group_absence_confirmations &&
           left.pidfd_opened == right.pidfd_opened &&
           left.pidfd_identity_verified == right.pidfd_identity_verified &&
           left.pidfd_closed_after_group_gone == right.pidfd_closed_after_group_gone &&
           left.final_deadline_recorded == right.final_deadline_recorded &&
           left.cleanup_completed_before_final_deadline ==
               right.cleanup_completed_before_final_deadline &&
           left.leader_exit_observed_before_group_cleanup ==
               right.leader_exit_observed_before_group_cleanup &&
           left.descendant_group_member_observed == right.descendant_group_member_observed &&
           left.foreign_process_survived == right.foreign_process_survived &&
           left.foreign_fd_excluded == right.foreign_fd_excluded &&
           left.deadline_exceeded == right.deadline_exceeded &&
           left.output_overflow == right.output_overflow &&
           left.pre_source_revalidated == right.pre_source_revalidated &&
           left.pre_container_identity == right.pre_container_identity &&
           left.pre_mount_inspected == right.pre_mount_inspected &&
           left.pre_proc_credentials == right.pre_proc_credentials &&
           left.post_source_revalidated == right.post_source_revalidated &&
           left.post_container_identity == right.post_container_identity &&
           left.post_mount_inspected == right.post_mount_inspected &&
           left.post_proc_credentials == right.post_proc_credentials &&
           left.registered_identity_matched == right.registered_identity_matched &&
           left.registered_mount_matched == right.registered_mount_matched &&
           left.expected_size == right.expected_size &&
           left.stdout_read_errno == right.stdout_read_errno &&
           left.stderr_read_errno == right.stderr_read_errno &&
           left.launch_failure_stage == right.launch_failure_stage &&
           left.launch_errno == right.launch_errno && left.wait_status == right.wait_status &&
           left.command_argv == right.command_argv && left.stdout_bytes == right.stdout_bytes &&
           left.stderr_bytes == right.stderr_bytes &&
           left.diagnostic.phase == right.diagnostic.phase &&
           left.diagnostic.error_number == right.diagnostic.error_number &&
           left.diagnostic.message == right.diagnostic.message;
}

bool exact_read_runner_self_checks(std::string& error) {
    const std::vector<std::pair<ExactInputReadRunnerTestCase, ExactInputReadOutcome>> cases = {
        {ExactInputReadRunnerTestCase::CommandStartFailure,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::LeaderExitWithDescendant,
         ExactInputReadOutcome::DeadlineExceeded},
        {ExactInputReadRunnerTestCase::ForeignFdExcluded, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::MaxSizeExact, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::EmbeddedNulExact, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::HeldOpenAfterExactBytes,
         ExactInputReadOutcome::DeadlineExceeded},
        {ExactInputReadRunnerTestCase::ExtraByteThenEof, ExactInputReadOutcome::ByteMismatch},
        {ExactInputReadRunnerTestCase::BeyondSentinel, ExactInputReadOutcome::OutputLimitExceeded},
        {ExactInputReadRunnerTestCase::ReadErrorAfterBytes, ExactInputReadOutcome::StreamError},
        {ExactInputReadRunnerTestCase::ExitSignaled, ExactInputReadOutcome::ExitSignaled},
        {ExactInputReadRunnerTestCase::ExitNonzero, ExactInputReadOutcome::ExitNonzero},
        {ExactInputReadRunnerTestCase::NonemptyStderr, ExactInputReadOutcome::StderrNotEmpty},
    };
    for (const auto& [test_case, outcome] : cases) {
        ExactInputReadObservation observation;
        ExactInputMountDiagnostic diagnostic;
        if (!exact_input_mount_test_read_runner_case(test_case, observation, diagnostic) ||
            observation.outcome != outcome || !observation.attempted ||
            !observation.terminal_frozen) {
            error = "deterministic exact-read outcome or process custody differed";
            return false;
        }
        const bool start_failure = test_case == ExactInputReadRunnerTestCase::CommandStartFailure;
        if (observation.command_started == start_failure || !observation.child_reaped ||
            !observation.wait_status_valid || !observation.process_group_owned ||
            !observation.process_group_gone || !observation.pidfd_opened ||
            !observation.pidfd_identity_verified || !observation.pidfd_closed_after_group_gone ||
            observation.group_absence_confirmations < 2u || !observation.final_deadline_recorded ||
            !observation.cleanup_completed_before_final_deadline) {
            error = "exact-read start/child/PGID evidence was not causal";
            return false;
        }
        if (start_failure &&
            (observation.launch_failure_stage != ExactInputReadLaunchStage::Execute ||
             observation.launch_errno != ENOENT)) {
            error = "real exec failure did not preserve exact stage and errno";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::LeaderExitWithDescendant &&
            (!observation.leader_exit_observed_before_group_cleanup ||
             !observation.descendant_group_member_observed ||
             !observation.foreign_process_survived)) {
            error = "leader-exit cleanup lost descendant or foreign-process evidence";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::ForeignFdExcluded &&
            (!observation.foreign_fd_excluded || observation.stdout_bytes != "fd-ok" ||
             !observation.stdout_eof || !observation.stderr_eof)) {
            error = "execed helper inherited the sentinel foreign descriptor";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::MaxSizeExact &&
            (!observation.stdout_eof || !observation.stderr_eof ||
             observation.stdout_bytes.size() != 8192u)) {
            error = "maximum exact output lacked true EOF";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::EmbeddedNulExact &&
            observation.stdout_bytes != std::string("a\0b", 3)) {
            error = "embedded-NUL runner output was not binary exact";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::HeldOpenAfterExactBytes &&
            (!observation.deadline_exceeded || observation.stdout_eof)) {
            error = "held-open exact bytes were accepted without EOF";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::ExtraByteThenEof &&
            (!observation.stdout_eof || observation.output_overflow ||
             observation.stdout_bytes != "abcX")) {
            error = "expected+1 EOF was not retained as a byte mismatch";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::BeyondSentinel &&
            !observation.output_overflow) {
            error = "data beyond the sentinel was not an overflow";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::ReadErrorAfterBytes &&
            (observation.stdout_bytes.empty() || observation.stdout_read_errno != EIO)) {
            error = "causal read error did not follow available bytes";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::NonemptyStderr &&
            observation.stderr_bytes != "bad") {
            error = "stderr remained merged or empty";
            return false;
        }
    }
    return true;
}

bool recover_injected_setup(ExactInputMountFailurePoint point, std::string& error) {
    ExactInputMountRecoveryController controller;
    ExactInputMountHandle handle;
    ExactInputMountDiagnostic diagnostic;
    ExactInputMountOptions options;
    options.failure_point = point;
    if (controller.start(kConfig.data(), kConfig.size(), handle, diagnostic, options)) {
        error = "injected setup boundary unexpectedly reached ReadyForObservation";
        return false;
    }
    if (diagnostic.message.find("injected") == std::string::npos &&
        point != ExactInputMountFailurePoint::SidecarCreateReportedTimeout) {
        error = "setup boundary did not produce exact injected diagnostic: " + diagnostic.message;
        return false;
    }
    ExactInputMountHandle second;
    if (controller.start(kConfig.data(), kConfig.size(), second, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Capacity) {
        error = "post-registration setup failure did not retain the fixed owner slot";
        return false;
    }
    ExactInputMountRecoveryReceipt receipt;
    if (!controller.recover_all(receipt, diagnostic) || !truthful_partial_terminal(receipt)) {
        error = "injected setup graph did not recover exactly: " + diagnostic.message;
        return false;
    }
    const bool expect_input = point != ExactInputMountFailurePoint::AfterDirectory;
    const bool expect_network_a = point != ExactInputMountFailurePoint::AfterDirectory &&
                                  point != ExactInputMountFailurePoint::AfterInputFile;
    const bool expect_network_b = expect_network_a &&
                                  point != ExactInputMountFailurePoint::AfterNetworkACreated &&
                                  point != ExactInputMountFailurePoint::AfterNetworkAVerified;
    const bool expect_holder = point == ExactInputMountFailurePoint::AfterHolderCreated ||
                               point == ExactInputMountFailurePoint::AfterHolderAttachedA ||
                               point == ExactInputMountFailurePoint::AfterHolderAttachedB ||
                               point == ExactInputMountFailurePoint::AfterHolder ||
                               point == ExactInputMountFailurePoint::AfterTopology ||
                               point == ExactInputMountFailurePoint::AfterSidecarCreate ||
                               point == ExactInputMountFailurePoint::AfterMountInspect ||
                               point == ExactInputMountFailurePoint::SidecarCreateReportedTimeout;
    const bool expect_sidecar = point == ExactInputMountFailurePoint::AfterSidecarCreate ||
                                point == ExactInputMountFailurePoint::AfterMountInspect ||
                                point == ExactInputMountFailurePoint::SidecarCreateReportedTimeout;
    if (!receipt.directory_acquired || receipt.input_acquired != expect_input ||
        receipt.network_a_acquired != expect_network_a ||
        receipt.network_b_acquired != expect_network_b ||
        receipt.holder_acquired != expect_holder || receipt.sidecar_acquired != expect_sidecar) {
        error = "injected setup receipt did not identify exactly the acquired resource prefix";
        return false;
    }
    const bool after_a_create = point != ExactInputMountFailurePoint::AfterDirectory &&
                                point != ExactInputMountFailurePoint::AfterInputFile;
    const bool after_a_verify =
        after_a_create && point != ExactInputMountFailurePoint::AfterNetworkACreated;
    const bool after_b_create =
        after_a_verify && point != ExactInputMountFailurePoint::AfterNetworkAVerified;
    const bool after_b_verify =
        after_b_create && point != ExactInputMountFailurePoint::AfterNetworkBCreated;
    const bool after_ipam =
        after_b_verify && point != ExactInputMountFailurePoint::AfterNetworkBVerified;
    const bool after_holder_create = after_ipam &&
                                     point != ExactInputMountFailurePoint::AfterBothIpamVerified &&
                                     point != ExactInputMountFailurePoint::AfterNetworks;
    const bool after_attach_a =
        after_holder_create && point != ExactInputMountFailurePoint::AfterHolderCreated;
    const bool after_attach_b =
        after_attach_a && point != ExactInputMountFailurePoint::AfterHolderAttachedA;
    const auto exact_count = [](std::uint32_t actual, bool expected) {
        return actual == (expected ? 1u : 0u);
    };
    if (!exact_count(receipt.network_a_create_count, after_a_create) ||
        !exact_count(receipt.network_a_verify_count, after_a_verify) ||
        !exact_count(receipt.network_b_create_count, after_b_create) ||
        !exact_count(receipt.network_b_verify_count, after_b_verify) ||
        !exact_count(receipt.both_ipam_verify_count, after_ipam) ||
        !exact_count(receipt.holder_create_count, after_holder_create) ||
        !exact_count(receipt.holder_attach_a_verify_count, after_attach_a) ||
        !exact_count(receipt.holder_attach_b_count, after_attach_b)) {
        error = "setup fault was not bracketed by exact preceding/following event counts";
        return false;
    }
    return true;
}

bool wait_for_abort(pid_t child, std::string& error) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        error = "waitpid for fatal-fallback child failed";
        return false;
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT) {
        error = "fatal-fallback child did not terminate by SIGABRT";
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace rut::test::ipv4_topology;
    if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--exact-input-read-helper")
        return run_exact_read_helper(argv[2], argc == 4 ? argv[3] : nullptr);
    std::string runner_error;
    if (!exact_read_runner_self_checks(runner_error)) {
        std::cerr << "FAIL [#358 exact input read runner]: " << runner_error << "\n";
        return 1;
    }
    if (argc == 2 && std::string(argv[1]) == "--exact-input-read-runner-self-check") {
        std::cerr << "PASS: #358 binary-safe exact input read runner\n";
        return 0;
    }
    // Wrong-thread destruction is fatal even before any resource mutation.
    pid_t child = fork();
    if (child < 0) {
        std::cerr << "FAIL [#358 exact input mount death setup]: fork failed\n";
        return 1;
    }
    if (child == 0) {
        auto* foreign_thread_controller = new ExactInputMountRecoveryController;
        std::thread destroyer([&] { delete foreign_thread_controller; });
        destroyer.join();
        _exit(0);
    }
    std::string death_error;
    if (!wait_for_abort(child, death_error)) {
        std::cerr << "FAIL [#358 exact input mount wrong-thread death]: " << death_error << "\n";
        return 1;
    }

    auto controller = std::make_unique<ExactInputMountRecoveryController>();
    ExactInputMountHandle handle;
    ExactInputMountDiagnostic diagnostic;
    if (!controller->start(kConfig.data(), kConfig.size(), handle, diagnostic)) {
        const char* required = std::getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED");
        const bool must_run = required != nullptr && std::string(required) == "1";
        if (diagnostic.phase == ExactInputMountPhase::Preflight) {
            std::cerr << (must_run ? "FAIL" : "SKIP")
                      << " [#358 exact input mount preflight]: " << diagnostic.message << "\n";
            return must_run ? 1 : 77;
        }
        std::cerr << "FAIL [#358 exact input mount setup]: " << diagnostic.message << "\n";
        return 1;
    }
    ExactInputMountSnapshot snapshot;
    if (!controller->snapshot(handle, snapshot, diagnostic)) {
        std::cerr << "FAIL [#358 exact input mount snapshot]: " << diagnostic.message << "\n";
        return 1;
    }
    if (snapshot.state != ExactInputMountState::ReadyForObservation ||
        snapshot.destination != kExactInputMountDestination || snapshot.source_path.empty() ||
        snapshot.source_inode == 0 || snapshot.source_size != kConfig.size() ||
        snapshot.requested_type != "bind" || !snapshot.requested_read_only ||
        snapshot.requested_source != snapshot.source_path ||
        snapshot.requested_destination != snapshot.destination ||
        snapshot.requested_propagation != "rprivate" || snapshot.realized_type != "bind" ||
        !snapshot.realized_read_only || snapshot.realized_source != snapshot.source_path ||
        snapshot.realized_destination != snapshot.destination || !snapshot.realized_mode.empty() ||
        snapshot.realized_propagation != "rprivate" || !snapshot.exact_container_identity ||
        !snapshot.exact_proc_credentials || !snapshot.parser_mutation_matrix_passed ||
        snapshot.parser_rejections < 15u) {
        std::cerr << "FAIL [#358 exact input mount evidence]: snapshot was incomplete\n";
        return 1;
    }

    // The controller is fixed-capacity and every operation is construction-thread bound.
    ExactInputMountHandle capacity_handle;
    if (controller->start(kConfig.data(), kConfig.size(), capacity_handle, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Capacity) {
        std::cerr << "FAIL [#358 exact input mount capacity]: busy slot was accepted\n";
        return 1;
    }
    bool wrong_thread_accepted = true;
    std::thread wrong_thread([&] {
        ExactInputMountSnapshot ignored;
        ExactInputMountDiagnostic rejected;
        wrong_thread_accepted = controller->snapshot(handle, ignored, rejected) ||
                                rejected.phase != ExactInputMountPhase::Thread;
    });
    wrong_thread.join();
    if (wrong_thread_accepted) {
        std::cerr << "FAIL [#358 exact input mount thread custody]: foreign thread was accepted\n";
        return 1;
    }
    ExactInputMountHandle moved(std::move(handle));
    ExactInputMountSnapshot ignored_snapshot;
    if (controller->snapshot(handle, ignored_snapshot, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Lifecycle ||
        !controller->snapshot(moved, snapshot, diagnostic)) {
        std::cerr << "FAIL [#358 exact input mount move custody]: " << diagnostic.message << "\n";
        return 1;
    }

    bool wrong_thread_read_accepted = true;
    std::thread wrong_read_thread([&] {
        ExactInputReadObservation rejected_observation;
        ExactInputMountDiagnostic rejected;
        wrong_thread_read_accepted =
            controller->observe_input_read(moved, rejected_observation, rejected) ||
            rejected.phase != ExactInputMountPhase::Thread;
    });
    wrong_read_thread.join();
    if (wrong_thread_read_accepted) {
        std::cerr << "FAIL [#358 exact input read thread custody]: foreign thread was accepted\n";
        return 1;
    }
    ExactInputReadObservation read_observation;
    if (!controller->observe_input_read(moved, read_observation, diagnostic) ||
        read_observation.outcome != ExactInputReadOutcome::Complete ||
        !read_observation.terminal_frozen || read_observation.stdout_bytes != kConfig ||
        !read_observation.stderr_bytes.empty() || !read_observation.stdout_eof ||
        !read_observation.stderr_eof || !read_observation.child_reaped ||
        !read_observation.wait_status_valid || !read_observation.process_group_owned ||
        !read_observation.process_group_gone || read_observation.deadline_exceeded ||
        read_observation.output_overflow || read_observation.stdout_read_errno != 0 ||
        read_observation.stderr_read_errno != 0 || !read_observation.pre_source_revalidated ||
        !read_observation.pre_container_identity || !read_observation.pre_mount_inspected ||
        !read_observation.pre_proc_credentials || !read_observation.post_source_revalidated ||
        !read_observation.post_container_identity || !read_observation.post_mount_inspected ||
        !read_observation.post_proc_credentials || !read_observation.registered_identity_matched ||
        !read_observation.registered_mount_matched ||
        read_observation.command_argv !=
            std::vector<std::string>(
                {"docker",
                 "exec",
                 "--user",
                 std::to_string(snapshot.source_uid) + ":" + std::to_string(snapshot.source_gid),
                 snapshot.sidecar_id,
                 "/bin/cat",
                 kExactInputMountDestination})) {
        std::cerr << "FAIL [#358 exact input read observation]: " << diagnostic.message << "\n";
        return 1;
    }
    const ExactInputReadObservation frozen_read = read_observation;
    const std::uint64_t read_commands = exact_input_mount_test_command_count();
    ExactInputReadObservation read_replay;
    if (!controller->observe_input_read(moved, read_replay, diagnostic) ||
        !read_observation_equal(read_replay, frozen_read) ||
        exact_input_mount_test_command_count() != read_commands ||
        controller->observe_input_read(handle, read_replay, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Lifecycle) {
        std::cerr << "FAIL [#358 exact input read one-shot replay]\n";
        return 1;
    }

    child = fork();
    if (child < 0) {
        std::cerr << "FAIL [#358 exact input mount handle-thread death setup]: fork failed\n";
        return 1;
    }
    if (child == 0) {
        {
            ExactInputMountHandle child_handle(std::move(moved));
        }
        _exit(0);
    }
    if (!wait_for_abort(child, death_error)) {
        std::cerr << "FAIL [#358 exact input mount handle-thread death]: " << death_error << "\n";
        return 1;
    }

    // A live borrowed handle makes destruction fail-stop before the owner graph can unwind.
    child = fork();
    if (child < 0) {
        std::cerr << "FAIL [#358 exact input mount live-handle death setup]: fork failed\n";
        return 1;
    }
    if (child == 0) {
        controller.reset();
        _exit(0);
    }
    if (!wait_for_abort(child, death_error)) {
        std::cerr << "FAIL [#358 exact input mount live-handle death]: " << death_error << "\n";
        return 1;
    }

    ExactInputMountRecoveryReceipt receipt;
    if (!controller->finish(moved, receipt, diagnostic) || !exact_terminal(receipt) ||
        !receipt.first_topology_revalidated || !receipt.second_topology_revalidated) {
        std::cerr << "FAIL [#358 exact input mount recovery]: " << diagnostic.message << "\n";
        return 1;
    }
    const ExactInputMountRecoveryReceipt frozen = receipt;
    ExactInputMountRecoveryReceipt replay;
    if (controller->finish(moved, replay, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Lifecycle ||
        !controller->recover_all(replay, diagnostic) || !receipt_equal(replay, frozen)) {
        std::cerr << "FAIL [#358 exact input mount frozen replay]: " << diagnostic.message << "\n";
        return 1;
    }

    // A handle scope may return custody without initiating partial cleanup.
    {
        ExactInputMountHandle scoped;
        if (!controller->start(kConfig.data(), kConfig.size(), scoped, diagnostic)) {
            std::cerr << "FAIL [#358 exact input mount scope handoff setup]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        if (controller->snapshot(moved, ignored_snapshot, diagnostic) ||
            diagnostic.phase != ExactInputMountPhase::Lifecycle) {
            std::cerr << "FAIL [#358 exact input mount stale generation]: stale handle accepted\n";
            return 1;
        }
        ExactInputReadObservation stale_read;
        if (controller->observe_input_read(moved, stale_read, diagnostic) ||
            diagnostic.phase != ExactInputMountPhase::Lifecycle) {
            std::cerr << "FAIL [#358 exact input read stale generation]: stale handle accepted\n";
            return 1;
        }
    }
    if (!controller->recover_all(receipt, diagnostic) || !exact_terminal(receipt)) {
        std::cerr << "FAIL [#358 exact input mount scope handoff recovery]: " << diagnostic.message
                  << "\n";
        return 1;
    }

    for (const ExactInputMountFailurePoint point : {
             ExactInputMountFailurePoint::AfterDirectory,
             ExactInputMountFailurePoint::AfterInputFile,
             ExactInputMountFailurePoint::AfterNetworkACreated,
             ExactInputMountFailurePoint::AfterNetworkAVerified,
             ExactInputMountFailurePoint::AfterNetworkBCreated,
             ExactInputMountFailurePoint::AfterNetworkBVerified,
             ExactInputMountFailurePoint::AfterBothIpamVerified,
             ExactInputMountFailurePoint::AfterNetworks,
             ExactInputMountFailurePoint::AfterHolderCreated,
             ExactInputMountFailurePoint::AfterHolderAttachedA,
             ExactInputMountFailurePoint::AfterHolderAttachedB,
             ExactInputMountFailurePoint::AfterHolder,
             ExactInputMountFailurePoint::AfterTopology,
             ExactInputMountFailurePoint::AfterSidecarCreate,
             ExactInputMountFailurePoint::AfterMountInspect,
             ExactInputMountFailurePoint::SidecarCreateReportedTimeout,
         }) {
        std::string error;
        if (!recover_injected_setup(point, error)) {
            std::cerr << "FAIL [#358 exact input mount failure boundary]: " << error << "\n";
            return 1;
        }
    }

    // A controller that never started owns no graph. Recovery freezes a
    // truthful N/A receipt without consulting Docker or the host filesystem.
    {
        ExactInputMountRecoveryController never_started;
        const std::uint64_t commands_before = exact_input_mount_test_command_count();
        ExactInputMountRecoveryReceipt never_started_receipt;
        if (!never_started.recover_all(never_started_receipt, diagnostic) ||
            never_started_receipt.state != ExactInputMountState::Settled ||
            never_started_receipt.terminal_result !=
                ExactInputMountTerminalResult::SettledCleanly ||
            !never_started_receipt.attempted || never_started_receipt.graph_mutated ||
            !never_started_receipt.cleanup_not_applicable ||
            !never_started_receipt.manifest_not_applicable ||
            !never_started_receipt.final_zero_residue ||
            !never_started_receipt.settlement_complete || !never_started_receipt.terminal_frozen ||
            exact_input_mount_test_command_count() != commands_before) {
            std::cerr << "FAIL [#358 exact input mount never-started recovery]\n";
            return 1;
        }
        const ExactInputMountRecoveryReceipt frozen_never_started = never_started_receipt;
        ExactInputMountRecoveryReceipt never_started_replay;
        if (!never_started.recover_all(never_started_replay, diagnostic) ||
            !receipt_equal(never_started_replay, frozen_never_started) ||
            exact_input_mount_test_command_count() != commands_before) {
            std::cerr << "FAIL [#358 exact input mount never-started replay]\n";
            return 1;
        }
    }

    // A pre-mutation failure is truthfully settled as not applicable and is
    // safe both for explicit recovery and ordinary controller destruction.
    {
        ExactInputMountRecoveryController pre_mutation;
        ExactInputMountHandle unused;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::PreflightBeforeMutation;
        if (pre_mutation.start(kConfig.data(), kConfig.size(), unused, diagnostic, options) ||
            diagnostic.phase != ExactInputMountPhase::Preflight ||
            !pre_mutation.recover_all(receipt, diagnostic) || !receipt.cleanup_not_applicable ||
            receipt.graph_mutated || !receipt.settlement_complete || !receipt.terminal_frozen ||
            receipt.terminal_result != ExactInputMountTerminalResult::SettledCleanly ||
            receipt.sidecar_settled || receipt.input_settled || receipt.directory_settled ||
            receipt.holder_settled || receipt.network_b_settled || receipt.network_a_settled ||
            !receipt.manifest_not_applicable || !receipt.final_zero_residue) {
            std::cerr << "FAIL [#358 exact input mount pre-mutation settlement]: "
                      << diagnostic.message << "\n";
            return 1;
        }
        const ExactInputMountRecoveryReceipt frozen_not_applicable = receipt;
        ExactInputMountRecoveryReceipt not_applicable_replay;
        if (!pre_mutation.recover_all(not_applicable_replay, diagnostic) ||
            !receipt_equal(not_applicable_replay, frozen_not_applicable)) {
            std::cerr << "FAIL [#358 exact input mount pre-mutation replay]\n";
            return 1;
        }
    }
    child = fork();
    if (child < 0) {
        std::cerr << "FAIL [#358 exact input mount pre-mutation death setup]: fork failed\n";
        return 1;
    }
    if (child == 0) {
        {
            ExactInputMountRecoveryController pre_mutation;
            ExactInputMountHandle unused;
            ExactInputMountDiagnostic child_diagnostic;
            ExactInputMountOptions options;
            options.failure_point = ExactInputMountFailurePoint::PreflightBeforeMutation;
            (void)pre_mutation.start(
                kConfig.data(), kConfig.size(), unused, child_diagnostic, options);
        }
        _exit(0);
    }
    int pre_mutation_status = 0;
    if (waitpid(child, &pre_mutation_status, 0) != child || !WIFEXITED(pre_mutation_status) ||
        WEXITSTATUS(pre_mutation_status) != 0) {
        std::cerr << "FAIL [#358 exact input mount pre-mutation death]: unsafe destruction\n";
        return 1;
    }

    // Revalidation rejection retains the complete graph; retry performs no replayed setup.
    {
        ExactInputMountRecoveryController guarded;
        ExactInputMountHandle guarded_handle;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::RejectSidecarRevalidationOnce;
        if (!guarded.start(kConfig.data(), kConfig.size(), guarded_handle, diagnostic, options) ||
            guarded.finish(guarded_handle, receipt, diagnostic) || receipt.sidecar_settled ||
            receipt.input_settled || diagnostic.phase != ExactInputMountPhase::SidecarSettlement ||
            !guarded.recover_all(receipt, diagnostic) || !exact_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input mount guarded sidecar retry]: "
                      << diagnostic.message << "\n";
            return 1;
        }
    }

    // A real network disconnect blocks at the fresh topology proof before input cleanup.
    {
        ExactInputMountRecoveryController disconnected;
        ExactInputMountHandle disconnected_handle;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::DisconnectNetworkBeforeInputCleanup;
        options.restore_test_disconnect_on_retry = true;
        if (!disconnected.start(
                kConfig.data(), kConfig.size(), disconnected_handle, diagnostic, options) ||
            disconnected.finish(disconnected_handle, receipt, diagnostic) ||
            !receipt.sidecar_settled || receipt.input_settled || receipt.directory_settled ||
            diagnostic.phase != ExactInputMountPhase::TopologyRevalidation ||
            !disconnected.recover_all(receipt, diagnostic) || !exact_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input mount disconnected topology retry]: "
                      << diagnostic.message << "\n";
            return 1;
        }
    }

    // Topology settlement evidence is committed per resource. A failure after
    // holder and B removal retains their exact ordinals; retry removes A only.
    {
        ExactInputMountRecoveryController partial_topology;
        ExactInputMountHandle partial_handle;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::RejectNetworkASettlementOnce;
        if (!partial_topology.start(
                kConfig.data(), kConfig.size(), partial_handle, diagnostic, options) ||
            partial_topology.finish(partial_handle, receipt, diagnostic) ||
            diagnostic.phase != ExactInputMountPhase::NetworkSettlement ||
            !receipt.holder_settled || !receipt.network_b_settled || receipt.network_a_settled ||
            receipt.holder_order == 0u || receipt.network_b_order <= receipt.holder_order ||
            receipt.network_a_order != 0u || receipt.holder_remove_command_count != 1u ||
            receipt.network_b_remove_command_count != 1u ||
            receipt.network_a_remove_command_count != 0u || receipt.final_zero_residue ||
            receipt.settlement_complete || receipt.terminal_frozen) {
            std::cerr << "FAIL [#358 exact input mount partial topology custody]: "
                      << diagnostic.message << "\n";
            return 1;
        }
        const std::uint32_t holder_order = receipt.holder_order;
        const std::uint32_t network_b_order = receipt.network_b_order;
        if (!partial_topology.recover_all(receipt, diagnostic) || !exact_terminal(receipt) ||
            receipt.holder_order != holder_order || receipt.network_b_order != network_b_order ||
            receipt.network_a_order <= network_b_order ||
            receipt.holder_remove_command_count != 1u ||
            receipt.network_b_remove_command_count != 1u ||
            receipt.network_a_remove_command_count != 1u) {
            std::cerr << "FAIL [#358 exact input mount topology retry]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        const ExactInputMountRecoveryReceipt frozen_partial = receipt;
        const std::uint64_t commands_before_replay = exact_input_mount_test_command_count();
        ExactInputMountRecoveryReceipt partial_replay;
        if (!partial_topology.recover_all(partial_replay, diagnostic) ||
            !receipt_equal(partial_replay, frozen_partial) ||
            exact_input_mount_test_command_count() != commands_before_replay) {
            std::cerr << "FAIL [#358 exact input mount partial topology replay]\n";
            return 1;
        }
    }

    // Command-success/reported-timeout sidecar cleanup still requires exact absence proof.
    {
        ExactInputMountRecoveryController timed;
        ExactInputMountHandle timed_handle;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::SidecarCleanupReportedTimeout;
        if (!timed.start(kConfig.data(), kConfig.size(), timed_handle, diagnostic, options) ||
            !timed.finish(timed_handle, receipt, diagnostic) || !exact_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input mount timeout recovery]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    // Exact, externally caused disappearance settles the whole graph but can
    // never be rewritten into a successful operation result.
    for (const auto& anomaly : {
             std::pair{ExactInputMountFailurePoint::SidecarDisappearBeforeCleanup,
                       ExactInputMountPhase::SidecarSettlement},
             std::pair{ExactInputMountFailurePoint::HolderDisappearBeforeCleanup,
                       ExactInputMountPhase::HolderSettlement},
         }) {
        ExactInputMountRecoveryController anomalous;
        ExactInputMountHandle anomalous_handle;
        ExactInputMountOptions options;
        options.failure_point = anomaly.first;
        if (!anomalous.start(
                kConfig.data(), kConfig.size(), anomalous_handle, diagnostic, options) ||
            anomalous.finish(anomalous_handle, receipt, diagnostic) ||
            !operation_failure_terminal(receipt, anomaly.second)) {
            std::cerr << "FAIL [#358 exact input mount operation anomaly]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        const ExactInputMountRecoveryReceipt frozen_failure = receipt;
        ExactInputMountRecoveryReceipt failure_replay;
        if (anomalous.recover_all(failure_replay, diagnostic) ||
            !receipt_equal(failure_replay, frozen_failure)) {
            std::cerr << "FAIL [#358 exact input mount operation anomaly replay]\n";
            return 1;
        }
    }
    // A real sidecar death between the two identity brackets rejects stale
    // /proc credential evidence and still permits exact recovery.
    {
        ExactInputMountRecoveryController bracketed;
        ExactInputMountHandle never_borrowed;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::CredentialBoundarySidecarDeath;
        if (bracketed.start(kConfig.data(), kConfig.size(), never_borrowed, diagnostic, options) ||
            diagnostic.phase != ExactInputMountPhase::MountInspect ||
            diagnostic.message.find("post-read exact sidecar identity proof failed") ==
                std::string::npos ||
            !bracketed.recover_all(receipt, diagnostic) || !truthful_partial_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input mount credential bracket]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    // A successful cat followed by real sidecar death cannot satisfy the
    // post-command immutable-identity bracket. Recovery remains sidecar-first
    // and freezes the original observation failure after proving zero residue.
    {
        ExactInputMountRecoveryController died_after_read;
        ExactInputMountHandle death_handle;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::InputReadPostCommandSidecarDeath;
        if (!died_after_read.start(
                kConfig.data(), kConfig.size(), death_handle, diagnostic, options)) {
            std::cerr << "FAIL [#358 exact input post-read death setup]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        ExactInputReadObservation failed;
        if (died_after_read.observe_input_read(death_handle, failed, diagnostic) ||
            failed.outcome != ExactInputReadOutcome::ContainerIdentityFailed ||
            !failed.pre_source_revalidated || !failed.pre_container_identity ||
            !failed.pre_mount_inspected || !failed.pre_proc_credentials ||
            !failed.command_started || !failed.child_reaped || !failed.process_group_owned ||
            !failed.process_group_gone || failed.post_container_identity ||
            diagnostic.phase != ExactInputMountPhase::InputObservation) {
            std::cerr << "FAIL [#358 exact input post-read death bracket]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        const ExactInputReadObservation frozen_failed = failed;
        const std::uint64_t failed_commands = exact_input_mount_test_command_count();
        ExactInputReadObservation failed_replay;
        if (died_after_read.observe_input_read(death_handle, failed_replay, diagnostic) ||
            !read_observation_equal(failed_replay, frozen_failed) ||
            exact_input_mount_test_command_count() != failed_commands ||
            died_after_read.finish(death_handle, receipt, diagnostic) ||
            !operation_failure_terminal(receipt, ExactInputMountPhase::InputObservation) ||
            receipt.sidecar_order == 0u || receipt.input_order <= receipt.sidecar_order ||
            receipt.directory_order <= receipt.input_order || !receipt.final_zero_residue) {
            std::cerr << "FAIL [#358 exact input failed-read recovery]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        const ExactInputMountRecoveryReceipt frozen_failure = receipt;
        const std::uint64_t recovery_commands = exact_input_mount_test_command_count();
        if (died_after_read.recover_all(receipt, diagnostic) ||
            !receipt_equal(receipt, frozen_failure) ||
            exact_input_mount_test_command_count() != recovery_commands) {
            std::cerr << "FAIL [#358 exact input failed-read frozen receipt]\n";
            return 1;
        }
    }
    // Source-bracket refusal is a one-shot attempted failure with no cat.
    {
        ExactInputMountRecoveryController source_rejected;
        ExactInputMountHandle source_handle;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::InputReadRejectSourceRevalidation;
        if (!source_rejected.start(
                kConfig.data(), kConfig.size(), source_handle, diagnostic, options)) {
            std::cerr << "FAIL [#358 exact input source rejection setup]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        const std::uint64_t before_rejection = exact_input_mount_test_command_count();
        ExactInputReadObservation rejected;
        if (source_rejected.observe_input_read(source_handle, rejected, diagnostic) ||
            rejected.outcome != ExactInputReadOutcome::SourceRevalidationFailed ||
            rejected.command_started || !rejected.attempted || !rejected.terminal_frozen ||
            exact_input_mount_test_command_count() != before_rejection) {
            std::cerr << "FAIL [#358 exact input source rejection]: " << diagnostic.message << "\n";
            return 1;
        }
        if (source_rejected.finish(source_handle, receipt, diagnostic) ||
            !operation_failure_terminal(receipt, ExactInputMountPhase::InputObservation)) {
            std::cerr << "FAIL [#358 exact input source rejection recovery]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    // The mounted input is uninterpreted bytes in this slice, including embedded NUL.
    {
        const std::string binary_input("a\0b\n", 4);
        ExactInputMountRecoveryController binary;
        ExactInputMountHandle binary_handle;
        ExactInputMountSnapshot binary_snapshot;
        ExactInputReadObservation binary_read;
        if (!binary.start(binary_input.data(), binary_input.size(), binary_handle, diagnostic) ||
            !binary.snapshot(binary_handle, binary_snapshot, diagnostic) ||
            binary_snapshot.source_size != binary_input.size() ||
            !binary.observe_input_read(binary_handle, binary_read, diagnostic) ||
            binary_read.stdout_bytes != binary_input || !binary_read.stdout_eof ||
            !binary.finish(binary_handle, receipt, diagnostic) || !exact_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input mount embedded NUL]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    // The owner computes its capture sentinel from the owned bytes and retains
    // all 8192 bytes plus true EOF, independent of the public snapshot size.
    {
        std::string maximum(8192, '\0');
        for (size_t index = 0; index < maximum.size(); ++index)
            maximum[index] = static_cast<char>((index % 251u) + 1u);
        ExactInputMountRecoveryController max_owner;
        ExactInputMountHandle max_handle;
        ExactInputReadObservation max_read;
        if (!max_owner.start(maximum.data(), maximum.size(), max_handle, diagnostic) ||
            !max_owner.observe_input_read(max_handle, max_read, diagnostic) ||
            max_read.expected_size != maximum.size() || max_read.stdout_bytes != maximum ||
            !max_read.stdout_eof || !max_read.stderr_eof || max_read.output_overflow ||
            !max_owner.finish(max_handle, receipt, diagnostic) || !exact_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input maximum read]: " << diagnostic.message << "\n";
            return 1;
        }
    }
    std::cerr << "PASS: #358 exact read-only input mount owner and ordered recovery\n";
    return 0;
}
