#include "fixture_exact_input_mount_owner.h"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>

#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace rut::test::ipv4_topology;

const std::string kConfig =
    "events {}\nhttp { server { listen 8080; location / { proxy_pass "
    "http://127.0.0.1:9000; } } }\n";

enum class BuilderMode {
    Success,
    Empty,
    False,
    Overflow,
    ThrowStandard,
    ThrowNonstandard,
    Reenter
};

struct BuilderContext {
    BuilderMode mode = BuilderMode::Success;
    ExactInputMountRecoveryController* controller = nullptr;
    std::uint32_t calls = 0;
    std::string token;
    std::string positive_ip;
    std::string guard_ip;
    std::string expected_bytes;
    bool foreign_thread_rejected = false;
    bool recursive_entries_rejected = false;
    bool recursive_commands_unchanged = false;
};

bool topology_config_builder(const ExactInputTopologyBuildRequest& request,
                             ExactInputTopologyBuildSink& sink,
                             void* opaque) {
    auto& context = *static_cast<BuilderContext*>(opaque);
    ++context.calls;
    context.token = request.token.data();
    context.positive_ip = request.positive_ipv4.data();
    context.guard_ip = request.guard_ipv4.data();
    context.expected_bytes = "events {}\nhttp { server { listen " + context.positive_ip +
                             ":41857; location / { proxy_pass http://127.0.0.1:9000; } } }\n";
    if (request.port != kExactInputTopologyBuilderPort || context.token.size() != 48u ||
        context.positive_ip.empty() || context.guard_ip.empty() ||
        context.positive_ip == context.guard_ip)
        return false;
    if (context.mode == BuilderMode::Empty) return true;
    if (context.mode == BuilderMode::False) return false;
    if (context.mode == BuilderMode::ThrowStandard) throw std::runtime_error("untrusted detail");
    if (context.mode == BuilderMode::ThrowNonstandard) throw 17;
    if (context.mode == BuilderMode::Overflow) {
        std::string maximum(kExactInputBuilderCapacity, 'x');
        if (!sink.append(maximum.data(), maximum.size())) return false;
        const char extra = 'y';
        (void)sink.append(&extra, 1u);
        return true;
    }
    if (!sink.append(context.expected_bytes.data(), context.expected_bytes.size())) return false;
    if (context.mode != BuilderMode::Reenter) return true;

    ExactInputMountHandle unused;
    std::thread foreign([&] {
        ExactInputMountDiagnostic diagnostic;
        ExactInputMountSnapshot snapshot;
        ExactInputReadObservation read;
        ExactInputWriteRefusalObservation write;
        ExactInputMountRecoveryReceipt receipt;
        const bool rejected =
            !context.controller->start(kConfig.data(), kConfig.size(), unused, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread &&
            !context.controller->start_with_topology_builder(
                topology_config_builder, opaque, unused, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread &&
            !context.controller->snapshot(unused, snapshot, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread &&
            !context.controller->observe_input_read(unused, read, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread &&
            !context.controller->observe_input_write_refusal(unused, write, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread &&
            !context.controller->finish(unused, receipt, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread &&
            !context.controller->recover_all(receipt, diagnostic) &&
            diagnostic.phase == ExactInputMountPhase::Thread;
        context.foreign_thread_rejected = rejected;
    });
    foreign.join();
    const std::uint64_t commands = exact_input_mount_test_command_count();
    ExactInputMountDiagnostic diagnostic;
    ExactInputMountSnapshot snapshot;
    ExactInputReadObservation read;
    ExactInputWriteRefusalObservation write;
    ExactInputMountRecoveryReceipt receipt;
    context.recursive_entries_rejected =
        !context.controller->start(kConfig.data(), kConfig.size(), unused, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder &&
        !context.controller->start_with_topology_builder(
            topology_config_builder, opaque, unused, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder &&
        !context.controller->snapshot(unused, snapshot, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder &&
        !context.controller->observe_input_read(unused, read, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder &&
        !context.controller->observe_input_write_refusal(unused, write, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder &&
        !context.controller->finish(unused, receipt, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder &&
        !context.controller->recover_all(receipt, diagnostic) &&
        diagnostic.phase == ExactInputMountPhase::InputBuilder;
    context.recursive_commands_unchanged = exact_input_mount_test_command_count() == commands;
    return true;
}

bool exact_terminal(const ExactInputMountRecoveryReceipt& receipt) {
    const bool nginx_order = !receipt.nginx_sibling_acquired ||
                             (receipt.nginx_sibling_settled && receipt.nginx_sibling_order != 0u &&
                              receipt.nginx_sibling_order < receipt.sidecar_order);
    return receipt.state == ExactInputMountState::Settled && receipt.settlement_complete &&
           receipt.terminal_result == ExactInputMountTerminalResult::SettledCleanly &&
           receipt.graph_mutated && !receipt.cleanup_not_applicable && receipt.sidecar_acquired &&
           receipt.input_acquired && receipt.directory_acquired && receipt.holder_acquired &&
           receipt.network_b_acquired && receipt.network_a_acquired && receipt.terminal_frozen &&
           nginx_order && receipt.sidecar_settled && receipt.input_settled &&
           receipt.directory_settled && receipt.holder_settled && receipt.network_b_settled &&
           receipt.network_a_settled && receipt.manifest_not_applicable &&
           receipt.final_zero_residue && receipt.sidecar_order < receipt.input_order &&
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
    for (const std::uint32_t order : {receipt.nginx_sibling_order,
                                      receipt.sidecar_order,
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
           exact_event(receipt.nginx_sibling_acquired,
                       receipt.nginx_sibling_settled,
                       receipt.nginx_sibling_order) &&
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

bool builder_bracket_equal(const ExactInputBuilderBracketEvidence& left,
                           const ExactInputBuilderBracketEvidence& right) {
    return left.topology_verified == right.topology_verified &&
           left.snapshot_equal_to_a == right.snapshot_equal_to_a &&
           left.tcp_absence_verified == right.tcp_absence_verified &&
           left.tcp_absence_pre_equal == right.tcp_absence_pre_equal &&
           left.tcp_absence_post_equal == right.tcp_absence_post_equal &&
           left.tcp6_absence_verified == right.tcp6_absence_verified &&
           left.tcp6_absence_pre_equal == right.tcp6_absence_pre_equal &&
           left.tcp6_absence_post_equal == right.tcp6_absence_post_equal &&
           left.positive_refusal_verified == right.positive_refusal_verified &&
           left.positive_refusal_pre_equal == right.positive_refusal_pre_equal &&
           left.positive_refusal_post_equal == right.positive_refusal_post_equal &&
           left.guard_refusal_verified == right.guard_refusal_verified &&
           left.guard_refusal_pre_equal == right.guard_refusal_pre_equal &&
           left.guard_refusal_post_equal == right.guard_refusal_post_equal;
}

bool builder_evidence_equal(const ExactInputBuilderEvidence& left,
                            const ExactInputBuilderEvidence& right) {
    return left.applicable == right.applicable &&
           left.request_validated == right.request_validated && left.token == right.token &&
           left.positive_ipv4 == right.positive_ipv4 && left.guard_ipv4 == right.guard_ipv4 &&
           left.port == right.port && builder_bracket_equal(left.bracket_a, right.bracket_a) &&
           builder_bracket_equal(left.bracket_b, right.bracket_b) &&
           builder_bracket_equal(left.bracket_c, right.bracket_c) &&
           builder_bracket_equal(left.bracket_d, right.bracket_d) &&
           left.invocation_count == right.invocation_count &&
           left.returned_normally == right.returned_normally &&
           left.threw_exception == right.threw_exception &&
           left.callback_reported_success == right.callback_reported_success &&
           left.reentry_attempted == right.reentry_attempted && left.sink_size == right.sink_size &&
           left.sink_overflow == right.sink_overflow &&
           left.output_accepted == right.output_accepted &&
           left.directory_acquired_after_builder == right.directory_acquired_after_builder &&
           left.input_acquired_after_builder == right.input_acquired_after_builder;
}

bool receipt_equal(const ExactInputMountRecoveryReceipt& left,
                   const ExactInputMountRecoveryReceipt& right) {
    return left.state == right.state && left.terminal_result == right.terminal_result &&
           left.attempted == right.attempted && left.graph_mutated == right.graph_mutated &&
           left.mutation_may_have_occurred == right.mutation_may_have_occurred &&
           left.recovery_required == right.recovery_required &&
           left.cleanup_not_applicable == right.cleanup_not_applicable &&
           left.nginx_sibling_acquired == right.nginx_sibling_acquired &&
           left.sidecar_acquired == right.sidecar_acquired &&
           left.input_acquired == right.input_acquired &&
           left.directory_acquired == right.directory_acquired &&
           left.holder_acquired == right.holder_acquired &&
           left.network_b_acquired == right.network_b_acquired &&
           left.network_a_acquired == right.network_a_acquired &&
           left.nginx_sibling_settled == right.nginx_sibling_settled &&
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
           left.nginx_create_count == right.nginx_create_count &&
           left.nginx_start_count == right.nginx_start_count &&
           left.nginx_remove_count == right.nginx_remove_count &&
           left.holder_remove_command_count == right.holder_remove_command_count &&
           left.network_b_remove_command_count == right.network_b_remove_command_count &&
           left.network_a_remove_command_count == right.network_a_remove_command_count &&
           left.nginx_sibling_order == right.nginx_sibling_order &&
           left.sidecar_order == right.sidecar_order && left.input_order == right.input_order &&
           left.directory_order == right.directory_order &&
           left.holder_order == right.holder_order &&
           left.network_b_order == right.network_b_order &&
           left.network_a_order == right.network_a_order &&
           builder_evidence_equal(left.builder, right.builder) &&
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
    if (name == "immediate") return 0;
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
    if (name == "control-eof-descendant") {
        const pid_t leader = getpid();
        const pid_t descendant = fork();
        if (descendant < 0) return 126;
        if (descendant == 0) {
            // Do not make either stream reach EOF until this process has
            // causally observed that its leader exited and it was adopted by
            // the supervisor subreaper.
            for (unsigned attempt = 0; attempt < 1000u && getppid() == leader; ++attempt)
                (void)poll(nullptr, 0, 1);
            if (getppid() == leader || !write_all(STDOUT_FILENO, "control-eof-descendant-live"))
                _exit(125);
            if (close(STDOUT_FILENO) != 0 || close(STDERR_FILENO) != 0) _exit(125);
            (void)poll(nullptr, 0, 3000);
            _exit(124);
        }
        return 0;
    }
    if (name == "handoff") {
        constexpr unsigned kGenerations = 32;
        for (unsigned generation = 0; generation < kGenerations; ++generation) {
            const pid_t next = fork();
            if (next < 0) return 126;
            if (next > 0) return 0;
        }
        errno = 0;
        const bool setpgid_blocked = setpgid(0, 0) < 0 && errno == EPERM;
        errno = 0;
        const bool setsid_blocked = setsid() < 0 && errno == EPERM;
        if (!setpgid_blocked || !setsid_blocked || !write_all(STDOUT_FILENO, "handoff")) _exit(126);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        (void)poll(nullptr, 0, 3000);
        _exit(0);
    }
    if (name == "confinement") {
        const pid_t ordinary = fork();
        if (ordinary < 0) return 126;
        if (ordinary == 0) {
            errno = 0;
            const bool group_denied = setpgid(0, 0) < 0 && errno == EPERM;
            errno = 0;
            const bool session_denied = setsid() < 0 && errno == EPERM;
            _exit(group_denied && session_denied ? 0 : 125);
        }
        int ordinary_status = 0;
        if (waitpid(ordinary, &ordinary_status, 0) != ordinary || !WIFEXITED(ordinary_status) ||
            WEXITSTATUS(ordinary_status) != 0)
            return 125;
#ifdef SYS_clone
        const pid_t clone_parent =
            static_cast<pid_t>(syscall(SYS_clone, CLONE_PARENT | SIGCHLD, 0, nullptr, nullptr, 0));
        if (clone_parent < 0) return 126;
        if (clone_parent == 0) _exit(0);
        int ignored = 0;
        errno = 0;
        if (waitpid(clone_parent, &ignored, WNOHANG) >= 0 || errno != ECHILD) return 125;
#endif
        return write_all(STDOUT_FILENO, "confined") ? 0 : 126;
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
           left.pidfd_opened == right.pidfd_opened &&
           left.pidfd_identity_verified == right.pidfd_identity_verified &&
           left.pidfd_closed_after_group_gone == right.pidfd_closed_after_group_gone &&
           left.final_deadline_recorded == right.final_deadline_recorded &&
           left.cleanup_completed_before_final_deadline ==
               right.cleanup_completed_before_final_deadline &&
           left.leader_exit_observed_before_group_cleanup ==
               right.leader_exit_observed_before_group_cleanup &&
           left.descendant_group_member_observed == right.descendant_group_member_observed &&
           left.supervisor_session_verified == right.supervisor_session_verified &&
           left.supervisor_subreaper_verified == right.supervisor_subreaper_verified &&
           left.actual_exec_observed == right.actual_exec_observed &&
           left.subtree_confinement_installed == right.subtree_confinement_installed &&
           left.group_echild_observed == right.group_echild_observed &&
           left.control_eof_cleanup == right.control_eof_cleanup &&
           left.setpgid_denied == right.setpgid_denied &&
           left.setsid_denied == right.setsid_denied &&
           left.clone_parent_observed == right.clone_parent_observed &&
           left.adopted_reap_count == right.adopted_reap_count &&
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
           left.command_argv == right.command_argv &&
           left.resolved_executable == right.resolved_executable &&
           left.stdout_bytes == right.stdout_bytes && left.stderr_bytes == right.stderr_bytes &&
           left.diagnostic.phase == right.diagnostic.phase &&
           left.diagnostic.error_number == right.diagnostic.error_number &&
           left.diagnostic.message == right.diagnostic.message;
}

bool write_bracket_equal(const ExactInputWriteSourceBracket& left,
                         const ExactInputWriteSourceBracket& right) {
    return left.source_revalidated == right.source_revalidated &&
           left.source_bytes_revalidated == right.source_bytes_revalidated &&
           left.retained_ofd_revalidated == right.retained_ofd_revalidated &&
           left.container_identity_revalidated == right.container_identity_revalidated &&
           left.mount_revalidated == right.mount_revalidated &&
           left.proc_credentials_revalidated == right.proc_credentials_revalidated &&
           left.registered_identity_matched == right.registered_identity_matched &&
           left.registered_mount_matched == right.registered_mount_matched &&
           left.source_path == right.source_path && left.source_device == right.source_device &&
           left.source_inode == right.source_inode && left.source_mode == right.source_mode &&
           left.source_uid == right.source_uid && left.source_gid == right.source_gid &&
           left.source_size == right.source_size && left.source_links == right.source_links &&
           left.source_mtime_seconds == right.source_mtime_seconds &&
           left.source_mtime_nanoseconds == right.source_mtime_nanoseconds &&
           left.source_ctime_seconds == right.source_ctime_seconds &&
           left.source_ctime_nanoseconds == right.source_ctime_nanoseconds;
}

bool write_refusal_observation_equal(const ExactInputWriteRefusalObservation& left,
                                     const ExactInputWriteRefusalObservation& right) {
    return left.outcome == right.outcome && left.attempted == right.attempted &&
           left.terminal_frozen == right.terminal_frozen &&
           left.caller_deadline_recorded == right.caller_deadline_recorded &&
           left.final_deadline_nanoseconds == right.final_deadline_nanoseconds &&
           left.credentials == right.credentials &&
           left.expected_target_stderr == right.expected_target_stderr &&
           write_bracket_equal(left.initial_bracket, right.initial_bracket) &&
           write_bracket_equal(left.middle_bracket, right.middle_bracket) &&
           write_bracket_equal(left.final_bracket, right.final_bracket) &&
           read_observation_equal(left.control, right.control) &&
           read_observation_equal(left.target, right.target) &&
           left.diagnostic.phase == right.diagnostic.phase &&
           left.diagnostic.error_number == right.diagnostic.error_number &&
           left.diagnostic.message == right.diagnostic.message;
}

bool complete_supervisor_evidence(const ExactInputReadObservation& observation) {
    return observation.attempted && observation.terminal_frozen && observation.command_started &&
           observation.stdout_eof && observation.stderr_eof && observation.child_reaped &&
           observation.wait_status_valid && observation.process_group_owned &&
           observation.process_group_gone && observation.pidfd_opened &&
           observation.pidfd_identity_verified && observation.pidfd_closed_after_group_gone &&
           observation.final_deadline_recorded &&
           observation.cleanup_completed_before_final_deadline &&
           observation.supervisor_session_verified && observation.supervisor_subreaper_verified &&
           observation.actual_exec_observed && observation.subtree_confinement_installed &&
           observation.group_echild_observed && observation.adopted_reap_count > 0u &&
           !observation.deadline_exceeded && !observation.output_overflow &&
           observation.stdout_read_errno == 0 && observation.stderr_read_errno == 0 &&
           !observation.resolved_executable.empty() &&
           observation.resolved_executable.front() == '/';
}

bool complete_write_bracket(const ExactInputWriteSourceBracket& bracket) {
    return bracket.source_revalidated && bracket.source_bytes_revalidated &&
           bracket.retained_ofd_revalidated && bracket.container_identity_revalidated &&
           bracket.mount_revalidated && bracket.proc_credentials_revalidated &&
           bracket.registered_identity_matched && bracket.registered_mount_matched &&
           !bracket.source_path.empty() && bracket.source_device != 0u &&
           bracket.source_inode != 0u && (bracket.source_mode & 07777u) == 0600u &&
           bracket.source_links == 1u;
}

bool complete_builder_bracket(const ExactInputBuilderBracketEvidence& bracket) {
    return bracket.topology_verified && bracket.snapshot_equal_to_a &&
           bracket.tcp_absence_verified && bracket.tcp_absence_pre_equal &&
           bracket.tcp_absence_post_equal && bracket.tcp6_absence_verified &&
           bracket.tcp6_absence_pre_equal && bracket.tcp6_absence_post_equal &&
           bracket.positive_refusal_verified && bracket.positive_refusal_pre_equal &&
           bracket.positive_refusal_post_equal && bracket.guard_refusal_verified &&
           bracket.guard_refusal_pre_equal && bracket.guard_refusal_post_equal;
}

bool exact_read_runner_self_checks(std::string& error) {
    const std::vector<std::pair<ExactInputReadRunnerTestCase, ExactInputReadOutcome>> cases = {
        {ExactInputReadRunnerTestCase::CommandStartFailure,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::ImmediateExecSuccess, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::LeaderExitWithDescendant,
         ExactInputReadOutcome::DeadlineExceeded},
        {ExactInputReadRunnerTestCase::ForkHandoffChain, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::SubtreeConfinement, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::ParentControlEof, ExactInputReadOutcome::Complete},
        {ExactInputReadRunnerTestCase::StatusShort, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusOversize, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusMultiple, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusBadMagic, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusBadVersion, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusReserved, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusNoneStage, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusPidfdOpenStage,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusPidfdIdentityStage,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusExecStatusProtocolStage,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusUnknownStage,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusZeroErrno, ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusNegativeErrno,
         ExactInputReadOutcome::CommandStartFailed},
        {ExactInputReadRunnerTestCase::StatusZeroBytePreExecDeath,
         ExactInputReadOutcome::CommandStartFailed},
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
        const bool protocol_failure =
            test_case >= ExactInputReadRunnerTestCase::StatusShort &&
            test_case <= ExactInputReadRunnerTestCase::StatusZeroBytePreExecDeath;
        const bool start_failure =
            test_case == ExactInputReadRunnerTestCase::CommandStartFailure || protocol_failure;
        if (observation.command_started == start_failure || !observation.child_reaped ||
            !observation.wait_status_valid || !observation.process_group_owned ||
            !observation.process_group_gone || !observation.pidfd_opened ||
            !observation.pidfd_identity_verified || !observation.pidfd_closed_after_group_gone ||
            !observation.final_deadline_recorded ||
            !observation.cleanup_completed_before_final_deadline ||
            !observation.supervisor_session_verified ||
            !observation.supervisor_subreaper_verified ||
            !observation.subtree_confinement_installed || !observation.group_echild_observed ||
            observation.adopted_reap_count == 0u ||
            observation.actual_exec_observed == start_failure) {
            error = "exact-read start/child/PGID evidence was not causal";
            return false;
        }
        if (observation.resolved_executable.empty() ||
            observation.resolved_executable.front() != '/') {
            error = "direct execve executable evidence was not resolved without a shell";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::CommandStartFailure &&
            (observation.launch_failure_stage != ExactInputReadLaunchStage::Execute ||
             observation.launch_errno != ENOENT)) {
            error = "real exec failure did not preserve exact stage and errno";
            return false;
        }
        if (protocol_failure &&
            (observation.launch_failure_stage != ExactInputReadLaunchStage::ExecStatusProtocol ||
             observation.launch_errno != EPROTO)) {
            error = "malformed exec-status datagram was not rejected fail closed";
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
        if (test_case == ExactInputReadRunnerTestCase::ForkHandoffChain &&
            (observation.adopted_reap_count != 33u || !observation.setpgid_denied ||
             !observation.setsid_denied || !observation.descendant_group_member_observed)) {
            error = "32-generation handoff chain escaped exact subreaper/group custody";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::SubtreeConfinement &&
            (!observation.setpgid_denied || !observation.setsid_denied ||
             !observation.clone_parent_observed || observation.adopted_reap_count != 2u)) {
            error = "seccomp or CLONE_PARENT custody evidence was incomplete";
            return false;
        }
        if (test_case == ExactInputReadRunnerTestCase::ParentControlEof &&
            (!observation.control_eof_cleanup || !observation.stdout_eof ||
             !observation.stderr_eof || observation.stdout_bytes != "control-eof-descendant-live" ||
             !observation.leader_exit_observed_before_group_cleanup ||
             !observation.descendant_group_member_observed ||
             observation.adopted_reap_count != 2u || !observation.group_echild_observed ||
             !observation.cleanup_completed_before_final_deadline)) {
            error = "parent control EOF did not causally trigger supervisor cleanup";
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
            (!observation.deadline_exceeded || !observation.stdout_eof)) {
            error = "held-open exact bytes did not require bounded cleanup before EOF";
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
    for (unsigned repetition = 0; repetition < 32u; ++repetition) {
        ExactInputReadObservation observation;
        ExactInputMountDiagnostic diagnostic;
        if (!exact_input_mount_test_read_runner_case(
                ExactInputReadRunnerTestCase::ForkHandoffChain, observation, diagnostic) ||
            observation.outcome != ExactInputReadOutcome::Complete ||
            observation.adopted_reap_count != 33u || !observation.group_echild_observed) {
            error = "repeated 32-generation handoff custody was not deterministic";
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

bool recover_injected_write_refusal(ExactInputMountFailurePoint point,
                                    std::size_t expected_attempted_commands,
                                    std::string& error) {
    ExactInputMountRecoveryController controller;
    ExactInputMountHandle handle;
    ExactInputMountDiagnostic diagnostic;
    ExactInputMountOptions options;
    options.failure_point = point;
    if (!controller.start(kConfig.data(), kConfig.size(), handle, diagnostic, options)) {
        error = "write-refusal failure setup failed: " + diagnostic.message;
        return false;
    }
    ExactInputReadObservation read;
    if (!controller.observe_input_read(handle, read, diagnostic)) {
        error = "write-refusal failure prerequisite read failed: " + diagnostic.message;
        return false;
    }
    const std::uint64_t before = exact_input_mount_test_observation_command_count();
    ExactInputWriteRefusalObservation failed;
    if (controller.observe_input_write_refusal(handle, failed, diagnostic) || !failed.attempted ||
        !failed.terminal_frozen || failed.outcome == ExactInputWriteRefusalOutcome::Complete ||
        diagnostic.phase != ExactInputMountPhase::WriteRefusalObservation ||
        exact_input_mount_test_observation_command_count() - before !=
            expected_attempted_commands) {
        error = "write-refusal injected failure was not truthful: " + diagnostic.message;
        return false;
    }
    const ExactInputWriteRefusalObservation frozen = failed;
    const std::uint64_t after = exact_input_mount_test_observation_command_count();
    ExactInputWriteRefusalObservation replay;
    if (controller.observe_input_write_refusal(handle, replay, diagnostic) ||
        !write_refusal_observation_equal(replay, frozen) ||
        exact_input_mount_test_observation_command_count() != after) {
        error = "write-refusal failure replay issued a command or changed evidence";
        return false;
    }
    ExactInputMountRecoveryReceipt receipt;
    if (controller.finish(handle, receipt, diagnostic) ||
        !operation_failure_terminal(receipt, ExactInputMountPhase::WriteRefusalObservation) ||
        !receipt.sidecar_settled || !receipt.input_settled || !receipt.directory_settled ||
        !receipt.holder_settled || !receipt.network_b_settled || !receipt.network_a_settled ||
        !receipt.final_zero_residue) {
        error = "write-refusal failure did not settle to exact zero residue: " + diagnostic.message;
        return false;
    }
    const ExactInputMountRecoveryReceipt frozen_receipt = receipt;
    const std::uint64_t settled_commands = exact_input_mount_test_command_count();
    if (controller.recover_all(receipt, diagnostic) || !receipt_equal(receipt, frozen_receipt) ||
        exact_input_mount_test_command_count() != settled_commands) {
        error = "write-refusal settled failure receipt was not immutable";
        return false;
    }
    return true;
}

bool recover_injected_nginx_lifecycle(ExactInputMountFailurePoint point,
                                      ExactInputNginxLifecycleOutcome expected_outcome,
                                      std::uint32_t expected_start_count,
                                      bool expect_frozen_absence,
                                      std::string& error) {
    ExactInputMountRecoveryController controller;
    BuilderContext context;
    context.controller = &controller;
    ExactInputMountHandle handle;
    ExactInputMountDiagnostic diagnostic;
    ExactInputMountOptions options;
    options.failure_point = point;
    ExactInputReadObservation read;
    ExactInputWriteRefusalObservation write;
    ExactInputNginxLifecycleObservation lifecycle;
    if (!controller.start_with_topology_builder(
            topology_config_builder, &context, handle, diagnostic, options) ||
        !controller.observe_input_read(handle, read, diagnostic) ||
        !controller.observe_input_write_refusal(handle, write, diagnostic) ||
        controller.observe_nginx_lifecycle(handle, lifecycle, diagnostic) ||
        lifecycle.outcome != expected_outcome || !lifecycle.attempted ||
        !lifecycle.terminal_frozen || !lifecycle.operation_failed || lifecycle.create_count != 1u ||
        lifecycle.start_count != expected_start_count ||
        lifecycle.exact_absence != expect_frozen_absence) {
        error = "injected nginx lifecycle did not freeze its exact failure: " + diagnostic.message;
        return false;
    }
    const ExactInputNginxLifecycleObservation frozen = lifecycle;
    const std::uint64_t commands = exact_input_mount_test_command_count();
    ExactInputNginxLifecycleObservation replay;
    if (controller.observe_nginx_lifecycle(handle, replay, diagnostic) ||
        replay.outcome != frozen.outcome || replay.container_id != frozen.container_id ||
        replay.create_argv != frozen.create_argv || replay.create_count != frozen.create_count ||
        replay.start_count != frozen.start_count || replay.remove_count != frozen.remove_count ||
        replay.exact_absence != frozen.exact_absence ||
        exact_input_mount_test_command_count() != commands) {
        error = "injected nginx lifecycle replay was not frozen and command-free";
        return false;
    }
    ExactInputMountRecoveryReceipt receipt;
    if (controller.finish(handle, receipt, diagnostic) ||
        !operation_failure_terminal(receipt, ExactInputMountPhase::Lifecycle) ||
        !receipt.nginx_sibling_acquired || !receipt.nginx_sibling_settled ||
        receipt.nginx_sibling_order == 0u || receipt.nginx_sibling_order >= receipt.sidecar_order ||
        receipt.nginx_create_count != 1u || receipt.nginx_start_count != expected_start_count ||
        receipt.nginx_remove_count != 1u) {
        error =
            "injected nginx lifecycle did not recover in exact graph order: " + diagnostic.message;
        return false;
    }
    const std::uint64_t settled_commands = exact_input_mount_test_command_count();
    ExactInputMountRecoveryReceipt replay_receipt;
    if (controller.recover_all(replay_receipt, diagnostic) ||
        !receipt_equal(receipt, replay_receipt) ||
        exact_input_mount_test_command_count() != settled_commands) {
        error = "injected nginx lifecycle terminal recovery replay was not inert";
        return false;
    }
    return true;
}

struct BuilderRecoveryCase {
    const char* name;
    BuilderMode mode;
    ExactInputMountFailurePoint failure_point;
    ExactInputMountPhase failure_phase;
    int failure_errno;
    const char* failure_message;
    bool returned_normally;
    bool threw_exception;
    bool callback_reported_success;
    bool sink_overflow;
    bool output_accepted;
    bool directory_acquired;
    bool prove_fresh_generation;
};

bool recover_topology_builder_failure(const BuilderRecoveryCase& test, std::string& error) {
    ExactInputMountRecoveryController controller;
    BuilderContext context;
    context.mode = test.mode;
    context.controller = &controller;
    ExactInputMountHandle never_borrowed;
    ExactInputMountDiagnostic diagnostic;
    ExactInputMountOptions options;
    options.failure_point = test.failure_point;
    if (controller.start_with_topology_builder(
            topology_config_builder, &context, never_borrowed, diagnostic, options) ||
        diagnostic.phase != test.failure_phase || diagnostic.error_number != test.failure_errno ||
        diagnostic.message != test.failure_message || context.calls != 1u) {
        error = std::string(test.name) + " did not freeze its exact initial failure";
        return false;
    }
    const ExactInputMountDiagnostic frozen_failure = diagnostic;
    const std::uint64_t failed_commands = exact_input_mount_test_command_count();
    BuilderContext blocked_context;
    blocked_context.controller = &controller;
    if (controller.start_with_topology_builder(
            topology_config_builder, &blocked_context, never_borrowed, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Capacity || blocked_context.calls != 0u ||
        context.calls != 1u || exact_input_mount_test_command_count() != failed_commands) {
        error = std::string(test.name) + " did not retain the busy failed generation";
        return false;
    }

    ExactInputMountRecoveryReceipt receipt;
    if (!controller.recover_all(receipt, diagnostic) || !truthful_partial_terminal(receipt) ||
        !receipt.mutation_may_have_occurred || !receipt.recovery_required ||
        receipt.cleanup_not_applicable || !receipt.builder.applicable ||
        !receipt.builder.request_validated || receipt.builder.invocation_count != 1u ||
        receipt.builder.returned_normally != test.returned_normally ||
        receipt.builder.threw_exception != test.threw_exception ||
        receipt.builder.callback_reported_success != test.callback_reported_success ||
        receipt.builder.reentry_attempted || receipt.builder.sink_overflow != test.sink_overflow ||
        receipt.builder.output_accepted != test.output_accepted ||
        receipt.builder.directory_acquired_after_builder != test.directory_acquired ||
        receipt.builder.input_acquired_after_builder ||
        receipt.directory_acquired != test.directory_acquired || receipt.input_acquired ||
        receipt.sidecar_acquired || !receipt.holder_acquired || !receipt.network_b_acquired ||
        !receipt.network_a_acquired || !complete_builder_bracket(receipt.builder.bracket_a) ||
        !complete_builder_bracket(receipt.builder.bracket_b) ||
        receipt.builder.bracket_d.topology_verified ||
        receipt.diagnostic.phase != frozen_failure.phase ||
        receipt.diagnostic.error_number != frozen_failure.error_number ||
        receipt.diagnostic.message != frozen_failure.message ||
        !receipt.first_topology_revalidated || !receipt.second_topology_revalidated ||
        receipt.sidecar_order != 0u || receipt.input_order != 0u ||
        receipt.directory_order != (test.directory_acquired ? 1u : 0u) ||
        receipt.holder_order != (test.directory_acquired ? 2u : 1u) ||
        receipt.network_b_order != (test.directory_acquired ? 3u : 2u) ||
        receipt.network_a_order != (test.directory_acquired ? 4u : 3u) ||
        receipt.holder_remove_command_count != 1u || receipt.network_b_remove_command_count != 1u ||
        receipt.network_a_remove_command_count != 1u ||
        receipt.builder.bracket_c.topology_verified != test.directory_acquired) {
        error = std::string(test.name) +
                " did not produce truthful bracketed ordered zero-residue recovery";
        return false;
    }
    const std::size_t expected_sink_size =
        test.sink_overflow ? kExactInputBuilderCapacity
                           : (test.output_accepted ? context.expected_bytes.size() : 0u);
    if (receipt.builder.sink_size != expected_sink_size) {
        error = std::string(test.name) + " froze an unexpected builder sink size";
        return false;
    }

    const ExactInputMountRecoveryReceipt frozen_receipt = receipt;
    const std::uint64_t terminal_commands = exact_input_mount_test_command_count();
    ExactInputMountRecoveryReceipt replay;
    if (!controller.recover_all(replay, diagnostic) || !receipt_equal(replay, frozen_receipt) ||
        exact_input_mount_test_command_count() != terminal_commands || context.calls != 1u) {
        error = std::string(test.name) + " terminal replay changed evidence or ran work";
        return false;
    }

    if (test.prove_fresh_generation) {
        BuilderContext fresh_context;
        fresh_context.controller = &controller;
        ExactInputMountHandle fresh_handle;
        if (!controller.start_with_topology_builder(
                topology_config_builder, &fresh_context, fresh_handle, diagnostic) ||
            fresh_context.calls != 1u || !controller.finish(fresh_handle, receipt, diagnostic) ||
            !exact_terminal(receipt) || receipt.builder.invocation_count != 1u) {
            error = std::string(test.name) + " did not permit one clean fresh generation";
            return false;
        }
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
    std::uint32_t write_mutation_rejections = 0u;
    ExactInputMountDiagnostic write_selfcheck_diagnostic;
    if (!exact_input_mount_test_write_refusal_self_checks(write_mutation_rejections,
                                                          write_selfcheck_diagnostic) ||
        write_mutation_rejections != 16u) {
        std::cerr << "FAIL [#358 write-refusal classifier/mutation matrix]: "
                  << write_selfcheck_diagnostic.message << "\n";
        return 1;
    }
    std::uint32_t builder_mutation_rejections = 0u;
    ExactInputMountDiagnostic builder_selfcheck_diagnostic;
    if (!exact_input_mount_test_builder_self_checks(builder_mutation_rejections,
                                                    builder_selfcheck_diagnostic) ||
        builder_mutation_rejections != 20u) {
        std::cerr << "FAIL [#408 topology builder pure mutation matrix]: "
                  << builder_selfcheck_diagnostic.message << "\n";
        return 1;
    }
    std::uint32_t lifecycle_mutation_rejections = 0u;
    ExactInputMountDiagnostic lifecycle_selfcheck_diagnostic;
    if (!exact_input_mount_test_nginx_lifecycle_self_checks(lifecycle_mutation_rejections,
                                                            lifecycle_selfcheck_diagnostic) ||
        lifecycle_mutation_rejections != 39u) {
        std::cerr << "FAIL [#358 nginx lifecycle pure mutation matrix]: "
                  << lifecycle_selfcheck_diagnostic.message << "\n";
        return 1;
    }
    {
        ExactInputTopologyBuildSink binary;
        const std::string nul("a\0b", 3u);
        if (!binary.append(nul.data(), nul.size()) || binary.size() != nul.size() ||
            std::string(binary.data(), binary.size()) != nul || binary.overflowed()) {
            std::cerr << "FAIL [#408 topology builder embedded NUL sink]\n";
            return 1;
        }
        ExactInputTopologyBuildSink maximum;
        std::string bytes(kExactInputBuilderCapacity, 'x');
        const char sentinel = 'y';
        if (!maximum.append(bytes.data(), bytes.size()) || maximum.size() != bytes.size() ||
            maximum.overflowed() || maximum.append(&sentinel, 1u) || !maximum.overflowed() ||
            maximum.append(nullptr, 0u) || maximum.size() != kExactInputBuilderCapacity) {
            std::cerr << "FAIL [#408 topology builder capacity/sticky overflow sink]\n";
            return 1;
        }
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
    const std::uint64_t pre_read_write_commands = exact_input_mount_test_command_count();
    ExactInputWriteRefusalObservation pre_read_write;
    if (controller->observe_input_write_refusal(moved, pre_read_write, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Lifecycle ||
        exact_input_mount_test_command_count() != pre_read_write_commands) {
        std::cerr << "FAIL [#358 write refusal requires exact read]\n";
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
        !read_observation.supervisor_session_verified ||
        !read_observation.supervisor_subreaper_verified || !read_observation.actual_exec_observed ||
        !read_observation.subtree_confinement_installed ||
        !read_observation.group_echild_observed || read_observation.adopted_reap_count == 0u ||
        read_observation.resolved_executable.empty() ||
        read_observation.resolved_executable.front() != '/' || read_observation.output_overflow ||
        read_observation.stdout_read_errno != 0 || read_observation.stderr_read_errno != 0 ||
        !read_observation.pre_source_revalidated || !read_observation.pre_container_identity ||
        !read_observation.pre_mount_inspected || !read_observation.pre_proc_credentials ||
        !read_observation.post_source_revalidated || !read_observation.post_container_identity ||
        !read_observation.post_mount_inspected || !read_observation.post_proc_credentials ||
        !read_observation.registered_identity_matched ||
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

    bool wrong_thread_write_accepted = true;
    std::thread wrong_write_thread([&] {
        ExactInputWriteRefusalObservation rejected_observation;
        ExactInputMountDiagnostic rejected;
        wrong_thread_write_accepted =
            controller->observe_input_write_refusal(moved, rejected_observation, rejected) ||
            rejected.phase != ExactInputMountPhase::Thread;
    });
    wrong_write_thread.join();
    if (wrong_thread_write_accepted) {
        std::cerr << "FAIL [#358 exact write-refusal thread custody]: foreign thread accepted\n";
        return 1;
    }

    ExactInputWriteRefusalObservation write_refusal;
    if (!controller->observe_input_write_refusal(moved, write_refusal, diagnostic) ||
        write_refusal.outcome != ExactInputWriteRefusalOutcome::Complete ||
        !write_refusal.attempted || !write_refusal.terminal_frozen ||
        !write_refusal.caller_deadline_recorded || write_refusal.final_deadline_nanoseconds <= 0 ||
        write_refusal.credentials !=
            std::to_string(snapshot.source_uid) + ":" + std::to_string(snapshot.source_gid) ||
        write_refusal.expected_target_stderr !=
            "dd: failed to open '/etc/nginx/nginx.conf': Read-only file system\n" ||
        !complete_write_bracket(write_refusal.initial_bracket) ||
        !write_bracket_equal(write_refusal.initial_bracket, write_refusal.middle_bracket) ||
        !write_bracket_equal(write_refusal.initial_bracket, write_refusal.final_bracket) ||
        !complete_supervisor_evidence(write_refusal.control) ||
        write_refusal.control.outcome != ExactInputReadOutcome::Complete ||
        !write_refusal.control.stdout_bytes.empty() ||
        !write_refusal.control.stderr_bytes.empty() ||
        !complete_supervisor_evidence(write_refusal.target) ||
        write_refusal.target.outcome != ExactInputReadOutcome::ExitNonzero ||
        !WIFEXITED(write_refusal.target.wait_status) ||
        WEXITSTATUS(write_refusal.target.wait_status) != 1 ||
        !write_refusal.target.stdout_bytes.empty() ||
        write_refusal.target.stderr_bytes != write_refusal.expected_target_stderr ||
        write_refusal.control.command_argv != std::vector<std::string>({"docker",
                                                                        "exec",
                                                                        "--env",
                                                                        "LC_ALL=C",
                                                                        "--user",
                                                                        write_refusal.credentials,
                                                                        snapshot.sidecar_id,
                                                                        "/usr/bin/dd",
                                                                        "if=/dev/zero",
                                                                        "of=/dev/null",
                                                                        "bs=1",
                                                                        "count=1",
                                                                        "conv=notrunc",
                                                                        "status=none"}) ||
        write_refusal.target.command_argv != std::vector<std::string>({"docker",
                                                                       "exec",
                                                                       "--env",
                                                                       "LC_ALL=C",
                                                                       "--user",
                                                                       write_refusal.credentials,
                                                                       snapshot.sidecar_id,
                                                                       "/usr/bin/dd",
                                                                       "if=/etc/nginx/nginx.conf",
                                                                       "of=/etc/nginx/nginx.conf",
                                                                       "bs=1",
                                                                       "count=1",
                                                                       "conv=notrunc",
                                                                       "status=none"})) {
        std::cerr << "FAIL [#358 exact write-refusal observation]: " << diagnostic.message << "\n";
        return 1;
    }
    const ExactInputWriteRefusalObservation frozen_write_refusal = write_refusal;
    const std::uint64_t write_commands = exact_input_mount_test_command_count();
    ExactInputWriteRefusalObservation write_replay;
    if (!controller->observe_input_write_refusal(moved, write_replay, diagnostic) ||
        !write_refusal_observation_equal(write_replay, frozen_write_refusal) ||
        exact_input_mount_test_command_count() != write_commands ||
        controller->observe_input_write_refusal(handle, write_replay, diagnostic) ||
        diagnostic.phase != ExactInputMountPhase::Lifecycle) {
        std::cerr << "FAIL [#358 exact write-refusal one-shot replay]\n";
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
        !receipt.first_topology_revalidated || !receipt.second_topology_revalidated ||
        receipt.builder.applicable || receipt.builder.request_validated ||
        receipt.builder.invocation_count != 0u || receipt.builder.output_accepted ||
        receipt.mutation_may_have_occurred || receipt.recovery_required) {
        std::cerr << "FAIL [#358 exact input mount recovery]: " << diagnostic.message << "\n";
        return 1;
    }
    for (const auto& injected : {
             std::pair{ExactInputMountFailurePoint::WriteRefusalRejectInitialBracket, 0u},
             std::pair{ExactInputMountFailurePoint::WriteRefusalRejectMiddleBracket, 1u},
             std::pair{ExactInputMountFailurePoint::WriteRefusalRejectFinalBracket, 2u},
             std::pair{ExactInputMountFailurePoint::WriteRefusalPostTargetSidecarDeath, 2u},
         }) {
        std::string error;
        if (!recover_injected_write_refusal(injected.first, injected.second, error)) {
            std::cerr << "FAIL [#358 write-refusal attempted failure recovery]: " << error << "\n";
            return 1;
        }
    }
    // Destructor fallback distinguishes a truthful operation failure from an
    // incomplete cleanup: terminal zero-residue operation failure is safe,
    // while a still-owned graph remains fail-stop.
    child = fork();
    if (child < 0) {
        std::cerr << "FAIL [#358 operation-failure destructor setup]: fork failed\n";
        return 1;
    }
    if (child == 0) {
        {
            ExactInputMountRecoveryController implicit;
            {
                ExactInputMountHandle implicit_handle;
                ExactInputMountOptions options;
                options.failure_point =
                    ExactInputMountFailurePoint::WriteRefusalRejectInitialBracket;
                ExactInputMountDiagnostic child_diagnostic;
                ExactInputReadObservation read;
                ExactInputWriteRefusalObservation refusal;
                if (!implicit.start(kConfig.data(),
                                    kConfig.size(),
                                    implicit_handle,
                                    child_diagnostic,
                                    options) ||
                    !implicit.observe_input_read(implicit_handle, read, child_diagnostic) ||
                    implicit.observe_input_write_refusal(
                        implicit_handle, refusal, child_diagnostic))
                    _exit(125);
            }
        }
        _exit(0);
    }
    int implicit_status = 0;
    while (waitpid(child, &implicit_status, 0) < 0 && errno == EINTR) {
    }
    if (!WIFEXITED(implicit_status) || WEXITSTATUS(implicit_status) != 0) {
        std::cerr << "FAIL [#358 terminal operation-failure destructor]\n";
        return 1;
    }

    // The destructor's pure terminal-settlement guard must reject any
    // incomplete cleanup. Real-resource destructor fail-stop is covered above
    // by parent-custodied wrong-thread/live-handle cases; do not intentionally
    // abort a process that alone owns a Docker graph.
    ExactInputMountRecoveryReceipt settled_failure;
    settled_failure.state = ExactInputMountState::Settled;
    settled_failure.terminal_result = ExactInputMountTerminalResult::SettledWithOperationFailure;
    settled_failure.attempted = true;
    settled_failure.graph_mutated = true;
    settled_failure.sidecar_acquired = settled_failure.input_acquired = true;
    settled_failure.directory_acquired = settled_failure.holder_acquired = true;
    settled_failure.network_b_acquired = settled_failure.network_a_acquired = true;
    settled_failure.sidecar_settled = settled_failure.input_settled = true;
    settled_failure.directory_settled = settled_failure.holder_settled = true;
    settled_failure.network_b_settled = settled_failure.network_a_settled = true;
    settled_failure.final_zero_residue = true;
    settled_failure.settlement_complete = true;
    settled_failure.terminal_frozen = true;
    ExactInputMountRecoveryReceipt incomplete_cleanup = settled_failure;
    incomplete_cleanup.sidecar_settled = false;
    if (!exact_input_mount_test_terminal_settlement(settled_failure) ||
        exact_input_mount_test_terminal_settlement(incomplete_cleanup)) {
        std::cerr << "FAIL [#358 incomplete-cleanup destructor settlement guard]\n";
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
        ExactInputWriteRefusalObservation stale_write;
        if (controller->observe_input_write_refusal(moved, stale_write, diagnostic) ||
            diagnostic.phase != ExactInputMountPhase::Lifecycle) {
            std::cerr
                << "FAIL [#358 exact write-refusal stale generation]: stale handle accepted\n";
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
            receipt.mutation_may_have_occurred || receipt.recovery_required ||
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
            !failed.process_group_gone || !failed.supervisor_session_verified ||
            !failed.supervisor_subreaper_verified || !failed.actual_exec_observed ||
            !failed.subtree_confinement_installed || !failed.group_echild_observed ||
            failed.post_container_identity ||
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
    // #408 success: the callback alone owns formatting and the exact bytes are
    // observed through the already-proven read and write-refusal suffix.
    {
        ExactInputMountRecoveryController built;
        BuilderContext context;
        context.controller = &built;
        ExactInputMountHandle built_handle;
        ExactInputMountSnapshot built_snapshot;
        ExactInputReadObservation built_read;
        ExactInputWriteRefusalObservation built_write;
        ExactInputNginxLifecycleObservation lifecycle;
        if (!built.start_with_topology_builder(
                topology_config_builder, &context, built_handle, diagnostic) ||
            context.calls != 1u || context.expected_bytes.empty() ||
            context.expected_bytes.find("listen " + context.positive_ip + ":41857") ==
                std::string::npos ||
            context.expected_bytes.find("listen 0.0.0.0:") != std::string::npos ||
            context.expected_bytes.find("listen 41857") != std::string::npos ||
            context.expected_bytes.find("listen " + context.guard_ip + ":41857") !=
                std::string::npos ||
            !built.snapshot(built_handle, built_snapshot, diagnostic) ||
            built_snapshot.source_size != context.expected_bytes.size() ||
            !built.observe_input_read(built_handle, built_read, diagnostic) ||
            built_read.stdout_bytes != context.expected_bytes ||
            !built.observe_input_write_refusal(built_handle, built_write, diagnostic) ||
            !built.observe_nginx_lifecycle(built_handle, lifecycle, diagnostic) ||
            lifecycle.outcome != ExactInputNginxLifecycleOutcome::Complete ||
            !lifecycle.attempted || !lifecycle.terminal_frozen ||
            !lifecycle.caller_deadline_recorded || lifecycle.final_deadline_nanoseconds <= 0 ||
            !lifecycle.create_attempted || !lifecycle.created || lifecycle.create_count != 1u ||
            !lifecycle.start_attempted || !lifecycle.started || lifecycle.start_count != 1u ||
            lifecycle.remove_count != 1u || !lifecycle.same_source_inode ||
            lifecycle.same_mount_instance || !lifecycle.sibling_mount_independently_verified ||
            !lifecycle.sample_a.complete || !lifecycle.sample_b.complete ||
            !lifecycle.sample_a.container_identity_verified ||
            !lifecycle.sample_a.source_revalidated || !lifecycle.sample_a.mount_verified ||
            !lifecycle.sample_a.topology_verified || !lifecycle.sample_a.cgroup_exact ||
            !lifecycle.sample_a.pidfile_exact || !lifecycle.sample_a.tcp_exact ||
            !lifecycle.sample_a.tcp6_port_absent ||
            !lifecycle.sample_a.end_container_identity_verified ||
            !lifecycle.sample_a.end_source_revalidated || !lifecycle.sample_a.end_mount_verified ||
            !lifecycle.sample_a.end_topology_verified || !lifecycle.sample_a.end_cgroup_exact ||
            !lifecycle.sample_a.end_pidfile_exact || !lifecycle.sample_a.end_process_socket_owned ||
            lifecycle.sample_a.bracket_end_nanoseconds <
                lifecycle.sample_a.bracket_start_nanoseconds ||
            !lifecycle.sample_b.container_identity_verified ||
            !lifecycle.sample_b.source_revalidated || !lifecycle.sample_b.mount_verified ||
            !lifecycle.sample_b.topology_verified || !lifecycle.sample_b.cgroup_exact ||
            !lifecycle.sample_b.pidfile_exact || !lifecycle.sample_b.tcp_exact ||
            !lifecycle.sample_b.tcp6_port_absent ||
            !lifecycle.sample_b.end_container_identity_verified ||
            !lifecycle.sample_b.end_source_revalidated || !lifecycle.sample_b.end_mount_verified ||
            !lifecycle.sample_b.end_topology_verified || !lifecycle.sample_b.end_cgroup_exact ||
            !lifecycle.sample_b.end_pidfile_exact || !lifecycle.sample_b.end_process_socket_owned ||
            lifecycle.sample_b.bracket_end_nanoseconds <
                lifecycle.sample_b.bracket_start_nanoseconds ||
            !lifecycle.samples_at_least_250ms_apart ||
            lifecycle.sample_b.bracket_start_nanoseconds -
                    lifecycle.sample_a.bracket_end_nanoseconds <
                250000000LL ||
            lifecycle.sample_a.master_pid != lifecycle.sample_b.master_pid ||
            lifecycle.sample_a.worker_pid != lifecycle.sample_b.worker_pid ||
            lifecycle.sample_a.master_start != lifecycle.sample_b.master_start ||
            lifecycle.sample_a.worker_start != lifecycle.sample_b.worker_start ||
            lifecycle.sample_a.listener_inode == 0u ||
            lifecycle.sample_a.listener_inode != lifecycle.sample_b.listener_inode ||
            !lifecycle.quit_attempted || !lifecycle.quit_only || !lifecycle.stopped_exit_zero ||
            lifecycle.term_attempted || lifecycle.kill_attempted ||
            lifecycle.force_remove_attempted || lifecycle.uncertain_cleanup ||
            !lifecycle.cgroup_empty_after_stop || !lifecycle.removed_nonforce ||
            !lifecycle.exact_absence || !lifecycle.baseline_restored ||
            lifecycle.operation_failed || lifecycle.container_id.size() != 64u ||
            lifecycle.container_name != "rut358-nginx-" + context.token ||
            ![&] {
                const std::uint64_t commands = exact_input_mount_test_command_count();
                ExactInputNginxLifecycleObservation replay;
                return built.observe_nginx_lifecycle(built_handle, replay, diagnostic) &&
                       replay.outcome == lifecycle.outcome &&
                       replay.container_id == lifecycle.container_id &&
                       replay.create_argv == lifecycle.create_argv &&
                       replay.sample_a.listener_inode == lifecycle.sample_a.listener_inode &&
                       replay.sample_b.listener_inode == lifecycle.sample_b.listener_inode &&
                       replay.remove_count == lifecycle.remove_count &&
                       replay.terminal_frozen == lifecycle.terminal_frozen &&
                       exact_input_mount_test_command_count() == commands;
            }() ||
            !built.finish(built_handle, receipt, diagnostic) || !exact_terminal(receipt) ||
            !receipt.nginx_sibling_acquired || !receipt.nginx_sibling_settled ||
            receipt.nginx_sibling_order == 0u ||
            receipt.nginx_sibling_order >= receipt.sidecar_order ||
            receipt.nginx_create_count != 1u || receipt.nginx_start_count != 1u ||
            receipt.nginx_remove_count != 1u || !receipt.builder.applicable ||
            !receipt.builder.request_validated || receipt.builder.invocation_count != 1u ||
            !receipt.builder.returned_normally || receipt.builder.threw_exception ||
            !receipt.builder.callback_reported_success || receipt.builder.reentry_attempted ||
            receipt.builder.sink_overflow ||
            receipt.builder.sink_size != context.expected_bytes.size() ||
            !receipt.builder.output_accepted || !receipt.builder.directory_acquired_after_builder ||
            !receipt.builder.input_acquired_after_builder ||
            !complete_builder_bracket(receipt.builder.bracket_a) ||
            !complete_builder_bracket(receipt.builder.bracket_b) ||
            !complete_builder_bracket(receipt.builder.bracket_c) ||
            !complete_builder_bracket(receipt.builder.bracket_d) ||
            std::string(receipt.builder.token.data()) != context.token ||
            std::string(receipt.builder.positive_ipv4.data()) != context.positive_ip ||
            std::string(receipt.builder.guard_ipv4.data()) != context.guard_ip ||
            receipt.builder.port != kExactInputTopologyBuilderPort ||
            !receipt.mutation_may_have_occurred || !receipt.recovery_required) {
            std::cerr << "FAIL [#408 topology-bound exact input success]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    for (const auto& test : std::array{
             std::tuple{ExactInputMountFailurePoint::NginxCreateReportedTimeout,
                        ExactInputNginxLifecycleOutcome::CreateFailed,
                        0u,
                        true},
             std::tuple{ExactInputMountFailurePoint::NginxStartReportedTimeout,
                        ExactInputNginxLifecycleOutcome::StartFailed,
                        1u,
                        true},
             std::tuple{ExactInputMountFailurePoint::NginxRemoveUnresolved,
                        ExactInputNginxLifecycleOutcome::RemovalFailed,
                        1u,
                        false},
         }) {
        std::string error;
        if (!recover_injected_nginx_lifecycle(std::get<0>(test),
                                              std::get<1>(test),
                                              std::get<2>(test),
                                              std::get<3>(test),
                                              error)) {
            std::cerr << "FAIL [#358 nginx lifecycle uncertain recovery]: " << error << "\n";
            return 1;
        }
    }
    // Every public entry rejects during the callback. Foreign-thread entries
    // touch no controller state; same-thread entries latch one fail-closed outer
    // result after authoritative bracket B. Recovery is explicit and replay is inert.
    {
        ExactInputMountRecoveryController reentrant;
        BuilderContext context;
        context.mode = BuilderMode::Reenter;
        context.controller = &reentrant;
        ExactInputMountHandle never_borrowed;
        if (reentrant.start_with_topology_builder(
                topology_config_builder, &context, never_borrowed, diagnostic) ||
            diagnostic.phase != ExactInputMountPhase::InputBuilder || context.calls != 1u ||
            !context.foreign_thread_rejected || !context.recursive_entries_rejected ||
            !context.recursive_commands_unchanged) {
            std::cerr << "FAIL [#408 topology builder recursive/foreign entry]: "
                      << diagnostic.message << "\n";
            return 1;
        }
        const std::uint64_t failed_commands = exact_input_mount_test_command_count();
        if (reentrant.start_with_topology_builder(
                topology_config_builder, &context, never_borrowed, diagnostic) ||
            diagnostic.phase != ExactInputMountPhase::Capacity || context.calls != 1u ||
            exact_input_mount_test_command_count() != failed_commands ||
            !reentrant.recover_all(receipt, diagnostic) || !truthful_partial_terminal(receipt) ||
            !receipt.builder.reentry_attempted || receipt.builder.invocation_count != 1u ||
            !complete_builder_bracket(receipt.builder.bracket_a) ||
            !complete_builder_bracket(receipt.builder.bracket_b)) {
            std::cerr << "FAIL [#408 topology builder busy/recovery]: " << diagnostic.message
                      << "\n";
            return 1;
        }
        const ExactInputMountRecoveryReceipt frozen = receipt;
        const std::uint64_t terminal_commands = exact_input_mount_test_command_count();
        if (!reentrant.recover_all(receipt, diagnostic) || !receipt_equal(receipt, frozen) ||
            exact_input_mount_test_command_count() != terminal_commands) {
            std::cerr << "FAIL [#408 topology builder terminal replay]\n";
            return 1;
        }
        BuilderContext next_generation;
        next_generation.controller = &reentrant;
        ExactInputMountHandle next_handle;
        if (!reentrant.start_with_topology_builder(
                topology_config_builder, &next_generation, next_handle, diagnostic) ||
            next_generation.calls != 1u || !reentrant.finish(next_handle, receipt, diagnostic) ||
            !exact_terminal(receipt) || receipt.builder.invocation_count != 1u) {
            std::cerr << "FAIL [#408 topology builder fresh generation]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    // These are real controller generations, not classifier-only cases. Each
    // callback/output boundary retains the failed slot through authoritative B,
    // then proves ordered explicit cleanup and inert terminal replay. Only the
    // deepest uncertain-input prefix repeats with a fresh successful generation.
    for (const BuilderRecoveryCase& test : std::array<BuilderRecoveryCase, 7>{{
             {"callback false",
              BuilderMode::False,
              ExactInputMountFailurePoint::None,
              ExactInputMountPhase::InputBuilder,
              0,
              "topology input builder reported failure",
              true,
              false,
              false,
              false,
              false,
              false,
              false},
             {"callback standard exception",
              BuilderMode::ThrowStandard,
              ExactInputMountFailurePoint::None,
              ExactInputMountPhase::InputBuilder,
              0,
              "topology input builder threw an exception",
              false,
              true,
              false,
              false,
              false,
              false,
              false},
             {"callback non-standard exception",
              BuilderMode::ThrowNonstandard,
              ExactInputMountFailurePoint::None,
              ExactInputMountPhase::InputBuilder,
              0,
              "topology input builder threw an exception",
              false,
              true,
              false,
              false,
              false,
              false,
              false},
             {"empty successful sink",
              BuilderMode::Empty,
              ExactInputMountFailurePoint::None,
              ExactInputMountPhase::InputBuilder,
              EINVAL,
              "topology input builder produced empty output",
              true,
              false,
              true,
              false,
              false,
              false,
              false},
             {"sticky sink overflow",
              BuilderMode::Overflow,
              ExactInputMountFailurePoint::None,
              ExactInputMountPhase::InputBuilder,
              EOVERFLOW,
              "topology input builder output exceeded 8192 bytes",
              true,
              false,
              true,
              true,
              false,
              false,
              false},
             {"directory may have mutated",
              BuilderMode::Success,
              ExactInputMountFailurePoint::BuilderDirectoryMayHaveMutated,
              ExactInputMountPhase::Directory,
              0,
              "injected uncertain directory creation result",
              true,
              false,
              true,
              false,
              true,
              false,
              false},
             {"input may have mutated",
              BuilderMode::Success,
              ExactInputMountFailurePoint::BuilderInputMayHaveMutated,
              ExactInputMountPhase::InputFile,
              0,
              "injected uncertain exact input creation result",
              true,
              false,
              true,
              false,
              true,
              true,
              true},
         }}) {
        std::string error;
        if (!recover_topology_builder_failure(test, error)) {
            std::cerr << "FAIL [#408 topology builder real failure recovery]: " << error << "\n";
            return 1;
        }
    }
    // Synthetic evidence corruption never mutates the live topology. Each
    // bracket/observation rejects locally, retains capacity, and recovers the
    // exact acquired prefix before the next independent owner generation.
    struct BuilderFaultExpectation {
        ExactInputMountFailurePoint point;
        std::uint32_t calls;
        bool output;
        bool directory;
        bool input;
    };
    for (const BuilderFaultExpectation expectation : std::array<BuilderFaultExpectation, 8>{{
             {ExactInputMountFailurePoint::BuilderRejectBracketA, 0u, false, false, false},
             {ExactInputMountFailurePoint::BuilderRejectBracketB, 1u, false, false, false},
             {ExactInputMountFailurePoint::BuilderRejectBracketC, 1u, true, true, false},
             {ExactInputMountFailurePoint::BuilderRejectBracketD, 1u, true, true, true},
             {ExactInputMountFailurePoint::BuilderRejectTcpBracket, 0u, false, false, false},
             {ExactInputMountFailurePoint::BuilderRejectTcp6Bracket, 0u, false, false, false},
             {ExactInputMountFailurePoint::BuilderRejectPositiveProbeBracket,
              0u,
              false,
              false,
              false},
             {ExactInputMountFailurePoint::BuilderRejectGuardProbeBracket, 0u, false, false, false},
         }}) {
        ExactInputMountRecoveryController corrupted;
        BuilderContext context;
        context.controller = &corrupted;
        ExactInputMountHandle never_borrowed;
        ExactInputMountOptions options;
        options.failure_point = expectation.point;
        if (corrupted.start_with_topology_builder(
                topology_config_builder, &context, never_borrowed, diagnostic, options) ||
            diagnostic.phase != ExactInputMountPhase::InputBuilder ||
            context.calls != expectation.calls || !corrupted.recover_all(receipt, diagnostic) ||
            !truthful_partial_terminal(receipt) ||
            receipt.diagnostic.phase != ExactInputMountPhase::InputBuilder ||
            !receipt.builder.applicable || receipt.builder.invocation_count != expectation.calls ||
            receipt.builder.output_accepted != expectation.output ||
            receipt.builder.directory_acquired_after_builder != expectation.directory ||
            receipt.builder.input_acquired_after_builder != expectation.input ||
            receipt.directory_acquired != expectation.directory ||
            receipt.input_acquired != expectation.input || !receipt.mutation_may_have_occurred ||
            !receipt.recovery_required || !receipt.graph_mutated) {
            std::cerr << "FAIL [#408 topology builder synthetic bracket corruption]: "
                      << diagnostic.message << "\n";
            return 1;
        }
    }
    {
        ExactInputMountRecoveryController priority;
        BuilderContext context;
        context.mode = BuilderMode::ThrowStandard;
        context.controller = &priority;
        ExactInputMountHandle never_borrowed;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::BuilderRejectBracketB;
        if (priority.start_with_topology_builder(
                topology_config_builder, &context, never_borrowed, diagnostic, options) ||
            diagnostic.phase != ExactInputMountPhase::InputBuilder ||
            diagnostic.message != "builder whole topology bracket differed from bracket A" ||
            !priority.recover_all(receipt, diagnostic) || !truthful_partial_terminal(receipt) ||
            !receipt.builder.threw_exception || receipt.builder.returned_normally ||
            receipt.builder.invocation_count != 1u ||
            receipt.diagnostic.message !=
                "builder whole topology bracket differed from bracket A") {
            std::cerr << "FAIL [#408 topology bracket B failure priority]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    {
        ExactInputMountRecoveryController uncertain;
        BuilderContext context;
        context.controller = &uncertain;
        ExactInputMountHandle never_borrowed;
        ExactInputMountOptions options;
        options.failure_point = ExactInputMountFailurePoint::BuilderNetworkMayHaveMutated;
        if (uncertain.start_with_topology_builder(
                topology_config_builder, &context, never_borrowed, diagnostic, options) ||
            diagnostic.phase != ExactInputMountPhase::Networks || context.calls != 0u ||
            !uncertain.recover_all(receipt, diagnostic) || !receipt.mutation_may_have_occurred ||
            !receipt.recovery_required || receipt.graph_mutated || receipt.cleanup_not_applicable ||
            !receipt.settlement_complete || !receipt.terminal_frozen ||
            !receipt.final_zero_residue ||
            receipt.terminal_result != ExactInputMountTerminalResult::SettledCleanly ||
            receipt.network_a_acquired || receipt.network_b_acquired || receipt.holder_acquired ||
            receipt.directory_acquired || receipt.input_acquired || receipt.sidecar_acquired) {
            std::cerr << "FAIL [#408 possible versus proven mutation receipt]: "
                      << diagnostic.message << "\n";
            return 1;
        }
    }
    std::cerr << "PASS: #358 exact read-only input mount owner and ordered recovery\n";
    return 0;
}
