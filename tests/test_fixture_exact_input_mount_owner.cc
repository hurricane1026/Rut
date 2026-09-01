#include "fixture_exact_input_mount_owner.h"
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

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
           receipt.terminal_frozen && receipt.sidecar_settled && receipt.input_settled &&
           receipt.directory_settled && receipt.holder_settled && receipt.network_b_settled &&
           receipt.network_a_settled && receipt.manifest_settled && receipt.final_zero_residue &&
           receipt.sidecar_order < receipt.input_order &&
           receipt.input_order < receipt.directory_order &&
           receipt.directory_order < receipt.holder_order &&
           receipt.holder_order < receipt.network_b_order &&
           receipt.network_b_order < receipt.network_a_order;
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
    if (!controller.recover_all(receipt, diagnostic) || !exact_terminal(receipt)) {
        error = "injected setup graph did not recover exactly: " + diagnostic.message;
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

int main() {
    using namespace rut::test::ipv4_topology;
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
        !controller->recover_all(replay, diagnostic) ||
        replay.sidecar_order != frozen.sidecar_order || replay.input_order != frozen.input_order ||
        replay.directory_order != frozen.directory_order ||
        replay.holder_order != frozen.holder_order ||
        replay.network_b_order != frozen.network_b_order ||
        replay.network_a_order != frozen.network_a_order ||
        replay.diagnostic.phase != frozen.diagnostic.phase ||
        replay.diagnostic.message != frozen.diagnostic.message) {
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
    }
    if (!controller->recover_all(receipt, diagnostic) || !exact_terminal(receipt)) {
        std::cerr << "FAIL [#358 exact input mount scope handoff recovery]: " << diagnostic.message
                  << "\n";
        return 1;
    }

    for (const ExactInputMountFailurePoint point : {
             ExactInputMountFailurePoint::AfterManifest,
             ExactInputMountFailurePoint::AfterDirectory,
             ExactInputMountFailurePoint::AfterInputFile,
             ExactInputMountFailurePoint::AfterNetworks,
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
    // The mounted input is uninterpreted bytes in this slice, including embedded NUL.
    {
        const std::string binary_input("a\0b\n", 4);
        ExactInputMountRecoveryController binary;
        ExactInputMountHandle binary_handle;
        ExactInputMountSnapshot binary_snapshot;
        if (!binary.start(binary_input.data(), binary_input.size(), binary_handle, diagnostic) ||
            !binary.snapshot(binary_handle, binary_snapshot, diagnostic) ||
            binary_snapshot.source_size != binary_input.size() ||
            !binary.finish(binary_handle, receipt, diagnostic) || !exact_terminal(receipt)) {
            std::cerr << "FAIL [#358 exact input mount embedded NUL]: " << diagnostic.message
                      << "\n";
            return 1;
        }
    }
    std::cerr << "PASS: #358 exact read-only input mount owner and ordered recovery\n";
    return 0;
}
