// Standalone #358 Stage 2a1 protocol self-check.
//
// This test intentionally has no Docker, sudo, namespace, IP socket, or shell
// dependency.  The parent creates and owns the control socket; the child only
// connects to the already-listening endpoint and reports its identity.

#include "fixture_worker_protocol.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace rut::test::fixture_worker_protocol;

bool run_transport_tests(const Token& token, std::string& error) {
    auto one_case = [&](const std::vector<unsigned char>& bytes,
                        size_t bytes_to_write,
                        bool expect_success,
                        bool fragment) {
        int sockets[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
        bool wrote = true;
        if (fragment) {
            for (size_t i = 0; i != bytes_to_write && wrote; ++i)
                wrote = write(sockets[0], bytes.data() + i, 1) == 1;
        } else if (bytes_to_write != 0) {
            wrote = write(sockets[0], bytes.data(), bytes_to_write) ==
                    static_cast<ssize_t>(bytes_to_write);
        }
        if (shutdown(sockets[0], SHUT_WR) != 0) wrote = false;
        Frame received;
        const bool result = receive_frame(sockets[1], received, kHandshakeMs);
        close(sockets[0]);
        close(sockets[1]);
        return wrote && result == expect_success;
    };

    const Frame fragmented_frame{kPing, token, {9, 8, 7, 6, 5}};
    const std::vector<unsigned char> fragmented_bytes = frame_bytes(fragmented_frame);
    int fragmented_sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fragmented_sockets) != 0) {
        error = "fragmented frame socketpair failed";
        return false;
    }
    bool fragmented_write = true;
    for (size_t i = 0; i != fragmented_bytes.size() && fragmented_write; ++i)
        fragmented_write = write(fragmented_sockets[0], fragmented_bytes.data() + i, 1) == 1;
    (void)shutdown(fragmented_sockets[0], SHUT_WR);
    Frame fragmented_received;
    const bool fragmented_read =
        receive_frame(fragmented_sockets[1], fragmented_received, kHandshakeMs);
    const bool fragmented_exact = fragmented_received.type == fragmented_frame.type &&
                                  token_equal(fragmented_received.token, fragmented_frame.token) &&
                                  fragmented_received.payload == fragmented_frame.payload;
    close(fragmented_sockets[0]);
    close(fragmented_sockets[1]);
    if (!fragmented_write || !fragmented_read || !fragmented_exact) {
        error = "fragmented frame transport test failed";
        return false;
    }
    const Frame ping{kPing, token, {}};
    const std::vector<unsigned char> ping_bytes = frame_bytes(ping);
    if (!one_case(ping_bytes, kHeaderBytes - 1, false, false)) {
        error = "truncated header transport test failed";
        return false;
    }
    Frame payload_frame{kPing, token, {1, 2, 3, 4}};
    const std::vector<unsigned char> payload_bytes = frame_bytes(payload_frame);
    if (!one_case(payload_bytes, kHeaderBytes + 2, false, false)) {
        error = "truncated payload transport test failed";
        return false;
    }
    std::vector<unsigned char> oversized = ping_bytes;
    oversized[8] = static_cast<unsigned char>((kMaxPayload + 1) & 0xff);
    oversized[9] = static_cast<unsigned char>(((kMaxPayload + 1) >> 8) & 0xff);
    if (!one_case(oversized, kHeaderBytes, false, false)) {
        error = "oversized receive transport test failed";
        return false;
    }
    if (!one_case({}, 0, false, false)) {
        error = "early EOF transport test failed";
        return false;
    }
    int closed_peer[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, closed_peer) != 0) {
        error = "closed-peer socketpair failed";
        return false;
    }
    close(closed_peer[1]);
    const bool closed_peer_rejected = !send_frame(closed_peer[0], ping, kHandshakeMs);
    close(closed_peer[0]);
    if (!closed_peer_rejected) {
        error = "closed-peer send did not fail without terminating the process";
        return false;
    }
    return true;
}

bool run_malformed_input_tests(std::string& error) {
    Token token;
    const std::string valid_token(2 * kTokenBytes, 'a');
    if (!token_from_hex(valid_token.c_str(), token)) {
        error = "valid token was rejected";
        return false;
    }
    const std::array<std::string, 5> malformed_tokens{"",
                                                      std::string(63, 'a'),
                                                      std::string(65, 'a'),
                                                      std::string(63, 'a') + "x",
                                                      std::string(64, 'a') + "0"};
    for (const std::string& malformed : malformed_tokens) {
        if (token_from_hex(malformed.c_str(), token)) {
            error = "malformed token was accepted";
            return false;
        }
    }
    Report malformed_report;
    malformed_report.exe = "/fixture";
    const char malformed_argv[] = "/fixture\0--fixture-worker\0bad";
    malformed_report.argv.assign(malformed_argv, sizeof(malformed_argv) - 1);
    malformed_report.mode = "ready";
    if (malformed_report.argv.empty() || malformed_report.argv.back() == '\0') {
        error = "malformed argv mutation was not non-vacuous";
        return false;
    }
    const std::vector<unsigned char> malformed_payload = encode_report(malformed_report);
    Report decoded;
    if (malformed_payload.empty() || decode_report(malformed_payload, decoded)) {
        error = "malformed NUL-separated argv was accepted";
        return false;
    }
    return true;
}

int worker_main(const char* executable,
                const char* path,
                const char* token_text,
                const char* mode) {
    if (strcmp(mode, "ready") != 0 && strcmp(mode, "no-ready") != 0 &&
        strcmp(mode, "term-ignore") != 0 && strcmp(mode, "wrapper-early-death") != 0)
        return 2;
    Token token;
    if (!token_from_hex(token_text, token)) return 2;
    if (strcmp(mode, "term-ignore") == 0 || strcmp(mode, "wrapper-early-death") == 0) {
        struct sigaction action{};
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, nullptr) != 0) return 3;
    }
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) return 3;
    const pid_t lease_parent = getppid();
    u64 groups_clear = 0;
    if (!child_security_setup(groups_clear) ||
        (getppid() != lease_parent && strcmp(mode, "wrapper-early-death") != 0))
        return 3;
    const int fd = connect_control(path);
    if (fd < 0) return 4;
    if (strcmp(mode, "no-ready") == 0) {
        // A lease is held by the control connection.  Closing it must release
        // an unready worker without relying on an unbounded pause.
        for (;;) {
            pollfd descriptor{fd, POLLIN, 0};
            const int ready = poll(&descriptor, 1, 100);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || (ready > 0 && (descriptor.revents & (POLLIN | POLLERR | POLLHUP)))) {
                char byte = 0;
                if (read(fd, &byte, 1) <= 0) break;
            }
        }
        close(fd);
        return 0;
    }
    ProcIdentity proc;
    if (!read_proc(getpid(), proc)) {
        close(fd);
        return 5;
    }
    Report report;
    report.target_pid = static_cast<u64>(getpid());
    report.wrapper_pid = static_cast<u64>(getppid());
    report.start = proc.start;
    report.pgid = static_cast<u64>(proc.pgid);
    report.uid = proc.uid;
    report.gid = proc.gid;
    report.netns = proc.netns;
    report.exe_dev = proc.exe_dev;
    report.exe_ino = proc.exe_ino;
    report.no_new_privs = proc.no_new_privs ? 1 : 0;
    report.capabilities_clear = proc.capabilities_clear ? 1 : 0;
    report.groups_clear = groups_clear;
    report.groups_unchanged = groups_clear == 0 ? 1 : 0;
    report.exe = proc.exe;
    report.argv = make_expected_argv(executable, path, token_text, mode);
    report.mode = mode;
    Frame ready{kReady, token, encode_report(report)};
    if (ready.payload.empty() || !send_frame(fd, ready, kHandshakeMs)) {
        close(fd);
        return 6;
    }
    for (;;) {
        Frame command;
        if (!receive_frame(fd, command, 60'000) || !token_equal(command.token, token) ||
            !command.payload.empty()) {
            close(fd);
            return 7;
        }
        if (command.type == kPing) {
            if (!send_frame(fd, Frame{kPong, token, {}}, kHandshakeMs)) break;
        } else if (command.type == kRelease) {
            (void)send_frame(fd, Frame{kReleased, token, {}}, kHandshakeMs);
            close(fd);
            return 0;
        } else {
            close(fd);
            return 8;
        }
    }
    return 9;
}

int wrapper_main(const char* executable, const char* path, const char* token, const char* mode) {
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) return 20;
    const pid_t parent = getppid();
    const pid_t target = fork();
    if (target < 0) return 21;
    if (target == 0) {
        execl(executable,
              executable,
              "--fixture-worker",
              path,
              token,
              mode,
              static_cast<char*>(nullptr));
        _exit(127);
    }
    if (strcmp(mode, "wrapper-early-death") == 0) _exit(0);
    if (getppid() != parent) {
        (void)kill(target, SIGTERM);
        (void)waitpid(target, nullptr, 0);
        return 22;
    }
    int status = 0;
    pid_t result;
    do {
        result = waitpid(target, &status, 0);
    } while (result < 0 && errno == EINTR);
    if (result != target) return 23;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 24;
}

struct TempDir {
    std::string path;
    std::string socket;
    ~TempDir() {
        if (!socket.empty()) (void)unlink(socket.c_str());
        if (!path.empty()) (void)rmdir(path.c_str());
    }
};

bool make_temp(TempDir& temp) {
    std::array<char, 64> pattern{};
    const int written = snprintf(pattern.data(), pattern.size(), "/tmp/rut358-proto-XXXXXX");
    if (written <= 0 || static_cast<size_t>(written) >= pattern.size() ||
        mkdtemp(pattern.data()) == nullptr)
        return false;
    temp.path = pattern.data();
    temp.socket = temp.path + "/control.sock";
    return true;
}

bool launch_worker(const std::string& executable,
                   const TempDir& temp,
                   const Token& token,
                   const char* mode,
                   Child& child) {
    std::array<char, 2 * kTokenBytes + 1> token_text{};
    for (size_t i = 0; i != kTokenBytes; ++i)
        snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
    child.pid = fork();
    if (child.pid < 0) return false;
    if (child.pid == 0) {
        execl(executable.c_str(),
              executable.c_str(),
              "--fixture-wrapper",
              temp.socket.c_str(),
              token_text.data(),
              mode,
              static_cast<char*>(nullptr));
        _exit(127);
    }
    return true;
}

bool reject_changed(
    bool field_changed, bool baseline, bool mutated, const char* label, std::string& error) {
    if (!field_changed) {
        error = std::string("mutation did not change field: ") + label;
        return false;
    }
    if (baseline == mutated) {
        error = std::string("mutation did not change validation result: ") + label;
        return false;
    }
    if (!baseline || mutated) {
        error = std::string("mutation was accepted: ") + label;
        return false;
    }
    return true;
}

bool run_ready_case(const std::string& executable, std::string& error, const char* mode = "ready") {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "secure temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "parent-owned AF_UNIX listener creation failed";
        return false;
    }
    Token token;
    const u64 seed = static_cast<u64>(getpid()) ^
                     static_cast<u64>(std::chrono::steady_clock::now().time_since_epoch().count());
    for (size_t i = 0; i != token.bytes.size(); ++i)
        token.bytes[i] = static_cast<unsigned char>((seed >> ((i % 8) * 8)) + i * 17 + 3);
    Child child;
    if (!launch_worker(executable, temp, token, mode, child)) {
        close(listener);
        error = "direct worker launch failed";
        return false;
    }
    int control = -1;
    Peer peer;
    Frame ready;
    Report report;
    bool cleaned = false;
    if (!accept_bounded(listener, control) || !get_peer(control, peer) ||
        !receive_frame(control, ready, kHandshakeMs) || ready.type != kReady ||
        !decode_report(ready.payload, report)) {
        error = "missing or malformed READY frame";
    } else {
        child.target_pid = peer.pid;
        ProcIdentity proc;
        ProcIdentity wrapper;
        const std::string expected_exe = executable;
        const std::string expected_argv = [&] {
            std::array<char, 2 * kTokenBytes + 1> text{};
            for (size_t i = 0; i != kTokenBytes; ++i)
                snprintf(text.data() + i * 2, 3, "%02x", token.bytes[i]);
            return make_expected_argv(executable.c_str(), temp.socket.c_str(), text.data(), mode);
        }();
        const std::string expected_wrapper_argv = [&] {
            std::array<char, 2 * kTokenBytes + 1> text{};
            for (size_t i = 0; i != kTokenBytes; ++i)
                snprintf(text.data() + i * 2, 3, "%02x", token.bytes[i]);
            return make_expected_argv(
                executable.c_str(), temp.socket.c_str(), text.data(), mode, "--fixture-wrapper");
        }();
        const bool baseline_fields =
            read_proc(child.target_pid, proc) && read_proc(child.pid, wrapper) &&
            report.wrapper_pid == static_cast<u64>(child.pid) && proc.ppid == child.pid &&
            wrapper.uid == proc.uid && wrapper.gid == proc.gid && wrapper.exe == expected_exe &&
            wrapper.cmdline == expected_wrapper_argv &&
            identity_matches_report(report,
                                    peer,
                                    proc,
                                    expected_exe,
                                    expected_argv,
                                    mode,
                                    token,
                                    ready.token,
                                    true,
                                    false);
        if (!baseline_fields) {
            error = "READY identity did not match SO_PEERCRED and /proc";
        } else if (identity_matches_report(report,
                                           peer,
                                           proc,
                                           expected_exe,
                                           expected_argv,
                                           mode,
                                           token,
                                           ready.token,
                                           true,
                                           false,
                                           true) != (proc.supplementary_groups == 0)) {
            error = "strict supplementary-group semantics were not enforced";
        } else if (!send_frame(control, Frame{kPing, token, {}}, kHandshakeMs)) {
            error = "bounded PING write failed";
        } else {
            Frame pong;
            if (!receive_frame(control, pong, kHandshakeMs) || pong.type != kPong ||
                !token_equal(pong.token, token) || !pong.payload.empty())
                error = "bounded PONG read failed";
            else {
                const bool baseline = identity_matches_report(report,
                                                              peer,
                                                              proc,
                                                              expected_exe,
                                                              expected_argv,
                                                              mode,
                                                              token,
                                                              ready.token,
                                                              true,
                                                              false);
                Report changed = report;
                changed.target_pid++;
                (void)reject_changed(changed.target_pid != report.target_pid,
                                     baseline,
                                     identity_matches_report(changed,
                                                             peer,
                                                             proc,
                                                             expected_exe,
                                                             expected_argv,
                                                             mode,
                                                             token,
                                                             ready.token,
                                                             true,
                                                             false),
                                     "report PID",
                                     error);
                changed = report;
                changed.wrapper_pid = report.target_pid + 1;
                const bool synthetic = identity_matches_report(changed,
                                                               peer,
                                                               proc,
                                                               expected_exe,
                                                               expected_argv,
                                                               mode,
                                                               token,
                                                               ready.token,
                                                               true,
                                                               false);
                if (error.empty() && !synthetic)
                    error = "synthetic wrapper!=target model was rejected";
                changed.target_pid = changed.wrapper_pid;
                const bool wrapper_only = identity_matches_report(changed,
                                                                  peer,
                                                                  proc,
                                                                  expected_exe,
                                                                  expected_argv,
                                                                  mode,
                                                                  token,
                                                                  ready.token,
                                                                  true,
                                                                  false);
                if (error.empty() && wrapper_only) error = "wrapper-only identity was accepted";

                for (const char* label : {"peer PID", "peer uid", "peer gid"}) {
                    Peer peer_mutation = peer;
                    if (strcmp(label, "peer PID") == 0)
                        ++peer_mutation.pid;
                    else if (strcmp(label, "peer uid") == 0)
                        ++peer_mutation.uid;
                    else
                        ++peer_mutation.gid;
                    const bool mutated_accepts = identity_matches_report(report,
                                                                         peer_mutation,
                                                                         proc,
                                                                         expected_exe,
                                                                         expected_argv,
                                                                         mode,
                                                                         token,
                                                                         ready.token,
                                                                         true,
                                                                         false);
                    if (error.empty())
                        (void)reject_changed(
                            (strcmp(label, "peer PID") == 0 && peer_mutation.pid != peer.pid) ||
                                (strcmp(label, "peer uid") == 0 && peer_mutation.uid != peer.uid) ||
                                (strcmp(label, "peer gid") == 0 && peer_mutation.gid != peer.gid),
                            baseline,
                            mutated_accepts,
                            label,
                            error);
                }

                const std::array<const char*, 11> labels{"report uid",
                                                         "report gid",
                                                         "start time",
                                                         "PGID",
                                                         "uid",
                                                         "gid",
                                                         "netns inode",
                                                         "executable",
                                                         "argv",
                                                         "mode",
                                                         "groups state"};
                for (const char* label : labels) {
                    Report mutation = report;
                    ProcIdentity proc_mutation = proc;
                    if (strcmp(label, "report uid") == 0) mutation.uid++;
                    if (strcmp(label, "report gid") == 0) mutation.gid++;
                    if (strcmp(label, "uid") == 0) proc_mutation.uid++;
                    if (strcmp(label, "gid") == 0) proc_mutation.gid++;
                    if (strcmp(label, "start time") == 0) mutation.start++;
                    if (strcmp(label, "PGID") == 0) mutation.pgid++;
                    if (strcmp(label, "netns inode") == 0) mutation.netns++;
                    if (strcmp(label, "executable") == 0) mutation.exe = "/bad/executable";
                    if (strcmp(label, "argv") == 0) mutation.argv.push_back('x');
                    if (strcmp(label, "mode") == 0) mutation.mode = "no-ready";
                    if (strcmp(label, "groups state") == 0) mutation.groups_clear ^= 1;
                    const bool mutated_accepts = identity_matches_report(mutation,
                                                                         peer,
                                                                         proc_mutation,
                                                                         expected_exe,
                                                                         expected_argv,
                                                                         mode,
                                                                         token,
                                                                         ready.token,
                                                                         true,
                                                                         false);
                    if (error.empty()) {
                        bool field_changed = false;
                        if (strcmp(label, "report uid") == 0)
                            field_changed = mutation.uid != report.uid;
                        else if (strcmp(label, "report gid") == 0)
                            field_changed = mutation.gid != report.gid;
                        else if (strcmp(label, "uid") == 0)
                            field_changed = proc_mutation.uid != proc.uid;
                        else if (strcmp(label, "gid") == 0)
                            field_changed = proc_mutation.gid != proc.gid;
                        else if (strcmp(label, "start time") == 0)
                            field_changed = mutation.start != report.start;
                        else if (strcmp(label, "PGID") == 0)
                            field_changed = mutation.pgid != report.pgid;
                        else if (strcmp(label, "netns inode") == 0)
                            field_changed = mutation.netns != report.netns;
                        else if (strcmp(label, "executable") == 0)
                            field_changed = mutation.exe != report.exe;
                        else if (strcmp(label, "argv") == 0)
                            field_changed = mutation.argv != report.argv;
                        else if (strcmp(label, "mode") == 0)
                            field_changed = mutation.mode != report.mode;
                        else if (strcmp(label, "groups state") == 0)
                            field_changed = mutation.groups_clear != report.groups_clear;
                        (void)reject_changed(
                            field_changed, baseline, mutated_accepts, label, error);
                    }
                }

                std::vector<unsigned char> raw = frame_bytes(ready);
                const bool raw_baseline = valid_frame_header(raw.data(), token);
                raw[12] ^= 1;
                const bool token_changed =
                    !std::equal(raw.data() + 12, raw.data() + kHeaderBytes, token.bytes.begin());
                const bool token_rejected = token_changed && !valid_frame_header(raw.data(), token);
                raw = frame_bytes(ready);
                raw[4] = static_cast<unsigned char>(kVersion + 1);
                const bool version_changed = raw[4] != static_cast<unsigned char>(kVersion);
                const bool version_rejected =
                    version_changed && !valid_frame_header(raw.data(), token);
                raw = frame_bytes(ready);
                raw[8] = static_cast<unsigned char>(kMaxPayload + 1);
                raw[9] = static_cast<unsigned char>((kMaxPayload + 1) >> 8);
                const bool length_changed =
                    raw[8] != frame_bytes(ready)[8] || raw[9] != frame_bytes(ready)[9];
                const bool length_rejected =
                    length_changed && !valid_frame_header(raw.data(), token);
                if (error.empty() &&
                    (!raw_baseline || !token_rejected || !version_rejected || !length_rejected))
                    error = "token/version/length mutation was not causally rejected";

                ProcIdentity stale = proc;
                stale.start++;
                const bool stale_rejected = !identity_matches_report(report,
                                                                     peer,
                                                                     stale,
                                                                     expected_exe,
                                                                     expected_argv,
                                                                     mode,
                                                                     token,
                                                                     ready.token,
                                                                     true,
                                                                     false);
                if (error.empty() && !stale_rejected) error = "stale identity was accepted";
                const bool unsafe_pgid_rejected = [&] {
                    Report unsafe = report;
                    unsafe.pgid = 1;
                    return !identity_matches_report(unsafe,
                                                    peer,
                                                    proc,
                                                    expected_exe,
                                                    expected_argv,
                                                    mode,
                                                    token,
                                                    ready.token,
                                                    true,
                                                    false);
                }();
                if (error.empty() && !unsafe_pgid_rejected) error = "unsafe PGID was accepted";
                ProcIdentity stale_cleanup = proc;
                ++stale_cleanup.start;
                if (error.empty() &&
                    safe_cleanup(child, report, peer, stale_cleanup, token, ready.token, true))
                    error = "stale cleanup identity was accepted";
                if (error.empty() && !process_alive(child.target_pid))
                    error = "stale cleanup changed process state";
                if (error.empty()) {
                    const auto cleanup_started = std::chrono::steady_clock::now();
                    cleaned = safe_cleanup(child, report, peer, proc, token, ready.token, true);
                    if (!cleaned) error = "verified TERM/KILL cleanup failed";
                    if (error.empty() && strcmp(mode, "term-ignore") == 0 &&
                        std::chrono::steady_clock::now() - cleanup_started <
                            std::chrono::milliseconds(kCleanupMs - 50))
                        error = "TERM-ignore target did not exercise bounded KILL fallback";
                }
            }
        }
    }
    if (control >= 0) close(control);
    close(listener);
    if (!cleaned && child.pid > 1 && !child.reaped) {
        ProcIdentity proc;
        if (child.target_pid > 1 && read_proc(child.target_pid, proc))
            (void)safe_cleanup_unready(child, proc, proc.cmdline, true);
        if (!child.reaped) (void)reap_bounded(child, kCleanupMs);
    }
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (access(temp.socket.c_str(), F_OK) == 0 && error.empty())
        error = "control socket artifact survived cleanup";
    return error.empty() && cleaned && access(temp.socket.c_str(), F_OK) != 0 &&
           access(temp.path.c_str(), F_OK) != 0;
}

bool run_no_ready_case(const std::string& executable, std::string& error) {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "induced-failure temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "induced-failure listener creation failed";
        return false;
    }
    Token token;
    for (size_t i = 0; i != token.bytes.size(); ++i)
        token.bytes[i] = static_cast<unsigned char>(0xa0 + i);
    Child child;
    if (!launch_worker(executable, temp, token, "no-ready", child)) {
        close(listener);
        error = "induced-failure worker launch failed";
        return false;
    }
    int control = -1;
    std::array<char, 2 * kTokenBytes + 1> token_text{};
    for (size_t i = 0; i != kTokenBytes; ++i)
        snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
    const std::string expected_worker_argv =
        make_expected_argv(executable.c_str(), temp.socket.c_str(), token_text.data(), "no-ready");
    Peer peer;
    bool ok = accept_bounded(listener, control) && get_peer(control, peer);
    if (ok) child.target_pid = peer.pid;
    ProcIdentity identity;
    if (!ok || !read_proc(child.target_pid, identity))
        error = "missing-READY path did not reach bounded state";
    if (ok && error.empty()) {
        if (safe_cleanup_unready(child, identity, expected_worker_argv, false))
            error = "cleanup without authority was accepted";
        if (error.empty() && !process_alive(child.target_pid))
            error = "unauthorized cleanup changed process state";
    }
    if (control >= 0) close(control);
    close(listener);
    if (error.empty() && !child.reaped && !reap_bounded(child, kCleanupMs))
        error = "control disappearance did not terminate wrapper/target lease";
    if (error.empty() && process_alive(child.target_pid))
        error = "control disappearance left target process alive";
    if (!child.reaped && child.pid > 1 && child.target_pid > 1) {
        (void)safe_cleanup_unready(child, identity, expected_worker_argv, true);
        if (!child.reaped) (void)reap_bounded(child, kCleanupMs);
    }
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (error.empty() && access(temp.socket.c_str(), F_OK) == 0)
        error = "failure socket artifact survived";
    return error.empty() && child.reaped && access(temp.socket.c_str(), F_OK) != 0 &&
           access(temp.path.c_str(), F_OK) != 0;
}

bool run_ready_lease_loss_case(const std::string& executable,
                               const char* mode,
                               std::string& error) {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "ready lease-loss temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "ready lease-loss listener creation failed";
        return false;
    }
    Token token;
    for (size_t i = 0; i != kTokenBytes; ++i) token.bytes[i] = static_cast<unsigned char>(0x60 + i);
    Child child;
    if (!launch_worker(executable, temp, token, mode, child)) {
        close(listener);
        error = "ready lease-loss worker launch failed";
        return false;
    }
    int control = -1;
    Peer peer;
    Frame ready;
    Report report;
    ProcIdentity target;
    if (!accept_bounded(listener, control) || !get_peer(control, peer) ||
        !receive_frame(control, ready, kHandshakeMs) || ready.type != kReady ||
        !decode_report(ready.payload, report)) {
        error = "ready lease-loss READY was missing or malformed";
    } else {
        child.target_pid = peer.pid;
        std::array<char, 2 * kTokenBytes + 1> token_text{};
        for (size_t i = 0; i != kTokenBytes; ++i)
            snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
        const std::string expected_argv =
            make_expected_argv(executable.c_str(), temp.socket.c_str(), token_text.data(), mode);
        if (!read_proc(child.target_pid, target) ||
            report.target_pid != static_cast<u64>(peer.pid) ||
            report.wrapper_pid != static_cast<u64>(child.pid) || target.ppid != child.pid ||
            report.argv != expected_argv) {
            error = "ready lease-loss identity was not established";
        } else {
            close(control);
            control = -1;
            close(listener);
            listener = -1;
            if (!reap_bounded(child, kHandshakeMs)) {
                (void)safe_cleanup_unready(child, target, expected_argv, true);
                if (!child.reaped) (void)reap_bounded(child, kCleanupMs);
            }
            if (!child.reaped || process_alive(child.target_pid))
                error = "ready lease loss left wrapper or target alive";
        }
    }
    if (control >= 0) close(control);
    if (listener >= 0) close(listener);
    if (!child.reaped && child.pid > 1) (void)reap_bounded(child, kCleanupMs);
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (error.empty() && access(temp.socket.c_str(), F_OK) == 0)
        error = "ready lease-loss socket artifact survived";
    return error.empty() && child.reaped && access(temp.socket.c_str(), F_OK) != 0 &&
           access(temp.path.c_str(), F_OK) != 0;
}

bool run_wrapper_early_death_case(const std::string& executable, std::string& error) {
    TempDir temp;
    if (!make_temp(temp)) {
        error = "early-wrapper-death temporary directory creation failed";
        return false;
    }
    int listener = -1;
    if (!create_listener(temp.socket, listener)) {
        error = "early-wrapper-death listener creation failed";
        return false;
    }
    Token token;
    for (size_t i = 0; i != kTokenBytes; ++i) token.bytes[i] = static_cast<unsigned char>(0x40 + i);
    Child child;
    if (!launch_worker(executable, temp, token, "wrapper-early-death", child)) {
        close(listener);
        error = "early-wrapper-death worker launch failed";
        return false;
    }
    int control = -1;
    Peer peer;
    Frame ready;
    Report report;
    bool target_cleaned = false;
    if (!accept_bounded(listener, control) || !get_peer(control, peer) ||
        !receive_frame(control, ready, kHandshakeMs) || ready.type != kReady ||
        !decode_report(ready.payload, report)) {
        error = "early-wrapper-death READY was missing or malformed";
    } else {
        child.target_pid = peer.pid;
        std::array<char, 2 * kTokenBytes + 1> token_text{};
        for (size_t i = 0; i != kTokenBytes; ++i)
            snprintf(token_text.data() + i * 2, 3, "%02x", token.bytes[i]);
        const std::string expected_argv = make_expected_argv(
            executable.c_str(), temp.socket.c_str(), token_text.data(), "wrapper-early-death");
        ProcIdentity target;
        if (!read_proc(child.target_pid, target) || !reap_bounded(child, kHandshakeMs)) {
            error = "early wrapper was not reaped as the direct child";
        } else if (report.wrapper_pid == static_cast<u64>(child.pid) || target.ppid == child.pid ||
                   !target.no_new_privs || !target.capabilities_clear ||
                   !identity_matches_report(report,
                                            peer,
                                            target,
                                            executable,
                                            expected_argv,
                                            "wrapper-early-death",
                                            token,
                                            ready.token,
                                            true,
                                            false)) {
            error = "wrapper-early-death target was incorrectly authenticated";
        } else if (safe_cleanup(child, report, peer, target, token, ready.token, true)) {
            error = "live target was reported cleaned after wrapper death";
        } else if (!process_alive(child.target_pid)) {
            error = "wrapper-death mutation unexpectedly lost the live target";
        } else {
            target_cleaned = safe_cleanup_orphan_target(child.target_pid, target, true);
            if (!target_cleaned) error = "orphan target identity-safe cleanup failed";
        }
    }
    if (control >= 0) close(control);
    close(listener);
    if (!child.reaped && child.pid > 1) (void)reap_bounded(child, kCleanupMs);
    (void)unlink(temp.socket.c_str());
    (void)rmdir(temp.path.c_str());
    if (error.empty() && access(temp.socket.c_str(), F_OK) == 0)
        error = "early-wrapper-death socket artifact survived";
    return error.empty() && target_cleaned && child.reaped &&
           access(temp.socket.c_str(), F_OK) != 0 && access(temp.path.c_str(), F_OK) != 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 5 && strcmp(argv[1], "--fixture-worker") == 0)
        return worker_main(argv[0], argv[2], argv[3], argv[4]);
    if (argc == 5 && strcmp(argv[1], "--fixture-wrapper") == 0)
        return wrapper_main(argv[0], argv[2], argv[3], argv[4]);
    if (argc != 1) {
        std::cerr << "usage: test_fixture_worker_protocol\n";
        return 2;
    }
    std::array<char, PATH_MAX> self{};
    const ssize_t length = readlink("/proc/self/exe", self.data(), self.size() - 1);
    if (length <= 0) {
        std::cerr << "FAIL [#358 Stage 2a1]: cannot resolve test executable\n";
        return 1;
    }
    self[static_cast<size_t>(length)] = '\0';
    std::string error;
    Token transport_token;
    for (size_t i = 0; i != transport_token.bytes.size(); ++i)
        transport_token.bytes[i] = static_cast<unsigned char>(i + 1);
    if (!run_transport_tests(transport_token, error) || !run_malformed_input_tests(error) ||
        !run_ready_case(self.data(), error) || !run_ready_case(self.data(), error, "term-ignore") ||
        !run_no_ready_case(self.data(), error) ||
        !run_ready_lease_loss_case(self.data(), "ready", error) ||
        !run_ready_lease_loss_case(self.data(), "term-ignore", error) ||
        !run_wrapper_early_death_case(self.data(), error)) {
        std::cerr << "FAIL [#358 Stage 2a1 protocol self-check]: " << error << "\n";
        return 1;
    }
    std::cerr << "PASS: #358 Stage 2a1 parent-owned authenticated fixture-worker protocol, "
                 "causal identity mutations, bounded cleanup, and failure artifact cleanup\n";
    return 0;
}
