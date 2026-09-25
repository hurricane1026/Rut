// Envoy oracle-recording and Envoy-vs-generated-RUT pair differential harness
// (envoy-pr-plan.md, PR 2 and PR 6).
//
// The oracle mode never asserts RUT behavior: no RUT/converter/runtime code
// is invoked there at all. It drives the pinned Envoy image against a small
// recording upstream over loopback, records the exact bytes observed on the
// wire, and writes them as a ready-to-commit C++ header
// (tests/fixtures/envoy_oracle_milestone_s.inc once the lead commits the CI
// artifact). Only two invariants are asserted for real (see
// `assert_get_smoke` / `assert_connect_failure`); everything else is
// recorded evidence for PRs 3-6, not a behavioral claim.
//
// The pair mode (PR 6) DOES exercise RUT: it converts the same milestone-S
// bootstrap with `rut-envoy-convert` and runs the generated `.rut` source
// through the real `rut` binary, on the same listener/upstream ports Envoy
// just used, against the same recording upstream and client case table.
// Upstream and downstream bytes are compared exactly (only a synthesized
// `date:` header value is normalized before the downstream comparison).
//
// Modes:
//   --self-test [rut] [rut-envoy-convert]
//                                    Exercises the pieces that need no
//                                    docker: the recording upstream against
//                                    the raw client on loopback, and the
//                                    transcript writer's escaping. When both
//                                    binary paths are given, also runs the
//                                    asserted cases through the real `rut`
//                                    binary (converted from the milestone-S
//                                    bootstrap) and compares them against the
//                                    committed Envoy oracle fixture
//                                    (date-normalized) -- this is the
//                                    strongest local evidence for the pair
//                                    logic below, since it needs no docker.
//                                    Without the binaries, that pass is
//                                    skipped with a printed note, not a
//                                    failure.
//   --oracle-milestone-s <out-path> Runs the milestone-S bootstrap through
//                                    the pinned Envoy image (docker
//                                    required); writes the transcript to
//                                    <out-path>. Exits 77 (SKIP) when docker
//                                    or the pinned image is unavailable,
//                                    unless RUT_ENVOY_DIFFERENTIAL_REQUIRED=1
//                                    is set, in which case it exits 1.
//   --pair-milestone-s <rut> <rut-envoy-convert> [<out.inc>]
//                                    Runs the milestone-S bootstrap through
//                                    the pinned Envoy image, then converts it
//                                    and runs the result through `rut`, both
//                                    on the same ports against the same
//                                    recording upstream; compares every case
//                                    byte for byte (date-normalized
//                                    downstream only). Same docker
//                                    prerequisites/skip contract as
//                                    --oracle-milestone-s. Exits 1 if any
//                                    `asserted` case mismatches; record-only
//                                    cases are printed but never affect the
//                                    exit code. <out.inc> is optional; when
//                                    given, both sides' bytes are written
//                                    there as a transcript header.
//
// This file is intentionally independent of tests/test_nginx_differential.cc
// (do not copy it): the scope here is much smaller (one bootstrap shape, a
// small fixed case table) and does not need that file's much larger
// process-launch self-check infrastructure.

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RUT_PINNED_ENVOY_IMAGE
#error "RUT_PINNED_ENVOY_IMAGE must be provided by the build system"
#endif

// The committed Envoy-only oracle transcript (PR 2). Used only by the
// `--self-test` RUT pass (PR 6) to compare the real `rut` binary's output
// against recorded Envoy bytes without needing docker.
#include "fixtures/envoy_oracle_milestone_s.inc"

namespace {

constexpr const char* kEnvoyImage = RUT_PINNED_ENVOY_IMAGE;
constexpr int kClientTimeoutMs = 3000;
// How many times to retry Envoy's own listener port after a bind collision
// (see launch_envoy_with_port_retry()): that port cannot be pre-bound from
// this process (Envoy binds it itself inside the container), so this harness
// can only probe-allocate it and race everyone else for it.
constexpr int kMaxListenPortAttempts = 3;
// Bounded grace window given to a HEAD response after its header terminator,
// to catch a body sent in a later TCP segment (RFC 9110 §9.3.2 forbids one).
// Short relative to kClientTimeoutMs: it only needs to observe bytes the
// peer was about to send anyway, not to wait out a legitimately silent peer.
constexpr int kHeadBodyGraceMs = 200;

// ── Small process helpers ──────────────────────────────────────────────

// Builds a null-terminated argv suitable for execvp() from `args`. The
// returned pointers alias `args`' own storage, so `args` must outlive the
// result and must not be mutated afterward (reallocation would invalidate
// every c_str() pointer already copied out).
//
// Callers must call this *before* fork(): std::vector/std::string
// construction is ordinary heap allocation, which is not async-signal-safe.
// If another thread held the allocator lock at the instant of fork(), a
// child that then allocated could hang forever (round-3 review, "Build the
// Docker argv before entering the fork child"). Every fork() below builds
// its argv first and only touches async-signal-safe calls (open/dup2/close/
// execvp/_exit) once inside the child.
std::vector<char*> build_argv(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    return argv;
}

// Runs `argv` to completion (or until `timeout_ms` elapses, in which case the
// child is SIGKILLed), discarding its stdio. Returns the exit code, or -1 if
// the process could not be spawned, was killed, or did not exit normally.
int run_and_wait(const std::vector<std::string>& argv, int timeout_ms) {
    const std::vector<char*> args = build_argv(argv);
    const pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        const int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
        }
        execvp(args[0], args.data());
        _exit(127);
    }
    const int64_t deadline_ms =
        static_cast<int64_t>(timeout_ms) +
        static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count());
    int status = 0;
    for (;;) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (waited < 0 && errno == EINTR) continue;
        if (waited < 0) return -1;
        const int64_t now_ms =
            static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
        if (now_ms >= deadline_ms) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
            return -1;
        }
        struct timespec ts{0, 5'000'000};
        nanosleep(&ts, nullptr);
    }
}

bool command_on_path(const char* name) {
    const char* path_env = getenv("PATH");
    if (path_env == nullptr) return false;
    std::string path(path_env);
    size_t start = 0;
    while (start <= path.size()) {
        const size_t colon = path.find(':', start);
        const std::string dir =
            path.substr(start, colon == std::string::npos ? colon : colon - start);
        if (!dir.empty()) {
            const std::string candidate = dir + "/" + name;
            if (access(candidate.c_str(), X_OK) == 0) return true;
        }
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return false;
}

int missing_prerequisite(const std::string& message) {
    std::cerr << "SKIP: " << message << "\n";
    const char* required = getenv("RUT_ENVOY_DIFFERENTIAL_REQUIRED");
    return (required != nullptr && std::string(required) == "1") ? 1 : 77;
}

// Checks the three prerequisites named in envoy-pr-plan.md PR 2: docker on
// PATH, `docker info` succeeding within 10s, and the pinned image already
// present locally (`docker image inspect`, never a pull). Returns empty on
// success, else a human-readable reason suitable for `missing_prerequisite`.
std::string check_docker_prerequisites() {
    if (!command_on_path("docker")) return "docker not found on PATH";
    if (run_and_wait({"docker", "info"}, 10'000) != 0)
        return "docker info did not succeed within 10s (is the daemon running?)";
    if (run_and_wait({"docker", "image", "inspect", kEnvoyImage}, 10'000) != 0)
        return std::string("pinned Envoy image ") + kEnvoyImage +
               " is not present locally (docker image inspect failed); this test never pulls";
    return "";
}

// ── Sockets ─────────────────────────────────────────────────────────────

bool allocate_loopback_port(uint16_t* port) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool ok = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    if (ok) {
        socklen_t len = sizeof(addr);
        ok = getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0;
        if (ok) *port = ntohs(addr.sin_port);
    }
    close(fd);
    return ok;
}

// A loopback port that has been allocated by binding and *listening* on it,
// rather than probe-binding and closing (see allocate_loopback_port() above).
// The caller owns `fd` and must either hand it to a consumer that adopts it
// (RecordingUpstream::adopt()) or close() it directly.
struct BoundPort {
    int fd = -1;
    uint16_t port = 0;
};

// Allocates an ephemeral loopback port and leaves it bound and listening, so
// the port stays reserved until the caller's eventual consumer takes over the
// socket. Plain allocate_loopback_port() closes its probe socket immediately
// after learning the port number, which leaves a window where another
// process on the same host can grab that port before this harness's own
// consumer gets around to binding it (round-6 review, "Keep allocated ports
// reserved until their consumers bind"). Used for the recording upstream,
// whose listening socket this process itself owns end to end; Envoy's own
// listener port cannot use this (Envoy binds it inside the container), so
// that one still goes through the probe-and-retry path in
// launch_envoy_with_port_retry().
bool allocate_bound_loopback_port(BoundPort* out) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return false;
    }
    if (listen(fd, 16) != 0) {
        close(fd);
        return false;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        close(fd);
        return false;
    }
    out->fd = fd;
    out->port = ntohs(addr.sin_port);
    return true;
}

// Allocates an ephemeral loopback port and leaves it bound but deliberately
// *not* listening, so the port stays reserved for the caller without ever
// accepting a connection. Used for the connect_failure case's "closed"
// upstream port: like allocate_bound_loopback_port() above, this exists so
// the port stays reserved end to end instead of going through
// allocate_loopback_port()'s probe-and-immediately-close pattern, which
// leaves a window where another host process can bind and listen on the
// port before Envoy's connect attempt (round-7 review, "Keep the
// connect-failure port reserved"). A bound, non-listening TCP socket still
// answers connect() with RST/ECONNREFUSED on Linux -- the same "connection
// refused" semantics as a port nothing has ever bound -- so holding this
// reservation does not change the bytes Envoy observes, and therefore does
// not change the oracle fixture's recorded connect_failure body (98-byte
// "upstream connect error or disconnect/reset before headers. reset reason:
// remote connection failure"). The caller owns `fd` and must close() it once
// the connect-failure exchange is done.
bool allocate_reserved_closed_port(BoundPort* out) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    // Deliberately no SO_REUSEADDR: on Linux, when SO_REUSEADDR is set on
    // *this* socket, a second, unrelated socket that also sets SO_REUSEADDR
    // can bind (and even listen()) on the exact same address:port pair while
    // this one is still alive and unconnected -- verified empirically on
    // this host, and exactly the hijack this function exists to prevent.
    // Leaving SO_REUSEADDR unset here is what makes the reservation
    // exclusive: a later bind() to this port from any other socket fails
    // with EADDRINUSE for as long as `fd` stays open.
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return false;
    }
    // Deliberately no listen(): a backlog-less bound socket rejects every
    // connect() attempt instead of accepting it.
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        close(fd);
        return false;
    }
    out->fd = fd;
    out->port = ntohs(addr.sin_port);
    return true;
}

// Core of allocate_distinct_ports(), parameterized on the port source so
// self_test_allocate_distinct_ports_exhaustion() can force the "every
// attempt collides" path deterministically (round-9 review, "Return failure
// when no distinct port was found") without needing to actually exhaust real
// ephemeral ports. Tracks whether *each* output got assigned and fails the
// whole call the moment one output's 32 attempts all collide with an
// already-seen port -- previously the loop just fell through to the next
// output, leaving that output's pointee at its caller-supplied initial value
// (zero-initialized in the current caller) while still returning success.
bool allocate_distinct_ports_with(const std::vector<uint16_t*>& outs,
                                  const std::function<bool(uint16_t*)>& allocate_one) {
    std::vector<uint16_t> seen;
    for (uint16_t* out : outs) {
        bool assigned = false;
        for (int attempt = 0; attempt < 32; attempt++) {
            uint16_t candidate = 0;
            if (!allocate_one(&candidate)) return false;
            if (std::find(seen.begin(), seen.end(), candidate) == seen.end()) {
                seen.push_back(candidate);
                *out = candidate;
                assigned = true;
                break;
            }
        }
        if (!assigned) return false;
    }
    return true;
}

bool allocate_distinct_ports(const std::vector<uint16_t*>& outs) {
    return allocate_distinct_ports_with(outs, allocate_loopback_port);
}

int connect_with_timeout(uint16_t port, int timeout_ms) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    const int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags);
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    pollfd pfd{fd, POLLOUT, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        close(fd);
        return -1;
    }
    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0 || err != 0) {
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, flags);
    return fd;
}

bool tcp_port_open(uint16_t port) {
    const int fd = connect_with_timeout(port, 200);
    if (fd < 0) return false;
    close(fd);
    return true;
}

bool send_all(int fd, const std::string& data) {
    size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

int64_t now_ms() {
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch())
                                    .count());
}

// Case-insensitive search for a header named `name` inside the CRLF-joined
// header block `headers` (no leading request/status line, no trailing blank
// line). Returns the OWS-trimmed value of the first match, or empty+false.
bool find_header(const std::string& headers, const std::string& name, std::string* value) {
    size_t start = 0;
    while (start < headers.size()) {
        size_t line_end = headers.find("\r\n", start);
        if (line_end == std::string::npos) line_end = headers.size();
        const std::string line = headers.substr(start, line_end - start);
        const size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            if (key.size() == name.size() &&
                std::equal(key.begin(), key.end(), name.begin(), [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a)) ==
                           std::tolower(static_cast<unsigned char>(b));
                })) {
                std::string v = line.substr(colon + 1);
                size_t a = v.find_first_not_of(" \t");
                size_t b = v.find_last_not_of(" \t");
                *value = a == std::string::npos ? "" : v.substr(a, b - a + 1);
                return true;
            }
        }
        if (line_end == headers.size()) break;
        start = line_end + 2;
    }
    return false;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool header_equals_ci(const std::string& raw, const std::string& name, const std::string& expect) {
    const size_t header_end = raw.find("\r\n\r\n");
    const std::string headers = header_end == std::string::npos ? raw : raw.substr(0, header_end);
    std::string value;
    if (!find_header(headers, name, &value)) return false;
    return value == expect;
}

// Result of read_http_message(): the bytes captured so far, and whether the
// message's framing (headers, plus body if any) actually completed within
// the deadline. `complete == false` means the caller observed a partial
// exchange (timeout or premature EOF mid-frame) and must not treat `bytes`
// as a trustworthy recording (round-3 review, "Reject partial exchanges
// before writing the oracle transcript").
struct ReadResult {
    std::string bytes;
    bool complete = false;
};

// Reads one complete HTTP/1.x message from `fd`: headers up to the blank
// line, then a body framed by Content-Length (skipped entirely when
// `head_request` is true, per RFC 9110 §9.3.2), else read-to-EOF. Bounded by
// `timeout_ms` total. Always returns whatever was captured, even on a
// partial read, but `complete` is false whenever the framing did not finish
// (record-only cases must check it; see ReadResult).
//
// For a HEAD response specifically, RFC 9110 §9.3.2 forbids a body; after
// the header terminator this waits up to kHeadBodyGraceMs for the peer to
// send one anyway (in a later TCP segment) so a violation shows up as extra
// bytes here instead of being silently dropped by returning immediately.
ReadResult read_http_message(int fd, bool head_request, int timeout_ms) {
    std::string buf;
    const int64_t deadline = now_ms() + timeout_ms;
    char chunk[4096];
    size_t header_end = std::string::npos;
    for (;;) {
        header_end = buf.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        const int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return {buf, false};
        pollfd pfd{fd, POLLIN, 0};
        if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) return {buf, false};
        const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) return {buf, false};
        buf.append(chunk, static_cast<size_t>(n));
    }
    if (head_request) {
        // A HEAD response never carries a body (RFC 9110 §9.3.2): the
        // headers are the entire message, so finding the blank line is
        // completion. Still wait up to kHeadBodyGraceMs for the peer to
        // send one anyway (in a later TCP segment) so a violation shows up
        // as extra captured bytes instead of being silently dropped by
        // returning immediately.
        const int64_t grace_deadline = now_ms() + kHeadBodyGraceMs;
        for (;;) {
            const int64_t remaining = grace_deadline - now_ms();
            if (remaining <= 0) break;
            pollfd pfd{fd, POLLIN, 0};
            if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) break;
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) break;
            buf.append(chunk, static_cast<size_t>(n));
        }
        return {buf, true};
    }
    const std::string headers = buf.substr(0, header_end);
    std::string cl_value;
    std::string connection_value;
    const bool has_cl = find_header(headers, "Content-Length", &cl_value);
    find_header(headers, "Connection", &connection_value);
    std::transform(connection_value.begin(),
                   connection_value.end(),
                   connection_value.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    const size_t body_start = header_end + 4;
    if (has_cl) {
        char* end = nullptr;
        const long want = strtol(cl_value.c_str(), &end, 10);
        const size_t total = body_start + (want > 0 ? static_cast<size_t>(want) : 0u);
        while (buf.size() < total) {
            const int64_t remaining = deadline - now_ms();
            if (remaining <= 0) return {buf, false};
            pollfd pfd{fd, POLLIN, 0};
            if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) return {buf, false};
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return {buf, false};
            buf.append(chunk, static_cast<size_t>(n));
        }
        return {buf, true};
    }
    if (connection_value.find("close") != std::string::npos) {
        for (;;) {
            const int64_t remaining = deadline - now_ms();
            if (remaining <= 0) return {buf, false};
            pollfd pfd{fd, POLLIN, 0};
            const int pr = poll(&pfd, 1, static_cast<int>(remaining));
            if (pr <= 0) return {buf, false};
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            // EOF (n == 0) is the expected terminator for close-delimited
            // framing, i.e. completion, not a partial read. Any other
            // failure (n < 0) is a real partial exchange.
            if (n == 0) return {buf, true};
            if (n < 0) return {buf, false};
            buf.append(chunk, static_cast<size_t>(n));
        }
    }
    // Neither Content-Length nor Connection: close: framing is fully
    // determined by the headers alone (assumed zero-length body), so this is
    // complete as soon as the blank line was found above.
    return {buf, true};
}

// ── Listener ownership probe ────────────────────────────────────────────

// The asterisk-form request-target `*` (RFC 9112 §3.2.4) never matches the
// milestone-S bootstrap's "/" prefix route (a leading "*" is not a leading
// "/"), so Envoy's router finds no route for it and answers with a local
// 404 -- confirmed by the oracle recording itself:
// tests/fixtures/envoy_oracle_milestone_s.inc's own `options_star` case
// records exactly this (`// options_star: upstream not contacted`, and a
// downstream reply of "HTTP/1.1 404 Not Found" + "server: envoy" +
// "content-length: 0", i.e. an empty body). kOwnershipProbeRequest reuses
// that exact request shape so probe_confirms_envoy_ownership() can require
// the exact recorded reply shape to tell "this is the Envoy container this
// harness launched" apart from "some unrelated process happens to be
// listening on this port" (round-8 review, "Verify listener ownership
// instead of timing process liveness") -- all without touching
// kBootstrapTemplate (below) or the "backend" cluster/recording upstream at
// all: this is exactly the milestone-S bootstrap already used for every
// other case, unmodified, so the oracle transcript and #700's pair-mode
// conversion still see the identical bootstrap Envoy served.
constexpr char kOwnershipProbeRequest[] =
    "OPTIONS * HTTP/1.1\r\nHost: rut-ownership-probe.internal\r\n\r\n";
// The request-target the probe above sends, i.e. RecordingUpstream::path_key()'s
// key for it -- used only to assert the recording upstream never saw it (see
// run_oracle_milestone_s()); the probe itself never contacts any upstream,
// since asterisk-form requests never match kBootstrapTemplate's "/" route.
constexpr char kOwnershipProbeTarget[] = "*";

// Sends kOwnershipProbeRequest on `port` and checks the response against
// exactly what the milestone-S bootstrap's router-not-found local reply
// always answers for it (see kOwnershipProbeRequest's comment): a 404
// status line, Envoy's "server: envoy" header, and an empty body. A foreign
// listener will fail to complete this exchange, answer a different status,
// lack the "server: envoy" header, or return a non-empty body; any of those
// means ownership is not confirmed.
bool probe_confirms_envoy_ownership(uint16_t port, int timeout_ms, std::string* error) {
    const int fd = connect_with_timeout(port, timeout_ms);
    if (fd < 0) {
        *error = "ownership probe: could not connect";
        return false;
    }
    if (!send_all(fd, kOwnershipProbeRequest)) {
        close(fd);
        *error = "ownership probe: could not send probe request";
        return false;
    }
    const ReadResult read = read_http_message(fd, /*head_request=*/false, timeout_ms);
    close(fd);
    if (!read.complete) {
        *error = "ownership probe: response did not complete";
        return false;
    }
    if (!starts_with(read.bytes, "HTTP/1.1 404")) {
        *error =
            "ownership probe: expected a 404 status line for the asterisk-form request, got a "
            "different response";
        return false;
    }
    if (!header_equals_ci(read.bytes, "server", "envoy")) {
        *error = "ownership probe: response is missing Envoy's \"server: envoy\" header";
        return false;
    }
    const size_t header_end = read.bytes.find("\r\n\r\n");
    const std::string body =
        header_end == std::string::npos ? std::string() : read.bytes.substr(header_end + 4);
    if (!body.empty()) {
        *error = "ownership probe: expected an empty body for the router-not-found local reply";
        return false;
    }
    return true;
}

// ── Transcript escaping (self-contained; see --self-test) ─────────────

// Escapes the interior of one wire "line" for a C++ string-literal body.
// Every `\xHH` is immediately followed by a closing+reopening quote pair
// (written here as the two characters '"' '"'), so a following byte that
// happens to render as a hex digit (e.g. printable 'a'-'f'/'0'-'9') can never
// be absorbed into the escape by the compiler's greedy \x lexing.
std::string escape_wire_bytes(const std::string& bytes) {
    std::string out;
    for (unsigned char c : bytes) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c >= 0x20 && c < 0x7f) {
                    out += static_cast<char>(c);
                } else {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\x%02x\"\"", c);
                    out += esc;
                }
        }
    }
    return out;
}

// Wraps `bytes` as a sequence of adjacent quoted literals, one per wire line
// (split just after each "\r\n"), matching the style already used for
// multi-line wire fixtures elsewhere in tests/ (e.g. test_nginx_differential
// .cc's kRequest). A trailing empty piece (buffer ends exactly on "\r\n") is
// dropped; an entirely empty buffer renders as a bare `""`.
std::string wrap_wire_literal(const std::string& bytes) {
    if (bytes.empty()) return "\"\"";
    std::vector<std::string> pieces;
    size_t start = 0;
    for (;;) {
        const size_t crlf = bytes.find("\r\n", start);
        if (crlf == std::string::npos) {
            pieces.push_back(bytes.substr(start));
            break;
        }
        pieces.push_back(bytes.substr(start, crlf + 2 - start));
        start = crlf + 2;
    }
    if (!pieces.empty() && pieces.back().empty()) pieces.pop_back();
    std::ostringstream out;
    for (size_t i = 0; i < pieces.size(); i++) {
        if (i != 0) out << "\n    ";
        out << '"' << escape_wire_bytes(pieces[i]) << '"';
    }
    return out.str();
}

// Decodes a wrapped literal produced by `wrap_wire_literal`/`escape_wire_bytes`
// back to raw bytes, using the same greedy hex-digit lexing a real C++
// compiler uses for `\xHH...`. This is the harness's "compile-check by
// re-parsing": if the writer ever stopped splitting after `\xHH`, a byte that
// looks like a following hex digit would be silently absorbed here exactly as
// it would by a real compiler, and the round-trip in --self-test would fail.
bool decode_wire_literal(const std::string& wrapped, std::string* out) {
    out->clear();
    size_t i = 0;
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    while (i < wrapped.size()) {
        if (wrapped[i] != '"') return false;
        i++;
        while (i < wrapped.size() && wrapped[i] != '"') {
            if (wrapped[i] == '\\') {
                i++;
                if (i >= wrapped.size()) return false;
                const char e = wrapped[i];
                if (e == '\\' || e == '"') {
                    out->push_back(e);
                    i++;
                } else if (e == 'r') {
                    out->push_back('\r');
                    i++;
                } else if (e == 'n') {
                    out->push_back('\n');
                    i++;
                } else if (e == 't') {
                    out->push_back('\t');
                    i++;
                } else if (e == 'x') {
                    i++;
                    if (i >= wrapped.size() || !is_hex(wrapped[i])) return false;
                    unsigned value = 0;
                    while (i < wrapped.size() && is_hex(wrapped[i])) {
                        value = value * 16u + static_cast<unsigned>(hex_val(wrapped[i]));
                        i++;
                    }
                    out->push_back(static_cast<char>(value & 0xffu));
                } else {
                    return false;
                }
            } else {
                out->push_back(wrapped[i]);
                i++;
            }
        }
        if (i >= wrapped.size() || wrapped[i] != '"') return false;
        i++;
        while (i < wrapped.size() && (wrapped[i] == ' ' || wrapped[i] == '\n' ||
                                      wrapped[i] == '\t' || wrapped[i] == '\r'))
            i++;
    }
    return true;
}

// ── Recording upstream ──────────────────────────────────────────────────

// One-thread accept loop that records the raw bytes of every request it
// receives, keyed by request-target path (query string stripped), and
// replies from a fixed table (falling back to a default reply). Connections
// are kept open across requests (Envoy pools upstream connections); a
// request headers block naming `Connection: close` closes after replying.
class RecordingUpstream {
public:
    // Adopts an already-bound, already-listening socket, typically the `fd`
    // out of allocate_bound_loopback_port(): binding a fresh socket to a port
    // number learned earlier (the old start(uint16_t port) behavior) leaves a
    // window where another process can take that port first (round-6 review,
    // "Keep allocated ports reserved until their consumers bind"). Takes
    // ownership of `listen_fd` on success; on failure the caller still owns
    // it and must close it.
    bool adopt(int listen_fd) {
        if (listen_fd < 0) return false;
        listen_fd_ = listen_fd;
        stopping_.store(false);
        accept_thread_ = std::thread([this] { accept_loop(); });
        return true;
    }

    void set_reply(const std::string& path, const std::string& reply_bytes) {
        std::lock_guard<std::mutex> lock(mu_);
        replies_[path] = reply_bytes;
    }

    void set_default_reply(const std::string& reply_bytes) {
        std::lock_guard<std::mutex> lock(mu_);
        default_reply_ = reply_bytes;
    }

    std::vector<std::string> requests_for(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = requests_by_path_.find(path);
        return it == requests_by_path_.end() ? std::vector<std::string>{} : it->second;
    }

    // Discards every recorded request without stopping the accept loop or
    // dropping pooled connections. `--pair-milestone-s` (PR 6) uses this to
    // reuse one live upstream across the Envoy and RUT phases -- same
    // ports, same reply table -- while still being able to attribute each
    // phase's recorded bytes unambiguously (`requests_for(...).front()`).
    void clear_requests() {
        std::lock_guard<std::mutex> lock(mu_);
        requests_by_path_.clear();
    }

    // Idempotent: safe to call more than once (the destructor calls it again
    // after an explicit stop()).
    void stop() {
        stopping_.store(true);
        // accept_loop() reads listen_fd_ on every iteration
        // (accept(listen_fd_, ...)) with no synchronization, so this thread
        // must not write to listen_fd_ while that thread could still be
        // running: doing so is a data race (UB, and ThreadSanitizer flags it
        // under --self-test; round-3 review, "Stop racing on the listener
        // descriptor"). shutdown()+close() unblock a thread parked in
        // accept() without changing the value of listen_fd_ itself, so they
        // are safe to call before join(); the assignment to -1 is deferred
        // until the accept thread has actually joined.
        if (listen_fd_ >= 0) {
            shutdown(listen_fd_, SHUT_RDWR);
            close(listen_fd_);
        }
        if (accept_thread_.joinable()) accept_thread_.join();
        listen_fd_ = -1;
        // Unblock every still-running handler (each is parked in poll()/recv()
        // on its own fd) and join it before this object's mutex and maps go
        // away underneath it. Only shutdown() here, never close(): each
        // handler thread closes its own fd exactly once via finish_connection,
        // so a stale/reused fd number is never touched from this thread.
        std::vector<std::thread> threads_to_join;
        {
            std::lock_guard<std::mutex> lock(conn_mu_);
            for (const int fd : active_fds_) shutdown(fd, SHUT_RDWR);
            active_fds_.clear();
            threads_to_join.swap(conn_threads_);
        }
        for (std::thread& t : threads_to_join) {
            if (t.joinable()) t.join();
        }
    }

    ~RecordingUpstream() { stop(); }

private:
    // Removes fd from the active-connection bookkeeping and closes it. Called
    // exactly once per connection, from that connection's own handler thread,
    // regardless of which return path in handle_connection triggered it (see
    // ConnGuard below).
    void finish_connection(int fd) {
        {
            std::lock_guard<std::mutex> lock(conn_mu_);
            active_fds_.erase(std::remove(active_fds_.begin(), active_fds_.end(), fd),
                              active_fds_.end());
        }
        close(fd);
    }

    void accept_loop() {
        while (!stopping_.load()) {
            const int fd = accept(listen_fd_, nullptr, nullptr);
            if (fd < 0) {
                if (stopping_.load()) return;
                continue;
            }
            std::lock_guard<std::mutex> lock(conn_mu_);
            active_fds_.push_back(fd);
            conn_threads_.emplace_back(&RecordingUpstream::handle_connection, this, fd);
        }
    }

    static std::string path_key(const std::string& target) {
        const size_t q = target.find('?');
        return q == std::string::npos ? target : target.substr(0, q);
    }

    // Guarantees finish_connection(fd) runs exactly once, on whichever return
    // path handle_connection takes (including the ones taken when stop()
    // shuts the fd down from another thread), without editing every return
    // site.
    struct ConnGuard {
        RecordingUpstream* self;
        int fd;
        ~ConnGuard() { self->finish_connection(fd); }
    };

    void handle_connection(int fd) {
        ConnGuard guard{this, fd};
        std::string buf;
        char chunk[4096];
        for (;;) {
            size_t header_end;
            for (;;) {
                header_end = buf.find("\r\n\r\n");
                if (header_end != std::string::npos) break;
                pollfd pfd{fd, POLLIN, 0};
                if (poll(&pfd, 1, 5000) <= 0) {
                    return;
                }
                const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
                if (n <= 0) {
                    return;
                }
                buf.append(chunk, static_cast<size_t>(n));
            }
            const std::string headers = buf.substr(0, header_end);
            std::string cl_value;
            const bool has_cl = find_header(headers, "Content-Length", &cl_value);
            const size_t body_start = header_end + 4;
            size_t total = body_start;
            if (has_cl) {
                char* end = nullptr;
                const long want = strtol(cl_value.c_str(), &end, 10);
                if (want > 0) total += static_cast<size_t>(want);
            }
            while (buf.size() < total) {
                pollfd pfd{fd, POLLIN, 0};
                if (poll(&pfd, 1, 5000) <= 0) {
                    return;
                }
                const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
                if (n <= 0) {
                    return;
                }
                buf.append(chunk, static_cast<size_t>(n));
            }
            const std::string request_raw = buf.substr(0, total);
            const size_t line_end = headers.find("\r\n");
            const std::string request_line =
                line_end == std::string::npos ? headers : headers.substr(0, line_end);
            const size_t sp1 = request_line.find(' ');
            const size_t sp2 =
                sp1 == std::string::npos ? std::string::npos : request_line.find(' ', sp1 + 1);
            const std::string target = (sp1 == std::string::npos || sp2 == std::string::npos)
                                           ? std::string{}
                                           : request_line.substr(sp1 + 1, sp2 - sp1 - 1);
            const std::string key = path_key(target);
            std::string reply;
            {
                std::lock_guard<std::mutex> lock(mu_);
                requests_by_path_[key].push_back(request_raw);
                const auto it = replies_.find(key);
                reply = it == replies_.end() ? default_reply_ : it->second;
            }
            if (!send_all(fd, reply)) {
                return;
            }
            std::string connection_value;
            find_header(headers, "Connection", &connection_value);
            std::transform(connection_value.begin(),
                           connection_value.end(),
                           connection_value.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            buf.erase(0, total);
            if (connection_value.find("close") != std::string::npos) {
                return;
            }
        }
    }

    int listen_fd_ = -1;
    std::atomic<bool> stopping_{false};
    std::thread accept_thread_;
    std::mutex mu_;
    std::map<std::string, std::vector<std::string>> requests_by_path_;
    std::map<std::string, std::string> replies_;
    // Bookkeeping for connections currently inside handle_connection, so
    // stop() can unblock and join every one of them instead of only the
    // accept thread (see stop()/finish_connection()/ConnGuard above).
    std::mutex conn_mu_;
    std::vector<int> active_fds_;
    std::vector<std::thread> conn_threads_;
    std::string default_reply_ =
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
};

// ── Envoy process management ────────────────────────────────────────────

// Counts real `docker rm -f` invocations from EnvoyInstance::stop() (and
// nowhere else), so self_test_envoy_instance_skips_docker_when_unlaunched()
// can assert that an EnvoyInstance which never called launch() invokes
// docker zero times, without needing a stubbed docker binary on PATH
// (round-15 review, "Skip Docker teardown for instances that were never
// launched").
int g_docker_rm_invocations = 0;

struct EnvoyInstance {
    pid_t pid = -1;
    std::string name;
    std::string log_path;
    // Set once launch() actually forks a docker child; guards stop()'s
    // `docker rm -f` call so instances that never launched (every dummy-
    // child self-test case wraps a plain forked process, never a real
    // docker container) don't invoke docker at all. Cleared right after
    // stop() runs the docker teardown once, so a redundant later stop()
    // call (an explicit one followed by the destructor's automatic one)
    // never re-invokes it either.
    bool launched = false;

    bool launch(const std::string& bootstrap_path, uint16_t /*listen_port*/) {
        // docker run --pull=never --rm --network host --name <name>
        //   -e ENVOY_UID=0
        //   -v <bootstrap>:/etc/envoy/rut-bootstrap.json:ro,z
        //   <image> -c /etc/envoy/rut-bootstrap.json
        //   --concurrency 1 --disable-hot-restart --log-level info
        //
        // --log-level is "info", not the quieter "warn" used before the
        // round-9 review: wait_ready_and_confirm_ownership()'s launch-
        // specific ownership evidence (envoy_log_confirms_listener()) keys
        // off Envoy's `starting main dispatch loop` line, which Envoy logs
        // at ENVOY_LOG(info, ...) (source/server/server.cc,
        // InstanceBase::run()); at "warn" that line is filtered out and
        // ownership could never be confirmed against a real container. This
        // does not touch the bootstrap JSON itself (still byte-identical to
        // what pair mode and the oracle use) or the recorded wire bytes of
        // any case, only Envoy's own stderr verbosity.
        //
        // VERIFY (envoy-pr-plan.md PR2): the official image's
        // distribution/docker/docker-entrypoint.sh (checked at tag
        // v1.39.1) does:
        //   if [ "${1#-}" != "$1" ]; then set -- envoy "$@"; fi
        //   ...
        //   if [ "$ENVOY_UID" != "0" ] && [ "$USERID" = 0 ]; then
        //       ...su-exec envoy...
        //   else exec "$@"; fi
        // Our first argument is "-c", which starts with '-', so the
        // entrypoint prepends "envoy" for us; passing ENVOY_UID=0 takes
        // the `else exec "$@"` branch directly (no usermod/su-exec
        // re-exec), running as the image's default root user. Both
        // match this command exactly as planned; no deviation found.
        //
        // Built before fork(): see build_argv()'s comment (round-3 review,
        // "Build the Docker argv before entering the fork child"). The
        // accept thread inside `RecordingUpstream` (already running by the
        // time run_oracle_milestone_s() reaches this call) is exactly the
        // kind of concurrent thread that makes post-fork allocation unsafe.
        std::vector<std::string> argv = {
            "docker",        "run",       "--pull=never",
            "--rm",          "--network", "host",
            "--name",        name,        "-e",
            "ENVOY_UID=0",   "-v",        bootstrap_path + ":/etc/envoy/rut-bootstrap.json:ro,z",
            kEnvoyImage,     "-c",        "/etc/envoy/rut-bootstrap.json",
            "--concurrency", "1",         "--disable-hot-restart",
            "--log-level",   "info"};
        const std::vector<char*> args = build_argv(argv);
        pid = fork();
        if (pid < 0) return false;
        // From here a docker child was (or is being) created under `name`,
        // so stop() must run `docker rm -f` for it even if this process
        // itself never reaches "starting main dispatch loop".
        launched = true;
        if (pid == 0) {
            const int log_fd = open(log_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (log_fd >= 0) {
                dup2(log_fd, STDOUT_FILENO);
                dup2(log_fd, STDERR_FILENO);
                if (log_fd > STDERR_FILENO) close(log_fd);
            }
            execvp(args[0], args.data());
            _exit(127);
        }
        return true;
    }

    void stop() {
        if (pid > 0) kill(pid, SIGTERM);
        // Skip docker teardown entirely for an instance that never actually
        // launched a container (round-15 review, "Skip Docker teardown for
        // instances that were never launched"): self-test EnvoyInstance
        // objects wrap dummy forked processes without ever calling launch(),
        // so `name` is empty and no container was ever created. Running
        // `docker rm -f` for those anyway wastes up to this call's 10s
        // timeout each -- four times in --self-test -- and, if a Docker CLI
        // or daemon is present but unresponsive, pushes the whole self-test
        // toward CTest's 60s limit for no benefit. `launched` is cleared
        // right after so a later, redundant stop() call never re-invokes it.
        if (launched) {
            g_docker_rm_invocations++;
            run_and_wait({"docker", "rm", "-f", name}, 10'000);
            launched = false;
        }
        if (pid > 0) {
            const int64_t deadline = now_ms() + 5000;
            int status = 0;
            for (;;) {
                const pid_t waited = waitpid(pid, &status, WNOHANG);
                if (waited == pid) break;
                if (waited < 0 && errno == ECHILD) {
                    // Already reaped by someone else (e.g. a caller that
                    // explicitly waitpid()'d this pid before dropping the
                    // EnvoyInstance) -- round-9 review, "Treat ECHILD as an
                    // already-stopped child". Without this, a stale/reaped
                    // pid would sit through the full 5s deadline below and
                    // then be signaled again, potentially hitting an
                    // unrelated process if the pid has since been recycled.
                    break;
                }
                if (now_ms() >= deadline) {
                    kill(pid, SIGKILL);
                    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
                    }
                    break;
                }
                struct timespec ts{0, 10'000'000};
                nanosleep(&ts, nullptr);
            }
            pid = -1;
        }
    }

    ~EnvoyInstance() { stop(); }
};

void dump_log(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::cerr << "---- envoy log (" << path << ") ----\n" << in.rdbuf() << "\n---- end log ----\n";
}

std::string read_file_contents(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::string();
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Pure, self-test-friendly ownership evidence check: does `contents` (the
// captured stdout+stderr of an Envoy child) prove that *this specific
// process* finished startup owning its listeners?
//
// A generic protocol-level reply (probe_confirms_envoy_ownership()) cannot
// rule out a foreign Envoy-like process answering on the same port while our
// own launched container is still starting or has already lost the bind
// race (round-9 review, "Use a launch-specific listener ownership
// challenge"): any Envoy that happens to be listening produces the same
// 404/"server: envoy"/empty-body reply for the probe's asterisk-form
// request. What is launch-specific is the *process itself*: Envoy logs
// `starting main dispatch loop` (source/server/server.cc,
// InstanceBase::run(), `ENVOY_LOG(info, "starting main dispatch loop")`,
// verified against the v1.39.1 tag) right before it enters its blocking
// event loop, and it only reaches that point after every configured
// listener has already been added and successfully bound -- a bind failure
// during config application aborts startup before run() is ever called. So
// this exact line appearing in *our* launched child's own log is
// launch-specific evidence that our child (not some other process) owns the
// listener, regardless of what any other process on the port answers.
//
// A bind collision is reported separately, as an "address already in use"
// message (see log_indicates_address_in_use()); if that appears anywhere in
// the log, ownership is never confirmed by this function even if a startup
// line also appears (defensive -- the two should never coexist for the same
// listener in practice).
bool envoy_log_confirms_listener(const std::string& contents) {
    std::string lower = contents;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lower.find("address already in use") != std::string::npos ||
        lower.find("address in use") != std::string::npos) {
        return false;
    }
    return contents.find("starting main dispatch loop") != std::string::npos;
}

// Polls `port` until a TCP connect succeeds, failing early (without waiting
// out `timeout_ms`) if `proc`'s child has already exited -- shared by the
// Envoy and RUT readiness waits below (PR 6 adds the RUT side; `EnvoyInstance`
// already carried this exact loop for PR 2, inlined here so both instance
// types share one implementation).
template <typename ProcessInstance>
bool wait_ready_process(uint16_t port,
                        ProcessInstance& proc,
                        int timeout_ms,
                        const char* exited_early_message,
                        const char* timed_out_message,
                        std::string* error) {
    const int64_t deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        if (proc.pid > 0) {
            int status = 0;
            const pid_t waited = waitpid(proc.pid, &status, WNOHANG);
            if (waited == proc.pid) {
                proc.pid = -1;
                *error = exited_early_message;
                return false;
            }
        }
        if (tcp_port_open(port)) return true;
        struct timespec ts{0, 50'000'000};
        nanosleep(&ts, nullptr);
    }
    *error = timed_out_message;
    return false;
}

bool wait_ready(uint16_t port, EnvoyInstance& envoy, int timeout_ms, std::string* error) {
    return wait_ready_process(port,
                              envoy,
                              timeout_ms,
                              "docker run exited before Envoy became ready",
                              "timed out waiting for Envoy to accept connections",
                              error);
}

// wait_ready() only proves that *some* process is now accepting connections
// on `port`; it does not prove that process is the Envoy container this
// harness just launched. When another process wins the bind race for a
// probe-allocated listener port, that foreign socket can already be open
// (satisfying tcp_port_open()) before Envoy's own doomed bind attempt inside
// the container finishes failing and the docker child exits to report the
// collision, so wait_ready() can return true for an unrelated listener and
// bypass launch_envoy_with_port_retry()'s EADDRINUSE-retry branch entirely
// (round-7 review, "readiness may observe a foreign listener").
//
// A fixed grace period on its own is not enough to rule that out (round-8
// review, "Verify listener ownership instead of timing process liveness"):
// a cold or loaded `docker run` can take longer than any fixed grace period
// to reach Envoy's own failed bind and exit, so the foreign listener's
// process being merely *alive* through the grace period proves nothing
// about who owns `port`. The liveness recheck below stays as a cheap first
// step (a child that has already exited certainly never owned the port),
// but real confirmation comes from the protocol: probe_confirms_envoy_
// ownership() is retried until it succeeds, the tracked child exits, or the
// overall readiness deadline passes. A foreign listener that answers
// differently (or not at all) never confirms, and a child that exits while
// probing is caught immediately instead of waiting out the full deadline.
bool wait_ready_and_confirm_ownership(
    uint16_t port, EnvoyInstance& envoy, int timeout_ms, int grace_ms, std::string* error) {
    const int64_t deadline = now_ms() + timeout_ms;
    if (!wait_ready(port, envoy, timeout_ms, error)) return false;

    // Cheap first step: a child that already exited never owned `port`.
    struct timespec grace{grace_ms / 1000, static_cast<long>(grace_ms % 1000) * 1'000'000};
    nanosleep(&grace, nullptr);
    if (envoy.pid > 0) {
        int status = 0;
        const pid_t waited = waitpid(envoy.pid, &status, WNOHANG);
        if (waited == envoy.pid) {
            envoy.pid = -1;
            *error =
                "docker run exited shortly after the listener port opened; a different "
                "process likely won the bind race";
            return false;
        }
    }

    // Real confirmation: the protocol-level probe, retried within the
    // overall readiness deadline. The probe alone is not launch-specific --
    // any Envoy-like process answering on `port` produces the same reply
    // (round-9 review, "Use a launch-specific listener ownership
    // challenge") -- so a probe success is only provisional until this
    // launched child's own captured log also reports having finished
    // startup as the owner of its listeners (envoy_log_confirms_listener()).
    // A foreign listener that happens to answer like Envoy therefore still
    // fails here, because nothing ever writes that line into *our* child's
    // log file.
    std::string probe_error;
    for (;;) {
        if (envoy.pid > 0) {
            int status = 0;
            const pid_t waited = waitpid(envoy.pid, &status, WNOHANG);
            if (waited == envoy.pid) {
                envoy.pid = -1;
                *error = "docker run exited while confirming listener ownership";
                return false;
            }
        }
        if (probe_confirms_envoy_ownership(port, 1000, &probe_error) &&
            envoy_log_confirms_listener(read_file_contents(envoy.log_path))) {
            return true;
        }
        if (now_ms() >= deadline) {
            *error =
                "timed out confirming listener ownership (protocol probe and/or launch-specific "
                "log evidence never both succeeded): " +
                probe_error;
            return false;
        }
        struct timespec retry_ts{0, 50'000'000};
        nanosleep(&retry_ts, nullptr);
    }
}

// Polls until `port` stops accepting connections (or `timeout_ms` elapses),
// returning the final observation either way. Used between the Envoy and RUT
// phases of `--pair-milestone-s`: both sides listen on the SAME port in
// sequence, so the harness must see Envoy's listener actually go away before
// starting `rut` on it.
bool wait_port_closed(uint16_t port, int timeout_ms) {
    const int64_t deadline = now_ms() + timeout_ms;
    do {
        if (!tcp_port_open(port)) return true;
        struct timespec ts{0, 50'000'000};
        nanosleep(&ts, nullptr);
    } while (now_ms() < deadline);
    return !tcp_port_open(port);
}

// ── RUT process management (PR 6) ───────────────────────────────────────

// Renders a `waitpid` status for a FAIL message: "exited N" for a normal
// exit, "killed by signal N" for one it did not ask for.
std::string describe_wait_status(int status) {
    if (WIFEXITED(status)) return "exited " + std::to_string(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) return "killed by signal " + std::to_string(WTERMSIG(status));
    return "unknown wait status";
}

// Launches the real `rut` binary (built by this repo, not a container) on
// the listener/upstream ports baked into `rut_source_path` by
// `rut-envoy-convert`. Mirrors `EnvoyInstance` above: fork/exec, redirect
// stdio to a log file, SIGTERM-then-SIGKILL teardown with reaping.
struct RutInstance {
    pid_t pid = -1;
    std::string log_path;
    // Set by stop() when the child had already exited on its own -- a crash
    // or unexpected exit, not our SIGTERM/SIGKILL -- before this call sent
    // it any signal. A caller that sees this after a run must treat the
    // whole result as a failure: byte comparisons collected up to that point
    // prove nothing about a binary that has since crashed.
    bool exited_unexpectedly = false;
    std::string unexpected_exit_description;

    bool launch(const std::string& rut_binary, const std::string& rut_source_path) {
        pid = fork();
        if (pid < 0) return false;
        if (pid == 0) {
            const int log_fd = open(log_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (log_fd >= 0) {
                dup2(log_fd, STDOUT_FILENO);
                dup2(log_fd, STDERR_FILENO);
                if (log_fd > STDERR_FILENO) close(log_fd);
            }
            // rut <source.rut> --shards 1 --no-pin --drain 0
            //
            // No CLI port override is passed: the listener port comes from
            // the `listen :<port>` line `rut-envoy-convert` already baked
            // into `rut_source_path` from the SAME bootstrap Envoy is (or
            // was) serving (envoy-pr-plan.md PR 6: "pass only what is
            // required"). `--drain 0` skips the graceful drain window on
            // SIGTERM: this harness always stops `rut` with no in-flight
            // connections, so the only effect of a nonzero drain here is
            // teardown latency (tests/test_nginx_differential.cc uses the
            // same flag for the same reason).
            std::vector<std::string> argv = {
                rut_binary, rut_source_path, "--shards", "1", "--no-pin", "--drain", "0"};
            std::vector<char*> args;
            args.reserve(argv.size() + 1);
            for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
            args.push_back(nullptr);
            execv(rut_binary.c_str(), args.data());
            _exit(127);
        }
        return true;
    }

    // Returns false iff the child had already exited by itself before this
    // call sent it any signal -- an unexpected exit (crash or otherwise)
    // that `exited_unexpectedly` / `unexpected_exit_description` describe.
    // Returns true when there was nothing to stop, or when the child ended
    // because of the SIGTERM/SIGKILL sent here (an intentional teardown).
    bool stop() {
        if (pid <= 0) return true;
        int status = 0;
        // Check before signaling: if the child is already a zombie here, it
        // exited on its own, not because we asked it to.
        const pid_t precheck = waitpid(pid, &status, WNOHANG);
        if (precheck == pid) {
            exited_unexpectedly = true;
            unexpected_exit_description = describe_wait_status(status);
            pid = -1;
            return false;
        }
        kill(pid, SIGTERM);
        const int64_t deadline = now_ms() + 5000;
        for (;;) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) break;
            if (now_ms() >= deadline) {
                kill(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
                }
                break;
            }
            struct timespec ts{0, 10'000'000};
            nanosleep(&ts, nullptr);
        }
        pid = -1;
        return true;
    }

    ~RutInstance() { stop(); }
};

bool wait_ready(uint16_t port, RutInstance& rut, int timeout_ms, std::string* error) {
    return wait_ready_process(port,
                              rut,
                              timeout_ms,
                              "rut exited before it became ready",
                              "timed out waiting for rut to accept connections",
                              error);
}

void dump_rut_log(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::cerr << "---- rut log (" << path << ") ----\n" << in.rdbuf() << "\n---- end log ----\n";
}

// ── Converter invocation (PR 6) ──────────────────────────────────────────

// Runs `rut-envoy-convert --format bootstrap-json <bootstrap_path>`,
// redirecting stdout to `out_rut_path` and capturing stderr into
// `*stderr_out`. Returns true only on exit 0 with empty stderr (the
// contract both --self-test's RUT pass and --pair-milestone-s rely on); the
// caller prints `*stderr_out` on failure.
bool run_converter_to_file(const std::string& converter_binary,
                           const std::string& bootstrap_path,
                           const std::string& out_rut_path,
                           std::string* stderr_out) {
    const std::string stderr_path = out_rut_path + ".stderr";
    const pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        const int out_fd = open(out_rut_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
        const int err_fd = open(stderr_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (out_fd >= 0) dup2(out_fd, STDOUT_FILENO);
        if (err_fd >= 0) dup2(err_fd, STDERR_FILENO);
        if (out_fd > STDERR_FILENO) close(out_fd);
        if (err_fd > STDERR_FILENO) close(err_fd);
        std::vector<std::string> argv = {
            converter_binary, "--format", "bootstrap-json", bootstrap_path};
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        execv(converter_binary.c_str(), args.data());
        _exit(127);
    }
    int status = 0;
    const int64_t deadline_ms = now_ms() + 10'000;
    for (;;) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno == EINTR) continue;
        if (waited < 0) {
            unlink(stderr_path.c_str());
            return false;
        }
        if (now_ms() >= deadline_ms) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
            unlink(stderr_path.c_str());
            return false;
        }
        struct timespec ts{0, 5'000'000};
        nanosleep(&ts, nullptr);
    }
    {
        std::ifstream in(stderr_path);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            *stderr_out = ss.str();
        }
    }
    unlink(stderr_path.c_str());
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 && stderr_out->empty();
}

// ── Bootstrap template ──────────────────────────────────────────────────

// The milestone-S bootstrap (docs/envoy-converter.md, "milestone-S";
// tests/test_envoy_convert.cc's `milestone_s_json`), with the listener and
// upstream endpoint ports left as placeholders so this harness can bind
// loopback ephemeral ports per run. This is also the exact bootstrap #700's
// pair mode feeds to `rut-envoy-convert`, whose converter on this branch's
// ancestry does not lower direct_response routes or multi-route lists --
// so, unlike an earlier version of the ownership probe above, this bootstrap
// is never modified to support it (round-8 review, "adding a
// direct_response route ... changes the milestone-S bootstrap itself").
const char kBootstrapTemplate[] = R"json({
"static_resources": {
"listeners": [{
"name": "ingress",
"address": {"socket_address": {"address": "0.0.0.0", "port_value": %LISTEN_PORT%}},
"filter_chains": [{"filters": [{
"name": "envoy.filters.network.http_connection_manager",
"typed_config": {
"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
"stat_prefix": "ingress",
"codec_type": "HTTP1",
"generate_request_id": false,
"route_config": {"name": "local", "virtual_hosts": [{
"name": "all",
"domains": ["*"],
"routes": [{"match": {"prefix": "/"}, "route": {"cluster": "backend", "timeout": "0s"}}]
}]},
"http_filters": [{"name": "envoy.filters.http.router",
"typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router", "suppress_envoy_headers": true}}]
}}]}]
}],
"clusters": [{
"name": "backend",
"type": "STATIC",
"connect_timeout": "5s",
"load_assignment": {"cluster_name": "backend", "endpoints": [{"lb_endpoints": [{
"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": %UPSTREAM_PORT%}}}
}]}]}
}]
}
})json";

void replace_all(std::string* text, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = text->find(from, pos)) != std::string::npos) {
        text->replace(pos, from.size(), to);
        pos += to.size();
    }
}

std::string render_bootstrap(uint16_t listen_port, uint16_t upstream_port) {
    std::string text = kBootstrapTemplate;
    replace_all(&text, "%LISTEN_PORT%", std::to_string(listen_port));
    replace_all(&text, "%UPSTREAM_PORT%", std::to_string(upstream_port));
    return text;
}

bool write_file_mode(const std::string& path, const std::string& contents, mode_t mode) {
    const int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, mode);
    if (fd < 0) return false;
    size_t offset = 0;
    bool wrote_ok = true;
    while (offset < contents.size()) {
        const ssize_t n = write(fd, contents.data() + offset, contents.size() - offset);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        wrote_ok = false;
        break;
    }
    close(fd);
    return wrote_ok;
}

std::string make_temp_dir(const char* prefix) {
    std::string pattern = std::string("/tmp/") + prefix + "-XXXXXX";
    std::vector<char> buf(pattern.begin(), pattern.end());
    buf.push_back('\0');
    if (mkdtemp(buf.data()) == nullptr) return {};
    return std::string(buf.data());
}

// Recursively removes `path` (best-effort; errors are ignored since this is
// only ever cleanup, with no good way to surface a failure). Every directory
// this harness creates via make_temp_dir()/TempDir is flat -- at most a
// handful of regular files (bootstrap.json, envoy-attemptN.log,
// transcript.inc) directly inside it -- but this recurses anyway so it stays
// correct if that ever changes.
void remove_dir_recursive(const std::string& path) {
    DIR* dir = opendir(path.c_str());
    if (dir != nullptr) {
        struct dirent* entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const std::string name = entry->d_name;
            if (name == "." || name == "..") continue;
            std::string child = path;
            child += "/";
            child += name;
            struct stat st{};
            if (lstat(child.c_str(), &st) != 0) continue;
            if (S_ISDIR(st.st_mode)) {
                remove_dir_recursive(child);
            } else {
                unlink(child.c_str());
            }
        }
        closedir(dir);
    }
    rmdir(path.c_str());
}

// RAII owner of a make_temp_dir() directory: removes it (and everything the
// harness wrote inside it) on destruction, unless RUT_ENVOY_KEEP_TMP=1 is
// set in the environment to keep it around for diagnostics (round-15
// review, "Remove temporary harness directories after each run") -- every
// make_temp_dir() call site previously leaked its directory forever, so
// long-lived or repeated local/CI runs accumulated /tmp/rut-envoy-* entries
// without bound.
class TempDir {
public:
    explicit TempDir(const char* prefix) : path_(make_temp_dir(prefix)) {}

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    TempDir(TempDir&&) = delete;
    TempDir& operator=(TempDir&&) = delete;

    ~TempDir() {
        if (path_.empty() || keep_for_diagnostics()) return;
        remove_dir_recursive(path_);
    }

    const std::string& path() const { return path_; }
    bool empty() const { return path_.empty(); }

private:
    static bool keep_for_diagnostics() {
        const char* v = getenv("RUT_ENVOY_KEEP_TMP");
        return v != nullptr && std::string(v) == "1";
    }

    std::string path_;
};

// ── Case table ───────────────────────────────────────────────────────────

struct CaseSpec {
    const char* name;
    std::string client_bytes;
    bool is_head;
    std::string upstream_path;   // key for the recording upstream's reply table
    std::string upstream_reply;  // exact bytes the recording upstream sends back
};

constexpr char kHost[] = "Host: client.example\r\n";

std::vector<CaseSpec> run1_cases() {
    const std::string smoke_reply =
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n"
        "X-Upstream-Case: Yes\r\n\r\nhello";
    std::vector<CaseSpec> cases;
    cases.push_back({"get_smoke",
                     "GET /smoke?q=1 HTTP/1.1\r\nHost: client.example\r\nUser-Agent: rut-diff/1\r\n"
                     "X-Mixed-Case: Value\r\nAccept: */*\r\n\r\n",
                     false,
                     "/smoke",
                     smoke_reply});
    cases.push_back({"get_upstream_date_server",
                     "GET /date HTTP/1.1\r\nHost: client.example\r\nUser-Agent: rut-diff/1\r\n"
                     "X-Mixed-Case: Value\r\nAccept: */*\r\n\r\n",
                     false,
                     "/date",
                     "HTTP/1.1 200 Fine\r\nX-First: 1\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
                     "Server: origin/1.0\r\nContent-Length: 2\r\n\r\nok"});
    cases.push_back({"get_client_close",
                     "GET /close HTTP/1.1\r\nHost: client.example\r\nUser-Agent: rut-diff/1\r\n"
                     "X-Mixed-Case: Value\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                     false,
                     "/close",
                     smoke_reply});
    cases.push_back({"get_hop_by_hop",
                     "GET /hop HTTP/1.1\r\nHost: client.example\r\nUser-Agent: rut-diff/1\r\n"
                     "X-Mixed-Case: Value\r\nAccept: */*\r\n"
                     "Connection: keep-alive, X-Drop-Me\r\nKeep-Alive: timeout=5\r\n"
                     "Proxy-Connection: keep-alive\r\nTE: trailers\r\nX-Drop-Me: 1\r\n"
                     "X-Forwarded-Proto: https\r\n\r\n",
                     false,
                     "/hop",
                     smoke_reply});
    cases.push_back({"head_smoke",
                     std::string("HEAD /head HTTP/1.1\r\n") + kHost + "\r\n",
                     true,
                     "/head",
                     "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"});
    cases.push_back(
        {"post_fixed",
         std::string("POST /upload HTTP/1.1\r\n") + kHost + "Content-Length: 4\r\n\r\nabcd",
         false,
         "/upload",
         "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"});
    cases.push_back({"trace",
                     std::string("TRACE /trace HTTP/1.1\r\n") + kHost + "\r\n",
                     false,
                     "/trace",
                     "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    cases.push_back({"options_star",
                     std::string("OPTIONS * HTTP/1.1\r\n") + kHost + "\r\n",
                     false,
                     "*",
                     smoke_reply});
    cases.push_back({"connect_authority",
                     "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
                     false,
                     "example.com:443",
                     smoke_reply});
    return cases;
}

// The run-2 case (PR 2's second Envoy instance, pointed at a closed port):
// `get_smoke`'s exact client bytes, renamed. Shared by oracle, pair and
// self-test modes so the client bytes for this case can never drift from the
// ones actually recorded in the oracle fixture's `kEnvoyOracle_connect_failure_*`.
CaseSpec connect_failure_case() {
    CaseSpec spec = run1_cases().front();  // get_smoke
    spec.name = "connect_failure";
    return spec;
}

// The six cases envoy-pr-plan.md PR 6 requires byte-for-byte agreement on.
// Shared by --pair-milestone-s (which also runs the four record-only cases)
// and --self-test's RUT pass (which only needs the asserted cases against
// the committed oracle).
// get_hop_by_hop, trace and options_star were record-only until CI run
// 36069445967 showed their Envoy and RUT bytes equal; connect_authority stays
// record-only because Envoy closes that connection and Rut does not.
constexpr const char* kAssertedCaseNames[] = {"get_smoke",
                                              "get_upstream_date_server",
                                              "get_client_close",
                                              "head_smoke",
                                              "post_fixed",
                                              "connect_failure",
                                              "get_hop_by_hop",
                                              "trace",
                                              "options_star"};

bool is_asserted_case(const std::string& name) {
    for (const char* asserted : kAssertedCaseNames)
        if (name == asserted) return true;
    return false;
}

// ── Case results & transcript ────────────────────────────────────────────

struct CaseResult {
    std::string name;
    std::string client_bytes;
    // Whether the downstream exchange (client request + Envoy's response)
    // actually finished framing within the deadline; see ReadResult. Never
    // trust downstream_bytes when this is false.
    bool exchange_complete = false;
    bool upstream_contacted = false;
    // How many times the recording upstream observed a request for this
    // case's path. Expected to be 0 (never contacted) or 1; more than one is
    // treated as corrupt evidence (an unexpected retry/duplicate), not a
    // single trustworthy recording (round-3 review, "Reject partial
    // exchanges before writing the oracle transcript").
    int upstream_contact_count = 0;
    std::string upstream_bytes;  // first observed request, if any
    std::string downstream_bytes;
};

bool run_client_case(uint16_t listen_port, const CaseSpec& spec, CaseResult* result) {
    result->name = spec.name;
    result->client_bytes = spec.client_bytes;
    const int fd = connect_with_timeout(listen_port, kClientTimeoutMs);
    if (fd < 0) return false;
    const bool sent = send_all(fd, spec.client_bytes);
    if (sent) {
        const ReadResult read = read_http_message(fd, spec.is_head, kClientTimeoutMs);
        result->downstream_bytes = read.bytes;
        result->exchange_complete = read.complete;
    }
    close(fd);
    return sent && result->exchange_complete;
}

// Runs every case in `cases` against an already-listening `listen_port`, in
// order, returning one `CaseResult` per case (populated with client/
// downstream bytes only -- see `fill_upstream_bytes` for the upstream side).
// Shared by --pair-milestone-s (Envoy and RUT phases) and --self-test's RUT
// pass; --oracle-milestone-s keeps its own inline loop (PR 2, unchanged).
std::vector<CaseResult> run_case_batch(uint16_t listen_port, const std::vector<CaseSpec>& cases) {
    std::vector<CaseResult> results;
    results.reserve(cases.size());
    for (const auto& spec : cases) {
        CaseResult r;
        if (!run_client_case(listen_port, spec, &r))
            std::cerr << "WARN: case " << spec.name << " exchange did not complete cleanly\n";
        results.push_back(std::move(r));
    }
    return results;
}

// Fills in `upstream_contacted`/`upstream_contact_count`/`upstream_bytes` on
// each result in `results` from what `upstream` actually recorded for that
// case's path, matching cases by name against `cases` to find each one's
// `upstream_path`. Returns false if any case's path recorded more than one
// request: a retried, replayed or otherwise duplicated upstream request
// (which could repeat a side effect in production, e.g. the fixed-length
// POST) must fail the harness immediately rather than be silently reduced
// to the first observation. `upstream_contact_count` is always recorded
// (even on the failing path) so the same at-most-once-contact rule
// `validate_results` enforces again at transcript-write time (round-3
// review) still catches a duplicate that reaches a transcript writer some
// other way.
bool fill_upstream_bytes(std::vector<CaseResult>* results,
                         const std::vector<CaseSpec>& cases,
                         RecordingUpstream& upstream) {
    bool ok = true;
    for (auto& r : *results) {
        const auto it = std::find_if(
            cases.begin(), cases.end(), [&](const CaseSpec& s) { return r.name == s.name; });
        if (it == cases.end()) continue;
        const auto observed = upstream.requests_for(it->upstream_path);
        r.upstream_contact_count = static_cast<int>(observed.size());
        if (observed.empty()) continue;
        if (observed.size() > 1) {
            std::cerr << "FAIL: upstream recorded " << observed.size() << " requests for case "
                      << r.name << " (path \"" << it->upstream_path
                      << "\"), expected exactly one\n";
            ok = false;
            continue;
        }
        r.upstream_contacted = true;
        r.upstream_bytes = observed.front();
    }
    return ok;
}

// Refuses evidence that would make write_transcript() emit a fixture
// claiming bytes for an exchange that never actually completed, or claiming
// a single upstream request when the recording upstream in fact observed
// more than one (round-3 review, "Reject partial exchanges before writing
// the oracle transcript"). Returns empty on success, else a human-readable
// reason.
std::string validate_results(const std::vector<CaseResult>& results) {
    for (const auto& r : results) {
        if (!r.exchange_complete) {
            return "case \"" + r.name +
                   "\": downstream exchange did not complete (partial read/timeout); refusing "
                   "to record it as evidence";
        }
        if (r.upstream_contact_count > 1) {
            return "case \"" + r.name + "\": upstream was contacted " +
                   std::to_string(r.upstream_contact_count) +
                   " times (expected at most 1); refusing to record ambiguous evidence";
        }
    }
    return "";
}

// Returns `raw` with its `date:` header value replaced by a fixed
// placeholder, UNLESS that value is exactly `preserved_date` (the literal
// the recording upstream sent for `get_upstream_date_server`, which Envoy
// and RUT must both preserve unchanged -- normalizing it away would hide a
// real bug). Every other case's `date` is synthesized to "now" by whichever
// side produced it, so those are always normalized before a byte comparison.
// `preserved_date` is empty for every other case, which never matches a
// real Date value and so always normalizes.
std::string normalize_date_for_compare(const std::string& raw, const std::string& preserved_date) {
    const size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return raw;
    const std::string head = raw.substr(0, header_end);
    const std::string rest = raw.substr(header_end);  // "\r\n\r\n" + body
    std::vector<std::string> lines;
    size_t start = 0;
    for (;;) {
        const size_t nl = head.find("\r\n", start);
        if (nl == std::string::npos) {
            lines.push_back(head.substr(start));
            break;
        }
        lines.push_back(head.substr(start, nl - start));
        start = nl + 2;
    }
    for (auto& line : lines) {
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        const std::string key = line.substr(0, colon);
        constexpr char kDate[] = "date";
        if (key.size() != 4 || !std::equal(key.begin(), key.end(), kDate, [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) == b;
            }))
            continue;
        std::string value = line.substr(colon + 1);
        const size_t a = value.find_first_not_of(" \t");
        const size_t b = value.find_last_not_of(" \t");
        const std::string trimmed = a == std::string::npos ? "" : value.substr(a, b - a + 1);
        if (trimmed != preserved_date) {
            // Replace only the value bytes, keeping the exact prefix (the
            // whitespace between ':' and the value, which may differ
            // between implementations) and any trailing whitespace intact,
            // so this never hides a real formatting difference elsewhere on
            // the line.
            const std::string prefix = a == std::string::npos ? value : value.substr(0, a);
            const std::string suffix = a == std::string::npos ? "" : value.substr(b + 1);
            std::string new_line = line.substr(0, colon + 1);
            new_line += prefix;
            new_line += "<normalized-date>";
            new_line += suffix;
            line = std::move(new_line);
        }
    }
    std::string out;
    for (size_t i = 0; i < lines.size(); i++) {
        if (i != 0) out += "\r\n";
        out += lines[i];
    }
    out += rest;
    return out;
}

bool write_transcript(const std::string& path, const std::vector<CaseResult>& results) {
    const std::string validation_error = validate_results(results);
    if (!validation_error.empty()) {
        std::cerr << "FAIL: refusing to write oracle transcript: " << validation_error << "\n";
        return false;
    }
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    time_t now = time(nullptr);
    char date_buf[64];
    struct tm tm_buf{};
    gmtime_r(&now, &tm_buf);
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    out << "#pragma once\n\n";
    out << "// Envoy oracle transcript recorded against " << kEnvoyImage << " (" << date_buf
        << ").\n";
    out << "// Generated by tests/test_envoy_differential.cc --oracle-milestone-s; do not\n";
    out << "// hand-edit. See docs/envoy-converter.md \"Test layers\" and\n";
    out << "// envoy-pr-plan.md PR 2.\n\n";
    for (const auto& r : results) {
        out << "static constexpr char kEnvoyOracle_" << r.name << "_client[] =\n    "
            << wrap_wire_literal(r.client_bytes) << ";\n";
        if (!r.upstream_contacted) out << "// " << r.name << ": upstream not contacted\n";
        out << "static constexpr char kEnvoyOracle_" << r.name << "_upstream[] =\n    "
            << wrap_wire_literal(r.upstream_bytes) << ";\n";
        out << "static constexpr char kEnvoyOracle_" << r.name << "_downstream[] =\n    "
            << wrap_wire_literal(r.downstream_bytes) << ";\n\n";
    }
    // Explicitly flush and close before checking the stream's state (round-15
    // review, "Check transcript close errors before reporting success"):
    // `return static_cast<bool>(out)` here previously ran *before* the
    // stream's destructor performed its implicit final flush/close, so a
    // write failure that only surfaces at that point (e.g. the destination
    // filesystem filling up right as the last, still-buffered bytes are
    // written out) was never observed -- the small transcripts this function
    // writes usually fit entirely in ofstream's internal buffer until close,
    // so nothing had actually failed yet by the time the old check ran. The
    // caller could be told the transcript was written successfully while a
    // truncated (or empty) file was left on disk.
    out.flush();
    out.close();
    return out.good();
}

// One case's paired Envoy/RUT observation (--pair-milestone-s, PR 6).
struct PairCaseResult {
    std::string name;
    bool asserted = false;
    CaseResult envoy;
    CaseResult rut;
};

// Writes both sides' bytes for every pair case as a transcript header, in
// the same one-literal-per-wire-line style as `write_transcript`. This is
// the "<out.inc>" CI artifact evidence for PR 6: unlike the oracle
// transcript, each case here carries two upstream and two downstream
// literals (`_envoy_*` / `_rut_*`) so a reviewer can diff them directly.
bool write_pair_transcript(const std::string& path, const std::vector<PairCaseResult>& results) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    time_t now = time(nullptr);
    char date_buf[64];
    struct tm tm_buf{};
    gmtime_r(&now, &tm_buf);
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    out << "#pragma once\n\n";
    out << "// Envoy-vs-generated-RUT pair transcript recorded against " << kEnvoyImage << " ("
        << date_buf << ").\n";
    out << "// Generated by tests/test_envoy_differential.cc --pair-milestone-s; do not\n";
    out << "// hand-edit. See docs/envoy-compatibility.md and envoy-pr-plan.md PR 6.\n\n";
    for (const auto& r : results) {
        out << "// " << r.name << (r.asserted ? " (asserted)" : " (record-only)") << "\n";
        out << "static constexpr char kEnvoyVsRut_" << r.name << "_client[] =\n    "
            << wrap_wire_literal(r.envoy.client_bytes) << ";\n";
        if (!r.envoy.upstream_contacted)
            out << "// " << r.name << ": envoy upstream not contacted\n";
        out << "static constexpr char kEnvoyVsRut_" << r.name << "_envoy_upstream[] =\n    "
            << wrap_wire_literal(r.envoy.upstream_bytes) << ";\n";
        out << "static constexpr char kEnvoyVsRut_" << r.name << "_envoy_downstream[] =\n    "
            << wrap_wire_literal(r.envoy.downstream_bytes) << ";\n";
        if (!r.rut.upstream_contacted) out << "// " << r.name << ": rut upstream not contacted\n";
        out << "static constexpr char kEnvoyVsRut_" << r.name << "_rut_upstream[] =\n    "
            << wrap_wire_literal(r.rut.upstream_bytes) << ";\n";
        out << "static constexpr char kEnvoyVsRut_" << r.name << "_rut_downstream[] =\n    "
            << wrap_wire_literal(r.rut.downstream_bytes) << ";\n\n";
    }
    return static_cast<bool>(out);
}

int count_header(const std::string& raw, const std::string& name) {
    const size_t header_end = raw.find("\r\n\r\n");
    std::string headers = header_end == std::string::npos ? raw : raw.substr(0, header_end);
    int count = 0;
    size_t start = 0;
    while (start < headers.size()) {
        size_t line_end = headers.find("\r\n", start);
        if (line_end == std::string::npos) line_end = headers.size();
        const std::string line = headers.substr(start, line_end - start);
        const size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            if (key.size() == name.size() &&
                std::equal(key.begin(), key.end(), name.begin(), [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a)) ==
                           std::tolower(static_cast<unsigned char>(b));
                }))
                count++;
        }
        if (line_end == headers.size()) break;
        start = line_end + 2;
    }
    return count;
}

const CaseResult* find_case(const std::vector<CaseResult>& results, const std::string& name) {
    for (const auto& r : results)
        if (r.name == name) return &r;
    return nullptr;
}

bool assert_get_smoke(const std::vector<CaseResult>& results) {
    const CaseResult* c = find_case(results, "get_smoke");
    if (c == nullptr) {
        std::cerr << "FAIL [get_smoke]: case missing\n";
        return false;
    }
    bool ok = true;
    if (!starts_with(c->downstream_bytes, "HTTP/1.1 200 ")) {
        std::cerr << "FAIL [get_smoke]: downstream does not start with \"HTTP/1.1 200 \"\n";
        ok = false;
    }
    if (!ends_with(c->downstream_bytes, "hello")) {
        std::cerr << "FAIL [get_smoke]: downstream does not end with \"hello\"\n";
        ok = false;
    }
    if (!c->upstream_contacted) {
        std::cerr << "FAIL [get_smoke]: upstream was not contacted\n";
        ok = false;
    } else {
        const size_t line_end = c->upstream_bytes.find("\r\n");
        const std::string request_line = line_end == std::string::npos
                                             ? c->upstream_bytes
                                             : c->upstream_bytes.substr(0, line_end);
        if (request_line != "GET /smoke?q=1 HTTP/1.1") {
            std::cerr << "FAIL [get_smoke]: upstream request line was \"" << request_line
                      << "\", expected \"GET /smoke?q=1 HTTP/1.1\"\n";
            ok = false;
        }
        if (count_header(c->upstream_bytes, "host") != 1 ||
            !header_equals_ci(c->upstream_bytes, "host", "client.example")) {
            std::cerr << "FAIL [get_smoke]: upstream did not have exactly one host header equal "
                         "to \"client.example\"\n";
            ok = false;
        }
    }
    if (!header_equals_ci(c->downstream_bytes, "server", "envoy")) {
        std::cerr << "FAIL [get_smoke]: downstream server header was not \"envoy\"\n";
        ok = false;
    }
    return ok;
}

bool assert_connect_failure(const std::vector<CaseResult>& results) {
    const CaseResult* c = find_case(results, "connect_failure");
    if (c == nullptr) {
        std::cerr << "FAIL [connect_failure]: case missing\n";
        return false;
    }
    if (!starts_with(c->downstream_bytes, "HTTP/1.1 503 ")) {
        std::cerr << "FAIL [connect_failure]: downstream does not start with \"HTTP/1.1 503 \"\n";
        return false;
    }
    return true;
}

// ── --oracle-milestone-s ─────────────────────────────────────────────────

int container_name_suffix_counter = 0;

std::string make_container_name(const char* label) {
    return std::string("rut-envoy-oracle-") + std::to_string(getpid()) + "-" + label + "-" +
           std::to_string(container_name_suffix_counter++);
}

// Case-insensitive scan of an Envoy log for a bind-collision message (Envoy
// logs `Address already in use` when its own listen() call races another
// process for the port), used by launch_envoy_with_port_retry() to tell a
// genuine startup failure apart from a port collision worth retrying.
bool log_indicates_address_in_use(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    std::string contents = ss.str();
    std::transform(contents.begin(), contents.end(), contents.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return contents.find("address already in use") != std::string::npos ||
           contents.find("address in use") != std::string::npos;
}

// Launches `envoy` against a bootstrap rendered from `*listen_port` and
// `other_port` (the upstream port for run 1, the deliberately-closed port for
// run 2), and waits for it to accept connections.
//
// Envoy binds `*listen_port` itself inside the container, so unlike the
// recording upstream's port (reserved end to end via
// allocate_bound_loopback_port()/RecordingUpstream::adopt()), this harness
// can only probe-allocate the number and hand it to Envoy, leaving a window
// for another process to take it first. When that happens,
// wait_ready_and_confirm_ownership() fails (either because Envoy's own log
// names the collision immediately, or, if a foreign listener was briefly
// mistaken for readiness, because the docker child exits during the
// post-readiness grace period) and this function retries on a freshly
// allocated port, up to kMaxListenPortAttempts attempts total (round-6
// review, "detect a collision ... retry with a fresh port ... print that it
// retried, and never record a failed attempt as evidence"; round-7 review,
// "readiness may observe a foreign listener"). A failed attempt's container
// is torn down before either retrying or returning, so nothing from it
// survives to be mistaken for evidence; only a `true` return leaves
// `envoy`/`*listen_port` describing a live, ready Envoy instance confirmed
// to still own the port.
bool launch_envoy_with_port_retry(const std::string& dir,
                                  const char* label,
                                  uint16_t* listen_port,
                                  uint16_t other_port,
                                  EnvoyInstance* envoy,
                                  std::string* error) {
    const std::string bootstrap_path = dir + "/bootstrap.json";
    for (int attempt = 1; attempt <= kMaxListenPortAttempts; attempt++) {
        if (!write_file_mode(bootstrap_path, render_bootstrap(*listen_port, other_port), 0644)) {
            *error = "could not write bootstrap.json";
            return false;
        }
        envoy->name = make_container_name(label);
        envoy->log_path = dir + "/envoy-attempt" + std::to_string(attempt) + ".log";
        if (!envoy->launch(bootstrap_path, *listen_port)) {
            *error = "could not fork/exec docker run";
            return false;
        }
        if (wait_ready_and_confirm_ownership(*listen_port, *envoy, 15'000, 300, error)) {
            return true;
        }

        const bool collided = log_indicates_address_in_use(envoy->log_path);
        envoy->stop();
        if (!collided || attempt == kMaxListenPortAttempts) return false;

        uint16_t fresh_port = 0;
        if (!allocate_loopback_port(&fresh_port)) {
            *error = "could not allocate a replacement loopback port after a bind collision";
            return false;
        }
        std::cerr << "RETRY: Envoy listener port " << *listen_port
                  << " lost a bind race to another process (attempt " << attempt << "/"
                  << kMaxListenPortAttempts << "); retrying on port " << fresh_port << "\n";
        *listen_port = fresh_port;
    }
    return false;
}

int run_oracle_milestone_s(const std::string& output_path) {
    const std::string missing = check_docker_prerequisites();
    if (!missing.empty()) return missing_prerequisite(missing);

    // The recording upstream's port is reserved end to end: this process
    // binds and listens on it right here and keeps that same socket alive
    // until RecordingUpstream::adopt() takes it over, so no other process can
    // ever grab it out from under us (round-6 review, "Keep allocated ports
    // reserved until their consumers bind"). Envoy's two listener ports can
    // only be probe-allocated (Envoy binds its own port inside the
    // container), so they still go through allocate_distinct_ports() below.
    // The connect_failure case's "closed" port is likewise reserved end to
    // end via allocate_reserved_closed_port(): it stays bound but
    // non-listening (never probed-and-released) so no other host process can
    // claim it before run 2's connect attempt (round-7 review, "Keep the
    // connect-failure port reserved").
    BoundPort upstream_bound;
    if (!allocate_bound_loopback_port(&upstream_bound)) {
        std::cerr << "FAIL: could not allocate loopback port for the recording upstream\n";
        return 1;
    }
    const uint16_t upstream_port1 = upstream_bound.port;

    BoundPort closed_reserved;
    if (!allocate_reserved_closed_port(&closed_reserved)) {
        std::cerr << "FAIL: could not allocate the connect_failure case's closed port\n";
        close(upstream_bound.fd);
        return 1;
    }
    const uint16_t closed_port = closed_reserved.port;

    uint16_t listen_port1 = 0, listen_port2 = 0;
    if (!allocate_distinct_ports({&listen_port1, &listen_port2})) {
        std::cerr << "FAIL: could not allocate loopback ports\n";
        close(upstream_bound.fd);
        close(closed_reserved.fd);
        return 1;
    }

    std::vector<CaseResult> results;

    // ---- Run 1: live recording upstream ----
    {
        TempDir dir("rut-envoy-oracle");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            return 1;
        }
        RecordingUpstream upstream;
        for (const auto& spec : run1_cases())
            upstream.set_reply(spec.upstream_path, spec.upstream_reply);
        if (!upstream.adopt(upstream_bound.fd)) {
            std::cerr << "FAIL: could not start recording upstream\n";
            close(upstream_bound.fd);
            return 1;
        }

        EnvoyInstance envoy;
        std::string ready_error;
        if (!launch_envoy_with_port_retry(
                dir.path(), "run1", &listen_port1, upstream_port1, &envoy, &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy.log_path);
            return 1;
        }

        // launch_envoy_with_port_retry() above already ran the ownership
        // probe (wait_ready_and_confirm_ownership()) against this same live
        // recording upstream; confirm it never actually reached it (round-8
        // review, "the recording upstream must not be contacted by the
        // probe"), before any of run1_cases()'s own evidence -- including
        // the later options_star case, which shares this same request
        // target and is likewise never contacted -- is collected below.
        if (!upstream.requests_for(kOwnershipProbeTarget).empty()) {
            std::cerr << "FAIL: the listener-ownership probe contacted the recording upstream; "
                         "the asterisk-form request must be answered by Envoy's own "
                         "router-not-found local reply, never routed to a cluster\n";
            envoy.stop();
            upstream.stop();
            return 1;
        }

        const auto cases = run1_cases();
        for (const auto& spec : cases) {
            CaseResult r;
            if (!run_client_case(listen_port1, spec, &r))
                std::cerr << "WARN: case " << spec.name << " exchange did not complete cleanly\n";
            results.push_back(std::move(r));
        }

        envoy.stop();

        for (auto& r : results) {
            const auto it = std::find_if(
                cases.begin(), cases.end(), [&](const CaseSpec& s) { return r.name == s.name; });
            if (it == cases.end()) continue;
            const auto observed = upstream.requests_for(it->upstream_path);
            r.upstream_contact_count = static_cast<int>(observed.size());
            if (!observed.empty()) {
                r.upstream_contacted = true;
                r.upstream_bytes = observed.front();
            }
        }
        upstream.stop();
    }

    // ---- Run 2: connect_failure against a closed upstream port ----
    {
        TempDir dir("rut-envoy-oracle2");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            close(closed_reserved.fd);
            return 1;
        }
        EnvoyInstance envoy;
        std::string ready_error;
        if (!launch_envoy_with_port_retry(
                dir.path(), "run2", &listen_port2, closed_port, &envoy, &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy.log_path);
            close(closed_reserved.fd);
            return 1;
        }
        CaseSpec spec = run1_cases().front();  // get_smoke's exact client bytes
        CaseResult r;
        if (!run_client_case(listen_port2, spec, &r))
            std::cerr << "WARN: case connect_failure exchange did not complete cleanly\n";
        // The connect-failure exchange is now complete; only past this point
        // is it safe to release the reservation on `closed_port` (round-7
        // review, "Keep the connect-failure port reserved").
        close(closed_reserved.fd);
        r.name = "connect_failure";  // run_client_case sets this from `spec` ("get_smoke");
                                     // override after the call, not before.
        r.upstream_contacted = false;
        results.push_back(std::move(r));
        envoy.stop();
    }

    if (!write_transcript(output_path, results)) {
        std::cerr << "FAIL: could not write transcript to " << output_path << "\n";
        return 1;
    }
    std::cerr << "wrote transcript to " << output_path << "\n";

    const bool smoke_ok = assert_get_smoke(results);
    const bool connect_failure_ok = assert_connect_failure(results);
    return (smoke_ok && connect_failure_ok) ? 0 : 1;
}

// ── --pair-milestone-s (PR 6) ────────────────────────────────────────────

// Compares one pair case's Envoy and RUT observations, printing
// MATCH/MISMATCH with escaped literals for either mismatching side. Returns
// true iff both sides produced a complete exchange (see
// `CaseResult::exchange_complete`) AND both upstream and downstream bytes
// agree (downstream compared after `normalize_date_for_compare`, everything
// else byte for byte). Two exchanges that both failed identically (e.g. a
// connection refused on both sides yielding two empty buffers) must never
// report MATCH: that would let the harness pass without ever exercising the
// case.
bool compare_pair_case(const PairCaseResult& c) {
    const std::string preserved_date =
        c.name == "get_upstream_date_server" ? "Mon, 01 Jan 2024 00:00:00 GMT" : std::string();
    const std::string envoy_down =
        normalize_date_for_compare(c.envoy.downstream_bytes, preserved_date);
    const std::string rut_down = normalize_date_for_compare(c.rut.downstream_bytes, preserved_date);
    const bool both_complete = c.envoy.exchange_complete && c.rut.exchange_complete;
    const bool upstream_match = c.envoy.upstream_contacted == c.rut.upstream_contacted &&
                                c.envoy.upstream_bytes == c.rut.upstream_bytes;
    const bool downstream_match = envoy_down == rut_down;
    const bool match = both_complete && upstream_match && downstream_match;
    std::cerr << (match ? "MATCH    [" : "MISMATCH [") << c.name << "]"
              << (c.asserted ? " (asserted)" : " (record-only)") << "\n";
    if (!both_complete) {
        std::cerr << "  incomplete exchange: envoy=" << (c.envoy.exchange_complete ? "yes" : "no")
                  << " rut=" << (c.rut.exchange_complete ? "yes" : "no") << "\n";
    }
    if (!upstream_match) {
        std::cerr << "  upstream envoy: \"" << escape_wire_bytes(c.envoy.upstream_bytes) << "\"\n";
        std::cerr << "  upstream rut:   \"" << escape_wire_bytes(c.rut.upstream_bytes) << "\"\n";
    }
    if (!downstream_match) {
        std::cerr << "  downstream envoy: \"" << escape_wire_bytes(envoy_down) << "\"\n";
        std::cerr << "  downstream rut:   \"" << escape_wire_bytes(rut_down) << "\"\n";
    }
    return match;
}

int run_pair_milestone_s(const std::string& rut_binary,
                         const std::string& converter_binary,
                         const std::string& transcript_path) {
    const std::string missing = check_docker_prerequisites();
    if (!missing.empty()) return missing_prerequisite(missing);

    uint16_t listen_port1 = 0, upstream_port1 = 0, listen_port2 = 0, closed_port = 0;
    if (!allocate_distinct_ports({&listen_port1, &upstream_port1, &listen_port2, &closed_port})) {
        std::cerr << "FAIL: could not allocate loopback ports\n";
        return 1;
    }

    std::vector<PairCaseResult> comparisons;

    // ---- Run 1: live recording upstream, Envoy then RUT, same ports ----
    {
        const std::string dir = make_temp_dir("rut-envoy-pair");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            return 1;
        }
        const std::string bootstrap_path = dir + "/bootstrap.json";
        if (!write_file_mode(
                bootstrap_path, render_bootstrap(listen_port1, upstream_port1), 0644)) {
            std::cerr << "FAIL: could not write bootstrap.json\n";
            return 1;
        }
        const std::string out_rut_path = dir + "/out.rut";
        std::string convert_stderr;
        if (!run_converter_to_file(
                converter_binary, bootstrap_path, out_rut_path, &convert_stderr)) {
            std::cerr << "FAIL: rut-envoy-convert did not exit 0 with empty stderr on the "
                         "milestone-S bootstrap\n";
            if (!convert_stderr.empty()) std::cerr << "stderr: " << convert_stderr << "\n";
            return 1;
        }

        RecordingUpstream upstream;
        const auto cases = run1_cases();
        for (const auto& spec : cases) upstream.set_reply(spec.upstream_path, spec.upstream_reply);
        if (!upstream.start(upstream_port1)) {
            std::cerr << "FAIL: could not start recording upstream\n";
            return 1;
        }

        // Envoy first.
        EnvoyInstance envoy;
        envoy.name = make_container_name("pair-run1");
        envoy.log_path = dir + "/envoy.log";
        if (!envoy.launch(bootstrap_path, listen_port1)) {
            std::cerr << "FAIL: could not fork/exec docker run\n";
            upstream.stop();
            return 1;
        }
        std::string ready_error;
        if (!wait_ready(listen_port1, envoy, 15'000, &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy.log_path);
            upstream.stop();
            return 1;
        }
        auto envoy_results = run_case_batch(listen_port1, cases);
        envoy.stop();
        if (!fill_upstream_bytes(&envoy_results, cases, upstream)) {
            upstream.stop();
            return 1;
        }
        if (!wait_port_closed(listen_port1, 5000)) {
            std::cerr << "FAIL: listener port " << listen_port1
                      << " did not become free after stopping Envoy\n";
            upstream.stop();
            return 1;
        }
        upstream.clear_requests();

        // Then RUT, on the same ports, against the same (now-cleared)
        // recording upstream.
        RutInstance rut;
        rut.log_path = dir + "/rut.log";
        if (!rut.launch(rut_binary, out_rut_path)) {
            std::cerr << "FAIL: could not fork/exec rut\n";
            upstream.stop();
            return 1;
        }
        std::string rut_ready_error;
        if (!wait_ready(listen_port1, rut, 15'000, &rut_ready_error)) {
            std::cerr << "FAIL: " << rut_ready_error << "\n";
            dump_rut_log(rut.log_path);
            upstream.stop();
            return 1;
        }
        auto rut_results = run_case_batch(listen_port1, cases);
        const bool rut_stopped_cleanly = rut.stop();
        const bool rut_upstream_ok = fill_upstream_bytes(&rut_results, cases, upstream);
        upstream.stop();
        if (!rut_stopped_cleanly) {
            std::cerr << "FAIL: rut exited unexpectedly before teardown ("
                      << rut.unexpected_exit_description << ")\n";
            dump_rut_log(rut.log_path);
            return 1;
        }
        if (!rut_upstream_ok) return 1;

        for (const auto& spec : cases) {
            PairCaseResult c;
            c.name = spec.name;
            c.asserted = is_asserted_case(spec.name);
            if (const auto* e = find_case(envoy_results, spec.name)) c.envoy = *e;
            if (const auto* r = find_case(rut_results, spec.name)) c.rut = *r;
            comparisons.push_back(std::move(c));
        }
    }

    // ---- Run 2: connect_failure against a closed upstream port ----
    {
        const std::string dir = make_temp_dir("rut-envoy-pair2");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            return 1;
        }
        const std::string bootstrap_path = dir + "/bootstrap.json";
        if (!write_file_mode(bootstrap_path, render_bootstrap(listen_port2, closed_port), 0644)) {
            std::cerr << "FAIL: could not write bootstrap.json\n";
            return 1;
        }
        const std::string out_rut_path = dir + "/out.rut";
        std::string convert_stderr;
        if (!run_converter_to_file(
                converter_binary, bootstrap_path, out_rut_path, &convert_stderr)) {
            std::cerr << "FAIL: rut-envoy-convert did not exit 0 with empty stderr on the "
                         "closed-port bootstrap\n";
            if (!convert_stderr.empty()) std::cerr << "stderr: " << convert_stderr << "\n";
            return 1;
        }
        const CaseSpec spec = connect_failure_case();

        EnvoyInstance envoy;
        envoy.name = make_container_name("pair-run2");
        envoy.log_path = dir + "/envoy.log";
        if (!envoy.launch(bootstrap_path, listen_port2)) {
            std::cerr << "FAIL: could not fork/exec docker run\n";
            return 1;
        }
        std::string ready_error;
        if (!wait_ready(listen_port2, envoy, 15'000, &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy.log_path);
            return 1;
        }
        PairCaseResult c;
        c.name = "connect_failure";
        c.asserted = true;
        if (!run_client_case(listen_port2, spec, &c.envoy))
            std::cerr << "WARN: case connect_failure (envoy) exchange did not complete cleanly\n";
        c.envoy.name = "connect_failure";
        envoy.stop();
        if (!wait_port_closed(listen_port2, 5000)) {
            std::cerr << "FAIL: listener port " << listen_port2
                      << " did not become free after stopping Envoy\n";
            return 1;
        }

        RutInstance rut;
        rut.log_path = dir + "/rut.log";
        if (!rut.launch(rut_binary, out_rut_path)) {
            std::cerr << "FAIL: could not fork/exec rut\n";
            return 1;
        }
        std::string rut_ready_error;
        if (!wait_ready(listen_port2, rut, 15'000, &rut_ready_error)) {
            std::cerr << "FAIL: " << rut_ready_error << "\n";
            dump_rut_log(rut.log_path);
            return 1;
        }
        if (!run_client_case(listen_port2, spec, &c.rut))
            std::cerr << "WARN: case connect_failure (rut) exchange did not complete cleanly\n";
        c.rut.name = "connect_failure";
        if (!rut.stop()) {
            std::cerr << "FAIL: rut exited unexpectedly before teardown ("
                      << rut.unexpected_exit_description << ")\n";
            dump_rut_log(rut.log_path);
            return 1;
        }

        comparisons.push_back(std::move(c));
    }

    bool any_asserted_mismatch = false;
    for (const auto& c : comparisons) {
        if (!compare_pair_case(c) && c.asserted) any_asserted_mismatch = true;
    }

    if (!transcript_path.empty()) {
        if (!write_pair_transcript(transcript_path, comparisons)) {
            std::cerr << "FAIL: could not write pair transcript to " << transcript_path << "\n";
            return 1;
        }
        std::cerr << "wrote pair transcript to " << transcript_path << "\n";
    }

    return any_asserted_mismatch ? 1 : 0;
}

// ── --self-test ───────────────────────────────────────────────────────

bool self_test_escaping() {
    std::string sample = "before\r\n\"\\";
    sample.push_back('\x00');
    sample.push_back('\x7f');
    sample.push_back('\xff');
    sample += "AfterA1b2\r\n";
    const std::string wrapped = wrap_wire_literal(sample);
    std::string decoded;
    if (!decode_wire_literal(wrapped, &decoded)) {
        std::cerr << "FAIL [self-test escaping]: wrapped literal did not re-parse: " << wrapped
                  << "\n";
        return false;
    }
    if (decoded != sample) {
        std::cerr << "FAIL [self-test escaping]: round-trip mismatch (sizes " << decoded.size()
                  << " vs " << sample.size() << ")\n";
        return false;
    }
    // Empty buffer renders as a bare `""` and round-trips to empty.
    std::string empty_decoded;
    if (!decode_wire_literal(wrap_wire_literal(""), &empty_decoded) || !empty_decoded.empty()) {
        std::cerr << "FAIL [self-test escaping]: empty-buffer round trip failed\n";
        return false;
    }
    std::cerr << "PASS [self-test escaping]\n";
    return true;
}

bool self_test_recording_upstream() {
    // Round-6 review, "Keep allocated ports reserved until their consumers
    // bind": the upstream's port must come from allocate_bound_loopback_port()
    // (bound and listening from the moment it's allocated) rather than
    // probe-and-close, and RecordingUpstream must adopt that live fd instead
    // of binding a fresh socket of its own.
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test upstream]: could not allocate a loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;

    // While the first port is still held open (and not yet adopted into a
    // RecordingUpstream), a second allocation must come back with a
    // different port: proof that holding the listening socket open actually
    // reserves the port against a racing allocator, unlike a probe-bind that
    // has already closed by the time its caller gets around to using the
    // port number.
    uint16_t second_port = 0;
    if (!allocate_loopback_port(&second_port)) {
        std::cerr << "FAIL [self-test upstream]: could not allocate a second loopback port\n";
        close(bound.fd);
        return false;
    }
    if (second_port == port) {
        std::cerr << "FAIL [self-test upstream]: second allocation collided with the "
                     "still-live first port\n";
        close(bound.fd);
        return false;
    }

    RecordingUpstream server;
    server.set_reply("/x", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    server.set_reply("/head", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    if (!server.adopt(bound.fd)) {
        std::cerr << "FAIL [self-test upstream]: could not adopt the bound listening socket\n";
        close(bound.fd);
        return false;
    }

    bool ok = true;

    // Content-Length-framed GET, then a second request on the same
    // connection (keep-alive), then a Connection: close request.
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test upstream]: could not connect\n";
            server.stop();
            return false;
        }
        const std::string req1 = "GET /x HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd, req1)) ok = false;
        const ReadResult resp1 = read_http_message(fd, /*head_request=*/false, kClientTimeoutMs);
        if (!resp1.complete || resp1.bytes != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") {
            std::cerr << "FAIL [self-test upstream]: unexpected reply 1: " << resp1.bytes
                      << " (complete=" << resp1.complete << ")\n";
            ok = false;
        }
        const std::string req2 =
            "POST /x HTTP/1.1\r\nHost: t.example\r\nContent-Length: 3\r\n\r\nabc";
        if (!send_all(fd, req2)) ok = false;
        const ReadResult resp2 = read_http_message(fd, /*head_request=*/false, kClientTimeoutMs);
        if (!resp2.complete || resp2.bytes != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") {
            std::cerr << "FAIL [self-test upstream]: unexpected reply 2: " << resp2.bytes
                      << " (complete=" << resp2.complete << ")\n";
            ok = false;
        }
        const std::string req3 =
            "HEAD /head HTTP/1.1\r\nHost: t.example\r\nConnection: close\r\n\r\n";
        if (!send_all(fd, req3)) ok = false;
        const ReadResult resp3 = read_http_message(fd, /*head_request=*/true, kClientTimeoutMs);
        if (!resp3.complete || resp3.bytes != "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") {
            std::cerr << "FAIL [self-test upstream]: unexpected HEAD reply: " << resp3.bytes
                      << " (complete=" << resp3.complete << ")\n";
            ok = false;
        }
        // The server must have closed after Connection: close: further reads hit EOF.
        char probe;
        const ssize_t n = recv(fd, &probe, 1, 0);
        if (n != 0) {
            std::cerr << "FAIL [self-test upstream]: server did not close after "
                         "Connection: close\n";
            ok = false;
        }
        close(fd);
        const auto recorded = server.requests_for("/x");
        if (recorded.size() != 2 || recorded[0] != req1 || recorded[1] != req2) {
            std::cerr << "FAIL [self-test upstream]: recorded /x requests did not match "
                         "byte-for-byte\n";
            ok = false;
        }
        const auto recorded_head = server.requests_for("/head");
        if (recorded_head.size() != 1 || recorded_head[0] != req3) {
            std::cerr << "FAIL [self-test upstream]: recorded /head request did not match\n";
            ok = false;
        }
    }

    server.stop();
    if (ok) std::cerr << "PASS [self-test upstream]\n";
    return ok;
}

// Covers round-3 review thread P1 ("Reject partial exchanges before writing
// the oracle transcript"): read_http_message() must report an incomplete
// frame as incomplete rather than silently returning whatever partial bytes
// it captured, and write_transcript() must refuse to write anything (no
// output file at all) when any case is incomplete or the upstream was
// contacted more than once.
bool self_test_partial_exchange_rejection() {
    bool ok = true;

    // read_http_message(): a Content-Length body that never fully arrives
    // (the peer sends a short prefix and closes) must come back incomplete.
    //
    // Uses allocate_bound_loopback_port() (round-12 review, "Keep the
    // partial-exchange listener bound across allocation"): plain
    // allocate_loopback_port() closes its probe socket before this test's
    // own listen_fd gets a chance to bind, leaving a window where another
    // process on the host can grab the port first -- the same race
    // round-6's review fixed for the recording upstream. Adopting the
    // already-bound-and-listening fd here closes that window the same way.
    {
        BoundPort bound;
        if (!allocate_bound_loopback_port(&bound)) {
            std::cerr << "FAIL [self-test partial]: could not allocate a loopback port\n";
            return false;
        }
        const uint16_t port = bound.port;
        const int listen_fd = bound.fd;
        std::thread server([listen_fd] {
            const int fd = accept(listen_fd, nullptr, nullptr);
            if (fd < 0) return;
            // Advertises a 10-byte body but sends only 3 bytes, then closes:
            // a connection that dies mid-frame.
            send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
            close(fd);
        });
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test partial]: could not connect to fake server\n";
            ok = false;
        } else {
            const ReadResult read = read_http_message(fd, /*head_request=*/false, 500);
            if (read.complete) {
                std::cerr << "FAIL [self-test partial]: truncated Content-Length body was "
                             "reported complete\n";
                ok = false;
            }
            if (read.bytes.find("abc") == std::string::npos) {
                std::cerr << "FAIL [self-test partial]: partial bytes were not captured\n";
                ok = false;
            }
            close(fd);
        }
        // Unconditionally unblock the fake server's accept() before joining
        // (round-15 review, "Unblock the fake server before joining on
        // connect failure"): if connect_with_timeout() above failed (e.g.
        // transient descriptor exhaustion), nothing ever connected, so the
        // server thread is still parked in accept() and this join() would
        // otherwise hang until CTest's 60s timeout. shutdown() on a Linux
        // listening socket reliably makes a blocked accept() return an
        // error, so doing this before join() -- for both the success and
        // failure paths -- makes the fake listener joinable no matter what
        // happened above.
        shutdown(listen_fd, SHUT_RDWR);
        server.join();
        close(listen_fd);
    }

    // write_transcript(): must reject an incomplete exchange and a
    // duplicated upstream contact, in both cases without creating the
    // output file, and must accept a fully valid run.
    {
        TempDir dir("rut-envoy-selftest");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test partial]: could not create temp dir\n";
            return false;
        }
        const std::string out_path = dir.path() + "/transcript.inc";

        CaseResult incomplete;
        incomplete.name = "bad_incomplete";
        incomplete.client_bytes = "GET / HTTP/1.1\r\n\r\n";
        incomplete.exchange_complete = false;
        incomplete.upstream_contacted = true;
        incomplete.upstream_contact_count = 1;
        incomplete.upstream_bytes = "GET / HTTP/1.1\r\n\r\n";
        incomplete.downstream_bytes = "HTTP/1.1 200 O";
        if (write_transcript(out_path, {incomplete})) {
            std::cerr << "FAIL [self-test partial]: write_transcript accepted an incomplete "
                         "exchange\n";
            ok = false;
        }
        struct stat st{};
        if (stat(out_path.c_str(), &st) == 0) {
            std::cerr << "FAIL [self-test partial]: write_transcript left a file behind for a "
                         "rejected incomplete-exchange run\n";
            ok = false;
        }

        CaseResult duplicated;
        duplicated.name = "bad_duplicate";
        duplicated.client_bytes = "GET / HTTP/1.1\r\n\r\n";
        duplicated.exchange_complete = true;
        duplicated.upstream_contacted = true;
        duplicated.upstream_contact_count = 2;
        duplicated.upstream_bytes = "GET / HTTP/1.1\r\n\r\n";
        duplicated.downstream_bytes = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        if (write_transcript(out_path, {duplicated})) {
            std::cerr << "FAIL [self-test partial]: write_transcript accepted a duplicated "
                         "upstream contact\n";
            ok = false;
        }
        if (stat(out_path.c_str(), &st) == 0) {
            std::cerr << "FAIL [self-test partial]: write_transcript left a file behind for a "
                         "rejected duplicate-contact run\n";
            ok = false;
        }

        CaseResult good;
        good.name = "ok";
        good.client_bytes = "GET / HTTP/1.1\r\n\r\n";
        good.exchange_complete = true;
        good.upstream_contacted = true;
        good.upstream_contact_count = 1;
        good.upstream_bytes = "GET / HTTP/1.1\r\n\r\n";
        good.downstream_bytes = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        if (!write_transcript(out_path, {good})) {
            std::cerr << "FAIL [self-test partial]: write_transcript rejected a fully valid run\n";
            ok = false;
        }

        // Round-15 review, "Check transcript close errors before reporting
        // success": a write failure that only surfaces at the final,
        // implicit flush/close must not be reported as success. Forced
        // deterministically with RLIMIT_FSIZE=0 (SIGXFSZ ignored so the
        // failing write() returns EFBIG instead of killing the process):
        // open() itself still succeeds (RLIMIT_FSIZE only affects write()),
        // and this transcript is small enough to stay entirely inside
        // ofstream's internal buffer until close(), so nothing fails until
        // that single final flush -- exactly the case the old
        // `return static_cast<bool>(out)` (checked before the destructor's
        // implicit close) could miss.
        {
            const std::string over_limit_path = dir.path() + "/transcript_over_limit.inc";
            struct rlimit original_limit{};
            if (getrlimit(RLIMIT_FSIZE, &original_limit) != 0) {
                std::cerr << "FAIL [self-test partial]: could not read RLIMIT_FSIZE\n";
                ok = false;
            } else {
                void (*old_handler)(int) = signal(SIGXFSZ, SIG_IGN);
                struct rlimit tiny_limit{0, original_limit.rlim_max};
                if (setrlimit(RLIMIT_FSIZE, &tiny_limit) != 0) {
                    std::cerr << "FAIL [self-test partial]: could not set RLIMIT_FSIZE\n";
                    ok = false;
                } else {
                    if (write_transcript(over_limit_path, {good})) {
                        std::cerr << "FAIL [self-test partial]: write_transcript reported "
                                     "success despite the final flush exceeding RLIMIT_FSIZE\n";
                        ok = false;
                    }
                    setrlimit(RLIMIT_FSIZE, &original_limit);
                }
                signal(SIGXFSZ, old_handler);
            }
        }
    }

    if (ok) std::cerr << "PASS [self-test partial exchange rejection]\n";
    return ok;
}

// Covers round-15 review thread P2 ("Unblock the fake server before joining
// on connect failure" / "generally make the fake listener joinable without
// hanging"): directly exercises the shutdown()-before-join() pattern against
// a thread parked in accept() that nothing ever connects to -- the exact
// situation self_test_partial_exchange_rejection()'s connect-failure branch
// used to leave unresolved. The accept() thread is detached (not joined)
// so this self-test cannot itself hang forever if the pattern regresses;
// instead it polls a bounded deadline and reports a clear failure.
bool self_test_fake_listener_unblocks_on_shutdown() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test fake listener unblock]: could not allocate a loopback port\n";
        return false;
    }
    const int listen_fd = bound.fd;
    auto accept_returned = std::make_shared<std::atomic<bool>>(false);
    std::thread server([listen_fd, accept_returned] {
        accept(listen_fd, nullptr, nullptr);
        accept_returned->store(true);
    });
    server.detach();

    // Give the thread a moment to actually enter accept() before trying to
    // unblock it.
    struct timespec ts{0, 50'000'000};
    nanosleep(&ts, nullptr);
    shutdown(listen_fd, SHUT_RDWR);

    bool ok = true;
    const int64_t deadline = now_ms() + 2000;
    while (!accept_returned->load()) {
        if (now_ms() >= deadline) {
            std::cerr << "FAIL [self-test fake listener unblock]: accept() did not unblock "
                         "within 2s of shutdown()\n";
            ok = false;
            break;
        }
        struct timespec poll_ts{0, 10'000'000};
        nanosleep(&poll_ts, nullptr);
    }
    close(listen_fd);
    if (ok) std::cerr << "PASS [self-test fake listener unblock]\n";
    return ok;
}

// Covers round-3 review thread P2 ("Build the Docker argv before entering
// the fork child"): build_argv() must produce a correctly null-terminated
// argv that aliases its input, and the prebuild-then-fork pattern it enables
// (used by run_and_wait()/EnvoyInstance::launch()) must actually work
// end-to-end.
bool self_test_argv_builder() {
    bool ok = true;
    const std::vector<std::string> input = {"printf", "one", "two"};
    const std::vector<char*> argv = build_argv(input);
    if (argv.size() != input.size() + 1) {
        std::cerr << "FAIL [self-test argv builder]: expected " << (input.size() + 1)
                  << " entries, got " << argv.size() << "\n";
        ok = false;
    } else {
        if (argv.back() != nullptr) {
            std::cerr << "FAIL [self-test argv builder]: argv is not null-terminated\n";
            ok = false;
        }
        for (size_t i = 0; i < input.size(); i++) {
            if (argv[i] == nullptr || input[i] != argv[i]) {
                std::cerr << "FAIL [self-test argv builder]: argv[" << i
                          << "] does not alias the source string\n";
                ok = false;
            }
        }
    }
    // Exercise the whole prebuild-then-fork path end to end: a real
    // fork+exec using an argv built entirely before fork(), with only
    // async-signal-safe work in the child.
    if (run_and_wait({"true"}, 2000) != 0) {
        std::cerr << "FAIL [self-test argv builder]: run_and_wait({\"true\"}) did not exit 0\n";
        ok = false;
    }
    if (run_and_wait({"false"}, 2000) != 1) {
        std::cerr << "FAIL [self-test argv builder]: run_and_wait({\"false\"}) did not exit 1\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test argv builder]\n";
    return ok;
}

// Covers round-9 review thread P3 ("Return failure when no distinct port was
// found"): if every one of an output's 32 allocation attempts collides with
// an already-seen port, allocate_distinct_ports() must fail the whole call
// instead of silently leaving that output unassigned and still reporting
// success. Forces the exhaustion path deterministically via
// allocate_distinct_ports_with()'s injectable port source (a fixed port
// repeated forever), rather than trying to actually exhaust real ephemeral
// ports.
bool self_test_allocate_distinct_ports_exhaustion() {
    bool ok = true;

    // A source that always returns the same port can never produce a second
    // distinct value, so the second output's 32 attempts must all collide.
    {
        uint16_t out1 = 0, out2 = 0;
        const bool result = allocate_distinct_ports_with({&out1, &out2}, [](uint16_t* port) {
            *port = 4242;
            return true;
        });
        if (result) {
            std::cerr << "FAIL [self-test allocate distinct ports exhaustion]: expected failure "
                         "when every candidate collides, got success\n";
            ok = false;
        }
    }

    // A source that fails outright must also fail the call (pre-existing
    // behavior, checked here for completeness alongside the exhaustion
    // path).
    {
        uint16_t out1 = 0;
        const bool result = allocate_distinct_ports_with({&out1}, [](uint16_t*) { return false; });
        if (result) {
            std::cerr << "FAIL [self-test allocate distinct ports exhaustion]: expected failure "
                         "when the port source fails, got success\n";
            ok = false;
        }
    }

    // Sanity check: a source that always produces a fresh distinct port
    // still succeeds and assigns every output.
    {
        uint16_t out1 = 0, out2 = 0;
        uint16_t next = 100;
        const bool result = allocate_distinct_ports_with({&out1, &out2}, [&next](uint16_t* port) {
            *port = next++;
            return true;
        });
        if (!result || out1 != 100 || out2 != 101) {
            std::cerr << "FAIL [self-test allocate distinct ports exhaustion]: expected success "
                         "with distinct assigned ports 100/101, got result="
                      << result << " out1=" << out1 << " out2=" << out2 << "\n";
            ok = false;
        }
    }

    if (ok) std::cerr << "PASS [self-test allocate distinct ports exhaustion]\n";
    return ok;
}

// A minimal stand-in for a foreign listener, used only by
// self_test_wait_ready_ownership() below: it adopts an already-bound,
// already-listening socket and answers every connection made to it with a
// fixed canned reply, so the test can exercise probe_confirms_envoy_
// ownership()'s two outcomes (a matching reply vs. a non-matching one)
// without a real Envoy.
class FakeReplyListener {
public:
    bool adopt(int listen_fd, std::string reply) {
        if (listen_fd < 0) return false;
        listen_fd_ = listen_fd;
        reply_ = std::move(reply);
        stopping_.store(false);
        thread_ = std::thread([this] { run(); });
        return true;
    }

    void stop() {
        stopping_.store(true);
        if (listen_fd_ >= 0) {
            shutdown(listen_fd_, SHUT_RDWR);
            close(listen_fd_);
        }
        if (thread_.joinable()) thread_.join();
        listen_fd_ = -1;
    }

    ~FakeReplyListener() { stop(); }

private:
    void run() {
        while (!stopping_.load()) {
            const int fd = accept(listen_fd_, nullptr, nullptr);
            if (fd < 0) {
                if (stopping_.load()) return;
                continue;
            }
            // Best-effort drain of whatever the probe sent, so its send()
            // never blocks on a full socket buffer while nobody reads; the
            // canned reply below does not depend on the request bytes.
            char discard[1024];
            pollfd pfd{fd, POLLIN, 0};
            if (poll(&pfd, 1, 50) > 0) recv(fd, discard, sizeof(discard), MSG_DONTWAIT);
            send_all(fd, reply_);
            close(fd);
        }
    }

    int listen_fd_ = -1;
    std::string reply_;
    std::atomic<bool> stopping_{false};
    std::thread thread_;
};

// Covers round-7 review thread P2 ("Verify the opened port belongs to the
// launched Envoy") and round-8 review thread P2 ("Verify listener ownership
// instead of timing process liveness"): wait_ready() alone proves only that
// *some* process is accepting connections on the port, not that it is the
// Envoy this harness launched, and a fixed grace period on the tracked
// child's liveness cannot rule that out either -- a foreign listener whose
// owning process is not the tracked docker child at all stays alive
// indefinitely, so "child is still alive" is not evidence of ownership
// (this is exactly what the previous version of this self-test got wrong:
// it treated a still-foreign-held listener as confirmed ownership solely
// because its dummy child remained alive, without ever checking what that
// listener actually answered). wait_ready_and_confirm_ownership() must
// instead settle it with a protocol-level probe. This test simulates the
// race directly (no docker needed): FakeReplyListener stands in for a
// foreign process's listener (answering either like Envoy or not), and a
// forked child stands in for the docker run process.
bool self_test_wait_ready_ownership() {
    bool ok = true;

    // Case 1 (negative): the "docker child" dies shortly after the foreign
    // listener is already open (which never answers anything), so ownership
    // must NOT be confirmed -- caught by the cheap liveness recheck before
    // any probe is even attempted.
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr
                << "FAIL [self-test wait_ready ownership]: could not allocate a loopback port\n";
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test wait_ready ownership]: fork failed\n";
            close(foreign.fd);
            return false;
        }
        if (child == 0) {
            struct timespec ts{0, 150'000'000};
            nanosleep(&ts, nullptr);
            _exit(1);
        }
        EnvoyInstance envoy;
        envoy.pid = child;
        std::string error;
        const bool confirmed =
            wait_ready_and_confirm_ownership(foreign.port, envoy, 2000, 400, &error);
        if (confirmed) {
            std::cerr << "FAIL [self-test wait_ready ownership]: confirmed ownership of a port "
                         "a foreign listener holds while the tracked child exited\n";
            ok = false;
        }
        if (error.empty()) {
            std::cerr << "FAIL [self-test wait_ready ownership]: expected a non-empty error on "
                         "case 1 (child exits)\n";
            ok = false;
        }
        if (envoy.pid != -1) {
            std::cerr << "FAIL [self-test wait_ready ownership]: envoy.pid was not cleared after "
                         "detecting exit\n";
            ok = false;
        }
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        close(foreign.fd);
    }

    // Case 2 (negative): the tracked child stays alive for the entire probe
    // window, but the listener it "owns" answers with a non-Envoy response
    // (no "server: envoy" header, wrong status). Ownership must NOT be
    // confirmed, and -- unlike case 1 -- envoy.pid must still be set,
    // proving the rejection came from the protocol probe rather than from
    // the child having exited.
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr
                << "FAIL [self-test wait_ready ownership]: could not allocate a loopback port\n";
            return false;
        }
        FakeReplyListener listener;
        if (!listener.adopt(foreign.fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")) {
            std::cerr << "FAIL [self-test wait_ready ownership]: could not adopt the foreign "
                         "listener socket\n";
            close(foreign.fd);
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test wait_ready ownership]: fork failed\n";
            listener.stop();
            return false;
        }
        if (child == 0) {
            struct timespec ts{5, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        }
        EnvoyInstance envoy;
        envoy.pid = child;
        std::string error;
        const bool confirmed =
            wait_ready_and_confirm_ownership(foreign.port, envoy, 1200, 100, &error);
        if (confirmed) {
            std::cerr << "FAIL [self-test wait_ready ownership]: confirmed ownership of a "
                         "foreign listener that answered a non-Envoy response\n";
            ok = false;
        }
        if (error.empty()) {
            std::cerr << "FAIL [self-test wait_ready ownership]: expected a non-empty error on "
                         "case 2 (non-Envoy response)\n";
            ok = false;
        }
        if (envoy.pid != child) {
            std::cerr << "FAIL [self-test wait_ready ownership]: case 2 cleared envoy.pid, but "
                         "the tracked child never exited -- rejection must come from the probe, "
                         "not from process liveness\n";
            ok = false;
        }
        kill(child, SIGKILL);
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        // Reaped explicitly above; clear envoy.pid so ~EnvoyInstance()'s
        // stop() below doesn't wait out its 5s deadline on an already-reaped
        // (or worse, recycled) pid (round-9 review, "Treat ECHILD as an
        // already-stopped child").
        envoy.pid = -1;
        listener.stop();
    }

    // Case 3 (negative -- round-9 review, "Use a launch-specific listener
    // ownership challenge"): the tracked child stays alive, and a *foreign*
    // listener answers exactly like the milestone-S bootstrap's real
    // router-not-found local reply for an asterisk-form request does (404,
    // "server: envoy", empty body -- see tests/fixtures/
    // envoy_oracle_milestone_s.inc's own `options_star` case). Before the
    // round-9 fix this alone was accepted as confirmed ownership; now the
    // protocol reply matching is not enough, because envoy.log_path (this
    // process's own captured log, checked by envoy_log_confirms_listener())
    // never gets Envoy's `starting main dispatch loop` line -- nothing ever
    // wrote to that path. Ownership must NOT be confirmed, and envoy.pid
    // must still be set (rejection comes from the log check outliving the
    // protocol probe, not from the child having exited).
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr
                << "FAIL [self-test wait_ready ownership]: could not allocate a loopback port\n";
            return false;
        }
        const std::string envoy_like_reply =
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nserver: envoy\r\n\r\n";
        FakeReplyListener listener;
        if (!listener.adopt(foreign.fd, envoy_like_reply)) {
            std::cerr << "FAIL [self-test wait_ready ownership]: could not adopt the foreign "
                         "listener socket\n";
            close(foreign.fd);
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test wait_ready ownership]: fork failed\n";
            listener.stop();
            return false;
        }
        if (child == 0) {
            struct timespec ts{5, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        }
        EnvoyInstance envoy;
        envoy.pid = child;
        envoy.log_path = "/nonexistent/rut-envoy-selftest-case3.log";
        std::string error;
        const bool confirmed =
            wait_ready_and_confirm_ownership(foreign.port, envoy, 1200, 100, &error);
        if (confirmed) {
            std::cerr << "FAIL [self-test wait_ready ownership]: confirmed ownership of a "
                         "foreign listener that merely answered like Envoy, with no "
                         "launch-specific log evidence\n";
            ok = false;
        }
        if (error.empty()) {
            std::cerr << "FAIL [self-test wait_ready ownership]: expected a non-empty error on "
                         "case 3 (matching reply, no log evidence)\n";
            ok = false;
        }
        if (envoy.pid != child) {
            std::cerr << "FAIL [self-test wait_ready ownership]: case 3 cleared envoy.pid, but "
                         "the tracked child never exited -- rejection must come from the log "
                         "check, not from process liveness\n";
            ok = false;
        }
        kill(child, SIGKILL);
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        // See case 2's comment: clear envoy.pid after an explicit reap.
        envoy.pid = -1;
        listener.stop();
    }

    // Case 4 (positive): same matching protocol reply as case 3, but this
    // time envoy.log_path names a real file containing Envoy's post-bind
    // startup line (as the launched child's own captured stdout+stderr
    // would after a real bind succeeds). Ownership must be confirmed.
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr
                << "FAIL [self-test wait_ready ownership]: could not allocate a loopback port\n";
            return false;
        }
        const std::string envoy_like_reply =
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nserver: envoy\r\n\r\n";
        FakeReplyListener listener;
        if (!listener.adopt(foreign.fd, envoy_like_reply)) {
            std::cerr << "FAIL [self-test wait_ready ownership]: could not adopt the foreign "
                         "listener socket\n";
            close(foreign.fd);
            return false;
        }
        TempDir dir("rut-envoy-selftest-case4");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test wait_ready ownership]: could not create temp dir for "
                         "case 4's fake log\n";
            listener.stop();
            return false;
        }
        const std::string log_path = dir.path() + "/envoy.log";
        if (!write_file_mode(log_path,
                             "[info] initializing epoch 0\n[info] starting main dispatch loop\n",
                             0644)) {
            std::cerr << "FAIL [self-test wait_ready ownership]: could not write case 4's fake "
                         "log\n";
            listener.stop();
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test wait_ready ownership]: fork failed\n";
            listener.stop();
            return false;
        }
        if (child == 0) {
            struct timespec ts{5, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        }
        EnvoyInstance envoy;
        envoy.pid = child;
        envoy.log_path = log_path;
        std::string error;
        const bool confirmed =
            wait_ready_and_confirm_ownership(foreign.port, envoy, 2000, 200, &error);
        if (!confirmed) {
            std::cerr << "FAIL [self-test wait_ready ownership]: did not confirm ownership for a "
                         "listener answering like Envoy with launch-specific log evidence "
                         "present: "
                      << error << "\n";
            ok = false;
        }
        kill(child, SIGKILL);
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        // See case 2's comment: clear envoy.pid after an explicit reap.
        envoy.pid = -1;
        listener.stop();
    }

    if (ok) std::cerr << "PASS [self-test wait_ready ownership]\n";
    return ok;
}

// Covers round-9 review thread P2 ("Use a launch-specific listener
// ownership challenge"): envoy_log_confirms_listener() is the small pure
// function the log-based ownership check reduces to, exercised directly
// here with three literal strings so its logic is verified independent of
// any process/log-file plumbing.
bool self_test_envoy_log_confirms_listener() {
    bool ok = true;

    if (!envoy_log_confirms_listener("[info] starting main dispatch loop\n")) {
        std::cerr << "FAIL [self-test envoy log confirms listener]: startup line present should "
                     "confirm\n";
        ok = false;
    }

    if (envoy_log_confirms_listener("[critical] Address already in use: bind: [::]:10000\n")) {
        std::cerr << "FAIL [self-test envoy log confirms listener]: address-in-use present "
                     "should never confirm\n";
        ok = false;
    }

    if (envoy_log_confirms_listener("[info] loading 1 listener(s)\n")) {
        std::cerr << "FAIL [self-test envoy log confirms listener]: neither line present should "
                     "never confirm\n";
        ok = false;
    }

    if (ok) std::cerr << "PASS [self-test envoy log confirms listener]\n";
    return ok;
}

// Covers round-15 review thread P2 ("Remove temporary harness directories
// after each run"): TempDir must remove its directory (and everything
// written inside it) once it goes out of scope, but must instead preserve it
// when RUT_ENVOY_KEEP_TMP=1 is set, for diagnostics.
bool self_test_temp_dir_cleanup() {
    bool ok = true;

    // Default: removed on scope exit.
    std::string removed_path;
    {
        TempDir dir("rut-envoy-selftest-cleanup");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test temp dir cleanup]: could not create temp dir\n";
            return false;
        }
        removed_path = dir.path();
        if (!write_file_mode(removed_path + "/marker", "x", 0644)) {
            std::cerr << "FAIL [self-test temp dir cleanup]: could not write inside temp dir\n";
            ok = false;
        }
    }
    struct stat st{};
    if (stat(removed_path.c_str(), &st) == 0) {
        std::cerr << "FAIL [self-test temp dir cleanup]: " << removed_path
                  << " still exists after its TempDir went out of scope\n";
        ok = false;
    }

    // RUT_ENVOY_KEEP_TMP=1: preserved on scope exit.
    std::string kept_path;
    setenv("RUT_ENVOY_KEEP_TMP", "1", 1);
    {
        TempDir dir("rut-envoy-selftest-keep");
        if (dir.empty()) {
            std::cerr
                << "FAIL [self-test temp dir cleanup]: could not create temp dir (keep case)\n";
            unsetenv("RUT_ENVOY_KEEP_TMP");
            return false;
        }
        kept_path = dir.path();
    }
    unsetenv("RUT_ENVOY_KEEP_TMP");
    if (stat(kept_path.c_str(), &st) != 0) {
        std::cerr << "FAIL [self-test temp dir cleanup]: RUT_ENVOY_KEEP_TMP=1 did not preserve "
                  << kept_path << "\n";
        ok = false;
    } else {
        remove_dir_recursive(kept_path);  // clean up manually; this run kept it deliberately
    }

    if (ok) std::cerr << "PASS [self-test temp dir cleanup]\n";
    return ok;
}

// Covers round-15 review thread P2 ("Skip Docker teardown for instances
// that were never launched"): constructing and destroying an EnvoyInstance
// that never called launch() -- exactly what every dummy-child self-test
// case above does -- must never invoke `docker rm -f`, checked via
// g_docker_rm_invocations rather than a stubbed docker binary. Also checks
// that an unlaunched instance wrapping a real (dummy) pid still reaps it,
// so the docker-skip guard doesn't accidentally skip process cleanup too.
bool self_test_envoy_instance_skips_docker_when_unlaunched() {
    const int before = g_docker_rm_invocations;
    {
        EnvoyInstance envoy;  // name/log_path left empty; launch() never called
    }
    if (g_docker_rm_invocations != before) {
        std::cerr << "FAIL [self-test envoy instance skips docker]: destroying a never-launched "
                     "EnvoyInstance with no pid invoked docker rm -f\n";
        return false;
    }

    const pid_t child = fork();
    if (child < 0) {
        std::cerr << "FAIL [self-test envoy instance skips docker]: fork failed\n";
        return false;
    }
    if (child == 0) {
        _exit(0);
    }
    {
        EnvoyInstance envoy;
        envoy.pid = child;
    }
    if (g_docker_rm_invocations != before) {
        std::cerr << "FAIL [self-test envoy instance skips docker]: destroying a never-launched "
                     "EnvoyInstance wrapping a dummy pid invoked docker rm -f\n";
        return false;
    }
    // The dummy child must still have been reaped despite skipping docker
    // teardown: waitpid() for an already-reaped child returns -1/ECHILD.
    int status = 0;
    const pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited != -1 || errno != ECHILD) {
        std::cerr << "FAIL [self-test envoy instance skips docker]: dummy child was not reaped "
                     "by EnvoyInstance::stop()\n";
        return false;
    }

    std::cerr << "PASS [self-test envoy instance skips docker]\n";
    return true;
}

// Covers round-7 review thread P2 ("Keep the connect-failure port
// reserved"): allocate_reserved_closed_port() must hold the port so no other
// bind can claim it, while still producing "connection refused" semantics
// (RST/ECONNREFUSED) for a connect() attempt, matching the oracle's recorded
// connect_failure body.
bool self_test_reserved_closed_port() {
    bool ok = true;
    BoundPort closed;
    if (!allocate_reserved_closed_port(&closed)) {
        std::cerr << "FAIL [self-test reserved closed port]: allocation failed\n";
        return false;
    }

    // The port must stay held: a second socket cannot bind to it while the
    // reservation is live.
    {
        const int probe = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(closed.port);
        if (probe >= 0) {
            const int one = 1;
            setsockopt(probe, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            if (bind(probe, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
                std::cerr << "FAIL [self-test reserved closed port]: a second socket was able to "
                             "bind the reserved port\n";
                ok = false;
            }
            close(probe);
        }
    }

    // A connect() attempt must be refused immediately (RST/ECONNREFUSED),
    // never accepted, since nothing ever calls listen() on this socket.
    {
        const int fd = connect_with_timeout(closed.port, 1000);
        if (fd >= 0) {
            std::cerr << "FAIL [self-test reserved closed port]: connect() unexpectedly "
                         "succeeded against a bound-but-not-listening port\n";
            close(fd);
            ok = false;
        }
    }

    close(closed.fd);
    if (ok) std::cerr << "PASS [self-test reserved closed port]\n";
    return ok;
}

// ── Codex-review regression self-tests (no docker, no `rut` binary) ─────

// Exercises the exact `fill_upstream_bytes` path a retried/replayed
// upstream request would hit: two requests recorded for one case's path
// must fail the harness, not silently compare only the first one.
bool self_test_duplicate_upstream_rejected() {
    uint16_t port = 0;
    if (!allocate_loopback_port(&port)) {
        std::cerr << "FAIL [self-test duplicate-upstream]: could not allocate a loopback port\n";
        return false;
    }
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/dup", reply);
    if (!upstream.start(port)) {
        std::cerr << "FAIL [self-test duplicate-upstream]: could not start upstream\n";
        return false;
    }
    bool ok = true;
    {
        // Two requests to the same path on one keep-alive connection stand
        // in for a retried or replayed upstream request.
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test duplicate-upstream]: could not connect\n";
            upstream.stop();
            return false;
        }
        const std::string req = "GET /dup HTTP/1.1\r\nHost: t.example\r\n\r\n";
        for (int i = 0; i < 2; i++) {
            if (!send_all(fd, req) || read_http_message(fd, false, kClientTimeoutMs).bytes != reply)
                ok = false;
        }
        close(fd);
    }
    const std::vector<CaseSpec> cases = {{"dup_case", "", false, "/dup", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "dup_case";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (fill_ok) {
        std::cerr << "FAIL [self-test duplicate-upstream]: fill_upstream_bytes accepted two "
                     "recorded requests for one case\n";
        ok = false;
    }
    if (results[0].upstream_contacted) {
        std::cerr << "FAIL [self-test duplicate-upstream]: upstream_contacted was set true "
                     "despite the duplicate\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test duplicate-upstream]\n";
    return ok;
}

// Exercises the exact `RutInstance::stop()` path a crash before intentional
// teardown would hit: `/bin/true` stands in for a `rut` binary that exits on
// its own (no docker or real `rut` binary needed), and stop() must report
// that as an unexpected exit rather than a clean teardown.
bool self_test_rut_early_exit_detected() {
    RutInstance rut;
    rut.log_path = "/dev/null";
    if (!rut.launch("/bin/true", "unused.rut")) {
        std::cerr << "FAIL [self-test rut early exit]: could not fork/exec /bin/true\n";
        return false;
    }
    // Give the child time to exit on its own before stop() is asked to tear
    // it down.
    struct timespec ts{0, 200'000'000};
    nanosleep(&ts, nullptr);
    const bool stopped_cleanly = rut.stop();
    bool ok = true;
    if (stopped_cleanly) {
        std::cerr << "FAIL [self-test rut early exit]: stop() reported a clean teardown for a "
                     "process that had already exited on its own\n";
        ok = false;
    }
    if (!rut.exited_unexpectedly) {
        std::cerr << "FAIL [self-test rut early exit]: exited_unexpectedly was not set\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test rut early exit]\n";
    return ok;
}

// Exercises the exact `compare_pair_case` path two identically-failed
// exchanges would hit (e.g. a connection refused on both sides before a
// single byte crossed the wire, leaving two equal empty buffers): it must
// report a mismatch, not a match.
bool self_test_pair_both_failed_rejected() {
    PairCaseResult c;
    c.name = "both_failed";
    c.asserted = true;
    c.envoy.exchange_complete = false;
    c.rut.exchange_complete = false;
    const bool match = compare_pair_case(c);
    if (match) {
        std::cerr << "FAIL [self-test pair both-failed]: compare_pair_case matched two "
                     "incomplete exchanges\n";
        return false;
    }
    std::cerr << "PASS [self-test pair both-failed]\n";
    return true;
}

// Exercises the exact `read_http_message` HEAD path against a deliberately
// spec-violating peer that sends a body five milliseconds after the header
// terminator, in a separate TCP segment/`send()`: the bounded grace window
// must observe it rather than the exchange completing (and comparing equal
// to a body-less reference) before the body arrives.
bool self_test_head_body_detected() {
    uint16_t port = 0;
    if (!allocate_loopback_port(&port)) {
        std::cerr << "FAIL [self-test head body]: could not allocate a loopback port\n";
        return false;
    }
    const int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "FAIL [self-test head body]: could not create listening socket\n";
        return false;
    }
    const int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(listen_fd, 1) != 0) {
        std::cerr << "FAIL [self-test head body]: could not bind/listen\n";
        close(listen_fd);
        return false;
    }
    std::thread server([listen_fd] {
        const int conn = accept(listen_fd, nullptr, nullptr);
        if (conn < 0) return;
        char buf[512];
        recv(conn, buf, sizeof(buf), 0);  // discard the request
        const std::string headers = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        send(conn, headers.data(), headers.size(), 0);
        struct timespec delay{0, 20'000'000};
        nanosleep(&delay, nullptr);
        const std::string body = "oops!";
        send(conn, body.data(), body.size(), 0);
        close(conn);
    });
    bool ok = true;
    const int fd = connect_with_timeout(port, kClientTimeoutMs);
    if (fd < 0) {
        std::cerr << "FAIL [self-test head body]: could not connect\n";
        ok = false;
    } else {
        const std::string req = "HEAD /x HTTP/1.1\r\nHost: t.example\r\n\r\n";
        send_all(fd, req);
        const ReadResult resp = read_http_message(fd, /*head_request=*/true, kClientTimeoutMs);
        if (!ends_with(resp.bytes, "oops!")) {
            std::cerr << "FAIL [self-test head body]: the grace window did not observe the "
                         "unexpected HEAD body bytes\n";
            ok = false;
        }
        close(fd);
    }
    server.join();
    close(listen_fd);
    if (ok) std::cerr << "PASS [self-test head body]\n";
    return ok;
}

// ── --self-test RUT pass (PR 6) ─────────────────────────────────────────
//
// No docker needed: converts the milestone-S bootstrap, starts the real
// `rut` binary against the in-process recording upstream on ephemeral
// loopback ports, runs the asserted cases, and compares them against
// the committed Envoy oracle fixture (tests/fixtures/envoy_oracle_milestone_s.inc,
// date-normalized). This is the strongest local evidence for the pair logic
// above that this environment (no docker) can produce.

struct OracleCase {
    const char* name;
    const char* upstream;
    size_t upstream_len;
    const char* downstream;
    size_t downstream_len;
};

#define RUT_ORACLE_CASE(n)                              \
    OracleCase{#n,                                      \
               kEnvoyOracle_##n##_upstream,             \
               sizeof(kEnvoyOracle_##n##_upstream) - 1, \
               kEnvoyOracle_##n##_downstream,           \
               sizeof(kEnvoyOracle_##n##_downstream) - 1}

// One entry per name in `kAssertedCaseNames`, same order.
const OracleCase kAssertedOracleCases[] = {
    RUT_ORACLE_CASE(get_smoke),
    RUT_ORACLE_CASE(get_upstream_date_server),
    RUT_ORACLE_CASE(get_client_close),
    RUT_ORACLE_CASE(head_smoke),
    RUT_ORACLE_CASE(post_fixed),
    RUT_ORACLE_CASE(connect_failure),
    RUT_ORACLE_CASE(get_hop_by_hop),
    RUT_ORACLE_CASE(trace),
    RUT_ORACLE_CASE(options_star),
};

#undef RUT_ORACLE_CASE

// Compares one RUT-side result against its recorded Envoy oracle bytes
// (date-normalized on the downstream side only), printing PASS/FAIL with
// escaped literals on mismatch. Returns false only on an actual mismatch
// (a missing result is reported as a mismatch by the caller before this is
// reached).
bool compare_case_against_oracle(const CaseResult& result, const OracleCase& oracle) {
    const std::string oracle_upstream(oracle.upstream, oracle.upstream_len);
    const std::string oracle_downstream(oracle.downstream, oracle.downstream_len);
    const std::string preserved_date = std::string(oracle.name) == "get_upstream_date_server"
                                           ? "Mon, 01 Jan 2024 00:00:00 GMT"
                                           : std::string();
    const std::string rut_down =
        normalize_date_for_compare(result.downstream_bytes, preserved_date);
    const std::string oracle_down = normalize_date_for_compare(oracle_downstream, preserved_date);
    const bool upstream_match = result.upstream_bytes == oracle_upstream;
    const bool downstream_match = rut_down == oracle_down;
    const bool match = result.exchange_complete && upstream_match && downstream_match;
    std::cerr << (match ? "PASS [self-test rut vs oracle: " : "FAIL [self-test rut vs oracle: ")
              << oracle.name << "]\n";
    if (!result.exchange_complete) {
        std::cerr << "  rut exchange did not complete\n";
    }
    if (!upstream_match) {
        std::cerr << "  upstream oracle: \"" << escape_wire_bytes(oracle_upstream) << "\"\n";
        std::cerr << "  upstream rut:    \"" << escape_wire_bytes(result.upstream_bytes) << "\"\n";
    }
    if (!downstream_match) {
        std::cerr << "  downstream oracle: \"" << escape_wire_bytes(oracle_down) << "\"\n";
        std::cerr << "  downstream rut:    \"" << escape_wire_bytes(rut_down) << "\"\n";
    }
    return match;
}

bool run_self_test_rut_pass(const std::string& rut_binary, const std::string& converter_binary) {
    bool ok = true;
    std::vector<CaseResult> results;  // indices align with kAssertedOracleCases

    // ---- Live recording upstream: every asserted case but connect_failure ----
    {
        const std::string dir = make_temp_dir("rut-envoy-selftest");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test rut]: could not create temp directory\n";
            return false;
        }
        uint16_t listen_port = 0, upstream_port = 0;
        if (!allocate_distinct_ports({&listen_port, &upstream_port})) {
            std::cerr << "FAIL [self-test rut]: could not allocate loopback ports\n";
            return false;
        }
        const std::string bootstrap_path = dir + "/bootstrap.json";
        if (!write_file_mode(bootstrap_path, render_bootstrap(listen_port, upstream_port), 0644)) {
            std::cerr << "FAIL [self-test rut]: could not write bootstrap.json\n";
            return false;
        }
        const std::string out_rut_path = dir + "/out.rut";
        std::string convert_stderr;
        if (!run_converter_to_file(
                converter_binary, bootstrap_path, out_rut_path, &convert_stderr)) {
            std::cerr << "FAIL [self-test rut]: rut-envoy-convert did not exit 0 with empty "
                         "stderr\n";
            if (!convert_stderr.empty()) std::cerr << "stderr: " << convert_stderr << "\n";
            return false;
        }

        RecordingUpstream upstream;
        const auto all_cases = run1_cases();
        for (const auto& spec : all_cases)
            upstream.set_reply(spec.upstream_path, spec.upstream_reply);
        if (!upstream.start(upstream_port)) {
            std::cerr << "FAIL [self-test rut]: could not start recording upstream\n";
            return false;
        }

        RutInstance rut;
        rut.log_path = dir + "/rut.log";
        if (!rut.launch(rut_binary, out_rut_path)) {
            std::cerr << "FAIL [self-test rut]: could not fork/exec rut\n";
            upstream.stop();
            return false;
        }
        std::string ready_error;
        if (!wait_ready(listen_port, rut, 15'000, &ready_error)) {
            std::cerr << "FAIL [self-test rut]: " << ready_error << "\n";
            dump_rut_log(rut.log_path);
            upstream.stop();
            return false;
        }
        std::vector<CaseSpec> live_asserted;
        for (const auto& spec : all_cases)
            if (is_asserted_case(spec.name)) live_asserted.push_back(spec);
        auto live_results = run_case_batch(listen_port, live_asserted);
        const bool rut_stopped_cleanly = rut.stop();
        const bool rut_upstream_ok = fill_upstream_bytes(&live_results, live_asserted, upstream);
        upstream.stop();
        if (!rut_stopped_cleanly) {
            std::cerr << "FAIL [self-test rut]: rut exited unexpectedly before teardown ("
                      << rut.unexpected_exit_description << ")\n";
            dump_rut_log(rut.log_path);
            return false;
        }
        if (!rut_upstream_ok) return false;
        for (auto& r : live_results) results.push_back(std::move(r));
    }

    // ---- connect_failure: closed upstream port ----
    {
        const std::string dir = make_temp_dir("rut-envoy-selftest2");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test rut]: could not create temp directory\n";
            return false;
        }
        uint16_t listen_port = 0, closed_port = 0;
        if (!allocate_distinct_ports({&listen_port, &closed_port})) {
            std::cerr << "FAIL [self-test rut]: could not allocate loopback ports\n";
            return false;
        }
        const std::string bootstrap_path = dir + "/bootstrap.json";
        if (!write_file_mode(bootstrap_path, render_bootstrap(listen_port, closed_port), 0644)) {
            std::cerr << "FAIL [self-test rut]: could not write bootstrap.json\n";
            return false;
        }
        const std::string out_rut_path = dir + "/out.rut";
        std::string convert_stderr;
        if (!run_converter_to_file(
                converter_binary, bootstrap_path, out_rut_path, &convert_stderr)) {
            std::cerr << "FAIL [self-test rut]: rut-envoy-convert did not exit 0 with empty "
                         "stderr (closed-port bootstrap)\n";
            if (!convert_stderr.empty()) std::cerr << "stderr: " << convert_stderr << "\n";
            return false;
        }
        RutInstance rut;
        rut.log_path = dir + "/rut.log";
        if (!rut.launch(rut_binary, out_rut_path)) {
            std::cerr << "FAIL [self-test rut]: could not fork/exec rut\n";
            return false;
        }
        std::string ready_error;
        if (!wait_ready(listen_port, rut, 15'000, &ready_error)) {
            std::cerr << "FAIL [self-test rut]: " << ready_error << "\n";
            dump_rut_log(rut.log_path);
            return false;
        }
        CaseResult r;
        if (!run_client_case(listen_port, connect_failure_case(), &r))
            std::cerr << "WARN: case connect_failure exchange did not complete cleanly\n";
        r.name = "connect_failure";
        if (!rut.stop()) {
            std::cerr << "FAIL [self-test rut]: rut exited unexpectedly before teardown ("
                      << rut.unexpected_exit_description << ")\n";
            dump_rut_log(rut.log_path);
            return false;
        }
        results.push_back(std::move(r));
    }

    for (const auto& oracle : kAssertedOracleCases) {
        const CaseResult* result = find_case(results, oracle.name);
        if (result == nullptr) {
            std::cerr << "FAIL [self-test rut vs oracle: " << oracle.name << "]: case missing\n";
            ok = false;
            continue;
        }
        if (!compare_case_against_oracle(*result, oracle)) ok = false;
    }
    if (ok) std::cerr << "PASS [self-test rut vs oracle]\n";
    return ok;
}

int run_self_test(const std::string& rut_binary, const std::string& converter_binary) {
    bool ok = true;
    ok &= self_test_escaping();
    ok &= self_test_recording_upstream();
    ok &= self_test_partial_exchange_rejection();
    ok &= self_test_fake_listener_unblocks_on_shutdown();
    ok &= self_test_argv_builder();
    ok &= self_test_allocate_distinct_ports_exhaustion();
    ok &= self_test_envoy_log_confirms_listener();
    ok &= self_test_wait_ready_ownership();
    ok &= self_test_temp_dir_cleanup();
    ok &= self_test_envoy_instance_skips_docker_when_unlaunched();
    ok &= self_test_reserved_closed_port();
    ok &= self_test_duplicate_upstream_rejected();
    ok &= self_test_rut_early_exit_detected();
    ok &= self_test_pair_both_failed_rejected();
    ok &= self_test_head_body_detected();
    if (!rut_binary.empty() && !converter_binary.empty()) {
        ok &= run_self_test_rut_pass(rut_binary, converter_binary);
    } else {
        std::cerr << "NOTE: --self-test RUT pass skipped (pass [rut-binary] "
                     "[rut-envoy-convert-binary] to run it)\n";
    }
    return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc >= 2 && std::string(argv[1]) == "--self-test") {
        const std::string rut_binary = argc >= 3 ? argv[2] : "";
        const std::string converter_binary = argc >= 4 ? argv[3] : "";
        return run_self_test(rut_binary, converter_binary);
    }
    if (argc >= 3 && std::string(argv[1]) == "--oracle-milestone-s")
        return run_oracle_milestone_s(argv[2]);
    if (argc >= 4 && std::string(argv[1]) == "--pair-milestone-s") {
        const std::string transcript_path = argc >= 5 ? argv[4] : "";
        return run_pair_milestone_s(argv[2], argv[3], transcript_path);
    }
    std::cerr << "usage: " << argv[0]
              << " --self-test [rut-binary] [rut-envoy-convert-binary] | "
                 "--oracle-milestone-s <output-path> | "
                 "--pair-milestone-s <rut-binary> <rut-envoy-convert-binary> [<output-path>]\n";
    return 2;
}
