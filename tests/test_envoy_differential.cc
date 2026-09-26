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
#include <utility>
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
// Bounded grace window used to catch bytes a peer sends after this harness
// considers a response's own framing already complete: a HEAD body sent in
// a later TCP segment (RFC 9110 §9.3.2 forbids one), or -- round-6 review,
// "Check persistent responses for trailing wire bytes" -- erroneous bytes
// sent right after a Content-Length-framed body on a persistent (non-close)
// response, which a caller relying on that framing to demarcate the
// response would otherwise never see. Short relative to kClientTimeoutMs:
// it only needs to observe bytes the peer was about to send anyway, not to
// wait out a legitimately silent peer.
constexpr int kTrailingBytesGraceMs = 200;

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
    // Why `complete` is false, when the reader can say something more
    // specific than "partial read/timeout" (round-7 review, "Reject EOF on
    // responses advertised as persistent"): a persistence mismatch is
    // reported here so callers print it distinctly instead of folding it
    // into the generic partial-exchange message. Empty otherwise.
    std::string reason;
};

// The `ReadResult::reason` for a peer that closed a connection whose
// response did not advertise `Connection: close`.
constexpr char kPersistenceMismatchReason[] =
    "persistence mismatch: peer closed the connection after a response that did not "
    "advertise Connection: close";

// Reads one complete HTTP/1.x message from `fd`: headers up to the blank
// line, then a body framed by Content-Length (skipped entirely when
// `head_request` is true, per RFC 9110 §9.3.2), else read-to-EOF. Bounded by
// `timeout_ms` total. Always returns whatever was captured, even on a
// partial read, but `complete` is false whenever the framing did not finish
// (record-only cases must check it; see ReadResult).
//
// For a HEAD response specifically, RFC 9110 §9.3.2 forbids a body; after
// the header terminator this waits up to kTrailingBytesGraceMs for the peer to
// send one anyway (in a later TCP segment) so a violation shows up as extra
// bytes here instead of being silently dropped by returning immediately.
//
// `client_requested_close` says whether the REQUEST this response answers
// carried `Connection: close`: RFC 9112 §9.6 obliges the server to close
// after its final response to such a request whether or not the response
// echoes the option, so an EOF then is expected, not a persistence mismatch.
ReadResult read_http_message(int fd,
                             bool head_request,
                             int timeout_ms,
                             bool client_requested_close = false) {
    std::string buf;
    const int64_t deadline = now_ms() + timeout_ms;
    char chunk[4096];
    size_t header_end = std::string::npos;
    for (;;) {
        header_end = buf.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        const int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return {buf, false, {}};
        pollfd pfd{fd, POLLIN, 0};
        if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) return {buf, false, {}};
        const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) return {buf, false, {}};
        buf.append(chunk, static_cast<size_t>(n));
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
    const bool advertises_close =
        connection_value.find("close") != std::string::npos || client_requested_close;
    if (head_request) {
        // A HEAD response never carries a body (RFC 9110 §9.3.2): the
        // headers are the entire message, so finding the blank line is
        // completion. Still wait up to kTrailingBytesGraceMs for the peer to
        // send one anyway (in a later TCP segment) so a violation shows up
        // as extra captured bytes instead of being silently dropped by
        // returning immediately. An EOF in that window is fine only when
        // the response advertised `Connection: close`; otherwise the peer
        // closed a connection it declared persistent (round-7 review,
        // "Reject EOF on responses advertised as persistent", applied to
        // head_smoke the same way as to the Content-Length branch below).
        // An abortive close (a non-retryable negative recv(), most notably
        // ECONNRESET) is treated the same as that unexpected EOF: `poll()`
        // reports the fd readable, but `recv()` returning -1 instead of 0 is
        // not proof of an orderly close the old `if (n <= 0) break;` used to
        // let through unexamined (round-8 review, "Reject resets during the
        // persistent-response grace check"). A retryable error
        // (EINTR/EAGAIN/EWOULDBLOCK, a spurious wakeup) just waits out the
        // rest of the grace window instead.
        const int64_t grace_deadline = now_ms() + kTrailingBytesGraceMs;
        for (;;) {
            const int64_t remaining = grace_deadline - now_ms();
            if (remaining <= 0) break;
            pollfd pfd{fd, POLLIN, 0};
            const int pr = poll(&pfd, 1, static_cast<int>(remaining));
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (pr == 0) break;
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n == 0 && !advertises_close) return {buf, false, kPersistenceMismatchReason};
            if (n == 0) break;
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                if (!advertises_close) return {buf, false, kPersistenceMismatchReason};
                break;
            }
            buf.append(chunk, static_cast<size_t>(n));
        }
        return {buf, true, {}};
    }
    const size_t body_start = header_end + 4;
    if (has_cl) {
        char* end = nullptr;
        const long want = strtol(cl_value.c_str(), &end, 10);
        const size_t total = body_start + (want > 0 ? static_cast<size_t>(want) : 0u);
        while (buf.size() < total) {
            const int64_t remaining = deadline - now_ms();
            if (remaining <= 0) return {buf, false, {}};
            pollfd pfd{fd, POLLIN, 0};
            if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) return {buf, false, {}};
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return {buf, false, {}};
            buf.append(chunk, static_cast<size_t>(n));
        }
        if (advertises_close) {
            // A Content-Length-framed response can declare `connection:
            // close` (e.g. get_client_close) without the peer actually
            // closing the socket afterwards -- the body alone completing is
            // not proof of that. Require the same bounded EOF this function
            // already requires for close-delimited (no Content-Length)
            // framing below, so a peer that advertises close but stays open
            // is reported as an incomplete/broken exchange, not silently
            // accepted as complete (round-4 review).
            const int64_t remaining = deadline - now_ms();
            if (remaining <= 0) return {buf, false, {}};
            pollfd pfd{fd, POLLIN, 0};
            if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) return {buf, false, {}};
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n != 0) return {buf, false, {}};
            return {buf, true, {}};
        }
        // Persistent (keep-alive) framing: round-6 review, "Check
        // persistent responses for trailing wire bytes". The advertised
        // Content-Length body completing is not proof the peer sent nothing
        // more: for an asserted persistent case (post_fixed, trace, ...)
        // this harness closes its own socket immediately after this call
        // returns, so any erroneous bytes the peer appended in a later TCP
        // segment would otherwise never be observed by anything, letting a
        // caller compare captured bytes that equal the oracle/other side
        // even though the wire itself carried unsolicited trailing data.
        // Use a short bounded grace window (not the full remaining
        // deadline): a well-behaved persistent peer says nothing more until
        // the next request, so waiting out the whole per-case timeout here
        // would slow down every persistent case for no reason. Actual bytes
        // (n > 0) are a violation, and so is an EOF (n == 0): the response
        // did not advertise `Connection: close`, so a peer that closes here
        // anyway broke the persistence it declared -- for an asserted
        // keep-alive case (post_fixed, trace, options_star, ...) that is a
        // real behavioral difference, and it must fail the case distinctly
        // even when both sides' bytes are otherwise identical (round-7
        // review, "Reject EOF on responses advertised as persistent"). Only
        // a timeout (nothing arrived at all) is fine. A non-retryable
        // negative recv() (most notably ECONNRESET from an abortive close)
        // is treated exactly like that EOF: `poll()` reporting the fd
        // readable and `recv()` then failing instead of returning 0 is still
        // the peer tearing the connection down instead of leaving it open as
        // its response promised, and the old code let it fall through to the
        // "nothing arrived" success path unexamined (round-8 review, "Reject
        // resets during the persistent-response grace check"). A retryable
        // error (EINTR/EAGAIN/EWOULDBLOCK) just waits out the rest of the
        // grace window.
        const int64_t grace_deadline = now_ms() + kTrailingBytesGraceMs;
        for (;;) {
            const int64_t grace_remaining = grace_deadline - now_ms();
            if (grace_remaining <= 0) return {buf, true, {}};
            pollfd pfd{fd, POLLIN, 0};
            const int pr = poll(&pfd, 1, static_cast<int>(grace_remaining));
            if (pr < 0) {
                if (errno == EINTR) continue;
                return {buf, true, {}};
            }
            if (pr == 0) return {buf, true, {}};
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n > 0) {
                buf.append(chunk, static_cast<size_t>(n));
                return {buf, false, {}};
            }
            if (n == 0) return {buf, false, kPersistenceMismatchReason};
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return {buf, false, kPersistenceMismatchReason};
        }
    }
    if (advertises_close) {
        for (;;) {
            const int64_t remaining = deadline - now_ms();
            if (remaining <= 0) return {buf, false, {}};
            pollfd pfd{fd, POLLIN, 0};
            const int pr = poll(&pfd, 1, static_cast<int>(remaining));
            if (pr <= 0) return {buf, false, {}};
            const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            // EOF (n == 0) is the expected terminator for close-delimited
            // framing, i.e. completion, not a partial read. Any other
            // failure (n < 0) is a real partial exchange.
            if (n == 0) return {buf, true, {}};
            if (n < 0) return {buf, false, {}};
            buf.append(chunk, static_cast<size_t>(n));
        }
    }
    // Neither Content-Length nor Connection: close: framing is fully
    // determined by the headers alone (assumed zero-length body), so this is
    // complete as soon as the blank line was found above.
    return {buf, true, {}};
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

    // Full accounting of every request this upstream has recorded, keyed by
    // path, since start()/clear_requests(). fill_upstream_bytes() below only
    // ever queries the paths a case expects; a request landing on any other
    // path (a spurious or misrouted side-effecting request) would otherwise
    // never be looked up at all and so could never fail the harness. This
    // lets a caller reconcile the complete observed set against the complete
    // expected set instead.
    std::map<std::string, std::vector<std::string>> all_requests() {
        std::lock_guard<std::mutex> lock(mu_);
        return requests_by_path_;
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

// Renders a `waitpid` status for a FAIL message: "exited N" for a normal
// exit, "killed by signal N" for one it did not ask for. Forward-declared
// here (defined below, "RUT process management") so `EnvoyInstance::stop()`
// can share it with `RutInstance::stop()` rather than duplicating it.
std::string describe_wait_status(int status);

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
    // Set by stop() when the docker-run child had already exited on its own
    // -- Envoy crashed, or the container otherwise died -- before this call
    // ever signaled it. Mirrors `RutInstance::exited_unexpectedly` (round-6
    // review, "Reject unexpected Envoy exits during pair runs"): a caller
    // that sees this after a run must treat the whole result as a failure,
    // since byte comparisons collected up to that point prove nothing about
    // an Envoy that has since died.
    bool exited_unexpectedly = false;
    std::string unexpected_exit_description;

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

    // Returns false iff the docker-run child ended other than because of the
    // teardown this call performed: it had already exited by itself before
    // this call sent it any signal or ran `docker rm -f`, or the status
    // finally reaped is not one that teardown can produce -- an unexpected
    // exit (Envoy crash or otherwise) that `exited_unexpectedly` /
    // `unexpected_exit_description` describe. Returns true when there was
    // nothing to stop, or when the child ended because of the teardown this
    // call performed (round-6 review, "Reject unexpected Envoy exits during
    // pair runs"; round-7 review, "Verify the Envoy status reaped after
    // teardown"; mirrors `RutInstance::stop()`'s precheck and reaped-status
    // check). Docker teardown itself is skipped entirely for an instance
    // that never actually launched a container (round-15 review, "Skip
    // Docker teardown for instances that were never launched"): self-test
    // EnvoyInstance objects wrap dummy forked processes without ever
    // calling launch(), so `name` is empty and no container was ever
    // created. Running `docker rm -f` for those anyway wastes up to this
    // call's 10s timeout each -- four times in --self-test -- and, if a
    // Docker CLI or daemon is present but unresponsive, pushes the whole
    // self-test toward CTest's 60s limit for no benefit. `launched` is
    // cleared right after so a later, redundant stop() call (an explicit
    // one followed by the destructor's automatic one) never re-invokes it
    // either.
    bool stop() {
        if (pid <= 0) return true;
        int status = 0;
        // Check before signaling/removing the container: if the child is
        // already a zombie here, it exited on its own, not because we asked
        // it to.
        const pid_t precheck = waitpid(pid, &status, WNOHANG);
        if (precheck == pid) {
            exited_unexpectedly = true;
            unexpected_exit_description = describe_wait_status(status);
            pid = -1;
            // `docker run --rm` normally removes the container on exit, but
            // a crash mid-startup can leave it behind; still attempt cleanup.
            if (launched) {
                g_docker_rm_invocations++;
                run_and_wait({"docker", "rm", "-f", name}, 10'000);
                launched = false;
            }
            return false;
        }
        if (precheck < 0 && errno == ECHILD) {
            // Round-11 review, "Handle ECHILD before signaling the stored
            // PID": `pid` is no longer a child of this process -- already
            // reaped by another caller before this call ever ran, or (worse)
            // recycled by the OS for an unrelated live process since. Either
            // way, treat it exactly like the "already exited" precheck just
            // above and return before ever reaching kill() below: mirrors
            // the identical fix in `RutInstance::stop()` (same file).
            // Signaling a live-but-unrelated process because its PID number
            // happens to match a stale value here would be far worse than
            // skipping a signal this call was never going to be able to
            // deliver to the intended process anyway.
            exited_unexpectedly = true;
            unexpected_exit_description =
                "already reaped or no longer a child process (ECHILD) before this call could "
                "signal it";
            pid = -1;
            if (launched) {
                g_docker_rm_invocations++;
                run_and_wait({"docker", "rm", "-f", name}, 10'000);
                launched = false;
            }
            return false;
        }
        // Round-10 review, "Do not infer SIGTERM delivery from kill
        // success": mirrors the identical fix in `RutInstance::stop()`
        // (same file) -- kill(pid, SIGTERM) succeeding does not prove `pid`
        // was alive when the signal arrived, since POSIX kill() also
        // succeeds against an unreaped zombie. waitid(WNOHANG | WNOWAIT)
        // reports an already-exited (zombie) docker-run client WITHOUT
        // consuming its wait status, so it can still be reaped normally
        // afterward; `si_pid` must be zeroed first since waitid() returns 0
        // with an unspecified `siginfo_t` when WNOHANG finds no match, not
        // just when it finds one. If the child is already a zombie right
        // here, it did not die from a signal this call sent -- do not
        // signal it, reap it directly, and report the unexpected early
        // exit (still attempting `docker rm -f` cleanup, same as the
        // precheck branch above).
        //
        // The remaining window -- the child exiting between this waitid()
        // check and the kill() call right below -- cannot be closed this
        // way (see `RutInstance::stop()`'s identical note for why), and is
        // bounded the same way: the pair harness's transcript-completeness
        // checks require every asserted case's exchange to have already
        // completed before stop() is ever called.
        siginfo_t zombie_info{};
        if (waitid(P_PID, pid, &zombie_info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
            zombie_info.si_pid == pid) {
            int reap_status = 0;
            while (waitpid(pid, &reap_status, 0) < 0 && errno == EINTR) {
            }
            exited_unexpectedly = true;
            unexpected_exit_description = describe_wait_status(reap_status);
            pid = -1;
            if (launched) {
                g_docker_rm_invocations++;
                run_and_wait({"docker", "rm", "-f", name}, 10'000);
                launched = false;
            }
            return false;
        }
        const bool term_sent = kill(pid, SIGTERM) == 0;
        if (launched) {
            g_docker_rm_invocations++;
            run_and_wait({"docker", "rm", "-f", name}, 10'000);
            launched = false;
        }
        const int64_t deadline = now_ms() + 5000;
        bool escalated = false;
        for (;;) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) break;
            if (waited < 0 && errno == ECHILD) {
                // Already reaped by someone else (e.g. a caller that
                // explicitly waitpid()'d this pid before dropping the
                // EnvoyInstance) -- round-9 review, "Treat ECHILD as an
                // already-stopped child". Without this, a stale/reaped pid
                // would sit through the full 5s deadline below and then be
                // signaled again, potentially hitting an unrelated process
                // if the pid has since been recycled.
                break;
            }
            if (now_ms() >= deadline) {
                kill(pid, SIGKILL);
                escalated = true;
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
                }
                break;
            }
            struct timespec ts{0, 10'000'000};
            nanosleep(&ts, nullptr);
        }
        pid = -1;
        // The precheck above only catches a child that had ALREADY exited
        // before this call signaled it; a child that died in the window
        // between that precheck and the `kill`/`docker rm -f` above was
        // reaped by the loop just like an intentional teardown would be (a
        // zombie still accepts, and silently no-ops, a kill()). Verify the
        // reaped status is one the teardown THIS call performed can
        // actually produce. The child is the attached `docker run` client,
        // whose own exit status is the container's (Envoy's) exit code, or
        // death by our SIGKILL when this call escalated:
        //   - exit 0: Envoy handled the SIGTERM the docker client proxied
        //     to it (`--sig-proxy` is on by default without a TTY) and
        //     shut down normally;
        //   - exit 143 (128 + SIGTERM): the proxied SIGTERM reached the
        //     container before Envoy had installed its handler (early
        //     startup), so the kernel default terminated it;
        //   - exit 137 (128 + SIGKILL): `docker rm -f` won the race with the
        //     proxied SIGTERM and force-killed the container;
        //   - killed by SIGKILL: only when this call escalated (the docker
        //     client itself did not exit within the grace period).
        // Anything else -- a crash signal reported as exit 134/139, any
        // other nonzero exit, a signal death this call did not send, or a
        // SIGTERM-shaped status when the SIGTERM was never delivered -- is
        // unexpected, however it was reaped.
        const bool clean = escalated ? (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
                                     : (WIFEXITED(status) &&
                                        (WEXITSTATUS(status) == 128 + SIGKILL ||
                                         (term_sent && (WEXITSTATUS(status) == 0 ||
                                                        WEXITSTATUS(status) == 128 + SIGTERM))));
        if (!clean) {
            exited_unexpectedly = true;
            unexpected_exit_description = describe_wait_status(status);
            return false;
        }
        return true;
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

// Round-12 review, "Detect concurrent SO_REUSEPORT owners before accepting
// readiness": `rut` sets SO_REUSEPORT on every listener it binds
// (src/runtime/socket.cc:33-36), so a second, same-UID `rut` process racing
// this harness for a probe-allocated port does not fail with EADDRINUSE the
// way every other collision this harness detects does -- both binds
// succeed, the losing process still logs the same "Listening on port N"
// evidence, and the kernel load-balances new connections between the two,
// so later pair-case traffic can land on whichever instance the kernel
// happens to pick. Neither the protocol probe nor the log-confirmation
// check above can tell the two apart: both are real, both answer
// identically, both logged startup on this exact port.
//
// Counts how many rows of a /proc/net/tcp- or /proc/net/tcp6-style table are
// in the LISTEN state (`st` field "0A", i.e. decimal 10) and bound to
// `port`. Each row is a DISTINCT socket with its own inode column (the last
// field), so more than one row for the same port means more than one live
// listener holds it right now, whether or not they are in the same
// SO_REUSEPORT group. Takes the table's TEXT, not a path, so it is
// exercisable directly with synthetic tables, independent of the real
// /proc filesystem.
int count_listeners_on_port(const std::string& tcp_table, uint16_t port) {
    char port_hex[8];
    std::snprintf(port_hex, sizeof(port_hex), "%04X", port);
    int count = 0;
    std::istringstream lines(tcp_table);
    std::string line;
    bool skipped_header = false;
    while (std::getline(lines, line)) {
        if (!skipped_header) {
            skipped_header = true;
            continue;
        }
        std::istringstream fields(line);
        std::string sl, local_address, rem_address, st;
        if (!(fields >> sl >> local_address >> rem_address >> st)) continue;
        if (st != "0A") continue;
        const size_t colon = local_address.rfind(':');
        if (colon == std::string::npos) continue;
        std::string local_port = local_address.substr(colon + 1);
        std::transform(
            local_port.begin(), local_port.end(), local_port.begin(), [](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            });
        if (local_port == port_hex) count++;
    }
    return count;
}

// Live counterpart: sums count_listeners_on_port() over the real
// /proc/net/tcp and /proc/net/tcp6 tables (a dual-stack socket appears in
// exactly one of the two, never both, so this never double-counts a single
// listener). Either table being missing or unreadable (no /proc, a
// restrictive sandbox) contributes 0 rather than failing outright -- every
// caller only ever treats a count ABOVE the one listener it expects as a
// signal, so undercounting here can only make the check silently pass,
// never falsely trigger a retry.
int count_listeners_on_port(uint16_t port) {
    return count_listeners_on_port(read_file_contents("/proc/net/tcp"), port) +
           count_listeners_on_port(read_file_contents("/proc/net/tcp6"), port);
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
bool wait_ready_and_confirm_ownership(uint16_t port,
                                      EnvoyInstance& envoy,
                                      int timeout_ms,
                                      int grace_ms,
                                      std::string* error,
                                      bool* reuseport_collision = nullptr) {
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
            // Round-12 review, "Detect concurrent SO_REUSEPORT owners before
            // accepting readiness": both the protocol probe and the log
            // confirmation just above can be satisfied identically by a
            // second, real listener sharing this exact port -- see
            // count_listeners_on_port()'s comment. Exactly one LISTEN row
            // for `port` is the healthy case (this launch's own listener);
            // more than one means a co-owner exists right now.
            if (count_listeners_on_port(port) > 1) {
                if (reuseport_collision != nullptr) *reuseport_collision = true;
                *error = "more than one LISTEN socket is bound to port " + std::to_string(port) +
                         " (a concurrent process shares it, e.g. via SO_REUSEPORT); a different "
                         "process likely raced this port";
                return false;
            }
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
        //
        // Built before fork(): see build_argv()'s comment (round-3 review,
        // "Build the Docker argv before entering the fork child"). The
        // recording upstream's accept thread and the Envoy/RUT readiness
        // polling loop already running by the time callers reach this are
        // exactly the kind of concurrent activity that makes post-fork
        // allocation unsafe.
        std::vector<std::string> argv = {
            rut_binary, rut_source_path, "--shards", "1", "--no-pin", "--drain", "0"};
        const std::vector<char*> args = build_argv(argv);
        pid = fork();
        if (pid < 0) return false;
        if (pid == 0) {
            const int log_fd = open(log_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (log_fd >= 0) {
                dup2(log_fd, STDOUT_FILENO);
                dup2(log_fd, STDERR_FILENO);
                if (log_fd > STDERR_FILENO) close(log_fd);
            }
            execv(args[0], args.data());
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
        if (precheck < 0 && errno == ECHILD) {
            // Round-11 review, "Handle ECHILD before signaling the stored
            // PID": mirrors the identical fix in `EnvoyInstance::stop()`
            // (same file) -- `pid` is no longer a child of this process,
            // already reaped by another caller before this call ever ran,
            // or (worse) recycled by the OS for an unrelated live process
            // since. Return before ever reaching kill() below rather than
            // risk signaling an unrelated process because its PID number
            // happens to match a stale value here.
            exited_unexpectedly = true;
            unexpected_exit_description =
                "already reaped or no longer a child process (ECHILD) before this call could "
                "signal it";
            pid = -1;
            return false;
        }
        // Round-10 review, "Do not infer SIGTERM delivery from kill
        // success": kill(pid, SIGTERM) succeeding does not prove `pid` was
        // alive when the signal arrived -- POSIX kill() also succeeds
        // against an unreaped zombie (verified: a zombie still accepts a
        // signal with rc==0, it just has no effect), so a child that exited
        // on its own in the gap between the precheck above and the kill()
        // call below would still make kill() "succeed" and the reap loop
        // below still observe a clean-looking exit 0, exactly the false
        // "clean teardown" round-9's `term_sent` check was meant to catch.
        // Narrow the gap as far as the kernel allows: waitid(WNOHANG |
        // WNOWAIT) reports an already-exited (zombie) child WITHOUT
        // consuming its wait status, so a positive result here can still be
        // reaped normally afterward. If `pid` is already a zombie at this
        // exact point, it did not die because of a signal this call sent
        // (nothing has been sent yet) -- do not signal it at all, reap it
        // directly, and report the unexpected early exit. `si_pid` must be
        // zeroed first: waitid() returns 0 with an unspecified/unset
        // `siginfo_t` when WNOHANG finds nothing, not just when it finds a
        // match (verified: `si_pid` reads 0 in the no-match case).
        //
        // The remaining window cannot be closed this way: a child that
        // exits between this waitid() check and the kill(pid, SIGTERM) call
        // two lines below is indistinguishable from one that was already a
        // zombie right up until that instant, because POSIX gives no way to
        // learn a process's exit status ahead of actually reaping it, and
        // reaping it here would remove the evidence the reap loop below
        // needs to classify how it ended. This is documented and left as a
        // residual TOCTOU rather than "fixed": its worst-case effect (an
        // unexpected RUT exit in that instant being misreported as clean)
        // is independently bounded by two things a mid-teardown crash would
        // almost always also disturb -- rut_log_confirms_listener()'s
        // launch-time evidence has nothing to do with shutdown and would not
        // catch it, but the pair harness's transcript-completeness checks
        // (validate_pair_results()/fill_upstream_bytes()) require every
        // asserted case's exchange to have already completed before stop()
        // is ever called, so a `rut` that crashes in this exact instant, as
        // opposed to sometime during the run, has no in-flight evidence left
        // to corrupt.
        siginfo_t zombie_info{};
        if (waitid(P_PID, pid, &zombie_info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
            zombie_info.si_pid == pid) {
            int reap_status = 0;
            while (waitpid(pid, &reap_status, 0) < 0 && errno == EINTR) {
            }
            exited_unexpectedly = true;
            unexpected_exit_description = describe_wait_status(reap_status);
            pid = -1;
            return false;
        }
        // Round-9 review, "Require SIGTERM delivery before accepting a clean
        // RUT exit": record whether the signal actually reached a still-
        // extant process. kill() fails with ESRCH once `pid` has already
        // been reaped out from under this call (nothing but this function
        // ever reaps it, but the precheck above cannot rule out every gap,
        // e.g. if some future caller reaps it independently); a reaped
        // exit-0-shaped status that this call never actually delivered a
        // signal for must not be trusted as an intentional teardown,
        // mirroring EnvoyInstance::stop()'s `term_sent`.
        const bool term_sent = kill(pid, SIGTERM) == 0;
        const int64_t deadline = now_ms() + 5000;
        bool escalated = false;
        for (;;) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) break;
            if (waited < 0 && errno != EINTR) {
                // No such child left to wait for (consistent with
                // `term_sent` already being false above): nothing will ever
                // come back from waitpid() for this pid, so stop spinning
                // instead of waiting out the full deadline.
                break;
            }
            if (now_ms() >= deadline) {
                kill(pid, SIGKILL);
                escalated = true;
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
                }
                break;
            }
            struct timespec ts{0, 10'000'000};
            nanosleep(&ts, nullptr);
        }
        pid = -1;
        // Round-6 review, "Verify the status reaped after signaling RUT":
        // the precheck above only catches a child that had ALREADY exited
        // before stop() sent it any signal. A child that dies during the
        // TOCTOU window between that precheck and `kill(pid, SIGTERM)` right
        // above is a still-open gap: a zombie process still accepts (and
        // silently no-ops) a kill(), so the `waitpid(..., WNOHANG)` loop
        // just reaped above would otherwise be trusted as evidence of a
        // clean, intentional teardown regardless of what actually killed the
        // child. Verify the reaped status matches the teardown THIS call
        // actually performed: rut blocks SIGTERM/SIGINT and exits via a
        // normal `return` from `main` once it observes one (src/main.cc,
        // `sigwait`/`sigtimedwait` loop), so a SIGTERM that sufficed must
        // produce a plain exit 0; a SIGTERM that did not (this call
        // escalated to SIGKILL) must produce death by exactly that signal.
        // Anything else -- a crash signal, a nonzero exit, escaping SIGKILL,
        // or a plain exit 0 this call never actually signaled (`term_sent`
        // false) -- is unexpected, however it was reaped.
        const bool clean = escalated ? (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
                                     : (term_sent && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (!clean) {
            exited_unexpectedly = true;
            unexpected_exit_description = describe_wait_status(status);
            return false;
        }
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
// `*stderr_out`. Returns true only on exit 0 with a stderr that is empty or
// consists solely of `warning:` lines (the converter warns, per the #692
// review, that Rut does not enforce the cluster's connect_timeout; any other
// stderr text is a conversion failure). Both --self-test's RUT pass and
// --pair-milestone-s rely on this; the caller prints `*stderr_out` on
// failure.
bool converter_stderr_is_warnings_only(const std::string& text) {
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t end = text.find('\n', pos);
        const std::string line =
            text.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        if (!line.empty() && line.rfind("warning: ", 0) != 0) return false;
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return true;
}

bool run_converter_to_file(const std::string& converter_binary,
                           const std::string& bootstrap_path,
                           const std::string& out_rut_path,
                           std::string* stderr_out) {
    const std::string stderr_path = out_rut_path + ".stderr";
    // Built before fork(): see build_argv()'s comment (round-3 review,
    // "Build the Docker argv before entering the fork child").
    std::vector<std::string> argv = {
        converter_binary, "--format", "bootstrap-json", bootstrap_path};
    const std::vector<char*> args = build_argv(argv);
    const pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        const int out_fd = open(out_rut_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
        const int err_fd = open(stderr_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (out_fd >= 0) dup2(out_fd, STDOUT_FILENO);
        if (err_fd >= 0) dup2(err_fd, STDERR_FILENO);
        if (out_fd > STDERR_FILENO) close(out_fd);
        if (err_fd > STDERR_FILENO) close(err_fd);
        execv(args[0], args.data());
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
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           converter_stderr_is_warnings_only(*stderr_out);
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
    // Record-only (not in kAssertedCaseNames) on this branch: a client-forged
    // `X-Envoy-Internal: true` and an `X-Forwarded-Client-Cert` header must
    // never reach the upstream. Envoy removes both unconditionally for this
    // milestone config (`ConnectionManagerUtility::mutateRequestHeaders`:
    // `removeEnvoyInternalRequest()` with `internal_request` always false,
    // and `forward_client_cert_details` defaulting to SANITIZE), so its
    // recorded upstream bytes are the assertion the pair comparison checks
    // RUT against. PR #696's round-7 fix strips both on the RUT side; until
    // it cascades to this branch RUT still forwards them, so these two are
    // expected to MISMATCH on upstream bytes and stay record-only rather than
    // asserted (promote once a pinned-Envoy CI run shows them equal).
    cases.push_back({"get_forged_envoy_internal",
                     "GET /internal HTTP/1.1\r\nHost: client.example\r\nUser-Agent: rut-diff/1\r\n"
                     "X-Envoy-Internal: true\r\nAccept: */*\r\n\r\n",
                     false,
                     "/internal",
                     smoke_reply});
    cases.push_back({"get_forged_xfcc",
                     "GET /xfcc HTTP/1.1\r\nHost: client.example\r\nUser-Agent: rut-diff/1\r\n"
                     "X-Forwarded-Client-Cert: Hash=deadbeef;Subject=\"CN=forged\"\r\n"
                     "Accept: */*\r\n\r\n",
                     false,
                     "/xfcc",
                     smoke_reply});
    // Record-only (not in kAssertedCaseNames), alongside the two forged-header
    // cases above: a client-supplied `X-Envoy-External-Address: 10.0.0.1`.
    // PR #696 round-8 (fix ID4) makes RUT strip this header unconditionally
    // before forwarding. Codex's review there claimed Envoy strips a
    // client-supplied value here too, but a worker who checked Envoy
    // v1.39.1's `ConnectionManagerUtility::mutateRequestHeaders()` for this
    // milestone's exact shape (`use_remote_address: false`) found Envoy does
    // NOT remove a client-supplied value in that configuration -- contradicting
    // the Codex claim. This case exists to record what the pinned Envoy
    // image's recorded upstream bytes actually show, which will settle the
    // disagreement once a pinned-Envoy CI run captures it; until then it
    // stays record-only and is expected to diverge (RUT strips the header,
    // while Envoy's recorded behavior may forward it unchanged). The matrix
    // row on PR #696 documents RUT's stripping as intentional Rut-side
    // hardening regardless of how this case's evidence settles.
    cases.push_back({"get_forged_envoy_external_address",
                     "GET /external-address HTTP/1.1\r\nHost: client.example\r\n"
                     "User-Agent: rut-diff/1\r\nX-Envoy-External-Address: 10.0.0.1\r\n"
                     "Accept: */*\r\n\r\n",
                     false,
                     "/external-address",
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

// Case names whose whole point is unreachable-upstream behavior, not
// forwarding: `options_star` (Envoy answers the control `OPTIONS *` request
// with a local 404, never routing it -- docs/envoy-compatibility.md, "Local
// replies (404 for OPTIONS * and authority-form CONNECT)") and
// `connect_failure` (the upstream port is deliberately closed to exercise
// the connect-failure local reply), and `connect_authority` (authority-form
// CONNECT hits the same unmatched-route local 404 as `options_star`; the
// committed oracle's `kEnvoyOracle_connect_authority_upstream` is empty --
// "upstream not contacted" -- so a correct run contacts the upstream zero
// times, and classifying it as a forwarding case would make every run of
// this record-only case a "forwarding not exercised" mismatch, which could
// never demonstrate parity once its downstream persistence difference is
// fixed; round-7 review, "Exempt authority-form CONNECT from forwarding
// checks"). Every other case exists specifically to exercise forwarding, so
// `compare_pair_case` below requires actual upstream contact for them
// (round-6 review, "Require expected upstream contact for forwarded cases").
// Moved above fill_upstream_bytes() (round-10 review, "Attribute stray
// traffic without blaming local asserted cases"): these locally-handled
// cases have `upstream_contact_count == 0` BY DESIGN, so fill_upstream_
// bytes()'s stray-traffic attribution must not treat their zero count as
// suspicious the way it does for a case that is actually supposed to
// forward.
bool case_expects_upstream_forward(const std::string& name) {
    return name != "options_star" && name != "connect_failure" && name != "connect_authority";
}

// Splits `cases` into the subset the CLI's exit-code contract requires exact
// evidence for (`is_asserted_case()`) and everything else (record-only:
// evidence is recorded, but per the CLI contract must never gate PASS/FAIL).
// Callers run each half against the SAME live proxy instance but in
// temporally separate windows, clearing the recording upstream's log
// between them (round-11 review, "Attribute duplicate contacts to the
// originating case"): a record-only request misrouted onto -- or otherwise
// colliding with -- an asserted case's own expected upstream path would
// previously inflate that asserted case's contact count into a false
// "duplicate", failing the run despite the record-only contract. Running
// the two halves in isolation means neither half's traffic is ever present
// in the log when the other half's evidence is attributed, so a
// record-only misroute can only ever land on record-only evidence.
void split_asserted_and_record_only(const std::vector<CaseSpec>& cases,
                                    std::vector<CaseSpec>* asserted,
                                    std::vector<CaseSpec>* record_only) {
    for (const auto& spec : cases) {
        (is_asserted_case(spec.name) ? *asserted : *record_only).push_back(spec);
    }
}

// ── Case results & transcript ────────────────────────────────────────────

struct CaseResult {
    std::string name;
    std::string client_bytes;
    // Whether the downstream exchange (client request + Envoy's response)
    // actually finished framing within the deadline; see ReadResult. Never
    // trust downstream_bytes when this is false.
    bool exchange_complete = false;
    // `ReadResult::reason` for the downstream read, when it had one (e.g. a
    // persistence mismatch); empty for a plain partial read/timeout.
    std::string exchange_failure_reason;
    bool upstream_contacted = false;
    // How many times the recording upstream observed a request for this
    // case's path. Expected to be 0 (never contacted) or 1; more than one is
    // treated as corrupt evidence (an unexpected retry/duplicate), not a
    // single trustworthy recording (round-3 review, "Reject partial
    // exchanges before writing the oracle transcript").
    int upstream_contact_count = 0;
    // Set by fill_upstream_bytes() when this case's own upstream evidence is
    // unreliable (a duplicate contact for its path, or unexpected traffic
    // elsewhere while this case's own expected path saw none) but the case
    // is record-only, so the CLI contract ("record-only cases never affect
    // the exit code") keeps the anomaly from being fatal (round-9 review,
    // "Keep record-only upstream duplicates/misroutes out of acceptance").
    // write_pair_transcript() flags it with a NOTE instead of presenting the
    // bytes as trustworthy evidence.
    bool upstream_ambiguous = false;
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
        // Whether this case's own request asked for close (get_client_close):
        // the reader then expects the EOF instead of reporting it as a
        // persistence mismatch.
        std::string request_connection;
        const size_t request_line_end = spec.client_bytes.find("\r\n");
        const size_t request_head_end = spec.client_bytes.find("\r\n\r\n");
        if (request_line_end != std::string::npos && request_head_end != std::string::npos &&
            request_head_end > request_line_end) {
            find_header(spec.client_bytes.substr(request_line_end + 2,
                                                 request_head_end - request_line_end - 2),
                        "Connection",
                        &request_connection);
        }
        std::transform(request_connection.begin(),
                       request_connection.end(),
                       request_connection.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        const bool client_requested_close = request_connection.find("close") != std::string::npos;
        const ReadResult read =
            read_http_message(fd, spec.is_head, kClientTimeoutMs, client_requested_close);
        result->downstream_bytes = read.bytes;
        result->exchange_complete = read.complete;
        result->exchange_failure_reason = read.reason;
    }
    close(fd);
    return sent && result->exchange_complete;
}

// Renders why `r`'s downstream exchange did not complete, for every message
// that reports one: the specific `ReadResult::reason` when the reader had
// one, else the generic partial read/timeout wording.
std::string describe_incomplete_exchange(const CaseResult& r) {
    return r.exchange_failure_reason.empty() ? std::string("partial read/timeout")
                                             : r.exchange_failure_reason;
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
            std::cerr << "WARN: case " << spec.name << " exchange did not complete cleanly ("
                      << describe_incomplete_exchange(r) << ")\n";
        results.push_back(std::move(r));
    }
    return results;
}

// Fills in `upstream_contacted`/`upstream_contact_count`/`upstream_bytes` on
// each result in `results` from what `upstream` actually recorded for that
// case's path, matching cases by name against `cases` to find each one's
// `upstream_path`. A case's path recording more than one request -- a
// retried, replayed or otherwise duplicated upstream request (which could
// repeat a side effect in production, e.g. the fixed-length POST) -- is
// ambiguous evidence for THAT case; `upstream_contact_count` is always
// recorded (even for an ambiguous case) so the same at-most-once-contact
// rule `validate_results`/`validate_pair_results` enforce again at
// transcript-write time (round-3 review) still catches a duplicate that
// reaches a transcript writer some other way.
//
// The per-case lookups above only ever query the expected `upstream_path`
// for each case in `cases`, so a request that lands on any other path --
// a spurious or misrouted side-effecting request that was never supposed
// to reach the upstream at all -- would never be queried and every
// asserted comparison above could still pass (round-4 review). Guard
// against that separately: every path `upstream` has ever recorded a
// request for must be one of `cases`' own expected `upstream_path`s.
//
// Since round-11 review's batch isolation, `cases` here is always PURELY
// the asserted batch or PURELY the record-only batch, never mixed (see
// split_asserted_and_record_only()). That makes the anomaly's fatal/NOTE
// classification a property of the WHOLE BATCH, not of any individual
// case's own contact count: for a pure-asserted batch, unlisted traffic can
// only have come from one of this batch's own (asserted) cases and must
// fail the run, even when every case ALSO already recorded its own expected
// contact -- an extra request is still a real, potentially side-effecting
// anomaly (round-15 review, "Reject unlisted traffic even after expected
// contacts succeed"): the old per-case "attribute to whichever case never
// saw ITS OWN contact" elimination logic silently skipped every case once
// they had all been contacted, hiding exactly this. For a pure-record-only
// batch, the CLI contract promises record-only cases never affect the exit
// code (round-9 review, "Keep record-only upstream duplicates/misroutes out
// of acceptance"), so it stays a NOTE regardless; the elimination-based
// attribution (whichever record-only case(s) never saw their own expected
// contact -- the most plausible source) is still applied there, for the
// transcript's benefit, marking `upstream_ambiguous` on eligible cases only
// (case_expects_upstream_forward(): `options_star`/`connect_failure`/
// `connect_authority` have `upstream_contact_count == 0` BY DESIGN and are
// never a plausible source, round-10 review).
//
// The per-case duplicate check above is likewise only ever fatal for an
// asserted case (`is_asserted_case()`), which -- now that batches are pure
// -- means fatal exactly when the whole batch is the asserted one.
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
            const bool asserted = is_asserted_case(r.name);
            std::cerr << (asserted ? "FAIL: " : "NOTE: ") << "upstream recorded " << observed.size()
                      << " requests for case " << r.name << " (path \"" << it->upstream_path
                      << "\"), expected exactly one\n";
            if (asserted) {
                ok = false;
            } else {
                r.upstream_ambiguous = true;
            }
            continue;
        }
        r.upstream_contacted = true;
        r.upstream_bytes = observed.front();
    }
    // A batch is either purely asserted or purely record-only (see the
    // comment above); an empty batch has nothing to attribute anomalies to
    // and is conservatively treated as non-fatal.
    const bool batch_is_asserted =
        !cases.empty() && std::all_of(cases.begin(), cases.end(), [](const CaseSpec& s) {
            return is_asserted_case(s.name);
        });
    for (const auto& [path, reqs] : upstream.all_requests()) {
        const bool expected = std::any_of(
            cases.begin(), cases.end(), [&](const CaseSpec& s) { return s.upstream_path == path; });
        if (expected) continue;
        std::cerr << (batch_is_asserted ? "FAIL: " : "NOTE: ") << "upstream recorded "
                  << reqs.size() << " request(s) for path \"" << path
                  << "\", which is not any case's expected upstream_path\n";
        if (batch_is_asserted) {
            ok = false;
            continue;
        }
        for (auto& r : *results) {
            const auto it = std::find_if(
                cases.begin(), cases.end(), [&](const CaseSpec& s) { return r.name == s.name; });
            if (it == cases.end() || r.upstream_contact_count != 0) continue;
            // A case that never expects to forward at all (options_star,
            // connect_failure, connect_authority) has zero contact by
            // design; it is never a plausible source of stray traffic.
            if (!case_expects_upstream_forward(r.name)) continue;
            r.upstream_ambiguous = true;
        }
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
            return "case \"" + r.name + "\": downstream exchange did not complete (" +
                   describe_incomplete_exchange(r) + "); refusing to record it as evidence";
        }
        if (r.upstream_contact_count > 1) {
            return "case \"" + r.name + "\": upstream was contacted " +
                   std::to_string(r.upstream_contact_count) +
                   " times (expected at most 1); refusing to record ambiguous evidence";
        }
    }
    return "";
}

// True iff `value` has the exact 29-byte RFC 1123 (IMF-fixdate, RFC 9110
// §5.6.7) shape every synthesized HTTP Date must have -- `Sun, 06 Nov 1994
// 08:49:37 GMT` -- with in-range day/hour/minute/second fields, AND names an
// actual calendar date: the day is valid for that month and year (Gregorian
// leap years: divisible by 4, except century years unless also divisible by
// 400), and the weekday token matches the one that date actually falls on
// (Sakamoto's algorithm). Round-7 review only range-checked each field
// independently, which still accepted an impossible date like `Sun, 31 Feb
// 2026 12:00:00 GMT`: if Envoy emits a valid synthesized Date while RUT
// emits one shaped like that, normalize_date_for_compare() below would
// replace both with the same placeholder and let an asserted pair case
// match despite RUT's Date being malformed (round-13 review, "Validate
// calendar dates before normalization"). Same check
// tests/test_nginx_differential.cc's normalize_date() applies before it
// mutates a Date, so the placeholder substitution below can only ever hide
// the unavoidable timestamp difference, never a malformed value.
//
// Seconds are capped at 59, not 60: this project has no citation that Envoy
// (or `rut`) ever synthesizes a leap-second `:60` Date, so treating it as
// valid would only widen what counts as "well-formed" without evidence.
bool is_rfc1123_http_date(const std::string& value) {
    if (value.size() != 29) return false;
    const char* date = value.data();
    const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    const auto find_token_index =
        [](const char* v, const char* const* tokens, size_t count) -> int {
        for (size_t i = 0; i < count; i++)
            if (memcmp(v, tokens[i], 3) == 0) return static_cast<int>(i);
        return -1;
    };
    // Index 0 = Mon .. 6 = Sun (ISO weekday order), matched against the
    // computed weekday below (see the Sakamoto/kWeekdays remark further
    // down for the index translation between the two).
    static const char* const kWeekdays[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
    static const char* const kMonths[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const auto two_digits = [&](size_t offset) {
        return is_digit(date[offset]) && is_digit(date[offset + 1])
                   ? static_cast<unsigned>(date[offset] - '0') * 10u +
                         static_cast<unsigned>(date[offset + 1] - '0')
                   : 100u;
    };
    const int weekday_index =
        find_token_index(date, kWeekdays, sizeof(kWeekdays) / sizeof(kWeekdays[0]));
    const int month_index =
        find_token_index(date + 8, kMonths, sizeof(kMonths) / sizeof(kMonths[0]));
    if (weekday_index < 0 || date[3] != ',' || date[4] != ' ' || date[7] != ' ' ||
        month_index < 0 || date[11] != ' ' || date[16] != ' ' || date[19] != ':' ||
        date[22] != ':' || date[25] != ' ' || memcmp(date + 26, "GMT", 3) != 0)
        return false;
    for (size_t i = 12; i < 16; i++)
        if (!is_digit(date[i])) return false;
    const unsigned day = two_digits(5);
    const unsigned year = static_cast<unsigned>((date[12] - '0') * 1000 + (date[13] - '0') * 100 +
                                                (date[14] - '0') * 10 + (date[15] - '0'));
    const unsigned hour = two_digits(17);
    const unsigned minute = two_digits(20);
    const unsigned second = two_digits(23);
    if (hour > 23 || minute > 59 || second > 59) return false;

    // Day-of-month must be valid for THIS month and year, not just <= 31.
    static const unsigned kDaysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap_year = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    const unsigned days_in_month =
        (month_index == 1 && leap_year) ? 29u : kDaysInMonth[static_cast<size_t>(month_index)];
    if (day < 1 || day > days_in_month) return false;

    // Sakamoto's algorithm: the weekday for a Gregorian calendar date, as
    // 0 = Sunday .. 6 = Saturday.
    static const int kSakamotoMonthTable[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};
    int adjusted_year = static_cast<int>(year);
    const int month_1based = month_index + 1;
    if (month_1based < 3) adjusted_year -= 1;
    const int sakamoto_weekday =
        (adjusted_year + adjusted_year / 4 - adjusted_year / 100 + adjusted_year / 400 +
         kSakamotoMonthTable[month_index] + static_cast<int>(day)) %
        7;
    // Translate Sakamoto's 0=Sunday..6=Saturday into kWeekdays' 0=Mon..6=Sun
    // indexing: Sunday (0) maps to kWeekdays' last slot (6), Monday (1) to
    // kWeekdays' first slot (0), and so on.
    const int computed_weekday_index = (sakamoto_weekday + 6) % 7;
    if (computed_weekday_index != weekday_index) return false;

    return true;
}

// Returns `raw` with its `date:` header value replaced by a fixed
// placeholder, UNLESS that value is exactly `preserved_date` (the literal
// the recording upstream sent for `get_upstream_date_server`, which Envoy
// and RUT must both preserve unchanged -- normalizing it away would hide a
// real bug). Every other case's `date` is synthesized to "now" by whichever
// side produced it, so those are always normalized before a byte comparison.
// `preserved_date` is empty for every other case, which never matches a
// real Date value and so always normalizes.
//
// A synthesized value is only replaced when it passes is_rfc1123_http_date();
// a malformed one (`date: garbage`) is left verbatim in the returned bytes
// and `*dates_valid` is cleared, so the caller fails the case instead of
// letting the placeholder erase a real regression (round-7 review). Every
// well-formed (or absent) Date leaves `*dates_valid` untouched.
std::string normalize_date_for_compare(const std::string& raw,
                                       const std::string& preserved_date,
                                       bool* dates_valid) {
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
            if (!is_rfc1123_http_date(trimmed)) {
                *dates_valid = false;
                continue;  // leave the malformed value visible in the output
            }
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

// Applies validate_results()'s evidentiary rule (complete exchange, upstream
// contacted at most once) to BOTH sides of every ASSERTED pair case, so
// write_pair_transcript refuses ambiguous evidence exactly like
// write_transcript does (round-3 review, applied uniformly to the pair
// harness too). Returns empty on success, else a human-readable reason
// naming which side failed.
//
// Record-only rows are deliberately exempt (round-8 review, "Keep
// record-only transcript failures out of acceptance"): the CLI contract
// promises record-only cases never affect the run's exit code (see
// run_pair_milestone_s()'s `any_asserted_mismatch`), but every
// --pair-milestone-s invocation that CI runs also writes a transcript, and
// this validation used to apply uniformly to every row regardless of
// `asserted`. An incomplete or ambiguous record-only observation -- exactly
// the kind of real divergence this record-only harness exists to surface,
// not evidence backing a PASS/FAIL decision -- would make write_pair_transcript()
// fail and turn that observation into a hard CI failure anyway. Only rows
// whose bytes actually gate acceptance need the strict "never write
// ambiguous evidence" rule below.
std::string validate_pair_results(const std::vector<PairCaseResult>& results) {
    for (const auto& r : results) {
        if (!r.asserted) continue;
        const std::pair<const char*, const CaseResult*> sides[] = {{"envoy", &r.envoy},
                                                                   {"rut", &r.rut}};
        for (const auto& side : sides) {
            const std::string label = "case \"" + r.name + "\" (" + side.first + ")";
            if (!side.second->exchange_complete) {
                return label + ": downstream exchange did not complete (" +
                       describe_incomplete_exchange(*side.second) +
                       "); refusing to record it as evidence";
            }
            if (side.second->upstream_contact_count > 1) {
                return label + ": upstream was contacted " +
                       std::to_string(side.second->upstream_contact_count) +
                       " times (expected at most 1); refusing to record ambiguous evidence";
            }
        }
    }
    return "";
}

// Writes both sides' bytes for every pair case as a transcript header, in
// the same one-literal-per-wire-line style as `write_transcript`. This is
// the "<out.inc>" CI artifact evidence for PR 6: unlike the oracle
// transcript, each case here carries two upstream and two downstream
// literals (`_envoy_*` / `_rut_*`) so a reviewer can diff them directly.
bool write_pair_transcript(const std::string& path, const std::vector<PairCaseResult>& results) {
    const std::string validation_error = validate_pair_results(results);
    if (!validation_error.empty()) {
        std::cerr << "FAIL: refusing to write pair transcript: " << validation_error << "\n";
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
    out << "// Envoy-vs-generated-RUT pair transcript recorded against " << kEnvoyImage << " ("
        << date_buf << ").\n";
    out << "// Generated by tests/test_envoy_differential.cc --pair-milestone-s; do not\n";
    out << "// hand-edit. See docs/envoy-compatibility.md and envoy-pr-plan.md PR 6.\n\n";
    for (const auto& r : results) {
        out << "// " << r.name << (r.asserted ? " (asserted)" : " (record-only)") << "\n";
        // Record-only rows skip validate_pair_results()'s strict evidentiary
        // rule above, so an incomplete exchange or an ambiguous (>1) upstream
        // contact can reach here; flag it with a NOTE instead of silently
        // presenting the raw bytes as if they were as trustworthy as an
        // asserted row's (round-8 review, "Keep record-only transcript
        // failures out of acceptance").
        if (!r.asserted) {
            if (!r.envoy.exchange_complete)
                out << "// NOTE: " << r.name << " (envoy): downstream exchange did not complete ("
                    << describe_incomplete_exchange(r.envoy) << ")\n";
            if (!r.rut.exchange_complete)
                out << "// NOTE: " << r.name << " (rut): downstream exchange did not complete ("
                    << describe_incomplete_exchange(r.rut) << ")\n";
            if (r.envoy.upstream_contact_count > 1)
                out << "// NOTE: " << r.name << " (envoy): upstream was contacted "
                    << r.envoy.upstream_contact_count << " times (ambiguous evidence)\n";
            if (r.rut.upstream_contact_count > 1)
                out << "// NOTE: " << r.name << " (rut): upstream was contacted "
                    << r.rut.upstream_contact_count << " times (ambiguous evidence)\n";
            // Set by fill_upstream_bytes() when this case's own path saw zero
            // contacts but unexplained traffic landed on some other path in
            // the same batch (round-9 review): the case's own bytes below
            // are trustworthy (there is nothing to report for them), but the
            // case is flagged ambiguous because it is the likely source of
            // that stray request.
            if (r.envoy.upstream_ambiguous)
                out << "// NOTE: " << r.name
                    << " (envoy): upstream recorded unattributed traffic on another path "
                       "while this case's own path saw none (ambiguous evidence)\n";
            if (r.rut.upstream_ambiguous)
                out << "// NOTE: " << r.name
                    << " (rut): upstream recorded unattributed traffic on another path while "
                       "this case's own path saw none (ambiguous evidence)\n";
        }
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
        bool reuseport_collision = false;
        if (wait_ready_and_confirm_ownership(
                *listen_port, *envoy, 15'000, 300, error, &reuseport_collision)) {
            return true;
        }

        // Round-12 review, "Detect concurrent SO_REUSEPORT owners before
        // accepting readiness": a co-owner detected by
        // count_listeners_on_port() never leaves Envoy's own log naming an
        // address-in-use collision (its bind() genuinely succeeded), so
        // that signal alone is folded into `collided` here to take the
        // same retry-on-a-fresh-port path as a real bind collision.
        const bool collided = reuseport_collision || log_indicates_address_in_use(envoy->log_path);
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

// Scan of rut's own stderr log for its listen/bind failure message
// (src/main.cc's run_shards(): `write_str("Failed to create listen socket
// for shard "); ...; write_error("", lfd_result.error())`, where
// write_error() renders `Error::code` -- the raw errno
// (include/rut/runtime/error.h's `from_errno`) -- as `errno=<N>`; the
// `create_listen_socket`/`bind_listener_shard` path that produces it,
// include/rut/runtime/socket.h and listener_context.h, reports EADDRINUSE
// verbatim from a failed bind()). Matches on that literal errno value rather
// than a platform-specific strerror string, the same way
// log_indicates_address_in_use() matches Envoy's own log text, so this only
// fires for the one errno a bind()/listen() collision actually produces,
// never for an unrelated startup failure that happens to also name "listen
// socket".
bool rut_log_indicates_address_in_use(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string contents = ss.str();
    return contents.find("Failed to create listen socket") != std::string::npos &&
           contents.find(std::string("errno=") + std::to_string(EADDRINUSE)) != std::string::npos;
}

// The exact bytes of an OPTIONS * request: both Envoy and every generated
// rut config answer this locally with a 404, never routing it to an
// upstream (docs/envoy-compatibility.md, "Local replies (404 for OPTIONS *
// and authority-form CONNECT)"), and the committed oracle fixture pins the
// exact downstream bytes for it (kEnvoyOracle_options_star_downstream in
// fixtures/envoy_oracle_milestone_s.inc: status 404, `server: envoy` --
// the converter mirrors Envoy's own default server_name byte for byte).
// Used below as the RUT-ownership readiness probe: a request no bootstrap
// this harness ever generates can route anywhere, so a correct answer can
// never come from an upstream having been contacted.
constexpr char kReadinessProbeRequest[] = "OPTIONS * HTTP/1.1\r\nHost: client.example\r\n\r\n";

// Reads just the status line and header block of one HTTP/1.x response from
// `fd`, bounded by `timeout_ms`. Unlike read_http_message() above, this
// never reads a body and applies none of that function's persistence/framing
// checks: it exists only to let the readiness probe below inspect a status
// code and a header, and the caller tears the connection down the instant
// the header block is captured (or the read fails) either way.
bool read_response_head(int fd, int timeout_ms, std::string* out) {
    std::string buf;
    const int64_t deadline = now_ms() + timeout_ms;
    char chunk[4096];
    for (;;) {
        const size_t header_end = buf.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            *out = buf.substr(0, header_end);
            return true;
        }
        const int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return false;
        pollfd pfd{fd, POLLIN, 0};
        if (poll(&pfd, 1, static_cast<int>(remaining)) <= 0) return false;
        const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) return false;
        buf.append(chunk, static_cast<size_t>(n));
    }
}

// Round-9 review, "Do not accept a RUT-like response as proof of
// ownership": rut_probe_confirms_ownership()'s HTTP-level probe alone cannot
// tell a genuine `rut` process apart from ANOTHER generated-rut process that
// happens to win the same probe-allocated port -- every generated rut
// config answers `kReadinessProbeRequest` with the exact same 404 +
// `server: envoy` bytes, so a foreign one still between its own failed
// bind() and exit can be mistaken for confirmed ownership. Close the gap
// with process-side evidence, the same way PR #694 closed it for Envoy
// (`log_indicates_address_in_use()`/its RUT counterpart just above): require
// rut's own captured stdout/stderr to show it actually completed its
// post-bind startup for THIS port (src/main.cc's `write_str("Listening on
// port "); write_u32(port); write_str(" with ");` line -- confirmed exact
// text) and never logged the bind-failure text
// `rut_log_indicates_address_in_use()` matches. A pure function taking the
// log's contents (not a path) so it can be exercised directly with literal
// strings, independent of any real file or process.
bool rut_log_confirms_listener(const std::string& log_contents, uint16_t port) {
    if (log_contents.find("Failed to create listen socket") != std::string::npos &&
        log_contents.find(std::string("errno=") + std::to_string(EADDRINUSE)) !=
            std::string::npos) {
        return false;
    }
    return log_contents.find(std::string("Listening on port ") + std::to_string(port) + " with") !=
           std::string::npos;
}

// wait_ready()/tcp_port_open() only prove that *some* process is now
// accepting connections on `port` -- the same limitation
// wait_ready_and_confirm_ownership() (EnvoyInstance overload, above) exists
// to close for Envoy's docker child. Unlike that child, though, a foreign
// process racing rut for a probe-allocated port has no reason to ever exit
// on its own once rut's own bind() attempt fails with EADDRINUSE: rut fails
// closed and exits, but nothing makes the FOREIGN listener go away, so the
// short "did the tracked child die during a grace period" check that works
// for Envoy's docker child cannot catch this case here -- a long-lived
// foreign listener would pass an alive-only check forever. Prove ownership
// instead by holding a real HTTP/1.1 conversation: `rut`, unlike an
// arbitrary foreign listener, answers `kReadinessProbeRequest` with a
// specific 404 (`server: envoy`) and never forwards it anywhere, so a
// correct answer can only come from the generated rut config itself
// (round-8 review, "Verify RUT owns the port before declaring readiness") --
// AND, since another generated rut process can answer identically (round-9
// review above), confirms `rut.log_path` shows the tracked child itself
// completed startup on this exact port via rut_log_confirms_listener(). A
// probe reply that matches but whose log does not (yet) confirm ownership
// falls through and retries, rather than being trusted alone: the log may
// simply not have flushed yet, or it may belong to a different, still-dying
// foreign process. Retries the whole connect+probe+alive-check cycle --
// rechecking the tracked child is still alive on every iteration, not just
// once -- until either it succeeds or `deadline_ms` (wall clock) runs out:
// rut can accept a TCP connection slightly before its own request-handling
// loop is ready to answer one.
bool rut_probe_confirms_ownership(uint16_t port, RutInstance& rut, int64_t deadline_ms) {
    while (now_ms() < deadline_ms) {
        if (rut.pid > 0) {
            int status = 0;
            const pid_t waited = waitpid(rut.pid, &status, WNOHANG);
            if (waited == rut.pid) {
                rut.pid = -1;
                return false;
            }
        }
        const int budget_ms = static_cast<int>(std::min<int64_t>(deadline_ms - now_ms(), 1000));
        if (budget_ms > 0) {
            const int fd = connect_with_timeout(port, budget_ms);
            if (fd >= 0) {
                std::string head;
                const bool answered = send_all(fd, kReadinessProbeRequest) &&
                                      read_response_head(fd, budget_ms, &head);
                close(fd);
                if (answered && starts_with(head, "HTTP/1.1 404 ") &&
                    header_equals_ci(head, "server", "envoy")) {
                    std::ifstream log_in(rut.log_path);
                    std::stringstream log_ss;
                    log_ss << log_in.rdbuf();
                    if (rut_log_confirms_listener(log_ss.str(), port)) return true;
                }
            }
        }
        struct timespec ts{0, 20'000'000};
        nanosleep(&ts, nullptr);
    }
    return false;
}

// RUT counterpart to wait_ready_and_confirm_ownership(EnvoyInstance&, ...)
// above: wait_ready() alone can be fooled by a foreign listener that already
// owns the probe-allocated port (see rut_probe_confirms_ownership()'s
// comment for why the Envoy-side grace-period trick does not transfer), so
// launch_rut_with_port_retry() below must not treat plain TCP acceptance as
// readiness. `confirm_ms` bounds the probe phase separately from
// `timeout_ms` (which wait_ready() may already have spent waiting for the
// initial TCP accept).
bool wait_ready_and_confirm_ownership(uint16_t port,
                                      RutInstance& rut,
                                      int timeout_ms,
                                      int confirm_ms,
                                      std::string* error,
                                      bool* reuseport_collision = nullptr) {
    if (!wait_ready(port, rut, timeout_ms, error)) return false;
    if (!rut_probe_confirms_ownership(port, rut, now_ms() + confirm_ms)) {
        *error =
            "did not observe rut's own HTTP local reply (404, server: envoy) on the listener "
            "port before the deadline; a different process likely won the bind race, or rut "
            "exited while this harness was confirming ownership";
        return false;
    }
    // Round-12 review, "Detect concurrent SO_REUSEPORT owners before
    // accepting readiness": `rut` sets SO_REUSEPORT on every listener it
    // binds (src/runtime/socket.cc:33-36), so a second, same-UID `rut`
    // sharing this exact port passes the probe above identically -- see
    // count_listeners_on_port()'s comment. Exactly one LISTEN row for
    // `port` is the healthy case; more than one means a co-owner exists.
    if (count_listeners_on_port(port) > 1) {
        if (reuseport_collision != nullptr) *reuseport_collision = true;
        *error = "more than one LISTEN socket is bound to port " + std::to_string(port) +
                 " (a concurrent rut process shares it via SO_REUSEPORT); a different process "
                 "likely raced this port";
        return false;
    }
    return true;
}

// RUT-side counterpart to launch_envoy_with_port_retry(), used everywhere
// this file launches `rut` against a converted milestone-S bootstrap
// (--pair-milestone-s and --self-test's RUT pass): renders a bootstrap for
// `*listen_port`/`other_port`, converts it with `converter_binary`, and
// launches `rut_binary` against the result, waiting for it to accept
// connections. RUT binds `*listen_port` itself (the port is baked into the
// generated .rut source by rut-envoy-convert, same as Envoy binding the port
// baked into its own bootstrap JSON), so like Envoy's listener port this one
// can only be probe-allocated by this harness, leaving the same bind-race
// window; when rut's own stderr names the collision
// (rut_log_indicates_address_in_use()), this retries on a freshly allocated
// port, up to kMaxListenPortAttempts attempts total -- the same "detect a
// collision ... retry with a fresh port ... print that it retried, and never
// record a failed attempt as evidence" contract as
// launch_envoy_with_port_retry() (round-6 review on PR #694, mirrored here
// for RUT). A failed attempt's process and converted source are torn down /
// left unreferenced before either retrying or returning, so nothing from it
// survives to be mistaken for evidence; only a `true` return leaves
// `rut`/`*listen_port`/`*rut_source_path` describing a live, ready `rut`
// instance backed by the bootstrap that produced it.
bool launch_rut_with_port_retry(const std::string& dir,
                                const std::string& rut_binary,
                                const std::string& converter_binary,
                                uint16_t* listen_port,
                                uint16_t other_port,
                                std::string* rut_source_path,
                                RutInstance* rut,
                                std::string* error) {
    const std::string bootstrap_path = dir + "/bootstrap-rut.json";
    for (int attempt = 1; attempt <= kMaxListenPortAttempts; attempt++) {
        if (!write_file_mode(bootstrap_path, render_bootstrap(*listen_port, other_port), 0644)) {
            *error = "could not write bootstrap.json";
            return false;
        }
        *rut_source_path = dir + "/out-attempt" + std::to_string(attempt) + ".rut";
        std::string convert_stderr;
        if (!run_converter_to_file(
                converter_binary, bootstrap_path, *rut_source_path, &convert_stderr)) {
            *error = "rut-envoy-convert did not exit 0 with warnings-only stderr";
            if (!convert_stderr.empty()) *error += "; stderr: " + convert_stderr;
            return false;
        }
        rut->log_path = dir + "/rut-attempt" + std::to_string(attempt) + ".log";
        if (!rut->launch(rut_binary, *rut_source_path)) {
            *error = "could not fork/exec rut";
            return false;
        }
        bool reuseport_collision = false;
        if (wait_ready_and_confirm_ownership(
                *listen_port, *rut, 15'000, 5'000, error, &reuseport_collision))
            return true;

        // Round-12 review, "Detect concurrent SO_REUSEPORT owners before
        // accepting readiness": a co-owner detected by
        // count_listeners_on_port() never leaves rut's own log naming an
        // address-in-use collision (its bind() genuinely succeeded), so
        // that signal alone is folded into `collided` here to take the
        // same retry-on-a-fresh-port path as a real bind collision.
        const bool collided =
            reuseport_collision || rut_log_indicates_address_in_use(rut->log_path);
        rut->stop();
        if (!collided || attempt == kMaxListenPortAttempts) return false;

        uint16_t fresh_port = 0;
        if (!allocate_loopback_port(&fresh_port)) {
            *error = "could not allocate a replacement loopback port after a bind collision";
            return false;
        }
        std::cerr << "RETRY: rut listener port " << *listen_port
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
        std::vector<CaseSpec> asserted_cases, record_only_cases;
        split_asserted_and_record_only(cases, &asserted_cases, &record_only_cases);

        auto run_and_collect = [&](const std::vector<CaseSpec>& subset) {
            for (const auto& spec : subset) {
                CaseResult r;
                if (!run_client_case(listen_port1, spec, &r))
                    std::cerr << "WARN: case " << spec.name
                              << " exchange did not complete cleanly ("
                              << describe_incomplete_exchange(r) << ")\n";
                results.push_back(std::move(r));
            }
        };
        auto attribute_upstream = [&](const std::vector<CaseSpec>& subset, size_t begin) {
            for (size_t i = begin; i < results.size(); i++) {
                auto& r = results[i];
                const auto it = std::find_if(subset.begin(), subset.end(), [&](const CaseSpec& s) {
                    return r.name == s.name;
                });
                if (it == subset.end()) continue;
                const auto observed = upstream.requests_for(it->upstream_path);
                r.upstream_contact_count = static_cast<int>(observed.size());
                if (!observed.empty()) {
                    r.upstream_contacted = true;
                    r.upstream_bytes = observed.front();
                }
            }
        };
        // Round-11 review, "Attribute duplicate contacts to the originating
        // case": run the asserted cases to completion and attribute their
        // upstream evidence FIRST, then reset the recording upstream's log
        // before running the record-only cases as a second, isolated batch
        // on this same Envoy instance. Without this, a record-only request
        // that lands on (or is misattributed to) an asserted case's own
        // expected path -- e.g. a forged-header case misrouted onto
        // `/smoke` -- would inflate that asserted case's contact count into
        // a false duplicate, and validate_results() below fails the whole
        // run unconditionally on any count > 1, contradicting the CLI's
        // "record-only never affects the exit code" contract.
        const size_t asserted_begin = results.size();
        run_and_collect(asserted_cases);
        attribute_upstream(asserted_cases, asserted_begin);
        upstream.clear_requests();
        const size_t record_only_begin = results.size();
        run_and_collect(record_only_cases);
        attribute_upstream(record_only_cases, record_only_begin);

        if (!envoy.stop()) {
            std::cerr << "FAIL: envoy exited unexpectedly before teardown ("
                      << envoy.unexpected_exit_description << ")\n";
            dump_log(envoy.log_path);
            return 1;
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
            std::cerr << "WARN: case connect_failure exchange did not complete cleanly ("
                      << describe_incomplete_exchange(r) << ")\n";
        // The connect-failure exchange is now complete; only past this point
        // is it safe to release the reservation on `closed_port` (round-7
        // review, "Keep the connect-failure port reserved").
        close(closed_reserved.fd);
        r.name = "connect_failure";  // run_client_case sets this from `spec` ("get_smoke");
                                     // override after the call, not before.
        r.upstream_contacted = false;
        results.push_back(std::move(r));
        if (!envoy.stop()) {
            std::cerr << "FAIL: envoy exited unexpectedly before teardown ("
                      << envoy.unexpected_exit_description << ")\n";
            dump_log(envoy.log_path);
            return 1;
        }
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
// `CaseResult::exchange_complete`), both upstream and downstream bytes agree
// (downstream compared after `normalize_date_for_compare`, everything else
// byte for byte), AND -- for every case except the two named in
// `case_expects_upstream_forward` -- both sides actually contacted the
// upstream exactly once. Two exchanges that both failed identically (e.g. a
// connection refused on both sides yielding two empty buffers, or the
// recording upstream itself becoming unavailable and both proxies answering
// with matching, fully framed local error responses) must never report
// MATCH: that would let the harness pass without ever exercising forwarding
// at all.
bool compare_pair_case(const PairCaseResult& c) {
    const std::string preserved_date =
        c.name == "get_upstream_date_server" ? "Mon, 01 Jan 2024 00:00:00 GMT" : std::string();
    bool envoy_dates_valid = true;
    bool rut_dates_valid = true;
    const std::string envoy_down =
        normalize_date_for_compare(c.envoy.downstream_bytes, preserved_date, &envoy_dates_valid);
    const std::string rut_down =
        normalize_date_for_compare(c.rut.downstream_bytes, preserved_date, &rut_dates_valid);
    const bool both_complete = c.envoy.exchange_complete && c.rut.exchange_complete;
    const bool dates_valid = envoy_dates_valid && rut_dates_valid;
    const bool upstream_match = c.envoy.upstream_contacted == c.rut.upstream_contacted &&
                                c.envoy.upstream_bytes == c.rut.upstream_bytes;
    const bool expects_forward = case_expects_upstream_forward(c.name);
    // A forwarding case must show exactly one contact on both sides; an
    // exempt case (options_star, connect_failure, connect_authority) must
    // show exactly ZERO -- not merely "don't care" -- so that if both
    // proxies unexpectedly forwarded one of these (e.g. `options_star`
    // routed to an upstream that happens to answer identically on both
    // sides) the mismatch in what was supposed to stay local is still
    // caught instead of silently reported as MATCH (round-8 review,
    // "Require zero contacts for locally handled cases").
    const bool forwarding_exercised =
        expects_forward
            ? (c.envoy.upstream_contact_count == 1 && c.rut.upstream_contact_count == 1)
            : (c.envoy.upstream_contact_count == 0 && c.rut.upstream_contact_count == 0);
    const bool downstream_match = envoy_down == rut_down;
    const bool match =
        both_complete && dates_valid && upstream_match && forwarding_exercised && downstream_match;
    std::cerr << (match ? "MATCH    [" : "MISMATCH [") << c.name << "]"
              << (c.asserted ? " (asserted)" : " (record-only)") << "\n";
    if (!both_complete) {
        std::cerr << "  incomplete exchange: envoy="
                  << (c.envoy.exchange_complete
                          ? "yes"
                          : "no (" + describe_incomplete_exchange(c.envoy) + ")")
                  << " rut="
                  << (c.rut.exchange_complete ? "yes"
                                              : "no (" + describe_incomplete_exchange(c.rut) + ")")
                  << "\n";
    }
    if (!dates_valid) {
        std::cerr << "  malformed synthesized Date (not a 29-byte RFC 1123 value): envoy="
                  << (envoy_dates_valid ? "ok" : "invalid")
                  << " rut=" << (rut_dates_valid ? "ok" : "invalid") << "\n";
    }
    if (!upstream_match) {
        std::cerr << "  upstream envoy: \"" << escape_wire_bytes(c.envoy.upstream_bytes) << "\"\n";
        std::cerr << "  upstream rut:   \"" << escape_wire_bytes(c.rut.upstream_bytes) << "\"\n";
    }
    if (!forwarding_exercised) {
        std::cerr << "  forwarding not exercised: envoy upstream_contact_count="
                  << c.envoy.upstream_contact_count
                  << " rut upstream_contact_count=" << c.rut.upstream_contact_count
                  << (expects_forward ? " (expected exactly 1 on each side)\n"
                                      : " (expected exactly 0 on each side; this case is exempt "
                                        "from forwarding)\n");
    }
    if (!downstream_match) {
        std::cerr << "  downstream envoy: \"" << escape_wire_bytes(envoy_down) << "\"\n";
        std::cerr << "  downstream rut:   \"" << escape_wire_bytes(rut_down) << "\"\n";
    }
    return match;
}

// Round-12 review, "Prevent record-only crashes from failing pair mode":
// classifies a proxy `stop()` failure observed by either phase of
// run_pair_milestone_s() -- called ONLY after that phase's asserted batch
// has already run to completion and had its own upstream evidence captured
// and validated (`fill_upstream_bytes()` for `asserted_cases`, which stays
// fatal on its own) -- as a non-fatal NOTE rather than a hard failure. A
// proxy crash that happened during (or before) the asserted batch is
// already caught independently: the affected asserted case's own exchange
// would be incomplete, which compare_pair_case()'s `both_complete` check
// turns into an asserted MISMATCH regardless of this function. So a
// `stop()` failure reaching here can only mean the proxy died during or
// after the record-only batch, which the CLI contract says must never gate
// acceptance (`any_asserted_mismatch` in run_pair_milestone_s()) -- note it
// and mark every record-only result ambiguous instead.
void note_record_only_phase_crash(const char* proxy_label,
                                  const std::string& unexpected_exit_description,
                                  std::vector<CaseResult>* record_only_results) {
    std::cerr << "NOTE: " << proxy_label
              << " exited unexpectedly during or after the record-only batch ("
              << unexpected_exit_description
              << "); asserted evidence was already captured, so this does not fail the run\n";
    for (auto& r : *record_only_results) r.upstream_ambiguous = true;
}

int run_pair_milestone_s(const std::string& rut_binary,
                         const std::string& converter_binary,
                         const std::string& transcript_path) {
    const std::string missing = check_docker_prerequisites();
    if (!missing.empty()) return missing_prerequisite(missing);

    // The recording upstream's port is reserved end to end, the same way
    // run_oracle_milestone_s() reserves it (round-6 review, "Keep allocated
    // ports reserved until their consumers bind"): this process binds and
    // listens on it right here and keeps that same socket alive until
    // RecordingUpstream::adopt() takes it over below, so no other process can
    // ever grab it out from under us. Envoy's two listener ports can only be
    // probe-allocated (Envoy binds its own port inside the container), so
    // they still go through allocate_distinct_ports() below; probe
    // allocation naturally never returns a still-bound port. The
    // connect_failure case's "closed" port is likewise reserved end to end
    // via allocate_reserved_closed_port(), exactly as run_oracle_milestone_s()
    // does: it stays bound but non-listening (never probed-and-released) so
    // no other host process can claim it before either side's run-2 connect
    // attempt (round-7 review, "Keep the connect-failure port reserved").
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
    // The reservation must outlive BOTH sides' run-2 connect attempts, and
    // this function has many early-return failure paths between here and
    // there; release it from a guard rather than at every one of them (run 2
    // below also releases it explicitly once its exchanges are done).
    struct ClosedPortReservation {
        int fd;
        ~ClosedPortReservation() {
            if (fd >= 0) close(fd);
        }
        void release() {
            if (fd >= 0) close(fd);
            fd = -1;
        }
    } closed_reservation{closed_reserved.fd};
    const uint16_t closed_port = closed_reserved.port;

    uint16_t listen_port1 = 0, listen_port2 = 0;
    if (!allocate_distinct_ports({&listen_port1, &listen_port2})) {
        std::cerr << "FAIL: could not allocate loopback ports\n";
        close(upstream_bound.fd);
        return 1;
    }

    std::vector<PairCaseResult> comparisons;

    // ---- Run 1: live recording upstream, Envoy then RUT, same ports ----
    {
        TempDir dir("rut-envoy-pair");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            return 1;
        }
        RecordingUpstream upstream;
        const auto cases = run1_cases();
        std::vector<CaseSpec> asserted_cases, record_only_cases;
        split_asserted_and_record_only(cases, &asserted_cases, &record_only_cases);
        for (const auto& spec : cases) upstream.set_reply(spec.upstream_path, spec.upstream_reply);
        if (!upstream.adopt(upstream_bound.fd)) {
            std::cerr << "FAIL: could not start recording upstream\n";
            return 1;
        }

        // Envoy first, through the same bind-collision retry oracle mode
        // uses: Envoy binds `listen_port1` itself inside the container, so
        // another process can take the probe-allocated number first;
        // launch_envoy_with_port_retry() renders the bootstrap, detects the
        // collision in Envoy's log, re-renders on a fresh port and retries,
        // updating `listen_port1` so the RUT launch below (which re-renders
        // and re-converts from the same variable) and wait_port_closed()
        // follow it (round-7 review, "Route pair-mode Envoy starts through
        // the retry helper").
        //
        // Round-15 review, "Isolate record-only cases before ignoring proxy
        // crashes": the asserted and record-only batches now each get their
        // OWN Envoy instance (and, below, their own RUT instance), launched
        // and torn down in full before the next one starts. A single shared
        // instance's stop() failure, observed only after BOTH batches had
        // run, could not be safely attributed to either one -- a crash
        // actually triggered by an asserted request (e.g. during connection
        // cleanup, after its response was already captured) could be
        // wrongly downgraded to a non-fatal record-only NOTE just because it
        // was only OBSERVED after the record-only batch ran. A dedicated
        // instance per batch means whichever instance's stop() fails can
        // only ever have seen that batch's own traffic, so the asserted
        // instance's stop() failure stays fatal and the record-only
        // instance's stays a NOTE.
        std::string ready_error;
        EnvoyInstance envoy_asserted;
        if (!launch_envoy_with_port_retry(dir.path(),
                                          "pair-run1-asserted",
                                          &listen_port1,
                                          upstream_port1,
                                          &envoy_asserted,
                                          &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy_asserted.log_path);
            upstream.stop();
            return 1;
        }
        // Round-11 review, "Attribute duplicate contacts to the originating
        // case": run the asserted cases against this Envoy instance first
        // and attribute their upstream evidence while the log holds only
        // their own traffic; the record-only cases run against a separate
        // instance below, after this one is fully stopped and validated, on
        // a freshly-cleared log -- see split_asserted_and_record_only()'s
        // comment for why. Applied identically to the RUT phase below.
        auto envoy_asserted_results = run_case_batch(listen_port1, asserted_cases);
        if (!fill_upstream_bytes(&envoy_asserted_results, asserted_cases, upstream)) {
            envoy_asserted.stop();
            upstream.stop();
            return 1;
        }
        if (!envoy_asserted.stop()) {
            std::cerr << "FAIL: envoy exited unexpectedly before teardown ("
                      << envoy_asserted.unexpected_exit_description << ")\n";
            dump_log(envoy_asserted.log_path);
            upstream.stop();
            return 1;
        }
        if (!wait_port_closed(listen_port1, 5000)) {
            std::cerr << "FAIL: listener port " << listen_port1
                      << " did not become free after stopping the asserted-batch Envoy instance\n";
            upstream.stop();
            return 1;
        }
        upstream.clear_requests();

        EnvoyInstance envoy_record_only;
        if (!launch_envoy_with_port_retry(dir.path(),
                                          "pair-run1-record-only",
                                          &listen_port1,
                                          upstream_port1,
                                          &envoy_record_only,
                                          &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy_record_only.log_path);
            upstream.stop();
            return 1;
        }
        auto envoy_record_only_results = run_case_batch(listen_port1, record_only_cases);
        // Never fatal here: none of `record_only_cases` is an asserted case,
        // so fill_upstream_bytes() cannot return false for this call (see
        // its "Either anomaly ... is only made fatal ... for an asserted
        // case" comment) -- the return value needs no check.
        fill_upstream_bytes(&envoy_record_only_results, record_only_cases, upstream);
        // This instance only ever ran the record-only batch, so a stop()
        // failure here is unambiguously attributable to it (round-12/
        // round-15 review).
        if (!envoy_record_only.stop()) {
            dump_log(envoy_record_only.log_path);
            note_record_only_phase_crash(
                "envoy", envoy_record_only.unexpected_exit_description, &envoy_record_only_results);
        }
        if (!wait_port_closed(listen_port1, 5000)) {
            std::cerr << "FAIL: listener port " << listen_port1
                      << " did not become free after stopping the record-only-batch Envoy "
                         "instance\n";
            upstream.stop();
            return 1;
        }
        upstream.clear_requests();
        auto envoy_results = std::move(envoy_asserted_results);
        envoy_results.insert(envoy_results.end(),
                             std::make_move_iterator(envoy_record_only_results.begin()),
                             std::make_move_iterator(envoy_record_only_results.end()));

        // Then RUT, on the same ports, against the same (now-cleared)
        // recording upstream. RUT's listener port has the same bind-race
        // exposure Envoy's did just above (this process can only
        // probe-allocate it, since RUT itself owns the eventual bind() --
        // launch_rut_with_port_retry() re-renders/re-converts the bootstrap
        // on a fresh port and retries, same contract as
        // launch_envoy_with_port_retry(), and never leaves a failed
        // attempt's process or log to be mistaken for evidence. Same
        // per-batch instance isolation as the Envoy phase above (round-15
        // review).
        RutInstance rut_asserted;
        std::string rut_source_path;
        std::string rut_ready_error;
        if (!launch_rut_with_port_retry(dir.path(),
                                        rut_binary,
                                        converter_binary,
                                        &listen_port1,
                                        upstream_port1,
                                        &rut_source_path,
                                        &rut_asserted,
                                        &rut_ready_error)) {
            std::cerr << "FAIL: " << rut_ready_error << "\n";
            dump_rut_log(rut_asserted.log_path);
            upstream.stop();
            return 1;
        }
        auto rut_asserted_results = run_case_batch(listen_port1, asserted_cases);
        const bool rut_asserted_fill_ok =
            fill_upstream_bytes(&rut_asserted_results, asserted_cases, upstream);
        const bool rut_asserted_stopped_cleanly = rut_asserted.stop();
        if (!rut_asserted_fill_ok) {
            upstream.stop();
            return 1;
        }
        if (!rut_asserted_stopped_cleanly) {
            std::cerr << "FAIL: rut exited unexpectedly before teardown ("
                      << rut_asserted.unexpected_exit_description << ")\n";
            dump_rut_log(rut_asserted.log_path);
            upstream.stop();
            return 1;
        }
        if (!wait_port_closed(listen_port1, 5000)) {
            std::cerr << "FAIL: listener port " << listen_port1
                      << " did not become free after stopping the asserted-batch RUT instance\n";
            upstream.stop();
            return 1;
        }
        upstream.clear_requests();

        RutInstance rut_record_only;
        std::string rut_record_only_source_path;
        std::string rut_record_only_ready_error;
        if (!launch_rut_with_port_retry(dir.path(),
                                        rut_binary,
                                        converter_binary,
                                        &listen_port1,
                                        upstream_port1,
                                        &rut_record_only_source_path,
                                        &rut_record_only,
                                        &rut_record_only_ready_error)) {
            std::cerr << "FAIL: " << rut_record_only_ready_error << "\n";
            dump_rut_log(rut_record_only.log_path);
            upstream.stop();
            return 1;
        }
        auto rut_record_only_results = run_case_batch(listen_port1, record_only_cases);
        // Never fatal here, same reasoning as the Envoy phase above.
        fill_upstream_bytes(&rut_record_only_results, record_only_cases, upstream);
        const bool rut_record_only_stopped_cleanly = rut_record_only.stop();
        upstream.stop();
        // This instance only ever ran the record-only batch, so a stop()
        // failure here is unambiguously attributable to it (round-12/
        // round-15 review).
        if (!rut_record_only_stopped_cleanly) {
            dump_rut_log(rut_record_only.log_path);
            note_record_only_phase_crash(
                "rut", rut_record_only.unexpected_exit_description, &rut_record_only_results);
        }
        auto rut_results = std::move(rut_asserted_results);
        rut_results.insert(rut_results.end(),
                           std::make_move_iterator(rut_record_only_results.begin()),
                           std::make_move_iterator(rut_record_only_results.end()));

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
        TempDir dir("rut-envoy-pair2");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            return 1;
        }
        const CaseSpec spec = connect_failure_case();

        // Same bind-collision retry as run 1 (round-7 review); a retry moves
        // `listen_port2`, which the RUT launch below then follows.
        EnvoyInstance envoy;
        std::string ready_error;
        if (!launch_envoy_with_port_retry(
                dir.path(), "pair-run2", &listen_port2, closed_port, &envoy, &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy.log_path);
            return 1;
        }
        PairCaseResult c;
        c.name = "connect_failure";
        c.asserted = true;
        if (!run_client_case(listen_port2, spec, &c.envoy))
            std::cerr << "WARN: case connect_failure (envoy) exchange did not complete cleanly ("
                      << describe_incomplete_exchange(c.envoy) << ")\n";
        c.envoy.name = "connect_failure";
        if (!envoy.stop()) {
            std::cerr << "FAIL: envoy exited unexpectedly before teardown ("
                      << envoy.unexpected_exit_description << ")\n";
            dump_log(envoy.log_path);
            return 1;
        }
        if (!wait_port_closed(listen_port2, 5000)) {
            std::cerr << "FAIL: listener port " << listen_port2
                      << " did not become free after stopping Envoy\n";
            return 1;
        }

        RutInstance rut;
        std::string rut_source_path;
        std::string rut_ready_error;
        if (!launch_rut_with_port_retry(dir.path(),
                                        rut_binary,
                                        converter_binary,
                                        &listen_port2,
                                        closed_port,
                                        &rut_source_path,
                                        &rut,
                                        &rut_ready_error)) {
            std::cerr << "FAIL: " << rut_ready_error << "\n";
            dump_rut_log(rut.log_path);
            return 1;
        }
        if (!run_client_case(listen_port2, spec, &c.rut))
            std::cerr << "WARN: case connect_failure (rut) exchange did not complete cleanly ("
                      << describe_incomplete_exchange(c.rut) << ")\n";
        c.rut.name = "connect_failure";
        if (!rut.stop()) {
            std::cerr << "FAIL: rut exited unexpectedly before teardown ("
                      << rut.unexpected_exit_description << ")\n";
            dump_rut_log(rut.log_path);
            return 1;
        }

        // Both sides' connect-failure exchanges are now complete; only past
        // this point is it safe to release the reservation on `closed_port`
        // (round-7 review, "Keep the connect-failure port reserved").
        closed_reservation.release();

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
        const ReadResult resp3 = read_http_message(
            fd, /*head_request=*/true, kClientTimeoutMs, /*client_requested_close=*/true);
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
// it captured, and write_transcript()/write_pair_transcript() must refuse to
// write anything (no output file at all) when any case -- or, for the pair
// transcript, either side of any case -- is incomplete or the upstream was
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

        // write_pair_transcript(): the same rule applies to EITHER side of a
        // pair case (round-3 review, applied uniformly via
        // validate_pair_results() so the pair transcript can't smuggle in
        // evidence write_transcript would have refused).
        const std::string pair_out_path = dir.path() + "/pair_transcript.inc";

        PairCaseResult incomplete_pair;
        incomplete_pair.name = "bad_incomplete_pair";
        incomplete_pair.asserted = true;
        incomplete_pair.envoy = good;
        incomplete_pair.rut = good;
        incomplete_pair.rut.exchange_complete = false;
        if (write_pair_transcript(pair_out_path, {incomplete_pair})) {
            std::cerr << "FAIL [self-test partial]: write_pair_transcript accepted an "
                         "incomplete rut exchange\n";
            ok = false;
        }
        if (stat(pair_out_path.c_str(), &st) == 0) {
            std::cerr << "FAIL [self-test partial]: write_pair_transcript left a file behind "
                         "for a rejected incomplete-exchange run\n";
            ok = false;
        }

        PairCaseResult duplicated_pair;
        duplicated_pair.name = "bad_duplicate_pair";
        duplicated_pair.asserted = true;
        duplicated_pair.envoy = good;
        duplicated_pair.envoy.upstream_contact_count = 2;
        duplicated_pair.rut = good;
        if (write_pair_transcript(pair_out_path, {duplicated_pair})) {
            std::cerr << "FAIL [self-test partial]: write_pair_transcript accepted a "
                         "duplicated envoy upstream contact\n";
            ok = false;
        }
        if (stat(pair_out_path.c_str(), &st) == 0) {
            std::cerr << "FAIL [self-test partial]: write_pair_transcript left a file behind "
                         "for a rejected duplicate-contact run\n";
            ok = false;
        }

        PairCaseResult good_pair;
        good_pair.name = "ok_pair";
        good_pair.asserted = true;
        good_pair.envoy = good;
        good_pair.rut = good;
        if (!write_pair_transcript(pair_out_path, {good_pair})) {
            std::cerr << "FAIL [self-test partial]: write_pair_transcript rejected a fully "
                         "valid run\n";
            ok = false;
        }

        // Round-8 review, "Keep record-only transcript failures out of
        // acceptance": a record-only row's incomplete exchange must NOT make
        // write_pair_transcript() fail the way an asserted row's does above,
        // and the incompleteness must still show up in the output as a NOTE
        // rather than being silently hidden.
        PairCaseResult incomplete_record_only;
        incomplete_record_only.name = "connect_authority";
        incomplete_record_only.asserted = false;
        incomplete_record_only.envoy = good;
        incomplete_record_only.rut = good;
        incomplete_record_only.rut.exchange_complete = false;
        if (!write_pair_transcript(pair_out_path, {incomplete_record_only})) {
            std::cerr << "FAIL [self-test partial]: write_pair_transcript rejected a record-only "
                         "row with an incomplete exchange (record-only rows must never fail the "
                         "run)\n";
            ok = false;
        } else {
            std::ifstream in(pair_out_path);
            std::stringstream ss;
            ss << in.rdbuf();
            if (ss.str().find("NOTE: connect_authority (rut): downstream exchange did not "
                              "complete") == std::string::npos) {
                std::cerr << "FAIL [self-test partial]: write_pair_transcript did not flag the "
                             "incomplete record-only row with a NOTE\n";
                ok = false;
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
// (used by run_and_wait()/EnvoyInstance::launch()/RutInstance::launch()/
// run_converter_to_file()) must actually work end-to-end.
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
//
// Deliberately does NOT close an accepted connection right after replying:
// neither the canned reply nor the probe's request carries `Connection:
// close`, so a real HTTP/1.1 peer -- including the real Envoy this fake
// stands in for -- leaves it open. read_http_message()'s persistence checks
// (round-6/7/8 reviews on this file: reject trailing bytes, an EOF, or a
// reset on a response that never advertised close) correctly tell such an
// early close apart from a well-behaved persistent peer; closing immediately
// here would make every probe against this fake look like exactly the kind
// of broken persistence those checks exist to catch, rather than the
// well-formed-vs-malformed-reply distinction this fake is actually for.
// Every accepted connection is instead tracked and closed from stop().
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
        std::vector<int> fds;
        {
            std::lock_guard<std::mutex> lock(mu_);
            fds.swap(accepted_fds_);
        }
        for (const int fd : fds) close(fd);
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
            std::lock_guard<std::mutex> lock(mu_);
            accepted_fds_.push_back(fd);
        }
    }

    int listen_fd_ = -1;
    std::mutex mu_;
    std::vector<int> accepted_fds_;
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

// RUT counterpart to self_test_wait_ready_ownership() above, covering
// round-8 review, "Verify RUT owns the port before declaring readiness": an
// alive-only check (the Envoy-side fix) is not enough for rut, because
// nothing forces a foreign listener that races rut for a port to ever exit
// on its own. Both cases here keep the tracked "rut" child alive for the
// WHOLE confirmation window -- an alive-only check would wrongly confirm
// ownership in the negative case below -- so only the protocol probe itself
// (rut_probe_confirms_ownership()) can tell the two apart.
bool self_test_rut_wait_ready_ownership() {
    bool ok = true;

    // Negative case: a foreign listener answers every request with a
    // well-formed but non-rut response (200, `Server: not-envoy`) while the
    // dummy child stays alive throughout. Ownership must NOT be confirmed:
    // an alive-only check would be fooled by exactly this shape.
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not allocate a "
                         "loopback port\n";
            return false;
        }
        RecordingUpstream fake;
        fake.set_default_reply("HTTP/1.1 200 OK\r\nServer: not-envoy\r\nContent-Length: 0\r\n\r\n");
        if (!fake.adopt(foreign.fd)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not start the fake "
                         "foreign listener\n";
            close(foreign.fd);
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: fork failed\n";
            ok = false;
        } else if (child == 0) {
            struct timespec ts{5, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        } else {
            RutInstance rut;
            rut.pid = child;
            std::string error;
            const bool confirmed =
                wait_ready_and_confirm_ownership(foreign.port, rut, 2000, 800, &error);
            if (confirmed) {
                std::cerr << "FAIL [self-test rut wait_ready ownership]: confirmed ownership of "
                             "a foreign listener answering a non-rut response while the tracked "
                             "child stayed alive\n";
                ok = false;
            }
            if (error.empty()) {
                std::cerr << "FAIL [self-test rut wait_ready ownership]: expected a non-empty "
                             "error on the negative case\n";
                ok = false;
            }
            kill(child, SIGKILL);
            int status = 0;
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
        }
        fake.stop();
    }

    // Round-9 review, "Do not accept a RUT-like response as proof of
    // ownership": a foreign listener that answers EXACTLY like a generated
    // rut config would (404, `server: envoy`) -- e.g. another generated rut
    // process that won the same probe-allocated port and is still between
    // its own failed bind() and exit -- must NOT confirm ownership on the
    // probe reply alone when the tracked child's own log never shows it
    // completed startup on this port. Distinguishes this case from the
    // positive case below purely by the log's contents, proving the
    // rejection comes from rut_log_confirms_listener(), not the probe.
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not allocate a "
                         "loopback port\n";
            return false;
        }
        RecordingUpstream fake;
        fake.set_default_reply(
            "HTTP/1.1 404 Not Found\r\ndate: Thu, 24 Sep 2026 18:18:42 GMT\r\nserver: "
            "envoy\r\ncontent-length: 0\r\n\r\n");
        if (!fake.adopt(foreign.fd)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not start the fake "
                         "RUT-like listener\n";
            close(foreign.fd);
            return false;
        }
        const std::string dir = make_temp_dir("rut-selftest-ownership-nolog");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not create temp "
                         "directory\n";
            fake.stop();
            return false;
        }
        const std::string log_path = dir + "/rut.log";
        // Deliberately never mentions "Listening on port" for this port: the
        // tracked "rut" child (the dummy fork below) never actually wrote
        // this log, standing in for a still-starting or foreign process
        // whose log gives no evidence of owning `foreign.port`.
        if (!write_file_mode(log_path, "rut: starting up\n", 0644)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not write the fake log "
                         "file\n";
            fake.stop();
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: fork failed\n";
            ok = false;
        } else if (child == 0) {
            struct timespec ts{5, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        } else {
            RutInstance rut;
            rut.pid = child;
            rut.log_path = log_path;
            std::string error;
            const bool confirmed =
                wait_ready_and_confirm_ownership(foreign.port, rut, 2000, 800, &error);
            if (confirmed) {
                std::cerr << "FAIL [self-test rut wait_ready ownership]: confirmed ownership of a "
                             "RUT-like reply with no confirming startup log\n";
                ok = false;
            }
            if (error.empty()) {
                std::cerr << "FAIL [self-test rut wait_ready ownership]: expected a non-empty "
                             "error on the no-confirming-log case\n";
                ok = false;
            }
            kill(child, SIGKILL);
            int status = 0;
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
        }
        fake.stop();
    }

    // Positive case: the foreign listener answers exactly like a generated
    // rut config would (404, `server: envoy`) AND the tracked "rut" child's
    // log shows it completed startup on this exact port, so ownership must
    // be confirmed even though nothing here is a real `rut` process --
    // proving the probe checks the RESPONSE plus the log, not the process
    // identity.
    {
        BoundPort foreign;
        if (!allocate_bound_loopback_port(&foreign)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not allocate a "
                         "loopback port\n";
            return false;
        }
        RecordingUpstream fake;
        fake.set_default_reply(
            "HTTP/1.1 404 Not Found\r\ndate: Thu, 24 Sep 2026 18:18:42 GMT\r\nserver: "
            "envoy\r\ncontent-length: 0\r\n\r\n");
        if (!fake.adopt(foreign.fd)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not start the fake "
                         "positive listener\n";
            close(foreign.fd);
            return false;
        }
        const std::string dir = make_temp_dir("rut-selftest-ownership-log");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not create temp "
                         "directory\n";
            fake.stop();
            return false;
        }
        const std::string log_path = dir + "/rut.log";
        // The exact post-bind startup text src/main.cc writes
        // (write_str("Listening on port "); write_u32(port); write_str("
        // with "); write_u32(shard_count); write_str(" shard(s)\n");), for
        // this test's `foreign.port`.
        if (!write_file_mode(
                log_path,
                "Listening on port " + std::to_string(foreign.port) + " with 1 shard(s)\n",
                0644)) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: could not write the fake log "
                         "file\n";
            fake.stop();
            return false;
        }
        const pid_t child = fork();
        if (child < 0) {
            std::cerr << "FAIL [self-test rut wait_ready ownership]: fork failed\n";
            ok = false;
        } else if (child == 0) {
            struct timespec ts{5, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        } else {
            RutInstance rut;
            rut.pid = child;
            rut.log_path = log_path;
            std::string error;
            const bool confirmed =
                wait_ready_and_confirm_ownership(foreign.port, rut, 2000, 800, &error);
            if (!confirmed) {
                std::cerr << "FAIL [self-test rut wait_ready ownership]: did not confirm "
                             "ownership for a foreign listener answering exactly like rut would "
                             "with a confirming log: "
                          << error << "\n";
                ok = false;
            }
            if (fake.all_requests().count("*") == 0) {
                std::cerr << "FAIL [self-test rut wait_ready ownership]: the probe never reached "
                             "the fake listener at all\n";
                ok = false;
            }
            kill(child, SIGKILL);
            int status = 0;
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
        }
        fake.stop();
    }

    if (ok) std::cerr << "PASS [self-test rut wait_ready ownership]\n";
    return ok;
}

// Round-9 review, "Do not accept a RUT-like response as proof of
// ownership": exercises rut_log_confirms_listener() directly against three
// literal log shapes, independent of any real process, socket or file.
bool self_test_rut_log_confirms_listener() {
    bool ok = true;
    const uint16_t port = 54321;
    if (!rut_log_confirms_listener("Listening on port 54321 with 1 shard(s)\n", port)) {
        std::cerr << "FAIL [self-test rut log confirms listener]: rejected a log with the exact "
                     "startup line for this port\n";
        ok = false;
    }
    if (rut_log_confirms_listener("rut: starting up\n", port)) {
        std::cerr << "FAIL [self-test rut log confirms listener]: accepted a log missing the "
                     "startup line entirely\n";
        ok = false;
    }
    if (rut_log_confirms_listener(
            "Failed to create listen socket (errno=" + std::to_string(EADDRINUSE) +
                ", source=0)\nListening on port 54321 with 1 shard(s)\n",
            port)) {
        std::cerr << "FAIL [self-test rut log confirms listener]: accepted a log naming "
                     "EADDRINUSE even though the startup line was also present\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test rut log confirms listener]\n";
    return ok;
}

// Round-12 review, "Detect concurrent SO_REUSEPORT owners before accepting
// readiness": exercises count_listeners_on_port(const std::string&,
// uint16_t) directly against synthetic /proc/net/tcp[6]-shaped tables,
// independent of the real /proc filesystem -- an empty table, a single
// LISTEN row, two LISTEN rows on the same port (the reuseport-group shape,
// alongside a non-LISTEN row and a different-port row that must not be
// counted), and a tcp6-shaped v4-mapped row.
bool self_test_count_listeners_on_port() {
    bool ok = true;
    const char* kHeader =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
        "timeout inode\n";
    {
        const int count = count_listeners_on_port(std::string(kHeader), 0x1F90);
        if (count != 0) {
            std::cerr << "FAIL [self-test count listeners]: header-only table reported " << count
                      << ", expected 0\n";
            ok = false;
        }
    }
    {
        const std::string table =
            std::string(kHeader) +
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  "
            "      0 12345 1 0000000000000000 100 0 0 10 0\n";
        const int count = count_listeners_on_port(table, 0x1F90);
        if (count != 1) {
            std::cerr << "FAIL [self-test count listeners]: single-listener table reported "
                      << count << ", expected 1\n";
            ok = false;
        }
    }
    {
        // Row 0 and row 1: two LISTEN sockets sharing port 0x1F90 (the
        // reuseport-group shape). Row 2: an ESTABLISHED (st 01) row on the
        // same port, which must not count. Row 3: a LISTEN row on a
        // different port (0x2710), which must not count either.
        const std::string table =
            std::string(kHeader) +
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  "
            "      0 12345 1 0000000000000000 100 0 0 10 0\n"
            "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  "
            "      0 12346 1 0000000000000000 100 0 0 10 0\n"
            "   2: 0100007F:1F90 0200007F:1234 01 00000000:00000000 00:00000000 00000000  1000  "
            "      0 12347 1 0000000000000000 100 0 0 10 0\n"
            "   3: 0100007F:2710 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  "
            "      0 12348 1 0000000000000000 100 0 0 10 0\n";
        const int count = count_listeners_on_port(table, 0x1F90);
        if (count != 2) {
            std::cerr << "FAIL [self-test count listeners]: two-owner table reported " << count
                      << ", expected 2\n";
            ok = false;
        }
    }
    {
        // tcp6-shaped table with a 128-bit v4-mapped address; only the port
        // suffix after the last ':' is parsed, so the wider address field
        // does not need special-casing.
        const std::string table6 =
            "  sl  local_address                         remote_address                        "
            "st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000000000000000000000000000:1F90 "
            "00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  "
            "1000        0 12349 1 0000000000000000 100 0 0 10 0\n";
        const int count = count_listeners_on_port(table6, 0x1F90);
        if (count != 1) {
            std::cerr << "FAIL [self-test count listeners]: tcp6-shaped table reported " << count
                      << ", expected 1\n";
            ok = false;
        }
    }
    if (ok) std::cerr << "PASS [self-test count listeners]\n";
    return ok;
}

// Live counterpart: opens two real SO_REUSEPORT listeners on the exact same
// loopback port -- precisely the shape a concurrent same-UID `rut` produces
// against a probe-allocated port (src/runtime/socket.cc:33-36) -- and
// confirms count_listeners_on_port(uint16_t) (the /proc/net/tcp[6] live
// reader) reports 2, not 1, for it.
bool self_test_count_listeners_on_port_live_reuseport() {
    const int fd1 = socket(AF_INET, SOCK_STREAM, 0);
    if (fd1 < 0) {
        std::cerr << "FAIL [self-test count listeners live]: could not create the first socket\n";
        return false;
    }
    const int one = 1;
    setsockopt(fd1, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr1{};
    addr1.sin_family = AF_INET;
    addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr1.sin_port = 0;
    if (bind(fd1, reinterpret_cast<sockaddr*>(&addr1), sizeof(addr1)) != 0 ||
        listen(fd1, 16) != 0) {
        std::cerr << "FAIL [self-test count listeners live]: could not bind/listen the first "
                     "SO_REUSEPORT socket\n";
        close(fd1);
        return false;
    }
    socklen_t len1 = sizeof(addr1);
    if (getsockname(fd1, reinterpret_cast<sockaddr*>(&addr1), &len1) != 0) {
        std::cerr << "FAIL [self-test count listeners live]: getsockname failed\n";
        close(fd1);
        return false;
    }
    const uint16_t port = ntohs(addr1.sin_port);

    const int fd2 = socket(AF_INET, SOCK_STREAM, 0);
    if (fd2 < 0) {
        std::cerr << "FAIL [self-test count listeners live]: could not create the second socket\n";
        close(fd1);
        return false;
    }
    setsockopt(fd2, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr2{};
    addr2.sin_family = AF_INET;
    addr2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr2.sin_port = htons(port);
    bool ok = true;
    if (bind(fd2, reinterpret_cast<sockaddr*>(&addr2), sizeof(addr2)) != 0 ||
        listen(fd2, 16) != 0) {
        std::cerr << "FAIL [self-test count listeners live]: could not bind/listen a second "
                     "SO_REUSEPORT socket on the same port -- SO_REUSEPORT may be unsupported "
                     "here\n";
        ok = false;
    } else {
        const int count = count_listeners_on_port(port);
        if (count != 2) {
            std::cerr << "FAIL [self-test count listeners live]: expected 2 live listeners on "
                         "port "
                      << port << ", got " << count << "\n";
            ok = false;
        }
    }
    close(fd1);
    close(fd2);
    if (ok) std::cerr << "PASS [self-test count listeners live]\n";
    return ok;
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
// upstream request would hit for an ASSERTED case: two requests recorded
// for one case's path must fail the harness, not silently compare only the
// first one. Uses "get_smoke" (a real entry in kAssertedCaseNames) so this
// exercises the asserted-is-fatal branch (round-9 review, "Keep record-only
// upstream duplicates out of acceptance" -- the record-only counterpart is
// self_test_duplicate_upstream_record_only_not_fatal() below).
bool self_test_duplicate_upstream_rejected() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test duplicate-upstream]: could not allocate a loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/dup", reply);
    if (!upstream.adopt(bound.fd)) {
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
    const std::vector<CaseSpec> cases = {{"get_smoke", "", false, "/dup", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "get_smoke";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (fill_ok) {
        std::cerr << "FAIL [self-test duplicate-upstream]: fill_upstream_bytes accepted two "
                     "recorded requests for an asserted case\n";
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

// Round-9 review, "Keep record-only upstream duplicates out of acceptance":
// the exact same duplicate-contact shape as self_test_duplicate_upstream_
// rejected() above, but for a record-only case ("get_forged_xfcc", not in
// kAssertedCaseNames) -- fill_upstream_bytes() must NOT fail the batch for
// it (the CLI contract promises record-only cases never affect the exit
// code), but must still flag the case's own evidence as ambiguous rather
// than silently trusting the first observation.
bool self_test_duplicate_upstream_record_only_not_fatal() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test duplicate-upstream record-only]: could not allocate a "
                     "loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/dup", reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr << "FAIL [self-test duplicate-upstream record-only]: could not start upstream\n";
        return false;
    }
    bool ok = true;
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test duplicate-upstream record-only]: could not connect\n";
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
    const std::vector<CaseSpec> cases = {{"get_forged_xfcc", "", false, "/dup", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "get_forged_xfcc";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (!fill_ok) {
        std::cerr << "FAIL [self-test duplicate-upstream record-only]: fill_upstream_bytes failed "
                     "the batch for a record-only case's duplicate\n";
        ok = false;
    }
    if (results[0].upstream_contacted) {
        std::cerr << "FAIL [self-test duplicate-upstream record-only]: upstream_contacted was set "
                     "true despite the duplicate\n";
        ok = false;
    }
    if (!results[0].upstream_ambiguous) {
        std::cerr << "FAIL [self-test duplicate-upstream record-only]: upstream_ambiguous was not "
                     "set for the record-only case's duplicate\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test duplicate-upstream record-only]\n";
    return ok;
}

// Round-4 review: a request landing on a path no case expects (a spurious
// or misrouted side-effecting request) must fail fill_upstream_bytes when it
// leaves an ASSERTED case's own expected path uncontacted, even though every
// per-case lookup it performs would still pass, because none of them ever
// query a path outside the case table. Uses "get_smoke" so this exercises
// the asserted-is-fatal branch (round-9 review, "Exempt record-only
// misroutes from pair acceptance" -- the record-only counterpart is
// self_test_unexpected_upstream_path_record_only_not_fatal() below).
bool self_test_unexpected_upstream_path_rejected() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr
            << "FAIL [self-test unexpected-upstream-path]: could not allocate a loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/expected", reply);
    upstream.set_default_reply(reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path]: could not start upstream\n";
        return false;
    }
    bool ok = true;
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path]: could not connect\n";
            upstream.stop();
            return false;
        }
        // The case table below only ever names "/expected". This request to
        // an unlisted path stands in for a spurious or misrouted request a
        // buggy proxy sent in addition to the expected one.
        const std::string req = "GET /unlisted HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd, req) || read_http_message(fd, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd);
    }
    const std::vector<CaseSpec> cases = {{"get_smoke", "", false, "/expected", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "get_smoke";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (fill_ok) {
        std::cerr << "FAIL [self-test unexpected-upstream-path]: fill_upstream_bytes accepted a "
                     "request to a path no case expected, leaving an asserted case uncontacted\n";
        ok = false;
    }
    // The one case that was actually expected must still be reported
    // correctly: it saw zero requests, not the unlisted one.
    if (results[0].upstream_contacted || results[0].upstream_contact_count != 0) {
        std::cerr << "FAIL [self-test unexpected-upstream-path]: the expected case's own "
                     "accounting was disturbed by the unlisted request\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test unexpected-upstream-path]\n";
    return ok;
}

// Round-9 review, "Exempt record-only misroutes from pair acceptance": the
// exact same unlisted-path shape as self_test_unexpected_upstream_path_
// rejected() above, but the one case in the table is record-only
// ("get_forged_xfcc") -- fill_upstream_bytes() must NOT fail the batch (the
// CLI contract promises record-only cases never affect the exit code), but
// must flag that case as ambiguous, since it is the only plausible source of
// the stray request.
bool self_test_unexpected_upstream_path_record_only_not_fatal() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only]: could not allocate a "
                     "loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/expected", reply);
    upstream.set_default_reply(reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr
            << "FAIL [self-test unexpected-upstream-path record-only]: could not start upstream\n";
        return false;
    }
    bool ok = true;
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path record-only]: could not "
                         "connect\n";
            upstream.stop();
            return false;
        }
        const std::string req = "GET /unlisted HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd, req) || read_http_message(fd, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd);
    }
    const std::vector<CaseSpec> cases = {{"get_forged_xfcc", "", false, "/expected", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "get_forged_xfcc";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (!fill_ok) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only]: fill_upstream_bytes "
                     "failed the batch for a record-only case's misroute\n";
        ok = false;
    }
    if (results[0].upstream_contacted || results[0].upstream_contact_count != 0) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only]: the record-only "
                     "case's own accounting was disturbed by the unlisted request\n";
        ok = false;
    }
    if (!results[0].upstream_ambiguous) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only]: upstream_ambiguous "
                     "was not set for the record-only case\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test unexpected-upstream-path record-only]\n";
    return ok;
}

// Round-10 review, "Attribute stray traffic without blaming local asserted
// cases": a real `run1_cases()` batch always contains asserted, locally-
// handled cases (`options_star`, `connect_failure`, `connect_authority`)
// whose `upstream_contact_count` is 0 BY DESIGN -- they never forward at
// all -- alongside record-only forwarding cases. Before the fix, the mere
// presence of such an asserted zero-contact case made ANY stray path in the
// same batch "attributable to an asserted case" (since the old check only
// asked "is this case asserted and at zero contact", never "does this case
// even expect to forward"), so a record-only case's own misroute could
// still fail the whole batch. This exercises exactly that combination:
// "options_star" (asserted, locally-handled, never contacted) sits in the
// same `cases` table as "get_forged_xfcc" (record-only, its own expected
// path also never contacted) while the actual stray request lands on an
// unlisted path -- fill_upstream_bytes() must not fail the batch, must
// leave "options_star" unmarked (it was never a plausible source), and must
// flag "get_forged_xfcc" as ambiguous (the only plausible source left).
bool self_test_unexpected_upstream_path_ignores_asserted_local_case() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path ignores local]: could not allocate "
                     "a loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_default_reply(reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path ignores local]: could not start "
                     "upstream\n";
        return false;
    }
    bool ok = true;
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path ignores local]: could not "
                         "connect\n";
            upstream.stop();
            return false;
        }
        // Neither "options_star"'s nor "get_forged_xfcc"'s expected path
        // below is ever hit; only this unlisted one is.
        const std::string req = "GET /unlisted HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd, req) || read_http_message(fd, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd);
    }
    const std::vector<CaseSpec> cases = {{"options_star", "", false, "*", reply},
                                         {"get_forged_xfcc", "", false, "/expected", reply}};
    std::vector<CaseResult> results(2);
    results[0].name = "options_star";
    results[1].name = "get_forged_xfcc";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (!fill_ok) {
        std::cerr << "FAIL [self-test unexpected-upstream-path ignores local]: fill_upstream_bytes "
                     "failed the batch because an asserted, locally-handled zero-contact case sat "
                     "alongside the real (record-only) misroute\n";
        ok = false;
    }
    if (results[0].upstream_ambiguous) {
        std::cerr << "FAIL [self-test unexpected-upstream-path ignores local]: the asserted "
                     "locally-handled case (\"options_star\") was marked ambiguous even though it "
                     "never expects to forward and cannot be the source\n";
        ok = false;
    }
    if (!results[1].upstream_ambiguous) {
        std::cerr << "FAIL [self-test unexpected-upstream-path ignores local]: the record-only "
                     "forwarding case (\"get_forged_xfcc\") was not marked ambiguous\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test unexpected-upstream-path ignores local]\n";
    return ok;
}

// Round-15 review, "Reject unlisted traffic even after expected contacts
// succeed" (P1): the exact gap the review describes -- an asserted case
// gets its OWN expected contact (so no case has upstream_contact_count == 0
// for the old elimination logic to "attribute" the extra traffic to), but
// the upstream ALSO recorded a second, unlisted request. Since
// fill_upstream_bytes() is only ever called with a batch that is purely
// asserted or purely record-only (round-11 review), unlisted traffic during
// a pure-asserted batch must fail regardless of whether every case already
// got its own contact.
bool self_test_unexpected_upstream_path_rejected_even_with_all_contacts() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path all-contacts]: could not allocate "
                     "a loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/expected", reply);
    upstream.set_default_reply(reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr
            << "FAIL [self-test unexpected-upstream-path all-contacts]: could not start upstream\n";
        return false;
    }
    bool ok = true;
    {
        const int fd1 = connect_with_timeout(port, kClientTimeoutMs);
        if (fd1 < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path all-contacts]: could not "
                         "connect (expected)\n";
            upstream.stop();
            return false;
        }
        const std::string req1 = "GET /expected HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd1, req1) || read_http_message(fd1, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd1);

        // The extra, unlisted request: sent AFTER the expected one succeeds,
        // so every case in `cases` below already has a nonzero contact
        // count by the time fill_upstream_bytes() looks at it.
        const int fd2 = connect_with_timeout(port, kClientTimeoutMs);
        if (fd2 < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path all-contacts]: could not "
                         "connect (unlisted)\n";
            upstream.stop();
            return false;
        }
        const std::string req2 = "GET /unlisted HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd2, req2) || read_http_message(fd2, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd2);
    }
    const std::vector<CaseSpec> cases = {{"get_smoke", "", false, "/expected", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "get_smoke";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (fill_ok) {
        std::cerr << "FAIL [self-test unexpected-upstream-path all-contacts]: fill_upstream_bytes "
                     "accepted an asserted batch with an extra unlisted request even though its "
                     "own expected contact also succeeded\n";
        ok = false;
    }
    if (!results[0].upstream_contacted || results[0].upstream_contact_count != 1) {
        std::cerr << "FAIL [self-test unexpected-upstream-path all-contacts]: the case's own "
                     "accounting was disturbed by the stray request\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test unexpected-upstream-path all-contacts]\n";
    return ok;
}

// Round-15 review companion to the above: the identical shape, but the one
// case in the table is record-only ("get_forged_xfcc") -- fill_upstream_
// bytes() must NOT fail the batch (the CLI contract promises record-only
// cases never affect the exit code), even though the case's own expected
// contact also succeeded and there is nothing to attribute the extra
// traffic to.
bool self_test_unexpected_upstream_path_record_only_not_fatal_even_with_all_contacts() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only all-contacts]: could "
                     "not allocate a loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/expected", reply);
    upstream.set_default_reply(reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only all-contacts]: could "
                     "not start upstream\n";
        return false;
    }
    bool ok = true;
    {
        const int fd1 = connect_with_timeout(port, kClientTimeoutMs);
        if (fd1 < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path record-only all-contacts]: "
                         "could not connect (expected)\n";
            upstream.stop();
            return false;
        }
        const std::string req1 = "GET /expected HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd1, req1) || read_http_message(fd1, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd1);

        const int fd2 = connect_with_timeout(port, kClientTimeoutMs);
        if (fd2 < 0) {
            std::cerr << "FAIL [self-test unexpected-upstream-path record-only all-contacts]: "
                         "could not connect (unlisted)\n";
            upstream.stop();
            return false;
        }
        const std::string req2 = "GET /unlisted HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd2, req2) || read_http_message(fd2, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd2);
    }
    const std::vector<CaseSpec> cases = {{"get_forged_xfcc", "", false, "/expected", reply}};
    std::vector<CaseResult> results(1);
    results[0].name = "get_forged_xfcc";
    const bool fill_ok = fill_upstream_bytes(&results, cases, upstream);
    upstream.stop();
    if (!fill_ok) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only all-contacts]: "
                     "fill_upstream_bytes failed a record-only batch over an unlisted request, "
                     "despite the CLI's record-only contract\n";
        ok = false;
    }
    if (!results[0].upstream_contacted || results[0].upstream_contact_count != 1) {
        std::cerr << "FAIL [self-test unexpected-upstream-path record-only all-contacts]: the "
                     "case's own accounting was disturbed by the stray request\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test unexpected-upstream-path record-only all-contacts]\n";
    return ok;
}

// Round-11 review, "Attribute duplicate contacts to the originating case":
// reproduces the exact scenario the review describes -- a record-only
// case's request misrouted onto an ASSERTED case's own listed path (e.g.
// "get_forged_xfcc" landing on "/smoke" instead of its own "/xfcc") -- and
// proves the fix keeps that misroute from ever being seen as a duplicate on
// get_smoke's own path: run_oracle_milestone_s()/run_pair_milestone_s() now
// run the asserted and record-only cases as two isolated batches against a
// freshly-cleared upstream log (split_asserted_and_record_only()), so
// fill_upstream_bytes() is called once per batch, never with both cases'
// specs and a combined log at the same time. This test drives
// fill_upstream_bytes() the same way those callers now do: once for the
// asserted batch, `clear_requests()`, then once for the record-only batch.
bool self_test_record_only_misroute_isolated_by_batch() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test record-only misroute isolated]: could not allocate a "
                     "loopback port\n";
        return false;
    }
    const uint16_t port = bound.port;
    RecordingUpstream upstream;
    const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    upstream.set_reply("/smoke", reply);
    upstream.set_default_reply(reply);
    if (!upstream.adopt(bound.fd)) {
        std::cerr << "FAIL [self-test record-only misroute isolated]: could not start upstream\n";
        return false;
    }
    const std::vector<CaseSpec> asserted_cases = {{"get_smoke", "", false, "/smoke", reply}};
    const std::vector<CaseSpec> record_only_cases = {
        {"get_forged_xfcc", "", false, "/xfcc", reply}};
    bool ok = true;

    // Asserted batch: exactly one real request to get_smoke's own path.
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test record-only misroute isolated]: could not connect (1)\n";
            upstream.stop();
            return false;
        }
        const std::string req = "GET /smoke HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd, req) || read_http_message(fd, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd);
    }
    std::vector<CaseResult> asserted_results(1);
    asserted_results[0].name = "get_smoke";
    const bool asserted_fill_ok = fill_upstream_bytes(&asserted_results, asserted_cases, upstream);
    upstream.clear_requests();

    // Record-only batch, against the freshly-cleared log: the forged case's
    // request is misrouted onto "/smoke" -- get_smoke's own path -- instead
    // of its own "/xfcc", standing in for the exact collision the review
    // describes.
    {
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test record-only misroute isolated]: could not connect (2)\n";
            upstream.stop();
            return false;
        }
        const std::string req = "GET /smoke HTTP/1.1\r\nHost: t.example\r\n\r\n";
        if (!send_all(fd, req) || read_http_message(fd, false, kClientTimeoutMs).bytes != reply)
            ok = false;
        close(fd);
    }
    std::vector<CaseResult> record_only_results(1);
    record_only_results[0].name = "get_forged_xfcc";
    const bool record_only_fill_ok =
        fill_upstream_bytes(&record_only_results, record_only_cases, upstream);
    upstream.stop();

    if (!asserted_fill_ok) {
        std::cerr << "FAIL [self-test record-only misroute isolated]: the asserted batch was "
                     "rejected even though its own log never saw the later misroute\n";
        ok = false;
    }
    if (!asserted_results[0].upstream_contacted ||
        asserted_results[0].upstream_contact_count != 1) {
        std::cerr << "FAIL [self-test record-only misroute isolated]: get_smoke's own evidence "
                     "was not exactly one contact\n";
        ok = false;
    }
    if (!record_only_fill_ok) {
        std::cerr << "FAIL [self-test record-only misroute isolated]: the record-only batch made "
                     "the run fail despite the CLI's record-only contract\n";
        ok = false;
    }
    if (!record_only_results[0].upstream_ambiguous) {
        std::cerr << "FAIL [self-test record-only misroute isolated]: the misrouted record-only "
                     "case was not marked ambiguous\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test record-only misroute isolated]\n";
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

// Round-9 review, "Require SIGTERM delivery before accepting a clean RUT
// exit": simulates a child that is entirely gone by the time stop() tries to
// signal it -- reaping it directly here, standing in for "the child exited
// on its own and was collected before stop() got a chance to act". Before
// the round-11 fix below, this fell through the precheck (`waitpid()`
// returns `ECHILD`, not `pid`) all the way to `kill(pid, SIGTERM)`, which
// was then guaranteed to fail with ESRCH -- exercising the round-9
// `term_sent` check instead of the (then nonexistent) precheck-level ECHILD
// handling. Round-11 review, "Handle ECHILD before signaling the stored
// PID": the precheck itself now catches this case and returns before ever
// reaching kill(), so this test now exercises that earlier return instead;
// the observable outcome (`stopped_cleanly == false`,
// `exited_unexpectedly == true`) is unchanged, but self_test_stop_echild_
// precheck_no_signal() below is the one that actually proves no signal is
// sent, using a target pid that is still alive.
bool self_test_rut_stop_requires_delivered_signal() {
    RutInstance rut;
    rut.log_path = "/dev/null";
    if (!rut.launch("/bin/true", "unused.rut")) {
        std::cerr << "FAIL [self-test rut stop requires signal]: could not fork/exec /bin/true\n";
        return false;
    }
    // Reap the child ourselves: once reaped, `pid` no longer names any
    // process, so the precheck inside stop() (which calls waitpid() again)
    // finds nothing but `ECHILD`.
    int status = 0;
    const pid_t reaped = waitpid(rut.pid, &status, 0);
    if (reaped != rut.pid) {
        std::cerr << "FAIL [self-test rut stop requires signal]: could not reap /bin/true\n";
        return false;
    }
    const bool stopped_cleanly = rut.stop();
    bool ok = true;
    if (stopped_cleanly) {
        std::cerr << "FAIL [self-test rut stop requires signal]: stop() reported a clean "
                     "teardown despite never being able to deliver SIGTERM\n";
        ok = false;
    }
    if (!rut.exited_unexpectedly) {
        std::cerr << "FAIL [self-test rut stop requires signal]: exited_unexpectedly was not set\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test rut stop requires signal]\n";
    return ok;
}

// Creates a process that is alive but is NOT this test process's own child:
// forks a middle process which itself forks `*sentinel_pid` (a long sleeper)
// and then exits immediately, so the sentinel is reparented away before this
// function returns (the middle process is reaped here, so it never lingers
// as a zombie). Because the sentinel was never this process's direct child,
// `waitpid(*sentinel_pid, ..., WNOHANG)` deterministically fails with
// `ECHILD` -- no TOCTOU timing window, no need to actually reap a real
// child and risk a race with the OS recycling its pid. This is what lets
// self_test_stop_echild_precheck_no_signal() below prove a live process was
// never signaled, rather than only checking stop()'s return flags (which
// can't by themselves distinguish "kill() was never attempted" from
// "kill() was attempted and happened to fail").
//
// Assumes this test process is not itself PID 1 / a child subreaper (true
// of every environment this suite runs in); under a subreaper the sentinel
// would be reparented to that subreaper instead of becoming un-waitable
// from here, which would invalidate the ECHILD assumption below.
bool make_orphan_sentinel(pid_t* sentinel_pid) {
    int fds[2];
    if (pipe(fds) != 0) return false;
    const pid_t mid = fork();
    if (mid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (mid == 0) {
        close(fds[0]);
        const pid_t grand = fork();
        if (grand == 0) {
            close(fds[1]);
            struct timespec ts{20, 0};
            nanosleep(&ts, nullptr);
            _exit(0);
        }
        if (grand > 0) {
            ssize_t written = 0;
            while (written < static_cast<ssize_t>(sizeof(grand))) {
                const ssize_t n = write(fds[1],
                                        reinterpret_cast<const char*>(&grand) + written,
                                        sizeof(grand) - written);
                if (n <= 0) break;
                written += n;
            }
        }
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    pid_t grand = -1;
    ssize_t total_read = 0;
    while (total_read < static_cast<ssize_t>(sizeof(grand))) {
        const ssize_t n =
            read(fds[0], reinterpret_cast<char*>(&grand) + total_read, sizeof(grand) - total_read);
        if (n <= 0) break;
        total_read += n;
    }
    close(fds[0]);
    int status = 0;
    while (waitpid(mid, &status, 0) < 0 && errno == EINTR) {
    }
    if (total_read != static_cast<ssize_t>(sizeof(grand)) || grand <= 0) return false;
    *sentinel_pid = grand;
    return true;
}

// Round-11 review, "Handle ECHILD before signaling the stored PID": proves
// that neither `EnvoyInstance::stop()` nor `RutInstance::stop()` ever
// signals `pid` once the initial precheck observes `ECHILD` -- the concrete
// risk the review raised is that a stale/recycled pid could otherwise be
// signaled and hit a completely unrelated live process. Using a real,
// currently-alive sentinel process that is not this test's own child (see
// make_orphan_sentinel() above) makes that concrete: if either stop()
// reached its kill() call, the sentinel -- having no SIGTERM handler --
// would die; this test asserts it is still alive afterward, not merely that
// stop() returned the expected flags.
bool self_test_stop_echild_precheck_no_signal() {
    pid_t sentinel = -1;
    if (!make_orphan_sentinel(&sentinel)) {
        std::cerr << "FAIL [self-test stop echild no-signal]: could not create an orphan "
                     "sentinel process\n";
        return false;
    }
    bool ok = true;
    {
        RutInstance rut;
        rut.pid = sentinel;
        rut.log_path = "/dev/null";
        const bool stopped_cleanly = rut.stop();
        if (stopped_cleanly) {
            std::cerr << "FAIL [self-test stop echild no-signal]: RutInstance::stop() reported "
                         "a clean teardown for an ECHILD precheck\n";
            ok = false;
        }
        if (!rut.exited_unexpectedly) {
            std::cerr << "FAIL [self-test stop echild no-signal]: RutInstance exited_unexpectedly "
                         "was not set\n";
            ok = false;
        }
        if (rut.pid != -1) {
            std::cerr << "FAIL [self-test stop echild no-signal]: RutInstance::stop() did not "
                         "clear pid\n";
            ok = false;
        }
        if (kill(sentinel, 0) != 0) {
            std::cerr << "FAIL [self-test stop echild no-signal]: sentinel process is no longer "
                         "alive after RutInstance::stop() -- a signal reached it\n";
            ok = false;
        }
    }
    {
        EnvoyInstance envoy;
        envoy.pid = sentinel;
        envoy.name = "rut-diff-selftest-echild-no-signal";
        envoy.log_path = "/dev/null";
        const bool stopped_cleanly = envoy.stop();
        if (stopped_cleanly) {
            std::cerr << "FAIL [self-test stop echild no-signal]: EnvoyInstance::stop() reported "
                         "a clean teardown for an ECHILD precheck\n";
            ok = false;
        }
        if (!envoy.exited_unexpectedly) {
            std::cerr << "FAIL [self-test stop echild no-signal]: EnvoyInstance "
                         "exited_unexpectedly was not set\n";
            ok = false;
        }
        if (envoy.pid != -1) {
            std::cerr << "FAIL [self-test stop echild no-signal]: EnvoyInstance::stop() did not "
                         "clear pid\n";
            ok = false;
        }
        if (kill(sentinel, 0) != 0) {
            std::cerr << "FAIL [self-test stop echild no-signal]: sentinel process is no longer "
                         "alive after EnvoyInstance::stop() -- a signal reached it\n";
            ok = false;
        }
    }
    // Best-effort cleanup: the sentinel was never this process's own child
    // (that is the whole point), so it cannot be waitpid()'d from here; its
    // eventual parent/reaper reaps it once SIGKILL takes effect.
    kill(sentinel, SIGKILL);
    if (ok) std::cerr << "PASS [self-test stop echild no-signal]\n";
    return ok;
}

// Round-6 review, "Verify the status reaped after signaling RUT": the
// precheck exercised above only catches a child that had already exited
// before stop() ever signaled it. This exercises the status-verification
// logic that guards the rest of stop()'s reap: a script that traps SIGTERM
// and exits 0 -- the exact shape rut's own graceful shutdown produces
// (src/main.cc blocks SIGTERM/SIGINT, drains, then returns 0) -- must be
// reported as a clean teardown, while one that traps SIGTERM but exits
// nonzero (it "handled" the signal, but not the way an intentional teardown
// of rut itself would) must not, even though waitpid() reaps a normal exit
// either way.
bool self_test_rut_stop_verifies_exit_status() {
    const std::string dir = make_temp_dir("rut-diff-selftest-stop");
    if (dir.empty()) {
        std::cerr << "FAIL [self-test rut stop status]: could not create temp directory\n";
        return false;
    }
    auto run_case = [&](const char* script_body, bool expect_clean, const char* label) {
        const std::string script = dir + "/" + label + ".sh";
        if (!write_file_mode(script, script_body, 0755)) {
            std::cerr << "FAIL [self-test rut stop status]: could not write " << label << ".sh\n";
            return false;
        }
        RutInstance rut;
        rut.log_path = "/dev/null";
        if (!rut.launch(script, "unused.rut")) {
            std::cerr << "FAIL [self-test rut stop status]: could not fork/exec " << label
                      << ".sh\n";
            return false;
        }
        // Give the script time to install its trap before stop() sends
        // SIGTERM.
        struct timespec ts{0, 100'000'000};
        nanosleep(&ts, nullptr);
        const bool stopped_cleanly = rut.stop();
        bool ok = true;
        if (stopped_cleanly != expect_clean) {
            std::cerr << "FAIL [self-test rut stop status]: stop() for " << label << " returned "
                      << (stopped_cleanly ? "clean" : "unexpected") << ", expected "
                      << (expect_clean ? "clean" : "unexpected") << "\n";
            ok = false;
        }
        if (rut.exited_unexpectedly == expect_clean) {
            std::cerr << "FAIL [self-test rut stop status]: exited_unexpectedly for " << label
                      << " is " << (rut.exited_unexpectedly ? "true" : "false") << ", expected "
                      << (expect_clean ? "false" : "true") << "\n";
            ok = false;
        }
        return ok;
    };
    bool ok = true;
    ok &= run_case("#!/bin/sh\ntrap 'exit 0' TERM\nsleep 5\n", /*expect_clean=*/true, "clean");
    ok &= run_case("#!/bin/sh\ntrap 'exit 7' TERM\nsleep 5\n", /*expect_clean=*/false, "dirty");
    if (ok) std::cerr << "PASS [self-test rut stop status]\n";
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

// Round-6 review, "Require expected upstream contact for forwarded cases":
// if the recording upstream becomes unavailable, both proxies can answer a
// forwarding case with matching, fully framed local error responses while
// `upstream_contacted`/bytes stay equal (both empty) -- `compare_pair_case`
// must not call that a MATCH for a case whose whole point is to exercise
// forwarding.
bool self_test_pair_unexercised_forwarding_rejected() {
    PairCaseResult c;
    c.name = "get_smoke";  // a forwarding case, not in the exempt list
    c.asserted = true;
    c.envoy.exchange_complete = true;
    c.rut.exchange_complete = true;
    c.envoy.downstream_bytes = c.rut.downstream_bytes = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
    // Both sides agree upstream was never contacted -- exactly the
    // evidence-free shape that must not pass for a case expected to forward.
    c.envoy.upstream_contacted = c.rut.upstream_contacted = false;
    c.envoy.upstream_contact_count = c.rut.upstream_contact_count = 0;
    const bool match = compare_pair_case(c);
    if (match) {
        std::cerr << "FAIL [self-test pair unexercised forwarding]: compare_pair_case matched a "
                     "forwarding case with zero upstream contact on both sides\n";
        return false;
    }
    std::cerr << "PASS [self-test pair unexercised forwarding]\n";
    return true;
}

// Companion to the above: `options_star`, `connect_failure` and
// `connect_authority` are exempt from the forwarding-contact requirement
// (Envoy never routes any of them to the upstream by design; see
// case_expects_upstream_forward()), so the same zero-contact shape must
// still MATCH for them, proving the round-6 fix does not regress these
// cases (round-7 review added `connect_authority`, whose oracle records
// "upstream not contacted").
bool self_test_pair_exempt_cases_zero_contact_matches() {
    bool ok = true;
    for (const char* name : {"options_star", "connect_failure", "connect_authority"}) {
        PairCaseResult c;
        c.name = name;
        c.asserted = true;
        c.envoy.exchange_complete = true;
        c.rut.exchange_complete = true;
        c.envoy.downstream_bytes = c.rut.downstream_bytes = "HTTP/1.1 404 Not Found\r\n\r\n";
        c.envoy.upstream_contacted = c.rut.upstream_contacted = false;
        c.envoy.upstream_contact_count = c.rut.upstream_contact_count = 0;
        if (!compare_pair_case(c)) {
            std::cerr << "FAIL [self-test pair exempt zero-contact]: compare_pair_case rejected "
                      << name << " despite zero upstream contact, which is expected for it\n";
            ok = false;
        }
    }
    if (ok) std::cerr << "PASS [self-test pair exempt zero-contact]\n";
    return ok;
}

// Round-8 review, "Require zero contacts for locally handled cases":
// compare_pair_case() must require exactly ZERO upstream contacts for an
// exempt case, not just "don't require exactly one". Before that fix,
// `!expects_forward` alone made `forwarding_exercised` unconditionally true,
// so a case that is supposed to stay local (like `options_star`) but was
// unexpectedly forwarded by both proxies -- and happened to get back
// matching bytes from doing so -- would still report MATCH, hiding the fact
// that the documented local-404 behavior was no longer being exercised at
// all. Same byte-identical downstream shape as the zero-contact test above,
// but with both sides showing one contact each, must now MISMATCH.
bool self_test_pair_exempt_cases_nonzero_contact_rejected() {
    bool ok = true;
    for (const char* name : {"options_star", "connect_failure", "connect_authority"}) {
        PairCaseResult c;
        c.name = name;
        c.asserted = true;
        c.envoy.exchange_complete = true;
        c.rut.exchange_complete = true;
        c.envoy.downstream_bytes = c.rut.downstream_bytes = "HTTP/1.1 404 Not Found\r\n\r\n";
        c.envoy.upstream_bytes = c.rut.upstream_bytes = "GET / HTTP/1.1\r\n\r\n";
        c.envoy.upstream_contacted = c.rut.upstream_contacted = true;
        c.envoy.upstream_contact_count = c.rut.upstream_contact_count = 1;
        if (compare_pair_case(c)) {
            std::cerr << "FAIL [self-test pair exempt nonzero-contact]: compare_pair_case "
                         "matched "
                      << name << " despite both sides unexpectedly forwarding it to the upstream\n";
            ok = false;
        }
    }
    if (ok) std::cerr << "PASS [self-test pair exempt nonzero-contact]\n";
    return ok;
}

// Round-12 review, "Prevent record-only crashes from failing pair mode": a
// fake proxy that serves exactly one connection (standing in for the single
// asserted case run against it below) and then exits on its own -- never
// accepting a second connection, standing in for a crash during or right
// after the asserted batch, before the record-only batch could complete --
// must not turn into a fatal run_pair_milestone_s() outcome. Unit-tests
// note_record_only_phase_crash() itself: given a `stop()` failure and a
// batch of record-only results, it must mark them ambiguous rather than
// the caller returning fatal. (Round-15 review moved run_pair_milestone_s()
// to a SEPARATE proxy instance per batch, so production no longer shares
// one instance across both the way this single fake proxy does; see
// self_test_pair_isolated_instances_crash_classification() below for that
// two-instance shape.)
bool self_test_pair_record_only_crash_is_a_note() {
    BoundPort bound;
    if (!allocate_bound_loopback_port(&bound)) {
        std::cerr << "FAIL [self-test pair record-only crash]: could not allocate a loopback "
                     "port\n";
        return false;
    }
    const uint16_t port = bound.port;
    // Advertises `Connection: close`: the fake proxy below closes the
    // connection right after replying (standing in for its own exit), and
    // read_http_message() treats an EOF on a response that did NOT
    // advertise close as a persistence violation rather than completion.
    const std::string reply = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi";

    const pid_t fake_proxy = fork();
    if (fake_proxy < 0) {
        std::cerr << "FAIL [self-test pair record-only crash]: fork failed\n";
        close(bound.fd);
        return false;
    }
    if (fake_proxy == 0) {
        // Serve exactly one connection (the asserted case below), then exit
        // without ever accepting a second -- the record-only case's
        // connection attempt finds nothing listening, exactly like a crash
        // that happened during or right after the asserted batch.
        const int fd = accept(bound.fd, nullptr, nullptr);
        if (fd >= 0) {
            char buf[512];
            const ssize_t ignored = recv(fd, buf, sizeof(buf), 0);
            (void)ignored;
            send_all(fd, reply);
            close(fd);
        }
        _exit(1);
    }
    close(bound.fd);

    RutInstance rut;
    rut.pid = fake_proxy;
    rut.log_path = "/dev/null";

    const std::vector<CaseSpec> asserted_cases = {
        {"get_smoke", "GET /smoke HTTP/1.1\r\nHost: t.example\r\n\r\n", false, "/smoke", reply}};
    const std::vector<CaseSpec> record_only_cases = {
        {"get_forged_xfcc",
         "GET /xfcc HTTP/1.1\r\nHost: t.example\r\n\r\n",
         false,
         "/xfcc",
         reply}};

    auto asserted_results = run_case_batch(port, asserted_cases);
    bool ok = true;
    if (asserted_results.size() != 1 || !asserted_results[0].exchange_complete) {
        std::cerr << "FAIL [self-test pair record-only crash]: the asserted case's own exchange "
                     "did not complete before the fake proxy exited\n";
        ok = false;
    }

    // By now the fake proxy has served its one connection and is exiting
    // (or has already exited); this stands in for the record-only batch
    // running against a proxy that died during or right after the asserted
    // batch.
    auto record_only_results = run_case_batch(port, record_only_cases);
    if (record_only_results.size() != 1) {
        std::cerr << "FAIL [self-test pair record-only crash]: expected exactly one record-only "
                     "result\n";
        ok = false;
    }

    const bool stopped_cleanly = rut.stop();
    if (stopped_cleanly) {
        std::cerr << "FAIL [self-test pair record-only crash]: stop() reported a clean teardown "
                     "for a proxy that exited on its own\n";
        ok = false;
    } else {
        note_record_only_phase_crash(
            "fake-proxy", rut.unexpected_exit_description, &record_only_results);
    }
    if (!record_only_results.empty() && !record_only_results[0].upstream_ambiguous) {
        std::cerr << "FAIL [self-test pair record-only crash]: the record-only case was not "
                     "marked ambiguous after the post-batch crash note\n";
        ok = false;
    }
    // The property under test is precisely that nothing above ever returns
    // (or would need to return) a fatal outcome for run_pair_milestone_s():
    // reaching this line at all, with `ok` still reflecting only the
    // evidence checks above, is the pass condition.
    if (ok) std::cerr << "PASS [self-test pair record-only crash]\n";
    return ok;
}

// Round-15 review, "Isolate record-only cases before ignoring proxy
// crashes": drives run_pair_milestone_s()'s per-batch instance isolation
// directly -- a dedicated fake instance for the asserted batch, stopped and
// validated BEFORE a second, separate fake instance is started for the
// record-only batch. Each instance crashes at CLEANUP (traps SIGTERM and
// exits 7, not a clean exit 0) rather than exiting on its own beforehand
// (that TOCTOU-precheck path is already covered by
// self_test_rut_stop_requires_delivered_signal() and friends), exercising
// stop()'s "a signal was delivered but the resulting exit status doesn't
// match an intentional teardown" branch specifically, in each phase.
//
// The asserted-phase instance's crash must be fatal on its own -- observing
// it can never be downgraded to a NOTE, and (in production) no record-only
// instance is ever launched after it. The record-only-phase instance is a
// wholly separate process that never saw the asserted batch's traffic, so
// its own crash at cleanup is unambiguously attributable to it and must be
// a NOTE, exactly like self_test_pair_record_only_crash_is_a_note() above
// -- but now via a dedicated instance rather than a shared one.
bool self_test_pair_isolated_instances_crash_classification() {
    // Serves exactly one connection with a fixed reply, then blocks forever
    // in pause() rather than exiting -- so the ONLY way this process ends is
    // by being signaled, and it deliberately reports a crash (exit 7, not
    // 0) when that happens, standing in for a bug during connection
    // cleanup.
    auto make_crash_on_term_proxy = [](uint16_t* out_port, pid_t* out_pid) -> bool {
        BoundPort bound;
        if (!allocate_bound_loopback_port(&bound)) return false;
        const pid_t pid = fork();
        if (pid < 0) {
            close(bound.fd);
            return false;
        }
        if (pid == 0) {
            signal(SIGTERM, [](int) { _exit(7); });
            const int fd = accept(bound.fd, nullptr, nullptr);
            if (fd >= 0) {
                char buf[512];
                const ssize_t ignored = recv(fd, buf, sizeof(buf), 0);
                (void)ignored;
                send_all(fd, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi");
                close(fd);
            }
            for (;;) pause();
        }
        close(bound.fd);
        *out_port = bound.port;
        *out_pid = pid;
        return true;
    };

    bool ok = true;
    const std::string reply = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi";

    // Phase 1: the asserted-phase instance.
    uint16_t asserted_port = 0;
    pid_t asserted_pid = -1;
    if (!make_crash_on_term_proxy(&asserted_port, &asserted_pid)) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: could not create the "
                     "asserted-phase fake instance\n";
        return false;
    }
    RutInstance rut_asserted;
    rut_asserted.pid = asserted_pid;
    rut_asserted.log_path = "/dev/null";
    const std::vector<CaseSpec> asserted_cases = {
        {"get_smoke", "GET /smoke HTTP/1.1\r\nHost: t.example\r\n\r\n", false, "/smoke", reply}};
    auto asserted_results = run_case_batch(asserted_port, asserted_cases);
    if (asserted_results.size() != 1 || !asserted_results[0].exchange_complete) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: the asserted case's "
                     "own exchange did not complete\n";
        ok = false;
    }
    const bool asserted_stopped_cleanly = rut_asserted.stop();
    if (asserted_stopped_cleanly) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: stop() reported a "
                     "clean teardown for an asserted-phase instance that crashed at cleanup "
                     "(exit 7)\n";
        ok = false;
    }
    // Mirrors run_pair_milestone_s(): an asserted-phase stop() failure is
    // fatal by itself here -- no note_record_only_phase_crash() call, no
    // attribution needed.

    // Phase 2: a SEPARATE instance for the record-only batch -- independent
    // of phase 1 by construction, never conditioned on phase 1 succeeding.
    uint16_t record_only_port = 0;
    pid_t record_only_pid = -1;
    if (!make_crash_on_term_proxy(&record_only_port, &record_only_pid)) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: could not create the "
                     "record-only-phase fake instance\n";
        return false;
    }
    RutInstance rut_record_only;
    rut_record_only.pid = record_only_pid;
    rut_record_only.log_path = "/dev/null";
    const std::vector<CaseSpec> record_only_cases = {
        {"get_forged_xfcc",
         "GET /xfcc HTTP/1.1\r\nHost: t.example\r\n\r\n",
         false,
         "/xfcc",
         reply}};
    auto record_only_results = run_case_batch(record_only_port, record_only_cases);
    if (record_only_results.size() != 1 || !record_only_results[0].exchange_complete) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: the record-only "
                     "case's own exchange did not complete\n";
        ok = false;
    }
    const bool record_only_stopped_cleanly = rut_record_only.stop();
    if (record_only_stopped_cleanly) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: stop() reported a "
                     "clean teardown for a record-only-phase instance that crashed at cleanup "
                     "(exit 7)\n";
        ok = false;
    } else {
        note_record_only_phase_crash("fake-record-only-proxy",
                                     rut_record_only.unexpected_exit_description,
                                     &record_only_results);
    }
    if (!record_only_results.empty() && !record_only_results[0].upstream_ambiguous) {
        std::cerr << "FAIL [self-test pair isolated crash classification]: the record-only "
                     "instance's crash was not marked ambiguous\n";
        ok = false;
    }

    if (ok) std::cerr << "PASS [self-test pair isolated crash classification]\n";
    return ok;
}

// Round-4 review: verifies the exact unblock mechanism
// self_test_head_body_detected()'s connect-failure branch relies on, so a
// client connect() failure (e.g. transient fd exhaustion) can never leave
// that self-test's server thread parked in accept() forever and hang
// server.join() (and so the whole self-test binary, until an external
// timeout kills it, instead of reporting the connect failure normally).
// shutdown()+close() on the listening socket -- never the reverse, see
// RecordingUpstream::stop() -- must make a thread blocked in accept() on
// that same fd return promptly.
bool self_test_accept_unblocks_on_shutdown_close() {
    uint16_t port = 0;
    if (!allocate_loopback_port(&port)) {
        std::cerr << "FAIL [self-test accept-unblock]: could not allocate a loopback port\n";
        return false;
    }
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "FAIL [self-test accept-unblock]: could not create listening socket\n";
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
        std::cerr << "FAIL [self-test accept-unblock]: could not bind/listen\n";
        close(listen_fd);
        return false;
    }
    std::atomic<bool> accept_returned{false};
    std::thread server([listen_fd, &accept_returned] {
        accept(listen_fd, nullptr, nullptr);
        accept_returned.store(true);
    });
    // Give the server thread time to actually enter the blocking accept()
    // call before unblocking it, matching the real connect-failure branch's
    // ordering (the thread starts before the connect attempt that may fail).
    struct timespec delay{0, 50'000'000};
    nanosleep(&delay, nullptr);
    shutdown(listen_fd, SHUT_RDWR);
    close(listen_fd);
    listen_fd = -1;
    server.join();
    const bool ok = accept_returned.load();
    if (!ok) {
        std::cerr << "FAIL [self-test accept-unblock]: accept() did not return after "
                     "shutdown()+close() on its own listening socket\n";
    } else {
        std::cerr << "PASS [self-test accept-unblock]\n";
    }
    return ok;
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
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
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
        // The server thread is parked in accept(listen_fd, ...) with no
        // client ever going to connect now. Unblock it the same way
        // RecordingUpstream::stop() does (shutdown() then close(), never the
        // reverse) before joining, or server.join() below hangs until an
        // external timeout kills the whole self-test binary instead of
        // reporting this failure normally (round-4 review). Null out
        // listen_fd so the shared cleanup below does not double-close it.
        shutdown(listen_fd, SHUT_RDWR);
        close(listen_fd);
        listen_fd = -1;
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
    if (listen_fd >= 0) close(listen_fd);
    if (ok) std::cerr << "PASS [self-test head body]\n";
    return ok;
}

// Round-8 review, "Reject resets during the persistent-response grace
// check", HEAD counterpart: read_http_message()'s HEAD branch has its own
// grace-window loop, separate from the Content-Length body one exercised by
// self_test_persistent_trailing_bytes_detected()'s kAbortiveReset case below.
// An abortive close (SO_LINGER{on, 0}, RST instead of FIN) there must be
// rejected identically to an orderly EOF: a HEAD response that did not
// advertise `Connection: close` still promised to stay open, and the old
// `if (n <= 0) break;` let a non-retryable negative recv() (ECONNRESET) fall
// through to a reported-complete result unexamined.
bool self_test_head_grace_reset_detected() {
    uint16_t port = 0;
    if (!allocate_loopback_port(&port)) {
        std::cerr << "FAIL [self-test head grace reset]: could not allocate a loopback port\n";
        return false;
    }
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "FAIL [self-test head grace reset]: could not create listening socket\n";
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
        std::cerr << "FAIL [self-test head grace reset]: could not bind/listen\n";
        close(listen_fd);
        return false;
    }
    std::thread server([listen_fd] {
        const int conn = accept(listen_fd, nullptr, nullptr);
        if (conn < 0) return;
        char buf[512];
        recv(conn, buf, sizeof(buf), 0);  // discard the request
        // No Content-Length, no Connection: close -- persistent framing.
        const std::string headers = "HTTP/1.1 200 OK\r\n\r\n";
        send(conn, headers.data(), headers.size(), 0);
        // SO_LINGER{on, 0}: close() below sends RST immediately instead of
        // the usual orderly FIN, so the client's recv() in the grace window
        // fails with ECONNRESET rather than returning 0.
        struct linger lin{1, 0};
        setsockopt(conn, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
        close(conn);
    });
    bool ok = true;
    const int fd = connect_with_timeout(port, kClientTimeoutMs);
    if (fd < 0) {
        std::cerr << "FAIL [self-test head grace reset]: could not connect\n";
        ok = false;
        shutdown(listen_fd, SHUT_RDWR);
        close(listen_fd);
        listen_fd = -1;
    } else {
        const std::string req = "HEAD /x HTTP/1.1\r\nHost: t.example\r\n\r\n";
        send_all(fd, req);
        const ReadResult resp = read_http_message(fd, /*head_request=*/true, kClientTimeoutMs);
        if (resp.complete) {
            std::cerr << "FAIL [self-test head grace reset]: ECONNRESET after a HEAD response "
                         "that did not advertise Connection: close was reported complete\n";
            ok = false;
        } else if (resp.reason != kPersistenceMismatchReason) {
            std::cerr << "FAIL [self-test head grace reset]: ECONNRESET after a persistent HEAD "
                         "response was rejected without the persistence-mismatch reason (got \""
                      << resp.reason << "\")\n";
            ok = false;
        }
        close(fd);
    }
    server.join();
    if (listen_fd >= 0) close(listen_fd);
    if (ok) std::cerr << "PASS [self-test head grace reset]\n";
    return ok;
}

// Round-6 review, "Check persistent responses for trailing wire bytes": for
// a persistent (non-close) Content-Length-framed response, read_http_message
// used to return {buf, true} the instant the advertised body length was
// captured, with no check for the peer sending anything more -- unlike the
// `Connection: close` branch immediately above it, which already required a
// bounded EOF. Verifies both shapes directly: a persistent response
// followed by erroneous trailing bytes in a later TCP segment must now be
// reported incomplete, while an ordinary persistent response with no
// trailing bytes must still be reported complete (no regression on the
// common case every asserted persistent case, e.g. post_fixed/trace,
// depends on).
//
// Round-7 review, "Reject EOF on responses advertised as persistent": the
// same grace window used to accept an EOF too, so a proxy that closed every
// downstream connection while producing bytes identical to the other side
// would still pass. Now an EOF after a response that did not advertise
// `Connection: close` is reported incomplete with
// kPersistenceMismatchReason, while an EOF after one that did advertise
// close stays complete (get_client_close, connect_authority's Envoy side).
enum class PeerTail : uint8_t {
    kSettleThenClose,  // well-behaved persistent peer: quiet, closes later
    kTrailingGarbage,  // persistent peer appends bytes after the body
    kImmediateClose,   // persistent peer closes right after the body
    kAdvertisedClose,  // `Connection: close` response, then closes
    // Round-8 review, "Reject resets during the persistent-response grace
    // check": an abortive close (SO_LINGER{on, 0}, which makes the kernel
    // send RST instead of the usual FIN) makes the grace window's poll()
    // report the fd readable and recv() then fail with ECONNRESET, instead
    // of the orderly EOF (recv() == 0) kImmediateClose above exercises. Both
    // must be rejected identically: a response that did not advertise
    // `Connection: close` still promised to stay open.
    kAbortiveReset,
};

bool self_test_persistent_trailing_bytes_detected() {
    auto run_case = [](PeerTail tail, const char* label) {
        uint16_t port = 0;
        if (!allocate_loopback_port(&port)) {
            std::cerr << "FAIL [self-test " << label << "]: could not allocate a loopback port\n";
            return false;
        }
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            std::cerr << "FAIL [self-test " << label << "]: could not create listening socket\n";
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
            std::cerr << "FAIL [self-test " << label << "]: could not bind/listen\n";
            close(listen_fd);
            return false;
        }
        std::thread server([listen_fd, tail] {
            const int conn = accept(listen_fd, nullptr, nullptr);
            if (conn < 0) return;
            char buf[512];
            recv(conn, buf, sizeof(buf), 0);  // discard the request
            // No `Connection: close` (except kAdvertisedClose): persistent
            // framing, exactly the shape post_fixed/trace exercise.
            const std::string resp =
                tail == PeerTail::kAdvertisedClose
                    ? "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    : "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";
            send(conn, resp.data(), resp.size(), 0);
            if (tail == PeerTail::kTrailingGarbage) {
                struct timespec delay{0, 20'000'000};
                nanosleep(&delay, nullptr);
                const std::string garbage = "oops!";
                send(conn, garbage.data(), garbage.size(), 0);
            }
            if (tail == PeerTail::kSettleThenClose || tail == PeerTail::kTrailingGarbage) {
                struct timespec settle{0, 250'000'000};
                nanosleep(&settle, nullptr);
            }
            if (tail == PeerTail::kAbortiveReset) {
                // SO_LINGER{on, 0}: close() below sends RST immediately
                // instead of the usual orderly FIN, so the client's recv()
                // in the grace window fails with ECONNRESET rather than
                // returning 0.
                struct linger lin{1, 0};
                setsockopt(conn, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
            }
            close(conn);
        });
        bool ok = true;
        const int fd = connect_with_timeout(port, kClientTimeoutMs);
        if (fd < 0) {
            std::cerr << "FAIL [self-test " << label << "]: could not connect\n";
            ok = false;
            shutdown(listen_fd, SHUT_RDWR);
            close(listen_fd);
            listen_fd = -1;
        } else {
            const std::string req =
                "POST /x HTTP/1.1\r\nHost: t.example\r\nContent-Length: 0\r\n\r\n";
            send_all(fd, req);
            const ReadResult resp = read_http_message(fd, /*head_request=*/false, kClientTimeoutMs);
            switch (tail) {
                case PeerTail::kTrailingGarbage:
                    if (resp.complete) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: trailing bytes after a persistent response's declared "
                                     "Content-Length were not detected (reported complete)\n";
                        ok = false;
                    }
                    break;
                case PeerTail::kSettleThenClose:
                    if (!resp.complete) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: an ordinary persistent response with no trailing "
                                     "bytes was reported incomplete ("
                                  << resp.reason << ")\n";
                        ok = false;
                    }
                    break;
                case PeerTail::kImmediateClose:
                    if (resp.complete) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: EOF after a response that did not advertise "
                                     "Connection: close was reported complete\n";
                        ok = false;
                    } else if (resp.reason != kPersistenceMismatchReason) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: EOF after a persistent response was rejected without "
                                     "the persistence-mismatch reason (got \""
                                  << resp.reason << "\")\n";
                        ok = false;
                    }
                    break;
                case PeerTail::kAbortiveReset:
                    if (resp.complete) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: ECONNRESET after a response that did not advertise "
                                     "Connection: close was reported complete\n";
                        ok = false;
                    } else if (resp.reason != kPersistenceMismatchReason) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: ECONNRESET after a persistent response was rejected "
                                     "without the persistence-mismatch reason (got \""
                                  << resp.reason << "\")\n";
                        ok = false;
                    }
                    break;
                case PeerTail::kAdvertisedClose:
                    if (!resp.complete) {
                        std::cerr << "FAIL [self-test " << label
                                  << "]: EOF after a response advertising Connection: close "
                                     "was reported incomplete ("
                                  << resp.reason << ")\n";
                        ok = false;
                    }
                    break;
            }
            close(fd);
        }
        server.join();
        if (listen_fd >= 0) close(listen_fd);
        if (ok) std::cerr << "PASS [self-test " << label << "]\n";
        return ok;
    };
    bool ok = true;
    ok &= run_case(PeerTail::kTrailingGarbage, "persistent trailing bytes detected");
    ok &= run_case(PeerTail::kSettleThenClose, "persistent no trailing bytes");
    ok &= run_case(PeerTail::kImmediateClose, "persistent EOF is a persistence mismatch");
    ok &= run_case(PeerTail::kAdvertisedClose, "advertised close then EOF is complete");
    ok &= run_case(PeerTail::kAbortiveReset, "persistent ECONNRESET is a persistence mismatch");
    return ok;
}

// Envoy-side counterpart to self_test_rut_early_exit_detected() above,
// covering round-10 review, "Do not infer SIGTERM delivery from kill
// success" (the fix applies identically to EnvoyInstance::stop()): a
// docker-run child that has already exited on its own -- and is therefore
// an unreaped zombie -- by the time stop() is called must be reported as an
// unexpected exit, never a clean teardown. `/bin/true` stands in for the
// docker client (no docker binary needed; stop()'s `docker rm -f` side call
// simply fails fast and is ignored). This is caught by stop()'s very first
// precheck, same as the RUT counterpart; the round-10 waitid(WNOHANG |
// WNOWAIT) check added right before kill() sits just after it for the
// (unfalsifiable in a deterministic test) narrower window between the two.
bool self_test_envoy_early_exit_detected() {
    EnvoyInstance envoy;
    envoy.name = "rut-diff-selftest-envoy-early-exit";
    envoy.log_path = "/dev/null";
    const std::vector<std::string> argv = {"/bin/true"};
    const std::vector<char*> args = build_argv(argv);
    envoy.pid = fork();
    if (envoy.pid < 0) {
        std::cerr << "FAIL [self-test envoy early exit]: fork failed\n";
        return false;
    }
    if (envoy.pid == 0) {
        const int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
        }
        execv(args[0], args.data());
        _exit(127);
    }
    // Give the child time to exit on its own before stop() is asked to tear
    // it down.
    struct timespec ts{0, 200'000'000};
    nanosleep(&ts, nullptr);
    const bool stopped_cleanly = envoy.stop();
    bool ok = true;
    if (stopped_cleanly) {
        std::cerr << "FAIL [self-test envoy early exit]: stop() reported a clean teardown for a "
                     "process that had already exited on its own\n";
        ok = false;
    }
    if (!envoy.exited_unexpectedly) {
        std::cerr << "FAIL [self-test envoy early exit]: exited_unexpectedly was not set\n";
        ok = false;
    }
    if (ok) std::cerr << "PASS [self-test envoy early exit]\n";
    return ok;
}

// Round-7 review, "Verify the Envoy status reaped after teardown": the
// docker-run child's reaped status must match the teardown
// EnvoyInstance::stop() itself performed, exactly as
// self_test_rut_stop_verifies_exit_status() checks for RutInstance. No
// docker involved: the "docker run" child is a shell script standing in for
// the attached docker client, which exits with the container's exit code.
// stop()'s `docker rm -f <name>` side call simply fails fast (no such
// container, or no docker binary at all) and is ignored either way.
bool self_test_envoy_stop_verifies_exit_status() {
    const std::string dir = make_temp_dir("rut-diff-selftest-envoy-stop");
    if (dir.empty()) {
        std::cerr << "FAIL [self-test envoy stop status]: could not create temp directory\n";
        return false;
    }
    auto run_case = [&](const char* script_body, bool expect_clean, const char* label) {
        const std::string script = dir + "/" + label + ".sh";
        if (!write_file_mode(script, script_body, 0755)) {
            std::cerr << "FAIL [self-test envoy stop status]: could not write " << label << ".sh\n";
            return false;
        }
        EnvoyInstance envoy;
        envoy.name = std::string("rut-diff-selftest-no-such-container-") + label;
        envoy.log_path = "/dev/null";
        // Stand-in for EnvoyInstance::launch(): same fork/exec shape, argv
        // built before fork().
        std::vector<std::string> argv = {script};
        const std::vector<char*> args = build_argv(argv);
        envoy.pid = fork();
        if (envoy.pid < 0) {
            std::cerr << "FAIL [self-test envoy stop status]: could not fork " << label << ".sh\n";
            return false;
        }
        if (envoy.pid == 0) {
            const int null_fd = open("/dev/null", O_RDWR);
            if (null_fd >= 0) {
                dup2(null_fd, STDOUT_FILENO);
                dup2(null_fd, STDERR_FILENO);
                if (null_fd > STDERR_FILENO) close(null_fd);
            }
            execv(args[0], args.data());
            _exit(127);
        }
        // Give the script time to install its trap before stop() sends
        // SIGTERM.
        struct timespec ts{0, 100'000'000};
        nanosleep(&ts, nullptr);
        const bool stopped_cleanly = envoy.stop();
        bool ok = true;
        if (stopped_cleanly != expect_clean) {
            std::cerr << "FAIL [self-test envoy stop status]: stop() for " << label << " returned "
                      << (stopped_cleanly ? "clean" : "unexpected") << ", expected "
                      << (expect_clean ? "clean" : "unexpected") << " ("
                      << envoy.unexpected_exit_description << ")\n";
            ok = false;
        }
        if (envoy.exited_unexpectedly == expect_clean) {
            std::cerr << "FAIL [self-test envoy stop status]: exited_unexpectedly for " << label
                      << " is " << (envoy.exited_unexpectedly ? "true" : "false") << ", expected "
                      << (expect_clean ? "false" : "true") << "\n";
            ok = false;
        }
        return ok;
    };
    bool ok = true;
    // Envoy honored the proxied SIGTERM: docker run exits 0.
    ok &= run_case("#!/bin/sh\ntrap 'exit 0' TERM\nsleep 5\n", /*expect_clean=*/true, "term-ok");
    // `docker rm -f` force-killed the container first: docker run exits 137.
    ok &= run_case(
        "#!/bin/sh\ntrap 'exit 137' TERM\nsleep 5\n", /*expect_clean=*/true, "rm-f-killed");
    // The container died of something else in the teardown window
    // (nonzero exit that no teardown step produces): unexpected.
    ok &= run_case("#!/bin/sh\ntrap 'exit 7' TERM\nsleep 5\n", /*expect_clean=*/false, "crashed");
    // A crash signal reported by docker run as 128 + SIGSEGV: unexpected.
    ok &=
        run_case("#!/bin/sh\ntrap 'exit 139' TERM\nsleep 5\n", /*expect_clean=*/false, "segv-exit");
    if (ok) std::cerr << "PASS [self-test envoy stop status]\n";
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
    bool rut_dates_valid = true;
    bool oracle_dates_valid = true;
    const std::string rut_down =
        normalize_date_for_compare(result.downstream_bytes, preserved_date, &rut_dates_valid);
    const std::string oracle_down =
        normalize_date_for_compare(oracle_downstream, preserved_date, &oracle_dates_valid);
    const bool dates_valid = rut_dates_valid && oracle_dates_valid;
    const bool upstream_match = result.upstream_bytes == oracle_upstream;
    const bool downstream_match = rut_down == oracle_down;
    const bool match =
        result.exchange_complete && dates_valid && upstream_match && downstream_match;
    std::cerr << (match ? "PASS [self-test rut vs oracle: " : "FAIL [self-test rut vs oracle: ")
              << oracle.name << "]\n";
    if (!result.exchange_complete) {
        std::cerr << "  rut exchange did not complete (" << describe_incomplete_exchange(result)
                  << ")\n";
    }
    if (!dates_valid) {
        std::cerr << "  malformed synthesized Date (not a 29-byte RFC 1123 value): oracle="
                  << (oracle_dates_valid ? "ok" : "invalid")
                  << " rut=" << (rut_dates_valid ? "ok" : "invalid") << "\n";
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

// Round-7 review, "Validate synthesized Date values before normalizing
// them": a `date:` value that is not a well-formed 29-byte RFC 1123 date
// must fail the comparison instead of being replaced by the placeholder
// (which would let `date: garbage` on both sides compare equal), while two
// well-formed but different synthesized dates still normalize to a MATCH and
// the preserved upstream date still passes through untouched.
bool self_test_malformed_date_rejected() {
    bool ok = true;
    const std::string valid = "Tue, 01 Jan 2030 00:00:00 GMT";
    if (!is_rfc1123_http_date(valid)) {
        std::cerr << "FAIL [self-test malformed date]: a valid RFC 1123 date was rejected\n";
        ok = false;
    }
    // Round-13 review, "Validate calendar dates before normalization": Feb
    // 29 2028 is a real leap day (2028 % 4 == 0, % 100 != 0) that actually
    // falls on a Tuesday -- both the day-in-month and weekday computations
    // must accept it.
    if (!is_rfc1123_http_date("Tue, 29 Feb 2028 00:00:00 GMT")) {
        std::cerr << "FAIL [self-test malformed date]: a valid leap-day RFC 1123 date (Tue, 29 "
                     "Feb 2028) was rejected\n";
        ok = false;
    }
    for (const char* bad : {"garbage",
                            "",
                            "Xue, 01 Jan 2030 00:00:00 GMT",
                            "Tue; 01 Jan 2030 00:00:00 GMT",
                            "Tue, 00 Jan 2030 00:00:00 GMT",
                            "Tue, 01 Xxx 2030 00:00:00 GMT",
                            "Tue, 01 Jan 20X0 00:00:00 GMT",
                            "Tue, 01 Jan 2030 24:00:00 GMT",
                            "Tue, 01 Jan 2030 00:60:00 GMT",
                            "Tue, 01 Jan 2030 00:00:60 GMT",
                            "Tue, 01 Jan 2030 00:00:00 UTC",
                            "Tue, 01 Jan 2030 00:00:00 GMT ",
                            "<normalized-date>",
                            // Round-13 review, "Validate calendar dates before
                            // normalization": these all have a structurally well-formed
                            // 29-byte shape with every field independently in range, but name
                            // an impossible or mislabeled calendar date -- the exact gap a
                            // per-field-only check missed.
                            //
                            // February never has 31 days, in a leap year or not.
                            "Sun, 31 Feb 2026 12:00:00 GMT",
                            // 2026 is not a leap year (not divisible by 4), so Feb only has 28
                            // days; day 29 is invalid regardless of the weekday token.
                            "Mon, 29 Feb 2026 00:00:00 GMT",
                            // A real, validly-shaped date (Nov 6 1994, day-in-month and every
                            // field in range) that actually falls on a Sunday, mislabeled here
                            // as a Monday.
                            "Mon, 06 Nov 1994 08:49:37 GMT"}) {
        if (is_rfc1123_http_date(bad)) {
            std::cerr << "FAIL [self-test malformed date]: accepted \"" << bad << "\"\n";
            ok = false;
        }
    }

    auto make_pair =
        [](const char* name, const std::string& envoy_date, const std::string& rut_date) {
            PairCaseResult c;
            c.name = name;
            c.asserted = true;
            c.envoy.exchange_complete = c.rut.exchange_complete = true;
            c.envoy.upstream_contacted = c.rut.upstream_contacted = true;
            c.envoy.upstream_contact_count = c.rut.upstream_contact_count = 1;
            c.envoy.upstream_bytes = c.rut.upstream_bytes = "TRACE /trace HTTP/1.1\r\n\r\n";
            c.envoy.downstream_bytes =
                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\ndate: " + envoy_date + "\r\n\r\n";
            c.rut.downstream_bytes =
                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\ndate: " + rut_date + "\r\n\r\n";
            return c;
        };
    // Both sides malformed and byte-identical: must NOT match.
    if (compare_pair_case(make_pair("trace", "garbage", "garbage"))) {
        std::cerr << "FAIL [self-test malformed date]: compare_pair_case matched two identical "
                     "malformed Date values\n";
        ok = false;
    }
    // Only RUT malformed: must not match either.
    if (compare_pair_case(make_pair("trace", valid, "garbage"))) {
        std::cerr << "FAIL [self-test malformed date]: compare_pair_case matched a malformed RUT "
                     "Date against a valid Envoy one\n";
        ok = false;
    }
    // Two well-formed, different synthesized dates: the placeholder still
    // hides the unavoidable timestamp difference.
    if (!compare_pair_case(make_pair("trace", valid, "Wed, 02 Jan 2030 12:34:56 GMT"))) {
        std::cerr << "FAIL [self-test malformed date]: compare_pair_case rejected two valid, "
                     "differing synthesized Date values\n";
        ok = false;
    }
    // The preserved upstream date is exempt from validation-and-replacement
    // by name: it passes through verbatim on both sides and still matches.
    if (!compare_pair_case(make_pair("get_upstream_date_server",
                                     "Mon, 01 Jan 2024 00:00:00 GMT",
                                     "Mon, 01 Jan 2024 00:00:00 GMT"))) {
        std::cerr << "FAIL [self-test malformed date]: compare_pair_case rejected the preserved "
                     "upstream Date\n";
        ok = false;
    }
    // The oracle comparison path validates the same way.
    {
        CaseResult r;
        r.name = "trace";
        r.exchange_complete = true;
        r.upstream_bytes = "TRACE /trace HTTP/1.1\r\n\r\n";
        r.downstream_bytes = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\ndate: garbage\r\n\r\n";
        const std::string oracle_down =
            "HTTP/1.1 200 OK\r\ncontent-length: 0\r\ndate: " + valid + "\r\n\r\n";
        const OracleCase oracle{"trace",
                                r.upstream_bytes.data(),
                                r.upstream_bytes.size(),
                                oracle_down.data(),
                                oracle_down.size()};
        if (compare_case_against_oracle(r, oracle)) {
            std::cerr << "FAIL [self-test malformed date]: compare_case_against_oracle accepted a "
                         "malformed RUT Date\n";
            ok = false;
        }
        r.downstream_bytes = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\ndate: " + valid + "\r\n\r\n";
        if (!compare_case_against_oracle(r, oracle)) {
            std::cerr << "FAIL [self-test malformed date]: compare_case_against_oracle rejected a "
                         "valid RUT Date\n";
            ok = false;
        }
    }
    if (ok) std::cerr << "PASS [self-test malformed date]\n";
    return ok;
}

// Round-6-review parity for RUT (PR #694 mirrored onto pair mode's RUT
// launch, launch_rut_with_port_retry() above): a genuine listener-port bind
// collision must be retried on a fresh port rather than reported as a
// failure. allocate_distinct_ports()/allocate_loopback_port() never hand out
// an already-bound port on their own, so nothing in the normal run exercises
// this path -- this test forces the collision deterministically by holding
// the first candidate port bound and listening (without SO_REUSEPORT) for
// the whole first attempt, exactly like another process racing this harness
// for the same ephemeral port would, then releases it once the race window
// (rut's own first bind() attempt) has passed. Needs the real
// `rut`/`rut-envoy-convert` binaries; skipped (not failed) without them,
// same contract as run_self_test_rut_pass() below.
bool self_test_rut_port_retry(const std::string& rut_binary, const std::string& converter_binary) {
    if (rut_binary.empty() || converter_binary.empty()) {
        std::cerr << "NOTE: --self-test rut port retry skipped (pass [rut-binary] "
                     "[rut-envoy-convert-binary] to run it)\n";
        return true;
    }
    const std::string dir = make_temp_dir("rut-envoy-portretry");
    if (dir.empty()) {
        std::cerr << "FAIL [self-test rut port retry]: could not create temp directory\n";
        return false;
    }
    uint16_t listen_port = 0, upstream_port = 0;
    if (!allocate_distinct_ports({&listen_port, &upstream_port})) {
        std::cerr << "FAIL [self-test rut port retry]: could not allocate loopback ports\n";
        return false;
    }
    const uint16_t first_candidate = listen_port;

    // Pre-bind the first candidate port live and hold it for the duration of
    // rut's first bind attempt -- deliberately without SO_REUSEPORT, so
    // rut's own SO_REUSEPORT bind() (create_listen_socket(),
    // src/runtime/socket.cc) still collides: Linux only shares a port across
    // SO_REUSEPORT sockets when every socket that ever bound it, including
    // the first, opted in. Deliberately bind()-only, no listen(): a bound
    // socket already reserves the port for EADDRINUSE purposes, and leaving
    // it out of LISTEN state makes an incoming connect() fail closed
    // (ECONNREFUSED) instead of being silently accepted by this held socket
    // itself -- wait_ready()/tcp_port_open() otherwise cannot tell "rut is
    // ready" apart from "something else answered the probe", which would
    // false-positive the very race this test forces.
    const int held_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (held_fd < 0) {
        std::cerr << "FAIL [self-test rut port retry]: could not create a socket to hold the "
                     "candidate port\n";
        return false;
    }
    sockaddr_in held_addr{};
    held_addr.sin_family = AF_INET;
    held_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    held_addr.sin_port = htons(first_candidate);
    if (bind(held_fd, reinterpret_cast<sockaddr*>(&held_addr), sizeof(held_addr)) != 0) {
        std::cerr << "FAIL [self-test rut port retry]: could not pre-bind the candidate port\n";
        close(held_fd);
        return false;
    }

    RutInstance rut;
    std::string rut_source_path;
    std::string error;
    const bool launched = launch_rut_with_port_retry(dir,
                                                     rut_binary,
                                                     converter_binary,
                                                     &listen_port,
                                                     upstream_port,
                                                     &rut_source_path,
                                                     &rut,
                                                     &error);
    // The race window is over the instant launch_rut_with_port_retry()
    // returns (success or not): release the held port either way.
    close(held_fd);

    bool ok = true;
    if (!launched) {
        std::cerr << "FAIL [self-test rut port retry]: " << error << "\n";
        dump_rut_log(rut.log_path);
        ok = false;
    } else if (listen_port == first_candidate) {
        std::cerr << "FAIL [self-test rut port retry]: rut bound the pre-held port "
                  << first_candidate << " instead of retrying on a fresh one\n";
        ok = false;
    } else {
        std::cerr << "PASS [self-test rut port retry]: retried " << first_candidate << " -> "
                  << listen_port << "\n";
    }
    rut.stop();
    return ok;
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
        // Same end-to-end port reservation as run_oracle_milestone_s() /
        // run_pair_milestone_s(): the recording upstream binds and listens
        // right here (allocate_bound_loopback_port()), so no other process
        // can take it before RecordingUpstream::adopt() below takes over.
        BoundPort upstream_bound;
        if (!allocate_bound_loopback_port(&upstream_bound)) {
            std::cerr << "FAIL [self-test rut]: could not allocate a loopback port for the "
                         "recording upstream\n";
            return false;
        }
        const uint16_t upstream_port = upstream_bound.port;
        uint16_t listen_port = 0;
        if (!allocate_distinct_ports({&listen_port})) {
            std::cerr << "FAIL [self-test rut]: could not allocate loopback ports\n";
            close(upstream_bound.fd);
            return false;
        }

        RecordingUpstream upstream;
        const auto all_cases = run1_cases();
        for (const auto& spec : all_cases)
            upstream.set_reply(spec.upstream_path, spec.upstream_reply);
        if (!upstream.adopt(upstream_bound.fd)) {
            std::cerr << "FAIL [self-test rut]: could not start recording upstream\n";
            return false;
        }

        // RUT's own listener port, like Envoy's/RUT's elsewhere in this file,
        // can only be probe-allocated -- retry on a bind collision the same
        // way launch_rut_with_port_retry() does everywhere else.
        RutInstance rut;
        std::string rut_source_path;
        std::string ready_error;
        if (!launch_rut_with_port_retry(dir,
                                        rut_binary,
                                        converter_binary,
                                        &listen_port,
                                        upstream_port,
                                        &rut_source_path,
                                        &rut,
                                        &ready_error)) {
            std::cerr << "FAIL [self-test rut]: " << ready_error << "\n";
            dump_rut_log(rut.log_path);
            upstream.stop();
            return false;
        }
        // The readiness probe launch_rut_with_port_retry() just ran
        // (wait_ready_and_confirm_ownership() -> rut_probe_confirms_ownership())
        // sends an `OPTIONS *` request, which every generated rut config
        // answers locally; it must never reach this live recording upstream
        // (round-8 review, "Verify RUT owns the port before declaring
        // readiness": "The probe must not contact the recording upstream").
        // Check this before running any case, while the upstream has
        // recorded nothing else yet.
        if (!upstream.all_requests().empty()) {
            std::cerr << "FAIL [self-test rut]: the readiness probe contacted the recording "
                         "upstream (expected zero requests before any case runs)\n";
            rut.stop();
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
        uint16_t listen_port = 0;
        if (!allocate_distinct_ports({&listen_port})) {
            std::cerr << "FAIL [self-test rut]: could not allocate loopback ports\n";
            return false;
        }
        // The connect_failure case's "closed" port must stay reserved end to
        // end, exactly like run_pair_milestone_s()'s ClosedPortReservation:
        // allocate_distinct_ports() only probe-binds and immediately
        // releases each port, leaving a window for another process to bind
        // and listen on it before this exchange's connect() attempt below,
        // which would then hit an unrelated listener instead of exercising
        // connection refusal (round-8 review, "Reserve the self-test's
        // connect-failure port").
        BoundPort closed_reserved;
        if (!allocate_reserved_closed_port(&closed_reserved)) {
            std::cerr << "FAIL [self-test rut]: could not allocate the connect_failure case's "
                         "closed port\n";
            return false;
        }
        struct ClosedPortReservation {
            int fd;
            ~ClosedPortReservation() {
                if (fd >= 0) close(fd);
            }
            void release() {
                if (fd >= 0) close(fd);
                fd = -1;
            }
        } closed_reservation{closed_reserved.fd};
        const uint16_t closed_port = closed_reserved.port;
        const std::string bootstrap_path = dir + "/bootstrap.json";
        if (!write_file_mode(bootstrap_path, render_bootstrap(listen_port, closed_port), 0644)) {
            std::cerr << "FAIL [self-test rut]: could not write bootstrap.json\n";
            return false;
        }
        RutInstance rut;
        std::string rut_source_path;
        std::string ready_error;
        if (!launch_rut_with_port_retry(dir,
                                        rut_binary,
                                        converter_binary,
                                        &listen_port,
                                        closed_port,
                                        &rut_source_path,
                                        &rut,
                                        &ready_error)) {
            std::cerr << "FAIL [self-test rut]: " << ready_error << "\n";
            dump_rut_log(rut.log_path);
            return false;
        }
        CaseResult r;
        if (!run_client_case(listen_port, connect_failure_case(), &r))
            std::cerr << "WARN: case connect_failure exchange did not complete cleanly ("
                      << describe_incomplete_exchange(r) << ")\n";
        r.name = "connect_failure";
        // The connect_failure exchange above is done; safe to release now.
        closed_reservation.release();
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
    ok &= self_test_rut_wait_ready_ownership();
    ok &= self_test_rut_log_confirms_listener();
    ok &= self_test_count_listeners_on_port();
    ok &= self_test_count_listeners_on_port_live_reuseport();
    ok &= self_test_reserved_closed_port();
    ok &= self_test_duplicate_upstream_rejected();
    ok &= self_test_duplicate_upstream_record_only_not_fatal();
    ok &= self_test_unexpected_upstream_path_rejected();
    ok &= self_test_unexpected_upstream_path_record_only_not_fatal();
    ok &= self_test_unexpected_upstream_path_ignores_asserted_local_case();
    ok &= self_test_unexpected_upstream_path_rejected_even_with_all_contacts();
    ok &= self_test_unexpected_upstream_path_record_only_not_fatal_even_with_all_contacts();
    ok &= self_test_record_only_misroute_isolated_by_batch();
    ok &= self_test_rut_early_exit_detected();
    ok &= self_test_rut_stop_requires_delivered_signal();
    ok &= self_test_rut_stop_verifies_exit_status();
    ok &= self_test_stop_echild_precheck_no_signal();
    ok &= self_test_pair_both_failed_rejected();
    ok &= self_test_pair_unexercised_forwarding_rejected();
    ok &= self_test_pair_exempt_cases_zero_contact_matches();
    ok &= self_test_pair_exempt_cases_nonzero_contact_rejected();
    ok &= self_test_pair_record_only_crash_is_a_note();
    ok &= self_test_pair_isolated_instances_crash_classification();
    ok &= self_test_accept_unblocks_on_shutdown_close();
    ok &= self_test_head_body_detected();
    ok &= self_test_head_grace_reset_detected();
    ok &= self_test_persistent_trailing_bytes_detected();
    ok &= self_test_envoy_early_exit_detected();
    ok &= self_test_envoy_stop_verifies_exit_status();
    ok &= self_test_malformed_date_rejected();
    ok &= self_test_rut_port_retry(rut_binary, converter_binary);
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
