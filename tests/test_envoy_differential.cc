// Envoy oracle-recording differential harness (envoy-pr-plan.md, PR 2).
//
// This binary never asserts RUT behavior: no RUT/converter/runtime code is
// invoked here at all. It drives the pinned Envoy image against a small
// recording upstream over loopback, records the exact bytes observed on the
// wire, and writes them as a ready-to-commit C++ header
// (tests/fixtures/envoy_oracle_milestone_s.inc once the lead commits the CI
// artifact). Only two invariants are asserted for real (see
// `assert_get_smoke` / `assert_connect_failure`); everything else is
// recorded evidence for PRs 3-6, not a behavioral claim.
//
// Modes:
//   --self-test                     Exercises the pieces that need no
//                                    docker: the recording upstream against
//                                    the raw client on loopback, and the
//                                    transcript writer's escaping.
//   --oracle-milestone-s <out-path> Runs the milestone-S bootstrap through
//                                    the pinned Envoy image (docker
//                                    required); writes the transcript to
//                                    <out-path>. Exits 77 (SKIP) when docker
//                                    or the pinned image is unavailable,
//                                    unless RUT_ENVOY_DIFFERENTIAL_REQUIRED=1
//                                    is set, in which case it exits 1.
//
// This file is intentionally independent of tests/test_nginx_differential.cc
// (do not copy it): the scope here is much smaller (one bootstrap shape, no
// byte-equality assertions, no converter/runtime involvement) and does not
// need that file's process-launch self-check infrastructure.

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
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RUT_PINNED_ENVOY_IMAGE
#error "RUT_PINNED_ENVOY_IMAGE must be provided by the build system"
#endif

namespace {

constexpr const char* kEnvoyImage = RUT_PINNED_ENVOY_IMAGE;
constexpr int kClientTimeoutMs = 3000;

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

bool allocate_distinct_ports(const std::vector<uint16_t*>& outs) {
    std::vector<uint16_t> seen;
    for (uint16_t* out : outs) {
        for (int attempt = 0; attempt < 32; attempt++) {
            uint16_t candidate = 0;
            if (!allocate_loopback_port(&candidate)) return false;
            if (std::find(seen.begin(), seen.end(), candidate) == seen.end()) {
                seen.push_back(candidate);
                *out = candidate;
                break;
            }
        }
    }
    return true;
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
    // A HEAD response never carries a body (RFC 9110 §9.3.2): the headers
    // are the entire message, so finding the blank line is completion.
    if (head_request) return {buf, true};
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
    bool start(uint16_t port) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;
        const int one = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
        if (listen(listen_fd_, 16) != 0) return false;
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

struct EnvoyInstance {
    pid_t pid = -1;
    std::string name;
    std::string log_path;

    bool launch(const std::string& bootstrap_path, uint16_t /*listen_port*/) {
        // docker run --pull=never --rm --network host --name <name>
        //   -e ENVOY_UID=0
        //   -v <bootstrap>:/etc/envoy/rut-bootstrap.json:ro,z
        //   <image> -c /etc/envoy/rut-bootstrap.json
        //   --concurrency 1 --disable-hot-restart --log-level warn
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
            "--log-level",   "warn"};
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
            execvp(args[0], args.data());
            _exit(127);
        }
        return true;
    }

    void stop() {
        if (pid > 0) kill(pid, SIGTERM);
        run_and_wait({"docker", "rm", "-f", name}, 10'000);
        if (pid > 0) {
            const int64_t deadline = now_ms() + 5000;
            int status = 0;
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
        }
    }

    ~EnvoyInstance() { stop(); }
};

void dump_log(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::cerr << "---- envoy log (" << path << ") ----\n" << in.rdbuf() << "\n---- end log ----\n";
}

bool wait_ready(uint16_t port, EnvoyInstance& envoy, int timeout_ms, std::string* error) {
    const int64_t deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        if (envoy.pid > 0) {
            int status = 0;
            const pid_t waited = waitpid(envoy.pid, &status, WNOHANG);
            if (waited == envoy.pid) {
                envoy.pid = -1;
                *error = "docker run exited before Envoy became ready";
                return false;
            }
        }
        if (tcp_port_open(port)) return true;
        struct timespec ts{0, 50'000'000};
        nanosleep(&ts, nullptr);
    }
    *error = "timed out waiting for Envoy to accept connections";
    return false;
}

// ── Bootstrap template ──────────────────────────────────────────────────

// The milestone-S bootstrap (docs/envoy-converter.md, "milestone-S";
// tests/test_envoy_convert.cc's `milestone_s_json`), with the listener and
// upstream endpoint ports left as placeholders so this harness can bind
// loopback ephemeral ports per run.
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
    return sent;
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
    return static_cast<bool>(out);
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

int run_oracle_milestone_s(const std::string& output_path) {
    const std::string missing = check_docker_prerequisites();
    if (!missing.empty()) return missing_prerequisite(missing);

    uint16_t listen_port1 = 0, upstream_port1 = 0, listen_port2 = 0, closed_port = 0;
    if (!allocate_distinct_ports({&listen_port1, &upstream_port1, &listen_port2, &closed_port})) {
        std::cerr << "FAIL: could not allocate loopback ports\n";
        return 1;
    }

    std::vector<CaseResult> results;

    // ---- Run 1: live recording upstream ----
    {
        const std::string dir = make_temp_dir("rut-envoy-oracle");
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

        RecordingUpstream upstream;
        for (const auto& spec : run1_cases())
            upstream.set_reply(spec.upstream_path, spec.upstream_reply);
        if (!upstream.start(upstream_port1)) {
            std::cerr << "FAIL: could not start recording upstream\n";
            return 1;
        }

        EnvoyInstance envoy;
        envoy.name = make_container_name("run1");
        envoy.log_path = dir + "/envoy.log";
        if (!envoy.launch(bootstrap_path, listen_port1)) {
            std::cerr << "FAIL: could not fork/exec docker run\n";
            return 1;
        }
        std::string ready_error;
        if (!wait_ready(listen_port1, envoy, 15'000, &ready_error)) {
            std::cerr << "FAIL: " << ready_error << "\n";
            dump_log(envoy.log_path);
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
        const std::string dir = make_temp_dir("rut-envoy-oracle2");
        if (dir.empty()) {
            std::cerr << "FAIL: could not create temp directory\n";
            return 1;
        }
        const std::string bootstrap_path = dir + "/bootstrap.json";
        if (!write_file_mode(bootstrap_path, render_bootstrap(listen_port2, closed_port), 0644)) {
            std::cerr << "FAIL: could not write bootstrap.json\n";
            return 1;
        }
        EnvoyInstance envoy;
        envoy.name = make_container_name("run2");
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
        CaseSpec spec = run1_cases().front();  // get_smoke's exact client bytes
        CaseResult r;
        if (!run_client_case(listen_port2, spec, &r))
            std::cerr << "WARN: case connect_failure exchange did not complete cleanly\n";
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
    uint16_t port = 0;
    if (!allocate_loopback_port(&port)) {
        std::cerr << "FAIL [self-test upstream]: could not allocate a loopback port\n";
        return false;
    }
    RecordingUpstream server;
    server.set_reply("/x", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    server.set_reply("/head", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    if (!server.start(port)) {
        std::cerr << "FAIL [self-test upstream]: could not start server\n";
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
    {
        uint16_t port = 0;
        if (!allocate_loopback_port(&port)) {
            std::cerr << "FAIL [self-test partial]: could not allocate a loopback port\n";
            return false;
        }
        const int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            std::cerr << "FAIL [self-test partial]: could not create listen socket\n";
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
            std::cerr << "FAIL [self-test partial]: could not bind/listen\n";
            close(listen_fd);
            return false;
        }
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
        server.join();
        close(listen_fd);
    }

    // write_transcript(): must reject an incomplete exchange and a
    // duplicated upstream contact, in both cases without creating the
    // output file, and must accept a fully valid run.
    {
        const std::string dir = make_temp_dir("rut-envoy-selftest");
        if (dir.empty()) {
            std::cerr << "FAIL [self-test partial]: could not create temp dir\n";
            return false;
        }
        const std::string out_path = dir + "/transcript.inc";

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
    }

    if (ok) std::cerr << "PASS [self-test partial exchange rejection]\n";
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

int run_self_test() {
    bool ok = true;
    ok &= self_test_escaping();
    ok &= self_test_recording_upstream();
    ok &= self_test_partial_exchange_rejection();
    ok &= self_test_argv_builder();
    return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc >= 2 && std::string(argv[1]) == "--self-test") return run_self_test();
    if (argc >= 3 && std::string(argv[1]) == "--oracle-milestone-s")
        return run_oracle_milestone_s(argv[2]);
    std::cerr << "usage: " << argv[0] << " --self-test | --oracle-milestone-s <output-path>\n";
    return 2;
}
