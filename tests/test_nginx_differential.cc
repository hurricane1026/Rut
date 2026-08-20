#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using rut::u16;
using rut::u32;

namespace {

static constexpr const char* kNginxImage =
    "nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40";
static constexpr char kRequest[] =
    "GET /encoded/%7Euser?tag=unreserved HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "X-Dup: one\r\n"
    "X-Dup: two\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kGatewayRequest[] =
    "GET /missing?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kBackendResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: differential-backend\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
    "Content-Length: 2\r\n\r\nok";
static constexpr char kApiResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 2\r\n"
    "Connection: close\r\n"
    "\r\nok";
static constexpr char kGatewayResponseNormalized[] =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 157\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<html>\r\n"
    "<head><title>502 Bad Gateway</title></head>\r\n"
    "<body>\r\n"
    "<center><h1>502 Bad Gateway</h1></center>\r\n"
    "<hr><center>nginx/1.29.7</center>\r\n"
    "</body>\r\n"
    "</html>\r\n";

struct Child {
    pid_t pid = -1;
    std::string log_path;
    int status = 0;
    bool reaped = false;
    bool status_valid = false;
};

static bool poll_child(Child& child) {
    if (child.pid < 0) return child.reaped;
    if (child.reaped) return true;
    int status = 0;
    const pid_t rc = waitpid(child.pid, &status, WNOHANG);
    if (rc == child.pid) {
        child.status = status;
        child.status_valid = true;
        child.reaped = true;
        return true;
    }
    if (rc < 0 && errno == EINTR) return false;
    if (rc < 0) {
        child.reaped = true;
        child.status_valid = false;
        return true;
    }
    return false;
}

static bool wait_child(Child& child, int timeout_ms) {
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 20) {
        if (poll_child(child)) return true;
        usleep(20'000);
    }
    return false;
}

static bool spawn_child(const std::vector<std::string>& args,
                        const std::string& log_path,
                        Child& child) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    const pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        const int fd = open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) _exit(127);
        if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) _exit(127);
        close(fd);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    child.pid = pid;
    child.log_path = log_path;
    child.status = 0;
    child.reaped = false;
    child.status_valid = false;
    return true;
}

static bool stop_child(Child& child) {
    if (child.pid < 0) return true;
    if (poll_child(child)) {
        child.pid = -1;
        return false;
    }
    if (kill(child.pid, SIGTERM) != 0) {
        if (errno != ESRCH) {
            (void)kill(child.pid, SIGKILL);
            (void)wait_child(child, 2000);
        } else {
            (void)poll_child(child);
        }
        child.pid = -1;
        return false;
    }
    if (!wait_child(child, 3000)) {
        kill(child.pid, SIGKILL);
        const bool reaped = wait_child(child, 2000);
        if (!reaped) {
            const pid_t rc = waitpid(child.pid, &child.status, 0);
            child.reaped = rc == child.pid;
            child.status_valid = child.reaped;
            child.pid = -1;
            return false;
        }
        child.pid = -1;
        // SIGKILL was needed for cleanup; this is always a test failure.
        return false;
    }
    const bool clean = child.status_valid &&
                       ((WIFEXITED(child.status) && WEXITSTATUS(child.status) == 0) ||
                        (WIFSIGNALED(child.status) && WTERMSIG(child.status) == SIGTERM));
    child.pid = -1;
    return clean;
}

static bool command_ok(const std::vector<std::string>& args,
                       const std::string& log_path = "/dev/null") {
    Child child;
    if (!spawn_child(args, log_path, child)) return false;
    if (!wait_child(child, 10'000)) {
        kill(child.pid, SIGKILL);
        const pid_t rc = waitpid(child.pid, &child.status, 0);
        child.reaped = rc == child.pid;
        child.status_valid = child.reaped;
        child.pid = -1;
        return false;
    }
    child.pid = -1;
    return child.status_valid && WIFEXITED(child.status) && WEXITSTATUS(child.status) == 0;
}

struct ChildGuard {
    Child child;
    ~ChildGuard() { (void)stop_child(child); }
};

static bool docker_remove(const std::string& name) {
    return command_ok({"docker", "rm", "-f", name});
}

struct DockerGuard {
    explicit DockerGuard(const std::string& name) : name(name) {}
    std::string name;
    bool active = true;

    bool remove() {
        if (!active) return true;
        if (!docker_remove(name)) return false;
        active = false;
        return true;
    }

    ~DockerGuard() {
        if (active) (void)docker_remove(name);
    }
};

static bool run_named_docker_probe(const std::string& name,
                                   const std::string& log_path,
                                   std::string& error) {
    Child probe;
    bool probe_ok = false;
    if (spawn_child({"docker", "run", "--pull=never", "--network", "host", "--name", name,
                     kNginxImage, "nginx", "-v"},
                    log_path,
                    probe)) {
        if (wait_child(probe, 10'000)) {
            probe_ok = probe.status_valid && WIFEXITED(probe.status) &&
                       WEXITSTATUS(probe.status) == 0;
            probe.pid = -1;
        } else {
            // Reap the CLI before rm -f so a timed-out docker client cannot
            // race the explicit container cleanup.
            (void)stop_child(probe);
        }
    } else {
        error = "failed to start host-network probe CLI";
    }
    const bool removed = docker_remove(name);
    if (!removed) {
        error = "docker rm -f failed for host-network probe " + name;
        return false;
    }
    if (!probe_ok) {
        if (error.empty()) error = "host-network startup probe failed";
        return false;
    }
    return true;
}

struct TempDir {
    char path[64] = "/tmp/rut-nginx-differential-XXXXXX";
    bool created = false;
    std::string source;
    std::string nginx_config;
    std::string nginx_log;
    std::string rut_log;
    std::string preflight_log;

    bool create() {
        if (!mkdtemp(path)) return false;
        created = true;
        source = std::string(path) + "/generated.rut";
        nginx_config = std::string(path) + "/nginx.conf";
        nginx_log = std::string(path) + "/nginx.log";
        rut_log = std::string(path) + "/rut.log";
        preflight_log = std::string(path) + "/preflight.log";
        return true;
    }

    ~TempDir() {
        if (created) {
            unlink(source.c_str());
            unlink(nginx_config.c_str());
            unlink(nginx_log.c_str());
            unlink(rut_log.c_str());
            unlink(preflight_log.c_str());
            rmdir(path);
        }
    }
};

static bool write_file(const std::string& path, const char* data, size_t len) {
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        const ssize_t n = write(fd, data + off, len - off);
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        close(fd);
        return false;
    }
    return close(fd) == 0;
}

static bool allocate_port(u16& port) {
    for (int attempt = 0; attempt < 8; attempt++) {
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bool ok = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        socklen_t len = sizeof(addr);
        if (ok) ok = getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0;
        if (ok) port = ntohs(addr.sin_port);
        close(fd);
        if (ok && port != 0) return true;
    }
    return false;
}

static int connect_once(u16 port) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

static bool wait_ready(u16 port, Child& child, std::string& error) {
    for (int attempt = 0; attempt < 200; attempt++) {
        if (poll_child(child)) {
            error = "process exited before readiness";
            return false;
        }
        const int fd = connect_once(port);
        if (fd >= 0) {
            close(fd);
            return true;
        }
        usleep(25'000);
    }
    error = "readiness timeout";
    return false;
}

static bool send_all(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        const ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

static size_t header_end(const std::vector<char>& bytes) {
    if (bytes.size() < 4) return 0;
    for (size_t i = 3; i < bytes.size(); i++)
        if (bytes[i - 3] == '\r' && bytes[i - 2] == '\n' && bytes[i - 1] == '\r' &&
            bytes[i] == '\n')
            return i + 1;
    return 0;
}

static bool parse_content_length(const std::vector<char>& bytes, size_t end, size_t& length) {
    const char needle[] = "content-length:";
    for (size_t i = 0; i + sizeof(needle) - 1 <= end; i++) {
        bool match = true;
        for (size_t j = 0; j < sizeof(needle) - 1; j++) {
            char c = bytes[i + j];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            if (c != needle[j] && !(j == 14 && c == ':')) {
                match = false;
                break;
            }
        }
        if (!match || (i != 0 && bytes[i - 1] != '\n')) continue;
        size_t p = i + sizeof(needle) - 1;
        while (p < end && (bytes[p] == ' ' || bytes[p] == '\t')) p++;
        if (p == end || bytes[p] < '0' || bytes[p] > '9') return false;
        size_t value = 0;
        while (p < end && bytes[p] >= '0' && bytes[p] <= '9') {
            const size_t digit = static_cast<size_t>(bytes[p++] - '0');
            if (value > (1u << 20) || value * 10 > (1u << 20) - digit) return false;
            value = value * 10 + digit;
        }
        length = value;
        return true;
    }
    return false;
}

static bool read_response(int fd, std::vector<char>& bytes, std::string& error) {
    using Clock = std::chrono::steady_clock;
    static constexpr auto kResponseReadBudget = std::chrono::seconds(5);
    const Clock::time_point deadline = Clock::now() + kResponseReadBudget;
    const auto deadline_expired = [&]() { return Clock::now() >= deadline; };

    bytes.clear();
    bytes.reserve(4096);
    for (;;) {
        if (deadline_expired()) {
            error = "response deadline exceeded";
            return false;
        }

        char buf[4096];
        const ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            bytes.insert(bytes.end(), buf, buf + n);
            const size_t end = header_end(bytes);
            if (end != 0) {
                size_t body_len = 0;
                if (!parse_content_length(bytes, end, body_len)) {
                    error = "response has no valid Content-Length";
                    return false;
                }
                if (bytes.size() >= end + body_len) {
                    if (bytes.size() != end + body_len) error = "response has trailing bytes";
                    return bytes.size() == end + body_len;
                }
            }
            if (deadline_expired()) {
                error = "response deadline exceeded";
                return false;
            }
            continue;
        }
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (deadline_expired()) {
                error = "response deadline exceeded";
                return false;
            }
            continue;
        }
        error = n == 0 ? "response ended before Content-Length body" : "response read failed";
        return false;
    }
}

static bool read_eof(int fd, std::string& error) {
    for (int attempt = 0; attempt < 40; attempt++) {
        pollfd p{fd, POLLIN | POLLHUP | POLLERR, 0};
        const int ready = poll(&p, 1, 50);
        if (ready < 0) {
            if (errno == EINTR) continue;
            error = "EOF poll failed";
            return false;
        }
        if (ready == 0) continue;
        char extra[256];
        const ssize_t n = recv(fd, extra, sizeof(extra), 0);
        if (n == 0) return true;
        if (n > 0) {
            error = "bytes arrived after the Content-Length response";
            return false;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        error = "EOF recv failed";
        return false;
    }
    error = "EOF timeout";
    return false;
}

struct DeadPort {
    int fd = -1;

    bool reserve(u16 port) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(fd);
            fd = -1;
            return false;
        }
        return true;  // Deliberately do not listen: connect gets ECONNREFUSED.
    }

    ~DeadPort() {
        if (fd >= 0) close(fd);
    }
};

struct Recorder {
    int listen_fd = -1;
    u16 port = 0;
    u32 expected_requests = 1;
    std::atomic<bool> running{false};
    std::atomic<u32> accepted{0};
    std::atomic<u32> requests{0};
    std::vector<char> request;
    std::vector<std::vector<char>> history;
    pthread_t thread{};
    bool thread_started = false;

    static void* run(void* opaque) {
        auto* self = static_cast<Recorder*>(opaque);
        const int fd = self->listen_fd;
        while (self->running.load(std::memory_order_acquire)) {
            pollfd listener_poll{fd, POLLIN, 0};
            const int ready = poll(&listener_poll, 1, 50);
            if (ready < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (!self->running.load(std::memory_order_acquire)) break;
            if (ready == 0 || !(listener_poll.revents & POLLIN)) continue;
            const int client = accept(fd, nullptr, nullptr);
            if (client < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }
            self->accepted.fetch_add(1, std::memory_order_release);
            const int flags = fcntl(client, F_GETFL, 0);
            if (flags < 0 || fcntl(client, F_SETFL, flags | O_NONBLOCK) != 0) {
                close(client);
                continue;
            }
            timeval send_timeout{0, 200000};
            (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
            std::vector<char> wire;
            char buf[4096];
            for (;;) {
                pollfd client_poll{client, POLLIN, 0};
                const int client_ready = poll(&client_poll, 1, 50);
                if (client_ready < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (!self->running.load(std::memory_order_acquire)) break;
                if (client_ready == 0) continue;
                const ssize_t n = recv(client, buf, sizeof(buf), 0);
                if (n > 0) {
                    wire.insert(wire.end(), buf, buf + n);
                    if (header_end(wire) != 0) break;
                } else if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                    continue;
                } else {
                    break;
                }
            }
            const bool complete = header_end(wire) != 0;
            if (complete) {
                self->history.push_back(wire);
                if (self->history.size() == 1) self->request = wire;
                self->requests.fetch_add(1, std::memory_order_release);
                (void)send_all(client, kBackendResponse, sizeof(kBackendResponse) - 1);
            }
            shutdown(client, SHUT_RDWR);
            close(client);
            if (self->requests.load(std::memory_order_acquire) >= self->expected_requests) {
                self->running.store(false, std::memory_order_release);
                break;
            }
        }
        return nullptr;
    }

    bool setup(u16 requested_port = 0, u32 expected = 1) {
        if (expected == 0 || expected > 3) return false;
        expected_requests = expected;
        for (int attempt = 0; attempt < 8; attempt++) {
            listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (listen_fd < 0) continue;
            int one = 1;
            setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(requested_port);
            if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
                listen(listen_fd, 8) != 0) {
                close(listen_fd);
                listen_fd = -1;
                continue;
            }
            socklen_t len = sizeof(addr);
            if (getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
                close(listen_fd);
                listen_fd = -1;
                continue;
            }
            const int flags = fcntl(listen_fd, F_GETFL, 0);
            if (flags < 0 || fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
                close(listen_fd);
                listen_fd = -1;
                continue;
            }
            port = ntohs(addr.sin_port);
            accepted.store(0, std::memory_order_relaxed);
            requests.store(0, std::memory_order_relaxed);
            request.clear();
            history.clear();
            running.store(true, std::memory_order_release);
            if (pthread_create(&thread, nullptr, &Recorder::run, this) == 0) {
                thread_started = true;
                return true;
            }
            running.store(false, std::memory_order_release);
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        return false;
    }

    void stop() {
        running.store(false, std::memory_order_release);
        if (thread_started) {
            pthread_join(thread, nullptr);
            thread_started = false;
        }
        if (listen_fd >= 0) {
            shutdown(listen_fd, SHUT_RDWR);
            close(listen_fd);
            listen_fd = -1;
        }
    }

    ~Recorder() { stop(); }
};

static bool normalize_date(std::vector<char>& bytes) {
    const char needle[] = "Date: ";
    for (size_t i = 0; i + sizeof(needle) - 1 + 30 < bytes.size(); i++) {
        if (memcmp(bytes.data() + i, needle, sizeof(needle) - 1) != 0) continue;
        if (i != 0 && bytes[i - 1] != '\n') continue;
        if (bytes[i + sizeof(needle) - 1 + 29] != '\r' ||
            bytes[i + sizeof(needle) - 1 + 30] != '\n')
            return false;
        memset(bytes.data() + i + sizeof(needle) - 1, 'X', 29);
        return true;
    }
    return false;
}

static void dump_wire(const char* label, const std::vector<char>& wire) {
    const size_t n = wire.size() < 4096 ? wire.size() : 4096;
    std::cerr << label << " length=" << wire.size() << " escaped=";
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = static_cast<unsigned char>(wire[i]);
        if (c == '\r') std::cerr << "\\r";
        else if (c == '\n') std::cerr << "\\n";
        else if (c == '\t') std::cerr << "\\t";
        else if (c >= 0x20 && c < 0x7f) std::cerr << static_cast<char>(c);
        else std::cerr << "\\x" << std::hex << static_cast<int>(c) << std::dec;
    }
    std::cerr << "\n" << label << " hex=" << std::hex;
    for (size_t i = 0; i < n; i++) std::cerr << (i ? " " : "") << (static_cast<int>(static_cast<unsigned char>(wire[i])) & 0xff);
    std::cerr << std::dec << "\n";
}

static void dump_log(const std::string& path, const char* label) {
    const int fd = open(path.c_str(), O_RDONLY);
    std::cerr << label << " (max 8192 bytes):\n";
    if (fd < 0) {
        std::cerr << "<unavailable>\n";
        return;
    }
    char buf[1024];
    size_t total = 0;
    while (total < 8192) {
        const size_t want = sizeof(buf) < 8192 - total ? sizeof(buf) : 8192 - total;
        const ssize_t n = read(fd, buf, want);
        if (n > 0) {
            std::cerr.write(buf, n);
            total += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (total == 0) std::cerr << "<empty>\n";
    else if (total == 8192) std::cerr << "\n<truncated>\n";
    close(fd);
}

static bool log_contains(const std::string& path, const char* needle) {
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    std::string contents;
    char buf[1024];
    while (contents.size() < 8192) {
        const size_t want = sizeof(buf) < 8192 - contents.size() ? sizeof(buf) : 8192 - contents.size();
        const ssize_t n = read(fd, buf, want);
        if (n > 0) {
            contents.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);
    return contents.find(needle) != std::string::npos;
}

static bool log_empty(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return true;
    char byte = 0;
    const ssize_t n = read(fd, &byte, 1);
    close(fd);
    return n == 0;
}

static bool starts_with_200(const std::vector<char>& response) {
    static constexpr char kStatus[] = "HTTP/1.1 200 ";
    return response.size() >= sizeof(kStatus) - 1 &&
           memcmp(response.data(), kStatus, sizeof(kStatus) - 1) == 0;
}

static int missing_prerequisite(const char* message) {
    std::cerr << "SKIP: " << message << "\n";
    const char* required = getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED");
    return required && strcmp(required, "1") == 0 ? 1 : 77;
}

static bool capture_case(u16 frontend_port,
                         u16 backend_port,
                         const std::string& source_path,
                         const std::string& nginx_config_path,
                         const std::string& nginx_log_path,
                         const std::string& rut_log_path,
                         const std::string& rut_path,
                         const std::string& container_name,
                         std::vector<char>& nginx_downstream,
                         std::vector<char>& nginx_upstream,
                         std::vector<char>& rut_downstream,
                         std::vector<char>& rut_upstream,
                         std::string& error) {
    Recorder recorder;
    if (!recorder.setup(backend_port)) {
        error = "backend recorder setup failed";
        return false;
    }

    // Declare the Docker guard before the child guard so shutdown stops the
    // docker client before removing its container on every return path.
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker", "run", "--pull=never", "--network", "host", "--name",
                     container_name, "-v", nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                     kNginxImage, "nginx", "-g", "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) {
        return false;
    }
    const int nginx_client = connect_once(frontend_port);
    if (nginx_client < 0 || !send_all(nginx_client, kRequest, sizeof(kRequest) - 1) ||
        !read_response(nginx_client, nginx_downstream, error)) {
        if (nginx_client >= 0) close(nginx_client);
        error = "nginx request/response failed: " + error;
        return false;
    }
    close(nginx_client);
    if (!stop_child(nginx.child)) {
        error = "failed to stop nginx";
        return false;
    }
    if (!docker.remove()) {
        error = "docker rm -f failed after nginx run";
        return false;
    }
    recorder.stop();
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1) {
        error = "nginx recorder did not observe exactly one request";
        return false;
    }
    nginx_upstream = recorder.request;

    Recorder fresh_recorder;
    if (!fresh_recorder.setup(backend_port)) {
        error = "fresh backend recorder setup failed";
        return false;
    }
    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start production RUT";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) {
        return false;
    }
    const int rut_client = connect_once(frontend_port);
    if (rut_client < 0 || !send_all(rut_client, kRequest, sizeof(kRequest) - 1) ||
        !read_response(rut_client, rut_downstream, error)) {
        if (rut_client >= 0) close(rut_client);
        error = "RUT request/response failed: " + error;
        return false;
    }
    close(rut_client);
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT";
        return false;
    }
    fresh_recorder.stop();
    if (fresh_recorder.accepted.load(std::memory_order_acquire) != 1 ||
        fresh_recorder.requests.load(std::memory_order_acquire) != 1) {
        error = "RUT recorder did not observe exactly one request";
        return false;
    }
    rut_upstream = fresh_recorder.request;
    if (rut_upstream != nginx_upstream) {
        error = "upstream wire mismatch";
        dump_wire("nginx upstream", nginx_upstream);
        dump_wire("RUT upstream", rut_upstream);
        return false;
    }
    return true;
}

static bool capture_gateway_case(u16 frontend_port,
                                 u16 backend_port,
                                 const std::string& source_path,
                                 const std::string& nginx_config_path,
                                 const std::string& nginx_log_path,
                                 const std::string& rut_log_path,
                                 const std::string& rut_path,
                                 const std::string& container_name,
                                 std::vector<char>& nginx_response,
                                 std::vector<char>& rut_response,
                                 std::string& error) {
    DeadPort dead;
    if (!dead.reserve(backend_port)) {
        error = "failed to reserve unavailable upstream port";
        return false;
    }

    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker", "run", "--pull=never", "--network", "host", "--name",
                      container_name, "-v", nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage, "nginx", "-g", "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for gateway case";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;
    const int nginx_client = connect_once(frontend_port);
    if (nginx_client < 0 || !send_all(nginx_client, kGatewayRequest, sizeof(kGatewayRequest) - 1) ||
        !read_response(nginx_client, nginx_response, error) || !read_eof(nginx_client, error)) {
        if (nginx_client >= 0) close(nginx_client);
        error = "nginx gateway response/EOF failed: " + error;
        return false;
    }
    close(nginx_client);
    if (!stop_child(nginx.child)) {
        error = "failed to stop nginx after gateway case";
        return false;
    }
    if (!docker.remove()) {
        error = "docker rm -f failed after nginx gateway case";
        return false;
    }

    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start production RUT for gateway case";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) return false;
    const int rut_client = connect_once(frontend_port);
    if (rut_client < 0 || !send_all(rut_client, kGatewayRequest, sizeof(kGatewayRequest) - 1) ||
        !read_response(rut_client, rut_response, error) || !read_eof(rut_client, error)) {
        if (rut_client >= 0) close(rut_client);
        error = "RUT gateway response/EOF failed: " + error;
        return false;
    }
    close(rut_client);
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT after gateway case";
        return false;
    }
    return true;
}

static std::string api_request(const char* target) {
    return std::string("GET ") + target + " HTTP/1.1\r\n"
           "Host: client.example\r\n"
           "X-Dup: one\r\n"
           "X-Dup: two\r\n"
           "Connection: close\r\n\r\n";
}

static bool capture_api_side(u16 frontend_port,
                             u16 backend_port,
                             const std::string& source_path,
                             const std::string& nginx_config_path,
                             const std::string& nginx_log_path,
                             const std::string& rut_log_path,
                             const std::string& rut_path,
                             const std::string& container_name,
                             bool pinned_nginx,
                             std::vector<std::vector<char>>& downstream,
                             std::vector<std::vector<char>>& upstream,
                             std::string& error) {
    static constexpr const char* kTargets[] = {"/api/", "/api/x", "/api/x?y=1"};
    Recorder recorder;
    if (!recorder.setup(backend_port, 3)) {
        error = "API backend recorder setup failed";
        return false;
    }

    // Keep the same cleanup ordering as the existing captures: the child is
    // stopped before its Docker container is removed on every return path.
    DockerGuard docker(container_name);
    docker.active = pinned_nginx;
    ChildGuard process;
    if (pinned_nginx) {
        if (!spawn_child({"docker", "run", "--pull=never", "--network", "host", "--name",
                          container_name, "-v", nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                          kNginxImage, "nginx", "-g", "daemon off;"},
                         nginx_log_path,
                         process.child)) {
            error = "failed to start pinned nginx for API case";
            return false;
        }
    } else if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                            rut_log_path,
                            process.child)) {
        error = "failed to start production RUT for API case";
        return false;
    }
    if (!wait_ready(frontend_port, process.child, error)) return false;

    downstream.clear();
    downstream.reserve(3);
    for (size_t i = 0; i < 3; i++) {
        const std::string request = api_request(kTargets[i]);
        const int client = connect_once(frontend_port);
        std::vector<char> response;
        std::string vector_error;
        const bool ok = client >= 0 && send_all(client, request.data(), request.size()) &&
                        read_response(client, response, vector_error) && read_eof(client, vector_error);
        if (client >= 0) close(client);
        if (!ok) {
            error = std::string(pinned_nginx ? "nginx" : "RUT") +
                    " API vector " + std::to_string(i + 1) + " failed: " +
                    (vector_error.empty() ? "connect/send failed" : vector_error);
            return false;
        }
        downstream.push_back(std::move(response));
    }

    if (!stop_child(process.child)) {
        error = std::string("failed to stop ") + (pinned_nginx ? "nginx" : "production RUT") +
                " after API case";
        return false;
    }
    if (pinned_nginx && !docker.remove()) {
        error = "docker rm -f failed after nginx API case";
        return false;
    }
    recorder.stop();
    if (recorder.accepted.load(std::memory_order_acquire) != 3 ||
        recorder.requests.load(std::memory_order_acquire) != 3 || recorder.history.size() != 3) {
        error = std::string(pinned_nginx ? "nginx" : "RUT") +
                " API recorder did not observe exactly three requests";
        return false;
    }
    upstream = recorder.history;
    return true;
}

static bool capture_api_case(u16 frontend_port,
                             u16 backend_port,
                             const std::string& source_path,
                             const std::string& nginx_config_path,
                             const std::string& nginx_log_path,
                             const std::string& rut_log_path,
                             const std::string& rut_path,
                             const std::string& nginx_container_name,
                             std::vector<std::vector<char>>& nginx_downstream,
                             std::vector<std::vector<char>>& nginx_upstream,
                             std::vector<std::vector<char>>& rut_downstream,
                             std::vector<std::vector<char>>& rut_upstream,
                             std::string& error) {
    if (!capture_api_side(frontend_port,
                          backend_port,
                          source_path,
                          nginx_config_path,
                          nginx_log_path,
                          rut_log_path,
                          rut_path,
                          nginx_container_name,
                          true,
                          nginx_downstream,
                          nginx_upstream,
                          error))
        return false;
    if (!capture_api_side(frontend_port,
                          backend_port,
                          source_path,
                          nginx_config_path,
                          nginx_log_path,
                          rut_log_path,
                          rut_path,
                          nginx_container_name + "-rut",
                          false,
                          rut_downstream,
                          rut_upstream,
                          error))
        return false;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 || argv[1][0] != '/') {
        std::cerr << "usage: test_nginx_differential <absolute-rut-executable>\n";
        return 1;
    }
#ifndef __linux__
    return missing_prerequisite("pinned nginx differential requires Linux host networking");
#else
    TempDir temp;
    if (!temp.create()) {
        std::cerr << "FAIL [preflight]: secure temporary directory creation failed\n";
        return 1;
    }
    const char* suffix = strrchr(temp.path, '/');
    const std::string probe_name =
        "rut-nginx-probe-" + std::to_string(getpid()) + "-" + (suffix ? suffix + 1 : "tmp");
    if (!command_ok({"docker", "info"}, temp.preflight_log)) {
        if (log_contains(temp.preflight_log, "Cannot connect to the Docker daemon") ||
            log_contains(temp.preflight_log, "Is the docker daemon running") ||
            log_empty(temp.preflight_log) ||
            access(temp.preflight_log.c_str(), F_OK) != 0)
            return missing_prerequisite("Docker daemon unavailable");
        std::cerr << "FAIL [preflight]: Docker daemon probe failed\n";
        dump_log(temp.preflight_log, "Docker preflight log");
        return 1;
    }
    if (!command_ok({"docker", "image", "inspect", kNginxImage}, temp.preflight_log)) {
        if (log_contains(temp.preflight_log, "No such image") ||
            log_contains(temp.preflight_log, "No such object") ||
            log_contains(temp.preflight_log, "not found"))
            return missing_prerequisite("exact pinned nginx image is not available locally");
        std::cerr << "FAIL [preflight]: exact pinned nginx image inspection failed\n";
        dump_log(temp.preflight_log, "Docker preflight log");
        return 1;
    }

    // This is a real host-network startup probe. Once daemon and image
    // inspection succeeded, all failures here are test failures rather than
    // silently becoming a skipped compatibility result.
    std::string probe_error;
    if (!run_named_docker_probe(probe_name, temp.preflight_log, probe_error)) {
        std::cerr << "FAIL [preflight]: Docker host-network startup probe failed\n";
        if (!probe_error.empty()) std::cerr << probe_error << "\n";
        dump_log(temp.preflight_log, "Docker preflight log");
        return 1;
    }
    u16 frontend_port = 0;
    u16 backend_port = 0;
    if (!allocate_port(frontend_port) || !allocate_port(backend_port) || frontend_port == backend_port) {
        std::cerr << "FAIL [preflight]: bounded dynamic port allocation failed\n";
        return 1;
    }

    std::string fragment = "server {\n  listen " + std::to_string(frontend_port) +
                           ";\n  location / {\n    proxy_pass http://127.0.0.1:" +
                           std::to_string(backend_port) + ";\n  }\n}\n";
    auto parsed = rut::nginx::parse({fragment.data(), static_cast<rut::u32>(fragment.size())});
    if (!parsed) {
        std::cerr << "FAIL [parse]: nginx fragment rejected at " << parsed.error().span.line << ":"
                  << parsed.error().span.col << "\n";
        return 1;
    }
    auto lowered = rut::nginx::lower_to_rut(parsed.value());
    if (!lowered) {
        std::cerr << "FAIL [lower]: converter rejected model at " << lowered.error().span.line << ":"
                  << lowered.error().span.col << "\n";
        return 1;
    }
    if (!write_file(temp.source, lowered.value().data, lowered.value().len)) {
        std::cerr << "FAIL [source]: secure generated source write failed\n";
        return 1;
    }

    std::string nginx_config = "events {}\nhttp {\n" + fragment + "}\n";
    if (!write_file(temp.nginx_config, nginx_config.data(), nginx_config.size())) {
        std::cerr << "FAIL [nginx-config]: config write failed\n";
        return 1;
    }

    std::vector<char> nginx_response;
    std::vector<char> rut_response;
    std::vector<char> nginx_request;
    std::vector<char> rut_request;
    std::string error;
    const char* source_suffix = strrchr(temp.path, '/');
    source_suffix = source_suffix ? source_suffix + 1 : temp.path;
    const std::string container =
        "rut-nginx-diff-" + std::to_string(getpid()) + "-" + source_suffix;
    if (!capture_case(frontend_port,
                      backend_port,
                      temp.source,
                      temp.nginx_config,
                      temp.nginx_log,
                      temp.rut_log,
                      argv[1],
                      container,
                      nginx_response,
                      nginx_request,
                      rut_response,
                      rut_request,
                      error)) {
        std::cerr << "FAIL [differential]: " << error << "\n";
        dump_wire("nginx response", nginx_response);
        dump_wire("RUT response", rut_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    if (!starts_with_200(nginx_response) || !starts_with_200(rut_response)) {
        std::cerr << "FAIL [compare]: one or both complete responses were not HTTP/1.1 200\n";
        dump_wire("nginx response", nginx_response);
        dump_wire("RUT response", rut_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    std::vector<char> normalized_nginx = nginx_response;
    std::vector<char> normalized_rut = rut_response;
    if (!normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
        normalized_nginx != normalized_rut) {
        std::cerr << "FAIL [compare]: downstream response mismatch after Date normalization\n";
        dump_wire("nginx response", nginx_response);
        dump_wire("RUT response", rut_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    const std::string request(nginx_request.begin(), nginx_request.end());
    if (nginx_request.empty() || nginx_request != rut_request ||
        request.find("GET /encoded/%7Euser?tag=unreserved HTTP/1.1\r\n") ==
            std::string::npos) {
        std::cerr << "FAIL [compare]: upstream request mismatch or target was decoded\n";
        dump_wire("nginx request", nginx_request);
        dump_wire("RUT request", rut_request);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    const std::string expected_request =
        std::string("GET /encoded/%7Euser?tag=unreserved HTTP/1.1\r\n") +
        "Host: 127.0.0.1:" + std::to_string(backend_port) + "\r\n" +
        "X-Dup: one\r\n"
        "X-Dup: two\r\n"
        "\r\n";
    if (request != expected_request) {
        std::cerr << "FAIL [assertions]: upstream request policy invariant failed\n";
        dump_wire("upstream request", nginx_request);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx and RUT differential success case\n";
    std::vector<char> nginx_gateway_response;
    std::vector<char> rut_gateway_response;
    std::string gateway_error;
    const std::string gateway_container = container + "-gateway";
    if (!capture_gateway_case(frontend_port,
                              backend_port,
                              temp.source,
                              temp.nginx_config,
                              temp.nginx_log,
                              temp.rut_log,
                              argv[1],
                              gateway_container,
                              nginx_gateway_response,
                              rut_gateway_response,
                              gateway_error)) {
        std::cerr << "FAIL [gateway differential]: " << gateway_error << "\n";
        dump_wire("nginx gateway response", nginx_gateway_response);
        dump_wire("RUT gateway response", rut_gateway_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    static constexpr char kGatewayStatus[] = "HTTP/1.1 502 Bad Gateway\r\n";
    if (nginx_gateway_response.size() < sizeof(kGatewayStatus) - 1 ||
        rut_gateway_response.size() < sizeof(kGatewayStatus) - 1 ||
        memcmp(nginx_gateway_response.data(), kGatewayStatus, sizeof(kGatewayStatus) - 1) != 0 ||
        memcmp(rut_gateway_response.data(), kGatewayStatus, sizeof(kGatewayStatus) - 1) != 0) {
        std::cerr << "FAIL [gateway compare]: expected exact HTTP/1.1 502 status\n";
        dump_wire("nginx gateway response", nginx_gateway_response);
        dump_wire("RUT gateway response", rut_gateway_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    std::vector<char> normalized_nginx_gateway = nginx_gateway_response;
    std::vector<char> normalized_rut_gateway = rut_gateway_response;
    if (!normalize_date(normalized_nginx_gateway) || !normalize_date(normalized_rut_gateway) ||
        normalized_nginx_gateway != normalized_rut_gateway ||
        normalized_nginx_gateway.size() != sizeof(kGatewayResponseNormalized) - 1 ||
        memcmp(normalized_nginx_gateway.data(),
               kGatewayResponseNormalized,
               sizeof(kGatewayResponseNormalized) - 1) != 0) {
        std::cerr << "FAIL [gateway compare]: exact 502 response mismatch after Date normalization\n";
        dump_wire("nginx gateway response", nginx_gateway_response);
        dump_wire("RUT gateway response", rut_gateway_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx and RUT unavailable-upstream gateway case (502 + EOF)\n";

    u16 api_frontend_port = 0;
    u16 api_backend_port = 0;
    if (!allocate_port(api_frontend_port) || !allocate_port(api_backend_port) ||
        api_frontend_port == api_backend_port) {
        std::cerr << "FAIL [api preflight]: bounded dynamic port allocation failed\n";
        return 1;
    }
    const std::string api_fragment =
        "server {\n  listen " + std::to_string(api_frontend_port) +
        ";\n  location /api/ {\n    proxy_pass http://127.0.0.1:" +
        std::to_string(api_backend_port) + "/;\n  }\n}\n";
    auto api_parsed = rut::nginx::parse(
        {api_fragment.data(), static_cast<rut::u32>(api_fragment.size())});
    if (!api_parsed) {
        std::cerr << "FAIL [api parse]: nginx fragment rejected at " << api_parsed.error().span.line
                  << ":" << api_parsed.error().span.col << "\n";
        return 1;
    }
    auto api_lowered = rut::nginx::lower_to_rut(api_parsed.value());
    if (!api_lowered) {
        std::cerr << "FAIL [api lower]: converter rejected model at "
                  << api_lowered.error().span.line << ":" << api_lowered.error().span.col << "\n";
        return 1;
    }
    if (!write_file(temp.source, api_lowered.value().data, api_lowered.value().len)) {
        std::cerr << "FAIL [api source]: secure generated source overwrite failed\n";
        return 1;
    }
    const std::string api_nginx_config =
        "events {}\nhttp {\n" + api_fragment + "}\n";
    if (!write_file(temp.nginx_config, api_nginx_config.data(), api_nginx_config.size())) {
        std::cerr << "FAIL [api nginx-config]: config overwrite failed\n";
        return 1;
    }

    std::vector<std::vector<char>> nginx_api_responses;
    std::vector<std::vector<char>> nginx_api_requests;
    std::vector<std::vector<char>> rut_api_responses;
    std::vector<std::vector<char>> rut_api_requests;
    std::string api_error;
    const std::string api_container = container + "-api";
    if (!capture_api_case(api_frontend_port,
                          api_backend_port,
                          temp.source,
                          temp.nginx_config,
                          temp.nginx_log,
                          temp.rut_log,
                          argv[1],
                          api_container,
                          nginx_api_responses,
                          nginx_api_requests,
                          rut_api_responses,
                          rut_api_requests,
                          api_error)) {
        std::cerr << "FAIL [api differential]: " << api_error << "\n";
        for (size_t i = 0; i < nginx_api_responses.size(); i++)
            dump_wire(("nginx API response " + std::to_string(i + 1)).c_str(),
                      nginx_api_responses[i]);
        for (size_t i = 0; i < rut_api_responses.size(); i++)
            dump_wire(("RUT API response " + std::to_string(i + 1)).c_str(),
                      rut_api_responses[i]);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }

    static constexpr const char* kApiTargets[] = {"/", "/x", "/x?y=1"};
    for (size_t i = 0; i < 3; i++) {
        if (!starts_with_200(nginx_api_responses[i]) || !starts_with_200(rut_api_responses[i])) {
            std::cerr << "FAIL [api compare " << (i + 1)
                      << "]: expected HTTP/1.1 200 response\n";
            dump_wire("nginx API response", nginx_api_responses[i]);
            dump_wire("RUT API response", rut_api_responses[i]);
            dump_log(temp.nginx_log, "nginx log");
            dump_log(temp.rut_log, "RUT log");
            return 1;
        }
        std::vector<char> normalized_nginx_api = nginx_api_responses[i];
        std::vector<char> normalized_rut_api = rut_api_responses[i];
        if (!normalize_date(normalized_nginx_api) || !normalize_date(normalized_rut_api) ||
            normalized_nginx_api != normalized_rut_api ||
            normalized_nginx_api.size() != sizeof(kApiResponseNormalized) - 1 ||
            memcmp(normalized_nginx_api.data(),
                   kApiResponseNormalized,
                   sizeof(kApiResponseNormalized) - 1) != 0) {
            std::cerr << "FAIL [api compare " << (i + 1)
                      << "]: downstream response mismatch after Date normalization\n";
            dump_wire("nginx API response", nginx_api_responses[i]);
            dump_wire("RUT API response", rut_api_responses[i]);
            dump_log(temp.nginx_log, "nginx log");
            dump_log(temp.rut_log, "RUT log");
            return 1;
        }
        const std::string expected_request =
            std::string("GET ") + kApiTargets[i] + " HTTP/1.1\r\n" +
            "Host: 127.0.0.1:" + std::to_string(api_backend_port) + "\r\n" +
            "X-Dup: one\r\n"
            "X-Dup: two\r\n"
            "\r\n";
        const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
        if (nginx_api_requests[i] != expected_wire || rut_api_requests[i] != expected_wire) {
            std::cerr << "FAIL [api compare " << (i + 1)
                      << "]: exact upstream request wire mismatch\n";
            dump_wire("expected API request", expected_wire);
            dump_wire("nginx API request", nginx_api_requests[i]);
            dump_wire("RUT API request", rut_api_requests[i]);
            dump_log(temp.nginx_log, "nginx log");
            dump_log(temp.rut_log, "RUT log");
            return 1;
        }
    }
    std::cerr << "PASS: pinned nginx and RUT /api/ proxy URI replacement case (3 vectors)\n";
    return 0;
#endif
}
