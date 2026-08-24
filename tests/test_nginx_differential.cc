#include "downstream_publication_gate.h"
#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "rut/runtime/io_event.h"
#include "rut_iouring_gate.h"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using rut::u16;
using rut::u32;
using rut::u64;

namespace {

static constexpr const char* kNginxImage =
    "nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40";
static constexpr char kRequest[] =
    "GET /encoded/%7Euser?tag=unreserved HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "X-Dup: one\r\n"
    "X-Dup: two\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kGatewayKeepAliveRequest1[] =
    "GET /missing?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n\r\n";
static constexpr char kGatewayCloseRequest2[] =
    "GET /missing?q=2 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kOptionsStarRequest[] =
    "OPTIONS * HTTP/1.1\r\n"
    "Host: options-star-client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kOptionsStarResponseNormalized[] =
    "HTTP/1.1 400 Bad Request\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 157\r\n"
    "Connection: close\r\n\r\n"
    "<html>\r\n"
    "<head><title>400 Bad Request</title></head>\r\n"
    "<body>\r\n"
    "<center><h1>400 Bad Request</h1></center>\r\n"
    "<hr><center>nginx/1.29.7</center>\r\n"
    "</body>\r\n"
    "</html>\r\n";
static constexpr char kConnectAuthorityRequest[] =
    "CONNECT example.com:443 HTTP/1.1\r\n"
    // Keep Host valid but distinct from the authority-form target so this
    // baseline cannot accidentally attribute target selection to Host.
    "Host: connect-client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kConnectAuthorityResponseNormalized[] =
    "HTTP/1.1 405 Not Allowed\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 157\r\n"
    "Connection: close\r\n\r\n"
    "<html>\r\n"
    "<head><title>405 Not Allowed</title></head>\r\n"
    "<body>\r\n"
    "<center><h1>405 Not Allowed</h1></center>\r\n"
    "<hr><center>nginx/1.29.7</center>\r\n"
    "</body>\r\n"
    "</html>\r\n";
static constexpr char kDefaultBufferingTimeoutRequest[] =
    "GET /buffered-timeout?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n\r\n";
static constexpr char kDefaultBufferingCloseTimeoutRequest[] =
    "GET /buffered-close-timeout?case=explicit-close HTTP/1.1\r\n"
    "Host: close-timeout-client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kDefaultBufferingTimeoutOrigin[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: stall-origin\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
    "Content-Length: 12\r\n\r\n"
    "hello";
static constexpr char kDefaultBufferingTimeoutResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 12\r\n"
    "Connection: keep-alive\r\n\r\n";
static constexpr char kDefaultBufferingCloseTimeoutResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 12\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kDefaultBufferingCompleteRequest[] =
    "GET /buffered-complete?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n\r\n";
static constexpr char kDefaultBufferingPostCompleteRequestHead[] =
    "POST /buffered-post-complete?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "X-Test: binary-defaults\r\n"
    "Content-Length: 12\r\n\r\n";
static constexpr unsigned char kDefaultBufferingPostCompleteRequestBody[] = {
    0x00, 0x61, 0x0d, 0x0a, 0xff, 0x7f, 'x', 0x00, 'N', 'G', 'I', 'X'};
static constexpr u32 kDefaultBufferingPostCompleteRequestPrefixBody = 5;
static_assert(sizeof(kDefaultBufferingPostCompleteRequestBody) == 12);
static_assert(kDefaultBufferingPostCompleteRequestPrefixBody <
              sizeof(kDefaultBufferingPostCompleteRequestBody));
static constexpr char kDefaultBufferingCompleteOriginPart1[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: complete-origin\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
    "Content-Length: 12\r\n\r\n"
    "abc";
static constexpr char kDefaultBufferingCompleteOriginPart2[] = "def";
static constexpr char kDefaultBufferingCompleteOriginPart3[] = "ghi";
static constexpr char kDefaultBufferingCompleteOriginPart4[] = "jkl";
static constexpr char kDefaultBufferingCompleteResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 12\r\n"
    "Connection: keep-alive\r\n\r\n"
    "abcdefghijkl";
static constexpr char kDefaultBufferingCloseCompleteRequest[] =
    "GET /buffered-close-complete?case=explicit-close HTTP/1.1\r\n"
    "Host: close-client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kDefaultBufferingCloseCompleteOriginPart1[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: close-complete-origin\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
    "Content-Length: 14\r\n\r\n"
    "clo";
static constexpr char kDefaultBufferingCloseCompleteOriginPart2[] = "se-";
static constexpr char kDefaultBufferingCloseCompleteOriginPart3[] = "comp";
static constexpr char kDefaultBufferingCloseCompleteOriginPart4[] = "lete";
static constexpr char kDefaultBufferingCloseCompleteResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 14\r\n"
    "Connection: close\r\n\r\n"
    "close-complete";
static constexpr char kDefaultBufferingEofRequest[] =
    "GET /buffered-eof?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n\r\n";
static constexpr char kDefaultBufferingCloseEofRequest[] =
    "GET /buffered-close-eof?case=explicit-close HTTP/1.1\r\n"
    "Host: close-eof-client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kDefaultBufferingEofResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 12\r\n"
    "Connection: keep-alive\r\n\r\n"
    "hello";
static constexpr char kDefaultBufferingCloseEofResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 12\r\n"
    "Connection: close\r\n\r\n"
    "hello";
static constexpr char kApiRedirectBody[] =
    "<html>\r\n"
    "<head><title>301 Moved Permanently</title></head>\r\n"
    "<body>\r\n"
    "<center><h1>301 Moved Permanently</h1></center>\r\n"
    "<hr><center>nginx/1.29.7</center>\r\n"
    "</body>\r\n"
    "</html>\r\n";
static constexpr char kBackendResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: differential-backend\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
    "Content-Length: 2\r\n\r\nok";
static constexpr char kSuccessResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 2\r\n"
    "Connection: close\r\n"
    "\r\nok";
static constexpr char kHeadRequest[] =
    "HEAD /head?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kHeadKeepAliveRequest1[] =
    "HEAD /head?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n\r\n";
static constexpr char kHeadKeepAliveRequest2[] =
    "HEAD /head?q=2 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kHeadGatewayKeepAliveRequest1[] =
    "HEAD /missing?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n\r\n";
static constexpr char kHeadGatewayKeepAliveRequest2[] =
    "HEAD /missing?q=2 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kHeadGatewayRequest[] =
    "HEAD /missing?q=1 HTTP/1.1\r\n"
    "Host: client.example\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kHeadBackendResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: origin-head\r\n"
    "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
    "Content-Length: 5\r\n\r\n"
    "hello";
static constexpr char kHeadResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 5\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kHeadKeepAliveResponseNormalized[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Length: 5\r\n"
    "Connection: keep-alive\r\n\r\n";
static constexpr char kHeadGatewayResponseNormalized[] =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 157\r\n"
    "Connection: close\r\n\r\n";
static constexpr char kHeadGatewayKeepAliveResponseNormalized[] =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 157\r\n"
    "Connection: keep-alive\r\n\r\n";
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
static constexpr char kGatewayKeepAliveResponseNormalized[] =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Server: nginx/1.29.7\r\n"
    "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 157\r\n"
    "Connection: keep-alive\r\n"
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
        if (child.reaped) child.pid = -1;
        return false;
    }
    if (!wait_child(child, 3000)) {
        (void)kill(child.pid, SIGKILL);
        const bool reaped = wait_child(child, 2000);
        if (!reaped) {
            // Keep the pid so a later bounded cleanup attempt can retry.  An
            // unbounded waitpid here could deadlock an identity owner-death
            // cleanup if the child could not actually be killed/reaped.
            return false;
        }
        child.pid = -1;
        // SIGKILL was needed for cleanup; this is always a test failure.
        return false;
    }
    const bool clean =
        child.status_valid && ((WIFEXITED(child.status) && WEXITSTATUS(child.status) == 0) ||
                               (WIFSIGNALED(child.status) && WTERMSIG(child.status) == SIGTERM));
    child.pid = -1;
    return clean;
}

static bool settle_expected_failure_child(Child& child) {
    if (poll_child(child)) {
        const bool failed =
            child.status_valid && ((WIFEXITED(child.status) && WEXITSTATUS(child.status) != 0) ||
                                   WIFSIGNALED(child.status));
        child.pid = -1;
        return failed;
    }
    if (stop_child(child)) return true;
    if (!child.reaped || !child.status_valid) return false;
    return (WIFEXITED(child.status) && WEXITSTATUS(child.status) != 0) || WIFSIGNALED(child.status);
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
    if (spawn_child({"docker",
                     "run",
                     "--pull=never",
                     "--network",
                     "host",
                     "--name",
                     name,
                     kNginxImage,
                     "nginx",
                     "-v"},
                    log_path,
                    probe)) {
        if (wait_child(probe, 10'000)) {
            probe_ok =
                probe.status_valid && WIFEXITED(probe.status) && WEXITSTATUS(probe.status) == 0;
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
    std::string gate_control;
    std::string rut_iouring_gate_control;

    bool create() {
        if (!mkdtemp(path)) return false;
        created = true;
        source = std::string(path) + "/generated.rut";
        nginx_config = std::string(path) + "/nginx.conf";
        nginx_log = std::string(path) + "/nginx.log";
        rut_log = std::string(path) + "/rut.log";
        preflight_log = std::string(path) + "/preflight.log";
        gate_control = std::string(path) + "/downstream-gate.control";
        rut_iouring_gate_control = std::string(path) + "/rut-iouring-gate.control";
        return true;
    }

    ~TempDir() {
        if (created) {
            unlink(source.c_str());
            unlink(nginx_config.c_str());
            unlink(nginx_log.c_str());
            unlink(rut_log.c_str());
            unlink(preflight_log.c_str());
            unlink(gate_control.c_str());
            unlink(rut_iouring_gate_control.c_str());
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

static bool has_exact_single_content_length_12(const std::vector<char>& bytes, size_t end) {
    if (end < 4 || end > bytes.size()) return false;
    size_t line_start = 0;
    while (line_start + 1 < end && !(bytes[line_start] == '\r' && bytes[line_start + 1] == '\n'))
        line_start++;
    if (line_start + 1 >= end) return false;
    line_start += 2;

    u32 content_length_count = 0;
    while (line_start + 1 < end) {
        if (bytes[line_start] == '\r' && bytes[line_start + 1] == '\n') break;
        size_t line_end = line_start;
        while (line_end + 1 < end && !(bytes[line_end] == '\r' && bytes[line_end + 1] == '\n'))
            line_end++;
        if (line_end + 1 >= end) return false;
        size_t colon = line_start;
        while (colon < line_end && bytes[colon] != ':') colon++;
        if (colon == line_end) return false;

        static constexpr char kName[] = "content-length";
        bool name_matches = colon - line_start == sizeof(kName) - 1;
        for (size_t i = 0; name_matches && i < sizeof(kName) - 1; i++) {
            char c = bytes[line_start + i];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            name_matches = c == kName[i];
        }
        if (name_matches) {
            content_length_count++;
            size_t value_begin = colon + 1;
            while (value_begin < line_end &&
                   (bytes[value_begin] == ' ' || bytes[value_begin] == '\t'))
                value_begin++;
            size_t value_end = line_end;
            while (value_end > value_begin &&
                   (bytes[value_end - 1] == ' ' || bytes[value_end - 1] == '\t'))
                value_end--;
            if (value_end - value_begin != 2 || bytes[value_begin] != '1' ||
                bytes[value_begin + 1] != '2')
                return false;
        }
        line_start = line_end + 2;
    }
    return content_length_count == 1;
}

static bool normalize_date(std::vector<char>& bytes);

static bool validate_exact_normalized_response(const std::vector<char>& bytes,
                                               const char* expected,
                                               std::string& error) {
    std::vector<char> normalized = bytes;
    if (!normalize_date(normalized)) {
        error = "pinned response has no unique valid Date field";
        return false;
    }
    const size_t expected_len = strlen(expected);
    if (normalized.size() != expected_len ||
        memcmp(normalized.data(), expected, expected_len) != 0) {
        error = "pinned response did not match the exact Date-normalized wire baseline";
        return false;
    }
    return true;
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

static bool read_head_response(int fd, std::vector<char>& bytes, std::string& error) {
    using Clock = std::chrono::steady_clock;
    static constexpr auto kResponseReadBudget = std::chrono::seconds(5);
    const Clock::time_point deadline = Clock::now() + kResponseReadBudget;

    bytes.clear();
    bytes.reserve(1024);
    for (;;) {
        if (Clock::now() >= deadline) {
            error = "HEAD response deadline exceeded";
            return false;
        }
        char buf[1024];
        const ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            bytes.insert(bytes.end(), buf, buf + n);
            const size_t end = header_end(bytes);
            if (end != 0) {
                if (bytes.size() != end) {
                    error = "HEAD response included body bytes with headers";
                    return false;
                }
                return true;
            }
            continue;
        }
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        error = n == 0 ? "HEAD response ended before headers" : "HEAD response read failed";
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

static bool wait_keepalive_quiet_or_eof(int fd, int quiet_ms, bool& eof, std::string& error) {
    using Clock = std::chrono::steady_clock;
    const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(quiet_ms);
    eof = false;
    while (Clock::now() < deadline) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        pollfd p{fd, POLLIN | POLLHUP | POLLERR, 0};
        const int ready = poll(&p, 1, remaining > 50 ? 50 : static_cast<int>(remaining));
        if (ready < 0) {
            if (errno == EINTR) continue;
            error = "keep-alive quiet-window poll failed";
            return false;
        }
        if (ready == 0) continue;
        if (p.revents & (POLLIN | POLLHUP)) {
            char extra[256];
            const ssize_t n = recv(fd, extra, sizeof(extra), 0);
            if (n == 0) {
                eof = true;
                return true;
            }
            if (n > 0) {
                error = "unexpected downstream body/data during HEAD quiet window";
                return false;
            }
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            error = "keep-alive quiet-window recv failed";
            return false;
        }
        if (p.revents & POLLERR) {
            error = "keep-alive quiet-window socket error";
            return false;
        }
    }
    return true;
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
    std::atomic<bool> thread_alive{false};
    std::atomic<bool> listener_failed{false};
    std::atomic<u32> accepted{0};
    std::atomic<u32> requests{0};
    std::vector<char> request;
    std::vector<std::vector<char>> history;
    const char* response_bytes = kBackendResponse;
    u32 response_bytes_len = sizeof(kBackendResponse) - 1;
    // Opt-in pinned-nginx semantic-baseline mode. The response is one
    // application-level send_all operation, after which the origin remains
    // open and silent until the proxy retires it. The listener stays live
    // until explicit test cleanup so retries remain observable.
    bool wait_response_peer_close = false;
    bool observe_extra_requests_until_stop = false;
    // Default-off semantic-baseline mode: four distinct, permit-gated
    // application writes make progress timing observable without making any
    // claim about TCP segmentation or nginx read boundaries.
    bool permit_gated_complete_response = false;
    const char* response_fragment_bytes[4] = {
        kDefaultBufferingCompleteOriginPart1,
        kDefaultBufferingCompleteOriginPart2,
        kDefaultBufferingCompleteOriginPart3,
        kDefaultBufferingCompleteOriginPart4,
    };
    u32 response_fragment_lengths[4] = {
        sizeof(kDefaultBufferingCompleteOriginPart1) - 1,
        sizeof(kDefaultBufferingCompleteOriginPart2) - 1,
        sizeof(kDefaultBufferingCompleteOriginPart3) - 1,
        sizeof(kDefaultBufferingCompleteOriginPart4) - 1,
    };
    // Default-off positive-request baseline mode: do not publish the request
    // or respond until the declared fixed Content-Length body is fully read.
    bool read_exact_content_length_12_body = false;
    std::atomic<u32> response_fragment_permit{0};
    std::atomic<u32> response_fragments_sent{0};
    std::atomic<u64> response_fragment_sent_ns[4]{};
    // Separate default-off mode for the incomplete clean-EOF baseline. The
    // origin sends its configured prefix, stays application-open behind this
    // gate, and only the test may authorize the clean close.
    bool gate_incomplete_response_close = false;
    std::atomic<bool> response_close_permit{false};
    std::atomic<bool> response_closed_by_gate{false};
    std::atomic<bool> response_close_failed{false};
    std::atomic<u64> response_close_released_ns{0};
    std::atomic<bool> response_sent_open{false};
    std::atomic<bool> response_send_failed{false};
    std::atomic<bool> response_peer_closed{false};
    std::atomic<bool> response_peer_unexpected_data{false};
    std::atomic<bool> response_peer_observation_failed{false};
    std::atomic<u64> response_sent_ns{0};
    std::atomic<u64> response_peer_closed_ns{0};
    // Test-only witnesses for the default response path. A successful
    // converter completion vector must make exactly one application-level
    // send_all call and then cleanly shut down and close that origin episode.
    std::atomic<u32> response_send_all_calls{0};
    std::atomic<bool> response_send_succeeded{false};
    std::atomic<bool> response_clean_shutdown{false};
    std::atomic<bool> response_connection_closed{false};
    pthread_t thread{};
    bool thread_started = false;

    static void* run(void* opaque) {
        auto* self = static_cast<Recorder*>(opaque);
        struct LivenessGuard {
            Recorder* recorder;
            ~LivenessGuard() { recorder->thread_alive.store(false, std::memory_order_release); }
        } liveness_guard{self};
        self->thread_alive.store(true, std::memory_order_release);
        const auto fail_listener = [self]() {
            if (self->running.exchange(false, std::memory_order_acq_rel))
                self->listener_failed.store(true, std::memory_order_release);
        };
        const int fd = self->listen_fd;
        while (self->running.load(std::memory_order_acquire)) {
            pollfd listener_poll{fd, POLLIN, 0};
            const int ready = poll(&listener_poll, 1, 50);
            if (ready < 0) {
                if (errno == EINTR) continue;
                fail_listener();
                break;
            }
            if (!self->running.load(std::memory_order_acquire)) break;
            if (ready == 0) continue;
            if (listener_poll.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                fail_listener();
                break;
            }
            if (!(listener_poll.revents & POLLIN)) continue;
            const int client = accept(fd, nullptr, nullptr);
            if (client < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                fail_listener();
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
                    const size_t end = header_end(wire);
                    if (end != 0) {
                        if (!self->read_exact_content_length_12_body) break;
                        if (!has_exact_single_content_length_12(wire, end)) break;
                        if (wire.size() >= end + 12) break;
                    }
                } else if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                    continue;
                } else {
                    break;
                }
            }
            const size_t request_header_end = header_end(wire);
            const bool complete = request_header_end != 0 &&
                                  (!self->read_exact_content_length_12_body ||
                                   (has_exact_single_content_length_12(wire, request_header_end) &&
                                    wire.size() == request_header_end + 12));
            bool response_sent = false;
            if (complete) {
                self->history.push_back(wire);
                if (self->history.size() == 1) self->request = wire;
                self->requests.fetch_add(1, std::memory_order_release);
                if (self->permit_gated_complete_response) {
                    response_sent = true;
                    for (u32 part = 0; part < 4; part++) {
                        while (self->running.load(std::memory_order_acquire) &&
                               self->response_fragment_permit.load(std::memory_order_acquire) <=
                                   part) {
                            usleep(1000);
                        }
                        if (!self->running.load(std::memory_order_acquire) ||
                            !send_all(client,
                                      self->response_fragment_bytes[part],
                                      self->response_fragment_lengths[part])) {
                            response_sent = false;
                            break;
                        }
                        const u64 sent_ns = static_cast<u64>(
                            std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count());
                        self->response_fragment_sent_ns[part].store(sent_ns,
                                                                    std::memory_order_relaxed);
                        self->response_fragments_sent.store(part + 1, std::memory_order_release);
                    }
                } else {
                    self->response_send_all_calls.fetch_add(1, std::memory_order_relaxed);
                    response_sent =
                        send_all(client, self->response_bytes, self->response_bytes_len);
                }
                if (response_sent)
                    self->response_send_succeeded.store(true, std::memory_order_release);
                if (self->wait_response_peer_close || self->gate_incomplete_response_close) {
                    if (!response_sent) {
                        self->response_send_failed.store(true, std::memory_order_release);
                    } else {
                        const u64 sent_ns = static_cast<u64>(
                            std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count());
                        self->response_sent_ns.store(sent_ns, std::memory_order_relaxed);
                        self->response_sent_open.store(true, std::memory_order_release);
                    }
                }
                if (response_sent && self->gate_incomplete_response_close) {
                    while (self->running.load(std::memory_order_acquire) &&
                           !self->response_close_permit.load(std::memory_order_acquire)) {
                        char byte = 0;
                        const ssize_t n = recv(client, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
                        if (n == 0 || (n < 0 && errno == ECONNRESET)) {
                            self->response_peer_closed.store(true, std::memory_order_release);
                            break;
                        }
                        if (n > 0) {
                            self->response_peer_unexpected_data.store(true,
                                                                      std::memory_order_release);
                            break;
                        }
                        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                            self->response_peer_observation_failed.store(true,
                                                                         std::memory_order_release);
                            break;
                        }
                        usleep(1000);
                    }
                    if (self->running.load(std::memory_order_acquire) &&
                        self->response_close_permit.load(std::memory_order_acquire) &&
                        !self->response_peer_closed.load(std::memory_order_acquire) &&
                        !self->response_peer_unexpected_data.load(std::memory_order_acquire) &&
                        !self->response_peer_observation_failed.load(std::memory_order_acquire)) {
                        const u64 released_ns = static_cast<u64>(
                            std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count());
                        self->response_close_released_ns.store(released_ns,
                                                               std::memory_order_relaxed);
                        if (shutdown(client, SHUT_RDWR) == 0) {
                            self->response_closed_by_gate.store(true, std::memory_order_release);
                        } else {
                            self->response_close_failed.store(true, std::memory_order_release);
                        }
                    }
                } else if (response_sent && self->wait_response_peer_close) {
                    bool observed = false;
                    while (self->running.load(std::memory_order_acquire)) {
                        pollfd peer_poll{client, POLLIN | POLLHUP | POLLERR, 0};
                        const int peer_ready = poll(&peer_poll, 1, 50);
                        if (peer_ready < 0) {
                            if (errno == EINTR) continue;
                            self->response_peer_observation_failed.store(true,
                                                                         std::memory_order_release);
                            observed = true;
                            break;
                        }
                        if (peer_ready == 0) continue;
                        char unexpected[64];
                        const ssize_t n = recv(client, unexpected, sizeof(unexpected), 0);
                        if (n == 0 || (n < 0 && errno == ECONNRESET)) {
                            const u64 closed_ns = static_cast<u64>(
                                std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch())
                                    .count());
                            self->response_peer_closed_ns.store(closed_ns,
                                                                std::memory_order_relaxed);
                            self->response_peer_closed.store(true, std::memory_order_release);
                        } else if (n > 0) {
                            self->response_peer_unexpected_data.store(true,
                                                                      std::memory_order_release);
                        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                            self->response_peer_observation_failed.store(true,
                                                                         std::memory_order_release);
                        } else {
                            continue;
                        }
                        observed = true;
                        break;
                    }
                    if (!observed && self->running.load(std::memory_order_acquire)) {
                        self->response_peer_observation_failed.store(true,
                                                                     std::memory_order_release);
                    }
                }
            }
            const bool clean_shutdown = shutdown(client, SHUT_RDWR) == 0;
            const bool connection_closed = close(client) == 0;
            if (response_sent) {
                self->response_clean_shutdown.store(clean_shutdown, std::memory_order_release);
                self->response_connection_closed.store(connection_closed,
                                                       std::memory_order_release);
            }
            if (!self->observe_extra_requests_until_stop &&
                self->requests.load(std::memory_order_acquire) >= self->expected_requests) {
                self->running.store(false, std::memory_order_release);
                break;
            }
        }
        return nullptr;
    }

    bool setup(u16 requested_port = 0,
               u32 expected = 1,
               const char* response_override = nullptr,
               u32 response_override_len = 0) {
        if (expected == 0 || expected > 3) return false;
        if ((response_override == nullptr) != (response_override_len == 0)) return false;
        if ((permit_gated_complete_response && gate_incomplete_response_close) ||
            (wait_response_peer_close && gate_incomplete_response_close))
            return false;
        expected_requests = expected;
        response_bytes = response_override != nullptr ? response_override : kBackendResponse;
        response_bytes_len =
            response_override != nullptr ? response_override_len : sizeof(kBackendResponse) - 1;
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
            response_sent_open.store(false, std::memory_order_relaxed);
            response_send_failed.store(false, std::memory_order_relaxed);
            response_peer_closed.store(false, std::memory_order_relaxed);
            response_peer_unexpected_data.store(false, std::memory_order_relaxed);
            response_peer_observation_failed.store(false, std::memory_order_relaxed);
            response_sent_ns.store(0, std::memory_order_relaxed);
            response_peer_closed_ns.store(0, std::memory_order_relaxed);
            response_send_all_calls.store(0, std::memory_order_relaxed);
            response_send_succeeded.store(false, std::memory_order_relaxed);
            response_clean_shutdown.store(false, std::memory_order_relaxed);
            response_connection_closed.store(false, std::memory_order_relaxed);
            response_fragment_permit.store(permit_gated_complete_response ? 1u : 0u,
                                           std::memory_order_relaxed);
            response_fragments_sent.store(0, std::memory_order_relaxed);
            for (auto& sent_ns : response_fragment_sent_ns)
                sent_ns.store(0, std::memory_order_relaxed);
            response_close_permit.store(false, std::memory_order_relaxed);
            response_closed_by_gate.store(false, std::memory_order_relaxed);
            response_close_failed.store(false, std::memory_order_relaxed);
            response_close_released_ns.store(0, std::memory_order_relaxed);
            thread_alive.store(false, std::memory_order_relaxed);
            listener_failed.store(false, std::memory_order_relaxed);
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

static bool complete_origin_episode_is_exact(const Recorder& recorder) {
    return recorder.accepted.load(std::memory_order_acquire) == 1 &&
           recorder.requests.load(std::memory_order_acquire) == 1 &&
           recorder.response_send_all_calls.load(std::memory_order_acquire) == 1 &&
           recorder.response_send_succeeded.load(std::memory_order_acquire) &&
           recorder.response_clean_shutdown.load(std::memory_order_acquire) &&
           recorder.response_connection_closed.load(std::memory_order_acquire);
}

static bool wait_for_live_complete_origin_episode(Recorder& recorder,
                                                  Child& process,
                                                  const char* side,
                                                  std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        if (poll_child(process)) {
            error = std::string(side) + " process exited before completion observation";
            return false;
        }
        if (!recorder.running.load(std::memory_order_acquire)) {
            error = std::string(side) + " recorder stopped before completion observation";
            return false;
        }
        if (!recorder.thread_alive.load(std::memory_order_acquire) ||
            recorder.listener_failed.load(std::memory_order_acquire)) {
            error = std::string(side) +
                    " recorder listener exited or failed before completion observation";
            return false;
        }
        if (recorder.accepted.load(std::memory_order_acquire) > 1 ||
            recorder.requests.load(std::memory_order_acquire) > 1 ||
            recorder.response_send_all_calls.load(std::memory_order_acquire) > 1) {
            error = std::string(side) + " origin retried during completion observation";
            return false;
        }
        if (complete_origin_episode_is_exact(recorder)) return true;
        usleep(1000);
    }
    error = std::string(side) +
            " origin did not prove one complete send_all followed by clean shutdown/close";
    return false;
}

static bool observe_live_complete_origin_quiet(Recorder& recorder,
                                               Child& process,
                                               const char* side,
                                               std::string& error) {
    if (!wait_for_live_complete_origin_episode(recorder, process, side, error)) return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    for (;;) {
        if (poll_child(process)) {
            error = std::string(side) + " process exited during post-EOF live observation";
            return false;
        }
        if (!recorder.running.load(std::memory_order_acquire) ||
            !recorder.thread_alive.load(std::memory_order_acquire) ||
            recorder.listener_failed.load(std::memory_order_acquire) ||
            !complete_origin_episode_is_exact(recorder)) {
            error = std::string(side) +
                    " origin changed or recorder listener stopped/failed during post-EOF live "
                    "observation";
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return true;
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const int wait_ms = remaining > 50 ? 50 : static_cast<int>(remaining);
        (void)poll(nullptr, 0, wait_ms > 0 ? wait_ms : 1);
    }
}

// Pinned-baseline backend for two requests on one downstream connection. It
// keeps accepted upstream fds open, records the connection id with every
// request, and deliberately delays the representation body after the response
// headers so a HEAD leak cannot be hidden by coalescing.
struct KeepAlivePinnedRecorder {
    enum class FirstResponseMode : uint8_t {
        Normal,
        InvalidHeaderWaitPeerClose,
        IncompleteWaitGate,
    };
    enum class ActiveWaitKind : uint8_t {
        None,
        InvalidHeaderPeerClose,
        IncompleteGate,
        IncompleteAbortHold,
    };
    enum class IncompleteGateState : uint8_t {
        Idle,
        SentOpenWaitingGate,
        SendFailed,
        PeerClosedBeforeGate,
        UnexpectedDataBeforeGate,
        ProbeFailed,
        ClosedByGate,
        Aborted,
    };
    enum class IncompleteGateCommand : uint8_t {
        Wait,
        Close,
        Abort,
    };
    explicit KeepAlivePinnedRecorder(FirstResponseMode mode = FirstResponseMode::Normal)
        : first_response_mode(mode) {}
    struct Entry {
        u32 connection_id = 0;
        std::vector<char> wire;
    };
    struct Active {
        int fd = -1;
        u32 connection_id = 0;
        std::vector<char> wire;
        size_t parsed = 0;
        bool body_pending = false;
        ActiveWaitKind wait_kind = ActiveWaitKind::None;
        std::chrono::steady_clock::time_point body_due{};
    };

    int listen_fd = -1;
    u16 port = 0;
    std::atomic<bool> running{false};
    std::atomic<u32> accepted{0};
    std::atomic<u32> requests{0};
    std::vector<Entry> history;
    u32 body_delay_ms = 250;
    // Immutable after setup. These test-only modes deliberately report only
    // observable origin socket behavior; exact io_uring ownership evidence
    // belongs to the focused runtime tests.
    const FirstResponseMode first_response_mode;
    std::atomic<bool> first_malformed_sent_open{false};
    std::atomic<bool> first_malformed_send_failed{false};
    std::atomic<bool> first_peer_closed{false};
    std::atomic<bool> first_peer_unexpected_data{false};
    std::atomic<bool> first_peer_observation_failed{false};
    std::atomic<IncompleteGateState> incomplete_gate_state{IncompleteGateState::Idle};
    std::atomic<IncompleteGateCommand> incomplete_gate_command{IncompleteGateCommand::Wait};
    pthread_t thread{};
    bool thread_started = false;

    static size_t find_header_end(const std::vector<char>& bytes, size_t from) {
        if (bytes.size() < from + 4) return 0;
        for (size_t i = from + 3; i < bytes.size(); i++) {
            if (bytes[i - 3] == '\r' && bytes[i - 2] == '\n' && bytes[i - 1] == '\r' &&
                bytes[i] == '\n')
                return i + 1;
        }
        return 0;
    }

    static bool send_head_response(int fd) {
        static constexpr char kHeaders[] =
            "HTTP/1.1 200 OK\r\n"
            "Server: origin-head\r\n"
            "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
            "Content-Length: 5\r\n\r\n";
        return send_all(fd, kHeaders, sizeof(kHeaders) - 1);
    }

    static bool send_head_body(int fd) { return send_all(fd, "hello", 5); }

    enum class PeerProbe : uint8_t {
        Open,
        Closed,
        UnexpectedData,
        Failed,
    };

    static PeerProbe probe_peer_nonblocking(int fd) {
        char byte = 0;
        ssize_t n;
        do {
            n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
        } while (n < 0 && errno == EINTR);
        if (n == 0 || (n < 0 && errno == ECONNRESET)) return PeerProbe::Closed;
        if (n > 0) return PeerProbe::UnexpectedData;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return PeerProbe::Open;
        return PeerProbe::Failed;
    }

    static bool process_next_request(KeepAlivePinnedRecorder& self,
                                     Active& item,
                                     std::chrono::steady_clock::time_point now) {
        const size_t end = find_header_end(item.wire, item.parsed);
        if (end == 0) return true;
        const bool first_request = self.requests.load(std::memory_order_relaxed) == 0;
        std::vector<char> request(item.wire.begin() + item.parsed, item.wire.begin() + end);
        self.history.push_back({item.connection_id, request});
        self.requests.fetch_add(1, std::memory_order_release);
        item.parsed = end;
        if (self.first_response_mode == FirstResponseMode::InvalidHeaderWaitPeerClose &&
            first_request) {
            static constexpr char kMalformed[] = "HTTP/1.1 200 OK\r\n:\r\n\r\n";
            if (item.wire.size() != end) {
                self.first_peer_unexpected_data.store(true, std::memory_order_release);
                return false;
            }
            if (!send_all(item.fd, kMalformed, sizeof(kMalformed) - 1)) {
                self.first_malformed_send_failed.store(true, std::memory_order_release);
                return false;
            }
            item.wait_kind = ActiveWaitKind::InvalidHeaderPeerClose;
            self.first_malformed_sent_open.store(true, std::memory_order_release);
            return true;
        }
        if (self.first_response_mode == FirstResponseMode::IncompleteWaitGate && first_request) {
            static constexpr char kIncomplete[] = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n";
            if (self.incomplete_gate_command.load(std::memory_order_acquire) ==
                IncompleteGateCommand::Abort) {
                item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                return true;
            }
            if (item.wire.size() != end) {
                self.incomplete_gate_state.store(IncompleteGateState::UnexpectedDataBeforeGate,
                                                 std::memory_order_release);
                item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                return true;
            }
            if (!send_all(item.fd, kIncomplete, sizeof(kIncomplete) - 1)) {
                self.incomplete_gate_state.store(IncompleteGateState::SendFailed,
                                                 std::memory_order_release);
                item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                return true;
            }
            item.wait_kind = ActiveWaitKind::IncompleteGate;
            if (self.incomplete_gate_command.load(std::memory_order_acquire) ==
                IncompleteGateCommand::Abort) {
                item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
            } else {
                self.incomplete_gate_state.store(IncompleteGateState::SentOpenWaitingGate,
                                                 std::memory_order_release);
            }
            return true;
        }
        if (!send_head_response(item.fd)) return false;
        item.body_pending = true;
        item.body_due = now + std::chrono::milliseconds(self.body_delay_ms);
        return true;
    }

    static void* run(void* opaque) {
        auto* self = static_cast<KeepAlivePinnedRecorder*>(opaque);
        std::vector<Active> active;
        u32 next_connection_id = 1;
        const auto acknowledge_incomplete_abort = [&]() {
            if (self->first_response_mode != FirstResponseMode::IncompleteWaitGate ||
                self->incomplete_gate_command.load(std::memory_order_acquire) !=
                    IncompleteGateCommand::Abort ||
                self->incomplete_gate_state.load(std::memory_order_acquire) ==
                    IncompleteGateState::ClosedByGate)
                return;
            for (auto& item : active) {
                if (item.wait_kind == ActiveWaitKind::None ||
                    item.wait_kind == ActiveWaitKind::IncompleteGate)
                    item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
            }
            // This release is the recorder-thread acknowledgement: every live
            // incomplete item is parked before callers may tear down the proxy.
            self->incomplete_gate_state.store(IncompleteGateState::Aborted,
                                              std::memory_order_release);
        };
        while (self->running.load(std::memory_order_acquire)) {
            acknowledge_incomplete_abort();
            std::vector<pollfd> polls;
            polls.reserve(active.size() + 1);
            polls.push_back({self->listen_fd, POLLIN, 0});
            for (const auto& item : active)
                polls.push_back({item.fd, POLLIN | POLLERR | POLLHUP, 0});
            const size_t polled_active_count = active.size();
            const int ready = poll(polls.data(), polls.size(), 25);
            if (ready < 0) {
                if (errno == EINTR) continue;
                break;
            }
            acknowledge_incomplete_abort();

            if (self->incomplete_gate_command.load(std::memory_order_acquire) !=
                    IncompleteGateCommand::Abort &&
                (polls[0].revents & POLLIN)) {
                for (;;) {
                    const int client = accept(self->listen_fd, nullptr, nullptr);
                    if (client < 0) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        self->running.store(false, std::memory_order_release);
                        break;
                    }
                    timeval timeout{0, 500000};
                    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                    const u32 id = next_connection_id++;
                    active.push_back({client, id, {}, 0, false, ActiveWaitKind::None, {}});
                    self->accepted.fetch_add(1, std::memory_order_release);
                }
            }

            const auto now = std::chrono::steady_clock::now();
            for (size_t index = polled_active_count; index > 0; index--) {
                Active& item = active[index - 1];
                const size_t poll_index = index;
                bool remove = false;
                acknowledge_incomplete_abort();
                if (item.wait_kind == ActiveWaitKind::IncompleteGate) {
                    IncompleteGateCommand command =
                        self->incomplete_gate_command.load(std::memory_order_acquire);
                    if (command == IncompleteGateCommand::Abort) {
                        item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                        acknowledge_incomplete_abort();
                    } else {
                        PeerProbe probe = probe_peer_nonblocking(item.fd);
                        if (probe == PeerProbe::Open && (polls[poll_index].revents & POLLHUP))
                            probe = PeerProbe::Closed;
                        if (probe == PeerProbe::Open && (polls[poll_index].revents & POLLERR))
                            probe = PeerProbe::Failed;
                        // Abort wins over any observation made by a probe that
                        // was already in progress when teardown requested it.
                        command = self->incomplete_gate_command.load(std::memory_order_acquire);
                        if (command == IncompleteGateCommand::Abort) {
                            item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                            acknowledge_incomplete_abort();
                        } else if (probe == PeerProbe::Closed) {
                            item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                            self->incomplete_gate_state.store(
                                IncompleteGateState::PeerClosedBeforeGate,
                                std::memory_order_release);
                            acknowledge_incomplete_abort();
                        } else if (probe == PeerProbe::UnexpectedData) {
                            item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                            self->incomplete_gate_state.store(
                                IncompleteGateState::UnexpectedDataBeforeGate,
                                std::memory_order_release);
                            acknowledge_incomplete_abort();
                        } else if (probe == PeerProbe::Failed) {
                            item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                            self->incomplete_gate_state.store(IncompleteGateState::ProbeFailed,
                                                              std::memory_order_release);
                            acknowledge_incomplete_abort();
                        } else if (command == IncompleteGateCommand::Close) {
                            // The final open/no-data probe and the close occur in
                            // the recorder thread. ClosedByGate proves only that
                            // the authorized close happened; the downstream 502
                            // is the observable evidence that EOF was consumed.
                            const int fd = item.fd;
                            item.fd = -1;
                            (void)close(fd);
                            self->incomplete_gate_state.store(IncompleteGateState::ClosedByGate,
                                                              std::memory_order_release);
                            remove = true;
                        }
                    }
                }
                if (item.wait_kind != ActiveWaitKind::IncompleteAbortHold && item.body_pending &&
                    now >= item.body_due) {
                    if (!send_head_body(item.fd)) remove = true;
                    item.body_pending = false;
                    // A second request may already be in the same upstream
                    // recv buffer. Consume at most one complete header now;
                    // do not rely on a future POLLIN edge for buffered data.
                    if (!remove && !process_next_request(*self, item, now)) remove = true;
                    acknowledge_incomplete_abort();
                }
                if (!remove && item.wait_kind == ActiveWaitKind::InvalidHeaderPeerClose &&
                    (polls[poll_index].revents & (POLLIN | POLLERR | POLLHUP))) {
                    char unexpected[256];
                    const ssize_t n = recv(item.fd, unexpected, sizeof(unexpected), 0);
                    if (n == 0 || (n < 0 && errno == ECONNRESET)) {
                        self->first_peer_closed.store(true, std::memory_order_release);
                        remove = true;
                    } else if (n > 0) {
                        self->first_peer_unexpected_data.store(true, std::memory_order_release);
                        remove = true;
                    } else if ((polls[poll_index].revents & POLLHUP) != 0 &&
                               (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        self->first_peer_closed.store(true, std::memory_order_release);
                        remove = true;
                    } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                        self->first_peer_observation_failed.store(true, std::memory_order_release);
                        remove = true;
                    }
                }
                if (!remove && !item.body_pending && item.wait_kind == ActiveWaitKind::None &&
                    (polls[poll_index].revents & POLLIN)) {
                    char buf[4096];
                    const ssize_t n = recv(item.fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        item.wire.insert(item.wire.end(), buf, buf + n);
                        if (!process_next_request(*self, item, now)) remove = true;
                        acknowledge_incomplete_abort();
                    } else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN &&
                                          errno != EWOULDBLOCK)) {
                        remove = true;
                    }
                }
                if (!remove && item.wait_kind == ActiveWaitKind::None &&
                    (polls[poll_index].revents & (POLLERR | POLLHUP)))
                    remove = true;
                if (remove) {
                    if (item.fd >= 0) {
                        shutdown(item.fd, SHUT_RDWR);
                        close(item.fd);
                    }
                    active.erase(active.begin() + static_cast<ptrdiff_t>(index - 1));
                }
            }
            acknowledge_incomplete_abort();
        }
        if (self->first_response_mode == FirstResponseMode::IncompleteWaitGate) {
            const IncompleteGateState state =
                self->incomplete_gate_state.load(std::memory_order_acquire);
            const bool abort_requested =
                self->incomplete_gate_command.load(std::memory_order_acquire) ==
                IncompleteGateCommand::Abort;
            if ((abort_requested && state != IncompleteGateState::ClosedByGate) ||
                state == IncompleteGateState::Idle ||
                state == IncompleteGateState::SentOpenWaitingGate) {
                for (auto& item : active) {
                    if (item.wait_kind == ActiveWaitKind::None ||
                        item.wait_kind == ActiveWaitKind::IncompleteGate)
                        item.wait_kind = ActiveWaitKind::IncompleteAbortHold;
                }
                self->incomplete_gate_state.store(IncompleteGateState::Aborted,
                                                  std::memory_order_release);
            }
        }
        for (auto& item : active) {
            shutdown(item.fd, SHUT_RDWR);
            close(item.fd);
        }
        if (self->listen_fd >= 0) {
            close(self->listen_fd);
            self->listen_fd = -1;
        }
        return nullptr;
    }

    bool setup(u16 requested_port) {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) return false;
        int one = 1;
        (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(requested_port);
        if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(listen_fd, 8) != 0) {
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        const int flags = fcntl(listen_fd, F_GETFL, 0);
        if (flags < 0 || fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        socklen_t len = sizeof(addr);
        if (getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        port = ntohs(addr.sin_port);
        history.clear();
        accepted.store(0, std::memory_order_relaxed);
        requests.store(0, std::memory_order_relaxed);
        first_malformed_sent_open.store(false, std::memory_order_relaxed);
        first_malformed_send_failed.store(false, std::memory_order_relaxed);
        first_peer_closed.store(false, std::memory_order_relaxed);
        first_peer_unexpected_data.store(false, std::memory_order_relaxed);
        first_peer_observation_failed.store(false, std::memory_order_relaxed);
        incomplete_gate_state.store(IncompleteGateState::Idle, std::memory_order_relaxed);
        incomplete_gate_command.store(IncompleteGateCommand::Wait, std::memory_order_relaxed);
        running.store(true, std::memory_order_release);
        if (pthread_create(&thread, nullptr, &KeepAlivePinnedRecorder::run, this) != 0) {
            running.store(false, std::memory_order_release);
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        thread_started = true;
        return true;
    }

    void abort_incomplete_gate() {
        if (first_response_mode != FirstResponseMode::IncompleteWaitGate) return;
        // Only the recorder thread may acknowledge Aborted after parking its
        // active item. Callers publish the command and wait for that release.
        incomplete_gate_command.store(IncompleteGateCommand::Abort, std::memory_order_release);
    }

    void stop() {
        abort_incomplete_gate();
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

    ~KeepAlivePinnedRecorder() { stop(); }
};

static bool wait_pinned_requests(KeepAlivePinnedRecorder& recorder,
                                 u32 expected,
                                 std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        const u32 requests = recorder.requests.load(std::memory_order_acquire);
        if (requests > expected) {
            error = "pinned recorder saw unexpected extra requests";
            return false;
        }
        if (requests == expected) return true;
        usleep(5000);
    }
    error = "pinned recorder request deadline exceeded";
    return false;
}

static void settle_for_invalid_target_side_effects();

static bool wait_first_malformed_peer_close(KeepAlivePinnedRecorder& recorder, std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (recorder.first_malformed_send_failed.load(std::memory_order_acquire)) {
            error = "origin failed to send the first malformed response";
            return false;
        }
        if (recorder.first_peer_unexpected_data.load(std::memory_order_acquire)) {
            error = "origin 1 received unexpected bytes after its recorded request";
            return false;
        }
        if (recorder.first_peer_observation_failed.load(std::memory_order_acquire)) {
            error = "origin 1 peer-close observation failed";
            return false;
        }
        if (recorder.accepted.load(std::memory_order_acquire) > 1 ||
            recorder.requests.load(std::memory_order_acquire) > 1) {
            error = "unexpected upstream activity occurred before downstream request 2";
            return false;
        }
        if (recorder.first_peer_closed.load(std::memory_order_acquire)) {
            if (!recorder.first_malformed_sent_open.load(std::memory_order_acquire)) {
                error = "origin 1 closed without publishing its malformed response";
                return false;
            }
            return true;
        }
        usleep(5000);
    }
    error = "proxy did not close origin 1 after the malformed response";
    return false;
}

static bool exercise_malformed_head_reuse(u16 frontend_port,
                                          KeepAlivePinnedRecorder& recorder,
                                          const char* side,
                                          std::vector<std::vector<char>>& responses,
                                          std::string& error) {
    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 ||
        !send_all(client.fd, kHeadKeepAliveRequest1, sizeof(kHeadKeepAliveRequest1) - 1)) {
        error = std::string(side) + " malformed HEAD request 1 send failed";
        return false;
    }

    responses.clear();
    std::vector<char> first;
    std::string detail;
    if (!read_head_response(client.fd, first, detail)) {
        error = std::string(side) + " malformed HEAD response 1 failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(
            first, kHeadGatewayKeepAliveResponseNormalized, detail)) {
        error = std::string(side) + " malformed HEAD response 1 mismatch: " + detail;
        return false;
    }
    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, detail) || eof) {
        error = eof ? std::string(side) + " closed downstream after malformed response 1"
                    : std::string(side) + " malformed response 1 quiet window failed: " + detail;
        return false;
    }
    responses.push_back(std::move(first));

    detail.clear();
    if (!wait_first_malformed_peer_close(recorder, detail)) {
        error = std::string(side) + " malformed origin-close evidence failed: " + detail;
        return false;
    }
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1) {
        error = std::string(side) + " did not have exactly one upstream before request 2";
        return false;
    }

    if (!send_all(client.fd, kHeadKeepAliveRequest2, sizeof(kHeadKeepAliveRequest2) - 1)) {
        error = std::string(side) + " malformed HEAD request 2 send failed";
        return false;
    }
    std::vector<char> second;
    detail.clear();
    if (!read_head_response(client.fd, second, detail)) {
        error = std::string(side) + " malformed HEAD response 2 failed: " + detail;
        return false;
    }
    if (!read_eof(client.fd, detail)) {
        error = std::string(side) + " malformed HEAD response 2 EOF failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kHeadResponseNormalized, detail)) {
        error = std::string(side) + " malformed HEAD response 2 mismatch: " + detail;
        return false;
    }
    responses.push_back(std::move(second));

    if (!wait_pinned_requests(recorder, 2, detail)) {
        error = std::string(side) + " malformed request-2 origin evidence failed: " + detail;
        return false;
    }
    // Keep both the proxy and recorder live so a delayed retry, replay, or third
    // accept remains observable instead of being suppressed by test cleanup.
    settle_for_invalid_target_side_effects();
    if (recorder.accepted.load(std::memory_order_acquire) != 2 ||
        recorder.requests.load(std::memory_order_acquire) != 2 ||
        recorder.first_malformed_send_failed.load(std::memory_order_acquire) ||
        recorder.first_peer_unexpected_data.load(std::memory_order_acquire) ||
        recorder.first_peer_observation_failed.load(std::memory_order_acquire) ||
        !recorder.first_malformed_sent_open.load(std::memory_order_acquire) ||
        !recorder.first_peer_closed.load(std::memory_order_acquire)) {
        error = std::string(side) + " malformed phase saw extra or incomplete origin activity";
        return false;
    }
    return true;
}

static const char* incomplete_gate_state_name(KeepAlivePinnedRecorder::IncompleteGateState state) {
    using State = KeepAlivePinnedRecorder::IncompleteGateState;
    switch (state) {
        case State::Idle:
            return "Idle";
        case State::SentOpenWaitingGate:
            return "SentOpenWaitingGate";
        case State::SendFailed:
            return "SendFailed";
        case State::PeerClosedBeforeGate:
            return "PeerClosedBeforeGate";
        case State::UnexpectedDataBeforeGate:
            return "UnexpectedDataBeforeGate";
        case State::ProbeFailed:
            return "ProbeFailed";
        case State::ClosedByGate:
            return "ClosedByGate";
        case State::Aborted:
            return "Aborted";
    }
    return "unknown";
}

static bool wait_incomplete_gate_state(KeepAlivePinnedRecorder& recorder,
                                       KeepAlivePinnedRecorder::IncompleteGateState expected,
                                       std::string& error) {
    using State = KeepAlivePinnedRecorder::IncompleteGateState;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        const State state = recorder.incomplete_gate_state.load(std::memory_order_acquire);
        if (state == expected) return true;
        const bool transitional = expected == State::SentOpenWaitingGate
                                      ? state == State::Idle
                                      : state == State::SentOpenWaitingGate;
        if (!transitional) {
            error = std::string("incomplete origin gate entered ") +
                    incomplete_gate_state_name(state) + " while waiting for " +
                    incomplete_gate_state_name(expected);
            return false;
        }
        if (recorder.accepted.load(std::memory_order_acquire) > 1 ||
            recorder.requests.load(std::memory_order_acquire) > 1) {
            error = "unexpected upstream activity occurred before incomplete gate completion";
            return false;
        }
        usleep(5000);
    }
    error = std::string("deadline waiting for incomplete origin gate state ") +
            incomplete_gate_state_name(expected);
    return false;
}

static bool abort_incomplete_gate_and_wait(KeepAlivePinnedRecorder& recorder,
                                           std::chrono::milliseconds budget) {
    using State = KeepAlivePinnedRecorder::IncompleteGateState;
    if (recorder.incomplete_gate_state.load(std::memory_order_acquire) == State::ClosedByGate)
        return true;
    recorder.abort_incomplete_gate();
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        const State state = recorder.incomplete_gate_state.load(std::memory_order_acquire);
        if (state == State::Aborted || state == State::ClosedByGate) return true;
        usleep(5000);
    }
    return false;
}

static bool exercise_incomplete_eof_head_reuse(u16 frontend_port,
                                               KeepAlivePinnedRecorder& recorder,
                                               const char* side,
                                               std::vector<std::vector<char>>& responses,
                                               std::string& error) {
    using Command = KeepAlivePinnedRecorder::IncompleteGateCommand;
    using State = KeepAlivePinnedRecorder::IncompleteGateState;
    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    struct GateAbortGuard {
        KeepAlivePinnedRecorder& recorder;
        bool armed = true;
        ~GateAbortGuard() {
            if (!armed) return;
            (void)abort_incomplete_gate_and_wait(recorder, std::chrono::seconds(1));
        }
    } gate_guard{recorder};
    if (client.fd < 0 ||
        !send_all(client.fd, kHeadKeepAliveRequest1, sizeof(kHeadKeepAliveRequest1) - 1)) {
        error = std::string(side) + " incomplete HEAD request 1 send failed";
        return false;
    }

    responses.clear();
    std::string detail;
    if (!wait_incomplete_gate_state(recorder, State::SentOpenWaitingGate, detail)) {
        error = std::string(side) + " incomplete origin did not reach gate: " + detail;
        return false;
    }
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1) {
        error = std::string(side) + " incomplete phase did not have exactly one origin request";
        return false;
    }

    // Positive incomplete bytes must not publish a response or close the
    // reusable downstream until this test explicitly authorizes origin EOF.
    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, detail) || eof) {
        error = eof ? std::string(side) + " closed downstream before incomplete EOF gate"
                    : std::string(side) + " incomplete pre-EOF quiet window failed: " + detail;
        return false;
    }
    if (recorder.incomplete_gate_state.load(std::memory_order_acquire) !=
            State::SentOpenWaitingGate ||
        recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1) {
        error = std::string(side) + " incomplete origin changed before EOF authorization";
        return false;
    }

    recorder.incomplete_gate_command.store(Command::Close, std::memory_order_release);
    detail.clear();
    if (!wait_incomplete_gate_state(recorder, State::ClosedByGate, detail)) {
        error = std::string(side) + " incomplete EOF authorization failed: " + detail;
        return false;
    }
    gate_guard.armed = false;

    std::vector<char> first;
    if (!read_head_response(client.fd, first, detail)) {
        error = std::string(side) + " incomplete HEAD response 1 failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(
            first, kHeadGatewayKeepAliveResponseNormalized, detail)) {
        error = std::string(side) + " incomplete HEAD response 1 mismatch: " + detail;
        return false;
    }
    eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, detail) || eof) {
        error = eof ? std::string(side) + " closed downstream after incomplete 502"
                    : std::string(side) + " incomplete response 1 quiet window failed: " + detail;
        return false;
    }
    responses.push_back(std::move(first));

    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1 ||
        recorder.incomplete_gate_state.load(std::memory_order_acquire) != State::ClosedByGate) {
        error = std::string(side) + " incomplete phase changed before downstream request 2";
        return false;
    }
    if (!send_all(client.fd, kHeadKeepAliveRequest2, sizeof(kHeadKeepAliveRequest2) - 1)) {
        error = std::string(side) + " incomplete HEAD request 2 send failed";
        return false;
    }
    std::vector<char> second;
    detail.clear();
    if (!read_head_response(client.fd, second, detail)) {
        error = std::string(side) + " incomplete HEAD response 2 failed: " + detail;
        return false;
    }
    if (!read_eof(client.fd, detail)) {
        error = std::string(side) + " incomplete HEAD response 2 EOF failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kHeadResponseNormalized, detail)) {
        error = std::string(side) + " incomplete HEAD response 2 mismatch: " + detail;
        return false;
    }
    responses.push_back(std::move(second));

    if (!wait_pinned_requests(recorder, 2, detail)) {
        error = std::string(side) + " incomplete request-2 origin evidence failed: " + detail;
        return false;
    }
    settle_for_invalid_target_side_effects();
    if (recorder.accepted.load(std::memory_order_acquire) != 2 ||
        recorder.requests.load(std::memory_order_acquire) != 2 ||
        recorder.incomplete_gate_state.load(std::memory_order_acquire) != State::ClosedByGate) {
        error = std::string(side) + " incomplete phase saw extra or incomplete origin activity";
        return false;
    }
    return true;
}

static bool normalize_date(std::vector<char>& bytes) {
    const size_t header_length = header_end(bytes);
    if (header_length == 0) return false;

    size_t date_count = 0;
    size_t date_start = 0;
    for (size_t line_start = 0; line_start < header_length;) {
        size_t line_end = line_start;
        while (line_end + 1 < header_length &&
               !(bytes[line_end] == '\r' && bytes[line_end + 1] == '\n'))
            line_end++;
        if (line_end + 1 >= header_length) return false;
        if (line_end == line_start) break;
        if (line_end - line_start >= 6 &&
            memcmp(bytes.data() + line_start, "Date: ", sizeof("Date: ") - 1) == 0) {
            date_count++;
            if (date_count != 1) return false;
            date_start = line_start + sizeof("Date: ") - 1;
            if (line_end - date_start != 29) return false;
        }
        line_start = line_end + 2;
    }
    if (date_count != 1) return false;

    const char* date = bytes.data() + date_start;
    const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    const auto token_is_one_of = [](const char* value, const char* const* tokens, size_t count) {
        for (size_t i = 0; i < count; i++)
            if (memcmp(value, tokens[i], 3) == 0) return true;
        return false;
    };
    static const char* const kWeekdays[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
    static const char* const kMonths[] = {
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    };
    const auto two_digits = [&](size_t offset) {
        return is_digit(date[offset]) && is_digit(date[offset + 1])
                   ? static_cast<unsigned>(date[offset] - '0') * 10u +
                         static_cast<unsigned>(date[offset + 1] - '0')
                   : 100u;
    };
    if (!token_is_one_of(date, kWeekdays, sizeof(kWeekdays) / sizeof(kWeekdays[0])) ||
        date[3] != ',' || date[4] != ' ' || date[7] != ' ' ||
        !token_is_one_of(date + 8, kMonths, sizeof(kMonths) / sizeof(kMonths[0])) ||
        date[11] != ' ' || date[16] != ' ' || date[19] != ':' || date[22] != ':' ||
        date[25] != ' ' || memcmp(date + 26, "GMT", 3) != 0)
        return false;
    for (size_t i = 12; i < 16; i++)
        if (!is_digit(date[i])) return false;
    const unsigned day = two_digits(5);
    const unsigned hour = two_digits(17);
    const unsigned minute = two_digits(20);
    const unsigned second = two_digits(23);
    if (day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return false;

    // Mutation is deliberately last: invalid input remains byte-for-byte unchanged.
    memset(bytes.data() + date_start, 'X', 29);
    return true;
}

static bool run_normalize_date_self_checks() {
    static constexpr char kValidPrefix[] = "HTTP/1.1 400 Bad Request\r\nDate: ";
    static constexpr char kValidDate[] = "Tue, 01 Jan 2030 00:00:00 GMT";
    static constexpr char kValidSuffix[] = "\r\nContent-Length: 0\r\n\r\n";
    const std::string valid_wire = std::string(kValidPrefix) + kValidDate + kValidSuffix;

    std::vector<char> valid(valid_wire.begin(), valid_wire.end());
    const std::string valid_body_date = valid_wire + "Date: body-is-not-a-header\r\n";
    valid.assign(valid_body_date.begin(), valid_body_date.end());
    const std::vector<char> valid_before = valid;
    if (!normalize_date(valid) || valid.size() != valid_before.size()) {
        std::cerr << "FAIL [Date normalizer self-check]: valid Date was rejected\n";
        return false;
    }
    const std::string expected_valid = std::string(kValidPrefix) + "XXXXXXXXXXXXXXXXXXXXXXXXXXXXX" +
                                       kValidSuffix + "Date: body-is-not-a-header\r\n";
    if (std::string(valid.begin(), valid.end()) != expected_valid) {
        std::cerr << "FAIL [Date normalizer self-check]: valid Date mutation was not exact\n";
        return false;
    }

    const auto expect_invalid = [](const char* label, const std::string& wire) {
        std::vector<char> bytes(wire.begin(), wire.end());
        const std::vector<char> before = bytes;
        if (normalize_date(bytes) || bytes != before) {
            std::cerr << "FAIL [Date normalizer self-check]: " << label
                      << " was accepted or mutated\n";
            return false;
        }
        return true;
    };
    if (!expect_invalid("duplicate Date header",
                        valid_wire.substr(0, valid_wire.size() - 2) +
                            "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\n\r\n") ||
        !expect_invalid(
            "invalid weekday",
            std::string(kValidPrefix) + "Xue, 01 Jan 2030 00:00:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid punctuation",
            std::string(kValidPrefix) + "Tue; 01 Jan 2030 00:00:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid day range",
            std::string(kValidPrefix) + "Tue, 00 Jan 2030 00:00:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid month",
            std::string(kValidPrefix) + "Tue, 01 Xxx 2030 00:00:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid year digit",
            std::string(kValidPrefix) + "Tue, 01 Jan 20X0 00:00:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid hour range",
            std::string(kValidPrefix) + "Tue, 01 Jan 2030 24:00:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid minute range",
            std::string(kValidPrefix) + "Tue, 01 Jan 2030 00:60:00 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid second range",
            std::string(kValidPrefix) + "Tue, 01 Jan 2030 00:00:60 GMT" + kValidSuffix) ||
        !expect_invalid(
            "invalid GMT suffix",
            std::string(kValidPrefix) + "Tue, 01 Jan 2030 00:00:00 GMS" + kValidSuffix) ||
        !expect_invalid(
            "invalid fixed-width value",
            std::string(kValidPrefix) + "Tue, 01 Jan 2030 00:00:00 GMTX" + kValidSuffix))
        return false;
    return true;
}

static void dump_wire(const char* label, const std::vector<char>& wire) {
    const size_t n = wire.size() < 4096 ? wire.size() : 4096;
    std::cerr << label << " length=" << wire.size() << " escaped=";
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = static_cast<unsigned char>(wire[i]);
        if (c == '\r')
            std::cerr << "\\r";
        else if (c == '\n')
            std::cerr << "\\n";
        else if (c == '\t')
            std::cerr << "\\t";
        else if (c >= 0x20 && c < 0x7f)
            std::cerr << static_cast<char>(c);
        else
            std::cerr << "\\x" << std::hex << static_cast<int>(c) << std::dec;
    }
    std::cerr << "\n" << label << " hex=" << std::hex;
    for (size_t i = 0; i < n; i++)
        std::cerr << (i ? " " : "")
                  << (static_cast<int>(static_cast<unsigned char>(wire[i])) & 0xff);
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
    if (total == 0)
        std::cerr << "<empty>\n";
    else if (total == 8192)
        std::cerr << "\n<truncated>\n";
    close(fd);
}

static bool log_contains(const std::string& path, const char* needle) {
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    std::string contents;
    char buf[1024];
    while (contents.size() < 8192) {
        const size_t want =
            sizeof(buf) < 8192 - contents.size() ? sizeof(buf) : 8192 - contents.size();
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

static bool log_count_line_with(const std::string& path,
                                const char* marker,
                                const char* context,
                                u32& count) {
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    std::string contents;
    char buf[1024];
    while (contents.size() < 8192) {
        const size_t want =
            sizeof(buf) < 8192 - contents.size() ? sizeof(buf) : 8192 - contents.size();
        const ssize_t n = read(fd, buf, want);
        if (n > 0) {
            contents.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            close(fd);
            return false;
        }
        break;
    }
    close(fd);
    count = 0;
    const std::string marker_text(marker);
    const std::string context_text(context);
    if (marker_text.empty() || context_text.empty()) return false;
    for (size_t line_start = 0;;) {
        const size_t line_end = contents.find('\n', line_start);
        if (line_end == std::string::npos) break;
        const std::string line = contents.substr(line_start, line_end - line_start);
        if (line.find(marker_text) != std::string::npos &&
            line.find(context_text) != std::string::npos)
            count++;
        line_start = line_end + 1;
    }
    return true;
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

static bool starts_with_400(const std::vector<char>& response) {
    static constexpr char kStatus[] = "HTTP/1.1 400 Bad Request\r\n";
    return response.size() >= sizeof(kStatus) - 1 &&
           memcmp(response.data(), kStatus, sizeof(kStatus) - 1) == 0;
}

static void settle_for_invalid_target_side_effects() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        if (remaining <= 0) return;
        const int wait_ms = remaining > 50 ? 50 : static_cast<int>(remaining);
        (void)poll(nullptr, 0, wait_ms > 0 ? wait_ms : 1);
    }
}

static int missing_prerequisite(const char* message) {
    std::cerr << "SKIP: " << message << "\n";
    const char* required = getenv("RUT_NGINX_DIFFERENTIAL_REQUIRED");
    return required && strcmp(required, "1") == 0 ? 1 : 77;
}

struct DefaultBufferingTimeoutObservation {
    std::vector<char> downstream;
    u64 first_downstream_byte_ns = 0;
    u64 downstream_eof_ns = 0;
};

struct DefaultBufferingCompleteObservation {
    std::vector<char> downstream;
    u64 request_prefix_sent_ns = 0;
    u64 request_suffix_sent_ns = 0;
    u64 first_downstream_byte_ns = 0;
    u64 downstream_complete_ns = 0;
    u64 downstream_eof_ns = 0;
};

struct DefaultBufferingEofObservation {
    std::vector<char> downstream;
    u64 origin_close_authorized_ns = 0;
    u64 origin_close_released_ns = 0;
    u64 first_downstream_byte_ns = 0;
    u64 downstream_eof_ns = 0;
};

static u64 steady_now_ns() {
    return static_cast<u64>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count());
}

static bool capture_nginx_default_buffering_timeout(u16 frontend_port,
                                                    const std::string& nginx_config_path,
                                                    const std::string& nginx_log_path,
                                                    const std::string& container_name,
                                                    Recorder& recorder,
                                                    const char* request,
                                                    u32 request_len,
                                                    const char* expected_response_normalized,
                                                    DefaultBufferingTimeoutObservation& observation,
                                                    std::string& error) {
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for default-buffering timeout baseline";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 || !send_all(client.fd, request, request_len)) {
        error = "default-buffering timeout downstream request failed";
        return false;
    }

    const auto origin_send_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!recorder.response_sent_open.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < origin_send_deadline) {
        if (recorder.response_send_failed.load(std::memory_order_acquire) ||
            recorder.response_peer_observation_failed.load(std::memory_order_acquire) ||
            recorder.accepted.load(std::memory_order_acquire) > 1 ||
            recorder.requests.load(std::memory_order_acquire) > 1) {
            error = "default-buffering origin failed before publishing its open response";
            return false;
        }
        usleep(5000);
    }
    if (!recorder.response_sent_open.load(std::memory_order_acquire) ||
        recorder.response_sent_ns.load(std::memory_order_acquire) == 0 ||
        recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1) {
        error = "default-buffering origin did not publish exactly one open response";
        return false;
    }

    // The origin issued one application-level send_all call and remains open.
    // This proves an observable downstream quiet interval; it makes no claim
    // about send(2), TCP segment, nginx read, or completion boundaries.
    bool early_eof = false;
    std::string detail;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, early_eof, detail) || early_eof) {
        error = early_eof ? "nginx closed before the configured read timeout"
                          : "nginx committed bytes before the configured read timeout: " + detail;
        return false;
    }
    if (recorder.response_peer_closed.load(std::memory_order_acquire) ||
        recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
        recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
        error = "origin connection changed during the pre-timeout quiet interval";
        return false;
    }

    observation.downstream.clear();
    observation.first_downstream_byte_ns = 0;
    observation.downstream_eof_ns = 0;
    const auto downstream_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < downstream_deadline) {
        pollfd p{client.fd, POLLIN | POLLHUP | POLLERR, 0};
        const int ready = poll(&p, 1, 50);
        if (ready < 0) {
            if (errno == EINTR) continue;
            error = "default-buffering downstream poll failed";
            return false;
        }
        if (ready == 0) continue;
        char bytes[1024];
        const ssize_t n = recv(client.fd, bytes, sizeof(bytes), 0);
        const u64 now_ns = steady_now_ns();
        if (n > 0) {
            if (observation.first_downstream_byte_ns == 0)
                observation.first_downstream_byte_ns = now_ns;
            observation.downstream.insert(observation.downstream.end(), bytes, bytes + n);
            if (observation.downstream.size() > 4096) {
                error = "default-buffering downstream response exceeded bounded capacity";
                return false;
            }
            continue;
        }
        if (n == 0) {
            observation.downstream_eof_ns = now_ns;
            break;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        error = "default-buffering downstream recv failed";
        return false;
    }
    if (observation.first_downstream_byte_ns == 0 || observation.downstream_eof_ns == 0) {
        error = "default-buffering response or EOF exceeded the bounded harness deadline";
        return false;
    }

    const auto origin_close_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!recorder.response_peer_closed.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < origin_close_deadline) {
        if (recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
            recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
            error = "origin peer-close observation failed after timeout";
            return false;
        }
        usleep(5000);
    }
    const u64 origin_sent_ns = recorder.response_sent_ns.load(std::memory_order_acquire);
    const u64 origin_closed_ns = recorder.response_peer_closed_ns.load(std::memory_order_acquire);
    if (!recorder.response_peer_closed.load(std::memory_order_acquire) || origin_closed_ns == 0) {
        error = "nginx did not retire the silent origin before test cleanup";
        return false;
    }

    static constexpr u64 kMinimumTimeoutNs = 800'000'000ull;
    static constexpr u64 kMaximumTimeoutNs = 3'000'000'000ull;
    const auto in_timeout_class = [&](u64 event_ns) {
        return event_ns >= origin_sent_ns && event_ns - origin_sent_ns >= kMinimumTimeoutNs &&
               event_ns - origin_sent_ns < kMaximumTimeoutNs;
    };
    if (!in_timeout_class(observation.first_downstream_byte_ns) ||
        !in_timeout_class(observation.downstream_eof_ns) || !in_timeout_class(origin_closed_ns)) {
        error = "default-buffering events were outside the one-second timeout class";
        return false;
    }

    detail.clear();
    if (!validate_exact_normalized_response(
            observation.downstream, expected_response_normalized, detail)) {
        error = "default-buffering timeout wire mismatch: " + detail;
        return false;
    }
    const std::string downstream_text(observation.downstream.begin(), observation.downstream.end());
    if (downstream_text.find("hello") != std::string::npos ||
        downstream_text.find("502") != std::string::npos ||
        downstream_text.find("504") != std::string::npos) {
        error = "default-buffering timeout leaked body or failure bytes";
        return false;
    }

    settle_for_invalid_target_side_effects();
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1 ||
        recorder.response_send_failed.load(std::memory_order_acquire) ||
        recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
        recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
        error = "default-buffering timeout saw retry or incomplete origin evidence";
        return false;
    }

    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    if (!nginx_stopped) {
        error = "failed to stop nginx after default-buffering timeout baseline";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after default-buffering timeout baseline";
        return false;
    }
    return true;
}

static bool capture_nginx_default_buffering_complete(
    u16 frontend_port,
    const std::string& nginx_config_path,
    const std::string& nginx_log_path,
    const std::string& container_name,
    Recorder& recorder,
    const std::vector<char>& request_prefix,
    const std::vector<char>& request_suffix,
    u32 request_buffering_observation_ms,
    const char* expected_response_normalized,
    bool expect_downstream_close,
    DefaultBufferingCompleteObservation& observation,
    std::string& error) {
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for default-buffering complete baseline";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 || request_prefix.empty() ||
        !send_all(client.fd, request_prefix.data(), request_prefix.size())) {
        error = "default-buffering complete downstream request failed";
        return false;
    }
    observation.request_prefix_sent_ns = steady_now_ns();
    observation.request_suffix_sent_ns = 0;
    if (observation.request_prefix_sent_ns == 0) {
        error = "default-buffering request-prefix timestamp failed";
        return false;
    }
    if (request_buffering_observation_ms != 0) {
        bool eof = false;
        std::string detail;
        if (!wait_keepalive_quiet_or_eof(
                client.fd, static_cast<int>(request_buffering_observation_ms), eof, detail)) {
            error = "downstream was not quiet during default request buffering: " + detail;
            return false;
        }
        if (eof) {
            error = "nginx closed downstream during incomplete default-buffered request body";
            return false;
        }
        const u64 observation_complete_ns = steady_now_ns();
        if (observation_complete_ns < observation.request_prefix_sent_ns ||
            observation_complete_ns - observation.request_prefix_sent_ns <
                static_cast<u64>(request_buffering_observation_ms) * 1'000'000ull) {
            error = "default request-buffering observation ended before its required duration";
            return false;
        }
        if (recorder.accepted.load(std::memory_order_acquire) != 0 ||
            recorder.requests.load(std::memory_order_acquire) != 0) {
            error = "nginx contacted the origin before the fixed request body completed";
            return false;
        }
        if (request_suffix.empty() ||
            !send_all(client.fd, request_suffix.data(), request_suffix.size())) {
            error = "default-buffering complete request-body suffix send failed";
            return false;
        }
        observation.request_suffix_sent_ns = steady_now_ns();
        if (observation.request_suffix_sent_ns < observation.request_prefix_sent_ns) {
            error = "default-buffering request-suffix timestamp failed";
            return false;
        }
    } else if (!request_suffix.empty()) {
        error = "request suffix requires a finite request-buffering observation";
        return false;
    }

    const auto wait_for_fragment = [&](u32 expected, int budget_ms) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
        while (recorder.response_fragments_sent.load(std::memory_order_acquire) < expected &&
               std::chrono::steady_clock::now() < deadline) {
            if (recorder.response_send_failed.load(std::memory_order_acquire) ||
                recorder.response_peer_observation_failed.load(std::memory_order_acquire) ||
                recorder.accepted.load(std::memory_order_acquire) > 1 ||
                recorder.requests.load(std::memory_order_acquire) > 1)
                return false;
            usleep(1000);
        }
        return recorder.response_fragments_sent.load(std::memory_order_acquire) == expected;
    };
    if (!wait_for_fragment(1, 2000)) {
        error = "origin did not publish the first permit-gated response fragment";
        return false;
    }

    for (u32 part = 0; part < 3; part++) {
        bool eof = false;
        std::string detail;
        if (!wait_keepalive_quiet_or_eof(client.fd, 400, eof, detail) || eof) {
            error = eof ? "nginx closed downstream before the declared body completed"
                        : "nginx exposed a nonfinal default-buffered response: " + detail;
            return false;
        }
        recorder.response_fragment_permit.store(part + 2, std::memory_order_release);
        if (!wait_for_fragment(part + 2, 500)) {
            error = "origin did not publish the next permitted response fragment";
            return false;
        }
    }

    u64 fragment_ns[4]{};
    for (u32 part = 0; part < 4; part++) {
        fragment_ns[part] =
            recorder.response_fragment_sent_ns[part].load(std::memory_order_acquire);
        if (fragment_ns[part] == 0 ||
            (part != 0 && (fragment_ns[part] <= fragment_ns[part - 1] ||
                           fragment_ns[part] - fragment_ns[part - 1] < 350'000'000ull ||
                           fragment_ns[part] - fragment_ns[part - 1] > 650'000'000ull))) {
            error = "permit-gated origin fragment timing left the required progress window";
            return false;
        }
    }
    if (fragment_ns[3] - fragment_ns[0] <= 1'000'000'000ull) {
        error = "permit-gated response did not span more than one timeout interval";
        return false;
    }

    observation.downstream.clear();
    observation.first_downstream_byte_ns = 0;
    observation.downstream_complete_ns = 0;
    observation.downstream_eof_ns = 0;
    const size_t expected_response_size = strlen(expected_response_normalized);
    const u64 response_deadline_ns = fragment_ns[3] + 500'000'000ull;
    for (;;) {
        const u64 now_ns = steady_now_ns();
        if (now_ns >= response_deadline_ns) {
            error = "nginx did not emit the completed buffered response within 500ms";
            return false;
        }
        const int remaining_ms = static_cast<int>((response_deadline_ns - now_ns) / 1'000'000ull);
        pollfd p{client.fd, POLLIN | POLLHUP | POLLERR, 0};
        const int ready =
            poll(&p, 1, remaining_ms > 50 ? 50 : (remaining_ms > 0 ? remaining_ms : 1));
        if (ready < 0) {
            if (errno == EINTR) continue;
            error = "completed-buffer response poll failed";
            return false;
        }
        if (ready == 0) continue;
        char bytes[1024];
        const ssize_t n = recv(client.fd, bytes, sizeof(bytes), 0);
        const u64 recv_ns = steady_now_ns();
        if (n > 0) {
            if (observation.first_downstream_byte_ns == 0)
                observation.first_downstream_byte_ns = recv_ns;
            observation.downstream.insert(observation.downstream.end(), bytes, bytes + n);
            if (observation.downstream.size() > expected_response_size) {
                error = "completed-buffer response included trailing bytes";
                return false;
            }
            const size_t end = header_end(observation.downstream);
            size_t body_len = 0;
            if (end != 0 && parse_content_length(observation.downstream, end, body_len) &&
                observation.downstream.size() == end + body_len) {
                observation.downstream_complete_ns = recv_ns;
                break;
            }
            continue;
        }
        if (n == 0) {
            error = "nginx closed downstream before the complete buffered response";
            return false;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        error = "completed-buffer response recv failed";
        return false;
    }
    if (observation.first_downstream_byte_ns < fragment_ns[3] ||
        observation.downstream_complete_ns < fragment_ns[3] ||
        observation.first_downstream_byte_ns - fragment_ns[3] >= 500'000'000ull ||
        observation.downstream_complete_ns - fragment_ns[3] >= 500'000'000ull) {
        error = "completed buffered response left the post-final promptness window";
        return false;
    }

    std::string detail;
    if (!validate_exact_normalized_response(
            observation.downstream, expected_response_normalized, detail)) {
        error = "default-buffering complete wire mismatch: " + detail;
        return false;
    }

    bool eof = false;
    detail.clear();
    if (!wait_keepalive_quiet_or_eof(client.fd, expect_downstream_close ? 500 : 200, eof, detail)) {
        error = "downstream disposition after the exact completed response failed: " + detail;
        return false;
    }
    if (expect_downstream_close != eof) {
        error = expect_downstream_close
                    ? "nginx did not close downstream after the explicit-close response"
                    : "nginx did not preserve the downstream keep-alive connection";
        return false;
    }
    if (eof) {
        observation.downstream_eof_ns = steady_now_ns();
        if (observation.downstream_eof_ns < observation.downstream_complete_ns ||
            observation.downstream_eof_ns - fragment_ns[3] >= 500'000'000ull) {
            error = "explicit-close EOF left the post-final promptness window";
            return false;
        }
    }

    const auto origin_close_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!recorder.response_peer_closed.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < origin_close_deadline) {
        if (recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
            recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
            error = "origin peer-close observation failed after complete response";
            return false;
        }
        usleep(5000);
    }
    const u64 origin_closed_ns = recorder.response_peer_closed_ns.load(std::memory_order_acquire);
    if (!recorder.response_peer_closed.load(std::memory_order_acquire) ||
        origin_closed_ns < fragment_ns[3]) {
        error = "nginx did not retire the completed origin before cleanup";
        return false;
    }

    settle_for_invalid_target_side_effects();
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1 ||
        recorder.response_send_failed.load(std::memory_order_acquire) ||
        recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
        recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
        error = "default-buffering complete baseline saw retry or incomplete origin evidence";
        return false;
    }

    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    if (!nginx_stopped) {
        error = "failed to stop nginx after default-buffering complete baseline";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after default-buffering complete baseline";
        return false;
    }
    return true;
}

static bool capture_nginx_default_buffering_eof(u16 frontend_port,
                                                const std::string& nginx_config_path,
                                                const std::string& nginx_log_path,
                                                const std::string& container_name,
                                                Recorder& recorder,
                                                const char* request,
                                                u32 request_len,
                                                const char* expected_response_normalized,
                                                DefaultBufferingEofObservation& observation,
                                                std::string& error) {
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for default-buffering EOF baseline";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 || request == nullptr || request_len == 0 ||
        expected_response_normalized == nullptr || !send_all(client.fd, request, request_len)) {
        error = "default-buffering EOF downstream request failed";
        return false;
    }

    const auto origin_send_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!recorder.response_sent_open.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < origin_send_deadline) {
        if (recorder.response_send_failed.load(std::memory_order_acquire) ||
            recorder.response_peer_closed.load(std::memory_order_acquire) ||
            recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
            recorder.response_peer_observation_failed.load(std::memory_order_acquire) ||
            recorder.accepted.load(std::memory_order_acquire) > 1 ||
            recorder.requests.load(std::memory_order_acquire) > 1) {
            error = "default-buffering EOF origin failed before reaching its close gate";
            return false;
        }
        usleep(1000);
    }
    const u64 origin_sent_ns = recorder.response_sent_ns.load(std::memory_order_acquire);
    if (!recorder.response_sent_open.load(std::memory_order_acquire) || origin_sent_ns == 0 ||
        recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1) {
        error = "default-buffering EOF origin did not publish exactly one open prefix";
        return false;
    }

    // nginx default buffering must expose neither the serialized header nor
    // the incomplete body while the origin remains open behind the test gate.
    bool early_eof = false;
    std::string detail;
    if (!wait_keepalive_quiet_or_eof(client.fd, 400, early_eof, detail) || early_eof) {
        error = early_eof ? "nginx closed downstream before the origin EOF gate"
                          : "nginx exposed bytes before the origin EOF gate: " + detail;
        return false;
    }
    if (recorder.response_closed_by_gate.load(std::memory_order_acquire) ||
        recorder.response_peer_closed.load(std::memory_order_acquire) ||
        recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
        recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
        error = "default-buffering EOF origin changed before close authorization";
        return false;
    }

    observation.origin_close_authorized_ns = steady_now_ns();
    recorder.response_close_permit.store(true, std::memory_order_release);
    const auto close_gate_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (!recorder.response_closed_by_gate.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < close_gate_deadline) {
        if (recorder.response_close_failed.load(std::memory_order_acquire) ||
            recorder.response_peer_closed.load(std::memory_order_acquire) ||
            recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
            recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
            error = "origin peer changed instead of completing the authorized clean EOF";
            return false;
        }
        usleep(1000);
    }
    const u64 origin_close_released_ns =
        recorder.response_close_released_ns.load(std::memory_order_acquire);
    observation.origin_close_released_ns = origin_close_released_ns;
    if (!recorder.response_closed_by_gate.load(std::memory_order_acquire) ||
        recorder.response_close_failed.load(std::memory_order_acquire) ||
        observation.origin_close_authorized_ns == 0 || origin_close_released_ns == 0 ||
        origin_close_released_ns < observation.origin_close_authorized_ns ||
        origin_close_released_ns - observation.origin_close_authorized_ns >= 500'000'000ull ||
        origin_close_released_ns < origin_sent_ns) {
        error = "origin did not complete the authorized clean EOF";
        return false;
    }

    observation.downstream.clear();
    observation.first_downstream_byte_ns = 0;
    observation.downstream_eof_ns = 0;
    const u64 downstream_deadline_ns = origin_close_released_ns + 500'000'000ull;
    for (;;) {
        const u64 loop_now_ns = steady_now_ns();
        if (loop_now_ns >= downstream_deadline_ns) break;
        const u64 remaining_ns = downstream_deadline_ns - loop_now_ns;
        const int remaining_ms = static_cast<int>(remaining_ns / 1'000'000ull);
        pollfd p{client.fd, POLLIN | POLLHUP | POLLERR, 0};
        const int ready =
            poll(&p, 1, remaining_ms > 50 ? 50 : (remaining_ms > 0 ? remaining_ms : 1));
        if (ready < 0) {
            if (errno == EINTR) continue;
            error = "default-buffering EOF downstream poll failed";
            return false;
        }
        if (ready == 0) continue;
        char bytes[1024];
        const ssize_t n = recv(client.fd, bytes, sizeof(bytes), 0);
        const u64 now_ns = steady_now_ns();
        if (n > 0) {
            if (observation.first_downstream_byte_ns == 0)
                observation.first_downstream_byte_ns = now_ns;
            observation.downstream.insert(observation.downstream.end(), bytes, bytes + n);
            if (observation.downstream.size() > strlen(expected_response_normalized)) {
                error = "default-buffering EOF response included trailing bytes";
                return false;
            }
            continue;
        }
        if (n == 0) {
            observation.downstream_eof_ns = now_ns;
            break;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        error = "default-buffering EOF downstream recv failed";
        return false;
    }
    if (observation.first_downstream_byte_ns == 0 || observation.downstream_eof_ns == 0 ||
        observation.first_downstream_byte_ns < origin_close_released_ns ||
        observation.downstream_eof_ns < observation.first_downstream_byte_ns ||
        observation.first_downstream_byte_ns - origin_close_released_ns >= 500'000'000ull ||
        observation.downstream_eof_ns - origin_close_released_ns >= 500'000'000ull ||
        observation.downstream_eof_ns - origin_sent_ns >= 900'000'000ull) {
        error = "default-buffering EOF response left the prompt sub-timeout class";
        return false;
    }

    detail.clear();
    if (!validate_exact_normalized_response(
            observation.downstream, expected_response_normalized, detail)) {
        error = "default-buffering EOF wire mismatch: " + detail;
        return false;
    }
    const std::string downstream_text(observation.downstream.begin(), observation.downstream.end());
    if (downstream_text.find("502") != std::string::npos ||
        downstream_text.find("504") != std::string::npos) {
        error = "default-buffering EOF response included failure bytes";
        return false;
    }

    settle_for_invalid_target_side_effects();
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1 ||
        recorder.response_send_failed.load(std::memory_order_acquire) ||
        recorder.response_close_failed.load(std::memory_order_acquire) ||
        recorder.response_peer_closed.load(std::memory_order_acquire) ||
        recorder.response_peer_unexpected_data.load(std::memory_order_acquire) ||
        recorder.response_peer_observation_failed.load(std::memory_order_acquire)) {
        error = "default-buffering EOF baseline saw retry or invalid gate evidence";
        return false;
    }

    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    if (!nginx_stopped) {
        error = "failed to stop nginx after default-buffering EOF baseline";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after default-buffering EOF baseline";
        return false;
    }
    return true;
}

static bool capture_nginx_head_keepalive_success(u16 frontend_port,
                                                 const std::string& nginx_config_path,
                                                 const std::string& nginx_log_path,
                                                 const std::string& container_name,
                                                 KeepAlivePinnedRecorder& recorder,
                                                 std::vector<std::vector<char>>& responses,
                                                 std::string& error) {
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for pinned keep-alive HEAD baseline";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 ||
        !send_all(client.fd, kHeadKeepAliveRequest1, sizeof(kHeadKeepAliveRequest1) - 1)) {
        error = "failed to send first pinned keep-alive HEAD request";
        return false;
    }
    responses.clear();
    std::vector<char> first;
    if (!read_head_response(client.fd, first, error)) return false;
    if (!validate_exact_normalized_response(first, kHeadKeepAliveResponseNormalized, error))
        return false;
    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, error) || eof) {
        if (error.empty()) error = "nginx closed first pinned HEAD keep-alive response";
        return false;
    }
    responses.push_back(std::move(first));

    if (!send_all(client.fd, kHeadKeepAliveRequest2, sizeof(kHeadKeepAliveRequest2) - 1)) {
        error = "failed to send second pinned close-intent HEAD request";
        return false;
    }
    std::vector<char> second;
    if (!read_head_response(client.fd, second, error) || !read_eof(client.fd, error)) return false;
    if (!validate_exact_normalized_response(second, kHeadResponseNormalized, error)) return false;
    responses.push_back(std::move(second));

    if (!wait_pinned_requests(recorder, 2, error)) return false;
    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    if (!nginx_stopped) {
        error = "failed to stop nginx after pinned keep-alive HEAD baseline";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after pinned keep-alive HEAD baseline";
        return false;
    }
    settle_for_invalid_target_side_effects();
    if (recorder.requests.load(std::memory_order_acquire) != 2 ||
        recorder.accepted.load(std::memory_order_acquire) > 2) {
        error = "pinned keep-alive HEAD baseline saw unexpected extra upstream activity";
        return false;
    }
    return true;
}

static bool capture_nginx_head_keepalive_gateway(u16 frontend_port,
                                                 u16 backend_port,
                                                 const std::string& nginx_config_path,
                                                 const std::string& nginx_log_path,
                                                 const std::string& container_name,
                                                 DeadPort& dead,
                                                 std::vector<std::vector<char>>& responses,
                                                 u32& connect_failure_count,
                                                 std::string& error) {
    if (dead.fd < 0) {
        error = "pinned HEAD gateway dead port is not reserved";
        return false;
    }
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for keep-alive HEAD gateway baseline";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 ||
        !send_all(
            client.fd, kHeadGatewayKeepAliveRequest1, sizeof(kHeadGatewayKeepAliveRequest1) - 1)) {
        error = "failed to send first pinned HEAD gateway request";
        return false;
    }
    responses.clear();
    std::vector<char> first;
    if (!read_head_response(client.fd, first, error)) return false;
    if (!validate_exact_normalized_response(first, kHeadGatewayKeepAliveResponseNormalized, error))
        return false;
    responses.push_back(std::move(first));
    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, error) || eof) {
        if (error.empty()) error = "nginx closed first pinned HEAD gateway response";
        return false;
    }
    if (!send_all(
            client.fd, kHeadGatewayKeepAliveRequest2, sizeof(kHeadGatewayKeepAliveRequest2) - 1)) {
        error = "failed to send second pinned HEAD gateway request";
        return false;
    }
    std::vector<char> second;
    if (!read_head_response(client.fd, second, error) || !read_eof(client.fd, error)) return false;
    if (!validate_exact_normalized_response(second, kHeadGatewayResponseNormalized, error))
        return false;
    responses.push_back(std::move(second));

    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    const std::string upstream_context = "127.0.0.1:" + std::to_string(backend_port);
    const bool log_readable = log_count_line_with(
        nginx_log_path, "connect() failed", upstream_context.c_str(), connect_failure_count);
    if (!nginx_stopped) {
        error = "failed to stop nginx after pinned HEAD gateway baseline";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after pinned HEAD gateway baseline";
        return false;
    }
    if (responses.size() != 2) {
        error = "pinned HEAD gateway baseline did not produce exactly two responses";
        return false;
    }
    if (!log_readable || connect_failure_count != 2) {
        error =
            "pinned HEAD gateway baseline did not produce exactly two scoped connect failures "
            "(actual " +
            std::to_string(connect_failure_count) + ")";
        return false;
    }
    return true;
}

static bool capture_rut_head_keepalive_success(u16 frontend_port,
                                               const std::string& source_path,
                                               const std::string& rut_log_path,
                                               const std::string& rut_path,
                                               KeepAlivePinnedRecorder& recorder,
                                               std::vector<std::vector<char>>& responses,
                                               std::string& error) {
    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start production RUT for reusable HEAD success differential";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) {
        error = "RUT reusable HEAD success readiness failed: " + error;
        return false;
    }

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 ||
        !send_all(client.fd, kHeadKeepAliveRequest1, sizeof(kHeadKeepAliveRequest1) - 1)) {
        error = "RUT reusable HEAD success request 1 send failed";
        return false;
    }
    responses.clear();
    std::vector<char> first;
    std::string detail;
    if (!read_head_response(client.fd, first, detail)) {
        error = "RUT reusable HEAD success response 1 failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(first, kHeadKeepAliveResponseNormalized, detail)) {
        error = "RUT reusable HEAD success response 1 mismatch: " + detail;
        return false;
    }
    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, detail) || eof) {
        error = eof ? "RUT reusable HEAD success response 1 closed during quiet window"
                    : "RUT reusable HEAD success response 1 quiet window failed: " + detail;
        return false;
    }
    responses.push_back(std::move(first));

    if (!send_all(client.fd, kHeadKeepAliveRequest2, sizeof(kHeadKeepAliveRequest2) - 1)) {
        error = "RUT reusable HEAD success request 2 send failed";
        return false;
    }
    std::vector<char> second;
    detail.clear();
    if (!read_head_response(client.fd, second, detail)) {
        error = "RUT reusable HEAD success response 2 failed: " + detail;
        return false;
    }
    if (!read_eof(client.fd, detail)) {
        error = "RUT reusable HEAD success response 2 EOF failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kHeadResponseNormalized, detail)) {
        error = "RUT reusable HEAD success response 2 mismatch: " + detail;
        return false;
    }
    responses.push_back(std::move(second));

    if (!wait_pinned_requests(recorder, 2, detail)) {
        error = "RUT reusable HEAD success upstream evidence failed: " + detail;
        return false;
    }
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT after reusable HEAD success differential";
        return false;
    }
    settle_for_invalid_target_side_effects();
    if (recorder.requests.load(std::memory_order_acquire) != 2 ||
        recorder.accepted.load(std::memory_order_acquire) != 2) {
        error = "RUT reusable HEAD success saw unexpected upstream accept/request count";
        return false;
    }
    return true;
}

static bool capture_rut_head_keepalive_gateway(u16 frontend_port,
                                               const std::string& source_path,
                                               const std::string& rut_log_path,
                                               const std::string& rut_path,
                                               DeadPort& dead,
                                               std::vector<std::vector<char>>& responses,
                                               std::string& error) {
    if (dead.fd < 0) {
        error = "RUT reusable HEAD gateway dead port is not reserved";
        return false;
    }
    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start production RUT for reusable HEAD gateway differential";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) {
        error = "RUT reusable HEAD gateway readiness failed: " + error;
        return false;
    }

    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 ||
        !send_all(
            client.fd, kHeadGatewayKeepAliveRequest1, sizeof(kHeadGatewayKeepAliveRequest1) - 1)) {
        error = "RUT reusable HEAD gateway request 1 send failed";
        return false;
    }
    responses.clear();
    std::vector<char> first;
    std::string detail;
    if (!read_head_response(client.fd, first, detail)) {
        error = "RUT reusable HEAD gateway response 1 failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(
            first, kHeadGatewayKeepAliveResponseNormalized, detail)) {
        error = "RUT reusable HEAD gateway response 1 mismatch: " + detail;
        return false;
    }
    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, detail) || eof) {
        error = eof ? "RUT reusable HEAD gateway response 1 closed during quiet window"
                    : "RUT reusable HEAD gateway response 1 quiet window failed: " + detail;
        return false;
    }
    responses.push_back(std::move(first));

    if (!send_all(
            client.fd, kHeadGatewayKeepAliveRequest2, sizeof(kHeadGatewayKeepAliveRequest2) - 1)) {
        error = "RUT reusable HEAD gateway request 2 send failed";
        return false;
    }
    std::vector<char> second;
    detail.clear();
    if (!read_head_response(client.fd, second, detail)) {
        error = "RUT reusable HEAD gateway response 2 failed: " + detail;
        return false;
    }
    if (!read_eof(client.fd, detail)) {
        error = "RUT reusable HEAD gateway response 2 EOF failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kHeadGatewayResponseNormalized, detail)) {
        error = "RUT reusable HEAD gateway response 2 mismatch: " + detail;
        return false;
    }
    responses.push_back(std::move(second));

    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT after reusable HEAD gateway differential";
        return false;
    }
    if (responses.size() != 2) {
        error = "RUT reusable HEAD gateway did not produce exactly two complete responses";
        return false;
    }
    return true;
}

static bool capture_nginx_head_malformed_reuse(u16 frontend_port,
                                               const std::string& nginx_config_path,
                                               const std::string& nginx_log_path,
                                               const std::string& container_name,
                                               KeepAlivePinnedRecorder& recorder,
                                               std::vector<std::vector<char>>& responses,
                                               std::string& error) {
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for malformed reusable HEAD differential";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    const bool exercised =
        exercise_malformed_head_reuse(frontend_port, recorder, "nginx", responses, error);
    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    if (!exercised) return false;
    if (!nginx_stopped) {
        error = "failed to stop nginx after malformed reusable HEAD differential";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after malformed reusable HEAD differential";
        return false;
    }
    return true;
}

static bool capture_rut_head_malformed_reuse(u16 frontend_port,
                                             const std::string& source_path,
                                             const std::string& rut_log_path,
                                             const std::string& rut_path,
                                             KeepAlivePinnedRecorder& recorder,
                                             std::vector<std::vector<char>>& responses,
                                             std::string& error) {
    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start generated RUT for malformed reusable HEAD differential";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) {
        error = "generated RUT malformed reusable HEAD readiness failed: " + error;
        return false;
    }

    const bool exercised =
        exercise_malformed_head_reuse(frontend_port, recorder, "RUT", responses, error);
    const bool rut_stopped = stop_child(rut.child);
    if (!exercised) return false;
    if (!rut_stopped) {
        error = "failed to stop generated RUT after malformed reusable HEAD differential";
        return false;
    }
    return true;
}

static bool capture_nginx_head_incomplete_eof_reuse(u16 frontend_port,
                                                    const std::string& nginx_config_path,
                                                    const std::string& nginx_log_path,
                                                    const std::string& container_name,
                                                    KeepAlivePinnedRecorder& recorder,
                                                    std::vector<std::vector<char>>& responses,
                                                    std::string& error) {
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for incomplete-EOF reusable HEAD differential";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) {
        if (!abort_incomplete_gate_and_wait(recorder, std::chrono::seconds(4)))
            error += " (recorder did not acknowledge incomplete-gate Abort before teardown)";
        return false;
    }

    const bool exercised =
        exercise_incomplete_eof_head_reuse(frontend_port, recorder, "nginx", responses, error);
    const bool abort_acknowledged =
        exercised || abort_incomplete_gate_and_wait(recorder, std::chrono::seconds(4));
    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    if (!abort_acknowledged) {
        error += " (recorder did not acknowledge incomplete-gate Abort before teardown)";
        return false;
    }
    if (!exercised) return false;
    if (!nginx_stopped) {
        error = "failed to stop nginx after incomplete-EOF reusable HEAD differential";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after incomplete-EOF reusable HEAD differential";
        return false;
    }
    return true;
}

static bool capture_rut_head_incomplete_eof_reuse(u16 frontend_port,
                                                  const std::string& source_path,
                                                  const std::string& rut_log_path,
                                                  const std::string& rut_path,
                                                  KeepAlivePinnedRecorder& recorder,
                                                  std::vector<std::vector<char>>& responses,
                                                  std::string& error) {
    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start generated RUT for incomplete-EOF reusable HEAD differential";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) {
        if (!abort_incomplete_gate_and_wait(recorder, std::chrono::seconds(4)))
            error += " (recorder did not acknowledge incomplete-gate Abort before teardown)";
        error = "generated RUT incomplete-EOF reusable HEAD readiness failed: " + error;
        return false;
    }

    const bool exercised =
        exercise_incomplete_eof_head_reuse(frontend_port, recorder, "RUT", responses, error);
    const bool abort_acknowledged =
        exercised || abort_incomplete_gate_and_wait(recorder, std::chrono::seconds(4));
    const bool rut_stopped = stop_child(rut.child);
    if (!abort_acknowledged) {
        error += " (recorder did not acknowledge incomplete-gate Abort before teardown)";
        return false;
    }
    if (!exercised) return false;
    if (!rut_stopped) {
        error = "failed to stop generated RUT after incomplete-EOF reusable HEAD differential";
        return false;
    }
    return true;
}

static void dump_pinned_history(const KeepAlivePinnedRecorder& recorder,
                                const char* side = "PINNED") {
    std::cerr << side << " upstream accepted=" << recorder.accepted.load(std::memory_order_acquire)
              << " requests=" << recorder.requests.load(std::memory_order_acquire)
              << " history=" << recorder.history.size() << "\n";
    for (size_t i = 0; i < recorder.history.size(); i++) {
        std::cerr << side << " upstream history[" << i
                  << "] connection_id=" << recorder.history[i].connection_id << "\n";
        const std::string label = std::string(side) + " upstream request";
        dump_wire(label.c_str(), recorder.history[i].wire);
    }
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
    recorder.observe_extra_requests_until_stop = true;
    if (!recorder.setup(backend_port)) {
        error = "backend recorder setup failed";
        return false;
    }

    // Declare the Docker guard before the child guard so shutdown stops the
    // docker client before removing its container on every return path.
    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) {
        return false;
    }
    const int nginx_client = connect_once(frontend_port);
    bool nginx_ok = nginx_client >= 0;
    if (nginx_ok) nginx_ok = send_all(nginx_client, kRequest, sizeof(kRequest) - 1);
    if (nginx_ok) nginx_ok = read_response(nginx_client, nginx_downstream, error);
    if (nginx_ok) nginx_ok = read_eof(nginx_client, error);
    if (nginx_client >= 0) close(nginx_client);
    if (!nginx_ok) {
        error = "nginx request/response failed: " + error;
        return false;
    }
    if (!observe_live_complete_origin_quiet(recorder, nginx.child, "nginx", error)) return false;
    if (!stop_child(nginx.child)) {
        error = "failed to stop nginx";
        return false;
    }
    if (!docker.remove()) {
        error = "docker rm -f failed after nginx run";
        return false;
    }
    recorder.stop();
    if (recorder.thread_alive.load(std::memory_order_acquire) ||
        recorder.listener_failed.load(std::memory_order_acquire) ||
        !complete_origin_episode_is_exact(recorder) || recorder.history.size() != 1 ||
        recorder.request != recorder.history[0]) {
        error = "nginx recorder joined with inexact completion lifecycle";
        return false;
    }
    nginx_upstream = recorder.request;

    Recorder fresh_recorder;
    fresh_recorder.observe_extra_requests_until_stop = true;
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
    bool rut_ok = rut_client >= 0;
    if (rut_ok) rut_ok = send_all(rut_client, kRequest, sizeof(kRequest) - 1);
    if (rut_ok) rut_ok = read_response(rut_client, rut_downstream, error);
    if (rut_ok) rut_ok = read_eof(rut_client, error);
    if (rut_client >= 0) close(rut_client);
    if (!rut_ok) {
        error = "RUT request/response failed: " + error;
        return false;
    }
    if (!observe_live_complete_origin_quiet(fresh_recorder, rut.child, "generated RUT", error))
        return false;
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT";
        return false;
    }
    fresh_recorder.stop();
    if (fresh_recorder.thread_alive.load(std::memory_order_acquire) ||
        fresh_recorder.listener_failed.load(std::memory_order_acquire) ||
        !complete_origin_episode_is_exact(fresh_recorder) || fresh_recorder.history.size() != 1 ||
        fresh_recorder.request != fresh_recorder.history[0]) {
        error = "RUT recorder joined with inexact completion lifecycle";
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

static bool capture_pinned_local_rejection_case(u16 frontend_port,
                                                u16 backend_port,
                                                const std::string& nginx_config_path,
                                                const std::string& nginx_log_path,
                                                const std::string& container_name,
                                                const char* case_name,
                                                const char* request,
                                                size_t request_len,
                                                const char* expected_response_normalized,
                                                std::vector<char>& downstream,
                                                std::string& error) {
    Recorder recorder;
    recorder.observe_extra_requests_until_stop = true;
    if (!recorder.setup(backend_port)) {
        error = std::string(case_name) + " backend recorder setup failed";
        return false;
    }

    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = std::string("failed to start pinned nginx for ") + case_name + " case";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    const int client = connect_once(frontend_port);
    bool ok = client >= 0;
    if (ok) ok = send_all(client, request, request_len);
    if (ok) ok = read_response(client, downstream, error);
    if (ok) ok = read_eof(client, error);
    if (client >= 0) close(client);
    if (!ok) {
        error = std::string("nginx ") + case_name + " response/EOF failed: " + error;
        return false;
    }

    std::string detail;
    if (!validate_exact_normalized_response(downstream, expected_response_normalized, detail)) {
        error = std::string(case_name) + " downstream response mismatch: " + detail;
        return false;
    }

    // Keep nginx and the recorder live after the complete response and EOF so
    // delayed upstream effects cannot be hidden by test cleanup.
    settle_for_invalid_target_side_effects();
    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    recorder.stop();
    if (!nginx_stopped) {
        error = std::string("failed to stop nginx after ") + case_name + " case";
        return false;
    }
    if (!container_removed) {
        error = std::string("docker rm -f failed after ") + case_name + " case";
        return false;
    }
    if (recorder.accepted.load(std::memory_order_acquire) != 0 ||
        recorder.requests.load(std::memory_order_acquire) != 0 || !recorder.request.empty() ||
        !recorder.history.empty()) {
        error = std::string(case_name) + " unexpectedly contacted the configured upstream";
        return false;
    }
    return true;
}

static bool capture_rut_local_rejection_case(u16 frontend_port,
                                             u16 backend_port,
                                             const std::string& source_path,
                                             const std::string& rut_log_path,
                                             const std::string& rut_path,
                                             const char* case_name,
                                             const char* request,
                                             size_t request_len,
                                             const char* expected_response_normalized,
                                             std::vector<char>& downstream,
                                             std::string& error) {
    Recorder recorder;
    recorder.observe_extra_requests_until_stop = true;
    if (!recorder.setup(backend_port)) {
        error = std::string("generated-RUT ") + case_name + " backend recorder setup failed";
        return false;
    }

    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = std::string("failed to start generated RUT for ") + case_name + " case";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) {
        error = std::string("generated-RUT ") + case_name + " readiness failed: " + error;
        return false;
    }

    const int client = connect_once(frontend_port);
    bool ok = client >= 0;
    if (ok) ok = send_all(client, request, request_len);
    if (ok) ok = read_response(client, downstream, error);
    if (ok) ok = read_eof(client, error);
    if (client >= 0) close(client);
    if (!ok) {
        error = std::string("generated-RUT ") + case_name + " response/EOF failed: " + error;
        return false;
    }

    std::string detail;
    if (!validate_exact_normalized_response(downstream, expected_response_normalized, detail)) {
        error =
            std::string("generated-RUT ") + case_name + " downstream response mismatch: " + detail;
        return false;
    }

    // Keep the generated RUT process and recorder live after the complete
    // response and EOF so delayed forwarding cannot be hidden by cleanup.
    settle_for_invalid_target_side_effects();
    const bool rut_stopped = stop_child(rut.child);
    recorder.stop();
    if (!rut_stopped) {
        error = std::string("failed to stop generated RUT after ") + case_name + " case";
        return false;
    }
    if (recorder.accepted.load(std::memory_order_acquire) != 0 ||
        recorder.requests.load(std::memory_order_acquire) != 0 || !recorder.request.empty() ||
        !recorder.history.empty()) {
        error = std::string("generated-RUT ") + case_name +
                " unexpectedly contacted the configured upstream";
        return false;
    }
    return true;
}

static bool capture_head_case(u16 frontend_port,
                              u16 backend_port,
                              const std::string& nginx_config_path,
                              const std::string& nginx_log_path,
                              const std::string& container_name,
                              std::vector<char>& downstream,
                              std::vector<char>& upstream,
                              std::string& error) {
    Recorder recorder;
    if (!recorder.setup(backend_port, 1, kHeadBackendResponse, sizeof(kHeadBackendResponse) - 1)) {
        error = "HEAD backend recorder setup failed";
        return false;
    }

    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for HEAD case";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    const int client = connect_once(frontend_port);
    bool ok = client >= 0;
    if (ok) ok = send_all(client, kHeadRequest, sizeof(kHeadRequest) - 1);
    if (ok) ok = read_head_response(client, downstream, error);
    if (ok) ok = read_eof(client, error);
    if (client >= 0) close(client);
    if (!ok) {
        error = "nginx HEAD response/EOF failed: " + error;
        return false;
    }

    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    recorder.stop();
    if (!nginx_stopped) {
        error = "failed to stop nginx after HEAD case";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after HEAD case";
        return false;
    }
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1 || recorder.history.size() != 1) {
        error = "HEAD recorder did not observe exactly one request";
        return false;
    }

    const std::string expected_request = std::string("HEAD /head?q=1 HTTP/1.1\r\n") +
                                         "Host: 127.0.0.1:" + std::to_string(backend_port) +
                                         "\r\n\r\n";
    upstream = recorder.history[0];
    const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
    if (upstream != expected_wire) {
        error = "HEAD upstream request wire mismatch";
        dump_wire("expected HEAD upstream", expected_wire);
        dump_wire("actual HEAD upstream", upstream);
        return false;
    }

    std::vector<char> normalized = downstream;
    const std::vector<char> expected_response(
        kHeadResponseNormalized, kHeadResponseNormalized + sizeof(kHeadResponseNormalized) - 1);
    if (!normalize_date(normalized) || normalized != expected_response) {
        error = "HEAD downstream response did not match the exact pinned header-only baseline";
        dump_wire("expected HEAD response", expected_response);
        dump_wire("actual HEAD response", downstream);
        return false;
    }
    return true;
}

static bool capture_head_rut_case(u16 frontend_port,
                                  u16 backend_port,
                                  const std::string& source_path,
                                  const std::string& rut_log_path,
                                  const std::string& rut_path,
                                  std::vector<char>& downstream,
                                  std::vector<char>& upstream,
                                  std::string& error) {
    Recorder recorder;
    if (!recorder.setup(backend_port, 1, kHeadBackendResponse, sizeof(kHeadBackendResponse) - 1)) {
        error = "HEAD RUT backend recorder setup failed";
        return false;
    }

    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start production RUT for HEAD case";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) return false;

    const int client = connect_once(frontend_port);
    bool ok = client >= 0;
    if (ok) ok = send_all(client, kHeadRequest, sizeof(kHeadRequest) - 1);
    if (ok) ok = read_head_response(client, downstream, error);
    if (ok) ok = read_eof(client, error);
    if (client >= 0) close(client);
    if (!ok) {
        error = "RUT HEAD response/EOF failed: " + error;
        return false;
    }
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT after HEAD case";
        return false;
    }
    recorder.stop();
    if (recorder.accepted.load(std::memory_order_acquire) != 1 ||
        recorder.requests.load(std::memory_order_acquire) != 1 || recorder.history.size() != 1) {
        error = "RUT HEAD recorder did not observe exactly one request";
        return false;
    }
    const std::string expected_request = std::string("HEAD /head?q=1 HTTP/1.1\r\n") +
                                         "Host: 127.0.0.1:" + std::to_string(backend_port) +
                                         "\r\n\r\n";
    upstream = recorder.history[0];
    const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
    if (upstream != expected_wire) {
        error = "RUT HEAD upstream request wire mismatch";
        dump_wire("expected RUT HEAD upstream", expected_wire);
        dump_wire("actual RUT HEAD upstream", upstream);
        return false;
    }
    const std::vector<char> expected_response(
        kHeadResponseNormalized, kHeadResponseNormalized + sizeof(kHeadResponseNormalized) - 1);
    std::vector<char> normalized = downstream;
    if (!normalize_date(normalized) || normalized != expected_response) {
        error = "RUT HEAD downstream response did not match the exact pinned header-only baseline";
        dump_wire("expected RUT HEAD response", expected_response);
        dump_wire("actual RUT HEAD response", downstream);
        return false;
    }
    return true;
}

static bool capture_head_gateway_case(u16 frontend_port,
                                      u16 backend_port,
                                      const std::string& nginx_config_path,
                                      const std::string& nginx_log_path,
                                      const std::string& container_name,
                                      std::vector<char>& downstream,
                                      std::string& error,
                                      DeadPort* held_dead = nullptr) {
    // Keep the unavailable endpoint reserved through nginx shutdown and log
    // inspection. This makes the connection failure deterministic and prevents
    // another process from satisfying the request between those observations.
    DeadPort local_dead;
    DeadPort& dead = held_dead != nullptr ? *held_dead : local_dead;
    if (held_dead == nullptr && !dead.reserve(backend_port)) {
        error = "failed to reserve unavailable HEAD gateway upstream port";
        return false;
    }
    if (held_dead != nullptr && dead.fd < 0 && !dead.reserve(backend_port)) {
        error = "failed to reserve unavailable HEAD gateway upstream port";
        return false;
    }

    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for HEAD gateway case";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;

    const int client = connect_once(frontend_port);
    bool ok = client >= 0;
    if (ok) ok = send_all(client, kHeadGatewayRequest, sizeof(kHeadGatewayRequest) - 1);
    if (ok) ok = read_head_response(client, downstream, error);
    if (ok) ok = read_eof(client, error);
    if (client >= 0) close(client);
    if (!ok) {
        error = "nginx HEAD gateway response/EOF failed: " + error;
        return false;
    }

    const bool nginx_stopped = stop_child(nginx.child);
    const bool container_removed = docker.remove();
    const std::string upstream_context = "127.0.0.1:" + std::to_string(backend_port);
    u32 connect_failure_record_count = 0;
    const bool log_readable = log_count_line_with(
        nginx_log_path, "connect() failed", upstream_context.c_str(), connect_failure_record_count);
    if (!nginx_stopped) {
        error = "failed to stop nginx after HEAD gateway case";
        return false;
    }
    if (!container_removed) {
        error = "docker rm -f failed after HEAD gateway case";
        return false;
    }
    if (!log_readable || connect_failure_record_count != 1) {
        error =
            "HEAD gateway log did not contain exactly one line-scoped pinned upstream connect "
            "failure";
        return false;
    }

    std::vector<char> normalized = downstream;
    const std::vector<char> expected(
        kHeadGatewayResponseNormalized,
        kHeadGatewayResponseNormalized + sizeof(kHeadGatewayResponseNormalized) - 1);
    if (!normalize_date(normalized) || normalized != expected) {
        error = "HEAD gateway response did not match the exact pinned header-only baseline";
        dump_wire("expected HEAD gateway response", expected);
        dump_wire("actual HEAD gateway response", downstream);
        return false;
    }
    return true;
}

static bool capture_head_gateway_rut_case(u16 frontend_port,
                                          u16 backend_port,
                                          const std::string& source_path,
                                          const std::string& rut_log_path,
                                          const std::string& rut_path,
                                          DeadPort& dead,
                                          std::vector<char>& downstream,
                                          std::string& error) {
    if (dead.fd < 0) {
        error = "HEAD RUT gateway dead port was not reserved";
        return false;
    }
    ChildGuard rut;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     rut.child)) {
        error = "failed to start production RUT for HEAD gateway case";
        return false;
    }
    if (!wait_ready(frontend_port, rut.child, error)) return false;
    const int client = connect_once(frontend_port);
    bool ok = client >= 0;
    if (ok) ok = send_all(client, kHeadGatewayRequest, sizeof(kHeadGatewayRequest) - 1);
    if (ok) ok = read_head_response(client, downstream, error);
    if (ok) ok = read_eof(client, error);
    if (client >= 0) close(client);
    if (!ok) {
        error = "RUT HEAD gateway response/EOF failed: " + error;
        return false;
    }
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT after HEAD gateway case";
        return false;
    }
    std::vector<char> normalized = downstream;
    const std::vector<char> expected(
        kHeadGatewayResponseNormalized,
        kHeadGatewayResponseNormalized + sizeof(kHeadGatewayResponseNormalized) - 1);
    if (!normalize_date(normalized) || normalized != expected) {
        error = "RUT HEAD gateway response did not match the exact pinned header-only baseline";
        dump_wire("expected RUT HEAD gateway response", expected);
        dump_wire("actual RUT HEAD gateway response", downstream);
        dump_log(rut_log_path, "RUT HEAD gateway log");
        return false;
    }
    (void)backend_port;
    return true;
}

static bool exercise_sequential_gateway_failures(u16 frontend_port,
                                                 Child& frontend,
                                                 const char* side,
                                                 std::vector<std::vector<char>>& responses,
                                                 std::string& error) {
    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client{connect_once(frontend_port)};
    if (client.fd < 0 ||
        !send_all(client.fd, kGatewayKeepAliveRequest1, sizeof(kGatewayKeepAliveRequest1) - 1)) {
        error = std::string(side) + " sequential gateway request 1 send failed";
        return false;
    }

    responses.clear();
    std::vector<char> first;
    std::string detail;
    if (!read_response(client.fd, first, detail)) {
        error = std::string(side) + " sequential gateway response 1 failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(first, kGatewayKeepAliveResponseNormalized, detail)) {
        error = std::string(side) + " sequential gateway response 1 mismatch: " + detail;
        return false;
    }
    responses.push_back(std::move(first));

    bool eof = false;
    if (!wait_keepalive_quiet_or_eof(client.fd, 500, eof, detail) || eof) {
        error = eof ? std::string(side) +
                          " closed the sequential gateway downstream during the quiet window"
                    : std::string(side) + " sequential gateway quiet window failed: " + detail;
        return false;
    }
    if (poll_child(frontend)) {
        error = std::string(side) + " exited during the sequential gateway quiet window";
        return false;
    }

    if (!send_all(client.fd, kGatewayCloseRequest2, sizeof(kGatewayCloseRequest2) - 1)) {
        error = std::string(side) + " sequential gateway request 2 send failed";
        return false;
    }
    std::vector<char> second;
    detail.clear();
    if (!read_response(client.fd, second, detail)) {
        error = std::string(side) + " sequential gateway response 2 failed: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kGatewayResponseNormalized, detail)) {
        error = std::string(side) + " sequential gateway response 2 mismatch: " + detail;
        return false;
    }
    if (!read_eof(client.fd, detail)) {
        error = std::string(side) + " sequential gateway response 2 EOF failed: " + detail;
        return false;
    }
    responses.push_back(std::move(second));

    if (responses.size() != 2) {
        error = std::string(side) +
                " sequential gateway did not produce exactly two complete responses";
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
                                 std::vector<std::vector<char>>& nginx_responses,
                                 std::vector<std::vector<char>>& rut_responses,
                                 std::string& error) {
    DeadPort dead;
    if (!dead.reserve(backend_port)) {
        error = "failed to reserve unavailable upstream port";
        return false;
    }

    DockerGuard docker(container_name);
    ChildGuard nginx;
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-v",
                      nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     nginx_log_path,
                     nginx.child)) {
        error = "failed to start pinned nginx for gateway case";
        return false;
    }
    if (!wait_ready(frontend_port, nginx.child, error)) return false;
    if (!exercise_sequential_gateway_failures(
            frontend_port, nginx.child, "nginx", nginx_responses, error))
        return false;
    if (!stop_child(nginx.child)) {
        error = "failed to stop nginx after gateway case";
        return false;
    }
    if (!docker.remove()) {
        error = "docker rm -f failed after nginx gateway case";
        return false;
    }
    const std::string upstream_context = "127.0.0.1:" + std::to_string(backend_port);
    u32 connect_failure_record_count = 0;
    const bool log_readable = log_count_line_with(
        nginx_log_path, "connect() failed", upstream_context.c_str(), connect_failure_record_count);
    if (!log_readable || connect_failure_record_count != 2) {
        error =
            "nginx sequential gateway log did not contain exactly two line-scoped connect "
            "failures for " +
            upstream_context + " (actual " + std::to_string(connect_failure_record_count) + ")";
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
    if (!exercise_sequential_gateway_failures(
            frontend_port, rut.child, "RUT", rut_responses, error))
        return false;
    if (!stop_child(rut.child)) {
        error = "failed to stop production RUT after gateway case";
        return false;
    }
    return true;
}

static std::string api_request(const char* target) {
    return std::string("GET ") + target +
           " HTTP/1.1\r\n"
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
        if (!spawn_child({"docker",
                          "run",
                          "--pull=never",
                          "--network",
                          "host",
                          "--name",
                          container_name,
                          "-v",
                          nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                          kNginxImage,
                          "nginx",
                          "-g",
                          "daemon off;"},
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
                        read_response(client, response, vector_error) &&
                        read_eof(client, vector_error);
        if (client >= 0) close(client);
        if (!ok) {
            error = std::string(pinned_nginx ? "nginx" : "RUT") + " API vector " +
                    std::to_string(i + 1) +
                    " failed: " + (vector_error.empty() ? "connect/send failed" : vector_error);
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

static std::string api_redirect_request(const char* target, const char* host) {
    return std::string("GET ") + target + " HTTP/1.1\r\nHost: " + host +
           "\r\nConnection: close\r\n\r\n";
}

static std::vector<char> expected_api_redirect(u16 frontend_port, const char* target_suffix) {
    const std::string response =
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Server: nginx/1.29.7\r\n"
        "Date: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 169\r\n"
        "Location: http://client.example:" +
        std::to_string(frontend_port) + "/api/" + target_suffix +
        "\r\n"
        "Connection: close\r\n"
        "\r\n" +
        kApiRedirectBody;
    return std::vector<char>(response.begin(), response.end());
}

static bool capture_api_redirect_side(u16 frontend_port,
                                      u16 backend_port,
                                      const std::string& source_path,
                                      const std::string& nginx_config_path,
                                      const std::string& nginx_log_path,
                                      const std::string& rut_log_path,
                                      const std::string& rut_path,
                                      const std::string& container_name,
                                      bool pinned_nginx,
                                      std::vector<std::vector<char>>& responses,
                                      std::string& error) {
    static constexpr const char* kTargets[] = {"/api", "/api?x=1"};
    static constexpr const char* kLocationSuffixes[] = {"", "?x=1"};
    Recorder recorder;
    if (!recorder.setup(backend_port, 1)) {
        error = "API redirect backend recorder setup failed";
        return false;
    }

    DockerGuard docker(container_name);
    docker.active = pinned_nginx;
    ChildGuard process;
    if (pinned_nginx) {
        if (!spawn_child({"docker",
                          "run",
                          "--pull=never",
                          "--network",
                          "host",
                          "--name",
                          container_name,
                          "-v",
                          nginx_config_path + ":/etc/nginx/nginx.conf:ro",
                          kNginxImage,
                          "nginx",
                          "-g",
                          "daemon off;"},
                         nginx_log_path,
                         process.child)) {
            error = "failed to start pinned nginx for API redirect case";
            return false;
        }
    } else if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                            rut_log_path,
                            process.child)) {
        error = "failed to start production RUT for API redirect case";
        return false;
    }
    if (!wait_ready(frontend_port, process.child, error)) return false;

    responses.clear();
    responses.reserve(2);
    for (size_t i = 0; i < 2; i++) {
        const std::string host =
            i == 0 ? "client.example" : "client.example:" + std::to_string(frontend_port);
        const std::string request = api_redirect_request(kTargets[i], host.c_str());
        const int client = connect_once(frontend_port);
        std::vector<char> response;
        std::string vector_error;
        bool ok = client >= 0;
        if (ok) ok = send_all(client, request.data(), request.size());
        if (ok) ok = read_response(client, response, vector_error);
        if (ok) ok = read_eof(client, vector_error);
        if (client >= 0) close(client);
        responses.push_back(std::move(response));
        if (!ok) {
            error = std::string(pinned_nginx ? "nginx" : "RUT") + " API redirect vector " +
                    std::to_string(i + 1) +
                    " failed: " + (vector_error.empty() ? "connect/send failed" : vector_error);
            return false;
        }
    }

    // Keep the process and recorder alive during the bounded late-connect window.
    settle_for_invalid_target_side_effects();
    const bool process_stopped = stop_child(process.child);
    recorder.stop();
    const bool side_effect_free = recorder.accepted.load(std::memory_order_acquire) == 0 &&
                                  recorder.requests.load(std::memory_order_acquire) == 0 &&
                                  recorder.history.empty();
    if (!side_effect_free) {
        error = std::string(pinned_nginx ? "nginx" : "RUT") +
                " API redirect phase caused an upstream side effect";
        return false;
    }
    if (!process_stopped) {
        error = std::string("failed to stop ") + (pinned_nginx ? "nginx" : "production RUT") +
                " after API redirect case";
        return false;
    }
    if (pinned_nginx && !docker.remove()) {
        error = "docker rm -f failed after nginx API redirect case";
        return false;
    }
    for (size_t i = 0; i < responses.size(); i++) {
        std::vector<char> normalized = responses[i];
        const std::vector<char> expected =
            expected_api_redirect(frontend_port, kLocationSuffixes[i]);
        if (!normalize_date(normalized) || normalized != expected) {
            error = std::string(pinned_nginx ? "nginx" : "RUT") + " API redirect vector " +
                    std::to_string(i + 1) + " did not match the exact pinned response baseline";
            return false;
        }
    }
    return true;
}

static bool capture_api_redirect_case(u16 frontend_port,
                                      u16 backend_port,
                                      const std::string& source_path,
                                      const std::string& nginx_config_path,
                                      const std::string& nginx_log_path,
                                      const std::string& rut_log_path,
                                      const std::string& rut_path,
                                      const std::string& container_name,
                                      std::vector<std::vector<char>>& nginx_responses,
                                      std::vector<std::vector<char>>& rut_responses,
                                      std::string& error) {
    if (!capture_api_redirect_side(frontend_port,
                                   backend_port,
                                   source_path,
                                   nginx_config_path,
                                   nginx_log_path,
                                   rut_log_path,
                                   rut_path,
                                   container_name,
                                   true,
                                   nginx_responses,
                                   error))
        return false;
    if (!capture_api_redirect_side(frontend_port,
                                   backend_port,
                                   source_path,
                                   nginx_config_path,
                                   nginx_log_path,
                                   rut_log_path,
                                   rut_path,
                                   container_name + "-rut",
                                   false,
                                   rut_responses,
                                   error))
        return false;
    if (nginx_responses.size() != rut_responses.size()) {
        error = "nginx and RUT API redirect vector counts differ";
        return false;
    }
    for (size_t i = 0; i < nginx_responses.size(); i++) {
        std::vector<char> normalized_nginx = nginx_responses[i];
        std::vector<char> normalized_rut = rut_responses[i];
        if (!normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
            normalized_nginx != normalized_rut) {
            error = "nginx and RUT API redirect responses differ after Date normalization";
            return false;
        }
    }
    return true;
}

static bool capture_api_invalid_case(u16 frontend_port,
                                     u16 backend_port,
                                     const std::string& source_path,
                                     const std::string& rut_log_path,
                                     const std::string& rut_path,
                                     std::vector<std::vector<char>>& responses,
                                     std::string& error) {
    static constexpr const char* kInvalidTargets[] = {"/api//x", "/api/./x", "/api/%7Euser"};
    Recorder recorder;
    if (!recorder.setup(backend_port, 1)) {
        error = "API invalid-target backend recorder setup failed";
        return false;
    }

    ChildGuard process;
    if (!spawn_child({rut_path, source_path, "--shards", "1", "--no-pin", "--drain", "0"},
                     rut_log_path,
                     process.child)) {
        error = "failed to start production RUT for API invalid-target case";
        return false;
    }
    if (!wait_ready(frontend_port, process.child, error)) return false;

    responses.clear();
    responses.reserve(3);
    for (size_t i = 0; i < sizeof(kInvalidTargets) / sizeof(kInvalidTargets[0]); i++) {
        const std::string request = api_request(kInvalidTargets[i]);
        const int client = connect_once(frontend_port);
        std::vector<char> response;
        std::string vector_error;
        bool ok = client >= 0;
        if (ok) ok = send_all(client, request.data(), request.size());
        if (ok) ok = read_response(client, response, vector_error);
        if (ok && !starts_with_400(response)) {
            vector_error = "expected complete HTTP/1.1 400 status line";
            ok = false;
        }
        if (ok) ok = read_eof(client, vector_error);
        if (client >= 0) close(client);
        responses.push_back(std::move(response));
        if (!ok) {
            error = "RUT invalid-target API vector " + std::to_string(i + 1) + " (" +
                    kInvalidTargets[i] +
                    ") failed: " + (vector_error.empty() ? "connect/send failed" : vector_error);
            return false;
        }
    }

    // Keep the RUT process and recorder alive for a fixed interval. Any delayed
    // connect is a failure, even if no complete request reaches the recorder.
    settle_for_invalid_target_side_effects();
    const bool process_stopped = stop_child(process.child);
    recorder.stop();
    const bool side_effect_free = recorder.accepted.load(std::memory_order_acquire) == 0 &&
                                  recorder.requests.load(std::memory_order_acquire) == 0 &&
                                  recorder.history.empty();
    if (!side_effect_free) {
        error = "RUT invalid-target API phase caused an upstream side effect";
        return false;
    }
    if (!process_stopped) {
        error = "failed to stop production RUT after API invalid-target case";
        return false;
    }
    return true;
}

struct DownstreamGateMapping {
    int fd = -1;
    rut_downstream_publication_gate* gate = nullptr;

    bool create(const std::string& path) {
        fd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || ftruncate(fd, sizeof(*gate)) != 0) return false;
        void* mapped = mmap(nullptr, sizeof(*gate), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapped == MAP_FAILED) return false;
        gate = static_cast<rut_downstream_publication_gate*>(mapped);
        memset(gate, 0, sizeof(*gate));
        gate->magic = RUT_DOWNSTREAM_GATE_MAGIC;
        gate->version = RUT_DOWNSTREAM_GATE_VERSION;
        gate->layout_size = sizeof(*gate);
        gate->intercepted_fd = -1;
        rut_downstream_gate_store(&gate->state, RUT_DOWNSTREAM_GATE_DISARMED);
        return msync(gate, sizeof(*gate), MS_SYNC) == 0;
    }

    ~DownstreamGateMapping() {
        if (gate != nullptr) munmap(gate, sizeof(*gate));
        if (fd >= 0) close(fd);
    }
};

struct DownstreamGateRelease {
    rut_downstream_publication_gate* gate = nullptr;

    ~DownstreamGateRelease() {
        if (gate == nullptr) return;
        const u32 state = rut_downstream_gate_load(&gate->state);
        if (state != RUT_DOWNSTREAM_GATE_RELEASED && state != RUT_DOWNSTREAM_GATE_FAILED) {
            if (rut_downstream_gate_load(&gate->error_code) == RUT_DOWNSTREAM_GATE_ERROR_NONE)
                rut_downstream_gate_store(&gate->error_code, RUT_DOWNSTREAM_GATE_ERROR_TRANSITION);
            rut_downstream_gate_store(&gate->state, RUT_DOWNSTREAM_GATE_FAILED);
        }
        rut_downstream_gate_wake(&gate->state);
    }
};

struct RutIoUringGateMapping {
    int fd = -1;
    rut_iouring_gate* gate = nullptr;
    Child* child = nullptr;

    bool create(const std::string& path) {
        fd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || ftruncate(fd, sizeof(*gate)) != 0) return false;
        void* mapped = mmap(nullptr, sizeof(*gate), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapped == MAP_FAILED) return false;
        gate = static_cast<rut_iouring_gate*>(mapped);
        memset(gate, 0, sizeof(*gate));
        pthread_mutexattr_t attributes;
        if (pthread_mutexattr_init(&attributes) != 0) return false;
        const bool mutex_initialized =
            pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED) == 0 &&
            pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST) == 0 &&
            pthread_mutex_init(&gate->identity_mutex, &attributes) == 0;
        (void)pthread_mutexattr_destroy(&attributes);
        if (!mutex_initialized) return false;
        rut_downstream_gate_store(&gate->identity_mutex_initialized, 1);
        gate->magic = RUT_IOURING_GATE_MAGIC;
        gate->version = RUT_IOURING_GATE_VERSION;
        gate->layout_size = sizeof(*gate);
        gate->ring_fd = -1;
        gate->intercepted_fd = -1;
        rut_downstream_gate_store(&gate->state, RUT_DOWNSTREAM_GATE_DISARMED);
        return msync(gate, sizeof(*gate), MS_SYNC) == 0;
    }

    ~RutIoUringGateMapping() {
        if (gate != nullptr) {
            if ((child == nullptr || child->pid < 0) &&
                rut_downstream_gate_load(&gate->identity_mutex_initialized) == 1) {
                (void)pthread_mutex_destroy(&gate->identity_mutex);
                rut_downstream_gate_store(&gate->identity_mutex_initialized, 0);
            }
            munmap(gate, sizeof(*gate));
        }
        if (fd >= 0) close(fd);
    }
};

struct RutIoUringGateProcessMapping {
    // Member declaration order is a lifetime contract: reverse destruction
    // must destroy mapping before child_guard because mapping consults the
    // still-live Child state before deciding whether its robust mutex is safe
    // to destroy.  This also keeps a failed-stop writer protected until the
    // final ChildGuard cleanup attempt.
    ChildGuard child_guard;
    RutIoUringGateMapping mapping;

    RutIoUringGateProcessMapping() { mapping.child = &child_guard.child; }
};

struct RutIoUringGateRelease {
    rut_iouring_gate* gate = nullptr;

    ~RutIoUringGateRelease() {
        if (gate == nullptr) return;
        const u32 state = rut_downstream_gate_load(&gate->state);
        if (state != RUT_DOWNSTREAM_GATE_RELEASED && state != RUT_DOWNSTREAM_GATE_FAILED) {
            u32 expected = RUT_IOURING_GATE_ERROR_NONE;
            (void)__atomic_compare_exchange_n(&gate->error_code,
                                              &expected,
                                              RUT_IOURING_GATE_ERROR_TRANSITION,
                                              false,
                                              __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
            rut_downstream_gate_store(&gate->state, RUT_DOWNSTREAM_GATE_FAILED);
        }
        rut_downstream_gate_wake(&gate->state);
    }
};

static bool wait_for_downstream_gate_hook(rut_downstream_publication_gate& gate,
                                          int timeout_ms,
                                          std::string& error) {
    const int64_t deadline = rut_downstream_gate_now_ms() + timeout_ms;
    while (rut_downstream_gate_now_ms() < deadline) {
        if (rut_downstream_gate_load(&gate.state) == RUT_DOWNSTREAM_GATE_FAILED) {
            error = "preload hook reported startup failure " +
                    std::to_string(rut_downstream_gate_load(&gate.error_code));
            return false;
        }
        if (rut_downstream_gate_load(&gate.hook_magic_ok) == 1 &&
            rut_downstream_gate_load(&gate.hook_version) == RUT_DOWNSTREAM_GATE_VERSION &&
            rut_downstream_gate_load(&gate.hook_layout_size) == sizeof(gate) &&
            rut_downstream_gate_load(&gate.target_master_pid) != 0)
            return true;
        const u32 current = rut_downstream_gate_load(&gate.state);
        timespec bounded_wait{0, 50'000'000};
        (void)syscall(SYS_futex, &gate.state, FUTEX_WAIT, current, &bounded_wait, nullptr, 0);
    }
    error = "preload hook startup handshake timeout";
    return false;
}

static bool downstream_has_no_readable_byte(int fd, std::string& error) {
    pollfd probe{fd, POLLIN | POLLHUP | POLLERR, 0};
    int ready;
    do {
        ready = poll(&probe, 1, 0);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0) {
        error = "pre-release downstream poll failed";
        return false;
    }
    char byte = 0;
    const ssize_t n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
    if (n > 0)
        error = "a downstream response byte was readable before gate release";
    else if (n == 0)
        error = "downstream reached EOF before gate release";
    else
        error = "pre-release downstream peek failed";
    return false;
}

static bool read_two_responses_and_eof(int fd,
                                       std::vector<char>& first,
                                       std::vector<char>& second,
                                       std::string& error,
                                       std::vector<char>* raw_wire = nullptr,
                                       std::vector<char>* tail = nullptr) {
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::seconds(5);
    std::vector<char> wire;
    const auto snapshot = [&]() {
        if (raw_wire != nullptr) *raw_wire = wire;
        first.clear();
        second.clear();
        const auto take_frame = [&](size_t offset, std::vector<char>& frame, size_t& next) {
            if (offset >= wire.size()) return false;
            std::vector<char> suffix(wire.begin() + static_cast<ptrdiff_t>(offset), wire.end());
            const size_t end = header_end(suffix);
            size_t body_length = 0;
            if (end == 0 || !parse_content_length(suffix, end, body_length) ||
                end + body_length > suffix.size())
                return false;
            next = offset + end + body_length;
            frame.assign(wire.begin() + static_cast<ptrdiff_t>(offset),
                         wire.begin() + static_cast<ptrdiff_t>(next));
            return true;
        };
        size_t second_offset = 0;
        size_t wire_end = 0;
        const bool first_ok = take_frame(0, first, second_offset);
        const bool second_ok = first_ok && take_frame(second_offset, second, wire_end);
        if (tail != nullptr) {
            const size_t tail_offset = second_ok ? wire_end : (first_ok ? second_offset : 0);
            tail->assign(wire.begin() + static_cast<ptrdiff_t>(tail_offset), wire.end());
        }
        return first_ok && second_ok && wire_end == wire.size();
    };
    bool eof = false;
    while (Clock::now() < deadline && !eof) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        pollfd input{fd, POLLIN | POLLHUP | POLLERR, 0};
        const int wait_ms = remaining > 100 ? 100 : static_cast<int>(remaining);
        const int ready = poll(&input, 1, wait_ms > 0 ? wait_ms : 1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            (void)snapshot();
            error = "two-response downstream poll failed";
            return false;
        }
        if (ready == 0) continue;
        char bytes[4096];
        const ssize_t n = recv(fd, bytes, sizeof(bytes), 0);
        if (n > 0) {
            wire.insert(wire.end(), bytes, bytes + n);
            continue;
        }
        if (n == 0) {
            eof = true;
            break;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        (void)snapshot();
        error = "two-response downstream recv failed";
        return false;
    }
    if (!eof) {
        (void)snapshot();
        error = "server EOF did not follow the second response";
        return false;
    }
    if (!snapshot()) {
        error = "downstream wire was not exactly two Content-Length responses";
        return false;
    }
    return true;
}

static bool run_two_response_diagnostic_self_check() {
    static constexpr char kCompleteFirst[] = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na";
    static constexpr char kTruncatedSecond[] =
        "HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\nxy";
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return false;
    const std::string wire = std::string(kCompleteFirst) + kTruncatedSecond;
    const bool sent = send_all(sockets[0], wire.data(), wire.size());
    const bool shut_down = shutdown(sockets[0], SHUT_WR) == 0;
    std::vector<char> first;
    std::vector<char> second;
    std::vector<char> raw;
    std::vector<char> tail;
    std::string error;
    const bool accepted = sent && shut_down &&
                          read_two_responses_and_eof(sockets[1], first, second, error, &raw, &tail);
    close(sockets[0]);
    close(sockets[1]);
    const std::vector<char> expected_raw(wire.begin(), wire.end());
    const std::vector<char> expected_first(kCompleteFirst,
                                           kCompleteFirst + sizeof(kCompleteFirst) - 1u);
    const std::vector<char> expected_tail(kTruncatedSecond,
                                          kTruncatedSecond + sizeof(kTruncatedSecond) - 1u);
    if (accepted || raw != expected_raw || first != expected_first || !second.empty() ||
        tail != expected_tail ||
        error != "downstream wire was not exactly two Content-Length responses") {
        std::cerr << "FAIL [two-response diagnostic self-check]: truncated second frame was not "
                     "preserved exactly\n";
        dump_wire("diagnostic self-check raw", raw);
        dump_wire("diagnostic self-check first", first);
        dump_wire("diagnostic self-check second", second);
        dump_wire("diagnostic self-check carry", tail);
        return false;
    }
    return true;
}

struct LateSuccessorObservation {
    std::vector<char> first;
    std::vector<char> second;
    std::vector<char> raw_wire;
    std::vector<char> tail;
    u32 connect_attempts = 0;
    std::string gate_evidence;
};

static void dump_late_successor_observation(const char* side,
                                            const LateSuccessorObservation& observation) {
    const std::string prefix(side);
    dump_wire((prefix + " raw wire").c_str(), observation.raw_wire);
    dump_wire((prefix + " response 1").c_str(), observation.first);
    dump_wire((prefix + " response 2").c_str(), observation.second);
    dump_wire((prefix + " tail").c_str(), observation.tail);
    std::vector<char> normalized_first = observation.first;
    std::vector<char> normalized_second = observation.second;
    if (normalize_date(normalized_first))
        dump_wire((prefix + " normalized response 1").c_str(), normalized_first);
    if (normalize_date(normalized_second))
        dump_wire((prefix + " normalized response 2").c_str(), normalized_second);
    std::cerr << prefix << " gate/journal evidence: " << observation.gate_evidence << "\n";
}

static bool run_nginx_downstream_gate_spike(u16 frontend_port,
                                            u16 backend_port,
                                            TempDir& temp,
                                            const std::string& container_name,
                                            const char* preload_path,
                                            std::string& error,
                                            DeadPort* shared_dead = nullptr,
                                            const std::string* shared_fragment = nullptr,
                                            LateSuccessorObservation* observation = nullptr) {
    if (preload_path == nullptr || preload_path[0] != '/' || access(preload_path, R_OK) != 0) {
        error = "preload helper path is not an absolute readable file";
        return false;
    }
    struct stat preload_stat{};
    if (stat(preload_path, &preload_stat) != 0 || !S_ISREG(preload_stat.st_mode)) {
        error = "preload helper is not a regular file";
        return false;
    }

    DeadPort owned_dead;
    if (shared_dead == nullptr && !owned_dead.reserve(backend_port)) {
        error = "failed to reserve the gate spike dead upstream";
        return false;
    }
    if (shared_dead != nullptr && shared_dead->fd < 0) {
        error = "shared dead upstream reservation is not live";
        return false;
    }
    const std::string local_fragment =
        "server {\n  listen " + std::to_string(frontend_port) +
        ";\n  location / {\n    proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n  }\n}\n";
    const std::string& fragment = shared_fragment == nullptr ? local_fragment : *shared_fragment;
    const std::string config = "events {}\nhttp {\n" + fragment + "}\n";
    if (!write_file(temp.nginx_config, config.data(), config.size())) {
        error = "failed to write nginx gate spike config";
        return false;
    }

    DownstreamGateMapping mapping;
    if (!mapping.create(temp.gate_control)) {
        error = "failed to create shared downstream gate control";
        return false;
    }
    Child nginx;
    bool child_settled = false;
    bool cleanup_clean = true;
    struct GateEvidenceCapture {
        rut_downstream_publication_gate* gate;
        Child* child;
        const bool* child_settled;
        const bool* cleanup_clean;
        LateSuccessorObservation* observation;
        ~GateEvidenceCapture() {
            if (observation == nullptr) return;
            if (!*child_settled || child->pid >= 0) {
                observation->gate_evidence =
                    "cleanup failure: nginx helper may still be live; shared metadata suppressed";
                return;
            }
            observation->gate_evidence =
                std::string(*cleanup_clean ? "cleanup=clean " : "cleanup=failed-but-reaped ") +
                "state=" + std::to_string(rut_downstream_gate_load(&gate->state)) +
                " error=" + std::to_string(rut_downstream_gate_load(&gate->error_code)) +
                " master=" + std::to_string(gate->target_master_pid) +
                " worker=" + std::to_string(gate->intercepted_pid) +
                " op=" + std::to_string(gate->intercepted_operation) +
                " bytes=" + std::to_string(gate->intercepted_length) +
                " r2=" + std::to_string(gate->request_two_length);
        }
    } gate_evidence_capture{mapping.gate, &nginx, &child_settled, &cleanup_clean, observation};
    DockerGuard docker(container_name);
    struct StopGuard {
        Child* child;
        bool* settled;
        bool* clean;
        std::string* error;
        bool stop() {
            if (child->pid < 0) {
                *settled = true;
                return *clean;
            }
            *clean = stop_child(*child);
            *settled = child->pid < 0;
            if (!*clean) {
                if (!error->empty()) *error += "; ";
                *error += *settled ? "bounded nginx cleanup required an abnormal reap"
                                   : "bounded nginx cleanup could not stop/reap helper; evidence "
                                     "suppressed";
            }
            return *clean;
        }
        ~StopGuard() {
            if (!*settled) (void)stop();
        }
    } stop_guard{&nginx, &child_settled, &cleanup_clean, &error};
    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client;
    DownstreamGateRelease release{mapping.gate};
    if (!spawn_child({"docker",
                      "run",
                      "--pull=never",
                      "--network",
                      "host",
                      "--name",
                      container_name,
                      "-e",
                      "LD_PRELOAD=/rut-gate/preload.so",
                      "-e",
                      "RUT_DOWNSTREAM_GATE_CONTROL=/rut-gate/control",
                      "-e",
                      "RUT_DOWNSTREAM_GATE_TARGET_EXECUTABLE=/usr/sbin/nginx",
                      "-v",
                      std::string(preload_path) + ":/rut-gate/preload.so:ro",
                      "-v",
                      temp.gate_control + ":/rut-gate/control",
                      "-v",
                      temp.nginx_config + ":/etc/nginx/nginx.conf:ro",
                      kNginxImage,
                      "nginx",
                      "-g",
                      "daemon off;"},
                     temp.nginx_log,
                     nginx)) {
        error = "failed to start pinned nginx with downstream gate preload";
        return false;
    }
    if (!wait_ready(frontend_port, nginx, error)) return false;
    if (!wait_for_downstream_gate_hook(*mapping.gate, 3000, error)) return false;
    if (rut_downstream_gate_load(&mapping.gate->state) != RUT_DOWNSTREAM_GATE_DISARMED ||
        mapping.gate->intercepted_operation != RUT_DOWNSTREAM_GATE_OP_NONE ||
        mapping.gate->intercepted_fd != -1) {
        error = "disarmed readiness traffic changed downstream gate state";
        return false;
    }

    client.fd = connect_once(frontend_port);
    if (client.fd < 0) {
        error = "failed to connect target downstream client";
        return false;
    }
    sockaddr_in local{};
    socklen_t local_length = sizeof(local);
    if (getsockname(client.fd, reinterpret_cast<sockaddr*>(&local), &local_length) != 0 ||
        local_length < sizeof(local) || local.sin_family != AF_INET) {
        error = "failed to resolve target downstream peer identity";
        return false;
    }
    mapping.gate->target_peer_ipv4_be = local.sin_addr.s_addr;
    mapping.gate->target_peer_port_be = local.sin_port;
    mapping.gate->request_two_length = sizeof(kGatewayCloseRequest2) - 1u;
    memcpy(mapping.gate->request_two, kGatewayCloseRequest2, mapping.gate->request_two_length);
    if (!rut_downstream_gate_cas(
            &mapping.gate->state, RUT_DOWNSTREAM_GATE_DISARMED, RUT_DOWNSTREAM_GATE_ARMED)) {
        error = "failed to arm downstream gate from DISARMED";
        return false;
    }
    rut_downstream_gate_wake(&mapping.gate->state);
    if (!send_all(client.fd, kGatewayKeepAliveRequest1, sizeof(kGatewayKeepAliveRequest1) - 1u)) {
        error = "failed to send request 1 to pinned nginx gate spike";
        return false;
    }
    if (!rut_downstream_gate_wait_until(mapping.gate, RUT_DOWNSTREAM_GATE_HIT, 5000)) {
        error = "downstream gate did not HIT first target 502; hook error " +
                std::to_string(rut_downstream_gate_load(&mapping.gate->error_code));
        return false;
    }
    static constexpr unsigned char kExpectedPrefix[] = "HTTP/1.1 502 ";
    const u32 target_master = rut_downstream_gate_load(&mapping.gate->target_master_pid);
    if (target_master == 0 || mapping.gate->intercepted_fd < 0 ||
        mapping.gate->intercepted_pid == 0 || mapping.gate->intercepted_pid == target_master ||
        mapping.gate->intercepted_ppid != target_master ||
        mapping.gate->intercepted_operation < RUT_DOWNSTREAM_GATE_OP_WRITE ||
        mapping.gate->intercepted_operation > RUT_DOWNSTREAM_GATE_OP_SENDMSG ||
        mapping.gate->intercepted_length < sizeof(kExpectedPrefix) - 1u ||
        mapping.gate->intercepted_prefix_length < sizeof(kExpectedPrefix) - 1u ||
        memcmp(mapping.gate->intercepted_prefix, kExpectedPrefix, sizeof(kExpectedPrefix) - 1u) !=
            0) {
        error = "downstream gate HIT metadata did not identify a worker HTTP/1.1 502 write";
        return false;
    }
    if (!downstream_has_no_readable_byte(client.fd, error)) return false;
    if (!send_all(client.fd, kGatewayCloseRequest2, sizeof(kGatewayCloseRequest2) - 1u)) {
        error = "failed to send exact request 2 while response 1 was gated";
        return false;
    }
    if (!rut_downstream_gate_cas(
            &mapping.gate->state, RUT_DOWNSTREAM_GATE_HIT, RUT_DOWNSTREAM_GATE_R2_SENT)) {
        error = "failed downstream gate HIT to R2_SENT transition";
        return false;
    }
    rut_downstream_gate_wake(&mapping.gate->state);
    if (!rut_downstream_gate_wait_until(mapping.gate, RUT_DOWNSTREAM_GATE_R2_ARRIVED, 5000)) {
        error = "hook did not prove exact request 2 arrival; hook error " +
                std::to_string(rut_downstream_gate_load(&mapping.gate->error_code));
        return false;
    }
    if (!downstream_has_no_readable_byte(client.fd, error)) return false;
    if (!rut_downstream_gate_cas(
            &mapping.gate->state, RUT_DOWNSTREAM_GATE_R2_ARRIVED, RUT_DOWNSTREAM_GATE_RELEASED)) {
        error = "failed downstream gate R2_ARRIVED to RELEASED transition";
        return false;
    }
    rut_downstream_gate_wake(&mapping.gate->state);

    std::vector<char> first;
    std::vector<char> second;
    std::vector<char> raw_wire;
    std::vector<char> tail;
    const bool read_ok =
        read_two_responses_and_eof(client.fd, first, second, error, &raw_wire, &tail);
    if (observation != nullptr) {
        observation->first = first;
        observation->second = second;
        observation->raw_wire = raw_wire;
        observation->tail = tail;
    }
    if (!read_ok) return false;
    std::string detail;
    if (!validate_exact_normalized_response(first, kGatewayKeepAliveResponseNormalized, detail)) {
        error = "gated nginx response 1 mismatch: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kGatewayResponseNormalized, detail)) {
        error = "gated nginx response 2 mismatch: " + detail;
        return false;
    }
    if (poll_child(nginx)) {
        error = "pinned nginx exited after the gated two-response exchange";
        return false;
    }
    if (rut_downstream_gate_load(&mapping.gate->error_code) != RUT_DOWNSTREAM_GATE_ERROR_NONE ||
        rut_downstream_gate_load(&mapping.gate->state) != RUT_DOWNSTREAM_GATE_RELEASED) {
        error = "downstream gate did not remain cleanly RELEASED";
        return false;
    }

    std::cerr << "gate evidence: master pid=" << target_master
              << " worker pid=" << mapping.gate->intercepted_pid
              << " worker ppid=" << mapping.gate->intercepted_ppid
              << " operation=" << mapping.gate->intercepted_operation
              << " bytes=" << mapping.gate->intercepted_length << "\n";

    close(client.fd);
    client.fd = -1;
    const bool nginx_stopped = stop_guard.stop();
    const bool container_removed = docker.remove();
    if (!nginx_stopped || !container_removed) {
        error = !nginx_stopped ? "failed to TERM/reap gated pinned nginx"
                               : "failed to remove gated pinned nginx container";
        return false;
    }
    const std::string upstream_context = "127.0.0.1:" + std::to_string(backend_port);
    u32 connect_attempts = 0;
    if (!log_count_line_with(
            temp.nginx_log, "connect() failed", upstream_context.c_str(), connect_attempts) ||
        connect_attempts != 2) {
        error = "pinned nginx log did not prove exactly two scoped dead-port connect failures";
        return false;
    }
    if (observation != nullptr) {
        observation->connect_attempts = connect_attempts;
    }
    return true;
}

static bool wait_for_rut_iouring_gate_hook(rut_iouring_gate& gate,
                                           int timeout_ms,
                                           std::string& error) {
    const int64_t deadline = rut_downstream_gate_now_ms() + timeout_ms;
    while (rut_downstream_gate_now_ms() < deadline) {
        if (rut_downstream_gate_load(&gate.state) == RUT_DOWNSTREAM_GATE_FAILED) {
            error =
                "RUT io_uring hook reported startup failure " +
                std::to_string(rut_downstream_gate_load(&gate.error_code)) +
                " with ring_ready=" + std::to_string(rut_downstream_gate_load(&gate.ring_ready));
            return false;
        }
        if (rut_downstream_gate_load(&gate.hook_magic_ok) == 1 &&
            rut_downstream_gate_load(&gate.hook_version) == RUT_IOURING_GATE_VERSION &&
            rut_downstream_gate_load(&gate.hook_layout_size) == sizeof(gate) &&
            rut_downstream_gate_load(&gate.target_pid) != 0 &&
            rut_downstream_gate_load(&gate.ring_ready) == 1 && gate.ring_fd >= 0)
            return true;
        const u32 current = rut_downstream_gate_load(&gate.state);
        timespec bounded_wait{0, 50'000'000};
        (void)syscall(SYS_futex, &gate.state, FUTEX_WAIT, current, &bounded_wait, nullptr, 0);
    }
    error = "RUT io_uring preload startup/ring handshake timeout";
    return false;
}

static bool run_rut_iouring_gate_spike(u16 frontend_port,
                                       u16 backend_port,
                                       TempDir& temp,
                                       const char* rut_path,
                                       const char* preload_path,
                                       bool expect_identity_failure,
                                       bool expect_ready_mutation_failure,
                                       bool expect_owner_death,
                                       bool expect_connect_journal_failure,
                                       std::string& error,
                                       DeadPort* shared_dead = nullptr,
                                       const std::string* shared_fragment = nullptr,
                                       LateSuccessorObservation* observation = nullptr) {
    if (rut_path == nullptr || rut_path[0] != '/' || access(rut_path, X_OK) != 0) {
        error = "RUT executable path is not absolute and executable";
        return false;
    }
    if (preload_path == nullptr || preload_path[0] != '/' || access(preload_path, R_OK) != 0) {
        error = "RUT io_uring preload path is not absolute and readable";
        return false;
    }
    struct stat preload_stat{};
    if (stat(preload_path, &preload_stat) != 0 || !S_ISREG(preload_stat.st_mode)) {
        error = "RUT io_uring preload is not a regular file";
        return false;
    }
    DeadPort owned_dead;
    if (shared_dead == nullptr && !owned_dead.reserve(backend_port)) {
        error = "failed to reserve RUT io_uring gate dead upstream";
        return false;
    }
    if (shared_dead != nullptr && shared_dead->fd < 0) {
        error = "shared RUT dead upstream reservation is not live";
        return false;
    }
    const std::string local_fragment =
        "server {\n  listen " + std::to_string(frontend_port) +
        ";\n  location / {\n    proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n  }\n}\n";
    const std::string& fragment = shared_fragment == nullptr ? local_fragment : *shared_fragment;
    auto parsed = rut::nginx::parse({fragment.data(), static_cast<rut::u32>(fragment.size())});
    if (!parsed) {
        error = "RUT io_uring gate nginx fragment parse failed";
        return false;
    }
    auto lowered = rut::nginx::lower_to_rut(parsed.value());
    if (!lowered || !write_file(temp.source, lowered.value().data, lowered.value().len)) {
        error = "RUT io_uring gate converter output failed";
        return false;
    }

    RutIoUringGateProcessMapping process_mapping;
    ChildGuard& rut_process = process_mapping.child_guard;
    RutIoUringGateMapping& mapping = process_mapping.mapping;
    if (!mapping.create(temp.rut_iouring_gate_control)) {
        error = "failed to create RUT io_uring shared gate control";
        return false;
    }
    struct GateEvidenceCapture {
        rut_iouring_gate* gate;
        Child* child;
        const bool* child_settled;
        const bool* cleanup_clean;
        LateSuccessorObservation* observation;
        ~GateEvidenceCapture() {
            if (observation == nullptr) return;
            if (!*child_settled || child->pid >= 0) {
                observation->gate_evidence =
                    "cleanup failure: helper may still be live; shared metadata suppressed";
                return;
            }
            observation->gate_evidence =
                std::string(*cleanup_clean ? "cleanup=clean " : "cleanup=failed-but-reaped ") +
                "state=" + std::to_string(rut_downstream_gate_load(&gate->state)) +
                " error=" + std::to_string(rut_downstream_gate_load(&gate->error_code)) +
                " ring=" + std::to_string(gate->ring_fd) +
                " send_fd=" + std::to_string(gate->intercepted_fd) +
                " send_bytes=" + std::to_string(gate->intercepted_length) +
                " cq_head=" + std::to_string(gate->cq_head_at_hit) +
                " cq_tail=" + std::to_string(gate->cq_tail_at_arrival) +
                " fragments=" + std::to_string(gate->witness_fragments) +
                " witness=" + std::to_string(gate->witness_length) +
                " attempts=" + std::to_string(gate->connect_attempt_count) +
                " overflow=" + std::to_string(gate->connect_journal_overflow) +
                " duplicate=" + std::to_string(gate->connect_journal_duplicate);
            for (u32 i = 0;
                 i < gate->connect_attempt_count && i < RUT_IOURING_GATE_CONNECT_JOURNAL_CAPACITY;
                 i++) {
                observation->gate_evidence +=
                    " [fd=" + std::to_string(gate->connect_attempts[i].fd) +
                    " user_data=" + std::to_string(gate->connect_attempts[i].user_data) + "]";
            }
        }
    };
    bool child_settled = false;
    bool cleanup_clean = true;
    GateEvidenceCapture gate_evidence_capture{
        mapping.gate, &rut_process.child, &child_settled, &cleanup_clean, observation};
    struct StopGuard {
        Child* child;
        bool* settled;
        bool* clean;
        std::string* error;
        void report_failure() {
            if (!error->empty()) *error += "; ";
            *error += *settled ? "bounded RUT cleanup required an abnormal reap"
                               : "bounded RUT cleanup could not stop/reap helper; evidence "
                                 "suppressed";
        }
        bool stop() {
            if (child->pid < 0) {
                *settled = true;
                return *clean;
            }
            *clean = stop_child(*child);
            *settled = child->pid < 0;
            if (!*clean) report_failure();
            return *clean;
        }
        bool settle_expected_failure() {
            *clean = settle_expected_failure_child(*child);
            *settled = child->pid < 0;
            if (!*clean) report_failure();
            return *clean;
        }
        ~StopGuard() {
            if (!*settled) (void)stop();
        }
    } stop_guard{&rut_process.child, &child_settled, &cleanup_clean, &error};
    struct ClientGuard {
        int fd = -1;
        ~ClientGuard() {
            if (fd >= 0) close(fd);
        }
    } client;
    RutIoUringGateRelease release{mapping.gate};
    const std::string preload_environment = std::string("LD_PRELOAD=") + preload_path;
    const std::string control_environment =
        "RUT_IOURING_GATE_CONTROL=" + temp.rut_iouring_gate_control;
    const std::string target_environment =
        std::string("RUT_IOURING_GATE_TARGET_EXECUTABLE=") + rut_path;
    const std::string identity_environment =
        std::string("RUT_IOURING_GATE_INJECT_DUPLICATE_SQ=") + (expect_identity_failure ? "1" : "");
    const std::string mutation_environment =
        std::string("RUT_IOURING_GATE_INJECT_READY_MASK_MUTATION=") +
        (expect_ready_mutation_failure ? "1" : "");
    const std::string owner_death_environment =
        std::string("RUT_IOURING_GATE_INJECT_OWNER_DEATH=") + (expect_owner_death ? "1" : "");
    const std::string connect_journal_environment =
        std::string("RUT_IOURING_GATE_INJECT_DUPLICATE_CONNECT_JOURNAL=") +
        (expect_connect_journal_failure ? "1" : "");
    if (!spawn_child({"env",
                      preload_environment,
                      control_environment,
                      target_environment,
                      identity_environment,
                      mutation_environment,
                      owner_death_environment,
                      connect_journal_environment,
                      rut_path,
                      temp.source,
                      "--shards",
                      "1",
                      "--no-pin",
                      "--drain",
                      "0"},
                     temp.rut_log,
                     rut_process.child)) {
        error = "failed to start generated-source RUT with io_uring gate preload";
        return false;
    }
    if (expect_owner_death) {
        if (!wait_child(rut_process.child, 3000) || !rut_process.child.status_valid ||
            !WIFEXITED(rut_process.child.status) || WEXITSTATUS(rut_process.child.status) != 86) {
            error = "owner-death helper did not exit while holding identity mutex";
            return false;
        }
        rut_process.child.pid = -1;
        if (!rut_iouring_gate_lock_identity(mapping.gate, 500)) {
            error = "controller could not recover robust identity mutex after owner death";
            return false;
        }
        rut_iouring_gate_unlock_identity(mapping.gate);
        if (rut_downstream_gate_load(&mapping.gate->state) != RUT_DOWNSTREAM_GATE_FAILED ||
            rut_downstream_gate_load(&mapping.gate->error_code) !=
                RUT_IOURING_GATE_ERROR_TRANSITION ||
            rut_downstream_gate_load(&mapping.gate->ring_ready) != 0 ||
            mapping.gate->ring_fd != -1 || mapping.gate->intercepted_fd != -1 ||
            mapping.gate->intercepted_opcode != 0 || mapping.gate->recv_user_data != 0 ||
            mapping.gate->witness_length != 0 || mapping.gate->connect_attempt_count != 0 ||
            mapping.gate->connect_journal_overflow != 0 ||
            mapping.gate->connect_journal_duplicate != 0) {
            error = "owner-death recovery left a published identity";
            return false;
        }
        return true;
    }
    if (!wait_ready(frontend_port, rut_process.child, error)) return false;
    if (expect_identity_failure || expect_ready_mutation_failure) {
        if (!rut_iouring_gate_wait_until(mapping.gate, RUT_DOWNSTREAM_GATE_FAILED, 3000)) {
            error = expect_identity_failure
                        ? "duplicate SQ mapping did not fail the RUT io_uring gate"
                        : "ready SQ mask mutation did not fail the RUT io_uring gate";
            return false;
        }
        if (!stop_guard.settle_expected_failure()) {
            error = "failed to TERM/reap RUT after identity rejection";
            return false;
        }
        if (rut_downstream_gate_load(&mapping.gate->error_code) != RUT_IOURING_GATE_ERROR_RING ||
            rut_downstream_gate_load(&mapping.gate->ring_ready) != 0 ||
            mapping.gate->ring_fd != -1 || mapping.gate->intercepted_fd != -1 ||
            mapping.gate->intercepted_opcode != 0 || mapping.gate->intercepted_length != 0 ||
            mapping.gate->intercepted_prefix_length != 0 ||
            mapping.gate->intercepted_user_data != 0 || mapping.gate->recv_user_data != 0 ||
            mapping.gate->sq_head_at_hit != 0 || mapping.gate->sq_tail_at_hit != 0 ||
            mapping.gate->cq_head_at_hit != 0 || mapping.gate->cq_tail_at_arrival != 0 ||
            mapping.gate->witness_fragments != 0 || mapping.gate->witness_length != 0 ||
            mapping.gate->connect_attempt_count != 0 ||
            mapping.gate->connect_journal_overflow != 0 ||
            mapping.gate->connect_journal_duplicate != 0) {
            error = "identity failure published metadata after process settlement";
            return false;
        }
        return true;
    }
    if (!wait_for_rut_iouring_gate_hook(*mapping.gate, 3000, error)) return false;
    if (rut_downstream_gate_load(&mapping.gate->state) != RUT_DOWNSTREAM_GATE_DISARMED ||
        mapping.gate->intercepted_opcode != 0 || mapping.gate->intercepted_fd != -1 ||
        mapping.gate->intercepted_user_data != 0 || mapping.gate->recv_user_data != 0 ||
        mapping.gate->witness_fragments != 0 || mapping.gate->witness_length != 0 ||
        mapping.gate->connect_attempt_count != 0 || mapping.gate->connect_journal_overflow != 0 ||
        mapping.gate->connect_journal_duplicate != 0) {
        error = "disarmed RUT readiness traffic armed the io_uring gate";
        return false;
    }

    client.fd = connect_once(frontend_port);
    if (client.fd < 0) {
        error = "failed to connect RUT io_uring target downstream";
        return false;
    }
    sockaddr_in local{};
    socklen_t local_length = sizeof(local);
    if (getsockname(client.fd, reinterpret_cast<sockaddr*>(&local), &local_length) != 0 ||
        local_length < sizeof(local) || local.sin_family != AF_INET) {
        error = "failed to resolve RUT target peer identity";
        return false;
    }
    mapping.gate->target_peer_ipv4_be = local.sin_addr.s_addr;
    mapping.gate->target_peer_port_be = local.sin_port;
    mapping.gate->target_upstream_ipv4_be = htonl(INADDR_LOOPBACK);
    mapping.gate->target_upstream_port_be = htons(backend_port);
    mapping.gate->request_two_length = sizeof(kGatewayCloseRequest2) - 1u;
    memcpy(mapping.gate->request_two, kGatewayCloseRequest2, mapping.gate->request_two_length);
    if (!rut_downstream_gate_cas(
            &mapping.gate->state, RUT_DOWNSTREAM_GATE_DISARMED, RUT_DOWNSTREAM_GATE_ARMED)) {
        error = "failed to arm RUT io_uring gate";
        return false;
    }
    rut_downstream_gate_wake(&mapping.gate->state);
    if (!send_all(client.fd, kGatewayKeepAliveRequest1, sizeof(kGatewayKeepAliveRequest1) - 1u)) {
        error = "failed to send RUT io_uring request 1";
        return false;
    }
    if (expect_connect_journal_failure) {
        if (!rut_iouring_gate_wait_until(mapping.gate, RUT_DOWNSTREAM_GATE_FAILED, 5000)) {
            error = "duplicate Connect journal identity did not fail the RUT gate";
            return false;
        }
        if (!downstream_has_no_readable_byte(client.fd, error)) return false;
        if (!stop_guard.settle_expected_failure()) {
            error = "failed to TERM/reap RUT after Connect journal rejection";
            return false;
        }
        if (rut_downstream_gate_load(&mapping.gate->error_code) !=
                RUT_IOURING_GATE_ERROR_CONNECT_JOURNAL ||
            mapping.gate->connect_attempt_count != 1 ||
            mapping.gate->connect_journal_overflow != 0 ||
            mapping.gate->connect_journal_duplicate != 1) {
            error = "Connect journal rejection did not preserve exact fail-closed evidence";
            return false;
        }
        return true;
    }
    if (!rut_iouring_gate_wait_until(mapping.gate, RUT_DOWNSTREAM_GATE_HIT, 5000)) {
        error = "RUT io_uring gate did not HIT; hook error " +
                std::to_string(rut_downstream_gate_load(&mapping.gate->error_code));
        return false;
    }
    static constexpr unsigned char kExpectedPrefix[] = "HTTP/1.1 502 ";
    if (mapping.gate->target_pid != static_cast<u32>(rut_process.child.pid) ||
        mapping.gate->ring_fd < 0 || mapping.gate->intercepted_fd < 0 ||
        mapping.gate->intercepted_opcode != IORING_OP_SEND ||
        mapping.gate->intercepted_length < sizeof(kExpectedPrefix) - 1u ||
        mapping.gate->intercepted_prefix_length != sizeof(kExpectedPrefix) - 1u ||
        memcmp(mapping.gate->intercepted_prefix, kExpectedPrefix, sizeof(kExpectedPrefix) - 1u) !=
            0 ||
        mapping.gate->recv_user_data == 0 ||
        (mapping.gate->recv_user_data & 0xffu) != static_cast<rut::u8>(rut::IoEventType::Recv) ||
        (mapping.gate->intercepted_user_data & 0xffu) !=
            static_cast<rut::u8>(rut::IoEventType::Send) ||
        ((mapping.gate->recv_user_data >> 8) & 0xffffffu) !=
            ((mapping.gate->intercepted_user_data >> 8) & 0xffffffu) ||
        mapping.gate->sq_tail_at_hit <= mapping.gate->sq_head_at_hit) {
        error = "RUT io_uring HIT metadata did not prove target 502 Send/Recv ownership";
        return false;
    }
    if (!downstream_has_no_readable_byte(client.fd, error)) return false;
    if (!send_all(client.fd, kGatewayCloseRequest2, sizeof(kGatewayCloseRequest2) - 1u)) {
        error = "failed to send exact RUT request 2 while enter was gated";
        return false;
    }
    if (!rut_downstream_gate_cas(
            &mapping.gate->state, RUT_DOWNSTREAM_GATE_HIT, RUT_DOWNSTREAM_GATE_R2_SENT)) {
        error = "failed RUT gate HIT to R2_SENT transition";
        return false;
    }
    rut_downstream_gate_wake(&mapping.gate->state);
    if (!rut_iouring_gate_wait_until(mapping.gate, RUT_DOWNSTREAM_GATE_R2_ARRIVED, 5000)) {
        error = "RUT hook did not prove raw-CQ request 2 arrival; hook error " +
                std::to_string(rut_downstream_gate_load(&mapping.gate->error_code));
        return false;
    }
    if (mapping.gate->witness_length != sizeof(kGatewayCloseRequest2) - 1u ||
        mapping.gate->witness_fragments == 0 ||
        mapping.gate->cq_tail_at_arrival <= mapping.gate->cq_head_at_hit) {
        error = "RUT raw-CQ witness metadata was incomplete";
        return false;
    }
    if (!downstream_has_no_readable_byte(client.fd, error)) return false;
    if (!rut_downstream_gate_cas(
            &mapping.gate->state, RUT_DOWNSTREAM_GATE_R2_ARRIVED, RUT_DOWNSTREAM_GATE_RELEASED)) {
        error = "failed RUT gate R2_ARRIVED to RELEASED transition";
        return false;
    }
    rut_downstream_gate_wake(&mapping.gate->state);

    std::vector<char> first;
    std::vector<char> second;
    std::vector<char> raw_wire;
    std::vector<char> tail;
    const bool read_ok =
        read_two_responses_and_eof(client.fd, first, second, error, &raw_wire, &tail);
    if (observation != nullptr) {
        observation->first = first;
        observation->second = second;
        observation->raw_wire = raw_wire;
        observation->tail = tail;
    }
    if (!read_ok) return false;
    std::string detail;
    if (!validate_exact_normalized_response(first, kGatewayKeepAliveResponseNormalized, detail)) {
        error = "gated RUT response 1 mismatch: " + detail;
        return false;
    }
    if (!validate_exact_normalized_response(second, kGatewayResponseNormalized, detail)) {
        error = "gated RUT response 2 mismatch: " + detail;
        return false;
    }
    if (poll_child(rut_process.child)) {
        error = "RUT exited after gated two-response exchange";
        return false;
    }
    if (rut_downstream_gate_load(&mapping.gate->error_code) != RUT_IOURING_GATE_ERROR_NONE ||
        rut_downstream_gate_load(&mapping.gate->state) != RUT_DOWNSTREAM_GATE_RELEASED) {
        error = "RUT io_uring gate did not remain cleanly RELEASED";
        return false;
    }
    if (mapping.gate->connect_attempt_count != 2 || mapping.gate->connect_journal_overflow != 0 ||
        mapping.gate->connect_journal_duplicate != 0) {
        error = "RUT production ring did not journal exactly two upstream Connect SQEs";
        return false;
    }
    const rut_iouring_gate_connect_attempt& attempt1 = mapping.gate->connect_attempts[0];
    const rut_iouring_gate_connect_attempt& attempt2 = mapping.gate->connect_attempts[1];
    const u64 episode1 = (attempt1.user_data >> 32) & 0xffffffu;
    const u64 episode2 = (attempt2.user_data >> 32) & 0xffffffu;
    if (attempt1.fd < 0 || attempt2.fd < 0 || attempt1.ipv4_be != htonl(INADDR_LOOPBACK) ||
        attempt2.ipv4_be != htonl(INADDR_LOOPBACK) || attempt1.port_be != htons(backend_port) ||
        attempt2.port_be != htons(backend_port) || attempt1.address_length != sizeof(sockaddr_in) ||
        attempt2.address_length != sizeof(sockaddr_in) ||
        (attempt1.user_data & 0xffu) != static_cast<rut::u8>(rut::IoEventType::UpstreamConnect) ||
        (attempt2.user_data & 0xffu) != static_cast<rut::u8>(rut::IoEventType::UpstreamConnect) ||
        episode1 == 0 || episode2 == 0 || episode1 == episode2) {
        error = "RUT Connect journal did not contain two unique exact target episodes";
        return false;
    }
    std::cerr << "RUT gate evidence: pid=" << mapping.gate->target_pid
              << " ring=" << mapping.gate->ring_fd << " send-fd=" << mapping.gate->intercepted_fd
              << " bytes=" << mapping.gate->intercepted_length
              << " raw-cq-fragments=" << mapping.gate->witness_fragments << "\n";

    close(client.fd);
    client.fd = -1;
    if (!stop_guard.stop()) {
        error = "failed to TERM/reap generated-source RUT after io_uring gate spike";
        return false;
    }
    if (observation != nullptr) {
        observation->connect_attempts = mapping.gate->connect_attempt_count;
    }
    return true;
}

static bool run_late_successor_differential(u16 frontend_port,
                                            u16 backend_port,
                                            TempDir& temp,
                                            const char* rut_path,
                                            const char* nginx_preload_path,
                                            const char* rut_preload_path,
                                            const std::string& container_name,
                                            LateSuccessorObservation& nginx,
                                            LateSuccessorObservation& generated_rut,
                                            std::string& fragment,
                                            std::string& error) {
    DeadPort dead;
    if (!dead.reserve(backend_port)) {
        error = "failed to hold the shared dead upstream for both differential sides";
        return false;
    }
    fragment =
        "server {\n  listen " + std::to_string(frontend_port) +
        ";\n  location / {\n    proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n  }\n}\n";

    if (!run_nginx_downstream_gate_spike(frontend_port,
                                         backend_port,
                                         temp,
                                         container_name,
                                         nginx_preload_path,
                                         error,
                                         &dead,
                                         &fragment,
                                         &nginx)) {
        error = "pinned-nginx side: " + error;
        return false;
    }
    if (!run_rut_iouring_gate_spike(frontend_port,
                                    backend_port,
                                    temp,
                                    rut_path,
                                    rut_preload_path,
                                    false,
                                    false,
                                    false,
                                    false,
                                    error,
                                    &dead,
                                    &fragment,
                                    &generated_rut)) {
        error = "converter-generated RUT side: " + error;
        return false;
    }

    std::vector<char> normalized_nginx_first = nginx.first;
    std::vector<char> normalized_nginx_second = nginx.second;
    std::vector<char> normalized_rut_first = generated_rut.first;
    std::vector<char> normalized_rut_second = generated_rut.second;
    if (!normalize_date(normalized_nginx_first) || !normalize_date(normalized_nginx_second) ||
        !normalize_date(normalized_rut_first) || !normalize_date(normalized_rut_second)) {
        error = "one composed response lacked exactly one syntactically valid Date field";
        return false;
    }
    const std::vector<char> expected_first(
        kGatewayKeepAliveResponseNormalized,
        kGatewayKeepAliveResponseNormalized + sizeof(kGatewayKeepAliveResponseNormalized) - 1u);
    const std::vector<char> expected_second(
        kGatewayResponseNormalized,
        kGatewayResponseNormalized + sizeof(kGatewayResponseNormalized) - 1u);
    if (normalized_nginx_first != expected_first || normalized_rut_first != expected_first ||
        normalized_nginx_second != expected_second || normalized_rut_second != expected_second ||
        normalized_nginx_first != normalized_rut_first ||
        normalized_nginx_second != normalized_rut_second) {
        error = "exact nginx/generated-RUT response pair differed after strict Date normalization";
        return false;
    }
    if (!nginx.tail.empty() || !generated_rut.tail.empty() || nginx.connect_attempts != 2 ||
        generated_rut.connect_attempts != 2) {
        error = "composed sides did not prove two frames, zero tail, and exactly two attempts";
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    const bool nginx_gate_spike = argc == 3 && strcmp(argv[1], "--nginx-gate-spike") == 0;
    const bool late_successor_differential =
        argc == 5 && strcmp(argv[1], "--late-successor-differential") == 0;
    const bool rut_iouring_gate_spike =
        argc == 4 && strcmp(argv[1], "--rut-iouring-gate-spike") == 0;
    const bool rut_iouring_gate_identity_negative =
        argc == 4 && strcmp(argv[1], "--rut-iouring-gate-identity-negative") == 0;
    const bool rut_iouring_gate_ready_mutation_negative =
        argc == 4 && strcmp(argv[1], "--rut-iouring-gate-ready-mutation-negative") == 0;
    const bool rut_iouring_gate_owner_death_negative =
        argc == 4 && strcmp(argv[1], "--rut-iouring-gate-owner-death-negative") == 0;
    const bool rut_iouring_gate_connect_journal_negative =
        argc == 4 && strcmp(argv[1], "--rut-iouring-gate-connect-journal-negative") == 0;
    const bool normal_differential =
        (argc == 2 && argv[1][0] == '/') ||
        (argc == 4 && argv[1][0] == '/' && argv[2][0] == '/' && argv[3][0] == '/');
    if ((!nginx_gate_spike && !rut_iouring_gate_spike && !rut_iouring_gate_identity_negative &&
         !rut_iouring_gate_ready_mutation_negative && !rut_iouring_gate_owner_death_negative &&
         !rut_iouring_gate_connect_journal_negative && !late_successor_differential &&
         !normal_differential) ||
        (nginx_gate_spike && argv[2][0] != '/') ||
        ((rut_iouring_gate_spike || rut_iouring_gate_identity_negative ||
          rut_iouring_gate_ready_mutation_negative || rut_iouring_gate_owner_death_negative ||
          rut_iouring_gate_connect_journal_negative) &&
         (argv[2][0] != '/' || argv[3][0] != '/')) ||
        (late_successor_differential &&
         (argv[2][0] != '/' || argv[3][0] != '/' || argv[4][0] != '/'))) {
        std::cerr << "usage: test_nginx_differential <absolute-rut-executable> "
                     "<absolute-nginx-preload-helper> <absolute-rut-preload-helper>\n"
                     "   or: test_nginx_differential --nginx-gate-spike "
                     "<absolute-preload-helper>\n"
                     "   or: test_nginx_differential --rut-iouring-gate-spike "
                     "<absolute-rut-executable> <absolute-preload-helper>\n"
                     "   or: test_nginx_differential --rut-iouring-gate-identity-negative "
                     "<absolute-rut-executable> <absolute-preload-helper>\n"
                     "   or: test_nginx_differential --rut-iouring-gate-ready-mutation-negative "
                     "<absolute-rut-executable> <absolute-preload-helper>\n"
                     "   or: test_nginx_differential --rut-iouring-gate-owner-death-negative "
                     "<absolute-rut-executable> <absolute-preload-helper>\n"
                     "   or: test_nginx_differential --rut-iouring-gate-connect-journal-negative "
                     "<absolute-rut-executable> <absolute-preload-helper>\n"
                     "   or: test_nginx_differential --late-successor-differential "
                     "<absolute-rut-executable> <absolute-nginx-preload-helper> "
                     "<absolute-rut-preload-helper>\n";
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
    if (!run_normalize_date_self_checks()) return 1;
    if (!run_two_response_diagnostic_self_check()) return 1;
    if (rut_iouring_gate_spike || rut_iouring_gate_identity_negative ||
        rut_iouring_gate_ready_mutation_negative || rut_iouring_gate_owner_death_negative ||
        rut_iouring_gate_connect_journal_negative) {
        u16 rut_frontend_port = 0;
        u16 rut_backend_port = 0;
        if (!allocate_port(rut_frontend_port) || !allocate_port(rut_backend_port) ||
            rut_frontend_port == rut_backend_port) {
            std::cerr << "FAIL [RUT io_uring gate preflight]: dynamic port allocation failed\n";
            return 1;
        }
        std::string gate_error;
        if (!run_rut_iouring_gate_spike(rut_frontend_port,
                                        rut_backend_port,
                                        temp,
                                        argv[2],
                                        argv[3],
                                        rut_iouring_gate_identity_negative,
                                        rut_iouring_gate_ready_mutation_negative,
                                        rut_iouring_gate_owner_death_negative,
                                        rut_iouring_gate_connect_journal_negative,
                                        gate_error)) {
            std::cerr << "FAIL [RUT io_uring gate "
                      << (rut_iouring_gate_identity_negative
                              ? "identity negative]: "
                              : (rut_iouring_gate_ready_mutation_negative
                                     ? "ready mutation negative]: "
                                     : (rut_iouring_gate_owner_death_negative
                                            ? "owner death negative]: "
                                            : (rut_iouring_gate_connect_journal_negative
                                                   ? "Connect journal negative]: "
                                                   : "spike]: "))))
                      << gate_error << "\n";
            dump_log(temp.rut_log, "RUT io_uring gate log");
            return 1;
        }
        if (rut_iouring_gate_identity_negative) {
            std::cerr << "PASS: duplicate target SQ mapping failed closed with ring_ready=0\n";
            return 0;
        }
        if (rut_iouring_gate_ready_mutation_negative) {
            std::cerr << "PASS: ready SQ mask mutation failed closed and could not revive\n";
            return 0;
        }
        if (rut_iouring_gate_owner_death_negative) {
            std::cerr << "PASS: robust identity owner death recovered without blocking\n";
            return 0;
        }
        if (rut_iouring_gate_connect_journal_negative) {
            std::cerr << "PASS: duplicate upstream Connect journal identity failed closed\n";
            return 0;
        }
        std::cerr << "PASS: converter-generated RUT gate reached "
                     "HIT/R2_SENT/R2_ARRIVED/RELEASED with no pre-release downstream byte "
                     "and emitted both exact 502 responses\n";
        return 0;
    }
    const char* suffix = strrchr(temp.path, '/');
    const std::string probe_name =
        "rut-nginx-probe-" + std::to_string(getpid()) + "-" + (suffix ? suffix + 1 : "tmp");
    if (!command_ok({"docker", "info"}, temp.preflight_log)) {
        if (log_contains(temp.preflight_log, "Cannot connect to the Docker daemon") ||
            log_contains(temp.preflight_log, "Is the docker daemon running") ||
            log_empty(temp.preflight_log) || access(temp.preflight_log.c_str(), F_OK) != 0)
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
    if (!allocate_port(frontend_port) || !allocate_port(backend_port) ||
        frontend_port == backend_port) {
        std::cerr << "FAIL [preflight]: bounded dynamic port allocation failed\n";
        return 1;
    }

    if (nginx_gate_spike) {
        const char* source_suffix = strrchr(temp.path, '/');
        source_suffix = source_suffix ? source_suffix + 1 : temp.path;
        const std::string gate_container =
            "rut-nginx-gate-" + std::to_string(getpid()) + "-" + source_suffix;
        std::string gate_error;
        if (!run_nginx_downstream_gate_spike(
                frontend_port, backend_port, temp, gate_container, argv[2], gate_error)) {
            std::cerr << "FAIL [nginx downstream gate spike]: " << gate_error << "\n";
            dump_log(temp.nginx_log, "pinned nginx gate log");
            return 1;
        }
        std::cerr << "PASS: pinned nginx gate reached HIT/R2_SENT/R2_ARRIVED/RELEASED with no "
                     "pre-release downstream byte and emitted both exact 502 responses\n";
        return 0;
    }

    if (late_successor_differential) {
        const char* source_suffix = strrchr(temp.path, '/');
        source_suffix = source_suffix ? source_suffix + 1 : temp.path;
        const std::string gate_container =
            "rut-nginx-late-" + std::to_string(getpid()) + "-" + source_suffix;
        LateSuccessorObservation nginx_observation;
        LateSuccessorObservation rut_observation;
        std::string shared_fragment;
        std::string gate_error;
        if (!run_late_successor_differential(frontend_port,
                                             backend_port,
                                             temp,
                                             argv[2],
                                             argv[3],
                                             argv[4],
                                             gate_container,
                                             nginx_observation,
                                             rut_observation,
                                             shared_fragment,
                                             gate_error)) {
            std::cerr << "FAIL [late-successor differential]: " << gate_error << "\n";
            dump_late_successor_observation("pinned nginx", nginx_observation);
            dump_late_successor_observation("generated RUT", rut_observation);
            std::cerr << "shared nginx fragment:\n" << shared_fragment;
            dump_log(temp.source, "converter-generated RUT source");
            dump_log(temp.nginx_log, "pinned nginx gate log");
            dump_log(temp.rut_log, "generated RUT gate log");
            return 1;
        }
        std::cerr << "PASS: converter-generated RUT late successor matches pinned nginx at the "
                     "causal publication boundary (two exact 502 responses, EOF, two attempts)\n";
        return 0;
    }

    std::string fragment =
        "server {\n  listen " + std::to_string(frontend_port) +
        ";\n  location / {\n    proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n  }\n}\n";
    auto parsed = rut::nginx::parse({fragment.data(), static_cast<rut::u32>(fragment.size())});
    if (!parsed) {
        std::cerr << "FAIL [parse]: nginx fragment rejected at " << parsed.error().span.line << ":"
                  << parsed.error().span.col << "\n";
        return 1;
    }
    auto lowered = rut::nginx::lower_to_rut(parsed.value());
    if (!lowered) {
        std::cerr << "FAIL [lower]: converter rejected model at " << lowered.error().span.line
                  << ":" << lowered.error().span.col << "\n";
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

    if (argc == 4) {
        LateSuccessorObservation late_nginx;
        LateSuccessorObservation late_rut;
        std::string late_fragment;
        std::string late_error;
        if (!run_late_successor_differential(frontend_port,
                                             backend_port,
                                             temp,
                                             argv[1],
                                             argv[2],
                                             argv[3],
                                             container + "-late-successor",
                                             late_nginx,
                                             late_rut,
                                             late_fragment,
                                             late_error)) {
            std::cerr << "FAIL [late-successor differential]: " << late_error << "\n";
            dump_late_successor_observation("pinned nginx late", late_nginx);
            dump_late_successor_observation("generated RUT late", late_rut);
            std::cerr << "shared nginx fragment:\n" << late_fragment;
            dump_log(temp.source, "converter-generated RUT source");
            dump_log(temp.nginx_log, "pinned nginx late gate log");
            dump_log(temp.rut_log, "generated RUT late gate log");
            return 1;
        }
        std::cerr << "PASS: monolithic converter-generated late-successor differential matched "
                     "pinned nginx with causal gates and exact attempt evidence\n";
    }

    std::vector<char> options_star_response;
    std::string options_star_error;
    if (!capture_pinned_local_rejection_case(frontend_port,
                                             backend_port,
                                             temp.nginx_config,
                                             temp.nginx_log,
                                             container + "-options-star",
                                             "OPTIONS-star",
                                             kOptionsStarRequest,
                                             sizeof(kOptionsStarRequest) - 1,
                                             kOptionsStarResponseNormalized,
                                             options_star_response,
                                             options_star_error)) {
        std::cerr << "FAIL [pinned OPTIONS-star]: " << options_star_error << "\n";
        dump_wire("pinned OPTIONS-star response", options_star_response);
        dump_log(temp.nginx_log, "pinned OPTIONS-star nginx log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx rejects explicit-close OPTIONS * before location /, "
                 "returns the exact generated 400 response and EOF, and performs no upstream "
                 "operation\n";

    std::vector<char> rut_options_star_response;
    std::string rut_options_star_error;
    if (!capture_rut_local_rejection_case(frontend_port,
                                          backend_port,
                                          temp.source,
                                          temp.rut_log,
                                          argv[1],
                                          "OPTIONS-star",
                                          kOptionsStarRequest,
                                          sizeof(kOptionsStarRequest) - 1,
                                          kOptionsStarResponseNormalized,
                                          rut_options_star_response,
                                          rut_options_star_error)) {
        std::cerr << "FAIL [generated-RUT OPTIONS-star]: " << rut_options_star_error << "\n";
        dump_wire("nginx OPTIONS-star response", options_star_response);
        dump_wire("generated-RUT OPTIONS-star response", rut_options_star_response);
        dump_log(temp.nginx_log, "nginx OPTIONS-star log");
        dump_log(temp.rut_log, "generated-RUT OPTIONS-star log");
        return 1;
    }
    std::vector<char> normalized_nginx_options_star = options_star_response;
    std::vector<char> normalized_rut_options_star = rut_options_star_response;
    const std::vector<char> expected_options_star_response(
        kOptionsStarResponseNormalized,
        kOptionsStarResponseNormalized + sizeof(kOptionsStarResponseNormalized) - 1);
    if (!normalize_date(normalized_nginx_options_star) ||
        !normalize_date(normalized_rut_options_star) ||
        normalized_nginx_options_star != expected_options_star_response ||
        normalized_rut_options_star != expected_options_star_response ||
        normalized_nginx_options_star != normalized_rut_options_star) {
        std::cerr << "FAIL [OPTIONS-star differential]: exact nginx/generated-RUT mismatch\n";
        dump_wire("expected OPTIONS-star response", expected_options_star_response);
        dump_wire("nginx OPTIONS-star response", options_star_response);
        dump_wire("generated-RUT OPTIONS-star response", rut_options_star_response);
        dump_log(temp.nginx_log, "nginx OPTIONS-star log");
        dump_log(temp.rut_log, "generated-RUT OPTIONS-star log");
        return 1;
    }
    std::cerr << "PASS: converter-generated RUT OPTIONS * matches pinned nginx exactly after "
                 "Date normalization, including EOF and zero upstream effects\n";

    std::vector<char> connect_authority_response;
    std::string connect_authority_error;
    if (!capture_pinned_local_rejection_case(frontend_port,
                                             backend_port,
                                             temp.nginx_config,
                                             temp.nginx_log,
                                             container + "-connect-authority",
                                             "CONNECT authority-form",
                                             kConnectAuthorityRequest,
                                             sizeof(kConnectAuthorityRequest) - 1,
                                             kConnectAuthorityResponseNormalized,
                                             connect_authority_response,
                                             connect_authority_error)) {
        std::cerr << "FAIL [pinned CONNECT authority-form]: " << connect_authority_error << "\n";
        dump_wire("pinned CONNECT authority-form response", connect_authority_response);
        dump_log(temp.nginx_log, "pinned CONNECT authority-form nginx log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx rejects explicit-close authority-form CONNECT with the "
                 "exact generated 405 response and EOF and performs no upstream operation\n";

    std::vector<char> rut_connect_authority_response;
    std::string rut_connect_authority_error;
    if (!capture_rut_local_rejection_case(frontend_port,
                                          backend_port,
                                          temp.source,
                                          temp.rut_log,
                                          argv[1],
                                          "CONNECT authority-form",
                                          kConnectAuthorityRequest,
                                          sizeof(kConnectAuthorityRequest) - 1,
                                          kConnectAuthorityResponseNormalized,
                                          rut_connect_authority_response,
                                          rut_connect_authority_error)) {
        std::cerr << "FAIL [generated-RUT CONNECT authority-form]: " << rut_connect_authority_error
                  << "\n";
        dump_wire("pinned CONNECT authority-form response", connect_authority_response);
        dump_wire("generated-RUT CONNECT authority-form response", rut_connect_authority_response);
        dump_log(temp.nginx_log, "nginx CONNECT authority-form log");
        dump_log(temp.rut_log, "generated-RUT CONNECT authority-form log");
        return 1;
    }
    std::vector<char> normalized_nginx_connect = connect_authority_response;
    std::vector<char> normalized_rut_connect = rut_connect_authority_response;
    const std::vector<char> expected_connect_authority_response(
        kConnectAuthorityResponseNormalized,
        kConnectAuthorityResponseNormalized + sizeof(kConnectAuthorityResponseNormalized) - 1);
    if (!normalize_date(normalized_nginx_connect) || !normalize_date(normalized_rut_connect) ||
        normalized_nginx_connect != expected_connect_authority_response ||
        normalized_rut_connect != expected_connect_authority_response ||
        normalized_nginx_connect != normalized_rut_connect) {
        std::cerr << "FAIL [CONNECT authority-form differential]: exact nginx/generated-RUT "
                     "mismatch\n";
        dump_wire("expected CONNECT authority-form response", expected_connect_authority_response);
        dump_wire("nginx CONNECT authority-form response", connect_authority_response);
        dump_wire("generated-RUT CONNECT authority-form response", rut_connect_authority_response);
        dump_log(temp.nginx_log, "nginx CONNECT authority-form log");
        dump_log(temp.rut_log, "generated-RUT CONNECT authority-form log");
        return 1;
    }
    std::cerr << "PASS: converter-generated RUT authority-form CONNECT matches pinned nginx "
                 "exactly after Date normalization, including EOF and zero upstream effects\n";

    Recorder default_buffering_timeout_origin;
    default_buffering_timeout_origin.wait_response_peer_close = true;
    default_buffering_timeout_origin.observe_extra_requests_until_stop = true;
    if (!default_buffering_timeout_origin.setup(backend_port,
                                                1,
                                                kDefaultBufferingTimeoutOrigin,
                                                sizeof(kDefaultBufferingTimeoutOrigin) - 1)) {
        std::cerr << "FAIL [pinned default buffering timeout]: origin setup failed\n";
        return 1;
    }
    const std::string default_buffering_timeout_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_buffering_timeout_config.find("proxy_buffering") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_buffering_timeout_config.data(),
                    default_buffering_timeout_config.size())) {
        std::cerr << "FAIL [pinned default buffering timeout]: semantic config write failed\n";
        return 1;
    }
    DefaultBufferingTimeoutObservation default_buffering_timeout_observation;
    std::string default_buffering_timeout_error;
    if (!capture_nginx_default_buffering_timeout(frontend_port,
                                                 temp.nginx_config,
                                                 temp.nginx_log,
                                                 container + "-default-buffering-timeout",
                                                 default_buffering_timeout_origin,
                                                 kDefaultBufferingTimeoutRequest,
                                                 sizeof(kDefaultBufferingTimeoutRequest) - 1,
                                                 kDefaultBufferingTimeoutResponseNormalized,
                                                 default_buffering_timeout_observation,
                                                 default_buffering_timeout_error)) {
        std::cerr << "FAIL [pinned default buffering timeout]: " << default_buffering_timeout_error
                  << "\n";
        dump_wire("pinned default-buffering timeout response",
                  default_buffering_timeout_observation.downstream);
        dump_log(temp.nginx_log, "pinned default-buffering timeout nginx log");
        return 1;
    }
    default_buffering_timeout_origin.stop();
    const std::string expected_default_buffering_request =
        "GET /buffered-timeout?q=1 HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(backend_port) +
        "\r\n\r\n";
    const std::vector<char> expected_default_buffering_request_wire(
        expected_default_buffering_request.begin(), expected_default_buffering_request.end());
    if (default_buffering_timeout_origin.request != expected_default_buffering_request_wire ||
        default_buffering_timeout_origin.history.size() != 1 ||
        default_buffering_timeout_origin.history[0] != expected_default_buffering_request_wire) {
        std::cerr << "FAIL [pinned default buffering timeout]: exact upstream wire mismatch\n";
        dump_wire("expected default-buffering timeout upstream request",
                  expected_default_buffering_request_wire);
        dump_wire("actual default-buffering timeout upstream request",
                  default_buffering_timeout_origin.request);
        return 1;
    }
    const u64 default_buffering_origin_sent_ns =
        default_buffering_timeout_origin.response_sent_ns.load(std::memory_order_acquire);
    const u64 default_buffering_origin_closed_ns =
        default_buffering_timeout_origin.response_peer_closed_ns.load(std::memory_order_acquire);
    const double first_byte_seconds =
        static_cast<double>(default_buffering_timeout_observation.first_downstream_byte_ns -
                            default_buffering_origin_sent_ns) /
        1e9;
    const double eof_seconds =
        static_cast<double>(default_buffering_timeout_observation.downstream_eof_ns -
                            default_buffering_origin_sent_ns) /
        1e9;
    const double origin_close_seconds =
        static_cast<double>(default_buffering_origin_closed_ns - default_buffering_origin_sent_ns) /
        1e9;
    std::cerr << "PASS: pinned nginx default response buffering drops incomplete body at "
                 "proxy_read_timeout (header/EOF/origin-close seconds="
              << first_byte_seconds << "/" << eof_seconds << "/" << origin_close_seconds
              << ", one upstream request)\n";

    Recorder default_buffering_close_timeout_origin;
    default_buffering_close_timeout_origin.wait_response_peer_close = true;
    default_buffering_close_timeout_origin.observe_extra_requests_until_stop = true;
    if (!default_buffering_close_timeout_origin.setup(backend_port,
                                                      1,
                                                      kDefaultBufferingTimeoutOrigin,
                                                      sizeof(kDefaultBufferingTimeoutOrigin) - 1)) {
        std::cerr << "FAIL [pinned default buffering explicit-close timeout]: origin setup "
                     "failed\n";
        return 1;
    }
    const std::string default_buffering_close_timeout_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_buffering_close_timeout_config.find("proxy_buffering") != std::string::npos ||
        default_buffering_close_timeout_config.find("proxy_http_version") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_buffering_close_timeout_config.data(),
                    default_buffering_close_timeout_config.size())) {
        std::cerr << "FAIL [pinned default buffering explicit-close timeout]: semantic config "
                     "write failed\n";
        return 1;
    }
    DefaultBufferingTimeoutObservation default_buffering_close_timeout_observation;
    std::string default_buffering_close_timeout_error;
    if (!capture_nginx_default_buffering_timeout(frontend_port,
                                                 temp.nginx_config,
                                                 temp.nginx_log,
                                                 container + "-default-buffering-close-timeout",
                                                 default_buffering_close_timeout_origin,
                                                 kDefaultBufferingCloseTimeoutRequest,
                                                 sizeof(kDefaultBufferingCloseTimeoutRequest) - 1,
                                                 kDefaultBufferingCloseTimeoutResponseNormalized,
                                                 default_buffering_close_timeout_observation,
                                                 default_buffering_close_timeout_error)) {
        std::cerr << "FAIL [pinned default buffering explicit-close timeout]: "
                  << default_buffering_close_timeout_error << "\n";
        dump_wire("pinned default-buffering explicit-close timeout response",
                  default_buffering_close_timeout_observation.downstream);
        dump_log(temp.nginx_log, "pinned default-buffering explicit-close timeout nginx log");
        return 1;
    }
    default_buffering_close_timeout_origin.stop();
    const std::string expected_default_buffering_close_timeout_request =
        "GET /buffered-close-timeout?case=explicit-close HTTP/1.1\r\nHost: 127.0.0.1:" +
        std::to_string(backend_port) + "\r\n\r\n";
    const std::vector<char> expected_default_buffering_close_timeout_request_wire(
        expected_default_buffering_close_timeout_request.begin(),
        expected_default_buffering_close_timeout_request.end());
    if (default_buffering_close_timeout_origin.request !=
            expected_default_buffering_close_timeout_request_wire ||
        default_buffering_close_timeout_origin.history.size() != 1 ||
        default_buffering_close_timeout_origin.history[0] !=
            expected_default_buffering_close_timeout_request_wire ||
        default_buffering_close_timeout_origin.accepted.load(std::memory_order_acquire) != 1 ||
        default_buffering_close_timeout_origin.requests.load(std::memory_order_acquire) != 1) {
        std::cerr << "FAIL [pinned default buffering explicit-close timeout]: exact upstream "
                     "wire mismatch\n";
        dump_wire("expected default-buffering explicit-close timeout upstream request",
                  expected_default_buffering_close_timeout_request_wire);
        dump_wire("actual default-buffering explicit-close timeout upstream request",
                  default_buffering_close_timeout_origin.request);
        return 1;
    }
    const u64 close_timeout_origin_sent_ns =
        default_buffering_close_timeout_origin.response_sent_ns.load(std::memory_order_acquire);
    const u64 close_timeout_origin_closed_ns =
        default_buffering_close_timeout_origin.response_peer_closed_ns.load(
            std::memory_order_acquire);
    std::cerr
        << "PASS: pinned nginx default response buffering honors one explicit downstream close "
           "after incomplete-body inactivity (header/EOF/origin-close seconds="
        << static_cast<double>(
               default_buffering_close_timeout_observation.first_downstream_byte_ns -
               close_timeout_origin_sent_ns) /
               1e9
        << "/"
        << static_cast<double>(default_buffering_close_timeout_observation.downstream_eof_ns -
                               close_timeout_origin_sent_ns) /
               1e9
        << "/"
        << static_cast<double>(close_timeout_origin_closed_ns - close_timeout_origin_sent_ns) / 1e9
        << ", one exact upstream request)\n";

    Recorder default_buffering_complete_origin;
    default_buffering_complete_origin.wait_response_peer_close = true;
    default_buffering_complete_origin.observe_extra_requests_until_stop = true;
    default_buffering_complete_origin.permit_gated_complete_response = true;
    if (!default_buffering_complete_origin.setup(backend_port)) {
        std::cerr << "FAIL [pinned default buffering complete]: origin setup failed\n";
        return 1;
    }
    const std::string default_buffering_complete_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_buffering_complete_config.find("proxy_buffering") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_buffering_complete_config.data(),
                    default_buffering_complete_config.size())) {
        std::cerr << "FAIL [pinned default buffering complete]: semantic config write failed\n";
        return 1;
    }
    DefaultBufferingCompleteObservation default_buffering_complete_observation;
    std::string default_buffering_complete_error;
    const std::vector<char> default_buffering_complete_request(
        kDefaultBufferingCompleteRequest,
        kDefaultBufferingCompleteRequest + sizeof(kDefaultBufferingCompleteRequest) - 1);
    const std::vector<char> no_request_suffix;
    if (!capture_nginx_default_buffering_complete(frontend_port,
                                                  temp.nginx_config,
                                                  temp.nginx_log,
                                                  container + "-default-buffering-complete",
                                                  default_buffering_complete_origin,
                                                  default_buffering_complete_request,
                                                  no_request_suffix,
                                                  0,
                                                  kDefaultBufferingCompleteResponseNormalized,
                                                  false,
                                                  default_buffering_complete_observation,
                                                  default_buffering_complete_error)) {
        std::cerr << "FAIL [pinned default buffering complete]: "
                  << default_buffering_complete_error << "\n";
        dump_wire("pinned default-buffering complete response",
                  default_buffering_complete_observation.downstream);
        dump_log(temp.nginx_log, "pinned default-buffering complete nginx log");
        return 1;
    }
    default_buffering_complete_origin.stop();
    const std::string expected_default_buffering_complete_request =
        "GET /buffered-complete?q=1 HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(backend_port) +
        "\r\n\r\n";
    const std::vector<char> expected_default_buffering_complete_request_wire(
        expected_default_buffering_complete_request.begin(),
        expected_default_buffering_complete_request.end());
    if (default_buffering_complete_origin.request !=
            expected_default_buffering_complete_request_wire ||
        default_buffering_complete_origin.history.size() != 1 ||
        default_buffering_complete_origin.history[0] !=
            expected_default_buffering_complete_request_wire) {
        std::cerr << "FAIL [pinned default buffering complete]: exact upstream wire mismatch\n";
        dump_wire("expected default-buffering complete upstream request",
                  expected_default_buffering_complete_request_wire);
        dump_wire("actual default-buffering complete upstream request",
                  default_buffering_complete_origin.request);
        return 1;
    }
    const u64 complete_first_origin_ns =
        default_buffering_complete_origin.response_fragment_sent_ns[0].load(
            std::memory_order_acquire);
    const u64 complete_final_origin_ns =
        default_buffering_complete_origin.response_fragment_sent_ns[3].load(
            std::memory_order_acquire);
    const u64 complete_origin_closed_ns =
        default_buffering_complete_origin.response_peer_closed_ns.load(std::memory_order_acquire);
    const u64 complete_part2_origin_ns =
        default_buffering_complete_origin.response_fragment_sent_ns[1].load(
            std::memory_order_acquire);
    const u64 complete_part3_origin_ns =
        default_buffering_complete_origin.response_fragment_sent_ns[2].load(
            std::memory_order_acquire);
    std::cerr
        << "PASS: pinned nginx default response buffering withholds fragmented complete "
           "body, then emits it atomically (origin-gaps="
        << static_cast<double>(complete_part2_origin_ns - complete_first_origin_ns) / 1e9 << "/"
        << static_cast<double>(complete_part3_origin_ns - complete_part2_origin_ns) / 1e9 << "/"
        << static_cast<double>(complete_final_origin_ns - complete_part3_origin_ns) / 1e9
        << ", origin-span/final-to-first/final-to-complete/final-to-origin-close seconds="
        << static_cast<double>(complete_final_origin_ns - complete_first_origin_ns) / 1e9 << "/"
        << static_cast<double>(default_buffering_complete_observation.first_downstream_byte_ns -
                               complete_final_origin_ns) /
               1e9
        << "/"
        << static_cast<double>(default_buffering_complete_observation.downstream_complete_ns -
                               complete_final_origin_ns) /
               1e9
        << "/" << static_cast<double>(complete_origin_closed_ns - complete_final_origin_ns) / 1e9
        << ", four origin writes, one upstream request)\n";

    Recorder default_buffering_close_complete_origin;
    default_buffering_close_complete_origin.wait_response_peer_close = true;
    default_buffering_close_complete_origin.observe_extra_requests_until_stop = true;
    default_buffering_close_complete_origin.permit_gated_complete_response = true;
    default_buffering_close_complete_origin.response_fragment_bytes[0] =
        kDefaultBufferingCloseCompleteOriginPart1;
    default_buffering_close_complete_origin.response_fragment_bytes[1] =
        kDefaultBufferingCloseCompleteOriginPart2;
    default_buffering_close_complete_origin.response_fragment_bytes[2] =
        kDefaultBufferingCloseCompleteOriginPart3;
    default_buffering_close_complete_origin.response_fragment_bytes[3] =
        kDefaultBufferingCloseCompleteOriginPart4;
    default_buffering_close_complete_origin.response_fragment_lengths[0] =
        sizeof(kDefaultBufferingCloseCompleteOriginPart1) - 1;
    default_buffering_close_complete_origin.response_fragment_lengths[1] =
        sizeof(kDefaultBufferingCloseCompleteOriginPart2) - 1;
    default_buffering_close_complete_origin.response_fragment_lengths[2] =
        sizeof(kDefaultBufferingCloseCompleteOriginPart3) - 1;
    default_buffering_close_complete_origin.response_fragment_lengths[3] =
        sizeof(kDefaultBufferingCloseCompleteOriginPart4) - 1;
    if (!default_buffering_close_complete_origin.setup(backend_port)) {
        std::cerr << "FAIL [pinned default buffering explicit close]: origin setup failed\n";
        return 1;
    }
    const std::string default_buffering_close_complete_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_buffering_close_complete_config.find("proxy_buffering") != std::string::npos ||
        default_buffering_close_complete_config.find("proxy_http_version") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_buffering_close_complete_config.data(),
                    default_buffering_close_complete_config.size())) {
        std::cerr << "FAIL [pinned default buffering explicit close]: semantic config write "
                     "failed\n";
        return 1;
    }
    DefaultBufferingCompleteObservation default_buffering_close_complete_observation;
    std::string default_buffering_close_complete_error;
    const std::vector<char> default_buffering_close_complete_request(
        kDefaultBufferingCloseCompleteRequest,
        kDefaultBufferingCloseCompleteRequest + sizeof(kDefaultBufferingCloseCompleteRequest) - 1);
    if (!capture_nginx_default_buffering_complete(frontend_port,
                                                  temp.nginx_config,
                                                  temp.nginx_log,
                                                  container + "-default-buffering-close-complete",
                                                  default_buffering_close_complete_origin,
                                                  default_buffering_close_complete_request,
                                                  no_request_suffix,
                                                  0,
                                                  kDefaultBufferingCloseCompleteResponseNormalized,
                                                  true,
                                                  default_buffering_close_complete_observation,
                                                  default_buffering_close_complete_error)) {
        std::cerr << "FAIL [pinned default buffering explicit close]: "
                  << default_buffering_close_complete_error << "\n";
        dump_wire("pinned default-buffering explicit-close response",
                  default_buffering_close_complete_observation.downstream);
        dump_log(temp.nginx_log, "pinned default-buffering explicit-close nginx log");
        return 1;
    }
    default_buffering_close_complete_origin.stop();
    const std::string expected_default_buffering_close_complete_request =
        "GET /buffered-close-complete?case=explicit-close HTTP/1.1\r\nHost: 127.0.0.1:" +
        std::to_string(backend_port) + "\r\n\r\n";
    const std::vector<char> expected_default_buffering_close_complete_request_wire(
        expected_default_buffering_close_complete_request.begin(),
        expected_default_buffering_close_complete_request.end());
    if (default_buffering_close_complete_origin.request !=
            expected_default_buffering_close_complete_request_wire ||
        default_buffering_close_complete_origin.history.size() != 1 ||
        default_buffering_close_complete_origin.history[0] !=
            expected_default_buffering_close_complete_request_wire ||
        default_buffering_close_complete_origin.accepted.load(std::memory_order_acquire) != 1 ||
        default_buffering_close_complete_origin.requests.load(std::memory_order_acquire) != 1) {
        std::cerr
            << "FAIL [pinned default buffering explicit close]: exact upstream wire mismatch\n";
        dump_wire("expected default-buffering explicit-close upstream request",
                  expected_default_buffering_close_complete_request_wire);
        dump_wire("actual default-buffering explicit-close upstream request",
                  default_buffering_close_complete_origin.request);
        return 1;
    }
    const u64 close_part1_origin_ns =
        default_buffering_close_complete_origin.response_fragment_sent_ns[0].load(
            std::memory_order_acquire);
    const u64 close_part2_origin_ns =
        default_buffering_close_complete_origin.response_fragment_sent_ns[1].load(
            std::memory_order_acquire);
    const u64 close_part3_origin_ns =
        default_buffering_close_complete_origin.response_fragment_sent_ns[2].load(
            std::memory_order_acquire);
    const u64 close_part4_origin_ns =
        default_buffering_close_complete_origin.response_fragment_sent_ns[3].load(
            std::memory_order_acquire);
    const u64 close_origin_closed_ns =
        default_buffering_close_complete_origin.response_peer_closed_ns.load(
            std::memory_order_acquire);
    std::cerr
        << "PASS: pinned nginx default response buffering honors one explicit downstream close "
           "after exact fragmented completion (origin-gaps="
        << static_cast<double>(close_part2_origin_ns - close_part1_origin_ns) / 1e9 << "/"
        << static_cast<double>(close_part3_origin_ns - close_part2_origin_ns) / 1e9 << "/"
        << static_cast<double>(close_part4_origin_ns - close_part3_origin_ns) / 1e9
        << ", origin-span/final-to-first/final-to-complete/final-to-EOF/"
           "final-to-origin-close seconds="
        << static_cast<double>(close_part4_origin_ns - close_part1_origin_ns) / 1e9 << "/"
        << static_cast<double>(
               default_buffering_close_complete_observation.first_downstream_byte_ns -
               close_part4_origin_ns) /
               1e9
        << "/"
        << static_cast<double>(default_buffering_close_complete_observation.downstream_complete_ns -
                               close_part4_origin_ns) /
               1e9
        << "/"
        << static_cast<double>(default_buffering_close_complete_observation.downstream_eof_ns -
                               close_part4_origin_ns) /
               1e9
        << "/" << static_cast<double>(close_origin_closed_ns - close_part4_origin_ns) / 1e9
        << ", four origin writes, one exact upstream request)\n";

    Recorder default_combined_buffering_post_origin;
    default_combined_buffering_post_origin.wait_response_peer_close = true;
    default_combined_buffering_post_origin.observe_extra_requests_until_stop = true;
    default_combined_buffering_post_origin.permit_gated_complete_response = true;
    default_combined_buffering_post_origin.read_exact_content_length_12_body = true;
    if (!default_combined_buffering_post_origin.setup(backend_port)) {
        std::cerr << "FAIL [pinned default combined buffering POST]: origin setup failed\n";
        return 1;
    }
    const std::string default_combined_buffering_post_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_combined_buffering_post_config.find("proxy_request_buffering") !=
            std::string::npos ||
        default_combined_buffering_post_config.find("proxy_buffering") != std::string::npos ||
        default_combined_buffering_post_config.find("proxy_http_version") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_combined_buffering_post_config.data(),
                    default_combined_buffering_post_config.size())) {
        std::cerr
            << "FAIL [pinned default combined buffering POST]: semantic config write failed\n";
        return 1;
    }
    std::vector<char> default_combined_buffering_post_prefix(
        kDefaultBufferingPostCompleteRequestHead,
        kDefaultBufferingPostCompleteRequestHead +
            sizeof(kDefaultBufferingPostCompleteRequestHead) - 1);
    default_combined_buffering_post_prefix.insert(
        default_combined_buffering_post_prefix.end(),
        reinterpret_cast<const char*>(kDefaultBufferingPostCompleteRequestBody),
        reinterpret_cast<const char*>(kDefaultBufferingPostCompleteRequestBody) +
            kDefaultBufferingPostCompleteRequestPrefixBody);
    const std::vector<char> default_combined_buffering_post_suffix(
        reinterpret_cast<const char*>(kDefaultBufferingPostCompleteRequestBody) +
            kDefaultBufferingPostCompleteRequestPrefixBody,
        reinterpret_cast<const char*>(kDefaultBufferingPostCompleteRequestBody) +
            sizeof(kDefaultBufferingPostCompleteRequestBody));
    DefaultBufferingCompleteObservation default_combined_buffering_post_observation;
    std::string default_combined_buffering_post_error;
    if (!capture_nginx_default_buffering_complete(frontend_port,
                                                  temp.nginx_config,
                                                  temp.nginx_log,
                                                  container + "-default-combined-buffering-post",
                                                  default_combined_buffering_post_origin,
                                                  default_combined_buffering_post_prefix,
                                                  default_combined_buffering_post_suffix,
                                                  1200,
                                                  kDefaultBufferingCompleteResponseNormalized,
                                                  false,
                                                  default_combined_buffering_post_observation,
                                                  default_combined_buffering_post_error)) {
        std::cerr << "FAIL [pinned default combined buffering POST]: "
                  << default_combined_buffering_post_error << "\n";
        dump_wire("pinned default combined-buffering POST response",
                  default_combined_buffering_post_observation.downstream);
        dump_log(temp.nginx_log, "pinned default combined-buffering POST nginx log");
        return 1;
    }
    default_combined_buffering_post_origin.stop();
    const std::string expected_default_combined_buffering_post_head =
        "POST /buffered-post-complete?q=1 HTTP/1.1\r\nHost: 127.0.0.1:" +
        std::to_string(backend_port) + "\r\nContent-Length: 12\r\nX-Test: binary-defaults\r\n\r\n";
    std::vector<char> expected_default_combined_buffering_post_request(
        expected_default_combined_buffering_post_head.begin(),
        expected_default_combined_buffering_post_head.end());
    expected_default_combined_buffering_post_request.insert(
        expected_default_combined_buffering_post_request.end(),
        reinterpret_cast<const char*>(kDefaultBufferingPostCompleteRequestBody),
        reinterpret_cast<const char*>(kDefaultBufferingPostCompleteRequestBody) +
            sizeof(kDefaultBufferingPostCompleteRequestBody));
    if (default_combined_buffering_post_origin.request !=
            expected_default_combined_buffering_post_request ||
        default_combined_buffering_post_origin.history.size() != 1 ||
        default_combined_buffering_post_origin.history[0] !=
            expected_default_combined_buffering_post_request ||
        default_combined_buffering_post_origin.accepted.load(std::memory_order_acquire) != 1 ||
        default_combined_buffering_post_origin.requests.load(std::memory_order_acquire) != 1) {
        std::cerr
            << "FAIL [pinned default combined buffering POST]: exact upstream wire mismatch\n";
        dump_wire("expected default combined-buffering POST upstream request",
                  expected_default_combined_buffering_post_request);
        dump_wire("actual default combined-buffering POST upstream request",
                  default_combined_buffering_post_origin.request);
        return 1;
    }
    const u64 combined_part1_origin_ns =
        default_combined_buffering_post_origin.response_fragment_sent_ns[0].load(
            std::memory_order_acquire);
    const u64 combined_part2_origin_ns =
        default_combined_buffering_post_origin.response_fragment_sent_ns[1].load(
            std::memory_order_acquire);
    const u64 combined_part3_origin_ns =
        default_combined_buffering_post_origin.response_fragment_sent_ns[2].load(
            std::memory_order_acquire);
    const u64 combined_part4_origin_ns =
        default_combined_buffering_post_origin.response_fragment_sent_ns[3].load(
            std::memory_order_acquire);
    const u64 combined_origin_closed_ns =
        default_combined_buffering_post_origin.response_peer_closed_ns.load(
            std::memory_order_acquire);
    std::cerr
        << "PASS: pinned nginx defaults buffer a fragmented positive-CL POST before origin "
           "connect and withhold its fragmented complete response (request-prefix-to-suffix="
        << static_cast<double>(default_combined_buffering_post_observation.request_suffix_sent_ns -
                               default_combined_buffering_post_observation.request_prefix_sent_ns) /
               1e9
        << ", origin-gaps="
        << static_cast<double>(combined_part2_origin_ns - combined_part1_origin_ns) / 1e9 << "/"
        << static_cast<double>(combined_part3_origin_ns - combined_part2_origin_ns) / 1e9 << "/"
        << static_cast<double>(combined_part4_origin_ns - combined_part3_origin_ns) / 1e9
        << ", origin-span/final-to-first/final-to-complete/final-to-origin-close seconds="
        << static_cast<double>(combined_part4_origin_ns - combined_part1_origin_ns) / 1e9 << "/"
        << static_cast<double>(
               default_combined_buffering_post_observation.first_downstream_byte_ns -
               combined_part4_origin_ns) /
               1e9
        << "/"
        << static_cast<double>(default_combined_buffering_post_observation.downstream_complete_ns -
                               combined_part4_origin_ns) /
               1e9
        << "/" << static_cast<double>(combined_origin_closed_ns - combined_part4_origin_ns) / 1e9
        << ", four origin writes, one exact binary upstream request)\n";

    Recorder default_buffering_eof_origin;
    default_buffering_eof_origin.gate_incomplete_response_close = true;
    default_buffering_eof_origin.observe_extra_requests_until_stop = true;
    if (!default_buffering_eof_origin.setup(backend_port,
                                            1,
                                            kDefaultBufferingTimeoutOrigin,
                                            sizeof(kDefaultBufferingTimeoutOrigin) - 1)) {
        std::cerr << "FAIL [pinned default buffering EOF]: origin setup failed\n";
        return 1;
    }
    const std::string default_buffering_eof_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_buffering_eof_config.find("proxy_buffering") != std::string::npos ||
        default_buffering_eof_config.find("proxy_http_version") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_buffering_eof_config.data(),
                    default_buffering_eof_config.size())) {
        std::cerr << "FAIL [pinned default buffering EOF]: semantic config write failed\n";
        return 1;
    }
    DefaultBufferingEofObservation default_buffering_eof_observation;
    std::string default_buffering_eof_error;
    if (!capture_nginx_default_buffering_eof(frontend_port,
                                             temp.nginx_config,
                                             temp.nginx_log,
                                             container + "-default-buffering-eof",
                                             default_buffering_eof_origin,
                                             kDefaultBufferingEofRequest,
                                             sizeof(kDefaultBufferingEofRequest) - 1,
                                             kDefaultBufferingEofResponseNormalized,
                                             default_buffering_eof_observation,
                                             default_buffering_eof_error)) {
        std::cerr << "FAIL [pinned default buffering EOF]: " << default_buffering_eof_error << "\n";
        dump_wire("pinned default-buffering EOF response",
                  default_buffering_eof_observation.downstream);
        dump_log(temp.nginx_log, "pinned default-buffering EOF nginx log");
        return 1;
    }
    default_buffering_eof_origin.stop();
    const std::string expected_default_buffering_eof_request =
        "GET /buffered-eof?q=1 HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(backend_port) +
        "\r\n\r\n";
    const std::vector<char> expected_default_buffering_eof_request_wire(
        expected_default_buffering_eof_request.begin(),
        expected_default_buffering_eof_request.end());
    if (default_buffering_eof_origin.request != expected_default_buffering_eof_request_wire ||
        default_buffering_eof_origin.history.size() != 1 ||
        default_buffering_eof_origin.history[0] != expected_default_buffering_eof_request_wire ||
        default_buffering_eof_origin.accepted.load(std::memory_order_acquire) != 1 ||
        default_buffering_eof_origin.requests.load(std::memory_order_acquire) != 1 ||
        !default_buffering_eof_origin.response_closed_by_gate.load(std::memory_order_acquire) ||
        default_buffering_eof_origin.response_close_failed.load(std::memory_order_acquire)) {
        std::cerr << "FAIL [pinned default buffering EOF]: exact upstream wire mismatch\n";
        dump_wire("expected default-buffering EOF upstream request",
                  expected_default_buffering_eof_request_wire);
        dump_wire("actual default-buffering EOF upstream request",
                  default_buffering_eof_origin.request);
        return 1;
    }
    const u64 eof_origin_sent_ns =
        default_buffering_eof_origin.response_sent_ns.load(std::memory_order_acquire);
    const u64 eof_origin_released_ns =
        default_buffering_eof_origin.response_close_released_ns.load(std::memory_order_acquire);
    std::cerr << "PASS: pinned nginx default response buffering withholds an incomplete body "
                 "until clean origin EOF, then flushes the exact prefix and closes "
                 "(send-to-release/release-to-first/release-to-EOF seconds="
              << static_cast<double>(eof_origin_released_ns - eof_origin_sent_ns) / 1e9 << "/"
              << static_cast<double>(default_buffering_eof_observation.first_downstream_byte_ns -
                                     eof_origin_released_ns) /
                     1e9
              << "/"
              << static_cast<double>(default_buffering_eof_observation.downstream_eof_ns -
                                     eof_origin_released_ns) /
                     1e9
              << ", one upstream request)\n";

    Recorder default_buffering_close_eof_origin;
    default_buffering_close_eof_origin.gate_incomplete_response_close = true;
    default_buffering_close_eof_origin.observe_extra_requests_until_stop = true;
    if (!default_buffering_close_eof_origin.setup(backend_port,
                                                  1,
                                                  kDefaultBufferingTimeoutOrigin,
                                                  sizeof(kDefaultBufferingTimeoutOrigin) - 1)) {
        std::cerr << "FAIL [pinned default buffering explicit-close EOF]: origin setup failed\n";
        return 1;
    }
    const std::string default_buffering_close_eof_config =
        "events {}\nhttp {\n  access_log off;\n  server {\n    listen 127.0.0.1:" +
        std::to_string(frontend_port) +
        ";\n    location / {\n      proxy_pass http://127.0.0.1:" + std::to_string(backend_port) +
        ";\n      proxy_read_timeout 1s;\n    }\n  }\n}\n";
    if (default_buffering_close_eof_config.find("proxy_buffering") != std::string::npos ||
        default_buffering_close_eof_config.find("proxy_http_version") != std::string::npos ||
        !write_file(temp.nginx_config,
                    default_buffering_close_eof_config.data(),
                    default_buffering_close_eof_config.size())) {
        std::cerr << "FAIL [pinned default buffering explicit-close EOF]: semantic config write "
                     "failed\n";
        return 1;
    }
    DefaultBufferingEofObservation default_buffering_close_eof_observation;
    std::string default_buffering_close_eof_error;
    if (!capture_nginx_default_buffering_eof(frontend_port,
                                             temp.nginx_config,
                                             temp.nginx_log,
                                             container + "-default-buffering-close-eof",
                                             default_buffering_close_eof_origin,
                                             kDefaultBufferingCloseEofRequest,
                                             sizeof(kDefaultBufferingCloseEofRequest) - 1,
                                             kDefaultBufferingCloseEofResponseNormalized,
                                             default_buffering_close_eof_observation,
                                             default_buffering_close_eof_error)) {
        std::cerr << "FAIL [pinned default buffering explicit-close EOF]: "
                  << default_buffering_close_eof_error << "\n";
        dump_wire("pinned default-buffering explicit-close EOF response",
                  default_buffering_close_eof_observation.downstream);
        dump_log(temp.nginx_log, "pinned default-buffering explicit-close EOF nginx log");
        return 1;
    }
    default_buffering_close_eof_origin.stop();
    const std::string expected_default_buffering_close_eof_request =
        "GET /buffered-close-eof?case=explicit-close HTTP/1.1\r\nHost: 127.0.0.1:" +
        std::to_string(backend_port) + "\r\n\r\n";
    const std::vector<char> expected_default_buffering_close_eof_request_wire(
        expected_default_buffering_close_eof_request.begin(),
        expected_default_buffering_close_eof_request.end());
    if (default_buffering_close_eof_origin.request !=
            expected_default_buffering_close_eof_request_wire ||
        default_buffering_close_eof_origin.history.size() != 1 ||
        default_buffering_close_eof_origin.history[0] !=
            expected_default_buffering_close_eof_request_wire ||
        default_buffering_close_eof_origin.accepted.load(std::memory_order_acquire) != 1 ||
        default_buffering_close_eof_origin.requests.load(std::memory_order_acquire) != 1 ||
        !default_buffering_close_eof_origin.response_closed_by_gate.load(
            std::memory_order_acquire) ||
        default_buffering_close_eof_origin.response_close_failed.load(std::memory_order_acquire)) {
        std::cerr << "FAIL [pinned default buffering explicit-close EOF]: exact upstream wire or "
                     "joined origin evidence mismatch\n";
        dump_wire("expected default-buffering explicit-close EOF upstream request",
                  expected_default_buffering_close_eof_request_wire);
        dump_wire("actual default-buffering explicit-close EOF upstream request",
                  default_buffering_close_eof_origin.request);
        return 1;
    }
    const u64 close_eof_origin_sent_ns =
        default_buffering_close_eof_origin.response_sent_ns.load(std::memory_order_acquire);
    const u64 close_eof_origin_authorized_ns =
        default_buffering_close_eof_observation.origin_close_authorized_ns;
    const u64 close_eof_origin_released_ns =
        default_buffering_close_eof_observation.origin_close_released_ns;
    std::cerr
        << "PASS: pinned nginx default response buffering honors one explicit downstream close "
           "after authorized clean origin EOF and publishes the exact incomplete prefix "
           "(send-to-authorization/authorization-to-release/release-to-first/release-to-EOF "
           "seconds="
        << static_cast<double>(close_eof_origin_authorized_ns - close_eof_origin_sent_ns) / 1e9
        << "/"
        << static_cast<double>(close_eof_origin_released_ns - close_eof_origin_authorized_ns) / 1e9
        << "/"
        << static_cast<double>(default_buffering_close_eof_observation.first_downstream_byte_ns -
                               close_eof_origin_released_ns) /
               1e9
        << "/"
        << static_cast<double>(default_buffering_close_eof_observation.downstream_eof_ns -
                               close_eof_origin_released_ns) /
               1e9
        << ", one exact upstream request)\n";

    // Restore the converter fragment's minimal nginx config for the existing
    // differential cases. The semantic baselines above are intentionally not
    // parsed, lowered, or compared to RUT.
    if (!write_file(temp.nginx_config, nginx_config.data(), nginx_config.size())) {
        std::cerr << "FAIL [nginx-config]: config restore after semantic baseline failed\n";
        return 1;
    }
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
    std::string nginx_success_detail;
    std::string rut_success_detail;
    if (!validate_exact_normalized_response(
            nginx_response, kSuccessResponseNormalized, nginx_success_detail) ||
        !validate_exact_normalized_response(
            rut_response, kSuccessResponseNormalized, rut_success_detail) ||
        !normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
        normalized_nginx != normalized_rut) {
        std::cerr << "FAIL [compare]: exact downstream response mismatch after strict Date "
                     "normalization"
                  << (nginx_success_detail.empty() ? "" : ": nginx " + nginx_success_detail)
                  << (rut_success_detail.empty() ? "" : ": RUT " + rut_success_detail) << "\n";
        dump_wire("nginx response", nginx_response);
        dump_wire("RUT response", rut_response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    const std::string request(nginx_request.begin(), nginx_request.end());
    if (nginx_request.empty() || nginx_request != rut_request ||
        request.find("GET /encoded/%7Euser?tag=unreserved HTTP/1.1\r\n") == std::string::npos) {
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
    std::cerr << "PASS: converter-generated RUT matches pinned nginx for the bounded sequential "
                 "explicit-close completion vector (one complete fixed-CL origin send, immediate "
                 "clean origin EOF, exact normalized response/downstream EOF, no retry); this "
                 "does not claim pipelined successors or broader client/config behavior\n";
    std::vector<std::vector<char>> nginx_gateway_responses;
    std::vector<std::vector<char>> rut_gateway_responses;
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
                              nginx_gateway_responses,
                              rut_gateway_responses,
                              gateway_error)) {
        std::cerr << "FAIL [gateway differential]: " << gateway_error << "\n";
        for (const auto& response : nginx_gateway_responses)
            dump_wire("nginx sequential gateway response", response);
        for (const auto& response : rut_gateway_responses)
            dump_wire("RUT sequential gateway response", response);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    if (nginx_gateway_responses.size() != 2 || rut_gateway_responses.size() != 2) {
        std::cerr << "FAIL [gateway compare]: expected exactly two complete responses per side\n";
        return 1;
    }
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized_nginx_gateway = nginx_gateway_responses[i];
        std::vector<char> normalized_rut_gateway = rut_gateway_responses[i];
        if (!normalize_date(normalized_nginx_gateway) || !normalize_date(normalized_rut_gateway) ||
            normalized_nginx_gateway != normalized_rut_gateway) {
            std::cerr << "FAIL [gateway compare]: response " << (i + 1)
                      << " differs after strict Date normalization\n";
            dump_wire("nginx sequential gateway response", nginx_gateway_responses[i]);
            dump_wire("RUT sequential gateway response", rut_gateway_responses[i]);
            dump_log(temp.nginx_log, "nginx log");
            dump_log(temp.rut_log, "RUT log");
            return 1;
        }
    }
    std::cerr << "PASS: converter-generated RUT matches pinned nginx for bounded sequential GET "
                 "unavailable-upstream 502 -> 502 on one downstream (response 1 keep-alive + live "
                 "quiet window, response 2 close + real EOF, exactly two scoped nginx connect "
                 "failures); this excludes pipelining/#276 and broader client/config behavior\n";

    std::vector<char> nginx_head_response;
    std::vector<char> nginx_head_request;
    std::string head_error;
    const std::string head_container = container + "-head";
    if (!capture_head_case(frontend_port,
                           backend_port,
                           temp.nginx_config,
                           temp.nginx_log,
                           head_container,
                           nginx_head_response,
                           nginx_head_request,
                           head_error)) {
        std::cerr << "FAIL [HEAD baseline]: " << head_error << "\n";
        dump_wire("nginx HEAD response", nginx_head_response);
        dump_wire("nginx HEAD request", nginx_head_request);
        dump_log(temp.nginx_log, "nginx log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx HEAD proxy response baseline (header-only downstream, "
                 "one upstream request)\n";

    std::vector<char> nginx_head_gateway_response;
    std::string head_gateway_error;
    const std::string head_gateway_container = container + "-head-gateway";
    if (!capture_head_gateway_case(frontend_port,
                                   backend_port,
                                   temp.nginx_config,
                                   temp.nginx_log,
                                   head_gateway_container,
                                   nginx_head_gateway_response,
                                   head_gateway_error)) {
        std::cerr << "FAIL [HEAD gateway baseline]: " << head_gateway_error << "\n";
        dump_wire("nginx HEAD gateway response", nginx_head_gateway_response);
        dump_log(temp.nginx_log, "nginx HEAD gateway log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx HEAD unavailable-upstream gateway baseline "
                 "(header-only 502 + EOF)\n";

    KeepAlivePinnedRecorder keepalive_recorder;
    if (!keepalive_recorder.setup(backend_port)) {
        std::cerr << "FAIL [pinned HEAD keep-alive]: backend recorder setup failed\n";
        return 1;
    }
    std::vector<std::vector<char>> keepalive_responses;
    std::string keepalive_error;
    const std::string keepalive_container = container + "-head-keepalive";
    if (!capture_nginx_head_keepalive_success(frontend_port,
                                              temp.nginx_config,
                                              temp.nginx_log,
                                              keepalive_container,
                                              keepalive_recorder,
                                              keepalive_responses,
                                              keepalive_error)) {
        std::cerr << "FAIL [pinned HEAD keep-alive]: " << keepalive_error << "\n";
        for (const auto& response : keepalive_responses)
            dump_wire("pinned HEAD downstream", response);
        keepalive_recorder.stop();
        dump_pinned_history(keepalive_recorder);
        dump_log(temp.nginx_log, "pinned nginx keep-alive log");
        return 1;
    }
    keepalive_recorder.stop();
    if (keepalive_responses.size() != 2 || keepalive_recorder.history.size() != 2 ||
        keepalive_recorder.accepted.load(std::memory_order_acquire) != 2 ||
        keepalive_recorder.requests.load(std::memory_order_acquire) != 2 ||
        keepalive_recorder.history[0].connection_id != 1 ||
        keepalive_recorder.history[1].connection_id != 2 ||
        keepalive_recorder.history[0].connection_id ==
            keepalive_recorder.history[1].connection_id) {
        std::cerr
            << "FAIL [pinned HEAD keep-alive]: exact upstream count/connection mapping failed\n";
        for (const auto& response : keepalive_responses)
            dump_wire("pinned HEAD downstream", response);
        dump_pinned_history(keepalive_recorder);
        return 1;
    }
    const char* const expected_keepalive_responses[] = {
        kHeadKeepAliveResponseNormalized,
        kHeadResponseNormalized,
    };
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized = keepalive_responses[i];
        const size_t expected_len = strlen(expected_keepalive_responses[i]);
        if (!normalize_date(normalized) || normalized.size() != expected_len ||
            memcmp(normalized.data(), expected_keepalive_responses[i], expected_len) != 0) {
            std::cerr << "FAIL [pinned HEAD keep-alive]: exact response " << (i + 1)
                      << " mismatch\n";
            dump_wire("expected pinned HEAD response",
                      std::vector<char>(expected_keepalive_responses[i],
                                        expected_keepalive_responses[i] + expected_len));
            dump_wire("actual pinned HEAD response", keepalive_responses[i]);
            dump_pinned_history(keepalive_recorder);
            return 1;
        }
        const std::string expected_request =
            std::string(i == 0 ? "HEAD /head?q=1 HTTP/1.1\r\n" : "HEAD /head?q=2 HTTP/1.1\r\n") +
            "Host: 127.0.0.1:" + std::to_string(backend_port) + "\r\n\r\n";
        const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
        if (keepalive_recorder.history[i].wire != expected_wire) {
            std::cerr << "FAIL [pinned HEAD keep-alive]: exact upstream request " << (i + 1)
                      << " mismatch\n";
            dump_wire("expected pinned upstream request", expected_wire);
            dump_wire("actual pinned upstream request", keepalive_recorder.history[i].wire);
            dump_pinned_history(keepalive_recorder);
            return 1;
        }
    }
    for (const auto& response : keepalive_responses) dump_wire("pinned HEAD downstream", response);
    dump_pinned_history(keepalive_recorder, "nginx reusable HEAD success");
    std::cerr << "PASS: pinned nginx HEAD keep-alive success baseline (two upstream connections)\n";

    KeepAlivePinnedRecorder rut_keepalive_recorder;
    if (!rut_keepalive_recorder.setup(backend_port)) {
        std::cerr << "FAIL [reusable HEAD success RUT]: backend recorder setup failed\n";
        return 1;
    }
    std::vector<std::vector<char>> rut_keepalive_responses;
    std::string rut_keepalive_error;
    if (!capture_rut_head_keepalive_success(frontend_port,
                                            temp.source,
                                            temp.rut_log,
                                            argv[1],
                                            rut_keepalive_recorder,
                                            rut_keepalive_responses,
                                            rut_keepalive_error)) {
        std::cerr << "FAIL [reusable HEAD success RUT]: " << rut_keepalive_error << "\n";
        for (size_t i = 0; i < rut_keepalive_responses.size(); i++) {
            const std::string label = "RUT reusable HEAD success response " + std::to_string(i + 1);
            dump_wire(label.c_str(), rut_keepalive_responses[i]);
        }
        rut_keepalive_recorder.stop();
        dump_pinned_history(rut_keepalive_recorder, "RUT reusable HEAD success");
        dump_log(temp.rut_log, "RUT reusable HEAD success log");
        return 1;
    }
    rut_keepalive_recorder.stop();
    if (rut_keepalive_responses.size() != 2 || rut_keepalive_recorder.history.size() != 2 ||
        rut_keepalive_recorder.accepted.load(std::memory_order_acquire) != 2 ||
        rut_keepalive_recorder.requests.load(std::memory_order_acquire) != 2 ||
        rut_keepalive_recorder.history[0].connection_id != 1 ||
        rut_keepalive_recorder.history[1].connection_id != 2 ||
        rut_keepalive_recorder.history[0].connection_id ==
            rut_keepalive_recorder.history[1].connection_id) {
        std::cerr << "FAIL [reusable HEAD success RUT]: exact fresh upstream count/connection "
                     "mapping failed\n";
        dump_pinned_history(keepalive_recorder, "nginx reusable HEAD success");
        dump_pinned_history(rut_keepalive_recorder, "RUT reusable HEAD success");
        return 1;
    }
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized_nginx = keepalive_responses[i];
        std::vector<char> normalized_rut = rut_keepalive_responses[i];
        const char* expected_response = expected_keepalive_responses[i];
        const size_t expected_len = strlen(expected_response);
        const std::string expected_request =
            std::string(i == 0 ? "HEAD /head?q=1 HTTP/1.1\r\n" : "HEAD /head?q=2 HTTP/1.1\r\n") +
            "Host: 127.0.0.1:" + std::to_string(backend_port) + "\r\n\r\n";
        const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
        if (!normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
            normalized_nginx != normalized_rut || normalized_rut.size() != expected_len ||
            memcmp(normalized_rut.data(), expected_response, expected_len) != 0 ||
            keepalive_recorder.history[i].wire != expected_wire ||
            rut_keepalive_recorder.history[i].wire != expected_wire ||
            keepalive_recorder.history[i].wire != rut_keepalive_recorder.history[i].wire) {
            std::cerr << "FAIL [reusable HEAD success differential]: request " << (i + 1)
                      << " nginx/RUT wire mismatch\n";
            dump_wire("expected reusable HEAD response",
                      std::vector<char>(expected_response, expected_response + expected_len));
            dump_wire("nginx reusable HEAD response", keepalive_responses[i]);
            dump_wire("RUT reusable HEAD response", rut_keepalive_responses[i]);
            dump_wire("expected reusable HEAD upstream request", expected_wire);
            dump_wire("nginx reusable HEAD upstream request", keepalive_recorder.history[i].wire);
            dump_wire("RUT reusable HEAD upstream request", rut_keepalive_recorder.history[i].wire);
            dump_pinned_history(keepalive_recorder, "nginx reusable HEAD success");
            dump_pinned_history(rut_keepalive_recorder, "RUT reusable HEAD success");
            dump_log(temp.nginx_log, "nginx reusable HEAD success log");
            dump_log(temp.rut_log, "RUT reusable HEAD success log");
            return 1;
        }
    }
    std::cerr << "PASS: converter-generated RUT reusable HEAD success matches pinned nginx "
                 "(two downstream responses, two fresh upstream connections)\n";

    KeepAlivePinnedRecorder nginx_malformed_recorder(
        KeepAlivePinnedRecorder::FirstResponseMode::InvalidHeaderWaitPeerClose);
    if (!nginx_malformed_recorder.setup(backend_port)) {
        std::cerr << "FAIL [pinned malformed HEAD]: backend recorder setup failed\n";
        return 1;
    }
    std::vector<std::vector<char>> nginx_malformed_responses;
    std::string nginx_malformed_error;
    if (!capture_nginx_head_malformed_reuse(frontend_port,
                                            temp.nginx_config,
                                            temp.nginx_log,
                                            container + "-head-malformed",
                                            nginx_malformed_recorder,
                                            nginx_malformed_responses,
                                            nginx_malformed_error)) {
        std::cerr << "FAIL [pinned malformed HEAD]: " << nginx_malformed_error << "\n";
        for (const auto& response : nginx_malformed_responses)
            dump_wire("pinned malformed HEAD downstream", response);
        nginx_malformed_recorder.stop();
        dump_pinned_history(nginx_malformed_recorder, "nginx malformed HEAD");
        dump_log(temp.nginx_log, "pinned nginx malformed HEAD log");
        return 1;
    }
    nginx_malformed_recorder.stop();

    KeepAlivePinnedRecorder rut_malformed_recorder(
        KeepAlivePinnedRecorder::FirstResponseMode::InvalidHeaderWaitPeerClose);
    if (!rut_malformed_recorder.setup(backend_port)) {
        std::cerr << "FAIL [generated-RUT malformed HEAD]: backend recorder setup failed\n";
        return 1;
    }
    std::vector<std::vector<char>> rut_malformed_responses;
    std::string rut_malformed_error;
    if (!capture_rut_head_malformed_reuse(frontend_port,
                                          temp.source,
                                          temp.rut_log,
                                          argv[1],
                                          rut_malformed_recorder,
                                          rut_malformed_responses,
                                          rut_malformed_error)) {
        std::cerr << "FAIL [generated-RUT malformed HEAD]: " << rut_malformed_error << "\n";
        for (const auto& response : rut_malformed_responses)
            dump_wire("generated-RUT malformed HEAD downstream", response);
        rut_malformed_recorder.stop();
        dump_pinned_history(rut_malformed_recorder, "RUT malformed HEAD");
        dump_log(temp.rut_log, "generated-RUT malformed HEAD log");
        return 1;
    }
    rut_malformed_recorder.stop();

    const auto malformed_recorder_is_exact = [](const KeepAlivePinnedRecorder& recorder) {
        return recorder.accepted.load(std::memory_order_acquire) == 2 &&
               recorder.requests.load(std::memory_order_acquire) == 2 &&
               recorder.history.size() == 2 && recorder.history[0].connection_id == 1 &&
               recorder.history[1].connection_id == 2 &&
               recorder.history[0].connection_id != recorder.history[1].connection_id &&
               recorder.first_malformed_sent_open.load(std::memory_order_acquire) &&
               !recorder.first_malformed_send_failed.load(std::memory_order_acquire) &&
               recorder.first_peer_closed.load(std::memory_order_acquire) &&
               !recorder.first_peer_unexpected_data.load(std::memory_order_acquire) &&
               !recorder.first_peer_observation_failed.load(std::memory_order_acquire);
    };
    if (nginx_malformed_responses.size() != 2 || rut_malformed_responses.size() != 2 ||
        !malformed_recorder_is_exact(nginx_malformed_recorder) ||
        !malformed_recorder_is_exact(rut_malformed_recorder)) {
        std::cerr << "FAIL [malformed HEAD differential]: exact response/origin cardinality "
                     "or close evidence failed\n";
        dump_pinned_history(nginx_malformed_recorder, "nginx malformed HEAD");
        dump_pinned_history(rut_malformed_recorder, "RUT malformed HEAD");
        dump_log(temp.nginx_log, "pinned nginx malformed HEAD log");
        dump_log(temp.rut_log, "generated-RUT malformed HEAD log");
        return 1;
    }

    const char* const expected_malformed_responses[] = {
        kHeadGatewayKeepAliveResponseNormalized,
        kHeadResponseNormalized,
    };
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized_nginx = nginx_malformed_responses[i];
        std::vector<char> normalized_rut = rut_malformed_responses[i];
        const char* expected_response = expected_malformed_responses[i];
        const size_t expected_len = strlen(expected_response);
        const std::string expected_request =
            std::string(i == 0 ? "HEAD /head?q=1 HTTP/1.1\r\n" : "HEAD /head?q=2 HTTP/1.1\r\n") +
            "Host: 127.0.0.1:" + std::to_string(backend_port) + "\r\n\r\n";
        const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
        if (!normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
            normalized_nginx.size() != expected_len || normalized_rut.size() != expected_len ||
            memcmp(normalized_nginx.data(), expected_response, expected_len) != 0 ||
            memcmp(normalized_rut.data(), expected_response, expected_len) != 0 ||
            normalized_nginx != normalized_rut ||
            nginx_malformed_recorder.history[i].wire != expected_wire ||
            rut_malformed_recorder.history[i].wire != expected_wire ||
            nginx_malformed_recorder.history[i].wire != rut_malformed_recorder.history[i].wire) {
            std::cerr << "FAIL [malformed HEAD differential]: request " << (i + 1)
                      << " nginx/generated-RUT observable wire mismatch\n";
            dump_wire("expected malformed HEAD response",
                      std::vector<char>(expected_response, expected_response + expected_len));
            dump_wire("nginx malformed HEAD response", nginx_malformed_responses[i]);
            dump_wire("generated-RUT malformed HEAD response", rut_malformed_responses[i]);
            dump_wire("expected malformed HEAD upstream request", expected_wire);
            dump_wire("nginx malformed HEAD upstream request",
                      nginx_malformed_recorder.history[i].wire);
            dump_wire("generated-RUT malformed HEAD upstream request",
                      rut_malformed_recorder.history[i].wire);
            dump_pinned_history(nginx_malformed_recorder, "nginx malformed HEAD");
            dump_pinned_history(rut_malformed_recorder, "RUT malformed HEAD");
            dump_log(temp.nginx_log, "pinned nginx malformed HEAD log");
            dump_log(temp.rut_log, "generated-RUT malformed HEAD log");
            return 1;
        }
    }
    std::cerr << "PASS: converter-generated RUT malformed/open-peer reusable HEAD matches pinned "
                 "nginx (two exact responses, fresh origin wires, final EOF; exact io_uring "
                 "owner masks covered separately)\n";

    KeepAlivePinnedRecorder nginx_incomplete_recorder(
        KeepAlivePinnedRecorder::FirstResponseMode::IncompleteWaitGate);
    if (!nginx_incomplete_recorder.setup(backend_port)) {
        std::cerr << "FAIL [pinned incomplete-EOF HEAD]: backend recorder setup failed\n";
        return 1;
    }
    std::vector<std::vector<char>> nginx_incomplete_responses;
    std::string nginx_incomplete_error;
    if (!capture_nginx_head_incomplete_eof_reuse(frontend_port,
                                                 temp.nginx_config,
                                                 temp.nginx_log,
                                                 container + "-head-incomplete-eof",
                                                 nginx_incomplete_recorder,
                                                 nginx_incomplete_responses,
                                                 nginx_incomplete_error)) {
        std::cerr << "FAIL [pinned incomplete-EOF HEAD]: " << nginx_incomplete_error << "\n";
        for (const auto& response : nginx_incomplete_responses)
            dump_wire("pinned incomplete-EOF HEAD downstream", response);
        nginx_incomplete_recorder.stop();
        dump_pinned_history(nginx_incomplete_recorder, "nginx incomplete-EOF HEAD");
        dump_log(temp.nginx_log, "pinned nginx incomplete-EOF HEAD log");
        return 1;
    }
    nginx_incomplete_recorder.stop();

    KeepAlivePinnedRecorder rut_incomplete_recorder(
        KeepAlivePinnedRecorder::FirstResponseMode::IncompleteWaitGate);
    if (!rut_incomplete_recorder.setup(backend_port)) {
        std::cerr << "FAIL [generated-RUT incomplete-EOF HEAD]: backend recorder setup failed\n";
        return 1;
    }
    std::vector<std::vector<char>> rut_incomplete_responses;
    std::string rut_incomplete_error;
    if (!capture_rut_head_incomplete_eof_reuse(frontend_port,
                                               temp.source,
                                               temp.rut_log,
                                               argv[1],
                                               rut_incomplete_recorder,
                                               rut_incomplete_responses,
                                               rut_incomplete_error)) {
        std::cerr << "FAIL [generated-RUT incomplete-EOF HEAD]: " << rut_incomplete_error << "\n";
        for (const auto& response : rut_incomplete_responses)
            dump_wire("generated-RUT incomplete-EOF HEAD downstream", response);
        rut_incomplete_recorder.stop();
        dump_pinned_history(rut_incomplete_recorder, "RUT incomplete-EOF HEAD");
        dump_log(temp.rut_log, "generated-RUT incomplete-EOF HEAD log");
        return 1;
    }
    rut_incomplete_recorder.stop();

    using IncompleteState = KeepAlivePinnedRecorder::IncompleteGateState;
    const auto incomplete_recorder_is_exact = [](const KeepAlivePinnedRecorder& recorder) {
        return recorder.accepted.load(std::memory_order_acquire) == 2 &&
               recorder.requests.load(std::memory_order_acquire) == 2 &&
               recorder.history.size() == 2 && recorder.history[0].connection_id == 1 &&
               recorder.history[1].connection_id == 2 &&
               recorder.history[0].connection_id != recorder.history[1].connection_id &&
               recorder.incomplete_gate_state.load(std::memory_order_acquire) ==
                   IncompleteState::ClosedByGate;
    };
    if (nginx_incomplete_responses.size() != 2 || rut_incomplete_responses.size() != 2 ||
        !incomplete_recorder_is_exact(nginx_incomplete_recorder) ||
        !incomplete_recorder_is_exact(rut_incomplete_recorder)) {
        std::cerr << "FAIL [incomplete-EOF HEAD differential]: exact response/origin cardinality "
                     "or gate evidence failed\n";
        dump_pinned_history(nginx_incomplete_recorder, "nginx incomplete-EOF HEAD");
        dump_pinned_history(rut_incomplete_recorder, "RUT incomplete-EOF HEAD");
        dump_log(temp.nginx_log, "pinned nginx incomplete-EOF HEAD log");
        dump_log(temp.rut_log, "generated-RUT incomplete-EOF HEAD log");
        return 1;
    }

    const char* const expected_incomplete_responses[] = {
        kHeadGatewayKeepAliveResponseNormalized,
        kHeadResponseNormalized,
    };
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized_nginx = nginx_incomplete_responses[i];
        std::vector<char> normalized_rut = rut_incomplete_responses[i];
        const char* expected_response = expected_incomplete_responses[i];
        const size_t expected_len = strlen(expected_response);
        const std::string expected_request =
            std::string(i == 0 ? "HEAD /head?q=1 HTTP/1.1\r\n" : "HEAD /head?q=2 HTTP/1.1\r\n") +
            "Host: 127.0.0.1:" + std::to_string(backend_port) + "\r\n\r\n";
        const std::vector<char> expected_wire(expected_request.begin(), expected_request.end());
        if (!normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
            normalized_nginx.size() != expected_len || normalized_rut.size() != expected_len ||
            memcmp(normalized_nginx.data(), expected_response, expected_len) != 0 ||
            memcmp(normalized_rut.data(), expected_response, expected_len) != 0 ||
            normalized_nginx != normalized_rut ||
            nginx_incomplete_recorder.history[i].wire != expected_wire ||
            rut_incomplete_recorder.history[i].wire != expected_wire ||
            nginx_incomplete_recorder.history[i].wire != rut_incomplete_recorder.history[i].wire) {
            std::cerr << "FAIL [incomplete-EOF HEAD differential]: request " << (i + 1)
                      << " nginx/generated-RUT observable wire mismatch\n";
            dump_wire("expected incomplete-EOF HEAD response",
                      std::vector<char>(expected_response, expected_response + expected_len));
            dump_wire("nginx incomplete-EOF HEAD response", nginx_incomplete_responses[i]);
            dump_wire("generated-RUT incomplete-EOF HEAD response", rut_incomplete_responses[i]);
            dump_wire("expected incomplete-EOF HEAD upstream request", expected_wire);
            dump_wire("nginx incomplete-EOF HEAD upstream request",
                      nginx_incomplete_recorder.history[i].wire);
            dump_wire("generated-RUT incomplete-EOF HEAD upstream request",
                      rut_incomplete_recorder.history[i].wire);
            dump_pinned_history(nginx_incomplete_recorder, "nginx incomplete-EOF HEAD");
            dump_pinned_history(rut_incomplete_recorder, "RUT incomplete-EOF HEAD");
            dump_log(temp.nginx_log, "pinned nginx incomplete-EOF HEAD log");
            dump_log(temp.rut_log, "generated-RUT incomplete-EOF HEAD log");
            return 1;
        }
    }
    std::cerr << "PASS: converter-generated RUT incomplete-header/test-authorized-EOF reusable "
                 "HEAD matches pinned nginx (two exact responses, fresh origin wires, final "
                 "downstream EOF; zero-owner evidence covered separately)\n";

    DeadPort keepalive_dead;
    if (!keepalive_dead.reserve(backend_port)) {
        std::cerr << "FAIL [pinned HEAD gateway keep-alive]: dead-port reservation failed\n";
        return 1;
    }
    std::vector<std::vector<char>> keepalive_gateway_responses;
    u32 keepalive_gateway_failures = 0;
    std::string keepalive_gateway_error;
    if (!capture_nginx_head_keepalive_gateway(frontend_port,
                                              backend_port,
                                              temp.nginx_config,
                                              temp.nginx_log,
                                              container + "-head-gateway-keepalive",
                                              keepalive_dead,
                                              keepalive_gateway_responses,
                                              keepalive_gateway_failures,
                                              keepalive_gateway_error)) {
        std::cerr << "FAIL [pinned HEAD gateway keep-alive]: " << keepalive_gateway_error << "\n";
        for (const auto& response : keepalive_gateway_responses)
            dump_wire("pinned HEAD gateway downstream", response);
        dump_log(temp.nginx_log, "pinned nginx HEAD gateway keep-alive log");
        return 1;
    }
    if (keepalive_gateway_responses.size() != 2 || keepalive_gateway_failures != 2) {
        std::cerr << "FAIL [pinned HEAD gateway keep-alive]: expected two responses and two "
                     "scoped connect failures\n";
        for (const auto& response : keepalive_gateway_responses)
            dump_wire("pinned HEAD gateway downstream", response);
        dump_log(temp.nginx_log, "pinned nginx HEAD gateway keep-alive log");
        return 1;
    }
    const char* const expected_gateway_responses[] = {
        kHeadGatewayKeepAliveResponseNormalized,
        kHeadGatewayResponseNormalized,
    };
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized = keepalive_gateway_responses[i];
        const size_t expected_len = strlen(expected_gateway_responses[i]);
        if (!normalize_date(normalized) || normalized.size() != expected_len ||
            memcmp(normalized.data(), expected_gateway_responses[i], expected_len) != 0) {
            std::cerr << "FAIL [pinned HEAD gateway keep-alive]: exact response " << (i + 1)
                      << " mismatch\n";
            dump_wire("actual pinned HEAD gateway response", keepalive_gateway_responses[i]);
            dump_log(temp.nginx_log, "pinned nginx HEAD gateway keep-alive log");
            return 1;
        }
    }
    for (const auto& response : keepalive_gateway_responses)
        dump_wire("pinned HEAD gateway downstream", response);
    std::cerr << "PASS: pinned nginx HEAD keep-alive gateway baseline "
                 "(two scoped nginx connect-failure log records + EOF)\n";

    // This differential proves only the two complete observable downstream response wires.
    // It does not assert a RUT connect-attempt count. The separate focused runtime regression
    // upstream_reuse.paired_head_failure_never_reconnects_or_replays owns the no-pool/no-replay
    // invariant.
    std::vector<std::vector<char>> rut_keepalive_gateway_responses;
    std::string rut_keepalive_gateway_error;
    if (!capture_rut_head_keepalive_gateway(frontend_port,
                                            temp.source,
                                            temp.rut_log,
                                            argv[1],
                                            keepalive_dead,
                                            rut_keepalive_gateway_responses,
                                            rut_keepalive_gateway_error)) {
        std::cerr << "FAIL [reusable HEAD gateway RUT]: " << rut_keepalive_gateway_error << "\n";
        for (size_t i = 0; i < rut_keepalive_gateway_responses.size(); i++) {
            const std::string label = "RUT reusable HEAD gateway response " + std::to_string(i + 1);
            dump_wire(label.c_str(), rut_keepalive_gateway_responses[i]);
        }
        dump_log(temp.nginx_log, "nginx reusable HEAD gateway log");
        dump_log(temp.rut_log, "RUT reusable HEAD gateway log");
        return 1;
    }
    if (rut_keepalive_gateway_responses.size() != 2) {
        std::cerr << "FAIL [reusable HEAD gateway differential]: RUT produced "
                  << rut_keepalive_gateway_responses.size() << " responses, expected 2\n";
        dump_log(temp.rut_log, "RUT reusable HEAD gateway log");
        return 1;
    }
    for (size_t i = 0; i < 2; i++) {
        std::vector<char> normalized_nginx = keepalive_gateway_responses[i];
        std::vector<char> normalized_rut = rut_keepalive_gateway_responses[i];
        const char* expected_response = expected_gateway_responses[i];
        const size_t expected_len = strlen(expected_response);
        if (!normalize_date(normalized_nginx) || !normalize_date(normalized_rut) ||
            normalized_nginx != normalized_rut || normalized_rut.size() != expected_len ||
            memcmp(normalized_rut.data(), expected_response, expected_len) != 0) {
            std::cerr << "FAIL [reusable HEAD gateway differential]: response " << (i + 1)
                      << " nginx/RUT wire mismatch\n";
            dump_wire("expected reusable HEAD gateway response",
                      std::vector<char>(expected_response, expected_response + expected_len));
            dump_wire("nginx reusable HEAD gateway response", keepalive_gateway_responses[i]);
            dump_wire("RUT reusable HEAD gateway response", rut_keepalive_gateway_responses[i]);
            dump_log(temp.nginx_log, "nginx reusable HEAD gateway log");
            dump_log(temp.rut_log, "RUT reusable HEAD gateway log");
            return 1;
        }
    }
    std::cerr << "PASS: converter-generated RUT reusable HEAD connect failure matches pinned "
                 "nginx (two complete observable response wires; RUT connect-attempt count "
                 "not asserted; no-pool/no-replay covered separately by "
                 "upstream_reuse.paired_head_failure_never_reconnects_or_replays)\n";
    close(keepalive_dead.fd);
    keepalive_dead.fd = -1;

    std::vector<char> rut_head_response;
    std::vector<char> rut_head_request;
    std::string rut_head_error;
    if (!capture_head_rut_case(frontend_port,
                               backend_port,
                               temp.source,
                               temp.rut_log,
                               argv[1],
                               rut_head_response,
                               rut_head_request,
                               rut_head_error)) {
        std::cerr << "FAIL [HEAD RUT differential]: " << rut_head_error << "\n";
        dump_wire("nginx HEAD response", nginx_head_response);
        dump_wire("RUT HEAD response", rut_head_response);
        dump_wire("nginx HEAD request", nginx_head_request);
        dump_wire("RUT HEAD request", rut_head_request);
        dump_log(temp.rut_log, "RUT HEAD log");
        return 1;
    }
    const std::vector<char> expected_head_response(
        kHeadResponseNormalized, kHeadResponseNormalized + sizeof(kHeadResponseNormalized) - 1);
    const std::string expected_head_request = std::string("HEAD /head?q=1 HTTP/1.1\r\n") +
                                              "Host: 127.0.0.1:" + std::to_string(backend_port) +
                                              "\r\n\r\n";
    const std::vector<char> expected_head_wire(expected_head_request.begin(),
                                               expected_head_request.end());
    std::vector<char> normalized_nginx_head = nginx_head_response;
    std::vector<char> normalized_rut_head = rut_head_response;
    if (!normalize_date(normalized_nginx_head) || !normalize_date(normalized_rut_head) ||
        normalized_nginx_head != expected_head_response ||
        normalized_rut_head != expected_head_response ||
        normalized_nginx_head != normalized_rut_head || nginx_head_request != expected_head_wire ||
        rut_head_request != expected_head_wire || nginx_head_request != rut_head_request) {
        std::cerr << "FAIL [HEAD differential]: exact nginx/RUT HEAD mismatch\n";
        dump_wire("expected HEAD response", expected_head_response);
        dump_wire("nginx HEAD response", nginx_head_response);
        dump_wire("RUT HEAD response", rut_head_response);
        dump_wire("expected HEAD upstream", expected_head_wire);
        dump_wire("nginx HEAD upstream", nginx_head_request);
        dump_wire("RUT HEAD upstream", rut_head_request);
        dump_log(temp.nginx_log, "nginx HEAD log");
        dump_log(temp.rut_log, "RUT HEAD log");
        return 1;
    }
    std::cerr << "PASS: converter-generated RUT HEAD success matches pinned nginx\n";

    DeadPort head_gateway_dead;
    if (!head_gateway_dead.reserve(backend_port)) {
        std::cerr
            << "FAIL [HEAD gateway differential]: failed to reserve unavailable upstream port\n";
        return 1;
    }
    std::vector<char> nginx_head_gateway_differential_response;
    std::string nginx_head_gateway_differential_error;
    const std::string head_gateway_differential_container = container + "-head-differential";
    if (!capture_head_gateway_case(frontend_port,
                                   backend_port,
                                   temp.nginx_config,
                                   temp.nginx_log,
                                   head_gateway_differential_container,
                                   nginx_head_gateway_differential_response,
                                   nginx_head_gateway_differential_error,
                                   &head_gateway_dead)) {
        std::cerr << "FAIL [HEAD gateway differential nginx]: "
                  << nginx_head_gateway_differential_error << "\n";
        dump_wire("nginx HEAD gateway response", nginx_head_gateway_differential_response);
        dump_log(temp.nginx_log, "nginx HEAD gateway log");
        return 1;
    }
    std::vector<char> rut_head_gateway_differential_response;
    std::string rut_head_gateway_differential_error;
    if (!capture_head_gateway_rut_case(frontend_port,
                                       backend_port,
                                       temp.source,
                                       temp.rut_log,
                                       argv[1],
                                       head_gateway_dead,
                                       rut_head_gateway_differential_response,
                                       rut_head_gateway_differential_error)) {
        std::cerr << "FAIL [HEAD gateway differential RUT]: " << rut_head_gateway_differential_error
                  << "\n";
        dump_wire("nginx HEAD gateway response", nginx_head_gateway_differential_response);
        dump_wire("RUT HEAD gateway response", rut_head_gateway_differential_response);
        dump_log(temp.rut_log, "RUT HEAD gateway log");
        return 1;
    }
    const std::vector<char> expected_head_gateway_response(
        kHeadGatewayResponseNormalized,
        kHeadGatewayResponseNormalized + sizeof(kHeadGatewayResponseNormalized) - 1);
    std::vector<char> normalized_nginx_head_gateway = nginx_head_gateway_differential_response;
    std::vector<char> normalized_rut_head_gateway = rut_head_gateway_differential_response;
    if (!normalize_date(normalized_nginx_head_gateway) ||
        !normalize_date(normalized_rut_head_gateway) ||
        normalized_nginx_head_gateway != expected_head_gateway_response ||
        normalized_rut_head_gateway != expected_head_gateway_response ||
        normalized_nginx_head_gateway != normalized_rut_head_gateway) {
        std::cerr << "FAIL [HEAD gateway differential]: exact nginx/RUT mismatch\n";
        dump_wire("expected HEAD gateway response", expected_head_gateway_response);
        dump_wire("nginx HEAD gateway response", nginx_head_gateway_differential_response);
        dump_wire("RUT HEAD gateway response", rut_head_gateway_differential_response);
        dump_log(temp.nginx_log, "nginx HEAD gateway log");
        dump_log(temp.rut_log, "RUT HEAD gateway log");
        return 1;
    }
    std::cerr
        << "PASS: converter-generated RUT HEAD unavailable-upstream gateway matches pinned nginx\n";

    u16 api_frontend_port = 0;
    u16 api_backend_port = 0;
    if (!allocate_port(api_frontend_port) || !allocate_port(api_backend_port) ||
        api_frontend_port == api_backend_port) {
        std::cerr << "FAIL [api preflight]: bounded dynamic port allocation failed\n";
        return 1;
    }
    const std::string api_fragment = "server {\n  listen " + std::to_string(api_frontend_port) +
                                     ";\n  location /api/ {\n    proxy_pass http://127.0.0.1:" +
                                     std::to_string(api_backend_port) + "/;\n  }\n}\n";
    auto api_parsed =
        rut::nginx::parse({api_fragment.data(), static_cast<rut::u32>(api_fragment.size())});
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
    const std::string generated_api_source(api_lowered.value().data, api_lowered.value().len);
    static constexpr const char* kGeneratedApiRequirements[] = {
        "route \"/api\" {",
        "if req.method == GET && req.pathOnly == \"/api\"",
        "return redirect({",
        "target_transform: {",
        "request_policy: {",
        "response_policy: {",
        "failure_policy: {"};
    for (const char* requirement : kGeneratedApiRequirements) {
        if (generated_api_source.find(requirement) == std::string::npos) {
            std::cerr << "FAIL [api source]: converter output lacks required redirect/forward "
                         "artifact: "
                      << requirement << "\n";
            return 1;
        }
    }
    if (!write_file(temp.source, api_lowered.value().data, api_lowered.value().len)) {
        std::cerr << "FAIL [api source]: secure generated source overwrite failed\n";
        return 1;
    }
    const std::string api_nginx_config = "events {}\nhttp {\n" + api_fragment + "}\n";
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
            dump_wire(("RUT API response " + std::to_string(i + 1)).c_str(), rut_api_responses[i]);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }

    static constexpr const char* kApiTargets[] = {"/", "/x", "/x?y=1"};
    for (size_t i = 0; i < 3; i++) {
        if (!starts_with_200(nginx_api_responses[i]) || !starts_with_200(rut_api_responses[i])) {
            std::cerr << "FAIL [api compare " << (i + 1) << "]: expected HTTP/1.1 200 response\n";
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

    std::vector<std::vector<char>> api_redirect_responses;
    std::string api_redirect_error;
    const std::string api_redirect_container = container + "-api-redirect";
    std::vector<std::vector<char>> rut_api_redirect_responses;
    if (!capture_api_redirect_case(api_frontend_port,
                                   api_backend_port,
                                   temp.source,
                                   temp.nginx_config,
                                   temp.nginx_log,
                                   temp.rut_log,
                                   argv[1],
                                   api_redirect_container,
                                   api_redirect_responses,
                                   rut_api_redirect_responses,
                                   api_redirect_error)) {
        std::cerr << "FAIL [api redirect differential]: " << api_redirect_error << "\n";
        for (size_t i = 0; i < api_redirect_responses.size(); i++)
            dump_wire(("nginx API redirect response " + std::to_string(i + 1)).c_str(),
                      api_redirect_responses[i]);
        for (size_t i = 0; i < rut_api_redirect_responses.size(); i++)
            dump_wire(("RUT API redirect response " + std::to_string(i + 1)).c_str(),
                      rut_api_redirect_responses[i]);
        dump_log(temp.nginx_log, "nginx log");
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    std::cerr << "PASS: pinned nginx and converter-generated RUT /api automatic slash redirect "
                 "case (2 vectors, no upstream side effects)\n";

    std::vector<std::vector<char>> invalid_api_responses;
    std::string invalid_api_error;
    if (!capture_api_invalid_case(api_frontend_port,
                                  api_backend_port,
                                  temp.source,
                                  temp.rut_log,
                                  argv[1],
                                  invalid_api_responses,
                                  invalid_api_error)) {
        std::cerr << "FAIL [api invalid-target boundary]: " << invalid_api_error << "\n";
        for (size_t i = 0; i < invalid_api_responses.size(); i++)
            dump_wire(("RUT invalid-target API response " + std::to_string(i + 1)).c_str(),
                      invalid_api_responses[i]);
        dump_log(temp.rut_log, "RUT log");
        return 1;
    }
    std::cerr << "PASS: RUT /api/ out-of-slice targets fail closed (3 vectors, no upstream side "
                 "effects)\n";
    return 0;
#endif
}
