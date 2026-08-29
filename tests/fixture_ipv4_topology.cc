#include "fixture_ipv4_topology.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RUT_PINNED_NGINX_IMAGE
#error "RUT_PINNED_NGINX_IMAGE must be provided by the build system"
#endif

namespace rut::test::ipv4_topology {
namespace {

using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr const char* kStageLabel = "rut.stage=358-stage2a2";

struct CommandResult {
    bool started = false;
    bool timed_out = false;
    bool process_group_verified = false;
    int status = 0;
    std::string output;
};

struct DescendantProbe {
    pid_t pid = -1;
    pid_t pgid = -1;
    bool marker_received = false;
    bool same_pgid = false;
    bool alive_before_cleanup = false;
};

static bool exited_zero(const CommandResult& result) {
    return result.started && !result.timed_out && WIFEXITED(result.status) &&
           WEXITSTATUS(result.status) == 0;
}

static std::string trim(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' '))
        value.pop_back();
    size_t first = 0;
    while (first < value.size() &&
           (value[first] == ' ' || value[first] == '\n' || value[first] == '\r'))
        first++;
    return value.substr(first);
}

static bool process_group_gone(pid_t pgid) {
    if (kill(-pgid, 0) == 0) return false;
    return errno == ESRCH;
}

[[noreturn]] static void runner_fail_stop(pid_t pgid, const char* reason) {
    dprintf(STDERR_FILENO,
            "fatal topology command cleanup failure (pgid %ld): %s\n",
            static_cast<long>(pgid),
            reason);
    // This is deliberately the only unbounded path: returning here could
    // orphan a same-uid command group.  SIGKILL is not catchable; once the
    // group is gone, terminate this runner rather than returning a normal
    // CommandResult.
    for (;;) {
        if (process_group_gone(pgid)) _exit(125);
        (void)kill(-pgid, SIGKILL);
        (void)usleep(10000);
    }
}

static bool terminate_group_bounded(pid_t pgid) {
    if (process_group_gone(pgid)) return true;
    (void)kill(-pgid, SIGTERM);
    const auto term_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (std::chrono::steady_clock::now() < term_deadline) {
        if (process_group_gone(pgid)) return true;
        (void)usleep(10000);
    }
    (void)kill(-pgid, SIGKILL);
    const auto kill_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    while (std::chrono::steady_clock::now() < kill_deadline) {
        if (process_group_gone(pgid)) return true;
        (void)usleep(10000);
    }
    return process_group_gone(pgid);
}

static void require_group_gone(pid_t pgid, const char* reason) {
    if (process_group_gone(pgid)) return;
    if (!terminate_group_bounded(pgid) || !process_group_gone(pgid)) runner_fail_stop(pgid, reason);
}

static bool run_command(const std::vector<std::string>& arguments,
                        CommandResult& result,
                        int timeout_ms = 15000,
                        bool report_success_as_timeout = false,
                        bool inject_descendant = false,
                        DescendantProbe* descendant_probe = nullptr) {
    result = {};
    if (arguments.empty()) return false;
    int pipe_fds[2] = {-1, -1};
    if (pipe(pipe_fds) != 0) return false;
    int marker_fds[2] = {-1, -1};
    if (inject_descendant && pipe(marker_fds) != 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        if (marker_fds[0] != -1) close(marker_fds[0]);
        if (marker_fds[1] != -1) close(marker_fds[1]);
        return false;
    }
    if (child == 0) {
        (void)setpgid(0, 0);
        if (inject_descendant) {
            const pid_t descendant = fork();
            if (descendant == 0) {
                close(marker_fds[0]);
                struct {
                    pid_t pid;
                    pid_t pgid;
                } marker{getpid(), getpgrp()};
                const char* bytes = reinterpret_cast<const char*>(&marker);
                size_t written = 0;
                while (written < sizeof(marker)) {
                    const ssize_t count =
                        write(marker_fds[1], bytes + written, sizeof(marker) - written);
                    if (count > 0)
                        written += static_cast<size_t>(count);
                    else if (count < 0 && errno == EINTR)
                        continue;
                    else
                        _exit(126);
                }
                close(marker_fds[1]);
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                (void)usleep(5000000);
                _exit(0);
            }
            close(marker_fds[0]);
            close(marker_fds[1]);
        }
        close(pipe_fds[0]);
        (void)dup2(pipe_fds[1], STDOUT_FILENO);
        (void)dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(pipe_fds[1]);
    if (inject_descendant) close(marker_fds[1]);
    (void)setpgid(child, child);
    const int flags = fcntl(pipe_fds[0], F_GETFL, 0);
    (void)fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
    result.started = true;
    if (inject_descendant) {
        pollfd marker_descriptor{marker_fds[0], POLLIN, 0};
        if (poll(&marker_descriptor, 1, 1000) <= 0) {
            close(marker_fds[0]);
            if (!terminate_group_bounded(child))
                runner_fail_stop(child, "descendant marker PGID remained alive");
            close(pipe_fds[0]);
            return false;
        }
        struct {
            pid_t pid;
            pid_t pgid;
        } marker{};
        size_t received = 0;
        while (received < sizeof(marker)) {
            const ssize_t count = read(marker_fds[0],
                                       reinterpret_cast<char*>(&marker) + received,
                                       sizeof(marker) - received);
            if (count > 0)
                received += static_cast<size_t>(count);
            else if (count < 0 && errno == EINTR)
                continue;
            else
                break;
        }
        close(marker_fds[0]);
        if (received != sizeof(marker) || marker.pid <= 0 || marker.pgid != child ||
            getpgid(marker.pid) != child || kill(marker.pid, 0) != 0) {
            if (!terminate_group_bounded(child))
                runner_fail_stop(child, "invalid descendant marker PGID remained alive");
            close(pipe_fds[0]);
            return false;
        }
        if (descendant_probe != nullptr) {
            descendant_probe->pid = marker.pid;
            descendant_probe->pgid = marker.pgid;
            descendant_probe->marker_received = true;
            descendant_probe->same_pgid = true;
        }
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    bool reaped = false;
    bool pipe_closed = false;
    while (!reaped || !pipe_closed) {
        char buffer[4096];
        for (;;) {
            const ssize_t count = read(pipe_fds[0], buffer, sizeof(buffer));
            if (count > 0) {
                if (result.output.size() + static_cast<size_t>(count) > 65536) {
                    if (!terminate_group_bounded(child))
                        runner_fail_stop(child, "output limit PGID remained alive");
                    for (;;) {
                        const pid_t waited = waitpid(child, &result.status, 0);
                        if (waited == child) break;
                        if (waited < 0 && errno == EINTR) continue;
                        if (waited < 0 && errno == ECHILD) break;
                        if (waited < 0 && !terminate_group_bounded(child))
                            runner_fail_stop(child, "wait recovery PGID remained alive");
                        if (waited < 0) break;
                    }
                    require_group_gone(child, "output-limit PGID remained alive");
                    result.process_group_verified = true;
                    close(pipe_fds[0]);
                    result.timed_out = true;
                    return false;
                }
                result.output.append(buffer, static_cast<size_t>(count));
                continue;
            }
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) break;
            pipe_closed = count == 0 || (count < 0 && errno != EINTR);
            break;
        }
        if (!reaped) {
            const pid_t waited = waitpid(child, &result.status, WNOHANG);
            if (waited == child)
                reaped = true;
            else if (waited < 0 && errno != EINTR) {
                // The child is always our own process-group leader.  A
                // waitpid failure must not leave that group running.
                if (errno == ECHILD) {
                    // There is no valid child to wait for anymore.  The
                    // process-group liveness check is authoritative here.
                    if (!terminate_group_bounded(child))
                        runner_fail_stop(child, "ECHILD PGID remained alive");
                } else {
                    if (!terminate_group_bounded(child))
                        runner_fail_stop(child, "non-EINTR wait PGID remained alive");
                    // The bounded helper proved the group disappeared; do
                    // not attempt an invalid waitpid recovery.
                }
                require_group_gone(child, "wait-recovery PGID remained alive");
                result.process_group_verified = true;
                close(pipe_fds[0]);
                return false;
            }
        }
        if (reaped && pipe_closed) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            (void)kill(-child, SIGTERM);
            (void)usleep(100000);
            if (!reaped) (void)kill(-child, SIGKILL);
            while (!reaped) {
                const pid_t waited = waitpid(child, &result.status, 0);
                if (waited == child)
                    reaped = true;
                else if (waited < 0 && errno == EINTR)
                    continue;
                else if (waited < 0) {
                    // ECHILD means waitpid is no longer valid.  In either
                    // case, terminate and verify the complete PGID without
                    // issuing another invalid wait operation.
                    reaped = terminate_group_bounded(child);
                    if (!reaped) runner_fail_stop(child, "timeout PGID remained alive");
                }
            }
            result.timed_out = true;
            break;
        }
        pollfd descriptor{pipe_fds[0], POLLIN, 0};
        (void)poll(&descriptor, 1, 25);
    }
    if (descendant_probe != nullptr && descendant_probe->marker_received) {
        descendant_probe->alive_before_cleanup = kill(descendant_probe->pid, 0) == 0;
        if (!descendant_probe->alive_before_cleanup)
            runner_fail_stop(child, "descendant disappeared before cleanup checkpoint");
    }
    require_group_gone(child, "normal command completion PGID remained alive");
    result.process_group_verified = true;
    close(pipe_fds[0]);
    if (report_success_as_timeout && reaped && !result.timed_out && WIFEXITED(result.status) &&
        WEXITSTATUS(result.status) == 0) {
        result.timed_out = true;
        return false;
    }
    return reaped && !result.timed_out;
}

static bool read_file(const std::string& path, std::string& output) {
    output.clear();
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buffer[4096];
    for (;;) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            if (output.size() + static_cast<size_t>(count) > 65536) {
                close(fd);
                return false;
            }
            output.append(buffer, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        const bool success = count == 0;
        close(fd);
        return success;
    }
}

static bool high_entropy_token(std::string& token) {
    std::array<unsigned char, 24> bytes{};
    if (getrandom(bytes.data(), bytes.size(), 0) != static_cast<ssize_t>(bytes.size()))
        return false;
    static constexpr char hex[] = "0123456789abcdef";
    token.clear();
    for (unsigned char byte : bytes) {
        token.push_back(hex[byte >> 4]);
        token.push_back(hex[byte & 15]);
    }
    return true;
}

struct TempDir {
    char path[64] = "/tmp/rut358-topology-XXXXXX";
    bool created = false;
    std::string manifest;
    bool create() {
        if (mkdtemp(path) == nullptr || chmod(path, 0700) != 0) return false;
        created = true;
        manifest = std::string(path) + "/manifest";
        return true;
    }
    ~TempDir() {
        if (!created) return;
        unlink(manifest.c_str());
        rmdir(path);
    }
};

struct Network {
    std::string name;
    std::string id;
    std::string subnet;
    std::string gateway;
    bool exists = false;
};

struct Endpoint {
    std::string network_name;
    std::string network_id;
    std::string address;
    std::string cidr;
    std::string gateway;
};

static bool split_exact(const std::string& text,
                        char delimiter,
                        size_t expected,
                        std::vector<std::string>& fields) {
    fields.clear();
    size_t start = 0;
    for (;;) {
        const size_t end = text.find(delimiter, start);
        fields.push_back(text.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return fields.size() == expected;
}

static bool endpoint_equal(const Endpoint& left, const Endpoint& right) {
    return left.network_name == right.network_name && left.network_id == right.network_id &&
           left.address == right.address && left.cidr == right.cidr &&
           left.gateway == right.gateway;
}

static bool endpoint_set_equal(const std::vector<Endpoint>& expected,
                               const std::vector<Endpoint>& actual) {
    if (expected.size() != actual.size()) return false;
    for (const Endpoint& wanted : expected) {
        size_t matches = 0;
        for (const Endpoint& observed : actual)
            if (endpoint_equal(wanted, observed)) matches++;
        if (matches != 1) return false;
    }
    return true;
}

static bool no_published_ports(const std::string& port_bindings, const std::string& network_ports) {
    if (port_bindings != "{}" && port_bindings != "null") return false;
    if (network_ports == "null" || network_ports == "{}") return true;
    // Docker represents a host publication as an array of host bindings;
    // image-declared container ports without a publication are null.
    return network_ports.find('[') == std::string::npos &&
           network_ports.find(":null") != std::string::npos;
}

static std::string proc_hex(u32 value) {
    std::ostringstream text;
    text << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << ntohl(value);
    return text.str();
}

static std::string proc_mask_hex(u32 value) {
    std::ostringstream text;
    text << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << value;
    return text.str();
}

struct ProcIdentity {
    u64 start = 0;
    ino_t netns = 0;
};

static bool proc_identity(pid_t pid, ProcIdentity& identity, bool require_netns = true) {
    std::string stat_contents;
    if (!read_file("/proc/" + std::to_string(pid) + "/stat", stat_contents)) return false;
    const size_t end = stat_contents.rfind(") ");
    if (end == std::string::npos) return false;
    std::istringstream fields(stat_contents.substr(end + 2));
    char state = 0;
    long ignored = 0;
    if (!(fields >> state >> ignored >> ignored)) return false;
    for (int field = 6; field <= 22; field++) {
        std::string value;
        if (!(fields >> value)) return false;
        if (field == 22) {
            char* end = nullptr;
            identity.start = strtoull(value.c_str(), &end, 10);
            if (end == value.c_str() || *end != '\0') return false;
        }
    }
    struct stat status{};
    if (stat(("/proc/" + std::to_string(pid) + "/ns/net").c_str(), &status) != 0) {
        if (require_netns) return false;
        identity.netns = 0;
        return true;
    }
    identity.netns = status.st_ino;
    return identity.start != 0 && identity.netns != 0;
}

static bool parse_ipv4(const std::string& text, u32& value) {
    in_addr address{};
    if (inet_pton(AF_INET, text.c_str(), &address) != 1) return false;
    value = ntohl(address.s_addr);
    return true;
}

static bool parse_cidr(const std::string& text, u32& low, u32& high) {
    const size_t slash = text.find('/');
    if (slash == std::string::npos) return false;
    u32 address = 0;
    if (!parse_ipv4(text.substr(0, slash), address)) return false;
    char* end = nullptr;
    const std::string prefix_text = text.substr(slash + 1);
    const unsigned long prefix = strtoul(prefix_text.c_str(), &end, 10);
    if (end == prefix_text.c_str() || *end != '\0' || prefix == 0 || prefix > 30) return false;
    const u32 mask = prefix == 0 ? 0u : 0xffffffffu << (32u - static_cast<u32>(prefix));
    low = address & mask;
    if (address != low) return false;
    high = low | ~mask;
    return true;
}

static bool valid_gateway(const std::string& subnet, const std::string& gateway) {
    u32 low = 0, high = 0, value = 0;
    if (!parse_cidr(subnet, low, high) || !parse_ipv4(gateway, value)) return false;
    const u32 first_octet = value >> 24;
    return value > low && value < high && first_octet != 0 && first_octet != 127;
}

static bool choose_address(const std::string& subnet,
                           const std::string& gateway,
                           std::string& address) {
    u32 low = 0, high = 0, gateway_value = 0;
    if (!parse_cidr(subnet, low, high) || !valid_gateway(subnet, gateway) ||
        !parse_ipv4(gateway, gateway_value))
        return false;
    for (u32 candidate = low + 1; candidate < high; candidate++) {
        if (candidate == gateway_value || ((candidate >> 24) & 0xffu) == 127u ||
            ((candidate >> 24) & 0xffu) == 0u || candidate == low || candidate == high)
            continue;
        in_addr value{htonl(candidate)};
        char printed[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &value, printed, sizeof(printed)) != nullptr) {
            address = printed;
            return true;
        }
    }
    return false;
}

static bool container_netns_inode(const std::string& holder, ino_t& inode) {
    CommandResult result;
    if (!run_command({"docker", "exec", holder, "readlink", "/proc/1/ns/net"}, result) ||
        !exited_zero(result))
        return false;
    const std::string text = trim(result.output);
    const size_t left = text.find('[');
    const size_t right = text.find(']', left == std::string::npos ? left : left + 1);
    if (left == std::string::npos || right == std::string::npos || right <= left + 1) return false;
    char* end = nullptr;
    const std::string value_text = text.substr(left + 1, right - left - 1);
    const unsigned long long value = strtoull(value_text.c_str(), &end, 10);
    if (end == value_text.c_str() || *end != '\0' || value == 0) return false;
    inode = static_cast<ino_t>(value);
    return true;
}

class Fixture {
public:
    explicit Fixture(std::string token) : token_(std::move(token)) {
        network_a_.name = "rut358-a-" + token_;
        network_b_.name = "rut358-b-" + token_;
        holder_name_ = "rut358-holder-" + token_;
    }
    ~Fixture() {
        std::string ignored;
        (void)cleanup(ignored);
    }

    const std::string& token() const { return token_; }
    const std::string& holder_name() const { return holder_name_; }
    const Network& network_a() const { return network_a_; }
    const Network& network_b() const { return network_b_; }
    const std::string& positive_ip() const { return positive_ip_; }
    const std::string& guard_ip() const { return guard_ip_; }
    pid_t holder_pid() const { return holder_pid_; }

    bool create_networks(FailurePoint point, std::string& error) {
        if (!create_network(network_a_, point, error)) return false;
        if (point == FailurePoint::AfterNetworkACreated) return injected(error);
        if (!verify_network(network_a_, error)) return false;
        if (point == FailurePoint::AfterNetworkAVerified) return injected(error);
        if (!create_network(network_b_, point, error)) return false;
        if (point == FailurePoint::AfterNetworkBCreated) return injected(error);
        if (!verify_network(network_b_, error)) return false;
        if (point == FailurePoint::AfterNetworkBVerified) return injected(error);
        u32 low_a = 0, high_a = 0, low_b = 0, high_b = 0;
        if (!parse_cidr(network_a_.subnet, low_a, high_a) ||
            !parse_cidr(network_b_.subnet, low_b, high_b) || (low_a <= high_b && low_b <= high_a) ||
            !choose_address(network_a_.subnet, network_a_.gateway, positive_ip_) ||
            !choose_address(network_b_.subnet, network_b_.gateway, guard_ip_) ||
            positive_ip_ == guard_ip_) {
            error = "Docker-managed IPAM was overlapping or did not provide valid addresses";
            return false;
        }
        if (point == FailurePoint::AfterBothIpamVerified) return injected(error);
        return true;
    }

    bool create_holder(FailurePoint point, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "run",
                          "--pull=never",
                          "--detach",
                          "--name",
                          holder_name_,
                          "--network",
                          network_a_.name,
                          "--ip",
                          positive_ip_,
                          "--cap-drop",
                          "ALL",
                          "--security-opt",
                          "no-new-privileges",
                          "--read-only",
                          "--tmpfs",
                          "/tmp:rw,noexec,nosuid,size=1m",
                          "--entrypoint",
                          "/bin/sleep",
                          "--label",
                          kStageLabel,
                          "--label",
                          "rut.token=" + token_,
                          RUT_PINNED_NGINX_IMAGE,
                          "infinity"},
                         result) ||
            !exited_zero(result)) {
            error = "inert pinned-image holder creation failed: " + trim(result.output);
            discover_holder();
            return false;
        }
        holder_exists_ = true;
        if (!discover_holder()) {
            error = "holder was created but exact ID/PID discovery failed";
            return false;
        }
        if (point == FailurePoint::AfterHolderCreated) return injected(error);
        return true;
    }

    bool attach_holder(FailurePoint point, std::string& error) {
        if (point == FailurePoint::AfterHolderAttachedA) return injected(error);
        CommandResult result;
        if (!run_command(
                {"docker", "network", "connect", "--ip", guard_ip_, network_b_.name, holder_name_},
                result) ||
            !exited_zero(result)) {
            error = "holder attachment to bridge B failed: " + trim(result.output);
            return false;
        }
        if (point == FailurePoint::AfterHolderAttachedB) return injected(error);
        return true;
    }

    bool verify_topology(FailurePoint point, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.Name}}|{{.Id}}|{{index .Config.Labels \"rut.stage\"}}|{{index "
                          ".Config.Labels \"rut.token\"}} {{range $name,$v := "
                          ".NetworkSettings.Networks}}{{$name}}|{{$v.NetworkID}}|{{$v.IPAddress}}|{"
                          "{$v.Gateway}} {{end}}",
                          holder_name_},
                         result) ||
            !exited_zero(result)) {
            error = "holder membership inspection failed: " + trim(result.output);
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string metadata;
        std::vector<std::string> metadata_fields;
        if (!(fields >> metadata) || !split_exact(metadata, '|', 4, metadata_fields) ||
            metadata_fields[0] != "/" + holder_name_ || metadata_fields[1] != holder_id_ ||
            metadata_fields[2] != "358-stage2a2" || metadata_fields[3] != token_) {
            error = "holder name/labels were not exact";
            return false;
        }
        std::vector<Endpoint> actual;
        std::string endpoint_text;
        while (fields >> endpoint_text) {
            std::vector<std::string> endpoint_fields;
            if (!split_exact(endpoint_text, '|', 4, endpoint_fields)) {
                error = "holder endpoint association was malformed";
                return false;
            }
            const Network* network =
                endpoint_fields[0] == network_a_.name
                    ? &network_a_
                    : (endpoint_fields[0] == network_b_.name ? &network_b_ : nullptr);
            if (network == nullptr) {
                error = "holder exposed an unexpected network endpoint";
                return false;
            }
            const size_t slash = network->subnet.find('/');
            if (slash == std::string::npos) {
                error = "verified network subnet was malformed";
                return false;
            }
            actual.push_back({endpoint_fields[0],
                              endpoint_fields[1],
                              endpoint_fields[2],
                              endpoint_fields[2] + network->subnet.substr(slash),
                              endpoint_fields[3]});
        }
        const std::vector<Endpoint> expected = {
            {network_a_.name,
             network_a_.id,
             positive_ip_,
             positive_ip_ + network_a_.subnet.substr(network_a_.subnet.find('/')),
             network_a_.gateway},
            {network_b_.name,
             network_b_.id,
             guard_ip_,
             guard_ip_ + network_b_.subnet.substr(network_b_.subnet.find('/')),
             network_b_.gateway}};
        if (!endpoint_set_equal(expected, actual)) {
            error = "holder endpoint associations were not exact";
            return false;
        }
        std::vector<Endpoint> swapped = actual;
        if (swapped.size() == 2) {
            std::swap(swapped[0].network_id, swapped[1].network_id);
            if (endpoint_set_equal(expected, swapped)) {
                error = "endpoint cross-swap mutation was accepted";
                return false;
            }
        }
        if (!verify_membership(network_a_, error) || !verify_membership(network_b_, error))
            return false;
        if (!run_command(
                {"docker",
                 "inspect",
                 "-f",
                 "{{.Path}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.PortBindings}}"
                 " {{.HostConfig.SecurityOpt}} {{json .HostConfig.CapDrop}} "
                 "{{json .Config.ExposedPorts}} {{json .NetworkSettings.Ports}}",
                 holder_name_},
                result) ||
            !exited_zero(result)) {
            error = "holder was not inert/read-only/capability-dropped with no published ports";
            return false;
        }
        std::istringstream security_fields(trim(result.output));
        std::string path, readonly, bindings, security, cap_drop, exposed, network_ports;
        if (!(security_fields >> path >> readonly >> bindings >> security >> cap_drop >> exposed >>
              network_ports) ||
            path != "/bin/sleep" || readonly != "true" ||
            !no_published_ports(bindings, network_ports) || security != "[no-new-privileges]" ||
            cap_drop != "[\"ALL\"]" || exposed == "null") {
            error = "holder security/port publication fields were not exact";
            return false;
        }
        ProcIdentity holder_identity{};
        ProcIdentity host_identity{};
        if (!proc_identity(holder_pid_, holder_identity, false) ||
            !container_netns_inode(holder_name_, holder_identity.netns) ||
            !proc_identity(getpid(), host_identity) ||
            holder_identity.netns == host_identity.netns ||
            holder_identity.start != holder_start_) {
            error = "holder PID/start-time/netns identity was not stable or distinct from host";
            return false;
        }
        std::string tcp;
        if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/tcp", tcp)) {
            error = "holder /proc/net/tcp was unavailable";
            return false;
        }
        std::string routes;
        if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/route", routes)) {
            error = "holder /proc/net/route was unavailable";
            return false;
        }
        u32 low_a = 0, high_a = 0, low_b = 0, high_b = 0;
        if (!parse_cidr(network_a_.subnet, low_a, high_a) ||
            !parse_cidr(network_b_.subnet, low_b, high_b)) {
            error = "holder route validation saw malformed subnet";
            return false;
        }
        const u32 mask_a = high_a ^ low_a;
        const u32 mask_b = high_b ^ low_b;
        bool route_a = false, route_b = false;
        std::istringstream route_lines(routes);
        std::string route_line;
        std::getline(route_lines, route_line);  // header
        while (std::getline(route_lines, route_line)) {
            std::istringstream route_fields(route_line);
            std::string iface, destination, gateway, flags, refs, use, metric, mask;
            if (!(route_fields >> iface >> destination >> gateway >> flags >> refs >> use >>
                  metric >> mask))
                continue;
            route_a = route_a || (destination == proc_hex(low_a) && mask == proc_mask_hex(mask_a));
            route_b = route_b || (destination == proc_hex(low_b) && mask == proc_mask_hex(mask_b));
        }
        if (!route_a || !route_b) {
            error = "holder routes did not contain both exact Docker-managed subnets";
            return false;
        }
        if (tcp.find(":0000") != std::string::npos) {
            // The selected port is checked by probe_port_absent below; this
            // branch only rejects an obviously malformed proc table.
        }
        if (point == FailurePoint::AfterTopologyVerified) return injected(error);
        return true;
    }

    bool probe_port_absent(u16 port, std::string& error) {
        std::string tcp;
        if (!read_file("/proc/" + std::to_string(holder_pid_) + "/net/tcp", tcp)) {
            error = "holder /proc/net/tcp read failed";
            return false;
        }
        std::ostringstream port_hex;
        port_hex << std::uppercase << std::setfill('0') << std::setw(4) << std::hex << port;
        std::istringstream lines(tcp);
        std::string line;
        while (std::getline(lines, line)) {
            std::istringstream fields(line);
            std::string index, local_endpoint;
            if (fields >> index >> local_endpoint) {
                const size_t colon = local_endpoint.find(':');
                if (colon != std::string::npos &&
                    local_endpoint.substr(colon + 1) == port_hex.str()) {
                    error = "selected probe port appeared in holder /proc/net/tcp";
                    return false;
                }
            }
        }
        return true;
    }

    bool probe_refused(const std::string& address, u16 port, std::string& error) {
        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            error = "probe socket creation failed";
            return false;
        }
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port);
        if (inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) != 1 ||
            connect(fd, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == 0) {
            close(fd);
            error = "probe unexpectedly connected";
            return false;
        }
        int connect_error = errno;
        if (connect_error == EINPROGRESS) {
            pollfd descriptor{fd, POLLOUT, 0};
            const int ready = poll(&descriptor, 1, 2000);
            if (ready <= 0) {
                close(fd);
                error = ready == 0 ? "probe timed out" : "probe poll failed";
                return false;
            }
            socklen_t length = sizeof(connect_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &connect_error, &length) != 0) {
                close(fd);
                error = "probe SO_ERROR failed";
                return false;
            }
        }
        close(fd);
        if (connect_error != ECONNREFUSED) {
            error =
                "probe returned errno " + std::to_string(connect_error) + ", expected ECONNREFUSED";
            return false;
        }
        return true;
    }

    bool cleanup(std::string& error) {
        bool success = true;
        if (holder_exists_) {
            if (!validate_holder(error))
                success = false;
            else {
                CommandResult result;
                if (!run_command({"docker", "rm", "-f", holder_name_}, result) ||
                    !exited_zero(result)) {
                    error = "holder cleanup failed: " + trim(result.output);
                    success = false;
                } else {
                    holder_exists_ = false;
                }
            }
        }
        if (network_b_.exists) {
            if (network_b_.id.empty()) {
                if (!timeout_recovery_ || !discover_network(network_b_)) {
                    error = "refusing network B cleanup without recorded identity";
                    success = false;
                }
            }
            if (!verify_network(network_b_, error))
                success = false;
            else if (!remove_network(network_b_, error))
                success = false;
        }
        if (network_a_.exists) {
            if (network_a_.id.empty()) {
                if (!timeout_recovery_ || !discover_network(network_a_)) {
                    error = "refusing network A cleanup without recorded identity";
                    success = false;
                }
            }
            if (!verify_network(network_a_, error))
                success = false;
            else if (!remove_network(network_a_, error))
                success = false;
        }
        return success;
    }

private:
    bool injected(std::string& error) {
        error = "injected boundary failure";
        return false;
    }

    bool create_network(Network& network, FailurePoint point, std::string& error) {
        CommandResult result;
        const bool reported_timeout =
            point == FailurePoint::AfterNetworkACreationReportedTimeout && &network == &network_a_;
        if (!run_command({"docker",
                          "network",
                          "create",
                          "--driver",
                          "bridge",
                          "--label",
                          kStageLabel,
                          "--label",
                          "rut.token=" + token_,
                          network.name},
                         result,
                         15000,
                         reported_timeout) ||
            !exited_zero(result)) {
            error = "network creation failed: " + trim(result.output);
            if (reported_timeout && result.timed_out) {
                timeout_recovery_ = true;
                network.exists = true;
                if (!discover_network(network))
                    error += "; timeout recovery discovery failed";
                else
                    error = "injected actual-success/reported-timeout; recovered exact network ID";
            }
            return false;
        }
        network.exists = true;
        network.id = trim(result.output);
        if (network.id.empty() || network.id.find('\n') != std::string::npos) {
            error = "network creation returned no exact ID";
            return false;
        }
        if (point == FailurePoint::AfterNetworkACreated && &network == &network_a_) {
            return injected(error);
        }
        if (point == FailurePoint::AfterNetworkBCreated && &network == &network_b_) {
            return injected(error);
        }
        return true;
    }

    bool verify_network(Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{.Id}} {{.Name}} {{.Driver}} {{.Scope}} {{(index .IPAM.Config "
                          "0).Subnet}} {{(index .IPAM.Config 0).Gateway}} {{index .Labels "
                          "\"rut.stage\"}} {{index .Labels \"rut.token\"}}",
                          network.name},
                         result) ||
            !exited_zero(result)) {
            error = "network inspection failed: " + trim(result.output);
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string id, name, driver, scope, stage, token;
        if (!(fields >> id >> name >> driver >> scope >> network.subnet >> network.gateway >>
              stage >> token) ||
            id.empty() || id != network.id || name != network.name || driver != "bridge" ||
            scope != "local" || stage != "358-stage2a2" || token != token_ ||
            network.subnet.empty() || network.gateway.empty() ||
            !valid_gateway(network.subnet, network.gateway)) {
            error = "network ID/name/driver/scope/IPAM/labels were not exact";
            return false;
        }
        return true;
    }

    bool discover_network(Network& network) {
        CommandResult result;
        if (!run_command({"docker", "network", "inspect", "-f", "{{.Id}}", network.name}, result) ||
            !exited_zero(result))
            return false;
        network.id = trim(result.output);
        network.exists = !network.id.empty() && network.id.find('\n') == std::string::npos;
        return network.exists;
    }

    bool discover_holder() {
        CommandResult result;
        if (!run_command({"docker", "inspect", "-f", "{{.Id}} {{.State.Pid}}", holder_name_},
                         result) ||
            !exited_zero(result))
            return false;
        std::istringstream fields(trim(result.output));
        std::string id;
        if (!(fields >> id >> holder_pid_) || id.empty()) return false;
        holder_id_ = id;
        holder_exists_ = true;
        if (holder_pid_ <= 0) return true;
        ProcIdentity identity{};
        if (proc_identity(holder_pid_, identity, false)) holder_start_ = identity.start;
        return true;
    }

    bool validate_holder(std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "inspect",
                          "-f",
                          "{{.Id}} {{.Name}} {{index .Config.Labels \"rut.stage\"}} {{index "
                          ".Config.Labels \"rut.token\"}}",
                          holder_name_},
                         result) ||
            !exited_zero(result)) {
            error = "holder disappeared before verified cleanup";
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string id, name, stage, token;
        if (!(fields >> id >> name >> stage >> token)) {
            error = "holder identity inspection was malformed";
            return false;
        }
        if (holder_id_.empty() && timeout_recovery_) holder_id_ = id;
        if (holder_id_.empty()) {
            error = "refusing holder deletion without recorded identity";
            return false;
        }
        if (id != holder_id_ || name != "/" + holder_name_ || stage != "358-stage2a2" ||
            token != token_) {
            error = "refusing holder deletion because exact identity/labels changed";
            return false;
        }
        return true;
    }

    bool remove_network(Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker", "network", "rm", network.name}, result) ||
            !exited_zero(result)) {
            error = "network cleanup failed for " + network.name + ": " + trim(result.output);
            return false;
        }
        network.exists = false;
        return true;
    }

    bool verify_membership(const Network& network, std::string& error) {
        CommandResult result;
        if (!run_command({"docker",
                          "network",
                          "inspect",
                          "-f",
                          "{{.Id}}|{{.Name}} {{range $id,$v := "
                          ".Containers}}{{$id}}|{{$v.Name}}|{{$v.IPv4Address}} {{end}}",
                          network.name},
                         result) ||
            !exited_zero(result)) {
            error = "network/container membership was not bidirectionally verified";
            return false;
        }
        std::istringstream fields(trim(result.output));
        std::string network_header;
        std::vector<std::string> header_fields;
        if (!(fields >> network_header) || !split_exact(network_header, '|', 2, header_fields) ||
            header_fields[0] != network.id || header_fields[1] != network.name) {
            error = "network identity was not exact during reciprocal membership verification";
            return false;
        }
        std::string member;
        size_t count = 0;
        const size_t slash = network.subnet.find('/');
        const std::string expected_address =
            network.name == network_a_.name ? positive_ip_ : guard_ip_;
        if (slash == std::string::npos) {
            error = "network reciprocal subnet was malformed";
            return false;
        }
        while (fields >> member) {
            std::vector<std::string> member_fields;
            if (!split_exact(member, '|', 3, member_fields) || member_fields[0] != holder_id_ ||
                member_fields[1] != holder_name_ ||
                member_fields[2] != expected_address + network.subnet.substr(slash)) {
                error = "network reciprocal endpoint association was not exact";
                return false;
            }
            ++count;
        }
        if (count != 1) {
            error = "network had unexpected container membership count";
            return false;
        }
        return true;
    }

    std::string token_;
    std::string holder_name_;
    Network network_a_;
    Network network_b_;
    std::string positive_ip_;
    std::string guard_ip_;
    std::string holder_id_;
    pid_t holder_pid_ = -1;
    u64 holder_start_ = 0;
    bool holder_exists_ = false;
    bool timeout_recovery_ = false;
};

static bool write_manifest(const TempDir& temp, const Fixture& fixture) {
    const int fd = open(temp.manifest.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const std::string contents =
        "token=" + fixture.token() + "\nnetwork_a=" + fixture.network_a().name +
        "\nnetwork_b=" + fixture.network_b().name + "\nholder=" + fixture.holder_name() + "\n";
    size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = write(fd, contents.data() + offset, contents.size() - offset);
        if (count > 0)
            offset += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else {
            close(fd);
            return false;
        }
    }
    return close(fd) == 0;
}

static bool preflight(const Fixture& fixture, std::string& error) {
#ifndef __linux__
    error = "Linux is required";
    return false;
#else
    CommandResult result;
    if (!run_command({"docker", "info"}, result) || !exited_zero(result)) {
        error = "Docker daemon/permissions unavailable: " + trim(result.output);
        return false;
    }
    if (!run_command({"docker", "image", "inspect", RUT_PINNED_NGINX_IMAGE}, result) ||
        !exited_zero(result)) {
        error = "exact pinned image unavailable: " + trim(result.output);
        return false;
    }
    if (access("/sbin/ip", X_OK) != 0 && access("/usr/sbin/ip", X_OK) != 0 &&
        access("/bin/ip", X_OK) != 0 && access("/usr/bin/ip", X_OK) != 0) {
        error = "host ip capability is unavailable";
        return false;
    }
    for (const std::string& name :
         {fixture.network_a().name, fixture.network_b().name, fixture.holder_name()}) {
        if (run_command({"docker", "inspect", name}, result) && exited_zero(result)) {
            error = "exact target name already exists: " + name;
            return false;
        }
    }
    return true;
#endif
}

}  // namespace

bool audit_zero_residue(const std::string& token,
                        const std::string& network_a_name,
                        const std::string& network_b_name,
                        const std::string& holder_name,
                        std::string& error) {
    CommandResult result;
    for (const std::string& name : {network_a_name, network_b_name, holder_name}) {
        if (run_command({"docker", "inspect", name}, result) && exited_zero(result)) {
            error =
                "exact expected resource name remains (including possible ownership collision): " +
                name;
            return false;
        }
    }
    if (!run_command({"docker", "ps", "-aq", "--filter", "label=rut.token=" + token}, result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "labeled container residue remains";
        return false;
    }
    if (!run_command({"docker", "network", "ls", "-q", "--filter", "label=rut.token=" + token},
                     result) ||
        !exited_zero(result) || !trim(result.output).empty()) {
        error = "labeled network residue remains";
        return false;
    }
    return true;
}

bool pure_validation_self_checks(std::string& error) {
    u32 low = 0, high = 0;
    if (parse_cidr("10.0.0.1/24", low, high) || parse_cidr("10.0.0.0/31", low, high) ||
        parse_cidr("10.0.0.0/nope", low, high) || parse_cidr("10.0.0.0/", low, high)) {
        error = "malformed/prefix-edge CIDR validation was accepted";
        return false;
    }
    if (valid_gateway("10.0.0.0/24", "10.0.1.1") || valid_gateway("10.0.0.0/24", "10.0.0.0") ||
        valid_gateway("10.0.0.0/24", "10.0.0.255") || valid_gateway("127.0.0.0/24", "127.0.0.1")) {
        error = "invalid/out-of-subnet/network/broadcast/loopback gateway was accepted";
        return false;
    }
    if (!valid_gateway("10.0.0.0/24", "10.0.0.1")) {
        error = "valid gateway was rejected";
        return false;
    }
    std::string selected;
    if (!choose_address("192.0.2.0/30", "192.0.2.1", selected) || selected != "192.0.2.2" ||
        !choose_address("192.0.2.0/30", "192.0.2.2", selected) || selected != "192.0.2.1") {
        error = "usable /30 address selection did not consider low+1 and the higher usable address";
        return false;
    }
    if (no_published_ports("{\"80/tcp\":[]}", "null") ||
        no_published_ports("{}", "{\"80/tcp\":[{\"HostPort\":\"80\"}]}") ||
        !no_published_ports("{}", "{\"80/tcp\":null}")) {
        error = "published-port mutation validation was not causal";
        return false;
    }
    const Endpoint a{"a", "id-a", "10.0.0.2", "10.0.0.2/24", "10.0.0.1"};
    const Endpoint b{"b", "id-b", "10.0.1.2", "10.0.1.2/24", "10.0.1.1"};
    std::vector<Endpoint> expected{a, b};
    std::vector<Endpoint> swapped{b, a};
    std::swap(swapped[0].network_id, swapped[1].network_id);
    if (endpoint_set_equal(expected, swapped)) {
        error = "cross-swapped endpoint validation mutation was accepted";
        return false;
    }
    return true;
}

bool runner_descendant_self_check(std::string& error) {
    CommandResult result;
    DescendantProbe probe;
    if (!run_command({"/bin/true"}, result, 15000, false, true, &probe) ||
        !result.process_group_verified || !probe.marker_received || !probe.same_pgid ||
        !probe.alive_before_cleanup || probe.pid <= 0 || probe.pgid <= 0 ||
        !process_group_gone(probe.pgid) || kill(probe.pid, 0) == 0) {
        error = "runner descendant marker/PID/PGID handshake or cleanup proof failed";
        return false;
    }
    return true;
}

RunResult run(FailurePoint failure_point) {
    RunResult result;
    std::string token;
    if (!high_entropy_token(token)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = "high-entropy token generation unavailable";
        result.success = false;
        return result;
    }
    Fixture fixture(token);
    const auto audit = [&](std::string& error) {
        return audit_zero_residue(token,
                                  fixture.network_a().name,
                                  fixture.network_b().name,
                                  fixture.holder_name(),
                                  error);
    };
    TempDir temp;
    if (!temp.create() || !write_manifest(temp, fixture)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe = true;
        result.error = "parent-owned temporary manifest creation failed";
        return result;
    }
    if (!preflight(fixture, result.error)) {
        result.prerequisite_failure = true;
        result.optional_skip_safe =
            result.error.find("exact target name already exists") == std::string::npos;
        result.success = false;
        return result;
    }
    if (!fixture.create_networks(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterNetworkACreated &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkAVerified &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkBCreated &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkBVerified &&
         result.error == "injected boundary failure") ||
        (failure_point == FailurePoint::AfterNetworkACreationReportedTimeout &&
         result.error.find("injected actual-success/reported-timeout") != std::string::npos) ||
        (failure_point == FailurePoint::AfterBothIpamVerified &&
         result.error == "injected boundary failure")) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    if (!fixture.create_holder(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterHolderCreated &&
         result.error == "injected boundary failure")) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    if (!fixture.attach_holder(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterHolderAttachedA &&
         result.error.find("injected") != std::string::npos) ||
        (failure_point == FailurePoint::AfterHolderAttachedB &&
         result.error.find("injected") != std::string::npos)) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    if (!fixture.verify_topology(failure_point, result.error) ||
        (failure_point == FailurePoint::AfterTopologyVerified &&
         result.error.find("injected") != std::string::npos)) {
        if (!fixture.cleanup(result.error)) result.prerequisite_failure = false;
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = failure_point != FailurePoint::None &&
                         result.error.find("injected") != std::string::npos;
        return result;
    }
    static constexpr u16 kProbePort = 41857;
    if (!fixture.probe_port_absent(kProbePort, result.error) ||
        !fixture.probe_refused(fixture.positive_ip(), kProbePort, result.error)) {
        fixture.cleanup(result.error);
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = false;
        return result;
    }
    if (failure_point == FailurePoint::AfterFirstProbe) {
        result.error = "injected boundary failure";
        if (!fixture.cleanup(result.error)) {
            result.success = false;
            return result;
        }
        std::string residue_error;
        if (!audit(residue_error)) {
            result.error += "; " + residue_error;
            result.success = false;
            return result;
        }
        result.success = true;
        return result;
    }
    if (!fixture.probe_refused(fixture.guard_ip(), kProbePort, result.error)) {
        fixture.cleanup(result.error);
        std::string residue_error;
        if (!audit(residue_error)) result.error += "; " + residue_error;
        result.success = false;
        return result;
    }
    if (!fixture.cleanup(result.error)) {
        result.success = false;
        return result;
    }
    std::string residue_error;
    if (!audit(residue_error)) {
        result.error = residue_error;
        result.success = false;
        return result;
    }
    result.success = true;
    return result;
}

}  // namespace rut::test::ipv4_topology
