// Linux-only mechanism probe: identical TCP tunnel with copy or splice pumps.
// No HTTP routing, TLS, policy, or production-runtime integration.
#include "rut/common/ebpf_handoff_bytecode.h"
#include "rut/common/types.h"
#include "rut/runtime/ebpf_handoff.h"
#include "rut/runtime/slice_pool.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
using namespace rut;
constexpr u32 kConnections = 512;
constexpr u32 kBatch = 64 * 1024;
volatile sig_atomic_t stopping = 0;
void stop(int) {
    stopping = 1;
}

struct Direction {
    u8* bytes = nullptr;
    int pipe_fds[2] = {-1, -1};
    u32 pending = 0;
    u32 offset = 0;
    bool eof = false;
    bool shutdown_sent = false;
};
struct Pair {
    int fds[2] = {-1, -1};
    Direction directions[2]{};
    u32 generation = 0;
    bool active = false;
    bool connected = false;
    bool enrolled = false;
    bool draining_output = false;
    u64 source_cookie = 0;
    u64 target_cookie = 0;
    u64 output_start = 0;
};
struct Counters {
    u64 accepts = 0;
    u64 reads = 0;
    u64 writes = 0;
    u64 read_bytes = 0;
    u64 written_bytes = 0;
    u64 waits = 0;
    u64 events = 0;
    u64 setup_failures = 0;
    u64 io_failures = 0;
    u64 kernel_bytes = 0;
    u64 retirement_failures = 0;
    u64 admission_peer_closes = 0;
};
Pair pairs[kConnections];
SlicePool pool;
Counters counters;
int poll_fd = -1;
bool use_splice = false;
bool use_ebpf = false;
EbpfHandoffKernel kernel;

void close_pair(Pair& pair) {
    if (pair.enrolled) {
        ebpf::HandoffState state{};
        if (kernel.inspect(pair.source_cookie, state)) counters.kernel_bytes += state.control;
        if (!kernel.retire(pair.source_cookie, pair.target_cookie)) ++counters.retirement_failures;
    }
    for (u32 side = 0; side < 2; ++side) {
        if (pair.fds[side] >= 0) {
            epoll_ctl(poll_fd, EPOLL_CTL_DEL, pair.fds[side], nullptr);
            close(pair.fds[side]);
            pair.fds[side] = -1;
        }
        auto& dir = pair.directions[side];
        for (int& fd : dir.pipe_fds) {
            if (fd >= 0) close(fd);
            fd = -1;
        }
        if (dir.bytes) pool.free_written(dir.bytes, kBatch);
        dir = {};
    }
    pair.active = pair.connected = false;
    pair.enrolled = pair.draining_output = false;
}

// Nonblocking: a pending pipe/buffer is drained before accepting more input.
// EOF only shuts down the peer's write side after all queued bytes are sent.
bool pump(Pair& pair, u32 side) {
    auto& dir = pair.directions[side];
    const int kFrom = pair.fds[side];
    const int kTo = pair.fds[1u - side];
    if (use_ebpf && side == 1) {
        char byte;
        if (!dir.eof) {
            const ssize_t kN = recv(kFrom, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
            if (kN < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return true;
            if (kN != 0) {
                ++counters.io_failures;
                return false;
            }
            dir.eof = true;
        }
        ebpf::HandoffState state{};
        u64 progress = 0;
        if (!kernel.inspect(pair.source_cookie, state) || state.failed ||
            !EbpfHandoffKernel::output_progress(kTo, progress)) {
            ++counters.io_failures;
            return false;
        }
        pair.draining_output = progress < pair.output_start + state.control;
        if (!pair.draining_output && !dir.shutdown_sent) {
            if (shutdown(kTo, SHUT_WR) != 0 && errno != ENOTCONN) return false;
            dir.shutdown_sent = true;
        }
        return true;
    }
    for (u32 turn = 0; turn < 16; ++turn) {
        if (dir.pending != 0) {
            ++counters.writes;
            const ssize_t kN =
                use_splice
                    ? splice(dir.pipe_fds[0], nullptr, kTo, nullptr, dir.pending, SPLICE_F_NONBLOCK)
                    : send(kTo, dir.bytes + dir.offset, dir.pending, MSG_NOSIGNAL);
            if (kN < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
                ++counters.io_failures;
                return false;
            }
            if (kN == 0) return false;
            dir.pending -= static_cast<u32>(kN);
            dir.offset += static_cast<u32>(kN);
            counters.written_bytes += static_cast<u64>(kN);
            if (dir.pending != 0) continue;
            dir.offset = 0;
        }
        if (dir.eof) {
            if (!dir.shutdown_sent) {
                if (shutdown(kTo, SHUT_WR) != 0 && errno != ENOTCONN) return false;
                dir.shutdown_sent = true;
            }
            return true;
        }
        ++counters.reads;
        const ssize_t kN =
            use_splice ? splice(kFrom, nullptr, dir.pipe_fds[1], nullptr, kBatch, SPLICE_F_NONBLOCK)
                       : recv(kFrom, dir.bytes, kBatch, 0);
        if (kN < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            ++counters.io_failures;
            return false;
        }
        if (kN == 0) {
            dir.eof = true;
            continue;
        }
        dir.pending = static_cast<u32>(kN);
        counters.read_bytes += static_cast<u64>(kN);
    }
    return true;
}

bool arm(Pair& pair, u32 index, u32 side, int operation) {
    epoll_event event{};
    if (!pair.connected) {
        event.events = side == 1 ? EPOLLOUT : 0;
    } else {
        const auto& in = pair.directions[side];
        const auto& out = pair.directions[1u - side];
        if (!in.eof && in.pending == 0) event.events |= EPOLLIN;
        if (out.pending != 0) event.events |= EPOLLOUT;
        // Avoid repeatedly waking on a half-close while the peer is blocked.
        if (!in.eof && in.pending == 0) event.events |= EPOLLRDHUP;
    }
    event.data.u64 = (static_cast<u64>(pair.generation) << 32u) | (index * 2u + side + 1u);
    return epoll_ctl(poll_fd, operation, pair.fds[side], &event) == 0;
}

bool accept_pair(int client, u16 origin_port) {
    u32 index = 0;
    while (index < kConnections && pairs[index].active) ++index;
    if (index == kConnections) {
        close(client);
        return false;
    }
    auto& pair = pairs[index];
    pair.active = true;
    if (++pair.generation == 0) ++pair.generation;
    pair.fds[0] = client;
    pair.fds[1] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (pair.fds[1] < 0) return false;
    const int kOne = 1;
    for (const int kFd : pair.fds)
        if (setsockopt(kFd, IPPROTO_TCP, TCP_NODELAY, &kOne, sizeof(kOne)) != 0) return false;
    for (auto& dir : pair.directions) {
        if (use_splice) {
            if (pipe2(dir.pipe_fds, O_NONBLOCK | O_CLOEXEC) != 0 ||
                fcntl(dir.pipe_fds[1], F_SETPIPE_SZ, kBatch) < static_cast<int>(kBatch))
                return false;
        } else {
            dir.bytes = pool.alloc_bulk();
            if (!dir.bytes) return false;
        }
    }
    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    upstream.sin_port = htons(origin_port);
    if (connect(pair.fds[1], reinterpret_cast<sockaddr*>(&upstream), sizeof(upstream)) == 0)
        pair.connected = true;
    else if (errno != EINPROGRESS)
        return false;
    return arm(pair, index, 0, EPOLL_CTL_ADD) && arm(pair, index, 1, EPOLL_CTL_ADD);
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 4 || (strcmp(argv[1], "copy") != 0 && strcmp(argv[1], "splice") != 0 &&
                      strcmp(argv[1], "ebpf") != 0)) {
        fprintf(stderr, "usage: bench_kernel_relay copy|splice|ebpf FRONT_PORT ORIGIN_PORT\n");
        return 2;
    }
    use_splice = strcmp(argv[1], "splice") == 0;
    use_ebpf = strcmp(argv[1], "ebpf") == 0;
    char* end = nullptr;
    const long kFront = strtol(argv[2], &end, 10);
    if (!end || *end != '\0' || kFront < 1024 || kFront > 65535) return 2;
    const long kOrigin = strtol(argv[3], &end, 10);
    if (!end || *end != '\0' || kOrigin < 1024 || kOrigin > 65535 || kOrigin == kFront) return 2;
    if (!use_splice && !pool.init(1, 0, 0, 2 * kConnections)) return 2;
    if (use_ebpf) {
        const char* stage = kernel.init(kConnections, true, nullptr, true);
        if (stage) {
            fprintf(stderr,
                    "eBPF tunnel %s: errno=%d: %s\n%s\n",
                    stage,
                    errno,
                    strerror(errno),
                    kernel.verifier);
            return 1;
        }
    }
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    signal(SIGPIPE, SIG_IGN);
    poll_fd = epoll_create1(EPOLL_CLOEXEC);
    const int kListener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (poll_fd < 0 || kListener < 0) return 2;
    const int kOne = 1;
    // POSIX public socket.h provides these macros; avoid glibc-private headers.
    // NOLINTNEXTLINE(misc-include-cleaner)
    if (setsockopt(kListener, SOL_SOCKET, SO_REUSEADDR, &kOne, sizeof(kOne)) != 0) return 2;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(static_cast<u16>(kFront));
    if (bind(kListener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(kListener, 1024) != 0)
        return 2;
    epoll_event listener_event{};
    listener_event.events = EPOLLIN;
    if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, kListener, &listener_event) != 0) return 2;
    fprintf(stderr,
            "READY mode=%s batch=%u capacity=%u tcp_nodelay=1\n",
            argv[1],
            kBatch,
            kConnections);
    fflush(stderr);
    while (!stopping) {
        epoll_event events[256]{};
        ++counters.waits;
        bool draining = false;
        for (const auto& pair : pairs) draining = draining || pair.draining_output;
        const int kCount = epoll_wait(poll_fd, events, 256, draining ? 1 : 100);
        if (kCount < 0) {
            if (errno == EINTR) continue;
            return 2;
        }
        counters.events += static_cast<u64>(kCount);
        for (int i = 0; i < kCount; ++i) {
            const u64 kToken = events[i].data.u64;
            if (kToken == 0) {
                for (;;) {
                    const int kClient =
                        accept4(kListener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (kClient < 0) {
                        if (errno == EINTR) continue;
                        if (errno != EAGAIN && errno != EWOULDBLOCK) ++counters.setup_failures;
                        break;
                    }
                    ++counters.accepts;
                    if (!accept_pair(kClient, static_cast<u16>(kOrigin))) {
                        ++counters.setup_failures;
                        for (auto& pair : pairs)
                            if (pair.active && pair.fds[0] == kClient) close_pair(pair);
                    }
                }
                continue;
            }
            const u32 kSlot = static_cast<u32>(kToken) - 1u;
            const u32 kIndex = kSlot / 2u;
            if (kIndex >= kConnections) return 2;
            auto& pair = pairs[kIndex];
            if (!pair.active || pair.generation != static_cast<u32>(kToken >> 32u)) continue;
            if (!pair.connected) {
                // EPOLLHUP is reported even for a zero interest mask. A client
                // can close a readiness probe before the upstream establishes;
                // do not attempt to enroll that still-connecting source socket.
                if ((kSlot & 1u) == 0) {
                    close_pair(pair);
                    continue;
                }
                int error = 0;
                socklen_t length = sizeof(error);
                // NOLINTNEXTLINE(misc-include-cleaner)
                if (getsockopt(pair.fds[1], SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
                    error != 0) {
                    ++counters.setup_failures;
                    close_pair(pair);
                    continue;
                }
                pair.connected = true;
            }
            if (use_ebpf && !pair.enrolled) {
                char first;
                const ssize_t kPeek = recv(pair.fds[0], &first, 1, MSG_PEEK | MSG_DONTWAIT);
                if (kPeek == 0 ||
                    (kPeek < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    close_pair(pair);  // peer closed before sending a request
                    continue;
                }
                if (!EbpfHandoffKernel::output_progress(pair.fds[0], pair.output_start) ||
                    !kernel.enroll(pair.fds[1],
                                   pair.fds[0],
                                   pair.source_cookie,
                                   pair.target_cookie,
                                   kIndex,
                                   pair.generation)) {
                    const int kError = errno;
                    // A peer can disappear between the first peek and map
                    // insertion. Keep this distinct from setup failures; no
                    // request has reached the origin or kernel ownership yet.
                    const ssize_t kAfter = recv(pair.fds[0], &first, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (kAfter == 0 || (kAfter < 0 && (errno == ECONNRESET || errno == ENOTCONN))) {
                        ++counters.admission_peer_closes;
                        close_pair(pair);
                        continue;
                    }
                    fprintf(stderr, "enrollment failed: errno=%d slot=%u\n", kError, kIndex);
                    ++counters.setup_failures;
                    close_pair(pair);
                    continue;
                }
                pair.enrolled = true;
            }
            if (!pump(pair, 0) || !pump(pair, 1) ||
                (pair.directions[0].shutdown_sent && pair.directions[1].shutdown_sent) ||
                !arm(pair, kIndex, 0, EPOLL_CTL_MOD) || !arm(pair, kIndex, 1, EPOLL_CTL_MOD))
                close_pair(pair);
        }
        if (use_ebpf) {
            for (u32 index = 0; index < kConnections; ++index) {
                auto& pair = pairs[index];
                if (pair.active && pair.draining_output &&
                    (!pump(pair, 1) ||
                     (pair.directions[0].shutdown_sent && pair.directions[1].shutdown_sent) ||
                     !arm(pair, index, 0, EPOLL_CTL_MOD) || !arm(pair, index, 1, EPOLL_CTL_MOD)))
                    close_pair(pair);
            }
        }
    }
    for (auto& pair : pairs)
        if (pair.active) close_pair(pair);
    close(kListener);
    close(poll_fd);
    pool.destroy();
    kernel.destroy();
    fprintf(stderr,
            "COUNTERS {\"accepts\":%llu,\"reads\":%llu,\"writes\":%llu,"
            "\"read_bytes\":%llu,\"written_bytes\":%llu,\"waits\":%llu,\"events\":%llu,"
            "\"setup_failures\":%llu,\"io_failures\":%llu,\"kernel_bytes\":%llu,"
            "\"retirement_failures\":%llu,\"admission_peer_closes\":%llu}\n",
            static_cast<unsigned long long>(counters.accepts),
            static_cast<unsigned long long>(counters.reads),
            static_cast<unsigned long long>(counters.writes),
            static_cast<unsigned long long>(counters.read_bytes),
            static_cast<unsigned long long>(counters.written_bytes),
            static_cast<unsigned long long>(counters.waits),
            static_cast<unsigned long long>(counters.events),
            static_cast<unsigned long long>(counters.setup_failures),
            static_cast<unsigned long long>(counters.io_failures),
            static_cast<unsigned long long>(counters.kernel_bytes),
            static_cast<unsigned long long>(counters.retirement_failures),
            static_cast<unsigned long long>(counters.admission_peer_closes));
    return counters.setup_failures != 0 || counters.retirement_failures != 0 ? 1 : 0;
}
