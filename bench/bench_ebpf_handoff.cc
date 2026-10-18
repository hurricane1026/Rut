// Exercise permanent upstream enrollment and byte-accurate atomic ownership.
#include "rut/common/ebpf_bytecode.h"
#include "rut/common/ebpf_handoff_bytecode.h"
#include "rut/common/types.h"
#include "rut/runtime/ebpf_handoff.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>  // IWYU pragma: export
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>  // IWYU pragma: export
#include <sys/socket.h>    // IWYU pragma: export
#include <sys/time.h>      // IWYU pragma: export
#include <sys/types.h>
#include <time.h>  // IWYU pragma: export
#include <unistd.h>

using namespace rut;
// Use public POSIX headers above rather than glibc-private bits/asm headers.
// include-cleaner currently attributes these public types/macros to private
// implementation headers, even when the public umbrella is included directly.
// NOLINTBEGIN(misc-include-cleaner)
namespace {
struct Connection {
    int client = -1;
    int relay = -1;
    ~Connection() {
        if (client >= 0) close(client);
        if (relay >= 0) close(relay);
    }
    bool open() {
        int const kListener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (kListener < 0) return false;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        bool ok = bind(kListener, reinterpret_cast<sockaddr*>(&address), length) == 0 &&
                  listen(kListener, 1) == 0 &&
                  getsockname(kListener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
        if (ok) {
            client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            ok = client >= 0 && connect(client, reinterpret_cast<sockaddr*>(&address), length) == 0;
        }
        if (ok) relay = accept4(kListener, nullptr, nullptr, SOCK_CLOEXEC);
        close(kListener);
        if (!ok || relay < 0) return false;
        const int kSockets[] = {client, relay};
        for (const int kFd : kSockets) {
            const timeval kTimeout{5, 0};
            const int kOne = 1;
            if (setsockopt(kFd, SOL_SOCKET, SO_RCVTIMEO, &kTimeout, sizeof(kTimeout)) != 0 ||
                setsockopt(kFd, SOL_SOCKET, SO_SNDTIMEO, &kTimeout, sizeof(kTimeout)) != 0 ||
                setsockopt(kFd, IPPROTO_TCP, TCP_NODELAY, &kOne, sizeof(kOne)) != 0)
                return false;
        }
        return true;
    }
};
bool send_all(int fd, const char* bytes, size_t size) {
    while (size) {
        ssize_t const kN = send(fd, bytes, size, MSG_NOSIGNAL);
        if (kN < 0 && errno == EINTR) continue;
        if (kN <= 0) return false;
        bytes += kN;
        size -= static_cast<size_t>(kN);
    }
    return true;
}
bool read_exact(int fd, char* bytes, u32 length) {
    u32 read = 0;
    while (read < length) {
        const ssize_t kN = recv(fd, bytes + read, length - read, MSG_WAITALL);
        if (kN < 0 && errno == EINTR) continue;
        if (kN <= 0) {
            fprintf(stderr, "exact recv: %u/%u stopped %zd errno %d\n", read, length, kN, errno);
            return false;
        }
        read += static_cast<u32>(kN);
    }
    return true;
}
u64 now_ns() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<u64>(now.tv_sec) * 1000000000u + static_cast<u64>(now.tv_nsec);
}
u64 cpu_ns(const rusage& usage) {
    return static_cast<u64>(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000000000ull +
           static_cast<u64>(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) * 1000ull;
}
struct ThreadMeasurement {
    u64& cpu;
    rusage before{};
    explicit ThreadMeasurement(u64& value) : cpu(value) { getrusage(RUSAGE_THREAD, &before); }
    ~ThreadMeasurement() {
        rusage after{};
        getrusage(RUSAGE_THREAD, &after);
        cpu = cpu_ns(after) - cpu_ns(before);
    }
};
u8 payload(u32 offset) {
    return static_cast<u8>((offset * 131u + offset / 4096u) % 251u);
}
struct Writer {
    int fd;
    u32 size;
    u32 prequeue;
    u32 delay;
    const char* header;
    bool coalesced_tail = false;
    bool ok = false;
    u32 chunk_bytes = 4096;
    u64 cpu = 0;
};
void* write_response(void* argument) {
    auto& writer = *static_cast<Writer*>(argument);
    const ThreadMeasurement kMeasurement(writer.cpu);
    char initial[8192];
    const u32 kHeaderSize = static_cast<u32>(strlen(writer.header));
    memcpy(initial, writer.header, kHeaderSize);
    for (u32 i = 0; i < writer.prequeue; ++i)
        initial[kHeaderSize + i] = static_cast<char>(payload(i));
    if (!send_all(writer.fd, initial, kHeaderSize + writer.prequeue)) return nullptr;
    if (writer.delay) usleep(writer.delay);
    constexpr char kSuccessor[] = "next-response-1234";
    char block[65536 + sizeof(kSuccessor) - 1];
    for (u32 offset = writer.prequeue; offset < writer.size;) {
        const u32 kCount =
            writer.size - offset < writer.chunk_bytes ? writer.size - offset : writer.chunk_bytes;
        for (u32 i = 0; i < kCount; ++i) block[i] = static_cast<char>(payload(offset + i));
        u32 send_size = kCount;
        if (writer.coalesced_tail && offset + kCount == writer.size) {
            memcpy(block + kCount, kSuccessor, sizeof(kSuccessor) - 1);
            send_size += sizeof(kSuccessor) - 1;
        }
        if (!send_all(writer.fd, block, send_size)) return nullptr;
        offset += kCount;
    }
    if ((!writer.coalesced_tail || writer.prequeue == writer.size) &&
        !send_all(writer.fd, kSuccessor, sizeof(kSuccessor) - 1))
        return nullptr;
    writer.ok = shutdown(writer.fd, SHUT_WR) == 0;
    return nullptr;
}
struct Reader {
    int fd;
    u32 size;
    u32 delay;
    const char* header;
    bool ok = false;
    u32 chunk_bytes = 4096;
    u64 cpu = 0;
};
void* read_response(void* argument) {
    auto& reader = *static_cast<Reader*>(argument);
    const ThreadMeasurement kMeasurement(reader.cpu);
    if (reader.delay) usleep(reader.delay);
    char block[65536];
    const u32 kHeaderSize = static_cast<u32>(strlen(reader.header));
    if (!read_exact(reader.fd, block, kHeaderSize) ||
        memcmp(block, reader.header, kHeaderSize) != 0)
        return nullptr;
    for (u32 offset = 0; offset < reader.size;) {
        const u32 kCount =
            reader.size - offset < reader.chunk_bytes ? reader.size - offset : reader.chunk_bytes;
        const ssize_t kReceived = recv(reader.fd, block, kCount, 0);
        if (kReceived < 0 && errno == EINTR) continue;
        if (kReceived <= 0) return nullptr;
        for (ssize_t i = 0; i < kReceived; ++i)
            if (static_cast<u8>(block[i]) != payload(offset + static_cast<u32>(i))) {
                fprintf(stderr, "response mismatch at %u\n", offset + static_cast<u32>(i));
                return nullptr;
            }
        offset += static_cast<u32>(kReceived);
    }
    reader.ok = true;
    return nullptr;
}
bool number(const char* text, u32& out) {
    if (!*text) return false;
    out = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || out > (0xffffffffu - (*text - '0')) / 10u) return false;
        out = out * 10u + static_cast<u32>(*text - '0');
    }
    return true;
}
bool load_export(const char* prefix, const char* suffix, void* out, u32 size) {
    char path[4096];
    const int kLength = snprintf(path, sizeof(path), "%s.%s", prefix, suffix);
    if (kLength < 0 || static_cast<u32>(kLength) >= sizeof(path)) return false;
    const int kFd = open(path, O_RDONLY | O_CLOEXEC);
    if (kFd < 0) return false;
    auto* cursor = static_cast<u8*>(out);
    bool ok = true;
    while (size) {
        const ssize_t kN = read(kFd, cursor, size);
        if (kN < 0 && errno == EINTR) continue;
        if (kN <= 0) {
            ok = false;
            break;
        }
        cursor += kN;
        size -= static_cast<u32>(kN);
    }
    char extra = 0;
    ssize_t n;
    do {
        n = read(kFd, &extra, 1);
    } while (n < 0 && errno == EINTR);
    ok = ok && n == 0;
    close(kFd);
    return ok;
}
bool control_selftest(EbpfHandoffKernel& kernel) {
    constexpr u64 kCookie = ~u64{1};
    ebpf::HandoffState state{};
    state.control = 17;
    if (!EbpfHandoffKernel::update(kernel.fds[EbpfHandoffKernel::State], &kCookie, &state))
        return false;
    const u64 kDesired = (static_cast<u64>(ebpf::kHandoffOwned | 4096u) << 32u) | 17u;
    if (kernel.run_command({kCookie, 16, kDesired}) != EbpfHandoffKernel::Result::Retry ||
        !kernel.inspect(kCookie, state) || state.control != 17)
        return false;
    if (kernel.run_command({kCookie, 17, kDesired}) != EbpfHandoffKernel::Result::Committed ||
        kernel.run_command({kCookie, 17, kDesired}) != EbpfHandoffKernel::Result::Retry ||
        !kernel.inspect(kCookie, state) || state.control != kDesired)
        return false;
    state.failed = 1;
    if (!EbpfHandoffKernel::update(kernel.fds[EbpfHandoffKernel::State], &kCookie, &state) ||
        kernel.run_command({kCookie, kDesired, 17}) != EbpfHandoffKernel::Result::Retry ||
        kernel.publish_limit(kCookie, 100) != EbpfHandoffKernel::Result::Retry ||
        !kernel.inspect(kCookie, state) || state.control != kDesired || state.pass_limit)
        return false;
    if (!EbpfHandoffKernel::remove(kernel.fds[EbpfHandoffKernel::State], &kCookie)) return false;
    Connection source, target;
    u64 source_cookie = 0, target_cookie = 0;
    if (!source.open() || !target.open() || !EbpfHandoffKernel::cookie(source.relay, source_cookie))
        return false;
    state = {};
    state.control = 19;
    if (!EbpfHandoffKernel::update(kernel.fds[EbpfHandoffKernel::State], &source_cookie, &state))
        return false;
    if (kernel.enroll(source.relay, target.relay, source_cookie, target_cookie) ||
        !kernel.inspect(source_cookie, state) || state.control != 19)
        return false;
    if (!EbpfHandoffKernel::remove(kernel.fds[EbpfHandoffKernel::State], &source_cookie) ||
        !kernel.enroll(source.relay, target.relay, source_cookie, target_cookie))
        return false;
    // A duplicate target key must not delete the existing, successful enrollment.
    if (kernel.enroll(source.relay, target.relay, source_cookie, target_cookie)) return false;
    return kernel.inspect(source_cookie, state) && state.control == 0 &&
           kernel.retire(source_cookie, target_cookie);
}
bool notification_selftest(EbpfHandoffKernel& kernel) {
    // Reusing connection slots before draining old events can exhaust the ring.
    // Verify that overflow is visible in flow state, and that draining preserves
    // the old cookie/generation rather than confusing it with a reused slot.
    const u32 kCapacity = (kernel.ring_size - 1u) / 24u;
    u64 cookies[180]{};
    if (kCapacity + 3u > 180u) return false;
    for (u32 i = 0; i < kCapacity + 3u; ++i) {
        Connection source, target;
        u64 target_cookie = 0;
        if (!source.open() || !target.open() ||
            !kernel.enroll(source.relay, target.relay, cookies[i], target_cookie, 7, i + 1u) ||
            kernel.commit(cookies[i], 0, 1) != EbpfHandoffKernel::Result::Committed)
            return false;
        // A packet crossing the body end passes intact to userspace and emits
        // a terminal event. Receiving it proves the verdict helper has returned.
        char received[2];
        if (!send_all(source.client, "ab", 2) || !read_exact(source.relay, received, 2) ||
            memcmp(received, "ab", 2) != 0)
            return false;
        ebpf::HandoffState state{};
        if (!kernel.inspect(cookies[i], state) || ebpf::handoff_budget(state.control) ||
            state.tail_body != 1 || (state.failed != 0) != (i >= kCapacity))
            return false;
        if (i < kCapacity && (!send_all(source.client, "c", 1) ||
                              !read_exact(source.relay, received, 1) || received[0] != 'c'))
            return false;
        if (!kernel.retire(cookies[i], target_cookie)) return false;
    }
    ebpf::HandoffNotification event{};
    for (u32 i = 0; i < kCapacity; ++i) {
        if (!kernel.next_notification(event) || event.source_cookie != cookies[i] ||
            event.connection_id != 7 || event.generation != i + 1u)
            return false;
    }
    if (kernel.next_notification(event)) return false;
    // Redirect failure must also wake the consumer, once, with its flow identity.
    Connection source, target;
    u64 source_cookie = 0, target_cookie = 0;
    if (!source.open() || !target.open() ||
        !kernel.enroll(source.relay, target.relay, source_cookie, target_cookie, 7, 999) ||
        kernel.commit(source_cookie, 0, 1) != EbpfHandoffKernel::Result::Committed ||
        !EbpfHandoffKernel::remove(kernel.fds[EbpfHandoffKernel::Target], &target_cookie) ||
        !send_all(source.client, "a", 1))
        return false;
    pollfd ready{kernel.fds[EbpfHandoffKernel::Ring], POLLIN, 0};
    if (poll(&ready, 1, 5000) <= 0 || !kernel.next_notification(event) ||
        event.source_cookie != source_cookie || event.connection_id != 7 || event.generation != 999)
        return false;
    ebpf::HandoffState state{};
    if (!kernel.inspect(source_cookie, state) || !state.failed || kernel.next_notification(event))
        return false;
    return kernel.retire(source_cookie, target_cookie) &&
           kernel.retire(source_cookie, target_cookie);
}
}  // namespace
int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "";
    u32 size = 1048576, prequeue = 4096, delay = 10000, slow = 100000, chunk = 4096;
    bool packet = false, coalesced_tail = false, selftest = false, notifications = false;
    const char* export_prefix = nullptr;
    const bool kSplice = !strcmp(mode, "splice");
    bool valid =
        !strcmp(mode, "off") || !strcmp(mode, "auto") || !strcmp(mode, "required") || kSplice;
    for (int i = 2; valid && i < argc; ++i) {
        if (!strcmp(argv[i], "--handoff-prefix") && !export_prefix && i + 1 < argc) {
            export_prefix = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--packet-verdict") && !packet) {
            packet = true;
            continue;
        }
        if (!strcmp(argv[i], "--coalesced-tail") && !coalesced_tail) {
            coalesced_tail = true;
            continue;
        }
        if (!strcmp(argv[i], "--control-selftest") && !selftest) {
            selftest = true;
            continue;
        }
        if (!strcmp(argv[i], "--notification-selftest") && !notifications) {
            notifications = true;
            continue;
        }
        u32* value = nullptr;
        if (!strcmp(argv[i], "--size")) value = &size;
        if (!strcmp(argv[i], "--prequeue")) value = &prequeue;
        if (!strcmp(argv[i], "--delay-us")) value = &delay;
        if (!strcmp(argv[i], "--slow-reader-us")) value = &slow;
        if (!strcmp(argv[i], "--chunk-bytes")) value = &chunk;
        if (!value) {
            valid = false;
            break;
        }
        ++i;
        if (i >= argc || !number(argv[i], *value)) valid = false;
    }
    if (!valid || !size || size > ebpf::kHandoffBudgetMask || prequeue > 4096 || prequeue > size ||
        delay > 1000000 || slow > 1000000 || (notifications && (!packet || selftest)) ||
        (export_prefix && (!packet || !strcmp(mode, "off") || kSplice)) ||
        (kSplice && (selftest || notifications)) ||
        (chunk != 4096 && chunk != 16384 && chunk != 65536)) {
        fprintf(
            stderr,
            "usage: bench_ebpf_handoff off|auto|required|splice [--size N] [--prequeue 0..4096] "
            "[--delay-us N] [--slow-reader-us N] [--packet-verdict] [--coalesced-tail] "
            "[--control-selftest] [--notification-selftest] [--handoff-prefix PREFIX] "
            "[--chunk-bytes 4096|16384|65536]\n");
        return 2;
    }
    EbpfHandoffKernel kernel;
    const char* stage = nullptr;
    int unavailable = 0;
    bool available = strcmp(mode, "off") != 0 && !kSplice;
    ebpf::HandoffCode emitted{};
    if (export_prefix) {
        ebpf::emit_packet_handoff_bytecode(emitted);
        if (!load_export(export_prefix,
                         "packet-verdict.bpf",
                         emitted.verdict,
                         emitted.verdict_count * sizeof(ebpf::Instruction)) ||
            !load_export(export_prefix,
                         "handoff-commit.bpf",
                         emitted.commit,
                         emitted.commit_count * sizeof(ebpf::Instruction))) {
            fprintf(stderr, "invalid handoff export files\n");
            return 2;
        }
    }
    if (available) {
        stage = kernel.init(16, packet, export_prefix ? &emitted : nullptr);
        if (stage) {
            unavailable = errno;
            fprintf(
                stderr, "eBPF handoff %s: %s\n%s\n", stage, strerror(unavailable), kernel.verifier);
            kernel.destroy();
            if (!strcmp(mode, "required")) {
                printf("{\"available\":false,\"stage\":\"%s\",\"errno\":%d}\n", stage, unavailable);
                return 1;
            }
            available = false;
        }
    }
    if (selftest || notifications) {
        const bool kPassed =
            available && (notifications ? notification_selftest(kernel) : control_selftest(kernel));
        printf("{\"available\":%s,\"%s\":%s}\n",
               available ? "true" : "false",
               notifications ? "notification_selftest" : "control_selftest",
               kPassed ? "true" : "false");
        kernel.destroy();
        return available && !kPassed ? 1 : 0;
    }
    Connection source, target;
    if (!source.open() || !target.open()) return 2;
    rusage before{};
    getrusage(RUSAGE_SELF, &before);
    const u64 kStarted = now_ns();
    u64 relay_cpu = 0;
    rusage relay_before{};
    getrusage(RUSAGE_THREAD, &relay_before);
    struct Pipe {
        int fds[2] = {-1, -1};
        ~Pipe() {
            for (const int kFd : fds)
                if (kFd >= 0) close(kFd);
        }
    } pipe;
    if (kSplice && pipe2(pipe.fds, O_CLOEXEC) != 0) return 2;
    u64 source_cookie = 0, target_cookie = 0;
    if (available &&
        !kernel.enroll(source.relay, target.relay, source_cookie, target_cookie, 7, 19)) {
        perror("enroll");
        kernel.destroy();
        return 2;
    }
    const u64 kSetupDone = now_ns();
    char original[128], rewritten[128];
    snprintf(original,
             sizeof(original),
             "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nX-Test: old\r\n\r\n",
             size);
    snprintf(rewritten,
             sizeof(rewritten),
             "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nX-Test: rewritten\r\n\r\n",
             size);
    Writer writer{source.client, size, prequeue, delay, original, coalesced_tail};
    Reader reader{target.client, size, slow, rewritten};
    writer.chunk_bytes = reader.chunk_bytes = chunk;
    tcp_info initial_tcp{};
    static_assert(offsetof(tcp_info, tcpi_bytes_acked) == 120);
    socklen_t initial_tcp_length = sizeof(initial_tcp);
    if (getsockopt(target.relay, IPPROTO_TCP, TCP_INFO, &initial_tcp, &initial_tcp_length) != 0)
        return 2;
    u64 output_start = 0;
    if (!EbpfHandoffKernel::output_progress(target.relay, output_start)) return 2;
    pthread_t writer_thread{}, reader_thread{};
    if (pthread_create(&writer_thread, nullptr, write_response, &writer) != 0 ||
        pthread_create(&reader_thread, nullptr, read_response, &reader) != 0)
        return 2;
    char buffer[65536];
    const u32 kHeaderSize = static_cast<u32>(strlen(original));
    bool ok =
        read_exact(source.relay, buffer, kHeaderSize) && memcmp(buffer, original, kHeaderSize) == 0;
    if (ok && available && !packet)
        ok = kernel.publish_limit(source_cookie, kHeaderSize + size) ==
             EbpfHandoffKernel::Result::Committed;
    ok = ok && send_all(target.relay, rewritten, strlen(rewritten));
    const u64 kHeaderDone = now_ns();
    u64 control_ns = 0;
    u32 copied = 0, redirected = 0, spliced = 0, retries = 0;
    bool committed = false;
    while (ok && copied < size) {
        if (available) {
            const u64 kControlStart = now_ns();
            const auto kResult = kernel.commit(source_cookie, kHeaderSize + copied, size - copied);
            control_ns += now_ns() - kControlStart;
            if (kResult == EbpfHandoffKernel::Result::Error) {
                perror("commit");
                ok = false;
                break;
            }
            if (kResult == EbpfHandoffKernel::Result::Committed) {
                committed = true;
                redirected = size - copied;
                break;
            }
            ++retries;
        }
        const u32 kLeft = size - copied;
        if (kSplice) {
            const ssize_t kN =
                splice(source.relay, nullptr, pipe.fds[1], nullptr, kLeft, SPLICE_F_MOVE);
            if (kN < 0 && errno == EINTR) continue;
            if (kN <= 0) {
                ok = false;
                break;
            }
            for (ssize_t pending = kN; pending > 0;) {
                const ssize_t kSent = splice(pipe.fds[0],
                                             nullptr,
                                             target.relay,
                                             nullptr,
                                             static_cast<size_t>(pending),
                                             SPLICE_F_MOVE);
                if (kSent < 0 && errno == EINTR) continue;
                if (kSent <= 0) {
                    ok = false;
                    break;
                }
                pending -= kSent;
                copied += static_cast<u32>(kSent);
                spliced += static_cast<u32>(kSent);
            }
            continue;
        }
        const ssize_t kN =
            recv(source.relay, buffer, kLeft < chunk ? kLeft : chunk, available ? MSG_DONTWAIT : 0);
        if (kN < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            if (now_ns() - kStarted > 5000000000ull) {
                ok = false;
                break;
            }
            usleep(100);
            continue;
        }
        if (kN <= 0 || !send_all(target.relay, buffer, static_cast<size_t>(kN))) {
            ok = false;
            break;
        }
        copied += static_cast<u32>(kN);
    }
    ebpf::HandoffState state{};
    const u64 kCopyDone = now_ns();
    if (ok && committed && packet) {
        ebpf::HandoffNotification notification{};
        pollfd ready{kernel.fds[EbpfHandoffKernel::Ring], POLLIN, 0};
        while (!kernel.next_notification(notification)) {
            const int kResult = poll(&ready, 1, 100);
            if ((kResult < 0 && errno != EINTR) || now_ns() - kStarted > 5000000000ull) {
                ok = false;
                break;
            }
        }
        if (ok && (notification.source_cookie != source_cookie || notification.connection_id != 7 ||
                   notification.generation != 19))
            ok = false;
    }
    while (ok && committed) {
        if (!kernel.inspect(source_cookie, state) || state.failed) {
            ok = false;
            break;
        }
        if (!ebpf::handoff_budget(state.control)) break;
        if (packet) {
            ok = false;  // terminal notification must correspond to a terminal verdict
            break;
        }
        if (now_ns() - kStarted > 5000000000ull) {
            ok = false;
            break;
        }
        usleep(100);
    }
    const u64 kRedirectDone = now_ns();
    u64 barrier_ns = 0;
    u32 barrier_checks = 0;
    if (ok && committed && packet && state.tail_body) {
        const u64 kBarrierStart = now_ns();
        const u64 kPrefix = output_start + strlen(rewritten) + size - state.tail_body;
        while (ok) {
            ++barrier_checks;
            u64 progress = 0;
            if (!EbpfHandoffKernel::output_progress(target.relay, progress)) {
                ok = false;
                break;
            }
            if (progress >= kPrefix) break;
            if (now_ns() - kStarted > 5000000000ull) {
                ok = false;
                break;
            }
            usleep(100);
        }
        barrier_ns = now_ns() - kBarrierStart;
        for (u32 left = state.tail_body; ok && left;) {
            const u32 kCount = left < sizeof(buffer) ? left : sizeof(buffer);
            if (!read_exact(source.relay, buffer, kCount) ||
                !send_all(target.relay, buffer, kCount)) {
                ok = false;
                break;
            }
            copied += kCount;
            redirected -= kCount;
            left -= kCount;
        }
    }
    const u64 kTailDone = now_ns();
    // A zero budget does not prove TX-backlog drain. The peer reader provides
    // the completion barrier in this probe; the runtime needs a separate proof.
    if (!ok) {
        ebpf::HandoffState failed_state{};
        if (available && kernel.inspect(source_cookie, failed_state))
            fprintf(stderr,
                    "failed state: control=%llu frame=%u failed=%u copied=%u\n",
                    static_cast<unsigned long long>(failed_state.control),
                    failed_state.frame,
                    failed_state.failed,
                    copied);
        shutdown(source.client, SHUT_RDWR);
        shutdown(source.relay, SHUT_RDWR);
        shutdown(target.relay, SHUT_RDWR);
        shutdown(target.client, SHUT_RDWR);
    }
    pthread_join(writer_thread, nullptr);
    pthread_join(reader_thread, nullptr);
    const u64 kPeerDone = now_ns();
    constexpr char kSuccessor[] = "next-response-1234";
    char successor[sizeof(kSuccessor)]{};
    const bool kTailOk = ok && read_exact(source.relay, successor, sizeof(kSuccessor) - 1) &&
                         memcmp(successor, kSuccessor, sizeof(kSuccessor) - 1) == 0;
    char extra;
    const bool kBoundaryOk = kTailOk &&
                             recv(target.client, &extra, 1, MSG_PEEK | MSG_DONTWAIT) < 0 &&
                             (errno == EAGAIN || errno == EWOULDBLOCK);
    const bool kEofOk = kBoundaryOk && recv(source.relay, &extra, 1, 0) == 0 &&
                        shutdown(target.relay, SHUT_WR) == 0 &&
                        recv(target.client, &extra, 1, 0) == 0;
    bool retired = true;
    if (available) retired = kernel.retire(source_cookie, target_cookie);
    const bool kPassed = ok && writer.ok && reader.ok && kBoundaryOk && kEofOk && retired;
    const u64 kElapsed = now_ns() - kStarted;
    rusage after{};
    getrusage(RUSAGE_SELF, &after);
    rusage relay_after{};
    getrusage(RUSAGE_THREAD, &relay_after);
    relay_cpu = cpu_ns(relay_after) - cpu_ns(relay_before);
    kernel.destroy();
    printf(
        "{\"requested_mode\":\"%s\",\"available\":%s,\"backend\":\"%s\",\"transfer_ok\":%s,\"body_"
        "bytes\":%u,"
        "\"copied_body_bytes\":%u,\"redirected_body_bytes\":%u,\"spliced_body_bytes\":%u,"
        "\"successor_userspace_bytes\":%zu,"
        "\"half_close_ok\":%s,\"retired\":%s,\"commit_retries\":%u,\"unavailable_errno\":%d,"
        "\"elapsed_ns\":%llu,\"cpu_ns\":%llu,\"packet_verdict\":%s,\"tail_body_bytes\":%u,"
        "\"chunk_bytes\":%u,\"relay_cpu_ns\":%llu,\"writer_cpu_ns\":%llu,\"reader_cpu_ns\":%llu,"
        "\"setup_ns\":%llu,\"header_ns\":%llu,\"copy_or_handoff_ns\":%llu,\"control_ns\":%llu,"
        "\"redirect_wait_ns\":%llu,\"tail_ns\":%llu,\"barrier_ns\":%llu,\"barrier_checks\":%u,"
        "\"peer_join_ns\":%llu,\"retire_ns\":%llu}\n",
        mode,
        available ? "true" : "false",
        committed ? "sockhash" : (kSplice ? "splice" : "copy"),
        kPassed ? "true" : "false",
        size,
        copied - spliced,
        redirected,
        spliced,
        kTailOk ? sizeof(kSuccessor) - 1 : 0,
        kEofOk ? "true" : "false",
        retired ? "true" : "false",
        retries,
        unavailable,
        static_cast<unsigned long long>(kElapsed),
        static_cast<unsigned long long>(cpu_ns(after) - cpu_ns(before)),
        packet ? "true" : "false",
        state.tail_body,
        chunk,
        static_cast<unsigned long long>(relay_cpu),
        static_cast<unsigned long long>(writer.cpu),
        static_cast<unsigned long long>(reader.cpu),
        static_cast<unsigned long long>(kSetupDone - kStarted),
        static_cast<unsigned long long>(kHeaderDone - kSetupDone),
        static_cast<unsigned long long>(kCopyDone - kHeaderDone),
        static_cast<unsigned long long>(control_ns),
        static_cast<unsigned long long>(kRedirectDone - kCopyDone),
        static_cast<unsigned long long>(kTailDone - kRedirectDone),
        static_cast<unsigned long long>(barrier_ns),
        barrier_checks,
        static_cast<unsigned long long>(kPeerDone - kTailDone),
        static_cast<unsigned long long>(kStarted + kElapsed - kPeerDone));
    return kPassed ? 0 : 1;
}
// NOLINTEND(misc-include-cleaner)
