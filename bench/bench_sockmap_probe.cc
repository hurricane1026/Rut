// Isolated Linux capability experiment. No Rut compiler/runtime integration.
// Emits a bounded eBPF program directly; no ELF loader, libbpf, or LLVM linkage.
#include "rut/common/ebpf_bytecode.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
static_assert(sizeof(bpf_insn) == 8);
struct Resources {
    int fds[4] = {-1, -1, -1, -1};
    bool inserted[2] = {false, false};
    ~Resources() {
        for (int fd : fds)
            if (fd >= 0) close(fd);
    }
};
struct Connection {
    int client = -1;
    int relay = -1;
    ~Connection() {
        if (client >= 0) close(client);
        if (relay >= 0) close(relay);
    }
    bool open() {
        int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener < 0) return false;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        bool ok = bind(listener, reinterpret_cast<sockaddr*>(&address), length) == 0 &&
                  listen(listener, 1) == 0 &&
                  getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
        if (ok) {
            client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            ok = client >= 0 && connect(client, reinterpret_cast<sockaddr*>(&address), length) == 0;
        }
        if (ok) relay = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        close(listener);
        if (!ok || relay < 0) return false;
        const int kSockets[] = {client, relay};
        for (int fd : kSockets) {
            const timeval kTimeout{5, 0};
            const int kOne = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &kTimeout, sizeof(kTimeout)) != 0 ||
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &kTimeout, sizeof(kTimeout)) != 0 ||
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &kOne, sizeof(kOne)) != 0)
                return false;
        }
        return true;
    }
};
int bpf_call(int command, union bpf_attr& attr) {
    return static_cast<int>(syscall(SYS_bpf, command, &attr, sizeof(attr)));
}
bpf_insn insn(uint8_t code, uint8_t dst, uint8_t src, int16_t offset, int32_t value) {
    bpf_insn result{};
    result.code = code;
    result.dst_reg = dst;
    result.src_reg = src;
    result.off = offset;
    result.imm = value;
    return result;
}
char verifier[16384];
int load(bpf_insn* program, unsigned count, bpf_attach_type attach) {
    const char kLicense[] = "GPL";
    union bpf_attr attr{};
    attr.prog_type = BPF_PROG_TYPE_SK_SKB;
    attr.expected_attach_type = attach;
    attr.insn_cnt = count;
    attr.insns = reinterpret_cast<uintptr_t>(program);
    attr.license = reinterpret_cast<uintptr_t>(kLicense);
    attr.log_buf = reinterpret_cast<uintptr_t>(verifier);
    attr.log_size = sizeof(verifier);
    attr.log_level = 1;
    return bpf_call(BPF_PROG_LOAD, attr);
}
bool attach(int map, int program, bpf_attach_type type) {
    union bpf_attr attr{};
    attr.target_fd = map;
    attr.attach_bpf_fd = program;
    attr.attach_type = type;
    return bpf_call(BPF_PROG_ATTACH, attr) == 0;
}
bool insert(int map, uint32_t key, int socket_fd) {
    uint32_t value = static_cast<uint32_t>(socket_fd);
    union bpf_attr attr{};
    attr.map_fd = map;
    attr.key = reinterpret_cast<uintptr_t>(&key);
    attr.value = reinterpret_cast<uintptr_t>(&value);
    return bpf_call(BPF_MAP_UPDATE_ELEM, attr) == 0;
}
void templates(bpf_insn (&parser)[2], bpf_insn (&verdict)[10]) {
    parser[0] = insn(0x61, 0, 1, offsetof(__sk_buff, len), 0);
    parser[1] = insn(0x95, 0, 0, 0, 0);
    const bpf_insn kInstructions[] = {insn(0x61, 3, 1, offsetof(__sk_buff, local_port), 0),
                                      insn(0x15, 3, 0, 2, 0),
                                      insn(0xb7, 3, 0, 0, 0),
                                      insn(0x05, 0, 0, 1, 0),
                                      insn(0xb7, 3, 0, 0, 1),
                                      insn(0x18, 2, BPF_PSEUDO_MAP_FD, 0, 0),
                                      insn(0, 0, 0, 0, 0),
                                      insn(0xb7, 4, 0, 0, 0),
                                      insn(0x85, 0, 0, 0, BPF_FUNC_sk_redirect_map),
                                      insn(0x95, 0, 0, 0, 0)};
    memcpy(verdict, kInstructions, sizeof(verdict));
}
void body_templates(bpf_insn (&parser)[22], bpf_insn (&verdict)[31]) {
    static_assert(sizeof(bpf_insn) == sizeof(rut::ebpf::Instruction));
    static_assert(offsetof(__sk_buff, local_port) == rut::ebpf::kLocalPortOffset);
    static_assert(BPF_FUNC_map_lookup_elem == rut::ebpf::kMapLookupHelper);
    static_assert(BPF_FUNC_sk_redirect_map == rut::ebpf::kSocketRedirectHelper);
    rut::ebpf::BodyBytecode bytecode{};
    rut::ebpf::emit_body_bytecode(bytecode);
    memcpy(parser, bytecode.parser, sizeof(parser));
    memcpy(verdict, bytecode.verdict, sizeof(verdict));
}
bool artifact(const char* prefix, const char* suffix, void* bytes, size_t size, bool writing) {
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s.%s.bpf", prefix, suffix);
    if (length < 0 || static_cast<size_t>(length) >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return false;
    }
    int fd =
        open(path, writing ? O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC : O_RDONLY | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t done = 0;
    while (done < size) {
        ssize_t n = writing ? write(fd, static_cast<char*>(bytes) + done, size - done)
                            : read(fd, static_cast<char*>(bytes) + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            errno = EINVAL;
            return false;
        }
        done += static_cast<size_t>(n);
    }
    char extra;
    const bool kOk = writing || read(fd, &extra, 1) == 0;
    int result = close(fd);
    if (!kOk) errno = EINVAL;
    return kOk && result == 0;
}
const char* setup(Resources& resources,
                  int front,
                  int upstream,
                  bool inject_failure,
                  const char* prefix,
                  bool bounded) {
    bpf_insn parser[2], verdict[10], body_parser[22], body_verdict[31];
    templates(parser, verdict);
    body_templates(body_parser, body_verdict);
    bpf_insn* selected_parser = bounded ? body_parser : parser;
    bpf_insn* selected_verdict = bounded ? body_verdict : verdict;
    unsigned parser_count = bounded ? 22 : 2;
    unsigned verdict_count = bounded ? 31 : 10;
    if (prefix && (!artifact(prefix,
                             bounded ? "body-parser" : "parser",
                             selected_parser,
                             parser_count * sizeof(bpf_insn),
                             false) ||
                   !artifact(prefix,
                             bounded ? "body-verdict" : "verdict",
                             selected_verdict,
                             verdict_count * sizeof(bpf_insn),
                             false)))
        return "artifact_read";
    // The prototype accepts only the fixed tunnel or fixed-budget templates.
    bpf_insn expected_parser[2], expected_verdict[10], expected_body_parser[22],
        expected_body_verdict[31];
    templates(expected_parser, expected_verdict);
    body_templates(expected_body_parser, expected_body_verdict);
    if (memcmp(selected_parser,
               bounded ? expected_body_parser : expected_parser,
               parser_count * sizeof(bpf_insn)) != 0 ||
        memcmp(selected_verdict,
               bounded ? expected_body_verdict : expected_verdict,
               verdict_count * sizeof(bpf_insn)) != 0) {
        errno = EINVAL;
        return "artifact_validate";
    }
    union bpf_attr attr{};
    attr.map_type = BPF_MAP_TYPE_SOCKMAP;
    attr.key_size = attr.value_size = sizeof(uint32_t);
    attr.max_entries = 2;
    resources.fds[0] = bpf_call(BPF_MAP_CREATE, attr);
    if (resources.fds[0] < 0) return "map_create";
    sockaddr_in address{};
    socklen_t length = sizeof(address);
    if (getsockname(front, reinterpret_cast<sockaddr*>(&address), &length) != 0)
        return "getsockname";
    if (bounded) {
        attr = {};
        attr.map_type = BPF_MAP_TYPE_ARRAY;
        attr.key_size = attr.value_size = sizeof(uint32_t);
        attr.max_entries = 2;
        resources.fds[3] = bpf_call(BPF_MAP_CREATE, attr);
        if (resources.fds[3] < 0) return "budget_map_create";
        for (uint32_t key = 0; key < 2; ++key) {
            const uint32_t kValue = 1048576;
            attr = {};
            attr.map_fd = resources.fds[3];
            attr.key = reinterpret_cast<uintptr_t>(&key);
            attr.value = reinterpret_cast<uintptr_t>(&kValue);
            if (bpf_call(BPF_MAP_UPDATE_ELEM, attr) != 0) return "budget_init";
        }
        body_parser[3].imm = body_verdict[3].imm = ntohs(address.sin_port);
        body_parser[6].imm = body_verdict[6].imm = resources.fds[3];
        body_verdict[22].imm = resources.fds[0];
    } else {
        verdict[1].imm = ntohs(address.sin_port);
        verdict[5].imm = resources.fds[0];
    }
    resources.fds[1] = load(selected_parser, parser_count, BPF_SK_SKB_STREAM_PARSER);
    if (resources.fds[1] < 0) return "parser_load";
    resources.fds[2] = load(selected_verdict, verdict_count, BPF_SK_SKB_STREAM_VERDICT);
    if (resources.fds[2] < 0) return "verdict_load";
    if (!attach(resources.fds[0], resources.fds[1], BPF_SK_SKB_STREAM_PARSER))
        return "parser_attach";
    if (!attach(resources.fds[0], resources.fds[2], BPF_SK_SKB_STREAM_VERDICT))
        return "verdict_attach";
    // A consumed header and residual body can share an skb. Do not activate this
    // prototype on a nonempty receive queue; the regression fixture stalls otherwise.
    // This snapshot is not an atomic handoff guarantee against concurrent arrivals.
    int queued = 0;
    if (ioctl(front, FIONREAD, &queued) != 0) return "queue_probe";
    if (queued != 0) {
        errno = EAGAIN;
        return "prequeued_body";
    }
    if (!insert(resources.fds[0], 0, front)) return "front_insert";
    resources.inserted[0] = true;
    if (inject_failure) {
        errno = EIO;
        return "injected_after_front_insert";
    }
    if (!insert(resources.fds[0], 1, upstream)) return "upstream_insert";
    resources.inserted[1] = true;
    return nullptr;
}
bool send_all(int fd, const char* bytes, size_t size) {
    while (size) {
        ssize_t n = send(fd, bytes, size, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}
struct Transfer {
    int from;
    int to;
    size_t size;
    bool ok = false;
    size_t copied = 0;
};
void* copy_transfer(void* argument) {
    auto& transfer = *static_cast<Transfer*>(argument);
    char bytes[4096];
    while (transfer.copied < transfer.size) {
        size_t left = transfer.size - transfer.copied;
        ssize_t n = recv(transfer.from, bytes, left < sizeof(bytes) ? left : sizeof(bytes), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || !send_all(transfer.to, bytes, static_cast<size_t>(n))) return nullptr;
        transfer.copied += static_cast<size_t>(n);
    }
    transfer.ok = true;
    return nullptr;
}
void* write_transfer(void* argument) {
    auto& transfer = *static_cast<Transfer*>(argument);
    char bytes[4113];
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = static_cast<char>((i % 4096) % 251);
    for (size_t sent = 0; sent < transfer.size;) {
        size_t left = transfer.size - sent;
        // Put the last body bytes and successor in one send(), exercising a split at the budget.
        size_t n = left <= sizeof(bytes) ? left : 4096;
        if (!send_all(transfer.from, bytes, n)) return nullptr;
        sent += n;
    }
    transfer.ok = true;
    return nullptr;
}
bool exchange(int sender,
              int receiver,
              int relay_from,
              int relay_to,
              bool kernel,
              size_t size,
              bool slow,
              size_t& copied,
              size_t tail = 0,
              size_t prequeued = 0) {
    Transfer writer{sender, -1, size + tail - prequeued};
    Transfer relay{relay_from, relay_to, size};
    pthread_t writer_thread{}, relay_thread{};
    if (!kernel && pthread_create(&relay_thread, nullptr, copy_transfer, &relay) != 0) return false;
    if (pthread_create(&writer_thread, nullptr, write_transfer, &writer) != 0) {
        if (!kernel) pthread_join(relay_thread, nullptr);
        return false;
    }
    if (slow) usleep(100000);
    char bytes[4096];
    size_t received = 0;
    bool ok = true;
    while (received < size) {
        const size_t kLeft = size - received;
        ssize_t n = recv(receiver, bytes, kLeft < sizeof(bytes) ? kLeft : sizeof(bytes), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            fprintf(stderr,
                    "payload receive stopped at %zu/%zu: %s\n",
                    received,
                    size,
                    strerror(errno));
            ok = false;
            break;
        }
        for (ssize_t i = 0; i < n; ++i)
            if (bytes[i] != static_cast<char>(((received + static_cast<size_t>(i)) % 4096) % 251)) {
                if (ok)
                    fprintf(stderr,
                            "payload mismatch at %zu: %u\n",
                            received + static_cast<size_t>(i),
                            static_cast<unsigned char>(bytes[i]));
                ok = false;
            }
        received += static_cast<size_t>(n);
    }
    pthread_join(writer_thread, nullptr);
    if (!kernel) pthread_join(relay_thread, nullptr);
    if (tail) {
        char successor[17];
        if (tail != sizeof(successor) ||
            recv(relay_from, successor, sizeof(successor), MSG_WAITALL) != sizeof(successor))
            ok = false;
        else
            for (size_t i = 0; i < sizeof(successor); ++i)
                if (successor[i] != static_cast<char>(i)) ok = false;
    }
    if (tail) {
        char extra;
        if (recv(receiver, &extra, 1, MSG_PEEK | MSG_DONTWAIT) >= 0 ||
            (errno != EAGAIN && errno != EWOULDBLOCK))
            ok = false;
    }
    copied += relay.copied;
    return ok && writer.ok && (kernel || relay.ok) && received == size;
}
int configure_tls(int socket_fd) {
    if (setsockopt(socket_fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls")) != 0) return errno;
    // Synthetic record keys only test setsockopt compatibility. No handshake or TLS traffic.
    tls12_crypto_info_aes_gcm_128 crypto{};
    crypto.info.version = TLS_1_2_VERSION;
    crypto.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    if (setsockopt(socket_fd, SOL_TLS, TLS_TX, &crypto, sizeof(crypto)) != 0) return errno;
    return 0;
}
}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && !strcmp(argv[1], "emit")) {
        bpf_insn parser[2], verdict[10];
        templates(parser, verdict);
        bpf_insn body_parser[22], body_verdict[31];
        body_templates(body_parser, body_verdict);
        if (!artifact(argv[2], "parser", parser, sizeof(parser), true) ||
            !artifact(argv[2], "verdict", verdict, sizeof(verdict), true) ||
            !artifact(argv[2], "body-parser", body_parser, sizeof(body_parser), true) ||
            !artifact(argv[2], "body-verdict", body_verdict, sizeof(body_verdict), true)) {
            perror("emit");
            return 2;
        }
        printf(
            "{\"emitted\":true,\"parser_bytes\":%zu,\"verdict_bytes\":%zu,"
            "\"front_port_instruction\":1,\"map_fd_instruction\":5,"
            "\"body_parser_bytes\":176,\"body_verdict_bytes\":248,"
            "\"body_front_port_instruction\":3,\"body_budget_map_instruction\":6,"
            "\"body_socket_map_instruction\":22}\n",
            sizeof(parser),
            sizeof(verdict));
        return 0;
    }
    const char* mode = argc >= 2 ? argv[1] : "";
    bool inject = false, header = false, bounded = false, prequeued = false;
    const char* prefix = nullptr;
    bool valid =
        argc >= 2 && (!strcmp(mode, "off") || !strcmp(mode, "auto") || !strcmp(mode, "required"));
    for (int i = 2; i < argc && valid; ++i) {
        if (!strcmp(argv[i], "--fail-after-insert") && !inject)
            inject = true;
        else if (!strcmp(argv[i], "--prequeued-body") && !prequeued)
            prequeued = true;
        else if (!strcmp(argv[i], "--bounded-body") && !bounded)
            bounded = true;
        else if (!strcmp(argv[i], "--header-rewrite") && !header)
            header = true;
        else if (!strcmp(argv[i], "--bytecode") && !prefix && i + 1 < argc)
            prefix = argv[++i];
        else
            valid = false;
    }
    if (!valid || (prequeued && !header)) {
        fprintf(stderr,
                "usage: bench_sockmap_probe emit PREFIX | off|auto|required "
                "[--bytecode PREFIX] [--fail-after-insert] [--header-rewrite] [--bounded-body] "
                "[--prequeued-body]\n");
        return 2;
    }
    Connection front, origin;
    if (!front.open() || !origin.open()) return 2;
    size_t header_bytes = 0;
    if (header) {
        // Controlled fixture: exact header boundary; no read-ahead and no parser claim.
        const char kOriginal[] = "GET / HTTP/1.1\r\nHost: old\r\nContent-Length: 1048576\r\n\r\n";
        const char kRewritten[] =
            "GET / HTTP/1.1\r\nHost: rewritten\r\nContent-Length: 1048576\r\n\r\n";
        char received[sizeof(kRewritten)]{};
        char queued[sizeof(kOriginal) - 1 + 4096];
        memcpy(queued, kOriginal, sizeof(kOriginal) - 1);
        for (size_t i = 0; i < 4096; ++i)
            queued[sizeof(kOriginal) - 1 + i] = static_cast<char>(i % 251);
        if (!send_all(front.client, queued, sizeof(kOriginal) - 1 + (prequeued ? 4096 : 0)) ||
            recv(front.relay, received, sizeof(kOriginal) - 1, MSG_WAITALL) !=
                sizeof(kOriginal) - 1 ||
            memcmp(received, kOriginal, sizeof(kOriginal) - 1) != 0 ||
            !send_all(origin.relay, kRewritten, sizeof(kRewritten) - 1) ||
            recv(origin.client, received, sizeof(kRewritten) - 1, MSG_WAITALL) !=
                sizeof(kRewritten) - 1 ||
            memcmp(received, kRewritten, sizeof(kRewritten) - 1) != 0)
            return 1;
        header_bytes = sizeof(kOriginal) - 1;
    }
    Resources resources;
    const char* failed = nullptr;
    int error = 0;
    bool kernel = false;
    if (strcmp(mode, "off") != 0) {
        failed = setup(resources, front.relay, origin.relay, inject, prefix, bounded);
        error = failed ? errno : 0;
        if (failed) {
            // Roll back before payload forwarding; preserve the established connections.
            const bool kIneligible = !strcmp(failed, "prequeued_body");
            fprintf(stderr,
                    "eBPF %s at %s: %s\n%s\n",
                    kIneligible ? "ineligible" : "unavailable",
                    failed,
                    strerror(error),
                    verifier);
            printf("{\"mode\":\"%s\",\"backend\":\"%s\",\"stage\":\"%s\",\"errno\":%d}\n",
                   mode,
                   kIneligible ? "ineligible" : "unavailable",
                   failed,
                   error);
            if (!strcmp(mode, "required") && !kIneligible) return 1;
            if (resources.fds[0] >= 0) {
                for (uint32_t key = 0; key < 2; ++key) {
                    if (!resources.inserted[key]) continue;
                    union bpf_attr remove{};
                    remove.map_fd = resources.fds[0];
                    remove.key = reinterpret_cast<uintptr_t>(&key);
                    if (bpf_call(BPF_MAP_DELETE_ELEM, remove) != 0 && errno != ENOENT) {
                        fprintf(stderr, "rollback key %u: %s\n", key, strerror(errno));
                        return 2;
                    }
                }
            }
            for (int& fd : resources.fds) {
                if (fd >= 0) close(fd);
                fd = -1;
            }
        } else
            kernel = true;
    }
    size_t copied = 0;
    const bool kOk =
        exchange(front.client,
                 origin.client,
                 front.relay,
                 origin.relay,
                 kernel,
                 1048576,
                 true,
                 copied,
                 bounded && kernel ? 17 : 0,
                 prequeued ? 4096 : 0) &&
        exchange(origin.client,
                 front.client,
                 origin.relay,
                 front.relay,
                 kernel,
                 1048576,
                 true,
                 copied) &&
        ((bounded && kernel) ||
         exchange(
             front.client, origin.client, front.relay, origin.relay, kernel, 17, false, copied));
    // FIN propagation remains a userspace control operation; no payload is read here.
    char eof;
    const bool kHalfCloseOk =
        kOk && shutdown(front.client, SHUT_WR) == 0 && recv(front.relay, &eof, 1, 0) == 0 &&
        shutdown(origin.relay, SHUT_WR) == 0 && recv(origin.client, &eof, 1, 0) == 0 &&
        shutdown(origin.client, SHUT_WR) == 0 && recv(origin.relay, &eof, 1, 0) == 0 &&
        shutdown(front.relay, SHUT_WR) == 0 && recv(front.client, &eof, 1, 0) == 0;
    // Compatibility only: isolated fresh sockets and synthetic keys; no TLS traffic.
    int tls_only = -1, map_then_tls = -1, tls_then_map = -1;
    if (kernel) {
        Connection tls_front, tls_origin, tls;
        Resources tls_map;
        if (!tls_front.open() || !tls_origin.open() || !tls.open() ||
            setup(tls_map, tls_front.relay, tls_origin.relay, false, nullptr, false))
            return 2;
        map_then_tls = configure_tls(tls_front.relay);
        tls_only = configure_tls(tls.relay);
        if (tls_only == 0) tls_then_map = insert(tls_map.fds[0], 0, tls.relay) ? 0 : errno;
    }
    printf(
        "{\"mode\":\"%s\",\"backend\":\"%s\",\"transfer_ok\":%s,"
        "\"verified_bytes\":%u,\"relay_userspace_bytes\":%zu,\"header_userspace_bytes\":%zu,\"tls_"
        "only_errno\":%d,"
        "\"map_then_tls_errno\":%d,\"tls_then_map_errno\":%d,\"successor_userspace_bytes\":%u,"
        "\"half_close_ok\":%s}\n",
        mode,
        kernel ? "sockmap" : "copy",
        kOk ? "true" : "false",
        kOk ? 2097169u : 0u,
        copied,
        header_bytes,
        tls_only,
        map_then_tls,
        tls_then_map,
        bounded && kernel ? 17u : 0u,
        kHalfCloseOk ? "true" : "false");
    return kOk && kHalfCloseOk ? 0 : 1;
}
